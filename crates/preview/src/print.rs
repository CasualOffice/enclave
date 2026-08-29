//! Print grants: the capability `docs/05-API.md §9` mints, and the statement that spends it once.
//!
//! # What this replaces, and why it had to move
//!
//! `ENC-720` shipped the mint with its live grants in a `HashMap` behind a `Mutex` inside one API
//! process, and recorded the limit in its own source: *"a grant minted on one replica cannot be
//! redeemed on another."* That failed in the safe direction — a cross-replica presentation is
//! refused, never honoured twice — and it made print unusable behind a load balancer, which is
//! every real deployment. `ENC-724` moves the registry into `print_tokens`
//! (`docs/04-DATA-MODEL.md §15.2`).
//!
//! # Single use is one statement, and the shape of it is the argument
//!
//! [`redeem`] issues `UPDATE … WHERE redeemed_at IS NULL … RETURNING`. **The predicate names the
//! column the statement writes**, which is what makes it safe against itself: under `READ
//! COMMITTED` — what the application pool connects at — the second of two concurrent redemptions
//! blocks on the row lock the first took, and when the first commits, PostgreSQL re-evaluates the
//! second's `WHERE` against the *updated* row. `redeemed_at` is no longer `NULL`, so it matches
//! nothing and returns zero rows. Exactly one winner, on two machines that share nothing but this
//! database.
//!
//! The loser needs no arm of its own, and that is the point rather than a convenience: zero rows is
//! already the answer for a token that never existed, so "already spent" and "never issued" are
//! reached by the same path and cannot be told apart by a caller. The same is true of "expired"
//! (`expires_at > now()` sits in the same predicate) and of "another tenant's" (`tenant_id = $1`,
//! and row-level security besides). Four failures, one answer — `CLAUDE.md` rule 7 by construction
//! rather than by four `if`s that all have to keep returning the same thing.
//!
//! What is deliberately **not** used:
//!
//! * a `SELECT` then an `UPDATE` — both readers see `NULL`, both decide they may proceed, and
//!   neither blocked because the read took no lock. Two prints from one grant, and it is the exact
//!   shape `plans/M2-ACCESS-DELIVERY.md` D18 forbids for download budgets;
//! * a `DELETE … RETURNING` — correct on the race, but it destroys the evidence in the same
//!   statement, so a replay arriving a second later is indistinguishable from one arriving after
//!   the reaper has run.
//!
//! # The clock is PostgreSQL's, on every statement here
//!
//! `now()` is evaluated by the database in [`redeem`] and in [`reap_expired`], never passed in.
//! `crates/worker/src/invalidation.rs` found the cost of the alternative: a process running a few
//! seconds ahead of the database honours grants the database considers dead, or refuses ones it
//! considers live, in a window that is small, silent, and entirely avoidable. There is no parameter
//! here through which the next caller could reintroduce it.
//!
//! # A grant is bound to a principal, and row-level security cannot hold that
//!
//! Tenancy is the easy half. The half that matters is that a print grant names **one actor and one
//! sign-in**, and a second user *in the same tenant* is not that actor — a distinction RLS is blind
//! to, because both rows are this tenant's. The `actor_type`/`actor_id`/`session_id` triple is in
//! [`redeem`]'s `WHERE` rather than checked after it returns, so a presentation by the wrong
//! principal does not *consume* the grant on its way to being refused: a thief able to burn a
//! colleague's token would hold a denial of service for the price of a value they stole.
//!
//! `docs/12-TESTING.md §4.2` A21 is that test, and it uses a same-tenant thief on purpose. A
//! `tenant-beta` one would have been refused by row-level security whether or not this predicate
//! existed, which is how nine separate crates here have had a `tenant_id` predicate deleted without
//! a single test noticing.
//!
//! That is not a worry about this module; it was **measured** on it. Deleting `tenant_id = $1` from
//! [`REAP_SQL`] leaves `one_tenants_sweep_cannot_reach_anothers_grants` green, because RLS refuses
//! the other tenant's rows on its own. Deleting `actor_id IS NOT DISTINCT FROM $5` from
//! [`REDEEM_SQL`] fails `a_colleague_in_the_same_tenant_cannot_spend_another_persons_grant`
//! immediately, with RLS fully in force. The second is therefore the isolation test that means
//! something here, and the first is recorded as the boundary check beside it rather than as proof of
//! a predicate it does not actually exercise.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use core::fmt;
use enclave_core::{Actor, ActorKind, FileId, SessionId, TenantId, VersionId};
use rand::rand_core::TryRng as _;
use rand::rngs::SysRng;
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, Row as _};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::{PreviewError, Result};

/// Bytes of entropy in a print token.
///
/// 256 bits, with no structure. The same size and the same reasoning as `crates/auth`'s refresh
/// token and `crates/sharing`'s share token: there is nothing in it to guess, nothing to enumerate,
/// and no field an attacker can vary.
pub const PRINT_TOKEN_BYTES: usize = 32;

/// The plaintext of a print capability. Held for as long as it takes to return it, and no longer.
///
/// Wrapped in [`Zeroizing`] and printed as `PrintToken(redacted)` for the reason
/// `crates/sharing::ShareToken` gives: a `Debug` line inside a tracing span is a working capability
/// in a log aggregator, and the span is written by somebody who was not thinking about this type.
pub struct PrintToken(Zeroizing<String>);

impl fmt::Debug for PrintToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrintToken(redacted)")
    }
}

impl PrintToken {
    /// Mints a fresh capability from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// [`PreviewError::Entropy`] when the operating system declines. Propagated rather than
    /// unwrapped, for the reason `crates/auth`'s equivalent gives: a capability minted from a
    /// degraded entropy source is worse than no capability at all, and a caller can retry.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; PRINT_TOKEN_BYTES];
        SysRng.try_fill_bytes(&mut bytes).map_err(|_error| PreviewError::Entropy)?;
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))))
    }

    /// Accepts a value a caller presented, if it is the right *shape* to be one of ours.
    ///
    /// Shape only — nothing here says the token exists. It exists so a value that could not
    /// possibly be a grant is not turned into a digest and a round trip, and the caller must answer
    /// `None` exactly as it answers a token that hashed to nothing: a malformed presentation that
    /// produced a different status from an unknown one would be an oracle for the encoding.
    #[must_use]
    pub fn parse(presented: &str) -> Option<Self> {
        let decoded = URL_SAFE_NO_PAD.decode(presented).ok()?;
        (decoded.len() == PRINT_TOKEN_BYTES).then(|| Self(Zeroizing::new(presented.to_owned())))
    }

    /// The value handed to the caller, once, in the mint's response.
    ///
    /// Named `expose` rather than `as_str` so every place the plaintext escapes is greppable —
    /// `crates/sharing::ShareToken::expose`'s convention, kept deliberately identical.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value stored in `print_tokens.token_hash`.
    #[must_use]
    pub fn digest(&self) -> PrintTokenDigest {
        PrintTokenDigest(Sha256::digest(self.0.as_bytes()).into())
    }
}

/// SHA-256 of a print token: what the database holds, and the only form ever compared.
#[derive(Clone, Copy)]
pub struct PrintTokenDigest([u8; 32]);

impl fmt::Debug for PrintTokenDigest {
    /// A digest is not a credential, but printing it in full invites somebody to paste it into a
    /// bug report and from there into a `WHERE` clause. Eight hex characters correlate well enough.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrintTokenDigest({}…)", &self.to_hex()[..8])
    }
}

impl PartialEq for PrintTokenDigest {
    /// Constant time. A comparison that short-circuits leaks, byte by byte, how much of a guess was
    /// right — which over enough attempts reconstructs a stored digest.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for PrintTokenDigest {}

impl PrintTokenDigest {
    /// Lowercase hex, as stored in `print_tokens.token_hash`.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }
}

/// What one print grant permits, and to whom — the row as it is written.
///
/// Every field narrows it. A capability that named only the file would be redeemable by anyone who
/// obtained the token; one that named only the actor would survive the version being replaced. The
/// session is here because `docs/06 §5.1` puts a session reference in the watermark itself: a
/// printed page is attributable to one sign-in, and the grant that produced it should be too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintGrant {
    /// The file. One grant, one document.
    pub file: FileId,
    /// The version, resolved at mint time from the readable-version query, so a grant cannot come
    /// to refer to content uploaded after it was issued and cannot name a version antivirus has not
    /// cleared (`CLAUDE.md` rule 9).
    pub version: VersionId,
    /// Who asked. A grant is not transferable.
    pub actor: Actor,
    /// Which sign-in. `None` only for principals that have no session.
    pub session: Option<SessionId>,
    /// Whether whatever this grant is spent on must carry the viewer's mark.
    pub watermark: bool,
    /// When it stops being redeemable, whether or not anything has swept it.
    pub expires_at: DateTime<Utc>,
}

/// What a successful redemption yields: the narrowest possible answer.
///
/// The file and the actor are not returned, because the caller supplied both in the `WHERE` — a
/// redemption that *echoed* them would invite a handler to trust the row over the request context,
/// which is `CLAUDE.md` rule 3 read backwards. What only the row can say is which version was
/// pinned at mint time and whether the artefact must be marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a redeemed capability that is not spent is a print grant consumed for nothing"]
pub struct RedeemedPrint {
    /// The version the grant was minted against.
    pub version: VersionId,
    /// Whether the artefact must carry the viewer's mark, as decided at mint time.
    pub watermark: bool,
}

const ISSUE_SQL: &str = "\
    INSERT INTO print_tokens \
      (tenant_id, token_hash, file_id, version_id, actor_type, actor_id, session_id, watermark, \
       issued_at, expires_at) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)";

/// The redeeming statement. See the module header for why it is shaped exactly like this.
///
/// Every clause is load-bearing and none of them is a defence in depth for another:
/// `tenant_id`/`file_id` bind the grant to what the caller asked for, the actor triple binds it to
/// who is asking, `redeemed_at IS NULL` is the single-use property, and `expires_at > now()` is the
/// lifetime. Removing any one of them widens the capability, and each has a test that fails when it
/// is removed rather than a comment saying it should not be.
const REDEEM_SQL: &str = "\
    UPDATE print_tokens \
       SET redeemed_at = now() \
     WHERE tenant_id   = $1 \
       AND token_hash  = $2 \
       AND file_id     = $3 \
       AND actor_type  = $4 \
       AND actor_id IS NOT DISTINCT FROM $5 \
       AND session_id IS NOT DISTINCT FROM $6 \
       AND redeemed_at IS NULL \
       AND expires_at  > now() \
    RETURNING version_id, watermark";

/// The reaper's statement. Bounded, and it reads the same clock every other statement here does.
const REAP_SQL: &str = "\
    DELETE FROM print_tokens \
     WHERE ctid IN ( \
        SELECT ctid FROM print_tokens \
         WHERE tenant_id = $1 AND expires_at <= now() \
         LIMIT $2 \
     )";

/// Records a freshly minted grant.
///
/// The token itself is never passed in — only its digest — so there is no signature here through
/// which a plaintext capability could reach the database or a query log.
///
/// # Errors
///
/// [`PreviewError::Storage`] if the insert fails. A duplicate digest would be a primary-key
/// violation and is reported as one rather than swallowed: two grants hashing alike means the
/// CSPRNG has stopped being one, which is not a condition to continue through.
pub async fn issue(
    conn: &mut PgConnection,
    tenant: TenantId,
    digest: PrintTokenDigest,
    grant: &PrintGrant,
) -> Result<()> {
    sqlx::query(ISSUE_SQL)
        .bind(tenant.as_uuid())
        .bind(digest.to_hex())
        .bind(grant.file.as_uuid())
        .bind(grant.version.as_uuid())
        .bind(grant.actor.kind().as_str())
        .bind(grant.actor.subject_id())
        .bind(grant.session.map(|id| id.as_uuid()))
        .bind(grant.watermark)
        .bind(grant.expires_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Spends a grant, if this exact principal holds an unspent, unexpired one for this exact file.
///
/// Returns `Ok(None)` for a token that was never issued, one already redeemed, one whose lifetime
/// has elapsed, one minted in another tenant, one minted for another file, and one minted for
/// another actor or another sign-in. **Seven causes, one answer**, and there is no variant in the
/// return type through which a caller could learn which — a presenter told "expired" has been told
/// their token was real (`CLAUDE.md` rule 7).
///
/// # Errors
///
/// [`PreviewError::Storage`] if the statement fails, and [`PreviewError::MalformedRow`] if the
/// returned row cannot be read. Neither is a refusal: a database that could not answer has not
/// answered "no", and reporting it as one would make an outage look like a tenant full of replayed
/// tokens.
pub async fn redeem(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    actor: Actor,
    session: Option<SessionId>,
    digest: PrintTokenDigest,
) -> Result<Option<RedeemedPrint>> {
    let row = sqlx::query(REDEEM_SQL)
        .bind(tenant.as_uuid())
        .bind(digest.to_hex())
        .bind(file.as_uuid())
        .bind(actor.kind().as_str())
        .bind(actor.subject_id())
        .bind(session.map(|id| id.as_uuid()))
        .fetch_optional(&mut *conn)
        .await?;

    let Some(row) = row else { return Ok(None) };

    let version: uuid::Uuid = row.try_get("version_id").map_err(|_error| {
        PreviewError::MalformedRow { column: "version_id", reason: "missing or not a uuid" }
    })?;
    let watermark: bool = row.try_get("watermark").map_err(|_error| {
        PreviewError::MalformedRow { column: "watermark", reason: "missing or not a boolean" }
    })?;

    Ok(Some(RedeemedPrint { version: VersionId::from(version), watermark }))
}

/// Deletes one tenant's dead grants, up to `batch` of them, and reports how many went.
///
/// The predicate is `expires_at <= now()` and nothing else — deliberately not "redeemed", and
/// deliberately not a retention window. A row past its expiry is refused by [`redeem`] whether it
/// is here or not, so deleting it changes nothing any caller can observe, and that is the entire
/// safety argument: this sweep can be stopped, resumed, run twice or never run at all. The same
/// argument `crates/worker/src/invalidation.rs` makes about lifting a suppression, and the reason
/// neither pass needs a lock or a checkpoint.
///
/// A redeemed grant that has not yet expired is **kept**, and that is useful rather than
/// incidental: while the row is there a replay is refused by `redeemed_at IS NULL`, and after it is
/// gone a replay is refused by there being no row. Both are `Ok(None)`, so the sweep cannot change
/// what a caller sees.
///
/// # Errors
///
/// [`PreviewError::Storage`] if the delete fails.
pub async fn reap_expired(
    conn: &mut PgConnection,
    tenant: TenantId,
    batch: usize,
) -> Result<usize> {
    let bound = i64::try_from(batch).unwrap_or(i64::MAX);
    let deleted = sqlx::query(REAP_SQL)
        .bind(tenant.as_uuid())
        .bind(bound)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(usize::try_from(deleted).unwrap_or(usize::MAX))
}

/// Every actor kind the `print_tokens.actor_type` `CHECK` admits.
///
/// Not used by the statements above — they bind [`ActorKind::as_str`] directly, which is the point:
/// the column's vocabulary and the enum's are the same strings by construction. This exists so a
/// test can assert that, because the alternative is discovering the mismatch as a constraint
/// violation on the one principal kind nobody minted a grant for in a test.
///
/// # Why this is a filter rather than [`ActorKind::all`] (`ENC-919`)
///
/// It *was* `all()`, and that was right when the enum had five variants and the column listed the
/// same five. `ENC-879` added a sixth, [`ActorKind::ShareLink`], and the two stopped agreeing —
/// which this function's own test caught on `main` and neither contributing branch could have seen,
/// because `#83` added the variant and `#85` wrote the `CHECK` and neither contained the other.
///
/// The column is right and the exclusion is **structural rather than a policy choice**. A print
/// grant is minted for the caller its access token names, and `share_link` is the one kind no token
/// may ever carry: `AccessTokenIssuer::issue` refuses to mint one and `check_claims` refuses to
/// accept one, so a `typ` of `share_link` is a rejected token rather than a principal. There is no
/// request that could reach `POST /files/{id}/print-token` as a link bearer, so a row naming one
/// could not be written by any code path — and a `CHECK` that admitted it would be describing a
/// caller that cannot exist. It would also outlive its link: `print_tokens` has a stated lifetime
/// of its own and revoking a link does not sweep it, which is the laundering `ENC-879` refused for
/// `refresh_tokens.actor_type` by the same argument.
///
/// The `match` is exhaustive with no `_` arm on purpose. A seventh actor kind must not silently
/// join or silently miss this column; it has to be decided, here, by whoever adds it.
#[must_use]
pub fn stored_actor_kinds() -> Vec<&'static str> {
    ActorKind::all()
        .iter()
        .filter(|kind| match kind {
            ActorKind::User
            | ActorKind::Guest
            | ActorKind::ServiceAccount
            | ActorKind::McpClient
            | ActorKind::System => true,
            ActorKind::ShareLink => false,
        })
        .map(|kind| kind.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_token_never_prints_itself() {
        let token = PrintToken::generate().expect("entropy");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "PrintToken(redacted)");
        assert!(
            !rendered.contains(token.expose()),
            "the Debug impl leaked the token, so any tracing span carrying one is a live print \
             capability in a log aggregator"
        );
    }

    #[test]
    fn two_tokens_are_never_the_same() {
        // Not a statistical claim about the CSPRNG — a check that `generate` reads fresh entropy on
        // each call rather than caching, which is the way this goes wrong in practice.
        let a = PrintToken::generate().expect("entropy");
        let b = PrintToken::generate().expect("entropy");
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.digest().to_hex(), b.digest().to_hex());
    }

    #[test]
    fn a_token_carries_the_full_entropy_it_claims() {
        let token = PrintToken::generate().expect("entropy");
        let decoded = URL_SAFE_NO_PAD.decode(token.expose()).expect("base64url");
        assert_eq!(decoded.len(), PRINT_TOKEN_BYTES);
    }

    #[test]
    fn a_digest_is_the_column_the_migration_declares() {
        // `token_hash TEXT NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$')`. A digest rendered in
        // upper case, or as base64, or with a prefix, would be refused by the constraint at
        // runtime — on the insert, in production, for a caller who did nothing wrong.
        let hex = PrintToken::generate().expect("entropy").digest().to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "the digest is not lowercase hex, which `print_tokens.token_hash`'s CHECK refuses: \
             {hex}"
        );
    }

    #[test]
    fn a_presented_value_of_the_wrong_shape_is_not_a_token() {
        assert!(PrintToken::parse("").is_none());
        assert!(PrintToken::parse("not base64url!!").is_none());
        // Right alphabet, wrong length — the case a length check catches and a decode does not.
        assert!(PrintToken::parse(&URL_SAFE_NO_PAD.encode([0_u8; 16])).is_none());

        // The positive control. Without it every assertion above is satisfied by a `parse` that
        // returns `None` for everything, which is exactly the free-passing absence
        // `docs/12-TESTING.md §1.2` warns about.
        let real = PrintToken::generate().expect("entropy");
        let parsed = PrintToken::parse(real.expose()).expect("a freshly minted token parses");
        assert_eq!(parsed.digest(), real.digest());
    }

    #[test]
    fn the_stored_actor_vocabulary_is_the_migrations_own() {
        // The migration's CHECK, written out. If `ActorKind` gains a variant or renames a wire
        // string, this fails here rather than as a constraint violation on the one principal kind
        // no test happened to mint a grant for. It did exactly that on `main` for `share_link`
        // (`ENC-919`), which is the one thing about this failure worth keeping: the drift detector
        // worked, and it was the only thing that noticed.
        assert_eq!(
            stored_actor_kinds(),
            vec!["user", "guest", "service", "mcp", "system"],
            "this list is `migrations/0028_print_tokens.sql`'s CHECK and must stay byte-identical \
             to it — the migration is merged and forward-only, so a disagreement is fixed here or \
             in a new migration, never by editing that file"
        );
    }

    /// A link bearer is not a principal a print grant can name, and that is deliberate.
    ///
    /// The companion to the test above, and the reason it is a separate one: the list assertion
    /// would go green again if somebody "fixed" the drift by adding `share_link` to the expectation
    /// — the change that looks like housekeeping and is actually the defect. This asserts the
    /// exclusion itself, so that reading fails too.
    ///
    /// `ENC-919`. The kind is excluded because no access token may carry it, so no request can
    /// reach the minting endpoint as one; and because a print grant outlives its link, which is the
    /// laundering `ENC-879` refused for `refresh_tokens` by the same argument.
    #[test]
    fn a_share_link_bearer_is_not_an_actor_a_print_grant_can_name() {
        assert!(
            !stored_actor_kinds().contains(&ActorKind::ShareLink.as_str()),
            "a print grant naming a link bearer would outlive the link that produced it"
        );
        // The positive control. Without it this passes against a `stored_actor_kinds` that returns
        // nothing at all, which is the free-passing absence `docs/12-TESTING.md §1.2` warns about.
        assert!(stored_actor_kinds().contains(&ActorKind::User.as_str()));
        assert_eq!(stored_actor_kinds().len(), ActorKind::all().len() - 1);
    }
}
