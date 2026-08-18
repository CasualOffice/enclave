//! Opaque refresh tokens, their storage contract, and rotation with reuse detection
//! (`docs/03-LLD.md §5.3`, `docs/04-DATA-MODEL.md §6`).
//!
//! # Why the token is opaque
//!
//! An access token is a signed assertion because it must be verifiable without I/O. A refresh token
//! is the opposite: it is presented rarely, it must be revocable *immediately*, and it therefore
//! has to be looked up. Making it 256 bits of randomness with no structure means there is nothing
//! in it to forge, nothing to parse, and nothing an attacker learns from holding one.
//!
//! # Why only a hash is stored
//!
//! `refresh_tokens.token_hash` holds SHA-256 of the token, never the token. A database backup, a
//! replica, or a `SELECT` in a support query then contains no usable credential. SHA-256 rather
//! than Argon2 because the input is 256 bits of uniform randomness — there is no dictionary to
//! attack, so a slow hash would buy nothing and would put a 64 MiB allocation on the refresh path.
//!
//! # Rotation is the whole design
//!
//! Every successful refresh consumes the presented token and issues its successor. That turns a
//! stolen refresh token from a silent, indefinite compromise into a detectable one: either the
//! victim or the thief uses the consumed token next, and whichever it is,
//! [`RefreshOutcome::Replay`] follows. This is K3 and K4.

use core::fmt;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use enclave_core::{Actor, ClientType, DeviceId, SessionId, TenantId};
use rand::rand_core::TryRng as _;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AuthError;

/// Length of a refresh token's entropy, in bytes. 256 bits, per `docs/03-LLD.md §5.1`.
pub const REFRESH_TOKEN_BYTES: usize = 32;

/// Why a token or family was revoked. The strings match `refresh_tokens.revoke_reason` and
/// `token_revocations.reason`.
///
/// A closed enumeration because these values are read by incident response and by the sessions
/// list in the UI; free text would mean the difference between a user logging out and a detected
/// theft being a matter of spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevokeReason {
    /// The user logged out of this session.
    Logout,
    /// The user, or an administrator, ended every session.
    LogoutAll,
    /// A consumed refresh token was presented again (K4). The only reason that is also an
    /// incident.
    SessionReplay,
    /// An administrator revoked the session.
    AdminRevoke,
    /// The password changed.
    PasswordChange,
    /// An MFA method was reset or removed.
    MfaReset,
    /// The bound device was revoked or wiped.
    DeviceRevoked,
    /// The account was disabled or offboarded.
    Offboarded,
    /// Conditional access or a role change withdrew the session's basis.
    PolicyChange,
}

impl RevokeReason {
    /// Whether this revocation is evidence of an attack rather than an ordinary lifecycle event.
    ///
    /// Drives whether an incident is raised and the user notified (`docs/03-LLD.md §5.3` rule 2).
    #[must_use]
    pub const fn is_security_incident(self) -> bool {
        matches!(self, Self::SessionReplay)
    }
}

/// A refresh token's secret value.
///
/// Holds the plaintext, which is why [`fmt::Debug`] is written by hand and the inner buffer is
/// [`Zeroizing`]: this type exists for the few microseconds between generating a token and putting
/// it in a `Set-Cookie` header, and it must not survive a `{:?}` into a log or a core dump.
///
/// Equality is not implemented. Comparing two refresh tokens is never the right operation —
/// comparison happens on [`RefreshTokenDigest`], in constant time, against the store.
pub struct RefreshToken(Zeroizing<String>);

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshToken(<redacted>)")
    }
}

impl RefreshToken {
    /// Mints 256 bits from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`AuthError::EntropyUnavailable`] if the OS declines to provide randomness. rand 0.10 made
    /// this fallible, and propagating it is right: a refresh token minted from a degraded entropy
    /// source is worse than no token at all, and the alternative — unwrapping — would abort the
    /// process on a condition a caller can report and retry.
    pub fn generate() -> Result<Self, AuthError> {
        let mut bytes = Zeroizing::new([0_u8; REFRESH_TOKEN_BYTES]);
        SysRng.try_fill_bytes(bytes.as_mut_slice()).map_err(|_| AuthError::EntropyUnavailable)?;
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()))))
    }

    /// Accepts a token presented by a client.
    ///
    /// The length check is a cheap filter, not a security control — a wrong-length value would miss
    /// in the store anyway — but it keeps obviously malformed input from reaching a database
    /// lookup on an unauthenticated endpoint.
    ///
    /// # Errors
    ///
    /// [`AuthError::RefreshRejected`], the same error a genuinely unknown token produces, so that
    /// a malformed token and an unknown one are indistinguishable.
    pub fn parse(presented: &str) -> Result<Self, AuthError> {
        let decoded = URL_SAFE_NO_PAD.decode(presented).map_err(|_| AuthError::RefreshRejected)?;
        if decoded.len() != REFRESH_TOKEN_BYTES {
            return Err(AuthError::RefreshRejected);
        }
        Ok(Self(Zeroizing::new(presented.to_owned())))
    }

    /// The value to put in the cookie or the native keystore.
    ///
    /// Named `expose` rather than `as_str` so that every place the plaintext escapes is greppable.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value stored in `refresh_tokens.token_hash`.
    #[must_use]
    pub fn digest(&self) -> RefreshTokenDigest {
        RefreshTokenDigest(Sha256::digest(self.0.as_bytes()).into())
    }
}

/// SHA-256 of a refresh token: what the database holds, and the only form ever compared.
#[derive(Clone, Copy)]
pub struct RefreshTokenDigest([u8; 32]);

impl fmt::Debug for RefreshTokenDigest {
    /// The digest is not a credential, but printing it in full invites someone to paste it into a
    /// bug report and then into a `WHERE` clause. Eight hex characters is enough to correlate.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefreshTokenDigest({}…)", &self.to_hex()[..8])
    }
}

impl PartialEq for RefreshTokenDigest {
    /// Constant time. A digest comparison that short-circuits leaks, byte by byte, how much of a
    /// guess was right — which over enough attempts reconstructs a stored digest.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for RefreshTokenDigest {}

impl RefreshTokenDigest {
    /// Lowercase hex, as stored in `refresh_tokens.token_hash`.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            // Two hex digits per byte; `write!` to a String cannot fail.
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One row of `refresh_tokens` (`docs/04-DATA-MODEL.md §6`).
///
/// Carries the plaintext of nothing: `token_hash` is the digest, and the token itself only ever
/// exists in a [`RefreshToken`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// Row identity, and the `parent_id` a successor points at.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Family id — the `sid` claim. Constant across every rotation in one login session.
    pub session_id: SessionId,
    /// The principal this family belongs to.
    pub actor: Actor,
    /// Hex SHA-256 of the token.
    pub token_hash: String,
    /// Bound device, where the client has one. A refresh presented with a different device is
    /// rejected (`docs/03-LLD.md §5.3` rule 4).
    pub device_id: Option<DeviceId>,
    /// The client type this family was issued to.
    pub client: ClientType,
    /// The row this one replaced, forming the rotation chain.
    pub parent_id: Option<Uuid>,
    /// When this token was issued.
    pub issued_at: DateTime<Utc>,
    /// Sliding expiry; moves forward on each rotation.
    pub expires_at: DateTime<Utc>,
    /// Hard expiry from the original authentication; never moves.
    pub absolute_expires_at: DateTime<Utc>,
    /// When this token was consumed by a rotation. A second presentation after this is set is
    /// theft.
    pub consumed_at: Option<DateTime<Utc>>,
    /// When this token was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Why it was revoked.
    pub revoke_reason: Option<RevokeReason>,
}

impl RefreshRecord {
    /// Whether this token may still be exchanged at `now`.
    ///
    /// Both expiries are checked. The sliding one alone would let a family live forever through
    /// continuous refresh; the absolute one alone would let an abandoned session stay usable for
    /// ninety days.
    #[must_use]
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none()
            && self.revoked_at.is_none()
            && now < self.expires_at
            && now < self.absolute_expires_at
    }
}

/// Persistence for refresh families.
///
/// The atomicity requirement is in [`RefreshTokenStore::rotate`] and it is not negotiable: a
/// rotation that consumes the old token without recording the new one logs the user out, and one
/// that records the new token without consuming the old one leaves two valid tokens in a family —
/// which is exactly the state reuse detection is supposed to be able to rule out.
#[async_trait]
pub trait RefreshTokenStore: Send + Sync + fmt::Debug {
    /// Records the first token of a new family.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn insert(&self, record: RefreshRecord) -> Result<(), AuthError>;

    /// Looks a token up by its digest.
    ///
    /// Returns consumed and revoked rows too — the caller must see them, because a consumed row is
    /// the signal for K4 and a `None` there would silently downgrade a detected theft to an
    /// ordinary rejection.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshRecord>, AuthError>;

    /// Consumes `presented_id` and inserts `successor`, **in one transaction**.
    ///
    /// # Errors
    ///
    /// Storage failures, or [`AuthError::RefreshRejected`] if the presented row was consumed or
    /// revoked between the lookup and this call — the store is the serialisation point, so two
    /// concurrent refreshes of the same token must not both succeed.
    async fn rotate(
        &self,
        presented_id: Uuid,
        successor: RefreshRecord,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;

    /// Revokes every token in a family, returning the rows that were still outstanding.
    ///
    /// The return value is what lets the caller denylist the access tokens those rows correspond
    /// to; a `()` return would make the family revocation complete and the access tokens still
    /// valid for up to ten minutes.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn revoke_family(
        &self,
        session_id: SessionId,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError>;

    /// Revokes every family belonging to one subject.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn revoke_all_for_subject(
        &self,
        subject: Uuid,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError>;
}

/// What a presented refresh token turned out to be.
///
/// An enum rather than `Result<RefreshRecord, _>` because "this is a replay" is not an error
/// condition to be propagated and forgotten — it obliges the caller to revoke the family, denylist
/// the outstanding access tokens and raise an incident. Making it a variant of the success type
/// forces every caller to write that branch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a replay verdict obliges the caller to revoke the family"]
pub enum RefreshOutcome {
    /// The token is live and may be rotated.
    Usable(Box<RefreshRecord>),
    /// The token was already consumed. **K4**: a copy exists somewhere it should not.
    Replay(Box<RefreshRecord>),
    /// Unknown, revoked or expired. Nothing follows from it beyond a refusal.
    Rejected,
}

/// Classifies a presented token against its stored row.
///
/// Pure, and separate from the service that acts on it, so that the classification — the part that
/// decides whether a session is destroyed — can be tested without a store, a clock or a key.
pub fn classify(record: Option<RefreshRecord>, now: DateTime<Utc>) -> RefreshOutcome {
    let Some(record) = record else {
        return RefreshOutcome::Rejected;
    };
    // Order matters. Consumption is checked before expiry: a stolen token replayed after it
    // expired is still evidence of theft, and treating it as a plain expiry would discard the one
    // signal that a compromise happened.
    if record.consumed_at.is_some() {
        return RefreshOutcome::Replay(Box::new(record));
    }
    if record.revoked_at.is_some() || !record.is_usable_at(now) {
        return RefreshOutcome::Rejected;
    }
    RefreshOutcome::Usable(Box::new(record))
}

/// An in-memory [`RefreshTokenStore`], for tests and for the development stack.
///
/// Not a substitute for the PostgreSQL implementation: `rotate` here is atomic because a `Mutex`
/// makes it so, which proves nothing about the transaction the real store must use. It exists so
/// that the rotation and reuse-detection *logic* — the part that is easy to get wrong and hard to
/// see going wrong — can be tested without a database.
#[derive(Debug, Default)]
pub struct InMemoryRefreshStore {
    rows: std::sync::Mutex<Vec<RefreshRecord>>,
}

impl InMemoryRefreshStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every row, for assertions.
    ///
    /// # Panics
    ///
    /// If the lock was poisoned by a panic in another test.
    #[must_use]
    pub fn rows(&self) -> Vec<RefreshRecord> {
        #[allow(clippy::expect_used)]
        self.rows.lock().expect("in-memory store lock poisoned").clone()
    }
}

#[async_trait]
impl RefreshTokenStore for InMemoryRefreshStore {
    async fn insert(&self, record: RefreshRecord) -> Result<(), AuthError> {
        let mut rows = self.rows.lock().map_err(|_| AuthError::RefreshRejected)?;
        rows.push(record);
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshRecord>, AuthError> {
        let rows = self.rows.lock().map_err(|_| AuthError::RefreshRejected)?;
        Ok(rows.iter().find(|r| r.token_hash == token_hash).cloned())
    }

    async fn rotate(
        &self,
        presented_id: Uuid,
        successor: RefreshRecord,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut rows = self.rows.lock().map_err(|_| AuthError::RefreshRejected)?;
        let presented =
            rows.iter_mut().find(|r| r.id == presented_id).ok_or(AuthError::RefreshRejected)?;
        // Re-check under the lock. This is the in-memory stand-in for the real store's
        // `UPDATE ... WHERE consumed_at IS NULL`, and without it two concurrent refreshes of the
        // same token would both be granted.
        if presented.consumed_at.is_some() || presented.revoked_at.is_some() {
            return Err(AuthError::RefreshRejected);
        }
        presented.consumed_at = Some(now);
        rows.push(successor);
        Ok(())
    }

    async fn revoke_family(
        &self,
        session_id: SessionId,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError> {
        let mut rows = self.rows.lock().map_err(|_| AuthError::RefreshRejected)?;
        let mut affected = Vec::new();
        for row in rows.iter_mut().filter(|r| r.session_id == session_id) {
            if row.revoked_at.is_none() {
                row.revoked_at = Some(now);
                row.revoke_reason = Some(reason);
                affected.push(row.clone());
            }
        }
        Ok(affected)
    }

    async fn revoke_all_for_subject(
        &self,
        subject: Uuid,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError> {
        let mut rows = self.rows.lock().map_err(|_| AuthError::RefreshRejected)?;
        let mut affected = Vec::new();
        for row in rows.iter_mut().filter(|r| r.actor.subject_id() == Some(subject)) {
            if row.revoked_at.is_none() {
                row.revoked_at = Some(now);
                row.revoke_reason = Some(reason);
                affected.push(row.clone());
            }
        }
        Ok(affected)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use chrono::Duration;
    use enclave_core::UserId;

    fn record(now: DateTime<Utc>, token: &RefreshToken) -> RefreshRecord {
        RefreshRecord {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new_v7(),
            session_id: SessionId::new_v7(),
            actor: Actor::User(UserId::new_v7()),
            token_hash: token.digest().to_hex(),
            device_id: None,
            client: ClientType::Web,
            parent_id: None,
            issued_at: now,
            expires_at: now + Duration::days(14),
            absolute_expires_at: now + Duration::days(90),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
        }
    }

    #[test]
    fn a_generated_token_carries_256_bits_and_is_unpredictable() {
        let a = RefreshToken::generate().expect("entropy");
        let b = RefreshToken::generate().expect("entropy");
        assert_ne!(a.expose(), b.expose());
        assert_eq!(URL_SAFE_NO_PAD.decode(a.expose()).expect("base64").len(), REFRESH_TOKEN_BYTES);
        // Round-trips through the parser a client's value takes.
        assert_eq!(RefreshToken::parse(a.expose()).expect("parse").digest(), a.digest());
    }

    #[test]
    fn plaintext_never_appears_in_debug_output() {
        let token = RefreshToken::generate().expect("entropy");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "RefreshToken(<redacted>)");
        assert!(!rendered.contains(token.expose()));

        let digest = format!("{:?}", token.digest());
        assert!(!digest.contains(&token.digest().to_hex()), "the full digest must not be printed");
    }

    #[test]
    fn a_malformed_token_is_rejected_exactly_like_an_unknown_one() {
        for bad in ["", "short", "!!!not base64!!!", &"A".repeat(64)] {
            assert!(matches!(RefreshToken::parse(bad), Err(AuthError::RefreshRejected)));
        }
    }

    #[test]
    fn the_digest_is_sha256_of_the_token_text() {
        let token = RefreshToken::generate().expect("entropy");
        let expected: [u8; 32] = Sha256::digest(token.expose().as_bytes()).into();
        assert_eq!(token.digest().as_bytes(), &expected);
        assert_eq!(token.digest().to_hex().len(), 64);
    }

    #[test]
    fn classification_puts_replay_ahead_of_expiry() {
        let now = Utc::now();
        let token = RefreshToken::generate().expect("entropy");

        let live = record(now, &token);
        assert!(matches!(classify(Some(live), now), RefreshOutcome::Usable(_)));

        // Consumed *and* long expired: still a replay, because the evidence of theft matters more
        // than the fact that the stolen token would have been refused anyway.
        let mut stale_and_consumed = record(now, &token);
        stale_and_consumed.consumed_at = Some(now);
        assert!(matches!(
            classify(Some(stale_and_consumed), now + Duration::days(365)),
            RefreshOutcome::Replay(_)
        ));

        let mut revoked = record(now, &token);
        revoked.revoked_at = Some(now);
        assert_eq!(classify(Some(revoked), now), RefreshOutcome::Rejected);

        assert_eq!(classify(None, now), RefreshOutcome::Rejected);
    }

    #[test]
    fn the_absolute_expiry_outranks_the_sliding_one() {
        let now = Utc::now();
        let token = RefreshToken::generate().expect("entropy");
        let mut row = record(now, &token);
        // A family that has been refreshed right up to its ninetieth day: the sliding window says
        // yes, the absolute ceiling says no.
        row.expires_at = now + Duration::days(14);
        row.absolute_expires_at = now - Duration::seconds(1);
        assert!(!row.is_usable_at(now));
    }

    #[tokio::test]
    async fn k3_rotation_consumes_the_presented_token() {
        let now = Utc::now();
        let store = InMemoryRefreshStore::new();
        let first = RefreshToken::generate().expect("entropy");
        let original = record(now, &first);
        store.insert(original.clone()).await.expect("insert");

        let second = RefreshToken::generate().expect("entropy");
        let mut successor = record(now, &second);
        successor.session_id = original.session_id;
        successor.parent_id = Some(original.id);
        store.rotate(original.id, successor.clone(), now).await.expect("rotate");

        let presented_again = store.find_by_hash(&first.digest().to_hex()).await.expect("lookup");
        assert!(
            presented_again.as_ref().and_then(|r| r.consumed_at).is_some(),
            "K3: the presented token must be consumed"
        );
        assert_eq!(
            classify(presented_again, now),
            RefreshOutcome::Replay(Box::new(RefreshRecord {
                consumed_at: Some(now),
                ..original.clone()
            })),
            "K3: re-presenting it is a replay, not a success"
        );

        // ...and the successor is live.
        let successor_row = store.find_by_hash(&second.digest().to_hex()).await.expect("lookup");
        assert!(matches!(classify(successor_row, now), RefreshOutcome::Usable(_)));
    }

    #[tokio::test]
    async fn k3_a_consumed_token_cannot_be_rotated_a_second_time() {
        let now = Utc::now();
        let store = InMemoryRefreshStore::new();
        let first = RefreshToken::generate().expect("entropy");
        let original = record(now, &first);
        store.insert(original.clone()).await.expect("insert");

        let successor = record(now, &RefreshToken::generate().expect("entropy"));
        store.rotate(original.id, successor, now).await.expect("first rotation");

        // The store itself is the serialisation point; a racing second rotation must lose.
        let racer = record(now, &RefreshToken::generate().expect("entropy"));
        assert!(matches!(
            store.rotate(original.id, racer, now).await,
            Err(AuthError::RefreshRejected)
        ));
    }

    #[tokio::test]
    async fn k4_revoking_a_family_leaves_no_usable_token_in_it() {
        let now = Utc::now();
        let store = InMemoryRefreshStore::new();
        let first = RefreshToken::generate().expect("entropy");
        let original = record(now, &first);
        store.insert(original.clone()).await.expect("insert");

        let second = RefreshToken::generate().expect("entropy");
        let mut successor = record(now, &second);
        successor.session_id = original.session_id;
        store.rotate(original.id, successor, now).await.expect("rotate");

        let affected = store
            .revoke_family(original.session_id, RevokeReason::SessionReplay, now)
            .await
            .expect("revoke");
        assert_eq!(affected.len(), 2, "both the consumed token and its successor are revoked");
        assert!(affected.iter().all(|r| r.revoke_reason == Some(RevokeReason::SessionReplay)));

        // Nothing in the family is usable any more. The already-consumed token still classifies as
        // a replay rather than a plain rejection, and that is right: revoking a family does not
        // erase the evidence that a copy of that token exists.
        for hash in [first.digest().to_hex(), second.digest().to_hex()] {
            let row = store.find_by_hash(&hash).await.expect("lookup");
            assert!(
                !matches!(classify(row, now), RefreshOutcome::Usable(_)),
                "no token in a revoked family may be exchanged"
            );
        }
        let revoked_successor =
            store.find_by_hash(&second.digest().to_hex()).await.expect("lookup");
        assert_eq!(classify(revoked_successor, now), RefreshOutcome::Rejected);
    }

    #[test]
    fn only_replay_is_treated_as_a_security_incident() {
        assert!(RevokeReason::SessionReplay.is_security_incident());
        for ordinary in [
            RevokeReason::Logout,
            RevokeReason::LogoutAll,
            RevokeReason::AdminRevoke,
            RevokeReason::PasswordChange,
            RevokeReason::MfaReset,
            RevokeReason::DeviceRevoked,
            RevokeReason::Offboarded,
            RevokeReason::PolicyChange,
        ] {
            assert!(!ordinary.is_security_incident());
        }
    }
}
