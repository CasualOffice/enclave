//! Redemption, and the download budget that has to hold under concurrency.
//!
//! `docs/12-TESTING.md §4.4` H3: *"`max_downloads` holds under 50 concurrent redemptions (exactly
//! N succeed)."* That row exists because this is the one part of sharing with a wrong answer that
//! passes every single-threaded test.
//!
//! # The wrong shape, written out so it is recognisable
//!
//! ```text
//! let link = find(token)?;                        // download_count = 9, max = 10
//! if link.download_count >= link.max_downloads {  // 9 < 10, so: fine
//!     return Err(Exhausted);
//! }
//! issue_signed_url()?;
//! increment(link.id)?;                            // download_count = 10
//! ```
//!
//! Fifty requests arriving together all read `9`, all conclude there is budget, and all issue a
//! URL. The counter ends at 59 and fifty people have the file. Nothing in that code is obviously
//! wrong, every test of it passes, and the failure needs concurrency to appear — which is why
//! `plans/M2-ACCESS-DELIVERY.md` splits this task from link creation rather than leaving it as a
//! detail of one.
//!
//! # The shape that works
//!
//! `docs/04-DATA-MODEL.md §11` specifies it, and [`REDEEM_SQL`] is it: the limit is in the `WHERE`
//! clause of the `UPDATE`, so the read and the write are one statement and PostgreSQL serialises
//! the contenders on the row lock. **A zero-row result is the refusal.** The `CHECK` constraint in
//! migration 0008 is a backstop that turns a mistake here into a failed transaction rather than an
//! over-issued download.
//!
//! # The counter is spent before the URL exists
//!
//! [`redeem`] must be called *before* a signed URL is minted, in the same transaction, and the
//! transaction committed only if both succeeded. Issuing first and decrementing after means a crash
//! between them leaves a URL in the world that the budget never paid for — and `docs/06 §5.1`'s
//! URLs outlive the request that made them.
//!
//! This is also why [`redeem`] takes a `&mut PgConnection` (D10) rather than a pool: it cannot be
//! called outside the caller's transaction, so it cannot be committed separately from the work it
//! authorises.

use chrono::{DateTime, Utc};
use enclave_core::TenantId;
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::{Result, SharingError};
use crate::model::{ShareEventKind, ShareLink};
use crate::repo;
use crate::token::ShareToken;

/// What a successful redemption yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    /// The link, so the caller can apply `permission` and `allow_download`.
    pub link: ShareLink,
    /// The download count **after** this redemption — the value the row now holds.
    ///
    /// Returned by the `UPDATE` rather than read back, because a second `SELECT` would report
    /// whatever a concurrent redemption had done by then. This number is this caller's, and it is
    /// what an audit row should record.
    pub download_count: i64,
}

/// Resolves a token and spends one unit of its download budget, atomically.
///
/// Call inside the transaction that issues the signed URL, and commit only if both succeed. See the
/// module documentation for why the ordering is not negotiable.
///
/// `now` is passed rather than read so that expiry is evaluated against the same instant as the
/// rest of the request, and so the tests can place a link either side of its expiry without
/// sleeping.
///
/// # Errors
///
/// [`SharingError::LinkUnusable`] for a token that is unknown, malformed, expired or revoked, and
/// [`SharingError::BudgetExhausted`] when the limit is reached. Both render as `404` at the API
/// edge — see [`crate::error`] for why the redeemer is told nothing that distinguishes them.
pub async fn redeem(
    conn: &mut PgConnection,
    token: &ShareToken,
    now: DateTime<Utc>,
) -> Result<Redemption> {
    // The lookup is by digest and is not tenant-scoped, because redemption arrives with a token and
    // nothing else — establishing the tenant is what redeeming *does*. `uq_share_token` is global
    // for the same reason. Everything after this point runs tenant-scoped.
    let link =
        repo::find_by_digest(conn, token.digest()).await?.ok_or(SharingError::LinkUnusable)?;

    if !link.is_live(now) {
        return Err(SharingError::LinkUnusable);
    }

    let spent: Option<i64> = sqlx::query(REDEEM_SQL)
        .bind(link.tenant_id.as_uuid())
        .bind(link.id)
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?
        .map(|row| row.try_get("download_count"))
        .transpose()
        .map_err(|_| SharingError::MalformedRow {
            column: "download_count",
            reason: "missing or of an unexpected type",
        })?;

    // Zero rows is the refusal. Not an error condition to investigate — the ordinary answer when
    // the budget is spent, and the only one that is correct under concurrency.
    let Some(download_count) = spent else {
        return Err(SharingError::BudgetExhausted);
    };

    Ok(Redemption { link, download_count })
}

/// Records what a link did, including what it refused.
///
/// Separate from [`redeem`] so that the refusal paths can record too: an `AUTH_FAILED` or `BLOCKED`
/// row is the evidence that somebody probed a link, and a design where only successes are recorded
/// is one where the interesting traffic is invisible.
///
/// # Errors
///
/// Storage failures.
pub async fn record_event(
    conn: &mut PgConnection,
    tenant: TenantId,
    share_link_id: Uuid,
    event: ShareEventKind,
    context: EventContext<'_>,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(RECORD_EVENT_SQL)
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(share_link_id)
        .bind(event.as_str())
        // Bound as text and cast to `INET` in the statement, the way
        // `enclave_audit::sink` does — so this crate needs no INET-typed binding and the
        // two places that record a client address agree on the representation.
        .bind(context.ip.map(|ip| ip.to_string()))
        .bind(context.country)
        .bind(context.user_agent)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Where a redemption came from.
///
/// Every field is optional because every field is absent in some legitimate deployment — behind a
/// proxy that strips them, in a test, from a client that sends no user agent. A required field here
/// would mean inventing a value, and an invented country in a security event is worse than none.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventContext<'a> {
    /// The client address, after trusted-proxy resolution (`docs/06 §7`).
    pub ip: Option<std::net::IpAddr>,
    /// Two-letter country, if geo-IP resolved one.
    pub country: Option<&'a str>,
    /// The user agent as presented. Untrusted, recorded verbatim, never parsed for a decision.
    pub user_agent: Option<&'a str>,
}

/// The atomic decrement. `docs/04-DATA-MODEL.md §11` gives this statement; it is not paraphrased.
///
/// Three things are load-bearing:
///
/// 1. **The limit is in the `WHERE` clause.** That is what makes the read and the write one
///    operation, and what makes fifty concurrent callers serialise on the row lock instead of all
///    observing the same stale count.
/// 2. **`RETURNING` gives this caller's number.** A `SELECT` afterwards would report whatever a
///    concurrent redemption had reached by then.
/// 3. **Liveness is re-checked here**, not only in Rust. The Rust check gives the right error for
///    an expired link; this one closes the window between that check and this statement, in which a
///    concurrent revocation could land. Without it, revoking a link would not stop a redemption
///    already in flight — which is `docs/12 §4.4` H4, *"including for an already-open session"*.
const REDEEM_SQL: &str = "
UPDATE share_links
   SET download_count = download_count + 1
 WHERE tenant_id = $1
   AND id = $2
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > $3)
   AND (max_downloads IS NULL OR download_count < max_downloads)
 RETURNING download_count
";

const RECORD_EVENT_SQL: &str = "
INSERT INTO share_link_events
    (id, tenant_id, share_link_id, event, ip, country, user_agent, occurred_at)
VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8)
";
