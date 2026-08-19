//! The invalidation sweep: deleting suppressions that have already stopped suppressing.
//!
//! # What makes a suppression safely liftable
//!
//! Exactly one thing: **the search path already treats it as lifted.**
//!
//! `enclave_search::denylist::suppressed` — the query every search runs — keeps a row only while
//! `clears_at IS NULL OR clears_at > now()`. A row whose `clears_at` has passed is therefore not
//! suppressing anything before the sweep arrives and not suppressing anything after it leaves, and
//! deleting it changes nothing a caller can observe. That is the entire safety argument, and it is
//! also why this sweep can be stopped, resumed, run twice or never run at all.
//!
//! The dangerous version of this module is the one that decides for itself when a suppression has
//! served its purpose. Lifting a row that is still in force would resurface a file that the index
//! still holds under permissions that have changed — the one thing `plans/M3-DISCOVERY.md` D22 buys
//! with the in-transaction denylist write, given away by housekeeping.
//!
//! # The clock is the database's, and this is not a detail
//!
//! `suppressed` judges expiry against PostgreSQL's `now()`, because it runs inside the search's own
//! transaction. `lift_expired` originally took a timestamp from its *caller*, and those are two
//! different clocks: a worker running a few seconds ahead of the database would delete rows the
//! database still considered in force, and the file it was suppressing becomes findable early. The
//! window is small, silent, and exactly the correctness cost this loop is supposed to be incapable
//! of.
//!
//! That parameter is now gone from `lift_expired` itself: the `DELETE` compares `clears_at` against
//! `now()` in the same statement, so both predicates ask one clock the same question and the hazard
//! is not available to the next caller either. This loop reads no clock at all — which is the
//! strongest form of the property, because there is nothing left here to pass wrongly.
//!
//! # What today's schema cannot express
//!
//! `migrations/0011_search.sql` describes `clears_at` as "when the suppression may be lifted, **once
//! the index is known to have caught up**". Nothing in the schema can answer that second half, and
//! this module does not pretend otherwise:
//!
//! - a denylist row carries no reference to the index write that would satisfy it — no chunk
//!   generation, no manifest key, no epoch;
//! - `index_manifests.acl_epoch` is about a *rewrite* of a document's ACL tokens, not about the
//!   removal of a document from the vector store, which is what a revocation actually needs
//!   confirmed;
//! - a suppressed file may have no manifest row at all (never indexed, or already purged), so a
//!   join against manifests would answer "caught up" and "never existed" identically;
//! - a `NULL clears_at` — the schema's "not yet", and its safe default — is the case where nobody
//!   has yet asserted that the index is caught up. It is not the sweep's to guess.
//!
//! Any of those could be dressed up as a proxy. The result would be a mechanism named "the index
//! has caught up" that means something weaker, which is worse than not having it: the next reader
//! would use it to justify lifting a suppression the schema never said was liftable. `ENC-512`-class
//! surprises come from exactly that. The sweep therefore lifts on expiry alone, and the missing
//! signal is written down here rather than invented.
//!
//! # Concurrency and interruption
//!
//! One transaction per tenant, guarded by a **transaction-scoped advisory lock** on the tenant
//! ([`tenant_lock_key`]), taken with `pg_try_advisory_xact_lock`. Two sweeps in one deployment
//! therefore never meet inside a tenant's delete: the second is told so immediately
//! ([`TenantSweep::Contended`]) and moves to the next tenant instead of queueing behind row locks
//! it might deadlock against. The `_xact_` form releases at commit *or rollback*, including when
//! the process is killed mid-sweep, so a stopped worker leaks no lock — unlike a session lock,
//! which the outbox publisher has to unlock by hand on every path.
//!
//! Interruption needs no handling beyond that. A tenant is either swept or not; the rows of an
//! unswept tenant are expired rows that no search consults. "Correct, not merely eventually
//! correct" is the property, and it holds because expiry — not deletion — is what ends a
//! suppression.

use enclave_core::TenantId;
use enclave_db::DbPool;
use sqlx::PgConnection;
use tracing::debug;

use crate::error::Result;
use crate::Stop;

/// The advisory-lock class the sweep contends on, one per tenant.
///
/// Published rather than hidden for the reason `OUTBOX_PUBLISHER_LOCK_KEY` is: advisory-lock keys
/// share one namespace across the whole database, so every user of one has to be greppable. The
/// bytes spell `ENC` followed by a slot number.
///
/// The two-argument form of `pg_advisory_lock` occupies a different lock space from the
/// single-`bigint` form the outbox publisher uses, so these keys cannot collide with that one
/// however the numbers land.
pub const SWEEP_LOCK_CLASS: i32 = 0x454E_4302;

/// A stable 32-bit key for a tenant, for the second half of the advisory lock.
///
/// FNV-1a with its published constants, **not** [`std::collections::hash_map::DefaultHasher`]:
/// `RandomState` is seeded per process, so two worker replicas would compute different keys for the
/// same tenant and the lock would exclude nothing at all while looking exactly like it worked.
///
/// A collision between two tenants costs one skipped tenant on one pass, which the next pass picks
/// up. It cannot cost correctness — the lock only decides who does the deleting, never what may be
/// deleted.
#[must_use]
pub fn tenant_lock_key(tenant: TenantId) -> i32 {
    let mut hash: u32 = 0x811C_9DC5;
    for byte in tenant.as_uuid().into_bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash as i32
}

/// What one tenant's sweep did.
///
/// An enum rather than `Option<u64>` because "nobody swept this tenant" and "this tenant had
/// nothing to lift" are different facts about a deployment — one means two workers are contending,
/// the other means the denylist is in its steady state — and a `None` that means the first is read
/// as the second by whoever adds the metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSweep {
    /// The sweep held the tenant and lifted this many rows.
    Swept(u64),
    /// Another sweep held the tenant. Skipped without waiting; the holder is doing this work.
    Contended,
}

/// What one pass over a set of tenants did.
///
/// Returned rather than only logged so the scheduler, a health check or a test can assert on it —
/// and because a sweep that finds nothing must be distinguishable in metrics from a sweep that did
/// not run (`docs/12-TESTING.md`'s denylist-size exit criterion depends on the difference).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SweepOutcome {
    /// Tenants this pass held and swept.
    pub tenants_swept: usize,
    /// Tenants another sweep was already inside.
    pub tenants_contended: usize,
    /// Rows deleted, across every tenant this pass held.
    pub lifted: u64,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
}

/// Sweeps each tenant in turn, one transaction apiece, until the list ends or [`Stop`] is raised.
///
/// The tenant list is a parameter: see this crate's documentation for why housekeeping does not
/// enumerate tenants for itself.
///
/// Order is the caller's. Nothing here sorts or shuffles it, because the advisory lock — not a
/// consistent ordering — is what keeps two sweeps apart, and a caller that wants fairness across a
/// long list is better placed to decide what fair means.
///
/// # Errors
///
/// [`WorkerError`] from the first tenant that fails. Earlier tenants stay swept: each was its own
/// transaction, and rolling them back would undo work that was correct. The caller retries the
/// pass, which is free — every remaining row still matches.
pub async fn sweep(pool: &DbPool, tenants: &[TenantId], stop: &Stop) -> Result<SweepOutcome> {
    let mut outcome = SweepOutcome::default();

    for &tenant in tenants {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        match sweep_tenant(pool, tenant).await? {
            TenantSweep::Swept(lifted) => {
                outcome.tenants_swept += 1;
                outcome.lifted += lifted;
            }
            TenantSweep::Contended => outcome.tenants_contended += 1,
        }
    }

    debug!(
        swept = outcome.tenants_swept,
        contended = outcome.tenants_contended,
        lifted = outcome.lifted,
        stopped = outcome.stopped,
        "denylist sweep pass complete"
    );
    Ok(outcome)
}

/// Lifts one tenant's expired suppressions, in one transaction.
///
/// The whole tenant is one unit because [`enclave_search::lift_expired`] takes no bound, and
/// forking its statement to add a `LIMIT` would put a second copy of the expiry predicate in the
/// tree — the copy that eventually disagrees with the one every search reads. A tenant whose
/// denylist is large enough for that transaction to matter is a tenant whose *searches* are already
/// carrying that denylist on every query, so the bound belongs in `enclave-search` beside the
/// predicate, not here. Adding it needs a signature change to `lift_expired`, which this change
/// deliberately does not make.
///
/// # Errors
///
/// [`WorkerError`] if the lock probe, the clock read, the delete or the commit fails. A failure
/// rolls the transaction back, which lifts nothing and releases the lock.
pub async fn sweep_tenant(pool: &DbPool, tenant: TenantId) -> Result<TenantSweep> {
    let mut tx = pool.begin(tenant).await?;

    if !try_hold_tenant(&mut tx, tenant).await? {
        // Rolled back rather than dropped, so a failure to release the connection is reported here
        // instead of being swallowed by `Drop` on the way out.
        tx.rollback().await?;
        return Ok(TenantSweep::Contended);
    }

    let lifted = enclave_search::lift_expired(&mut tx, tenant).await?;
    tx.commit().await?;

    Ok(TenantSweep::Swept(lifted))
}

/// Tries to become the only sweep inside this tenant, without waiting.
///
/// `try` rather than the blocking form: a sweep that queued would hold a pooled connection for as
/// long as the other one keeps working, and the work is already being done by whoever holds the
/// lock. Returning immediately is both cheaper and self-correcting.
async fn try_hold_tenant(conn: &mut PgConnection, tenant: TenantId) -> Result<bool> {
    let (held,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(SWEEP_LOCK_CLASS)
        .bind(tenant_lock_key(tenant))
        .fetch_one(conn)
        .await?;
    Ok(held)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use uuid::Uuid;

    #[test]
    fn the_tenant_key_is_the_same_number_in_every_process() {
        // The property the lock rests on. A per-process seed — which is what `DefaultHasher` gives
        // you — would make two replicas take two different locks and exclude nothing, and the only
        // symptom would be two sweeps occasionally inside one tenant. Pinned against a literal so
        // that swapping the hash function has to be a deliberate edit to this line.
        let tenant = TenantId::from_uuid(
            Uuid::parse_str("0e11c1a1-0000-4000-8000-000000000001").expect("a fixed uuid"),
        );
        assert_eq!(tenant_lock_key(tenant), tenant_lock_key(tenant));
        assert_eq!(tenant_lock_key(tenant), -465_022_999);
    }

    #[test]
    fn different_tenants_get_different_keys() {
        let a = TenantId::new_v7();
        let b = TenantId::new_v7();
        assert_ne!(tenant_lock_key(a), tenant_lock_key(b));
    }

    #[test]
    fn a_contended_tenant_is_not_reported_as_a_quiet_one() {
        // The distinction `TenantSweep` exists for: a metric that folded these together would show
        // a healthy zero while two workers fought over every tenant.
        assert_ne!(TenantSweep::Contended, TenantSweep::Swept(0));
    }
}
