//! The epoch reconciler: finding index manifests whose ACL has moved on, and queueing a rebuild.
//!
//! `index_manifests.acl_epoch` records `files.acl_revision` as it stood when the index was last
//! written. A file whose `acl_revision` has since moved has stale `acl_tokens` in the vector store,
//! so the index will keep proposing it to callers who may no longer see it. This loop finds those
//! manifests and marks them `STALE`, which is what `idx_manifests_pending` — "what still needs
//! doing, oldest first" — puts in front of the indexer.
//!
//! # This is an efficiency mechanism. It is not a control.
//!
//! Say it plainly, because the failure mode is a reader who assumes the opposite. A stale
//! `acl_epoch` produces exactly one thing: an over-permissive candidate. That is the candidate
//! `docs/12-TESTING.md §4.3` S5 exists for, and `crates/search/src/postfilter.rs` drops it by
//! resolving against `acl_entries` every time, unconditionally, with no parameter that turns it off.
//! Staleness is *already safe*. What it costs is candidate slots: over-permissive proposals occupy
//! room in the over-fetch budget (`plans/M3-DISCOVERY.md` D21) and are thrown away, so a page comes
//! back short more often. Recall, not authorization.
//!
//! It follows that this loop can lag arbitrarily, be stopped for a week, or never run, and no
//! caller can observe a wrong answer — only a thinner one. If that ever stops being true, the
//! change that made it so is a defect in the *search* path, not a missing feature here.
//!
//! # How it is kept from quietly becoming load-bearing
//!
//! A reader who thinks this is a control will eventually make something depend on it, and the
//! moment that happens S4 keeps passing for the wrong reason. Three structural refusals, rather
//! than a comment asking people to be careful:
//!
//! 1. **No freshness oracle.** Nothing here answers "is this file's index current?" for one file.
//!    The public surface reports what this pass *changed* — counts and the ids it marked — which is
//!    useful to a scheduler and useless to a read path. A `fn is_fresh(file) -> bool` is the
//!    function a search would eventually call to skip work, and `postfilter.rs` explains at length
//!    why a post-filter conditional on such a signal is absent exactly when the signal is wrong.
//! 2. **It never writes `retrieval_denylist`.** Suppressing a stale-epoch file looks like a safety
//!    upgrade and is the opposite: it would make revocation's correctness appear to depend on this
//!    loop running, so S4 would pass because the reconciler ran rather than because the denylist
//!    write sits inside the ACL transaction (`plans/M3-DISCOVERY.md` D22). `tests/epoch.rs` asserts
//!    the denylist is untouched after a reconcile, so the "improvement" fails a test rather than
//!    passing review.
//! 3. **It writes one column of one table.** `status`, on `index_manifests`, which only the indexer
//!    reads.
//!
//! # Which manifests it marks, and which it deliberately leaves
//!
//! - **`READY` only.** Any other status is already in the indexer's queue, and stamping `STALE`
//!   over it would discard state the indexer owns: an in-flight `EMBEDDING` row would be restarted
//!   for no reason, and a `FAILED` row would be re-queued forever with its `attempts` budget — the
//!   only thing that quarantines a poisoned document — reset out from under it.
//! - **`acl_epoch <> acl_revision`, not `<`.** Equality is the only state that means "the index
//!   describes this ACL". An epoch *ahead* of the file's revision is as untrustworthy as one behind
//!   — it means somebody rewound a revision or a manifest was written from a read that no longer
//!   exists — and it converges on the next index write, because the writer stamps the revision it
//!   read. `<` would leave that row wrong forever while looking deliberate.
//! - **Trashed files are skipped.** Re-indexing a file with `deleted_at` set spends extraction and
//!   embedding budget on content that is on its way to being purged. Its removal from the index is
//!   deletion's job, not staleness's. This makes the loop do strictly *less* work, which is the
//!   only direction a pure efficiency mechanism may err in.
//!
//! # Concurrency and interruption
//!
//! Batches of manifest rows selected `FOR UPDATE … SKIP LOCKED`. Two reconcilers in one deployment
//! therefore *partition* the work rather than contending for it: a row locked by one is invisible
//! to the other, so no row is marked twice and — because a worker never waits for a row lock —
//! there is no wait-for cycle and a deadlock between them is not representable.
//!
//! The lock is taken `OF` the manifest rows only. Locking the joined `files` rows would make this
//! housekeeping loop block the ACL updates it exists to notice, which is the one interaction that
//! would make a slow reconciler visible to a user.
//!
//! No cursor and no claim column, because the predicate is self-consuming: a marked row is no
//! longer `READY`, so it cannot come back in the next batch. An interrupted run is a shorter run,
//! and what it leaves behind is what a run that had not started yet would leave behind — manifests
//! that are stale, findable, and dropped by the post-filter.

use enclave_core::{FileId, TenantId};
use enclave_db::DbPool;
use sqlx::Row as _;
use tracing::debug;
use uuid::Uuid;

use crate::error::{Result, WorkerError};
use crate::Stop;

/// How the reconciler paces itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcilerConfig {
    /// Manifests marked per transaction.
    ///
    /// Bounds two things at once: how long a batch holds row locks that a second reconciler has to
    /// skip past, and how much work a killed process discards. Neither is a correctness question —
    /// which is why this is a plain number rather than a tuned one.
    pub batch_size: u32,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self { batch_size: 200 }
    }
}

/// What one pass over a set of tenants did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconcileOutcome {
    /// Manifests moved to `STALE`.
    pub marked: u64,
    /// Transactions run, including the empty one that ends each tenant.
    pub batches: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
}

/// Reconciles each tenant in turn, in batches, until the list ends or [`Stop`] is raised.
///
/// The tenant list is a parameter: see this crate's documentation for why housekeeping does not
/// enumerate tenants for itself.
///
/// # Errors
///
/// [`WorkerError`] from the first batch that fails. Batches already committed stay committed —
/// each marked a set of manifests that genuinely are stale, and a retry re-selects whatever is
/// left.
pub async fn reconcile(
    pool: &DbPool,
    tenants: &[TenantId],
    config: ReconcilerConfig,
    stop: &Stop,
) -> Result<ReconcileOutcome> {
    let mut outcome = ReconcileOutcome::default();

    'tenants: for &tenant in tenants {
        loop {
            if stop.is_stopped() {
                outcome.stopped = true;
                break 'tenants;
            }

            let marked = reconcile_batch(pool, tenant, config.batch_size).await?;
            outcome.batches += 1;
            outcome.marked += marked.len() as u64;

            // A short batch means this tenant has nothing left that is *available* — either it is
            // reconciled, or the remainder is locked by another reconciler which is already
            // marking it. Both are reasons to move on rather than spin.
            if marked.len() < config.batch_size as usize {
                break;
            }
        }
    }

    debug!(
        marked = outcome.marked,
        batches = outcome.batches,
        stopped = outcome.stopped,
        "epoch reconcile pass complete"
    );
    Ok(outcome)
}

/// Marks up to `limit` of one tenant's stale manifests, in one transaction.
///
/// Returns the files it marked rather than a count. A count makes "it marked something" easy to
/// assert and "it marked the *right* something" impossible, and a reconciler that marks every
/// manifest on every pass — the plausible bug, one wrong join away — satisfies every count-shaped
/// assertion anyone would write.
///
/// # Errors
///
/// [`WorkerError`] if the statement or the commit fails.
pub async fn reconcile_batch(pool: &DbPool, tenant: TenantId, limit: u32) -> Result<Vec<FileId>> {
    let mut tx = pool.begin(tenant).await?;

    let rows = sqlx::query(MARK_STALE_SQL)
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;

    let marked = rows
        .iter()
        .map(|row| {
            row.try_get::<Uuid, _>("file_id").map(FileId::from).map_err(|_| {
                WorkerError::MalformedRow { column: "file_id", reason: "missing or not a uuid" }
            })
        })
        .collect::<Result<Vec<_>>>()?;

    tx.commit().await?;
    Ok(marked)
}

/// Manifests whose recorded epoch no longer matches the file's ACL revision, moved to `STALE`.
///
/// The tenant predicate is stated on both the update and the selection even though row-level
/// security already enforces it: the application predicate and RLS are two layers of the same
/// boundary (`docs/04-DATA-MODEL.md §3`), not one layer and a redundancy.
///
/// `FOR UPDATE OF c` — not `OF c, f` — so a long batch never blocks the ACL writes it is here to
/// notice. `SKIP LOCKED` is what lets a second reconciler take a disjoint set instead of waiting,
/// and it is the reason two of them cannot deadlock.
const MARK_STALE_SQL: &str = "
UPDATE index_manifests AS m
   SET status = 'STALE',
       updated_at = now()
 WHERE m.tenant_id = $1
   AND (m.tenant_id, m.file_id) IN (
       SELECT c.tenant_id, c.file_id
         FROM index_manifests AS c
         JOIN files AS f
           ON f.tenant_id = c.tenant_id AND f.id = c.file_id
        WHERE c.tenant_id = $1
          AND c.status = 'READY'
          AND c.acl_epoch <> f.acl_revision
          AND f.deleted_at IS NULL
        ORDER BY c.file_id
        LIMIT $2
        FOR UPDATE OF c SKIP LOCKED
   )
RETURNING m.file_id
";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_statement_never_marks_a_manifest_the_indexer_is_holding() {
        // Read as an assertion about the SQL because there is no other place to make it: the
        // status filter is one clause, deleting it passes every count-shaped test, and its absence
        // resets the `attempts` budget that quarantines a poisoned document.
        assert!(MARK_STALE_SQL.contains("c.status = 'READY'"));
        assert!(
            MARK_STALE_SQL.contains("SKIP LOCKED"),
            "two reconcilers must partition, not queue"
        );
        assert!(
            !MARK_STALE_SQL.contains("retrieval_denylist"),
            "a stale epoch is not a suppression; see this module's documentation"
        );
    }

    #[test]
    fn a_default_batch_is_bounded() {
        assert!(ReconcilerConfig::default().batch_size > 0);
    }
}
