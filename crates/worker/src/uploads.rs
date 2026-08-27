//! The upload reaper: the standing sweep that releases staged bytes nothing will ever read.
//!
//! `ENC-806`. [`enclave_uploads::reap_expired`] has existed since M1 with a full test suite and
//! **no production caller** — `crates/scheduler` runs storage reconciliation and nothing else, and
//! the worker's six passes were indexing, antivirus, content-scan, invalidation, epoch and
//! coverage. So every abandoned `CREATED`/`UPLOADING` session in every running deployment kept its
//! staged object indefinitely, and `docs/03-LLD.md §15`'s promise that orphaned staged objects are
//! reaped after `upload.session_ttl` was not true of anything that shipped. This module is the
//! caller. It is the tenth instance in this repository of complete, tested code that nothing ran.
//!
//! # Why this pass lives in `crates/worker` and not in `crates/scheduler`
//!
//! `crates/scheduler` is described as the home for periodic work and it owns the nightly quota
//! reconciliation, so it is the obvious answer. It is the wrong one, and the reason is not
//! convenience — it is that a *destructive* sweep needs five mechanisms, and four of them exist
//! here and none of them there.
//!
//! 1. **A verified object store.** The sweep deletes objects, so it needs a [`BlobStore`].
//!    `crates/worker/src/main.rs::object_store` composes one with `connect_and_verify`, so an
//!    unreachable or publicly-readable bucket refuses the start-up. The scheduler binary reads no
//!    `storage:` section at all; putting the sweep there means a *third* copy of that composition
//!    (after `crates/api` and here) whose only purpose is to be kept in step with the other two.
//! 2. **A tenant enumerator.** Every statement runs inside a `TenantScoped` transaction, so
//!    something has to produce the list, and the query that produces one cannot itself be
//!    tenant-scoped. [`crate::tenants::DbTenants`] is that adapter and the scheduler has no
//!    equivalent: its one pass enumerates *inside* `enclave_db::reconcile_storage`, so its binary
//!    holds a platform credential and no [`TenantSource`](crate::schedule::TenantSource).
//! 3. **A per-tenant loop with per-tenant failure isolation.** One tenant whose bucket is
//!    unreachable must not stop every other tenant's bytes being released.
//!    `enclave_scheduler::run_passes` has no tenant loop; it is a single-shot nightly tick typed to
//!    `Result<StorageReconciliation, DbError>`.
//! 4. **"The batch was full, go again immediately."** [`ReapReport::is_full`] exists precisely
//!    because a claim is bounded and a backlog has to drain, which is
//!    [`Tick::Progressed`](crate::schedule::Tick). `run_passes` has one interval and no notion of a
//!    tick that should not wait.
//! 5. **Deny-by-default, announced.** This is the decisive one. A sweep that deletes objects must
//!    not be scheduled when its store is absent, and — the whole lesson of `ENC-806` — that absence
//!    must be a line an operator *reads* rather than a graph that never left zero.
//!    [`Scheduler::scheduled`](crate::schedule::Scheduler::scheduled) is that mechanism and the
//!    binary logs it at start-up. `crates/scheduler` runs its one loop unconditionally and reports
//!    nothing about what it is or is not doing, which is the shape that let this defect survive.
//!
//! Nothing in `docs/02-HLD.md §5` is bent by that: the worker's own charter there is "…LDAP sync,
//! webhook delivery, **cleanup**". `docs/03-LLD.md §15` did say "reaped by the scheduler"; that
//! sentence has been corrected to name the process that actually reaps, because a doc naming a
//! process that never had the code is how this went unnoticed for five milestones.
//!
//! # This module reasons about nothing
//!
//! It calls [`enclave_uploads::reap_expired`] and [`enclave_uploads::reclaim_stranded`] and it
//! contains no SQL, no state name and no predicate of its own. That is deliberate and it is
//! asserted by [`tests::the_pass_never_reasons_about_strandedness_itself`].
//!
//! **Reclaiming a committed session deletes a live file's only copy.** Since `ENC-691` the staged
//! key *is* the version's `object_key` — nothing is copied on commit — so a sweep that claimed a
//! session which did commit would delete the bytes and leave `file_versions` pointing at nothing.
//! `ENC-787` made that unrepresentable rather than checked: `StrandedSession` has exactly one
//! constructor, `UploadRepository::claim_stranded`, whose statement asserts `NOT EXISTS` a version
//! naming the staged key inside the same `FOR UPDATE` claim, and it is the only value from which
//! the `SCANNING` → `EXPIRED` transition is reachable. A second path here that asked the same
//! question its own way would be a second answer, and the day the two disagree a customer loses a
//! file. So there is no second path.
//!
//! # Two transactions, not one
//!
//! Each claim takes `FOR UPDATE SKIP LOCKED` and holds its rows until the transaction ends, and
//! every release is a network round trip to the object store. Running both claims in one
//! transaction would hold the first batch's locks across the second batch's I/O — twice the
//! lock-holding for no atomicity worth having, since the two claims touch disjoint sets of rows and
//! neither depends on the other's outcome. `crates/cli/src/reclaim.rs` splits them for the same
//! reason.
//!
//! # What "progress" means here, and why it is not "something was released"
//!
//! See [`released_a_full_batch`]. Both halves of that rule are load-bearing.

use chrono::{DateTime, Duration, Utc};
use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_storage::BlobStore;
use enclave_uploads::{ReapReport, ReclaimReport};

use crate::error::Result;

/// What one tenant's upload-reaping tick did, in both halves.
///
/// Two reports rather than a summed one. They are different facts about a deployment: the first is
/// ordinary housekeeping of uploads nobody finished, the second is a repair of sessions stranded in
/// `SCANNING` — which since `ENC-691` should be a historical backlog draining to zero and staying
/// there. A number that keeps moving in the second is a defect somewhere upstream, and summing them
/// is how it would be read as ordinary abandonment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use = "the counts are how an operator sees a store that is refusing deletes"]
pub struct ReapPass {
    /// Abandoned `CREATED`/`UPLOADING` sessions past their TTL.
    pub expired: ReapReport,
    /// Sessions stranded in `SCANNING` with no version behind them (`ENC-787`).
    pub stranded: ReclaimReport,
    /// The ceiling both claims were run with.
    ///
    /// Carried on the report rather than threaded to whoever reads it, because "was this batch
    /// full" is the only question the answer is used for and a batch size that travelled separately
    /// would be a second copy of a number — compared against a pass it might not have produced.
    pub batch: usize,
}

impl ReapPass {
    /// Sessions whose staged bytes were released and whose row is now `EXPIRED`.
    #[must_use]
    pub const fn released(&self) -> usize {
        self.expired.released + self.stranded.reclaimed
    }

    /// Sessions the object store or the row refused, left for the next pass.
    #[must_use]
    pub const fn deferred(&self) -> usize {
        self.expired.deferred + self.stranded.deferred
    }
}

/// Whether a tick did anything a second tick could build on.
///
/// A named function for the reason [`made_progress`](crate::schedule) and `av_progressed` are:
/// so the rule can be asserted directly instead of being restated by a test that then agrees with a
/// broken loop.
///
/// **Full, *and* something was actually released.** Neither half is decoration.
///
/// *Full* is the backlog signal: both claims are bounded by `batch`, and a claim that came back
/// full is a claim that has more waiting. Without it a deployment with ten thousand abandoned
/// sessions would release a hundred every idle interval and take a day to drain what it could
/// clear in a minute.
///
/// *Released* is the spin guard, and it is the one that is easy to leave out. A deferral is not an
/// error — a store refusing deletes leaves the rows claimable, on purpose, so the next pass tries
/// again — which means a full batch that deferred every single session still matches the same
/// predicate next tick. Counting that as progress turns an object-store outage into a loop
/// re-issuing the same hundred deletes at the speed of the network, forever. Idling instead makes
/// the retry one bounded attempt per interval, which is what the deferral was for.
#[must_use]
pub const fn released_a_full_batch(pass: &ReapPass) -> bool {
    (pass.expired.released > 0 && pass.expired.is_full(pass.batch))
        || (pass.stranded.reclaimed > 0 && pass.stranded.is_full(pass.batch))
}

/// Releases one tenant's unreferenced staged bytes: abandoned sessions, then stranded ones.
///
/// `now` and `grace` are parameters rather than read here, for the reason every other pass in this
/// crate takes its clock: a loop that read `Utc::now()` internally could not be asked what it does
/// at a boundary without waiting for one. `grace` is how long a session must have been claiming to
/// scan before it is a candidate — see [`enclave_uploads::reclaim_stranded`], and
/// `crates/worker/src/main.rs::STRANDED_GRACE` for why an unattended sweep chooses a longer one
/// than an operator's repair command does.
///
/// # Ordering
///
/// Expired first, stranded second, and the order is a preference rather than a requirement: the two
/// claims match disjoint states (`CREATED`/`UPLOADING` against `SCANNING`) so neither can see the
/// other's rows. Expired goes first because it is the pass with the backlog in every deployment
/// running today, and because it is the one that cannot destroy anything a caller could still be
/// referring to.
///
/// # Errors
///
/// [`WorkerError`](crate::WorkerError) if a claim, a transaction or a commit fails. A failure in
/// the first half is returned before the second half is attempted, and the first half's commit
/// stands: the releases it made were correct, and re-running is free because a released session no
/// longer matches either predicate.
///
/// Failures releasing an *individual* session are not errors — they are counted in the reports'
/// `deferred` fields, so one unreachable object does not strand the rest of the tenant's batch
/// behind it.
pub async fn reap_pass(
    pool: &DbPool,
    tenant: TenantId,
    blob: &dyn BlobStore,
    now: DateTime<Utc>,
    grace: Duration,
    batch: usize,
) -> Result<ReapPass> {
    let mut tx = pool.begin(tenant).await?;
    let expired = enclave_uploads::reap_expired(&mut tx, blob, tenant, now, batch).await?;
    tx.commit().await?;

    let mut tx = pool.begin(tenant).await?;
    let stranded =
        enclave_uploads::reclaim_stranded(&mut tx, blob, tenant, now, grace, batch).await?;
    tx.commit().await?;

    Ok(ReapPass { expired, stranded, batch })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn expired(claimed: usize, released: usize, deferred: usize) -> ReapPass {
        ReapPass {
            expired: ReapReport { claimed, released, deferred },
            stranded: ReclaimReport::default(),
            batch: 100,
        }
    }

    fn stranded(found: usize, reclaimed: usize, deferred: usize) -> ReapPass {
        ReapPass {
            expired: ReapReport::default(),
            stranded: ReclaimReport { found, reclaimed, deferred },
            batch: 100,
        }
    }

    /// A full batch that released something is progress; a full batch that released nothing is not.
    ///
    /// The second half is the assertion that matters. It is the difference between a store outage
    /// costing one attempt per interval and a store outage costing a loop that re-issues the whole
    /// batch of deletes as fast as the network will refuse them — see [`released_a_full_batch`].
    #[test]
    fn a_batch_is_progress_only_when_it_was_full_and_actually_released_something() {
        assert!(released_a_full_batch(&expired(100, 100, 0)));
        assert!(released_a_full_batch(&stranded(100, 100, 0)));

        // Full, and every one of them deferred: the store is refusing. Not progress.
        assert!(!released_a_full_batch(&expired(100, 0, 100)));
        assert!(!released_a_full_batch(&stranded(100, 0, 100)));

        // Released everything it found, and the batch was not full: nothing left to go round for.
        assert!(!released_a_full_batch(&expired(3, 3, 0)));
        assert!(!released_a_full_batch(&stranded(3, 3, 0)));

        // Nothing at all, which is the steady state of a healthy deployment.
        assert!(!released_a_full_batch(&ReapPass::default()));
    }

    /// A half-deferred full batch still counts, because the half that succeeded drained the queue.
    #[test]
    fn a_partly_deferred_full_batch_is_still_progress() {
        assert!(released_a_full_batch(&expired(100, 60, 40)));
    }

    /// This module must never ask, for itself, whether a session is stranded.
    ///
    /// `ENC-787` put that question in a type with exactly one constructor — `StrandedSession`, built
    /// only by the claim that asserts `NOT EXISTS` a `file_versions` row naming the staged key.
    /// Since `ENC-691` the staged key *is* the committed version's `object_key`, so a second path
    /// that reasoned about the same question and got it wrong would delete a live file's only copy.
    /// A second path that got it *right* today is no better: it is a second answer, kept in step by
    /// nobody.
    ///
    /// Asserted against this module's own source because the tempting version of this pass is the
    /// one that "just" adds a state check or a `LEFT JOIN` while it is here.
    #[test]
    fn the_pass_never_reasons_about_strandedness_itself() {
        let source = include_str!("uploads.rs");
        let (code, _doc) = source.split_at(source.find("use chrono::").expect("the imports"));
        let body = &source[code.len()..];
        let body = &body[..body.find("#[cfg(test)]").expect("the test module")];

        for forbidden in [
            "sqlx::query",
            "upload_sessions",
            "file_versions",
            "'SCANNING'",
            "object_key",
            "staged_key",
            "UploadRepository",
            "StrandedSession",
        ] {
            assert!(
                !body.contains(forbidden),
                "`{forbidden}` appears in the reaping pass: the question of whether a session is \
                 stranded has exactly one answer, and it is `UploadRepository::claim_stranded`"
            );
        }
    }

    /// The counts an operator reads are the sum of both halves and nothing else.
    #[test]
    fn a_pass_reports_both_halves() {
        let pass = ReapPass {
            expired: ReapReport { claimed: 5, released: 4, deferred: 1 },
            stranded: ReclaimReport { found: 3, reclaimed: 1, deferred: 2 },
            batch: 100,
        };
        assert_eq!(pass.released(), 5);
        assert_eq!(pass.deferred(), 3);
    }
}
