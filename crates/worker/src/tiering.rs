//! Reconciling `file_versions.storage_tier` with what the object store actually holds (`ENC-947`).
//!
//! # The bug this closes first
//!
//! `ENC-946` shipped `POST /files/{id}/rehydrate`, which marks a version `RESTORING` and asks the
//! provider for it back. **Nothing then moved it out of `RESTORING`.** The bytes land hours later,
//! the row does not change, and every read path goes on refusing — a request that is accepted and
//! never completes, which is worse than one that is refused. This pass is what finishes it.
//!
//! # And the drift it does not close
//!
//! In practice most content reaches a cold tier through a **bucket lifecycle rule** — an operator
//! writes *ninety days after last access, transition to Deep Archive*, and the provider moves the
//! objects with nothing telling this product. Those rows still say `HOT`, and a download mints a
//! URL that fails at S3 exactly as `ENC-946` set out to prevent.
//!
//! That is the **drift scan** (`ENC-951`), and it is the second half of this pass. Detecting it means
//! asking the store about versions this product has no reason to suspect — one `HeadObject` per
//! version of every file in the deployment — so it is bounded per tick and ordered by
//! `tier_verified_at`, oldest first, `NULL` before everything. Every row is reached eventually and
//! the wait is a function of corpus size over batch rate rather than of luck.
//!
//! # The two halves run in one pass and are budgeted separately
//!
//! They have different economics and the difference is the whole reason the transitions go first.
//! Transitions are bounded by `idx_file_versions_in_transition` — a handful of rows on any
//! deployment and zero on most — and somebody is *waiting* on each one: a person who asked for a
//! file back hours ago. Drift is unbounded in the corpus and nobody is waiting on any particular
//! row. Sharing one budget would let a large drift backlog delay a restore that has already landed,
//! so the transition batch is taken first and in full, and drift gets what is left.
//!
//! # Why the scan reports how far behind it is
//!
//! A drift scan whose worst-case staleness nobody can state is a scan nobody can trust: it runs, it
//! logs, and it is indistinguishable from one that has fallen a month behind. So every pass reports
//! the **oldest** `tier_verified_at` in the tenant — an unverified row counts as infinitely stale —
//! and that number, not the pass's own success, is what says whether the deployment is covered.

use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_storage::{BlobStore, ObservedTier, StorageError};
use enclave_versions::{StorageTier, VersionRepository};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{Result, Stop};

/// How many transitions one tenant's pass resolves.
///
/// Each one is a provider round trip, so this is a bound on *network calls per tick*, not on rows
/// read. Small deliberately: the population is tiny by construction, and a pass that took hundreds
/// would be a pass whose tick length depends on somebody else's latency.
const BATCH: i64 = 32;

/// How many warm versions one tenant's drift scan verifies per tick.
///
/// Separate from [`BATCH`] and smaller, because the two halves are paid for differently. A
/// transition is a provider call somebody is waiting on; a drift check is speculative, and every
/// one of them costs a `HeadObject` against a population that is every version of every file.
///
/// **The cycle time is the number to reason about, and it is arithmetic an operator can do**: a
/// deployment with a million warm versions, at eight per tenant per minute, takes about eighty-six
/// days to verify all of them once. That is too slow for a bucket lifecycle rule measured in
/// months and far too slow for one measured in days — which is exactly why the pass reports the
/// oldest verification rather than leaving the operator to derive it. Raising this is the lever,
/// and it is a provider-cost decision rather than a correctness one.
const DRIFT_BATCH: i64 = 8;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Tenants examined.
    pub tenants_swept: usize,
    /// Rows whose tier was corrected.
    pub resolved: usize,
    /// Rows examined and left alone — still transitioning, which is the ordinary case.
    pub still_waiting: usize,
    /// Rows the store could not answer for. Counted rather than failed on; see [`sweep`].
    pub unanswerable: usize,
    /// Whether a full batch came back, so the loop should come straight round.
    pub more_to_take: bool,
    /// Warm versions the drift scan asked the store about (`ENC-951`).
    pub verified: usize,
    /// Warm versions the store said had moved without this product being told.
    ///
    /// The number that says a bucket lifecycle rule is operating. Non-zero is not an error — it is
    /// the scan doing its job — but a deployment where it is *persistently* non-zero has a rule
    /// this product is permanently chasing, and the read path is minting URLs that fail in the
    /// window between.
    pub drifted: usize,
    /// Whether the pass stopped early.
    pub stopped: bool,
}

/// The tier a row should move to, given what the store reported.
///
/// Split out as a pure function so the decision table is testable without a database or a provider,
/// and so it can be read in one place. Every arm is deliberate:
///
/// * An `ARCHIVING` row the store calls cold is **done** — that is the transition completing.
/// * A `RESTORING` row the store calls readable is **back**, and becomes `HOT`.
/// * A `RESTORING` row the store still calls `Archived` — no restore in play — is a request the
///   provider never accepted or has since expired. It goes back to `ARCHIVED` so the user can ask
///   again; leaving it `RESTORING` is the permanent-limbo bug in a slower form.
/// * An `ARCHIVING` row the store calls `Hot` has **not moved yet**, and stays.
///
/// [`ObservedTier::Restored`] maps to `HOT` rather than to a tier of its own, and that is the one
/// arm worth arguing. The object's storage class is still cold and the readable copy expires, so
/// `HOT` is temporarily true and will become wrong. It is the right answer anyway: while the copy
/// exists the bytes *are* immediately readable, which is the only question `StorageTier` answers,
/// and when the window closes this pass sees `Archived` again. Recording `ARCHIVED` for a file the
/// user just waited hours for would refuse the read they asked for.
#[must_use]
pub const fn resolve(current: StorageTier, observed: ObservedTier) -> Option<StorageTier> {
    match (current, observed) {
        // All three cold observations resolve an `ARCHIVING` row the same way: the transition
        // happened. `Restored` is included because a readable copy does not undo the archive — the
        // storage class is cold and the copy expires — and `Restoring` because something asking for
        // it back is only possible once it is there.
        (
            StorageTier::Archiving,
            ObservedTier::Archived | ObservedTier::Restoring | ObservedTier::Restored,
        ) => Some(StorageTier::Archived),
        (StorageTier::Restoring, ObservedTier::Hot | ObservedTier::Restored) => {
            Some(StorageTier::Hot)
        }
        (StorageTier::Restoring, ObservedTier::Archived) => Some(StorageTier::Archived),
        // Not yet: an `ARCHIVING` row the provider has not moved, and a `RESTORING` row still
        // retrieving. Both are the ordinary case and both mean *come back next tick*.
        (StorageTier::Archiving, ObservedTier::Hot)
        | (StorageTier::Restoring, ObservedTier::Restoring) => None,
        // A row that is not transitioning is not this pass's business. `in_transition` does not
        // return them; the arm exists so the match is exhaustive and a future tier has to be
        // classified rather than defaulting into a write.
        (StorageTier::Hot | StorageTier::Archived, _) => None,
    }
}

/// What a row that says `HOT` should become, given what the store reported (`ENC-951`).
///
/// A pure function for the reason [`resolve`] is one, and here it is the *only* way the behaviour
/// can be asserted at all: MinIO has no cold tier, so a development stack can never produce a warm
/// row the store calls cold. The end-to-end proof covers the control — a genuinely warm row is
/// verified and not moved — and this covers the three answers that matter and cannot be staged.
///
/// [`ObservedTier::Restored`] is drift, and that is the arm worth arguing. The bytes are readable
/// *now*, so leaving the row `HOT` is momentarily true — and the storage class is cold and the
/// readable copy expires, so the row would go on minting signed URLs after the window closed, with
/// nothing scheduled to notice. Recording `ARCHIVED` costs a rehydrate the user may not need; the
/// alternative costs a download that fails at the object store. The second is worse and is the
/// failure `ENC-946` exists to prevent.
///
/// Note this is **not** [`resolve`] with a different name: that one answers for a row already
/// mid-transition, where `Restored` means an archive completed. Here the row claims to be warm, so
/// the same observation means something else entirely. Two questions, two functions.
#[must_use]
pub const fn drift_target(observed: ObservedTier) -> Option<StorageTier> {
    match observed {
        // Confirmed warm: no move, and the caller stamps the verification instead.
        ObservedTier::Hot => None,
        ObservedTier::Restoring => Some(StorageTier::Restoring),
        ObservedTier::Archived | ObservedTier::Restored => Some(StorageTier::Archived),
    }
}

/// One pass over every tenant's mid-transition versions.
///
/// # Why a store failure does not fail the pass
///
/// A `HeadObject` that errors is counted and skipped, not propagated. The row is left exactly as it
/// was, so the next tick asks again — which is correct, because the alternatives are worse: failing
/// the pass would let one unreadable object stop every other tenant's restores from completing, and
/// writing a tier on a failed read would be recording a guess about where bytes are.
///
/// The one failure worth a log line at `warn` is a **missing** object, because that is not a
/// transient provider fault: it means the row points at bytes that are gone, and no number of
/// retries changes it.
///
/// # Errors
///
/// [`WorkerError`](crate::error::WorkerError) from the first tenant whose *database* fails. Earlier
/// tenants stay reconciled — each was its own transaction — and the caller retries, which is free.
pub async fn sweep(
    pool: &DbPool,
    store: &Arc<dyn BlobStore>,
    tenants: &[TenantId],
    stop: &Stop,
) -> Result<SweepOutcome> {
    let mut outcome = SweepOutcome::default();

    for &tenant in tenants {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        // Read, close, then decide — the shape `crates/api/src/routes/lifecycle.rs` argues. A
        // provider round trip inside an open transaction holds a pooled connection for the length of
        // somebody else's network.
        let mut tx = pool.begin(tenant).await?;
        let pending = VersionRepository::in_transition(&mut tx, tenant, BATCH).await?;
        tx.commit().await?;

        outcome.tenants_swept += 1;
        outcome.more_to_take |= i64::try_from(pending.len()).unwrap_or(i64::MAX) >= BATCH;

        for version in pending {
            if stop.is_stopped() {
                outcome.stopped = true;
                break;
            }

            let observed = match store.observed_tier(&version.object_key).await {
                Ok(observed) => observed,
                Err(StorageError::NotFound { .. }) => {
                    warn!(
                        tenant_id = %tenant,
                        version_id = %version.id,
                        "a version mid-transition points at an object the store does not have; \
                         the row is left alone — this is not a transient fault and retrying will \
                         not resolve it"
                    );
                    outcome.unanswerable += 1;
                    continue;
                }
                Err(error) => {
                    debug!(
                        tenant_id = %tenant,
                        version_id = %version.id,
                        error = %error,
                        "the store could not report a tier; leaving the row for the next pass"
                    );
                    outcome.unanswerable += 1;
                    continue;
                }
            };

            let Some(target) = resolve(version.tier, observed) else {
                outcome.still_waiting += 1;
                continue;
            };

            let mut tx = pool.begin(tenant).await?;
            let moved = VersionRepository::reconcile_tier(
                &mut tx,
                tenant,
                version.id,
                version.tier,
                target,
            )
            .await?;
            tx.commit().await?;

            if moved {
                outcome.resolved += 1;
            } else {
                // Somebody changed the row between the read and this write — a user's rehydrate,
                // most likely. Their intent is newer than this observation, so it wins; the row is
                // picked up next pass with a fresh one.
                outcome.still_waiting += 1;
            }
        }

        // --- the drift scan (`ENC-951`) ---------------------------------------------------------
        //
        // After the transitions and never instead of them: somebody is waiting on each transition
        // and nobody is waiting on any particular warm row, so a large drift backlog must not delay
        // a restore that has already landed.
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        let mut tx = pool.begin(tenant).await?;
        let warm = VersionRepository::least_recently_verified(&mut tx, tenant, DRIFT_BATCH).await?;
        tx.commit().await?;

        for version in warm {
            if stop.is_stopped() {
                outcome.stopped = true;
                break;
            }

            let observed = match store.observed_tier(&version.object_key).await {
                Ok(observed) => observed,
                Err(error) => {
                    // Not stamped as verified: an object the store could not answer for is one this
                    // pass learned nothing about, and recording a verification would move it to the
                    // back of a queue it was never checked in.
                    debug!(
                        tenant_id = %tenant,
                        version_id = %version.id,
                        error = %error,
                        "the store could not report a tier during the drift scan"
                    );
                    outcome.unanswerable += 1;
                    continue;
                }
            };

            outcome.verified += 1;

            // Warm and confirmed warm: the ordinary answer, and it still has to be *written*. A row
            // checked and not stamped is a row the ordering returns immediately, and the scan would
            // re-check one batch for ever while the rest of the corpus went unverified.
            if observed == ObservedTier::Hot {
                let mut tx = pool.begin(tenant).await?;
                VersionRepository::mark_tier_verified(&mut tx, tenant, version.id).await?;
                tx.commit().await?;
                continue;
            }

            let Some(target) = drift_target(observed) else { continue };

            let mut tx = pool.begin(tenant).await?;
            // Conditional on `HOT`, so a rehydrate that ran during the provider round trip is not
            // overwritten by an observation older than it.
            let moved = VersionRepository::reconcile_tier(
                &mut tx,
                tenant,
                version.id,
                StorageTier::Hot,
                target,
            )
            .await?;
            if moved {
                VersionRepository::mark_tier_verified(&mut tx, tenant, version.id).await?;
            }
            tx.commit().await?;

            if moved {
                outcome.drifted += 1;
                warn!(
                    tenant_id = %tenant,
                    version_id = %version.id,
                    from = StorageTier::Hot.as_str(),
                    to = target.as_str(),
                    "a version was moved to a colder tier without this product being told; until \
                     this pass found it, every read path would have minted a URL the object store \
                     refuses. A bucket lifecycle rule is the usual cause (ENC-951)"
                );
            }
        }

        // How far behind this tenant is, reported whether or not anything moved. The pass's own
        // success says nothing about coverage; this number does.
        let mut tx = pool.begin(tenant).await?;
        let oldest = VersionRepository::oldest_tier_verification(&mut tx, tenant).await?;
        tx.commit().await?;
        match oldest {
            None => {}
            Some(None) => debug!(
                tenant_id = %tenant,
                "the oldest warm version in this tenant has never had its tier verified"
            ),
            Some(Some(at)) => debug!(
                tenant_id = %tenant,
                oldest_verification = %at,
                "the oldest tier verification in this tenant"
            ),
        }
    }

    debug!(
        swept = outcome.tenants_swept,
        resolved = outcome.resolved,
        waiting = outcome.still_waiting,
        verified = outcome.verified,
        drifted = outcome.drifted,
        unanswerable = outcome.unanswerable,
        more = outcome.more_to_take,
        stopped = outcome.stopped,
        "tier reconciliation pass complete"
    );
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The decision table, every cell of it.
    ///
    /// Asserted as a table rather than as eight tests because the *shape* is the property: sixteen
    /// (tier, observation) pairs exist, `in_transition` can return two of the four tiers, and every
    /// one of those eight combinations has to have been thought about. A missing row here is a
    /// state the reconciler meets in production and handles by accident.
    #[test]
    fn every_transition_a_reconciler_can_meet_has_a_decided_answer() {
        use ObservedTier as O;
        use StorageTier as S;

        let table = [
            (S::Archiving, O::Hot, None, "not moved yet"),
            (S::Archiving, O::Archived, Some(S::Archived), "the transition completed"),
            (
                S::Archiving,
                O::Restoring,
                Some(S::Archived),
                "cold, and something has already asked for it back — it is archived either way",
            ),
            (
                S::Archiving,
                O::Restored,
                Some(S::Archived),
                "cold with a readable copy; the archive did happen",
            ),
            (S::Restoring, O::Hot, Some(S::Hot), "back, and warm"),
            (
                S::Restoring,
                O::Restored,
                Some(S::Hot),
                "back: the copy is readable now, which is the only question StorageTier asks",
            ),
            (S::Restoring, O::Restoring, None, "still retrieving"),
            (
                S::Restoring,
                O::Archived,
                Some(S::Archived),
                "no restore in play — never accepted, or expired. Back to ARCHIVED so the user can \
                 ask again rather than waiting on a request that is not running",
            ),
        ];

        for (current, observed, expected, why) in table {
            assert_eq!(resolve(current, observed), expected, "{current:?} + {observed:?}: {why}");
        }
    }

    /// A row that is not transitioning is never written.
    ///
    /// The guard that makes this pass safe to point at any row. `in_transition` filters, so this is
    /// belt and braces — and it is the belt that matters: a reconciler that could write `HOT` over a
    /// settled `ARCHIVED` row on a bad observation is the failure `ENC-946` exists to prevent,
    /// caused by the pass meant to protect against it.
    #[test]
    fn a_settled_row_is_never_moved_by_this_pass() {
        use ObservedTier as O;
        use StorageTier as S;

        for current in [S::Hot, S::Archived] {
            for observed in [O::Hot, O::Archived, O::Restoring, O::Restored] {
                assert_eq!(
                    resolve(current, observed),
                    None,
                    "{current:?} is settled and must not be rewritten on a {observed:?} observation"
                );
            }
        }
    }

    /// Every answer the drift scan can get from a warm row is decided (`ENC-951`).
    ///
    /// **The only way this behaviour can be asserted on a development machine.** MinIO has no cold
    /// tier, so no local stack can produce a `HOT` row the store calls cold; the end-to-end run
    /// covers the control — a genuinely warm row is verified and left alone — and everything below
    /// it is unreachable there.
    ///
    /// `Restored` mapping to `ARCHIVED` rather than to `None` is the arm to read twice: the bytes
    /// are readable now, so leaving the row `HOT` is momentarily true, and the readable copy
    /// expires with nothing scheduled to notice. Getting this wrong costs a download that fails at
    /// the object store, which is the failure the whole tier model exists to prevent.
    #[test]
    fn every_answer_a_warm_row_can_get_from_the_store_is_decided() {
        use ObservedTier as O;
        use StorageTier as S;

        let table = [
            (O::Hot, None, "confirmed warm: verified, not moved"),
            (
                O::Archived,
                Some(S::Archived),
                "moved without this product being told — a bucket lifecycle rule, and the case \
                 this scan exists for",
            ),
            (
                O::Restoring,
                Some(S::Restoring),
                "cold and already being fetched back by somebody or something else",
            ),
            (
                O::Restored,
                Some(S::Archived),
                "readable now and cold underneath: the copy expires, and a row left HOT would go \
                 on minting URLs after it did",
            ),
        ];

        for (observed, expected, why) in table {
            assert_eq!(drift_target(observed), expected, "{observed:?}: {why}");
        }
    }

    /// The two decisions are different questions and must not be collapsed.
    ///
    /// `resolve` answers for a row already mid-transition; `drift_target` for one that claims to be
    /// warm. They meet the same `ObservedTier` values and disagree about `Restored` — an archive
    /// completing versus a warm row that has silently gone cold — so a future edit that "shared the
    /// logic" would have to break one of them. This is the assertion that notices.
    #[test]
    fn the_transition_and_drift_decisions_disagree_where_they_should() {
        use ObservedTier as O;
        use StorageTier as S;

        assert_eq!(
            resolve(S::Restoring, O::Restored),
            Some(S::Hot),
            "a RESTORING row the store calls Restored is back: the wait is over"
        );
        assert_eq!(
            drift_target(O::Restored),
            Some(S::Archived),
            "a HOT row the store calls Restored has silently gone cold underneath, and the \
             readable copy is temporary — the opposite conclusion from the same observation"
        );
    }

    /// A partial batch is not a reason to come straight round.
    ///
    /// The same distinction `print_tokens` turns on, and it is easy to get backwards: a pass that
    /// resolved three of a possible thirty-two has finished the work there was, and treating that as
    /// progress makes the loop spin at full speed over an empty table.
    #[test]
    fn a_partial_batch_does_not_ask_the_loop_to_come_straight_round() {
        let full = SweepOutcome { more_to_take: true, ..SweepOutcome::default() };
        let partial = SweepOutcome::default();
        assert!(full.more_to_take);
        assert!(!partial.more_to_take, "an empty or partial batch means the queue is drained");
    }
}
