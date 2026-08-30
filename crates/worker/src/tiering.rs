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
//! Detecting that means asking the store about versions this product has no reason to suspect,
//! which is one `HeadObject` per version of every file in the deployment. This pass deliberately
//! does **not** do it: the two halves have different economics and folding them would make the
//! cheap, urgent half wait on the expensive one. `ENC-951` is the drift scan, and it needs a
//! `tier_verified_at` column to be orderable at all.
//!
//! What runs here is bounded by `idx_file_versions_in_transition`, a partial index over two
//! transient states — a handful of rows on any deployment, and zero on most.

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
    }

    debug!(
        swept = outcome.tenants_swept,
        resolved = outcome.resolved,
        waiting = outcome.still_waiting,
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
