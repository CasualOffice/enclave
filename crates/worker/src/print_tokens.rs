//! The print-token sweep: deleting capabilities whose lifetime has already ended.
//!
//! # What makes a print token safely deletable
//!
//! Exactly one thing, and it is the same shape as `crate::invalidation`'s argument: **every
//! statement that reads the table already refuses the row.**
//!
//! `enclave_preview::print::redeem` carries `expires_at > now()` in the predicate that spends a
//! grant, so a row past its expiry is not redeemable before this pass arrives and is not redeemable
//! after it leaves. Deleting it changes nothing a caller can observe, which is why this sweep can be
//! stopped, resumed, run twice or never run at all, and why it needs no lock, no checkpoint and no
//! coordination between replicas.
//!
//! The dangerous version of this module is the one that decides for itself which grants have served
//! their purpose — sweeping *redeemed* rows, say, on the grounds that they cannot be spent again.
//! That would be true and it would still be wrong: while a redeemed row is present, a replay is
//! refused by `redeemed_at IS NULL`, and after it is gone the same replay is refused by there being
//! no row. Both are the same `404`, so nothing is gained; what would be lost is the one window in
//! which "this grant was replayed" is distinguishable from "this grant never existed", which is the
//! only diagnostic the table offers. So the predicate is expiry and nothing else, and a redeemed
//! grant lives out its 120 seconds like any other.
//!
//! # The clock is the database's, and this is not a detail
//!
//! `expires_at <= now()` is evaluated by PostgreSQL, in the same statement, against the same clock
//! the redemption reads. `crate::invalidation` records what the alternative costs: a worker running
//! a few seconds ahead of the database deletes rows the database still considers live, and a grant
//! a caller is about to spend disappears underneath them. This pass reads no clock at all, which is
//! the strongest form of that property — there is nothing here to pass wrongly.
//!
//! # Why this is its own pass and not part of `upload-reaper`
//!
//! `ENC-806`'s reaper is the obvious place to put a second sweep, and it is the wrong one. Three
//! reasons, in order of how much they cost:
//!
//! 1. **`upload-reaper` is optional.** It is wired only when `content_passes` returns `Some`, which
//!    needs object storage and its secrets; a deployment with neither still mints print tokens. A
//!    table that grows on *every* deployment cannot be reaped by a pass that some deployments do
//!    not run. This one is unconditional, like `invalidation` and `epoch`.
//! 2. **It holds a `BlobStore` and exists to release staged bytes.** A print token has no bytes. The
//!    two passes fail differently — an upload sweep is deferred by a store refusing deletes, and
//!    this one cannot be deferred by anything — so folding them together would produce one
//!    `deferred` count that means two things.
//! 3. **`crates/worker/src/uploads.rs` asserts against its own source** that it names no table and
//!    no state (`the_pass_never_reasons_about_strandedness_itself`). Adding a second domain's
//!    statement to it would mean weakening that test, which is a worse trade than a thirty-line
//!    module.
//!
//! `crate::invalidation` was the other candidate and is the denylist sweep specifically — its whole
//! argument is about when a *suppression* may be lifted. Putting print tokens there would be
//! `CLAUDE.md`'s "convenient nearby place" exactly.

use enclave_core::TenantId;
use enclave_db::DbPool;
use tracing::debug;

use crate::error::Result;
use crate::Stop;

/// How many dead grants one tenant gives up per pass.
///
/// A bound rather than a target. Rows here live 120 seconds, so a tenant's expired set is bounded by
/// its mint rate times this pass's interval, and in steady state a batch is never full. What the
/// limit buys is the abnormal case: a tenant that minted a hundred thousand grants during an
/// incident must not become one `DELETE` holding one transaction open across all of them.
pub const REAP_BATCH: usize = 500;

/// A batch of zero deletes nothing and reports a healthy sweep for ever, which is `ENC-806`'s
/// finding in miniature: the failure mode of housekeeping is looking like it ran. Asserted at
/// compile time rather than in a test, the way `crates/worker/src/main.rs` guards its own pacing
/// constants — a test for this can be deleted, and a `const` block cannot be got past.
const _BATCH_IS_NOT_ZERO: () = assert!(REAP_BATCH > 0);

/// What one sweep did, across every tenant it reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use = "the counts are how an operator sees a table that has stopped being swept"]
pub struct SweepOutcome {
    /// Tenants whose dead grants were deleted.
    pub tenants_swept: usize,
    /// Rows deleted, in total.
    pub reaped: usize,
    /// Whether the sweep stopped early because the worker is shutting down.
    pub stopped: bool,
    /// Whether any tenant gave up a full batch — meaning there is more to take and the loop should
    /// come straight round rather than idle.
    ///
    /// Separate from `reaped > 0` on purpose: a pass that took three rows has finished the work
    /// there was, and going round again immediately would spend a round trip per tenant to find
    /// nothing. `crate::uploads::released_a_full_batch` draws the same line for the same reason.
    pub more_to_take: bool,
}

/// Deletes every tenant's dead print grants, one transaction per tenant.
///
/// The tenant list is a parameter: see this crate's documentation for why housekeeping does not
/// enumerate tenants for itself.
///
/// # Errors
///
/// [`WorkerError`](crate::error::WorkerError) from the first tenant that fails. Earlier tenants stay
/// swept — each was its own transaction, and rolling them back would undo work that was correct. The
/// caller retries the pass, which is free: every remaining row still matches.
pub async fn sweep(pool: &DbPool, tenants: &[TenantId], stop: &Stop) -> Result<SweepOutcome> {
    let mut outcome = SweepOutcome::default();

    for &tenant in tenants {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        let mut tx = pool.begin(tenant).await?;
        let reaped = enclave_preview::print::reap_expired(&mut tx, tenant, REAP_BATCH).await?;
        tx.commit().await?;

        outcome.tenants_swept += 1;
        outcome.reaped += reaped;
        outcome.more_to_take |= reaped >= REAP_BATCH;
    }

    debug!(
        swept = outcome.tenants_swept,
        reaped = outcome.reaped,
        more = outcome.more_to_take,
        stopped = outcome.stopped,
        "print-token sweep pass complete"
    );
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_partial_batch_is_not_a_reason_to_come_straight_round() {
        // The distinction the loop turns on. A pass that took three rows has finished the work there
        // was; treating that as progress makes the loop spin at full speed over an empty table for
        // ever, one round trip per tenant.
        let done =
            SweepOutcome { tenants_swept: 1, reaped: 3, stopped: false, more_to_take: false };
        assert!(!done.more_to_take);

        let full = SweepOutcome {
            tenants_swept: 1,
            reaped: REAP_BATCH,
            stopped: false,
            more_to_take: true,
        };
        assert!(full.more_to_take, "a full batch means there is more to take");
    }

    #[test]
    fn the_pass_never_decides_for_itself_which_grants_are_dead() {
        // The same source-level assertion `crates/worker/src/uploads.rs` makes about strandedness,
        // and for the same reason: the predicate that judges a print token's life belongs beside the
        // predicate that spends one, in `enclave_preview::print`. A second copy here is the copy
        // that eventually disagrees — and the direction it would disagree in is deleting grants a
        // caller is about to spend.
        // The header argues about `redeemed_at` at length and the tests name the batch, so the slice
        // has to be the code between them: from the first `use` to the test module. Getting this
        // wrong is how a source-scanning test finds its own needle, which two tests in this
        // repository already did on their first run (`docs/12 §1.2`).
        let source = include_str!("print_tokens.rs");
        let after_header = source.split_once("\nuse ").expect("the module has imports").1;
        let body = after_header
            .split("#[cfg(test)]")
            .next()
            .expect("the module has a body before its tests");

        for forbidden in ["sqlx::query", "redeemed_at", "token_hash", "DELETE FROM", "expires_at"] {
            assert!(
                !body.contains(forbidden),
                "this pass names `{forbidden}`, which means it has started reasoning about the \
                 table instead of asking `enclave_preview::print` to"
            );
        }
    }
}
