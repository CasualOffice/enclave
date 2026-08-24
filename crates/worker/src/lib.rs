//! `enclave-worker` — the housekeeping that runs *after* search is already correct.
//!
//! # The constraint this crate is written under
//!
//! **The worker's absence must cost only index size, never correctness.**
//!
//! That is not a quality bar, it is the shape of the design. `plans/M3-DISCOVERY.md` D22 refused
//! the natural invalidation design — enqueue a job, let a worker remove the document — because a
//! stopped worker would then leave a revoked file findable *and* the search would still answer,
//! confidently. So revocation writes `retrieval_denylist` in the same transaction as the ACL
//! change, every search reads it, and S4 (`docs/12-TESTING.md §4.3`) is the test that a stopped
//! worker changes nothing a caller can observe.
//!
//! Both housekeeping loops here run downstream of that. [`invalidation`] deletes suppressions that
//! have already stopped suppressing; [`epoch`] marks index manifests whose ACL has moved on so they
//! are rebuilt. Neither decides what a caller may see.
//!
//! [`schedule`] is what runs them, and it is the one module here that is neither a pass nor a
//! composition of what a deployment mounted: it owns the clock, the tenant list and the shutdown
//! path. Its own documentation argues the three decisions that are not a pass's to make.
//!
//! [`ocr`] is the one module here that is not housekeeping, and it is here because this is the
//! crate that composes what a deployment mounted. It builds the OCR stage [`indexing`] consults, or
//! — for the deployment that mounted nothing, which is almost all of them — builds nothing at all.
//! Its whole design is the three-state distinction between *no OCR configured*, *OCR configured and
//! working*, and *OCR configured and broken*; see that module for why the third must never be
//! reported as the first.
//!
//! [`antivirus`] is the pass that breaks the constraint outright, and it says so at the top of its
//! own module: its absence does not cost index size, it costs **every version in the deployment**.
//! It is the only thing in this workspace that writes `file_versions.status = 'AVAILABLE'`, so with
//! it absent nothing an uploader commits ever becomes readable and both content passes below run
//! correctly over nothing (`ENC-641`). It is here rather than in a crate of its own for the reason
//! [`scan`] is: it needs the pool, the object store and a scanner a deployment configured, and this
//! is the crate that composes what a deployment mounted. What it must never do is decide *policy* —
//! `enclave_antivirus::decide` owns `docs/06 §6.2` and this pass only translates its answer into two
//! rows.
//!
//! [`scan`] is the one pass here that is not housekeeping either, and it is the exception to the
//! constraint above: its absence costs more than index size. It reads a version's text through the
//! same extraction the indexing pass uses and records what `enclave_dlp`'s detectors found in
//! `security_facts`, which is the evidence every synchronous DLP decision is taken from
//! (`docs/06 §12`). That does not weaken the rule — nothing it writes decides *who may see what*,
//! and a version it has not reached is `unscanned`, whose meaning is the tenant's
//! `facts_unavailable` policy's to settle rather than this crate's. What it must never do is record
//! a scan it did not perform; see that module for why an unscannable document gets no row at all.
//!
//! [`coverage`] is downstream of everything, because it writes nothing at all: it takes the
//! index-coverage reading `crates/search/src/health.rs` computes, per tenant, and publishes it, so
//! that the three rules in `deploy/monitoring/alerts/search.yml` have a producer. Its output is an
//! operator's, never a caller's — see that module for why the reading is deliberately not stored
//! anywhere a search could reach it.
//!
//! # The failure mode to watch for is not a bug, it is a dependency
//!
//! The danger in this crate is not that a sweep is wrong. It is that something downstream starts
//! *relying* on it having run — a read path that consults `index_manifests.status`, a search that
//! trusts `acl_epoch`, a cache warmed only by the reconciler. At that moment S4 keeps passing, but
//! for the wrong reason: because the worker happened to be running, not because correctness never
//! depended on it. That regression is invisible in a green suite, so each module states what it is
//! *not* and the tests assert the negative — see
//! `the_reconciler_never_writes_a_suppression` in `tests/epoch.rs`.
//!
//! Two rules follow, and they are worth stating once here rather than discovering twice:
//!
//! 1. Nothing in this crate exposes a *freshness oracle* — no public "is this file's index current"
//!    predicate. A function shaped like that is the one a search path eventually calls, and
//!    `crates/search/src/postfilter.rs` explains at length why the post-filter must never become
//!    conditional on such a signal.
//! 2. Nothing in this crate *adds* a suppression. Writing `retrieval_denylist` is the job of
//!    whatever changed the ACL, inside that change's transaction. A worker that could suppress
//!    would make recall depend on it running, which is the same mistake as D22's rejected design
//!    pointing the other way.
//!
//! # Why no pass enumerates tenants
//!
//! Every entry point takes the tenants to work on. None of them goes and finds them, because the
//! query that produces a tenant list cannot itself be tenant-scoped, and reaching it means
//! [`DbPool::platform_connection`](enclave_db::DbPool::platform_connection) — the row-level-security
//! escape hatch, which `plans/M0-FOUNDATIONS.md` D3 restricts to three named callers, none of them
//! housekeeping. Adding a fourth caller for a cleanup job is exactly the sort of "just this once"
//! that the accessor exists to make reviewable.
//!
//! So every statement below runs inside [`DbPool::begin`](enclave_db::DbPool::begin), under RLS,
//! with an application `tenant_id` predicate beside it. The enumerator and the clock belong to
//! [`schedule`], which is the composition half of this crate rather than a pass: it takes a
//! [`TenantSource`](schedule::TenantSource) and calls it, and the only production implementation of
//! that trait — [`tenants::DbTenants`] — delegates to `enclave_db::active_tenants`, which is D3's
//! third named caller written where the escape hatch lives. `platform_connection` still has no
//! caller outside `crates/db`.
//!
//! `ENC-548` is where that split was made real: until then nothing called any of these passes, and
//! the four capabilities were as absent from a deployment as if none had been written.
//!
//! # Stopping and running twice
//!
//! Every unit of work here is one transaction, and every predicate is *self-consuming*: a lifted
//! row no longer matches "expired", a marked manifest no longer matches "READY with a stale epoch".
//! That is what makes both loops resumable without a cursor and safe to kill between batches — a
//! stopped run is a shorter run, not a half-finished one. [`Stop`] is checked at those boundaries
//! and nowhere else.

pub mod antivirus;
pub mod coverage;
pub mod embedding;
pub mod epoch;
pub mod error;
pub mod indexing;
pub mod invalidation;
pub mod ocr;
pub mod scan;
pub mod schedule;
pub mod tenants;

pub use error::{Result, WorkerError};

use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shared "stop after the current unit of work" flag.
///
/// A flag rather than a shutdown future, and checked only between transactions, because those are
/// the two halves of the same decision. Racing a `select!` against an in-flight batch would drop
/// the future mid-statement: `sqlx` rolls the transaction back, so nothing is corrupted, but the
/// work is thrown away and the connection is returned mid-conversation. There is no batch here long
/// enough to be worth interrupting — a sweep is one `DELETE`, a reconcile batch is one bounded
/// `UPDATE` — so the cheap, obvious thing is also the correct one.
///
/// Cloneable and cheap to share: every replica of a loop observes the same flag.
///
/// # The wake-up is a second mechanism, and it is not the same decision
///
/// [`Stop::sleep_until_stopped`] exists because a *scheduler* has a third state the passes do not:
/// idle. A pass is either inside a transaction or between two of them, and the flag covers both. A
/// scheduler spends almost all of its life asleep between ticks, and a flag alone means SIGTERM is
/// not noticed until the interval elapses — up to a minute for the coverage loop, against
/// Kubernetes' 30-second default grace period, which ends in `SIGKILL` **during** whatever the
/// worker started on its next tick. Waiting out an interval to shut down politely is how a process
/// gets killed impolitely.
///
/// So the sleep is interruptible and nothing else is. The passes still consult
/// [`Stop::is_stopped`] and only at their own boundaries; no in-flight batch is ever raced against
/// a future, which is the property the paragraph above this one is about.
#[derive(Clone, Debug, Default)]
pub struct Stop {
    flag: Arc<AtomicBool>,
    /// Woken once, for everyone, when the flag is raised. See [`Stop::sleep_until_stopped`].
    wake: Arc<tokio::sync::Notify>,
}

impl Stop {
    /// A signal that has not been raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises it. Idempotent, and safe to call from a signal handler or another task.
    ///
    /// The flag is set *before* the waiters are woken, so a sleeper that races the notification
    /// sees a raised flag when it re-checks. The other order would let a loop wake, find the flag
    /// still clear, and go back to sleep for a full interval.
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
    }

    /// Whether a loop should return at its next boundary.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Sleeps for `interval`, or returns the moment [`Stop::stop`] is called.
    ///
    /// Reports **why** it returned rather than leaving the caller to re-read the flag, because those
    /// are two different states for a scheduler — "the interval elapsed, do the next tick" against
    /// "shut down" — and a caller that inferred the second from a flag it read afterwards would have
    /// a race in it.
    ///
    /// `notify_waiters` only wakes waiters that are already registered, so the registration happens
    /// before the second flag check: a `stop()` landing between the two finds a registered waiter,
    /// and one landing before the first is caught by that check. There is no ordering in which this
    /// sleeps through a raised flag.
    pub async fn sleep_until_stopped(&self, interval: Duration) -> Woke {
        if self.is_stopped() {
            return Woke::Stopped;
        }

        let notified = self.wake.notified();
        tokio::pin!(notified);
        // Registers this waiter now, rather than on the first poll inside `select!`.
        notified.as_mut().enable();

        if self.is_stopped() {
            return Woke::Stopped;
        }

        tokio::select! {
            () = notified => Woke::Stopped,
            () = tokio::time::sleep(interval) => Woke::Elapsed,
        }
    }

    /// Resolves when the signal is raised, and immediately if it already has been.
    ///
    /// For the things that take a shutdown *future* rather than checking a flag —
    /// `axum::serve(…).with_graceful_shutdown` on the metrics socket, in particular. Written in
    /// terms of the same notification as [`Stop::sleep_until_stopped`] so there is one wake-up
    /// mechanism in this crate rather than two that have to be raised together.
    pub async fn stopped(&self) {
        loop {
            if self.is_stopped() {
                return;
            }
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_stopped() {
                return;
            }
            notified.await;
        }
    }
}

/// Why [`Stop::sleep_until_stopped`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// The interval elapsed. Run the next tick.
    Elapsed,
    /// [`Stop`] was raised. Return.
    Stopped,
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_clone_observes_the_same_signal() {
        // The loops take `&Stop` while whatever raises it holds a clone; if the flag were copied
        // rather than shared, a worker would keep running after shutdown and the only symptom
        // would be a process that never exits.
        let stop = Stop::new();
        let handle = stop.clone();
        assert!(!stop.is_stopped());
        handle.stop();
        assert!(stop.is_stopped());
    }

    #[test]
    fn raising_it_twice_is_not_an_error() {
        let stop = Stop::new();
        stop.stop();
        stop.stop();
        assert!(stop.is_stopped());
    }

    /// An hour-long interval that is never waited on, because the flag is already raised.
    ///
    /// The interval is deliberately absurd: if the flag check ever moved after the `select!`, this
    /// test would take an hour rather than failing an assertion, and an hour-long test is a failure
    /// nobody mistakes for a slow machine. Nothing here asserts a duration.
    #[tokio::test]
    async fn a_sleep_that_starts_stopped_never_sleeps() {
        let stop = Stop::new();
        stop.stop();
        assert_eq!(stop.sleep_until_stopped(Duration::from_secs(3600)).await, Woke::Stopped);
    }

    /// The positive control for the test above: with the flag clear, the interval is what ends the
    /// sleep, and the two outcomes are distinguishable.
    ///
    /// `ZERO` rather than a small number of milliseconds — a zero-length sleep is a yield, so this
    /// asserts which branch of the `select!` won and never how fast the machine is (`ENC-550`).
    #[tokio::test]
    async fn a_sleep_that_is_not_stopped_reports_the_interval_elapsing() {
        let stop = Stop::new();
        assert_eq!(stop.sleep_until_stopped(Duration::ZERO).await, Woke::Elapsed);
        assert!(!stop.is_stopped(), "sleeping must not raise the signal");
    }

    /// A signal raised *while* a loop is idle cuts the idle short.
    ///
    /// This is the operational half — the reason `Stop` carries a `Notify` at all. Without it a
    /// SIGTERM arriving one second into a sixty-second idle is noticed fifty-nine seconds later,
    /// which on Kubernetes' default grace period is a `SIGKILL` landing on whatever the worker
    /// started next.
    ///
    /// The verdict is the returned variant, never elapsed time. The `timeout` is only so that a
    /// regression fails in ten seconds instead of hanging for an hour, and ten seconds against an
    /// expected microsecond is not a speed assertion by any margin that could flake.
    #[tokio::test]
    async fn a_signal_raised_during_an_idle_ends_it() {
        let stop = Stop::new();
        let raiser = stop.clone();
        let sleeping =
            tokio::spawn(async move { stop.sleep_until_stopped(Duration::from_secs(3600)).await });

        // Let the sleeper reach its `select!` before the signal is raised, so this exercises the
        // notification rather than the flag check on the way in — which the test above covers.
        tokio::task::yield_now().await;
        raiser.stop();

        let woke = tokio::time::timeout(Duration::from_secs(10), sleeping)
            .await
            .expect("the idle did not end when the signal was raised")
            .expect("the sleeping task panicked");
        assert_eq!(woke, Woke::Stopped);
    }

    /// The shutdown *future*, for the socket that takes one, resolves on an already-raised signal.
    ///
    /// The already-raised case is the one worth pinning: the metrics listener is spawned before the
    /// scheduler starts, and a `stopped()` that only reacted to the notification would hang the
    /// process forever if the signal arrived in the gap between the two.
    #[tokio::test]
    async fn the_shutdown_future_resolves_on_a_signal_already_raised() {
        let stop = Stop::new();
        stop.stop();
        tokio::time::timeout(Duration::from_secs(10), stop.stopped())
            .await
            .expect("a signal raised before the wait began was never observed");
    }

    /// And it does **not** resolve while the signal is clear.
    ///
    /// The negative control for the two tests around it, and the one that matters to the metrics
    /// socket: `serve(…).with_graceful_shutdown(stop.stopped())` is spawned before the passes start,
    /// so a future that resolved on its own would close the exposition during start-up and every
    /// scrape afterwards would be a refused connection. Fifty milliseconds is not a claim about
    /// speed — a correct implementation never resolves at all, so no amount of load makes this pass
    /// when it should fail.
    #[tokio::test]
    async fn the_shutdown_future_does_not_resolve_on_its_own() {
        let stop = Stop::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stop.stopped()).await.is_err(),
            "the shutdown future resolved without a signal"
        );
    }

    /// And on one raised afterwards. Paired with the test above so neither can pass by the other's
    /// path — an implementation that only checked the flag once would fail this one.
    #[tokio::test]
    async fn the_shutdown_future_resolves_on_a_signal_raised_later() {
        let stop = Stop::new();
        let raiser = stop.clone();
        let waiting = tokio::spawn(async move { stop.stopped().await });

        tokio::task::yield_now().await;
        raiser.stop();

        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the wait did not end when the signal was raised")
            .expect("the waiting task panicked");
    }
}
