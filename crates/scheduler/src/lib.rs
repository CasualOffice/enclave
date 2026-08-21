//! `enclave-scheduler` — time-driven jobs.
//!
//! `docs/02-HLD.md §4` gives this crate "retention jobs, rescan/reindex scheduling, directory sync,
//! **quota reconciliation**, recurring cleanup". `ENC-584` lands the fourth of those and, with it,
//! the shape the other four will take.
//!
//! # What this crate owns, and what it does not
//!
//! It owns the **cadence** and nothing else. What one storage-quota pass *does* lives in
//! [`enclave_db::quota`], beside the statements it corrects and the `CHECK` constraint that bounds
//! them, and is proven there against a real PostgreSQL (`crates/db/tests/storage_quota.rs`).
//!
//! That split is the same one `crates/worker/src/schedule.rs` argues for its four passes, and it is
//! worth restating because the temptation runs the other way: a job that owned both would need a
//! database to test its clock, and the interesting properties of a clock — that a failing tick does
//! not end the loop, that a raised stop flag is honoured before a tick rather than after it — are
//! exactly the ones a database makes expensive to assert. Every test below runs with no PostgreSQL
//! anywhere.
//!
//! # Why the loop takes the pass as a parameter
//!
//! [`run_passes`] is generic over the pass rather than calling [`enclave_db::reconcile_storage`]
//! directly, and [`run_storage_reconciliation`] is the three-line binding that supplies the real
//! one. The seam exists so the loop's behaviour can be asserted — a pass that fails, a pass that
//! never gets to run because the stop flag was already raised — without inventing a database
//! failure to provoke it.

use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::Arc;

use enclave_db::{DbError, DbPool, StorageReconciliation};

/// How often storage quotas are reconciled against what the deployment actually stores.
///
/// Nightly, per `docs/04-DATA-MODEL.md §16`. The number is not a correctness knob: the counter is
/// maintained in the same statement as every write it bounds, so reconciliation repairs *defects*
/// rather than lag, and a deployment with no defects reconciles to zero drift every night forever.
/// Running it more often would find the same nothing more expensively; running it less often would
/// leave a write-path bug undetected for longer, which is the only thing this cadence buys.
pub const STORAGE_RECONCILIATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A cadence of zero would spin, and a pass that spins on a full-table sum per tenant is an
/// outage rather than a busy loop. Checked at compile time because the mistake would be made in a
/// constant, and a build failure is louder than a test.
const _CADENCE_IS_NOT_ZERO: () = {
    assert!(
        STORAGE_RECONCILIATION_INTERVAL.as_secs() > 0,
        "a zero interval turns the nightly pass into a spin over every tenant's file_versions"
    );
};

/// The shutdown flag, raised once and read by every loop.
///
/// Written here rather than borrowed from `crates/worker`: the scheduler depending on the worker to
/// learn how to stop would be an edge from a peer binary crate to another purely for a primitive,
/// which is the shape `plans/M0-FOUNDATIONS.md` D1 refuses. The type is thirty lines and its
/// semantics — check before a tick, and *instead of* the wait — are the whole of what a graceful
/// shutdown is.
#[derive(Debug, Clone, Default)]
pub struct Stop {
    raised: Arc<AtomicBool>,
    woken: Arc<tokio::sync::Notify>,
}

impl Stop {
    /// A flag that has not been raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises the flag and wakes every waiter.
    pub fn stop(&self) {
        self.raised.store(true, Ordering::SeqCst);
        self.woken.notify_waiters();
    }

    /// Whether the flag has been raised.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.raised.load(Ordering::SeqCst)
    }

    /// Waits out `interval`, or returns early if the flag is raised while waiting.
    ///
    /// The subscription is taken **before** the flag is re-read, so a `stop()` landing between the
    /// two is still observed. Without that ordering a shutdown arriving at exactly the wrong moment
    /// leaves the process waiting out a full interval — which for this job is a day.
    pub async fn sleep_until_stopped(&self, interval: Duration) -> Woke {
        let notified = self.woken.notified();
        if self.is_stopped() {
            return Woke::Stopped;
        }
        tokio::select! {
            () = notified => Woke::Stopped,
            () = tokio::time::sleep(interval) => Woke::Elapsed,
        }
    }
}

/// Why a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Woke {
    /// The interval ran out; go again.
    Elapsed,
    /// The stop flag was raised; do not.
    Stopped,
}

/// Runs `pass` every `interval` until `stop` is raised, and returns the number of passes run.
///
/// Three properties, each of which is separately load-bearing and separately tested:
///
/// * **the flag is checked before a tick**, so a process told to stop during start-up does not
///   begin a pass it will then be waited on to finish;
/// * **a failing pass does not end the loop.** A nightly job that exited on the first bad night
///   would take a transient database failure and turn it into "quota drift stopped being detected
///   three weeks ago", which reads from outside as a healthy deployment — `docs/11-OPERATIONS.md
///   §5.7` is entirely about not misreading a metric that went quiet;
/// * **the wait is an idle interval, not a deadline.** A tick that overruns delays the next one
///   rather than overlapping with it, so a slow pass degrades into a lower frequency instead of
///   into concurrent copies of itself summing the same table.
pub async fn run_passes<F, Fut>(interval: Duration, stop: &Stop, mut pass: F) -> usize
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<StorageReconciliation, DbError>>,
{
    let mut ran = 0_usize;

    loop {
        if stop.is_stopped() {
            return ran;
        }

        ran += 1;
        match pass().await {
            Ok(report) => tracing::info!(
                examined = report.examined,
                drifted = report.drifted,
                unmetered = report.unmetered,
                total_drift_bytes = report.total_drift_bytes,
                "storage quota reconciliation complete"
            ),
            // Logged and swallowed, deliberately. See the second property above.
            Err(error) => tracing::error!(
                %error,
                retryable = error.is_retryable(),
                "storage quota reconciliation failed; the next pass will try again"
            ),
        }

        if stop.sleep_until_stopped(interval).await == Woke::Stopped {
            return ran;
        }
    }
}

/// The storage-quota reconciliation loop, bound to the real pass.
///
/// # Panics
///
/// Never. The pass's failures are logged and the loop continues; see [`run_passes`].
pub async fn run_storage_reconciliation(pool: &DbPool, interval: Duration, stop: &Stop) -> usize {
    tracing::info!(
        interval_secs = interval.as_secs(),
        "storage quota reconciliation scheduled (docs/04-DATA-MODEL.md §16, ENC-584)"
    );
    run_passes(interval, stop, || enclave_db::reconcile_storage(pool)).await
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use core::sync::atomic::AtomicUsize;

    /// A flag raised before the loop starts must prevent the *first* pass, not merely the second.
    ///
    /// The positive control is the second half: the identical loop with the flag down runs exactly
    /// one pass and stops. Without it, "no pass ran" is satisfied by a loop that never calls its
    /// pass at all — which is `docs/12 §1.2`'s free-passing absence, in a file with no database in
    /// it to make the mistake obvious.
    #[tokio::test]
    async fn a_stop_raised_before_the_loop_starts_prevents_the_first_pass() {
        let calls = Arc::new(AtomicUsize::new(0));

        let stop = Stop::new();
        stop.stop();
        let counted = Arc::clone(&calls);
        let ran = run_passes(Duration::from_secs(3600), &stop, || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Ok(StorageReconciliation::default()) }
        })
        .await;
        assert_eq!(ran, 0);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a pass ran after the process was told to stop"
        );

        // The control: the same loop, flag down, stopped from inside the pass.
        let stop = Stop::new();
        let counted = Arc::clone(&calls);
        let raiser = stop.clone();
        let ran = run_passes(Duration::from_secs(3600), &stop, || {
            counted.fetch_add(1, Ordering::SeqCst);
            raiser.stop();
            async { Ok(StorageReconciliation::default()) }
        })
        .await;
        assert_eq!(ran, 1, "the loop must run a pass when it has not been told to stop");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A failing pass must not end the loop.
    ///
    /// The first two passes fail and the third succeeds; the loop must reach the third. A loop that
    /// propagated the first error would report one pass, which is the number this asserts against.
    #[tokio::test]
    async fn a_failing_pass_does_not_end_the_nightly_job() {
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Stop::new();
        let raiser = stop.clone();
        let counted = Arc::clone(&calls);

        let ran = run_passes(Duration::ZERO, &stop, || {
            let attempt = counted.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt >= 3 {
                raiser.stop();
            }
            async move {
                if attempt < 3 {
                    Err(DbError::Acquire(sqlx::Error::PoolTimedOut))
                } else {
                    Ok(StorageReconciliation { examined: 1, ..StorageReconciliation::default() })
                }
            }
        })
        .await;

        assert_eq!(ran, 3, "the loop stopped at the first failing pass");
    }

    /// The wait honours a stop raised while it is in flight, rather than sitting out the interval.
    ///
    /// A day is the real interval, so a loop that ignored the flag until the timer expired would
    /// hold a container in `SIGTERM` grace until it was `SIGKILL`ed — mid-pass, which is exactly
    /// what a graceful stop exists to avoid.
    #[tokio::test(start_paused = true)]
    async fn a_stop_raised_during_the_wait_ends_it_immediately() {
        let stop = Stop::new();
        let raiser = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            raiser.stop();
        });

        assert_eq!(stop.sleep_until_stopped(STORAGE_RECONCILIATION_INTERVAL).await, Woke::Stopped);
        assert!(stop.is_stopped());
    }

    /// And the other outcome, so the assertion above is not satisfied by a wait that never waits.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_is_not_interrupted_reports_that_it_elapsed() {
        let stop = Stop::new();
        assert_eq!(stop.sleep_until_stopped(Duration::from_secs(60)).await, Woke::Elapsed);
        assert!(!stop.is_stopped());
    }

    #[test]
    fn the_reconciliation_interval_is_nightly() {
        // docs/04-DATA-MODEL.md §16 says nightly, and this is the constant that has to agree.
        assert_eq!(STORAGE_RECONCILIATION_INTERVAL, Duration::from_secs(86_400));
    }
}
