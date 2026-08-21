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
//! Both loops here run downstream of that. [`invalidation`] deletes suppressions that have already
//! stopped suppressing; [`epoch`] marks index manifests whose ACL has moved on so they are rebuilt.
//! Neither decides what a caller may see.
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
//! # Why neither loop enumerates tenants
//!
//! Both entry points take the tenants to work on. They do not go and find them, because the query
//! that produces a tenant list cannot itself be tenant-scoped, and reaching it means
//! [`DbPool::platform_connection`](enclave_db::DbPool::platform_connection) — the row-level-security
//! escape hatch, which `plans/M0-FOUNDATIONS.md` D3 restricts to three named callers, none of them
//! housekeeping. Adding a fourth caller for a cleanup job is exactly the sort of "just this once"
//! that the accessor is `pub(crate)` to prevent.
//!
//! So every statement below runs inside [`DbPool::begin`](enclave_db::DbPool::begin), under RLS,
//! with an application `tenant_id` predicate beside it. The scheduler owns the enumerator and the
//! clock (`crates/scheduler`, "time-driven jobs … cleanup"); this crate owns one pass.
//!
//! # Stopping and running twice
//!
//! Every unit of work here is one transaction, and every predicate is *self-consuming*: a lifted
//! row no longer matches "expired", a marked manifest no longer matches "READY with a stale epoch".
//! That is what makes both loops resumable without a cursor and safe to kill between batches — a
//! stopped run is a shorter run, not a half-finished one. [`Stop`] is checked at those boundaries
//! and nowhere else.

pub mod coverage;
pub mod epoch;
pub mod error;
pub mod indexing;
pub mod invalidation;

pub use error::{Result, WorkerError};

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
#[derive(Clone, Debug, Default)]
pub struct Stop {
    flag: Arc<AtomicBool>,
}

impl Stop {
    /// A signal that has not been raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises it. Idempotent, and safe to call from a signal handler or another task.
    pub fn stop(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether a loop should return at its next boundary.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
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
}
