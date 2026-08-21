//! The scheduler, against a real PostgreSQL.
//!
//! # What these tests are about
//!
//! Not "the sweep works" — `tests/invalidation.rs` covers that, and the passes have had tests since
//! they were written. These are about the gap `ENC-548` found: **every pass in this crate had
//! exactly one caller, and it was its own test.** So what is asserted here is that starting the
//! scheduler causes the work to happen, which is the one thing no existing test could observe.
//!
//! # How they end without a stopwatch
//!
//! Every loop runs until [`Stop`] is raised, and nothing here sleeps waiting for one. The tenant
//! source raises it: it hands back the same list every time and, after a fixed number of calls,
//! raises the signal on its way out. Each loop then returns at its next boundary and
//! `Scheduler::run` returns when the last of them has.
//!
//! The cadence is [`Duration::ZERO`], so a tick that finds nothing yields rather than waiting. That
//! is not a short timeout dressed up as a fast one: nothing in these tests asserts on elapsed time,
//! and an implementation that ignored the signal would hang rather than pass (`ENC-550`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use enclave_core::{FileId, TenantId};
use enclave_db::DbPool;
use enclave_search::denylist;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::indexing::IndexPass;
use enclave_worker::schedule::{Cadence, IndexRunner, Scheduler, TenantSource};
use enclave_worker::{Result, Stop};

/// Ticks fast enough that nothing waits, and raises the signal itself.
const IMPATIENT: Cadence = Cadence {
    indexing_idle: Duration::ZERO,
    invalidation: Duration::ZERO,
    epoch: Duration::ZERO,
    coverage: Duration::ZERO,
};

/// Enough enumerations that every scheduled loop gets at least one full tick before the signal.
///
/// Loops share this source, so the count is across all of them; the number is a ceiling on how many
/// ticks happen, not a schedule. The assertions below are on *effects* that are idempotent — a
/// suppression is lifted once — so no interleaving of the loops changes the verdict.
const ENUMERATIONS_BEFORE_STOP: usize = 8;

/// The tenant list the scheduler is given, plus the thing that ends the test.
#[derive(Debug)]
struct FixedTenants {
    tenants: Vec<TenantId>,
    calls: AtomicUsize,
    stop: Stop,
}

impl FixedTenants {
    fn new(stop: Stop, tenants: Vec<TenantId>) -> Arc<Self> {
        Arc::new(Self { tenants, calls: AtomicUsize::new(0), stop })
    }
}

#[async_trait]
impl TenantSource for FixedTenants {
    async fn tenants(&self) -> Result<Vec<TenantId>> {
        if self.calls.fetch_add(1, Ordering::SeqCst) >= ENUMERATIONS_BEFORE_STOP {
            self.stop.stop();
        }
        Ok(self.tenants.clone())
    }
}

/// An [`IndexRunner`] that records what it was asked to index and does nothing.
///
/// A fake rather than a real pipeline because the subject here is the *scheduler*: whether
/// `Scheduler::run` spawns the indexing loop at all. What a real pass does with a claimed file is
/// `tests/indexing.rs`'s question, and answering it again here would need object storage.
#[derive(Debug, Default)]
struct RecordingRunner {
    seen: Mutex<Vec<TenantId>>,
}

impl RecordingRunner {
    fn seen(&self) -> Vec<TenantId> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

#[async_trait]
impl IndexRunner for RecordingRunner {
    async fn run(&self, tenant: TenantId, _stop: &Stop) -> Result<IndexPass> {
        self.seen.lock().expect("not poisoned").push(tenant);
        Ok(IndexPass::default())
    }
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(8).await.expect("application pool");
    (db, fixtures, pool)
}

/// Suppresses a new file in `tenant`, expiring at `clears_at`.
async fn suppressed_file(
    db: &TestDb,
    pool: &DbPool,
    tenant: TenantId,
    owner: enclave_core::UserId,
    clears_at: Option<chrono::DateTime<Utc>>,
) -> FileId {
    let now = Utc::now();
    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, owner, now).await.expect("spine");

    let mut tx = pool.begin(tenant).await.expect("begin");
    denylist::suppress(&mut tx, tenant, spine.file, "reindexing", now, clears_at)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");
    spine.file
}

/// Every denylist row a tenant still has, read through the application role.
async fn rows(pool: &DbPool, tenant: TenantId) -> Vec<FileId> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let found: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT file_id FROM retrieval_denylist WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .expect("read the denylist");
    tx.commit().await.expect("commit");
    found.into_iter().map(FileId::from).collect()
}

/// Which of these files a search would still treat as suppressed.
async fn still_suppressing(pool: &DbPool, tenant: TenantId, files: &[FileId]) -> Vec<FileId> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let found = denylist::suppressed(&mut tx, tenant, files).await.expect("suppressed");
    tx.commit().await.expect("commit");
    let mut found: Vec<FileId> = found.into_iter().collect();
    found.sort_by_key(FileId::as_uuid);
    found
}

/// Starting the scheduler is what makes the sweep happen.
///
/// The whole of `ENC-548`: `invalidation::sweep` was correct and had never been called by anything
/// but its own test, so a deployment's denylist grew forever. This asserts the wiring — run the
/// scheduler, and an expired suppression is gone afterwards.
///
/// The second file is the control, and it is not decoration. An assertion that a row disappeared
/// passes just as happily against a loop that deletes the whole table, and the failure mode of that
/// bug is a file becoming findable while its ACL change is still in force — the one thing
/// `plans/M3-DISCOVERY.md` D22 buys with the in-transaction denylist write.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn running_the_scheduler_lifts_expired_suppressions_and_nothing_else() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let now = Utc::now();

    let expired =
        suppressed_file(&db, &pool, alpha, owner, Some(now - chrono::Duration::minutes(5))).await;
    let in_force =
        suppressed_file(&db, &pool, alpha, owner, Some(now + chrono::Duration::hours(1))).await;

    // Both rows exist before the scheduler starts, or the assertion afterwards proves nothing.
    // Only one of them is *suppressing* — that is the point of the pair — so the precondition is
    // about the table and the postcondition is about both the table and what a search sees.
    let before = rows(&pool, alpha).await;
    assert!(before.contains(&expired) && before.contains(&in_force), "{before:?}");
    assert_eq!(
        still_suppressing(&pool, alpha, &[expired, in_force]).await,
        vec![in_force],
        "an expired row must already be suppressing nothing; expiry, not deletion, ends it"
    );

    let stop = Stop::new();
    let tenants = FixedTenants::new(stop.clone(), vec![alpha]);
    Scheduler::new(tenants).with_cadence(IMPATIENT).run(&pool, stop).await;

    let after = rows(&pool, alpha).await;
    assert!(!after.contains(&expired), "the scheduler never swept: the expired row is still there");
    assert!(
        after.contains(&in_force),
        "the scheduler deleted a suppression that is still in force, which makes a file findable \
         under an ACL that has changed"
    );
    assert_eq!(
        still_suppressing(&pool, alpha, &[expired, in_force]).await,
        vec![in_force],
        "what a search sees must be unchanged by the sweep"
    );

    drop(db);
}

/// `Scheduler::run` spawns the indexing loop, for every tenant, when a runner is configured.
///
/// The matching negative — that a scheduler with no runner does not run the pass — is **not**
/// asserted here, because at this level it would assert nothing: a runner that was never handed to
/// the scheduler cannot be called by it, so `seen().is_empty()` would pass against any
/// implementation whatsoever (`docs/12-TESTING.md §1.2`). That half is
/// `a_capability_that_is_absent_is_not_scheduled_and_one_that_is_present_is` in
/// `src/schedule.rs`, which reads it off `Scheduler::scheduled` where the decision actually lives.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn the_configured_indexing_pass_is_run_for_every_tenant() {
    let (db, fixtures, pool) = start().await;
    let tenants = vec![fixtures.alpha.id, fixtures.beta.id];

    let stop = Stop::new();
    let runner = Arc::new(RecordingRunner::default());
    Scheduler::new(FixedTenants::new(stop.clone(), tenants.clone()))
        .with_indexing(runner.clone())
        .with_cadence(IMPATIENT)
        .run(&pool, stop)
        .await;

    let seen = runner.seen();
    for tenant in &tenants {
        assert!(seen.contains(tenant), "the scheduler never indexed {tenant}");
    }

    drop(db);
}
