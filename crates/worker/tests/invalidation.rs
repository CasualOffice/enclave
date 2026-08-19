//! The invalidation sweep, against a real PostgreSQL.
//!
//! # What these tests are actually about
//!
//! Not "the DELETE works". The sweep's whole claim is that running it, not running it, running it
//! twice, or being killed halfway through are *indistinguishable to a caller* — because expiry, not
//! deletion, is what ends a suppression (`plans/M3-DISCOVERY.md` D22, `docs/12-TESTING.md §4.3` S4).
//!
//! So every assertion below about a row that was left behind is paired with an assertion about
//! `enclave_search::denylist::suppressed` — the query a search actually runs. A test that only
//! counted rows would pass just as happily for a sweep that had quietly become load-bearing.
//!
//! # Why they are ignored by default
//!
//! They need a live PostgreSQL with migrations 0001–0011, and the properties under test — row
//! locking, advisory locks, transaction clocks — are properties of PostgreSQL that a mock would
//! only assert about itself (`plans/M0-FOUNDATIONS.md` D7). CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use enclave_core::{FileId, TenantId};
use enclave_db::DbPool;
use enclave_search::denylist;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::invalidation::{self, TenantSweep, SWEEP_LOCK_CLASS};
use enclave_worker::Stop;
use uuid::Uuid;

async fn start(connections: u32) -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(connections).await.expect("application pool");
    (db, fixtures, pool)
}

/// Builds a file and suppresses it, in the tenant, with the given expiry.
async fn suppressed_file(
    db: &TestDb,
    pool: &DbPool,
    tenant: TenantId,
    owner: enclave_core::UserId,
    clears_at: Option<DateTime<Utc>>,
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
    let found: Vec<Uuid> =
        sqlx::query_scalar("SELECT file_id FROM retrieval_denylist WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .expect("read the denylist");
    tx.commit().await.expect("commit");
    found.into_iter().map(FileId::from).collect()
}

/// Which of these files a search would currently treat as suppressed.
async fn still_suppressing(pool: &DbPool, tenant: TenantId, files: &[FileId]) -> Vec<FileId> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let found = denylist::suppressed(&mut tx, tenant, files).await.expect("suppressed");
    tx.commit().await.expect("commit");
    let mut found: Vec<FileId> = found.into_iter().collect();
    found.sort_by_key(FileId::as_uuid);
    found
}

/// The sweep lifts what has expired and leaves what has not — including what never expires.
///
/// The third file is the one that matters most: `clears_at IS NULL` is the schema's "the index is
/// not known to have caught up", and it is the case a sweep that decided liftability for itself
/// would get wrong. A sweep that lifted all three would satisfy any assertion about the first.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn a_sweep_lifts_what_expired_and_leaves_what_did_not() {
    let (db, fixtures, pool) = start(4).await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let now = Utc::now();

    let expired = suppressed_file(&db, &pool, alpha, owner, Some(now - Duration::minutes(5))).await;
    let pending = suppressed_file(&db, &pool, alpha, owner, Some(now + Duration::hours(1))).await;
    let forever = suppressed_file(&db, &pool, alpha, owner, None).await;

    let swept = invalidation::sweep_tenant(&pool, alpha).await.expect("sweep");
    assert_eq!(swept, TenantSweep::Swept(1), "the sweep took the wrong number of rows");

    let remaining = rows(&pool, alpha).await;
    assert!(!remaining.contains(&expired), "an expired suppression survived the sweep");
    assert!(remaining.contains(&pending), "a suppression still in force was lifted early");
    assert!(remaining.contains(&forever), "a suppression with no expiry was lifted");

    // And the rows that survived are still doing their job, which is the assertion a row count
    // cannot make.
    let mut expected = vec![pending, forever];
    expected.sort_by_key(FileId::as_uuid);
    assert_eq!(still_suppressing(&pool, alpha, &[expired, pending, forever]).await, expected);

    // Running it again is a no-op rather than an error: the predicate is self-consuming.
    assert_eq!(
        invalidation::sweep_tenant(&pool, alpha).await.expect("second sweep"),
        TenantSweep::Swept(0)
    );

    drop(db);
}

/// Stopping between two tenants leaves the unswept one **correct**, not merely eventually correct.
///
/// The interesting assertion is the middle one: `tenant-beta`'s row is still sitting there, and a
/// search already ignores it. Nothing is waiting for housekeeping to become right — which is the
/// S4 property pointed the other way, and the reason the sweep needs no crash recovery at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn stopping_between_two_tenants_leaves_the_unswept_one_already_correct() {
    let (db, fixtures, pool) = start(4).await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let expiry = Some(Utc::now() - Duration::minutes(5));

    let in_alpha = suppressed_file(&db, &pool, alpha, fixtures.alpha.owner, expiry).await;
    let in_beta = suppressed_file(&db, &pool, beta, fixtures.beta.owner, expiry).await;

    // The first batch, and then the process dies. Sweeping one tenant of two is exactly what a
    // killed worker leaves behind.
    let outcome = invalidation::sweep(&pool, &[alpha], &Stop::new()).await.expect("first batch");
    assert_eq!(outcome.lifted, 1);
    assert_eq!(outcome.tenants_swept, 1);
    assert!(rows(&pool, alpha).await.is_empty());

    assert_eq!(rows(&pool, beta).await, vec![in_beta], "beta must be genuinely unswept");
    assert!(
        still_suppressing(&pool, beta, &[in_beta]).await.is_empty(),
        "an expired row waited for the sweep to stop suppressing — the file was unfindable for as \
         long as the worker was down"
    );
    assert!(
        still_suppressing(&pool, alpha, &[in_alpha]).await.is_empty(),
        "the swept tenant must reach the same answer, by a different route"
    );

    // A raised stop returns before opening a transaction at all.
    let stop = Stop::new();
    stop.stop();
    let outcome = invalidation::sweep(&pool, &[beta], &stop).await.expect("stopped pass");
    assert!(outcome.stopped);
    assert_eq!(outcome.tenants_swept, 0);
    assert_eq!(rows(&pool, beta).await, vec![in_beta], "a stopped pass wrote something");

    // Resuming converges, and needed no record of where the last pass got to.
    let outcome = invalidation::sweep(&pool, &[beta], &Stop::new()).await.expect("resumed pass");
    assert_eq!(outcome.lifted, 1);
    assert!(rows(&pool, beta).await.is_empty());

    drop(db);
}

/// A tenant another sweep is inside is skipped immediately, not queued behind it.
///
/// Deterministic rather than racy: the lock is held by a transaction this test owns, so the
/// exclusion is asserted instead of hoped for. The second half — that releasing it makes the tenant
/// immediately available — is what proves the lock is transaction-scoped and cannot be leaked by a
/// worker that dies holding it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn a_tenant_another_sweep_is_inside_is_skipped_rather_than_queued() {
    let (db, fixtures, pool) = start(4).await;
    let alpha = fixtures.alpha.id;
    let file = suppressed_file(
        &db,
        &pool,
        alpha,
        fixtures.alpha.owner,
        Some(Utc::now() - Duration::minutes(5)),
    )
    .await;

    let mut holder = pool.begin(alpha).await.expect("begin");
    let (held,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1, $2)")
        .bind(SWEEP_LOCK_CLASS)
        .bind(invalidation::tenant_lock_key(alpha))
        .fetch_one(&mut *holder)
        .await
        .expect("take the tenant lock");
    assert!(held, "the test could not take the lock it is about");

    assert_eq!(
        invalidation::sweep_tenant(&pool, alpha).await.expect("contended sweep"),
        TenantSweep::Contended,
        "a second sweep entered a tenant another sweep was already inside"
    );
    assert_eq!(rows(&pool, alpha).await, vec![file], "the contended sweep still deleted something");

    // A worker that dies mid-sweep ends its transaction, and the lock goes with it.
    holder.rollback().await.expect("release");
    assert_eq!(
        invalidation::sweep_tenant(&pool, alpha).await.expect("sweep"),
        TenantSweep::Swept(1),
        "the tenant stayed locked after the holder's transaction ended"
    );

    drop(db);
}

/// Two sweeps running at once lift every row exactly once, and neither deadlocks.
///
/// On a pool of eight, because `TestDb::pool` caps at two and a concurrency test on a pool of two
/// is a sequential test wearing `tokio::spawn` — the harness says so in as many words.
///
/// The assertion is the sum, not the split: which sweep gets which tenant is genuinely racy and
/// asserting it would make the test flaky for a property nobody needs. What must hold is that the
/// total is exactly the number of expired rows — a double-processed row would push it over, a
/// tenant both sweeps skipped would leave it short.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn two_concurrent_sweeps_neither_double_process_nor_deadlock() {
    const PER_TENANT: usize = 4;

    let (db, fixtures, pool) = start(8).await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let expiry = Some(Utc::now() - Duration::minutes(5));

    for _ in 0..PER_TENANT {
        suppressed_file(&db, &pool, alpha, fixtures.alpha.owner, expiry).await;
        suppressed_file(&db, &pool, beta, fixtures.beta.owner, expiry).await;
    }

    let tenants = vec![alpha, beta];
    let first = tokio::spawn({
        let (pool, tenants) = (pool.clone(), tenants.clone());
        async move { invalidation::sweep(&pool, &tenants, &Stop::new()).await }
    });
    let second = tokio::spawn({
        let (pool, tenants) = (pool.clone(), tenants.clone());
        async move { invalidation::sweep(&pool, &tenants, &Stop::new()).await }
    });

    // A deadlock surfaces here as an `Err` from PostgreSQL, not as a hang: the deadlock detector
    // aborts one side. Unwrapping both is the assertion.
    let first = first.await.expect("no task may panic").expect("the first sweep failed");
    let second = second.await.expect("no task may panic").expect("the second sweep failed");

    assert_eq!(
        first.lifted + second.lifted,
        (PER_TENANT * 2) as u64,
        "every expired row must be lifted exactly once across both sweeps"
    );
    assert_eq!(
        first.tenants_swept + first.tenants_contended,
        2,
        "every tenant must be accounted for, swept or skipped"
    );
    assert!(rows(&pool, alpha).await.is_empty());
    assert!(rows(&pool, beta).await.is_empty());

    drop(db);
}
