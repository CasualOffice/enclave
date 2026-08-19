//! The epoch reconciler, against a real PostgreSQL.
//!
//! # The shape every test here has to have
//!
//! A reconciler with a wrong join marks *everything*, and a reconciler that never fires marks
//! nothing. Both are one clause away from correct, and a test that asserts only "something was
//! marked" catches neither. So every test below names the file it expects to be marked and at least
//! one it expects to be left, and asserts the set rather than the count.
//!
//! # And the negative that matters more than any of them
//!
//! `the_reconciler_never_writes_a_suppression` is here to fail if somebody later "improves" this
//! loop into a safety mechanism. A stale `acl_epoch` is an over-permissive candidate, which the
//! post-filter drops (`docs/12-TESTING.md §4.3` S5); turning it into a denylist row would make S4
//! start passing because the reconciler ran, rather than because the denylist write lives inside
//! the ACL transaction (`plans/M3-DISCOVERY.md` D22).
//!
//! Ignored by default for the reason the rest of the workspace's database tests are: the properties
//! under test are PostgreSQL's (`plans/M0-FOUNDATIONS.md` D7). CI runs them with
//! `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId, UserId};
use enclave_db::DbPool;
use enclave_search::denylist;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::epoch::{self, ReconcilerConfig};
use enclave_worker::Stop;
use sqlx::PgConnection;
use uuid::Uuid;

async fn start(connections: u32) -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(connections).await.expect("application pool");
    (db, fixtures, pool)
}

/// An indexed file: the content spine, a version for the manifest to reference, and the manifest.
///
/// `acl_epoch` is stamped at the file's current `acl_revision`, which is what the indexer does on a
/// successful write. A test makes the file stale afterwards by moving the *file*, never the
/// manifest — the direction a permission change actually moves things.
async fn indexed_file(db: &TestDb, tenant: TenantId, owner: UserId, status: &str) -> FileId {
    let now = Utc::now();
    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, owner, now).await.expect("spine");

    let version = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 12, 'deadbeef', 'text/plain', 1, 0, 'AVAILABLE', $6, $7)",
    )
    .bind(version)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("objects/{version}"))
    .bind(Uuid::nil())
    .bind(owner.as_uuid())
    .bind(now)
    .execute(&mut admin)
    .await
    .expect("version");

    sqlx::query(
        "INSERT INTO index_manifests
           (tenant_id, file_id, version_id, index_version, extractor_version, chunker_version,
            embedding_model, acl_epoch, status, chunk_count, indexed_at, updated_at)
         SELECT $1, $2, $3, 1, 'x-1', 'c-1', 'm-1', f.acl_revision, $4, 3, $5, $5
           FROM files f WHERE f.tenant_id = $1 AND f.id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(version)
    .bind(status)
    .bind(now)
    .execute(&mut admin)
    .await
    .expect("manifest");

    spine.file
}

/// Moves a file's ACL on, the way a grant or a revocation does.
async fn move_the_acl(conn: &mut PgConnection, tenant: TenantId, file: FileId) {
    sqlx::query(
        "UPDATE files SET acl_revision = acl_revision + 1 WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .execute(conn)
    .await
    .expect("move the acl");
}

/// One manifest's status, epoch and last write, read through the application role.
async fn manifest(pool: &DbPool, tenant: TenantId, file: FileId) -> (String, i64, DateTime<Utc>) {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let row: (String, i64, DateTime<Utc>) = sqlx::query_as(
        "SELECT status, acl_epoch, updated_at FROM index_manifests
          WHERE tenant_id = $1 AND file_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("manifest");
    tx.commit().await.expect("commit");
    row
}

/// The reconciler marks the file whose ACL moved, and nothing else.
///
/// Four files, three of which must be left alone for three different reasons — an unchanged ACL, an
/// index write already in flight, and a trashed file. A reconciler that marked all four would pass
/// any assertion about the first one alone.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn it_marks_the_file_whose_acl_moved_and_leaves_the_ones_that_did_not() {
    let (db, fixtures, pool) = start(4).await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;

    let moved = indexed_file(&db, alpha, owner, "READY").await;
    let unchanged = indexed_file(&db, alpha, owner, "READY").await;
    let in_flight = indexed_file(&db, alpha, owner, "EMBEDDING").await;
    let trashed = indexed_file(&db, alpha, owner, "READY").await;

    let mut admin = db.connect().await.expect("admin connection");
    move_the_acl(&mut admin, alpha, moved).await;
    move_the_acl(&mut admin, alpha, in_flight).await;
    move_the_acl(&mut admin, alpha, trashed).await;
    sqlx::query("UPDATE files SET deleted_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(trashed.as_uuid())
        .execute(&mut admin)
        .await
        .expect("trash");

    let marked = epoch::reconcile_batch(&pool, alpha, 100).await.expect("reconcile");
    assert_eq!(marked, vec![moved], "the reconciler marked the wrong set");

    assert_eq!(manifest(&pool, alpha, moved).await.0, "STALE");
    assert_eq!(
        manifest(&pool, alpha, unchanged).await.0,
        "READY",
        "a file whose ACL never moved was queued for a rebuild"
    );
    assert_eq!(
        manifest(&pool, alpha, in_flight).await.0,
        "EMBEDDING",
        "an index write in flight was stamped over, discarding state the indexer owns"
    );
    assert_eq!(
        manifest(&pool, alpha, trashed).await.0,
        "READY",
        "a trashed file was queued for extraction and embedding it will never need"
    );

    // The epoch itself is untouched. Stamping it here would silence the trigger without doing the
    // rebuild — the manifest would claim to describe an ACL it has never seen.
    let (_, epoch_after, _) = manifest(&pool, alpha, moved).await;
    let revision: i64 =
        sqlx::query_scalar("SELECT acl_revision FROM files WHERE tenant_id = $1 AND id = $2")
            .bind(alpha.as_uuid())
            .bind(moved.as_uuid())
            .fetch_one(&mut admin)
            .await
            .expect("revision");
    assert_ne!(epoch_after, revision, "the reconciler stamped the epoch instead of the indexer");

    drop(db);
}

/// A run stopped between two batches leaves every manifest in a state the system already handles.
///
/// Three stale files, one per batch. After the first batch the other two are `READY` with a stale
/// epoch — which is not a half-finished state, it is the ordinary state of an index between a
/// permission change and the worker catching up, and the post-filter is what makes it safe.
///
/// Resuming needs no record of where the last pass stopped, and the second run must not touch what
/// the first one did: `updated_at` on the first file is the witness.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn an_interrupted_run_resumes_without_reprocessing_what_it_already_marked() {
    let (db, fixtures, pool) = start(4).await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;

    let mut files = Vec::new();
    let mut admin = db.connect().await.expect("admin connection");
    for _ in 0..3 {
        let file = indexed_file(&db, alpha, owner, "READY").await;
        move_the_acl(&mut admin, alpha, file).await;
        files.push(file);
    }

    // One batch, then the process dies.
    let first = epoch::reconcile_batch(&pool, alpha, 1).await.expect("first batch");
    assert_eq!(first.len(), 1, "the batch bound was not respected");
    let done = first[0];
    let (status, _, marked_at) = manifest(&pool, alpha, done).await;
    assert_eq!(status, "STALE");

    for file in files.iter().filter(|file| **file != done) {
        assert_eq!(
            manifest(&pool, alpha, *file).await.0,
            "READY",
            "the interrupted run left a manifest in a state nothing owns"
        );
    }

    // A raised stop returns before opening a transaction at all.
    let stop = Stop::new();
    stop.stop();
    let outcome = epoch::reconcile(&pool, &[alpha], ReconcilerConfig { batch_size: 1 }, &stop)
        .await
        .expect("stopped pass");
    assert!(outcome.stopped);
    assert_eq!(outcome.marked, 0);
    assert_eq!(outcome.batches, 0);

    // Resuming converges on the remaining two…
    let outcome =
        epoch::reconcile(&pool, &[alpha], ReconcilerConfig { batch_size: 1 }, &Stop::new())
            .await
            .expect("resumed pass");
    assert_eq!(outcome.marked, 2);
    for file in &files {
        assert_eq!(manifest(&pool, alpha, *file).await.0, "STALE");
    }

    // …and left the first one exactly as the interrupted run committed it.
    assert_eq!(
        manifest(&pool, alpha, done).await.2,
        marked_at,
        "a manifest was marked twice, so the predicate is not self-consuming"
    );

    drop(db);
}

/// The reconciler never suppresses anything, and never will without this test going red.
///
/// The tempting "safety" upgrade is to denylist a file whose epoch is stale. It would make S4 pass
/// for the wrong reason — because this loop ran, rather than because revocation writes the denylist
/// inside the ACL transaction — and it would make recall depend on housekeeping.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn the_reconciler_never_writes_a_suppression() {
    let (db, fixtures, pool) = start(4).await;
    let alpha = fixtures.alpha.id;

    let file = indexed_file(&db, alpha, fixtures.alpha.owner, "READY").await;
    let mut admin = db.connect().await.expect("admin connection");
    move_the_acl(&mut admin, alpha, file).await;

    let outcome = epoch::reconcile(&pool, &[alpha], ReconcilerConfig::default(), &Stop::new())
        .await
        .expect("reconcile");
    assert_eq!(outcome.marked, 1, "nothing is proven if the reconciler did no work");

    let mut tx = pool.begin(alpha).await.expect("begin");
    let suppressions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM retrieval_denylist WHERE tenant_id = $1")
            .bind(alpha.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count");
    let suppressed = denylist::suppressed(&mut tx, alpha, &[file]).await.expect("suppressed");
    tx.commit().await.expect("commit");

    assert_eq!(suppressions, 0, "the reconciler wrote a suppression");
    assert!(
        suppressed.is_empty(),
        "a stale epoch made a file unfindable; staleness is the post-filter's problem, not the \
         denylist's"
    );

    drop(db);
}

/// Two reconcilers running at once partition the work rather than duplicating it.
///
/// On a pool of eight, because `TestDb::pool` caps at two and a concurrency test on a pool of two
/// is a sequential test wearing `tokio::spawn`.
///
/// Two assertions, and the second is the one `SKIP LOCKED` is there for: the union covers every
/// stale file (nothing was dropped between them) and the intersection is empty (nothing was marked
/// twice). A deadlock would surface as an `Err` rather than a hang, so unwrapping is the assertion.
///
/// How the work *splits* is deliberately not asserted. It is genuinely racy — one reconciler
/// finishing before the other's first statement lands is a legitimate outcome — and a test that
/// demanded a split would be flaky about a property nobody needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn two_concurrent_reconcilers_partition_the_work() {
    const FILES: usize = 12;

    let (db, fixtures, pool) = start(8).await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let mut expected = Vec::new();
    for _ in 0..FILES {
        let file = indexed_file(&db, alpha, fixtures.alpha.owner, "READY").await;
        move_the_acl(&mut admin, alpha, file).await;
        expected.push(file);
    }

    async fn drain(pool: DbPool, tenant: TenantId) -> Vec<FileId> {
        let mut marked = Vec::new();
        loop {
            let batch = epoch::reconcile_batch(&pool, tenant, 3).await.expect("batch");
            if batch.is_empty() {
                return marked;
            }
            marked.extend(batch);
        }
    }

    let first = tokio::spawn(drain(pool.clone(), alpha));
    let second = tokio::spawn(drain(pool.clone(), alpha));
    let first = first.await.expect("no task may panic");
    let second = second.await.expect("no task may panic");

    let mut union: Vec<FileId> = first.iter().chain(second.iter()).copied().collect();
    union.sort_by_key(FileId::as_uuid);
    let mut distinct = union.clone();
    distinct.dedup();
    assert_eq!(union.len(), distinct.len(), "a manifest was marked by both reconcilers");

    expected.sort_by_key(FileId::as_uuid);
    assert_eq!(distinct, expected, "the two reconcilers did not cover every stale manifest");

    drop(db);
}
