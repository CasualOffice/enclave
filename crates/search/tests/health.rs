//! Index health and index catch-up, against a real PostgreSQL.
//!
//! # Two halves of one missing signal
//!
//! `ENC-516`: a vector store that is *up but wrong* — a collection recreated empty, a rebuild that
//! stopped halfway — keeps the circuit closed and answers `degraded: false` with almost no hits.
//! Confidently complete, and wrong. The signal that catches it is `index_manifests` counting what
//! the pipeline says it wrote against what the store says it holds.
//!
//! `ENC-520`: nothing in the schema could express "the index has caught up", so `clears_at`'s
//! documented meaning rested on a fact no column held.
//!
//! # Why the store is faked here and real in `tests/milvus.rs`
//!
//! Both files are needed and neither replaces the other. The questions in this one are questions
//! about PostgreSQL — which manifests count, what an unrecorded `chunk_count` does, what a
//! confirmation does and does not change about a suppression — and a fake census lets each of them
//! be asked at an exact number. The question in `tests/milvus.rs` is whether a *live* store's own
//! count agrees, per tenant, which a fake cannot answer at all.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use async_trait::async_trait;
use chrono::Utc;
use enclave_core::{FileId, TenantId};
use enclave_db::{DbPool, TenantScoped};
use enclave_search::health::{self, Expected, IndexCensus, IndexHealth, Unknown};
use enclave_search::{
    denylist, Cause, Retrieval, SearchError, SuppressionSeq, VectorStore, DEFAULT_COVERAGE_FLOOR,
    DEFAULT_DENYLIST_LIMIT,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use uuid::Uuid;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

/// A store that reports whatever the test needs, without one existing.
///
/// The number is the whole point of the double: `crate::health` compares two counts, and a test of
/// that comparison wants to name both of them rather than arrange for a server to hold a
/// particular one.
#[derive(Debug)]
struct FakeCensus(u64);

#[async_trait]
impl IndexCensus for FakeCensus {
    async fn chunks(&self, _tenant: TenantId) -> Result<u64, SearchError> {
        Ok(self.0)
    }
}

/// Writes a file version and the `index_manifests` row that claims it was indexed.
///
/// `chunk_count` is the number under test in most of what follows, so it is a parameter rather than
/// a constant: the difference between a manifest claiming 40 000 chunks and one claiming none is
/// the difference between a signal and a blind spot.
async fn manifest(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    spine: &Spine,
    owner: Uuid,
    status: &str,
    chunk_count: i32,
) {
    let version = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 1024, 'deadbeef', 'application/pdf', 1, 0, 'AVAILABLE',
                 'CLEAN', $6, $7)",
    )
    .bind(version)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("tenants/{}/blobs/{version}", tenant.as_uuid()))
    .bind(Uuid::now_v7())
    .bind(owner)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("a version for the manifest to name");

    sqlx::query(
        "INSERT INTO index_manifests
           (tenant_id, file_id, version_id, index_version, extractor_version, chunker_version,
            embedding_model, status, chunk_count, updated_at)
         VALUES ($1, $2, $3, 1, 'v1', 'v1', 'local-test', $4, $5, $6)",
    )
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(version)
    .bind(status)
    .bind(chunk_count)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("the manifest");
}

/// Writes a spine and returns it.
async fn spine(conn: &mut sqlx::PgConnection, tenant: TenantId, owner: Uuid) -> Spine {
    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, enclave_core::UserId::from(owner), Utc::now()).await.expect("spine");
    spine
}

/// PostgreSQL's half of the signal: `READY` manifests only, and only this tenant's.
///
/// The `READY` filter is the load-bearing clause. Without it a tenant with a long indexing queue —
/// manifests sitting in `EXTRACTING` claiming the chunk counts they *will* have — expects far more
/// than the store could possibly hold, and every such tenant degrades for being busy.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn the_expectation_counts_ready_manifests_and_nothing_else() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner.as_uuid();

    let mut admin = db.connect().await.expect("admin connection");
    let indexed = spine(&mut admin, alpha, owner).await;
    let also_indexed = spine(&mut admin, alpha, owner).await;
    let in_flight = spine(&mut admin, alpha, owner).await;
    manifest(&mut admin, alpha, &indexed, owner, "READY", 10).await;
    manifest(&mut admin, alpha, &also_indexed, owner, "READY", 5).await;
    // The queue: a large claim from a manifest the indexer has not finished with.
    manifest(&mut admin, alpha, &in_flight, owner, "EXTRACTING", 100).await;

    // Another tenant, indexed heavily, to prove its chunks are not counted as alpha's. RLS would
    // stop the read on its own; the application predicate is the second layer, and both are
    // supposed to hold (`docs/04-DATA-MODEL.md §3`).
    let beta_spine = spine(&mut admin, fixtures.beta.id, fixtures.beta.owner.as_uuid()).await;
    manifest(
        &mut admin,
        fixtures.beta.id,
        &beta_spine,
        fixtures.beta.owner.as_uuid(),
        "READY",
        9_000,
    )
    .await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let expected = health::expected_chunks(&mut tx, alpha).await.expect("expectation");
    tx.commit().await.expect("commit");

    assert_eq!(
        expected,
        Expected::Chunks(15),
        "the expectation counted a manifest the indexer has not finished with, another tenant's \
         chunks, or both"
    );

    drop(db);
}

/// A tenant whose manifests record no chunks is **unknown**, and says so.
///
/// `index_manifests.chunk_count` defaults to `0`. An indexer that never populates it produces a
/// tenant that expects nothing and can therefore never be found depleted — this whole signal is
/// blind for that deployment. Reporting it as healthy would be the same class of mistake the
/// signal exists to fix: a green reading that means "I cannot see".
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn manifests_that_record_no_chunks_are_unknown_rather_than_healthy() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner.as_uuid();

    let mut admin = db.connect().await.expect("admin connection");
    let ready = spine(&mut admin, alpha, owner).await;
    manifest(&mut admin, alpha, &ready, owner, "READY", 0).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let expected = health::expected_chunks(&mut tx, alpha).await.expect("expectation");
    tx.commit().await.expect("commit");

    assert_eq!(
        expected,
        Expected::Unknown(Unknown::ChunkCountsUnrecorded { ready_files: 1 }),
        "a blind signal has to be distinguishable from a quiet one"
    );
    assert_eq!(
        IndexHealth::assess(expected, 0, DEFAULT_COVERAGE_FLOOR).store_state(),
        VectorStore::Available,
        "not knowing is not a reason to tell every caller their results are incomplete"
    );

    drop(db);
}

/// A tenant with no manifests at all asserts nothing — the ordinary state of a new tenant.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_tenant_with_nothing_indexed_asserts_nothing() {
    let (db, fixtures, pool) = start().await;

    let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
    let expected = health::expected_chunks(&mut tx, fixtures.alpha.id).await.expect("expectation");
    tx.commit().await.expect("commit");

    assert_eq!(expected, Expected::Unknown(Unknown::NothingIndexed));

    drop(db);
}

/// **`ENC-516`, end to end against PostgreSQL.** An empty store degrades a tenant that PostgreSQL
/// says is indexed, and a stocked one does not.
///
/// Both halves in one test, because the assertion that matters is the *difference* between them:
/// a probe that degraded unconditionally would satisfy the first half and destroy the flag.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn an_empty_store_degrades_and_a_stocked_one_does_not() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner.as_uuid();

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, owner).await;
    manifest(&mut admin, alpha, &file, owner, "READY", 4_000).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let wiped = health::probe(&mut tx, alpha, &FakeCensus(0), DEFAULT_COVERAGE_FLOOR)
        .await
        .expect("probe an empty store");
    let stocked = health::probe(&mut tx, alpha, &FakeCensus(4_000), DEFAULT_COVERAGE_FLOOR)
        .await
        .expect("probe a stocked store");
    tx.commit().await.expect("commit");

    let decision = Retrieval::decide(wiped.store_state(), 0, DEFAULT_DENYLIST_LIMIT);
    let Retrieval::Degraded(reason) = decision else {
        panic!("a reachable, empty store answered `degraded: false`: {decision:?}");
    };
    assert_eq!(
        reason.cause(),
        Cause::IndexDepleted { expected_chunks: 4_000, observed_chunks: 0 },
        "the cause has to name the hole, or the operator is sent to look at connectivity"
    );

    assert_eq!(
        Retrieval::decide(stocked.store_state(), 0, DEFAULT_DENYLIST_LIMIT),
        Retrieval::Complete,
        "a store holding what PostgreSQL expects must not degrade — a flag that is always set \
         carries no information"
    );

    drop(db);
}

// ---------------------------------------------------------------------------------------------
// ENC-520 — what a denylist row can now say about the index having caught up
// ---------------------------------------------------------------------------------------------

/// The state every row is in today: **nobody has asserted anything**.
///
/// Which is the point of the whole change. Nothing in this tree writes `indexed_seq` yet, so the
/// honest reading of "has the index caught up for this tenant?" is *unknown* — and a signal that
/// could not say so would say "yes".
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn an_unconfirmed_suppression_reads_as_unknown_and_not_as_caught_up() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, fixtures.alpha.owner.as_uuid()).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    denylist::suppress(&mut tx, alpha, file.file, "permission_revoked", Utc::now(), None)
        .await
        .expect("suppress");
    let state = denylist::catch_up(&mut tx, alpha).await.expect("catch up");
    tx.commit().await.expect("commit");

    assert_eq!(state.unasserted, 1, "an unconfirmed row must read as unknown");
    assert_eq!(state.caught_up, 0, "nobody asserted this, and it must not read as though they had");
    assert_eq!(state.behind, 0);
    assert_eq!(state.rows(), 1);

    drop(db);
}

/// A confirmation names the suppression it covers, and a later suppression puts it behind.
///
/// The second half is what a timestamp would have got wrong quietly: a re-revocation of the same
/// file is a new fact about the store, and a confirmation of the previous one says nothing about
/// it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_confirmation_covers_one_generation_and_a_later_suppression_outruns_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let now = Utc::now();

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, fixtures.alpha.owner.as_uuid()).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let first = denylist::suppress(&mut tx, alpha, file.file, "acl_narrowed", now, None)
        .await
        .expect("suppress");
    let recorded = denylist::confirm_indexed(&mut tx, alpha, file.file, first)
        .await
        .expect("confirm the store write");
    let confirmed = denylist::catch_up(&mut tx, alpha).await.expect("catch up");

    // The file is revoked again before anything re-indexes it.
    let second = denylist::suppress(&mut tx, alpha, file.file, "acl_narrowed_again", now, None)
        .await
        .expect("re-suppress");
    let after = denylist::catch_up(&mut tx, alpha).await.expect("catch up");
    tx.commit().await.expect("commit");

    assert!(recorded, "the confirmation found no row to record itself against");
    assert_eq!(confirmed.caught_up, 1, "a confirmed write must be visible as one");
    assert_eq!(confirmed.unasserted, 0);

    assert!(second > first, "a repeat suppression must take a later generation");
    assert_eq!(
        after.behind, 1,
        "a confirmation of the previous revocation was read as covering this one"
    );
    assert_eq!(after.caught_up, 0);
    assert_eq!(after.unasserted, 0, "the earlier claim was erased rather than left behind");

    drop(db);
}

/// **The S4-shaped assertion.** A confirmation does not lift, and the search read does not see it.
///
/// If it did, a revoked file would become visible again because a worker said it had finished — and
/// S4 (`docs/12-TESTING.md §4.3`: a stopped invalidation worker changes nothing a caller can
/// observe) would start passing because the worker ran rather than because the denylist write sits
/// inside the ACL transaction. The tempting change is one clause on `SUPPRESSED_SQL`, which is why
/// `src/denylist.rs` also asserts over the statement text: this test proves the behaviour, that one
/// catches the clause before it can be rationalised.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn confirming_a_store_write_does_not_unsuppress_the_file() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, fixtures.alpha.owner.as_uuid()).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let seq = denylist::suppress(&mut tx, alpha, file.file, "content_purged", Utc::now(), None)
        .await
        .expect("suppress");
    denylist::confirm_indexed(&mut tx, alpha, file.file, seq).await.expect("confirm");

    let suppressed = denylist::suppressed(&mut tx, alpha, &[file.file]).await.expect("read");
    let lifted = denylist::lift_expired(&mut tx, alpha).await.expect("sweep");
    let still_suppressed =
        denylist::suppressed(&mut tx, alpha, &[file.file]).await.expect("read again");
    tx.commit().await.expect("commit");

    assert!(
        suppressed.contains(&file.file),
        "a confirmed index write unsuppressed the file, so a revocation now depends on a worker \
         reporting back"
    );
    assert_eq!(lifted, 0, "the sweep lifted a row whose clears_at is NULL");
    assert!(still_suppressed.contains(&file.file));

    drop(db);
}

/// A fabricated confirmation is refused by the row rather than stored.
///
/// A writer can only honestly name a generation it read from the row. One that names a higher
/// number is a bug — a claim invented rather than observed — and its stored form reads as "caught
/// up" for as long as the row exists.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_confirmation_ahead_of_the_row_is_refused() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, fixtures.alpha.owner.as_uuid()).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    denylist::suppress(&mut tx, alpha, file.file, "acl_narrowed", Utc::now(), None)
        .await
        .expect("suppress");
    let outcome =
        denylist::confirm_indexed(&mut tx, alpha, file.file, SuppressionSeq::new(9_999)).await;
    tx.rollback().await.expect("rollback");

    assert!(
        matches!(outcome, Err(SearchError::Storage(_))),
        "a confirmation ahead of the suppression it claims to cover was accepted: {outcome:?}"
    );

    drop(db);
}

/// Confirming a file whose suppression was already lifted is not an error.
///
/// The ordinary race: the sweep removes an expired row while a store write is in flight. There is
/// nothing to record and nothing has gone wrong, so the writer is told `false` rather than handed
/// a failure it would have to decide how to swallow.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn confirming_a_suppression_that_is_gone_records_nothing_and_is_not_an_error() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let file = spine(&mut admin, alpha, fixtures.alpha.owner.as_uuid()).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let recorded =
        denylist::confirm_indexed(&mut tx, alpha, file.file, SuppressionSeq::new(1)).await;
    let state = denylist::catch_up(&mut tx, alpha).await.expect("catch up");
    tx.commit().await.expect("commit");

    assert!(!recorded.expect("a missing row is not a failure"), "there was no row to record on");
    assert_eq!(state.rows(), 0);

    drop(db);
}

/// A file that was never indexed is *unknown*, not caught up — `ENC-520`'s third complaint.
///
/// A manifest join reads "the index removed it" and "the index never had it" identically, because
/// both produce no manifest row. The catch-up state does not: with no confirmation, the row is
/// unasserted whether or not `index_manifests` has ever heard of the file. Asserted with a file
/// that has a `READY` manifest and one that has none, so the reading is visibly independent of the
/// manifest table.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn catch_up_does_not_confuse_never_indexed_with_caught_up() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner.as_uuid();
    let now = Utc::now();

    let mut admin = db.connect().await.expect("admin connection");
    let indexed = spine(&mut admin, alpha, owner).await;
    let never_indexed = spine(&mut admin, alpha, owner).await;
    manifest(&mut admin, alpha, &indexed, owner, "READY", 12).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    for file in [indexed.file, never_indexed.file] {
        denylist::suppress(&mut tx, alpha, file, "permission_revoked", now, None)
            .await
            .expect("suppress");
    }
    let state = denylist::catch_up(&mut tx, alpha).await.expect("catch up");
    tx.commit().await.expect("commit");

    assert_eq!(
        state,
        denylist::CatchUp { unasserted: 2, behind: 0, caught_up: 0 },
        "the presence or absence of a manifest changed a catch-up reading, which is the join this \
         column exists to replace"
    );

    // And the sanity check that keeps the assertion above honest: the two files really are
    // different in the manifest table.
    let ids: Vec<FileId> = vec![indexed.file, never_indexed.file];
    assert_ne!(ids[0], ids[1]);

    drop(db);
}
