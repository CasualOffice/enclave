//! The manifest state machine against a real database.
//!
//! `crates/indexing/src/manifest.rs` carries structural tests — no public way to set a status, no
//! working state that reaches a terminal one, no status string the migration does not permit. None
//! of those execute a line of SQL. This file does.
//!
//! That split matters here more than usual: the interesting properties of this module are in the
//! SQL itself. `ON CONFLICT` deciding whether a retry keeps its `attempts`, `SKIP LOCKED` deciding
//! whether two workers partition or collide, and a `CASE` deciding whether `indexed_at` is set are
//! all invisible to a type checker and all wrong in ways that read as "indexing is a bit slow" or
//! "that file just never finished".
//!
//! `#[ignore]`d because they need PostgreSQL; CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::num::NonZeroU32;

use chrono::Utc;
use enclave_core::{FileId, TenantId, UserId, VersionId};
use enclave_indexing::{
    claim, enqueue, record, start, BuildVersions, ChunkerVersion, ExtractorVersion, ManifestStatus,
    Outcome, WorkingState,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test/1");
const EXTRACTOR: ExtractorVersion = ExtractorVersion::new("test/1");

fn versions() -> BuildVersions<'static> {
    BuildVersions { extractor: EXTRACTOR, chunker: CHUNKER, embedding_model: "" }
}

fn ready(chunks: u32) -> Outcome {
    Outcome::Ready { chunks: NonZeroU32::new(chunks).expect("a non-zero chunk count") }
}

async fn start_db() -> (TestDb, Fixtures) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    (db, fixtures)
}

/// A file with a version, so a manifest has something to point at.
async fn a_file(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> (FileId, VersionId) {
    let now = Utc::now();
    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, owner, now).await.expect("spine");
    let version = new_version(&mut *conn, tenant, spine.file, owner, 1).await;
    (spine.file, version)
}

async fn new_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    owner: UserId,
    major: i32,
) -> VersionId {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 12, 'deadbeef', 'text/plain', $6, 0, 'AVAILABLE', $7, $8)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(format!("objects/{id}"))
    .bind(Uuid::nil())
    .bind(major)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("version");
    VersionId::from(id)
}

/// `(status, chunk_count, attempts, failure_reason, indexed_at is null)`.
async fn manifest(
    conn: &mut PgConnection,
    file: FileId,
) -> (String, i32, i32, Option<String>, bool) {
    let row = sqlx::query(
        "SELECT status, chunk_count, attempts, failure_reason, indexed_at IS NULL AS unindexed
           FROM index_manifests WHERE file_id = $1",
    )
    .bind(file.as_uuid())
    .fetch_one(&mut *conn)
    .await
    .expect("read the manifest");

    (
        row.try_get("status").expect("status"),
        row.try_get("chunk_count").expect("chunk_count"),
        row.try_get("attempts").expect("attempts"),
        row.try_get("failure_reason").expect("failure_reason"),
        row.try_get("unindexed").expect("unindexed"),
    )
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_version_moves_from_enqueued_to_ready_and_records_when_it_became_searchable() {
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");
    assert_eq!(manifest(&mut conn, file).await.0, ManifestStatus::Pending.as_str());

    let claimed = claim(&mut conn, alpha, 10).await.expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].file_id, file);
    assert_eq!(manifest(&mut conn, file).await.0, ManifestStatus::Extracting.as_str());

    start(&mut conn, alpha, file, WorkingState::Embedding).await.expect("embedding");
    assert_eq!(manifest(&mut conn, file).await.0, ManifestStatus::Embedding.as_str());

    record(&mut conn, alpha, file, version, versions(), &ready(4)).await.expect("record");

    let (status, chunks, attempts, reason, unindexed) = manifest(&mut conn, file).await;
    assert_eq!(status, ManifestStatus::Ready.as_str());
    assert_eq!(chunks, 4, "the coverage check sums this column to decide the store is depleted");
    assert_eq!(attempts, 0, "a success is not an attempt to count");
    assert_eq!(reason, None);
    assert!(!unindexed, "a READY manifest must record when its text became searchable");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_failure_counts_the_attempt_and_leaves_the_file_claimable_again() {
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");
    claim(&mut conn, alpha, 10).await.expect("claim");

    let textless = enclave_indexing::TextlessSource {
        media_type: "application/pdf".to_owned(),
        pages_without_text: vec![1],
    };
    record(&mut conn, alpha, file, version, versions(), &Outcome::NoText(textless))
        .await
        .expect("record");

    let (status, chunks, attempts, reason, unindexed) = manifest(&mut conn, file).await;
    assert_eq!(status, ManifestStatus::Failed.as_str());
    assert_eq!(chunks, 0, "a failure must not leave a chunk count from a previous run");
    assert_eq!(attempts, 1);
    assert_eq!(reason.as_deref(), Some("no_text_extracted"));
    assert!(unindexed, "a file that never indexed must not carry an indexed_at");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn re_enqueuing_the_same_version_keeps_the_failures_it_has_already_had() {
    // The idempotence that matters. Indexing runs off an at-least-once outbox, so a redelivery is
    // ordinary — and if it reset `attempts`, a document that can never index would look like a
    // first-time failure forever and nothing would ever escalate it.
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");
    claim(&mut conn, alpha, 10).await.expect("claim");
    record(&mut conn, alpha, file, version, versions(), &Outcome::Unsupported)
        .await
        .expect("record");
    assert_eq!(manifest(&mut conn, file).await.2, 1);

    enqueue(&mut conn, alpha, file, version).await.expect("redelivery");

    let (status, _, attempts, _, _) = manifest(&mut conn, file).await;
    assert_eq!(attempts, 1, "a redelivery of the same version reset the failure history");
    assert_eq!(
        status,
        ManifestStatus::Skipped.as_str(),
        "a redelivery of the same version reopened a terminal row"
    );

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_new_version_reopens_the_file_and_forgets_the_old_version_s_failures() {
    // The other half of the same `ON CONFLICT`: a *different* version is different bytes, so the
    // previous version's failure says nothing about it. A row that stayed FAILED here would mean a
    // corrected upload of a document that once failed to parse is never indexed again.
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, first) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, first).await.expect("enqueue");
    claim(&mut conn, alpha, 10).await.expect("claim");
    record(&mut conn, alpha, file, first, versions(), &Outcome::Unsupported).await.expect("record");

    let second = new_version(&mut conn, alpha, file, fixtures.alpha.owner, 2).await;
    enqueue(&mut conn, alpha, file, second).await.expect("second version");

    let (status, _, attempts, reason, _) = manifest(&mut conn, file).await;
    assert_eq!(status, ManifestStatus::Pending.as_str(), "a new version must be indexable again");
    assert_eq!(attempts, 0, "the new version inherited the old one's failure count");
    assert_eq!(reason, None, "the new version inherited the old one's failure reason");

    assert_eq!(claim(&mut conn, alpha, 10).await.expect("claim").len(), 1);

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_terminal_row_is_never_claimed_again() {
    // `SKIPPED` is terminal but is not `READY`, and a claim predicate that only excluded `READY`
    // would re-claim every unsupported file on every pass — a worker spinning forever on files it
    // has already correctly decided about, which reads as load rather than as a bug.
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");
    claim(&mut conn, alpha, 10).await.expect("claim");
    record(&mut conn, alpha, file, version, versions(), &Outcome::Unsupported)
        .await
        .expect("record");

    assert!(
        claim(&mut conn, alpha, 10).await.expect("claim").is_empty(),
        "a file already decided about was handed out again"
    );

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_claim_never_crosses_a_tenant() {
    // Not the isolation control — RLS is — but the claim is a cross-tenant read shaped exactly like
    // the ones that leak, so it is asserted rather than assumed.
    let (db, fixtures) = start_db().await;
    let mut conn = db.connect().await.expect("connection");

    let (alpha_file, alpha_version) =
        a_file(&mut conn, fixtures.alpha.id, fixtures.alpha.owner).await;
    enqueue(&mut conn, fixtures.alpha.id, alpha_file, alpha_version).await.expect("alpha");

    let claimed = claim(&mut conn, fixtures.beta.id, 10).await.expect("beta claim");
    assert!(claimed.is_empty(), "beta claimed alpha's file: {claimed:?}");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_late_worker_cannot_drag_a_finished_row_back_into_a_working_state() {
    // The crash-and-resume case: a worker that finished, stalled, and then reported a working
    // state it had computed before. Without the guard in START_SQL the row leaves READY, the
    // coverage check stops counting its chunks, and the file quietly drops out of search.
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");
    claim(&mut conn, alpha, 10).await.expect("claim");
    record(&mut conn, alpha, file, version, versions(), &ready(2)).await.expect("record");

    start(&mut conn, alpha, file, WorkingState::Indexing).await.expect("a late transition");

    assert_eq!(
        manifest(&mut conn, file).await.0,
        ManifestStatus::Ready.as_str(),
        "a late working-state transition unpicked a finished manifest"
    );

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn recording_against_a_superseded_version_changes_nothing() {
    // A worker holding version 1 finishes after version 2 was enqueued. Its result describes bytes
    // the file no longer has, so it must not land — and in particular must not mark the row READY,
    // which would leave the new version unindexed while the manifest claimed otherwise.
    let (db, fixtures) = start_db().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, first) = a_file(&mut conn, alpha, fixtures.alpha.owner).await;

    enqueue(&mut conn, alpha, file, first).await.expect("enqueue");
    let second = new_version(&mut conn, alpha, file, fixtures.alpha.owner, 2).await;
    enqueue(&mut conn, alpha, file, second).await.expect("second version");

    record(&mut conn, alpha, file, first, versions(), &ready(9)).await.expect("stale record");

    let (status, chunks, _, _, _) = manifest(&mut conn, file).await;
    assert_eq!(
        status,
        ManifestStatus::Pending.as_str(),
        "a result for a superseded version marked the current one indexed"
    );
    assert_eq!(chunks, 0, "a superseded run's chunk count was recorded against the new version");

    drop(db);
}
