//! `chunk_text` — what a write leaves behind, against a real PostgreSQL.
//!
//! # What these are about
//!
//! The retrieval half of `ENC-515` lives in `crates/search/tests/lexical_content.rs`. This file is
//! about the *store*, and about the one property that is easy to get wrong in a way no query would
//! reveal: a write must **replace** a file's text, not add to it.
//!
//! Indexing runs off an at-least-once outbox, so a retry is the ordinary case, and a file is
//! re-indexed whenever a new version lands. Both are the routine path, not the exception, and an
//! implementation that only ever inserted would pass every "can search find it" test ever written
//! while accumulating the wording of every version a document has ever had — matchable, attributed
//! to a file that no longer contains it, and invisible to the post-filter because the caller is
//! genuinely authorised on the file.
//!
//! Ignored by default: they need a live PostgreSQL with migrations `0001`–`0013`. CI runs them with
//! `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{FileId, TenantId, UserId, VersionId};
use enclave_db::TenantScoped;
use enclave_indexing::{
    write_chunks, Chunk, ChunkBudget, Chunker, ChunkerVersion, Coordinates, Segment, SegmentKind,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test-1");

async fn start() -> (TestDb, Fixtures) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    (db, fixtures)
}

/// Chunks as the pipeline would produce them: through the real chunker, so the ids under test are
/// the deterministic ones `ENC-513` specified rather than values invented here.
fn chunks_of(version: VersionId, paragraphs: &[&str]) -> Vec<Chunk> {
    let segments: Vec<Segment> = paragraphs
        .iter()
        .map(|text| Segment {
            kind: SegmentKind::Paragraph,
            text: (*text).to_owned(),
            coordinates: Coordinates::none(),
        })
        .collect();
    // A tight budget so each paragraph stays its own chunk; the merge rules are `chunking.rs`'s
    // subject, not this file's.
    let chunker = Chunker::new(CHUNKER, ChunkBudget { target_chars: 1, ..ChunkBudget::DEFAULT });
    chunker.chunk(version, &segments)
}

/// A file with a version to hang chunks off.
async fn indexed_file(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
) -> (FileId, VersionId) {
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

/// Every chunk row of a file, ordered, as `(version_id, ordinal, text)`.
async fn stored(conn: &mut PgConnection, file: FileId) -> Vec<(Uuid, i64, String)> {
    sqlx::query(
        "SELECT version_id, ordinal, text FROM chunk_text WHERE file_id = $1 ORDER BY ordinal",
    )
    .bind(file.as_uuid())
    .fetch_all(&mut *conn)
    .await
    .expect("read chunk_text")
    .iter()
    .map(|row| {
        (
            row.try_get::<Uuid, _>("version_id").expect("version_id"),
            row.try_get::<i64, _>("ordinal").expect("ordinal"),
            row.try_get::<String, _>("text").expect("text"),
        )
    })
    .collect()
}

/// A retry writes the same rows again, and leaves the same number of them.
///
/// The failure this excludes is not an error anybody would see: a plain `INSERT` would raise a
/// duplicate-key violation and be noticed, but an `INSERT ... ON CONFLICT DO NOTHING` — the obvious
/// "make the retry safe" edit — would silently keep the *first* run's text forever, so a re-index
/// after a fix would leave the broken extraction in place.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_retry_of_the_same_version_updates_its_rows_rather_than_adding_more() {
    let (db, fixtures) = start().await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");
    let (file, version) = indexed_file(&mut admin, alpha, fixtures.alpha.owner).await;

    let first = chunks_of(version, &["alpha paragraph", "beta paragraph"]);
    let write =
        write_chunks(&mut admin, alpha, file, version, CHUNKER, &first).await.expect("first write");
    assert_eq!(write.written, 2);
    assert_eq!(write.pruned, 0, "there was nothing to prune on a first write");

    // The same version re-extracted, one paragraph corrected. Same ids, because the ids are a
    // function of the version, the chunker and the ordinal.
    let second = chunks_of(version, &["alpha paragraph", "beta paragraph corrected"]);
    let write = write_chunks(&mut admin, alpha, file, version, CHUNKER, &second)
        .await
        .expect("second write");
    assert_eq!(write.written, 2, "a retry must touch the same two rows");
    assert_eq!(write.pruned, 0);

    let rows = stored(&mut admin, file).await;
    assert_eq!(rows.len(), 2, "a retry duplicated the document's text: {rows:?}");
    assert_eq!(
        rows[1].2, "beta paragraph corrected",
        "the retry left the first run's text in place"
    );

    drop(db);
}

/// A new version's text replaces the old version's, in the same statement that writes it.
///
/// The assertion that matters is the *absence*: `covenant` was in v1 and is not in v2, and after
/// indexing v2 there must be no row anywhere containing it. A store that only upserted would still
/// hold it, and lexical search would still match it — a phrase deliberately removed from a document,
/// still findable through that document, with every permission check passing because the caller may
/// genuinely read the file.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_new_version_leaves_none_of_the_previous_version_s_text_behind() {
    let (db, fixtures) = start().await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");
    let (file, first_version) = indexed_file(&mut admin, alpha, fixtures.alpha.owner).await;

    let v1 = chunks_of(first_version, &["the covenant clause", "the notices clause"]);
    write_chunks(&mut admin, alpha, file, first_version, CHUNKER, &v1).await.expect("v1");

    let second_version = new_version(&mut admin, alpha, file, fixtures.alpha.owner, 2).await;
    let v2 = chunks_of(second_version, &["the notices clause"]);
    let write =
        write_chunks(&mut admin, alpha, file, second_version, CHUNKER, &v2).await.expect("v2");

    assert_eq!(write.written, 1);
    assert_eq!(write.pruned, 2, "v1's two chunks should have been pruned, not left beside v2's");

    let rows = stored(&mut admin, file).await;
    assert_eq!(rows.len(), 1, "the file kept text from more than one version: {rows:?}");
    assert_eq!(rows[0].0, second_version.as_uuid(), "the surviving row is not v2's");
    assert!(
        !rows.iter().any(|(_, _, text)| text.contains("covenant")),
        "text removed in v2 is still stored and still matchable: {rows:?}"
    );

    drop(db);
}

/// A version that extracted to nothing removes what the last one left.
///
/// "This version has no text" is a fact about the version. Answering it with the previous version's
/// text is the same lie in a quieter form, and this is the path that produces it: a scanned PDF
/// replacing a text original, or an extractor that refused.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_version_with_no_text_clears_the_file_rather_than_leaving_the_old_text() {
    let (db, fixtures) = start().await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");
    let (file, first_version) = indexed_file(&mut admin, alpha, fixtures.alpha.owner).await;

    let v1 = chunks_of(first_version, &["the indemnity clause"]);
    write_chunks(&mut admin, alpha, file, first_version, CHUNKER, &v1).await.expect("v1");

    let second_version = new_version(&mut admin, alpha, file, fixtures.alpha.owner, 2).await;
    let write = write_chunks(&mut admin, alpha, file, second_version, CHUNKER, &[])
        .await
        .expect("textless v2");

    assert_eq!(write.written, 0);
    assert_eq!(write.pruned, 1, "an empty run must prune, not no-op");
    assert!(
        stored(&mut admin, file).await.is_empty(),
        "a version that yielded no text left the previous version's text searchable"
    );

    drop(db);
}

/// A writer holding one tenant's session cannot put text under another tenant's id.
///
/// The write path is the one place a `tenant_id` is chosen rather than read, so this is where
/// `CLAUDE.md` rule 3 is tested from the writing side. It runs over the application pool — the
/// harness's own connection is a superuser, and a superuser bypasses row-level security entirely,
/// which is how every isolation test in this workspace once passed with isolation switched off
/// (PR #22).
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_session_scoped_to_one_tenant_cannot_write_text_for_another() {
    let (db, fixtures) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let pool = db.pool().await.expect("application pool");

    let mut admin = db.connect().await.expect("admin connection");
    let (beta_file, beta_version) = indexed_file(&mut admin, beta, fixtures.beta.owner).await;

    // The caller is honest about nothing: alpha's session, beta's tenant id, beta's file.
    let chunks = chunks_of(beta_version, &["a paragraph alpha may not store"]);
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin as alpha");
    let outcome = write_chunks(&mut tx, beta, beta_file, beta_version, CHUNKER, &chunks).await;
    // The transaction is poisoned by the refusal, so it is rolled back rather than committed.
    drop(tx);

    // The SQLSTATE is asserted, not merely the failure. `42501` is *row-level security refused
    // this row*, and it is the only answer that proves the isolation policy did the refusing — a
    // foreign key violation, a missing grant or a poisoned transaction would all satisfy
    // `is_err()` while saying nothing about tenancy.
    let error = outcome.expect_err("a session scoped to alpha wrote chunk text for beta");
    let sqlstate = match &error {
        enclave_indexing::IndexingError::Storage(sqlx::Error::Database(db_error)) => {
            db_error.code().map(|code| code.into_owned())
        }
        other => panic!("expected a database refusal, got {other:?}"),
    };
    assert_eq!(
        sqlstate.as_deref(),
        Some("42501"),
        "the cross-tenant write failed for a reason other than the isolation policy: {error:?}"
    );
    assert!(
        stored(&mut admin, beta_file).await.is_empty(),
        "the cross-tenant write left rows behind even though it reported failure"
    );

    // The positive control, over a fresh transaction because the one above is poisoned. The same
    // call under beta's own session succeeds, so the refusal above is about *whose* session it was
    // and not about the writer being broken for everyone.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin as beta");
    let write = write_chunks(&mut tx, beta, beta_file, beta_version, CHUNKER, &chunks)
        .await
        .expect("beta writing beta's own text");
    tx.commit().await.expect("commit");
    assert_eq!(write.written, chunks.len() as u64);

    drop(db);
}
