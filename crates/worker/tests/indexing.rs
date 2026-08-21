//! The indexing pass, end to end against a real database.
//!
//! # The row that matters
//!
//! `docs/12-TESTING.md §4.8` G-family: nothing serves content before antivirus completes
//! (`CLAUDE.md` rule 9). Indexing reads content, so it is subject to that rule — and the
//! consequence of getting it wrong here is quieter than on a download path. An indexer that reads a
//! `SCANNING` version puts the contents of an unscanned upload into the search index. Every
//! subsequent permission check on the *file* passes, because the caller genuinely may read the
//! file; what leaks is the content of something the scanner had not yet cleared, served as an
//! excerpt, with no error anywhere.
//!
//! `a_version_still_being_scanned_is_deferred_and_never_read` is that assertion, and it checks the
//! *store* as well as the manifest: a test that only checked the manifest would pass against an
//! implementation that read the bytes and then declined to record them.
//!
//! # Why the store is a fake and the database is not
//!
//! The property under test is which reads happen and what is written, and only a real PostgreSQL
//! can answer the second — the transaction boundary between `chunk_text` and `index_manifests` is
//! the thing being relied on. Object storage, by contrast, is being asked "were you called", which
//! a fake answers better than MinIO does: it records every key it was asked for, so "never read"
//! is checkable rather than inferred.
//!
//! # The OCR tests at the bottom, and what they need
//!
//! `ENC-546` added an optional OCR stage to the pass. Three of the tests below need the mounted
//! volumes as well as PostgreSQL and say so in their `#[ignore]` reason; CI provisions both in the
//! `test` job. They are here rather than in `tests/ocr_mounts.rs` because the property is what
//! reaches *the database* — a `READY` manifest over committed chunk text is only observable from
//! there, and that transaction boundary is the thing being relied on.
//!
//! `#[ignore]`d because they need PostgreSQL; CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use core::time::Duration;
use enclave_config::Config;
use enclave_core::{FileId, TenantId, UserId, VersionId};
use enclave_db::DbPool;
use enclave_indexing::{
    enqueue, ChunkBudget, Chunker, ChunkerVersion, ExtractOutcome, ExtractRequest, Extractor,
    ExtractorVersion, Pipeline, PlainTextExtractor, TextlessSource,
};
use enclave_preview::RenderBudget;
use enclave_worker::ocr::MountedOcr;

mod common;
use common::page_of_words;

use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StoreCapabilities, Support,
    UploadRequest, UploadSession,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::indexing::index_pass;
use enclave_worker::Stop;
use sqlx::{PgConnection, Row as _};
use url::Url;
use uuid::Uuid;

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test/1");
const EXTRACTOR: ExtractorVersion = ExtractorVersion::new("test/1");

/// Records every key it is asked to read, and serves the same bytes for all of them.
///
/// The recording is the point: "the scanning version's bytes were never fetched" is only checkable
/// from the store's side.
#[derive(Default)]
struct RecordingStore {
    body: Vec<u8>,
    reads: Mutex<Vec<String>>,
}

impl RecordingStore {
    fn new(body: &str) -> Self {
        Self { body: body.as_bytes().to_vec(), reads: Mutex::new(Vec::new()) }
    }

    /// The same store over bytes that are not text — a PDF, for the OCR tests.
    fn of_bytes(body: Vec<u8>) -> Self {
        Self { body, reads: Mutex::new(Vec::new()) }
    }

    fn reads(&self) -> Vec<String> {
        self.reads.lock().expect("the lock is not poisoned").clone()
    }
}

#[async_trait]
impl PublicAccessCheck for RecordingStore {
    async fn verify_not_public(
        &self,
    ) -> core::result::Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for RecordingStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "recording-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: 5 * 1024 * 1024,
                max_part_bytes: 5 * 1024 * 1024 * 1024,
                max_parts: 10_000,
            }),
            signed_urls: true,
            single_use_signed_urls: false,
            max_signed_url_ttl: Duration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: true,
            server_side_copy: true,
        }
    }

    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        unreachable!("the indexing pass never uploads")
    }

    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        unreachable!("the indexing pass never uploads")
    }

    async fn signed_download(&self, _key: &str, _ttl: Duration) -> StorageResult<Url> {
        // Not merely unimplemented: a signed URL for an *original* has no business being minted on
        // an indexing path, and a panic here would name that if one ever appeared.
        unreachable!("the indexing pass never mints a download URL")
    }

    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        self.reads.lock().expect("the lock is not poisoned").push(key.to_owned());
        let body = self.body.clone();
        let length = body.len() as u64;
        Ok(ByteStream::new(
            futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }),
            Some(length),
        ))
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        unreachable!("the indexing pass never copies")
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        unreachable!("the indexing pass never deletes")
    }
}

fn pipeline() -> Pipeline<PlainTextExtractor> {
    Pipeline::new(PlainTextExtractor, Chunker::new(CHUNKER, ChunkBudget::default()))
}

fn versions() -> enclave_indexing::BuildVersions<'static> {
    enclave_indexing::BuildVersions { extractor: EXTRACTOR, chunker: CHUNKER, embedding_model: "" }
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("pool");
    (db, fixtures, pool)
}

/// A file with one version, in the given antivirus state.
async fn a_file(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    status: &str,
    av_status: &str,
) -> (FileId, VersionId) {
    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, owner, Utc::now()).await.expect("spine");

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 12, 'deadbeef', 'text/plain', 1, 0, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("objects/{id}"))
    .bind(Uuid::nil())
    .bind(status)
    .bind(av_status)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("version");

    (spine.file, VersionId::from(id))
}

async fn manifest_status(conn: &mut PgConnection, file: FileId) -> (String, i32) {
    let row = sqlx::query("SELECT status, attempts FROM index_manifests WHERE file_id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("manifest");
    (row.try_get("status").expect("status"), row.try_get("attempts").expect("attempts"))
}

async fn chunk_rows(conn: &mut PgConnection, file: FileId) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM chunk_text WHERE file_id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("count")
        .try_get("n")
        .expect("n")
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_clean_version_is_extracted_chunked_and_recorded_ready() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new("the indemnity clause is on the third page"));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.claimed, 1);
    assert_eq!(pass.indexed, 1, "a clean, readable version was not indexed");
    assert_eq!(pass.deferred, 0);

    assert_eq!(manifest_status(&mut conn, file).await.0, "READY");
    assert!(chunk_rows(&mut conn, file).await > 0, "READY was recorded over no chunk text");
    assert_eq!(store.reads().len(), 1, "the version's bytes were read exactly once");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_version_still_being_scanned_is_deferred_and_never_read() {
    // CLAUDE.md rule 9. Asserted on the **store**, not only on the manifest: an implementation that
    // fetched the bytes and then declined to record them would pass a manifest-only check while
    // having already read an unscanned upload into worker memory.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "SCANNING", "PENDING").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new("an unscanned upload"));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.deferred, 1, "a version awaiting antivirus was not deferred");
    assert_eq!(pass.indexed, 0);
    assert_eq!(
        store.reads(),
        Vec::<String>::new(),
        "the bytes of a version antivirus has not cleared were read"
    );
    assert_eq!(
        chunk_rows(&mut conn, file).await,
        0,
        "text from an unscanned version reached the searchable store"
    );

    let (status, attempts) = manifest_status(&mut conn, file).await;
    assert_eq!(status, "PENDING", "a deferred file must be claimable again once the scan finishes");
    assert_eq!(attempts, 0, "waiting for a scan is not a failed attempt to index");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn an_infected_version_is_never_indexed() {
    // The same path as SCANNING, and worth its own row: `readable_version` refuses anything whose
    // `av_status` is not CLEAN, so a quarantined file is deferred rather than indexed. It stays
    // deferred forever, which is correct — the file is not going to become readable, and the
    // manifest shows a file the indexer keeps declining rather than one it silently dropped.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "INFECTED").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new("eicar-ish"));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.deferred, 1);
    assert_eq!(store.reads(), Vec::<String>::new(), "a quarantined version's bytes were read");
    assert_eq!(chunk_rows(&mut conn, file).await, 0);

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_pass_never_crosses_a_tenant() {
    let (db, fixtures, pool) = start().await;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, fixtures.alpha.id, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, fixtures.alpha.id, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new("alpha's contract"));
    let pass = index_pass(
        &pool,
        fixtures.beta.id,
        &pipeline(),
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.claimed, 0, "beta's pass claimed alpha's file");
    assert_eq!(store.reads(), Vec::<String>::new(), "beta's pass read alpha's bytes");

    drop(db);
}

// -------------------------------------------------------------------------------------------
// The OCR stage, through the pass — `ENC-546`.
// -------------------------------------------------------------------------------------------

/// Stands in for the PDF *text* extractor `ENC-545` is building.
///
/// It reports what that extractor reports for a scanned document: this source yielded no text, and
/// page 1 is where an image pipeline should look. A fake and not the real one on purpose — what is
/// under test here is `index_pass`'s routing, and a test that also depended on a PDF text parser
/// would go red for that parser's reasons on a line that names OCR.
///
/// It answers `supports` for everything, so the pass reaches `extract` whatever the row's declared
/// type says. That is load-bearing for `the_stage_dispatches_on_the_decided_type_not_the_declared_one`.
#[derive(Debug)]
struct TextlessPdf;

#[async_trait]
impl Extractor for TextlessPdf {
    fn extractor_version(&self) -> ExtractorVersion {
        ExtractorVersion::new("textless-pdf/1")
    }

    fn supports(&self, _declared_media_type: &str) -> bool {
        true
    }

    async fn extract(&self, _request: ExtractRequest) -> enclave_indexing::Result<ExtractOutcome> {
        Ok(ExtractOutcome::NoText(TextlessSource {
            media_type: "application/pdf".to_owned(),
            pages_without_text: vec![1],
        }))
    }
}

fn textless_pipeline() -> Pipeline<TextlessPdf> {
    Pipeline::new(TextlessPdf, Chunker::new(CHUNKER, ChunkBudget::default()))
}

/// `RenderBudget::DEFAULT` with the clock taken off.
///
/// `ENC-540`: `DEFAULT`'s 30-second wall clock passes on a developer's machine and timed out on a
/// hosted runner, and the two OCR tests that hit it read as an OCR defect rather than as a slow
/// machine. Nothing here asserts how fast anything is.
const UNTIMED: RenderBudget =
    RenderBudget { wall_clock: Duration::from_secs(600), ..RenderBudget::DEFAULT };

/// The stage a deployment with both volumes mounted builds.
///
/// Goes through `Config` and `MountedOcr::from_config` rather than constructing the parts, because
/// the composition is what `ENC-546` is about — `tests/ocr_mounts.rs` explains why the two variables
/// are passed explicitly rather than read as a whole process environment.
fn mounted_stage() -> MountedOcr {
    let config = Config {
        ocr_models: Some(
            std::env::var("ENCLAVE_OCR_MODELS")
                .expect("ENCLAVE_OCR_MODELS must name the mounted model directory")
                .into(),
        ),
        pdfium: Some(
            std::env::var("ENCLAVE_PDFIUM")
                .expect("ENCLAVE_PDFIUM must name the mounted PDFium")
                .into(),
        ),
        ..Config::default()
    };

    MountedOcr::from_config(&config, Chunker::new(CHUNKER, ChunkBudget::default()), UNTIMED)
        .expect("both volumes are mounted")
        .expect("a configuration naming both volumes must build a stage")
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014, OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_textless_document_reaches_the_stage_and_its_recovered_text_is_committed() {
    // **The positive control for every "OCR did not run" assertion in this file.** Those are
    // assertions about an absence and hold for free against a pass that never consults the stage at
    // all (`docs/12 §1.2`); this is the case where the text must come back, be chunked, and be
    // committed in the same transaction as the manifest.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::of_bytes(page_of_words()));
    let stage = mounted_stage();
    let pass = index_pass(
        &pool,
        alpha,
        &textless_pipeline(),
        Some(&stage),
        store.as_ref(),
        versions(),
        UNTIMED,
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.ocr_attempted, 1, "a textless document was never handed to the OCR stage");
    assert_eq!(pass.indexed, 1, "OCR recovered text and the pass did not record it as indexed");
    assert_eq!(pass.failed, 0);

    assert_eq!(manifest_status(&mut conn, file).await.0, "READY");
    assert!(chunk_rows(&mut conn, file).await > 0, "READY was recorded over no chunk text");
    assert_eq!(
        store.reads().len(),
        2,
        "the OCR path re-reads the bytes rather than holding a second copy; see the module \
         documentation of crates/worker/src/indexing.rs"
    );

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014, OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn the_stage_dispatches_on_the_decided_type_not_the_declared_one() {
    // The row says `text/plain` — `a_file` writes that for every fixture — and the extractor decided
    // `application/pdf` by reading the bytes. PDFium is reached, so the dispatch used the decided
    // type. Had it used the declared one, `NoPageImages` would have answered, no page would have been
    // rasterised, and the manifest would read FAILED.
    //
    // `Extractor::supports` says in its own words that a declared type is a hint and not a trust
    // boundary; this is the pass honouring that at the one place where it could quietly stop.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let declared: String = sqlx::query("SELECT mime_type FROM file_versions WHERE id = $1")
        .bind(version.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("the version row")
        .try_get("mime_type")
        .expect("mime_type");
    assert_eq!(declared, "text/plain", "the premise: the row does not say this is a PDF");

    let store = Arc::new(RecordingStore::of_bytes(page_of_words()));
    let stage = mounted_stage();
    let pass = index_pass(
        &pool,
        alpha,
        &textless_pipeline(),
        Some(&stage),
        store.as_ref(),
        versions(),
        UNTIMED,
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.indexed, 1, "the page was not rasterised, so the declared type was believed");
    assert_eq!(manifest_status(&mut conn, file).await.0, "READY");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn with_no_stage_configured_a_textless_document_behaves_exactly_as_it_did_before() {
    // "A deployment without the volumes behaves exactly as today", asserted rather than asserted-in-
    // a-commit-message. The identical file and the identical extractor as the test above: `FAILED`,
    // no chunk text, one read, and nothing handed to a stage that does not exist.
    //
    // Note what this is *not*: it is not an empty `READY`. A scanned document with no OCR configured
    // is visibly unsearchable, which is the documented absence D24 asks for.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::of_bytes(page_of_words()));
    let pass = index_pass(
        &pool,
        alpha,
        &textless_pipeline(),
        None,
        store.as_ref(),
        versions(),
        UNTIMED,
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.ocr_attempted, 0);
    assert_eq!(pass.failed, 1);
    assert_eq!(pass.indexed, 0);
    assert_eq!(manifest_status(&mut conn, file).await.0, "FAILED");
    assert_eq!(chunk_rows(&mut conn, file).await, 0, "a document nothing read produced chunk text");
    assert_eq!(store.reads().len(), 1, "the bytes were re-read with no stage to hand them to");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014, OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_document_that_produced_text_is_never_re_read_for_ocr() {
    // The cost guard on the branch in `index_pass`. `MountedOcr::retry` would return this outcome
    // untouched anyway — that pass-through is the guarantee and it lives in `OcrRetry` — so what
    // this asserts is the *optimisation*: an ordinary text document must not pay a second
    // object-storage read on a deployment that happens to have OCR mounted.
    //
    // Asserted on the store's read count rather than on `ocr_attempted` alone, because the counter
    // is ours and the read is the cost.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new("the indemnity clause is on the third page"));
    let stage = mounted_stage();
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        Some(&stage),
        store.as_ref(),
        versions(),
        UNTIMED,
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.indexed, 1);
    assert_eq!(pass.ocr_attempted, 0, "a document that produced text was handed to OCR");
    assert_eq!(store.reads().len(), 1, "a document that produced text paid for a second read");

    drop(db);
}
