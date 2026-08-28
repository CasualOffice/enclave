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
use enclave_core::{
    ClassificationOutcome, EffectiveClassification, FileId, LabelSource, TenantId, UserId,
    VersionId,
};
use enclave_db::DbPool;
use enclave_indexing::{
    enqueue, ChunkBudget, Chunker, ChunkerVersion, ExtractOutcome, ExtractRequest, Extractor,
    ExtractorVersion, Pipeline, PlainTextExtractor, TextlessSource,
};
use enclave_preview::RenderBudget;
use enclave_worker::ocr::MountedOcr;

mod common;
use common::{page_of_words, RecordingStore};

use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::indexing::index_pass;
use enclave_worker::Stop;
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test/1");
const EXTRACTOR: ExtractorVersion = ExtractorVersion::new("test/1");

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
///
/// A thin wrapper over `common::a_file`, which every content pass's tests share: the media type is
/// fixed here because nothing in this binary exercises routing, and passing `"text/plain"` at
/// sixteen call sites would say nothing at any of them.
async fn a_file(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    status: &str,
    av_status: &str,
) -> (FileId, VersionId) {
    common::a_file(conn, tenant, owner, status, av_status, "text/plain").await
}

/// The same file, with the spine it hangs on.
async fn a_file_on_a_spine(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    status: &str,
    av_status: &str,
) -> (Spine, VersionId) {
    common::a_file_on_a_spine(conn, tenant, owner, status, av_status, "text/plain").await
}

async fn manifest_status(conn: &mut PgConnection, file: FileId) -> (String, i32) {
    let row = sqlx::query("SELECT status, attempts FROM index_manifests WHERE file_id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("manifest");
    (row.try_get("status").expect("status"), row.try_get("attempts").expect("attempts"))
}

/// Grants the two actions a search hit needs, so the post-filter is not what this test measures.
///
/// `MetadataRead` to see the hit at all and `ContentRead` for the excerpt — both, because a test
/// that granted only the first would pass while proving that the *disclosure* rule works, which is
/// `crates/search`'s job and already covered there.
async fn grant_read(conn: &mut PgConnection, tenant: TenantId, file: FileId, caller: UserId) {
    for action in ["file.metadata_read", "file.content_read"] {
        sqlx::query(
            "INSERT INTO acl_entries
               (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
                effect, granted_by, granted_at)
             VALUES ($1, $2, 'FILE', $3, 'USER', $4, $5, 'ALLOW', $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(caller.as_uuid())
        .bind(action)
        .bind(Uuid::nil())
        .bind(Utc::now())
        .execute(&mut *conn)
        .await
        .expect("grant");
    }
}

/// A request context for the caller the grants above name.
fn search_ctx(tenant: TenantId, actor: UserId) -> enclave_core::RequestContext {
    enclave_core::RequestContext {
        actor: enclave_core::Actor::User(actor),
        ..enclave_core::RequestContext::system(tenant)
    }
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
        None,
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
        None,
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
        None,
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

// =================================================================================================
// The vector stage — `ENC-557`
// =================================================================================================
//
// # What these prove, and what `crates/search` already proved
//
// `ENC-547` proved that `MilvusIndex` writes and removes what it is given
// (`crates/search/tests/vector_write.rs`). What was missing was a caller. These assert the wiring:
// that a `READY` file's chunks are embedded and handed to the store *before* the manifest commits,
// that the manifest names the model that ran, and — the half that matters more — that a deployment
// which cannot embed refuses rather than recording a `READY` manifest over an empty collection.
//
// # Why the store is a fake in all but the last
//
// `docs/12 §1.1`: the property under test is what we hand the store and what we do with what comes
// back, not whether Milvus ranks well. A fake can be asked "what were you given", which is the
// question, and it *validates every record exactly as the collection would* — `ChunkRecord::validate`
// is the same call `MilvusIndex::upsert_chunks` makes, so a record the real collection would reject
// fails here rather than in a deployment. The last test then runs the whole pass against a real
// Milvus and reads the chunks back out, because "we called upsert" and "the collection is no longer
// empty" are different claims and `ENC-557` is about the second.

use enclave_core::ClassificationRank;
use enclave_embeddings::model::ACTIVE;
use enclave_embeddings::{
    Availability, Embedding, EmbeddingError, EmbeddingProvider, EmbeddingRouter, Local,
    LocalCeiling, ModelId, NoLocalModel, Remote, TextBatch,
};
use enclave_search::vector::{VectorIndex, VectorQuery};
use enclave_search::{
    ChunkRecord, MilvusConfig, MilvusIndex, Prefilter, SearchError, VectorWriter,
};
use enclave_worker::indexing::{FileClassification, UnclassifiedFiles, VectorStage};
use enclave_worker::WorkerError;

/// `docs/07 §2.3`'s default mapping, as a rank a deployment might assign it.
const RESTRICTED: ClassificationRank = ClassificationRank::new(40);

/// A classification source that answers, for the deployment that has one.
///
/// The counterpart to `UnclassifiedFiles`, and the reason every refusal below is not vacuous: with
/// this wired, the same pass indexes.
#[derive(Debug)]
struct FixedRank(ClassificationRank);

#[async_trait]
impl FileClassification for FixedRank {
    async fn effective_rank(
        &self,
        _conn: &mut PgConnection,
        _tenant: TenantId,
        _file: FileId,
    ) -> core::result::Result<ClassificationOutcome, WorkerError> {
        Ok(ClassificationOutcome::Labelled(EffectiveClassification::found(
            self.0,
            LabelSource::Resource,
        )))
    }
}

/// A local model that answers with vectors of a fixed width, and counts.
///
/// A provider rather than an `Embedder`, so the pass runs through the real `EmbeddingRouter` and the
/// real `TextBatch::<Local>::admit` — the double stands in for the weights, not for the routing.
#[derive(Debug)]
struct FixedWidthLocal {
    width: usize,
    model: ModelId,
    calls: Arc<Mutex<Vec<ClassificationRank>>>,
}

impl FixedWidthLocal {
    fn new(width: usize) -> (Self, Arc<Mutex<Vec<ClassificationRank>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (Self { width, model: ModelId::known("test-local/1"), calls: Arc::clone(&calls) }, calls)
    }
}

#[async_trait]
impl EmbeddingProvider<Local> for FixedWidthLocal {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        self.width
    }

    async fn embed(
        &self,
        batch: TextBatch<Local>,
    ) -> core::result::Result<Vec<Embedding>, EmbeddingError> {
        self.calls.lock().expect("lock").push(batch.rank());
        // A constant vector, so the real-Milvus test below can query for it exactly. What is being
        // measured there is retrieval of a chunk we wrote, not a model's ranking.
        Ok(batch.texts().iter().map(|_| Embedding::new(vec![0.25_f32; self.width])).collect())
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

/// A local provider that takes longer to answer than a connection may sit in a transaction.
///
/// `ENC-850`. The delay is the whole double: it stands in for a cold model load, a large batch, or
/// a machine under load — every one of which is ordinary, and any one of which used to terminate
/// the pass's connection with `25P03` because the transaction was still open while it happened.
#[derive(Debug)]
struct SlowLocal {
    inner: FixedWidthLocal,
    delay: Duration,
}

#[async_trait]
impl EmbeddingProvider<Local> for SlowLocal {
    fn model(&self) -> &ModelId {
        self.inner.model()
    }

    fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    async fn embed(
        &self,
        batch: TextBatch<Local>,
    ) -> core::result::Result<Vec<Embedding>, EmbeddingError> {
        tokio::time::sleep(self.delay).await;
        self.inner.embed(batch).await
    }

    async fn availability(&self) -> Availability {
        self.inner.availability().await
    }
}

/// A remote provider that fails the test on contact.
///
/// Present in the router of every test below so that the S8 assertion is about *reaching* a remote
/// provider rather than about what one answered — `crates/embeddings/tests/routing.rs` explains why
/// an erroring double would let a fallback pass.
#[derive(Debug)]
struct Forbidden;

#[async_trait]
impl EmbeddingProvider<Remote> for Forbidden {
    fn model(&self) -> &ModelId {
        unreachable!("the indexing pass reached a remote embedding provider")
    }

    fn dimensions(&self) -> usize {
        unreachable!("the indexing pass reached a remote embedding provider")
    }

    async fn embed(
        &self,
        _batch: TextBatch<Remote>,
    ) -> core::result::Result<Vec<Embedding>, EmbeddingError> {
        unreachable!("the indexing pass sent a document's text to a remote embedding provider")
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

/// A vector store that records what it was handed, having first validated it as the collection does.
#[derive(Debug, Default)]
struct RecordingWriter {
    batches: Mutex<Vec<Vec<ChunkRecord>>>,
    refuse: bool,
}

impl RecordingWriter {
    fn refusing() -> Self {
        Self { batches: Mutex::new(Vec::new()), refuse: true }
    }

    fn written(&self) -> Vec<ChunkRecord> {
        self.batches.lock().expect("lock").iter().flatten().cloned().collect()
    }
}

#[async_trait]
impl VectorWriter for RecordingWriter {
    async fn upsert_chunks(&self, chunks: &[ChunkRecord]) -> core::result::Result<(), SearchError> {
        if self.refuse {
            return Err(SearchError::VectorIndex { operation: "upsert", retryable: true });
        }
        for chunk in chunks {
            // The same call `MilvusIndex::upsert_chunks` makes. Without it a fake accepts records
            // the collection would reject, and a rejected batch is a silently unfindable file.
            chunk.validate(ACTIVE.dimension)?;
        }
        self.batches.lock().expect("lock").push(chunks.to_vec());
        Ok(())
    }

    async fn remove_file(
        &self,
        _tenant: TenantId,
        _file: FileId,
    ) -> core::result::Result<(), SearchError> {
        unreachable!("the indexing pass never removes a file")
    }
}

/// A stage over a working model, a classification source that answers, and a recording store.
fn working_stage(
    writer: Arc<RecordingWriter>,
    ranks: Box<dyn FileClassification>,
) -> (VectorStage, Arc<Mutex<Vec<ClassificationRank>>>) {
    let (local, calls) = FixedWidthLocal::new(ACTIVE.dimension as usize);
    // A *configured* remote provider and a ceiling that would admit ordinary content, so that
    // "nothing was sent remote" is a fact about the routing rather than about there being nowhere to
    // send it. `Forbidden` panics on contact.
    let router = EmbeddingRouter::new(local, Forbidden, LocalCeiling::at(RESTRICTED));
    let stage = VectorStage::for_collection(
        Box::new(router),
        ranks,
        Box::new(ArcWriter(writer)),
        ACTIVE.dimension,
    )
    .expect("the stage is wired at the active model's width");
    (stage, calls)
}

/// Lets a test keep a handle on the writer the stage owns.
#[derive(Debug)]
struct ArcWriter(Arc<RecordingWriter>);

#[async_trait]
impl VectorWriter for ArcWriter {
    async fn upsert_chunks(&self, chunks: &[ChunkRecord]) -> core::result::Result<(), SearchError> {
        self.0.upsert_chunks(chunks).await
    }

    async fn remove_file(
        &self,
        tenant: TenantId,
        file: FileId,
    ) -> core::result::Result<(), SearchError> {
        self.0.remove_file(tenant, file).await
    }
}

async fn manifest_model(conn: &mut PgConnection, file: FileId) -> String {
    sqlx::query("SELECT embedding_model FROM index_manifests WHERE file_id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("manifest")
        .try_get::<Option<String>, _>("embedding_model")
        .expect("embedding_model")
        .unwrap_or_default()
}

async fn chunk_texts(conn: &mut PgConnection, file: FileId) -> Vec<String> {
    sqlx::query("SELECT text FROM chunk_text WHERE file_id = $1 ORDER BY ordinal")
        .bind(file.as_uuid())
        .fetch_all(&mut *conn)
        .await
        .expect("chunk text")
        .into_iter()
        .map(|row| row.try_get::<String, _>("text").expect("text"))
        .collect()
}

/// The document every test below indexes: long enough to produce more than one chunk would be
/// nicer, but one chunk is enough to tell written from not-written and keeps the assertions exact.
const DOCUMENT: &str = "the indemnity clause is on the third page";

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_ready_file_is_embedded_and_its_chunks_written_to_the_vector_store() {
    // The positive control for every refusal below, and the assertion `ENC-557` is actually about:
    // before this, `chunk_text` filled and the collection stayed empty in every real deployment.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::default());
    let (stage, embedded) = working_stage(Arc::clone(&writer), Box::new(FixedRank(RESTRICTED)));
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.indexed, 1);
    assert_eq!(pass.embedded, 1, "a READY file's chunks were never embedded");
    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "READY");

    // The rank that reached the provider is the one the classification source gave, not a constant
    // chosen by the wiring. A stage that fabricated `PUBLIC` would pass every other assertion here
    // and would route this document to `Forbidden` under a ceiling that was working correctly.
    assert_eq!(&*embedded.lock().expect("lock"), &[RESTRICTED]);

    let written = writer.written();
    let texts = chunk_texts(&mut conn, spine.file).await;
    assert!(!texts.is_empty(), "READY was recorded over no chunk text");
    assert_eq!(
        written.len(),
        texts.len(),
        "the store and `chunk_text` disagree about how many chunks this file has"
    );

    for (record, text) in written.iter().zip(&texts) {
        // The same chunks went to both stores. A pass that embedded one thing and committed another
        // would make a search excerpt quote text the document does not contain.
        assert_eq!(&record.text, text);
        assert_eq!(record.tenant, alpha);
        assert_eq!(record.workspace, spine.workspace);
        assert_eq!(record.library, spine.library);
        assert_eq!(record.file, spine.file);
        assert_eq!(record.version, version);
        assert_eq!(record.classification_rank, RESTRICTED);
        assert_eq!(record.dense.len(), ACTIVE.dimension as usize);
        assert_eq!(record.acl_epoch, 1, "`files.acl_revision` did not reach the record");
        assert_eq!(record.mime_type, "text/plain");
        assert_eq!(record.title.as_deref(), Some(spine.file.as_uuid().to_string()).as_deref());
    }

    // And the manifest names the model that ran, which is what `docs/07 §3`'s reindex trigger
    // compares. `""` here would mean a model swap never triggers a rebuild of these chunks.
    assert_eq!(manifest_model(&mut conn, spine.file).await, "test-local/1");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_deployment_that_cannot_classify_a_file_refuses_rather_than_guessing_a_rank() {
    // The gap named rather than papered over. `ClassifiedText::new` requires the file's *effective*
    // classification and this deployment has no source for one, so the file is not embedded and not
    // recorded — instead of being embedded under a guessed `PUBLIC`, which would route it to a
    // hosted endpoint while the ceiling comparison worked perfectly.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::default());
    let (stage, embedded) = working_stage(Arc::clone(&writer), Box::new(UnclassifiedFiles));
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let error = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect_err("an unclassifiable file must not be embedded");
    assert!(matches!(error, WorkerError::Unclassified), "{error:?}");

    // Nothing was recorded and nothing was committed. A `READY` manifest here would be the document
    // that is filed, visible in the tree, and absent from every search.
    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "EXTRACTING");
    assert_eq!(chunk_rows(&mut conn, spine.file).await, 0);
    assert!(writer.written().is_empty(), "a chunk reached the store without a classification");
    assert!(embedded.lock().expect("lock").is_empty(), "text reached a provider without a rank");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_deployment_with_no_local_model_refuses_rather_than_indexing_nothing() {
    // The seam this task exists to build. No weights are mounted, so `NoLocalModel` refuses — and
    // the refusal must stop the file being recorded rather than produce a manifest over an empty
    // collection. This is `MountedOcr`'s "a failed mount is an outage, never an empty document",
    // one stage later.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::default());
    let stage = VectorStage::for_collection(
        Box::new(EmbeddingRouter::air_gapped(NoLocalModel)),
        Box::new(FixedRank(RESTRICTED)),
        Box::new(ArcWriter(Arc::clone(&writer))),
        ACTIVE.dimension,
    )
    .expect("wiring a stage does not need a model");
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let error = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect_err("a deployment with no model must not record an indexed document");
    assert!(
        matches!(error, WorkerError::Embedding(EmbeddingError::LocalUnavailable(_))),
        "{error:?}"
    );

    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "EXTRACTING");
    assert_eq!(chunk_rows(&mut conn, spine.file).await, 0);
    assert!(writer.written().is_empty());

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_store_that_refuses_the_batch_leaves_no_manifest_and_no_chunk_text() {
    // **The ordering assertion.** The store write happens before the transaction commits, so a
    // store that refuses leaves nothing behind and the file is retried whole.
    //
    // Watched to fail against the violation it is about: moving `upsert_chunks` after `tx.commit()`
    // leaves `READY` and committed chunk text over a collection that refused the batch — the
    // document search believes it can find and cannot, with no retry, because the manifest says it
    // is done.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::refusing());
    let (stage, _embedded) = working_stage(Arc::clone(&writer), Box::new(FixedRank(RESTRICTED)));
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let error = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect_err("a store that refuses the batch must not leave a READY manifest");
    assert!(matches!(error, WorkerError::Search(_)), "{error:?}");

    assert_eq!(
        manifest_status(&mut conn, spine.file).await.0,
        "EXTRACTING",
        "the manifest completed over a batch the store refused"
    );
    assert_eq!(
        chunk_rows(&mut conn, spine.file).await,
        0,
        "chunk text was committed over a batch the store refused"
    );

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_provider_whose_vectors_are_not_the_collections_width_is_refused_before_the_store() {
    // The per-batch half of `ENC-533`. The collection was created at the active model's width and
    // the provider is emitting another one, which means it is a different model: re-sending will
    // fail identically, and writing it would put two widths in one collection.
    //
    // Refused before the store rather than by it, so the error names both numbers — `crates/search`
    // discards a Milvus error's message on purpose (`CLAUDE.md` rule 10), leaving an operator with
    // `the vector index could not answer "upsert"` and no width at all.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::default());
    let (narrow, _calls) = FixedWidthLocal::new(8);
    let stage = VectorStage::for_collection(
        Box::new(EmbeddingRouter::new(narrow, Forbidden, LocalCeiling::at(RESTRICTED))),
        Box::new(FixedRank(RESTRICTED)),
        Box::new(ArcWriter(Arc::clone(&writer))),
        ACTIVE.dimension,
    )
    .expect("the collection is the active model's width");
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let error = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect_err("an 8-wide vector in a 1024-wide collection must not be written");
    match error {
        WorkerError::CollectionWidth { collection, model } => {
            assert_eq!(collection, ACTIVE.dimension);
            assert_eq!(model, 8);
        }
        other => panic!("expected a width refusal naming both numbers, got {other:?}"),
    }

    assert!(writer.written().is_empty(), "a mis-sized vector reached the store");
    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "EXTRACTING");
    assert_eq!(chunk_rows(&mut conn, spine.file).await, 0);

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_pass_with_no_stage_indexes_exactly_as_before_and_claims_no_model() {
    // The other half of the `Option`. A deployment that has configured no embedding model and no
    // vector store keeps indexing text, and its manifest says `""` — which `BuildVersions`
    // documents as the honest value for a deployment where nothing has embedded.
    //
    // The pair with `a_ready_file_is_embedded_and_its_chunks_written_to_the_vector_store` is the
    // point: one asserts the column is `test-local/1` when a stage ran, this one that it is empty
    // when none did. Either alone passes against a manifest writer that ignores the argument.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let store = Arc::new(RecordingStore::new(DOCUMENT));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(pass.indexed, 1);
    assert_eq!(pass.embedded, 0, "a pass with no stage embedded something");
    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "READY");
    assert!(chunk_rows(&mut conn, spine.file).await > 0);
    assert_eq!(manifest_model(&mut conn, spine.file).await, "");

    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and Milvus; CI runs it with --include-ignored"]
async fn the_pass_fills_a_real_collection_and_the_chunks_come_back_out() {
    // `ENC-557` end to end. Everything above uses a fake store, which can prove what we handed over
    // and not that the collection stopped being empty — and "the collection is empty in any real
    // deployment" is the whole of the row.
    //
    // The query vector is the one the double produced, so a miss here is our wiring and never
    // ranking: `docs/12 §1.1`.
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    // `ACTIVE.dimension` rather than a literal — `MilvusConfig::dimension` asks the caller building
    // the collection to read it from there, and this is a caller that can.
    let mut config = MilvusConfig::new(
        std::env::var("MILVUS_URI").unwrap_or_else(|_| "http://127.0.0.1:19530".to_owned()),
        ACTIVE.dimension,
    );
    config.collection = format!("enclave_worker_{}", Uuid::now_v7().simple());
    // Strong, not the production `Bounded`: this writes and immediately reads back, and under a
    // bounded read that race resolves differently on a loaded machine.
    config.consistency = milvus_consistency_strong();
    config.partitions = 2;

    let index = Arc::new(MilvusIndex::new(config));
    index.ensure_collection().await.expect("create the collection");

    let (local, _calls) = FixedWidthLocal::new(ACTIVE.dimension as usize);
    let stage = VectorStage::for_collection(
        Box::new(EmbeddingRouter::new(local, Forbidden, LocalCeiling::at(RESTRICTED))),
        Box::new(FixedRank(RESTRICTED)),
        Box::new(SharedIndex(Arc::clone(&index))),
        ACTIVE.dimension,
    )
    .expect("the collection is the active model's width");

    let store = Arc::new(RecordingStore::new(DOCUMENT));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");
    assert_eq!(pass.embedded, 1);

    let all = Prefilter::unnarrowed();
    let candidates = index
        .candidates(VectorQuery {
            tenant: alpha,
            embedding: &vec![0.25_f32; ACTIVE.dimension as usize],
            budget: 100,
            prefilter: &all,
        })
        .await
        .expect("query the collection the pass just wrote");

    assert!(
        candidates.iter().any(|candidate| candidate.file_id == spine.file),
        "the pass wrote no retrievable chunk: {} candidates",
        candidates.len()
    );

    drop(db);
}

/// The strong consistency level, named here so the test above reads as prose.
fn milvus_consistency_strong() -> milvus::v2::prelude::ConsistencyLevel {
    milvus::v2::prelude::ConsistencyLevel::Strong
}

/// Lets the real-Milvus test keep a handle on the index it also queries.
#[derive(Debug)]
struct SharedIndex(Arc<MilvusIndex>);

#[async_trait]
impl VectorWriter for SharedIndex {
    async fn upsert_chunks(&self, chunks: &[ChunkRecord]) -> core::result::Result<(), SearchError> {
        self.0.upsert_chunks(chunks).await
    }

    async fn remove_file(
        &self,
        tenant: TenantId,
        file: FileId,
    ) -> core::result::Result<(), SearchError> {
        self.0.remove_file(tenant, file).await
    }
}

/// **The exit criterion's last unjoined boundary**: text an indexing pass committed is text
/// lexical search finds.
///
/// M3 asks that a document be "searchable by its content". Three tests already cover the path in
/// overlapping segments, each with real components — `crates/indexing/tests/pdf.rs` takes a scanned
/// PDF through PDFium and `ocrs` to chunks that cite their page, `ocr_mounts.rs` takes a textless
/// outcome through the mounted stage to committed `chunk_text`, and
/// `crates/search/tests/lexical_content.rs` takes `chunk_text` to a search hit. What none of them
/// did was cross the last join in one process: a **pass** writing rows, and a **search** reading
/// them back.
///
/// That join is where an assumption would hide — the pass writing to a shape the search does not
/// read, or writing under a tenant the search does not scope to — and both would leave every
/// existing test green.
///
/// # Why the query is taken from what was stored
///
/// The word searched for is read out of `chunk_text`, not written into this test. Asserting a
/// literal would make the test a claim about *extraction* — and on the OCR path that is the
/// engine's accuracy against a platform's font rasterisation, which `ENC-569` removed from a test
/// for failing on Linux while passing on macOS (`docs/12 §1.1`). What is asserted here is the
/// property that belongs to us: whatever the pipeline committed is retrievable by searching for it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0017; CI runs it with --include-ignored"]
async fn text_an_indexing_pass_committed_is_text_lexical_search_finds() {
    use enclave_authorization::PgAclAuthorization;
    use enclave_db::TenantScoped;
    use enclave_search::degraded::{Retrieval, VectorStore};
    use enclave_search::{lexical, SearchResults, DEFAULT_DENYLIST_LIMIT};

    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");
    grant_read(&mut conn, alpha, spine.file, fixtures.alpha.owner).await;

    let store = Arc::new(RecordingStore::new("the perihelion review procedure is annual"));
    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        None,
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("pass");
    assert_eq!(pass.indexed, 1, "the pass indexed nothing, so there is nothing to find");

    // The query comes out of the rows the pass wrote, so this asserts retrieval and never
    // extraction. A word of six characters or more avoids the stop-word-ish noise a one-letter
    // token would match everywhere.
    let stored: String = sqlx::query("SELECT text FROM chunk_text WHERE file_id = $1 LIMIT 1")
        .bind(spine.file.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("the pass committed chunk text")
        .try_get("text")
        .expect("text");
    let word = stored
        .split_whitespace()
        .find(|w| w.chars().filter(|c| c.is_alphanumeric()).count() >= 6)
        .expect("the committed text holds a word worth searching for")
        .trim_matches(|c: char| !c.is_alphanumeric())
        .to_owned();

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    // `DegradedReason` has no public constructor — it is reachable only through `Retrieval::decide`,
    // which is what stops a degraded result being fabricated. Obtained the same way the search
    // crate's own tests obtain it.
    let reason = match Retrieval::decide(VectorStore::Unreachable, 0, DEFAULT_DENYLIST_LIMIT) {
        Retrieval::Degraded(reason) => reason,
        Retrieval::Complete => panic!("an unreachable vector store must degrade"),
    };
    let candidates =
        lexical::candidates(&mut tx, alpha, &word, 20, reason).await.expect("lexical candidates");
    let results = SearchResults::confirm_degraded(
        &mut tx,
        &authorization,
        &search_ctx(alpha, fixtures.alpha.owner),
        candidates,
    )
    .await
    .expect("confirm");
    tx.commit().await.expect("commit");

    assert!(
        results.hits().iter().any(|hit| hit.file_id == spine.file),
        "a document the pass indexed was not findable by a word the pass itself stored \
         (searched {word:?})"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn the_pass_holds_no_transaction_while_it_embeds() {
    // `ENC-850`. The pass used to open one transaction per file and keep it open across the object
    // read, text extraction, OCR *and* the embed — then commit. Every one of those is unbounded by
    // anything PostgreSQL knows about, and `idle_in_transaction_session_timeout` is 60 seconds by
    // deliberate configuration, because a transaction left open holds its `SET LOCAL
    // app.tenant_id`. So the database terminated the connection mid-embed with `25P03` and the pass
    // returned a database error for work that had nothing to do with the database. It reached
    // `main` and turned CI red; on a deployment it is a document that never indexes and an error
    // that names the wrong subsystem.
    //
    // The timeout is shortened to a second rather than waited out, because what is under test is
    // *that no transaction is open across the slow work*, not how long the timeout is. A test that
    // slept for sixty seconds would assert the constant.
    //
    // **Watched to fail**: with the embed back inside the transaction this fails with
    // `Indexing(Storage(Database(PgDatabaseError { code: "25P03", message: "terminating connection
    // due to idle-in-transaction timeout" })))` — the exact error CI reported.
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db
        .pool_with_idle_in_transaction_timeout(Duration::from_secs(1))
        .await
        .expect("a pool that ends an idle transaction in a second");
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, version) =
        a_file_on_a_spine(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN").await;
    enqueue(&mut conn, alpha, spine.file, version).await.expect("enqueue");

    let writer = Arc::new(RecordingWriter::default());
    let (inner, _calls) = FixedWidthLocal::new(ACTIVE.dimension as usize);
    // Three times the timeout, so a pass that holds a transaction cannot finish inside it by luck
    // on a fast machine — the failure this guards against must be deterministic, not a race.
    let slow = SlowLocal { inner, delay: Duration::from_secs(3) };
    let router = EmbeddingRouter::new(slow, Forbidden, LocalCeiling::at(RESTRICTED));
    let stage = VectorStage::for_collection(
        Box::new(router),
        Box::new(FixedRank(RESTRICTED)),
        Box::new(ArcWriter(Arc::clone(&writer))),
        ACTIVE.dimension,
    )
    .expect("the stage is wired at the active model's width");
    let store = Arc::new(RecordingStore::new(DOCUMENT));

    let pass = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("an embed slower than the idle-in-transaction timeout is ordinary, not a failure");

    assert_eq!(pass.indexed, 1, "the document was not indexed");
    assert_eq!(pass.embedded, 1, "the document was indexed but not embedded");

    // The ordering argument is unchanged by the split, so it is asserted rather than assumed: the
    // vectors were written, and the manifest that says so is committed.
    assert_eq!(writer.written().len(), 1, "the vectors never reached the store");
    assert_eq!(manifest_status(&mut conn, spine.file).await.0, "READY");

    drop(db);
}
