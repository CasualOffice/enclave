//! **The chain, in one process: a committed version becomes a row in the vector store.**
//!
//! `ENC-661`, and the assertion the last five rows each built one link of. Each of those links has
//! its own test with real components — `ENC-643` enqueues on commit, `ENC-641` moves a version to
//! `AVAILABLE`/`CLEAN`, `ENC-656` resolves a rank, `ENC-557` writes a `ChunkRecord`, and this row
//! is the provider that turns text into a vector — and none of them crossed the whole path. This
//! file does, with nothing faked between the commit and the collection:
//!
//! ```text
//! VersionService::commit  ->  index_manifests row      (ENC-643)
//!         av_pass         ->  AVAILABLE / CLEAN        (ENC-641)
//!        index_pass       ->  chunk_text + a manifest  (ENC-527)
//!                         ->  bge-m3 forward pass      (ENC-661)
//!                         ->  a row in Milvus          (ENC-557)
//! ```
//!
//! # What is real and what is a double, and why each
//!
//! Real: PostgreSQL, the commit path, the antivirus pass, the indexing pass, the mounted `bge-m3`
//! weights, and Milvus. Doubled: the **object store**, which is being asked "were you read" rather
//! than "did you store correctly" and which a recording fake answers better than MinIO does, and
//! the **antivirus engine**, because whether ClamAV detects EICAR is ClamAV's problem
//! (`docs/12 §1.1`) and what is ours is that a `Clean` verdict makes a version readable.
//!
//! # `docs/12 §1.2`, and why the negative control could not stand alone
//!
//! *"An assertion about an absence passes for free."* **"No vectors were written when the model is
//! absent" was true of every build of this workspace before this row** — not because the absence was
//! honoured but because nothing wrote vectors under any circumstances. That trap is live in exactly
//! this file, so the two are one test:
//! [`a_committed_document_reaches_the_vector_store_and_without_a_model_it_does_not`] runs the same
//! document through the same pass twice, once with a stage and once without, and asserts both
//! directions. Neither half is allowed to exist on its own.
//!
//! # Run it in release
//!
//! `rten` says so in its own documentation, and a debug build of the inference kernels turns a
//! two-second forward pass into something that reads as a hang.
//!
//! ```text
//! ENCLAVE_EMBEDDING_MODEL=/path/to/model DATABASE_URL=... \
//!     cargo test --release -p enclave-worker --test embedding -- --include-ignored
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use core::sync::atomic::{AtomicI64, Ordering};
use enclave_antivirus::{
    AntivirusScanner, EngineInfo, Result as AvResult, ScanHint, ScanPolicy, ScanVerdict,
};
use enclave_audit::ChainMode;
use enclave_core::{
    Actor, ClassificationId, ClassificationPolicy, ClassificationRank, FileId, RequestContext,
    TenantId, VersionId,
};
use enclave_db::{assign_classification, define_classification, DbPool, TenantScoped};
use enclave_embeddings::model::ACTIVE;
use enclave_indexing::{
    ChunkBudget, Chunker, ChunkerVersion, ExtractorVersion, Pipeline, PlainTextExtractor,
};
use enclave_preview::RenderBudget;
use enclave_search::vector::{VectorIndex, VectorQuery};
use enclave_search::{MilvusConfig, MilvusIndex, Prefilter};
use enclave_storage::ByteStream;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_versions::{NewVersion, VersionBump, VersionService};
use enclave_worker::antivirus::{av_pass, AvCursor};
use enclave_worker::embedding::MountedEmbedder;
use enclave_worker::indexing::{index_pass, PgClassification, VectorStage};
use enclave_worker::Stop;
use futures::StreamExt as _;
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

mod common;
use common::RecordingStore;

/// Attached to every `#[ignore]` so the requirement is named at the test rather than in a comment.
const NEEDS_EVERYTHING: &str =
    "requires a live PostgreSQL, a live Milvus and the converted bge-m3 \
                                weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it \
                                with --include-ignored";

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test/1");
const EXTRACTOR: ExtractorVersion = ExtractorVersion::new("test/1");

/// The rank this tenant assigns the document, distinct from every crate constant so a test that
/// accidentally compared against a default would still be comparing two different numbers.
const SECRET: ClassificationRank = ClassificationRank::new(70);

/// Long enough to chunk, and about one subject so a nonsense vector would be obvious in a failure.
const DOCUMENT: &str = "The drainage board met on Tuesday and resolved that the perihelion review \
                        procedure shall be carried out annually rather than quarterly, with the \
                        secretary to circulate the revised schedule before Michaelmas.";

fn pipeline() -> Pipeline<PlainTextExtractor> {
    Pipeline::new(PlainTextExtractor, Chunker::new(CHUNKER, ChunkBudget::default()))
}

/// `BuildVersions` with the model this deployment embeds with, exactly as `main.rs` assembles it.
fn versions(embedding_model: &str) -> enclave_indexing::BuildVersions<'_> {
    enclave_indexing::BuildVersions { extractor: EXTRACTOR, chunker: CHUNKER, embedding_model }
}

/// A distinct, increasing instant per write.
///
/// Anchored on `now()` rather than a fixed date: `audit_events` is range-partitioned by
/// `occurred_at` and migration 0001 pre-creates three months from the current one, so a fixture
/// clock on a fixed calendar date inserts into a partition that does not exist.
fn tick() -> DateTime<Utc> {
    static CLOCK: AtomicI64 = AtomicI64::new(1);
    Utc::now() + Duration::milliseconds(CLOCK.fetch_add(1, Ordering::Relaxed))
}

/// An engine that answers `Clean` without looking, which is the correct double here.
///
/// `docs/12 §1.1`: whether ClamAV detects EICAR is ClamAV's problem. What is ours is that a clean
/// verdict is what moves a version to `AVAILABLE`/`CLEAN` and therefore what makes the indexing
/// pass willing to read it — and that is asserted below by checking the pass *deferred* before this
/// engine ran.
#[derive(Debug)]
struct CleanEngine;

#[async_trait]
impl AntivirusScanner for CleanEngine {
    async fn scan(&self, mut stream: ByteStream, _hint: ScanHint) -> AvResult<ScanVerdict> {
        // Drained, so "the object was read" is true of this double as it is of a real engine.
        while let Some(chunk) = stream.next().await {
            chunk?;
        }
        Ok(ScanVerdict::Clean)
    }

    async fn engine_info(&self) -> AvResult<EngineInfo> {
        Ok(EngineInfo {
            engine: "FakeAV 1.0".to_owned(),
            signature_version: Some("27621".to_owned()),
            scans_content: true,
        })
    }
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a live PostgreSQL; CI provides a service container, locally use \
         deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool_with_connections(4).await.expect("pool");
    (db, fixtures, pool)
}

/// The mount every test here needs, or a panic naming the variable.
fn mount() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("ENCLAVE_EMBEDDING_MODEL").unwrap_or_else(|_| panic!("{NEEDS_EVERYTHING}")),
    )
}

/// A collection no other test binary will touch.
///
/// A shared name makes two runs delete each other's documents, and that failure looks exactly like
/// a writer that never wrote — `crates/search/tests/vector_write.rs` says the same.
fn collection() -> MilvusConfig {
    let mut config = MilvusConfig::new(
        std::env::var("MILVUS_URI").unwrap_or_else(|_| "http://127.0.0.1:19530".to_owned()),
        // `ACTIVE.dimension` and never a literal: `MilvusConfig::dimension` asks the caller building
        // a collection to read it from there, and this is a caller that can.
        ACTIVE.dimension,
    );
    config.collection = format!("enclave_e2e_{}", Uuid::now_v7().simple());
    // Strong, not the production `Bounded`: this writes and immediately reads back, and under a
    // bounded read that race resolves differently on a loaded machine.
    config.consistency = milvus::v2::prelude::ConsistencyLevel::Strong;
    config.partitions = 2;
    config
}

/// The stage the worker binary builds, assembled the same way `main.rs::vector_stage` assembles it.
///
/// Deliberately not a call into `main.rs` — that is a binary — but every component is the real one,
/// including the width, which is **read back from the server** rather than handed in. See
/// `MilvusIndex::dense_width`: passing `MilvusConfig::dimension` here would compare a constant with
/// itself, which is what `VectorStage::for_collection` asks its caller not to do.
async fn stage(index: &MilvusIndex, config: MilvusConfig) -> VectorStage {
    let embedder = MountedEmbedder::from_config(&enclave_config::Config {
        embedding_model: Some(mount()),
        search: enclave_config::SearchConfig {
            provider: enclave_config::SearchProvider::Milvus,
            milvus: Some(enclave_config::MilvusSettings {
                uri: config.uri.parse().expect("a valid URI"),
                token: None,
                collection: Some(config.collection.clone()),
            }),
        },
        ..enclave_config::Config::default()
    })
    .expect("the mounted weights load")
    .expect("a configuration naming the mount builds an embedder");

    let width = index
        .dense_width()
        .await
        .expect("read the collection's dense width back from the server")
        .expect("the collection this test just created has a dense field");

    VectorStage::for_collection(
        embedder.into_embedder(),
        Box::new(PgClassification::new(ClassificationPolicy::fail_closed())),
        Box::new(MilvusIndex::new(config)),
        width,
    )
    .expect("the collection is the active model's width")
}

/// Defines this tenant's `SECRET` label. **Once per test**, never once per document.
///
/// `classifications` carries a live-uniqueness constraint on both the key and the rank, per tenant,
/// so a helper that defined it per document fails the second one on a `23505` — a fixture defect
/// that reads exactly like a broken commit path, and did for two runs of this file.
async fn define_secret(pool: &DbPool, tenant: TenantId) -> ClassificationId {
    let secret = ClassificationId::new_v7();
    let mut tx = pool.begin(tenant).await.expect("begin");
    define_classification(&mut tx, secret, "SECRET", "Secret", SECRET)
        .await
        .expect("define the label");
    tx.commit().await.expect("commit");
    secret
}

/// Writes the containers, optionally labels them, and commits a version **through the real commit
/// path**.
///
/// The label is not decoration: `PgClassification` under the shipped `FAIL_CLOSED` default refuses
/// an unlabelled file, so a test that skipped it would assert nothing about embedding and would pass
/// for the wrong reason. `None` is therefore a *subject*, not a shortcut — it is the deployment
/// state `an_unlabelled_file_is_refused_while_a_labelled_one_is_embedded` is about.
///
/// It is assigned to the *folder*, so the rank arrives by inheritance — the case a resolver reading
/// only `files.classification_id` would answer `None` for while looking correct.
async fn a_committed_document(
    conn: &mut PgConnection,
    pool: &DbPool,
    fixtures: &Fixtures,
    label: Option<ClassificationId>,
) -> (Spine, VersionId) {
    let tenant = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;

    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, owner, Utc::now()).await.expect("write the spine");

    if let Some(label) = label {
        let mut tx = pool.begin(tenant).await.expect("begin");
        assign_classification(&mut tx, spine.folder, Some(label)).await.expect("assign");
        tx.commit().await.expect("commit");
    }

    let new = NewVersion {
        id: VersionId::new_v7(),
        file_id: spine.file,
        object_key: format!("{tenant}/{}", Uuid::now_v7()),
        storage_profile_id: Uuid::now_v7(),
        size_bytes: DOCUMENT.len() as i64,
        checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb924".to_owned(),
        mime_type: "text/plain".to_owned(),
        bump: VersionBump::Minor,
        created_by: owner,
        comment: Some("the first draft".to_owned()),
    };

    let ctx = RequestContext { actor: Actor::User(owner), ..RequestContext::system(tenant) };
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let committed = VersionService::commit(&mut tx, &ctx, ChainMode::Enabled, &new, tick())
        .await
        .expect("commit a version");
    tx.commit().await.expect("commit");

    (spine, committed.version.id)
}

async fn manifest(conn: &mut PgConnection, file: FileId) -> (String, String) {
    let row = sqlx::query("SELECT status, embedding_model FROM index_manifests WHERE file_id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("the manifest row");
    (
        row.try_get("status").expect("status"),
        row.try_get::<Option<String>, _>("embedding_model")
            .expect("embedding_model")
            .unwrap_or_default(),
    )
}

/// Whether the collection holds a chunk of `file`, asked through the query path a search uses.
///
/// `ceiling` is the caller's classification ceiling, so this doubles as the assertion that the rank
/// written into the collection is the one PostgreSQL holds: the same query at a ceiling below the
/// label must not find it.
async fn found(
    index: &MilvusIndex,
    tenant: TenantId,
    file: FileId,
    ceiling: Option<ClassificationRank>,
) -> bool {
    let prefilter = Prefilter::resolved_from_postgres(Vec::new(), ceiling);
    index
        .candidates(VectorQuery {
            tenant,
            // Any vector of the right width: this asks whether the row is *there and visible to the
            // filter*, never how well it ranks. `docs/12 §1.1` — ranking is Milvus's problem.
            embedding: &vec![0.02_f32; ACTIVE.dimension as usize],
            budget: 100,
            prefilter: &prefilter,
        })
        .await
        .expect("query the collection")
        .iter()
        .any(|candidate| candidate.file_id == file)
}

// =================================================================================================
// The assertion this whole row exists for
// =================================================================================================

/// **Commit → enqueue → antivirus → index → a row in the vector store.** And with no model, none.
///
/// The two halves are one test on purpose (`docs/12 §1.2`). "No vectors when the model is absent"
/// was true of every build before this row, for the wrong reason — nothing wrote vectors at all —
/// so it is asserted here only beside the run that *does* write one, over the same document, the
/// same pass and the same collection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL, a live Milvus and the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn a_committed_document_reaches_the_vector_store_and_without_a_model_it_does_not() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");

    let config = collection();
    let index = MilvusIndex::new(config.clone());
    index.ensure_collection().await.expect("provision the collection");

    // ---------------------------------------------------------------------------------------
    // 1. The commit enqueues it (`ENC-643`), and antivirus has not seen it yet.
    // ---------------------------------------------------------------------------------------
    let secret = define_secret(&pool, alpha).await;
    let (spine, version) = a_committed_document(&mut conn, &pool, &fixtures, Some(secret)).await;

    assert_eq!(
        manifest(&mut conn, spine.file).await.0,
        "PENDING",
        "the commit did not enqueue the version, so nothing would ever index it"
    );

    let store = Arc::new(RecordingStore::new(DOCUMENT));

    // ---------------------------------------------------------------------------------------
    // 2. An indexing pass before the scan **defers** rather than reading (`CLAUDE.md` rule 9).
    //
    //    This is not a detour. It is what makes the antivirus step below load-bearing rather than
    //    decorative: without it, a pass that read unscanned bytes would produce the same final
    //    state and every assertion after this point would still hold.
    // ---------------------------------------------------------------------------------------
    let stage = stage(&index, config.clone()).await;
    let early = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(ACTIVE.id),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("a deferral is not a failure");

    assert_eq!(early.deferred, 1, "an unscanned version was not deferred");
    assert_eq!(early.embedded, 0);
    assert!(store.reads().is_empty(), "an unscanned version's bytes were read");
    assert!(
        !found(&index, alpha, spine.file, None).await,
        "a version antivirus had not cleared reached the vector store"
    );

    // ---------------------------------------------------------------------------------------
    // 3. Antivirus clears it (`ENC-641`).
    // ---------------------------------------------------------------------------------------
    let scanned = av_pass(
        &pool,
        alpha,
        &CleanEngine,
        store.as_ref(),
        ScanPolicy::from_config(&enclave_config::AntivirusConfig::default()),
        10,
        AvCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("the antivirus pass");
    assert_eq!(scanned.cleared, 1, "the engine's clean verdict did not clear the version");

    let state: (String, String) = {
        let row = sqlx::query("SELECT status, av_status FROM file_versions WHERE id = $1")
            .bind(version.as_uuid())
            .fetch_one(&mut conn)
            .await
            .expect("the version row");
        (row.try_get("status").expect("status"), row.try_get("av_status").expect("av_status"))
    };
    assert_eq!(state, ("AVAILABLE".to_owned(), "CLEAN".to_owned()));

    // ---------------------------------------------------------------------------------------
    // 4. The indexing pass embeds it and writes the row.
    // ---------------------------------------------------------------------------------------
    let indexed = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        Some(&stage),
        store.as_ref(),
        versions(ACTIVE.id),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("the indexing pass");

    assert_eq!(indexed.indexed, 1, "the document was not indexed");
    assert_eq!(indexed.embedded, 1, "the document was indexed but not embedded");

    let (status, model) = manifest(&mut conn, spine.file).await;
    assert_eq!(status, "READY");
    assert_eq!(
        model, ACTIVE.id,
        "the manifest does not name the model that produced the vectors, so `docs/07 §3`'s \
         reindex trigger would compare a string nothing embedded under"
    );

    // **The row is in the store, at the right width and under the right rank.**
    //
    // The width is implicit and load-bearing: `candidates` searches the collection's dense field,
    // which was created at `ACTIVE.dimension`, and Milvus refuses a query vector of any other size
    // — so a hit at all is a hit against a 1024-wide row.
    assert!(
        found(&index, alpha, spine.file, None).await,
        "the pass reported `embedded: 1` and the collection holds nothing for this file"
    );
    assert!(
        found(&index, alpha, spine.file, Some(SECRET)).await,
        "a caller cleared to exactly the file's rank could not see it"
    );
    assert!(
        !found(&index, alpha, spine.file, Some(ClassificationRank::new(SECRET.get() - 1))).await,
        "a caller below the file's rank saw it, so the rank written into the collection is not \
         the one PostgreSQL holds"
    );

    // ---------------------------------------------------------------------------------------
    // 5. **The negative control**, and it is the same document through the same pass.
    //
    //    A second file, committed and cleared identically, indexed with **no stage** — which is
    //    what a deployment that has mounted no model has. It must be indexed and *not* embedded,
    //    and its manifest must honestly record no model.
    // ---------------------------------------------------------------------------------------
    let (unembedded, _) = a_committed_document(&mut conn, &pool, &fixtures, Some(secret)).await;
    av_pass(
        &pool,
        alpha,
        &CleanEngine,
        store.as_ref(),
        ScanPolicy::from_config(&enclave_config::AntivirusConfig::default()),
        10,
        AvCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("the antivirus pass");

    let without = index_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        // The difference, and the only difference.
        None,
        store.as_ref(),
        versions(""),
        RenderBudget::default(),
        10,
        &Stop::new(),
    )
    .await
    .expect("a pass with no stage still indexes");

    assert_eq!(without.indexed, 1, "a deployment with no model must still index text");
    assert_eq!(without.embedded, 0, "a pass with no stage embedded something");
    assert_eq!(manifest(&mut conn, unembedded.file).await, ("READY".to_owned(), String::new()));
    assert!(
        !found(&index, alpha, unembedded.file, None).await,
        "a pass with no embedding stage wrote to the vector store"
    );

    drop(db);
}

/// An unlabelled file is **not** embedded, and a labelled one beside it is.
///
/// `ENC-656`'s refusal, asserted where it now has consequences. Under the shipped `FAIL_CLOSED`
/// default a file whose chain carries no label has no rank to route by, and
/// `crates/worker/src/indexing.rs` argues at length that guessing one is wrong in both directions.
///
/// The pairing is the test. "The unlabelled file is not in the collection" held for free against
/// every build before this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL, a live Milvus and the converted bge-m3 weights on a volume named by ENCLAVE_EMBEDDING_MODEL; CI runs it with --include-ignored"]
async fn an_unlabelled_file_is_refused_while_a_labelled_one_is_embedded() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");

    let config = collection();
    let index = MilvusIndex::new(config.clone());
    index.ensure_collection().await.expect("provision the collection");
    let stage = stage(&index, config).await;

    // The control first, so a failure here is unambiguous: this one *must* embed.
    let secret = define_secret(&pool, alpha).await;
    let (labelled, _) = a_committed_document(&mut conn, &pool, &fixtures, Some(secret)).await;

    // And the subject: the identical spine, the identical commit, with nothing assigned anywhere
    // above it. Identical is the point — the only difference between the two documents is the
    // label, so the refusal cannot be attributed to anything else.
    let (bare, _) = a_committed_document(&mut conn, &pool, &fixtures, None).await;

    let store = Arc::new(RecordingStore::new(DOCUMENT));
    av_pass(
        &pool,
        alpha,
        &CleanEngine,
        store.as_ref(),
        ScanPolicy::from_config(&enclave_config::AntivirusConfig::default()),
        10,
        AvCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("the antivirus pass clears both");

    // One pass over both. The refusal stops the pass — `WorkerError::Unclassified` is not a verdict
    // about a document, so it aborts rather than recording `FAILED` — which means the labelled file
    // may or may not have been reached first. So the pass is run until it stops making progress,
    // and what is asserted is the *end state* of each file rather than a single pass's counters.
    for _ in 0..4 {
        let outcome = index_pass(
            &pool,
            alpha,
            &pipeline(),
            None,
            Some(&stage),
            store.as_ref(),
            versions(ACTIVE.id),
            RenderBudget::default(),
            10,
            &Stop::new(),
        )
        .await;
        if outcome.is_err() {
            // Expected: the unlabelled file refuses. Its transaction is rolled back and it stays
            // claimed, exactly as an object-storage outage leaves a file.
            continue;
        }
    }

    assert!(
        found(&index, alpha, labelled.file, None).await,
        "the labelled file was not embedded, so this test proves nothing about the refusal"
    );
    assert!(
        !found(&index, alpha, bare.file, None).await,
        "an unlabelled file was embedded, so a rank nobody assigned was written into the \
         collection and is deciding which callers can see the document"
    );

    drop(db);
}
