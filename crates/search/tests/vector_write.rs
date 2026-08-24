//! The write path: what puts chunks into the vector store, what takes them out, and the ordering
//! that makes a removal's claim about `retrieval_denylist` honest.
//!
//! # What is being tested, and what deliberately is not
//!
//! `ENC-547`. Until it, nothing wrote Milvus at all — `MilvusIndex` could create the collection,
//! search it, count it and ping it — so the index was permanently empty in any real deployment and
//! `retrieval_denylist.indexed_seq` had no honest producer, because there was nothing to confirm.
//!
//! These tests are about **our wiring**, not about Milvus. Nothing here measures whether the store
//! ranks well, how fast it is, or how its index behaves — only that the columns we build are the
//! ones the collection declares, that a re-index replaces rather than accumulates, that a removal
//! removes one file, and that the confirmation names the generation the removal *started* with.
//!
//! # A fixture that could not tell two implementations apart (`ENC-661`)
//!
//! Recorded here rather than in a commit message, because it is the kind of finding
//! `docs/12 §1.2` exists to produce and the next person to touch
//! [`the_dense_width_is_the_servers_answer_and_absent_means_absent`] needs it.
//!
//! `MilvusIndex::dense_width` was added so `VectorStage::for_collection` could be handed the width
//! **the server holds** rather than the width this process intended — the composition root sets
//! `MilvusConfig::dimension` from `enclave_embeddings::model::ACTIVE.dimension`, so passing that
//! back would compare a constant with itself.
//!
//! The first version of the test asked through the same handle that created the collection, and it
//! **passed with `dense_width` replaced by `Ok(Some(self.config.dimension))`** — the implementation
//! it exists to forbid. The two cases it could not distinguish were *"the width came from
//! `describe_collection`"* and *"the width came from our own configuration"*, and they are
//! indistinguishable by construction: `ensure_collection` creates the collection **at**
//! `config.dimension`, so the two numbers are equal in any fixture that uses one handle.
//!
//! It looked green for the reason a vacuous test always does: every assertion in it was true, and
//! none of them was true *because of* the mechanism named in the test.
//!
//! What the fixture had to become is the production failure itself: the collection is created
//! through one handle and interrogated through a **second handle configured for a different
//! width** — which is a process compiled against a different `ACTIVE.dimension` reading a
//! collection created by an older revision, by hand, or by a restore. That is what `ENC-533` is
//! about, and it errors at neither end.
//!
//! # Two kinds of test, and why the interesting one needs no Milvus
//!
//! The ordering that `ENC-520` and `ENC-547` care about is not observable against a real store: the
//! failure it forbids is a suppression landing **while the store call is in flight**, and there is
//! no way to arrange that around an RPC that takes single-digit milliseconds. So the handoff tests
//! use a fake [`VectorWriter`] that does its interfering *inside* `remove_file`, against a real
//! PostgreSQL row — which is the half that holds the state — and one further test runs the same
//! handoff against a real Milvus so that the two halves are known to fit.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{ChunkId, ClassificationRank, FileId, TenantId, VersionId};
use enclave_db::{DbPool, TenantScoped};
use enclave_search::health::IndexCensus;
use enclave_search::vector::{VectorIndex, VectorQuery};
use enclave_search::{
    denylist, remove_and_confirm, CatchUp, ChunkRecord, MilvusConfig, MilvusIndex, Prefilter,
    SearchError, SparseTerms, SuppressionSeq, VectorWriter,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use milvus::v2 as sdk;
use milvus::v2::prelude::ConsistencyLevel;
use uuid::Uuid;

/// Small enough that a vector is readable in a failure message, wide enough to be a real index.
const DIMENSION: u32 = 8;

/// Far above anything written here, so a missing result is a retrieval failure and never a
/// truncation (`plans/M3-DISCOVERY.md` D21).
const BUDGET: u32 = 100;

fn endpoint() -> String {
    std::env::var("MILVUS_URI").unwrap_or_else(|_| "http://127.0.0.1:19530".to_owned())
}

/// A collection no other test binary will touch — a shared name makes two runs delete each other's
/// documents, and that failure looks exactly like a writer that never wrote.
fn config() -> MilvusConfig {
    let mut config = MilvusConfig::new(endpoint(), DIMENSION);
    config.collection = format!("enclave_write_{}", Uuid::now_v7().simple());
    // Strong, not the production `Bounded`: these tests write and then immediately read back, and
    // under a bounded read that race resolves differently on a loaded machine. `MilvusConfig`
    // documents why the knob exists rather than the test sleeping.
    config.consistency = ConsistencyLevel::Strong;
    config.partitions = 2;
    config
}

/// A deterministic vector whose only job is to be distinct from the others.
fn dense(seed: usize) -> Vec<f32> {
    (0..DIMENSION as usize)
        .map(|axis| if axis == seed % DIMENSION as usize { 1.0 } else { 0.1 })
        .collect()
}

/// One chunk of `file`, fully populated. [`bare`] is the variant with everything optional absent.
fn chunk(tenant: TenantId, spine: &Spine, ordinal: usize, text: &str) -> ChunkRecord {
    ChunkRecord {
        // Deterministic in the same sense the real one is — the same `(file, ordinal)` yields the
        // same id — which is what makes the re-index test a re-index rather than a second document.
        chunk_id: ChunkId::from_uuid(Uuid::new_v5(
            &spine.file.as_uuid(),
            ordinal.to_string().as_bytes(),
        )),
        tenant,
        workspace: spine.workspace,
        library: spine.library,
        file: spine.file,
        version: VersionId::new_v7(),
        chunk_type: "BODY".to_owned(),
        title: Some(format!("document {}", spine.file)),
        text: text.to_owned(),
        dense: dense(ordinal),
        sparse: SparseTerms::from([(ordinal as u32, 1.0), (ordinal as u32 + 1, 0.5)]),
        classification_rank: ClassificationRank::new(0),
        // Wrong in the permissive direction on purpose, as `crates/search/tests/milvus.rs` does:
        // this is what a real index looks like between an ACL write and an index write, and nothing
        // downstream is allowed to believe it.
        acl_tokens: vec!["user:anyone".to_owned()],
        barrier_tokens: Vec::new(),
        acl_epoch: 1,
        mime_type: "application/pdf".to_owned(),
        language: Some("en".to_owned()),
        page_number: 1,
        sheet_name: None,
        section_path: Some("/".to_owned()),
        modified: Utc::now(),
    }
}

/// The same chunk with every nullable field absent.
///
/// `ENC-523` is the reason this exists as a fixture rather than as an afterthought: the validity
/// masks a nullable field needs are what a live server rejects a batch over, and a test that only
/// ever writes present values never exercises them.
fn bare(mut record: ChunkRecord) -> ChunkRecord {
    record.title = None;
    record.language = None;
    record.sheet_name = None;
    record.section_path = None;
    record.page_number = 0;
    record
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

/// Reads a tenant's catch-up counters through its own transaction.
async fn catch_up(pool: &DbPool, tenant: TenantId) -> CatchUp {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let counts = denylist::catch_up(&mut tx, tenant).await.expect("catch up");
    tx.commit().await.expect("commit");
    counts
}

/// Suppresses a file in its own transaction and returns the generation that created.
async fn suppress(
    pool: &DbPool,
    tenant: TenantId,
    file: FileId,
    now: DateTime<Utc>,
) -> SuppressionSeq {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let seq = denylist::suppress(&mut tx, tenant, file, "content_purged", now, None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");
    seq
}

/// What the fake writer does while the "store call" is in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum During {
    /// Nothing. The ordinary successful removal.
    Nothing,
    /// A second revocation of the same file lands, bumping the generation.
    ///
    /// This is the race the handoff exists for and it cannot be arranged around a real RPC.
    ASecondSuppression,
    /// The store refuses.
    Failure,
}

/// A [`VectorWriter`] that reports what the denylist row looked like at the moment it was called.
///
/// The observation is the point. "Confirmed after the store call" is not visible from outside —
/// both orders end with the same row — so the only way to assert it is to look at the row *from
/// inside* the store call, which is what a fake can do and a real Milvus cannot.
struct Interfering {
    pool: DbPool,
    tenant: TenantId,
    file: FileId,
    during: During,
    /// The row's state as the store call saw it.
    observed: Mutex<Option<CatchUp>>,
}

impl std::fmt::Debug for Interfering {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Interfering").field("during", &self.during).finish()
    }
}

#[async_trait]
impl VectorWriter for Interfering {
    async fn upsert_chunks(&self, _chunks: &[ChunkRecord]) -> Result<(), SearchError> {
        Ok(())
    }

    async fn remove_file(&self, tenant: TenantId, file: FileId) -> Result<(), SearchError> {
        assert_eq!(tenant, self.tenant, "the handoff asked the store about another tenant");
        assert_eq!(file, self.file, "the handoff asked the store about another file");

        *self.observed.lock().expect("observation") = Some(catch_up(&self.pool, tenant).await);

        match self.during {
            During::Nothing => Ok(()),
            During::ASecondSuppression => {
                suppress(&self.pool, tenant, file, Utc::now()).await;
                Ok(())
            }
            During::Failure => {
                Err(SearchError::VectorIndex { operation: "delete", retryable: true })
            }
        }
    }
}

impl Interfering {
    fn new(pool: DbPool, tenant: TenantId, file: FileId, during: During) -> Self {
        Self { pool, tenant, file, during, observed: Mutex::new(None) }
    }

    fn observed(&self) -> CatchUp {
        self.observed
            .lock()
            .expect("observation")
            .expect("the handoff never called the store at all")
    }
}

/// A suppressed file, with its spine written so the denylist's foreign key holds.
async fn suppressed_file(
    db: &TestDb,
    fixtures: &Fixtures,
    pool: &DbPool,
) -> (TenantId, FileId, SuppressionSeq) {
    let tenant = fixtures.alpha.id;
    let now = Utc::now();
    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    let seq = suppress(pool, tenant, spine.file, now).await;
    (tenant, spine.file, seq)
}

/// **`ENC-547`'s ordering, from inside the store call.**
///
/// The row must still be *unasserted* while the removal is running, and *caught up* once it has
/// returned. Both halves are needed and neither is enough: the first alone passes against a handoff
/// that never confirms anything, and the second alone passes against one that confirms first and
/// then removes — which is a claim about a write that had not happened.
///
/// # Why this one does not use a transaction, and the first version of it was vacuous
///
/// The observer is a second connection, and a second connection cannot see an uncommitted `UPDATE`.
/// Written against `TenantScoped::begin` — which is what the other tests here use and what a worker
/// would use — the "still unasserted" assertion therefore held *whatever the order was*, and the
/// deliberate violation that swapped the two statements passed. That is exactly `docs/12 §1.2`'s
/// recurring shape: an assertion about an absence that is satisfied for free.
///
/// So the connection here autocommits, which makes each statement visible as it happens and makes
/// the observation mean what it says. A pooled connection is a legitimate way to make this call
/// — [`remove_and_confirm`]'s documentation asks for one that is *not* inside the ACL transaction —
/// and the transactional case is covered by [`a_removal_that_failed_confirms_nothing`], which
/// catches the same swap from the other side because a confirmation written first survives the
/// commit that follows a failed removal.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn the_confirmation_is_written_after_the_store_call_and_not_before() {
    let (db, fixtures, pool) = start().await;
    let (tenant, file, seq) = suppressed_file(&db, &fixtures, &pool).await;

    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 1, behind: 0, caught_up: 0 },
        "a fresh suppression is unasserted, or the assertions below prove nothing"
    );

    let store = Interfering::new(pool.clone(), tenant, file, During::Nothing);
    let mut conn = db.connect().await.expect("an autocommitting connection");
    let recorded =
        remove_and_confirm(&mut conn, &store, tenant, file, seq).await.expect("the handoff runs");

    assert!(recorded, "nothing was recorded against a row that is still there");
    assert_eq!(
        store.observed(),
        CatchUp { unasserted: 1, behind: 0, caught_up: 0 },
        "the row was already confirmed when the store was called, so the claim names a removal that \
         had not happened"
    );
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 0, behind: 0, caught_up: 1 },
        "the removal completed and the row still says nobody has asserted anything"
    );

    drop(db);
}

/// **The race the handoff exists for.** A revocation that lands *during* the removal is not absorbed
/// by it.
///
/// The removal starts at generation 1. While it is in flight a second revocation of the same file
/// bumps the row to generation 2 — a real event: the file was re-shared and re-revoked, or a subtree
/// ACL change swept over it. The removal only ever covered generation 1, so the row must read
/// `behind`, which is the state that keeps the reconciler coming back to it.
///
/// A handoff that re-read the generation after the store call — the natural convenience refactor,
/// and the one `ENC-520` names — would confirm generation 2 and the row would read `caught_up`
/// about a revocation nothing had acted on. That is the whole correctness argument, and this is the
/// only place it is visible.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_suppression_that_lands_during_the_removal_is_not_absorbed() {
    let (db, fixtures, pool) = start().await;
    let (tenant, file, seq) = suppressed_file(&db, &fixtures, &pool).await;
    assert_eq!(seq, SuppressionSeq::new(1), "the first suppression is generation 1");

    let store = Interfering::new(pool.clone(), tenant, file, During::ASecondSuppression);
    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    let recorded =
        remove_and_confirm(&mut tx, &store, tenant, file, seq).await.expect("the handoff runs");
    tx.commit().await.expect("commit");

    assert!(recorded, "the confirmation did not reach the row");
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 0, behind: 1, caught_up: 0 },
        "the removal absorbed a suppression that landed while it was running, so the denylist now \
         claims a revocation is covered that nothing has acted on"
    );

    // The control, on the same row: a removal that names the *new* generation does move it to
    // caught up. Without this the assertion above is satisfied by a confirmation that never lands.
    let store = Interfering::new(pool.clone(), tenant, file, During::Nothing);
    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    remove_and_confirm(&mut tx, &store, tenant, file, SuppressionSeq::new(2))
        .await
        .expect("the second handoff runs");
    tx.commit().await.expect("commit");
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 0, behind: 0, caught_up: 1 },
        "a removal covering the current generation did not record as caught up, so `behind` above \
         may just mean `confirm_indexed` never works"
    );

    drop(db);
}

/// A removal that failed records nothing, and the row stays honestly *unknown*.
///
/// `NULL` is not "the index still holds it" — `migrations/0014_index_catch_up.sql` is emphatic that
/// it is *unknown* — and writing a confirmation anyway would be the fabricated claim the row's own
/// `CHECK` cannot detect, because the generation would be perfectly in range.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_removal_that_failed_confirms_nothing() {
    let (db, fixtures, pool) = start().await;
    let (tenant, file, seq) = suppressed_file(&db, &fixtures, &pool).await;

    let store = Interfering::new(pool.clone(), tenant, file, During::Failure);
    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    let outcome = remove_and_confirm(&mut tx, &store, tenant, file, seq).await;
    tx.commit().await.expect("commit");

    assert!(outcome.is_err(), "a store that refused reported success: {outcome:?}");
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 1, behind: 0, caught_up: 0 },
        "a failed removal was recorded as a completed one"
    );

    // The control. The same row, the same generation, a store that succeeds: it must move. Without
    // it, the assertion above holds against a `confirm_indexed` that is simply broken.
    let store = Interfering::new(pool.clone(), tenant, file, During::Nothing);
    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    remove_and_confirm(&mut tx, &store, tenant, file, seq).await.expect("the retry runs");
    tx.commit().await.expect("commit");
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 0, behind: 0, caught_up: 1 },
        "a successful removal did not record either, so the assertion above proves nothing"
    );

    drop(db);
}

/// **The write path, end to end against a real store.** A chunk written here is a candidate the
/// generator reads back.
///
/// This is the assertion that the collection's columns and the writer's columns are the same
/// columns. `src/milvus.rs` compares them structurally on every machine; only a live server proves
/// that Milvus *accepts* the batch — which is exactly where `ENC-523` found the last defect, and it
/// found it on the validity masks that a fully-populated fixture never exercises. So one of the two
/// chunks here has every nullable field absent, and it is asserted for by identity.
/// The dense width comes back from the **server**, and it is `None` for a collection that is absent.
///
/// `ENC-661`. `MilvusIndex::dense_width` exists so `VectorStage::for_collection` can be handed two
/// independently-sourced facts rather than a constant compared with itself: the composition root
/// sets `MilvusConfig::dimension` from `enclave_embeddings::model::ACTIVE.dimension`, so passing it
/// back would prove only that a constant equals itself.
///
/// The width used here is [`DIMENSION`] — **8**, not the active model's 1024 — precisely so that a
/// `dense_width` which returned the configured or the compiled-in value instead of the server's
/// would fail this by name. That is the whole point of the test; a fixture at 1024 would pass
/// against all three implementations.
///
/// The `None` half is not decoration either. It is a different fact from "the collection exists and
/// is the wrong width", and collapsing them would make a fresh deployment — where the collection is
/// about to be created — indistinguishable from a corrupt one.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn the_dense_width_is_the_servers_answer_and_absent_means_absent() {
    let created = config();
    let index = MilvusIndex::new(created.clone());

    assert_eq!(
        index.dense_width().await.expect("an absent collection is not an error"),
        None,
        "a collection that does not exist reported a width, so a fresh deployment cannot be told \
         from one whose collection is the wrong shape"
    );

    index.ensure_collection().await.expect("provision the collection");

    // **The handle that asks is configured for a different width from the one the collection was
    // created with**, and that is the whole test rather than an oddity of the fixture.
    //
    // The first version asked through the *same* handle, and it passed with `dense_width` replaced
    // by `Ok(Some(self.config.dimension))` — because `ensure_collection` creates the collection at
    // `config.dimension`, so the two numbers are equal by construction and the test could not tell
    // the server's answer from our own. Caught by performing the deliberate violation
    // (`docs/12 §1.2`), not by reading it.
    //
    // The arrangement below is the production failure exactly: a collection created by an older
    // revision, or by hand, or by a restore, read by a process compiled against a different
    // `ACTIVE.dimension`. That is what `ENC-533` is about, and it errors at neither end.
    let mut mismatched = created.clone();
    mismatched.dimension = DIMENSION * 2;
    let stale = MilvusIndex::new(mismatched);

    assert_eq!(
        stale.dense_width().await.expect("describe the collection"),
        Some(DIMENSION),
        "the width did not come from the server: the collection is {DIMENSION} wide and the handle \
         that asked was configured for {}, so a `dense_width` echoing its own configuration would \
         have answered the wrong number — and the width check built on it would compare a constant \
         with itself",
        DIMENSION * 2
    );
}

#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn a_written_chunk_is_a_candidate_the_generator_reads_back() {
    let tenant = TenantId::new_v7();
    let (populated, sparse) = (Spine::new(tenant), Spine::new(tenant));

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");

    index
        .upsert_chunks(&[
            chunk(tenant, &populated, 0, "the body of the populated document"),
            bare(chunk(tenant, &sparse, 1, "the body of the document with nothing optional set")),
        ])
        .await
        .expect("the store accepted the batch");

    assert_eq!(index.chunks(tenant).await.expect("census"), 2, "the batch did not land");

    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let proposed = index
        .candidates(VectorQuery { tenant, embedding: &embedding, budget: BUDGET, prefilter: &all })
        .await
        .expect("the index answers");

    let files: Vec<FileId> = proposed.iter().map(|candidate| candidate.file_id).collect();
    for expected in [populated.file, sparse.file] {
        assert!(files.contains(&expected), "{expected} was written and not proposed: {files:?}");
    }

    // And the body survived the round trip, so `text` is being written and not merely accepted. A
    // candidate with no excerpt would satisfy the membership assertion above on its own.
    let excerpt = proposed
        .iter()
        .find(|candidate| candidate.file_id == populated.file)
        .and_then(|candidate| candidate.excerpt.clone())
        .expect("a chunk with a body carries an excerpt");
    assert_eq!(excerpt.text(), "the body of the populated document");

    let client = raw_client().await;
    drop_collection(&client, &index.config().collection).await;
}

/// **Idempotence.** Re-indexing the same chunks replaces them; it does not accumulate a second copy.
///
/// `ENC-513` is why this is load-bearing rather than tidy: indexing runs off an at-least-once
/// outbox, so a worker that crashed halfway runs again as a matter of course. `chunk_id` is
/// deterministic, and Milvus does not enforce primary-key uniqueness on `insert` — only on `upsert`
/// — so a writer that used the obvious call would double the collection on every retry, and the
/// orphans would keep the `acl_tokens` of the run that wrote them forever.
///
/// The third chunk is the positive control: the count has to be *able* to move, or "still two"
/// means nothing.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn a_reindex_upserts_in_place_rather_than_accumulating() {
    let tenant = TenantId::new_v7();
    let spine = Spine::new(tenant);

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");

    let first = vec![
        chunk(tenant, &spine, 0, "the first pass"),
        chunk(tenant, &spine, 1, "the first pass"),
    ];
    index.upsert_chunks(&first).await.expect("the first pass");
    assert_eq!(index.chunks(tenant).await.expect("census"), 2);

    // The retry: same ids, different bodies, as a re-extraction of the same version would produce.
    let second = vec![
        chunk(tenant, &spine, 0, "the second pass"),
        chunk(tenant, &spine, 1, "the second pass"),
    ];
    index.upsert_chunks(&second).await.expect("the retry");
    assert_eq!(
        index.chunks(tenant).await.expect("census"),
        2,
        "the retry accumulated a second copy of every chunk instead of replacing them"
    );

    // The replacement is a replacement and not a no-op: the body that comes back is the second
    // pass's. Without this the count above is satisfied by a writer that silently dropped the retry.
    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let proposed = index
        .candidates(VectorQuery { tenant, embedding: &embedding, budget: BUDGET, prefilter: &all })
        .await
        .expect("the index answers");
    let excerpt = proposed
        .first()
        .and_then(|candidate| candidate.excerpt.clone())
        .expect("the file is still a candidate");
    assert_eq!(excerpt.text(), "the second pass", "the retry did not replace the chunk's body");

    // The control: a chunk with an id nobody has written before *does* raise the count.
    index
        .upsert_chunks(&[chunk(tenant, &spine, 2, "a third chunk")])
        .await
        .expect("a genuinely new chunk");
    assert_eq!(
        index.chunks(tenant).await.expect("census"),
        3,
        "the count cannot move at all, so `still 2` above says nothing about upserting"
    );

    let client = raw_client().await;
    drop_collection(&client, &index.config().collection).await;
}

/// **Removal.** One file's chunks leave; every other file's stay.
///
/// The deliberate violation is one clause: without `file_id`, [`VectorWriter::remove_file`] empties
/// the tenant's whole index. Nothing catches that at query time — a search over an emptied index
/// returns no hits, which reads exactly like a search that found nothing — so the assertion that the
/// *other* file survives is the one carrying the weight, and it is asserted by identity.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn removing_a_file_takes_its_chunks_and_leaves_the_rest() {
    let tenant = TenantId::new_v7();
    let (purged, kept) = (Spine::new(tenant), Spine::new(tenant));

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    index
        .upsert_chunks(&[
            chunk(tenant, &purged, 0, "the purged document"),
            chunk(tenant, &purged, 1, "the purged document, continued"),
            chunk(tenant, &kept, 2, "the document that stays"),
        ])
        .await
        .expect("the batch");
    assert_eq!(index.chunks(tenant).await.expect("census"), 3);

    index.remove_file(tenant, purged.file).await.expect("the removal");

    assert_eq!(
        index.chunks(tenant).await.expect("census"),
        1,
        "the removal took a number of chunks other than the purged file's two"
    );

    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let proposed = index
        .candidates(VectorQuery { tenant, embedding: &embedding, budget: BUDGET, prefilter: &all })
        .await
        .expect("the index answers");
    let files: Vec<FileId> = proposed.iter().map(|candidate| candidate.file_id).collect();
    assert_eq!(
        files,
        vec![kept.file],
        "the removal emptied the tenant's index rather than removing one file"
    );

    // Removing it again is not an error. The store is eventually consistent with a database that
    // has already decided, and a retry of a completed removal must not look like a fault.
    index.remove_file(tenant, purged.file).await.expect("a repeated removal is not a failure");

    let client = raw_client().await;
    drop_collection(&client, &index.config().collection).await;
}

/// The two halves together: a real removal from a real store, and the claim it leaves in PostgreSQL.
///
/// The handoff tests above use a fake because the race they are about cannot be arranged around a
/// real RPC. This one has no race in it; what it proves is that the same call works when the store
/// is the one that ships — that `remove_and_confirm` composes a `MilvusIndex` and a denylist row
/// without either of them needing an adapter written for the test.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search) and a live PostgreSQL \
            with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_removal_through_the_real_store_records_the_generation_it_started_with() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let now = Utc::now();

    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    index
        .upsert_chunks(&[chunk(tenant, &spine, 0, "a document about to be purged")])
        .await
        .expect("the batch");
    assert_eq!(
        index.chunks(tenant).await.expect("census"),
        1,
        "nothing was indexed, so the removal below has nothing to remove"
    );

    let seq = suppress(&pool, tenant, spine.file, now).await;
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 1, behind: 0, caught_up: 0 },
        "the row is not unasserted before the removal, so the change below proves nothing"
    );

    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    let recorded =
        remove_and_confirm(&mut tx, &index, tenant, spine.file, seq).await.expect("the handoff");
    tx.commit().await.expect("commit");

    assert!(recorded, "the confirmation did not reach the row");
    assert_eq!(index.chunks(tenant).await.expect("census"), 0, "the chunks are still in the store");
    assert_eq!(
        catch_up(&pool, tenant).await,
        CatchUp { unasserted: 0, behind: 0, caught_up: 1 },
        "the store write happened and PostgreSQL still says nobody has asserted anything"
    );

    let client = raw_client().await;
    drop_collection(&client, &index.config().collection).await;
    drop(db);
}

/// A chunk the collection cannot hold is refused before the connection is touched.
///
/// Not `#[ignore]`: it needs no server, which is the point. The refusal has to happen locally, or
/// the operator gets `the vector index could not answer \`upsert\`` — the SDK's message, which names
/// the offending field, is discarded by `CLAUDE.md` rule 10 — and a whole batch of files silently
/// stops being findable.
#[tokio::test]
async fn an_unindexable_chunk_is_refused_without_a_round_trip() {
    // Port 1 is reserved and nothing listens on it, so reaching the store is impossible: whatever
    // this returns, it cannot have come from a server.
    let mut settings = MilvusConfig::new("http://127.0.0.1:1", DIMENSION);
    settings.connect_timeout = std::time::Duration::from_millis(250);
    let index = MilvusIndex::new(settings);

    let tenant = TenantId::new_v7();
    let spine = Spine::new(tenant);
    let mut record = chunk(tenant, &spine, 0, "a body");
    record.dense = vec![0.5; DIMENSION as usize + 1];

    let outcome = index.upsert_chunks(&[record]).await;
    assert!(
        matches!(outcome, Err(SearchError::UnindexableChunk { column: "dense_vector", .. })),
        "a chunk of the wrong width was carried to a store that does not exist: {outcome:?}"
    );

    // The control: an empty batch is a no-op and reaches nothing either, which is the other half of
    // "before the connection is touched". A writer that connected first would fail here.
    index.upsert_chunks(&[]).await.expect("an empty batch is not an error");
}

/// A client for the test's own teardown.
async fn raw_client() -> sdk::ClientV2 {
    sdk::ClientV2::new(&sdk::prelude::ConnectConfig::new().uri(endpoint()))
        .await
        .expect("connect to Milvus")
}

/// Removes the test's collection, and does not fail the test if it cannot — a teardown that panics
/// replaces the real failure with its own.
async fn drop_collection(client: &sdk::ClientV2, collection: &str) {
    let request = sdk::request::collection::DropCollectionRequest::builder()
        .collection_name(collection)
        .build()
        .expect("a valid drop");
    if client.drop_collection(request).await.is_err() {
        eprintln!("could not drop {collection}; it is left behind for a human to remove");
    }
}
