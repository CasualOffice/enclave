//! The indexing pass — the thing that makes `chunk_text` non-empty in a real deployment.
//!
//! `ENC-527`'s last piece. Extraction, chunking, the chunk store and the manifest writer all
//! existed; nothing drove them, so degraded search behaved exactly as it had before `ENC-515`
//! landed. This drives them.
//!
//! # Rule 9 is why this reads versions through `readable_version`
//!
//! Indexing reads file *content*, and `CLAUDE.md` rule 9 says nothing serves content before
//! antivirus completes. [`enclave_preview::repo::readable_version`] already answers "may this
//! version's bytes be read" with a query carrying `status = 'AVAILABLE' AND av_status = 'CLEAN'`,
//! and returns `None` otherwise.
//!
//! This uses it rather than asking the question again. A second query deciding what is readable is
//! the one that drifts, and the drift is silent: an indexer reading a `SCANNING` version puts the
//! contents of an unscanned upload into the search index, where a permission check on the *file*
//! looks perfectly normal and the content is served as an excerpt.
//!
//! A version that is not readable is **deferred**, not failed — see
//! [`enclave_indexing::defer`]. "Not scanned yet" is not a verdict about the document.
//!
//! # One transaction per file, and what is inside it
//!
//! The chunk write and the manifest write share a transaction. Either order of a split would be
//! wrong in a way nothing reports: a manifest saying `READY` over text that was never committed is
//! a file that search believes it can find and cannot, and committed text with no manifest is text
//! the coverage check does not count, so the store reads as depleted while holding the right data.
//!
//! Files are separate transactions from each other. One document that fails to parse must not roll
//! back the twenty indexed before it, and each is independently retryable because the manifest
//! records where it got to.
//!
//! # Where the vector store joins, and why it is written *before* the commit
//!
//! `ENC-557`. [`VectorStage`] is [`Option`]al for the same reason [`MountedOcr`]
//! is: a deployment that has configured no embedding model and no vector store must cost nothing —
//! not a branch, not a query, not a call — and `None` is today's behaviour exactly.
//!
//! When it *is* present, the ordering question is the interesting one, because the vector store is
//! not transactional with PostgreSQL. Something has to be able to fail after the other side
//! succeeded, and the only decision available is **which surviving state a crash leaves behind**:
//!
//! * **Store write after the commit.** What survives is a manifest saying `READY` over vectors that
//!   were never written: a document search believes it can find and cannot, with `chunk_count`
//!   counted in the coverage probe, nothing in the log, and no retry — because the manifest says
//!   the file is done. That is the confidently-wrong answer this module's transaction paragraph is
//!   already about, arriving from a third direction.
//! * **Store write before the commit.** What survives is vectors with no manifest. They are
//!   candidates whose file the post-filter resolves against PostgreSQL before a caller sees
//!   anything (`CLAUDE.md` rule 5), so the cost is over-fetch and never disclosure; the file is
//!   still claimed and still retried; and the retry *replaces* them rather than adding to them,
//!   because `chunk_id` is deterministic per `(version, chunker, ordinal)` and
//!   [`VectorWriter::upsert_chunks`] is an upsert (`ENC-547` — Milvus does not enforce primary-key
//!   uniqueness on `insert`, and a retry against one produced four entities from two chunks).
//!
//! So the store write goes first and the PostgreSQL commit second, and the failure that survives a
//! crash is the self-correcting one. A store failure aborts the transaction, which means no chunk
//! text, no manifest, and a file that is retried whole — the same treatment an object-storage
//! failure already gets, and for the same reason: neither is a verdict about somebody's document.
//!
//! The cost, stated rather than discovered: the file's transaction is now held open across the
//! embedding pass and one RPC. This transaction already spans a storage read, extraction and — on a
//! scanned document — OCR at seconds per page, so this lengthens something that was never short;
//! but it is a real cost and the batch size is what bounds it.
//!
//! # What a stage refuses, and why refusing is the point
//!
//! There are two things a deployment can be missing here, and neither is allowed to become an empty
//! index entry:
//!
//! 1. **No local model.** `crates/embeddings` ships [`NoLocalModel`](enclave_embeddings::NoLocalModel),
//!    which refuses rather than returning an empty vector. The refusal propagates out of the pass
//!    and the file stays claimed, which is [`MountedOcr`]'s "a failed mount
//!    is an outage, never an empty document" applied to the model volume.
//! 2. **No effective classification.** [`FileClassification`] is where a file's rank comes from, and
//!    the shipped implementation — [`UnclassifiedFiles`] — refuses, because this deployment has no
//!    classification service and no `classifications` table to resolve a rank from.
//!    `ClassifiedText::new`'s own documentation is why that refusal is not pedantry: *"a truthful
//!    ceiling applied to a false rank routes confidently to the wrong place"*, and the rank is
//!    written into the collection as well as used for routing, so guessing it low invites a hosted
//!    endpoint to see restricted text and guessing it high files a document no ceiling admits.
//!
//! # Where OCR joins, and where it does not
//!
//! `ENC-546`. [`MountedOcr`] is [`Option`]al and threaded through as a
//! parameter, because "this deployment has no OCR" is the ordinary case and must cost nothing —
//! not a branch that could be wrong, not a byte re-read, not a call. `None` and today's behaviour
//! are the same behaviour.
//!
//! When it is present, it runs **after** [`Pipeline::prepare`] and **only** on
//! [`Outcome::NoText`]. Two things about that placement are worth stating, because both are easy to
//! get subtly wrong:
//!
//! 1. **The `NoText` test here is an optimisation, not the guarantee.** `OcrRetry::retry` already
//!    returns any other outcome untouched, and that is where the rule lives — it is the property
//!    that stops OCR turning *"this document failed"* into *"this document is empty"*. Deleting the
//!    test below changes no manifest; it only makes every indexed document pay for a second storage
//!    read. It is written this way for the same reason `pipeline::decide`'s `is_empty` early exit
//!    is, and labelled the same way so nobody later mistakes it for the control.
//! 2. **The bytes are read a second time rather than kept.** The first read is moved into the
//!    extractor, and cloning it would double a worker's peak residency — up to
//!    `max_output_bytes` twice, per document in flight — for a copy that is discarded unused on
//!    every document that produced text. The second read happens only for a document that produced
//!    none, and goes through the same bounded [`read_bounded`], so nothing is truncated and nothing
//!    unbounded is held. The cost is one extra `read_range` on the textless path; the alternative is
//!    a permanent doubling on every path.

use core::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{
    ChunkId, ClassificationOutcome, ClassificationPolicy, ClassificationRank,
    ClassificationResolution, FileId, LibraryId, TenantId, VersionId, WorkspaceId,
};
use enclave_db::{effective_classification_on, DbPool};
use enclave_embeddings::{model::ACTIVE, ClassifiedText, Embedder, ModelId};
use enclave_indexing::{
    claim, defer, record, write_chunks, BuildVersions, Chunk, ExtractRequest, Extractor, Outcome,
    Pipeline,
};
use enclave_preview::repo::readable_version;
use enclave_preview::RenderBudget;
use enclave_search::{ChunkRecord, SparseTerms, VectorWriter};
use enclave_storage::{BlobStore, ByteRange};
use sqlx::{PgConnection, Row as _};
use tracing::debug;

use crate::ocr::MountedOcr;
use crate::{Result, Stop, WorkerError};

/// Where a file's **effective** classification comes from.
///
/// A port and not a query, because the answer is not one this crate can compute. An effective
/// classification is the label after inheritance and after the classification stage has run and
/// possibly raised it (`docs/07 §2`), and `crates/classification` ships
/// `UnconfiguredClassification` — a policy stage that allows — rather than a resolver. There is no `classifications` table in `migrations/` for a rank to be read out of.
///
/// It takes a connection so that the implementation which eventually resolves a rank can do it in
/// the file's own transaction, alongside the rest of the pass, rather than opening a second one and
/// answering about a different snapshot.
///
/// # This is the input S8 rests on
///
/// `crates/embeddings/src/text.rs`: *"The rank is only as good as its source. `ClassifiedText::new`
/// is where a rank is attached, and indexing must attach the file's effective classification — the
/// label after the classification stage has run, not the one on the upload."* Everything the
/// embedding router does is a faithful consequence of the number this returns, and nothing
/// downstream can detect that it is wrong. Hence [`UnclassifiedFiles`].
#[async_trait]
pub trait FileClassification: Send + Sync {
    /// The rank to attach to this file's text, or a refusal.
    ///
    /// # Errors
    ///
    /// [`WorkerError::Unclassified`] when this deployment cannot resolve one, and storage failures
    /// for an implementation that reads a row.
    ///
    /// # Why an outcome rather than a rank
    ///
    /// `ENC-656`. A rank has no way to say *"nothing is labelled and the tenant told us what that
    /// means"*, so returning one collapses an assumption into a reading — and the difference is
    /// the whole of `ENC-574`'s argument. [`ClassificationOutcome`] is `#[must_use]` with no arm a
    /// caller can mistake for a number, so honouring `Assumed` is a decision this pass has to make
    /// out loud instead of one it makes by not noticing.
    async fn effective_rank(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<ClassificationOutcome>;
}

/// The classification source a deployment has before it configures one: none.
///
/// Deny-by-default, in the shape [`NoLocalModel`](enclave_embeddings::NoLocalModel) and
/// `crates/preview::NoRenderer` use, and for a sharper reason than either. The tempting stub is a
/// constant rank, and both constants are wrong in a way that is invisible from here:
///
/// * A low one (`PUBLIC`) is a lie in the direction of a hosted endpoint. A deployment with a
///   ceiling at `RESTRICTED` and a remote provider configured would send every document's text
///   off-network while the ceiling comparison worked perfectly — S8 defeated through its input
///   rather than through its logic, with every routing test still green.
/// * A high one is a lie in the direction of silence. `classification_rank` is what the vector
///   query's pre-filter compares against a caller's ceiling, so a rank above every ceiling files
///   each document correctly, shows it in the tree, and hides it from every search that should
///   find it — which `crates/embeddings` argues at length is the worse of the two failures because
///   nothing reports it.
///
/// So it refuses, and the file is not embedded and not recorded. When a rank has a real source this
/// type stays, for the deployment whose classification service is unreachable.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnclassifiedFiles;

#[async_trait]
impl FileClassification for UnclassifiedFiles {
    async fn effective_rank(
        &self,
        _conn: &mut PgConnection,
        _tenant: TenantId,
        _file: FileId,
    ) -> Result<ClassificationOutcome> {
        Err(WorkerError::Unclassified)
    }
}

/// The classification source a deployment with `migrations/0022` actually has.
///
/// Resolves the file's effective rank through `enclave_db::effective_classification_on`, which is
/// the *same* walk `crates/dlp`'s provider and the policy chain read — one definition of what a
/// file's label is, rather than a second that drifts. It takes the `&mut PgConnection` the trait
/// already hands over, so the resolution runs inside the pass's own transaction and cannot observe
/// a label the rest of the pass did not.
///
/// # `Assumed` is honoured here and refused on a request path
///
/// [`ClassificationResolution::require_for_indexing`] is the door `ENC-574` built for exactly this
/// caller, and its argument is worth restating where the assumption is acted on: embedding an
/// unlabelled document under an assumed rank is not the unrecallable act external sharing is,
/// because the assumed rank is *written into the collection and routes the provider*. A tenant that
/// assumes a high rank gets local-only embedding, not a leak. A tenant that assumes a low one has
/// said, in its own configuration, that unlabelled content is not sensitive.
///
/// What this type must never do is turn `Denied` into a rank. Under the default `FAIL_CLOSED` an
/// unlabelled file is not embedded, which is [`UnclassifiedFiles`]'s behaviour arrived at by
/// policy rather than by absence — and that is why that type stays rather than being deleted here.
#[derive(Debug, Clone, Copy)]
pub struct PgClassification {
    policy: ClassificationPolicy,
}

impl PgClassification {
    /// Reads labels under one tenant policy for unlabelled content.
    #[must_use]
    pub const fn new(policy: ClassificationPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl FileClassification for PgClassification {
    async fn effective_rank(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<ClassificationOutcome> {
        // A read failure is an outage, never "unlabelled". The distinction matters more here than
        // in most places this codebase makes it: under an `Assume` policy, "unlabelled" carries a
        // rank, so a swallowed error would not refuse — it would embed the document at whatever
        // rank the tenant nominated for content nobody has labelled.
        let effective = effective_classification_on(conn, tenant, file).await?;
        let resolution = match effective {
            Some(found) => ClassificationResolution::resolved(self.policy, found),
            None => ClassificationResolution::unlabelled(self.policy),
        };
        Ok(resolution.require_for_indexing())
    }
}

/// The embedding-and-vector-write half of an indexing pass.
///
/// Holds the three things that half needs and nothing else — no pool, no object store, no manifest
/// writer. In particular it holds no way to *read* the vector store: `crates/search/src/writer.rs`
/// refuses to answer what the index contains, and a stage that could ask would be one call away
/// from the per-file freshness oracle `crates/worker` states as its first rule.
///
/// # The width agreement, which is `ENC-533`
///
/// The collection's dense width is fixed when it is created and
/// [`ACTIVE.dimension`](enclave_embeddings::model::ACTIVE) is the width the model emits. Until this
/// stage existed the two agreed *by convention* — `enclave-search` does not depend on
/// `enclave-embeddings`, and `MilvusConfig::dimension`'s documentation says so and asks the caller
/// to read the constant rather than type a number. Nobody was in a position to check, because no
/// crate depended on both.
///
/// This one does, legitimately, and so [`VectorStage::for_collection`] refuses a disagreement at the
/// point a deployment is wired. The failure it prevents is the one that errors at neither end:
/// Milvus accepts vectors of the width its collection was created with and a model emits the width
/// it was trained at, so a mismatch surfaces as retrieval quality quietly degrading, and the
/// correction is a new collection plus every chunk of every tenant re-embedded (`docs/07 §9`).
pub struct VectorStage {
    embedder: Box<dyn Embedder>,
    ranks: Box<dyn FileClassification>,
    writer: Box<dyn VectorWriter>,
    dimension: u32,
}

impl fmt::Debug for VectorStage {
    /// Names the shape, never the wiring's contents.
    ///
    /// A derived `Debug` would print the writer, and a writer prints an endpoint and whatever else
    /// its client holds. This appears in a start-up log line (`CLAUDE.md` rule 10) — the same
    /// reason `schedule::PipelineRunner` writes its own.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VectorStage").field("dimension", &self.dimension).finish_non_exhaustive()
    }
}

impl VectorStage {
    /// Wires an embedder, a classification source and a vector store against one collection.
    ///
    /// `dimension` is the width the collection was **created** with — `MilvusConfig::dimension`, not
    /// a number chosen here — so that this is a comparison of two independently-sourced facts rather
    /// than a constant compared with itself.
    ///
    /// # Errors
    ///
    /// [`WorkerError::CollectionWidth`] when the collection is not the active model's width. See the
    /// type documentation: this is `ENC-533`, and it is refused at wiring time because afterwards it
    /// is a reindex.
    pub fn for_collection(
        embedder: Box<dyn Embedder>,
        ranks: Box<dyn FileClassification>,
        writer: Box<dyn VectorWriter>,
        dimension: u32,
    ) -> Result<Self> {
        if dimension != ACTIVE.dimension {
            return Err(WorkerError::CollectionWidth {
                collection: dimension,
                model: ACTIVE.dimension,
            });
        }
        Ok(Self { embedder, ranks, writer, dimension })
    }

    /// Embeds one version's chunks and writes them to the vector store.
    ///
    /// Returns the model that produced the vectors, which is what
    /// `index_manifests.embedding_model` records. It comes back from the embedder rather than from
    /// configuration because the route is per file: see [`enclave_embeddings::Embedded`].
    ///
    /// # Errors
    ///
    /// [`WorkerError::Unclassified`] when the file's rank cannot be resolved,
    /// [`WorkerError::Embedding`] when the provider refuses or returns a short batch,
    /// [`WorkerError::CollectionWidth`] when it returns vectors of the wrong width, and
    /// [`WorkerError::Search`] when the store refuses the write. Every one of them leaves the
    /// caller's transaction unwritten — that is the whole ordering argument in this module's
    /// documentation.
    /// Resolves the rank this file's vectors are written at.
    ///
    /// Split out of [`write`](Self::write) by `ENC-850`, and the split is the whole point: this is
    /// the only part of the stage that touches PostgreSQL, and it is fast. Embedding is neither.
    /// Keeping them in one method meant the caller's transaction stayed open across a model call,
    /// and `idle_in_transaction_session_timeout` — 60 seconds, deliberately — terminated the
    /// connection out from under it.
    ///
    /// # Errors
    ///
    /// [`WorkerError::Unclassified`] when the file's rank cannot be resolved.
    async fn resolve_rank(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<ClassificationRank> {
        // The rank first, and by itself. Nothing below is meaningful if this is a guess, so the
        // refusal happens before a byte of text is copied anywhere.
        //
        // Three arms, matched exhaustively rather than unwrapped: `ENC-656`'s whole point is that a
        // rank cannot express *"nothing is labelled and the tenant said what that means"*, and a
        // `let rank = ...` that flattened `Assumed` into `Labelled` would put an assumption into
        // the collection with no record that it was one.
        let rank = match self.ranks.effective_rank(conn, tenant, file).await? {
            ClassificationOutcome::Labelled(effective) => effective.rank(),
            // Logged at `info` rather than silently taken. The rank is written into the collection
            // and decides which provider sees the text, so an operator reading back why a document
            // routed the way it did needs to know the number was configuration, not a label.
            ClassificationOutcome::Assumed(assumed) => {
                debug!(
                    file = %file,
                    rank = assumed.rank().get(),
                    "no label on this file's chain; embedding at the rank the tenant assumes"
                );
                assumed.rank()
            }
            // `FAIL_CLOSED`, which is the default: the file is not embedded and not recorded, the
            // same outcome `UnclassifiedFiles` produces and for a stated reason rather than an
            // absent service.
            ClassificationOutcome::Denied { .. } => return Err(WorkerError::Unclassified),
        };
        Ok(rank)
    }

    /// Embeds one version's chunks and writes them to the vector store.
    ///
    /// Takes no connection, and must not acquire one: everything here is a model call and a store
    /// write, and the caller runs it with **no transaction open** (`ENC-850`). Returns the model
    /// that produced the vectors, which is what `index_manifests.embedding_model` records — from
    /// the embedder rather than from configuration, because the route is per file.
    ///
    /// # Errors
    ///
    /// [`WorkerError::Embedding`] when the provider refuses or returns a short batch,
    /// [`WorkerError::CollectionWidth`] when it returns vectors of the wrong width, and
    /// [`WorkerError::Search`] when the store refuses the write.
    async fn write(
        &self,
        rank: ClassificationRank,
        file: &FileFacts,
        version: VersionId,
        mime_type: &str,
        chunks: &[Chunk],
    ) -> Result<ModelId> {
        // The one place chunk text becomes embeddable text. `ClassifiedText` has no method that
        // returns its chunks, so from here the only readers are `TextBatch::<Local>::admit` and
        // `TextBatch::<Remote>::admit` — and holding the batch a remote provider takes *is* the
        // proof that this rank was below the deployment's ceiling.
        let text =
            ClassifiedText::new(rank, chunks.iter().map(|chunk| chunk.text.clone()).collect());

        // A short batch is already `EmbeddingError::IncompleteBatch`, so `embeddings` here is
        // exactly one vector per chunk and the `zip` below cannot silently truncate.
        let embedded = self.embedder.embed(text).await?;
        let model = embedded.model().clone();

        let mut records = Vec::with_capacity(chunks.len());
        for (chunk, embedding) in chunks.iter().zip(embedded.embeddings()) {
            // The second half of `ENC-533`, per batch rather than per deployment: a provider whose
            // vectors are not the width its collection was created with is a different model, and
            // re-sending will fail identically. `ChunkRecord::validate` refuses it too, inside
            // `MilvusIndex` — this refusal names both numbers, and holds for a store whose
            // implementation does not validate.
            let width = u32::try_from(embedding.dimensions()).unwrap_or(u32::MAX);
            if width != self.dimension {
                return Err(WorkerError::CollectionWidth {
                    collection: self.dimension,
                    model: width,
                });
            }
            records.push(file.record(chunk, rank, version, mime_type, embedding.as_slice()));
        }

        self.writer.upsert_chunks(&records).await?;
        Ok(model)
    }
}

/// The columns a [`ChunkRecord`] needs that the indexing queue does not carry.
///
/// Read once per file rather than once per chunk: every one of these is a property of the file, and
/// a per-chunk read would be the same row fetched two hundred times inside one transaction.
#[derive(Debug, Clone)]
struct FileFacts {
    /// The tenant the pass is running for, carried from its argument and **never read back out of
    /// the row** (`CLAUDE.md` rule 3). The query is tenant-scoped, so the two are the same value;
    /// taking it from the row would make that a coincidence rather than a property.
    tenant: TenantId,
    id: FileId,
    workspace: WorkspaceId,
    library: LibraryId,
    /// `files.name`, which the collection boosts lexically as `title`.
    name: String,
    /// `files.acl_revision` as it stands now, which is what the epoch reconciler compares.
    acl_epoch: i64,
    modified: DateTime<Utc>,
}

impl FileFacts {
    /// Builds the store record for one chunk.
    ///
    /// # What is deliberately empty, and why that is safe
    ///
    /// `acl_tokens` and `barrier_tokens` are `Vec::new()`. Nothing in this workspace computes
    /// either — `crates/search/src/vector.rs` says as much for barriers — and both are marked
    /// **optimisation only** by `docs/07 §4`: the vector query filters on neither, and every
    /// candidate is resolved against PostgreSQL by the post-filter before a caller sees it
    /// (`CLAUDE.md` rule 5). Empty claims nothing rather than claiming something false.
    ///
    /// `sparse` is empty too, and that one costs recall: `ACTIVE.sparse` records that `bge-m3`
    /// emits learned-sparse vectors natively, but `EmbeddingProvider` returns dense vectors only,
    /// so the collection's sparse field stays unfilled and hybrid retrieval runs on the dense side
    /// alone. A recall difference, not a correctness one — `crates/search`'s `SparseTerms` states
    /// that convention — and it is a gap in the port rather than something to synthesise here.
    ///
    /// `language` is `None` because nothing detects one, which is the convention
    /// `enclave_indexing::model::Coordinates` uses for every fact an extractor cannot state:
    /// absent rather than guessed.
    fn record(
        &self,
        chunk: &Chunk,
        rank: ClassificationRank,
        version: VersionId,
        mime_type: &str,
        dense: &[f32],
    ) -> ChunkRecord {
        ChunkRecord {
            chunk_id: ChunkId::from_uuid(chunk.id),
            tenant: self.tenant,
            workspace: self.workspace,
            library: self.library,
            file: self.id,
            version,
            chunk_type: chunk.kind.as_str().to_owned(),
            title: Some(self.name.clone()),
            text: chunk.text.clone(),
            dense: dense.to_vec(),
            sparse: SparseTerms::new(),
            classification_rank: rank,
            acl_tokens: Vec::new(),
            barrier_tokens: Vec::new(),
            acl_epoch: self.acl_epoch,
            mime_type: mime_type.to_owned(),
            language: None,
            // One-based pages, `0` for a document that has no pagination — the collection declares
            // the column `Int32` and not nullable, and `crates/search`'s `ChunkRecord` documents the
            // sentinel. `None` here is a fact the extractor declined to state, never a page 1 guess.
            page_number: chunk
                .coordinates
                .page_number
                .and_then(|page| i32::try_from(page).ok())
                .unwrap_or(0),
            sheet_name: chunk.coordinates.sheet_name.clone(),
            section_path: chunk.coordinates.section_path.clone(),
            modified: self.modified,
        }
    }
}

/// What one pass over a tenant's queue did.
///
/// Counted separately rather than summed into "processed", because the four mean different things
/// to an operator. `indexed` climbing is the system working; `failed` climbing is documents that
/// need looking at; `skipped` is types nobody has an extractor for; and `deferred` climbing while
/// the others stay flat means antivirus is behind, not that indexing is broken. A single total
/// would make those indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexPass {
    /// Files claimed this pass.
    pub claimed: usize,
    /// Files whose text is now searchable.
    pub indexed: usize,
    /// Files that produced no searchable text and were recorded `FAILED`.
    pub failed: usize,
    /// Files no extractor handles, recorded `SKIPPED`.
    pub skipped: usize,
    /// Files returned to the queue because their bytes are not readable yet.
    pub deferred: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
    /// Files whose textless outcome was handed to the OCR stage.
    ///
    /// Counted because it is otherwise unobservable, and because it is the number that says whether
    /// a mount is doing anything: `ocr_attempted` flat at zero on a deployment that mounted the
    /// volumes means nothing is reaching the stage — which is what a text extractor answering
    /// `Unsupported` for `application/pdf` looks like from here, and is exactly the gap `ENC-545`
    /// closes. It is not a success count; a rescued document also increments `indexed`.
    pub ocr_attempted: usize,
    /// Files whose chunks were embedded and written to the vector store.
    ///
    /// Outside the four-way sum for the same reason [`Self::ocr_attempted`] is: a document that was
    /// embedded is still exactly one of indexed, failed, skipped or deferred. It is here because it
    /// is otherwise unobservable, and because `embedded` flat at zero while `indexed` climbs is
    /// precisely the deployment `ENC-557` was about — text searchable, collection empty, every dense
    /// search returning nothing, and no counter anywhere saying so.
    pub embedded: usize,
}

/// Indexes up to `batch` of one tenant's queued files.
///
/// Returns rather than only logging, so a scheduler, a health check or a test can assert on the
/// outcome — the same reason `invalidation::sweep` does.
///
/// # Errors
///
/// [`WorkerError`] from the first file whose *storage or database* fails. Files already indexed in
/// this pass stay indexed: each was its own transaction. A document that fails to **parse** is not
/// an error — it is an [`Outcome`], recorded and counted, because a hostile or broken document is
/// the ordinary case here and must not stop the queue.
pub async fn index_pass<E: Extractor, S: BlobStore + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    pipeline: &Pipeline<E>,
    ocr: Option<&MountedOcr>,
    vectors: Option<&VectorStage>,
    store: &S,
    versions: BuildVersions<'_>,
    budget: RenderBudget,
    batch: i64,
    stop: &Stop,
) -> Result<IndexPass> {
    let mut outcome = IndexPass::default();

    let claimed = {
        let mut tx = pool.begin(tenant).await?;
        let claimed = claim(&mut tx, tenant, batch).await?;
        tx.commit().await?;
        claimed
    };
    outcome.claimed = claimed.len();

    for file in claimed {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        // The first of two transactions, and the split is `ENC-850`. Everything PostgreSQL is
        // needed for is read here and the transaction closes before a byte is fetched — because
        // what follows is an object read, text extraction, OCR and a model call, any one of which
        // can outlast `idle_in_transaction_session_timeout`. It did: 60 seconds is the configured
        // value, deliberately, since a transaction left open holds its `SET LOCAL app.tenant_id`,
        // and the pass was terminated mid-embed with `25P03`.
        let mut tx = pool.begin(tenant).await?;

        let Some(readable) = readable_version(&mut tx, tenant, file.version_id).await? else {
            // Not readable *yet*: scanning, quarantined, or superseded. Not a verdict.
            defer(&mut tx, tenant, file.file_id).await?;
            tx.commit().await?;
            outcome.deferred += 1;
            continue;
        };

        // Read now, used after the transaction is gone. Both are properties of a row that cannot
        // change underneath this pass: a version is immutable once committed, and the rank is
        // resolved against the file's chain as it stands at the moment the pass claimed it. A
        // reclassification landing mid-embed is handled the way every other one is — by the epoch
        // reconciler — and not by holding a transaction open in the hope of noticing.
        let facts = file_facts(&mut tx, tenant, file.file_id).await?;
        let rank = match vectors {
            Some(stage) => Some(stage.resolve_rank(&mut tx, tenant, file.file_id).await?),
            None => None,
        };
        tx.commit().await?;

        // Read before the extractor sees anything. The budget bounds what is read as well as what
        // is parsed — an extractor that is handed the whole of a 40 GB object has already lost,
        // whatever it then decides to do with it.
        let source = read_bounded(store, readable.object_key(), &budget).await?;

        let request = ExtractRequest {
            declared_media_type: readable.media_type().to_owned(),
            source,
            budget,
        };

        let mut prepared = pipeline.prepare(file.version_id, request).await?;

        // The stage, when a deployment mounted one. `matches!` is the optimisation the module
        // documentation labels: `MountedOcr::retry` returns any other outcome untouched, so removing
        // it changes no manifest and only makes every document pay the re-read below.
        if let Some(stage) = ocr {
            if matches!(prepared.outcome, Outcome::NoText(_)) {
                outcome.ocr_attempted += 1;
                let source = read_bounded(store, readable.object_key(), &budget).await?;
                prepared = stage.retry(file.version_id, prepared, source).await?;
            }
        }

        // The model that actually produced this file's vectors, for the manifest. `None` when no
        // stage is wired, in which case the caller's value stands — `BuildVersions` documents `""`
        // as the honest one for a deployment where nothing has embedded.
        let mut embedded_by: Option<ModelId> = None;

        // Still before the manifest is written, which is this module's ordering argument and is
        // unchanged: the surviving state after a crash must be vectors with no manifest, not a
        // `READY` manifest over vectors nothing wrote. What changed is only that no transaction is
        // open while it happens — the ordering was never what held the connection.
        //
        // A refusal here — no model, a store that will not take the batch — returns before the
        // second transaction is opened, so nothing is recorded and the file is retried whole,
        // exactly as before.
        if let Outcome::Ready { .. } = prepared.outcome {
            if let (Some(stage), Some(rank)) = (vectors, rank) {
                embedded_by = Some(
                    stage
                        .write(
                            rank,
                            &facts,
                            file.version_id,
                            readable.media_type(),
                            &prepared.chunks,
                        )
                        .await?,
                );
                outcome.embedded += 1;
            }
        }

        // The second transaction: the chunk rows and the manifest, which must be atomic with one
        // another. Both are fast, and nothing between here and the commit blocks on anything but
        // PostgreSQL.
        let mut tx = pool.begin(tenant).await?;

        if let Outcome::Ready { .. } = prepared.outcome {
            write_chunks(
                &mut tx,
                tenant,
                file.file_id,
                file.version_id,
                versions.chunker,
                &prepared.chunks,
            )
            .await?;
        }

        // The manifest names the model that ran, never one supplied beside it. A deployment string
        // could be typed once and left behind a model swap; this value came back from the provider
        // that produced the vectors two statements ago, in the same transaction that is about to
        // record it, so `docs/07 §3`'s reindex trigger compares something that was true.
        let recorded = BuildVersions {
            embedding_model: embedded_by.as_ref().map_or(versions.embedding_model, ModelId::as_str),
            ..versions
        };

        record(&mut tx, tenant, file.file_id, file.version_id, recorded, &prepared.outcome).await?;
        tx.commit().await?;

        match prepared.outcome {
            Outcome::Ready { .. } => outcome.indexed += 1,
            Outcome::NoText(_) | Outcome::Refused(_) => outcome.failed += 1,
            Outcome::Unsupported => outcome.skipped += 1,
        }
    }

    debug!(
        claimed = outcome.claimed,
        indexed = outcome.indexed,
        failed = outcome.failed,
        skipped = outcome.skipped,
        deferred = outcome.deferred,
        ocr_attempted = outcome.ocr_attempted,
        embedded = outcome.embedded,
        stopped = outcome.stopped,
        "indexing pass complete"
    );
    Ok(outcome)
}

/// Reads the file-level columns a chunk record needs.
///
/// Inside the pass's transaction, under RLS, with an application `tenant_id` predicate beside it —
/// the rule `crates/worker`'s documentation states for every statement in this crate.
///
/// `fetch_one` and not `fetch_optional`: this runs after [`readable_version`] has already resolved
/// a version of this file in this same transaction, and `file_versions` references `files`, so the
/// row exists in this snapshot. An absence is a database state the pass cannot proceed from rather
/// than a file to skip, and it surfaces as a storage error like any other.
///
/// # Errors
///
/// Storage failures, and [`WorkerError::MalformedRow`] for a column that does not decode.
async fn file_facts(conn: &mut PgConnection, tenant: TenantId, file: FileId) -> Result<FileFacts> {
    let row = sqlx::query(FILE_FACTS_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await?;

    let column = |name: &'static str| WorkerError::MalformedRow {
        column: name,
        reason: "missing or of an unexpected type",
    };

    Ok(FileFacts {
        tenant,
        id: file,
        workspace: WorkspaceId::from_uuid(
            row.try_get("workspace_id").map_err(|_| column("files.workspace_id"))?,
        ),
        library: LibraryId::from_uuid(
            row.try_get("library_id").map_err(|_| column("files.library_id"))?,
        ),
        name: row.try_get("name").map_err(|_| column("files.name"))?,
        acl_epoch: row.try_get("acl_revision").map_err(|_| column("files.acl_revision"))?,
        modified: row.try_get("modified_at").map_err(|_| column("files.modified_at"))?,
    })
}

/// The tenant predicate is beside RLS, not instead of it (`plans/M0-FOUNDATIONS.md` D3).
const FILE_FACTS_SQL: &str = "
    SELECT workspace_id, library_id, name, acl_revision, modified_at
      FROM files
     WHERE tenant_id = $1 AND id = $2
";

/// Reads the object, refusing rather than truncating if it exceeds the budget.
///
/// [`ByteStream::collect_bounded`] is the whole of it: it stops fetching the moment the accumulated
/// length would exceed the limit and returns [`enclave_storage::StorageError::TooLarge`]. That
/// distinction matters more here than it looks. A read that truncated at the cap would hand the
/// extractor a *prefix* of the document, which parses cleanly, chunks cleanly and indexes as though
/// complete — text that differs from the document, searchable, with nothing anywhere reporting a
/// problem. `ENC-511` refuses exactly that on the encoding side; this is the same refusal on the
/// size side.
///
/// The budget's `max_output_bytes` is the limit because it already bounds what the extractor may
/// produce: reading more than it could ever emit buys nothing and costs memory per worker.
///
/// `pub(crate)` since `ENC-613`: [`crate::scan`] reads the same objects for the same reason, and a
/// second bounded-read helper is a second place the refusal-rather-than-truncation rule above lives.
pub(crate) async fn read_bounded<S: BlobStore + ?Sized>(
    store: &S,
    key: &str,
    budget: &RenderBudget,
) -> Result<Vec<u8>> {
    let limit =
        usize::try_from(budget.max_output_bytes).map_err(|_| WorkerError::MalformedRow {
            column: "render_budget.max_output_bytes",
            reason: "larger than this platform's addressable memory",
        })?;

    let stream = store.read_range(key, ByteRange::from(0)).await?;
    stream.collect_bounded(limit).await.map_err(WorkerError::from)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The counters must not be collapsed into a total.
    ///
    /// `deferred` climbing while `indexed` stays flat means antivirus is behind; `failed` climbing
    /// means documents need looking at. A single "processed" number makes an operator unable to
    /// tell a stalled scanner from a broken extractor, and both look like "indexing is slow".
    #[test]
    fn a_pass_reports_each_reason_separately() {
        let pass = IndexPass {
            claimed: 4,
            indexed: 1,
            failed: 1,
            skipped: 1,
            deferred: 1,
            stopped: false,
            ocr_attempted: 0,
            embedded: 0,
        };
        assert_eq!(pass.indexed + pass.failed + pass.skipped + pass.deferred, pass.claimed);
    }

    /// `ocr_attempted` is outside that sum, deliberately.
    ///
    /// It is not a fifth disposition — a document handed to OCR still ends up in exactly one of the
    /// four. Adding it to the total would make the invariant above false for every deployment that
    /// mounted the volumes, which is the one whose numbers an operator most needs to trust.
    #[test]
    fn ocr_attempts_are_not_a_fifth_disposition() {
        let pass = IndexPass {
            claimed: 2,
            indexed: 1,
            failed: 1,
            skipped: 0,
            deferred: 0,
            stopped: false,
            ocr_attempted: 2,
            embedded: 1,
        };
        assert_eq!(pass.indexed + pass.failed + pass.skipped + pass.deferred, pass.claimed);
    }

    // ------------------------------------------------------------------------------------------
    // The width agreement (`ENC-533`)
    // ------------------------------------------------------------------------------------------
    //
    // The rest of the stage's behaviour — the classification refusal, the model recorded on the
    // manifest, what a store failure leaves behind — is asserted in `tests/indexing.rs` against a
    // real database, because every one of those properties is a statement about what did or did not
    // reach `index_manifests` and `chunk_text`, and only PostgreSQL can answer that.

    use enclave_embeddings::{EmbeddingRouter, NoLocalModel};

    /// A stage wired against a collection of `dimension`, with everything else deny-by-default.
    fn stage(dimension: u32) -> Result<VectorStage> {
        VectorStage::for_collection(
            Box::new(EmbeddingRouter::air_gapped(NoLocalModel)),
            Box::new(UnclassifiedFiles),
            Box::new(NoWriter),
            dimension,
        )
    }

    /// A writer that fails the test on contact. Nothing here should reach a store.
    #[derive(Debug)]
    struct NoWriter;

    #[async_trait]
    impl VectorWriter for NoWriter {
        async fn upsert_chunks(
            &self,
            _chunks: &[ChunkRecord],
        ) -> core::result::Result<(), enclave_search::SearchError> {
            unreachable!("wiring a stage must not write to the store")
        }

        async fn remove_file(
            &self,
            _tenant: TenantId,
            _file: FileId,
        ) -> core::result::Result<(), enclave_search::SearchError> {
            unreachable!("the indexing pass never removes a file")
        }
    }

    #[test]
    fn a_collection_that_is_not_the_active_models_width_is_refused_at_wiring_time() {
        // `ENC-533`. The failure this prevents errors at neither end: Milvus accepts vectors of the
        // width its collection was created with, and the model emits the width it was trained at.
        // What breaks is retrieval quality, silently, and the correction is a new collection plus
        // every chunk of every tenant re-embedded.
        //
        // 768 rather than an absurd number: it is the width of the model somebody would most
        // plausibly have created the collection against before Q14 was answered.
        for wrong in [0, 768, 384, ACTIVE.dimension - 1, ACTIVE.dimension + 1] {
            match stage(wrong) {
                Err(WorkerError::CollectionWidth { collection, model }) => {
                    assert_eq!(collection, wrong);
                    assert_eq!(model, ACTIVE.dimension);
                }
                other => panic!("a {wrong}-wide collection was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn a_collection_at_the_active_models_width_is_accepted() {
        // The positive control, and it is not decoration: every assertion above is satisfied by a
        // `for_collection` that refuses everything, which would be a stage no deployment can wire
        // and an `ENC-557` closed on paper.
        let built =
            stage(ACTIVE.dimension).expect("the active model's own width is the collection");
        assert_eq!(built.dimension, ACTIVE.dimension);
    }

    #[test]
    fn the_width_a_stage_checks_is_read_from_the_model_and_not_typed_here() {
        // The whole of `ENC-533` is that these two are set in different crates and nothing compared
        // them. A `const` block so a wrong one fails the build rather than a test run — the form
        // `enclave_embeddings::model` and `enclave_indexing::model` both use.
        const { assert!(ACTIVE.dimension == 1024, "bge-m3 emits 1024-dimensional dense vectors") };

        // And the refusal message can only ever carry two widths: an integer from configuration and
        // a compiled-in constant, never a path, a row or a document (`CLAUDE.md` rule 10).
        let shown =
            WorkerError::CollectionWidth { collection: 768, model: ACTIVE.dimension }.to_string();
        assert!(shown.contains("768"), "{shown}");
        assert!(shown.contains("1024"), "{shown}");
    }
}
