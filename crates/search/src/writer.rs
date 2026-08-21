//! The write side of the vector index: what puts chunks into it, what takes them out, and the one
//! ordering rule that makes a removal claim honest.
//!
//! # Why this is a second port and not two more methods on `VectorIndex`
//!
//! [`crate::vector::VectorIndex`] is the *candidate generator*, and its documentation is an argument
//! about what a search may believe. Nothing in this module is on a search path, and keeping the two
//! traits apart is what stops that argument being restated — or quietly widened — every time the
//! writer grows a method. It is the same separation [`crate::health::IndexCensus`] already has, for
//! the same reason: a health probe and a search ask different questions of the same server.
//!
//! # What a write is allowed to be wrong about
//!
//! `acl_tokens` and `barrier_tokens` written here are **an optimisation and never a permission**
//! (`docs/07-SEARCH-INDEXING.md §4`, `§6.5`). A writer that computes them from a stale ACL, from a
//! group membership that changed while the batch was in flight, or from nothing at all, produces an
//! index that is wrong in the permissive direction — which costs over-fetch budget and cannot cost
//! correctness, because [`crate::PostFilter::confirm`] resolves every candidate against PostgreSQL
//! and `tests/postfilter.rs` S5 is the standing proof. `crates/search/tests/milvus.rs` deliberately
//! writes the worst case: the caller's token on every chunk including the ones they may not see.
//!
//! That permissiveness is a licence for the *writer*, not for a reader. Nothing here may grow a
//! method that reports what the index holds — see the refusals below.
//!
//! # Idempotence is why this is an upsert
//!
//! `chunk_id` is deterministic per `(version, chunker, ordinal)` (`ENC-513`,
//! `enclave_indexing::chunk_id`) and indexing runs off an at-least-once outbox, so **a retry is the
//! ordinary case**. With an insert, a worker that crashed after writing half a document's chunks
//! writes a second copy of all of them on its next run, and nothing ever removes the first: the
//! orphan keeps the `acl_tokens` of the run that wrote it forever, because nothing knows it exists
//! to update. Not a leak — the post-filter still refuses it — but permanent over-fetch that worsens
//! with every retry and shows up as a drop ratio climbing for a reason nobody can find.
//!
//! Milvus does not enforce primary-key uniqueness on `insert`; it does on `upsert`. So
//! [`VectorWriter::upsert_chunks`] is an upsert, and
//! `tests/vector_write.rs::a_reindex_upserts_in_place_rather_than_accumulating` is what stops it
//! quietly becoming an insert again.
//!
//! # The removal handoff, which is the whole of `ENC-547`
//!
//! [`remove_and_confirm`] is two statements and an order. The order is the content:
//!
//! 1. [`crate::denylist::suppress`] returns a [`SuppressionSeq`] **before** any of this;
//! 2. the store call removes the file's chunks;
//! 3. [`crate::denylist::confirm_indexed`] records *that* generation.
//!
//! A confirmation written first would name a write that had not happened. A confirmation that
//! re-read the row afterwards would silently absorb a suppression that landed **during** the store
//! call — the second revocation would read as covered by a removal that ran before it existed, and
//! `retrieval_denylist` would say `caught_up` about a file whose newest revocation nothing has acted
//! on. That is why `seq` is a *parameter*: this function has no way to obtain one, so the wrong
//! version of it cannot be written here at all.
//!
//! It is deliberately not the safety property it looks like. Nothing on the search path reads those
//! columns — `crate::denylist`'s `neither_the_search_read_nor_the_lift_consults_the_catch_up_columns`
//! is the standing guard, and the suppression keeps suppressing whether or not this ever runs. What
//! a wrong confirmation costs is an operator's signal and a rebuild's input.
//!
//! # Three refusals, and they are the same ones `ENC-518` made
//!
//! 1. **Nothing here reports what the index contains.** [`VectorWriter::upsert_chunks`] and
//!    [`VectorWriter::remove_file`] return `()`, not the server's row counts. A `remove_file` that
//!    answered "0 entities matched" is one call away from `fn is_indexed(file) -> bool`, which is
//!    the predicate a search eventually uses to skip work. The count is also not the fact it looks
//!    like: Milvus reports what an expression matched when the delete entered the write-ahead log,
//!    which is not a statement about the collection afterwards.
//! 2. **There is no per-file freshness question.** The only thing this module writes about
//!    freshness is a claim, through [`crate::denylist::confirm_indexed`], and that column is read by
//!    an aggregate that cannot project a `file_id`.
//! 3. **[`remove_and_confirm`] cannot read a generation.** See above.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{
    ChunkId, ClassificationRank, FileId, LibraryId, TenantId, VersionId, WorkspaceId,
};
use sqlx::PgConnection;

use crate::denylist::{self, SuppressionSeq};
use crate::error::SearchError;

/// A learned-sparse vector: term ordinal to weight.
///
/// Spelled as a plain map rather than re-exported from the SDK so that a caller building one does
/// not take a dependency on the client library. It is structurally the type
/// `milvus::v2::prelude::SparseVector` aliases, which is what lets [`crate::MilvusIndex`] pass it
/// straight through.
///
/// Empty is legitimate and means "this model does not emit sparse vectors". The collection has the
/// field either way (`enclave_embeddings::model::ACTIVE.sparse` records that `bge-m3` does), and a
/// model that leaves it empty costs hybrid recall rather than correctness.
pub type SparseTerms = BTreeMap<u32, f32>;

/// One chunk, in the shape `docs/07-SEARCH-INDEXING.md §4` gives the collection.
///
/// Owned rather than borrowed because a batch is assembled from an extraction, a chunking pass and
/// an embedding pass that have all finished by the time it is written, and threading three sets of
/// lifetimes through a worker to save one clone per chunk buys nothing at the size of an RPC.
///
/// # Which fields can be absent, and why the others cannot
///
/// Four are [`Option`] because the collection marks them nullable: a text file has no sheet name, a
/// synthetic chunk has no title, and language detection legitimately fails. Everything else is
/// required *by the collection*, which is `ENC-523`'s correction: one helper had made every VarChar
/// nullable, `file_id` included, and a chunk naming no file is one the post-filter can never
/// resolve — dropped silently, as though the search had simply not matched it, while still costing
/// storage.
///
/// [`Self::page_number`] is the exception that is worth flagging rather than hiding: the collection
/// declares it `Int32` and not nullable, so a chunk from an unpaginated document has to write
/// *something*. Pages are one-based, so `0` is the convention for "no page", and it is a sentinel of
/// exactly the kind the nullable fields exist to avoid. Changing that is a schema change and
/// `docs/07 §4` is where it would be decided.
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkRecord {
    /// Deterministic per `(version, chunker, ordinal)` — `enclave_indexing::chunk_id`. It is what
    /// makes a re-index an upsert; see this module's documentation.
    pub chunk_id: ChunkId,
    /// The partition key, and the tenant this chunk belongs to. From the writer's verified context,
    /// never from anything a client supplied (`CLAUDE.md` rule 3).
    pub tenant: TenantId,
    /// Scope filter.
    pub workspace: WorkspaceId,
    /// Scope filter, and the one the query-time narrowing is resolved against — from PostgreSQL,
    /// per `docs/07 §6.1`.
    pub library: LibraryId,
    /// The join back to PostgreSQL, and the only field the post-filter needs.
    pub file: FileId,
    /// The version this chunk was cut from.
    pub version: VersionId,
    /// What this chunk is, for result presentation and boosting.
    pub chunk_type: String,
    /// The document's name, boosted lexically. Absent for a chunk of something unnamed.
    pub title: Option<String>,
    /// The chunk body. Sensitive storage — `docs/07 §4` — and the excerpt source.
    ///
    /// May be empty: a metadata-only update writes scalars and vectors and leaves the body alone,
    /// and `crate::milvus`'s decoder treats an empty body as a hit with nothing to quote rather
    /// than as a decode failure.
    pub text: String,
    /// The dense embedding, at the collection's width.
    ///
    /// Refused by [`ChunkRecord::validate`] if it is not, because the alternative is a rejected
    /// batch whose server message this crate deliberately discards (`CLAUDE.md` rule 10) — leaving
    /// an operator with `upsert failed` and no column name.
    pub dense: Vec<f32>,
    /// The learned-sparse embedding. Empty when the model does not emit one.
    pub sparse: SparseTerms,
    /// The ceiling the pre-filter compares against.
    pub classification_rank: ClassificationRank,
    /// **Optimisation only.** Read this module's documentation before treating it as anything else.
    pub acl_tokens: Vec<String>,
    /// **Optimisation only.** Barriers are enforced in the policy chain.
    pub barrier_tokens: Vec<String>,
    /// `files.acl_revision` at index time, which is what the epoch reconciler compares.
    pub acl_epoch: i64,
    /// The version's media type, for filtering.
    pub mime_type: String,
    /// The detected language, absent when detection did not run or did not settle.
    pub language: Option<String>,
    /// One-based page, or `0` for a document that has no pages. See the type documentation.
    pub page_number: i32,
    /// The sheet a spreadsheet chunk came from. Absent — not `""` — for everything else.
    pub sheet_name: Option<String>,
    /// The heading path a chunk sits under, for deep links and citations.
    pub section_path: Option<String>,
    /// The version's modification time, for recency filters and boosting.
    pub modified: DateTime<Utc>,
}

/// Longest `chunk_id` the collection accepts, in bytes.
const CHUNK_ID_BYTES: usize = 128;
/// Longest identifier-shaped VarChar the collection accepts, in bytes.
const ID_BYTES: usize = 64;
/// Longest `title` or `sheet_name`, in bytes.
const TITLE_BYTES: usize = 1024;
/// Longest `section_path`, in bytes.
const PATH_BYTES: usize = 1024;
/// Longest chunk body, in bytes.
const TEXT_BYTES: usize = 8192;
/// Longest single ACL or barrier token, in bytes.
const TOKEN_BYTES: usize = 128;
/// Most tokens one chunk may carry.
const TOKEN_CAPACITY: usize = 512;

impl ChunkRecord {
    /// Refuses a chunk the collection would reject, naming the field.
    ///
    /// # Why this is not left to the server
    ///
    /// Milvus rejects an over-long VarChar or a mis-sized vector for the whole batch, and its error
    /// message names the offending field — but that message is exactly what
    /// [`SearchError::VectorIndex`] discards, because a Milvus error's `Display` can echo the
    /// expression or the value that provoked it and this crate's values are tenant identifiers and
    /// document text (`CLAUDE.md` rule 10). So the choice is not "check here or get a good error
    /// there"; it is "check here or get `the vector index could not answer \"upsert\"` and no column
    /// name at all".
    ///
    /// The consequence of not noticing is the one the schema's own comments keep returning to: an
    /// insert that fails is a file that is silently unfindable. A whole batch is refused for one bad
    /// row, so the row has to be identifiable.
    ///
    /// # The limits are bytes, and the chunker's budget is characters
    ///
    /// `ChunkBudget::max_chars` is 3 200 and `text` here is 8 192 — but Milvus counts bytes and the
    /// chunker counts `str::len`, which is also bytes, so the two agree today. They would stop
    /// agreeing the moment either side moved to characters, and this is where that would surface.
    ///
    /// # Errors
    ///
    /// [`SearchError::UnindexableChunk`], naming the field, for a dense vector of the wrong width or
    /// a value longer than the collection's column.
    pub fn validate(&self, dimension: u32) -> Result<(), SearchError> {
        if self.dense.len() != dimension as usize {
            // Not a retryable upstream failure and not a malformed row: the collection's width is
            // fixed at creation and a vector of another width came from a different model
            // (`ENC-533`). Re-sending it will fail identically.
            return Err(unindexable("dense_vector", "is not the collection's width"));
        }

        let lengths: [(&'static str, usize, usize); 12] = [
            ("chunk_id", self.chunk_id.to_string().len(), CHUNK_ID_BYTES),
            ("tenant_id", self.tenant.to_string().len(), ID_BYTES),
            ("workspace_id", self.workspace.to_string().len(), ID_BYTES),
            ("library_id", self.library.to_string().len(), ID_BYTES),
            ("file_id", self.file.to_string().len(), ID_BYTES),
            ("version_id", self.version.to_string().len(), ID_BYTES),
            ("chunk_type", self.chunk_type.len(), ID_BYTES),
            ("title", self.title.as_ref().map_or(0, String::len), TITLE_BYTES),
            ("text", self.text.len(), TEXT_BYTES),
            ("mime_type", self.mime_type.len(), ID_BYTES),
            ("language", self.language.as_ref().map_or(0, String::len), ID_BYTES),
            ("sheet_name", self.sheet_name.as_ref().map_or(0, String::len), TITLE_BYTES),
        ];
        for (column, length, limit) in lengths {
            if length > limit {
                return Err(unindexable(column, "is longer than the collection's column"));
            }
        }
        if self.section_path.as_ref().map_or(0, String::len) > PATH_BYTES {
            return Err(unindexable("section_path", "is longer than the collection's column"));
        }

        for (column, tokens) in
            [("acl_tokens", &self.acl_tokens), ("barrier_tokens", &self.barrier_tokens)]
        {
            if tokens.len() > TOKEN_CAPACITY {
                return Err(unindexable(column, "holds more tokens than the collection's array"));
            }
            if tokens.iter().any(|token| token.len() > TOKEN_BYTES) {
                return Err(unindexable(
                    column,
                    "holds a token longer than the collection's array",
                ));
            }
        }

        Ok(())
    }
}

/// Builds the refusal, so every arm above reads as one line.
const fn unindexable(column: &'static str, reason: &'static str) -> SearchError {
    SearchError::UnindexableChunk { column, reason }
}

/// The write side of the vector store.
///
/// Implementations put chunks in and take them out. Nothing on this trait answers a question about
/// what is in there — see the module documentation, refusal 1.
#[async_trait]
pub trait VectorWriter: Send + Sync + std::fmt::Debug {
    /// Writes these chunks, replacing any that are already there under the same `chunk_id`.
    ///
    /// An **upsert**, not an insert, and the module documentation says why at length: indexing runs
    /// off an at-least-once outbox, so re-writing the same chunk is the ordinary case rather than
    /// the exceptional one.
    ///
    /// An empty batch is a no-op and not an error. A file that extracted to nothing is a legitimate
    /// outcome (`enclave_indexing::pipeline`'s `Outcome`), and making the writer refuse it would put
    /// a failure in the log for a document nothing is wrong with.
    ///
    /// Not atomic across the batch. Milvus has no transaction, so a partially applied write is a
    /// state a caller has to be able to live with — which it can, because the chunk ids are
    /// deterministic and the retry rewrites the same ones.
    ///
    /// # Errors
    ///
    /// A store that cannot be reached, a rejected write, or a chunk the collection cannot hold
    /// ([`ChunkRecord::validate`]).
    async fn upsert_chunks(&self, chunks: &[ChunkRecord]) -> Result<(), SearchError>;

    /// Removes every chunk of one file from the store.
    ///
    /// Whole-file rather than per-chunk because the callers are whole-file events: a purge, a
    /// revocation being cleaned up behind, a document deleted. A caller that knows the chunk ids
    /// would still have to handle the ones it does not know about — an interrupted run's, an older
    /// chunker's — and a removal that leaves those behind is the orphan case this module's
    /// documentation describes.
    ///
    /// Removing a file that is not there succeeds. There is no other useful answer: the store is
    /// eventually consistent with a database that has already decided, and reporting "nothing
    /// matched" as a failure would make a retry of a completed removal look like a fault.
    ///
    /// # Errors
    ///
    /// A store that cannot be reached, or a rejected delete.
    async fn remove_file(&self, tenant: TenantId, file: FileId) -> Result<(), SearchError>;
}

/// Removes a file's chunks and records that the removal covered `seq`.
///
/// **`seq` is the value [`crate::denylist::suppress`] returned before the removal started**, carried
/// in by the caller. This function cannot obtain one, and that is the design: a version that re-read
/// the row after the store call would confirm a generation created *by a suppression that landed
/// during the write*, and the row would then say `caught_up` about a revocation nothing had acted
/// on. `tests/vector_write.rs::a_suppression_that_lands_during_the_removal_is_not_absorbed` is that
/// scenario, arranged deliberately.
///
/// The store call is first, and it is `?`: a removal that failed records nothing, so the row stays
/// at whatever it honestly was — `NULL` for a file nobody has ever confirmed, which reads as
/// *unknown* and not as "no" (`migrations/0014_index_catch_up.sql`).
///
/// Returns whether a row was updated. `false` is the ordinary case where the suppression was lifted
/// while the removal was in flight, not a failure.
///
/// # This is housekeeping, and it holds `conn` across an RPC
///
/// Worth stating because the shape invites the opposite: `conn` is untouched until the store call
/// returns, so a transaction opened *around* this call stays open for the whole round trip to
/// Milvus. Give it a connection of its own from the worker's pool. It must not be the ACL
/// transaction in any case — the suppression belongs there and the confirmation deliberately does
/// not, because a confirmation inside the ACL write would be claiming a removal that had not
/// happened yet.
///
/// # Errors
///
/// The store's failures, storage failures, and the `CHECK` that refuses a confirmation ahead of the
/// row's own generation.
pub async fn remove_and_confirm(
    conn: &mut PgConnection,
    store: &dyn VectorWriter,
    tenant: TenantId,
    file: FileId,
    seq: SuppressionSeq,
) -> Result<bool, SearchError> {
    store.remove_file(tenant, file).await?;
    denylist::confirm_indexed(conn, tenant, file, seq).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn record(dimension: usize) -> ChunkRecord {
        ChunkRecord {
            chunk_id: ChunkId::new_v7(),
            tenant: TenantId::new_v7(),
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            file: FileId::new_v7(),
            version: VersionId::new_v7(),
            chunk_type: "BODY".to_owned(),
            title: Some("a document".to_owned()),
            text: "a body".to_owned(),
            dense: vec![0.5; dimension],
            sparse: SparseTerms::from([(1, 1.0)]),
            classification_rank: ClassificationRank::new(0),
            acl_tokens: vec!["user:someone".to_owned()],
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

    /// The positive control for every refusal below: an ordinary chunk passes.
    ///
    /// Without it, `validate` returning `Err` unconditionally satisfies all of them — which is
    /// `docs/12 §1.2`'s recurring shape with the sign flipped.
    #[test]
    fn an_ordinary_chunk_is_accepted() {
        record(8).validate(8).expect("an ordinary chunk is indexable");
    }

    #[test]
    fn a_vector_of_the_wrong_width_is_refused_by_name() {
        // The failure this prevents is not the rejection — Milvus would reject it too — but the
        // rejection arriving as `the vector index could not answer "upsert"` with the field name
        // stripped out by `CLAUDE.md` rule 10.
        let chunk = record(8);
        let error = chunk.validate(1024).expect_err("a 8-wide vector in a 1024-wide collection");
        assert!(
            matches!(error, SearchError::UnindexableChunk { column: "dense_vector", .. }),
            "the refusal did not name the field: {error}"
        );
    }

    #[test]
    fn an_over_long_body_is_refused_by_name() {
        let mut chunk = record(8);
        chunk.text = "x".repeat(TEXT_BYTES + 1);
        let error = chunk.validate(8).expect_err("a body longer than the column");
        assert!(
            matches!(error, SearchError::UnindexableChunk { column: "text", .. }),
            "the refusal did not name the field: {error}"
        );

        // And the boundary, so the check is `>` and not `>=`: a chunk that exactly fills the column
        // is indexable, and a test that only asserted the failure would pass against an off-by-one
        // that refuses every full chunk.
        chunk.text = "x".repeat(TEXT_BYTES);
        chunk.validate(8).expect("a chunk that exactly fills the column is indexable");
    }

    #[test]
    fn an_absent_optional_field_is_not_an_over_long_one() {
        // `map_or(0, …)` and not `unwrap_or_default().len()` — a `None` must measure as zero rather
        // than as anything the limit could reject.
        let mut chunk = record(8);
        chunk.title = None;
        chunk.language = None;
        chunk.sheet_name = None;
        chunk.section_path = None;
        chunk.validate(8).expect("a chunk with nothing optional set is indexable");
    }

    #[test]
    fn a_token_set_larger_than_the_array_is_refused_by_name() {
        // The schema's own note on `TOKEN_CAPACITY`: a token set that overflows is rejected at
        // insert time, and an insert that fails is a file that is silently unfindable.
        let mut chunk = record(8);
        chunk.acl_tokens = vec!["user:someone".to_owned(); TOKEN_CAPACITY + 1];
        let error = chunk.validate(8).expect_err("more tokens than the array holds");
        assert!(
            matches!(error, SearchError::UnindexableChunk { column: "acl_tokens", .. }),
            "the refusal did not name the field: {error}"
        );

        let mut chunk = record(8);
        chunk.barrier_tokens = vec!["b".repeat(TOKEN_BYTES + 1)];
        let error = chunk.validate(8).expect_err("a token longer than the array's element");
        assert!(
            matches!(error, SearchError::UnindexableChunk { column: "barrier_tokens", .. }),
            "the refusal did not name the field: {error}"
        );
    }

    /// `ENC-547`'s handoff, asserted over the source because there is nowhere else to assert it.
    ///
    /// `tests/vector_write.rs` proves the *behaviour* against a real row, and it is the test that
    /// matters. This one guards the two properties that make that behaviour structural rather than
    /// incidental, and both of them are things a plausible refactor does:
    ///
    /// - the generation is a **parameter**. A `remove_and_confirm(conn, store, tenant, file)` that
    ///   read the row itself is the obvious convenience, and it is the bug: the value it would read
    ///   includes any suppression that landed during the store call, so the row would say
    ///   `caught_up` about a revocation nothing had acted on.
    /// - the generation is not **constructed** here either. `SuppressionSeq::new` exists so a
    ///   writer can carry one across a process boundary; used *inside* this function it fabricates
    ///   the claim rather than observing it, and the row's `CHECK` cannot tell the two apart as
    ///   long as the value is in range.
    ///
    /// The first version of this test asserted only `contains("seq: SuppressionSeq")`, and a
    /// deliberate violation that renamed the parameter `_seq` and built a fresh one in the body
    /// **passed**. Hence the shape below.
    #[test]
    fn the_confirmation_generation_is_a_parameter_and_is_never_read_or_built_here() {
        let source = include_str!("writer.rs");
        let signature = source
            .split("\npub async fn remove_and_confirm(")
            .nth(1)
            .expect("remove_and_confirm is declared in this file");
        let (parameters, body) = signature.split_once(") -> Result<bool, SearchError> {").expect(
            "remove_and_confirm's signature is spelled as the module documentation describes",
        );
        let body = body.split("\n}").next().unwrap_or(body);

        assert!(
            parameters.contains("\n    seq: SuppressionSeq,"),
            "the caller no longer hands in the generation, so it is being found somewhere: \
             {parameters}"
        );
        assert!(body.contains(", seq)"), "the parameter is not what is confirmed: {body}");
        assert!(
            !body.contains("SuppressionSeq"),
            "a generation is built inside the handoff, which is a fabricated claim rather than an \
             observed one: {body}"
        );
        assert!(
            !body.contains("suppress"),
            "the handoff reads a generation of its own, which absorbs any suppression that landed \
             during the store call: {body}"
        );

        let store_call = body.find("remove_file").expect("the handoff calls the store");
        let confirm_call = body.find("confirm_indexed").expect("the handoff confirms");
        assert!(
            store_call < confirm_call,
            "the confirmation is written before the removal it claims to be about: {body}"
        );
    }
}
