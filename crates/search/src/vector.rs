//! The candidate-generator port, and the exact thing its pre-filter is allowed to be wrong about.
//!
//! # What a `VectorIndex` is for
//!
//! `plans/M3-DISCOVERY.md §4` sequences the post-filter first, against a fake, and this is the
//! interface the real generator arrives behind. Its whole output is `Vec<Candidate>` — the same
//! type `tests/postfilter.rs` builds by hand — so a real index is substitutable for that fake at
//! the one place it matters, [`crate::PostFilter::confirm`], and neither of them can reach a caller
//! any other way.
//!
//! There is deliberately nothing on this trait that returns a confirmed hit, a decision, or a
//! boolean about visibility. A port that could answer "may this caller see it?" is a port somebody
//! eventually asks.
//!
//! # The pre-filter, and what it is permitted to get wrong
//!
//! Say it precisely, because "coarse pre-filter" is the phrase under which a second authorization
//! system gets built by accident.
//!
//! **The pre-filter may be wrong in the permissive direction without any consequence.** If it
//! returns a chunk of a file the caller has no grant on, a file that was deleted, a file that was
//! re-classified upward an hour ago, or a file belonging to a tenant it should never have scanned —
//! the post-filter drops it, and `tests/postfilter.rs` S5 is the standing proof. Nothing downstream
//! reads a field this filter matched on.
//!
//! **It may equally be wrong in the restrictive direction**, and that costs recall: a candidate it
//! wrongly excludes is one no amount of post-filtering can put back. That is the honest price of
//! narrowing at all, and it is why the narrowing here is small.
//!
//! **What it may not be is *believed*.** The distinction is not academic. A filter that is assumed
//! correct is one whose staleness stops being a recall bug and becomes the only thing standing
//! between a caller and someone else's document — and `CLAUDE.md` rule 5 exists because that
//! assumption is the natural one to make under latency pressure.
//!
//! ## So: `acl_tokens` are not in the filter, and that is not an oversight
//!
//! `docs/07-SEARCH-INDEXING.md §4` marks `acl_tokens` **optimization only** and `§6.5` gives three
//! reasons they cannot be more than that: they are stale by construction between an ACL write and
//! an index write; a group-membership change multiplies into token churn across every file the
//! group can reach, so "just reindex" is unbounded work at exactly the moment correctness matters;
//! and deny semantics cannot be expressed as token overlap at all, so a token filter is not merely
//! stale, it is *incapable* of the answer.
//!
//! [`Prefilter`] therefore has no field for them and [`crate::milvus`] never emits a clause naming
//! them. That is asserted by a test rather than left to review, because the tempting version of
//! this change is a one-line addition that measures beautifully.
//!
//! ## What *is* in it, and where those values come from
//!
//! Two narrowings, both of which describe **scope the caller asked about**, not permission:
//!
//! - the tenant, which is how the Milvus partition key routes the scan (`docs/07 §4`);
//! - the libraries and classification ceiling the caller's request is confined to.
//!
//! `docs/07 §6.1` is specific about the provenance of the second: the accessible library set is
//! resolved **from PostgreSQL at query time, not from the index**. [`Prefilter`] has exactly one
//! constructor and it takes those values as arguments — this crate has no way to obtain them from
//! the vector store, so the class of bug where the index is asked which libraries it holds and then
//! filtered by its own answer cannot be written here.
//!
//! `barrier_tokens` are absent for a plainer reason: nothing in this crate can yet produce the
//! caller's barrier token set from an authoritative source, and a pre-filter fed from a guess is
//! worse than no pre-filter — it loses recall for a narrowing nobody can verify. Its absence costs
//! over-fetch budget (`plans/M3-DISCOVERY.md` D21 says that is the cheap side), and the barrier
//! control itself is where it has always been, in the policy chain.

use async_trait::async_trait;
use enclave_core::{ClassificationRank, LibraryId, TenantId};

use crate::degraded::VectorStore;
use crate::error::SearchError;
use crate::postfilter::Candidate;

/// The collection `docs/07-SEARCH-INDEXING.md §4` defines.
pub const COLLECTION: &str = "workspace_chunks";

/// Field names from `docs/07-SEARCH-INDEXING.md §4`.
///
/// Constants rather than literals at each call site so that the filter builder, the schema builder
/// and the result decoder cannot drift apart — a decoder reading `"file_id"` from a collection
/// created with `"fileId"` fails at runtime against a live server and nowhere earlier.
pub mod field {
    /// Primary key, deterministic per `(version, chunker, ordinal)`.
    pub const CHUNK_ID: &str = "chunk_id";
    /// Partition key. See [`super`] for why routing is not isolation.
    pub const TENANT_ID: &str = "tenant_id";
    /// Scope filter.
    pub const WORKSPACE_ID: &str = "workspace_id";
    /// Scope filter, resolved from PostgreSQL per `docs/07 §6.1`.
    pub const LIBRARY_ID: &str = "library_id";
    /// The join back to PostgreSQL, and the only field the post-filter needs.
    pub const FILE_ID: &str = "file_id";
    /// The version the chunk was cut from.
    pub const VERSION_ID: &str = "version_id";
    /// Result presentation and boosting.
    pub const CHUNK_TYPE: &str = "chunk_type";
    /// Boosted lexical field.
    pub const TITLE: &str = "title";
    /// Chunk body, and the excerpt source. Sensitive storage — `docs/07 §4`.
    pub const TEXT: &str = "text";
    /// Semantic retrieval.
    pub const DENSE_VECTOR: &str = "dense_vector";
    /// Learned sparse / BM25 hybrid.
    pub const SPARSE_VECTOR: &str = "sparse_vector";
    /// Ceiling filtering.
    pub const CLASSIFICATION_RANK: &str = "classification_rank";
    /// Optimization only, and this crate never filters on it. See [`super`].
    pub const ACL_TOKENS: &str = "acl_tokens";
    /// Mandatory segmentation, enforced in the policy chain and not here. See [`super`].
    pub const BARRIER_TOKENS: &str = "barrier_tokens";
    /// `files.acl_revision` at index time.
    pub const ACL_EPOCH: &str = "acl_epoch";
    /// Filter.
    pub const MIME_TYPE: &str = "mime_type";
    /// Filter.
    pub const LANGUAGE: &str = "language";
    /// Deep links and citations.
    pub const PAGE_NUMBER: &str = "page_number";
    /// Deep links and citations.
    pub const SHEET_NAME: &str = "sheet_name";
    /// Deep links and citations.
    pub const SECTION_PATH: &str = "section_path";
    /// Recency filters and boosting.
    pub const MODIFIED_TIMESTAMP: &str = "modified_timestamp";
}

/// The narrowing applied to a vector query, and nothing else.
///
/// Read [`self`](super::vector) before adding a field. The test that guards this type asserts what
/// the emitted filter may name, so a permission-shaped addition fails there rather than in review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prefilter {
    libraries: Vec<LibraryId>,
    ceiling: Option<ClassificationRank>,
}

impl Prefilter {
    /// The whole tenant, unnarrowed.
    ///
    /// The correct choice when the caller asked a tenant-wide question, and never a fallback for
    /// "the library resolution failed" — an unnarrowed scan is more expensive and returns more for
    /// the post-filter to drop, but it is not less safe, so it must not be reached for by a code
    /// path that was supposed to narrow and could not.
    #[must_use]
    pub fn unnarrowed() -> Self {
        Self::default()
    }

    /// Narrows to values the caller resolved **from PostgreSQL**, per `docs/07 §6.1`.
    ///
    /// Named for the provenance rather than the shape because that is the property review has to
    /// check: values sourced from the index and fed back to the index narrow nothing and prove
    /// nothing. An empty library list means "do not narrow by library", not "no libraries" — the
    /// latter is a decision for the caller to make before it gets here, by not searching.
    #[must_use]
    pub fn resolved_from_postgres(
        libraries: Vec<LibraryId>,
        ceiling: Option<ClassificationRank>,
    ) -> Self {
        Self { libraries, ceiling }
    }

    /// The libraries to confine the scan to, empty when unnarrowed.
    #[must_use]
    pub fn libraries(&self) -> &[LibraryId] {
        &self.libraries
    }

    /// The classification ceiling, if the caller has one.
    #[must_use]
    pub const fn ceiling(&self) -> Option<ClassificationRank> {
        self.ceiling
    }
}

/// One retrieval against the index.
#[derive(Debug, Clone, Copy)]
pub struct VectorQuery<'a> {
    /// The tenant, taken from the verified request context and never from a caller-supplied field
    /// (`CLAUDE.md` rule 3).
    pub tenant: TenantId,
    /// The query embedding, produced by the same model the collection was indexed with. A
    /// dimension mismatch is rejected by the server, which is the right place: this crate has no
    /// way to know which model produced a slice of floats.
    pub embedding: &'a [f32],
    /// How many candidates to ask for.
    ///
    /// A candidate budget, not a page size. The post-filter drops, so a page of 20 needs materially
    /// more than 20 candidates (`plans/M3-DISCOVERY.md` D21) — and D20's measurement is that
    /// raising this is nearly free while a second resolution pass is not. A caller that passes its
    /// page size here gets short pages and reads them as absence.
    pub budget: u32,
    /// The narrowing, and the whole of it.
    pub prefilter: &'a Prefilter,
}

/// A generator of candidates for the post-filter to confirm.
///
/// Implementations answer with things the caller *might* be allowed to see. Deciding which of them
/// they actually may see is [`crate::PostFilter::confirm`]'s job, unconditionally, every time.
#[async_trait]
pub trait VectorIndex: Send + Sync + std::fmt::Debug {
    /// Proposes candidates.
    ///
    /// # Errors
    ///
    /// Query failures, including a timed-out query. Deliberately **not** a degradation: `crate::error`
    /// and [`crate::degraded`] both state the doctrine — a single slow or failed query is an error,
    /// and only a state that persists across requests is allowed to change which retrieval path a
    /// search takes. An implementation that returned `Ok(vec![])` on an outage would be a search
    /// quietly reporting that the tenant has no such document.
    async fn candidates(&self, query: VectorQuery<'_>) -> Result<Vec<Candidate>, SearchError>;

    /// Whether the store can be reached, as a state rather than an error.
    ///
    /// Feeds [`crate::Retrieval::decide`]. Returns [`VectorStore::Unreachable`] rather than
    /// failing, because an unreachable index is the one condition degraded mode exists for, and an
    /// implementation that raised an error here would turn a recoverable loss of recall into a
    /// failed search.
    async fn reachability(&self) -> VectorStore;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_prefilter_carries_no_permission_of_any_kind() {
        // Note what this does and does not catch, because the comment here used to claim more than
        // the assertion delivers. It catches a field that the narrowing constructor *populates* and
        // the accessors do not expose — the round trip loses it and the equality fails. It does
        // **not** catch a field added with a default and set by some later builder method: both
        // sides would carry the default and compare equal.
        //
        // The load-bearing assertion is in `milvus.rs`, over the emitted filter and its template
        // bindings across every `Prefilter` shape. That one fails on a permission clause however
        // the field arrived, which is the property worth having. This is a cheap structural echo of
        // it, kept because it fails at the type rather than at the query.
        let narrowed = Prefilter::resolved_from_postgres(
            vec![LibraryId::new_v7()],
            Some(ClassificationRank::new(3)),
        );
        let rebuilt =
            Prefilter::resolved_from_postgres(narrowed.libraries().to_vec(), narrowed.ceiling());
        assert_eq!(narrowed, rebuilt, "a Prefilter holds something its accessors do not expose");
    }

    #[test]
    fn an_unnarrowed_prefilter_narrows_nothing() {
        let all = Prefilter::unnarrowed();
        assert!(all.libraries().is_empty());
        assert_eq!(all.ceiling(), None);
    }
}
