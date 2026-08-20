//! Which model the index is built against — the answer to `plans/M3-DISCOVERY.md` Q14.
//!
//! # Why the name and the width live in one value
//!
//! `index_manifests.embedding_model` records which model produced a chunk's vectors, and the Milvus
//! collection is created with a fixed dense width. Those two facts must agree, and they are written
//! in different crates at different times — the manifest by the indexing worker, the collection by
//! `enclave_search::milvus::collection_schema`.
//!
//! Held apart as a `&str` and a `u32`, they drift the moment somebody swaps the model: the name
//! changes, the width is left, and the collection quietly keeps accepting vectors of the old size
//! from a model that no longer produces them. Nothing errors — Milvus is being handed the width it
//! was created with — and retrieval degrades into nonsense that reads as "the search is bad now".
//!
//! So [`EmbeddingModel`] carries both, the constants below are the only way to obtain one, and its
//! fields are public for reading only because there is no constructor to build a different pairing.
//!
//! # Changing the model is a reindex, not a config edit
//!
//! `docs/07 §9`. A collection's dense width is fixed at creation; a different width needs a new
//! collection and every chunk of every tenant re-embedded. That is why Q14 was answered before the
//! first production index rather than after, and why this module says it out loud where an operator
//! choosing a model will read it.

/// A model, and the collection width it implies.
///
/// No constructor: the pairing of a name with a width is a fact about a published model, not a
/// choice a caller makes. See the module documentation for what goes wrong when the two are set
/// independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingModel {
    /// The identifier recorded in `index_manifests.embedding_model`.
    ///
    /// The published model id, not a friendly name: `docs/07 §3`'s reindex trigger compares this
    /// string, so it has to be the thing that actually changes when the model does.
    pub id: &'static str,
    /// The dense vector width the Milvus collection is created with.
    pub dimension: u32,
    /// Whether the model also emits sparse (lexical-weighted) vectors natively.
    ///
    /// The collection has a `SPARSE_INVERTED_INDEX` field either way. A model that does not produce
    /// them leaves it empty, and hybrid retrieval falls back to the dense side alone — which is a
    /// recall difference, not a correctness one.
    pub sparse: bool,
}

/// **The model this deployment's collections are built against.**
///
/// `bge-m3`. Chosen for two properties that are expensive to acquire later:
///
/// 1. **Multilingual.** `docs/14-I18N-L10N.md` has tenants in many languages, and an English-only
///    model fails *silently* on the rest — it does not error, it simply stops matching, which
///    surfaces as "search does not work for the Munich office" months after the index was built.
///    This is the same reasoning that made `migrations/0012` use `'simple'` rather than a stemmer.
/// 2. **Native sparse vectors.** The collection already has a sparse field
///    (`enclave_search::milvus`), and until now nothing produced values for it. A model that emits
///    both fills it from the same forward pass rather than needing a second model beside it.
///
/// The costs are real and worth stating: 1024 dimensions is four times the index size of a
/// 384-wide model, and `bge-m3` is the slowest per chunk of the candidates considered. Both were
/// accepted because index size is a bill and a wrong-language index is a defect.
pub const ACTIVE: EmbeddingModel =
    EmbeddingModel { id: "BAAI/bge-m3", dimension: 1024, sparse: true };

/// Where the weights come from at run time.
///
/// **Mounted, not baked into the image.** `docs/08-BYO-INFRA.md §18` covers air-gapped installs,
/// where a multi-gigabyte layer on every image pull is a real cost, and a mount lets the model be
/// staged once beside the deployment. It also means changing models does not require rebuilding
/// and re-certifying an image.
///
/// The cost is a startup dependency, and it is not free: a process that starts with no model must
/// refuse to index rather than index nothing. `NoLocalModel` already refuses rather than returning
/// an empty vector, so the failure is loud by construction — see this crate's documentation on the
/// three ways a document could otherwise end up indexed-with-nothing.
pub const DELIVERY: Delivery = Delivery::Mounted;

/// How the model's weights reach the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Staged on a volume and mounted at run time.
    Mounted,
    /// Shipped inside the container image.
    InImage,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width the collection is created with is the width the model emits.
    ///
    /// Asserted rather than assumed because the two are set in different crates, and a mismatch is
    /// not an error at either end: Milvus accepts the width it was created with, and the model
    /// emits the width it was trained at. What breaks is retrieval quality, silently.
    #[test]
    fn the_active_model_is_the_one_the_collection_is_built_for() {
        // `const` blocks: these are compile-time facts, so a wrong one should fail the build rather
        // than a test run. Same form as `enclave_indexing::model`'s overhead assertion.
        const { assert!(ACTIVE.dimension == 1024, "bge-m3 emits 1024-dimensional dense vectors") };
        const { assert!(ACTIVE.sparse, "bge-m3 was chosen because it fills the sparse field too") };
        const { assert!(!ACTIVE.id.is_empty(), "the manifest records this string") };
    }

    /// `index_manifests.embedding_model` is compared as a string to decide what needs reindexing.
    #[test]
    fn the_model_id_is_the_published_identifier() {
        // A friendly name here would not change when the published model did, so the reindex
        // trigger in `docs/07 §3` would never fire on a model swap.
        assert!(ACTIVE.id.contains('/'), "expected a published `org/model` identifier");
    }
}
