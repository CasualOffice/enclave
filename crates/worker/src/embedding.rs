//! The embedding stage, built from what a deployment mounted — or not built at all.
//!
//! `ENC-661`. `crates/embeddings` has had the port, the router and the classification routing since
//! `ENC-508`, and [`MountedModel`] since this row; nothing outside its tests ever constructed one.
//! This module is the constructor, and `crates/worker/src/main.rs` is its only caller.
//!
//! It is deliberately the same shape as [`crate::ocr`], because it is the same problem one artefact
//! along: a large binary blob an operator stages on a volume, optional, whose absence must be a
//! documented state and whose *failure* must be an outage.
//!
//! # Three states, and the middle one is the point
//!
//! [`Config::embedding_mounts`] answers with three states rather than two, and this module honours
//! all three:
//!
//! | Configuration | What is built | What a document does |
//! |---|---|---|
//! | No `embedding_model` | nothing — [`None`] | indexed for lexical search; manifest records `""` |
//! | Model **and** `search.milvus` | [`MountedEmbedder`] | embedded, and a row reaches the collection |
//! | Model, no vector store | **nothing is built; startup fails** | — |
//!
//! The third row is the one worth having, and it is `crates/worker/src/ocr.rs`'s argument with the
//! nouns changed: a deployment that staged 2.2 GB of weights against `search.provider: none` would
//! load them, find no [`VectorWriter`](enclave_search::VectorWriter) to build a stage over, and
//! index exactly as it did before — with the configuration file saying embedding was on.
//!
//! # This is the **only** guard, and that is deliberate
//!
//! Unlike the OCR pair, there is no matching check in `enclave_config::validate`. The first version
//! of `ENC-661` had one, and `crates/config/tests/ambient_environment.rs` caught what it did:
//! `ConfigLoader` reads the whole process environment, `ENCLAVE_EMBEDDING_MODEL` is what CI and
//! every runbook export, and so a shell with the model staged and no vector store made **every**
//! binary refuse to start — `enclave-api` included, which builds no vector stage and has no opinion
//! about one. `ENC-544`'s failure through a validator instead of a variable name.
//!
//! So the rule lives here, in the composition root of the one process that can act on it, and the
//! usual "a guard on one of two paths is missing on the day it matters" argument does not apply:
//! there is no second path. A `Config` assembled in code and a `Config` from the loader reach this
//! function identically.
//!
//! # What "absent" means here, and why it is not a degradation
//!
//! A deployment with no model is not a deployment with broken embedding. It is a deployment that
//! does not embed: its documents are extracted, chunked, committed to `chunk_text` and findable by
//! **lexical** search, and `index_manifests.embedding_model` records `""` — which
//! [`BuildVersions`](enclave_indexing::BuildVersions) documents as the honest value for exactly
//! that. Dense retrieval returns nothing, and it returns nothing *visibly*: `IndexPass::embedded`
//! stays at zero beside a climbing `indexed`, which `crates/worker/src/indexing.rs` records as the
//! observation `ENC-557` existed to make possible.
//!
//! What it must never become is the tempting shortcut: no model, so write the chunk with a zero
//! vector, or with no vector, and let the row exist. That is the indexed-with-nothing document
//! `crates/embeddings` is arranged against from three directions, and there is no code path here
//! that can express it — [`NoLocalModel`](enclave_embeddings::NoLocalModel) refuses rather than
//! returning an empty vector, and this module builds *nothing* rather than building a stage over it.
//!
//! # A failed mount is an error, never a document without vectors
//!
//! [`MountedModel::mounted`] fails rather than degrades, and the failure propagates out of
//! [`MountedEmbedder::from_config`] to whatever starts the worker. A volume that failed to attach is
//! an outage. Reporting it as a corpus of un-embedded files would leave every document it touched
//! absent from dense search long after the outage ended, with nothing saying so —
//! `crates/embeddings/src/error.rs` states that as the embedding crate's property and this module
//! does not get to weaken it at the composition layer.
//!
//! # Why the router is always air-gapped
//!
//! [`EmbeddingRouter::air_gapped`] and never [`EmbeddingRouter::new`], because
//! [`NoRemoteProvider`](enclave_embeddings::NoRemoteProvider) is the only
//! `EmbeddingProvider<Remote>` in this workspace. A router built with `new` and a configured
//! ceiling would route below-ceiling text to a provider that refuses by construction, so a
//! deployment's `PUBLIC` documents would fail to embed while its `RESTRICTED` ones succeeded —
//! which is a baffling symptom for a correct configuration.
//!
//! `air_gapped` sets [`LocalCeiling::EVERYTHING`](enclave_embeddings::LocalCeiling::EVERYTHING), so
//! every rank takes the local arm and the remote stub is never reached. That is *declared* rather
//! than inferred, which is the distinction `crates/embeddings/src/router.rs` draws: this deployment
//! embeds locally because it has no remote provider, and saying so makes the intent a fact the type
//! carries. When a remote provider exists, this is the function that gains a ceiling from
//! configuration, and it is one call site.
//!
//! # Threads
//!
//! `rten` pulls `rayon` unconditionally (`ENC-535`), and `tokenizers` brings it too, so an embedding
//! worker runs a thread pool nested inside a forward pass on a `spawn_blocking` thread. Nothing in
//! library code sets `RTEN_NUM_THREADS`, deliberately and for [`crate::ocr`]'s reason — a library
//! that mutates the process environment does so to every other thread in the process without being
//! asked. It is set beside the worker's CPU limit by whoever deploys it.

use enclave_config::{Config, EmbeddingMounts};
use enclave_embeddings::{EmbeddingRouter, MountedModel, NoRemoteProvider};

use crate::{Result, WorkerError};

/// The embedding half of the indexing pass's vector stage, over mounted weights.
///
/// A newtype over the router rather than the router itself, so this module owns the one decision
/// that is a decision — [`EmbeddingRouter::air_gapped`] and not
/// [`EmbeddingRouter::new`](enclave_embeddings::EmbeddingRouter::new) — rather than leaving it at a
/// call site in `main.rs` where a later edit would look like configuration plumbing. See the module
/// documentation.
///
/// Holds the weights and nothing else: no store handle, no client, no key. The no-egress property
/// `crates/embeddings/src/mounted.rs` states applies with more force here than for an extractor,
/// because this is the stage that has the whole of a document's text in memory as tokens.
#[derive(Debug)]
pub struct MountedEmbedder {
    router: EmbeddingRouter<MountedModel, NoRemoteProvider>,
}

impl MountedEmbedder {
    /// Builds the embedder a deployment's configuration asks for, if it asks for one.
    ///
    /// # Errors
    ///
    /// * [`WorkerError::IncompleteMount`] when a model is mounted and no vector store is
    ///   configured. `enclave_config` refuses that at startup too; this is the second guard, for a
    ///   `Config` built in code.
    /// * [`WorkerError::Embedding`] when a configured mount cannot be loaded — missing, unreadable,
    ///   not a `.rten` graph, missing its tokenizer, or emitting a width this build does not index
    ///   against. An outage, and reported as one.
    pub fn from_config(config: &Config) -> Result<Option<Self>> {
        let model = match config.embedding_mounts() {
            // The deny-by-default state, and the one every deployment is in until it stages a model.
            EmbeddingMounts::Absent => return Ok(None),
            EmbeddingMounts::Incomplete { present, missing } => {
                return Err(WorkerError::IncompleteMount { present, missing })
            }
            EmbeddingMounts::Mounted { model } => model,
        };

        // `?` and not a fallback: see the module documentation on why a failed mount is an outage.
        // This is also where `ENC-533`'s first half lands — `MountedModel::mounted` refuses a graph
        // whose declared width is not `ACTIVE.dimension`, so a deployment that converted the wrong
        // model finds out at start-up rather than through months of degraded retrieval.
        let model = MountedModel::mounted(model)?;

        Ok(Some(Self { router: EmbeddingRouter::air_gapped(model) }))
    }

    /// The embedder, boxed for
    /// [`VectorStage::for_collection`](crate::indexing::VectorStage::for_collection).
    ///
    /// Consuming, because a router holds the weights and there is exactly one stage per process.
    #[must_use]
    pub fn into_embedder(self) -> Box<dyn enclave_embeddings::Embedder> {
        Box::new(self.router)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::path::PathBuf;

    use enclave_config::{MilvusSettings, SearchConfig, SearchProvider};

    use super::*;

    /// A configuration with a vector store, so only the model half is in question.
    fn with_store(model: Option<PathBuf>) -> Config {
        Config {
            embedding_model: model,
            search: SearchConfig {
                provider: SearchProvider::Milvus,
                milvus: Some(MilvusSettings {
                    uri: "http://milvus:19530".parse().expect("a valid URI"),
                    token: None,
                    collection: None,
                }),
            },
            ..Config::default()
        }
    }

    #[test]
    fn a_deployment_with_no_model_builds_no_embedder() {
        // Today's behaviour, kept. On its own this passes for free against a `from_config` that
        // returns `None` for everything — the positive control is `both_halves_build_an_embedder`
        // in `tests/embedding_mount.rs`, which needs the real weights and so cannot live here.
        assert!(MountedEmbedder::from_config(&Config::default())
            .expect("no model is not an error")
            .is_none());

        // And a vector store on its own is still no embedder, rather than an error. That is the
        // asymmetry `Config::embedding_mounts` argues for, asserted at the layer that acts on it.
        assert!(MountedEmbedder::from_config(&with_store(None))
            .expect("a store without a model is the ordinary deployment")
            .is_none());
    }

    #[test]
    fn a_model_with_nowhere_to_write_refuses_rather_than_building_half_a_stage() {
        // The second of the two guards. `enclave_config` refuses this through the loader; a `Config`
        // assembled in code — a test, a future admin-API edit, an embedded default — never goes
        // through the loader.
        let stranded = Config {
            embedding_model: Some(PathBuf::from("/mnt/enclave/bge-m3")),
            ..Config::default()
        };
        match MountedEmbedder::from_config(&stranded) {
            Err(WorkerError::IncompleteMount { present, missing }) => {
                assert_eq!(present, "embedding_model");
                assert_eq!(missing, "search.milvus");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_mount_that_does_not_exist_is_an_error_and_never_a_silent_absence() {
        // The distinction this whole module turns on: "no embedding configured" is `Ok(None)` and
        // "a model configured against a volume that is not there" is `Err`. An implementation that
        // treated an unloadable mount as "no embedding" would give a deployment whose model volume
        // failed to attach a corpus of un-embedded files and no error anywhere — and, unlike the OCR
        // case, not even a `FAILED` manifest to read, because the text indexes perfectly well.
        let config = with_store(Some(PathBuf::from("/nonexistent/enclave/embedding-model")));

        let error = MountedEmbedder::from_config(&config)
            .expect_err("a missing volume must not read as `no embedding`");
        assert!(matches!(error, WorkerError::Embedding(_)), "{error:?}");
    }
}
