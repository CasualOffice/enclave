//! The port, what it produces, and the two providers a deployment has before it configures any.
//!
//! `docs/08-BYO-INFRA.md §2` specifies `EmbeddingProvider` as a single trait with a `residency()`
//! method. It is a single trait here too — the mechanics of turning strings into vectors are the
//! same wherever the model runs — but it is *generic over locality*, and that one change is what
//! moves S8 from a rule providers are asked to respect into a rule they cannot express a violation
//! of. See [`crate::locality`] for the argument and [`crate::text`] for the mechanism.
//!
//! # What is deliberately absent from this port
//!
//! **No `endpoint`, no `url`, no transport of any kind.** A port that could name where to send text
//! would let a caller pick the destination, which is the caller's-choice-of-client design D23
//! rejects. Where a provider sends things is a property of the provider, fixed when it is
//! constructed from configuration, and invisible from here.
//!
//! **No `embed_one`.** One method taking a batch, because a per-chunk method invites a loop that
//! retries individual chunks, and a retry loop is where a second provider gets introduced. It also
//! matches what the providers actually are: `embedding.batch_size` in `docs/08 §17` exists because
//! every real implementation is batched underneath.
//!
//! **No real model.** `plans/M3-DISCOVERY.md` Q14 — which local model, and whether it ships in the
//! image or mounts at runtime — is open, and it is a decision with an air-gapped install and a
//! container-size bill attached (`docs/08 §18`). Guessing it here would produce a `dimensions()`
//! that `index_manifests.embedding_model` records and a full reindex to change (`docs/07 §9`). So
//! the only providers in this crate are the two below, which refuse.

use async_trait::async_trait;
use std::borrow::Cow;

use crate::error::{EmbeddingError, Result};
use crate::locality::{Local, Locality, Remote};
use crate::text::TextBatch;

/// Which model produced a vector.
///
/// Recorded on `index_manifests.embedding_model` (`docs/07 §9`), where changing it triggers a full
/// reindex of affected content. A newtype rather than a `String` for the usual reason — it ends up
/// beside a `chunker_version` and a `generator_version` in the same struct, and three strings in a
/// row is three chances to pass them in the wrong order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelId(Cow<'static, str>);

impl ModelId {
    /// A model compiled into the binary, named by a literal.
    #[must_use]
    pub const fn known(name: &'static str) -> Self {
        Self(Cow::Borrowed(name))
    }

    /// A model named by configuration — the customer-hosted endpoint case of `docs/08 §11`.
    #[must_use]
    pub fn configured(name: String) -> Self {
        Self(Cow::Owned(name))
    }

    /// The name, for the manifest row and for logs.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One vector.
///
/// [`Debug`] is hand-written and prints only the width. An embedding is a lossy but genuine
/// representation of the text that produced it — inversion attacks on sentence embeddings are a
/// live research area — so a `tracing` line that captured 768 floats has captured document content
/// in a form that is merely inconvenient to read, which `CLAUDE.md` rule 10 does not carve out.
#[derive(Clone, PartialEq)]
pub struct Embedding(Vec<f32>);

impl Embedding {
    /// Wraps a provider's output.
    #[must_use]
    pub const fn new(values: Vec<f32>) -> Self {
        Self(values)
    }

    /// The width, which must match the collection's (`docs/07 §4`).
    #[must_use]
    pub fn dimensions(&self) -> usize {
        self.0.len()
    }

    /// The components, for the vector store.
    #[must_use]
    pub fn as_slice(&self) -> &[f32] {
        &self.0
    }
}

impl core::fmt::Debug for Embedding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Embedding").field("dimensions", &self.0.len()).finish()
    }
}

/// Whether a provider is answering right now.
///
/// # Why the router never asks
///
/// This exists for the admin "test connection" of `docs/08 §2`, for `/health`, and for the startup
/// residency validation of `docs/08 §18` — surfaces whose whole job is to report a state.
///
/// [`EmbeddingRouter`](crate::EmbeddingRouter) deliberately does not consult it before routing. A
/// router that asks "is the local model up?" has a branch for *no*, and that branch is the exact
/// line D23 is about: it is where a well-meaning edit writes `else { remote }`. Not asking leaves
/// nowhere for the fallback to be written. The pre-check would also be a lie — the model can fall
/// over between the check and the call — so it buys nothing in exchange for the branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Answering.
    Ready,
    /// Not answering. For a local provider this means indexing waits (`crates/embeddings/src/error.rs`).
    Unavailable,
}

/// Turns text into vectors, somewhere.
///
/// The `L` parameter is not documentation. `EmbeddingProvider<Remote>::embed` takes a
/// `TextBatch<Remote>`, which only [`TextBatch::<Remote>::admit`] can construct, which refuses at
/// and above the ceiling. That chain is what makes S8 a property of the type system rather than of
/// this crate's discipline — see [`crate::text`].
#[async_trait]
pub trait EmbeddingProvider<L: Locality>: Send + Sync {
    /// Which model this is, for `index_manifests.embedding_model`.
    fn model(&self) -> &ModelId;

    /// The width of the vectors it produces.
    ///
    /// Fixed per provider, and the collection is created against it (`docs/07 §4`). A provider
    /// whose width changes under a deployment is a model change, which is a full reindex.
    fn dimensions(&self) -> usize;

    /// Embeds a batch, one vector per chunk, in order.
    ///
    /// # Errors
    ///
    /// [`EmbeddingError::LocalUnavailable`] from a local provider that cannot be reached, and
    /// [`EmbeddingError::Provider`] for anything else. Never an error meaning "this text will not
    /// embed": there is no such text, and a variant for it would be one indexing could treat as
    /// final. See [`crate::error`].
    async fn embed(&self, batch: TextBatch<L>) -> Result<Vec<Embedding>>;

    /// Whether this provider is answering, for operator surfaces.
    ///
    /// Not part of the routing decision — see [`Availability`] for why that is deliberate.
    async fn availability(&self) -> Availability;
}

/// The name a provider reports before a deployment has chosen a model.
///
/// A `static` rather than a constant so [`EmbeddingProvider::model`] can hand out a reference to
/// it, and a distinct string rather than an empty one so an `index_manifests` row written under a
/// misconfiguration is recognisable as such instead of looking like a missing value.
static UNCONFIGURED_MODEL: ModelId = ModelId::known("unconfigured");

/// The local provider a deployment has when no model is configured.
///
/// The deny-by-default stub, in the shape `crates/core`'s policy stages and
/// `crates/preview::NoRenderer` already use: an unconfigured deployment refuses rather than falling
/// through to something permissive. Here the permissive thing it must not fall through to is
/// *remote* — and it cannot, because refusing is all this type can do and there is no path from its
/// error to another provider (see [`crate::router`]).
///
/// It is what the crate ships with because Q14 is open. When a model lands this type stays: a
/// deployment that has not mounted the model, or whose model volume failed to attach, wants exactly
/// this behaviour rather than a provider that silently produces nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalModel;

#[async_trait]
impl EmbeddingProvider<Local> for NoLocalModel {
    fn model(&self) -> &ModelId {
        &UNCONFIGURED_MODEL
    }

    /// Zero, because there is no collection this stub could be consistent with.
    ///
    /// A plausible-looking width — 384, 768 — would let a Milvus collection be created against a
    /// model that does not exist, and the mismatch would surface later as vectors of the wrong
    /// shape rather than now as an obviously unconfigured deployment.
    fn dimensions(&self) -> usize {
        0
    }

    async fn embed(&self, _batch: TextBatch<Local>) -> Result<Vec<Embedding>> {
        // `LocalUnavailable`, not a dedicated "unconfigured" variant, and not `Ok(vec![])`.
        //
        // `Ok(vec![])` is the dangerous one: it is what a stub written for convenience returns, and
        // it would let indexing complete a manifest over a document with no vectors — the silently
        // unfindable document D23 exists to prevent, produced by the very code meant to stand in
        // until there is a model. The router's count check would catch it, which is precisely why
        // that check is there; refusing here means it never has to.
        Err(EmbeddingError::LocalUnavailable(anyhow::anyhow!(
            "no local embedding model is configured in this deployment"
        )))
    }

    async fn availability(&self) -> Availability {
        Availability::Unavailable
    }
}

/// The remote provider a deployment has when none is configured.
///
/// Reached only when the ceiling admitted text to remote and nothing is wired there, which is a
/// contradiction in the configuration rather than an outage — so it reports
/// [`EmbeddingError::Unconfigured`] and is not retried.
///
/// # Why this does not quietly embed locally instead
///
/// It would be safe. Below-ceiling text on local compute violates nothing, and the temptation is
/// real: the deployment keeps indexing and nobody is paged.
///
/// It is refused because the misconfiguration would then be undetectable. An operator who set a
/// ceiling of `CONFIDENTIAL` intending everything below it to go to a hosted endpoint would see a
/// working system, a local GPU at a hundred percent, and an indexing backlog they would diagnose as
/// a capacity problem. An air-gapped deployment says so by wiring
/// [`EmbeddingRouter::air_gapped`](crate::EmbeddingRouter::air_gapped), which never takes this
/// route at all — declaring the intent rather than discovering it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRemoteProvider;

#[async_trait]
impl EmbeddingProvider<Remote> for NoRemoteProvider {
    fn model(&self) -> &ModelId {
        &UNCONFIGURED_MODEL
    }

    fn dimensions(&self) -> usize {
        0
    }

    async fn embed(&self, _batch: TextBatch<Remote>) -> Result<Vec<Embedding>> {
        Err(EmbeddingError::Unconfigured { locality: Remote::LABEL })
    }

    async fn availability(&self) -> Availability {
        Availability::Unavailable
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::ClassificationRank;

    use super::*;
    use crate::text::ClassifiedText;

    fn batch<L: Locality>(make: impl FnOnce(ClassifiedText) -> TextBatch<L>) -> TextBatch<L> {
        make(ClassifiedText::new(ClassificationRank::new(10), vec!["a paragraph".to_owned()]))
    }

    #[tokio::test]
    async fn an_unconfigured_local_model_refuses_rather_than_returning_nothing() {
        // The distinction that matters: `Ok(vec![])` from a stub is a document indexed with no
        // vectors, which looks filed and is unfindable.
        let error = NoLocalModel
            .embed(batch(TextBatch::<Local>::admit))
            .await
            .expect_err("an unconfigured model must not produce embeddings");
        assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");
        assert_eq!(NoLocalModel.availability().await, Availability::Unavailable);
    }

    #[tokio::test]
    async fn an_unconfigured_remote_provider_names_the_missing_configuration() {
        let batch = TextBatch::<Remote>::admit(
            ClassifiedText::new(ClassificationRank::new(10), vec!["a paragraph".to_owned()]),
            crate::LocalCeiling::at(ClassificationRank::new(40)),
        )
        .expect("below the ceiling");

        let error = NoRemoteProvider
            .embed(batch)
            .await
            .expect_err("an unconfigured provider must not produce embeddings");
        assert!(matches!(error, EmbeddingError::Unconfigured { locality: "remote" }), "{error:?}");
    }

    #[test]
    fn an_embedding_never_prints_its_components() {
        // Rule 10, applied to the lossy-but-real representation of the text. A log line holding 768
        // floats holds content in a form that is inconvenient to read, not content that is absent.
        let embedding = Embedding::new(vec![0.125_f32, -0.5, 0.75]);
        let rendered = format!("{embedding:?}");
        assert!(!rendered.contains("0.125"), "{rendered}");
        assert!(rendered.contains('3'), "the width is the useful half: {rendered}");
    }
}
