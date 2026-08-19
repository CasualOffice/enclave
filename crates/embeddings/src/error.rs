//! Errors, and the one distinction that decides whether a document ends up silently unfindable.
//!
//! `crates/preview/src/error.rs` draws a line between a *refusal* — an answer about a document,
//! final, cached as such — and an *error*, meaning the pipeline could not reach an answer. This
//! crate has no refusals. There is no such thing as text that will not embed: every failure here is
//! ours, every one is transient until an operator makes it otherwise, and every one must leave the
//! document in a state indexing will come back to.
//!
//! That is the whole of `plans/M3-DISCOVERY.md` D23's second half. An embedding failure that
//! indexing treats as final produces a manifest that says `READY` over a document with no vectors:
//! filed correctly, visible in the tree, and absent from every search that should have found it.
//! A visible failure is recoverable. A silent absence is discovered by a user concluding the
//! document was deleted.
//!
//! # Why the unconfigured local model reports as *unavailable*
//!
//! [`EmbeddingError::LocalUnavailable`] is what [`NoLocalModel`](crate::NoLocalModel) returns, and
//! it is deliberately not a distinct "nobody configured one" variant. The two are the same fact
//! from indexing's side — there is no local model right now — and they must produce the same
//! behaviour, which is to wait. A variant meaning "permanently unconfigured" is a variant somebody
//! will map to "give up on this document", and a deployment that has not finished its Q14 model
//! decision would then quietly mark its entire corpus indexed-without-embeddings.
//!
//! [`EmbeddingError::Unconfigured`] exists for the *remote* stub, where the diagnosis is different:
//! the ceiling admitted text to remote and no remote provider is wired, which is an operator error
//! in the routing configuration rather than an outage. See [`NoRemoteProvider`](crate::NoRemoteProvider).

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = EmbeddingError> = core::result::Result<T, E>;

/// Something went wrong producing embeddings. Never a statement about the text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmbeddingError {
    /// The local model could not be reached, or is not configured yet.
    ///
    /// **Indexing waits.** It does not fall back to a remote provider — there is no code path from
    /// here to one, see [`crate::text`] — and it does not index the document without vectors.
    #[error("the local embedding model is unavailable")]
    LocalUnavailable(#[source] anyhow::Error),

    /// A route was taken for which no provider is wired.
    ///
    /// The ceiling and the configured providers disagree. An air-gapped deployment wants
    /// [`EmbeddingRouter::air_gapped`](crate::EmbeddingRouter::air_gapped), which sets a ceiling
    /// under which this route is never taken; reaching this error means neither was done.
    #[error("no {locality} embedding provider is configured in this deployment")]
    Unconfigured {
        /// Which side of the routing rule is missing, as
        /// [`Locality::LABEL`](crate::Locality::LABEL).
        locality: &'static str,
    },

    /// A configured provider failed: transport, rate limit, a model that fell over.
    ///
    /// Carries a cause for the operator and nothing derived from the text — a provider error
    /// message that echoes the prompt is how document content reaches a log (`CLAUDE.md` rule 10),
    /// and provider SDKs do echo it. Implementations are responsible for not passing one on.
    #[error("the embedding provider failed")]
    Provider(#[source] anyhow::Error),

    /// The provider returned a different number of vectors than it was given chunks.
    ///
    /// Refused rather than reconciled, because there is no way to tell *which* chunks came back.
    /// Storing the short list would attach vectors to the wrong chunk coordinates, and storing it
    /// as a partial index would leave a document whose later pages are unsearchable while its
    /// manifest says `READY` — the same silent absence this module exists to prevent, arriving
    /// through arithmetic instead of through an outage.
    #[error("the provider returned {returned} embeddings for {expected} chunks")]
    IncompleteBatch {
        /// Chunks handed to the provider.
        expected: usize,
        /// Vectors it returned.
        returned: usize,
    },
}

impl From<EmbeddingError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Every variant names [`Dependency::EmbeddingProvider`], so `/health` and the error envelope
    /// both say which upstream is at fault rather than reporting a generic internal error during an
    /// embedding outage.
    ///
    /// `retryable` is the field indexing's backoff reads, and it is the one place the wait/give-up
    /// decision is expressed: [`EmbeddingError::Unconfigured`] is `false` because retrying a
    /// missing configuration is a loop, while an unavailable local model is `true` because coming
    /// back is exactly what D23 requires.
    fn from(value: EmbeddingError) -> Self {
        match value {
            EmbeddingError::LocalUnavailable(_) | EmbeddingError::Provider(_) => {
                Self::Upstream { dependency: Dependency::EmbeddingProvider, retryable: true }
            }
            EmbeddingError::Unconfigured { .. } => {
                Self::Upstream { dependency: Dependency::EmbeddingProvider, retryable: false }
            }
            // Not an upstream failure: the provider answered, and the answer was internally
            // inconsistent. Retrying the same request against the same provider will produce the
            // same count.
            other @ EmbeddingError::IncompleteBatch { .. } => {
                Self::Internal(anyhow::Error::new(other))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn an_unavailable_local_model_is_retryable_so_indexing_comes_back() {
        // D23: indexing waits. `retryable: false` here would be indexing giving up, which is the
        // document that looks indexed and is not.
        let error: CoreError =
            EmbeddingError::LocalUnavailable(anyhow::anyhow!("connection refused")).into();
        match error {
            CoreError::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::EmbeddingProvider);
                assert!(retryable);
            }
            other => panic!("expected an upstream failure, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_configuration_is_not_retried_forever() {
        let error: CoreError = EmbeddingError::Unconfigured { locality: "remote" }.into();
        match error {
            CoreError::Upstream { retryable, .. } => assert!(!retryable),
            other => panic!("expected an upstream failure, got {other:?}"),
        }
    }

    #[test]
    fn no_embedding_failure_is_ever_reported_as_a_missing_document() {
        // The shape `crates/preview` warns about, in the direction that matters here: if an
        // embedding failure mapped to `NotFound`, indexing would read "this document has nothing to
        // embed" and finish the manifest.
        for error in [
            EmbeddingError::LocalUnavailable(anyhow::anyhow!("down")),
            EmbeddingError::Unconfigured { locality: "local" },
            EmbeddingError::Provider(anyhow::anyhow!("429")),
            EmbeddingError::IncompleteBatch { expected: 8, returned: 3 },
        ] {
            let mapped: CoreError = error.into();
            assert!(!matches!(mapped, CoreError::NotFound), "{mapped:?}");
        }
    }
}
