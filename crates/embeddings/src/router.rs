//! The router — which is, deliberately, almost nothing.
//!
//! Everything S8 depends on happened before this module: the ceiling comparison lives in
//! [`TextBatch::<Remote>::admit`] and the locality of a provider is the trait it implements. What
//! is left here is wiring, and the interesting property of the wiring is what it *does not*
//! contain.
//!
//! # Read [`EmbeddingRouter::embed`] for what is missing
//!
//! There is no `if rank >= ceiling`. There is no `match residency`. There is no inspection of any
//! error the local provider returns, and so there is no arm in which a failure could be answered by
//! trying somewhere else. The body is a `match` on an admission result whose `Err` arm is the
//! above-ceiling path, and that arm calls a *free function* — [`embed_local_only`] — rather than a
//! method.
//!
//! The free function is the second half of the argument, and it is `crates/api/src/preview.rs`'s
//! technique applied here. That handler cannot serve an original because it holds no `BlobStore`:
//! not "it does not call one", but there is none in scope, so adding the behaviour means adding the
//! extractor, which is a diff a reviewer notices. [`embed_local_only`] takes `&L` and no `self`.
//! Someone debugging a local model that keeps timing out will end up inside it, because that is
//! where the failure surfaces — and there is no remote provider in scope for them to reach for.
//! To introduce a fallback they would have to change the function's signature, at which point they
//! are no longer fixing a timeout.
//!
//! # What a fallback would have to defeat
//!
//! Three independent things, in a single change:
//!
//! 1. `EmbeddingProvider<Remote>::embed` takes a `TextBatch<Remote>`, and the only constructor of
//!    one refuses at and above the ceiling ([`crate::text`]).
//! 2. The above-ceiling path holds no remote provider ([`embed_local_only`]).
//! 3. Being remote is implementing `EmbeddingProvider<Remote>`, so a client cannot be put in the
//!    local slot without an `impl` that says it is local ([`crate::locality`]).
//!
//! Each of the three is visible in a diff on its own. The point is that no single helpful edit —
//! not a retry, not a timeout handler, not a circuit breaker — gets past any of them by accident.

use crate::error::{EmbeddingError, Result};
use crate::locality::{Local, Remote};
use crate::provider::{Embedding, EmbeddingProvider, NoRemoteProvider};
use crate::text::{ClassifiedText, LocalCeiling, TextBatch};

/// Sends text to the provider its classification permits.
///
/// Both providers are held by value and by type: `L` can only be something implementing
/// `EmbeddingProvider<Local>` and `R` something implementing `EmbeddingProvider<Remote>`. There is
/// no slot that takes "a provider" and consults it about where it runs.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddingRouter<L, R> {
    local: L,
    remote: R,
    ceiling: LocalCeiling,
}

impl<L: EmbeddingProvider<Local>> EmbeddingRouter<L, NoRemoteProvider> {
    /// A deployment with no remote provider at all.
    ///
    /// The air-gapped and BYO-nothing wiring of `docs/08 §18`. It sets
    /// [`LocalCeiling::EVERYTHING`], so remote admission refuses every rank and
    /// [`NoRemoteProvider`] is never actually called — the refusal happens one step earlier, in the
    /// type, rather than at a provider that would have to be trusted to refuse.
    ///
    /// Declared rather than inferred. A deployment that simply left the remote provider
    /// unconfigured would look the same from the outside and behave differently: below-ceiling text
    /// would take the remote route and fail there. Saying "air-gapped" makes the intent a fact the
    /// type carries.
    #[must_use]
    pub const fn air_gapped(local: L) -> Self {
        Self { local, remote: NoRemoteProvider, ceiling: LocalCeiling::EVERYTHING }
    }
}

impl<L: EmbeddingProvider<Local>, R: EmbeddingProvider<Remote>> EmbeddingRouter<L, R> {
    /// Wires a deployment's two providers and its ceiling.
    ///
    /// The ceiling comes from configuration (`classifications.embedding_policy`, `docs/07 §2.3`)
    /// rather than from a constant here, because ranks are tenant-defined. Tightening it is always
    /// available and never breaks indexing — see [`LocalCeiling`].
    ///
    /// # On dimensions
    ///
    /// The two providers' `dimensions()` must agree, or one Milvus collection ends up holding
    /// vectors of two widths. That check is not made here on purpose: with Q14 open there is no
    /// local model, so both stubs report `0` and a constructor that refused disagreement would
    /// refuse nothing while looking like it checked. It belongs with the startup residency
    /// validation of `docs/08 §18`, alongside the model decision that gives it a number.
    #[must_use]
    pub const fn new(local: L, remote: R, ceiling: LocalCeiling) -> Self {
        Self { local, remote, ceiling }
    }

    /// The ceiling this deployment is running with, for admin surfaces and audit.
    #[must_use]
    pub const fn ceiling(&self) -> LocalCeiling {
        self.ceiling
    }

    /// Embeds text through whichever provider its classification permits.
    ///
    /// # Errors
    ///
    /// Whatever the chosen provider returned, unaltered, plus
    /// [`EmbeddingError::IncompleteBatch`] if it returned the wrong number of vectors. In
    /// particular [`EmbeddingError::LocalUnavailable`] propagates: indexing waits and retries, it
    /// does not fall back and it does not record the document as indexed
    /// (`plans/M3-DISCOVERY.md` D23).
    pub async fn embed(&self, text: ClassifiedText) -> Result<Vec<Embedding>> {
        let expected = text.chunk_count();

        // The whole routing decision. Note that this function performs no comparison: `admit` does,
        // once, and its `Err` — the text handed back unembedded — *is* the above-ceiling case.
        let embeddings = match TextBatch::<Remote>::admit(text, self.ceiling) {
            Ok(admitted) => self.remote.embed(admitted).await,
            Err(above_ceiling) => {
                embed_local_only(&self.local, TextBatch::<Local>::admit(above_ceiling)).await
            }
        }?;

        // A provider that returns fewer vectors than it was given chunks has silently dropped part
        // of a document. Storing the short list would attach vectors to the wrong chunk
        // coordinates; storing it as a partial index would leave a document whose later pages are
        // unsearchable under a manifest that says `READY`. Both are the silent absence D23 is
        // about, so the batch fails and indexing retries it whole.
        if embeddings.len() == expected {
            Ok(embeddings)
        } else {
            Err(EmbeddingError::IncompleteBatch { expected, returned: embeddings.len() })
        }
    }
}

/// The above-ceiling path: a local provider, a batch, and nothing else in scope.
///
/// A free function taking `&L` rather than a method on [`EmbeddingRouter`], for the reason the
/// module documentation gives at length: this is where a local model's failure surfaces, so this is
/// where a retry would be written, so this is the one place that must not be able to reach a remote
/// provider. It cannot — there is no `self`, and `L` is bounded by `EmbeddingProvider<Local>`.
///
/// It is a single call with no error handling because there is nothing correct to do with the
/// error. Indexing waits.
///
/// # Errors
///
/// The provider's, unaltered.
async fn embed_local_only<L: EmbeddingProvider<Local>>(
    local: &L,
    batch: TextBatch<Local>,
) -> Result<Vec<Embedding>> {
    local.embed(batch).await
}
