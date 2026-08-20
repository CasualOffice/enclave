//! `enclave-embeddings` — the embedding port, and classification routing that cannot be bypassed.
//!
//! M3's exit criterion S8: **`RESTRICTED` text never reaches a non-local embedding provider.**
//!
//! # The failure mode this crate is shaped around
//!
//! It is not that somebody picks the wrong provider. Picking the wrong provider is a configuration
//! error, it is visible in configuration, and an operator reviewing `embedding.provider` finds it.
//!
//! It is that a *fallback* picks it. `plans/M3-DISCOVERY.md` D23: a provider that is unreachable,
//! rate-limited or slow invites a retry against another one, and that is the moment the routing
//! rule is quietly violated by code that is trying to be helpful. Nobody decides to send
//! `RESTRICTED` text to a hosted API. Somebody adds a `.or_else(|_| self.secondary.embed(...))` at
//! 3am because indexing is backed up, and the rule is gone — with a green build, because the
//! routing test only ever exercised the path where the primary answered.
//!
//! Everything below follows from taking that seriously. A rule enforced by a check the router
//! performs protects the call sites that existed when it was written. A rule enforced by the type
//! system protects the call site added later, by someone who has not read this file.
//!
//! # How S8 is made structural
//!
//! Three properties, each independently sufficient to stop the accidental case, and none of them a
//! matter of discipline at a call site:
//!
//! **1. The text carries its own routing.** [`ClassifiedText`] holds chunks and the rank of the
//! content they came from, and exposes no way to read the chunks. The only functions that can are
//! [`TextBatch::<Local>::admit`] — infallible, because there is no rank a local model may not see —
//! and [`TextBatch::<Remote>::admit`], which returns `Err` at and above the ceiling.
//! `EmbeddingProvider<Remote>::embed` takes a `TextBatch<Remote>`. So holding one *is* the proof
//! that its text was below the ceiling, and there is no way to call a remote provider without
//! first holding that proof. There is exactly one rank-against-ceiling comparison in this crate.
//!
//! **2. The above-ceiling path holds no remote provider.** [`EmbeddingRouter::embed`] hands
//! above-ceiling text to a free function that takes the local provider and nothing else. This is
//! `crates/api/src/preview.rs`'s technique — that handler cannot serve an original because it holds
//! no `BlobStore`, not because it declines to — applied where a fallback would actually be written:
//! at the point where a local model's failure surfaces. Adding one there means changing a
//! signature, which is no longer a timeout fix.
//!
//! **3. Locality is a type, not a field.** A provider is local because `EmbeddingProvider<Local>`
//! is the trait it implements and the router's local slot is typed for that trait. `docs/08 §2`'s
//! `residency()` reports a fact; a fact has to be *asked for*, and the fallback case is exactly the
//! case where nobody asks. Wiring a network client into the local slot requires an
//! `impl EmbeddingProvider<Local> for …` — a false statement in a diff.
//!
//! Defeating S8 by accident would take all three at once. Defeating it deliberately takes a
//! re-labelling of restricted content as public, which is three unmistakable lines; `crates/embeddings/src/text.rs`
//! says so plainly rather than claiming a guarantee it does not have.
//!
//! # If the local model is unavailable, indexing waits
//!
//! D23's second half, and the reason there is no [`Availability`] check in the routing path. It
//! does not fall back, and it does not index without embedding: an un-embedded document that looks
//! indexed is filed correctly, visible in the tree, and absent from every search that should have
//! found it — worse than one that visibly failed, because a failure is recoverable and a silent
//! absence is discovered by a user concluding the document was deleted.
//!
//! So every failure here is transient and retryable ([`crate::error`]), the deny-by-default
//! [`NoLocalModel`] refuses rather than returning an empty vector, and the router refuses a batch
//! that comes back short ([`EmbeddingError::IncompleteBatch`]). Three separate ways for a document
//! to end up indexed-with-nothing, all closed.
//!
//! # What is deliberately not here
//!
//! **No weights, but the model is now decided.** Q14 is answered — [`model::ACTIVE`] is `bge-m3`
//! at 1024 dimensions, delivered by mount rather than baked into the image ([`model::DELIVERY`]).
//! That fixes the width the Milvus collection is created with and the string
//! `index_manifests.embedding_model` records; changing it later is a full reindex (`docs/07 §9`),
//! which is why it was settled before the first production index rather than after.
//!
//! What is still absent is the *inference*: this crate ships [`NoLocalModel`] and
//! [`NoRemoteProvider`], in the deny-by-default shape `crates/core`'s policy stages and
//! `crates/preview::NoRenderer` use. A deployment without weights refuses to index rather than
//! indexing nothing, which is the distinction the three guards above exist to hold.
//!
//! **No `APPROVED_ONLY` tier.** `docs/07 §2.3` has three tiers; this crate implements the boundary
//! S8 is about. [`Locality`] is sealed so the third arrives beside the ceiling rather than being
//! declared by a caller ([`crate::locality`]).
//!
//! **No `NO_INDEX` handling.** Content that must never leave the database is not extracted, not
//! chunked and never offered here. That belongs to indexing, which knows the library's
//! `ai_indexing_enabled` and the label's policy; this crate cannot tell the difference between text
//! it should not have been given and text it should.

pub mod error;
pub mod locality;
pub mod model;
pub mod provider;
pub mod router;
pub mod text;

pub use error::{EmbeddingError, Result};
pub use locality::{Local, Locality, Remote};
pub use model::{EmbeddingModel, ACTIVE, DELIVERY};
pub use provider::{
    Availability, Embedding, EmbeddingProvider, ModelId, NoLocalModel, NoRemoteProvider,
};
pub use router::EmbeddingRouter;
pub use text::{ClassifiedText, LocalCeiling, TextBatch};
