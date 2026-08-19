//! S8, from outside the crate: `RESTRICTED` text never reaches a non-local embedding provider.
//!
//! # Why the remote double panics instead of returning an error
//!
//! [`Forbidden`] fails the test the moment it is called, and it does so by panicking rather than by
//! returning `Err`. That difference is the whole design of this file.
//!
//! An error is something a router could plausibly handle and move past. A test whose remote double
//! returns `Err` and then asserts on the final `Result` cannot distinguish "the remote provider was
//! never reached" from "the remote provider was reached, refused, and the router recovered by going
//! local" — and the second of those is the exact bug `plans/M3-DISCOVERY.md` D23 is about. It would
//! pass. A panic cannot be recovered from into a green test, so the assertion is about *reaching*
//! the provider and not about what it answered.
//!
//! Every double also counts its calls, so a failure names which provider ran rather than only that
//! one of them did.
//!
//! # What these tests do not cover, because the compiler does
//!
//! The strongest guarantee here is not something a test can execute: text at or above the ceiling
//! cannot be *expressed* as an argument to a remote provider, because `TextBatch<Remote>` has one
//! constructor and it refuses. The `compile_fail` proofs of that sit on `TextBatch` in
//! `crates/embeddings/src/text.rs`, where they run under `cargo test` and where the claim is next
//! to the code making it.
//!
//! What this file adds is the runtime half — that the router, wired the way a deployment wires it,
//! never reaches the remote provider for text it must not — including when the local provider is
//! down, which is the case the type system does not cover on its own.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use enclave_core::ClassificationRank;
use enclave_embeddings::{
    Availability, ClassifiedText, Embedding, EmbeddingError, EmbeddingProvider, EmbeddingRouter,
    Local, LocalCeiling, ModelId, NoLocalModel, NoRemoteProvider, Remote, TextBatch,
};

/// The default mapping of `docs/07 §2.3`, as the ranks a deployment might assign it.
const RESTRICTED: ClassificationRank = ClassificationRank::new(40);
const HIGHLY_CONFIDENTIAL: ClassificationRank = ClassificationRank::new(30);
const CONFIDENTIAL: ClassificationRank = ClassificationRank::new(20);
const INTERNAL: ClassificationRank = ClassificationRank::new(10);
const PUBLIC: ClassificationRank = ClassificationRank::new(0);

/// Two chunks, so a provider returning one is detectably short.
fn text(rank: ClassificationRank) -> ClassifiedText {
    ClassifiedText::new(
        rank,
        vec!["the acquisition price is".to_owned(), "and the board approved it on".to_owned()],
    )
}

/// A call counter the test keeps a handle on after the provider has been moved into the router.
#[derive(Debug, Clone, Default)]
struct Calls(Arc<AtomicUsize>);

impl Calls {
    fn record(&self) {
        let _previous = self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A local model that works.
struct WorkingLocal {
    model: ModelId,
    calls: Calls,
}

#[async_trait]
impl EmbeddingProvider<Local> for WorkingLocal {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        4
    }

    async fn embed(&self, batch: TextBatch<Local>) -> Result<Vec<Embedding>, EmbeddingError> {
        self.calls.record();
        Ok(batch.texts().iter().map(|_| Embedding::new(vec![0.0_f32; 4])).collect())
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

fn working_local() -> (WorkingLocal, Calls) {
    let calls = Calls::default();
    (WorkingLocal { model: ModelId::known("test-local/1"), calls: calls.clone() }, calls)
}

/// A local model that is down — the D23 case.
///
/// Down rather than absent, and counting, so a test can assert that indexing *tried* local, failed,
/// and stopped there.
struct DownLocal {
    model: ModelId,
    calls: Calls,
}

#[async_trait]
impl EmbeddingProvider<Local> for DownLocal {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        4
    }

    async fn embed(&self, _batch: TextBatch<Local>) -> Result<Vec<Embedding>, EmbeddingError> {
        self.calls.record();
        Err(EmbeddingError::LocalUnavailable(anyhow::anyhow!("connection refused")))
    }

    async fn availability(&self) -> Availability {
        Availability::Unavailable
    }
}

fn down_local() -> (DownLocal, Calls) {
    let calls = Calls::default();
    (DownLocal { model: ModelId::known("test-local/1"), calls: calls.clone() }, calls)
}

/// A remote provider that fails the test if it is ever reached.
///
/// It panics rather than returning an error, for the reason the module documentation gives: an
/// error is recoverable, and a router that recovered from it would be committing the exact bug
/// under test while the assertion still passed.
struct Forbidden {
    model: ModelId,
}

impl Forbidden {
    fn new() -> Self {
        Self { model: ModelId::known("hosted-api/1") }
    }
}

#[async_trait]
impl EmbeddingProvider<Remote> for Forbidden {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        4
    }

    async fn embed(&self, batch: TextBatch<Remote>) -> Result<Vec<Embedding>, EmbeddingError> {
        panic!("S8 violated: text ranked {} reached a remote provider", batch.rank().get());
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

/// A remote provider that works, for the routes that are supposed to use one.
struct WorkingRemote {
    model: ModelId,
    calls: Calls,
}

#[async_trait]
impl EmbeddingProvider<Remote> for WorkingRemote {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        4
    }

    async fn embed(&self, batch: TextBatch<Remote>) -> Result<Vec<Embedding>, EmbeddingError> {
        self.calls.record();
        assert!(
            LocalCeiling::at(RESTRICTED).permits_remote(batch.rank()),
            "a batch reached this provider that the default mapping keeps local"
        );
        Ok(batch.texts().iter().map(|_| Embedding::new(vec![1.0_f32; 4])).collect())
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

fn working_remote() -> (WorkingRemote, Calls) {
    let calls = Calls::default();
    (WorkingRemote { model: ModelId::known("hosted-api/1"), calls: calls.clone() }, calls)
}

/// A provider that answers, but with fewer vectors than it was given chunks.
struct ShortLocal {
    model: ModelId,
}

#[async_trait]
impl EmbeddingProvider<Local> for ShortLocal {
    fn model(&self) -> &ModelId {
        &self.model
    }

    fn dimensions(&self) -> usize {
        4
    }

    async fn embed(&self, _batch: TextBatch<Local>) -> Result<Vec<Embedding>, EmbeddingError> {
        Ok(vec![Embedding::new(vec![0.0_f32; 4])])
    }

    async fn availability(&self) -> Availability {
        Availability::Ready
    }
}

// ---------------------------------------------------------------------------------------------
// S8
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn restricted_text_never_reaches_a_remote_provider() {
    // The exit criterion, as directly as it can be stated. `Forbidden` fails the test on contact,
    // so this asserts about *reaching* the provider rather than about what it answered.
    //
    // `RESTRICTED` itself is in the list, not merely ranks above it: an exclusive comparison in
    // `TextBatch::<Remote>::admit` would send exactly the label S8 names to a hosted endpoint, and
    // a test using only rank 41 would not notice.
    let (local, local_calls) = working_local();
    let router = EmbeddingRouter::new(local, Forbidden::new(), LocalCeiling::at(RESTRICTED));

    for rank in [RESTRICTED, ClassificationRank::new(41), ClassificationRank::new(i32::MAX)] {
        let embeddings = router.embed(text(rank)).await.expect("local embeds every rank");
        assert_eq!(embeddings.len(), 2);
    }
    assert_eq!(local_calls.count(), 3);
}

#[tokio::test]
async fn an_unavailable_local_model_makes_indexing_wait_rather_than_fall_back() {
    // D23's second half, and the case the type system alone does not cover: the local provider has
    // failed, there *is* a configured remote provider, and something has to decide not to use it.
    //
    // `Forbidden` is what makes the assertion mean anything. A double returning `Err` would let a
    // router that tried remote and recovered pass, and trying-and-recovering is the bug.
    let (local, local_calls) = down_local();
    let router = EmbeddingRouter::new(local, Forbidden::new(), LocalCeiling::at(RESTRICTED));

    let error = router
        .embed(text(RESTRICTED))
        .await
        .expect_err("an unavailable local model must not produce embeddings");

    assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");

    // Tried once, then propagated. A retry loop that eventually reached remote would have tripped
    // `Forbidden`; one that hammered local shows up here.
    assert_eq!(
        local_calls.count(),
        1,
        "the failure must propagate, not be retried into a fallback"
    );

    // Retryable, and named as the embedding provider's problem: indexing waits and comes back.
    // Anything final here is a document whose manifest completes with no vectors.
    let core: enclave_core::Error = error.into();
    assert!(
        matches!(core, enclave_core::Error::Upstream { retryable: true, .. }),
        "indexing must be told to come back: {core:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The routes that are supposed to work
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn text_below_the_ceiling_routes_to_the_configured_remote_provider() {
    // Without this, every test above would be satisfied by a router that refuses everything, and S8
    // would be met by a product that cannot index.
    let (local, local_calls) = working_local();
    let (remote, remote_calls) = working_remote();
    let router = EmbeddingRouter::new(local, remote, LocalCeiling::at(RESTRICTED));

    for rank in [PUBLIC, INTERNAL, CONFIDENTIAL, HIGHLY_CONFIDENTIAL] {
        let embeddings = router.embed(text(rank)).await.expect("below the ceiling");
        assert_eq!(embeddings.len(), 2);
    }

    assert_eq!(remote_calls.count(), 4);
    assert_eq!(local_calls.count(), 0, "below-ceiling text must not be routed local by accident");
}

// ---------------------------------------------------------------------------------------------
// The ceiling is configuration, not a constant
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tightening_the_ceiling_moves_text_to_local_rather_than_to_a_refusal() {
    // Two deployments, one rank, two answers — which is what "configured, not hardcoded" means.
    //
    // The second half is the one that matters operationally. An operator responding to an incident
    // by tightening the ceiling must not thereby stop indexing: if a tighter ceiling produced
    // refusals, the safe reaction would carry a cost, and a control with a cost is a control people
    // revert at 4am.
    let (loose_local, loose_local_calls) = working_local();
    let (remote, remote_calls) = working_remote();
    let loose = EmbeddingRouter::new(loose_local, remote, LocalCeiling::at(RESTRICTED));

    assert_eq!(loose.embed(text(CONFIDENTIAL)).await.expect("routes remote").len(), 2);
    assert_eq!(remote_calls.count(), 1);
    assert_eq!(loose_local_calls.count(), 0);

    // Same content, tighter ceiling — and now `Forbidden`, because after the change this content
    // must not reach a remote provider at all.
    let (tight_local, tight_local_calls) = working_local();
    let tight = EmbeddingRouter::new(tight_local, Forbidden::new(), LocalCeiling::at(CONFIDENTIAL));

    assert_eq!(
        tight.embed(text(CONFIDENTIAL)).await.expect("tightening must not stop indexing").len(),
        2
    );
    assert_eq!(tight_local_calls.count(), 1, "the text moved to local, it was not refused");
}

#[tokio::test]
async fn an_air_gapped_deployment_keeps_even_public_text_local() {
    // `docs/08 §18`. A hostile remote provider is wired in deliberately: the point is that
    // `LocalCeiling::EVERYTHING` is what makes the deployment air-gapped, not the absence of a
    // configured endpoint. `PUBLIC` is the interesting rank — leaking public chunks would still be
    // a network call from a network that is supposed to have none, and would still disclose the
    // corpus's size, chunking and language.
    let (local, local_calls) = working_local();
    let router = EmbeddingRouter::new(local, Forbidden::new(), LocalCeiling::EVERYTHING);

    for rank in [PUBLIC, INTERNAL, RESTRICTED] {
        assert_eq!(router.embed(text(rank)).await.expect("everything is local").len(), 2);
    }
    assert_eq!(local_calls.count(), 3);
}

#[tokio::test]
async fn the_air_gapped_constructor_wires_that_ceiling_and_not_another() {
    let (local, local_calls) = working_local();
    let router = EmbeddingRouter::air_gapped(local);

    assert_eq!(router.ceiling(), LocalCeiling::EVERYTHING);
    assert_eq!(router.embed(text(PUBLIC)).await.expect("local embeds every rank").len(), 2);
    assert_eq!(local_calls.count(), 1);
}

// ---------------------------------------------------------------------------------------------
// Deny by default
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unconfigured_deployment_refuses_rather_than_indexing_without_vectors() {
    // The shape `crates/core`'s policy stages and `crates/preview::NoRenderer` use. The tempting
    // stub — `Ok(vec![])` — would let indexing complete a manifest over a document with no
    // embeddings: the silently unfindable document D23 exists to prevent, delivered by the
    // scaffolding rather than by an outage.
    let router = EmbeddingRouter::air_gapped(NoLocalModel);

    let error = router.embed(text(RESTRICTED)).await.expect_err("nothing is configured");
    assert!(matches!(error, EmbeddingError::LocalUnavailable(_)), "{error:?}");
}

#[tokio::test]
async fn a_ceiling_that_routes_remote_with_no_remote_configured_is_an_error_not_a_quiet_local_run()
{
    // Below-ceiling text on local compute would be *safe*, which is exactly why this refuses:
    // silently absorbing the misconfiguration would leave an operator who meant to use a hosted
    // endpoint diagnosing a saturated local GPU as a capacity problem. An air-gapped deployment
    // declares itself with `air_gapped`.
    let (local, local_calls) = working_local();
    let router = EmbeddingRouter::new(local, NoRemoteProvider, LocalCeiling::at(RESTRICTED));

    let error = router.embed(text(INTERNAL)).await.expect_err("no remote provider is wired");
    assert!(matches!(error, EmbeddingError::Unconfigured { locality: "remote" }), "{error:?}");
    assert_eq!(local_calls.count(), 0, "a missing remote provider must not silently become local");

    // And it is not retried forever, because retrying a missing configuration is a loop.
    let core: enclave_core::Error = error.into();
    assert!(matches!(core, enclave_core::Error::Upstream { retryable: false, .. }), "{core:?}");
}

// ---------------------------------------------------------------------------------------------
// A document that looks indexed and is not
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_provider_that_returns_too_few_vectors_fails_the_whole_batch() {
    // The third way to a document that looks filed and is unfindable — arithmetic rather than an
    // outage. Storing the short list would attach vectors to the wrong chunk coordinates, so the
    // batch fails and indexing retries it whole.
    let router = EmbeddingRouter::air_gapped(ShortLocal { model: ModelId::known("short/1") });

    let error = router.embed(text(RESTRICTED)).await.expect_err("two chunks, one vector");
    assert!(
        matches!(error, EmbeddingError::IncompleteBatch { expected: 2, returned: 1 }),
        "{error:?}"
    );
}
