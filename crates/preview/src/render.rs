//! The rendering port, and the wrapper that makes its budget real.
//!
//! # What a renderer is handed, and what it is not
//!
//! [`RenderRequest`] carries **bytes**. Not an object key, not a signed URL, not a
//! [`BlobStore`](enclave_storage::BlobStore) handle — bytes, already fetched, and the profile to
//! produce. That is the no-egress property of `docs/06 §5` expressed as a type: a renderer cannot
//! fetch anything because it is given nothing to fetch with. An implementation that wanted to
//! reach the network would have to acquire a client of its own, which is a diff a reviewer notices
//! — the same technique `crates/api/src/preview.rs` uses to keep the preview handler away from
//! object storage.
//!
//! It also carries no identity. See [`crate::model`] for why that is structural rather than
//! incidental: the artefact this produces is cached, and a cached artefact that could name a viewer
//! is a watermark leak waiting for a cache hit.
//!
//! # `Bounded` is where the budget stops being a suggestion
//!
//! A renderer parses hostile input, so it is the component least able to promise it will stop.
//! [`Bounded`] wraps any [`Renderer`] and enforces the wall clock and the output cap from outside,
//! so a renderer that hangs, ignores its budget, or returns a gigabyte still cannot exceed either.
//! See [`crate::budget`] for the full argument.

use async_trait::async_trait;

use crate::budget::{Refusal, RenderBudget};
use crate::error::{PreviewError, Result};
use crate::model::RenditionProfile;

/// One rendering job.
///
/// Deliberately not `Clone`: a source is potentially hundreds of megabytes, and a type that copies
/// it silently is one accidental `.clone()` away from doubling the worker's peak memory.
#[derive(Debug)]
pub struct RenderRequest {
    /// Which derived form to produce.
    pub profile: RenditionProfile,
    /// The media type the *version row* declares.
    ///
    /// A hint, never a trust boundary. A renderer that dispatches on this alone renders whatever
    /// the uploader claimed the bytes were, which is how a parser gets fed something it was never
    /// written for. Implementations sniff the content and use this only to choose which sniffer to
    /// try first.
    pub declared_media_type: String,
    /// The bytes. See the module documentation for why these are bytes and not a key.
    pub source: Vec<u8>,
    /// The bounds this attempt runs inside.
    pub budget: RenderBudget,
}

/// What one page of a paginated artefact, or the whole of an unpaginated one, came out as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedArtifact {
    /// The artefact's bytes.
    pub bytes: Vec<u8>,
    /// The media type actually produced — determined by the profile, never echoed from the input.
    pub media_type: String,
    /// Pages represented, for paginated profiles.
    pub page_count: Option<u32>,
}

impl RenderedArtifact {
    /// How large this artefact is, for the output cap.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// The result of an attempt that did not fail.
///
/// `Refused` is a success, not an error — see [`crate::budget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderOutcome {
    /// An artefact was produced.
    Rendered(RenderedArtifact),
    /// No artefact, and re-running would not change that.
    Refused(Refusal),
}

impl RenderOutcome {
    /// The refusal, if this was one.
    #[must_use]
    pub const fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::Rendered(_) => None,
        }
    }
}

/// Turns a source into a base rendition.
///
/// Implementations are the sandboxed workers of `docs/06 §5`. This trait is the boundary between
/// the pipeline, which is ordinary code, and the parsers, which are not.
#[async_trait]
pub trait Renderer: Send + Sync {
    /// Which build this is, for the cache's generation check.
    ///
    /// Must change whenever the rendering output could change — a codec bump, a sanitizer fix, a
    /// different page size. A generator that forgets to advance this serves artefacts produced by
    /// the build it was meant to replace, including ones produced by a renderer since found to
    /// mis-sanitize.
    fn generator_version(&self) -> crate::model::GeneratorVersion;

    /// Whether this renderer handles the profile at all.
    ///
    /// Asked before the source is fetched, so an unsupported profile costs no object-storage read.
    fn supports(&self, profile: RenditionProfile) -> bool;

    /// Renders, or says why it did not.
    ///
    /// # Errors
    ///
    /// Only for failures that are *ours* — the worker died, the pipe broke. Anything about the
    /// document itself is a [`Refusal`] in the success channel.
    async fn render(&self, request: RenderRequest) -> Result<RenderOutcome>;
}

/// Enforces a renderer's budget from outside it.
///
/// Wrap every renderer in this. The inner renderer still receives its budget and should fail early,
/// but nothing depends on it doing so.
#[derive(Debug, Clone)]
pub struct Bounded<R> {
    inner: R,
}

impl<R> Bounded<R> {
    /// Wraps a renderer.
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    /// The renderer underneath, for tests and for composition.
    pub const fn inner(&self) -> &R {
        &self.inner
    }
}

#[async_trait]
impl<R: Renderer> Renderer for Bounded<R> {
    fn generator_version(&self) -> crate::model::GeneratorVersion {
        self.inner.generator_version()
    }

    fn supports(&self, profile: RenditionProfile) -> bool {
        self.inner.supports(profile)
    }

    async fn render(&self, request: RenderRequest) -> Result<RenderOutcome> {
        let budget = request.budget;

        // Before the renderer is entered, so a source that is over the cap is never parsed at all.
        // Checking afterwards would mean the parse this cap exists to prevent has already run.
        if request.source.len() as u64 > budget.max_input_bytes {
            return Ok(RenderOutcome::Refused(Refusal::InputTooLarge));
        }

        // The wall clock. `tokio::time::timeout` drops the future, which stops polling it — that
        // reclaims the task but *not* a thread stuck in synchronous parser code. That is precisely
        // why D17 puts the parser in another process: this bound is the pipeline's promise to its
        // caller, and the process limits are what make it true of the parser too. A renderer doing
        // real codec work must therefore hand it to `spawn_blocking` or to a subprocess, and this
        // wrapper's guarantee is that the *caller* is released on time either way.
        let outcome =
            match tokio::time::timeout(budget.wall_clock, self.inner.render(request)).await {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(RenderOutcome::Refused(Refusal::Timeout)),
            };

        let RenderOutcome::Rendered(artifact) = outcome else {
            return Ok(outcome);
        };

        if artifact.size_bytes() > budget.max_output_bytes {
            return Ok(RenderOutcome::Refused(Refusal::OutputTooLarge));
        }

        // Only paginated profiles are capped: a thumbnail is one image of the first page whatever
        // the document's length, so capping it would refuse a long book whose thumbnail costs the
        // same as any other.
        if let Some(pages) = artifact.page_count {
            if pages > budget.max_pages {
                return Ok(RenderOutcome::Refused(Refusal::TooManyPages));
            }
        }

        Ok(RenderOutcome::Rendered(artifact))
    }
}

/// A renderer that renders nothing.
///
/// The deny-by-default stub, in the shape `crates/core`'s policy stages already use: a deployment
/// with no rendering worker configured refuses every preview rather than falling through to
/// something that serves originals. `crates/api/src/preview.rs` returns `501` for the same reason
/// and with the same reasoning — the tempting shortcut, streaming the original until renditions
/// land, collapses `preview` and `download` into one permission on exactly the path where the
/// collapse is least visible.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRenderer;

#[async_trait]
impl Renderer for NoRenderer {
    fn generator_version(&self) -> crate::model::GeneratorVersion {
        crate::model::GeneratorVersion::new("none/0")
    }

    fn supports(&self, _profile: RenditionProfile) -> bool {
        false
    }

    async fn render(&self, _request: RenderRequest) -> Result<RenderOutcome> {
        Ok(RenderOutcome::Refused(Refusal::UnsupportedFormat))
    }
}

/// Never constructed; exists so `PreviewError` is used in this module's signatures.
const _: fn(PreviewError) = |_| ();
