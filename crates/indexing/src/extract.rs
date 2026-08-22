//! The extraction port, and the wrapper that makes its budget real.
//!
//! # The budget is `enclave-preview`'s, on purpose
//!
//! `plans/M3-DISCOVERY.md` D24: *"extraction is the same problem as rendering: a parser eating
//! hostile input. Its bounds are already written and tested (`crates/preview/src/budget.rs`); this
//! milestone reuses them rather than inventing a second set."*
//!
//! So this crate depends on [`enclave_preview`] for
//! [`RenderBudget`] and [`Refusal`], and
//! re-exports them under those names rather than aliasing them to extraction-flavoured ones. An
//! alias would read as a second type to the next person, and two names for one budget is how two
//! sets of numbers eventually appear behind them.
//!
//! The dependency looks heavier than it is, because D24 also decides where this code runs: the
//! sandboxed worker of `plans/M2-ACCESS-DELIVERY.md` D17 hosts *both* parsers. Rendering and
//! extraction are already co-resident by design, so sharing their bounds costs that process nothing
//! it was not carrying, and the deployment's memory limit, wall clock and input cap come from one
//! struct rather than from two that agree until someone tunes one of them.
//!
//! Only three things genuinely differ, and each is named where it lives rather than forked:
//!
//! - **The output cap is measured over a collection**, not a pixel buffer. See
//!   [`crate::model::TextDocument::size_bytes`].
//! - **The version marker is a reindex trigger, not a cache key.** See
//!   [`crate::model::ExtractorVersion`].
//! - **There is a third outcome.** See [`ExtractOutcome::NoText`].
//!
//! [`Refusal`] itself is reused whole. Extraction wanted a variant for
//! "an encoding we do not decode" and did not get one, which turned out to be right: *"nothing in
//! the pipeline extracts UTF-16"* is the same statement as *"nothing in the pipeline renders
//! video"*, both are actioned by adding a parser, and one code keeps them in one metric.
//!
//! # What an extractor is handed, and what it is not
//!
//! [`ExtractRequest`] carries **bytes** — not an object key, not a signed URL, not an
//! `enclave_storage::BlobStore` handle. That is the no-egress property of `docs/06 §5` expressed as
//! a type, and it matters more here than on the preview path: extraction is the stage that reads
//! the *whole* of a document's content, so an extractor that could reach the network is an
//! exfiltration primitive with the content already in hand.
//!
//! # `BoundedExtractor` is where the budget stops being a suggestion
//!
//! Identical in construction to [`Bounded`](enclave_preview::Bounded), and for the identical
//! reason: the component parsing hostile input is the one least able to promise it will stop. It is
//! a separate type rather than a reuse of `Bounded` only because `Bounded` is generic over
//! `Renderer`, and an [`Extractor`] is not one.

use async_trait::async_trait;
use enclave_preview::{Refusal, RenderBudget};

use crate::error::Result;
use crate::model::{ExtractorVersion, TextDocument};

/// One extraction job.
///
/// Deliberately not `Clone`, for the reason [`TextDocument`] is not.
#[derive(Debug)]
pub struct ExtractRequest {
    /// The media type the *version row* declares.
    ///
    /// A hint, never a trust boundary — the same status it has on `RenderRequest`. It selects which
    /// extractor is asked ([`Extractor::supports`]) and nothing after that: the extractor sniffs
    /// the content and refuses bytes that are not what they were claimed to be. An extractor that
    /// dispatched on this alone would parse whatever an uploader said the file was, which is how a
    /// parser gets fed something it was never written for.
    pub declared_media_type: String,
    /// The bytes. See the module documentation for why these are bytes and not a key.
    pub source: Vec<u8>,
    /// The bounds this attempt runs inside.
    pub budget: RenderBudget,
}

/// A source that parsed cleanly and contained no text.
///
/// The OCR hand-off, carried as data rather than left implicit. `pages_without_text` is the work
/// list: a scanned PDF reports every page, and an extractor that can say *which* pages were blank
/// lets OCR run over three of nine hundred instead of all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextlessSource {
    /// The media type the extractor decided on, from the content.
    pub media_type: String,
    /// One-based page numbers that yielded nothing, in order.
    ///
    /// Empty when the source has no pagination for OCR to work over — a text file of only
    /// whitespace is textless and there is nothing an image pipeline could rescue from it.
    pub pages_without_text: Vec<u32>,
}

/// The result of an attempt that did not fail.
///
/// `Refused` is a success, not an error — see [`crate::error`].
#[derive(Debug, PartialEq, Eq)]
pub enum ExtractOutcome {
    /// Text was extracted.
    Extracted(TextDocument),
    /// The source parsed, and yielded no text at all.
    ///
    /// The arm D24 exists to force. The tempting design has two outcomes and represents this as
    /// `Extracted` carrying an empty document, and that is exactly the failure the decision names:
    /// *"a scanned PDF that indexes as empty is invisible to search while appearing correctly
    /// filed, which is worse than one that failed to ingest — a failure is visible and a silent
    /// absence is not."*
    ///
    /// Nor is it a [`Refusal`]. A refusal is a verdict — re-running changes nothing — and this is
    /// the opposite: re-running *with OCR configured* is precisely what changes it. Until OCR ships
    /// (`ENC-161`) the pipeline records the manifest `FAILED` with a reason, per `docs/07 §2.1`, so
    /// the absence is on a surface somebody reads.
    NoText(TextlessSource),
    /// No text, and re-running changes nothing.
    Refused(Refusal),
}

impl ExtractOutcome {
    /// The refusal, if this was one.
    #[must_use]
    pub const fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Refused(refusal) => Some(*refusal),
            Self::Extracted(_) | Self::NoText(_) => None,
        }
    }

    /// The document, if text was found.
    #[must_use]
    pub const fn document(&self) -> Option<&TextDocument> {
        match self {
            Self::Extracted(document) => Some(document),
            Self::NoText(_) | Self::Refused(_) => None,
        }
    }
}

/// Turns a source into text and the structure it was found in.
///
/// Implementations are the sandboxed workers of `docs/06 §5`. This trait is the boundary between
/// the indexing pipeline, which is ordinary code, and the parsers, which are not.
///
/// # Adding OCR
///
/// An OCR engine is an `Extractor` like any other, registered for image media types and asked
/// again for the pages an earlier extractor reported in [`TextlessSource`]. D24 requires it to be a
/// first-class path rather than `docs/07 §2.1`'s *"fallback when a page yields no text"*, and the
/// difference is visible in this trait: a fallback is a `?:` inside somebody's extractor, whereas a
/// second `Extractor` handed a work list is a stage the pipeline can bound, meter and refuse
/// independently. Nothing here needs to change to admit one.
#[async_trait]
pub trait Extractor: Send + Sync {
    /// Which build this is, for `docs/07 §3`'s reindex trigger.
    ///
    /// Must change whenever the extracted text could change — a decoder swap, a different paragraph
    /// rule, a newly-recognised structure. An extractor that forgets to advance this leaves an
    /// index built by the build it replaced, and unlike a stale rendition nothing regenerates it on
    /// demand.
    fn extractor_version(&self) -> ExtractorVersion;

    /// Whether this extractor claims the *declared* media type.
    ///
    /// Asked before the source is fetched, so an unhandled type costs no object-storage read. It is
    /// an optimisation and not a security decision, in both directions: a `true` is not a promise
    /// to extract — the sniff may still refuse — and a `false` is not a claim that the bytes are
    /// safe, only that this extractor was not written for what the uploader said they were.
    fn supports(&self, declared_media_type: &str) -> bool;

    /// Extracts, or says why it did not.
    ///
    /// # Errors
    ///
    /// Only for failures that are *ours* — the worker died, the pipe broke. Anything about the
    /// document itself is a [`Refusal`] or a [`TextlessSource`] in the success channel.
    async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome>;
}

/// Enforces an extractor's budget from outside it.
///
/// Wrap every extractor in this. The inner extractor still receives its budget and should fail
/// early and cheaply, but nothing depends on it doing so.
#[derive(Debug, Clone)]
pub struct BoundedExtractor<E> {
    inner: E,
}

impl<E> BoundedExtractor<E> {
    /// Wraps an extractor.
    pub const fn new(inner: E) -> Self {
        Self { inner }
    }

    /// The extractor underneath, for tests and for composition.
    pub const fn inner(&self) -> &E {
        &self.inner
    }
}

#[async_trait]
impl<E: Extractor> Extractor for BoundedExtractor<E> {
    fn extractor_version(&self) -> ExtractorVersion {
        self.inner.extractor_version()
    }

    fn supports(&self, declared_media_type: &str) -> bool {
        self.inner.supports(declared_media_type)
    }

    async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome> {
        let budget = request.budget;

        // Before the extractor is entered, so a source over the cap is never parsed at all.
        // Checking afterwards would mean the parse this cap exists to prevent has already run.
        if request.source.len() as u64 > budget.max_input_bytes {
            return Ok(ExtractOutcome::Refused(Refusal::InputTooLarge));
        }

        // The wall clock. `tokio::time::timeout` drops the future, which stops polling it — that
        // reclaims the task but *not* a thread stuck in synchronous parser code. That is why D24
        // puts extraction in D17's worker: this bound is the pipeline's promise to its caller, and
        // the process limits are what make it true of the parser too. An extractor doing real
        // parsing must hand it to `spawn_blocking` or to a subprocess, and this wrapper's guarantee
        // is that the *caller* is released on time either way.
        let outcome =
            match tokio::time::timeout(budget.wall_clock, self.inner.extract(request)).await {
                Ok(result) => result?,
                Err(_elapsed) => return Ok(ExtractOutcome::Refused(Refusal::Timeout)),
            };

        let ExtractOutcome::Extracted(document) = outcome else {
            return Ok(outcome);
        };

        if document.size_bytes() > budget.max_output_bytes {
            return Ok(ExtractOutcome::Refused(Refusal::OutputTooLarge));
        }

        if let Some(pages) = document.page_count {
            if pages > budget.max_pages {
                return Ok(ExtractOutcome::Refused(Refusal::TooManyPages));
            }
        }

        // D24, enforced rather than trusted. An extractor that hands back a document with no
        // characters in it has described a scanned or empty source, whatever it believes it did,
        // and letting that through as `Extracted` is how a manifest reaches `READY` with nothing
        // behind it. Converted here, from outside, for the same reason the budget is: the component
        // that would have to notice is the one parsing hostile input.
        if document.is_empty() {
            return Ok(ExtractOutcome::NoText(TextlessSource {
                pages_without_text: (1..=document.page_count.unwrap_or(0)).collect(),
                media_type: document.media_type,
            }));
        }

        Ok(ExtractOutcome::Extracted(document))
    }
}

/// A shared extractor is an extractor.
///
/// `ENC-613`. Two passes now extract text from the same corpus — indexing, and the DLP scan that
/// produces `security_facts` — and `docs/06 §12`'s asynchronous scan has to read the *same* text
/// the index does. So the composition root builds **one** router, wraps it in one
/// [`BoundedExtractor`], and lends it to both, rather than assembling a second one that agrees with
/// the first until somebody registers a media type in one of the two places.
///
/// `?Sized` so that `Arc<dyn Extractor>` is covered: the trait is object-safe, and the erased form
/// is what lets two [`crate::Pipeline`]s share one instance without the binary naming a concrete
/// extractor type twice.
#[async_trait]
impl<E: Extractor + ?Sized> Extractor for std::sync::Arc<E> {
    fn extractor_version(&self) -> ExtractorVersion {
        (**self).extractor_version()
    }

    fn supports(&self, declared_media_type: &str) -> bool {
        (**self).supports(declared_media_type)
    }

    async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome> {
        (**self).extract(request).await
    }
}

/// An extractor that extracts nothing.
///
/// The deny-by-default stub, in the shape `crates/core`'s policy stages and
/// [`NoRenderer`](enclave_preview::NoRenderer) already use: a deployment with no extraction worker
/// configured refuses every source rather than falling through to something that indexes raw bytes.
/// The tempting shortcut — index the file's bytes as though they were text until a real extractor
/// lands — would put arbitrary binary content into Milvus's `text` field, which `docs/07 §4` treats
/// as sensitive storage precisely because it holds a copy of the content.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoExtractor;

#[async_trait]
impl Extractor for NoExtractor {
    fn extractor_version(&self) -> ExtractorVersion {
        ExtractorVersion::new("none/0")
    }

    fn supports(&self, _declared_media_type: &str) -> bool {
        false
    }

    async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
        Ok(ExtractOutcome::Refused(Refusal::UnsupportedFormat))
    }
}
