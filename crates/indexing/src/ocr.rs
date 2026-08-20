//! Optical character recognition: the pages a text extractor could not read, read as images.
//!
//! # Why this is a stage and not a fallback
//!
//! `plans/M3-DISCOVERY.md` D24: *"OCR is a first-class path, not the `docs/07` fallback 'when a page
//! yields no text'. A scanned PDF that indexes as empty is invisible to search while appearing
//! correctly filed, which is worse than one that failed to ingest — a failure is visible and a
//! silent absence is not."*
//!
//! The difference between a stage and a fallback is visible in the types. A fallback is a `?:`
//! inside somebody's extractor: it runs when the first attempt returned nothing, it cannot be
//! bounded separately, and when *it* returns nothing the caller cannot tell which of the two
//! produced the emptiness. What is here instead is:
//!
//! - [`OcrExtractor`], an ordinary [`Extractor`] registered for image media types, which a pipeline
//!   may use as its **primary** extractor for a scanned page uploaded as a PNG or a JPEG;
//! - [`OcrRetry`], which takes a [`Prepared`] whose outcome is [`Outcome::NoText`] and re-runs OCR
//!   over exactly the pages that outcome names, under a budget of its own.
//!
//! [`OcrRetry::retry`] passes any other outcome straight through untouched. That is structural
//! rather than polite: it is the reason OCR cannot turn *"this document failed"* into *"this
//! document is empty"*. A [`Outcome::Refused`] never reaches the OCR path at all, and an
//! [`IndexingError`] never becomes one — the `?`s below propagate, so a worker that died reports a
//! dead worker rather than a textless document (`crates/indexing/src/error.rs` makes that the
//! crate's stated property).
//!
//! # The work list is the input, and only the work list is read
//!
//! [`TextlessSource::pages_without_text`] exists so OCR runs over three pages of nine hundred rather
//! than all of them. [`OcrRetry::retry`] asks [`PageImages`] for exactly those page numbers and no
//! others, which is asserted rather than assumed — a retry that quietly widened to every page would
//! be correct and nine hundred times too expensive, and nothing about the output would show it.
//!
//! An empty work list means the source has no pagination an image pipeline could look at (a
//! whitespace-only text file), and the retry returns the original outcome without asking for
//! anything.
//!
//! # What a refusal on one page does to the whole document
//!
//! **Any page refused ⇒ the whole attempt is [`Outcome::Refused`], even if other pages yielded
//! text.** A blank page is not a refusal — a section divider that OCRs to nothing is ordinary, and
//! those are skipped.
//!
//! The cost of that rule is real and worth stating: a nine-hundred-page scan with one page that
//! times out fails as a whole, and stays unsearchable until somebody looks at it. It is taken
//! anyway, because `index_manifests` has one status per *version* and no way to express "pages
//! 4–900 are missing". The alternative — `READY` over an index holding three pages of nine hundred
//! — is D24's failure mode exactly: a document that appears correctly filed and searchable while
//! almost all of its content is absent, with nothing on any surface saying so.
//!
//! # The bounds are `enclave-preview`'s, applied per **page**
//!
//! D24 reuses [`RenderBudget`] rather than inventing a second set, and this module does — with one
//! deliberate difference recorded in [`OcrRetry::new`]: the budget is held by the retry and applied
//! to each page separately, not inherited from the extraction request that produced the work list.
//! OCR is seconds per page against milliseconds for text, so a nine-hundred-page scan under the text
//! extractor's wall clock is a guaranteed [`Refusal::Timeout`] and the criterion could never be met.
//! `lib.rs` named that as the one place a second set of numbers is genuinely warranted; this is that
//! place, and it is a different *value* for the same struct rather than a second struct.
//!
//! [`RenderBudget::max_pages`] bounds the work list itself, which is the only cap that matters for a
//! document nobody is waiting on: a hostile PDF declaring a million blank pages is a million OCR
//! invocations, and each one of those is individually inside its budget.
//!
//! # Hostile image input, in the order `raster.rs` fixes
//!
//! Identical to `crates/preview/src/raster.rs`, because it is the identical problem — a 70-byte PNG
//! declaring itself 65535×65535 asks for a 17 GiB allocation, and a decoder whose only verb is "give
//! me the pixels" performs it before anyone can object:
//!
//! 1. **Sniff.** Magic bytes against a closed allowlist. Not the declared media type — see
//!    [`Extractor::supports`], which is a hint and not a trust boundary.
//! 2. **Inspect the header.** [`ImageReader::into_decoder`] parses the header and nothing else.
//! 3. **Decide.** `total_bytes()` over [`RenderBudget::max_output_bytes`] refuses with no pixel
//!    buffer in existence.
//! 4. **Only then decode**, on the *same decoder object* the header check was made against.
//!    Checking with one parse and decoding with another is a parser differential in miniature.
//!
//! # What the engine is allowed to say
//!
//! Nothing. `ocrs` errors are `anyhow::Error` carrying whatever an inference runtime produced from
//! an image an uploader chose, and this module maps every one of them to a fixed [`Refusal`] code
//! without reading the message. `CLAUDE.md` rule 10: an OCR engine has just consumed a hostile
//! image, and a parser's message copied into a log line or a `failure_reason` column is how a
//! payload travels. The one string this module does surface — the mount path in
//! [`OcrModels::mounted`]'s error — is *operator configuration*, not content, and that distinction
//! is the whole of the rule.
//!
//! # The engine, and the cost that came with it
//!
//! `ocrs` on `rten` (`plans/M3-DISCOVERY.md` Q12): pure Rust, MIT OR Apache-2.0 across its tree, and
//! no `links` key, so nothing here builds or links a C toolchain. The workspace manifest carries the
//! comparison against the Tesseract bindings.
//!
//! It brings `rayon`, which contradicts the note the manifest attaches to `image` — a thread pool
//! nested inside a parser, on a `spawn_blocking` thread, is parallelism nobody is accounting for.
//! Taken anyway, and bounded from outside rather than pretended away: `rten` reads
//! `RTEN_NUM_THREADS`, so a D17 worker sets it beside its process CPU limit. Nothing in this module
//! sets it, because a library that mutates the process environment does so to every other thread in
//! the process without being asked.
//!
//! # Languages
//!
//! **English (Latin script) only** — Q12, and a decision rather than an omission. `ocrs`'s published
//! recognition model is trained on Latin script; a tenant whose documents are in Chinese gets
//! nothing back, which is `docs/14`'s silent-failure shape reintroduced through configuration. What
//! makes it acceptable *today* is that the failure is not silent here: a page that OCRs to nothing
//! is [`Outcome::NoText`], the manifest records `FAILED` with `no_text_extracted`, and that is a
//! surface somebody reads. Adding a script later is a new recognition model and a reindex of the
//! documents it changes — additive, not a migration.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use enclave_core::VersionId;
use enclave_preview::{Refusal, RenderBudget};
use image::{DynamicImage, ImageDecoder as _, ImageFormat, ImageReader, Limits, RgbImage};
use ocrs::{ImageSource, OcrEngine, OcrEngineParams};

use crate::chunk::Chunker;
use crate::error::{IndexingError, Result};
use crate::extract::{ExtractOutcome, ExtractRequest, Extractor, TextlessSource};
use crate::model::{Coordinates, ExtractorVersion, Segment, SegmentKind, TextDocument};
use crate::pipeline::{decide, Outcome, Prepared};

/// Which build this is, in the form [`Extractor::extractor_version`] requires.
///
/// Three components, one more than `raster.rs` needs, because two dependencies decide what comes
/// out: `ocrs` owns detection, layout and decoding, and `rten` owns the kernels that run the models.
/// A patch release of either is exactly the kind of change that alters recognised text while looking
/// as though it could not, and `tests` reads both out of `Cargo.lock` rather than trusting this
/// string.
///
/// # What this string does **not** cover, and cannot
///
/// **The model weights.** They are mounted at run time ([`OcrModels`]), so replacing the files on
/// the volume changes every future extraction's output while this marker stays still — and
/// `docs/07 §3`'s reindex trigger compares this marker. [`ExtractorVersion`] is deliberately
/// `&'static str` so that a version cannot be computed at run time (a marker derived from a file
/// hash differs between two replicas mid-rollout, and the reindex it triggers never converges), so
/// this is not fixable by hashing the weights here.
///
/// The honest statement is therefore: **swapping the mounted models is an operator action that must
/// be accompanied by bumping the `ocr/N` component of this constant and shipping it.** Recorded as a
/// gap rather than papered over; nothing in the type system enforces it today.
const EXTRACTOR: &str = "ocr/1+ocrs-0.12.2+rten-0.24.0";

/// The declared media types this extractor is asked about.
///
/// The same three formats `crates/preview/src/raster.rs` allowlists, and for the same reason: they
/// are the formats the `image` dependency is built with, so this list and the set of parsers an
/// uploader can reach are one set. Asserted against the workspace manifest in `tests` rather than
/// restated, because a feature enabled for some other crate's benefit would otherwise silently widen
/// it.
const SUPPORTED_MEDIA_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp"];

/// The formats this extractor will hand to a decoder.
const SUPPORTED_FORMATS: &[ImageFormat] = &[ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::WebP];

/// What this extractor reports having established about the bytes it read.
///
/// Never echoed from the uploader's claim — the only thing this extractor verified is that the
/// source is one of three raster formats it then recognised text in.
const DECIDED_MEDIA_TYPE: &str = "image/png";

/// The media type [`OcrRetry`] declares when handing a page image to the extractor.
///
/// Ours, not an uploader's: it names what a page rasteriser is contracted to emit
/// (`RenditionProfile::PagePng1x`). It selects which extractor is asked and nothing after that — the
/// extractor sniffs the bytes regardless, so a rasteriser that emitted something else would be
/// refused rather than believed.
const PAGE_IMAGE_MEDIA_TYPE: &str = "image/png";

/// The detection model's file name inside the mounted directory.
const DETECTION_MODEL: &str = "text-detection.rten";

/// The recognition model's file name inside the mounted directory.
const RECOGNITION_MODEL: &str = "text-recognition.rten";

/// The OCR models, loaded from the volume a deployment mounted them on.
///
/// # Mounted, never baked — and the reason is stronger here than for embeddings
///
/// `plans/M3-DISCOVERY.md` Q14 chose *mounted* for the embedding model on image size: `docs/08 §18`
/// covers air-gapped installs, where a multi-gigabyte layer on every image pull is a real cost.
/// That argument applies here too and is the weaker of the two.
///
/// The decisive one is licensing. `ocrs` ships no weights; the published models are
/// **CC-BY-SA-4.0** (stated on the `huggingface.co/robertknight/ocrs` model card), which is a
/// copyleft data licence.
/// `deny.toml`'s allowlist is permissive-only, and says why: *"Enclave ships as software an
/// enterprise self-hosts, so a copyleft dependency anywhere in the graph is a distribution
/// obligation on every one of those customers."* `cargo deny` would never see this one — the crate
/// is MIT OR Apache-2.0 and the weights are a separate download — so baking them into the image
/// would put a share-alike obligation inside a product image past a gate that structurally cannot
/// look at it.
///
/// Mounting means **we redistribute nothing**: the operator obtains the weights and stages them, and
/// the obligation stays where the licence put it. Whether we may ever ship them ourselves is a legal
/// question, not an engineering one, and it must be answered before any vendoring — which is why
/// there is no constructor here that takes bytes. `include_bytes!` is not something a caller can
/// express, so "bake the models in" is not a shortcut somebody reaches for under deadline.
///
/// The cost is a startup dependency, and it is not free: a process that starts with no models must
/// refuse to OCR rather than OCR nothing. [`mounted`](Self::mounted) fails loudly, and a deployment
/// that cannot build one simply has no [`OcrExtractor`] — which is
/// [`NoExtractor`](crate::NoExtractor) behaviour, the deny-by-default this crate already relies on.
pub struct OcrModels {
    engine: OcrEngine,
}

impl fmt::Debug for OcrModels {
    /// Names the type and nothing else.
    ///
    /// `OcrEngine` is not `Debug`, and would be the wrong thing to print if it were: a debug line
    /// carrying model internals is megabytes of weights in a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OcrModels").finish_non_exhaustive()
    }
}

impl OcrModels {
    /// Loads the detection and recognition models from a mounted directory.
    ///
    /// The directory holds `text-detection.rten` and `text-recognition.rten`, staged by the
    /// deployment. See the type documentation for why they are not in the image, and
    /// `tests/ocr.rs` for **which** two files those are — the released weights from `ocrs`'s own
    /// `download-models.sh`, not the similarly-named training checkpoints on the model card, which
    /// load and run and produce noise. That distinction cost a test run to find and is written down
    /// so it does not cost a deployment.
    ///
    /// # Errors
    ///
    /// [`IndexingError::Worker`] when either file is missing or does not load. This is *ours* and
    /// not a refusal: no document is involved, and a deployment whose model volume failed to attach
    /// has an outage rather than a corpus of textless files.
    ///
    /// The message names the path and **not** the runtime's error. The path is operator
    /// configuration, which is safe to surface and miserable to diagnose without; the runtime's
    /// message is derived from file contents, which is the class `CLAUDE.md` rule 10 keeps out of
    /// logs.
    pub fn mounted(directory: &Path) -> Result<Self> {
        let detection = load(&directory.join(DETECTION_MODEL))?;
        let recognition = load(&directory.join(RECOGNITION_MODEL))?;

        let engine = OcrEngine::new(OcrEngineParams {
            detection_model: Some(detection),
            recognition_model: Some(recognition),
            ..OcrEngineParams::default()
        })
        .map_err(|_| {
            IndexingError::Worker(anyhow::anyhow!(
                "the OCR models loaded but the engine could not be built from them"
            ))
        })?;

        Ok(Self { engine })
    }
}

/// Loads one `.rten` model file, reporting the path and never the runtime's message.
fn load(path: &PathBuf) -> Result<rten::Model> {
    rten::Model::load_file(path).map_err(|_| {
        IndexingError::Worker(anyhow::anyhow!(
            "the OCR model at {} could not be loaded",
            path.display()
        ))
    })
}

/// Recognises text in raster images, in process, on a blocking thread.
///
/// Holds the models and nothing else — no configuration, no client, no handle to anything. A field
/// could hold a store, and the no-egress property of [`crate::extract`] is worth more than the
/// flexibility: this is the stage that reads the whole of a document's content.
///
/// # Why every byte of the work runs on `spawn_blocking`
///
/// [`BoundedExtractor`](crate::BoundedExtractor)'s wall clock is `tokio::time::timeout`, which stops
/// polling a future — it cannot interrupt a thread already inside synchronous work, and a decode
/// followed by two model inferences is exactly that. On the runtime's poll thread a hostile image
/// stalls the executor and the budget expires with nobody able to act on it. It is not the process
/// isolation D17 asks for, and this module does not pretend otherwise.
#[derive(Debug, Clone)]
pub struct OcrExtractor {
    models: Arc<OcrModels>,
}

impl OcrExtractor {
    /// Builds an extractor over loaded models.
    ///
    /// [`Arc`] because the models are tens of megabytes and one worker runs many extractions
    /// concurrently, and because `spawn_blocking` needs an owned `'static` handle.
    #[must_use]
    pub const fn new(models: Arc<OcrModels>) -> Self {
        Self { models }
    }
}

#[async_trait]
impl Extractor for OcrExtractor {
    fn extractor_version(&self) -> ExtractorVersion {
        ExtractorVersion::new(EXTRACTOR)
    }

    fn supports(&self, declared_media_type: &str) -> bool {
        let essence = declared_media_type.split(';').next().unwrap_or_default().trim();
        SUPPORTED_MEDIA_TYPES.iter().any(|claimed| essence.eq_ignore_ascii_case(claimed))
    }

    async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome> {
        // Destructured rather than read field by field, so a field added to `ExtractRequest` later
        // — an identity, a store handle — fails this build instead of being quietly ignored by it.
        let ExtractRequest { declared_media_type: _, source, budget } = request;
        let models = Arc::clone(&self.models);

        match tokio::task::spawn_blocking(move || recognize(&models.engine, &source, budget)).await
        {
            Ok(outcome) => Ok(outcome),
            // A parser that panics has made a statement about the document: the same bytes panic the
            // same way every time, so this is a verdict and recording it is correct. Reporting it as
            // ours would invite the retry, and a file that reliably kills a worker thread is a
            // denial-of-service primitive the moment a scheduler is willing to run it again.
            Err(join) if join.is_panic() => Ok(ExtractOutcome::Refused(Refusal::SourceUnreadable)),
            // Cancellation is not about the document. The runtime is shutting down or the task was
            // aborted, and answering "this page has no text" would record an outage as an absence.
            Err(join) => Err(IndexingError::Worker(anyhow::Error::new(join))),
        }
    }
}

/// The whole synchronous pipeline, in the order the module documentation fixes.
///
/// Returns an outcome rather than a `Result` because nothing in it can fail on our side: the models
/// are already loaded, and everything the source is responsible for is a [`Refusal`].
fn recognize(engine: &OcrEngine, source: &[u8], budget: RenderBudget) -> ExtractOutcome {
    let image = match decode(source, budget) {
        Decoded::Page(image) => image,
        Decoded::Refused(refusal) => return ExtractOutcome::Refused(refusal),
    };

    let Ok(input) = ImageSource::from_bytes(image.as_raw(), image.dimensions())
        .map_err(drop)
        .and_then(|source| engine.prepare_input(source).map_err(drop))
    else {
        // The engine's own message is deliberately dropped rather than logged. See the module
        // documentation: it is derived from an image an uploader chose.
        return ExtractOutcome::Refused(Refusal::SourceUnreadable);
    };

    let Ok(text) = engine.get_text(&input) else {
        return ExtractOutcome::Refused(Refusal::SourceUnreadable);
    };

    if text.trim().is_empty() {
        // The scanned-but-blank page, and the honest answer for a page whose script this model was
        // not trained on. `BoundedExtractor` would reach the same conclusion from outside, but an
        // extractor that is only correct inside its wrapper is one that will be used unwrapped by
        // somebody who did not read this comment.
        return ExtractOutcome::NoText(TextlessSource {
            media_type: DECIDED_MEDIA_TYPE.to_owned(),
            // A single image is not paginated, so there is no page an image pipeline could be
            // pointed at that it has not already looked at.
            pages_without_text: Vec::new(),
        });
    }

    let segment = Segment {
        // `Document`, not `Paragraph`: the vocabulary's own gloss is "the whole source, for formats
        // with no interior structure to speak of", and an image is exactly that. OCR recovers a
        // reading order, not a paragraph structure, and claiming one would put a boundary in the
        // index that nothing in the source justifies.
        kind: SegmentKind::Document,
        text,
        // Nothing synthesised. A standalone image has no page number, and a citation that deep-links
        // to a page the format does not have is believed by whoever reads it.
        coordinates: Coordinates::none(),
    };

    // Belt and braces, and honestly labelled as such: no realistic page reaches it. The same
    // `max_output_bytes` already bounded the *decoded image*, and a page's pixels outweigh its words
    // by three or four orders of magnitude — an A4 scan is megabytes of buffer and kilobytes of text.
    // So this is unreachable in practice and is kept for the reason `text.rs` gives: an extractor
    // that is only correct inside `BoundedExtractor` is one somebody will use unwrapped.
    if segment.accounted_bytes() > budget.max_output_bytes {
        return ExtractOutcome::Refused(Refusal::OutputTooLarge);
    }

    ExtractOutcome::Extracted(TextDocument {
        segments: vec![segment],
        media_type: DECIDED_MEDIA_TYPE.to_owned(),
        page_count: None,
        extractor_version: ExtractorVersion::new(EXTRACTOR),
    })
}

/// A decoded page, or the verdict on why there is not one.
enum Decoded {
    /// Pixels, in the RGB form `ocrs` reads.
    Page(RgbImage),
    /// The source is not something this extractor will decode.
    Refused(Refusal),
}

/// Sniff → header → decide → decode, in that order and on one decoder object.
///
/// The order is the guarantee, not the individual checks — see the module documentation. Lifted from
/// `crates/preview/src/raster.rs` rather than reinvented, because it is the same decoder eating the
/// same class of input.
fn decode(source: &[u8], budget: RenderBudget) -> Decoded {
    // A second layer, enforced *inside* the decode where this function cannot reach. It is not the
    // guarantee, and for PNG it is in fact the layer that fires first — `image` validates the
    // declared dimensions against `max_alloc` while parsing the header, so a PNG bomb never reaches
    // the `total_bytes()` check below. That is a happy accident of one decoder and not something to
    // rely on: WebP carries its dimensions in a chunk rather than a fixed header, and a bound that
    // only holds where we happened to look is one format away from not holding.
    decode_bounded(source, budget, Some(budget.max_output_bytes))
}

/// [`decode`], with the decoder's own allocation limit made explicit.
///
/// `decoder_max_alloc` of `None` models a decoder that enforces nothing at header time — which is
/// what the second layer being absent looks like, and the only way to see this function's *own*
/// size check answer for a format whose decoder shadows it. `tests` uses it for exactly that; there
/// is no other caller, and the shadowing is why a test that simply fed a PNG bomb to [`decode`]
/// would prove `image`'s limit rather than ours.
fn decode_bounded(source: &[u8], budget: RenderBudget, decoder_max_alloc: Option<u64>) -> Decoded {
    let Some(format) = sniff(source) else {
        return Decoded::Refused(Refusal::UnsupportedFormat);
    };

    let mut limits = Limits::no_limits();
    limits.max_alloc = decoder_max_alloc;

    let mut reader = ImageReader::with_format(std::io::Cursor::new(source), format);
    reader.limits(limits);

    // Header only. A failure here is a source that carries the right magic bytes and then does not
    // parse — truncated, or a signature bolted onto something else.
    let Ok(decoder) = reader.into_decoder() else {
        return Decoded::Refused(Refusal::SourceUnreadable);
    };

    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 {
        // Zero-extent images are legal in some containers and useless in all of them, and
        // `ImageSource::from_bytes` rejects them one layer further in — where the rejection would be
        // an engine error rather than a verdict about the source.
        return Decoded::Refused(Refusal::SourceUnreadable);
    }

    // The bomb check, and the last statement before any pixel buffer could exist. `total_bytes()`
    // comes from the decoder rather than from arithmetic of ours that could disagree with it about
    // bit depth or channel count.
    if decoder.total_bytes() > budget.max_output_bytes {
        return Decoded::Refused(Refusal::OutputTooLarge);
    }

    // The same decoder object the header check was made against. Checking with one parse and
    // decoding with another is a parser differential in miniature, where the second reading is the
    // one that allocates.
    let Ok(image) = DynamicImage::from_decoder(decoder) else {
        return Decoded::Refused(Refusal::SourceUnreadable);
    };

    Decoded::Page(image.into_rgb8())
}

/// Decides the format from content, or refuses.
///
/// [`image::guess_format`] recognises signatures for formats this build cannot decode, which is what
/// makes the allowlist meaningful: a GIF is identified as a GIF and refused as one, rather than
/// reaching a decoder that would fail on it for the incidental reason that the feature is off.
fn sniff(source: &[u8]) -> Option<ImageFormat> {
    let format = image::guess_format(source).ok()?;
    SUPPORTED_FORMATS.contains(&format).then_some(format)
}

/// Supplies the raster image of one page of a source, for OCR to read.
///
/// The port that does not exist anywhere else in this codebase, and naming it is the point: OCR over
/// a scanned **PDF** needs each page rendered to pixels, and nothing in this repository renders a PDF
/// page. `crates/preview/src/raster.rs` refuses `PdfSanitized` and says why — a page tree is a
/// parser rather than a decoder and belongs in the D17 worker.
///
/// So the exit criterion *"a scanned, text-free PDF is searchable by its content"* needs an
/// implementation of this trait that this change does not provide. [`NoPageImages`] is what a
/// deployment has today, and it refuses honestly rather than making the gap invisible.
#[async_trait]
pub trait PageImages: Send + Sync {
    /// The image bytes of a one-based page, or `None` if this source cannot produce that page.
    ///
    /// `None` is *"there is no image for this page"* and is not a failure — a page outside the
    /// source's range, or a source nothing can rasterise. It leaves the page unrecognised, which
    /// leaves the document textless, which is a `FAILED` manifest somebody reads.
    ///
    /// # Errors
    ///
    /// Only for failures that are *ours* — the rasteriser died, the pipe broke. An error here must
    /// never be reported as a document without text; see `crates/indexing/src/error.rs`.
    async fn page_image(&self, page: u32) -> Result<Option<Vec<u8>>>;
}

/// The page source a deployment has when nothing can rasterise pages.
///
/// The deny-by-default stub, in the shape [`NoExtractor`](crate::NoExtractor) and
/// `crates/preview::NoRenderer` already use. It yields no image for any page, so an OCR retry over a
/// scanned PDF recovers nothing and the manifest keeps saying `FAILED` / `no_text_extracted`.
///
/// That is the correct behaviour and not a placeholder for it: the tempting shortcut — hand the OCR
/// engine the PDF's own bytes and let it try — feeds an image decoder a file that is not an image,
/// which is the dispatch-on-the-claim mistake `crates/preview/src/raster.rs` exists to avoid.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPageImages;

#[async_trait]
impl PageImages for NoPageImages {
    async fn page_image(&self, _page: u32) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Re-runs OCR over the pages a first extraction reported textless.
///
/// See the module documentation for why this is a stage rather than a fallback, and for the rule
/// about a refusal on one page.
#[derive(Debug)]
pub struct OcrRetry<E, P> {
    extractor: E,
    pages: P,
    chunker: Chunker,
    budget: RenderBudget,
}

impl<E: Extractor, P: PageImages> OcrRetry<E, P> {
    /// Builds a retry stage over an OCR extractor and a source of page images.
    ///
    /// `budget` is **per page**, and is held here rather than taken from the request that produced
    /// the work list. That is the one place `lib.rs` said a second set of numbers might genuinely be
    /// warranted: OCR is seconds per page against milliseconds for text, so a nine-hundred-page scan
    /// run under the text extractor's wall clock is a guaranteed [`Refusal::Timeout`] and the exit
    /// criterion could never be met. It is a different value for the same [`RenderBudget`] struct
    /// rather than a second struct, so D24's "one place to read the bounds from" still holds.
    ///
    /// Wrap `extractor` in [`BoundedExtractor`](crate::BoundedExtractor) before passing it here.
    /// This stage applies [`RenderBudget::max_pages`] to the work list; the wall clock and the
    /// output cap are the wrapper's job, for the reason `crates/preview/src/budget.rs` gives — the
    /// component parsing hostile input is the one least able to promise it will stop.
    pub const fn new(extractor: E, pages: P, chunker: Chunker, budget: RenderBudget) -> Self {
        Self { extractor, pages, chunker, budget }
    }

    /// Re-runs OCR if — and only if — the prepared outcome was [`Outcome::NoText`].
    ///
    /// Anything else is returned untouched. That is the property that keeps OCR from being a silent
    /// fallback: a [`Outcome::Refused`] stays a refusal, a `Ready` stays ready, and there is no path
    /// by which running OCR converts *"this document failed"* into *"this document is empty"*.
    ///
    /// # Errors
    ///
    /// Propagates whatever [`PageImages`] or the extractor returns as an error, unchanged and
    /// un-downgraded. A dead rasteriser is an outage, and recording it as a textless document would
    /// leave every file it touched invisible to search long after the outage ended.
    pub async fn retry(&self, version: VersionId, prepared: Prepared) -> Result<Prepared> {
        let textless = match prepared.outcome {
            Outcome::NoText(textless) => textless,
            outcome => return Ok(Prepared { outcome, chunks: prepared.chunks }),
        };

        if textless.pages_without_text.is_empty() {
            // No pagination for an image pipeline to work over. Returned without asking anything of
            // `PageImages`, so a source with nothing to OCR costs no rasteriser call at all.
            return Ok(Prepared { outcome: Outcome::NoText(textless), chunks: Vec::new() });
        }

        if textless.pages_without_text.len() as u64 > u64::from(self.budget.max_pages) {
            // The only cap that bounds the *document* rather than a page. Each of a million pages is
            // individually inside its budget, and a million of them is not.
            return Ok(Prepared {
                outcome: Outcome::Refused(Refusal::TooManyPages),
                chunks: Vec::new(),
            });
        }

        let mut segments: Vec<Segment> = Vec::new();
        let mut refused: Option<Refusal> = None;

        // Exactly the pages the work list names, in the order it names them. Widening this to every
        // page of the document would be correct and nine hundred times more expensive, and nothing
        // about the output would show it — which is why `tests` asserts what was asked for.
        for &page in &textless.pages_without_text {
            let Some(image) = self.pages.page_image(page).await? else {
                continue;
            };

            let outcome = self
                .extractor
                .extract(ExtractRequest {
                    declared_media_type: PAGE_IMAGE_MEDIA_TYPE.to_owned(),
                    source: image,
                    budget: self.budget,
                })
                .await?;

            match outcome {
                ExtractOutcome::Extracted(document) => {
                    for mut segment in document.segments {
                        // Stamped here rather than inside the extractor, because the extractor was
                        // handed an image and does not know which page of what it came from. This
                        // stage asked for the page, so this stage is what can say so — and a page
                        // number is the difference between a citation a reader can navigate to and
                        // one they cannot.
                        segment.coordinates.page_number = Some(page);
                        segments.push(segment);
                    }
                }
                // A blank page. Ordinary in a scanned document — a section divider, the back of a
                // sheet — and not a failure.
                ExtractOutcome::NoText(_) => {}
                // First refusal wins, because it is the one an operator will look at first and the
                // later ones are usually the same cause repeated.
                ExtractOutcome::Refused(refusal) => {
                    refused.get_or_insert(refusal);
                }
            }
        }

        if let Some(refusal) = refused {
            // **Before the text check, deliberately.** See the module documentation: a document that
            // recovered three pages of nine hundred and refused the rest is not `READY`, because the
            // manifest cannot say which parts are missing and a partial index that reads complete is
            // the failure D24 is about.
            return Ok(Prepared { outcome: Outcome::Refused(refusal), chunks: Vec::new() });
        }

        if segments.is_empty() {
            // OCR did not rescue it. The original work list is returned rather than a freshly
            // derived one, so a later attempt — better models, a rasteriser that now exists — still
            // knows which pages to look at.
            return Ok(Prepared { outcome: Outcome::NoText(textless), chunks: Vec::new() });
        }

        let document = TextDocument {
            segments,
            // The source's decided type, not the page images'. What was indexed is a scanned PDF;
            // that it was read through PNGs is this stage's business and not the manifest's.
            media_type: textless.media_type.clone(),
            // Not the work list's length. The work list holds the pages that yielded *no* text, so
            // it is not the document's page count, and a wrong one here would be applied to
            // `max_pages` by anything that trusted it.
            page_count: None,
            extractor_version: self.extractor.extractor_version(),
        };

        // The same `decide` the ordinary pipeline uses, so the `NonZeroU32` gate that makes
        // `READY`-with-no-chunks unconstructible is one function rather than two that agree.
        let decided = decide(version, &self.chunker, &document);
        Ok(match decided.outcome {
            // The chunker dropped everything it was given. The original work list is preserved for
            // the reason above; `decide` would have derived a new one from a document that has no
            // blank segments to derive it from.
            Outcome::NoText(_) => {
                Prepared { outcome: Outcome::NoText(textless), chunks: Vec::new() }
            }
            _ => decided,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::chunk::{ChunkBudget, ChunkerVersion};
    use crate::pipeline::{ManifestStatus, Reason};

    /// A one-pixel PNG, assembled rather than pasted, so the test says what it is made of.
    fn tiny_png() -> Vec<u8> {
        let mut bytes = Vec::new();
        let image = RgbImage::from_pixel(1, 1, image::Rgb([255, 255, 255]));
        DynamicImage::ImageRgb8(image)
            .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("encoding a 1×1 PNG");
        bytes
    }

    fn chunker() -> Chunker {
        Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default())
    }

    fn textless(pages: Vec<u32>) -> Prepared {
        Prepared {
            outcome: Outcome::NoText(TextlessSource {
                media_type: "application/pdf".to_owned(),
                pages_without_text: pages,
            }),
            chunks: Vec::new(),
        }
    }

    /// Records which pages were asked for, and answers each with the same image.
    #[derive(Debug, Default)]
    struct RecordingPages {
        asked: Mutex<Vec<u32>>,
        /// Pages this source cannot produce an image for.
        missing: Vec<u32>,
        /// Fails instead of answering — a dead rasteriser.
        broken: bool,
    }

    #[async_trait]
    impl PageImages for RecordingPages {
        async fn page_image(&self, page: u32) -> Result<Option<Vec<u8>>> {
            self.asked.lock().expect("no panics in this test").push(page);
            if self.broken {
                return Err(IndexingError::Worker(anyhow::anyhow!("the rasteriser died")));
            }
            if self.missing.contains(&page) {
                return Ok(None);
            }
            Ok(Some(tiny_png()))
        }
    }

    /// What the fake OCR extractor answers for each page image it is handed, in order.
    #[derive(Debug)]
    enum Answer {
        /// Recognised this text.
        Text(&'static str),
        /// A blank page.
        Blank,
        /// A verdict about this page.
        Refused(Refusal),
        /// The worker died.
        Failed,
    }

    #[derive(Debug)]
    struct FakeOcr {
        answers: Mutex<std::collections::VecDeque<Answer>>,
    }

    impl FakeOcr {
        fn new(answers: Vec<Answer>) -> Self {
            Self { answers: Mutex::new(answers.into_iter().collect()) }
        }
    }

    #[async_trait]
    impl Extractor for FakeOcr {
        fn extractor_version(&self) -> ExtractorVersion {
            ExtractorVersion::new("fake-ocr/1")
        }

        fn supports(&self, _declared_media_type: &str) -> bool {
            true
        }

        async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
            let answer = self
                .answers
                .lock()
                .expect("no panics in this test")
                .pop_front()
                .unwrap_or(Answer::Blank);

            Ok(match answer {
                Answer::Text(text) => ExtractOutcome::Extracted(TextDocument {
                    segments: vec![Segment {
                        kind: SegmentKind::Document,
                        text: text.to_owned(),
                        coordinates: Coordinates::none(),
                    }],
                    media_type: DECIDED_MEDIA_TYPE.to_owned(),
                    page_count: None,
                    extractor_version: ExtractorVersion::new("fake-ocr/1"),
                }),
                Answer::Blank => ExtractOutcome::NoText(TextlessSource {
                    media_type: DECIDED_MEDIA_TYPE.to_owned(),
                    pages_without_text: Vec::new(),
                }),
                Answer::Refused(refusal) => ExtractOutcome::Refused(refusal),
                Answer::Failed => {
                    return Err(IndexingError::Worker(anyhow::anyhow!("the OCR worker died")))
                }
            })
        }
    }

    fn retry_over(
        answers: Vec<Answer>,
        pages: RecordingPages,
    ) -> OcrRetry<FakeOcr, RecordingPages> {
        OcrRetry::new(FakeOcr::new(answers), pages, chunker(), RenderBudget::DEFAULT)
    }

    // ---------------------------------------------------------------------------------------
    // The decode order, provable without model weights.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_signature_outside_the_allowlist_never_reaches_a_decoder() {
        assert_eq!(sniff(b"GIF89a\x01\x00\x01\x00\x00\x00\x00"), None);
        assert_eq!(sniff(b"%PDF-1.7\n"), None);
        assert_eq!(sniff(b""), None);
        assert_eq!(sniff(&tiny_png()), Some(ImageFormat::Png));
    }

    /// CRC-32/ISO-HDLC, which is the checksum every PNG chunk carries.
    ///
    /// Written out because the bomb below has to be a **well-formed** PNG header. The first version
    /// of that test put four zero bytes here and passed with the bomb check deleted: a bad checksum
    /// makes the decoder refuse the file as unreadable, and the test's assertion accepted that as
    /// proof. It proved only that malformed input is refused, which nothing in this module needed a
    /// test for.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    /// Appends one well-formed PNG chunk: length, type, payload, checksum.
    fn chunk_onto(png: &mut Vec<u8>, kind: &[u8; 4], payload: &[u8]) {
        let mut typed = Vec::from(*kind);
        typed.extend_from_slice(payload);

        png.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        png.extend_from_slice(&typed);
        png.extend_from_slice(&crc32(&typed).to_be_bytes());
    }

    /// A structurally valid PNG declaring `width × height` and holding no pixels worth the name.
    ///
    /// Under a hundred bytes, whatever it claims. That asymmetry is the decode bomb: nothing about
    /// the file is large, and the allocation it asks for is not. The IDAT is an empty zlib stream
    /// and the IEND closes the file, so the container parses and only the *pixels* are missing —
    /// which is what puts the size check, rather than a truncation error, in the answering position.
    fn png_declaring(width: u32, height: u32) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        // 8-bit, colour type 6 (RGBA), deflate, adaptive filtering, no interlace.
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

        let mut png = Vec::from(*b"\x89PNG\r\n\x1a\n");
        chunk_onto(&mut png, b"IHDR", &ihdr);
        // `78 9C` is the zlib header the encoder emits; `03 00` is an empty final deflate block and
        // `00 00 00 01` its Adler-32.
        chunk_onto(&mut png, b"IDAT", &[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        chunk_onto(&mut png, b"IEND", &[]);
        png
    }

    #[test]
    fn a_well_formed_header_is_read_without_the_pixels_behind_it() {
        // The premise the bomb test rests on, asserted separately so it cannot rot silently. If
        // `into_decoder` ever needed an IDAT, the bomb test would start passing for the wrong reason
        // — the file would be refused as truncated before the size check was ever reached, which is
        // the exact failure the first version of it had.
        let header = png_declaring(20_000, 20_000);
        assert!(header.len() < 100, "the bomb must be small; it is {} bytes", header.len());

        let mut reader = ImageReader::with_format(std::io::Cursor::new(&header), ImageFormat::Png);
        reader.limits(Limits::no_limits());
        let decoder = reader.into_decoder().expect("a valid IHDR parses without any IDAT");
        assert_eq!(decoder.dimensions(), (20_000, 20_000));
        assert!(decoder.total_bytes() > 1_000_000_000, "20000×20000 RGBA is 1.6 GB");
    }

    #[test]
    fn a_decode_bomb_never_produces_a_pixel_buffer() {
        // The property, over both layers: whatever refuses it, nothing allocates 1.6 GB inside a
        // 1 kB budget. This test alone does not say *which* layer answered, which is why the next
        // one exists.
        let budget = RenderBudget { max_output_bytes: 1024, ..RenderBudget::DEFAULT };

        assert!(matches!(decode(&png_declaring(20_000, 20_000), budget), Decoded::Refused(_)));
    }

    #[test]
    fn the_header_size_check_refuses_a_bomb_the_decoder_itself_admitted() {
        // **This is the test of *our* check**, and it took two attempts to write honestly.
        //
        // The first version fed a PNG bomb to `decode` and asserted a refusal. It passed with the
        // `total_bytes()` check deleted — twice over: a malformed CRC made the file unreadable, and
        // once that was fixed `image`'s own `max_alloc` refused the header before our check was
        // reached. Neither run proved anything about this module.
        //
        // So the decoder's limit is lifted here, which is what a format that carries its dimensions
        // in a chunk rather than a fixed header does to us for real. The refusal is asserted
        // exactly: `SourceUnreadable` would mean the file failed to parse and the size was never
        // consulted.
        let budget = RenderBudget { max_output_bytes: 1024, ..RenderBudget::DEFAULT };

        match decode_bounded(&png_declaring(20_000, 20_000), budget, None) {
            Decoded::Refused(refusal) => assert_eq!(
                refusal,
                Refusal::OutputTooLarge,
                "a 1.6 GB decode inside a 1 kB budget was refused for the wrong reason"
            ),
            Decoded::Page(_) => panic!("a 1.6 GB allocation was performed inside a 1 kB budget"),
        }
    }

    #[test]
    fn a_source_within_the_budget_decodes() {
        // The other half of the bomb test: without this, a `decode` that refused everything would
        // pass the assertion above and prove nothing.
        match decode(&tiny_png(), RenderBudget::DEFAULT) {
            Decoded::Page(image) => assert_eq!(image.dimensions(), (1, 1)),
            Decoded::Refused(refusal) => panic!("a 1×1 PNG was refused as {refusal:?}"),
        }
    }

    #[test]
    fn the_media_types_claimed_are_the_formats_the_decoder_is_built_with() {
        // The manifest is read rather than restated. A test carrying its own copy of the list passes
        // when both copies are wrong together, and the failure that matters is a format enabled for
        // some other crate's benefit — every enabled format is a parser an uploader can reach.
        let manifest = include_str!("../../../Cargo.toml");
        let line = manifest
            .lines()
            .find(|line| line.starts_with("image "))
            .expect("the `image` dependency line");
        let features = line
            .split_once("features = [")
            .expect("the feature list")
            .1
            .split_once(']')
            .expect("the feature list's closing bracket")
            .0;

        for (media_type, feature) in
            [("image/png", "png"), ("image/jpeg", "jpeg"), ("image/webp", "webp")]
        {
            assert_eq!(
                SUPPORTED_MEDIA_TYPES.contains(&media_type),
                features.contains(&format!("\"{feature}\"")),
                "`{feature}` is enabled in one place and not the other"
            );
        }
        assert_eq!(
            features.matches('"').count() / 2,
            SUPPORTED_MEDIA_TYPES.len(),
            "a format is compiled in that this extractor does not claim, so it is a parser \
             reachable by upload that nobody decided to OCR"
        );
    }

    #[test]
    fn the_extractor_version_names_the_engine_the_lockfile_resolved() {
        // A patch release of either dependency changes recognised text while looking as though it
        // could not, and `docs/07 §3` compares this string to decide what needs reindexing.
        let lock = include_str!("../../../Cargo.lock");
        for crate_name in ["ocrs", "rten"] {
            let resolved = lock
                .split_once(&format!("\nname = \"{crate_name}\"\nversion = \""))
                .expect("the crate in the lockfile")
                .1
                .split_once('"')
                .expect("the version's closing quote")
                .0;
            assert!(
                EXTRACTOR.contains(&format!("{crate_name}-{resolved}")),
                "`{EXTRACTOR}` does not name {crate_name}-{resolved}: bump it, or the index keeps \
                 text produced by the build this one replaced"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // The retry: what OCR may and may not turn one outcome into.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn only_a_textless_outcome_is_retried() {
        // The property that keeps OCR from being a silent fallback. A refusal is a verdict about the
        // document; running OCR over it and reporting "no text" would turn a visible failure into an
        // invisible absence, which is the inversion D24 is about.
        let retry = retry_over(vec![Answer::Text("recovered")], RecordingPages::default());

        for outcome in [Outcome::Refused(Refusal::Timeout), Outcome::Unsupported] {
            let before = format!("{outcome:?}");
            let after = retry
                .retry(VersionId::new_v7(), Prepared { outcome, chunks: Vec::new() })
                .await
                .expect("the fake never errors");
            assert_eq!(format!("{:?}", after.outcome), before, "OCR rewrote a verdict");
        }

        assert!(
            retry.pages.asked.lock().expect("no panics").is_empty(),
            "a page image was fetched for an outcome OCR must not touch"
        );
    }

    #[tokio::test]
    async fn only_the_pages_the_work_list_names_are_rasterised() {
        // The work list is the difference between OCR running over three pages and over nine
        // hundred, and a retry that quietly widened would be correct and invisible.
        let retry = retry_over(
            vec![Answer::Text("page seven"), Answer::Text("page two hundred")],
            RecordingPages::default(),
        );

        retry.retry(VersionId::new_v7(), textless(vec![7, 200])).await.expect("no error");

        assert_eq!(*retry.pages.asked.lock().expect("no panics"), vec![7, 200]);
    }

    #[tokio::test]
    async fn recovered_text_becomes_ready_and_carries_the_page_it_came_from() {
        let retry =
            retry_over(vec![Answer::Text("the quarterly report")], RecordingPages::default());

        let prepared = retry.retry(VersionId::new_v7(), textless(vec![4])).await.expect("no error");

        assert_eq!(prepared.outcome.status(), ManifestStatus::Ready);
        assert_eq!(prepared.outcome.reason(), None);
        assert_eq!(prepared.outcome.chunk_count(), 1);
        assert_eq!(
            prepared.chunks.first().and_then(|chunk| chunk.coordinates.page_number),
            Some(4),
            "a chunk that cannot name its page is a citation nobody can navigate to"
        );
    }

    #[tokio::test]
    async fn a_page_that_refused_is_never_reported_as_a_document_without_text() {
        // The rule the module documentation argues for, and the one that is tempting to invert:
        // three good pages and one refusal is *not* READY, and it is not "no text" either. It is a
        // refusal, which is the only answer that puts the document on a surface somebody reads.
        let retry = retry_over(
            vec![
                Answer::Text("page one"),
                Answer::Refused(Refusal::Timeout),
                Answer::Text("three"),
            ],
            RecordingPages::default(),
        );

        let prepared =
            retry.retry(VersionId::new_v7(), textless(vec![1, 2, 3])).await.expect("no error");

        assert_eq!(prepared.outcome, Outcome::Refused(Refusal::Timeout));
        assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
        assert_eq!(prepared.outcome.reason(), Some(Reason::Refused));
        assert!(prepared.chunks.is_empty(), "a refused attempt must not leave chunks behind");
    }

    #[tokio::test]
    async fn ocr_that_recovers_nothing_leaves_the_work_list_intact() {
        // A blank page is ordinary; what must not happen is the work list being lost, because the
        // next attempt — better models, or a rasteriser that now exists — needs to know which pages
        // to look at.
        let retry = retry_over(vec![Answer::Blank, Answer::Blank], RecordingPages::default());

        let prepared =
            retry.retry(VersionId::new_v7(), textless(vec![3, 9])).await.expect("no error");

        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
        match prepared.outcome {
            Outcome::NoText(source) => {
                assert_eq!(source.pages_without_text, vec![3, 9]);
                assert_eq!(source.media_type, "application/pdf");
            }
            other => panic!("expected NoText, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_source_with_no_pages_costs_no_rasteriser_call() {
        // A whitespace-only text file is textless and there is nothing an image pipeline could
        // rescue from it.
        let retry = retry_over(vec![Answer::Text("never asked for")], RecordingPages::default());

        let prepared = retry.retry(VersionId::new_v7(), textless(vec![])).await.expect("no error");

        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
        assert!(retry.pages.asked.lock().expect("no panics").is_empty());
    }

    #[tokio::test]
    async fn a_work_list_longer_than_the_page_cap_is_refused_before_any_page_is_read() {
        // Each of a million pages is individually inside its budget; a million of them is not, and
        // the wall clock cannot see that because it is applied per page.
        let retry = retry_over(Vec::new(), RecordingPages::default());
        let pages = (1..=RenderBudget::DEFAULT.max_pages + 1).collect();

        let prepared = retry.retry(VersionId::new_v7(), textless(pages)).await.expect("no error");

        assert_eq!(prepared.outcome, Outcome::Refused(Refusal::TooManyPages));
        assert!(
            retry.pages.asked.lock().expect("no panics").is_empty(),
            "a page was rasterised before the cap that exists to prevent it was checked"
        );
    }

    #[tokio::test]
    async fn a_page_with_no_image_is_skipped_rather_than_failing_the_document() {
        // `NoPageImages`'s case, page by page: a source that cannot be rasterised recovers nothing
        // and stays FAILED, rather than being refused as though the document were malformed.
        let retry = retry_over(
            vec![Answer::Text("page five")],
            RecordingPages { missing: vec![2], ..RecordingPages::default() },
        );

        let prepared =
            retry.retry(VersionId::new_v7(), textless(vec![2, 5])).await.expect("no error");

        assert_eq!(prepared.outcome.status(), ManifestStatus::Ready);
        assert_eq!(
            prepared.chunks.first().and_then(|chunk| chunk.coordinates.page_number),
            Some(5),
            "the recovered text was attributed to the page that had no image"
        );
    }

    #[tokio::test]
    async fn no_page_images_recovers_nothing_and_says_so() {
        let retry = OcrRetry::new(
            FakeOcr::new(vec![Answer::Text("unreachable")]),
            NoPageImages,
            chunker(),
            RenderBudget::DEFAULT,
        );

        let prepared =
            retry.retry(VersionId::new_v7(), textless(vec![1, 2, 3])).await.expect("no error");

        assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
    }

    #[tokio::test]
    async fn a_dead_rasteriser_is_an_error_and_never_a_textless_document() {
        // `crates/indexing/src/error.rs` states this as the crate's property, and this is the path
        // that would break it: an outage recorded as "this document has no text" leaves every file
        // it touched invisible to search long after the outage ended, with nothing saying so.
        let retry =
            retry_over(Vec::new(), RecordingPages { broken: true, ..RecordingPages::default() });

        let error = retry
            .retry(VersionId::new_v7(), textless(vec![1]))
            .await
            .expect_err("a dead rasteriser must not be an outcome");
        assert!(matches!(error, IndexingError::Worker(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_dead_ocr_worker_is_an_error_and_never_a_textless_document() {
        let retry = retry_over(vec![Answer::Failed], RecordingPages::default());

        let error = retry
            .retry(VersionId::new_v7(), textless(vec![1]))
            .await
            .expect_err("a dead OCR worker must not be an outcome");
        assert!(matches!(error, IndexingError::Worker(_)), "{error:?}");
    }
}
