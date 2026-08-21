//! Rendering a PDF page to pixels, so that OCR has something to read.
//!
//! `ENC-537`. This is the last thing standing between the corpus and the M3 exit criterion *"a
//! scanned, text-free PDF is searchable by its content"*: [`OcrRetry`](crate::OcrRetry) has been
//! able to re-run OCR over named pages since `ENC-535`, and [`PageImages`] has been the port it asks
//! for them through, and until now every deployment answered [`NoPageImages`](crate::NoPageImages)
//! — no pixels, nothing recovered, `FAILED` / `no_text_extracted` forever.
//!
//! # Where this runs, and why it is not in `enclave-preview`
//!
//! `crates/preview/src/raster.rs` refuses `RenditionProfile::PdfSanitized` and gives the reason: a
//! page tree is *a parser rather than a decoder*, and it belongs in the out-of-process worker
//! `plans/M2-ACCESS-DELIVERY.md` D17 specifies. **That refusal is not touched by this module and
//! must not be.** `RasterRenderer` still supports exactly two raster profiles, there is no
//! [`Renderer`](enclave_preview::Renderer) implementation anywhere in this crate, and
//! `crates/preview/tests/raster.rs` continues to assert both.
//!
//! The distinction that makes this safe *where the preview path is not* is what happens to the
//! pixels:
//!
//! | | `PdfSanitized` on the preview path | This module |
//! |---|---|---|
//! | Who receives the output | a viewer's browser | the OCR engine, in the same process |
//! | Where it is stored | the rendition cache, keyed and served again | nowhere; the buffer is dropped |
//! | What it must be | *safe to open* — a sanitised document | pixels |
//! | Who is waiting | a person, on a request | nobody; an indexing job |
//!
//! The preview job is strictly harder: producing a *sanitised PDF* means deciding what in a hostile
//! document may be handed back to a browser, and a partial implementation there reports "preview
//! available" for a format whose sanitization nobody has written. Rasterising for OCR makes no such
//! claim. Nothing this module produces is ever served, cached, or addressable — the only consumer is
//! [`OcrExtractor`](crate::OcrExtractor), which sniffs the bytes rather than trusting them, and the
//! only path in is [`OcrRetry`](crate::OcrRetry) re-running a *failed* extraction.
//!
//! So it lives in `enclave-indexing`, beside the OCR engine that consumes it, in the process D24
//! already puts extraction in.
//!
//! # What that does **not** claim
//!
//! **This is in-process, and D17's sandbox does not exist yet.** `raster.rs` and
//! [`ocr`](crate::ocr) each make that admission about themselves and this module makes it in
//! stronger terms, because what is being run in-process is different in kind:
//!
//! - PDFium is **C++**. Every other parser this workspace ships — `image`, `ocrs`, `rten` — is
//!   Rust, so their worst case is a wrong answer, a panic, or an allocation. PDFium's worst case is
//!   memory corruption, and memory corruption in-process is the whole worker rather than one
//!   document.
//! - The `thread_safe` feature serialises **every** PDFium call in the process behind one mutex,
//!   because PDFium promises no thread safety at all. So a page engineered to take an hour does not
//!   merely burn one `spawn_blocking` thread — it blocks every other document's rasterisation in the
//!   process for that hour. The wall clock below releases the *caller*; it cannot release the mutex.
//!
//! Both are recorded as a residual in `plans/M3-THREAT-WALKTHROUGH.md §3` (R10) rather than argued
//! away, and D17 — a separate process with a memory limit, a CPU limit and a kill switch — is what
//! actually closes them. What is available today and is done here: deny-by-default (a deployment
//! that mounts no library has no rasteriser at all), a build of PDFium with **no V8 and no XFA** so
//! there is no JavaScript engine and no XML forms parser behind the page tree, no network or store
//! handle anywhere in this module, and the bounds below.
//!
//! # The budget, in the order `raster.rs` fixes
//!
//! A PDF's amplification is not a decode bomb's. A decode bomb declares dimensions and a decoder
//! allocates them; a PDF declares a *page size in points* and **we** choose how many pixels that
//! becomes, so the amplification is entirely on our side of the line. The largest `MediaBox` the
//! format permits is 14400 points square — 200 inches — which at [`RENDER_DPI`] would be 40000×40000
//! pixels and a 6.4 GB buffer, out of a file that can be under a kilobyte.
//!
//! The same four steps, with the PDF-shaped equivalent of each:
//!
//! 1. **Sniff.** `%PDF-` at offset zero, a closed allowlist of one signature. Not the declared media
//!    type, which is the uploader's claim — [`PdfiumPages`] is not told one.
//! 2. **Bound the input**, before the parser is entered at all. [`RenderBudget::max_input_bytes`].
//!    `raster.rs` gets this from [`Bounded`](enclave_preview::Bounded) wrapping it; nothing wraps a
//!    [`PageImages`], so it is done here.
//! 3. **Read the declared size without rendering.** [`PdfPage::width`] and `height` are the page
//!    tree's numbers, which is precisely `decoder.dimensions()`'s position in the raster order: the
//!    document has been parsed, and no pixel buffer exists.
//! 4. **Decide, then render.** [`raster_size`] converts points to pixels at [`RENDER_DPI`] and
//!    clamps the longest edge to [`MAX_EDGE`]; the resulting `width × height × 4` is checked against
//!    [`RenderBudget::max_output_bytes`] **before** [`PdfPage::render`] allocates anything.
//!
//! [`RenderBudget::max_pages`] is checked against the document's page count before any page is
//! fetched, for the reason [`OcrRetry`](crate::OcrRetry) already gives about the work list: each of
//! a million pages is individually inside its budget and a million of them is not.
//!
//! **Which of those two bounds is load-bearing, honestly.** [`MAX_EDGE`] is. It caps the buffer at
//! about 23 MB whatever the page declares, which is well inside [`RenderBudget::DEFAULT`]'s 256 MB —
//! so the `max_output_bytes` check never fires on the default budget, and a test that only fed it a
//! huge `MediaBox` would prove the clamp and not the check. It is kept, and tested against a
//! *tightened* budget, because it is what survives somebody raising [`MAX_EDGE`] and because a
//! deployment may set a smaller cap than the one this constant was chosen against. That is the same
//! relationship `ocr.rs` documents between its own size check and `image`'s `Limits::max_alloc`, and
//! it is written down for the same reason: a bound that only holds because of a constant somewhere
//! else is one edit away from not holding.
//!
//! # What the library is allowed to say
//!
//! Nothing. [`PdfiumError`](pdfium_render::prelude::PdfiumError) is discarded at every site without
//! being read — `CLAUDE.md` rule 10, and this is the sharpest case of it in the workspace: the
//! message has just been produced by a C++ parser from a document an uploader chose. The one string
//! this module surfaces is the mount path in [`PdfiumLibrary::mounted`]'s error, which is operator
//! configuration rather than content.
//!
//! # Mounted, never committed
//!
//! The same shape as the OCR weights (`ENC-535`) and the embedding model (`ENC-534`), so a
//! deployment stages three volumes in one operator story rather than three.
//!
//! The reason differs from the weights' and is worth stating: this is not a licence problem. PDFium
//! is BSD-3-Clause and the prebuilt binaries from `bblanchon/pdfium-binaries` are MIT around it, both
//! inside `deny.toml`'s allowlist. It is a **binary artefact** problem — a 7 MB shared library per
//! platform, which is content nobody reviews in a diff, cannot be audited by `cargo deny` (it is not
//! a crate), and would have to be vendored per target triple. `docs/08 §18`'s air-gapped installs
//! pay for it on every image pull either way.
//!
//! **The mounted binary and this crate's `pdfium_7881` feature are an ABI pair.** `pdfium-render`
//! resolves every export eagerly at `dlopen` time, so a mismatch fails loudly at
//! [`PdfiumLibrary::mounted`] rather than subtly at render — which is the good failure mode, and the
//! reason the workspace manifest pins the feature to a version instead of `pdfium_latest`.
//!
//! # The version marker gap, named rather than papered over
//!
//! `docs/07 §3` triggers a reindex by comparing `index_manifests.extractor_version`, and
//! [`OcrRetry`](crate::OcrRetry) composes that from the *OCR extractor* alone. The rasteriser
//! decides what pixels the engine sees, so a different PDFium renders a different image and can
//! recognise different text under a marker that did not move — and the marker cannot cover it
//! anyway, for exactly the reason [`OcrModels`](crate::OcrModels) gives about the weights:
//! [`ExtractorVersion`](crate::ExtractorVersion) is `&'static str` so that it cannot be computed at
//! run time, and the library is mounted at run time.
//!
//! So: **changing the mounted PDFium is an operator action that needs the OCR extractor's marker
//! bumped and shipped alongside it.** Recorded as a gap, the same way the weights' is; nothing in
//! the type system enforces either.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use enclave_preview::{Refusal, RenderBudget};
use image::codecs::png::{CompressionType, FilterType as PngFilter, PngEncoder};
use image::{ExtendedColorType, ImageEncoder as _};
use pdfium_render::prelude::{PdfDocument, PdfPage, Pdfium};

use crate::error::{IndexingError, Result};
use crate::ocr::{PageImage, PageImages};

/// The one signature this module will hand to a PDF parser.
///
/// At offset zero, which is stricter than the format: a PDF's header is permitted anywhere in the
/// first 1024 bytes and PDFium honours that. Deliberate, and the same posture `raster.rs` takes with
/// [`image::guess_format`] — a closed allowlist checked at a fixed position is a rule an
/// implementation cannot disagree with us about. The cost is refusing a file with leading junk,
/// which is a file no scanner produces.
const PDF_SIGNATURE: &[u8] = b"%PDF-";

/// The nominal resolution a page is rendered at, in dots per inch.
///
/// 200 dpi is the low end of what document OCR is conventionally run at — fax resolution — and it is
/// chosen for the recogniser rather than for a viewer. `raster.rs`'s `PAGE_1X_EDGE` works out at
/// roughly 135 dpi for A4, which is sized to be *legible on a screen*; recognition wants more stroke
/// detail than a reader does, and this is the one number where the two paths' requirements genuinely
/// differ.
///
/// An A4 page at this resolution is 1654×2339, which is inside [`MAX_EDGE`], so the common case is
/// rendered at the full nominal resolution and only unusual page sizes are scaled down.
const RENDER_DPI: f32 = 200.0;

/// The longest edge of a rendered page, in pixels, whatever the page declares.
///
/// **This is the bound that makes a PDF's amplification finite**, and it is a constant rather than a
/// budget field on purpose: [`RenderBudget`] is D24's one set of numbers and adding a seventh field
/// to it for one renderer's geometry is how two crates end up with two answers. The budget's job is
/// to bound the *result* ([`RenderBudget::max_output_bytes`], checked below); this constant's job is
/// to make the result a sane size in the first place.
///
/// 2400 clears A4 and US Letter at [`RENDER_DPI`] untouched and caps the RGBA buffer at about 23 MB.
/// A 200-inch page — the largest the format allows — comes out at 2400 on its long edge instead of
/// 40000, which is the difference between 23 MB and 6.4 GB.
const MAX_EDGE: u32 = 2_400;

/// Bytes per pixel in the buffer [`PdfPage::render`] fills.
///
/// PDFium's default bitmap format is BGRA and `as_rgba_bytes` returns the same count. Written as a
/// named constant because it is the multiplier in the only allocation this module performs, and an
/// arithmetic error here is the size check answering about a buffer a quarter the size of the real
/// one.
const BYTES_PER_PIXEL: u64 = 4;

/// The media type this module's output actually is.
///
/// Ours rather than an uploader's, and it matches the type
/// [`OcrRetry`](crate::OcrRetry) declares when handing a page image to the extractor. The extractor
/// sniffs regardless, so this is a routing hint and never a promise.
const PAGE_IMAGE_MEDIA_TYPE: &str = "image/png";

/// The file name of the shared library inside the mounted directory, per platform.
///
/// `libpdfium.so` on Linux, `libpdfium.dylib` on macOS. Taken from `pdfium-render` rather than
/// spelled here so that the name this looks for and the name it would load are one value.
fn library_file(directory: &Path) -> PathBuf {
    Pdfium::pdfium_platform_library_name_at_path(directory)
}

/// PDFium, loaded from the volume a deployment mounted it on.
///
/// See the module documentation for why it is mounted rather than vendored, and for the ABI pairing
/// between the mounted binary and this crate's `pdfium_7881` feature.
///
/// # Why this is a process singleton and not a value you can have two of
///
/// `FPDF_InitLibrary` initialises global state inside the C++ library, and `pdfium-render` models
/// that faithfully: its bindings live in a process-wide cell, and constructing a second `Pdfium`
/// **panics**. So a second `mounted` call cannot simply build another one.
///
/// This type therefore initialises once and hands back the same handle afterwards. A second call
/// naming a *different* directory is an error rather than a silent no-op, because silently ignoring
/// it would mean a deployment that reconfigured its mount kept rendering with the old library and
/// nothing anywhere said so.
pub struct PdfiumLibrary {
    pdfium: Pdfium,
    /// The library file this process actually loaded, for the mismatch error above.
    path: PathBuf,
}

impl fmt::Debug for PdfiumLibrary {
    /// Names the type and the path, and nothing from the library.
    ///
    /// `Pdfium` is not `Debug` and should not be: it is a table of function pointers into a shared
    /// object, which is an address-space map in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdfiumLibrary").field("path", &self.path).finish_non_exhaustive()
    }
}

/// The one initialisation, and the lock that makes "once" true under concurrency.
///
/// The lock is not redundant with the cell. Two threads can both observe an empty cell, both bind
/// the library successfully, and then both construct a `Pdfium` — and the second of those hits
/// `pdfium-render`'s `assert!`, which is a panic in a dependency rather than an error we could
/// report. The lock closes that window; the cell is what makes the fast path free.
static LIBRARY: OnceLock<Arc<PdfiumLibrary>> = OnceLock::new();
static MOUNTING: Mutex<()> = Mutex::new(());

impl PdfiumLibrary {
    /// Loads PDFium from a mounted directory, or returns the already-loaded one.
    ///
    /// # Errors
    ///
    /// [`IndexingError::Worker`] when the library is missing, is not loadable, or does not export
    /// the API this build was compiled against — and when a second call names a different directory
    /// than the one this process loaded.
    ///
    /// This is *ours* and never a refusal: no document is involved, and a deployment whose library
    /// volume failed to attach has an outage rather than a corpus of textless files. A caller that
    /// cannot build one has [`NoPageImages`](crate::NoPageImages), which is the deny-by-default this
    /// crate already relies on.
    ///
    /// The message names the path and **not** the library's error. The path is operator
    /// configuration, which is safe to surface and miserable to diagnose without; the loader's
    /// message is derived from a file on that volume.
    pub fn mounted(directory: &Path) -> Result<Arc<Self>> {
        let path = library_file(directory);

        // Held across the whole check-and-initialise, for the reason `MOUNTING` documents.
        let _guard = MOUNTING.lock().map_err(|_| {
            IndexingError::Worker(anyhow::anyhow!(
                "a previous attempt to mount PDFium panicked and the mount is unusable"
            ))
        })?;

        if let Some(existing) = LIBRARY.get() {
            if existing.path != path {
                return Err(IndexingError::Worker(anyhow::anyhow!(
                    "PDFium is already mounted from {} and cannot be re-mounted from {}",
                    existing.path.display(),
                    path.display()
                )));
            }
            return Ok(Arc::clone(existing));
        }

        let bindings = Pdfium::bind_to_library(&path).map_err(|_| {
            IndexingError::Worker(anyhow::anyhow!(
                "PDFium could not be loaded from {}",
                path.display()
            ))
        })?;

        let library = Arc::new(Self { pdfium: Pdfium::new(bindings), path });
        // Cannot fail: the cell is empty (checked above) and the lock is held.
        let library = LIBRARY.get_or_init(|| library);
        Ok(Arc::clone(library))
    }
}

/// The pages of one PDF, rendered on demand.
///
/// Built per document, because the source bytes are the document. Holds no store handle, no client
/// and no key — the no-egress property [`crate::extract`] states for extractors applies here for the
/// sharper reason: this is the stage that has the whole of a document decoded in memory.
#[derive(Debug, Clone)]
pub struct PdfiumPages {
    library: Arc<PdfiumLibrary>,
    /// `Arc` because every page render moves an owned handle onto a `spawn_blocking` thread, and a
    /// scanned document is tens of megabytes that must not be copied once per page.
    source: Arc<Vec<u8>>,
    budget: RenderBudget,
}

impl PdfiumPages {
    /// Builds a page source over one document's bytes.
    ///
    /// `budget` is the **per-page** budget — [`OcrRetry::new`](crate::OcrRetry::new)'s, not the text
    /// extractor's, for the reason given there.
    #[must_use]
    pub fn new(library: Arc<PdfiumLibrary>, source: Vec<u8>, budget: RenderBudget) -> Self {
        Self { library, source: Arc::new(source), budget }
    }

    /// The media type of what this produces, for a caller wiring the retry stage.
    #[must_use]
    pub const fn media_type() -> &'static str {
        PAGE_IMAGE_MEDIA_TYPE
    }
}

#[async_trait]
impl PageImages for PdfiumPages {
    async fn page_image(&self, page: u32) -> Result<PageImage> {
        let library = Arc::clone(&self.library);
        let source = Arc::clone(&self.source);
        let budget = self.budget;

        // `spawn_blocking` for the reason `raster.rs` and `ocr.rs` both give, and `timeout` around
        // it because — unlike an `Extractor` — nothing wraps a `PageImages` in `Bounded`, so this is
        // the only wall clock a page render has.
        //
        // What that promise is worth, exactly: the *caller* is released on time. Dropping a
        // `JoinHandle` does not stop a blocking task, so the PDFium call runs to completion holding
        // the crate's global mutex. That is not a shortcoming of this line, it is D17's whole
        // argument, and the module documentation states it rather than leaving it to be discovered.
        let render =
            tokio::task::spawn_blocking(move || rasterize(&library, &source, page, budget));

        match tokio::time::timeout(budget.wall_clock, render).await {
            Ok(Ok(image)) => Ok(image),
            // A parser that panics has made a statement about the document: the same bytes panic the
            // same way every time, so this is a verdict. Reporting it as ours would invite the
            // retry, and a file that reliably kills a worker thread is a denial-of-service primitive
            // the moment a scheduler is willing to run it again.
            Ok(Err(join)) if join.is_panic() => Ok(PageImage::Refused(Refusal::SourceUnreadable)),
            // Cancellation is not about the document — the runtime is shutting down. Answering
            // "this page has no image" would record an outage as an absence.
            Ok(Err(join)) => Err(IndexingError::Worker(anyhow::Error::new(join))),
            // D17: a timeout is a verdict, not an error. `Refused` rather than `Absent` so the
            // document fails visibly instead of being indexed without this page.
            Err(_elapsed) => Ok(PageImage::Refused(Refusal::Timeout)),
        }
    }
}

/// The whole synchronous pipeline, in the order the module documentation fixes.
///
/// Returns a [`PageImage`] rather than a `Result` because nothing in it can fail on our side: the
/// library is already loaded, and everything the source is responsible for is a verdict.
fn rasterize(library: &PdfiumLibrary, source: &[u8], page: u32, budget: RenderBudget) -> PageImage {
    // 1. Sniff, before a parser is constructed.
    if !source.starts_with(PDF_SIGNATURE) {
        return PageImage::Refused(Refusal::UnsupportedFormat);
    }

    // 2. The input cap, before the parser is entered. Checking afterwards would mean the parse this
    //    cap exists to prevent has already run.
    if source.len() as u64 > budget.max_input_bytes {
        return PageImage::Refused(Refusal::InputTooLarge);
    }

    // 3. The page tree. This is the parser, and everything below it is inside PDFium.
    let Ok(document) = library.pdfium.load_pdf_from_byte_slice(source, None) else {
        // Truncated, corrupt, or password-protected — `Refusal::SourceUnreadable`'s own gloss names
        // all three. The library's message is discarded unread.
        return PageImage::Refused(Refusal::SourceUnreadable);
    };

    // Bound to a local rather than returned straight out of the `match`. `PdfDocument` has a `Drop`
    // that closes the handle, and a borrow of it living into the tail expression is a borrow the
    // compiler must assume the destructor can observe.
    let image = match locate(&document, page, budget) {
        None => PageImage::Absent,
        Some(Located::Page(page)) => render_page(&page, budget),
        Some(Located::Refused(refusal)) => PageImage::Refused(refusal),
    };

    image
}

/// A page of the document, or the verdict on why there is not one to render.
enum Located<'a> {
    Page(PdfPage<'a>),
    Refused(Refusal),
}

/// Finds the requested page, applying the document-level page cap first.
///
/// `None` is [`PageImage::Absent`]: the document has no such page. Separated from [`rasterize`]
/// because the three ways a page number can fail to name a page — zero, past the end, and a document
/// with more pages than the budget allows — are easy to conflate and only the last is a verdict.
/// The two lifetimes are not interchangeable: `PdfPages::get` yields a `PdfPage<'a>` tied to the
/// document's *source bytes*, not to the borrow of the document handle, and writing them as one
/// lifetime makes the returned page outlive the `&PdfDocument` — which the borrow checker reads as a
/// borrow the document's destructor could observe.
fn locate<'a>(document: &PdfDocument<'a>, page: u32, budget: RenderBudget) -> Option<Located<'a>> {
    let count = document.pages().len();
    if count <= 0 {
        // A document with no pages parses and has nothing to rasterise. Absent, not a refusal: it
        // is the same answer as asking for page 4 of a three-page file.
        return None;
    }

    if u64::from(count.unsigned_abs()) > u64::from(budget.max_pages) {
        // The cap that bounds the *document* rather than a page. Checked before the page is fetched,
        // so a million-page file costs one page-tree parse and no renders. `OcrRetry` applies the
        // same cap to its work list; this one catches the case where the work list is short and the
        // document is not.
        return Some(Located::Refused(Refusal::TooManyPages));
    }

    // One-based, per `PageImages::page_image`. Page zero does not exist, and turning it into index
    // -1 or into page 1 are both wrong in a way nothing downstream could notice.
    let index = i32::try_from(page.checked_sub(1)?).ok()?;
    if index >= count {
        return None;
    }

    Some(match document.pages().get(index) {
        Ok(page) => Located::Page(page),
        // The page tree named a page the library then could not produce. A verdict about the
        // document, not an absence — a well-formed file does not do this.
        Err(_) => Located::Refused(Refusal::SourceUnreadable),
    })
}

/// Reads the declared page size, decides the raster size, checks it, and only then renders.
fn render_page(page: &PdfPage<'_>, budget: RenderBudget) -> PageImage {
    // The page tree's numbers, read with no pixel buffer in existence. This is `decoder.dimensions()`
    // in the raster order, and it is the last point at which a refusal costs nothing.
    let (points_width, points_height) = (page.width().value, page.height().value);
    let Some((width, height)) = raster_size(points_width, points_height) else {
        // A zero, negative, infinite or NaN page box. Legal to write into a file and meaningless to
        // render, and it is the input that turns every ratio in `raster_size` into nonsense.
        return PageImage::Refused(Refusal::SourceUnreadable);
    };

    // The bomb check, and the last statement before any pixel buffer could exist.
    if u64::from(width) * u64::from(height) * BYTES_PER_PIXEL > budget.max_output_bytes {
        return PageImage::Refused(Refusal::OutputTooLarge);
    }

    let (Ok(target_width), Ok(target_height)) = (i32::try_from(width), i32::try_from(height))
    else {
        // Unreachable: `MAX_EDGE` is far inside `i32`. Kept because the alternative to an explicit
        // refusal is a cast that silently produces a negative dimension.
        return PageImage::Refused(Refusal::OutputTooLarge);
    };

    // Only now. `None` for rotation: the page's own `/Rotate` is already applied by PDFium, and
    // asking for an extra rotation would turn every landscape scan on its side.
    let Ok(bitmap) = page.render(target_width, target_height, None) else {
        return PageImage::Refused(Refusal::SourceUnreadable);
    };

    // Read back through the library's own accessor rather than by reinterpreting the raw buffer:
    // the bitmap's format is PDFium's choice, and `as_rgba_bytes` is what knows how to normalise it.
    let rgba = bitmap.as_rgba_bytes();
    let Some(image) = image::RgbaImage::from_raw(width, height, rgba) else {
        // The buffer did not match the dimensions we asked for. Nothing a document should be able to
        // cause, and refusing is the only honest answer to a renderer that disagreed with itself.
        return PageImage::Refused(Refusal::SourceUnreadable);
    };

    let mut bytes = Vec::new();
    let encoder =
        PngEncoder::new_with_quality(&mut bytes, CompressionType::Default, PngFilter::Adaptive);
    if encoder.write_image(image.as_raw(), width, height, ExtendedColorType::Rgba8).is_err() {
        // The one error path that has run with the document's pixels in hand. A fixed verdict and
        // no message, per `CLAUDE.md` rule 10.
        return PageImage::Refused(Refusal::SourceUnreadable);
    }

    // The artefact, as opposed to the buffer behind it. PNG of a bounded image is bounded in
    // practice, so this is belt and braces — and it is the cap that applies to what actually crosses
    // the port, which is the number a caller's own budget was set against.
    if bytes.len() as u64 > budget.max_output_bytes {
        return PageImage::Refused(Refusal::OutputTooLarge);
    }

    PageImage::Rendered(bytes)
}

/// Converts a page box in points to a pixel size at [`RENDER_DPI`], clamped to [`MAX_EDGE`].
///
/// `None` for a box that is not a positive finite rectangle.
///
/// The clamp preserves the aspect ratio and never enlarges beyond the nominal resolution, so a page
/// smaller than [`MAX_EDGE`] at [`RENDER_DPI`] is rendered at exactly that resolution and only an
/// unusually large one is scaled down. Both edges are floored at one pixel: an extreme aspect ratio
/// scales the short edge below a pixel, and a zero-width bitmap is not something to hand a renderer.
///
/// Separated from [`render_page`] and given its own tests because it is the arithmetic that decides
/// how large the single allocation in this module is, and it is exactly the kind of code that stays
/// correct until somebody reorders two lines of it.
fn raster_size(points_width: f32, points_height: f32) -> Option<(u32, u32)> {
    if !points_width.is_finite()
        || !points_height.is_finite()
        || points_width <= 0.0
        || points_height <= 0.0
    {
        return None;
    }

    // `f64` for the conversion: a 14400-point edge at 200 dpi is 40000, which `f32` represents
    // exactly, but the products below are the kind that lose a pixel to rounding for no reason.
    let scale = f64::from(RENDER_DPI) / 72.0;
    let to_pixels = |points: f32| -> u32 {
        let pixels = f64::from(points) * scale;
        // `as` saturates at `u32::MAX` for an out-of-range float in Rust, which is the safe
        // direction here: the clamp below brings it back inside `MAX_EDGE`.
        (pixels.round() as u32).max(1)
    };

    let (width, height) = (to_pixels(points_width), to_pixels(points_height));
    let longest = width.max(height);
    if longest <= MAX_EDGE {
        return Some((width, height));
    }

    // `u64` because `width * MAX_EDGE` overflows `u32` at edges well inside what a page box may
    // declare, and an overflowing multiply would produce a *smaller* number — a silently mis-sized
    // render rather than a refusal.
    let scale_down = |value: u32| -> u32 {
        let scaled = u64::from(value) * u64::from(MAX_EDGE) / u64::from(longest);
        u32::try_from(scaled).unwrap_or(MAX_EDGE).max(1)
    };

    Some((scale_down(width), scale_down(height)))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// A4, in points.
    const A4: (f32, f32) = (595.0, 842.0);

    #[test]
    fn an_ordinary_page_is_rendered_at_the_nominal_resolution() {
        // The positive control for every clamp assertion below. Without it, a `raster_size` that
        // returned `(1, 1)` for everything would satisfy all of them.
        let (width, height) = raster_size(A4.0, A4.1).expect("A4 is a page");
        assert_eq!((width, height), (1653, 2339), "A4 at 200 dpi");
        assert!(width.max(height) <= MAX_EDGE, "A4 must not be scaled down");
    }

    #[test]
    fn the_largest_page_the_format_allows_does_not_become_a_six_gigabyte_buffer() {
        // 14400 points is 200 inches, the maximum `MediaBox` edge. At 200 dpi that is 40000 pixels
        // and, times four bytes, 6.4 GB — out of a file that can be under a kilobyte. This is the
        // amplification a PDF has that an image does not, and `MAX_EDGE` is the whole of the answer.
        let (width, height) = raster_size(14_400.0, 14_400.0).expect("a legal page box");

        assert_eq!((width, height), (MAX_EDGE, MAX_EDGE));
        let bytes = u64::from(width) * u64::from(height) * BYTES_PER_PIXEL;
        assert!(bytes < 32 * 1024 * 1024, "{bytes} bytes for a 200-inch page");
        assert!(
            bytes < RenderBudget::DEFAULT.max_output_bytes,
            "the clamp, not the budget, is what bounds this"
        );
    }

    #[test]
    fn the_clamp_preserves_the_aspect_ratio() {
        // A clamp that squared everything off would satisfy the test above and silently distort
        // every oversized page, which an OCR engine reads as skew.
        let (width, height) = raster_size(14_400.0, 7_200.0).expect("a legal page box");
        assert_eq!(width, MAX_EDGE);
        assert_eq!(height, MAX_EDGE / 2);
    }

    #[test]
    fn an_extreme_aspect_ratio_never_scales_an_edge_to_zero() {
        // A 200-inch by 1-point page scales its short edge to 0.46 pixels. Rounded down that is a
        // zero-height bitmap, which is a renderer error or an empty artefact depending on the
        // renderer.
        let (width, height) = raster_size(14_400.0, 1.0).expect("a legal page box");
        assert_eq!(width, MAX_EDGE);
        assert_eq!(height, 1);
    }

    #[test]
    fn a_page_box_that_is_not_a_rectangle_is_not_a_size() {
        // Every one of these can be written into a `/MediaBox` and none of them is renderable. They
        // are also the inputs that turn the ratio arithmetic into a division by zero or a NaN.
        for (width, height) in [
            (0.0, 842.0),
            (595.0, 0.0),
            (-595.0, 842.0),
            (f32::NAN, 842.0),
            (f32::INFINITY, 842.0),
            (f32::MAX, f32::MAX),
        ] {
            match raster_size(width, height) {
                None => {}
                // `f32::MAX` is the one that has to be checked rather than assumed: it is finite and
                // positive, so it reaches the arithmetic, and `as u32` saturating is what keeps it
                // from wrapping to something small.
                Some((w, h)) if width == f32::MAX => {
                    assert!(w.max(h) <= MAX_EDGE, "{width} × {height} rendered as {w} × {h}");
                }
                Some(size) => panic!("{width} × {height} was accepted as {size:?}"),
            }
        }
    }

    #[test]
    fn the_signature_is_checked_at_offset_zero_and_nowhere_else() {
        // The sniff, as a statement rather than as a side effect of a parser. A file whose header is
        // 200 bytes in is legal PDF and is refused here; that is the decision the module
        // documentation records, and a test is what keeps it a decision.
        assert!(b"%PDF-1.7\n".starts_with(PDF_SIGNATURE));
        assert!(!b"\n\n%PDF-1.7\n".starts_with(PDF_SIGNATURE));
        assert!(!b"\x89PNG\r\n\x1a\n".starts_with(PDF_SIGNATURE));
        assert!(!b"".starts_with(PDF_SIGNATURE));
    }

    #[test]
    fn the_mount_error_names_the_path_and_never_the_loaders_message() {
        // `CLAUDE.md` rule 10 at the one place this module surfaces a string. Runs without a library
        // on purpose: the absence is what it is about.
        let error = PdfiumLibrary::mounted(Path::new("/nonexistent/enclave-pdfium"))
            .expect_err("nothing is mounted there");

        assert!(matches!(error, IndexingError::Worker(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            "the extraction worker failed",
            "the crate's own error text is a fixed phrase"
        );

        let chain = format!("{error:?}");
        assert!(chain.contains("/nonexistent/enclave-pdfium"), "{chain}");
        // `libloading`'s errors render as one of these; none of them may appear.
        for leaked in ["dlopen", "no such file", "No such file", "os error", "image not found"] {
            assert!(!chain.contains(leaked), "the loader's message reached the error: {chain}");
        }
    }
}
