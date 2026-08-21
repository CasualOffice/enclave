//! Reading a PDF's text layer, page by page, and naming the pages that had none.
//!
//! `ENC-545`. `crates/indexing/src/pdf.rs` (`ENC-537`) gave the OCR path pixels and
//! `crates/indexing/src/ocr.rs` (`ENC-535`) gave it a recogniser, and the exit criterion *"a scanned,
//! text-free PDF is searchable by its content"* still could not be met, because **nothing extracted
//! `application/pdf` at all**. [`NoExtractor`](crate::NoExtractor) answered, so
//! [`Pipeline::prepare`](crate::Pipeline::prepare) returned [`Outcome::Unsupported`](crate::Outcome)
//! — `SKIPPED` / `unsupported_media_type` — and [`OcrRetry`](crate::OcrRetry) fires only on
//! [`Outcome::NoText`](crate::Outcome::NoText). Both halves of the machinery were reachable and
//! neither was ever reached.
//!
//! This module is the half in front of them: it produces the [`TextlessSource`] that the retry stage
//! takes as its work list.
//!
//! # The work list is the point, not a by-product
//!
//! `docs/07 §2.1` says *"per-page text with coordinates"* and D24 says why the *absence* of text has
//! to be reported per page rather than as a single flag: [`TextlessSource::pages_without_text`] lets
//! OCR run over three pages of nine hundred instead of all of them. A rasterise-plus-recognise is
//! seconds per page; the difference between a work list and a page count is the difference between a
//! document that gets OCR'd and one nobody can afford to.
//!
//! So a page that yielded nothing is not skipped here. It becomes a [`Segment`] with **empty text and
//! its page number**, which is exactly the shape `crate::pipeline`'s `textless` already derives a
//! work list from, and this module derives the same list directly rather than depending on that.
//!
//! # The three outcomes, and the one that is easy to get wrong
//!
//! | The document | Outcome | Why |
//! |---|---|---|
//! | every page has text | [`ExtractOutcome::Extracted`] | ordinary |
//! | **no** page has text | [`ExtractOutcome::NoText`] | the scan. Every page is on the work list |
//! | **some** pages have text | [`ExtractOutcome::Extracted`] | see below |
//!
//! The third row is the one that matters, because it is neither of the first two and both temptations
//! are wrong.
//!
//! It is **not** [`ExtractOutcome::NoText`]. That variant means *"the source parsed, and yielded no
//! text at all"*, and reporting it for a document that yielded ten pages of text would throw those
//! ten pages away — [`OcrRetry`](crate::OcrRetry) builds its document from the pages it recognised
//! and nothing else, so the outcome that recovers the three scanned pages is the outcome that loses
//! the ten typed ones. That is a *worse* partial index than doing nothing, arrived at deliberately.
//!
//! It is not a [`Refusal`] either: nothing about the document is a verdict. It parsed.
//!
//! So it is [`ExtractOutcome::Extracted`], and [`TextDocument::is_empty`] is what says so —
//! *"no segment holds any text"*, which is false the moment one page has words on it. That is the
//! same definition [`BoundedExtractor`](crate::BoundedExtractor) applies from outside, so this module
//! and its wrapper cannot disagree about which documents are textless.
//!
//! ## What that leaves undone, stated rather than implied
//!
//! A mixed document's **scanned pages are not OCR'd**, because [`OcrRetry::retry`](crate::OcrRetry)
//! passes every outcome except [`Outcome::NoText`](crate::Outcome::NoText) straight through, and that
//! pass-through is the property that stops OCR turning *"this document failed"* into *"this document
//! is empty"*. Loosening it here would be trading a documented gap for an undocumented inversion.
//!
//! The gap is real and it is D24's shape: a ninety-page report with three scanned exhibits indexes
//! `READY` over eighty-seven pages, and nothing on any surface says the exhibits are missing.
//! Closing it needs an outcome that can carry *both* a document and a work list — which is a change
//! to [`ExtractOutcome`], to `Outcome`, and to [`OcrRetry`](crate::OcrRetry)'s merge, not something
//! to smuggle in behind a PDF extractor. It is logged separately; what this module does is make sure
//! the information that closes it is **not thrown away**: the empty per-page segments are in the
//! document, carrying their page numbers, for whoever writes that merge.
//!
//! # The budget, in the order `pdf.rs` fixes
//!
//! D24 reuses [`RenderBudget`] rather than inventing a second set, and the rasteriser already spells
//! the order out: sniff → input cap → page cap → declared size → output cap → render. The text
//! equivalent, with the one substitution:
//!
//! 1. **Sniff.** [`PDF_SIGNATURE`] at offset zero — the same constant `pdf.rs` checks, imported
//!    rather than copied, because two allowlists are how one of them gets widened.
//! 2. **Bound the input**, before the parser is entered. Nothing here can rely on
//!    [`BoundedExtractor`](crate::BoundedExtractor) having done it: an extractor that is only correct
//!    inside its wrapper is one somebody will use unwrapped.
//! 3. **The page cap**, from the page tree's own count, before a single page is fetched. A
//!    million-page file costs one page-tree parse and no text extraction.
//! 4. **The output cap, as a running total** — this is where the render path's "read the declared
//!    size, then decide" has no counterpart, because a page's text has no declared size. Extraction's
//!    output is a *collection*, so it is bounded the way `text.rs` bounds one: charged per segment
//!    ([`Segment::accounted_bytes`], which includes
//!    [`SEGMENT_OVERHEAD_BYTES`](crate::SEGMENT_OVERHEAD_BYTES)) and checked **before** the segment is
//!    pushed, so the vector is never grown past the cap and measured afterwards.
//!
//! Step 4 is not decoration. A PDF's text amplification runs the same direction as its raster
//! amplification: nine hundred pages of nothing are nine hundred structs out of a file that declares
//! them in a few kilobytes, and without the per-segment charge a document of blank pages has an
//! accounted size of zero.
//!
//! # What the library is allowed to say
//!
//! Nothing, exactly as in `pdf.rs`. [`PdfiumError`](pdfium_render::prelude::PdfiumError) is dropped
//! unread at every site — `CLAUDE.md` rule 10 — and this module has just handed a C++ parser a
//! document an uploader chose. Every failure it can report is one of six fixed [`Refusal`] codes.
//!
//! # The version marker, and the same gap `ENC-537` recorded
//!
//! [`ExtractorVersion`] names this build and the `pdfium-render` release that resolved in
//! `Cargo.lock`, asserted against the lockfile in `tests` rather than trusted, because a patch
//! release of a text extractor is exactly the kind of change that alters output while looking as
//! though it could not.
//!
//! It cannot name the **mounted PDFium**, for the reason `pdf.rs` and
//! [`OcrModels`](crate::OcrModels) both give about their own run-time artefacts:
//! [`ExtractorVersion`] is `&'static str` by design, so that a marker cannot be computed at run time
//! and differ between two replicas mid-rollout, and the library is `dlopen`ed at run time. A
//! different PDFium can lay out a page's text differently under a marker that did not move.
//!
//! **So: changing the mounted PDFium is an operator action that needs this constant bumped and
//! shipped alongside it.** Recorded as a gap; nothing in the type system enforces it.
//!
//! # Where this runs
//!
//! In process, on a `spawn_blocking` thread, with everything `pdf.rs` says about that still true and
//! unmitigated: PDFium is C++, and `tokio::time::timeout` releases the *caller* rather than the
//! thread. `plans/M3-THREAT-WALKTHROUGH.md §3` R10 records it and `plans/M2-ACCESS-DELIVERY.md` D17
//! is what closes it.
//!
//! **This module is where the crate found out that `pdfium-render`'s `thread_safe` feature is not
//! the whole of the answer.** It locks each FFI *call*; two threads reading text off two documents
//! that carry fonts still interleave two *sequences*, and PDFium's globals are not re-entrant across
//! that — the process died with `SIGTRAP`, `SIGABRT` or `SIGSEGV`, seven runs out of eight. The
//! rasteriser had the same hazard latently and never fired it, because image-only pages never touch
//! the font machinery. `pdf.rs`'s `DOCUMENTS` lock now holds for the whole life of a document and
//! both modules take it, which makes PDFium work in this process serial per *document* rather than
//! per call.

use std::sync::Arc;

use async_trait::async_trait;
use enclave_preview::{Refusal, RenderBudget};
use pdfium_render::prelude::PdfDocument;

use crate::error::{IndexingError, Result};
use crate::extract::{ExtractOutcome, ExtractRequest, Extractor, TextlessSource};
use crate::model::{Coordinates, ExtractorVersion, Segment, SegmentKind, TextDocument};
use crate::pdf::{PdfiumLibrary, PDF_SIGNATURE};

/// Which build this is, in the form [`Extractor::extractor_version`] requires.
///
/// Two components: this module's own rules — what counts as a blank page, how a page's text is
/// normalised, that one page is one segment — and the parser that produces the characters. See the
/// module documentation for the third component that cannot be here and what an operator has to do
/// about it.
const EXTRACTOR: &str = "pdf-text/1+pdfium-render-0.9.3";

/// The declared media types this extractor is asked about.
///
/// One entry. `application/pdf` is the type `docs/07 §2.1` names `pdfium` for; the historical
/// `application/x-pdf` and friends are not claimed, because [`Extractor::supports`] is a routing hint
/// and a source that arrives under a spelling nothing claims is `SKIPPED` visibly rather than parsed
/// on a guess.
const SUPPORTED_MEDIA_TYPES: &[&str] = &["application/pdf"];

/// What this extractor reports having established about the bytes.
///
/// Decided from the content — the signature was checked and a page tree parsed — and never echoed
/// from the uploader's claim. It travels on to [`OcrRetry`](crate::OcrRetry) through
/// [`TextlessSource::media_type`] and ends up on the manifest, so what is recorded is the type of the
/// *source*, not of the page images OCR happened to read it through.
const DECIDED_MEDIA_TYPE: &str = "application/pdf";

/// Extracts a PDF's text layer, in process, on a blocking thread.
///
/// Holds the mounted library and nothing else — no configuration, no client, no store handle. A
/// field could hold one, and the no-egress property of [`crate::extract`] is worth more than the
/// flexibility: this is the stage that reads the whole of a document's content.
///
/// Only constructible when a deployment has mounted PDFium, so a deployment that has not still has
/// [`NoExtractor`](crate::NoExtractor) for `application/pdf` — the deny-by-default this crate relies
/// on is unchanged, and only a deployment that opted in runs a C++ parser over an upload.
#[derive(Debug, Clone)]
pub struct PdfTextExtractor {
    library: Arc<PdfiumLibrary>,
}

impl PdfTextExtractor {
    /// Builds an extractor over the mounted library.
    ///
    /// [`Arc`] for the reason [`PdfiumPages`](crate::PdfiumPages) takes one: `spawn_blocking` needs
    /// an owned `'static` handle, and the library is a process singleton that must not be built
    /// twice.
    #[must_use]
    pub const fn new(library: Arc<PdfiumLibrary>) -> Self {
        Self { library }
    }
}

#[async_trait]
impl Extractor for PdfTextExtractor {
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
        let library = Arc::clone(&self.library);

        match tokio::task::spawn_blocking(move || extract_text(&library, &source, budget)).await {
            Ok(outcome) => Ok(outcome),
            // A parser that panics has made a statement about the document: the same bytes panic the
            // same way every time, so this is a verdict and recording it is correct. Reporting it as
            // ours would invite the retry, and a file that reliably kills a worker thread is a
            // denial-of-service primitive the moment a scheduler is willing to run it again.
            Err(join) if join.is_panic() => Ok(ExtractOutcome::Refused(Refusal::SourceUnreadable)),
            // Cancellation is not about the document. The runtime is shutting down or the task was
            // aborted, and answering "this file has no text" would record an outage as an absence.
            Err(join) => Err(IndexingError::Worker(anyhow::Error::new(join))),
        }
    }
}

/// The whole synchronous pipeline, in the order the module documentation fixes.
///
/// Returns an outcome rather than a `Result` because nothing in it can fail on our side: the library
/// is already loaded, and everything the source is responsible for is a [`Refusal`] or a
/// [`TextlessSource`].
fn extract_text(library: &PdfiumLibrary, source: &[u8], budget: RenderBudget) -> ExtractOutcome {
    // 1. Sniff, before a parser is constructed.
    if !source.starts_with(PDF_SIGNATURE) {
        return ExtractOutcome::Refused(Refusal::UnsupportedFormat);
    }

    // 2. The input cap, before the parser is entered. Checking afterwards would mean the parse this
    //    cap exists to prevent has already run.
    if source.len() as u64 > budget.max_input_bytes {
        return ExtractOutcome::Refused(Refusal::InputTooLarge);
    }

    // One document in PDFium at a time. `pdf.rs`'s `DOCUMENTS` says why the `thread_safe` feature is
    // not enough, and this module is where that was found out: two threads reading text off two
    // documents that carry fonts crash the process. Taken *after* the sniff and the input cap, so
    // bytes that were never going to be parsed do not queue behind a document that is being.
    let _documents = PdfiumLibrary::documents();

    // 3. The page tree. This is the parser, and everything below it is inside PDFium.
    let Ok(document) = library.pdfium().load_pdf_from_byte_slice(source, None) else {
        // Truncated, corrupt, or password-protected — `Refusal::SourceUnreadable`'s own gloss names
        // all three. The library's message is discarded unread.
        return ExtractOutcome::Refused(Refusal::SourceUnreadable);
    };

    let count = document.pages().len();
    if count < 0 {
        // Not reachable through `FPDF_GetPageCount`, which reports failure as zero. Handled rather
        // than cast, because the alternative to an explicit refusal is an `unsigned_abs` that turns
        // a negative count into a large positive one and walks a page range that does not exist.
        return ExtractOutcome::Refused(Refusal::SourceUnreadable);
    }

    // 4. The document-level cap, before any page's text is fetched. `OcrRetry` applies the same
    //    number to its work list; this one catches what that list cannot see — a document with more
    //    pages than the budget allows, whatever the list ends up naming.
    let pages = count.unsigned_abs();
    if u64::from(pages) > u64::from(budget.max_pages) {
        return ExtractOutcome::Refused(Refusal::TooManyPages);
    }

    // Lazily, so that a refusal — a page the library will not produce, or the output cap — stops the
    // walk rather than being decided after every page has been read.
    assemble((0..count).map(|index| page_text(&document, index)), pages, budget.max_output_bytes)
}

/// One page's text, or the verdict on why there is not any.
///
/// A page the page tree named and the library then could not produce, or one whose text page will not
/// load, is a verdict about the *document* rather than a page without text: a well-formed file does
/// not do this, and reporting it as textless would hand a malformed document to OCR as though it were
/// a scan.
///
/// # Not covered by a test, and said so rather than assumed
///
/// `docs/12 §1.2` asks that a deliberate violation which fails *nothing* be recorded rather than
/// quietly reworded. Replacing both `map_err`s here with `else { return Ok(String::new()) }` — the
/// exact inversion the paragraph above argues against — leaves the whole suite green.
///
/// What holds the property is [`assemble`], which turns any [`Err`] into
/// [`ExtractOutcome::Refused`] and is tested directly; what is *not* held by anything is the mapping
/// in these two lines, because no fixture has been found in which a document parses, a page loads,
/// and its text page then does not. `a_truncated_document_is_a_text_verdict_and_never_an_error`
/// covers the failure one level up, at `load_pdf_from_byte_slice`, which is the one a real corrupt
/// file reaches.
fn page_text(document: &PdfDocument<'_>, index: i32) -> core::result::Result<String, Refusal> {
    let page = document.pages().get(index).map_err(|_| Refusal::SourceUnreadable)?;
    let text = page.text().map_err(|_| Refusal::SourceUnreadable)?;
    Ok(text.all())
}

/// Turns a sequence of page texts into the outcome, charging each page against the output cap.
///
/// Separated from [`extract_text`] and given its own tests because it holds every decision this
/// module makes that is not PDFium's — which page counts as textless, when the whole document is,
/// and where the output cap fires — and none of them should need a 7 MB shared library to prove.
///
/// The iterator is consumed lazily on purpose: see [`extract_text`].
fn assemble<I>(pages: I, page_count: u32, max_output_bytes: u64) -> ExtractOutcome
where
    I: IntoIterator<Item = core::result::Result<String, Refusal>>,
{
    let mut segments: Vec<Segment> = Vec::new();
    let mut without_text: Vec<u32> = Vec::new();
    let mut accounted: u64 = 0;

    for (index, page) in pages.into_iter().enumerate() {
        let text = match page {
            Ok(text) => normalize(&text),
            Err(refusal) => return ExtractOutcome::Refused(refusal),
        };

        // One-based, per `Coordinates::page_number` and `PageImages::page_image`. `saturating_add`
        // rather than a cast that could wrap: the page cap above bounds this far below `u32::MAX`,
        // and a page number that wrapped to zero would name a page no rasteriser can fetch.
        let number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        if text.is_empty() {
            without_text.push(number);
        }

        let segment = Segment {
            // Structural, so the chunker never merges two pages into one chunk. That is not a
            // presentation choice: `Coordinates` carries *one* page number, so a chunk spanning
            // pages 4 and 5 cites page 4 for text that is on page 5 — and a citation that
            // deep-links to the wrong page is worse than one that does not deep-link, because the
            // reader believes it. `docs/07 §2.2` already forbids crossing a slide boundary for the
            // same reason; a page is the paginated analogue.
            kind: SegmentKind::Page,
            text,
            coordinates: Coordinates { page_number: Some(number), ..Coordinates::none() },
        };

        // Charged *before* the push, so the vector is never grown past the cap and then measured.
        // The overhead term is what makes this bound a document of blank pages, whose text length is
        // zero however many of them there are.
        accounted = accounted.saturating_add(segment.accounted_bytes());
        if accounted > max_output_bytes {
            return ExtractOutcome::Refused(Refusal::OutputTooLarge);
        }
        segments.push(segment);
    }

    let document = TextDocument {
        segments,
        media_type: DECIDED_MEDIA_TYPE.to_owned(),
        // The page tree's count, not the number of segments built — they are equal here, and stating
        // the source's own number is what `BoundedExtractor`'s page check is entitled to read.
        page_count: Some(page_count),
        extractor_version: ExtractorVersion::new(EXTRACTOR),
    };

    // `TextDocument::is_empty` rather than a comparison of this module's own: *"no segment holds any
    // text"* is the definition `BoundedExtractor` applies from outside, and an extractor that
    // disagreed with its wrapper about which documents are textless would produce a `NoText` here and
    // an `Extracted` one call up, or the reverse.
    //
    // This is also the line that answers the mixed document: one page with words on it makes this
    // false, so a document with some text and some scanned pages is `Extracted`. The module
    // documentation argues why, and what that leaves undone.
    if document.is_empty() {
        return ExtractOutcome::NoText(TextlessSource {
            media_type: document.media_type,
            // Derived while walking the pages rather than recovered from the segments afterwards.
            // The same list `crate::pipeline`'s `textless` would produce, and it is built here so
            // that an unwrapped extractor still hands OCR a work list.
            pages_without_text: without_text,
        });
    }

    ExtractOutcome::Extracted(document)
}

/// Normalises one page's text, and reports a page with nothing on it as the empty string.
///
/// Three things happen, each of which is a decision:
///
/// - **Line endings collapse to `\n`.** `docs/07 §2` derives chunk IDs deterministically from chunk
///   text, so a document whose text layer carries `\r\n` and the same document carrying `\n` must not
///   chunk into two different sets of IDs. `text.rs` normalises for the identical reason.
/// - **`U+0000` is removed rather than refused.** `text.rs` treats a NUL as proof that the bytes are
///   not a text document and refuses the source, and that is right *there*, where the bytes are the
///   document: PostgreSQL's `text` cannot hold a NUL, so the file is not indexable however it
///   decodes. Here the string is not the file — it is what a parser made of the file — so a stray
///   NUL says something about PDFium's reconstruction of a glyph run and nothing about the document.
///   Refusing a ninety-page report because one character came back wrong would be a verdict on the
///   wrong party; dropping the character keeps the other eighty-nine pages indexable and still
///   guarantees `crate::store` is handed something PostgreSQL will accept.
/// - **A page of whitespace is empty.** The whole hand-off depends on this: `is_empty` on the
///   document is `text.is_empty()` per segment, not `trim().is_empty()`, so a page whose text layer
///   yields `" \n "` would count as text, the document would be `Extracted`, and OCR would never see
///   a scan that PDFium happened to return two spaces for.
fn normalize(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\0' => {}
            '\r' => {
                // `\r\n` is one break, not two. Written as a peek rather than two passes so the
                // string is walked once, which matters for a document whose text layer is tens of
                // megabytes.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            _ => out.push(character),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The pages of a document, as [`assemble`] wants them.
    fn pages(texts: &[&str]) -> Vec<core::result::Result<String, Refusal>> {
        texts.iter().map(|text| Ok((*text).to_owned())).collect()
    }

    fn assembled(texts: &[&str]) -> ExtractOutcome {
        let count = u32::try_from(texts.len()).expect("a small document");
        assemble(pages(texts), count, RenderBudget::DEFAULT.max_output_bytes)
    }

    #[test]
    fn the_media_types_claimed_are_matched_without_their_parameters() {
        assert!(supports("application/pdf"));
        assert!(supports("APPLICATION/PDF"));
        assert!(supports("application/pdf; version=1.7"));
        // Deliberate absences. `supports` is a routing hint, so a spelling nothing claims is
        // `SKIPPED` visibly rather than parsed on a guess.
        assert!(!supports("application/x-pdf"));
        assert!(!supports("image/png"));
        assert!(!supports("text/plain"));
        assert!(!supports(""));
    }

    /// [`Extractor::supports`] without a mounted library, which the check does not need.
    fn supports(declared: &str) -> bool {
        let essence = declared.split(';').next().unwrap_or_default().trim();
        SUPPORTED_MEDIA_TYPES.iter().any(|claimed| essence.eq_ignore_ascii_case(claimed))
    }

    #[test]
    fn a_page_of_text_becomes_one_segment_that_names_its_page() {
        // The positive control for every assertion below: without it, an `assemble` that produced
        // nothing at all would satisfy each of the absence checks that follow.
        let ExtractOutcome::Extracted(document) = assembled(&["first page", "second page"]) else {
            panic!("two pages of text are not textless");
        };

        assert_eq!(document.page_count, Some(2));
        assert_eq!(document.media_type, "application/pdf");
        assert_eq!(document.segments.len(), 2);
        for (index, segment) in document.segments.iter().enumerate() {
            assert_eq!(segment.kind, SegmentKind::Page);
            assert_eq!(
                segment.coordinates.page_number,
                Some(u32::try_from(index).expect("small") + 1),
                "a segment that cannot name its page is a citation nobody can navigate to"
            );
        }
        assert_eq!(document.segments[0].text, "first page");
        assert_eq!(document.segments[1].text, "second page");
    }

    #[test]
    fn a_document_whose_every_page_is_blank_is_textless_and_lists_all_of_them() {
        // The scan, and the whole reason this module exists. `Extracted` here would be D24's failure
        // mode: `READY` over an index holding nothing, and OCR never asked.
        match assembled(&["", "   \n  ", ""]) {
            ExtractOutcome::NoText(source) => {
                assert_eq!(source.media_type, "application/pdf");
                assert_eq!(source.pages_without_text, vec![1, 2, 3]);
            }
            other => panic!("a document of blank pages is not {other:?}"),
        }
    }

    #[test]
    fn a_mixed_document_is_extracted_and_keeps_the_blank_pages_that_name_themselves() {
        // The case that is neither of the other two. `NoText` would throw the typed pages away —
        // `OcrRetry` builds its document from what it recognised and nothing else — and a refusal
        // would be a verdict about a document that parsed. So: `Extracted`, by
        // `TextDocument::is_empty`'s own definition.
        //
        // The blank pages are still *in* the document with their numbers on them, which is what
        // leaves the gap closable: whoever writes the outcome that carries both a document and a
        // work list does not have to re-parse anything to find the pages.
        let ExtractOutcome::Extracted(document) = assembled(&["typed", "", "", "also typed"])
        else {
            panic!("a document with text on two of four pages is not textless");
        };

        assert!(!document.is_empty(), "one page with words on it makes a document non-empty");
        let blank: Vec<u32> = document
            .segments
            .iter()
            .filter(|segment| segment.text.is_empty())
            .filter_map(|segment| segment.coordinates.page_number)
            .collect();
        assert_eq!(blank, vec![2, 3], "the scanned pages are not identifiable from the document");
    }

    #[test]
    fn a_document_with_no_pages_at_all_is_textless_with_nothing_for_ocr_to_do() {
        // A page tree that parsed and holds nothing. Textless, and the work list is empty rather
        // than `[1]` — `OcrRetry` returns without asking the rasteriser for anything, which is the
        // honest answer for a document that has no page to rasterise.
        match assemble(Vec::new(), 0, RenderBudget::DEFAULT.max_output_bytes) {
            ExtractOutcome::NoText(source) => assert!(source.pages_without_text.is_empty()),
            other => panic!("a document with no pages is not {other:?}"),
        }
    }

    #[test]
    fn blank_pages_are_charged_against_the_output_cap_even_though_they_hold_no_text() {
        // The amplification, at the function that has to stop it: nine hundred blank pages are a few
        // kilobytes of file and nine hundred structs. Their text length is zero, so without
        // `SEGMENT_OVERHEAD_BYTES` this document's accounted size is zero and it passes every cap.
        let blank: Vec<&str> = vec![""; 900];
        let count = u32::try_from(blank.len()).expect("small");

        assert_eq!(
            assemble(pages(&blank), count, 1_024),
            ExtractOutcome::Refused(Refusal::OutputTooLarge)
        );

        // The positive control: the same pages under a cap that admits them are textless, not
        // refused. Without it this assertion passes against an `assemble` that refuses everything.
        assert!(matches!(assemble(pages(&blank), count, u64::MAX), ExtractOutcome::NoText(_)));
    }

    #[test]
    fn the_output_cap_fires_before_the_pages_past_it_are_read() {
        // "Checked before the push" is only worth something if the walk stops too — a cap that read
        // all nine hundred pages and then refused would have done the work it exists to prevent.
        let read = core::cell::Cell::new(0_u32);
        let lazy = (0..900).map(|_| {
            read.set(read.get() + 1);
            Ok("x".repeat(1_000))
        });

        assert_eq!(assemble(lazy, 900, 4_096), ExtractOutcome::Refused(Refusal::OutputTooLarge));
        assert!(read.get() < 900, "{} pages were read past the cap", read.get());
    }

    #[test]
    fn a_page_the_library_will_not_produce_refuses_the_document() {
        // A verdict, not a textless page: handing a malformed document to OCR as though it were a
        // scan would spend nine hundred rasterisations on a file that does not parse.
        let mut answers = pages(&["first page"]);
        answers.push(Err(Refusal::SourceUnreadable));
        answers.push(Ok("never read".to_owned()));

        assert_eq!(
            assemble(answers, 3, RenderBudget::DEFAULT.max_output_bytes),
            ExtractOutcome::Refused(Refusal::SourceUnreadable)
        );
    }

    #[test]
    fn line_endings_normalise_so_one_document_chunks_one_way() {
        // `docs/07 §2` derives chunk IDs from chunk text. If `\r\n` survived, the same document
        // produced by two writers would chunk into two different sets of IDs and the index would
        // hold both.
        assert_eq!(normalize("alpha\r\nbeta\rgamma\ndelta"), "alpha\nbeta\ngamma\ndelta");
    }

    #[test]
    fn a_nul_is_dropped_rather_than_stored() {
        // PostgreSQL's `text` cannot hold one, and `crate::store` is what would find that out — on
        // one file, at run time, as a `Storage` error that reads as a database problem.
        let normalized = normalize("inv\0oice");
        assert_eq!(normalized, "invoice");
        assert!(!normalized.contains('\0'));
    }

    #[test]
    fn a_page_of_whitespace_is_a_page_without_text() {
        // The hand-off depends on this exactly. `TextDocument::is_empty` asks `text.is_empty()`, not
        // `trim().is_empty()`, so a scan whose text layer returns two spaces would look like text,
        // the document would be `Extracted`, and OCR would never be asked.
        for blank in ["", " ", "\n\n", "\r\n \t"] {
            assert_eq!(normalize(blank), "", "{blank:?} is not a page with text on it");
        }
        // The positive control: text with whitespace around it survives.
        assert_eq!(normalize("  invoice  "), "invoice");
    }

    #[test]
    fn the_extractor_version_names_the_parser_the_lockfile_resolved() {
        // A patch release of `pdfium-render` changes extracted text while looking as though it could
        // not, and `docs/07 §3` compares this string to decide what needs reindexing.
        let lock = include_str!("../../../Cargo.lock");
        let resolved = lock
            .split_once("\nname = \"pdfium-render\"\nversion = \"")
            .expect("pdfium-render in the lockfile")
            .1
            .split_once('"')
            .expect("the version's closing quote")
            .0;

        assert!(
            EXTRACTOR.contains(&format!("pdfium-render-{resolved}")),
            "`{EXTRACTOR}` does not name pdfium-render-{resolved}: bump it, or the index keeps text \
             produced by the build this one replaced"
        );
    }
}
