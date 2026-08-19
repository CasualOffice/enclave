//! The first extractor in this crate that produces text: UTF-8 sources in, paragraphs out.
//!
//! # Encoding is a security boundary, not a nicety
//!
//! The rule is **UTF-8 or a refusal**. No lossy replacement, no charset detection, no honouring of
//! a declared `charset` parameter. Three reasons, and the first is the one that makes this a
//! control rather than a preference.
//!
//! **1. Two decoders that disagree produce two documents.** Preview and download hand a browser the
//! original bytes, and the browser decodes them by its own rules — BOM, `<meta charset>`, its own
//! detector. If indexing decodes by a different rule, the indexed text is not the displayed text,
//! and every decision made downstream of it is made about a document nobody can see: the DLP
//! pre-scan of `docs/07 §2`, the detected classification label, the excerpt a result shows. The
//! concrete form is unglamorous. `String::from_utf8_lossy` replaces each maximal invalid subpart
//! with one `U+FFFD`, so a Latin-1 `café` indexes as `caf<FFFD>`; a DLP pattern anchored on a word
//! boundary stops matching text a viewer reads plainly, and the miss looks like the rule not firing
//! rather than like an encoding problem.
//!
//! **2. Guessing *is* the differential.** A charset detector is a second independent guess sitting
//! next to the browser's, and confusable Shift-JIS, Latin-1 and UTF-8 byte sequences are an
//! established way to make one consumer read different text from another. Adding a detector here
//! would make ours the third opinion. If a charset is ever honoured it must be the *declared* one,
//! taken from the same string the delivery path puts in its `Content-Type`, so that the two
//! consumers are decoding by one rule — that is a decision with a tracker row, not something to
//! fold into an extractor.
//!
//! **3. `U+0000` is not storable.** PostgreSQL's `text` type cannot hold a NUL, so content
//! containing one is not indexable however it decodes; stripping it quietly is reason 1 in
//! miniature. A NUL anywhere in the source is therefore taken as proof that these bytes are not a
//! text document — which also catches, *before any decode*, a BOM-less UTF-16 file and any binary
//! misdeclared as `text/plain`, both of which are dense with them.
//!
//! Which refusal a source earns is deliberate:
//!
//! - A UTF-16 or UTF-32 byte-order mark is [`Refusal::UnsupportedFormat`]. We know exactly what the
//!   file is and have no decoder for it, and the action is to ship one.
//! - Invalid UTF-8 with no mark is [`Refusal::SourceUnreadable`] — it declared itself text and did
//!   not decode, which is that variant's definition.
//!
//! Keeping those apart is the argument `crates/preview/src/budget.rs` makes for distinct codes:
//! "we should ship a UTF-16 decoder" and "somebody is feeding us corrupt files" are different
//! operational signals and must not merge into one count.
//!
//! A UTF-8 BOM is stripped rather than kept. Left in place it becomes a `U+FEFF` at the head of the
//! first segment, where it is invisible in every log and every diff and quietly makes the first
//! token of the document unmatchable.
//!
//! # The order is the raster order; the sniff is the opposite polarity
//!
//! `crates/preview/src/raster.rs` fixes sniff → header → decide → parse, and this module keeps it:
//!
//! 1. **Sniff.** Byte-order marks and a NUL scan decide whether these bytes will be handed to a
//!    decoder at all.
//! 2. **Decide.** The decoded text cannot be larger than the source (UTF-8 in, UTF-8 out; the BOM
//!    only shrinks it), so the output cap is checked against the source length before decoding, and
//!    again as a running total while segments are built.
//! 3. **Decode**, strictly, once.
//! 4. **Segment**, against that running total, so the vector is never grown past the cap and then
//!    measured.
//!
//! What differs is the sniff's polarity, and it is worth stating because "sniff first" copied
//! without this observation becomes a sniff that always returns true. Raster matches magic bytes
//! against a closed allowlist. Text has no signature — that is what *plain* means — so there is
//! nothing to allowlist, and this sniff instead looks for evidence the bytes are **not** text.
//! Everything else goes to a strict decoder, which is itself the check that they were.
//!
//! # What is deliberately not claimed
//!
//! **`text/csv` and `application/json`.** `docs/07 §2.1` wants a structured reader whose chunk
//! boundaries are row groups and key paths. Emitting a spreadsheet export as prose paragraphs would
//! index it badly under a manifest that says `READY`, and nobody looks at a `READY` manifest again.
//!
//! **`text/html`.** `docs/07 §2.1` requires HTML to be sanitized before extraction. Running tag
//! soup through this would put script bodies and stylesheets into Milvus's `text` field, and a
//! search for a common word would return every page carrying the same analytics snippet.
//!
//! **Markdown structure.** `text/markdown` *is* claimed, and extracted as prose: all of the text is
//! there and only the heading trail is lost. A markdown-aware extractor emits
//! [`SegmentKind::Section`] with a `section_path`, and it is an [`ExtractorVersion`] bump away —
//! which is precisely what makes `docs/07 §3` reindex what this build produced.
//!
//! # Why every byte of this runs on `spawn_blocking`
//!
//! `CLAUDE.md` forbids blocking calls in async contexts, and here the reason is sharper than
//! throughput. [`BoundedExtractor`](crate::BoundedExtractor)'s wall clock is `tokio::time::timeout`,
//! which stops polling a future — it cannot interrupt a thread already inside synchronous work, and
//! validating and segmenting half a gigabyte of text is exactly that. On the runtime's poll thread
//! a large source would stall the executor and the budget would expire with nobody able to act on
//! it. It is not the process isolation D17 asks for, and this module does not pretend otherwise.

use async_trait::async_trait;
use enclave_preview::{Refusal, RenderBudget};

use crate::error::{IndexingError, Result};
use crate::extract::{ExtractOutcome, ExtractRequest, Extractor, TextlessSource};
use crate::model::{Coordinates, ExtractorVersion, Segment, SegmentKind, TextDocument};

/// Which build this is, in the form [`Extractor::extractor_version`] requires.
///
/// One component, unlike `raster.rs`'s two, because there is no third-party parser to pin: the
/// decoder is `core::str::from_utf8` and the definition of UTF-8 does not move. When a format
/// arrives that needs an external parser, its resolved version belongs in this string the way
/// `raster.rs` pins `image`, and for the same reason — a patch release of a parser is exactly the
/// kind of change that alters output while looking as though it could not.
const EXTRACTOR: &str = "text/1";

/// The declared media types this extractor is asked about.
///
/// A closed list, and short on purpose. See the module documentation for what is missing and why
/// each absence is a decision.
const SUPPORTED_MEDIA_TYPES: &[&str] = &["text/plain", "text/markdown"];

/// What this extractor reports having established about the bytes.
///
/// Not the declared type. The only fact this extractor verified is that the source is UTF-8 text,
/// so that is what it states; carrying `text/markdown` forward would be echoing a claim it never
/// checked, to a downstream consumer that would then trust it.
const DECIDED_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// The UTF-8 byte-order mark: stripped, never indexed.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Byte-order marks that identify an encoding this build does not decode.
///
/// Ordered longest-first, and that ordering is load-bearing: UTF-32LE opens `FF FE 00 00`, whose
/// first two bytes are the whole of the UTF-16LE mark. Matched the other way round, a UTF-32 file
/// would be reported as UTF-16 — harmless today, since both are one refusal, and a latent
/// mis-diagnosis the moment either gains a decoder.
const IDENTIFIED_BUT_UNDECODABLE: &[&[u8]] = &[
    &[0xFF, 0xFE, 0x00, 0x00], // UTF-32LE
    &[0x00, 0x00, 0xFE, 0xFF], // UTF-32BE
    &[0xFF, 0xFE],             // UTF-16LE
    &[0xFE, 0xFF],             // UTF-16BE
];

/// Extracts UTF-8 text, in process, on a blocking thread.
///
/// Holds no configuration, no client and no handle to anything — a field could hold a store, and
/// the no-egress property of [`crate::extract`] is worth more than the flexibility.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainTextExtractor;

#[async_trait]
impl Extractor for PlainTextExtractor {
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

        match tokio::task::spawn_blocking(move || extract_utf8(&source, budget)).await {
            Ok(outcome) => Ok(outcome),
            // A parser that panics has made a statement about the document: the same bytes panic
            // the same way every time, so this is a verdict and recording it is correct. Reporting
            // it as ours would invite the retry, and a file that reliably kills a worker thread is
            // a denial-of-service primitive the moment a scheduler is willing to run it again.
            Err(join) if join.is_panic() => Ok(ExtractOutcome::Refused(Refusal::SourceUnreadable)),
            // Cancellation is not about the document. The runtime is shutting down or the task was
            // aborted, and answering "this file has no text" would record an outage as an absence.
            Err(join) => Err(IndexingError::Worker(anyhow::Error::new(join))),
        }
    }
}

/// The whole synchronous pipeline, in the order the module documentation fixes.
///
/// Returns an outcome rather than a `Result` because nothing in it can fail on our side: there is
/// no encoder to break, no buffer to fail to write. Everything the source is responsible for is a
/// [`Refusal`] or a [`TextlessSource`].
fn extract_utf8(source: &[u8], budget: RenderBudget) -> ExtractOutcome {
    let Some(body) = sniff(source) else {
        return ExtractOutcome::Refused(Refusal::UnsupportedFormat);
    };

    // The decoded text is the same bytes, so the source length is the exact size the decode would
    // hold — the counterpart of raster's `total_bytes()`, and checked in the same position: before
    // anything owns it. It is not the whole bound. Segments carry per-unit overhead the text length
    // says nothing about, which is why `segment` re-checks as it goes.
    if body.len() as u64 > budget.max_output_bytes {
        return ExtractOutcome::Refused(Refusal::OutputTooLarge);
    }

    let Ok(text) = core::str::from_utf8(body) else {
        // Not lossy, not sniffed, not retried with another decoder. See the module documentation:
        // the second decoder is where the indexed text and the displayed text come apart.
        return ExtractOutcome::Refused(Refusal::SourceUnreadable);
    };

    let Some(segments) = segment(text, budget.max_output_bytes) else {
        return ExtractOutcome::Refused(Refusal::OutputTooLarge);
    };

    if segments.is_empty() {
        // A file of nothing but whitespace. `BoundedExtractor` would reach the same conclusion from
        // outside, but an extractor that is only correct inside its wrapper is one that will be
        // used unwrapped by someone who did not read this comment.
        return ExtractOutcome::NoText(TextlessSource {
            media_type: DECIDED_MEDIA_TYPE.to_owned(),
            // Nothing to hand OCR: a text file has no pages an image pipeline could look at.
            pages_without_text: Vec::new(),
        });
    }

    ExtractOutcome::Extracted(TextDocument {
        segments,
        media_type: DECIDED_MEDIA_TYPE.to_owned(),
        // Plain text has no pagination, so there is nothing for the page cap to apply to — the
        // same `None` a thumbnail reports, and for the same reason.
        page_count: None,
        extractor_version: ExtractorVersion::new(EXTRACTOR),
    })
}

/// Decides whether these bytes are handed to the decoder, and where the text starts.
///
/// `Some(body)` means "decode this as UTF-8"; `None` is [`Refusal::UnsupportedFormat`]. The two
/// `None` cases — an identified encoding we do not decode, and a NUL that says this is not text at
/// all — share a code deliberately: both are answered by shipping a parser, and neither says
/// anything about the file being corrupt.
fn sniff(source: &[u8]) -> Option<&[u8]> {
    if IDENTIFIED_BUT_UNDECODABLE.iter().any(|mark| source.starts_with(mark)) {
        return None;
    }

    // Whole input, not a prefix. The scan is one pass over bytes the decoder is about to walk
    // anyway, and a bound that only holds where we happened to look is one file away from not
    // holding — a UTF-16 document with a long ASCII preamble would sail past a prefix check and
    // then fail to store.
    if source.contains(&0x00) {
        return None;
    }

    Some(source.strip_prefix(UTF8_BOM).unwrap_or(source))
}

/// Splits text into paragraphs, refusing rather than growing past the cap.
///
/// `None` is [`Refusal::OutputTooLarge`]. The running total is checked *before* each push, so the
/// vector is never grown past the cap and measured afterwards — which is the same "decide before
/// allocating" the raster path applies to its pixel buffer, applied to the one thing extraction
/// allocates without bound.
fn segment(text: &str, max_output_bytes: u64) -> Option<Vec<Segment>> {
    let mut segments = Vec::new();
    let mut accounted: u64 = 0;
    let mut paragraph = String::new();

    // `str::lines` splits on `\n` and on `\r\n`, dropping the carriage return. That normalisation
    // is worth having deliberately: the same document authored on Windows and on Linux must produce
    // the same segments, or `docs/07 §2`'s deterministic chunk IDs differ between two copies of one
    // file and the index holds both.
    for line in text.lines() {
        if line.trim().is_empty() {
            if !flush(&mut paragraph, &mut segments, &mut accounted, max_output_bytes) {
                return None;
            }
            continue;
        }
        if !paragraph.is_empty() {
            paragraph.push('\n');
        }
        // Not trimmed. Leading whitespace is indentation, and indentation is meaning in both of the
        // formats this extractor claims.
        paragraph.push_str(line);
    }

    flush(&mut paragraph, &mut segments, &mut accounted, max_output_bytes).then_some(segments)
}

/// Emits the paragraph under construction, or reports that doing so would exceed the cap.
fn flush(
    paragraph: &mut String,
    segments: &mut Vec<Segment>,
    accounted: &mut u64,
    max_output_bytes: u64,
) -> bool {
    if paragraph.is_empty() {
        return true;
    }

    let segment = Segment {
        kind: SegmentKind::Paragraph,
        text: core::mem::take(paragraph),
        // Plain text has no interior geography. `None` rather than a synthesised page 1: a citation
        // that deep-links to a page the format does not have is believed by whoever reads it.
        coordinates: Coordinates::none(),
    };

    *accounted = accounted.saturating_add(segment.accounted_bytes());
    if *accounted > max_output_bytes {
        return false;
    }

    segments.push(segment);
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_media_types_claimed_are_matched_without_their_parameters() {
        assert!(PlainTextExtractor.supports("text/plain"));
        assert!(PlainTextExtractor.supports("text/plain; charset=utf-8"));
        assert!(PlainTextExtractor.supports("TEXT/PLAIN"));
        assert!(PlainTextExtractor.supports("text/markdown"));
        // The deliberate absences. Each is a format `docs/07 §2.1` wants read a different way, and
        // claiming one here would index it badly under a manifest that says it succeeded.
        assert!(!PlainTextExtractor.supports("text/csv"));
        assert!(!PlainTextExtractor.supports("text/html"));
        assert!(!PlainTextExtractor.supports("application/json"));
        assert!(!PlainTextExtractor.supports("application/pdf"));
        assert!(!PlainTextExtractor.supports(""));
    }

    #[test]
    fn a_utf8_bom_is_stripped_and_the_others_are_refused() {
        let mut with_bom = UTF8_BOM.to_vec();
        with_bom.extend_from_slice(b"hello");
        assert_eq!(sniff(&with_bom), Some(&b"hello"[..]));

        // An ASCII payload, so that for the two-byte marks the *mark* is the only thing that can
        // refuse this — a UTF-16-shaped payload would trip the NUL scan and prove nothing.
        for mark in IDENTIFIED_BUT_UNDECODABLE {
            let mut source = mark.to_vec();
            source.extend_from_slice(b"hello");
            assert_eq!(sniff(&source), None, "a {mark:02X?} mark reached the decoder");
        }
    }

    #[test]
    fn utf32_is_not_mistaken_for_utf16() {
        // The ordering the constant's comment claims. `FF FE 00 00` contains the UTF-16LE mark as
        // its first two bytes, so a shortest-first table would report the wrong encoding — one
        // refusal today, and a wrong decoder the moment either gains one.
        let longest = IDENTIFIED_BUT_UNDECODABLE[0];
        assert_eq!(longest, &[0xFF, 0xFE, 0x00, 0x00]);
        assert!(IDENTIFIED_BUT_UNDECODABLE.windows(2).all(|pair| pair[0].len() >= pair[1].len()));
    }

    #[test]
    fn a_nul_anywhere_means_these_bytes_are_not_a_text_document() {
        // Not a prefix scan. A BOM-less UTF-16 file with a long ASCII preamble is the case that
        // defeats one, and PostgreSQL refuses the NUL wherever in the string it turns up.
        let mut source = vec![b'a'; 64 * 1024];
        source.push(0x00);
        assert_eq!(sniff(&source), None);
    }

    #[test]
    fn segmentation_bounds_the_count_and_not_only_the_characters() {
        // The amplification, at the function that has to stop it: 20,000 blank-separated `x`s are
        // 40 kB of text and 20,000 segments. With a cap of 1,000 bytes the text alone would pass.
        let text = "x\n\n".repeat(20_000);
        assert!(text.len() as u64 > 1_000);
        assert_eq!(segment(&text, 1_000), None);
    }

    #[test]
    fn a_paragraph_keeps_its_interior_line_breaks_and_its_indentation() {
        let segments = segment("  one\n  two\n\nthree", u64::MAX).expect("within the cap");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].text, "  one\n  two");
        assert_eq!(segments[1].text, "three");
    }

    #[test]
    fn crlf_and_lf_produce_identical_segments() {
        // `docs/07 §2` derives chunk IDs deterministically. If line endings survived into the text,
        // one document checked out on two platforms would chunk into two different sets of IDs and
        // the index would hold both.
        let lf = segment("alpha\nbeta\n\ngamma", u64::MAX).expect("within the cap");
        let crlf = segment("alpha\r\nbeta\r\n\r\ngamma", u64::MAX).expect("within the cap");
        assert_eq!(lf, crlf);
    }
}
