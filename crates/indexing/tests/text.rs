//! `PlainTextExtractor` end to end: what it extracts, and every byte sequence it refuses.
//!
//! Most of this file is about encoding, which is the point. A byte sequence that decodes one way
//! here and another way in a browser is how the indexed text and the displayed text come apart, and
//! from there every DLP match, classification label and result excerpt is a statement about a
//! document nobody can see. `crates/indexing/src/text.rs` argues it; these are the assertions that
//! hold the argument in place.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_indexing::{
    BoundedExtractor, ExtractOutcome, ExtractRequest, Extractor, PlainTextExtractor, Refusal,
    RenderBudget, SegmentKind, TextDocument, SEGMENT_OVERHEAD_BYTES,
};

/// Runs the real extractor inside the real wrapper, which is the only configuration that ships.
async fn extract(declared: &str, source: Vec<u8>, budget: RenderBudget) -> ExtractOutcome {
    BoundedExtractor::new(PlainTextExtractor)
        .extract(ExtractRequest { declared_media_type: declared.to_owned(), source, budget })
        .await
        .expect("nothing about a document is an error")
}

fn expect_document(outcome: ExtractOutcome) -> TextDocument {
    match outcome {
        ExtractOutcome::Extracted(document) => document,
        other => panic!("expected text, got {other:?}"),
    }
}

/// The real extraction, asserted on its *content* rather than on something having come back.
///
/// A test that only checks `is_extracted()` passes against an extractor that returns a fixed
/// paragraph for every input.
#[tokio::test]
async fn a_text_source_extracts_to_the_paragraphs_it_is_written_in() {
    let source = "Retention policy\n\nRecords are held for seven years.\nDisposition runs \
                  nightly.\n\n\n  Exceptions are approved by Legal.\n";

    let document =
        expect_document(extract("text/plain", source.into(), RenderBudget::DEFAULT).await);

    assert_eq!(document.segments.len(), 3, "blank lines separate paragraphs; runs of them do not");
    assert_eq!(document.segments[0].text, "Retention policy");
    // Interior newlines survive inside a paragraph, so a sentence split across two source lines is
    // one run of text and not two chunks that each half-match a query.
    assert_eq!(
        document.segments[1].text,
        "Records are held for seven years.\nDisposition runs nightly."
    );
    // Indentation is meaning in both formats this extractor claims, so it is not trimmed away.
    assert_eq!(document.segments[2].text, "  Exceptions are approved by Legal.");

    assert!(document.segments.iter().all(|s| s.kind == SegmentKind::Paragraph));
    // No pagination in a text file, so there is nothing for the page cap to apply to.
    assert_eq!(document.page_count, None);
    assert_eq!(document.extractor_version.as_str(), "text/1");
    assert!(document.flatten().contains("seven years"));
}

/// The media type comes from what the extractor established, never from what the uploader claimed.
///
/// The same refusal-to-believe that `crates/preview/src/raster.rs` applies to its sources. The one
/// fact this extractor verified is that the bytes are UTF-8 text; echoing `text/markdown` forward
/// would hand a downstream markdown-aware consumer a claim nobody checked.
#[tokio::test]
async fn the_declared_media_type_is_not_echoed_into_the_document() {
    let document = expect_document(
        extract("text/markdown", "# Heading\n\nBody.".into(), RenderBudget::DEFAULT).await,
    );

    assert_eq!(document.media_type, "text/plain; charset=utf-8");
    // Markdown is extracted as prose today: all of the text is present and only the heading trail
    // is lost. A markdown-aware extractor emits `Section` with a `section_path`, behind a version
    // bump that makes `docs/07 §3` reindex what this build produced.
    assert_eq!(document.segments[0].text, "# Heading");
}

/// Invalid UTF-8 is a verdict, and the text is never repaired into something plausible.
///
/// `café` in Latin-1. `String::from_utf8_lossy` would index `caf<FFFD>`, which reads as a word to
/// nobody and matches as a word for nobody — while the same file, downloaded, shows `café` in the
/// viewer's browser. That divergence is the whole reason this refuses.
#[tokio::test]
async fn latin1_bytes_are_refused_rather_than_replaced() {
    let outcome = extract("text/plain", b"caf\xE9 receipts".to_vec(), RenderBudget::DEFAULT).await;

    assert_eq!(outcome.refusal(), Some(Refusal::SourceUnreadable));
    assert!(outcome.document().is_none(), "a lossy decode produced a document anyway");
}

/// A source truncated mid-character is a verdict too, and never a panic or an `Err`.
///
/// The last two bytes of a three-byte `€` — the shape a file cut off by a failed upload takes.
#[tokio::test]
async fn a_source_truncated_mid_character_is_refused_as_a_verdict() {
    let mut source = "price: ".as_bytes().to_vec();
    source.extend_from_slice(&"€".as_bytes()[..2]);

    let result = BoundedExtractor::new(PlainTextExtractor)
        .extract(ExtractRequest {
            declared_media_type: "text/plain".to_owned(),
            source,
            budget: RenderBudget::DEFAULT,
        })
        .await;

    // Asserted on the `Result` and not through the helper: the property is that a corrupt document
    // never reaches the error channel, where it would become a retry.
    let outcome = result.expect("a corrupt source is a verdict, not an error");
    assert_eq!(outcome.refusal(), Some(Refusal::SourceUnreadable));
}

/// An encoding we can name and cannot read is `UnsupportedFormat`, not `SourceUnreadable`.
///
/// The distinction `crates/preview/src/budget.rs` insists on for its own codes: "ship a UTF-16
/// decoder" and "somebody is feeding us corrupt files" are different operational signals, and one
/// metric holding both is a metric that answers neither.
#[tokio::test]
async fn a_utf16_source_is_refused_as_an_unsupported_format() {
    // "hi" in UTF-16LE, byte-order mark and all.
    let source = vec![0xFF, 0xFE, b'h', 0x00, b'i', 0x00];

    let outcome = extract("text/plain", source, RenderBudget::DEFAULT).await;
    assert_eq!(outcome.refusal(), Some(Refusal::UnsupportedFormat));
}

/// A UTF-8 mark is stripped, so the first token of the document is matchable.
///
/// Left in place, `U+FEFF` is invisible in every log and every diff and makes the first word of the
/// file unfindable — a bug that survives review because the evidence for it cannot be seen.
#[tokio::test]
async fn a_utf8_byte_order_mark_never_reaches_the_index() {
    let mut source = vec![0xEF, 0xBB, 0xBF];
    source.extend_from_slice(b"Quarterly report");

    let document = expect_document(extract("text/plain", source, RenderBudget::DEFAULT).await);

    assert_eq!(document.segments[0].text, "Quarterly report");
    assert!(!document.flatten().contains('\u{FEFF}'));
}

/// A NUL byte means these bytes are not a text document, wherever in the source it appears.
///
/// Two things at once: PostgreSQL's `text` cannot store `U+0000`, so this content is not indexable
/// however it decodes; and a BOM-less UTF-16 file or a binary misdeclared as `text/plain` announces
/// itself this way, before any decoder is handed it.
#[tokio::test]
async fn a_nul_byte_deep_in_an_otherwise_valid_source_refuses_it() {
    let mut source = "a".repeat(32 * 1024).into_bytes();
    source.push(0x00);
    source.extend_from_slice(b"more text");

    let outcome = extract("text/plain", source, RenderBudget::DEFAULT).await;
    assert_eq!(outcome.refusal(), Some(Refusal::UnsupportedFormat));
}

/// A source of nothing but whitespace is textless, not refused and not an empty success.
///
/// D24's arm, reached by the real extractor. There is nothing here for OCR either, and the empty
/// work list says so rather than implying pages that do not exist.
#[tokio::test]
async fn a_whitespace_only_source_is_reported_as_textless() {
    let outcome = extract("text/plain", "\n\n   \n\t\n".into(), RenderBudget::DEFAULT).await;

    match outcome {
        ExtractOutcome::NoText(textless) => {
            assert_eq!(textless.media_type, "text/plain; charset=utf-8");
            assert!(textless.pages_without_text.is_empty(), "a text file has no pages to OCR");
        }
        other => panic!("expected a textless source, got {other:?}"),
    }
}

/// The bomb the real extractor can be handed: tiny text, enormous structure.
///
/// A quarter of a megabyte of blank-separated single characters is 60,000 segments. Against a cap
/// of 4 KiB the *characters* are already over — so the cap is set above the text and below the
/// structure, which is the only setting that proves the count is bounded rather than the bytes.
#[tokio::test]
async fn a_source_that_expands_into_structure_is_refused_before_the_vector_grows() {
    let source = "x\n\n".repeat(60_000);
    let text_bytes = 60_000_u64; // one character per segment
    let budget = RenderBudget {
        max_output_bytes: 8 * text_bytes,
        max_input_bytes: 1024 * 1024,
        ..RenderBudget::DEFAULT
    };
    // The premise: text alone passes this cap, and 60,000 segments of overhead cannot.
    assert!(text_bytes < budget.max_output_bytes);
    assert!(60_000 * SEGMENT_OVERHEAD_BYTES > budget.max_output_bytes);

    let outcome = extract("text/plain", source.into(), budget).await;
    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

/// And the ordinary oversized source is refused before it is decoded at all.
#[tokio::test]
async fn a_source_larger_than_the_output_cap_is_refused_before_decoding() {
    let budget = RenderBudget {
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 1024,
        ..RenderBudget::DEFAULT
    };

    let outcome = extract("text/plain", vec![b'a'; 4096], budget).await;
    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

/// The formats this extractor declines, asserted through the port rather than the unit.
///
/// `supports` is what the pipeline routes on, and a `false` here means the source is never fetched
/// — an unhandled type costs no object-storage read.
#[tokio::test]
async fn the_formats_docs_07_wants_read_differently_are_not_claimed() {
    let extractor = BoundedExtractor::new(PlainTextExtractor);

    assert!(extractor.supports("text/plain; charset=utf-8"));
    assert!(extractor.supports("text/markdown"));
    // CSV and JSON want the structured reader of `docs/07 §2.1`, whose chunk boundaries are row
    // groups and key paths; HTML must be sanitized before extraction, or script bodies and
    // stylesheets land in Milvus's `text` field.
    for declined in ["text/csv", "text/html", "application/json", "application/pdf", "image/png"] {
        assert!(!extractor.supports(declined), "`{declined}` was claimed");
    }
}
