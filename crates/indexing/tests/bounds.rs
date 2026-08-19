//! The budget holds against an extractor that ignores it.
//!
//! Every extractor here is deliberately badly behaved, because a well-behaved one proves nothing:
//! `BoundedExtractor` exists for the case where the component reading hostile input is stuck,
//! wrong, or under someone else's control. A test whose extractor respects its budget is a test of
//! the extractor.
//!
//! The counterpart of `crates/preview/tests/bounds.rs`, deliberately so — the two files assert the
//! same four bounds because D24 says the two parsers run under one set of them. The bounds are
//! asserted separately rather than through one hostile extractor, so a regression names which one
//! stopped holding.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use async_trait::async_trait;
use enclave_indexing::{
    BoundedExtractor, Coordinates, ExtractOutcome, ExtractRequest, Extractor, ExtractorVersion,
    NoExtractor, Refusal, RenderBudget, Result, Segment, SegmentKind, TextDocument,
    SEGMENT_OVERHEAD_BYTES,
};

/// An extractor that does whatever it is told, however badly.
struct Rogue {
    /// How long to take, regardless of the budget it is handed.
    takes: Duration,
    /// How the document it hands back is built, however large.
    produces: fn() -> TextDocument,
}

#[async_trait]
impl Extractor for Rogue {
    fn extractor_version(&self) -> ExtractorVersion {
        ExtractorVersion::new("rogue/1")
    }

    fn supports(&self, _declared_media_type: &str) -> bool {
        true
    }

    async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
        // Note what is absent: this extractor never reads `request.budget`. That is the point.
        tokio::time::sleep(self.takes).await;
        Ok(ExtractOutcome::Extracted((self.produces)()))
    }
}

fn document(segments: Vec<Segment>, pages: Option<u32>) -> TextDocument {
    TextDocument {
        segments,
        media_type: "text/plain; charset=utf-8".to_owned(),
        page_count: pages,
        extractor_version: ExtractorVersion::new("rogue/1"),
    }
}

fn paragraph(text: &str) -> Segment {
    Segment {
        kind: SegmentKind::Paragraph,
        text: text.to_owned(),
        coordinates: Coordinates::none(),
    }
}

fn request(source: usize, budget: RenderBudget) -> ExtractRequest {
    ExtractRequest {
        declared_media_type: "text/plain".to_owned(),
        source: vec![b'a'; source],
        budget,
    }
}

/// The bound that matters most: an extractor that never returns must not hold the caller.
///
/// `start_paused` makes this deterministic rather than a race against a real clock — tokio
/// auto-advances time while every task is idle, so the extractor's hour and the budget's thirty
/// seconds resolve in the correct order without the test taking either.
#[tokio::test(start_paused = true)]
async fn an_extractor_that_hangs_is_refused_rather_than_awaited() {
    let budget = RenderBudget { wall_clock: Duration::from_secs(30), ..RenderBudget::DEFAULT };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::from_secs(3600),
        produces: || document(vec![paragraph("eventually")], None),
    });

    let outcome = extractor
        .extract(request(1024, budget))
        .await
        .expect("a hung extractor is a verdict, not an error");

    assert_eq!(outcome.refusal(), Some(Refusal::Timeout));
}

/// And the timeout is a *verdict*, not an error — the distinction D17 turns on.
///
/// If this arrived as `Err`, the caller's natural response is a retry, and a retry against a
/// document engineered to take forever is a denial-of-service primitive with a scheduler helping it
/// along.
#[tokio::test(start_paused = true)]
async fn a_timeout_never_arrives_in_the_error_channel() {
    let budget = RenderBudget { wall_clock: Duration::from_millis(1), ..RenderBudget::DEFAULT };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::from_secs(60),
        produces: || document(vec![paragraph("eventually")], None),
    });

    let result = extractor.extract(request(1, budget)).await;
    assert!(result.is_ok(), "a timeout became an error, which invites the retry it must not");
}

/// The extraction bomb: small going in, enormous coming out.
///
/// Not a decompression bomb — there is no compression here — but the same property measured where
/// extraction leaks it. Ten thousand empty segments carry no text at all, so a cap that counted
/// only characters would put this document's size at zero and pass it. `TextDocument::size_bytes`
/// charges the per-segment overhead precisely so the count is bounded too.
#[tokio::test]
async fn a_document_of_empty_segments_is_refused_however_little_text_it_holds() {
    let budget = RenderBudget {
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 64 * SEGMENT_OVERHEAD_BYTES,
        ..RenderBudget::DEFAULT
    };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        // One character of text between them, so this cannot pass as `NoText` instead.
        produces: || {
            let mut segments = vec![paragraph("x")];
            segments.extend((0..10_000).map(|_| paragraph("")));
            document(segments, None)
        },
    });

    let outcome =
        extractor.extract(request(16, budget)).await.expect("an oversized document is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

/// The same cap, reached the ordinary way.
#[tokio::test]
async fn a_document_over_the_output_cap_is_refused_however_small_its_source() {
    let budget = RenderBudget {
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 4096,
        ..RenderBudget::DEFAULT
    };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        produces: || document(vec![paragraph(&"x".repeat(8192))], None),
    });

    let outcome =
        extractor.extract(request(16, budget)).await.expect("an oversized document is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

/// The source is refused before the extractor is entered at all.
///
/// Asserted by giving the rogue extractor a document it would happily return: if the input check
/// ran after the call, this would come back `Extracted`.
#[tokio::test]
async fn an_oversized_source_is_refused_without_being_parsed() {
    let budget = RenderBudget { max_input_bytes: 128, ..RenderBudget::DEFAULT };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        produces: || document(vec![paragraph("parsed after all")], None),
    });

    let outcome =
        extractor.extract(request(129, budget)).await.expect("an oversized source is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::InputTooLarge));
}

/// The page cap applies to paginated sources.
#[tokio::test]
async fn a_paginated_source_over_the_page_cap_is_refused() {
    let budget = RenderBudget { max_pages: 10, ..RenderBudget::DEFAULT };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        produces: || document(vec![paragraph("page one")], Some(11)),
    });

    let outcome =
        extractor.extract(request(16, budget)).await.expect("too many pages is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::TooManyPages));
}

/// D24, enforced from outside the extractor rather than trusted to it.
///
/// A scanned document is the case: nine hundred page segments and not one character. An extractor
/// that hands that back as `Extracted` has described a source with no text whatever it believes it
/// did, and letting it through is how a manifest reaches `READY` with nothing behind it.
#[tokio::test]
async fn a_document_with_no_characters_cannot_be_returned_as_a_success() {
    // Above the default page cap on purpose. The bounds run before the emptiness check, so with
    // `RenderBudget::DEFAULT` a nine-hundred-page scan is `TooManyPages` and this test would assert
    // nothing about D24. That ordering is correct — a document over its bounds is refused whatever
    // it contains — and stating it here stops the next reader raising the cap in the wrapper
    // instead.
    let budget = RenderBudget { max_pages: 1_000, ..RenderBudget::DEFAULT };
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        produces: || document((0..900).map(|_| paragraph("")).collect(), Some(900)),
    });

    let outcome =
        extractor.extract(request(16, budget)).await.expect("a textless source is not a failure");

    match outcome {
        ExtractOutcome::NoText(textless) => {
            // The OCR work list, not merely a flag. Every page is named, in order, because an
            // engine that knows which three of nine hundred pages were blank does a nine-hundredth
            // of the work.
            assert_eq!(textless.pages_without_text.len(), 900);
            assert_eq!(textless.pages_without_text.first(), Some(&1));
            assert_eq!(textless.pages_without_text.last(), Some(&900));
        }
        other => panic!("an empty document was returned as {other:?}"),
    }
}

/// And that is not a refusal, which would be the wrong verdict entirely.
///
/// A refusal says re-running changes nothing. This is the one outcome where re-running — with OCR
/// configured — is exactly what changes it, so recording it as a refusal would make the scanned
/// document permanently unsearchable at the moment `ENC-161` shipped the thing that could read it.
#[tokio::test]
async fn a_textless_source_is_not_recorded_as_a_refusal() {
    let extractor = BoundedExtractor::new(Rogue {
        takes: Duration::ZERO,
        produces: || document(Vec::new(), Some(4)),
    });

    let outcome =
        extractor.extract(request(16, RenderBudget::DEFAULT)).await.expect("not an error");
    assert_eq!(outcome.refusal(), None);
    assert!(outcome.document().is_none());
}

/// A deployment with no extraction worker indexes nothing; it does not fall through.
///
/// The same deny-by-default shape as `NoRenderer`, and the shortcut it forecloses is worse here:
/// indexing a document's raw bytes as though they were text would put arbitrary binary content into
/// Milvus's `text` field, which `docs/07 §4` treats as sensitive storage because it holds a copy of
/// the content.
#[tokio::test]
async fn the_default_extractor_extracts_nothing() {
    let extractor = BoundedExtractor::new(NoExtractor);
    for claimed in ["text/plain", "application/pdf", "image/png", ""] {
        assert!(!extractor.supports(claimed), "`{claimed}` was claimed with no worker present");
    }

    let outcome = extractor
        .extract(request(16, RenderBudget::DEFAULT))
        .await
        .expect("refusing is not failing");
    assert_eq!(outcome.refusal(), Some(Refusal::UnsupportedFormat));
}
