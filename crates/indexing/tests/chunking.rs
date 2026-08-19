//! Chunking, and the determinism the whole indexing pipeline rests on.
//!
//! `docs/07-SEARCH-INDEXING.md §2`: a retried event must re-run stages without duplicating chunks.
//! Indexing is driven by an at-least-once outbox, so a retry is the ordinary case — and every test
//! here is about what happens on the second run.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_core::VersionId;
use enclave_indexing::chunk::{chunk_id, ChunkBudget, Chunker, ChunkerVersion};
use enclave_indexing::model::{Coordinates, Segment, SegmentKind};

fn chunker() -> Chunker {
    Chunker::new(ChunkerVersion::new("chunk/1"), ChunkBudget::DEFAULT)
}

fn segment(kind: SegmentKind, text: &str) -> Segment {
    Segment { kind, text: text.to_owned(), coordinates: Coordinates::default() }
}

fn prose(words: usize) -> String {
    "the quick brown fox jumps over the lazy dog. ".repeat(words)
}

/// The property the pipeline depends on: the same input yields the same ids, always.
///
/// Not "the same shape" — the same **identifiers**. A retried indexing run upserts because the ids
/// match; with random ones it inserts a second copy of every chunk and nothing ever removes the
/// first.
#[test]
fn the_same_version_and_chunker_always_produce_the_same_ids() {
    let version = VersionId::new_v7();
    let segments = vec![
        segment(SegmentKind::Paragraph, &prose(30)),
        segment(SegmentKind::Table, "a | b\n1 | 2"),
        segment(SegmentKind::Paragraph, &prose(30)),
    ];

    let first = chunker().chunk(version, &segments);
    let second = chunker().chunk(version, &segments);

    assert!(!first.is_empty(), "nothing was chunked, so nothing is proven");
    assert_eq!(first, second, "a second run produced different chunks");

    // And a fresh `Chunker` value, in case identity ever depended on instance state.
    let third = Chunker::new(ChunkerVersion::new("chunk/1"), ChunkBudget::DEFAULT)
        .chunk(version, &segments);
    assert_eq!(first, third);
}

/// A different version, or a different chunker, gives different ids.
///
/// The counterpart to the test above. If ids did not vary with the chunker, changing how text is
/// split would silently overwrite chunk 3's vector with an embedding of different text — the index
/// would hold a mixture of two schemes with no way to tell which was which.
#[test]
fn identity_changes_with_the_version_and_with_the_chunker() {
    let segments = vec![segment(SegmentKind::Paragraph, &prose(10))];
    let (a, b) = (VersionId::new_v7(), VersionId::new_v7());

    let for_a = chunker().chunk(a, &segments);
    let for_b = chunker().chunk(b, &segments);
    assert_ne!(for_a[0].id, for_b[0].id, "two versions share a chunk id");

    let other_chunker =
        Chunker::new(ChunkerVersion::new("chunk/2"), ChunkBudget::DEFAULT).chunk(a, &segments);
    assert_ne!(
        for_a[0].id, other_chunker[0].id,
        "a chunker change reused the old ids, so a reindex would overwrite chunk N's vector with \
         an embedding of different text"
    );
}

/// The separator in the id's name is load-bearing.
///
/// Without it, chunker `v1` ordinal `23` and chunker `v12` ordinal `3` hash the same bytes — one
/// chunk silently overwriting another's vector, in an index where nothing would ever notice.
#[test]
fn a_chunker_name_cannot_collide_with_an_ordinal() {
    let version = VersionId::new_v7();
    let ambiguous = chunk_id(version, ChunkerVersion::new("v1"), 23);
    let other = chunk_id(version, ChunkerVersion::new("v12"), 3);
    assert_ne!(ambiguous, other);
}

/// `docs/07 §2.2`: never across a table row group, slide or sheet-range boundary.
///
/// A chunk spanning two slides produces an excerpt that reads as one passage and came from two
/// places — and an excerpt is shown to a user as a quotation from a document.
#[test]
fn a_structural_boundary_is_never_crossed() {
    let version = VersionId::new_v7();
    // Small enough that a naive merger would happily combine all five.
    let segments = vec![
        segment(SegmentKind::Paragraph, "intro"),
        segment(SegmentKind::Slide, "slide one"),
        segment(SegmentKind::Slide, "slide two"),
        segment(SegmentKind::RowGroup, "1 | 2"),
        segment(SegmentKind::Paragraph, "outro"),
    ];

    let chunks = chunker().chunk(version, &segments);

    for chunk in &chunks {
        if chunk.kind == SegmentKind::Slide {
            assert!(
                !(chunk.text.contains("slide one") && chunk.text.contains("slide two")),
                "two slides were merged into one chunk: {:?}",
                chunk.text
            );
        }
        assert!(
            !(chunk.text.contains("slide") && chunk.text.contains("intro")),
            "a slide was merged with surrounding prose: {:?}",
            chunk.text
        );
    }

    // Both slides survived as their own chunks, so this did not pass by dropping them.
    let slides = chunks.iter().filter(|c| c.kind == SegmentKind::Slide).count();
    assert_eq!(slides, 2, "{chunks:#?}");
}

/// Prose *is* merged, or every paragraph becomes a chunk and the window means nothing.
#[test]
fn adjacent_prose_is_merged_up_to_the_window() {
    let version = VersionId::new_v7();
    let segments: Vec<Segment> =
        (0..8).map(|_| segment(SegmentKind::Paragraph, "a short paragraph.")).collect();

    let chunks = chunker().chunk(version, &segments);
    assert!(
        chunks.len() < segments.len(),
        "nothing was merged: {} chunks from {} paragraphs",
        chunks.len(),
        segments.len()
    );
}

/// No chunk exceeds the maximum, including after overlap is applied.
///
/// The overlap is the subtle one: applied by appending to the emitted chunk it would let every
/// chunk exceed `max_chars` by exactly the overlap, which is the bound the budget exists to hold.
#[test]
fn no_chunk_exceeds_the_maximum_however_long_the_source() {
    let version = VersionId::new_v7();
    let budget = ChunkBudget::DEFAULT;
    let chunker = Chunker::new(ChunkerVersion::new("chunk/1"), budget);

    let segments = vec![segment(SegmentKind::Paragraph, &prose(4_000))];
    let chunks = chunker.chunk(version, &segments);

    assert!(chunks.len() > 10, "a very long document produced {} chunks", chunks.len());
    for chunk in &chunks {
        assert!(
            chunk.text.len() <= budget.max_chars,
            "a chunk of {} exceeds the {} maximum",
            chunk.text.len(),
            budget.max_chars
        );
    }
}

/// Splitting a long run terminates, and covers it.
///
/// The loop that rewinds for overlap is the one that can fail to make progress. A budget whose
/// overlap approaches its window is a configuration a caller can write, and the failure mode is a
/// hung indexing worker rather than a bad chunk — so it is bounded rather than assumed.
#[test]
fn splitting_terminates_even_with_an_overlap_near_the_window() {
    let version = VersionId::new_v7();
    let hostile = ChunkBudget { target_chars: 100, max_chars: 120, overlap_chars: 118 };
    let chunker = Chunker::new(ChunkerVersion::new("chunk/1"), hostile);

    let chunks = chunker.chunk(version, &[segment(SegmentKind::Paragraph, &prose(200))]);
    assert!(!chunks.is_empty());
    for chunk in &chunks {
        assert!(chunk.text.len() <= hostile.max_chars);
    }
}

/// Text in any script survives, and does not panic the splitter.
///
/// Slicing a `&str` at a non-character boundary panics, and a chunker that panicked on a document
/// would take the indexing worker down with it — for every document, until somebody found the one
/// that did it.
#[test]
fn a_multibyte_document_is_split_without_panicking() {
    let version = VersionId::new_v7();
    let budget = ChunkBudget { target_chars: 60, max_chars: 80, overlap_chars: 10 };
    let chunker = Chunker::new(ChunkerVersion::new("chunk/1"), budget);

    for text in
        ["日本語のテキストです。".repeat(60), "مرحبا بالعالم ".repeat(60), "🙂🙃".repeat(200)]
    {
        let chunks = chunker.chunk(version, &[segment(SegmentKind::Paragraph, &text)]);
        assert!(!chunks.is_empty(), "nothing came out of a multibyte document");
        for chunk in &chunks {
            assert!(chunk.text.len() <= budget.max_chars);
            // The proof it cut on a boundary: it is still valid UTF-8, which `String` guarantees —
            // so the real assertion is that we got here without a panic.
            assert!(!chunk.text.is_empty());
        }
    }
}

/// Ordinals are dense and start at zero, because they are part of the identity.
#[test]
fn ordinals_are_dense_and_match_the_ids() {
    let version = VersionId::new_v7();
    let chunker = chunker();
    let chunks = chunker.chunk(version, &[segment(SegmentKind::Paragraph, &prose(300))]);

    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.ordinal as usize, index);
        assert_eq!(chunk.id, chunk_id(version, chunker.version(), chunk.ordinal));
    }
}

/// Empty and whitespace-only segments produce no chunks.
///
/// An empty chunk costs an embedding call and a vector, and matches nothing — it is spend with no
/// possible return.
#[test]
fn empty_segments_are_dropped_rather_than_embedded() {
    let version = VersionId::new_v7();
    let chunks = chunker().chunk(
        version,
        &[
            segment(SegmentKind::Paragraph, "   "),
            segment(SegmentKind::Paragraph, "\n\n"),
            segment(SegmentKind::Paragraph, "real text"),
        ],
    );
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].text, "real text");
}
