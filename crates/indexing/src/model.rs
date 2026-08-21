//! What an extraction produces: text, the structure it was found in, and the version of the build
//! that found it.
//!
//! # Structure is not decoration
//!
//! `docs/07-SEARCH-INDEXING.md §2.2` chunks along structural boundaries and keeps each chunk's
//! source coordinates, so a result can deep-link and a RAG answer can cite a place a person is able
//! to navigate to. That only works if extraction hands chunking the boundaries in the first place —
//! text flattened to one string has already lost them, and no later stage can recover a slide
//! number from a paragraph.
//!
//! [`SegmentKind`] therefore mirrors `§2.2`'s chunk vocabulary rather than inventing a second one.
//! Any single extractor emits a subset; the members it cannot produce are not omissions but formats
//! that have not arrived.
//!
//! # Why a segment is charged more than the bytes it holds
//!
//! This is the one place extraction's bound genuinely differs in *shape* from rendering's, and
//! [`TextDocument::size_bytes`] is where the difference is absorbed rather than forked. A raster
//! rendition is a single buffer whose size is `width × height × channels`, so bounding the buffer
//! bounds the output. Extraction's output is a *collection*, and its size is not a function of the
//! text length: ten million blank lines are ten megabytes going in and ten million structs coming
//! out. Small going in, enormous coming out — which is the same property
//! [`RenderBudget::max_output_bytes`](enclave_preview::RenderBudget::max_output_bytes) already
//! exists to bound, measured at a different place.
//!
//! So each segment is charged its text plus [`SEGMENT_OVERHEAD_BYTES`], and one existing knob
//! bounds both directions of the amplification. A second knob for the same attack is a knob
//! somebody sets inconsistently.

use core::fmt;

/// What a segment costs before it holds any text.
///
/// Not `size_of::<Segment>()`, which varies by target and moves whenever a field is added — a
/// floor, chosen so that a document made entirely of empty segments is charged roughly what a
/// million of them actually cost in a `Vec`, three `Option`s and a `String` allocation each.
///
/// Being approximate is fine and being *present* is not: without this term a bomb of ten million
/// blank lines has an accounted size of zero and passes every check in the crate.
pub const SEGMENT_OVERHEAD_BYTES: u64 = 128;

/// Which build of the extraction pipeline produced a document.
///
/// `docs/07 §3` lists an extractor change as a full-pipeline reindex trigger, so this string is
/// what makes that trigger fire. It is deliberately *not*
/// [`GeneratorVersion`](enclave_preview::GeneratorVersion), whose job is a cache key: a rendition
/// keyed by an old generator is a miss and is regenerated on demand, whereas an index built by an
/// old extractor is wrong until someone reindexes it. One is lazy and self-healing, the other is a
/// batch job with embedding spend attached, and giving them one type would invite the assumption
/// that they are managed the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtractorVersion(&'static str);

impl ExtractorVersion {
    /// Names an extractor build.
    ///
    /// `&'static str` so a version cannot be assembled from a runtime value. A generation marker
    /// computed at run time is one that differs between two replicas of the same deployment, and
    /// the reindex it triggers never converges.
    #[must_use]
    pub const fn new(version: &'static str) -> Self {
        Self(version)
    }

    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ExtractorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// The structural role of a run of text, from `docs/07 §2.2`'s chunk vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SegmentKind {
    /// The whole source, for formats with no interior structure to speak of.
    Document,
    /// A heading and the text beneath it.
    Section,
    /// A run of prose.
    Paragraph,
    /// A table, whole.
    Table,
    /// A band of rows, for tables too large to keep whole.
    RowGroup,
    /// A named range of a spreadsheet.
    SheetRange,
    /// One slide of a deck.
    Slide,
    /// One page of a paginated document.
    ///
    /// The paginated analogue of [`Slide`](Self::Slide), and structural for the same reason
    /// (`crate::chunk`): [`Coordinates`] carries **one** page number, so a chunk merged across a
    /// page boundary cites one page for text that is on two. `docs/07 §2.1` asks a PDF extractor for
    /// *"per-page text with coordinates"*, and this is the kind that keeps the second half of that
    /// true after chunking.
    Page,
    /// A fenced or indented block of code.
    CodeBlock,
    /// An ordered or unordered list.
    List,
}

impl SegmentKind {
    /// The stable machine-readable form, as `docs/07 §2.2` spells it.
    ///
    /// Stable because it reaches Milvus as `chunk_type` (`docs/07 §4`) and is used for result
    /// presentation and boosting: changing one of these strings silently re-ranks every stored
    /// chunk that carries the old spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Section => "section",
            Self::Paragraph => "paragraph",
            Self::Table => "table",
            Self::RowGroup => "row_group",
            Self::SheetRange => "sheet_range",
            Self::Slide => "slide",
            Self::Page => "page",
            Self::CodeBlock => "code_block",
            Self::List => "list",
        }
    }
}

impl fmt::Display for SegmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where in the source a segment was found.
///
/// Every field optional, and none of them synthesised. An extractor that cannot say which page a
/// paragraph came from leaves [`page_number`](Self::page_number) `None` rather than guessing 1: a
/// citation that deep-links to the wrong page is worse than one that does not deep-link, because
/// the reader believes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coordinates {
    /// One-based page, for paginated sources.
    pub page_number: Option<u32>,
    /// The worksheet a range came from.
    pub sheet_name: Option<String>,
    /// The heading trail, outermost first, joined as the source spells it.
    pub section_path: Option<String>,
}

impl Coordinates {
    /// Coordinates that claim nothing, for sources with no interior geography.
    #[must_use]
    pub const fn none() -> Self {
        Self { page_number: None, sheet_name: None, section_path: None }
    }
}

/// One structural unit of extracted text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// What this run of text is.
    pub kind: SegmentKind,
    /// The text itself, decoded and with line endings normalised to `\n`.
    pub text: String,
    /// Where it came from.
    pub coordinates: Coordinates,
}

impl Segment {
    /// What this segment is charged against the output cap.
    ///
    /// See the module documentation for why the overhead term is not optional.
    #[must_use]
    pub fn accounted_bytes(&self) -> u64 {
        self.text.len() as u64 + SEGMENT_OVERHEAD_BYTES
    }
}

/// Everything one extraction found.
///
/// Deliberately not `Clone`: a document is potentially hundreds of megabytes of text, and a type
/// that copies it silently is one accidental `.clone()` away from doubling the worker's peak
/// memory. The same reasoning `RenderRequest` uses, for the same reason.
#[derive(Debug, PartialEq, Eq)]
pub struct TextDocument {
    /// The segments, in reading order.
    pub segments: Vec<Segment>,
    /// The media type the extractor *decided* on, from the content — never echoed from the
    /// uploader's claim. See [`crate::extract`].
    pub media_type: String,
    /// Pages represented, for paginated sources.
    ///
    /// `None` for sources with no pagination, so the page cap has nothing to apply — the same
    /// convention `RenderedArtifact` uses for unpaginated profiles.
    pub page_count: Option<u32>,
    /// Which build produced this.
    pub extractor_version: ExtractorVersion,
}

impl TextDocument {
    /// What this document is charged against
    /// [`RenderBudget::max_output_bytes`](enclave_preview::RenderBudget::max_output_bytes).
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.segments.iter().map(Segment::accounted_bytes).fold(0, u64::saturating_add)
    }

    /// Whether this document carries no text at all.
    ///
    /// "No segment holds any text", not "no segments": an extractor that emits one segment per page
    /// of a scanned PDF produces nine hundred segments and not a single character, and that is
    /// precisely the case D24 refuses to let through as a success.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.iter().all(|segment| segment.text.is_empty())
    }

    /// The text, with segments separated by a blank line.
    ///
    /// A convenience for callers that genuinely want the flat form — a DLP pre-scan, a language
    /// detector. Chunking must not use it: flattening is where the coordinates go, and `docs/07
    /// §2.2` needs them.
    #[must_use]
    pub fn flatten(&self) -> String {
        self.segments.iter().map(|segment| segment.text.as_str()).collect::<Vec<_>>().join("\n\n")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn segment(text: &str) -> Segment {
        Segment {
            kind: SegmentKind::Paragraph,
            text: text.to_owned(),
            coordinates: Coordinates::none(),
        }
    }

    #[test]
    fn an_empty_segment_is_still_charged_for() {
        // The whole of the amplification defence. If this were zero, a document of ten million
        // blank lines would report a size of zero and pass the output cap it exists to fail.
        assert_eq!(segment("").accounted_bytes(), SEGMENT_OVERHEAD_BYTES);
        const { assert!(SEGMENT_OVERHEAD_BYTES > 0) };
    }

    #[test]
    fn a_document_of_blank_segments_is_charged_by_its_count() {
        let document = TextDocument {
            segments: (0..1_000).map(|_| segment("")).collect(),
            media_type: "text/plain".to_owned(),
            page_count: None,
            extractor_version: ExtractorVersion::new("test/1"),
        };
        assert_eq!(document.size_bytes(), 1_000 * SEGMENT_OVERHEAD_BYTES);
    }

    #[test]
    fn a_document_of_pages_that_yielded_nothing_reports_itself_empty() {
        // D24's failure mode, at the level of the type. Nine hundred segments and no characters is
        // a scanned document, and calling it non-empty because it has structure would let it index
        // as READY with nothing in it.
        let document = TextDocument {
            segments: (0..900).map(|_| segment("")).collect(),
            media_type: "application/pdf".to_owned(),
            page_count: Some(900),
            extractor_version: ExtractorVersion::new("test/1"),
        };
        assert!(document.is_empty());
    }

    #[test]
    fn segment_kinds_carry_the_vocabulary_docs_07_writes() {
        // Read against the document rather than restated from memory: these strings become Milvus
        // `chunk_type` values, and a spelling that drifts from `docs/07 §2.2` re-ranks stored
        // chunks that nobody reindexed.
        let doc = include_str!("../../../docs/07-SEARCH-INDEXING.md");
        for kind in [
            SegmentKind::Document,
            SegmentKind::Section,
            SegmentKind::Paragraph,
            SegmentKind::Table,
            SegmentKind::RowGroup,
            SegmentKind::SheetRange,
            SegmentKind::Slide,
            SegmentKind::Page,
            SegmentKind::CodeBlock,
            SegmentKind::List,
        ] {
            assert!(
                doc.contains(&format!("`{kind}`")),
                "`{kind}` is not a chunk type docs/07 §2.2 names"
            );
        }
    }
}
