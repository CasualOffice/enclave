//! What indexing one version *decided*, and the manifest state that decision implies.
//!
//! `ENC-527`: extraction, chunking and the chunk store exist as three parts with nothing joining
//! them. This is the join — the part that can be decided without touching a database, kept separate
//! from the part that cannot, so the decision is testable on its own.
//!
//! # The failure this module is arranged against
//!
//! `docs/07 §2.1` and D24: **a version that yielded no text must not be recorded `READY`.** A
//! scanned PDF indexed as READY-with-nothing-in-it is invisible to search while appearing correctly
//! filed, which is worse than one that failed to ingest — a failure is on a surface somebody reads,
//! and a silent absence is not.
//!
//! [`Outcome::Ready`] therefore carries a [`NonZeroU32`]. A `READY` manifest asserting no chunks is
//! not a value this crate can construct — it is refused by the only constructor the variant has,
//! rather than by a check somebody could reorder past.
//!
//! `TextDocument::is_empty` also answers "did this yield characters" honestly, counting nine hundred
//! blank pages as empty rather than as structure, and `prepare` exits early on it. That exit is an
//! optimisation and is commented as one: deleting it leaves every test here green, because the
//! chunker drops whitespace-only segments and the type refuses the result anyway.
//!
//! # Why the manifest write is not here
//!
//! [`Pipeline::prepare`] returns a decision and the chunks it produced; it writes nothing. The
//! caller writes the chunks ([`crate::write_chunks`]) and advances the manifest, in a transaction
//! this module does not own.
//!
//! That split is deliberate rather than tidy. A `prepare` that also wrote would need a connection,
//! and every test of the decision would then need a database — which is exactly the situation that
//! left `ENC-516`'s tests written and unwatched when the dev environment went down. The decision is
//! the part with the interesting failure mode, so it is the part that stays cheap to prove.

use core::num::NonZeroU32;

use enclave_core::VersionId;
use enclave_preview::Refusal;

use crate::chunk::{Chunk, Chunker};
use crate::extract::{ExtractOutcome, ExtractRequest, Extractor, TextlessSource};
use crate::model::TextDocument;
use crate::Result;

/// The manifest states `migrations/0011_search.sql` permits.
///
/// The spellings are asserted against that migration's `CHECK` constraint in this module's tests
/// rather than trusted, because a status this crate writes that the constraint does not list fails
/// at the database, at run time, on one file — and a status the constraint *does* list but nothing
/// reads is a file that sits in a state no worker collects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestStatus {
    /// Claimed, not yet started.
    Pending,
    /// An extractor is running.
    Extracting,
    /// Chunks exist and vectors are being produced.
    Embedding,
    /// Vectors exist and are being written to the index.
    Indexing,
    /// Searchable.
    Ready,
    /// Attempted and did not produce a searchable version. **Including "no text".**
    Failed,
    /// Indexed by a build that has since been superseded.
    Stale,
    /// Deliberately not indexed — no extractor handles this type.
    Skipped,
}

impl ManifestStatus {
    /// The exact string stored in `index_manifests.status`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Extracting => "EXTRACTING",
            Self::Embedding => "EMBEDDING",
            Self::Indexing => "INDEXING",
            Self::Ready => "READY",
            Self::Failed => "FAILED",
            Self::Stale => "STALE",
            Self::Skipped => "SKIPPED",
        }
    }
}

/// Why a version was recorded `FAILED` or `SKIPPED`.
///
/// Fixed vocabulary, never a parser's message. `migrations/0011` says the same thing about
/// `failure_reason` and gives the reason: this column is written by code that has just parsed a
/// hostile document, and echoing what that produced into a column every operator reads is how a
/// payload travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Parsed, and yielded no characters. The D24 case.
    NoText,
    /// The extractor refused: over budget, or not the bytes it was told to expect.
    Refused,
    /// No extractor claims this media type.
    Unsupported,
}

impl Reason {
    /// The exact string stored in `index_manifests.failure_reason`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoText => "no_text_extracted",
            Self::Refused => "extraction_refused",
            Self::Unsupported => "unsupported_media_type",
        }
    }
}

/// What indexing one version decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Text was extracted and chunked into at least one chunk.
    ///
    /// [`NonZeroU32`] on purpose: this is the only variant that maps to `READY`, so a `READY`
    /// manifest claiming no chunks is unconstructible. See the module documentation — that is D24's
    /// failure mode, and a type is a better place to refuse it than a review comment.
    Ready {
        /// How many chunks were produced. Becomes `index_manifests.chunk_count`, which
        /// `enclave_search`'s coverage check sums to decide whether the vector store is depleted.
        chunks: NonZeroU32,
    },
    /// The source parsed and yielded no text.
    ///
    /// Not `Ready { chunks: 0 }`, which cannot be written, and not a refusal — re-running *with OCR
    /// configured* is exactly what changes this, which is what makes it different from a verdict.
    NoText(TextlessSource),
    /// The extractor refused this attempt.
    Refused(Refusal),
    /// No extractor handles the declared media type.
    Unsupported,
}

impl Outcome {
    /// The manifest status this outcome implies.
    ///
    /// Total and non-configurable. There is no argument that turns [`Outcome::NoText`] into
    /// `READY`, because the whole point of the variant is that somebody, one day, under deadline,
    /// will want exactly that — an empty index entry makes a dashboard look complete.
    #[must_use]
    pub const fn status(&self) -> ManifestStatus {
        match self {
            Self::Ready { .. } => ManifestStatus::Ready,
            // FAILED rather than SKIPPED: a document that should have had text and did not is a
            // problem to be looked at, and SKIPPED is the state for files nobody expects to index.
            Self::NoText(_) | Self::Refused(_) => ManifestStatus::Failed,
            Self::Unsupported => ManifestStatus::Skipped,
        }
    }

    /// The reason recorded alongside a non-`READY` status, if there is one.
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        match self {
            Self::Ready { .. } => None,
            Self::NoText(_) => Some(Reason::NoText),
            Self::Refused(_) => Some(Reason::Refused),
            Self::Unsupported => Some(Reason::Unsupported),
        }
    }

    /// How many chunks to record. Zero for everything that is not [`Outcome::Ready`].
    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        match self {
            Self::Ready { chunks } => chunks.get(),
            _ => 0,
        }
    }
}

/// One version's worth of work, decided but not yet written.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// What was decided.
    pub outcome: Outcome,
    /// The chunks to store. Empty unless [`Outcome::Ready`], and in that case its length equals
    /// [`Outcome::chunk_count`] — asserted in this module's tests, because the two travelling
    /// separately is how a manifest comes to disagree with the rows it describes.
    pub chunks: Vec<Chunk>,
}

/// Extraction and chunking, joined.
#[derive(Debug)]
pub struct Pipeline<E> {
    extractor: E,
    chunker: Chunker,
}

impl<E: Extractor> Pipeline<E> {
    /// Builds a pipeline over one extractor and one chunker.
    pub const fn new(extractor: E, chunker: Chunker) -> Self {
        Self { extractor, chunker }
    }

    /// Runs extraction and chunking for one version, and decides what the manifest should say.
    ///
    /// Writes nothing — see the module documentation for why the write lives at the caller.
    ///
    /// # Errors
    ///
    /// Propagates whatever the extractor returns as an error. A *refusal* is not an error: it is
    /// [`Outcome::Refused`], because the attempt completed and reached a verdict.
    pub async fn prepare(&self, version: VersionId, request: ExtractRequest) -> Result<Prepared> {
        if !self.extractor.supports(&request.declared_media_type) {
            return Ok(Prepared { outcome: Outcome::Unsupported, chunks: Vec::new() });
        }

        let document = match self.extractor.extract(request).await? {
            ExtractOutcome::Extracted(document) => document,
            ExtractOutcome::NoText(source) => {
                return Ok(Prepared { outcome: Outcome::NoText(source), chunks: Vec::new() })
            }
            ExtractOutcome::Refused(refusal) => {
                return Ok(Prepared { outcome: Outcome::Refused(refusal), chunks: Vec::new() })
            }
        };

        Ok(decide(version, &self.chunker, &document))
    }
}

/// Chunks an already-extracted document and decides what the manifest should say.
///
/// Split out of [`Pipeline::prepare`] so there is **one** place the `NonZeroU32` gate lives. OCR
/// (`crate::ocr`) extracts by a different route — page images through a second extractor — and a
/// second copy of this decision is how one of the two eventually reaches `READY` over an empty
/// document while the other still refuses to.
pub(crate) fn decide(version: VersionId, chunker: &Chunker, document: &TextDocument) -> Prepared {
    // An early exit, and **not** the guarantee — measured, not assumed. Removing this block leaves
    // every test in this module green, because the chunker skips whitespace-only segments and the
    // `NonZeroU32` gate below then refuses the `Ready`. What this buys is not correctness but work:
    // nine hundred blank pages are not chunked before being discarded.
    //
    // It is kept for that reason and labelled, rather than deleted or left to look load-bearing.
    // The thing that actually makes READY-with-nothing-in-it unreachable is the type.
    if document.is_empty() {
        return Prepared { outcome: Outcome::NoText(textless(document)), chunks: Vec::new() };
    }

    let chunks = chunker.chunk(version, &document.segments);

    // **This is the guarantee.** `NonZeroU32::new(0)` is `None`, so there is no path from an empty
    // chunk list to `Outcome::Ready` — not a check that can be reordered away, but the only
    // constructor the variant has. Verified by deliberate violation: replacing this with
    // `unwrap_or(NonZeroU32::MIN)` makes `a_document_of_blank_pages_is_never_ready` fail by name,
    // while removing the `is_empty` block above changes nothing.
    let produced = u32::try_from(chunks.len()).ok().and_then(NonZeroU32::new);
    match produced {
        Some(chunks_produced) => {
            Prepared { outcome: Outcome::Ready { chunks: chunks_produced }, chunks }
        }
        None => Prepared { outcome: Outcome::NoText(textless(document)), chunks: Vec::new() },
    }
}

/// Describes a document that yielded no text, preserving the OCR work list.
///
/// `pages_without_text` is not decoration: a scanned PDF that can say *which* pages were blank lets
/// OCR run over three pages of nine hundred. The pages come from the segments' own coordinates, so
/// a document with no pagination yields an empty list — which is the honest answer, since there is
/// nothing an image pipeline could work over.
fn textless(document: &TextDocument) -> TextlessSource {
    let mut pages: Vec<u32> = document
        .segments
        .iter()
        .filter(|segment| segment.text.trim().is_empty())
        .filter_map(|segment| segment.coordinates.page_number)
        .collect();
    pages.sort_unstable();
    pages.dedup();

    TextlessSource { media_type: document.media_type.clone(), pages_without_text: pages }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use async_trait::async_trait;
    use enclave_preview::RenderBudget;

    use super::*;
    use crate::chunk::{ChunkBudget, ChunkerVersion};
    use crate::model::{Coordinates, ExtractorVersion, Segment, SegmentKind};

    /// What the fake extractor should answer. A description rather than an `ExtractOutcome`, because
    /// that type is deliberately not `Clone` — it carries a whole document — and the fake is asked
    /// once per test anyway.
    enum Answer {
        /// A document with these segment texts, each on the given page.
        Document(Vec<(&'static str, Option<u32>)>),
        /// The extractor itself reported no text.
        NoText,
        /// The media type is not handled, so `extract` must never be called.
        Unsupported,
    }

    struct Fake(Answer);

    #[async_trait]
    impl Extractor for Fake {
        fn extractor_version(&self) -> ExtractorVersion {
            ExtractorVersion::new("fake/1")
        }

        fn supports(&self, _declared_media_type: &str) -> bool {
            !matches!(self.0, Answer::Unsupported)
        }

        async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
            Ok(match &self.0 {
                Answer::Document(segments) => ExtractOutcome::Extracted(TextDocument {
                    segments: segments
                        .iter()
                        .map(|(text, page)| Segment {
                            kind: SegmentKind::Paragraph,
                            text: (*text).to_owned(),
                            coordinates: Coordinates { page_number: *page, ..Coordinates::none() },
                        })
                        .collect(),
                    media_type: "application/pdf".to_owned(),
                    page_count: None,
                    extractor_version: ExtractorVersion::new("fake/1"),
                }),
                Answer::NoText => ExtractOutcome::NoText(TextlessSource {
                    media_type: "application/pdf".to_owned(),
                    pages_without_text: vec![1],
                }),
                Answer::Unsupported => {
                    panic!("extract was called for a media type `supports` had rejected")
                }
            })
        }
    }

    async fn prepare(answer: Answer) -> Prepared {
        let chunker = Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default());
        Pipeline::new(Fake(answer), chunker)
            .prepare(
                VersionId::new_v7(),
                ExtractRequest {
                    declared_media_type: "application/pdf".to_owned(),
                    source: b"irrelevant".to_vec(),
                    budget: RenderBudget::default(),
                },
            )
            .await
            .expect("the fake never errors")
    }

    #[tokio::test]
    async fn text_becomes_ready_with_the_chunks_it_produced() {
        let prepared = prepare(Answer::Document(vec![("a real paragraph of text", Some(1))])).await;

        assert_eq!(prepared.outcome.status(), ManifestStatus::Ready);
        assert_eq!(prepared.outcome.reason(), None);
        assert!(prepared.outcome.chunk_count() > 0);
        assert_eq!(
            u32::try_from(prepared.chunks.len()).expect("a small count"),
            prepared.outcome.chunk_count(),
            "the manifest's chunk_count and the rows it describes must not travel separately"
        );
    }

    #[tokio::test]
    async fn a_document_of_blank_pages_is_never_ready() {
        // D24, and the reason this module exists. Nine hundred blank pages is a scanned document:
        // it parsed, so `Extracted` is the honest answer from the extractor, and recording that as
        // READY would leave it invisible to search while appearing correctly filed.
        //
        // What this proves is the `NonZeroU32` gate, not the `is_empty` early exit — the early exit
        // can be deleted and this still passes. Established by breaking each in turn rather than by
        // reading the code, because the two are indistinguishable from the outside.
        let blank = (1..=900).map(|page| ("   ", Some(page))).collect();
        let prepared = prepare(Answer::Document(blank)).await;

        assert_eq!(
            prepared.outcome.status(),
            ManifestStatus::Failed,
            "a version that yielded no text was recorded as though it had been indexed"
        );
        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
        assert_eq!(prepared.outcome.chunk_count(), 0);
        assert!(prepared.chunks.is_empty());
    }

    #[tokio::test]
    async fn a_blank_document_carries_its_pages_for_ocr() {
        // The work list is the difference between OCR running over three pages and over all of
        // them, so losing it here is a cost nobody would ever see as a bug.
        let prepared =
            prepare(Answer::Document(vec![("", Some(7)), ("", Some(2)), ("", Some(7))])).await;

        match prepared.outcome {
            Outcome::NoText(source) => {
                assert_eq!(source.pages_without_text, vec![2, 7], "sorted and deduplicated");
                assert_eq!(source.media_type, "application/pdf");
            }
            other => panic!("expected NoText, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_text_from_the_extractor_fails_rather_than_skipping() {
        let prepared = prepare(Answer::NoText).await;

        // FAILED, not SKIPPED: SKIPPED is for files nobody expects to index, and a document that
        // should have had text and did not is something for somebody to look at.
        assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
    }

    #[tokio::test]
    async fn an_unhandled_media_type_is_skipped_and_never_extracted() {
        // The fake panics if `extract` is reached, so this also asserts that `supports` is
        // consulted *before* any bytes are handed to a parser.
        let prepared = prepare(Answer::Unsupported).await;

        assert_eq!(prepared.outcome.status(), ManifestStatus::Skipped);
        assert_eq!(prepared.outcome.reason(), Some(Reason::Unsupported));
    }

    #[test]
    fn ready_is_the_only_status_with_chunks_and_no_reason() {
        let textless =
            TextlessSource { media_type: "application/pdf".to_owned(), pages_without_text: vec![] };
        for outcome in [
            Outcome::Ready { chunks: NonZeroU32::new(3).expect("3 is not zero") },
            Outcome::NoText(textless),
            Outcome::Unsupported,
        ] {
            let is_ready = outcome.status() == ManifestStatus::Ready;
            assert_eq!(
                is_ready,
                outcome.reason().is_none(),
                "{outcome:?} disagrees with itself about whether it succeeded"
            );
            assert_eq!(
                is_ready,
                outcome.chunk_count() > 0,
                "{outcome:?} reports a chunk count that contradicts its status"
            );
        }
    }

    #[test]
    fn every_status_is_one_the_migration_permits() {
        // Read out of the migration rather than restated. A status this crate writes that the CHECK
        // constraint does not list fails at the database, at run time, on one file — the kind of
        // defect that reaches production because the happy path never exercises it.
        let migration = include_str!("../../../migrations/0011_search.sql");
        // `status IN (` rather than "status" and "CHECK" separately: the first attempt at this
        // matched the file's header comment, which mentions both words and lists no values, so
        // every status "was missing" from a constraint the test had never found.
        let line = migration
            .lines()
            .find(|line| line.contains("status IN ("))
            .expect("0011 declares index_manifests.status with a CHECK listing its values");

        for status in [
            ManifestStatus::Pending,
            ManifestStatus::Extracting,
            ManifestStatus::Embedding,
            ManifestStatus::Indexing,
            ManifestStatus::Ready,
            ManifestStatus::Failed,
            ManifestStatus::Stale,
            ManifestStatus::Skipped,
        ] {
            assert!(
                line.contains(&format!("'{}'", status.as_str())),
                "{} is not in migration 0011's CHECK constraint",
                status.as_str()
            );
        }
    }
}
