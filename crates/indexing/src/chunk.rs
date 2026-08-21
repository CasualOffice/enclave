//! Turning extracted segments into the units that get embedded and indexed.
//!
//! # Deterministic identity is the whole design
//!
//! `docs/07-SEARCH-INDEXING.md §2` states the rule the pipeline depends on: *"Every stage is
//! idempotent on `(file_id, version_id, index_version)`. A retried event re-runs stages without
//! duplicating chunks: chunk IDs are deterministic, `chunk_id = uuid_v5(version_id, chunker_version
//! || ordinal)`."*
//!
//! That is not a tidiness property. Indexing is driven by an at-least-once outbox, so a retry is the
//! ordinary case rather than the exceptional one — a worker that crashes after upserting half a
//! document's chunks will run again. With random identifiers the second run inserts a *second* copy
//! of every chunk, and nothing ever removes the first: the index accumulates duplicates that all
//! match the same query, and the same document appears three times in a page of results because it
//! was indexed three times.
//!
//! Worse, and quietly: a duplicate carries the `acl_tokens` of the run that wrote it. An
//! orphaned copy from before a permission change keeps its old tokens forever, because nothing knows
//! it exists to update it. The post-filter still refuses it (`crates/search`), so this is not a
//! leak — it is permanent over-fetch that gets worse every retry, and a drop ratio that climbs for
//! a reason nobody can find.
//!
//! So [`chunk_id`] is a UUIDv5 over exactly the three things `docs/07` names, and
//! [`Chunker::chunk`] is a pure function of its input. Re-chunking the same version with the same
//! chunker yields byte-identical ids, which is what makes the upsert an upsert.
//!
//! # Why the chunker version is *in* the identity
//!
//! Changing how text is split changes what each ordinal means: chunk 3 of a document is a different
//! passage under a different splitter. If the version were not in the id, a chunker change would
//! silently overwrite chunk 3's vector with an embedding of different text, and the index would
//! hold a mixture of two schemes with no way to tell which was which.
//!
//! With it in, a chunker change writes a *new* set of ids and the old set is deleted by the
//! reindex — which is why `docs/07 §5` lists a chunker version change as a full-pipeline
//! reindex rather than a metadata update.
//!
//! # Boundaries the splitter may not cross
//!
//! `docs/07 §2.2`: never across a table row group, slide or sheet-range boundary. The reason is
//! retrieval quality with a security edge — a chunk spanning two slides produces an excerpt that
//! reads as one passage and came from two places, and an excerpt is shown to a user as a quotation
//! from a document.
//!
//! Structural segments are therefore never merged with their neighbours, and a segment too large
//! for the window is split *within itself*. Prose is merged freely, because a paragraph boundary
//! carries no such claim.

use enclave_core::VersionId;
use uuid::Uuid;

use crate::model::{Coordinates, Segment, SegmentKind};

/// The namespace for deterministic chunk identifiers.
///
/// A fixed UUID rather than one of the RFC 4122 predefined namespaces: those are for DNS, URLs, OIDs
/// and X.500 names, and a chunk is none of them. Deriving from `NAMESPACE_OID` would collide with
/// anybody else who did the same for a different purpose in the same database.
const CHUNK_NAMESPACE: Uuid = Uuid::from_bytes([
    0x1c, 0x9a, 0x4f, 0x2e, 0x7b, 0x63, 0x4e, 0x51, 0x9d, 0x0c, 0x3a, 0x8f, 0x61, 0xd2, 0x47, 0x10,
]);

/// Which build of the splitter produced a chunk.
///
/// Part of every chunk's identity — see the module documentation. Must change whenever the *split*
/// could change, which is a lower bar than whenever the code changes: a bug fix that moves one
/// boundary moves every ordinal after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkerVersion(&'static str);

impl ChunkerVersion {
    /// Names a chunker.
    #[must_use]
    pub const fn new(version: &'static str) -> Self {
        Self(version)
    }

    /// The stored form, recorded in `index_manifests.chunker_version`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for ChunkerVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// How text is divided.
///
/// `docs/07 §2.2` gives the targets in *tokens*; this counts characters, and the difference is
/// deliberate rather than an approximation nobody noticed. Tokenisation is a property of the
/// embedding model, and `ENC-509` has not chosen one — a chunker that guessed a tokenizer would
/// produce chunks sized for a model the deployment may not run, and changing it later is a full
/// reindex (`docs/07 §5`).
///
/// So the window is in characters, set from the model's token limit when there is one, and the
/// field names say `chars` so nobody reads them as tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkBudget {
    /// The size a prose chunk aims for.
    pub target_chars: usize,
    /// The size no chunk may exceed. A structural segment larger than this is split within itself.
    pub max_chars: usize,
    /// How much of the previous chunk each prose chunk repeats.
    ///
    /// `docs/07 §2.2` asks for ~15%. Overlap exists so a passage that straddles a boundary is
    /// retrievable from either side; without it, the sentence that answers the question is the one
    /// cut in half.
    pub overlap_chars: usize,
}

impl ChunkBudget {
    /// The default window: ~600 characters with ~15% overlap.
    ///
    /// Roughly 400–800 tokens for English prose at the usual ~4 characters per token, which is the
    /// range `docs/07 §2.2` asks for. It will be wrong for a language with a different ratio, and
    /// `Q13` is where that gets decided against a real model rather than estimated here.
    pub const DEFAULT: Self = Self { target_chars: 2_400, max_chars: 3_200, overlap_chars: 360 };
}

impl Default for ChunkBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One unit of text, ready to embed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Deterministic — see [`chunk_id`].
    pub id: Uuid,
    /// Position within the version, from zero. Part of the identity.
    pub ordinal: u32,
    /// What this chunk is, for result presentation and boosting (`docs/07 §4`).
    pub kind: SegmentKind,
    /// The text.
    pub text: String,
    /// Where it came from, so a result can deep-link and a citation can name a place a person can
    /// navigate to.
    pub coordinates: Coordinates,
}

/// Splits extracted segments into chunks.
#[derive(Debug, Clone, Copy)]
pub struct Chunker {
    budget: ChunkBudget,
    version: ChunkerVersion,
}

impl Chunker {
    /// Builds a chunker.
    #[must_use]
    pub const fn new(version: ChunkerVersion, budget: ChunkBudget) -> Self {
        Self { budget, version }
    }

    /// Which build this is, for `index_manifests.chunker_version`.
    #[must_use]
    pub const fn version(&self) -> ChunkerVersion {
        self.version
    }

    /// Divides a version's segments into chunks.
    ///
    /// Pure: the same segments, version and chunker always produce the same chunks, ids included.
    /// That is what makes a retried indexing run an upsert rather than a duplication — see the
    /// module documentation.
    #[must_use]
    pub fn chunk(&self, version: VersionId, segments: &[Segment]) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        let mut pending: Option<Chunk> = None;

        for segment in segments {
            if segment.text.trim().is_empty() {
                continue;
            }

            if is_structural(segment.kind) {
                // Flushed rather than merged: a chunk spanning two slides produces an excerpt that
                // reads as one passage and came from two places.
                flush(&mut pending, &mut chunks);
                self.split_oversized(segment, &mut chunks);
                continue;
            }

            match pending.as_mut() {
                // `+ 1` for the newline that joins them, expressed as `<` so clippy and the reader
                // agree about what is being compared.
                Some(open) if open.text.len() + segment.text.len() < self.budget.target_chars => {
                    open.text.push('\n');
                    open.text.push_str(&segment.text);
                }
                _ => {
                    flush(&mut pending, &mut chunks);
                    if segment.text.len() > self.budget.max_chars {
                        self.split_oversized(segment, &mut chunks);
                    } else {
                        pending = Some(Chunk {
                            // Assigned on flush, when the ordinal is known.
                            id: Uuid::nil(),
                            ordinal: 0,
                            kind: segment.kind,
                            text: segment.text.clone(),
                            coordinates: segment.coordinates.clone(),
                        });
                    }
                }
            }
        }
        flush(&mut pending, &mut chunks);

        // Ordinals and ids assigned in one pass at the end, so a chunk's identity depends on its
        // final position and not on the order the splitter happened to produce it in.
        for (ordinal, chunk) in chunks.iter_mut().enumerate() {
            let ordinal = u32::try_from(ordinal).unwrap_or(u32::MAX);
            chunk.ordinal = ordinal;
            chunk.id = chunk_id(version, self.version, ordinal);
        }
        chunks
    }

    /// Splits one segment that is too large to be a chunk, without crossing into its neighbours.
    ///
    /// Breaks at a paragraph, then a sentence, then a character boundary — in that order, because a
    /// break mid-sentence produces an excerpt that reads as a truncation and a break mid-character
    /// produces one that is not text at all.
    fn split_oversized(&self, segment: &Segment, chunks: &mut Vec<Chunk>) {
        let mut rest = segment.text.as_str();
        while !rest.is_empty() {
            if rest.len() <= self.budget.max_chars {
                chunks.push(self.piece(segment, rest));
                break;
            }

            let cut = break_point(rest, self.budget.target_chars, self.budget.max_chars);
            let (head, tail) = rest.split_at(cut);
            chunks.push(self.piece(segment, head));

            // Overlap: the next piece begins inside the one just emitted, so a passage straddling
            // the cut is retrievable from either side. Taken from the *emitted* text at a character
            // boundary, and applied by rewinding the cursor rather than by appending — appending
            // would let a chunk exceed `max_chars` by exactly the overlap, which is the bound the
            // budget exists to hold.
            let carried = head.len()
                - floor_char_boundary(head, head.len().saturating_sub(self.budget.overlap_chars));
            rest = &rest[cut - carried..];

            // Without this, a segment whose break point lands entirely inside the overlap makes no
            // progress and the loop never ends. `docs/07`'s ~15% overlap is far from that, but the
            // budget is configurable and a caller that sets overlap near `max_chars` deserves a
            // short chunk rather than a hung worker.
            if carried >= cut {
                rest = tail;
            }
        }
    }

    fn piece(&self, segment: &Segment, text: &str) -> Chunk {
        Chunk {
            id: Uuid::nil(),
            ordinal: 0,
            kind: segment.kind,
            text: text.trim().to_owned(),
            coordinates: segment.coordinates.clone(),
        }
    }
}

/// Whether a segment kind carries a boundary claim the splitter may not cross.
///
/// `docs/07 §2.2` names table row groups, slides and sheet ranges. Tables and code blocks are here
/// too: merging a code block into surrounding prose produces an excerpt in which the code and the
/// commentary are indistinguishable, and a table merged into a paragraph loses the only thing that
/// made its rows readable.
///
/// [`SegmentKind::Page`] is here for the sharper version of the slide argument (`ENC-545`).
/// [`Coordinates`] carries **one** `page_number`, and a chunk takes its coordinates from the first
/// segment that went into it — so merging pages 4 and 5 produces a chunk that cites page 4 for text
/// a reader will not find there. `crate::model::Coordinates` states the rule this protects: a
/// citation that deep-links to the wrong page is worse than one that does not deep-link, because the
/// reader believes it.
const fn is_structural(kind: SegmentKind) -> bool {
    matches!(
        kind,
        SegmentKind::Table
            | SegmentKind::RowGroup
            | SegmentKind::SheetRange
            | SegmentKind::Slide
            | SegmentKind::Page
            | SegmentKind::CodeBlock
    )
}

fn flush(pending: &mut Option<Chunk>, chunks: &mut Vec<Chunk>) {
    if let Some(chunk) = pending.take() {
        if !chunk.text.trim().is_empty() {
            chunks.push(chunk);
        }
    }
}

/// Where to cut an oversized run: the last paragraph break, else the last sentence end, else the
/// last character boundary within the window.
fn break_point(text: &str, target: usize, max: usize) -> usize {
    let ceiling = floor_char_boundary(text, max.min(text.len()));
    let window = &text[..ceiling];

    if let Some(at) = window.rfind("\n\n") {
        if at >= target / 2 {
            return at + 2;
        }
    }
    for terminator in [". ", ".\n", "! ", "? "] {
        if let Some(at) = window.rfind(terminator) {
            if at >= target / 2 {
                return at + terminator.len();
            }
        }
    }
    ceiling
}

/// The largest character boundary at or below `index`.
///
/// Written out rather than using the unstable `str::floor_char_boundary`, and it is not optional:
/// slicing a `&str` at a non-boundary panics, and the text here is arbitrary user content in any
/// script. A chunker that panicked on a document would take the indexing worker down with it.
fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut at = index.min(text.len());
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The deterministic identifier `docs/07 §2` specifies.
///
/// `uuid_v5(version_id, chunker_version || ordinal)`. UUIDv5 is SHA-1 based and not a security
/// primitive — nothing here depends on it being hard to forge. What it must be is *stable*: the
/// same three inputs give the same id on every machine, in every process, forever, which is what
/// makes a retried indexing run an upsert.
#[must_use]
pub fn chunk_id(version: VersionId, chunker: ChunkerVersion, ordinal: u32) -> Uuid {
    // The separator matters. Without it, chunker `v1` ordinal `23` and chunker `v12` ordinal `3`
    // hash the same bytes and collide — one chunk silently overwriting another's vector.
    let name = format!("{}\u{1f}{}\u{1f}{}", version.as_uuid(), chunker.as_str(), ordinal);
    Uuid::new_v5(&CHUNK_NAMESPACE, name.as_bytes())
}
