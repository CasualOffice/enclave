//! `enclave-indexing` — turning a document's bytes into text a search index can hold, inside bounds
//! the document cannot escape.
//!
//! Extraction is the widest attack surface in the product, tied with rendering and for the same
//! reason: it is a parser eating input an attacker chose. `plans/M3-DISCOVERY.md` D24 says so and
//! draws the conclusion — *"its bounds are already written and tested
//! (`crates/preview/src/budget.rs`); this milestone reuses them rather than inventing a second
//! set."*
//!
//! This crate does that literally. It depends on [`enclave_preview`] for
//! [`RenderBudget`] and [`Refusal`], and
//! [`BoundedExtractor`] is [`Bounded`](enclave_preview::Bounded) with an [`Extractor`] inside it.
//! Two crates making different choices about one problem is how one of them ends up wrong; where
//! extraction genuinely differs, [`extract`] names the difference rather than forking around it.
//!
//! # The three properties, and where each is enforced
//!
//! **1. An extractor cannot exceed its budget.** Enforced *around* the parser by
//! [`BoundedExtractor`], not inside it, because the component reading hostile input is the one
//! least able to promise it will stop. See [`extract`].
//!
//! **2. An extractor cannot reach anything.** [`ExtractRequest`] carries bytes — no object key, no
//! signed URL, no store handle. Extraction is the stage that reads the *whole* of a document, so an
//! extractor with network reach would be an exfiltration primitive with the content already in
//! hand.
//!
//! **3. A document that yields no text cannot be recorded as a success.** [`ExtractOutcome::NoText`]
//! is a distinct arm, and [`BoundedExtractor`] converts an empty [`TextDocument`] into it whatever
//! the inner extractor believed it produced. D24: *"a scanned PDF that indexes as empty is invisible
//! to search while appearing correctly filed, which is worse than one that failed to ingest — a
//! failure is visible and a silent absence is not."*
//!
//! # A refusal is an answer, not an error
//!
//! A source that will not extract — too large, an encoding we do not decode, engineered to hang —
//! produces a [`Refusal`] in the success channel. Only *our* failures are
//! [`IndexingError`]. `plans/M2-ACCESS-DELIVERY.md` D17: a timeout is a verdict. Treated as an error
//! it becomes a retry, and a retry against a document engineered to take forever is a
//! denial-of-service primitive with a scheduler helping it along.
//!
//! # What extracts today
//!
//! [`PlainTextExtractor`] — UTF-8 `text/plain` and `text/markdown`, producing paragraph segments.
//! Its encoding rule is **UTF-8 or a refusal**: no lossy replacement and no charset detection,
//! because a byte sequence that decodes differently in two decoders is how indexed text comes apart
//! from displayed text, and every DLP and classification decision downstream is then made about a
//! document nobody can see. [`text`] gives the argument in full, including why a NUL byte anywhere
//! refuses the source outright.
//!
//! # Where the text goes
//!
//! [`store`] writes chunk text to PostgreSQL, which is what lets degraded search find a document by
//! what it *says* rather than by what it is called (`ENC-515`). Milvus holds a copy too
//! (`docs/07 §4`) and it is the wrong copy for that caller by construction: the lexical fallback
//! runs when the vector store cannot be reached.
//!
//! [`write_chunks`] replaces a file's text rather than adding to it, in one statement, for the
//! reason [`store`] gives in full — half of that operation leaves the previous version's wording
//! matchable against a file that no longer contains it.
//!
//! # What is deliberately not here
//!
//! **No document formats.** PDF and OOXML are a ZIP parser, an XML parser and a page tree, each
//! with its own bomb, and they need the out-of-process worker of `plans/M2-ACCESS-DELIVERY.md` D17
//! with the process limits that make a memory bound real. [`NoExtractor`] answers for them, which is
//! the deny-by-default shape `crates/core`'s policy stages use. A partial implementation would be
//! worse than a refusal here in a way it is not for previews: a preview that renders half a document
//! looks wrong, and an index built from half a document looks like the document.
//!
//! # OCR, and the part of it that is still missing
//!
//! [`ocr`] answers `plans/M3-DISCOVERY.md` Q12: [`OcrExtractor`] recognises text in PNG, JPEG and
//! WebP sources with `ocrs`/`rten`, English (Latin script) only, and [`OcrRetry`] re-runs it over
//! exactly the pages an earlier extraction reported in [`TextlessSource`]. It is a **stage**, not a
//! fallback — D24 — and the property that makes that true is that [`OcrRetry::retry`] passes every
//! outcome except [`Outcome::NoText`] straight through, so OCR cannot turn *"this document failed"*
//! into *"this document is empty"*.
//!
//! Of the four things this crate previously said were undecided, three now are:
//!
//! 1. **The engine.** `ocrs` on `rten`: MIT OR Apache-2.0, pure Rust, and — the decisive property —
//!    no `links` key, so no C toolchain enters the D17 worker. The Tesseract bindings both declare
//!    `links = "tesseract"` and cannot even coexist in one graph. The workspace manifest carries the
//!    comparison; `rayon` comes along with `rten` and is an accepted cost, bounded by the worker's
//!    `RTEN_NUM_THREADS` and process CPU limit rather than by anything here.
//! 2. **Languages: English only.** Additive later — a new recognition model and a reindex of what it
//!    changes, not a migration. A page in a script the model was not trained on comes back
//!    [`ExtractOutcome::NoText`], which is a `FAILED` manifest with `no_text_extracted` rather than a
//!    silently empty index entry.
//! 3. **The cost ceiling.** [`OcrRetry::new`] takes its own [`RenderBudget`], applied **per page**.
//!    A different value for one struct, not a second struct — a 900-page scan under the text
//!    extractor's wall clock is a guaranteed [`Refusal::Timeout`], so this is the place `lib.rs`
//!    said a second set of numbers might be warranted.
//!
//! The fourth — **whether OCR output is marked as such**, since recognised text carries error and a
//! DLP or classification decision made on it is made on a guess — is answered only at the manifest
//! level. `index_manifests.extractor_version` records `ocr/1+…`, so *the document* is identifiable
//! as OCR-derived; an individual [`Chunk`] is not, because `migrations/0011` gives a chunk no column
//! for it. Whether per-chunk provenance is required is a policy question and is still open.
//!
//! # Pixels for the OCR path
//!
//! [`pdf`] supplies them (`ENC-537`). [`PdfiumPages`] renders a page with PDFium, **mounted at run
//! time** exactly as the OCR weights and the embedding model are, and [`NoPageImages`] remains what
//! a deployment that mounted nothing has — so the deny-by-default is unchanged and only a
//! deployment that opted in runs a C++ parser.
//!
//! Two things about it are worth reading before touching either module:
//!
//! - **`crates/preview/src/raster.rs` still refuses `PdfSanitized`, and that is not an oversight.**
//!   Rasterising for OCR and sanitising for a viewer are different jobs with different outputs;
//!   [`pdf`] sets the two side by side and says what makes the first safe where the second is not.
//! - **It runs in-process, and D17's sandbox still does not exist.** PDFium is the first
//!   memory-unsafe parser in this workspace's graph, so the gap between "bounded" and "isolated"
//!   matters more here than anywhere else it has been admitted. `plans/M3-THREAT-WALKTHROUGH.md §3`
//!   R10 records it.
//!
//! [`PageImages`] gained a third answer to carry this: [`PageImage::Refused`]. A rasteriser that
//! could only say "rendered" or "no image" would have to report a timeout as an absence, and an
//! absence is skipped — so a 900-page scan with one hostile page would be `READY` over 899 of them,
//! which is D24's failure mode arriving through the port built to prevent it.
//!
//! [`Refusal::Timeout`]: enclave_preview::Refusal::Timeout

pub mod chunk;
pub mod error;
pub mod extract;
pub mod manifest;
pub mod model;
pub mod ocr;
pub mod pdf;
pub mod pipeline;
pub mod store;
pub mod text;

pub use chunk::{chunk_id, Chunk, ChunkBudget, Chunker, ChunkerVersion};
pub use error::{IndexingError, Result};
pub use extract::{
    BoundedExtractor, ExtractOutcome, ExtractRequest, Extractor, NoExtractor, TextlessSource,
};
pub use manifest::{claim, defer, enqueue, record, start, BuildVersions, Claimed, WorkingState};
pub use model::{
    Coordinates, ExtractorVersion, Segment, SegmentKind, TextDocument, SEGMENT_OVERHEAD_BYTES,
};
pub use ocr::{NoPageImages, OcrExtractor, OcrModels, OcrRetry, PageImage, PageImages};
pub use pdf::{PdfiumLibrary, PdfiumPages};
pub use pipeline::{ManifestStatus, Outcome, Pipeline, Prepared, Reason};
pub use store::{write_chunks, ChunkWrite};
pub use text::PlainTextExtractor;

/// Re-exported so that a caller bounding an extraction and a caller bounding a render name the same
/// type rather than two that happen to agree. See [`extract`] for why this crate does not alias
/// them to extraction-flavoured names.
pub use enclave_preview::{Refusal, RenderBudget};
