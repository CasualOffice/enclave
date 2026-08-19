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
//! # What is deliberately not here
//!
//! **No document formats.** PDF and OOXML are a ZIP parser, an XML parser and a page tree, each
//! with its own bomb, and they need the out-of-process worker of `plans/M2-ACCESS-DELIVERY.md` D17
//! with the process limits that make a memory bound real. [`NoExtractor`] answers for them, which is
//! the deny-by-default shape `crates/core`'s policy stages use. A partial implementation would be
//! worse than a refusal here in a way it is not for previews: a preview that renders half a document
//! looks wrong, and an index built from half a document looks like the document.
//!
//! **No OCR, and not by accident** (`ENC-161`). The port is shaped to take one — an OCR engine is
//! another [`Extractor`], asked again for the pages an earlier one reported in [`TextlessSource`] —
//! but shipping an engine is blocked on a decision this crate cannot make for the deployment.
//! `plans/M3-DISCOVERY.md` Q12 asks for it before extraction ships; concretely it needs four things:
//!
//! 1. **The engine**, under this workspace's licence allowlist (`deny.toml`) and installable in an
//!    air-gapped image (`docs/08 §18`). Tesseract is Apache-2.0 and is a C dependency with a
//!    language-data payload; the Rust-native alternatives are weaker and are also new parsers.
//! 2. **Which languages ship by default.** Each trained language is tens of megabytes in the image,
//!    and a tenant whose documents are in a language nobody enabled gets silently empty results —
//!    the exact failure D24 is about, reintroduced through configuration.
//! 3. **The cost ceiling, in the same units as the budget.** OCR is seconds per page against
//!    milliseconds for text, so either [`RenderBudget::wall_clock`](enclave_preview::RenderBudget)
//!    is different for OCR or a 900-page scan is a guaranteed [`Refusal::Timeout`]. That is the one
//!    place a second budget may be genuinely warranted, and it should be decided rather than
//!    discovered.
//! 4. **Whether OCR output is marked as such.** Recognised text carries error, and a DLP rule or a
//!    classification decision made on it is made on a guess. Whether that is allowed is a policy
//!    question, not an extraction one.
//!
//! [`Refusal::Timeout`]: enclave_preview::Refusal::Timeout

pub mod error;
pub mod extract;
pub mod model;
pub mod text;

pub use error::{IndexingError, Result};
pub use extract::{
    BoundedExtractor, ExtractOutcome, ExtractRequest, Extractor, NoExtractor, TextlessSource,
};
pub use model::{
    Coordinates, ExtractorVersion, Segment, SegmentKind, TextDocument, SEGMENT_OVERHEAD_BYTES,
};
pub use text::PlainTextExtractor;

/// Re-exported so that a caller bounding an extraction and a caller bounding a render name the same
/// type rather than two that happen to agree. See [`extract`] for why this crate does not alias
/// them to extraction-flavoured names.
pub use enclave_preview::{Refusal, RenderBudget};
