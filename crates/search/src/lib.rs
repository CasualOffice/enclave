//! `enclave-search` — the authoritative post-filter, and the denylist that makes revocation immediate.
//!
//! # The one sentence
//!
//! **The vector index is a candidate generator. PostgreSQL is the authority.** (`CLAUDE.md` rule 5.)
//!
//! This crate is what makes that true. It is deliberately the *first* thing built in M3, before
//! there is a vector store to be tempted by: the guarantee before the thing it guards. Building it
//! against a fake candidate generator is not a shortcut — it is the only way to write the S5 test
//! honestly, because "the index proposed something the caller may not see" is two lines to arrange
//! in a fake and a research project to arrange in Milvus.
//!
//! # What is here, and what deliberately is not
//!
//! [`postfilter`] confirms candidates and withholds excerpts. [`denylist`] is what makes a
//! revocation take effect before the index hears about it.
//!
//! [`lexical`] and [`degraded`] are the first candidate generation in the crate, and they arrive in
//! the order the guarantee allows: a generator built *after* the post-filter, whose output is
//! wrapped in a type only the post-filter can consume. `plans/M3-DISCOVERY.md` D25 — degraded mode
//! is a worse recall guarantee, never a worse authorization guarantee — is enforced by that shape
//! rather than by a review comment.
//!
//! There is still **no vector store client**. When it lands, its candidates go through
//! [`SearchResults::confirm`], the sibling of the degraded path, and neither of them takes an
//! argument that turns the post-filter off.

pub mod degraded;
pub mod denylist;
pub mod error;
pub mod lexical;
pub mod postfilter;

pub use degraded::{
    Cause, DegradedReason, Retrieval, SearchResults, VectorStore, DEFAULT_DENYLIST_LIMIT,
};
pub use denylist::{lift_expired, suppress, suppressed};
pub use error::SearchError;
pub use lexical::LexicalCandidates;
pub use postfilter::{Candidate, Confirmed, DropCounts, PostFilter};
