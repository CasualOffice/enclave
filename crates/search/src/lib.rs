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
//! There is **no query planner, no ranking and no vector store client** yet. Those are candidate
//! *generation*, and generation is the part that is allowed to be wrong — so it is built after the
//! part that is not.

pub mod denylist;
pub mod error;
pub mod postfilter;

pub use denylist::{lift_expired, suppress, suppressed};
pub use error::SearchError;
pub use postfilter::{Candidate, Confirmed, DropCounts, PostFilter};
