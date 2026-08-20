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
//! [`excerpt`] answers a question `ENC-515` left open and `ENC-529` closes: what a quotation from a
//! document may look like. It is a small module with a long argument, because both obvious answers
//! — `ts_headline` over the indexed expression, `ts_headline` over the raw text — are wrong in ways
//! that are hard to see from a call site, and one of them is wrong *invisibly*.
//!
//! [`health`] is the signal that a store which is *up* can still be *wrong*. Reachability catches
//! loud failures; a collection recreated empty answers every probe and returns almost nothing, with
//! `degraded: false` on the response. It is per tenant, taken in a background loop, and it has no
//! per-file form — see its documentation for why a "is this file's index current?" predicate is the
//! one function this crate must never grow.
//!
//! [`vector`] and [`milvus`] are the real candidate generator, and they arrive last for the same
//! reason: the guarantee was built first, against a fake, and the real index has to fit the shape
//! the fake already proved. It does, literally — [`milvus::MilvusIndex`] hands back the same
//! `Vec<Candidate>` `tests/postfilter.rs` builds by hand, into the same
//! [`SearchResults::confirm`], with no argument that turns the post-filter off.
//!
//! # Two things named `VectorStore`, and why only one of them is
//!
//! [`degraded::VectorStore`] is a **health state**, not a client. The port a client implements is
//! [`vector::VectorIndex`]. The names are kept apart deliberately: `VectorStore::Unreachable` reads
//! as a fact about the world, and if the same identifier were also the trait every implementation
//! bore, that sentence would stop being obvious at a glance — which matters, because it is the
//! sentence [`Retrieval::decide`] turns on.

pub mod degraded;
pub mod denylist;
pub mod error;
pub mod excerpt;
pub mod health;
pub mod lexical;
pub mod milvus;
pub mod postfilter;
pub mod vector;

pub use degraded::{
    Cause, DegradedReason, Retrieval, SearchResults, VectorStore, DEFAULT_DENYLIST_LIMIT,
};
pub use denylist::{
    catch_up, confirm_indexed, lift_expired, suppress, suppressed, CatchUp, SuppressionSeq,
};
pub use error::SearchError;
pub use excerpt::{Excerpt, Highlights};
pub use health::{
    CoverageFloor, Expected, IndexCensus, IndexHealth, Unknown, DEFAULT_COVERAGE_FLOOR,
};
pub use lexical::LexicalCandidates;
pub use milvus::{MilvusConfig, MilvusIndex};
pub use postfilter::{Candidate, Confirmed, DropCounts, PostFilter};
pub use vector::{Prefilter, VectorIndex, VectorQuery};
