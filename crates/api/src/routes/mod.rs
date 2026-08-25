//! Route groups that are large enough to want a module of their own.
//!
//! The older handlers — `content`, `download`, `preview`, `me` — sit directly under `src/`, and
//! nothing about them is wrong; nothing is gained by moving working handlers. This directory exists
//! because a route added now has an obvious place to go that is not "another file in the crate
//! root", and because the policy-routing lint walks `crates/api/src` recursively
//! (`xtask/src/policy_routing.rs`), so a handler here is checked exactly as one there is.
//!
//! What lands here is a family that arrives whole — its wire types, its policy actions and its
//! refusals in one place a reviewer can read against the section of `docs/05-API.md` that specifies
//! it.
//!
//! [`auth`] is a directory member for one extra reason: `crates/api/src/auth.rs` already exists and
//! means something different. That file turns a bearer token into a
//! [`RequestContext`](enclave_core::RequestContext); this one is the surface that *issues* the token
//! in the first place. Two files called `auth.rs` in one flat module list would be a coin flip every
//! time somebody opened one.

pub mod auth;
pub mod search;
pub mod shares;
pub mod uploads;
