//! Route groups large enough to want a module of their own.
//!
//! `me`, `content`, `download` and `preview` sit flat in `crates/api/src` because each is one
//! surface, and nothing is gained by moving working handlers. What lands here is a family that
//! arrives whole — its wire types, its policy actions and its refusals in one place a reviewer can
//! read against the section of `docs/05-API.md` that specifies it.
//!
//! `auth` is a directory entry rather than a crate-root file for a second reason worth stating:
//! `crates/api/src/auth.rs` already exists and means the opposite thing. That file turns a bearer
//! token into a [`RequestContext`]; this one is the surface that *issues* the token. Two files
//! named `auth.rs` in one flat module list would be a coin flip every time somebody opened one.
//!
//! The policy-routing lint walks `crates/api/src` recursively (`xtask/src/policy_routing.rs`), so a
//! handler here is checked exactly as one at the crate root is.

pub mod auth;
pub mod delivery;
pub mod libraries;
pub mod search;
pub mod shares;
pub mod uploads;
pub mod workspaces;
