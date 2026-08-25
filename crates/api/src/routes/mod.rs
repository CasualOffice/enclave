<<<<<<< HEAD
//! Route modules added after the flat layout stopped scaling.
//!
//! The older handlers — `content`, `download`, `preview`, `me` — sit directly under `src/`, and
//! nothing about them is wrong. This directory exists because a route added now has an obvious
//! place to go that is not "another file in the crate root", and because the policy-routing lint
//! walks `crates/api/src` recursively (`xtask/src/policy_routing.rs`), so a handler here is checked
//! exactly as one there is.

pub mod search;
=======
//! Route groups that are large enough to want a module of their own.
//!
//! `me`, `content`, `download` and `preview` sit flat in `crates/api/src` because each is one
//! surface. `admin/` became a directory when it grew a second. This is the third such group and it
//! is a directory for the same reason — and because `crates/api/src/auth.rs` already exists and
//! means something different: that file turns a bearer token into a [`RequestContext`], and this
//! one is the surface that *issues* the token in the first place. Two files called `auth.rs` in one
//! flat module list would be a coin flip every time somebody opened one.

pub mod auth;
>>>>>>> worktree-agent-a248f44e337e8d030
