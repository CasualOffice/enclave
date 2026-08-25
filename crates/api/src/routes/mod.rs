//! Route modules added after the flat layout stopped scaling.
//!
//! The older handlers — `content`, `download`, `preview`, `me` — sit directly under `src/`, and
//! nothing about them is wrong. This directory exists because a route added now has an obvious
//! place to go that is not "another file in the crate root", and because the policy-routing lint
//! walks `crates/api/src` recursively (`xtask/src/policy_routing.rs`), so a handler here is checked
//! exactly as one there is.

pub mod search;
