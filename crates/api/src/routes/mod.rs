//! Route modules that own more than one endpoint.
//!
//! The older handlers each have a module at the crate root, one per endpoint family. This
//! directory exists because `ENC-719`–`ENC-721` land three endpoints that share one set of
//! invariants — they are the three delivery verbs of `CLAUDE.md` rule 6 that had no HTTP surface —
//! and splitting them across three root modules would put the reasoning about *why they must stay
//! distinct* in whichever of the three a reader happened to open first.

pub mod delivery;
