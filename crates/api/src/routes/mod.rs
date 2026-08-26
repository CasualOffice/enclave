//! Route modules.
//!
//! The oldest handlers each have a module at the crate root, one per endpoint family; newer ones
//! live here. [`delivery`] holds all three of `ENC-719`–`ENC-721` together rather than one module
//! per route, because what they share is the reasoning about why they must stay *apart* — three
//! separate modules would leave `CLAUDE.md` rule 6's argument in whichever of them a reader
//! happened to open first.

pub mod delivery;
