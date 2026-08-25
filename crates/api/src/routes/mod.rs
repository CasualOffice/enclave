//! The resource families whose handlers live in their own file rather than at the crate root.
//!
//! `content`, `download` and `preview` predate this module and stay where they are; nothing is
//! gained by moving working handlers. What lands here is a family that arrives whole — its wire
//! types, its policy actions and its refusals in one place a reviewer can read against the section
//! of `docs/05-API.md` that specifies it.

pub mod shares;
pub mod uploads;
