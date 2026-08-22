//! The tenant administration surface (`docs/05-API.md §14`).
//!
//! Everything here governs a tenant's own configuration rather than its content, which changes two
//! things about a handler and nothing else:
//!
//! 1. **The action is an [`AdminAction`](enclave_core::AdminAction) and the resource is the
//!    tenant.** Not the object being edited: this is the same reason
//!    `crates/conditional_access` ignores the `ResourceRef` it is handed — a decision that varied
//!    with the object would be an oracle for the object's existence, answerable by a caller the
//!    chain is about to refuse. "May this caller manage this tenant's policy" is the question, and
//!    the object's existence is settled afterwards, by a tenant-scoped statement that moves no rows.
//! 2. **A privileged mutation needs recent multi-factor authentication** (`docs/05-API.md §14`,
//!    `docs/06-SECURITY-DLP-ACCESS.md §22`). `conditional_access::require_step_up` is where that is
//!    applied, and its comment is where the part of it that is not yet in the right place is
//!    written down (`ENC-620`).
//!
//! Neither replaces the policy chain. `PolicyEngine::enforce` runs first on every route here, as
//! `CLAUDE.md` rule 1 requires and as `cargo run -p xtask -- policy-routing` checks.

pub mod conditional_access;
pub mod dlp;
