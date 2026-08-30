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
pub mod retention;

use axum::http::StatusCode;
use enclave_core::RequestContext;

use crate::error::Envelope;
use crate::state::StepUpPolicy;

/// Refuses a privileged mutation that is not backed by recent multi-factor authentication.
///
/// `docs/05-API.md §14`, `docs/06-SECURITY-DLP-ACCESS.md §22`. One function rather than one per
/// admin module: it lived privately in `dlp` and again in `conditional_access`, byte-identical but
/// for the log line, and a third caller (`workspaces::create`, `ENC-916`) is the point at which two
/// copies become the kind of duplication that drifts. A security check with three implementations
/// is a security check with three chances to be weakened one at a time, and the one that drifts is
/// the one nobody is reading.
///
/// It runs **after** `PolicyEngine::enforce`, so the chain decides first. The cost of that ordering
/// is honest and worth restating where it now applies to three surfaces: the engine has already
/// written an *allow* row when this refuses, so the audit log records a decision the request then
/// did not act on. The right home for the requirement is the conditional-access stage, where it is
/// a `RequireMfa` effect and would be audited as the denial it is. That is `ENC-620`.
///
/// `what` names the operation for the log line only. It is never returned to the caller: the
/// envelope is deliberately identical whatever was refused, because which admin surface a caller
/// reached is not something a caller who may not reach it should learn.
///
/// # Errors
///
/// An `Envelope` carrying `403 STEP_UP_REQUIRED` and the `acr`/`maxAge` the caller must satisfy.
pub(crate) fn require_step_up(
    ctx: &RequestContext,
    policy: StepUpPolicy,
    what: &'static str,
) -> Result<(), Envelope> {
    // `policy` rather than a constant: `security.mfa.admins_required` existed, was documented, and
    // was read by nothing, so this demanded a second factor the binary's `MfaVerifier` could never
    // check. A tenant administrator was refused their own policy surface for want of a factor they
    // had no way to present (`ENC-771`).
    if policy.satisfied_by(ctx.auth_strength, ctx.auth_age(chrono::Utc::now()).num_seconds()) {
        return Ok(());
    }

    tracing::warn!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        operation = what,
        "a privileged mutation was refused for want of a recent second factor"
    );
    Err(Envelope::new(
        StatusCode::FORBIDDEN,
        "STEP_UP_REQUIRED",
        "This action needs a fresher sign-in.",
        "Re-authenticate with a second factor and retry.",
    )
    .with_details(vec![serde_json::json!({
        "acr": "mfa",
        "maxAge": policy.max_age_secs(),
    })]))
}
