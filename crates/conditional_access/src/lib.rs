//! `enclave-conditional_access` — network, device and authentication-strength policy.
//!
//! The second stage of the canonical chain (`docs/03-LLD.md §12`), evaluated **before**
//! authorization so that a caller on a blocked network learns nothing about whether the resource
//! exists. `docs/06-SECURITY-DLP-ACCESS.md §7` is authoritative for what this stage decides.
//!
//! # Three things this crate is arranged around
//!
//! 1. **The client address is resolved honestly or not at all** ([`origin`]). A forwarding header
//!    is believed only from a configured network, hop by hop, right to left
//!    (`plans/M4-GOVERNANCE.md` D30). Every rule below is worth exactly as much as that resolution
//!    is honest, which is why it is the first module rather than a detail of the edge.
//! 2. **Two rule sets, not one with exemptions** ([`rules`]). Q19: service accounts and MCP tokens
//!    are governed by rules written for them — network allowlists and token binding — rather than
//!    by posture rules carrying an escape clause. The separation is enforced by the types.
//! 3. **Break-glass traverses this stage** ([`policy::BreakGlass`]). It has to: `docs/11 §5.6`
//!    exempts the emergency account from IP and zone policy and from nothing else, and a stage that
//!    is skipped cannot make that distinction — nor be audited, since audit happens inside the
//!    engine.

pub mod origin;
pub mod policy;
pub mod rules;
pub mod zone;

use async_trait::async_trait;
use enclave_core::{
    Action, ConditionalAccessService, RequestContext, ResourceRef, Result, StageDecision,
};

pub use origin::{ProxyTrust, ResolvedOrigin};
pub use policy::{Audience, BreakGlass, Evaluation, PolicySet};
pub use rules::{Effect, HumanCondition, HumanRule, MachineCondition, MachineRule, RuleMode};
pub use zone::{NetworkZone, ZoneMap};

/// Network/device/auth-strength policy evaluation, evaluated against **no configured policy**.
///
/// This is the correct answer to the empty case rather than a stub that shrugs: with nothing
/// configured, this stage has nothing to object to, so it allows and says so (docs/06-SECURITY-DLP-ACCESS.md §7).
///
/// It is named for that state deliberately. A type called `DefaultConditionalAccess` would read as "the usual
/// one" in a wiring block; this one reads as a question — is anything actually configured? The
/// answer is visible at start-up (`ApiState::unconfigured_stages`), and the `enterprise`
/// deployment profile refuses to boot while any remain.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredConditionalAccess;

#[async_trait]
impl ConditionalAccessService for UnconfiguredConditionalAccess {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}

/// Conditional access evaluated against a configured [`PolicySet`].
///
/// # Why the resource is not an input
///
/// [`ConditionalAccessService::evaluate`] is handed a `ResourceRef`, and this implementation
/// ignores it. That is deliberate rather than unfinished: this stage runs *before* authorization
/// precisely so that its refusal cannot depend on anything about the resource — a denial that
/// varied with the resource's classification would be an oracle for that classification, answerable
/// by a caller who is about to be told `404` for the resource's very existence. Resource-shaped
/// conditions (`classification == RESTRICTED AND action == DOWNLOAD`, from `docs/06 §7.1`) belong
/// to the classification stage, which runs after authorization has established the caller may see
/// the resource at all.
#[derive(Debug, Clone)]
pub struct ConfiguredConditionalAccess {
    policies: std::sync::Arc<PolicySet>,
}

impl ConfiguredConditionalAccess {
    /// Wraps a policy set.
    #[must_use]
    pub fn new(policies: PolicySet) -> Self {
        Self { policies: std::sync::Arc::new(policies) }
    }

    /// The configured policy, for the edge that needs its zone definitions.
    #[must_use]
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }
}

#[async_trait]
impl ConditionalAccessService for ConfiguredConditionalAccess {
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        let evaluation = self.policies.evaluate(ctx, action);

        // Simulation is reported and nothing else. `plans/M4-GOVERNANCE.md` D28 requires it to run
        // the same evaluation as enforcement, which it does — the mode is consulted once, after
        // matching — and this is where the difference becomes visible to an operator without
        // becoming visible to the caller.
        if !evaluation.simulated_rules().is_empty() {
            tracing::info!(
                %ctx.request_id,
                rules = ?evaluation.simulated_rules(),
                action = action.verb(),
                "conditional access rules matched in simulation"
            );
        }

        // High severity by design: `docs/11 §5.6` requires break-glass use to raise an immediate
        // alert to the security contact. The log line is the signal that alert is built on.
        if evaluation.break_glass_applied() {
            tracing::warn!(
                %ctx.request_id,
                %ctx.tenant_id,
                action = action.verb(),
                "break-glass session waived network conditional-access rules"
            );
        }

        Ok(evaluation.decision())
    }
}
