//! `enclave-classification` — Labels, ranks, inheritance, ceilings
//!
//! Security and governance — a policy service in the canonical chain.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

use async_trait::async_trait;
use enclave_core::{
    Action, ClassificationService, RequestContext, ResourceRef, Result, StageDecision,
};

/// Labels, ranks, inheritance, ceilings, evaluated against **no configured policy**.
///
/// This is the correct answer to the empty case rather than a stub that shrugs: with nothing
/// configured, this stage has nothing to object to, so it allows and says so (docs/06-SECURITY-DLP-ACCESS.md §9).
///
/// It is named for that state deliberately. A type called `DefaultClassification` would read as "the usual
/// one" in a wiring block; this one reads as a question — is anything actually configured? The
/// answer is visible at start-up (`ApiState::unconfigured_stages`), and the `enterprise`
/// deployment profile refuses to boot while any remain.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredClassification;

#[async_trait]
impl ClassificationService for UnconfiguredClassification {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}
