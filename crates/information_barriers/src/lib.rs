//! `enclave-information_barriers` — Mandatory segmentation
//!
//! Security and governance — a policy service in the canonical chain.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

use async_trait::async_trait;
use enclave_core::{BarrierService, RequestContext, ResourceRef, Result, StageDecision};

/// Mandatory segmentation, evaluated against **no configured policy**.
///
/// This is the correct answer to the empty case rather than a stub that shrugs: with nothing
/// configured, this stage has nothing to object to, so it allows and says so (docs/06-SECURITY-DLP-ACCESS.md §14).
///
/// It is named for that state deliberately. A type called `DefaultBarriers` would read as "the usual
/// one" in a wiring block; this one reads as a question — is anything actually configured? The
/// answer is visible at start-up (`ApiState::unconfigured_stages`), and the `enterprise`
/// deployment profile refuses to boot while any remain.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredBarriers;

#[async_trait]
impl BarrierService for UnconfiguredBarriers {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }

    /// No segments exist, so no caller is inside one.
    ///
    /// An empty list is the honest answer and the safe one: search builds its filter from these
    /// tokens, and an empty allowed-set combined with content that carries no barrier tokens
    /// matches everything unsegmented and nothing segmented — which is exactly right.
    async fn allowed_barrier_tokens(&self, _ctx: &RequestContext) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}
