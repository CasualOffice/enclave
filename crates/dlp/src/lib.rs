//! `enclave-dlp` — Detectors, policies, decisions, security facts
//!
//! Security and governance — a policy service in the canonical chain.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

use async_trait::async_trait;
use enclave_core::{Action, DlpService, RequestContext, ResourceRef, Result, StageDecision};

/// DLP in its `DISABLED` mode.
///
/// Unlike the other unconfigured stages, this one models a state the specification names explicitly:
/// `DISABLED` is one of the five modes in `docs/06-SECURITY-DLP-ACCESS.md §9`, alongside `MONITOR`,
/// `SIMULATION`, `WARN` and `ENFORCE`. A tenant may legitimately run with DLP off.
///
/// So this is not a placeholder for missing code — it is the correct behaviour of a real mode, and
/// it will remain reachable after `ENC-133` lands the detector engine. What changes then is that
/// the mode becomes a configuration choice rather than the only option.
///
/// It deliberately does **not** consult `SecurityFacts`. With DLP disabled there is no policy whose
/// conditions could reference them, so a missing-facts decision (`docs/06 §12`) cannot arise. The
/// moment any mode other than `DISABLED` exists, that handling does too.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledDlp;

#[async_trait]
impl DlpService for DisabledDlp {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}
