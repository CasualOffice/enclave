//! The DLP stage of the policy chain, in whichever of the five modes a tenant is running.
//!
//! # The whole of the mode's influence is three lines
//!
//! ```text
//! let verdict = self.rules.evaluate(action, facts);   // mode not in scope
//! let applied = self.mode.effect(&verdict);           // the one mapping
//! self.sink.record(&Observation::of(self.mode, …));   // records `Enforce.effect(&verdict)` too
//! ```
//!
//! `SIMULATION` and `ENFORCE` execute the identical first line — same detectors' output, same
//! facts, same rules, same comparisons — and differ only in what the second returns
//! (`plans/M4-GOVERNANCE.md` D28). There is no early return, no cached path and no branch on the
//! mode anywhere else in this module, which is what `tests/modes.rs` asserts by running one policy
//! both ways and comparing the recorded decision.
//!
//! # Q17, and what is *not* here
//!
//! Simulation consumes rate limits and does not consume quotas. Neither control is this stage's:
//! rate limiting is documented and not built (`docs/05 §…` specifies `RateLimit-*` headers that no
//! code emits), and a quota is charged by the write in `execute`, which a simulated evaluation
//! never reaches because it records rather than acts. So the answer is honoured by *construction*
//! rather than by a branch — there is no code here that could exempt a simulated evaluation from
//! load it genuinely caused, and none that could charge bytes never stored.

use std::sync::Arc;

use async_trait::async_trait;
use enclave_core::{
    Action, DlpService, FactsSnapshot, RequestContext, ResourceRef, Result, StageDecision,
};

use crate::mode::DlpMode;
use crate::observation::{Observation, ObservationSink};
use crate::policy::RuleSet;

/// DLP running one rule set in one mode.
///
/// Construct per tenant from configuration. Cheap to clone — the rules and the sink are shared.
#[derive(Debug, Clone)]
pub struct ModedDlp {
    mode: DlpMode,
    rules: RuleSet,
    sink: Arc<dyn ObservationSink>,
}

impl ModedDlp {
    /// Assembles the stage.
    ///
    /// The sink is required rather than optional. See [`ObservationSink`]: a mode whose only output
    /// is a record needs somewhere to put it, and defaulting to a discard would make `MONITOR` and
    /// `SIMULATION` indistinguishable from `DISABLED` in a way nothing reports.
    #[must_use]
    pub fn new(mode: DlpMode, rules: RuleSet, sink: Arc<dyn ObservationSink>) -> Self {
        Self { mode, rules, sink }
    }

    /// The mode in force, for the start-up banner and for an admin surface.
    #[must_use]
    pub const fn mode(&self) -> DlpMode {
        self.mode
    }

    /// The rules in force.
    #[must_use]
    pub const fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Evaluates, records, and returns what the mode decided.
    ///
    /// Split out from the trait method so a test can hold the [`Observation`] rather than only the
    /// [`StageDecision`] — the recorded decision is what D28 compares, and it is not recoverable
    /// from the decision alone. There is exactly one body; the trait method calls this one.
    #[must_use]
    pub fn evaluate_recording(
        &self,
        action: Action,
        resource: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> Observation {
        decide(self.mode, &self.rules, self.sink.as_ref(), action, resource, facts)
    }
}

/// Evaluate, act, record — **the only body that does those three things**.
///
/// A free function rather than a method, because there are now two stages that need it:
/// [`ModedDlp`], which holds one rule set for every tenant, and [`crate::tenant::TenantDlp`], which
/// loads a rule set per tenant from `dlp_rules` (`ENC-615`). A second copy of these three lines is
/// exactly the "second code path" `plans/M4-GOVERNANCE.md` D28's risk table warns about — it would
/// be the place a `SIMULATION`/`ENFORCE` divergence could appear without anyone editing
/// [`DlpMode::effect`].
///
/// The rules arrive as an argument and the mode does not reach them: `RuleSet::evaluate` still
/// takes no mode, so where the rules came from cannot change what they conclude.
#[must_use]
pub fn decide(
    mode: DlpMode,
    rules: &RuleSet,
    sink: &dyn ObservationSink,
    action: Action,
    resource: &ResourceRef,
    facts: &FactsSnapshot,
) -> Observation {
    // Step 1 — the conclusion. Mode-independent, and unable to be otherwise: `RuleSet` holds no
    // mode and `evaluate` takes none.
    let verdict = rules.evaluate(action, facts);

    // Step 2 — what this mode does about it. The only mode-sensitive line in the crate.
    let applied = mode.effect(&verdict);

    // Step 3 — the record, which computes `Enforce.effect(&verdict)` from the same function.
    let observation = Observation::of(mode, action, *resource, verdict, applied);

    // `DISABLED` inspects nothing, so there is nothing to record. Every other mode records,
    // including the ones that changed nothing about the request — a `MONITOR` evaluation that
    // found nothing is the evidence that the policy ran and was clean, which is what a rollout
    // is reading.
    if mode.evaluates() {
        sink.record(&observation);
    }

    observation
}

#[async_trait]
impl DlpService for ModedDlp {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> Result<StageDecision> {
        Ok(self.evaluate_recording(action, resource, facts).applied().clone().into_stage_decision())
    }
}
