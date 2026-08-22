//! What a DLP evaluation leaves behind, and where it goes.
//!
//! # Why this is a port and not a `tracing::info!`
//!
//! `MONITOR` and `SIMULATION` have no effect on the request. The record *is* the mode's entire
//! output, so a record nobody can read is a mode that does nothing — and "`SIMULATION` records
//! only" (`docs/12-TESTING.md §4.5` D2) is an assertion about an absence, which `docs/12 §1.2`
//! warns passes for free. A trait is what lets the test assert the *presence* of the record beside
//! the absence of the block.
//!
//! # What may not be in one
//!
//! `CLAUDE.md` rule 10: never log DLP match values. An [`Observation`] carries rule identities,
//! detector *counts* and mode names. There is no field a matched byte could occupy, which is the
//! same property `enclave_core::SecurityFacts` has and for the same reason — it makes deriving
//! `Debug` safe rather than dangerous.

use enclave_core::{Action, Obligations, ResourceRef};

use crate::mode::{DlpMode, Effect};
use crate::policy::{Basis, RuleId, Verdict};

/// One evaluation, as it will be read afterwards.
///
/// # The three fields that make `SIMULATION` answerable
///
/// * `verdict` — what the policy concluded, computed without reference to the mode.
/// * `would_enforce` — what `ENFORCE` would have done, obtained by calling
///   [`DlpMode::effect`] with [`DlpMode::Enforce`]. Not a second implementation: the same function
///   the live mode called, with a different argument.
/// * `applied` — what this mode actually did.
///
/// Under `ENFORCE` the last two are equal by construction. Under `SIMULATION` they differ in
/// exactly one way — the action was recorded rather than taken — and `would_enforce` is the answer
/// to *"what would this policy have done to last week's traffic"* that D28 exists to keep truthful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    mode: DlpMode,
    action: Action,
    resource: ResourceRef,
    verdict: Verdict,
    would_enforce: Effect,
    applied: Effect,
}

impl Observation {
    /// Records one evaluation.
    ///
    /// `would_enforce` is computed here rather than taken as an argument, so that no caller can
    /// record a would-be decision that [`DlpMode::effect`] would not have produced.
    #[must_use]
    pub fn of(
        mode: DlpMode,
        action: Action,
        resource: ResourceRef,
        verdict: Verdict,
        applied: Effect,
    ) -> Self {
        let would_enforce = DlpMode::Enforce.effect(&verdict);
        Self { mode, action, resource, verdict, would_enforce, applied }
    }

    /// The mode that was running.
    #[must_use]
    pub const fn mode(&self) -> DlpMode {
        self.mode
    }

    /// The action attempted.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// What it was attempted against.
    #[must_use]
    pub const fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// What the policy concluded, mode-independently.
    pub const fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    /// What `ENFORCE` would have done about it.
    pub const fn would_enforce(&self) -> &Effect {
        &self.would_enforce
    }

    /// What this mode did about it.
    pub const fn applied(&self) -> &Effect {
        &self.applied
    }

    /// Whether the request was actually refused.
    #[must_use]
    pub const fn was_blocked(&self) -> bool {
        self.applied.denies()
    }

    /// Whether enforcement *would* have refused it.
    #[must_use]
    pub const fn would_have_blocked(&self) -> bool {
        self.would_enforce.denies()
    }

    /// The obligations actually attached to the decision.
    pub fn applied_obligations(&self) -> Obligations {
        self.applied.obligations()
    }

    /// The rules that fired.
    #[must_use]
    pub fn fired(&self) -> Vec<&RuleId> {
        self.verdict.fired().iter().map(|(id, _)| id).collect()
    }

    /// Whether this evaluation permitted an action against content nobody has scanned.
    ///
    /// The `FAIL_OPEN_AUDIT` case, and the thing that makes the mode more than an allow: `docs/06
    /// §12` requires a high-visibility event and a priority rescan, and this is what a sink reads
    /// to raise them.
    #[must_use]
    pub const fn permitted_unscanned(&self) -> bool {
        matches!(self.verdict.basis(), Basis::Unscanned { .. })
    }
}

/// Where observations go.
///
/// Deliberately not defaulted to a no-op implementation. A sink that discards is a `MONITOR` mode
/// that monitors nothing, and the failure is silent — so the type system asks for one.
pub trait ObservationSink: Send + Sync + std::fmt::Debug {
    /// Records one evaluation.
    ///
    /// Infallible on purpose. A DLP evaluation that has already *decided* must not be turned into
    /// an error by a recording failure — the chain's own audit row is written by the engine and is
    /// what `CLAUDE.md` rule 10 makes non-optional. This sink is the DLP-specific detail beside it,
    /// and an implementation that cannot write should say so through its own metrics rather than
    /// convert a refusal into a `500`.
    fn record(&self, observation: &Observation);
}

/// The shipped sink: one structured `tracing` event per evaluation.
///
/// Honest about what it is. `docs/06 §13` wants incidents in a table and `docs/06 §9`'s admin
/// surface wants to query simulation history; neither exists, and a log line is what can be written
/// today without inventing a schema. `ENC-593` is the row for the durable one.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingObservations;

impl ObservationSink for TracingObservations {
    fn record(&self, observation: &Observation) {
        // Counts and identities only. The fields below are each either an enumeration variant, a
        // rule id or a boolean — there is no path from a matched byte to this line.
        tracing::info!(
            mode = observation.mode().as_str(),
            action = %observation.action(),
            resource = %observation.resource(),
            rules_fired = observation.fired().len(),
            blocked = observation.was_blocked(),
            would_block = observation.would_have_blocked(),
            unscanned = observation.permitted_unscanned(),
            "dlp evaluated"
        );
    }
}
