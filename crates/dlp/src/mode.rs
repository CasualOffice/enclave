//! The five DLP modes (`docs/06-SECURITY-DLP-ACCESS.md §9`), and the single function that turns a
//! verdict into what a mode does about it.
//!
//! # D28, expressed as a shape rather than as a rule
//!
//! `plans/M4-GOVERNANCE.md` D28: **`SIMULATION` must be indistinguishable from `ENFORCE` except in
//! its effect.** Same detectors, same facts, same evaluation, same audit row shape, same latency
//! budget. The plan's own risk table notes that *"nothing structurally prevents a second code path
//! appearing"*, so the arrangement here is chosen to make that path hard to write:
//!
//! 1. **Evaluation is never told the mode.** [`crate::policy::RuleSet`] holds rules and no mode
//!    field, and [`crate::policy::RuleSet::evaluate`] takes no mode argument. There is nowhere in
//!    the code that computes a verdict from which the mode is reachable, so a branch on it cannot
//!    be added without first changing a signature — which is a diff a reviewer sees.
//! 2. **One mapping, called twice.** [`DlpMode::effect`] is the only function that turns a verdict
//!    into an [`Effect`], and every observation records what `ENFORCE` would have done by calling
//!    *that same function* with [`DlpMode::Enforce`]. A simulation therefore cannot report a
//!    would-be decision that enforcement would not have taken: the two are the same call.
//!
//! A simulation that is fast because it skips work is a rehearsal of a different play, and
//! `docs/06 §9` requires simulation before enforcement for any `BLOCK` or `QUARANTINE` policy —
//! which is worth nothing if the two run different code.
//!
//! # The ladder
//!
//! | Mode | Evaluates | Records | Applies obligations | Denies |
//! |---|---|---|---|---|
//! | `DISABLED` | no | no | no | no |
//! | `MONITOR` | yes | yes | no | no |
//! | `SIMULATION` | yes | yes | no | no |
//! | `WARN` | yes | yes | yes | no |
//! | `ENFORCE` | yes | yes | yes | yes |
//!
//! `MONITOR` and `SIMULATION` have the same effect on a request and are not the same mode. The
//! difference is what the record *means*: `MONITOR` says a live policy observed this, `SIMULATION`
//! says a candidate policy was rehearsed against it. `docs/06 §9`'s "the admin UI refuses to enable
//! enforcement on a policy that has never been simulated" is a question asked of the second kind of
//! record, and a mode that recorded them identically could not answer it.
//!
//! `DISABLED` is the one mode that does not evaluate, and that is not an optimisation — it is what
//! the mode means. It is excluded from the D28 comparison for the same reason.

use enclave_core::{Obligations, ReasonCode, StageDecision};

use crate::policy::{Basis, Verdict};

/// How a tenant's DLP policy is being run (`docs/06 §9`).
///
/// Ordered from least to most enforcing, and the ordering is deliberate: `docs/06 §9`'s rollout
/// requirement is a walk up this list, and `plans/M4-GOVERNANCE.md §2` is the argument for why the
/// walk has to be possible at all — *a control that cannot be turned on gradually will be turned on
/// carelessly, or not at all.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum DlpMode {
    /// No content inspection at any enforcement point.
    ///
    /// A real mode a tenant may legitimately run in, not a placeholder. `crate::DisabledDlp` is its
    /// implementation and stays reachable.
    Disabled,
    /// Evaluate and record; the request is unaffected.
    ///
    /// The default, so a new deployment does not start refusing work before its rules have been
    /// tuned.
    #[default]
    Monitor,
    /// Evaluate and record what enforcement *would* have done; the request is unaffected.
    Simulation,
    /// Evaluate, record, and apply the obligations the rules demand — but never refuse.
    Warn,
    /// Evaluate, record, apply obligations, and refuse what the rules block.
    Enforce,
}

impl DlpMode {
    /// Every mode, in rollout order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Disabled, Self::Monitor, Self::Simulation, Self::Warn, Self::Enforce]
    }

    /// The stable form, as `docs/06 §9` spells it. Written into observations and audit rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "DISABLED",
            Self::Monitor => "MONITOR",
            Self::Simulation => "SIMULATION",
            Self::Warn => "WARN",
            Self::Enforce => "ENFORCE",
        }
    }

    /// Whether this mode inspects content at all.
    ///
    /// True for everything except [`Self::Disabled`]. Note what it is *not*: a licence to take a
    /// cheaper path. Every mode for which this is true runs the identical evaluation (D28).
    #[must_use]
    pub const fn evaluates(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether this mode may refuse a request.
    #[must_use]
    pub const fn enforces(self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Whether the obligations a rule demands are attached to the decision rather than only
    /// recorded.
    #[must_use]
    pub const fn applies_obligations(self) -> bool {
        matches!(self, Self::Warn | Self::Enforce)
    }

    /// What this mode does about a verdict.
    ///
    /// **The only place a mode influences an outcome.** Everything upstream of here — which rules
    /// govern the action, whether the facts were usable, what the detectors found — is computed
    /// without reference to the mode, which is what makes a `SIMULATION`/`ENFORCE` divergence a
    /// change to this one function rather than something that can drift in.
    pub fn effect(self, verdict: &Verdict) -> Effect {
        if !self.evaluates() {
            return Effect::Allow(Obligations::none());
        }

        // A missing-facts denial is the tenant's `facts_unavailable` policy speaking, and it is
        // still only a *conclusion*. Whether a conclusion is acted on is what the mode decides, and
        // a tenant that has not enabled enforcement has not asked DLP to refuse anything — so
        // `facts_unavailable` cannot enable blocking on their behalf. A non-enforcing mode that
        // could still deny would also be a mode nobody could roll out, which is §2's whole subject.
        if let Basis::Unavailable { code, .. } = verdict.basis() {
            return if self.enforces() {
                Effect::Deny(*code)
            } else {
                Effect::Allow(Obligations::none())
            };
        }

        if self.enforces() {
            if let Some(code) = verdict.blocking_code() {
                return Effect::Deny(code);
            }
        }

        if self.applies_obligations() {
            Effect::Allow(verdict.obligations())
        } else {
            Effect::Allow(Obligations::none())
        }
    }
}

impl std::fmt::Display for DlpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<enclave_config::DlpMode> for DlpMode {
    /// The operator's word for a mode, turned into the one the chain runs.
    ///
    /// Two types for one vocabulary, because `enclave-config` is the deserializable surface and
    /// this crate is where the mode does something. The mapping is total and exhaustive, so adding
    /// a sixth mode to either side fails to compile rather than silently arriving as `MONITOR`.
    fn from(configured: enclave_config::DlpMode) -> Self {
        match configured {
            enclave_config::DlpMode::Disabled => Self::Disabled,
            enclave_config::DlpMode::Monitor => Self::Monitor,
            enclave_config::DlpMode::Simulation => Self::Simulation,
            enclave_config::DlpMode::Warn => Self::Warn,
            enclave_config::DlpMode::Enforce => Self::Enforce,
        }
    }
}

/// What a mode decided to do about a verdict.
///
/// Two arms and no third. There is no "allow but note that an obligation could not be attached":
/// D29 says an obligation is satisfied or the operation fails, and an [`Effect`] that could carry
/// an unattached obligation is the third outcome D29 denies exists.
#[must_use = "an effect is what the DLP stage decided; dropping it skips the control"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Permit, subject to these obligations.
    Allow(Obligations),
    /// Refuse, with the code the caller may be shown.
    Deny(ReasonCode),
}

impl Effect {
    /// Whether this effect refuses the request.
    #[must_use]
    pub const fn denies(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// The obligations attached, if any.
    pub fn obligations(&self) -> Obligations {
        match self {
            Self::Allow(obligations) => obligations.clone(),
            Self::Deny(_) => Obligations::none(),
        }
    }

    /// Turns the effect into the chain's stage decision.
    pub fn into_stage_decision(self) -> StageDecision {
        match self {
            Self::Allow(obligations) => StageDecision::allow_with(obligations),
            Self::Deny(code) => StageDecision::deny(code),
        }
    }
}
