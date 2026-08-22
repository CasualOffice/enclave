//! DLP rules, and the **mode-independent** verdict evaluating them produces.
//!
//! # Nothing here can see the mode
//!
//! That is the point of the module boundary. A [`RuleSet`] holds rules; it has no mode field, and
//! [`RuleSet::evaluate`] takes no mode argument. `SIMULATION` and `ENFORCE` therefore cannot reach
//! different conclusions, because the code that reaches a conclusion has not been told which one is
//! running (`plans/M4-GOVERNANCE.md` D28, and [`crate::mode`] for the rest of the argument).
//!
//! # An action no rule governs never consults facts
//!
//! [`RuleSet::evaluate`] establishes *which rules apply* before it asks for facts, and returns
//! [`Basis::NotGoverned`] when none do. Without that ordering a tenant on `FAIL_CLOSED` would find
//! every action refused while a scan was pending — including the ones no policy has anything to say
//! about — which is the "control nobody dares enable" `plans/M4-GOVERNANCE.md §2` is arranged
//! against.

use enclave_core::{
    Action, ClassificationRank, DetectorCategory, Exposure, FactsOutcome, FactsSnapshot,
    FactsStaleness, Obligation, Obligations, ReasonCode, Remediation, RiskScore, SecurityFacts,
    Severity, UnscannedAllow,
};
use serde::{Deserialize, Serialize};

/// A rule's identity, as it appears in `dlp_policies` and in an observation.
///
/// A `String` rather than the `&'static str` [`crate::DetectorId`] uses, and the difference is
/// real: a detector is compiled in, a rule is a row a security administrator created.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(String);

impl RuleId {
    /// Names a rule.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a rule demands when it fires (`docs/06-SECURITY-DLP-ACCESS.md §10`).
///
/// The full documented vocabulary, and deliberately not `#[non_exhaustive]`: adding an action must
/// break [`DlpAction::demand`] and force someone to say what it means, rather than inheriting a
/// wildcard arm that treats it as nothing.
///
/// # Three of these cannot yet be carried out, and they refuse rather than pretend
///
/// `QUARANTINE` should mark the version, `REMOVE_SHARE` should delete the link and
/// `NOTIFY_SECURITY` should raise an incident. None of those side effects exists yet — the version
/// state machine, `crates/sharing`'s revocation path and `crates/incidents` are each somebody
/// else's milestone. An action we cannot carry out is an unsatisfiable obligation, and D29 says an
/// unsatisfiable obligation is a denial, so the first two refuse. `NOTIFY_SECURITY` is the
/// exception and is honest about it: the notification's destination *is* the observation sink, so
/// recording is the whole of it. `ENC-592` tracks the missing side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DlpAction {
    /// Explicitly permit. A rule that fires and does nothing, which exists so an exception can be
    /// written above a broader rule.
    Allow,
    /// Record the match and permit.
    Audit,
    /// Record the match, permit, and mark the record as one a user should be warned about.
    Warn,
    /// Permit once the caller records a business justification.
    RequireJustification,
    /// Permit once an approver signs off.
    RequireApproval,
    /// Refuse.
    Block,
    /// Refuse and hold the content for a security review.
    Quarantine,
    /// Remove the sharing link the action targets.
    RemoveShare,
    /// Permit the read, suppress every mutation path in the response.
    ReadOnly,
    /// Serve a rendition, never the original bytes.
    NoDownload,
    /// Stamp the rendition with an identifying watermark.
    Watermark,
    /// Raise the resource's classification.
    Reclassify {
        /// The rank to raise it to.
        to: ClassificationRank,
    },
    /// Raise the match to the security team.
    NotifySecurity,
}

/// What a fired rule requires of the chain, once translated out of `docs/06 §10`'s vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// Nothing beyond the record.
    Nothing,
    /// This obligation, which the caller must satisfy.
    Obligation(Obligation),
    /// A refusal, with the code the caller may be shown.
    Refusal(ReasonCode),
}

impl DlpAction {
    /// The stable form, as `docs/06 §10` spells it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Audit => "AUDIT",
            Self::Warn => "WARN",
            Self::RequireJustification => "REQUIRE_JUSTIFICATION",
            Self::RequireApproval => "REQUIRE_APPROVAL",
            Self::Block => "BLOCK",
            Self::Quarantine => "QUARANTINE",
            Self::RemoveShare => "REMOVE_SHARE",
            Self::ReadOnly => "READ_ONLY",
            Self::NoDownload => "NO_DOWNLOAD",
            Self::Watermark => "WATERMARK",
            Self::Reclassify { .. } => "RECLASSIFY",
            Self::NotifySecurity => "NOTIFY_SECURITY",
        }
    }

    /// What this action requires of the chain.
    ///
    /// `docs/06 §10`: *"actions that modify the request rather than reject it are returned as
    /// obligations the caller must apply — they are never silently dropped."* This is where that
    /// sentence is decided, once, so two call sites cannot classify one action differently.
    #[must_use]
    pub const fn demand(&self) -> Demand {
        match self {
            Self::Allow | Self::Audit | Self::Warn | Self::NotifySecurity => Demand::Nothing,
            Self::RequireJustification => Demand::Obligation(Obligation::RequireJustification),
            Self::RequireApproval => Demand::Obligation(Obligation::RequireApproval),
            Self::ReadOnly => Demand::Obligation(Obligation::ReadOnly),
            Self::NoDownload => Demand::Obligation(Obligation::NoDownload),
            Self::Watermark => Demand::Obligation(Obligation::Watermark),
            Self::Reclassify { to } => Demand::Obligation(Obligation::Reclassify { to: *to }),
            Self::Block | Self::Quarantine => Demand::Refusal(ReasonCode::DlpBlocked),
            // The link is not actually removed — see the type's documentation. Refusing the action
            // that would have broadened it is the fail-closed half of what this action means, and
            // it is the half that can be honoured today.
            Self::RemoveShare => Demand::Refusal(ReasonCode::ExternalShareBlocked),
        }
    }

    /// Whether `docs/06 §9` requires this action to be simulated before it may be enforced.
    ///
    /// *"Simulation is mandatory before enforcement for any policy whose effect is `BLOCK` or
    /// `QUARANTINE`."* Stated on the type so an admin surface can ask rather than re-derive.
    #[must_use]
    pub const fn requires_simulation_first(&self) -> bool {
        matches!(self, Self::Block | Self::Quarantine)
    }
}

impl std::fmt::Display for DlpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which actions a rule governs.
///
/// Predicates over the action rather than a list of every variant, because a rule written as "block
/// export of anything carrying payment data" has to keep working when a new content-exposing action
/// is added — and `Action::exposes_content` is where the codebase already decides what that means.
///
/// `Deserialize` is externally tagged and closed, so `{"exactly": …}` is an [`ActionScope`] and
/// nothing else can be. A stored scope naming a variant this enum does not have is refused by name
/// (`crate::store`), never trimmed to the clauses that parsed: a rule that lost a scope governs
/// *fewer* actions than the administrator wrote, and the actions it stops governing are the ones
/// nobody notices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionScope {
    /// Every action.
    Any,
    /// Anything that can put content, or a rendition of it, in front of the caller.
    ExposesContent,
    /// Anything that creates external exposure, or broadens one that already exists.
    ///
    /// The second half needs the resource, which is why [`ActionScope::matches`] takes the
    /// exposure the snapshot was gathered with.
    ExternalSharing,
    /// Exactly this action.
    Exactly(Action),
}

impl ActionScope {
    /// Whether this scope covers the attempt.
    #[must_use]
    pub fn matches(&self, action: Action, exposure: Exposure) -> bool {
        match self {
            Self::Any => true,
            Self::ExposesContent => action.exposes_content(),
            Self::ExternalSharing => {
                action.is_external_share()
                    || (exposure.is_external() && action.alters_existing_share())
            }
            Self::Exactly(exact) => *exact == action,
        }
    }
}

/// A condition over the facts a scan produced, or over the resource's label.
///
/// Q16 is binding here as much as in [`crate::detector`]: every condition is a comparison against a
/// count, a rank or a score. **There is no variant a pattern could occupy**, so a tenant asking for
/// a custom expression cannot be served by adding one to this enum either.
///
/// Storage is where that would otherwise be lost, because JSONB holds any document. `Deserialize`
/// is externally tagged and closed, so `{"pattern": "\\d{16}"}` in a stored rule produces
/// *unknown variant `pattern`* and the load **fails** — the rule is refused by name rather than
/// having the clause dropped. A rule that lost a condition matches **more** requests than the
/// administrator wrote, which is the permissive failure; a rule that keeps a condition nobody can
/// evaluate is the one this refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// At least this many findings in one category.
    CategoryAtLeast {
        /// The bucket.
        category: DetectorCategory,
        /// The threshold, inclusive.
        count: u32,
    },
    /// Any finding at all, in any category.
    AnyFinding,
    /// The most serious finding is at or above this severity.
    SeverityAtLeast(Severity),
    /// The composite risk score is at or above this.
    RiskAtLeast(RiskScore),
    /// The resource carries a label at or above this rank.
    ClassificationAtLeast(ClassificationRank),
}

impl Condition {
    /// Whether the condition holds.
    ///
    /// `label` is the resource's *current* classification, from the snapshot, rather than the one
    /// the scan resolved: a rule about `RESTRICTED` documents is about how the document is
    /// labelled, and a scan that inferred nothing must not read as "not restricted".
    #[must_use]
    pub fn holds(&self, facts: &SecurityFacts, label: Option<ClassificationRank>) -> bool {
        match self {
            Self::CategoryAtLeast { category, count } => facts.counts().get(*category) >= *count,
            Self::AnyFinding => !facts.counts().is_empty(),
            Self::SeverityAtLeast(threshold) => {
                facts.max_severity().is_some_and(|actual| actual >= *threshold)
            }
            Self::RiskAtLeast(threshold) => facts.risk_score() >= *threshold,
            Self::ClassificationAtLeast(rank) => {
                label.or_else(|| facts.classification()).is_some_and(|actual| actual >= *rank)
            }
        }
    }
}

/// One rule: what it governs, when it fires, and what it demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpRule {
    id: RuleId,
    scope: Vec<ActionScope>,
    conditions: Vec<Condition>,
    action: DlpAction,
}

impl DlpRule {
    /// Builds a rule.
    ///
    /// The conditions are conjunctive — *all* must hold — because that is the shape of every rule
    /// `docs/06 §8` describes ("card number within 50 characters of an expiry date"), and a rule
    /// language with disjunction is written as two rules.
    #[must_use]
    pub fn new(
        id: RuleId,
        scope: Vec<ActionScope>,
        conditions: Vec<Condition>,
        action: DlpAction,
    ) -> Self {
        Self { id, scope, conditions, action }
    }

    /// The rule's identity.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// What it demands when it fires.
    #[must_use]
    pub const fn action(&self) -> DlpAction {
        self.action
    }

    /// Which actions it governs.
    ///
    /// Exposed so [`crate::store`] can render a rule back into the row it came from. A rule that
    /// could be decoded and not re-encoded would make an admin surface unable to show an
    /// administrator what it stored, and would leave the two directions untestable against each
    /// other.
    #[must_use]
    pub fn scope(&self) -> &[ActionScope] {
        &self.scope
    }

    /// The conjunctive conditions. Empty means "whenever the action is governed".
    #[must_use]
    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// Whether this rule has anything to say about the attempt.
    ///
    /// A rule with an empty scope governs nothing. That is not a rule that applies to everything —
    /// the permissive reading of an empty list is how a mis-migrated policy row becomes a
    /// tenant-wide block.
    #[must_use]
    pub fn governs(&self, action: Action, exposure: Exposure) -> bool {
        self.scope.iter().any(|scope| scope.matches(action, exposure))
    }

    /// Whether the rule's conditions hold against these facts.
    ///
    /// A rule with no conditions fires whenever it governs the action — the "block every external
    /// share of this library" shape, which needs no detector.
    #[must_use]
    pub fn fires(&self, facts: &SecurityFacts, label: Option<ClassificationRank>) -> bool {
        self.conditions.iter().all(|condition| condition.holds(facts, label))
    }
}

/// What the evidence behind a verdict was.
///
/// Recorded so an observation says *why* as well as *what*. A `BLOCK` taken against fresh facts and
/// a `BLOCK` taken because no facts existed are the same outcome for very different reasons, and an
/// operator tuning a rollout needs to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// No rule governs this action, so facts were never consulted.
    NotGoverned,
    /// Decided against usable facts.
    Facts,
    /// No usable facts, and the tenant's `facts_unavailable` policy concluded a refusal.
    Unavailable {
        /// The code that conclusion carries.
        code: ReasonCode,
        /// What the caller can do about it.
        remediation: Remediation,
        /// Whether facts were absent or merely produced by another detector set.
        staleness: FactsStaleness,
    },
    /// No usable facts, and the tenant's policy permitted proceeding. The high-visibility audit
    /// event and the priority rescan are the observation's to raise.
    Unscanned {
        /// Whether facts were absent or produced by another detector set.
        staleness: FactsStaleness,
    },
}

/// What a rule set concluded about one attempt, before any mode decides what to do about it.
///
/// **Contains no mode and no effect.** That is what makes it the value D28's test compares: two
/// modes running the same policy over the same facts must produce equal verdicts, and they cannot
/// help doing so because neither was told which mode it was.
#[must_use = "a verdict is what the policy concluded; dropping it skips the control"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    basis: Basis,
    fired: Vec<(RuleId, DlpAction)>,
}

impl Verdict {
    /// What the conclusion rests on.
    #[must_use]
    pub const fn basis(&self) -> &Basis {
        &self.basis
    }

    /// The rules that fired, in rule order, with what each demanded.
    #[must_use]
    pub fn fired(&self) -> &[(RuleId, DlpAction)] {
        &self.fired
    }

    /// Whether any rule fired.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.fired.is_empty()
    }

    /// The refusal the fired rules demand, if any.
    ///
    /// The *first* in rule order rather than a computed "strongest": ranking refusals would need an
    /// ordering over reason codes that nothing else in the codebase has, and a security
    /// administrator who writes a specific rule above a general one already expressed their
    /// intended precedence by the order they wrote them in.
    #[must_use]
    pub fn blocking_code(&self) -> Option<ReasonCode> {
        self.fired.iter().find_map(|(_, action)| match action.demand() {
            Demand::Refusal(code) => Some(code),
            Demand::Nothing | Demand::Obligation(_) => None,
        })
    }

    /// Every obligation the fired rules demand.
    ///
    /// The union, including obligations from rules that *also* block: a mode that does not enforce
    /// still has to know what enforcement would have required, or its record understates the
    /// change an operator is about to make.
    pub fn obligations(&self) -> Obligations {
        let mut obligations = Obligations::none();
        for (_, action) in &self.fired {
            if let Demand::Obligation(obligation) = action.demand() {
                let _new = obligations.insert(obligation);
            }
        }
        obligations
    }

    /// Whether any fired rule is one `docs/06 §9` requires to be simulated before enforcement.
    #[must_use]
    pub fn requires_simulation_first(&self) -> bool {
        self.fired.iter().any(|(_, action)| action.requires_simulation_first())
    }
}

/// The rules in force for a tenant.
///
/// Holds **no mode**. See the module documentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<DlpRule>,
}

impl RuleSet {
    /// Assembles a rule set. Order is precedence order for refusals; see
    /// [`Verdict::blocking_code`].
    #[must_use]
    pub fn new(rules: Vec<DlpRule>) -> Self {
        Self { rules }
    }

    /// No rules at all — a tenant whose policies have not been written yet.
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// How many rules are in force.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether no rule is in force.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates every governing rule against the facts the chain gathered.
    ///
    /// Takes no mode and cannot reach one (D28). Takes the snapshot by reference and calls
    /// [`FactsSnapshot::require`] at most once, so the freshness question is answered where
    /// `ENC-581` put it rather than re-derived here.
    ///
    /// The returned [`UnscannedAllow`] — when the tenant's policy permitted proceeding without
    /// facts — is folded into [`Basis::Unscanned`] rather than dropped: it is `#[must_use]`
    /// precisely because fail-open without the audit trail is an ordinary allow nobody can find
    /// afterwards.
    pub fn evaluate(&self, action: Action, facts: &FactsSnapshot) -> Verdict {
        let exposure = facts.exposure();
        let governing: Vec<&DlpRule> =
            self.rules.iter().filter(|rule| rule.governs(action, exposure)).collect();

        // Before the facts, deliberately. An action no policy governs must not be refused because
        // a scan has not finished — nothing was going to be decided from that scan.
        if governing.is_empty() {
            return Verdict { basis: Basis::NotGoverned, fired: Vec::new() };
        }

        match facts.require(action) {
            FactsOutcome::Facts(facts_value) => {
                let label = facts.resource().classification();
                let fired = governing
                    .into_iter()
                    .filter(|rule| rule.fires(facts_value, label))
                    .map(|rule| (rule.id().clone(), rule.action()))
                    .collect();
                Verdict { basis: Basis::Facts, fired }
            }
            FactsOutcome::Denied { code, remediation } => Verdict {
                basis: Basis::Unavailable { code, remediation, staleness: facts.staleness() },
                fired: Vec::new(),
            },
            FactsOutcome::Unscanned(allow) => {
                let allow: UnscannedAllow = allow;
                Verdict {
                    basis: Basis::Unscanned { staleness: allow.staleness() },
                    fired: Vec::new(),
                }
            }
        }
    }
}
