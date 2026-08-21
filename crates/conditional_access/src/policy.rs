//! The configured policy, and how one request is decided against it.

use enclave_core::{Action, Actor, ActorKind, AuthStrength, RequestContext, StageDecision};

use crate::rules::{match_human, match_machine, Effect, Facts, HumanRule, MachineRule};
use crate::zone::ZoneMap;

/// Which rule set governs a principal (`plans/M4-GOVERNANCE.md` Q19).
///
/// Total over [`ActorKind`], deliberately, so that a new principal kind is a compile error here
/// rather than a principal no rule set covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Audience {
    /// A person: `user` or `guest`.
    Human,
    /// A credential: `service`, `mcp`, or `system`.
    Machine,
}

impl Audience {
    /// The rule set that governs this principal.
    ///
    /// # Why `system` is `Machine` rather than exempt
    ///
    /// `Actor::System` is not a private in-process identity. `crates/auth/src/claims.rs` maps the
    /// `typ: "system"` claim onto it, so a token can *assert* it — which means an exemption for
    /// `system` would be an exemption anybody holding such a token could reach, and Q19's whole
    /// point is that the exemption is the gap an attacker looks for.
    ///
    /// The consequence is worth stating because it is a real operational edge: in-process work
    /// (`RequestContext::system`) runs on loopback and in no zone, so a machine allowlist that does
    /// not include loopback denies the retention sweep and the outbox publisher. That failure is
    /// loud — the job errors — and it is the correct direction. It is not papered over here,
    /// because papering over it is exactly how the exemption gets written.
    #[must_use]
    pub const fn of(kind: ActorKind) -> Self {
        match kind {
            ActorKind::User | ActorKind::Guest => Self::Human,
            ActorKind::ServiceAccount | ActorKind::McpClient | ActorKind::System => Self::Machine,
        }
    }
}

/// Recognising the break-glass administrator (`docs/11-OPERATIONS.md §5.6`).
///
/// # Why conditional access is a stage break-glass traverses
///
/// `plans/M4-GOVERNANCE.md §5` names the risk plainly: *a zone rule that denies the network an
/// administrator is on is a control that cannot be undone through the product*, and asks that M4
/// not add a stage break-glass must traverse.
///
/// Break-glass does traverse this stage, and it must. Removing conditional access from the chain
/// for a principal means removing *every* effect — `NoDownload`, `PreviewOnly`, `RequireMfa` — and
/// `docs/11 §5.6` is explicit that the account is exempt from IP and zone policy and **not** from
/// MFA or audit. A stage that is skipped cannot honour that distinction, and a bypass that skips a
/// stage is exactly the shape `CLAUDE.md` rule 1 forbids. It also could not be audited, since audit
/// happens inside the engine.
///
/// So the exemption is narrow and lives inside the evaluation: rules that fire *because of where
/// the caller is* stop matching, `RequireTrustedNetwork` is satisfied, and everything else applies
/// unchanged. The lockout the risk table describes is undone; nothing else is.
///
/// # Why the exemption is conditioned on MFA
///
/// §5.6 says break-glass is not exempt from MFA. Rather than leaving that as a separate rule that
/// somebody must remember to write, it is a precondition of the exemption itself: a break-glass
/// token that authenticated with one factor gets no network exemption at all. The exemption cannot
/// therefore be used to *avoid* the requirement it is not exempt from.
#[derive(Debug, Clone)]
pub struct BreakGlass {
    scope: String,
}

impl BreakGlass {
    /// The scope a break-glass access token carries.
    ///
    /// A scope, not a configured user id, because scopes come from a *verified* token
    /// (`CLAUDE.md` rule 3): the deployment's token issuer decides who gets one, and no request can
    /// claim it for itself. A user-id list in `enclave.yaml` would be equivalent in effect and
    /// would put the identity of the emergency account in a file that ships to every host.
    pub const DEFAULT_SCOPE: &'static str = "admin:break_glass";

    /// Recognises break-glass by the default scope.
    #[must_use]
    pub fn default_scope() -> Self {
        Self::on_scope(Self::DEFAULT_SCOPE)
    }

    /// Recognises break-glass by a deployment-specific scope.
    #[must_use]
    pub fn on_scope(scope: impl Into<String>) -> Self {
        Self { scope: scope.into() }
    }

    /// Whether this request is a break-glass session.
    ///
    /// Three conditions, all required: a human principal, the scope in a verified token, and
    /// multi-factor authentication. Any of them missing means the ordinary rules apply in full.
    #[must_use]
    pub fn applies(&self, ctx: &RequestContext) -> bool {
        matches!(ctx.actor, Actor::User(_))
            && ctx.has_scope(&self.scope)
            && ctx.auth_strength.meets(AuthStrength::MultiFactor)
    }
}

/// What one evaluation concluded, including the rules that only rehearsed.
///
/// The decision is separated from the rule names because the names must never reach the caller —
/// `ReasonCode` is the whole of what crosses that boundary (`crates/core/src/error.rs`) — while an
/// operator needs them to understand a refusal and to read a simulation report.
#[derive(Debug)]
pub struct Evaluation {
    decision: StageDecision,
    enforced: Vec<(String, Effect)>,
    simulated: Vec<(String, Effect)>,
    /// Whether a break-glass session waived the network-shaped rules on this request. Recorded
    /// rather than inferred, because "the rules did not fire" and "the rules were waived" produce
    /// the same allow and only one of them is worth an alert.
    break_glass: bool,
}

impl Evaluation {
    /// The decision the chain acts on.
    pub fn decision(self) -> StageDecision {
        self.decision
    }

    /// The decision, without consuming the evaluation.
    pub fn peek(&self) -> &StageDecision {
        &self.decision
    }

    /// The enforcing rules that matched, by name.
    #[must_use]
    pub fn enforced_rules(&self) -> Vec<&str> {
        self.enforced.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// The simulating rules that matched, by name. These changed nothing.
    #[must_use]
    pub fn simulated_rules(&self) -> Vec<&str> {
        self.simulated.iter().map(|(name, _)| name.as_str()).collect()
    }

    /// Whether a break-glass session waived the network-shaped rules on this request.
    #[must_use]
    pub const fn break_glass_applied(&self) -> bool {
        self.break_glass
    }
}

/// Everything an administrator has configured for this stage.
///
/// Empty is a legitimate state and means "nothing to object to" — the same answer
/// [`crate::UnconfiguredConditionalAccess`] gives, reached through the same code rather than
/// through a shortcut, so a deployment that adds its first rule does not also change which
/// implementation is running.
#[derive(Debug, Clone)]
pub struct PolicySet {
    human: Vec<HumanRule>,
    machine: Vec<MachineRule>,
    zones: ZoneMap,
    break_glass: Option<BreakGlass>,
}

impl Default for PolicySet {
    fn default() -> Self {
        Self::empty()
    }
}

impl PolicySet {
    /// No rules, no zones, break-glass recognised by its default scope.
    ///
    /// Break-glass is on by default because it costs nothing when unused — no token carries the
    /// scope unless the issuer grants it — and because the failure it prevents is the one that
    /// cannot be fixed from inside the product.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            human: Vec::new(),
            machine: Vec::new(),
            zones: ZoneMap::empty(),
            break_glass: Some(BreakGlass::default_scope()),
        }
    }

    /// Adds the rules governing people.
    #[must_use]
    pub fn with_human_rules(mut self, rules: impl IntoIterator<Item = HumanRule>) -> Self {
        self.human.extend(rules);
        self
    }

    /// Adds the rules governing service accounts, MCP clients and `system`.
    #[must_use]
    pub fn with_machine_rules(mut self, rules: impl IntoIterator<Item = MachineRule>) -> Self {
        self.machine.extend(rules);
        self
    }

    /// Supplies the zone definitions rules refer to by name.
    #[must_use]
    pub fn with_zones(mut self, zones: ZoneMap) -> Self {
        self.zones = zones;
        self
    }

    /// Changes how a break-glass session is recognised, or turns the exemption off entirely.
    ///
    /// `None` is available for a deployment that would rather be locked out than carry the
    /// exemption. It is a decision worth being able to make explicitly; it is not the default,
    /// because the lockout it accepts cannot be undone through the product.
    #[must_use]
    pub fn with_break_glass(mut self, break_glass: Option<BreakGlass>) -> Self {
        self.break_glass = break_glass;
        self
    }

    /// Whether any rule is configured at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.human.is_empty() && self.machine.is_empty()
    }

    /// The zone definitions, for the edge that builds `NetworkContext::zones` from them.
    #[must_use]
    pub const fn zones(&self) -> &ZoneMap {
        &self.zones
    }

    /// Evaluates one request.
    ///
    /// The audience is chosen from the principal's kind, and **only one rule set runs**. A human
    /// rule cannot deny a service account and a machine rule cannot deny a person — which is what
    /// makes the two sets independent enough that neither needs an escape clause for the other's
    /// principals.
    #[must_use]
    pub fn evaluate(&self, ctx: &RequestContext, action: Action) -> Evaluation {
        let audience = Audience::of(ctx.actor.kind());
        let break_glass = self.break_glass.as_ref().is_some_and(|exemption| exemption.applies(ctx));

        let matches = match audience {
            Audience::Human => match_human(&self.human, ctx, action, break_glass),
            Audience::Machine => {
                match_machine(&self.machine, ctx, action, Facts { zones: &self.zones })
            }
        };

        // A break-glass session is inside *some* trusted network by fiat, which is what makes
        // `RequireTrustedNetwork` satisfiable for an administrator whose network a rule has just
        // put out of bounds. Everything else in the context is untouched, so `RequireMfa` and
        // `RequireManagedDevice` still evaluate against the real evidence.
        let decision = if break_glass {
            matches.resolve(&assume_trusted_network(ctx), action)
        } else {
            matches.resolve(ctx, action)
        };

        Evaluation {
            decision,
            enforced: matches.enforced,
            simulated: matches.simulated,
            break_glass,
        }
    }
}

/// A copy of the context in which the caller counts as being inside a trusted zone.
///
/// Cloned rather than mutated in place: the context the rest of the chain sees must be the honest
/// one. A break-glass session that rewrote `NetworkContext` for every later stage would put a
/// fabricated zone into the audit row, and audit is the one thing §5.6 does not exempt.
fn assume_trusted_network(ctx: &RequestContext) -> RequestContext {
    let mut relaxed = ctx.clone();
    relaxed.network.zones.push(BREAK_GLASS_ZONE.to_owned());
    relaxed
}

/// The synthetic zone a break-glass session is treated as being inside.
///
/// Named rather than anonymous so that a rule written as `InAnyZone(["…"])` cannot accidentally
/// collide with it: an administrator would have to define a zone with this exact name, and the name
/// says what it is.
const BREAK_GLASS_ZONE: &str = "__break_glass__";
