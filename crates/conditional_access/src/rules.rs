//! Two rule sets, one per class of principal (`plans/M4-GOVERNANCE.md` Q19).
//!
//! # Why two, and why this is the whole point
//!
//! Q19 asks whether conditional access applies to service accounts and MCP tokens. The answer is
//! yes, **with a separate rule set** — not one rule set with exemptions:
//!
//! > The rejected option is the one that looks simpler: a single rule set means every posture rule
//! > needs an escape clause for non-human principals, which is the exemption again, written once
//! > per rule instead of once. And an exemption is precisely the gap an attacker looks for —
//! > compromise a service token and the zone rules simply do not apply.
//!
//! The separation here is a *type* separation rather than a convention. [`HumanCondition`] has no
//! variant that names an actor kind outside `user`/`guest`, and [`MachineCondition`] has no
//! `PostureBelow` and no `AuthStrengthBelow` — a device-posture rule against a service account is
//! not a rule that is skipped, it is a rule that cannot be written. That is what removes the need
//! for an escape clause: there is no clause to escape.
//!
//! What machines get instead is what Q19 names: **network allowlists and token binding**. A
//! service account is a credential on a network; the meaningful questions about it are where it is
//! calling from and whether its token is bound to something.
//!
//! # Effects, and the one from `docs/06 §7` that is deliberately missing
//!
//! `docs/06 §7` lists the effects: allow, block, require MFA, require trusted network, require
//! managed device, preview only, no download, no sync — evaluated in priority order with the most
//! restrictive matching effect winning.
//!
//! **`allow` is not implemented as an effect**, and the reason is the resolution rule itself. If
//! the most restrictive matching effect wins, an `ALLOW` can never change an outcome: it is
//! strictly the least restrictive value, so any rule it competes with beats it. Offering the
//! variant anyway would let an administrator write "allow the auditors from anywhere", see it
//! accepted, and have it do nothing — an exemption that appears to exist. `docs/06 §7.4` records
//! this. An administrator who wants an exception writes a narrower matching condition on the
//! restrictive rule, which is visible in the rule that actually decides.

use core::net::IpAddr;

use enclave_core::{
    Action, ActorKind, AuthStrength, ClientType, DevicePosture, FileAction, Obligation, ReasonCode,
    RequestContext,
};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::zone::ZoneMap;

/// Whether a rule decides or merely rehearses (`docs/06 §7`, `plans/M4-GOVERNANCE.md` D28).
///
/// A simulated rule is matched by exactly the same code, against exactly the same context, and its
/// match is reported — the only difference is that it does not contribute to the outcome. D28 is
/// explicit that a cheaper simulation measures something other than what enforcement will do; the
/// evaluation here has no second path to take, because the mode is consulted once, after matching,
/// when the effect is collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleMode {
    /// The rule's effect applies.
    #[default]
    Enforce,
    /// The rule is evaluated and its match recorded; the effect is not applied.
    Simulation,
}

/// What a matching rule does, ordered most restrictive first.
///
/// The ordering is `Ord`, and that is load-bearing rather than tidy: "most restrictive matching
/// effect wins" is implemented as a sort, so the reason code a caller is shown is a property of
/// this declaration order and not of the order rules happen to appear in a file. Two deployments
/// with the same rules in different order therefore return the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// Refuse the action outright.
    Block,
    /// Refuse unless the caller is inside some trusted zone.
    RequireTrustedNetwork,
    /// Refuse unless the device is managed.
    RequireManagedDevice,
    /// Refuse unless the principal authenticated with more than one factor.
    RequireMfa,
    /// Serve renditions only: no original bytes, no mutation.
    PreviewOnly,
    /// No original bytes leave, whatever the caller asked for.
    NoDownload,
    /// Nothing replicates to a device.
    NoSync,
}

impl Effect {
    /// The refusal this effect produces for `action`, if it produces one.
    ///
    /// An effect is a *requirement*, so it denies only when the requirement is unmet or the action
    /// is one it forbids. `RequireMfa` against a caller who already used two factors is silent;
    /// `NoDownload` against a metadata read is silent. Returning `Option<ReasonCode>` rather than a
    /// bool keeps the reason attached to the decision that produced it, so the caller is told
    /// `STEP_UP_REQUIRED` rather than a generic denial they cannot act on.
    #[must_use]
    fn denies(self, ctx: &RequestContext, action: Action) -> Option<ReasonCode> {
        match self {
            Self::Block => Some(ReasonCode::AccessDenied),
            Self::RequireTrustedNetwork => {
                (!ctx.network.is_trusted_zone()).then_some(ReasonCode::NetworkNotAllowed)
            }
            Self::RequireManagedDevice => {
                (!ctx.device.meets(DevicePosture::Managed)).then_some(ReasonCode::DeviceNotManaged)
            }
            Self::RequireMfa => (!ctx.auth_strength.meets(AuthStrength::MultiFactor))
                .then_some(ReasonCode::StepUpRequired),
            Self::PreviewOnly => serves_original_bytes(action).then_some(ReasonCode::PreviewOnly),
            Self::NoDownload => takes_a_copy(action).then_some(ReasonCode::DownloadBlockedByPolicy),
            Self::NoSync => matches!(action, Action::File(FileAction::Sync))
                .then_some(ReasonCode::SyncNotPermitted),
        }
    }

    /// What this effect requires of an allowed action.
    ///
    /// The obligations are additive across every matching effect — `PreviewOnly` and `NoSync`
    /// together produce all three — because obligations are requirements rather than alternatives.
    /// "Most restrictive wins" selects which *denial* is reported; it never discards a constraint.
    fn obligations(self, into: &mut enclave_core::Obligations) {
        match self {
            Self::PreviewOnly => {
                into.insert(Obligation::NoDownload);
                into.insert(Obligation::ReadOnly);
            }
            Self::NoDownload => {
                into.insert(Obligation::NoDownload);
            }
            Self::NoSync => {
                into.insert(Obligation::NoSync);
            }
            Self::Block
            | Self::RequireTrustedNetwork
            | Self::RequireManagedDevice
            | Self::RequireMfa => {}
        }
    }
}

/// Whether the action hands the caller the stored bytes, or the ability to change them.
///
/// `Preview` is absent: a rendition is what `PreviewOnly` exists to still permit. `VersionRead` is
/// absent for the same reason — it reads version *metadata*; `ContentRead` is the byte-serving
/// action.
const fn serves_original_bytes(action: Action) -> bool {
    matches!(
        action,
        Action::File(
            FileAction::ContentRead
                | FileAction::Download
                | FileAction::Print
                | FileAction::Export
                | FileAction::Sync
                | FileAction::Edit
        )
    )
}

/// Whether the action produces a copy the caller keeps.
///
/// `CLAUDE.md` rule 6: preview, download, print, export and sync are five different things. This
/// names the subset `NoDownload` is about — the ones that leave with bytes — and deliberately does
/// not include `Sync`, which has its own effect and its own reason code.
const fn takes_a_copy(action: Action) -> bool {
    matches!(action, Action::File(FileAction::Download | FileAction::Print | FileAction::Export))
}

/// What a rule needs to know beyond the request context.
///
/// Zone membership is already resolved onto `NetworkContext::zones` at the edge, so a rule can
/// answer most questions from the context alone. This carries the map for the one case it cannot:
/// a machine allowlist naming a zone the request is *not* in still needs the zone's definition to
/// say so. Passed in rather than held on the rule so that one map serves every rule and a rule
/// cannot be evaluated against a zone definition different from the one that built the context.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Every zone this deployment defines.
    pub zones: &'a ZoneMap,
}

// --- Human rules -------------------------------------------------------------------------------

/// A condition about a person (`Actor::User` or `Actor::Guest`).
///
/// Every variant here is meaningless for a service account, which is why the machine rule set is a
/// separate type rather than the same one with a filter.
///
/// # The serialized form is the type separation, not a description of it
///
/// `Deserialize` is externally tagged and closed: `{"posture_below": "MANAGED"}` is a
/// `HumanCondition` and **nothing else can be**. A stored rule whose `audience` column says
/// `MACHINE` is decoded into [`MachineCondition`], which has no such variant, so serde refuses the
/// document by name rather than dropping the clause. That refusal is what stops storage from
/// becoming the escape hatch the type separation exists to remove (`ENC-590`,
/// `migrations/0019_conditional_access_rules.sql`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanCondition {
    /// The request arrived through one of these client types.
    ClientIs(Vec<ClientType>),
    /// The action is one of these.
    ActionIs(Vec<Action>),
    /// The action can put content in front of the caller (`Action::exposes_content`).
    ActionExposesContent,
    /// The resolved country is one of these. **An unknown country never matches**: a geo-fence
    /// that admits on absence of evidence is not a geo-fence (`NetworkContext::country`).
    CountryIn(Vec<String>),
    /// The resolved country is none of these. **An unknown country matches**, which is the same
    /// rule read in the other direction: "not in India" is true of a caller we cannot place, and a
    /// rule written as `country NOT IN [IN] THEN BLOCK` must block them.
    CountryNotIn(Vec<String>),
    /// The source address is inside at least one of these zones.
    InAnyZone(Vec<String>),
    /// The source address is inside none of these zones.
    OutsideEveryZone(Vec<String>),
    /// The principal authenticated more weakly than this.
    AuthStrengthBelow(AuthStrength),
    /// The device attested more weakly than this.
    PostureBelow(DevicePosture),
    /// The principal is external to the tenant.
    ActorIsGuest,
}

impl HumanCondition {
    /// Whether this condition is a statement about *where the caller is*.
    ///
    /// Break-glass is exempt from IP and zone policy and from nothing else
    /// (`docs/11-OPERATIONS.md §5.6`), so the exemption needs to know which conditions are
    /// network-shaped. Stated here, beside the variants, so that adding a network condition without
    /// classifying it is a non-exhaustive `match` rather than a silently unexempted rule.
    #[must_use]
    pub const fn is_network_shaped(&self) -> bool {
        matches!(
            self,
            Self::CountryIn(_)
                | Self::CountryNotIn(_)
                | Self::InAnyZone(_)
                | Self::OutsideEveryZone(_)
        )
    }

    fn matches(&self, ctx: &RequestContext, action: Action) -> bool {
        match self {
            Self::ClientIs(clients) => clients.contains(&ctx.client),
            Self::ActionIs(actions) => actions.contains(&action),
            Self::ActionExposesContent => action.exposes_content(),
            Self::CountryIn(list) => ctx
                .network
                .country
                .as_deref()
                .is_some_and(|country| contains_country(list, country)),
            Self::CountryNotIn(list) => ctx
                .network
                .country
                .as_deref()
                .is_none_or(|country| !contains_country(list, country)),
            Self::InAnyZone(zones) => zones.iter().any(|zone| ctx.network.in_zone(zone)),
            Self::OutsideEveryZone(zones) => !zones.iter().any(|zone| ctx.network.in_zone(zone)),
            Self::AuthStrengthBelow(required) => !ctx.auth_strength.meets(*required),
            Self::PostureBelow(required) => !ctx.device.meets(*required),
            Self::ActorIsGuest => ctx.actor.is_external(),
        }
    }
}

fn contains_country(list: &[String], country: &str) -> bool {
    list.iter().any(|candidate| candidate.eq_ignore_ascii_case(country))
}

/// One rule about people.
///
/// Conditions are conjunctive — every one must match — because that is how the examples in
/// `docs/06 §7.1` read, and because a disjunctive default would make a rule broaden every time
/// somebody added a clause meaning to narrow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanRule {
    /// A name an administrator recognises, echoed in logs and in the simulation report. Never
    /// shown to the caller: `ReasonCode` is the only thing that crosses that boundary.
    pub name: String,
    /// All of these must hold. An empty list matches every request, which is a rule an
    /// administrator can legitimately want ("require a managed device, always").
    pub when: Vec<HumanCondition>,
    /// What happens when they do.
    pub effect: Effect,
    /// Whether the effect applies or is merely recorded.
    pub mode: RuleMode,
}

impl HumanRule {
    /// A rule that enforces.
    #[must_use]
    pub fn new(name: impl Into<String>, when: Vec<HumanCondition>, effect: Effect) -> Self {
        Self { name: name.into(), when, effect, mode: RuleMode::Enforce }
    }

    /// The same rule in simulation.
    #[must_use]
    pub fn simulated(mut self) -> Self {
        self.mode = RuleMode::Simulation;
        self
    }

    /// Whether every condition holds.
    ///
    /// `exempt_network` drops the network-shaped conditions from consideration — used only by
    /// break-glass. Note the direction: an exempt condition is treated as **not matching**, so a
    /// rule that only fires because of where the caller is stops firing, and a rule with a
    /// non-network condition attached is unaffected.
    fn matches(&self, ctx: &RequestContext, action: Action, exempt_network: bool) -> bool {
        self.when.iter().all(|condition| {
            if exempt_network && condition.is_network_shaped() {
                return false;
            }
            condition.matches(ctx, action)
        })
    }
}

// --- Machine rules -----------------------------------------------------------------------------

/// A condition about a non-human principal: a service account, an MCP client, or `system`.
///
/// Deliberately without `PostureBelow` and `AuthStrengthBelow`. A service account has no device to
/// attest and no second factor to present, so a posture rule written against one could only ever
/// be a rule that always matches — which is why the single-rule-set design needs an escape clause
/// and this one does not.
///
/// The absence survives serialization: see [`HumanCondition`]'s note. There is no name in this
/// enum's `Deserialize` for a posture or an authentication strength, so a stored `MACHINE` rule
/// asking for one is rejected loudly rather than coerced into something that always matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MachineCondition {
    /// The principal is one of these kinds.
    ActorKindIs(Vec<ActorKind>),
    /// The request arrived through one of these client types.
    ClientIs(Vec<ClientType>),
    /// The action is one of these.
    ActionIs(Vec<Action>),
    /// The action can put content in front of the caller.
    ActionExposesContent,
    /// The source address is outside every listed network and every listed zone — the allowlist
    /// Q19 names, expressed as the condition under which it is *violated*, so that the rule reads
    /// "outside the allowlist, then block".
    SourceOutside {
        /// Literal networks that are inside the allowlist.
        networks: Vec<IpNetwork>,
        /// Named zones that are inside the allowlist.
        zones: Vec<String>,
    },
    /// The token names no registered client instance (`dev` claim absent) — the token binding Q19
    /// names, in the form available today. A sender-constrained token (mTLS or DPoP) is the
    /// stronger form and does not exist yet; this asks the weaker question honestly rather than
    /// claiming the stronger one.
    TokenNotBound,
    /// The address was relayed by a proxy rather than observed on the socket. A machine caller that
    /// is supposed to reach us directly and suddenly arrives through a forwarding chain is worth
    /// being able to refuse.
    OriginRelayed,
}

impl MachineCondition {
    /// Whether this condition is a statement about where the caller is. See
    /// [`HumanCondition::is_network_shaped`] — break-glass does not apply to machine principals
    /// (there is no break-glass service account), but the classification is stated for both sets so
    /// that the two cannot drift into disagreeing about what "network-shaped" means.
    #[must_use]
    pub const fn is_network_shaped(&self) -> bool {
        matches!(self, Self::SourceOutside { .. } | Self::OriginRelayed)
    }

    fn matches(&self, ctx: &RequestContext, action: Action, facts: Facts<'_>) -> bool {
        match self {
            Self::ActorKindIs(kinds) => kinds.contains(&ctx.actor.kind()),
            Self::ClientIs(clients) => clients.contains(&ctx.client),
            Self::ActionIs(actions) => actions.contains(&action),
            Self::ActionExposesContent => action.exposes_content(),
            Self::SourceOutside { networks, zones } => {
                !inside_allowlist(ctx.network.source_ip, networks, zones, facts)
            }
            Self::TokenNotBound => ctx.device.device_id.is_none(),
            Self::OriginRelayed => ctx.network.via_trusted_proxy,
        }
    }
}

/// Whether an address is inside a machine allowlist.
///
/// An **empty** allowlist puts nothing inside it, so `SourceOutside` with no networks and no zones
/// matches every request. That is the fail-closed reading and the opposite of the usual "empty
/// means unrestricted": a half-written allowlist must refuse rather than admit, because the rule
/// referring to it exists to refuse.
fn inside_allowlist(
    addr: IpAddr,
    networks: &[IpNetwork],
    zones: &[String],
    facts: Facts<'_>,
) -> bool {
    if networks.iter().any(|network| network.contains(addr)) {
        return true;
    }
    let resolved = facts.zones.zones_for(addr);
    zones.iter().any(|zone| resolved.iter().any(|held| held == zone))
}

/// One rule about machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRule {
    /// A name an administrator recognises.
    pub name: String,
    /// All of these must hold.
    pub when: Vec<MachineCondition>,
    /// What happens when they do.
    pub effect: Effect,
    /// Whether the effect applies or is merely recorded.
    pub mode: RuleMode,
}

impl MachineRule {
    /// A rule that enforces.
    #[must_use]
    pub fn new(name: impl Into<String>, when: Vec<MachineCondition>, effect: Effect) -> Self {
        Self { name: name.into(), when, effect, mode: RuleMode::Enforce }
    }

    /// The same rule in simulation.
    #[must_use]
    pub fn simulated(mut self) -> Self {
        self.mode = RuleMode::Simulation;
        self
    }

    fn matches(&self, ctx: &RequestContext, action: Action, facts: Facts<'_>) -> bool {
        self.when.iter().all(|condition| condition.matches(ctx, action, facts))
    }
}

// --- Shared evaluation -------------------------------------------------------------------------

/// Collects the effects of every matching rule, keeping enforcement and simulation apart.
#[derive(Debug, Default)]
pub(crate) struct Matches {
    pub(crate) enforced: Vec<(String, Effect)>,
    pub(crate) simulated: Vec<(String, Effect)>,
}

impl Matches {
    fn record(&mut self, name: &str, effect: Effect, mode: RuleMode) {
        match mode {
            RuleMode::Enforce => self.enforced.push((name.to_owned(), effect)),
            RuleMode::Simulation => self.simulated.push((name.to_owned(), effect)),
        }
    }

    /// Resolves the enforced effects into one decision.
    ///
    /// Denials are considered in [`Effect`]'s declaration order — most restrictive first — so the
    /// reason code is deterministic. Obligations are then unioned across *every* matching effect,
    /// because "most restrictive wins" chooses which refusal to report and never drops a
    /// requirement (`Obligations::merge` documents the same asymmetry for the chain as a whole).
    pub(crate) fn resolve(
        &self,
        ctx: &RequestContext,
        action: Action,
    ) -> enclave_core::StageDecision {
        let mut effects: Vec<Effect> = self.enforced.iter().map(|(_, effect)| *effect).collect();
        effects.sort_unstable();
        effects.dedup();

        for effect in &effects {
            if let Some(code) = effect.denies(ctx, action) {
                return enclave_core::StageDecision::deny(code);
            }
        }

        let mut obligations = enclave_core::Obligations::none();
        for effect in &effects {
            effect.obligations(&mut obligations);
        }
        if obligations.is_empty() {
            enclave_core::StageDecision::allow()
        } else {
            enclave_core::StageDecision::allow_with(obligations)
        }
    }
}

pub(crate) fn match_human(
    rules: &[HumanRule],
    ctx: &RequestContext,
    action: Action,
    exempt_network: bool,
) -> Matches {
    let mut matches = Matches::default();
    for rule in rules {
        if rule.matches(ctx, action, exempt_network) {
            matches.record(&rule.name, rule.effect, rule.mode);
        }
    }
    matches
}

pub(crate) fn match_machine(
    rules: &[MachineRule],
    ctx: &RequestContext,
    action: Action,
    facts: Facts<'_>,
) -> Matches {
    let mut matches = Matches::default();
    for rule in rules {
        if rule.matches(ctx, action, facts) {
            matches.record(&rule.name, rule.effect, rule.mode);
        }
    }
    matches
}
