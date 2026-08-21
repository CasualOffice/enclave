//! Q19 — conditional access evaluates for every principal, with a separate rule set for machines.
//!
//! Two properties are asserted throughout, and each negative has a positive control beside it
//! (`docs/12-TESTING.md §1.2`):
//!
//! * a rule written for people **does not** decide anything about a service account — proved
//!   against a machine rule that *does* decide, in the same test, so "nothing happened" cannot be
//!   satisfied by an evaluator that decides nothing at all;
//! * break-glass waives the network-shaped rules and **only** those — proved against the MFA and
//!   posture rules that still refuse the same session.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::net::IpAddr;

use enclave_conditional_access::{
    BreakGlass, Effect, HumanCondition, HumanRule, MachineCondition, MachineRule, NetworkZone,
    PolicySet, ZoneMap,
};
use enclave_core::{
    Action, Actor, ActorKind, AuthStrength, ClientType, DeviceContext, DeviceId, DevicePosture,
    FileAction, McpClientId, Obligation, ReasonCode, RequestContext, ServiceAccountId,
    StageDecision, StageOutcome, TenantId, UserId,
};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test fixture is an address")
}

/// A context for a person on an untrusted network, single factor, unmanaged device.
///
/// Built from `RequestContext::system` and then corrected field by field: `RequestContext` has no
/// `Deserialize` and no public constructor beyond `system`, which is the property `crates/core`
/// documents and which tests should not work around with a second construction path.
fn person() -> RequestContext {
    let mut ctx = RequestContext::system(TenantId::new_v7());
    ctx.actor = Actor::User(UserId::new_v7());
    ctx.client = ClientType::Web;
    ctx.auth_strength = AuthStrength::SingleFactor;
    ctx.network.source_ip = ip("192.0.2.44");
    ctx
}

fn service_account() -> RequestContext {
    let mut ctx = RequestContext::system(TenantId::new_v7());
    ctx.actor = Actor::ServiceAccount(ServiceAccountId::new_v7());
    ctx.client = ClientType::Api;
    ctx.auth_strength = AuthStrength::SingleFactor;
    ctx.network.source_ip = ip("192.0.2.44");
    ctx
}

fn mcp_client() -> RequestContext {
    let mut ctx = service_account();
    ctx.actor = Actor::McpClient(McpClientId::new_v7());
    ctx.client = ClientType::Mcp;
    ctx
}

fn denied_with(decision: &StageDecision) -> Option<ReasonCode> {
    match decision.outcome() {
        StageOutcome::Deny(code) => Some(*code),
        StageOutcome::Allow => None,
    }
}

const DOWNLOAD: Action = Action::File(FileAction::Download);
const PREVIEW: Action = Action::File(FileAction::Preview);

// --- Q19: the two rule sets are independent ----------------------------------------------------

/// The rule set separation, with the control that makes the absence meaningful.
///
/// A posture rule is written for people. The service account is on the same network, with the same
/// unknown device posture, attempting the same action — and the human rule does not touch it. That
/// half alone would pass against an evaluator that never denies anything, so the *same* policy set
/// carries a machine rule that refuses the *same* request, and the person the human rule refuses is
/// asserted alongside.
#[test]
fn a_posture_rule_written_for_people_never_decides_anything_about_a_service_account() {
    let policies = PolicySet::empty()
        .with_human_rules([HumanRule::new(
            "managed devices only",
            vec![HumanCondition::PostureBelow(DevicePosture::Managed)],
            Effect::Block,
        )])
        .with_machine_rules([MachineRule::new(
            "service accounts call from the egress",
            vec![MachineCondition::SourceOutside {
                networks: vec!["198.51.100.0/24".parse().unwrap()],
                zones: Vec::new(),
            }],
            Effect::Block,
        )]);

    // The human rule refuses the person it was written for.
    let refused_person = policies.evaluate(&person(), DOWNLOAD);
    assert_eq!(denied_with(refused_person.peek()), Some(ReasonCode::AccessDenied));
    assert_eq!(refused_person.enforced_rules(), ["managed devices only"]);

    // It says nothing at all about the service account, whose posture is equally unknown.
    let machine = service_account();
    assert!(!machine.device.meets(DevicePosture::Managed));
    let machine_eval = policies.evaluate(&machine, DOWNLOAD);
    assert!(
        !machine_eval.enforced_rules().contains(&"managed devices only"),
        "a human posture rule matched a machine principal"
    );

    // Positive control: the machine rule set does decide, and refuses the same request.
    assert_eq!(denied_with(machine_eval.peek()), Some(ReasonCode::AccessDenied));
    assert_eq!(machine_eval.enforced_rules(), ["service accounts call from the egress"]);
}

/// The mirror image: a machine rule cannot reach a person.
#[test]
fn a_machine_rule_never_decides_anything_about_a_person() {
    let policies = PolicySet::empty().with_machine_rules([MachineRule::new(
        "unbound machine tokens are refused",
        vec![MachineCondition::TokenNotBound],
        Effect::Block,
    )]);

    let human = person();
    assert!(human.device.device_id.is_none(), "the person's token is unbound too");
    assert!(policies.evaluate(&human, DOWNLOAD).peek().is_allowed());

    // Positive control: the same unbound-token condition refuses a machine.
    assert_eq!(
        denied_with(policies.evaluate(&service_account(), DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );
}

/// MCP clients are governed by the machine set too, and `system` is not exempt from it.
///
/// The `system` half is the one worth having: `crates/auth/src/claims.rs` maps a `typ: "system"`
/// claim onto `Actor::System`, so a token can assert it. An exemption would be reachable by
/// anybody holding such a token.
#[test]
fn every_non_human_principal_is_governed_by_the_machine_rule_set() {
    let policies = PolicySet::empty().with_machine_rules([MachineRule::new(
        "allowlist",
        vec![MachineCondition::SourceOutside {
            networks: vec!["198.51.100.0/24".parse().unwrap()],
            zones: Vec::new(),
        }],
        Effect::Block,
    )]);

    for ctx in [service_account(), mcp_client(), RequestContext::system(TenantId::new_v7())] {
        let kind = ctx.actor.kind();
        assert_eq!(
            denied_with(policies.evaluate(&ctx, DOWNLOAD).peek()),
            Some(ReasonCode::AccessDenied),
            "{kind} escaped the machine allowlist"
        );
    }

    // Positive control: the same allowlist admits a machine that is inside it.
    let mut inside = service_account();
    inside.network.source_ip = ip("198.51.100.9");
    assert!(policies.evaluate(&inside, DOWNLOAD).peek().is_allowed());
}

/// An empty allowlist admits nobody rather than everybody.
#[test]
fn an_empty_machine_allowlist_refuses_rather_than_admits() {
    let policies = PolicySet::empty().with_machine_rules([MachineRule::new(
        "allowlist not yet written",
        vec![MachineCondition::SourceOutside { networks: Vec::new(), zones: Vec::new() }],
        Effect::Block,
    )]);
    assert_eq!(
        denied_with(policies.evaluate(&service_account(), DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );
}

/// A zone named in a machine allowlist is resolved from the policy's own zone definitions.
#[test]
fn a_machine_allowlist_can_name_a_zone_instead_of_a_prefix() {
    let policies = PolicySet::empty()
        .with_zones(ZoneMap::new([NetworkZone::new(
            "Datacenter",
            ["198.51.100.0/24".parse().unwrap()],
        )]))
        .with_machine_rules([MachineRule::new(
            "service accounts call from the datacenter",
            vec![MachineCondition::SourceOutside {
                networks: Vec::new(),
                zones: vec!["Datacenter".to_owned()],
            }],
            Effect::Block,
        )]);

    let mut inside = service_account();
    inside.network.source_ip = ip("198.51.100.9");
    assert!(policies.evaluate(&inside, DOWNLOAD).peek().is_allowed());
    assert_eq!(
        denied_with(policies.evaluate(&service_account(), DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied),
        "an address outside the named zone was admitted"
    );
}

/// Token binding, in the form available today, and the control that it is really the `dev` claim
/// being asked about.
#[test]
fn token_binding_is_asked_about_the_dev_claim_and_answered_by_it() {
    let policies = PolicySet::empty().with_machine_rules([MachineRule::new(
        "bound tokens only",
        vec![MachineCondition::TokenNotBound],
        Effect::Block,
    )]);

    assert_eq!(
        denied_with(policies.evaluate(&service_account(), DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );

    let mut bound = service_account();
    bound.device =
        DeviceContext { device_id: Some(DeviceId::new_v7()), posture: DevicePosture::Unknown };
    assert!(policies.evaluate(&bound, DOWNLOAD).peek().is_allowed());
}

// --- Geo-fencing fails closed ------------------------------------------------------------------

/// An unknown country matches `CountryNotIn` and does not match `CountryIn`.
///
/// The asymmetry is the whole point: `NetworkContext::country` documents that an unavailable
/// geolocation must be treated as "unknown, never allowed", and a fence written as
/// `country NOT IN [IN] THEN BLOCK` therefore has to block a caller we cannot place.
#[test]
fn an_unplaceable_caller_is_outside_every_geofence_and_inside_none() {
    let fence = PolicySet::empty().with_human_rules([HumanRule::new(
        "downloads from India only",
        vec![
            HumanCondition::ActionIs(vec![DOWNLOAD]),
            HumanCondition::CountryNotIn(vec!["IN".to_owned()]),
        ],
        Effect::Block,
    )]);

    let unknown = person();
    assert_eq!(unknown.network.country, None);
    assert_eq!(
        denied_with(fence.evaluate(&unknown, DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied),
        "a caller we cannot place was treated as being in India"
    );

    // Positive control: a caller we *can* place inside the permitted country is allowed, so the
    // rule is not simply blocking everything.
    let mut placed = person();
    placed.network.country = Some("IN".to_owned());
    assert!(fence.evaluate(&placed, DOWNLOAD).peek().is_allowed());

    let mut elsewhere = person();
    elsewhere.network.country = Some("SG".to_owned());
    assert_eq!(
        denied_with(fence.evaluate(&elsewhere, DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );

    // And the inclusive direction never matches an unknown country.
    let inclusive = PolicySet::empty().with_human_rules([HumanRule::new(
        "only from India",
        vec![HumanCondition::CountryIn(vec!["IN".to_owned()])],
        Effect::Block,
    )]);
    assert!(inclusive.evaluate(&unknown, DOWNLOAD).peek().is_allowed());
    assert_eq!(
        denied_with(inclusive.evaluate(&placed, DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );
}

#[test]
fn country_matching_ignores_case_because_a_claim_and_a_rule_may_disagree_about_it() {
    let fence = PolicySet::empty().with_human_rules([HumanRule::new(
        "only from India",
        vec![HumanCondition::CountryNotIn(vec!["in".to_owned()])],
        Effect::Block,
    )]);
    let mut placed = person();
    placed.network.country = Some("IN".to_owned());
    assert!(fence.evaluate(&placed, DOWNLOAD).peek().is_allowed());
}

// --- Effects -----------------------------------------------------------------------------------

/// `docs/06 §7.1`'s third example: a sync client on an unmanaged device.
#[test]
fn an_effect_denies_the_actions_it_forbids_and_shapes_the_ones_it_does_not() {
    let policies = PolicySet::empty().with_human_rules([HumanRule::new(
        "no sync from unmanaged devices",
        vec![
            HumanCondition::ClientIs(vec![ClientType::Sync]),
            HumanCondition::PostureBelow(DevicePosture::Managed),
        ],
        Effect::NoSync,
    )]);

    let mut syncing = person();
    syncing.client = ClientType::Sync;
    assert_eq!(
        denied_with(policies.evaluate(&syncing, Action::File(FileAction::Sync)).peek()),
        Some(ReasonCode::SyncNotPermitted)
    );

    // The same rule, the same caller, an action it does not forbid: allowed, carrying the
    // obligation rather than dropping it.
    let allowed = policies.evaluate(&syncing, PREVIEW).decision();
    let obligations = allowed.ensure_allowed().expect("preview is not a sync");
    assert!(obligations.contains(&Obligation::NoSync));
}

/// "Most restrictive matching effect wins" chooses the *refusal*; obligations still union.
#[test]
fn the_most_restrictive_effect_supplies_the_reason_and_no_obligation_is_dropped() {
    let policies = PolicySet::empty().with_human_rules([
        HumanRule::new("no sync", Vec::new(), Effect::NoSync),
        HumanRule::new("preview only", Vec::new(), Effect::PreviewOnly),
        HumanRule::new("managed devices", Vec::new(), Effect::RequireManagedDevice),
    ]);

    // Downloading trips two refusals; the more restrictive one names the reason. `PreviewOnly`
    // would answer `PREVIEW_ONLY`, which is the less restrictive of the two and would tell the
    // caller to try a preview when the real problem is their device.
    assert_eq!(
        denied_with(policies.evaluate(&person(), DOWNLOAD).peek()),
        Some(ReasonCode::DeviceNotManaged)
    );

    // With the device managed, the download is refused by `PreviewOnly` instead.
    let mut managed = person();
    managed.device = DeviceContext { device_id: None, posture: DevicePosture::Managed };
    assert_eq!(
        denied_with(policies.evaluate(&managed, DOWNLOAD).peek()),
        Some(ReasonCode::PreviewOnly)
    );

    // On an action none of them forbids, every obligation survives.
    let obligations = policies
        .evaluate(&managed, PREVIEW)
        .decision()
        .ensure_allowed()
        .expect("preview is permitted");
    assert!(obligations.contains(&Obligation::NoDownload));
    assert!(obligations.contains(&Obligation::ReadOnly));
    assert!(obligations.contains(&Obligation::NoSync));
}

/// A requirement the caller already meets is silent.
#[test]
fn a_requirement_that_is_already_met_denies_nothing() {
    let policies = PolicySet::empty().with_human_rules([HumanRule::new(
        "step up for downloads",
        vec![HumanCondition::ActionIs(vec![DOWNLOAD])],
        Effect::RequireMfa,
    )]);

    assert_eq!(
        denied_with(policies.evaluate(&person(), DOWNLOAD).peek()),
        Some(ReasonCode::StepUpRequired)
    );

    let mut stepped_up = person();
    stepped_up.auth_strength = AuthStrength::MultiFactor;
    assert!(policies.evaluate(&stepped_up, DOWNLOAD).peek().is_allowed());
}

/// A simulated rule matches identically and changes nothing (`docs/06 §7`, D28).
#[test]
fn a_simulated_rule_matches_but_does_not_decide() {
    let rule = HumanRule::new(
        "block everything",
        vec![HumanCondition::ActionIs(vec![DOWNLOAD])],
        Effect::Block,
    );

    let enforcing = PolicySet::empty().with_human_rules([rule.clone()]);
    let simulating = PolicySet::empty().with_human_rules([rule.simulated()]);

    let enforced = enforcing.evaluate(&person(), DOWNLOAD);
    assert_eq!(denied_with(enforced.peek()), Some(ReasonCode::AccessDenied));
    assert_eq!(enforced.enforced_rules(), ["block everything"]);
    assert!(enforced.simulated_rules().is_empty());

    let simulated = simulating.evaluate(&person(), DOWNLOAD);
    assert!(simulated.peek().is_allowed());
    // The match is reported, which is what makes the simulation worth running. Without this the
    // assertion above would pass against a policy set that never evaluated the rule at all.
    assert_eq!(simulated.simulated_rules(), ["block everything"]);
    assert!(simulated.enforced_rules().is_empty());
}

// --- Break-glass ---------------------------------------------------------------------------

/// The lockout in `plans/M4-GOVERNANCE.md §5`'s risk table, and its escape.
///
/// A zone rule denies the network the administrator is on. Break-glass gets through — and the
/// positive controls prove the rule is real and that the exemption is not simply "allow this user".
#[test]
fn break_glass_waives_a_zone_rule_that_has_locked_the_administrator_out() {
    let policies = PolicySet::empty()
        .with_zones(ZoneMap::new([NetworkZone::new(
            "Corporate India",
            ["203.0.113.0/24".parse().unwrap()],
        )]))
        .with_human_rules([HumanRule::new(
            "administration from the corporate network only",
            vec![HumanCondition::OutsideEveryZone(vec!["Corporate India".to_owned()])],
            Effect::Block,
        )]);

    // Positive control: the rule really does lock an ordinary administrator out.
    let mut locked_out = person();
    locked_out.auth_strength = AuthStrength::MultiFactor;
    assert_eq!(
        denied_with(policies.evaluate(&locked_out, DOWNLOAD).peek()),
        Some(ReasonCode::AccessDenied)
    );

    // The same request, from a break-glass session, gets through.
    let mut emergency = locked_out.clone();
    emergency.scopes = [BreakGlass::DEFAULT_SCOPE].into_iter().collect();
    let evaluation = policies.evaluate(&emergency, DOWNLOAD);
    assert!(evaluation.peek().is_allowed(), "break-glass could not reach the admin console");
    assert!(evaluation.break_glass_applied());

    // And the exemption is recorded, so the alert `docs/11 §5.6` requires has something to fire on.
    assert!(!policies.evaluate(&locked_out, DOWNLOAD).break_glass_applied());
}

/// `RequireTrustedNetwork` is satisfiable for a break-glass session and for nobody else on that
/// network.
#[test]
fn break_glass_satisfies_a_trusted_network_requirement() {
    let policies = PolicySet::empty().with_human_rules([HumanRule::new(
        "trusted networks only",
        Vec::new(),
        Effect::RequireTrustedNetwork,
    )]);

    let mut ordinary = person();
    ordinary.auth_strength = AuthStrength::MultiFactor;
    assert_eq!(
        denied_with(policies.evaluate(&ordinary, DOWNLOAD).peek()),
        Some(ReasonCode::NetworkNotAllowed)
    );

    let mut emergency = ordinary.clone();
    emergency.scopes = [BreakGlass::DEFAULT_SCOPE].into_iter().collect();
    assert!(policies.evaluate(&emergency, DOWNLOAD).peek().is_allowed());
}

/// §5.6: exempt from IP and zone policy, **not** from MFA.
///
/// Two separate claims, both asserted. A break-glass session that did not step up gets no
/// exemption at all — so the exemption cannot be used to avoid the requirement it does not cover —
/// and a break-glass session that did step up is still refused by a non-network rule.
#[test]
fn break_glass_is_exempt_from_network_rules_and_from_nothing_else() {
    let network_rule = HumanRule::new(
        "corporate network only",
        vec![HumanCondition::OutsideEveryZone(vec!["Corporate India".to_owned()])],
        Effect::Block,
    );
    let posture_rule = HumanRule::new(
        "managed devices only",
        vec![HumanCondition::PostureBelow(DevicePosture::Managed)],
        Effect::Block,
    );
    let policies =
        PolicySet::empty().with_human_rules([network_rule.clone(), posture_rule.clone()]);

    // Stepped up: the network rule is waived, the posture rule is not.
    let mut emergency = person();
    emergency.auth_strength = AuthStrength::MultiFactor;
    emergency.scopes = [BreakGlass::DEFAULT_SCOPE].into_iter().collect();
    let evaluation = policies.evaluate(&emergency, DOWNLOAD);
    assert!(evaluation.break_glass_applied());
    assert_eq!(evaluation.enforced_rules(), ["managed devices only"]);
    assert_eq!(denied_with(evaluation.peek()), Some(ReasonCode::AccessDenied));

    // Positive control on the waiver: with only the network rule configured, the same session is
    // allowed — so "denied" above is the posture rule and not a break-glass that never worked.
    let network_only = PolicySet::empty().with_human_rules([network_rule]);
    assert!(network_only.evaluate(&emergency, DOWNLOAD).peek().is_allowed());

    // Single factor: no exemption, because §5.6 does not exempt break-glass from MFA.
    let mut unstepped = emergency.clone();
    unstepped.auth_strength = AuthStrength::SingleFactor;
    let evaluation = network_only.evaluate(&unstepped, DOWNLOAD);
    assert!(!evaluation.break_glass_applied());
    assert_eq!(denied_with(evaluation.peek()), Some(ReasonCode::AccessDenied));
}

/// There is no break-glass service account.
#[test]
fn a_machine_principal_holding_the_scope_gets_no_exemption() {
    let policies = PolicySet::empty().with_machine_rules([MachineRule::new(
        "allowlist",
        vec![MachineCondition::SourceOutside {
            networks: vec!["198.51.100.0/24".parse().unwrap()],
            zones: Vec::new(),
        }],
        Effect::Block,
    )]);

    let mut machine = service_account();
    machine.auth_strength = AuthStrength::MultiFactor;
    machine.scopes = [BreakGlass::DEFAULT_SCOPE].into_iter().collect();
    let evaluation = policies.evaluate(&machine, DOWNLOAD);
    assert!(!evaluation.break_glass_applied());
    assert_eq!(denied_with(evaluation.peek()), Some(ReasonCode::AccessDenied));
}

/// A deployment can refuse to carry the exemption at all.
#[test]
fn break_glass_can_be_turned_off() {
    let policies = PolicySet::empty().with_break_glass(None).with_human_rules([HumanRule::new(
        "trusted networks only",
        Vec::new(),
        Effect::RequireTrustedNetwork,
    )]);

    let mut emergency = person();
    emergency.auth_strength = AuthStrength::MultiFactor;
    emergency.scopes = [BreakGlass::DEFAULT_SCOPE].into_iter().collect();
    let evaluation = policies.evaluate(&emergency, DOWNLOAD);
    assert!(!evaluation.break_glass_applied());
    assert_eq!(denied_with(evaluation.peek()), Some(ReasonCode::NetworkNotAllowed));
}

// --- Through the chain's own trait -------------------------------------------------------------

/// The service the policy engine holds returns the evaluation's decision unchanged.
///
/// Not a formality: the trait takes a `ResourceRef` this implementation deliberately ignores, and
/// the test pins that the decision reaching the engine is the one the policy set produced.
#[tokio::test]
async fn the_stage_returns_what_the_policy_set_decided() {
    use enclave_conditional_access::ConfiguredConditionalAccess;
    use enclave_core::{ConditionalAccessService, FileId, ResourceRef};

    let policies = PolicySet::empty().with_human_rules([HumanRule::new(
        "no downloads",
        vec![HumanCondition::ActionIs(vec![DOWNLOAD])],
        Effect::Block,
    )]);
    let stage = ConfiguredConditionalAccess::new(policies);

    let ctx = person();
    let resource = ResourceRef::file(ctx.tenant_id, FileId::new_v7());

    let denied = stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation succeeds");
    assert_eq!(denied_with(&denied), Some(ReasonCode::AccessDenied));

    let allowed = stage.evaluate(&ctx, PREVIEW, &resource).await.expect("evaluation succeeds");
    assert!(allowed.is_allowed());
}

/// Audience assignment is total and puts `system` on the machine side.
#[test]
fn every_actor_kind_has_a_rule_set() {
    use enclave_conditional_access::Audience;
    assert_eq!(Audience::of(ActorKind::User), Audience::Human);
    assert_eq!(Audience::of(ActorKind::Guest), Audience::Human);
    assert_eq!(Audience::of(ActorKind::ServiceAccount), Audience::Machine);
    assert_eq!(Audience::of(ActorKind::McpClient), Audience::Machine);
    assert_eq!(Audience::of(ActorKind::System), Audience::Machine);
}
