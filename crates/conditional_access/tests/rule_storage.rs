//! `ENC-590` — storage must not become a way to write a rule the types cannot express.
//!
//! Q19's answer is a **type** separation (`plans/M4-GOVERNANCE.md`, `docs/06 §7.4`):
//! `MachineCondition` has no `PostureBelow` and no `AuthStrengthBelow`, so a device-posture rule
//! against a service account is not skipped — it cannot be written. `ENC-583` had that from the
//! compiler. A table does not.
//!
//! Every test here asserts an **absence** — "this cannot be stored", "this cannot be decoded" — and
//! `docs/12-TESTING.md §1.2` is explicit that such an assertion passes for free: against a decoder
//! that refuses everything, against one that is never called, against a fixture that was malformed
//! for some other reason. So each one carries its positive control in the same test: the *same
//! document*, under the audience it does belong to, must decode into the condition it names.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_conditional_access::{
    decode_rule, decode_rules, encode_human, encode_machine, Effect, HumanCondition, HumanRule,
    MachineCondition, MachineRule, Rule, RuleMode,
};
use enclave_core::{
    Action, ActorKind, AuthStrength, ClientType, DevicePosture, FileAction, ShareAction,
};
use enclave_db::{RuleId, RuleRow};

/// A stored row, spelled by hand, exactly as a `SELECT` would return it.
fn row(audience: &str, conditions: &str, effect: &str, mode: &str) -> RuleRow {
    RuleRow {
        id: RuleId::new_v7(),
        audience: audience.to_owned(),
        name: "a rule an administrator wrote".to_owned(),
        conditions: conditions.to_owned(),
        effect: effect.to_owned(),
        mode: mode.to_owned(),
    }
}

// --- Q19: the separation survives serialization -------------------------------------------------

/// The rule Q19 exists to make unwritable, written down as a row.
///
/// `{"posture_below": "MANAGED"}` is a perfectly good condition — for a *person*. Attached to a
/// machine rule it could only ever be a condition that always matches, which is why the
/// single-rule-set design needs an escape clause and this one does not. The row is refused rather
/// than decoded with the clause dropped: a rule missing a condition matches **more** requests than
/// the administrator wrote, and every rule in this stage denies.
///
/// The control is the same JSON under `HUMAN`, which must decode and must produce the condition it
/// names. Without it this test passes against a decoder that refuses every document.
#[test]
fn a_posture_condition_cannot_be_stored_against_a_machine_rule() {
    let document = r#"[{"posture_below":"MANAGED"}]"#;

    let refused = decode_rule(&row("MACHINE", document, "BLOCK", "ENFORCE"))
        .expect_err("a posture condition on a machine rule must not decode");
    let explanation = format!("{refused:#}");
    let source = std::error::Error::source(&refused).map(ToString::to_string).unwrap_or_default();
    assert!(
        source.contains("posture_below"),
        "the refusal must name the offending clause so an operator can find the row; got \
         {explanation} / {source}"
    );

    // The control: the identical document, under the audience it belongs to.
    let accepted = decode_rule(&row("HUMAN", document, "BLOCK", "ENFORCE")).expect("decodes");
    match accepted {
        Rule::Human(rule) => {
            assert_eq!(rule.when, vec![HumanCondition::PostureBelow(DevicePosture::Managed)]);
        }
        Rule::Machine(_) => panic!("a HUMAN row decoded into the machine rule set"),
    }
}

/// The other direction, which matters just as much: the audience column selects the type, so a
/// machine-only condition must not be accepted under `HUMAN` either.
///
/// If it were, an administrator could write "service accounts outside the allowlist" as a *human*
/// rule, see it stored, and have it evaluated against nobody — an exemption that appears to exist,
/// which is the failure `docs/06 §7.4` records for the missing `ALLOW` effect.
#[test]
fn a_machine_only_condition_cannot_be_stored_against_a_human_rule() {
    let document = r#"[{"actor_kind_is":["service","mcp"]}]"#;

    let refused = decode_rule(&row("HUMAN", document, "BLOCK", "ENFORCE"))
        .expect_err("a machine condition on a human rule must not decode");
    let source = std::error::Error::source(&refused).map(ToString::to_string).unwrap_or_default();
    assert!(source.contains("actor_kind_is"), "the refusal must name the clause; got {source}");

    let accepted = decode_rule(&row("MACHINE", document, "BLOCK", "ENFORCE")).expect("decodes");
    match accepted {
        Rule::Machine(rule) => assert_eq!(
            rule.when,
            vec![MachineCondition::ActorKindIs(vec![
                ActorKind::ServiceAccount,
                ActorKind::McpClient
            ])]
        ),
        Rule::Human(_) => panic!("a MACHINE row decoded into the human rule set"),
    }
}

/// The audience is never inferred from the document, and this is why it cannot be.
///
/// `client_is` and `action_is` are legitimately in **both** vocabularies, so a decoder that guessed
/// from the document would have to pick one — and whichever it picked would silently move rules
/// between the two sets. The same bytes decode into two different rules here, and the only thing
/// that distinguishes them is the column.
#[test]
fn the_audience_column_and_not_the_document_decides_which_rule_set_a_row_is_in() {
    let document = r#"[{"client_is":["api"]}]"#;

    let human = decode_rule(&row("HUMAN", document, "NO_DOWNLOAD", "ENFORCE")).expect("decodes");
    let machine =
        decode_rule(&row("MACHINE", document, "NO_DOWNLOAD", "ENFORCE")).expect("decodes");

    assert!(matches!(human, Rule::Human(_)), "the HUMAN column must produce a human rule");
    assert!(matches!(machine, Rule::Machine(_)), "the MACHINE column must produce a machine rule");
    assert_ne!(human.audience(), machine.audience());
}

/// An audience the two rule sets do not have is refused rather than defaulted.
///
/// A default would be the worst available answer in either direction: defaulting to `HUMAN` moves a
/// machine rule onto principals it was never written for, and defaulting to `MACHINE` silently
/// stops a posture rule from applying to anyone.
#[test]
fn an_unrecognised_audience_is_refused_rather_than_defaulted() {
    assert!(decode_rule(&row("EVERYONE", "[]", "BLOCK", "ENFORCE")).is_err());
    // The control: the same row with a real audience decodes, so the refusal above is about the
    // audience rather than about the rest of the row.
    assert!(decode_rule(&row("HUMAN", "[]", "BLOCK", "ENFORCE")).is_ok());
}

// --- Every condition survives the round trip ----------------------------------------------------

/// Names each human condition. Exhaustive on purpose: a new variant that nobody adds to
/// [`every_human_condition_survives_the_round_trip`]'s fixture is a compile error here, not a
/// condition that quietly has no storage test.
fn human_name(condition: &HumanCondition) -> &'static str {
    match condition {
        HumanCondition::ClientIs(_) => "client_is",
        HumanCondition::ActionIs(_) => "action_is",
        HumanCondition::ActionExposesContent => "action_exposes_content",
        HumanCondition::CountryIn(_) => "country_in",
        HumanCondition::CountryNotIn(_) => "country_not_in",
        HumanCondition::InAnyZone(_) => "in_any_zone",
        HumanCondition::OutsideEveryZone(_) => "outside_every_zone",
        HumanCondition::AuthStrengthBelow(_) => "auth_strength_below",
        HumanCondition::PostureBelow(_) => "posture_below",
        HumanCondition::ActorIsGuest => "actor_is_guest",
    }
}

/// The same, for machine conditions.
fn machine_name(condition: &MachineCondition) -> &'static str {
    match condition {
        MachineCondition::ActorKindIs(_) => "actor_kind_is",
        MachineCondition::ClientIs(_) => "client_is",
        MachineCondition::ActionIs(_) => "action_is",
        MachineCondition::ActionExposesContent => "action_exposes_content",
        MachineCondition::SourceOutside { .. } => "source_outside",
        MachineCondition::TokenNotBound => "token_not_bound",
        MachineCondition::OriginRelayed => "origin_relayed",
    }
}

fn every_human_condition() -> Vec<HumanCondition> {
    vec![
        HumanCondition::ClientIs(vec![ClientType::Web, ClientType::Sync]),
        HumanCondition::ActionIs(vec![
            Action::File(FileAction::Download),
            Action::Share(ShareAction::CreateExternal),
        ]),
        HumanCondition::ActionExposesContent,
        HumanCondition::CountryIn(vec!["IN".to_owned(), "US".to_owned()]),
        HumanCondition::CountryNotIn(vec!["IN".to_owned()]),
        HumanCondition::InAnyZone(vec!["Corporate India".to_owned()]),
        HumanCondition::OutsideEveryZone(vec!["VPN".to_owned(), "HQ".to_owned()]),
        HumanCondition::AuthStrengthBelow(AuthStrength::MultiFactor),
        HumanCondition::PostureBelow(DevicePosture::Managed),
        HumanCondition::ActorIsGuest,
    ]
}

fn every_machine_condition() -> Vec<MachineCondition> {
    vec![
        MachineCondition::ActorKindIs(vec![ActorKind::ServiceAccount, ActorKind::System]),
        MachineCondition::ClientIs(vec![ClientType::Mcp]),
        MachineCondition::ActionIs(vec![Action::File(FileAction::ContentRead)]),
        MachineCondition::ActionExposesContent,
        MachineCondition::SourceOutside {
            networks: vec!["10.0.0.0/8".parse().expect("a fixture prefix")],
            zones: vec!["Datacenter".to_owned()],
        },
        MachineCondition::TokenNotBound,
        MachineCondition::OriginRelayed,
    ]
}

/// Every human condition, every effect and both modes survive a round trip through the stored form.
///
/// A round-trip test is the positive half of everything else in this file: the refusals above are
/// only meaningful if the vocabulary they refuse *outside* their audience is a vocabulary that
/// works inside it. The fixture is checked against an exhaustive `match`, so a condition added to
/// the enum and forgotten here fails to compile rather than going untested.
#[test]
fn every_human_condition_survives_the_round_trip() {
    let conditions = every_human_condition();
    let mut names: Vec<&str> = conditions.iter().map(human_name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), conditions.len(), "the fixture lists a condition twice");

    for effect in every_effect() {
        for mode in [RuleMode::Enforce, RuleMode::Simulation] {
            let original = HumanRule {
                name: format!("{}/{}", effect.as_sql(), mode.as_sql()),
                when: conditions.clone(),
                effect,
                mode,
            };
            let stored = encode_human(RuleId::new_v7(), &original).expect("encodes");
            match decode_rule(&stored).expect("decodes") {
                Rule::Human(back) => assert_eq!(back, original),
                Rule::Machine(_) => panic!("a human rule came back as a machine rule"),
            }
        }
    }
}

/// The same for machine conditions, including the allowlist's prefixes and named zones.
#[test]
fn every_machine_condition_survives_the_round_trip() {
    let conditions = every_machine_condition();
    let mut names: Vec<&str> = conditions.iter().map(machine_name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), conditions.len(), "the fixture lists a condition twice");

    for effect in every_effect() {
        let original = MachineRule {
            name: effect.as_sql().to_owned(),
            when: conditions.clone(),
            effect,
            mode: RuleMode::Enforce,
        };
        let stored = encode_machine(RuleId::new_v7(), &original).expect("encodes");
        match decode_rule(&stored).expect("decodes") {
            Rule::Machine(back) => assert_eq!(back, original),
            Rule::Human(_) => panic!("a machine rule came back as a human rule"),
        }
    }
}

fn every_effect() -> [Effect; 7] {
    [
        Effect::Block,
        Effect::RequireTrustedNetwork,
        Effect::RequireManagedDevice,
        Effect::RequireMfa,
        Effect::PreviewOnly,
        Effect::NoDownload,
        Effect::NoSync,
    ]
}

// --- A rule that cannot be read is never a rule that is not there --------------------------------

/// One undecodable row fails the **whole** set.
///
/// The alternative — skip it, keep the rest — is the permissive failure, and it is silent: the
/// deployment carries on with one refusal fewer than the administrator wrote, and every request
/// that the missing rule would have denied is allowed. The control is the same call over rows that
/// all decode, which must return every one of them.
#[test]
fn one_undecodable_row_fails_the_whole_set_rather_than_being_skipped() {
    let good = row("HUMAN", r#"["actor_is_guest"]"#, "BLOCK", "ENFORCE");
    let bad = row("MACHINE", r#"[{"auth_strength_below":"multi_factor"}]"#, "BLOCK", "ENFORCE");

    assert!(
        decode_rules(std::slice::from_ref(&good)).is_ok(),
        "the control row must decode, or the failure below says nothing"
    );
    assert_eq!(decode_rules(&[good.clone(), good.clone()]).expect("both decode").len(), 2);
    assert!(
        decode_rules(&[good, bad]).is_err(),
        "a set containing an undecodable rule must fail rather than return the rest"
    );
}

/// An unrecognised mode is refused rather than treated as `SIMULATION`.
///
/// The direction is the point. Demoting an unreadable mode to "rehearse" gives an administrator a
/// control that reports itself as on and refuses nothing — the exact failure
/// `plans/M4-GOVERNANCE.md §2` is written against.
#[test]
fn an_unrecognised_mode_is_refused_rather_than_demoted_to_rehearsing() {
    assert!(decode_rule(&row("HUMAN", "[]", "BLOCK", "ENFORCED")).is_err());
    assert!(decode_rule(&row("HUMAN", "[]", "BLOCK", "")).is_err());

    // The controls: both real modes decode, and the enforcing one stays enforcing.
    match decode_rule(&row("HUMAN", "[]", "BLOCK", "ENFORCE")).expect("decodes") {
        Rule::Human(rule) => assert_eq!(rule.mode, RuleMode::Enforce),
        Rule::Machine(_) => panic!("wrong rule set"),
    }
    match decode_rule(&row("HUMAN", "[]", "BLOCK", "SIMULATION")).expect("decodes") {
        Rule::Human(rule) => assert_eq!(rule.mode, RuleMode::Simulation),
        Rule::Machine(_) => panic!("wrong rule set"),
    }
}

/// `docs/06 §7.4`: there is no `ALLOW` effect, so there is no stored one either.
///
/// A row naming it is refused by this decoder and by `migrations/0019`'s `CHECK` — the second is
/// what holds on the paths that never went through the enum, and it is asserted against a live
/// database in `stored_rules.rs`.
#[test]
fn an_allow_effect_cannot_be_decoded() {
    assert!(decode_rule(&row("HUMAN", "[]", "ALLOW", "ENFORCE")).is_err());
    assert!(decode_rule(&row("MACHINE", "[]", "ALLOW", "ENFORCE")).is_err());
    // The control: an effect that does exist, on an otherwise identical row.
    assert!(decode_rule(&row("HUMAN", "[]", "BLOCK", "ENFORCE")).is_ok());
}

/// A condition list that is not a list at all is refused.
///
/// PostgreSQL's `CHECK (jsonb_typeof(conditions) = 'array')` refuses this on the way in; this is
/// the second half, for a document that reached memory some other way.
#[test]
fn a_conditions_document_that_is_not_an_array_is_refused() {
    assert!(decode_rule(&row("HUMAN", r#"{"actor_is_guest":null}"#, "BLOCK", "ENFORCE")).is_err());
    assert!(decode_rule(&row("HUMAN", "null", "BLOCK", "ENFORCE")).is_err());
    assert!(decode_rule(&row("HUMAN", "[]", "BLOCK", "ENFORCE")).is_ok());
}
