//! The five DLP modes, driven through the real [`PolicyEngine`].
//!
//! Named for the rows of `docs/12-TESTING.md §4.5` that they discharge:
//!
//! | Row | Assertion |
//! |---|---|
//! | `D1` | `ENFORCE` blocks a sensitive external share synchronously |
//! | `D2` | `SIMULATION` records the decision and takes no action |
//! | `D3` | Missing security facts follow `facts_unavailable` — `FAIL_CLOSED` denies |
//! | `D4` | An unhandled obligation fails the operation rather than proceeding |
//!
//! # Why these run the whole chain rather than calling `RuleSet::evaluate`
//!
//! `docs/12 §1.1` draws the line at our integration. The interesting property is not that a
//! comparison against a count returns `true` — it is that a rule which fires becomes a refusal on
//! the way out of `PolicyEngine::enforce`, having been recorded on the way past, against the facts
//! the engine gathered once. Every stage but DLP allows here, so a refusal can only have come from
//! DLP.
//!
//! # The absence problem, and how each row closes it
//!
//! `docs/12 §1.2`: *an assertion about an absence passes for free.* "`SIMULATION` takes no action"
//! holds trivially against a simulation that never evaluates at all, so it is never asserted alone —
//! `d1_and_d2_one_policy_both_ways_records_the_same_decision` runs the **same policy over the same
//! facts in `ENFORCE`** and requires that one to block. The pairing is the control, and it is D28's
//! own test besides.

// Assertions are the point of a test: a panic here is the failure signal, not a production hazard.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use enclave_core::{
    Action, AuthorizationService, BarrierService, ClassificationRank, ClassificationService,
    ConditionalAccessService, DetectorCategory, DetectorCounts, DetectorSetVersion, Error,
    Exposure, FactsPolicy, FactsSnapshot, FactsUnavailable, FileAction, FileId, Obligation,
    Obligations, PolicyAuditSink, PolicyDecision, PolicyEngine, ReasonCode, RequestContext,
    ResourceRef, ResourceState, Result as CoreResult, RetentionService, ScanVersion, SecurityFacts,
    SecurityFactsProvider, ShareAction, Stage, StageDecision, TenantId, Utc, VersionId,
};
use enclave_dlp::mode::Effect;
use enclave_dlp::observation::{Observation, ObservationSink};
use enclave_dlp::policy::{ActionScope, Basis, Condition, DlpAction, DlpRule, RuleId, RuleSet};
use enclave_dlp::{DisabledDlp, DlpMode, ModedDlp};

// =================================================================================================
// Harness — every stage but DLP allows, so a refusal can only have come from DLP.
// =================================================================================================

/// Permits everything, attaching nothing.
#[derive(Debug, Clone, Copy)]
struct AllowAll;

#[async_trait]
impl ConditionalAccessService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

#[async_trait]
impl AuthorizationService for AllowAll {
    async fn authorize(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }

    async fn authorize_many(
        &self,
        _: &RequestContext,
        _: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        Ok(resources.iter().map(|_| StageDecision::allow()).collect())
    }
}

#[async_trait]
impl BarrierService for AllowAll {
    async fn evaluate(&self, _: &RequestContext, _: &ResourceRef) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }

    async fn allowed_barrier_tokens(&self, _: &RequestContext) -> CoreResult<Vec<String>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl ClassificationService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

#[async_trait]
impl RetentionService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

/// Discards the engine's own audit events.
///
/// The DLP observations are what these tests read; that every outcome also produces an audit row is
/// asserted in `crates/core/src/engine.rs` against a recording sink, and end to end against a real
/// one in `crates/api/tests/delivery.rs`.
#[derive(Debug, Clone, Copy)]
struct NoAudit;

#[async_trait]
impl PolicyAuditSink for NoAudit {
    async fn record_allow(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
        _: &Obligations,
    ) -> CoreResult<()> {
        Ok(())
    }

    async fn record_deny(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
        _: Stage,
        _: ReasonCode,
    ) -> CoreResult<()> {
        Ok(())
    }
}

/// Hands the engine one prepared snapshot, and counts how often it was asked for it.
#[derive(Debug)]
struct FixedFacts {
    snapshot: FactsSnapshot,
    calls: Mutex<usize>,
}

impl FixedFacts {
    fn new(snapshot: FactsSnapshot) -> Arc<Self> {
        Arc::new(Self { snapshot, calls: Mutex::new(0) })
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("call count")
    }
}

#[async_trait]
impl SecurityFactsProvider for FixedFacts {
    async fn gather(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<FactsSnapshot> {
        *self.calls.lock().expect("call count") += 1;
        Ok(self.snapshot.clone())
    }
}

/// Keeps every observation, so what a mode *recorded* is assertable and not only what it did.
#[derive(Debug, Default)]
struct Recorder {
    seen: Mutex<Vec<Observation>>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn observations(&self) -> Vec<Observation> {
        self.seen.lock().expect("observations").clone()
    }

    fn only(&self) -> Observation {
        let all = self.observations();
        assert_eq!(all.len(), 1, "expected exactly one observation, got {}", all.len());
        all.into_iter().next().expect("one observation")
    }
}

impl ObservationSink for Recorder {
    fn record(&self, observation: &Observation) {
        self.seen.lock().expect("observations").push(observation.clone());
    }
}

const ACTIVE_SET: &str = "builtin/1";
const EXTERNAL_SHARE: Action = Action::File(FileAction::ShareExternal);
const DOWNLOAD: Action = Action::File(FileAction::Download);

/// The rule most of these tests run: **block external sharing of anything carrying payment data**.
///
/// `docs/06 §9` makes this exactly the shape that must be simulated before it may be enforced, and
/// `docs/12 §4.5` D1 names it as the row.
fn payment_data_rule() -> RuleSet {
    RuleSet::new(vec![DlpRule::new(
        RuleId::new("block-external-share-of-payment-data"),
        vec![ActionScope::ExternalSharing],
        vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
        DlpAction::Block,
    )])
}

/// Facts as a scan finding `count` payment identifiers would have left them.
fn scanned(count: u32) -> SecurityFacts {
    let mut counts = DetectorCounts::none();
    counts.add(DetectorCategory::Financial, count);
    SecurityFacts::scanned(
        FileId::new_v7(),
        VersionId::new_v7(),
        counts,
        DetectorSetVersion::new(ACTIVE_SET),
        ScanVersion::new(1),
        Utc::now(),
    )
}

/// A completed, current scan over an internal, `INTERNAL`-labelled document.
fn fresh(count: u32) -> FactsSnapshot {
    FactsSnapshot::gathered(
        scanned(count),
        &DetectorSetVersion::new(ACTIVE_SET),
        FactsPolicy::fail_closed(),
        ResourceState::new(Exposure::Internal, Some(ClassificationRank::new(20))),
    )
}

/// No scan at all, under a named `facts_unavailable` mode.
fn unscanned(mode: FactsUnavailable, exposure: Exposure) -> FactsSnapshot {
    FactsSnapshot::missing(
        FactsPolicy::from_tenant_config(mode, ClassificationRank::RESTRICTED),
        ResourceState::new(exposure, Some(ClassificationRank::new(20))),
    )
}

fn engine(
    mode: DlpMode,
    rules: RuleSet,
    sink: Arc<Recorder>,
    facts: Arc<FixedFacts>,
) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(ModedDlp::new(mode, rules, sink as Arc<dyn ObservationSink>)),
        Arc::new(AllowAll),
        Arc::new(NoAudit),
    )
    .with_facts(facts as Arc<dyn SecurityFactsProvider>)
}

/// Runs the chain, taking the obligations by value so nothing is dropped (`CLAUDE.md` rule 8).
async fn run(engine: &PolicyEngine, action: Action) -> Result<Obligations, Error> {
    let tenant = TenantId::new_v7();
    let ctx = RequestContext::system(tenant);
    let resource = ResourceRef::file(tenant, FileId::new_v7());
    engine.enforce(&ctx, action, &resource).await.map(PolicyDecision::into_obligations)
}

/// Whether the chain refused, discharging the decision either way.
async fn refused(engine: &PolicyEngine, action: Action) -> bool {
    match run(engine, action).await {
        Ok(obligations) => {
            let _count = obligations.len();
            false
        }
        Err(Error::PolicyDenied { .. }) => true,
        Err(other) => panic!("the chain failed rather than deciding: {other:?}"),
    }
}

// =================================================================================================
// D1 + D2 + D28 — one policy, both ways.
// =================================================================================================

/// **D1**, **D2** and **D28** in one test, because separating them is what makes D2 vacuous.
///
/// The same rule set, the same facts and the same action are run under `ENFORCE` and under
/// `SIMULATION`. The order of the assertions matters:
///
/// 1. **The positive control first.** `ENFORCE` must refuse. Without it everything below holds
///    against a policy that never fires, a rule set that governs nothing, or a chain in which DLP
///    was never reached — `docs/12 §1.2`'s exact failure shape.
/// 2. **`SIMULATION` allows.** The absence, now meaningful.
/// 3. **The recorded decision is identical.** `verdict` — what the policy concluded — and
///    `would_enforce` — what `ENFORCE` would have done — must be equal across the two runs. That is
///    D28: the only permitted difference is that the action was recorded rather than taken.
/// 4. **The facts were read in both.** A simulation that is fast because it skips work is a
///    rehearsal of a different play.
#[tokio::test]
async fn d1_and_d2_one_policy_both_ways_records_the_same_decision() {
    // --- ENFORCE: the positive control, and D1 -------------------------------------------------
    let enforcing_sink = Recorder::new();
    let enforcing_facts = FixedFacts::new(fresh(3));
    let enforcing = engine(
        DlpMode::Enforce,
        payment_data_rule(),
        Arc::clone(&enforcing_sink),
        Arc::clone(&enforcing_facts),
    );

    let error = run(&enforcing, EXTERNAL_SHARE).await.expect_err("ENFORCE must refuse");
    match error {
        Error::PolicyDenied { code, .. } => assert_eq!(code, ReasonCode::DlpBlocked),
        other => panic!("D1: an external share of payment data was not blocked: {other:?}"),
    }

    // --- SIMULATION: the same everything -------------------------------------------------------
    let simulating_sink = Recorder::new();
    let simulating_facts = FixedFacts::new(fresh(3));
    let simulating = engine(
        DlpMode::Simulation,
        payment_data_rule(),
        Arc::clone(&simulating_sink),
        Arc::clone(&simulating_facts),
    );

    let obligations = run(&simulating, EXTERNAL_SHARE).await.expect("SIMULATION must not refuse");
    assert!(
        obligations.is_empty(),
        "D2: SIMULATION shaped the request as well as recording it: {obligations:?}"
    );

    // --- D28: the recorded decision is the same ------------------------------------------------
    let enforced = enforcing_sink.only();
    let simulated = simulating_sink.only();

    assert_eq!(
        simulated.verdict(),
        enforced.verdict(),
        "D28: the two modes reached different conclusions about the same policy and facts"
    );
    assert_eq!(
        simulated.would_enforce(),
        enforced.would_enforce(),
        "D28: simulation's answer to \"what would enforcement have done\" is not what it does"
    );
    assert!(
        simulated.would_have_blocked(),
        "D2 is vacuous unless the simulation recorded that it would have blocked"
    );
    assert!(!simulated.was_blocked(), "D2: SIMULATION took the action instead of recording it");
    assert!(enforced.was_blocked());

    // The rule fired in both, by name — so the equality above is two runs of a policy that did
    // something rather than two runs of one that did nothing.
    assert_eq!(simulated.fired().len(), 1);
    assert_eq!(simulated.fired()[0].as_str(), "block-external-share-of-payment-data");
    assert_eq!(simulated.fired(), enforced.fired());

    // And the same work was done in both.
    assert_eq!(enforcing_facts.calls(), 1);
    assert_eq!(simulating_facts.calls(), 1, "D28: SIMULATION skipped the facts read");
}

/// The `ENFORCE`/`SIMULATION` equality must hold for *every* outcome a policy can reach, not only
/// for the blocking one — a divergence in the clean case is a rollout that under-reports.
#[tokio::test]
async fn simulation_and_enforcement_agree_on_every_outcome_a_policy_can_reach() {
    let cases: [(&str, DlpAction, u32); 6] = [
        ("blocks", DlpAction::Block, 3),
        ("quarantines", DlpAction::Quarantine, 3),
        ("watermarks", DlpAction::Watermark, 3),
        ("demands a justification", DlpAction::RequireJustification, 3),
        ("audits only", DlpAction::Audit, 3),
        ("does not fire at all", DlpAction::Block, 0),
    ];

    for (name, action, findings) in cases {
        let rules = || {
            RuleSet::new(vec![DlpRule::new(
                RuleId::new("rule"),
                vec![ActionScope::Any],
                vec![Condition::CategoryAtLeast {
                    category: DetectorCategory::Financial,
                    count: 1,
                }],
                action,
            )])
        };

        let mut recorded = Vec::new();
        for mode in [DlpMode::Enforce, DlpMode::Simulation] {
            let sink = Recorder::new();
            let chain = engine(mode, rules(), Arc::clone(&sink), FixedFacts::new(fresh(findings)));
            let denied = refused(&chain, DOWNLOAD).await;
            if mode == DlpMode::Simulation {
                assert!(!denied, "SIMULATION refused a request for a policy that {name}");
            }
            recorded.push(sink.only());
        }

        assert_eq!(
            recorded[1].verdict(),
            recorded[0].verdict(),
            "D28: the verdicts diverged for a policy that {name}"
        );
        assert_eq!(
            recorded[1].would_enforce(),
            recorded[0].would_enforce(),
            "D28: the would-be decisions diverged for a policy that {name}"
        );
    }
}

// =================================================================================================
// The ladder — each mode does what `docs/06 §9` says and no more.
// =================================================================================================

/// `DISABLED` inspects nothing; `MONITOR` and `SIMULATION` observe; `WARN` shapes; `ENFORCE`
/// refuses.
///
/// One table, because the interesting failure is a mode doing *one step more* than it should, and
/// that is only visible beside its neighbours.
#[tokio::test]
async fn each_mode_does_exactly_what_its_rung_of_the_ladder_says() {
    // A policy that both shapes and blocks, so a mode's two independent behaviours are separable
    // within one run.
    let rules = || {
        RuleSet::new(vec![
            DlpRule::new(
                RuleId::new("watermark"),
                vec![ActionScope::Any],
                vec![Condition::AnyFinding],
                DlpAction::Watermark,
            ),
            DlpRule::new(
                RuleId::new("block"),
                vec![ActionScope::ExternalSharing],
                vec![Condition::AnyFinding],
                DlpAction::Block,
            ),
        ])
    };

    // (mode, records, attaches the watermark to a download, refuses an external share)
    let ladder = [
        (DlpMode::Disabled, false, false, false),
        (DlpMode::Monitor, true, false, false),
        (DlpMode::Simulation, true, false, false),
        (DlpMode::Warn, true, true, false),
        (DlpMode::Enforce, true, true, true),
    ];

    for (mode, records, shapes, refuses) in ladder {
        let sink = Recorder::new();
        let chain = engine(mode, rules(), Arc::clone(&sink), FixedFacts::new(fresh(2)));
        let obligations = run(&chain, DOWNLOAD).await.expect("a download is never blocked here");

        assert_eq!(sink.observations().len(), usize::from(records), "{mode}: recording");
        // The record has to say which mode produced it. `MONITOR` and `SIMULATION` differ in
        // *nothing else* — same evaluation, same effect on the request — so if the label were
        // wrong, `docs/06 §9`'s "the admin UI refuses to enable enforcement on a policy that has
        // never been simulated" would be reading a field that lies, while every behavioural
        // assertion in this file stayed green. Added because a deliberate break that stamped every
        // observation `MONITOR` failed no test at all.
        if records {
            assert_eq!(sink.only().mode(), mode, "the observation was stamped with another mode");
        }
        assert_eq!(
            obligations.contains(&Obligation::Watermark),
            shapes,
            "{mode}: obligation attachment"
        );

        let sink = Recorder::new();
        let chain = engine(mode, rules(), Arc::clone(&sink), FixedFacts::new(fresh(2)));
        assert_eq!(refused(&chain, EXTERNAL_SHARE).await, refuses, "{mode}: refusal");
    }
}

/// `DISABLED` as a mode and `DisabledDlp` as a type are the same behaviour.
///
/// `DisabledDlp` exists so a deployment that wants DLP off need not name a rule set and a sink.
/// That convenience is only safe while the two agree — otherwise turning DLP off through
/// configuration and turning it off through wiring would mean different things.
#[tokio::test]
async fn the_disabled_mode_and_the_disabled_service_agree() {
    let sink = Recorder::new();
    let moded = engine(
        DlpMode::Disabled,
        payment_data_rule(),
        Arc::clone(&sink),
        FixedFacts::new(fresh(9)),
    );
    assert!(!refused(&moded, EXTERNAL_SHARE).await, "DISABLED refused something");
    assert!(sink.observations().is_empty(), "DISABLED inspected content");

    let bare = PolicyEngine::new(
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(DisabledDlp),
        Arc::new(AllowAll),
        Arc::new(NoAudit),
    )
    .with_facts(FixedFacts::new(fresh(9)) as Arc<dyn SecurityFactsProvider>);
    assert!(!refused(&bare, EXTERNAL_SHARE).await, "DisabledDlp refused something");

    // The control: the *same* rule set in ENFORCE refuses the same request, so the two allows above
    // are DLP being off rather than a rule that never fires.
    let enforcing =
        engine(DlpMode::Enforce, payment_data_rule(), Recorder::new(), FixedFacts::new(fresh(9)));
    assert!(refused(&enforcing, EXTERNAL_SHARE).await);
}

// =================================================================================================
// D3 — missing facts.
// =================================================================================================

/// **D3** — missing security facts follow `facts_unavailable`, and `FAIL_CLOSED` denies.
///
/// Three legs, and the last two are the controls that stop the first passing for free:
///
/// * `FAIL_CLOSED` with no facts refuses.
/// * `FAIL_OPEN_AUDIT` with the same absent facts **permits**, and leaves the evidence that is the
///   entire difference between the two modes — so the refusal is the policy rather than "unscanned
///   content is always refused".
/// * `FAIL_CLOSED` with *fresh* facts that fire nothing permits — so the refusal is the absence of
///   facts rather than the mode refusing everything.
#[tokio::test]
async fn d3_missing_facts_follow_the_tenants_policy() {
    let sink = Recorder::new();
    let closed = engine(
        DlpMode::Enforce,
        payment_data_rule(),
        Arc::clone(&sink),
        FixedFacts::new(unscanned(FactsUnavailable::FailClosed, Exposure::Internal)),
    );
    let error = run(&closed, EXTERNAL_SHARE).await.expect_err("FAIL_CLOSED must refuse");
    match error {
        Error::PolicyDenied { code, .. } => assert_eq!(code, ReasonCode::DlpBlocked),
        other => panic!("D3: an unscanned external share was not refused: {other:?}"),
    }
    assert!(matches!(sink.only().verdict().basis(), Basis::Unavailable { .. }));

    // Control 1: the other configured mode genuinely fails open, and says so in the record.
    // `ShareExternal` is escalated whatever the tenant configured, so the fail-open case has to be
    // asked about an action it is allowed to answer.
    let sink = Recorder::new();
    let open = engine(
        DlpMode::Enforce,
        RuleSet::new(vec![DlpRule::new(
            RuleId::new("justify-downloads"),
            vec![ActionScope::ExposesContent],
            vec![Condition::AnyFinding],
            DlpAction::Block,
        )]),
        Arc::clone(&sink),
        FixedFacts::new(unscanned(FactsUnavailable::FailOpenAudit, Exposure::Internal)),
    );
    let obligations = run(&open, DOWNLOAD).await.expect("FAIL_OPEN_AUDIT permits an internal read");
    assert!(obligations.is_empty());
    assert!(
        sink.only().permitted_unscanned(),
        "the fail-open allow left no evidence, which is the entire difference between the modes"
    );

    // Control 2: `FAIL_CLOSED` with facts in hand permits a document that fires nothing, so leg one
    // is the missing facts rather than the mode.
    let clean =
        engine(DlpMode::Enforce, payment_data_rule(), Recorder::new(), FixedFacts::new(fresh(0)));
    assert!(!refused(&clean, EXTERNAL_SHARE).await, "a clean document was refused");
}

/// D27's mandatory escalation survives the trip through the chain: `FAIL_OPEN_AUDIT` does not
/// permit an external share of unscanned content, whatever the tenant configured.
#[tokio::test]
async fn external_sharing_of_unscanned_content_is_refused_under_either_configured_mode() {
    for mode in [FactsUnavailable::FailClosed, FactsUnavailable::FailOpenAudit] {
        let chain = engine(
            DlpMode::Enforce,
            payment_data_rule(),
            Recorder::new(),
            FixedFacts::new(unscanned(mode, Exposure::Internal)),
        );
        assert!(
            refused(&chain, EXTERNAL_SHARE).await,
            "unscanned content was shared externally under {mode}"
        );
    }
}

/// `ENC-588`, through the chain: changing the terms of a share that is **already external** is
/// refused for the same reason creating one is.
#[tokio::test]
async fn updating_an_already_external_share_is_refused_without_facts() {
    const UPDATE: Action = Action::Share(ShareAction::Update);
    let rules = || {
        RuleSet::new(vec![DlpRule::new(
            RuleId::new("govern-sharing"),
            vec![ActionScope::ExternalSharing],
            vec![Condition::AnyFinding],
            DlpAction::Block,
        )])
    };

    let external = engine(
        DlpMode::Enforce,
        rules(),
        Recorder::new(),
        FixedFacts::new(unscanned(FactsUnavailable::FailOpenAudit, Exposure::External)),
    );
    assert!(
        refused(&external, UPDATE).await,
        "the terms of an external link over unscanned content were changed under FAIL_OPEN_AUDIT"
    );

    // The control: the same update on an *internal* share is not even governed by the rule, and is
    // permitted — so the refusal above is the exposure rather than the action.
    let internal = engine(
        DlpMode::Enforce,
        rules(),
        Recorder::new(),
        FixedFacts::new(unscanned(FactsUnavailable::FailOpenAudit, Exposure::Internal)),
    );
    assert!(!refused(&internal, UPDATE).await, "an internal share update was refused");
}

/// An action no rule governs must not be refused because a scan has not finished.
///
/// The failure this prevents is the one `plans/M4-GOVERNANCE.md §2` is entirely about: a
/// `FAIL_CLOSED` tenant whose every request is refused while a scanning backlog drains is a tenant
/// that turns DLP off and never turns it back on.
#[tokio::test]
async fn an_action_no_rule_governs_is_never_refused_for_facts_it_did_not_need() {
    let sink = Recorder::new();
    // The rule governs external sharing only; a download is outside its scope.
    let chain = engine(
        DlpMode::Enforce,
        payment_data_rule(),
        Arc::clone(&sink),
        FixedFacts::new(unscanned(FactsUnavailable::FailClosed, Exposure::Internal)),
    );

    let obligations = run(&chain, DOWNLOAD).await.expect("an ungoverned action must proceed");
    assert!(obligations.is_empty());
    assert!(
        matches!(sink.only().verdict().basis(), Basis::NotGoverned),
        "facts were consulted for an action no rule governs"
    );

    // The control: the action the rule *does* govern is refused against the very same snapshot, so
    // the allow above is the scope rather than a chain that permits everything.
    let governed = engine(
        DlpMode::Enforce,
        payment_data_rule(),
        Recorder::new(),
        FixedFacts::new(unscanned(FactsUnavailable::FailClosed, Exposure::Internal)),
    );
    assert!(refused(&governed, EXTERNAL_SHARE).await);
}

// =================================================================================================
// D4 — obligations.
// =================================================================================================

/// **D4** — an obligation the caller cannot satisfy fails the operation.
///
/// Asserted at the level `enclave-core` owns: the chain hands back an obligation, and
/// `Obligations::require_none` — what a surface with no way to satisfy one calls — refuses. The
/// delivery-path half, where a `NO_DOWNLOAD` obligation stops a signed URL ever being minted, is
/// `crates/api/tests/delivery.rs`.
///
/// The control is the clean document: the same call proceeds when no obligation was attached, so
/// the refusal is the obligation rather than a check that refuses everything.
#[tokio::test]
async fn d4_an_obligation_that_cannot_be_satisfied_fails_the_operation() {
    let rules = || {
        RuleSet::new(vec![DlpRule::new(
            RuleId::new("justify-downloads-of-payment-data"),
            vec![ActionScope::ExposesContent],
            vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
            DlpAction::RequireJustification,
        )])
    };

    let chain = engine(DlpMode::Enforce, rules(), Recorder::new(), FixedFacts::new(fresh(2)));
    let obligations = run(&chain, DOWNLOAD).await.expect("the chain allows; the obligation binds");
    assert!(obligations.contains(&Obligation::RequireJustification));
    assert!(obligations.has_blocking());

    let error = obligations
        .require_none()
        .expect_err("a surface that cannot collect a justification must refuse");
    match error {
        Error::PolicyDenied { code, .. } => {
            assert_eq!(code, ReasonCode::DlpJustificationRequired);
        }
        other => panic!("D4: an unsatisfiable obligation did not fail the operation: {other:?}"),
    }

    // The control: with nothing found, no obligation is attached and the same call proceeds.
    let clean = engine(DlpMode::Enforce, rules(), Recorder::new(), FixedFacts::new(fresh(0)));
    let obligations = run(&clean, DOWNLOAD).await.expect("a clean document proceeds");
    assert!(obligations.is_empty());
    assert!(obligations.require_none().is_ok(), "require_none refuses even an empty set");
}

/// A blocking rule and a shaping rule in one policy: the refusal wins, and the obligation is still
/// recorded as part of what enforcement would have required.
///
/// The recorded half matters for rollout. An operator simulating a policy that both watermarks and
/// blocks needs to see both, or the record understates the change they are about to make.
#[tokio::test]
async fn a_blocking_rule_refuses_while_the_record_keeps_what_enforcement_would_have_required() {
    let rules = RuleSet::new(vec![
        DlpRule::new(
            RuleId::new("watermark"),
            vec![ActionScope::Any],
            vec![Condition::AnyFinding],
            DlpAction::Watermark,
        ),
        DlpRule::new(
            RuleId::new("block"),
            vec![ActionScope::Any],
            vec![Condition::AnyFinding],
            DlpAction::Block,
        ),
    ]);

    let sink = Recorder::new();
    let chain = engine(DlpMode::Enforce, rules, Arc::clone(&sink), FixedFacts::new(fresh(1)));
    assert!(refused(&chain, DOWNLOAD).await);

    let observed = sink.only();
    assert!(observed.was_blocked());
    assert_eq!(
        observed.verdict().obligations().len(),
        1,
        "the watermark the policy demands vanished from the record because the block won"
    );
    assert!(observed.applied_obligations().is_empty(), "a denial carries no obligations");
    assert!(matches!(observed.applied(), Effect::Deny(_)));
}

/// `docs/06 §9`: simulation is mandatory before enforcement for any `BLOCK` or `QUARANTINE` policy.
///
/// The predicate an admin surface asks lives on the type, so the rule is one statement rather than
/// a `matches!` in whichever screen needs it next.
#[test]
fn the_actions_that_must_be_simulated_first_are_block_and_quarantine() {
    assert!(DlpAction::Block.requires_simulation_first());
    assert!(DlpAction::Quarantine.requires_simulation_first());

    for benign in [
        DlpAction::Allow,
        DlpAction::Audit,
        DlpAction::Warn,
        DlpAction::Watermark,
        DlpAction::ReadOnly,
        DlpAction::NoDownload,
        DlpAction::RequireJustification,
        DlpAction::RequireApproval,
        DlpAction::NotifySecurity,
        DlpAction::RemoveShare,
        DlpAction::Reclassify { to: ClassificationRank::new(40) },
    ] {
        assert!(!benign.requires_simulation_first(), "{benign}");
    }
}
