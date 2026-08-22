//! The behavioural half of the audit-coverage gate: every stage that can refuse produces a row,
//! and the row can explain the refusal.
//!
//! `CLAUDE.md` rule 10, `plans/M4-GOVERNANCE.md` D32, `docs/12-TESTING.md §4.10` U5/U6.
//!
//! # Why this exists beside `cargo run -p xtask -- audit-coverage`
//!
//! The static gate proves a refusal is *constructed* somewhere the engine records it. It cannot
//! prove that the engine's write happened, and it cannot prove that the row which results is any
//! use to the person reading it. Those are different claims and they fail differently:
//!
//! * delete `record_deny` from the chain and the static gate still passes — every refusal is still
//!   constructed in a `Result<StageDecision>` function;
//! * drop the stage attribution from the row and both the static gate and `core`'s own engine
//!   tests still pass — the engine's tests assert against a `RecordingAudit` mock that receives a
//!   `Stage` argument, so they check that the *call* carried it, never that the *record* does.
//!
//! So this drives the real [`PolicyEngine`] into the real [`AuditEvent`] format, once per stage,
//! and asserts on the row. `enclave-audit` is the right crate for it: it owns the record format,
//! and it is the lowest crate that can see both the engine and the row.
//!
//! # What "the row can explain the refusal" means here
//!
//! Three things, and an incident investigation needs all three:
//!
//! 1. **that it was refused** — `outcome = DENY`;
//! 2. **why** — a `reason_code`, from the same closed vocabulary the caller was given, so the
//!    auditor and the user who was refused are reading the same word;
//! 3. **by what** — the stage, carried in `policy_refs` and therefore inside the hashed bytes.
//!
//! A row with the first two and not the third says a request was denied and gives no way to find
//! the control that denied it, which is the question an investigation actually starts from.
//!
//! # The direction that matters
//!
//! Every stage is driven, in a loop over [`Stage::ORDER`], so a stage added to the chain without a
//! matching audit call fails here by name. Adding a stage also changes `PolicyEngine::new`'s
//! arity, so the loop cannot silently skip the new one: the file stops compiling until someone
//! wires it, and then this test requires it to produce a row.

// Assertions are the point of a test; the workspace warns on these in shipped code.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use enclave_audit::{MemoryAuditSink, Outcome};
use enclave_core::{
    Action, Actor, AuthStrength, AuthorizationService, BarrierService, ClassificationService,
    ConditionalAccessService, DeviceContext, DevicePosture, DlpService, Error, FactsSnapshot,
    FileAction, FileId, NetworkContext, Obligation, Obligations, PolicyAuditSink, PolicyEngine,
    ReasonCode, RequestContext, RequestId, ResourceRef, Result, RetentionService, ScopeSet,
    SessionId, Stage, StageDecision, TenantId, UserId, Uuid,
};

/// The action every case runs, chosen because it is one the product actually refuses.
const ACTION: Action = Action::File(FileAction::Download);

/// A stage that allows, or refuses with a given code.
///
/// One type implementing all six stage traits, so that the loop below can put the *same* double in
/// every position and vary only which one refuses. Six near-identical doubles would drift, and a
/// drifted double is a test that proves something other than its name.
#[derive(Debug, Clone, Copy)]
struct Configurable {
    deny: Option<ReasonCode>,
    obligation: Option<Obligation>,
}

impl Configurable {
    const fn allow() -> Self {
        Self { deny: None, obligation: None }
    }

    const fn deny(code: ReasonCode) -> Self {
        Self { deny: Some(code), obligation: None }
    }

    const fn allow_with(obligation: Obligation) -> Self {
        Self { deny: None, obligation: Some(obligation) }
    }

    fn decide(self) -> StageDecision {
        match (self.deny, self.obligation) {
            (Some(code), _) => StageDecision::deny(code),
            (None, Some(obligation)) => {
                StageDecision::allow_with(std::iter::once(obligation).collect())
            }
            (None, None) => StageDecision::allow(),
        }
    }
}

#[async_trait]
impl ConditionalAccessService for Configurable {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(self.decide())
    }
}

#[async_trait]
impl AuthorizationService for Configurable {
    async fn authorize(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(self.decide())
    }

    async fn authorize_many(
        &self,
        _: &RequestContext,
        _: Action,
        resources: &[ResourceRef],
    ) -> Result<Vec<StageDecision>> {
        Ok(resources.iter().map(|_| self.decide()).collect())
    }
}

#[async_trait]
impl BarrierService for Configurable {
    async fn evaluate(&self, _: &RequestContext, _: &ResourceRef) -> Result<StageDecision> {
        Ok(self.decide())
    }

    async fn allowed_barrier_tokens(&self, _: &RequestContext) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl ClassificationService for Configurable {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(self.decide())
    }
}

#[async_trait]
impl DlpService for Configurable {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
        _: &FactsSnapshot,
    ) -> Result<StageDecision> {
        Ok(self.decide())
    }
}

#[async_trait]
impl RetentionService for Configurable {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(self.decide())
    }
}

/// A request context with every field the audit row copies actually populated.
///
/// Populated rather than defaulted so that a row which failed to copy one of them is
/// distinguishable from a row that copied an absent value.
fn context(tenant: TenantId) -> RequestContext {
    RequestContext {
        request_id: RequestId::new_v7(),
        tenant_id: tenant,
        actor: Actor::User(UserId::from_uuid(Uuid::from_u128(
            0x0192_0000_0000_7000_8000_0000_0000_0011,
        ))),
        session_id: Some(SessionId::from_uuid(Uuid::from_u128(
            0x0192_0000_0000_7000_8000_0000_0000_0012,
        ))),
        auth_strength: AuthStrength::MultiFactor,
        auth_time: chrono::Utc::now(),
        scopes: ScopeSet::from(vec!["files:read".to_owned()]),
        client: enclave_core::ClientType::Web,
        network: NetworkContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            country: Some("IN".to_owned()),
            asn: Some(64_500),
            zones: vec!["Corporate".to_owned()],
            via_trusted_proxy: false,
        },
        device: DeviceContext { device_id: None, posture: DevicePosture::Managed },
    }
}

fn resource(tenant: TenantId) -> ResourceRef {
    ResourceRef::file(tenant, FileId::new_v7())
}

/// Assemble an engine whose stages are exactly the six supplied, writing into `sink`.
///
/// Every stage is a positional argument on `PolicyEngine::new`, which is what makes a *new* stage
/// impossible to omit here: the file stops compiling.
fn engine(stages: [Configurable; 6], sink: &Arc<MemoryAuditSink>) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(stages[0]),
        Arc::new(stages[1]),
        Arc::new(stages[2]),
        Arc::new(stages[3]),
        Arc::new(stages[4]),
        Arc::new(stages[5]),
        Arc::clone(sink) as Arc<dyn PolicyAuditSink>,
    )
}

/// The six chain positions, in the order `PolicyEngine::new` takes them.
///
/// `Stage::TenantIsolation` is deliberately absent: it is not a service the engine holds, it is an
/// invariant the engine asserts itself, and it gets its own case below.
const CONFIGURABLE_STAGES: [Stage; 6] = [
    Stage::ConditionalAccess,
    Stage::Authorization,
    Stage::Barriers,
    Stage::Classification,
    Stage::Dlp,
    Stage::Retention,
];

/// A distinct reason code per stage, so that a row cannot be attributed to the right stage by
/// accident.
///
/// If every stage denied with `ACCESS_DENIED`, a chain that recorded a fixed code would pass, and
/// so would one that attributed every denial to the first stage. Different codes make the row's
/// two explanatory fields independently checkable.
const fn code_for(stage: Stage) -> ReasonCode {
    match stage {
        Stage::TenantIsolation => ReasonCode::AccessDenied,
        Stage::ConditionalAccess => ReasonCode::NetworkNotAllowed,
        Stage::Authorization => ReasonCode::AccessDenied,
        Stage::Barriers => ReasonCode::ExternalShareBlocked,
        Stage::Classification => ReasonCode::ClassificationCeiling,
        Stage::Dlp => ReasonCode::DlpBlocked,
        Stage::Retention => ReasonCode::LegalHoldActive,
    }
}

/// Every stage that can refuse writes exactly one row, and the row names it.
///
/// The loop is over `CONFIGURABLE_STAGES`, and its length is checked against `Stage::ORDER` below,
/// so a stage added to the chain and not to this test is a failure rather than an omission.
#[tokio::test]
async fn every_stage_that_denies_produces_one_row_that_names_it() {
    for (index, denier) in CONFIGURABLE_STAGES.iter().enumerate() {
        let sink = Arc::new(MemoryAuditSink::default());
        let code = code_for(*denier);

        let mut stages = [Configurable::allow(); 6];
        stages[index] = Configurable::deny(code);

        let tenant = TenantId::new_v7();
        let ctx = context(tenant);
        let target = resource(tenant);

        let error = engine(stages, &sink)
            .enforce(&ctx, ACTION, &target)
            .await
            .expect_err("the stage refused, so enforce must return an error");
        assert!(matches!(error, Error::PolicyDenied { .. }), "{denier}: {error:?}");

        let events = sink.events().expect("read the recorded events");
        assert_eq!(
            events.len(),
            1,
            "{denier}: expected exactly one audit row, got {}. More than one means the denial was \
             recorded twice; none means the refusal reached the caller with nothing written.",
            events.len()
        );

        let event = &events[0];
        assert_eq!(event.outcome, Outcome::Deny, "{denier}: the row does not record a refusal");
        assert_eq!(
            event.reason_code,
            Some(code),
            "{denier}: the row's reason code is not the one the caller was given, so the auditor \
             and the refused user are reading different words"
        );

        // The stage, inside the hashed bytes. "Denied" without "by which control" is not something
        // an investigation can start from.
        let attributed: Vec<&str> =
            event.policy_refs.iter().map(|reference| reference.kind.as_str()).collect();
        assert!(
            attributed.contains(&denier.as_str()),
            "{denier}: the row does not say which stage refused. policy_refs = {attributed:?}"
        );

        // And it names *that* stage rather than some stage: a chain that attributed every denial
        // to `conditional_access` would satisfy the assertion above for one case in six.
        for other in CONFIGURABLE_STAGES.iter().filter(|s| *s != denier) {
            assert!(
                !attributed.contains(&other.as_str()),
                "{denier}: the row also names {other}, so the attribution is not specific"
            );
        }

        // The row must be identifiable as belonging to this request, or it cannot be found.
        assert_eq!(event.tenant_id, tenant, "{denier}: wrong tenant on the row");
        assert_eq!(event.request_id, ctx.request_id, "{denier}: the row cannot be correlated");
        assert_eq!(event.action, ACTION, "{denier}: the row records a different action");
        assert_eq!(event.resource_id(), Some(target.id), "{denier}: wrong resource on the row");
    }
}

/// Tenant isolation is audited even though no service takes the decision.
///
/// It is the one stage the engine asserts itself (`docs/04 §3` gives the second layer, RLS), and
/// the one whose denial is deliberately indistinguishable from absence to the caller — `404`, never
/// `403`, so a probe cannot confirm the resource exists (`CLAUDE.md` rule 7). The row is therefore
/// the *only* place the difference is recorded, which makes it the row an investigation into a
/// cross-tenant probe depends on entirely.
#[tokio::test]
async fn a_cross_tenant_attempt_is_audited_even_though_the_caller_is_told_nothing() {
    let sink = Arc::new(MemoryAuditSink::default());
    let caller = TenantId::new_v7();
    let other = TenantId::new_v7();

    let error = engine([Configurable::allow(); 6], &sink)
        .enforce(&context(caller), ACTION, &resource(other))
        .await
        .expect_err("a cross-tenant reference must be refused");
    assert!(matches!(error, Error::NotFound), "expected NotFound, got {error:?}");

    let events = sink.events().expect("read the recorded events");
    assert_eq!(events.len(), 1, "the cross-tenant attempt produced {} rows", events.len());
    assert_eq!(events[0].outcome, Outcome::Deny);
    assert_eq!(
        events[0].tenant_id, caller,
        "the row belongs to the caller's chain, not the target's"
    );
    let attributed: Vec<&str> =
        events[0].policy_refs.iter().map(|reference| reference.kind.as_str()).collect();
    assert!(
        attributed.contains(&Stage::TenantIsolation.as_str()),
        "the row does not attribute the refusal to tenant isolation: {attributed:?}"
    );
}

/// No silent successes: an allow produces a row too, and the row carries the obligations.
///
/// The obligations are what make the row usable. "This download was allowed" and "this download
/// was allowed only watermarked" are different facts, and an auditor who cannot tell them apart
/// cannot say whether the control was applied.
///
/// This is also the positive control for the two tests above. Both of them assert that a refusal
/// produces a row; neither would notice a sink that recorded *everything* it was handed, including
/// operations that were never refused. Asserting the allow separately, with its own contents, is
/// what distinguishes a chain that records decisions from one that records events.
#[tokio::test]
async fn an_allow_produces_a_row_that_carries_its_obligations() {
    let sink = Arc::new(MemoryAuditSink::default());

    let mut stages = [Configurable::allow(); 6];
    stages[4] = Configurable::allow_with(Obligation::Watermark);

    let tenant = TenantId::new_v7();
    let ctx = context(tenant);
    let target = resource(tenant);

    let decision = engine(stages, &sink)
        .enforce(&ctx, ACTION, &target)
        .await
        .expect("every stage allowed, so the chain must allow");
    let obligations = decision.into_obligations();
    assert!(
        obligations.contains(&Obligation::Watermark),
        "the obligation did not reach the caller"
    );

    let events = sink.events().expect("read the recorded events");
    assert_eq!(events.len(), 1, "an allowed operation produced {} rows", events.len());
    assert_eq!(events[0].outcome, Outcome::Allow, "an allow was recorded as something else");
    assert_eq!(events[0].reason_code, None, "an allow carries no reason code");

    let detail = serde_json::to_string(&events[0].detail).expect("serialize the row's detail");
    assert!(
        detail.contains("WATERMARK"),
        "the row does not record that the allow was conditional; an auditor cannot tell it from an \
         unconditional one. detail = {detail}"
    );
}

/// An allow row cannot say whether the operation it permitted then happened.
///
/// This is `ENC-606` stated as a property of the chain, and it is the argument for the fix rather
/// than a complaint about it. `POST /files/{id}/download` on a file carrying `NO_DOWNLOAD` is
/// allowed by every stage, and the handler then refuses because original bytes cannot honour that
/// obligation (`CLAUDE.md` rule 8). `GET .../preview` on the same file is allowed and *succeeds*,
/// with its obligation discharged. Two requests, opposite outcomes — and, in the chain's row, the
/// same `outcome`, the same absent `reason_code`, the same absent `policy_refs`.
///
/// So the fix could not have been "the chain should have denied": it correctly did not, and there is
/// nothing the chain knows that would distinguish the two. The distinction is only available to the
/// handler, which is why `enclave_api::refusal` writes a **second** row rather than changing this
/// one — the more so because this one is inside the hash chain and cannot be changed at all.
///
/// Driven twice through the real engine rather than asserted about one row, because the claim is an
/// *equality between two rows* and a single-row assertion cannot express it.
#[tokio::test]
async fn an_allow_row_cannot_say_whether_the_operation_then_happened() {
    let mut stages = [Configurable::allow(); 6];
    stages[4] = Configurable::allow_with(Obligation::NoDownload);

    let tenant = TenantId::new_v7();
    let target = resource(tenant);

    let mut written = Vec::new();
    for _ in 0..2 {
        let sink = Arc::new(MemoryAuditSink::default());
        let _decision = engine(stages, &sink)
            .enforce(&context(tenant), ACTION, &target)
            .await
            .expect("every stage allowed");
        let events = sink.events().expect("read the recorded events");
        assert_eq!(events.len(), 1, "an allowed operation produced {} rows", events.len());
        written.push(events[0].clone());
    }

    // Imagine the first request refused by its handler and the second served. Nothing here differs.
    let refused = &written[0];
    let served = &written[1];
    assert_eq!(refused.outcome, Outcome::Allow);
    assert_eq!(
        (refused.outcome, &refused.reason_code, &refused.policy_refs, &refused.detail),
        (served.outcome, &served.reason_code, &served.policy_refs, &served.detail),
        "the two rows have stopped being identical, so this test no longer demonstrates what it \
         says: an ALLOW row is the same whether the obligation was discharged or refused"
    );

    // The positive control, so the equality above is not holding because both rows are empty: the
    // row does carry the obligation, which is the one hint it gives — and a hint about the
    // *chain*, not about what the surface did with it.
    let detail = serde_json::to_string(&refused.detail).expect("serialize the row's detail");
    assert!(detail.contains("NO_DOWNLOAD"), "the row records no obligation at all: {detail}");
}

/// A run with nothing to refuse still writes, and a run with everything to refuse writes once.
///
/// The liveness half of this file. Both tests above assert about the *contents* of a row, and
/// `docs/12-TESTING.md §1.2` records that an assertion about an absence — "no other stage is
/// named", "no second row" — passes for free against a sink that recorded nothing at all. Every
/// one of them would pass against an engine that audited nothing, if `events.len()` were ever
/// allowed to be zero. It is asserted here on its own so the failure is named rather than inferred.
#[tokio::test]
async fn the_sink_is_actually_written_to() {
    let sink = Arc::new(MemoryAuditSink::default());
    assert!(sink.is_empty().expect("read the sink"), "the sink did not start empty");

    let tenant = TenantId::new_v7();
    let ctx = context(tenant);
    let target = resource(tenant);

    let allowing = engine([Configurable::allow(); 6], &sink);
    let _decision = allowing.enforce(&ctx, ACTION, &target).await.expect("allowed");
    assert_eq!(sink.len().expect("read the sink"), 1, "the allow wrote no row");

    let denying = engine([Configurable::deny(ReasonCode::AccessDenied); 6], &sink);
    let _error = denying.enforce(&ctx, ACTION, &target).await.expect_err("denied");
    assert_eq!(sink.len().expect("read the sink"), 2, "the deny wrote no row");
}

/// The chain's stage list and this file's stage list are the same list.
///
/// Without this the loop could quietly cover five of six stages: `CONFIGURABLE_STAGES` is a
/// hand-written array, and a stage inserted into `Stage::ORDER` would leave it a stage short while
/// every assertion above still passed.
#[test]
fn this_file_covers_every_stage_the_chain_runs() {
    let mut expected: Vec<Stage> = Stage::ORDER.to_vec();
    expected.retain(|stage| *stage != Stage::TenantIsolation);
    assert_eq!(
        expected.as_slice(),
        CONFIGURABLE_STAGES.as_slice(),
        "the chain's stages and this file's have diverged. Tenant isolation is the only stage that \
         is not a service; every other one must be driven by \
         every_stage_that_denies_produces_one_row_that_names_it."
    );
}

/// An audit write failure fails the operation rather than being swallowed.
///
/// `CLAUDE.md` rule 10's other half: an unaudited action must not be treated as having happened.
/// The failure direction matters — an engine that logged the sink error and returned `Ok` would
/// serve the file with nothing recording that it did, which is exactly the silent success the exit
/// criterion forbids.
#[tokio::test]
async fn an_audit_write_failure_refuses_the_operation() {
    /// A sink that cannot write, standing in for a database that is down or a disk that is full.
    #[derive(Debug)]
    struct Failing;

    #[async_trait]
    impl PolicyAuditSink for Failing {
        async fn record_allow(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
            _: &Obligations,
        ) -> Result<()> {
            Err(Error::Internal(anyhow::anyhow!("the audit sink is unavailable")))
        }

        async fn record_deny(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
            _: Stage,
            _: ReasonCode,
        ) -> Result<()> {
            Err(Error::Internal(anyhow::anyhow!("the audit sink is unavailable")))
        }
    }

    let tenant = TenantId::new_v7();
    let ctx = context(tenant);
    let target = resource(tenant);

    let allowing = PolicyEngine::new(
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Failing),
    );
    let error = allowing
        .enforce(&ctx, ACTION, &target)
        .await
        .expect_err("an operation that could not be audited must not be reported as allowed");
    assert!(matches!(error, Error::Internal(_)), "expected the sink failure, got {error:?}");

    // And the same on the denial path, which is the one an incident depends on. A chain that
    // propagated the failure for allows and swallowed it for denials would pass the half above.
    let denying = PolicyEngine::new(
        Arc::new(Configurable::deny(ReasonCode::AccessDenied)),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Configurable::allow()),
        Arc::new(Failing),
    );
    let error = denying
        .enforce(&ctx, ACTION, &target)
        .await
        .expect_err("a denial that could not be audited must still fail");
    assert!(matches!(error, Error::Internal(_)), "expected the sink failure, got {error:?}");
}

/// Every reason code an audit row can carry survives the round trip through the row.
///
/// The other direction of the exit criterion: *every row in the audit table maps to a real
/// enforcement point*. A `ReasonCode` the row could not store, or stored as something else, is a
/// row that names a control that did not take the decision. Driven through the real chain rather
/// than constructed directly, so the assertion covers the path a denial actually takes.
#[tokio::test]
async fn every_reason_code_reaches_the_row_unchanged() {
    for code in ReasonCode::all() {
        let sink = Arc::new(MemoryAuditSink::default());
        let mut stages = [Configurable::allow(); 6];
        stages[1] = Configurable::deny(*code);

        let tenant = TenantId::new_v7();
        let _error = engine(stages, &sink)
            .enforce(&context(tenant), ACTION, &resource(tenant))
            .await
            .expect_err("the stage refused");

        let events = sink.events().expect("read the recorded events");
        assert_eq!(events.len(), 1, "{code}: expected one row");
        assert_eq!(
            events[0].reason_code,
            Some(*code),
            "{code}: the row stored a different reason code, so the auditor would be told the \
             wrong control refused"
        );
    }
}
