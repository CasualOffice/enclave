//! The policy chain — one implementation, called by every entry point.
//!
//! `docs/02-HLD.md §14` names the canonical order and `docs/03-LLD.md §12` specifies this type.
//! `CLAUDE.md` rule 1 forbids anything from going around it. This module is what those three
//! documents are describing.
//!
//! # Why it lives in `core`
//!
//! The engine is composition and nothing else: it holds six trait objects and calls them in a fixed
//! order. It needs no concrete policy implementation, so it introduces no dependency on the crates
//! that provide them, and putting it here means `api`, `worker`, `scheduler` and `mcp` all reach the
//! same code rather than each growing a variant of it.
//!
//! Auditing is the one thing the engine needs that `core` cannot own — `enclave-audit` depends on
//! `core`, so `core` depending back would be a cycle. [`PolicyAuditSink`] is the narrow port that
//! resolves it: the engine calls it, the audit crate implements it, and the dependency still points
//! inward.
//!
//! # The shape of a stage
//!
//! Every stage returns the same [`StageDecision`]. That uniformity is deliberate. A chain where each
//! stage has a bespoke decision type invites bespoke handling, and bespoke handling is where a stage
//! quietly stops being able to deny anything.
//!
//! # What the engine does not do
//!
//! It does not *apply* obligations. It returns them, and the caller satisfies them or fails
//! ([`crate::policy::PolicyDecision`] is `#[must_use]`). Watermarking a rendition is the preview
//! path's job; the engine's job is to say that a watermark is required and to make that
//! impossible to ignore silently.

use async_trait::async_trait;

use crate::action::{Action, ResourceRef};
use crate::context::RequestContext;
use crate::error::{Error, ReasonCode, Result};
use crate::policy::{Obligations, PolicyDecision};

/// What a single stage concluded.
///
/// `Deny` carries a [`ReasonCode`] and nothing else, for the reason given in
/// [`crate::error`]: there is no field in which internal reasoning could be leaked to a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The stage permits the action, subject to any obligations it attached.
    Allow,
    /// The stage refuses. The code is what the caller may be told.
    Deny(ReasonCode),
}

/// One stage's decision.
///
/// `#[must_use]` because a decision that is computed and dropped is a control that ran and was
/// ignored, which is indistinguishable from not running it at all — except that it costs latency.
#[must_use = "a stage decision must be consumed; dropping it skips the control it represents"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageDecision {
    outcome: StageOutcome,
    obligations: Obligations,
}

impl StageDecision {
    /// Permit, with nothing further required.
    pub fn allow() -> Self {
        Self { outcome: StageOutcome::Allow, obligations: Obligations::none() }
    }

    /// Permit, but only if the caller satisfies these obligations.
    pub fn allow_with(obligations: Obligations) -> Self {
        Self { outcome: StageOutcome::Allow, obligations }
    }

    /// Refuse, with the code the caller may be shown.
    pub fn deny(code: ReasonCode) -> Self {
        Self { outcome: StageOutcome::Deny(code), obligations: Obligations::none() }
    }

    /// The outcome, for inspection by tests and by the engine.
    pub const fn outcome(&self) -> &StageOutcome {
        &self.outcome
    }

    /// Whether this stage permitted the action.
    pub const fn is_allowed(&self) -> bool {
        matches!(self.outcome, StageOutcome::Allow)
    }

    /// Consumes the decision, yielding its obligations or the denial.
    ///
    /// # Errors
    ///
    /// [`Error::PolicyDenied`] when the stage refused.
    pub fn ensure_allowed(self) -> Result<Obligations> {
        match self.outcome {
            StageOutcome::Allow => Ok(self.obligations),
            StageOutcome::Deny(code) => Err(Error::denied(code)),
        }
    }
}

/// Network, device, authentication-strength and time/risk policy.
///
/// Evaluated **before** authorization, so that a caller on a blocked network learns nothing about
/// whether the resource exists (`docs/03-LLD.md §12`).
#[async_trait]
pub trait ConditionalAccessService: Send + Sync + std::fmt::Debug {
    /// Evaluates conditional access for one action on one resource.
    ///
    /// # Errors
    ///
    /// Evaluation failures. A failure is not a denial — the engine propagates it, and a caller that
    /// cannot evaluate policy must not proceed as though it had.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision>;
}

/// RBAC and ACL resolution.
#[async_trait]
pub trait AuthorizationService: Send + Sync + std::fmt::Debug {
    /// Resolves the caller's effective permission for one action on one resource.
    ///
    /// # Errors
    ///
    /// Resolution failures.
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision>;

    /// Batch form, required by the search post-filter (`docs/07-SEARCH-INDEXING.md §6.2`).
    ///
    /// Present on the trait rather than left to implementations because a per-hit loop over a
    /// hundred candidates is the difference between a search that meets its latency budget and one
    /// that does not, and the post-filter is not optional.
    ///
    /// # Errors
    ///
    /// Resolution failures.
    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> Result<Vec<StageDecision>>;

    /// Several actions across several resources, in one resolution.
    ///
    /// Returns one row per action, index-aligned with `actions`, each row index-aligned with
    /// `resources`.
    ///
    /// # Why this is on the trait, and why it is defaulted
    ///
    /// A listing page asks the same question about one page of files nine or ten times over — once
    /// per capability the response advertises — and `authorize_many` batches *resources*, not
    /// actions. `ENC-167` measured what that costs: ten actions over 200 candidates take **8.1 ms**
    /// in one pass and **68.5 ms** in ten, because resolution's price is transaction setup plus
    /// three round trips rather than the size of the batch. Sixty milliseconds per page is not a
    /// micro-optimisation on a budget of 300 ms for metadata (`docs/03 §23`).
    ///
    /// The default body loops [`Self::authorize_many`], so every stub, test double and
    /// not-yet-configured implementation keeps working unchanged and answers identically — it is
    /// only slower. An implementation that can do better overrides it. Adding it as a *required*
    /// method would have made a performance improvement a breaking change for six deny-by-default
    /// stages that have no use for it.
    ///
    /// # Errors
    ///
    /// Resolution failures.
    async fn authorize_many_actions(
        &self,
        ctx: &RequestContext,
        actions: &[Action],
        resources: &[ResourceRef],
    ) -> Result<Vec<Vec<StageDecision>>> {
        let mut rows = Vec::with_capacity(actions.len());
        for action in actions {
            rows.push(self.authorize_many(ctx, *action, resources).await?);
        }
        Ok(rows)
    }
}

/// Mandatory segmentation that overrides ordinary ACLs.
#[async_trait]
pub trait BarrierService: Send + Sync + std::fmt::Debug {
    /// Evaluates information barriers between the caller and the resource.
    ///
    /// # Errors
    ///
    /// Evaluation failures.
    async fn evaluate(&self, ctx: &RequestContext, resource: &ResourceRef)
        -> Result<StageDecision>;

    /// The barrier tokens this caller may see, for building search filters.
    ///
    /// # Errors
    ///
    /// Resolution failures.
    async fn allowed_barrier_tokens(&self, ctx: &RequestContext) -> Result<Vec<String>>;
}

/// Classification ceilings and label-driven restrictions.
#[async_trait]
pub trait ClassificationService: Send + Sync + std::fmt::Debug {
    /// Evaluates the resource's label against the caller's ceiling and the action.
    ///
    /// # Errors
    ///
    /// Evaluation failures.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision>;
}

/// Data-loss prevention.
#[async_trait]
pub trait DlpService: Send + Sync + std::fmt::Debug {
    /// Evaluates DLP policy for this action on this resource.
    ///
    /// # Errors
    ///
    /// Evaluation failures. When security facts are missing, implementations follow the tenant's
    /// `facts_unavailable` setting rather than defaulting to allow (`docs/06 §12`).
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision>;
}

/// Retention, records and legal hold.
#[async_trait]
pub trait RetentionService: Send + Sync + std::fmt::Debug {
    /// Evaluates whether retention state permits this action.
    ///
    /// Last in the chain deliberately: a caller who lacks permission is told they lack permission,
    /// rather than learning that a matter-specific legal hold exists (`docs/06 §15`).
    ///
    /// # Errors
    ///
    /// Evaluation failures.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision>;
}

/// The engine's audit port.
///
/// Narrow on purpose. `enclave-audit` owns the record format, the hash chain and the sinks; the
/// engine needs only to say "this happened". Keeping the surface this small is what lets the
/// dependency point inward.
#[async_trait]
pub trait PolicyAuditSink: Send + Sync + std::fmt::Debug {
    /// Records an allowed action and the obligations its decision carried.
    ///
    /// # Errors
    ///
    /// Persistence failures. Callers must not swallow them: an unaudited action is an action that
    /// must not be treated as having happened (`CLAUDE.md` rule 10).
    async fn record_allow(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        obligations: &Obligations,
    ) -> Result<()>;

    /// Records a denial, including the stage that produced it.
    ///
    /// # Errors
    ///
    /// Persistence failures.
    async fn record_deny(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        stage: Stage,
        code: ReasonCode,
    ) -> Result<()>;
}

/// The stages, in canonical order.
///
/// Named so a denial can be attributed in audit without the caller ever seeing which stage refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    /// Tenant isolation — asserted by the engine itself.
    TenantIsolation,
    /// Network, device, authentication strength.
    ConditionalAccess,
    /// RBAC and ACL.
    Authorization,
    /// Information barriers.
    Barriers,
    /// Classification ceilings.
    Classification,
    /// Data-loss prevention.
    Dlp,
    /// Retention, records, legal hold.
    Retention,
}

impl Stage {
    /// The canonical order, for tests that assert the chain has not been reordered.
    pub const ORDER: [Self; 7] = [
        Self::TenantIsolation,
        Self::ConditionalAccess,
        Self::Authorization,
        Self::Barriers,
        Self::Classification,
        Self::Dlp,
        Self::Retention,
    ];

    /// A stable name for audit and tracing.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantIsolation => "tenant_isolation",
            Self::ConditionalAccess => "conditional_access",
            Self::Authorization => "authorization",
            Self::Barriers => "barriers",
            Self::Classification => "classification",
            Self::Dlp => "dlp",
            Self::Retention => "retention",
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The policy chain.
///
/// Construct once at start-up and share. Every entry point calls [`PolicyEngine::enforce`].
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    conditional_access: std::sync::Arc<dyn ConditionalAccessService>,
    authorization: std::sync::Arc<dyn AuthorizationService>,
    barriers: std::sync::Arc<dyn BarrierService>,
    classification: std::sync::Arc<dyn ClassificationService>,
    dlp: std::sync::Arc<dyn DlpService>,
    retention: std::sync::Arc<dyn RetentionService>,
    audit: std::sync::Arc<dyn PolicyAuditSink>,
}

impl PolicyEngine {
    /// Assembles the chain.
    ///
    /// Every service is required. There is no builder with optional stages, because a chain with a
    /// stage left out compiles just as happily as one with all of them and fails only in the
    /// situation the stage existed for.
    pub fn new(
        conditional_access: std::sync::Arc<dyn ConditionalAccessService>,
        authorization: std::sync::Arc<dyn AuthorizationService>,
        barriers: std::sync::Arc<dyn BarrierService>,
        classification: std::sync::Arc<dyn ClassificationService>,
        dlp: std::sync::Arc<dyn DlpService>,
        retention: std::sync::Arc<dyn RetentionService>,
        audit: std::sync::Arc<dyn PolicyAuditSink>,
    ) -> Self {
        Self { conditional_access, authorization, barriers, classification, dlp, retention, audit }
    }

    /// The authorization stage this engine will actually consult.
    ///
    /// Exposed for exactly one purpose: computing the `capabilities` object of `docs/05-API.md §7`.
    /// That object promises the caller that the actions it offers are the ones the server will
    /// permit, and the only way to keep that promise is to ask *this* engine's resolver rather than
    /// a second one constructed alongside it — two resolvers over the same rows are a parallel
    /// implementation, and a parallel implementation is a UI that eventually disagrees with the
    /// server about what a user may do.
    ///
    /// It is a read-only handle to one stage, not a way around the chain: it cannot allow anything,
    /// it writes no audit row, and a handler that used it *instead of* [`PolicyEngine::enforce`]
    /// fails the ENC-110 policy-routing lint. A capabilities probe is a hint; the enforcement is
    /// still the chain, run when the action is actually attempted.
    ///
    /// The batch form ([`AuthorizationService::authorize_many`]) is what callers should use — a
    /// listing resolves every child in one query rather than one per row.
    #[must_use]
    pub fn authorization(&self) -> &std::sync::Arc<dyn AuthorizationService> {
        &self.authorization
    }

    /// Runs the canonical chain for one action on one resource.
    ///
    /// Stages run in the order in [`Stage::ORDER`] and short-circuit on the first denial. Every
    /// outcome — allow or deny — is audited before this returns, so no path can succeed unaudited.
    ///
    /// # Errors
    ///
    /// * [`Error::NotFound`] when the resource belongs to another tenant. Deliberately
    ///   indistinguishable from genuine absence: a `403` would confirm the resource exists
    ///   (`docs/06 §24`).
    /// * [`Error::PolicyDenied`] when a stage refuses.
    /// * Whatever a stage's own evaluation failed with. An evaluation failure is not a denial and
    ///   is not converted into one.
    pub async fn enforce(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<PolicyDecision> {
        // Stage 1. Not delegated to a service: tenant isolation is an invariant of the request, and
        // a service that could be swapped out is a service that could be swapped for one that says
        // yes. The database enforces it independently via RLS (`docs/04 §3`); this is the first of
        // the two layers, not the only one.
        if ctx.tenant_id != resource.tenant_id {
            self.audit
                .record_deny(
                    ctx,
                    action,
                    resource,
                    Stage::TenantIsolation,
                    ReasonCode::AccessDenied,
                )
                .await?;
            return Err(Error::NotFound);
        }

        let mut obligations = Obligations::none();

        macro_rules! stage {
            ($stage:expr, $call:expr) => {{
                let decision = $call.await?;
                if let StageOutcome::Deny(code) = *decision.outcome() {
                    self.audit.record_deny(ctx, action, resource, $stage, code).await?;
                    return Err(Error::denied(code));
                }
                obligations.merge(decision.ensure_allowed()?);
            }};
        }

        stage!(Stage::ConditionalAccess, self.conditional_access.evaluate(ctx, action, resource));
        stage!(Stage::Authorization, self.authorization.authorize(ctx, action, resource));
        stage!(Stage::Barriers, self.barriers.evaluate(ctx, resource));
        stage!(Stage::Classification, self.classification.evaluate(ctx, action, resource));
        stage!(Stage::Dlp, self.dlp.evaluate(ctx, action, resource));
        stage!(Stage::Retention, self.retention.evaluate(ctx, action, resource));

        self.audit.record_allow(ctx, action, resource, &obligations).await?;
        Ok(PolicyDecision::allow(obligations))
    }
}

/// Deny-by-default implementations, used until each real service lands.
///
/// Every method refuses. A stub that allowed would disable the chain silently and nothing would
/// notice until a security test was written months later — so the placeholder fails closed, which
/// is loud, immediate, and impossible to ship by accident (`plans/M0-FOUNDATIONS.md` D8).
pub mod stub {
    use super::{
        async_trait, Action, AuthorizationService, BarrierService, ClassificationService,
        ConditionalAccessService, DlpService, Obligations, PolicyAuditSink, ReasonCode,
        RequestContext, ResourceRef, Result, RetentionService, Stage, StageDecision,
    };

    /// Refuses everything, for every stage.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DenyAll;

    #[async_trait]
    impl ConditionalAccessService for DenyAll {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::AccessDenied))
        }
    }

    #[async_trait]
    impl AuthorizationService for DenyAll {
        async fn authorize(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::AccessDenied))
        }

        async fn authorize_many(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            resources: &[ResourceRef],
        ) -> Result<Vec<StageDecision>> {
            Ok(resources.iter().map(|_| StageDecision::deny(ReasonCode::AccessDenied)).collect())
        }
    }

    #[async_trait]
    impl BarrierService for DenyAll {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::AccessDenied))
        }

        async fn allowed_barrier_tokens(&self, _ctx: &RequestContext) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl ClassificationService for DenyAll {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::ClassificationCeiling))
        }
    }

    #[async_trait]
    impl DlpService for DenyAll {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::DlpBlocked))
        }
    }

    #[async_trait]
    impl RetentionService for DenyAll {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::RetentionBlocksDelete))
        }
    }

    /// Discards audit events.
    ///
    /// For tests and for the deny-all wiring only. Any binary that reaches production with this
    /// installed is violating `CLAUDE.md` rule 10, which is why it is named the way it is.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DiscardingAuditSink;

    #[async_trait]
    impl PolicyAuditSink for DiscardingAuditSink {
        async fn record_allow(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
            _obligations: &Obligations,
        ) -> Result<()> {
            Ok(())
        }

        async fn record_deny(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
            _stage: Stage,
            _code: ReasonCode,
        ) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::{Arc, Mutex};

    use super::stub::DiscardingAuditSink;
    use super::*;
    use crate::action::{FileAction, ResourceKind};
    use crate::id::TenantId;
    use crate::policy::Obligation;

    /// A stage that records that it ran, then returns whatever it was told to.
    #[derive(Debug, Clone)]
    struct Spy {
        stage: Stage,
        log: Arc<Mutex<Vec<Stage>>>,
        verdict: StageOutcome,
        obligation: Option<Obligation>,
    }

    impl Spy {
        fn allow(stage: Stage, log: &Arc<Mutex<Vec<Stage>>>) -> Arc<Self> {
            Arc::new(Self {
                stage,
                log: Arc::clone(log),
                verdict: StageOutcome::Allow,
                obligation: None,
            })
        }

        fn allow_with(stage: Stage, log: &Arc<Mutex<Vec<Stage>>>, o: Obligation) -> Arc<Self> {
            Arc::new(Self {
                stage,
                log: Arc::clone(log),
                verdict: StageOutcome::Allow,
                obligation: Some(o),
            })
        }

        fn deny(stage: Stage, log: &Arc<Mutex<Vec<Stage>>>, code: ReasonCode) -> Arc<Self> {
            Arc::new(Self {
                stage,
                log: Arc::clone(log),
                verdict: StageOutcome::Deny(code),
                obligation: None,
            })
        }

        fn run(&self) -> StageDecision {
            self.log.lock().expect("spy log").push(self.stage);
            match self.verdict {
                StageOutcome::Deny(code) => StageDecision::deny(code),
                StageOutcome::Allow => match self.obligation {
                    Some(o) => StageDecision::allow_with(std::iter::once(o).collect()),
                    None => StageDecision::allow(),
                },
            }
        }
    }

    #[async_trait]
    impl ConditionalAccessService for Spy {
        async fn evaluate(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(self.run())
        }
    }

    #[async_trait]
    impl AuthorizationService for Spy {
        async fn authorize(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(self.run())
        }
        async fn authorize_many(
            &self,
            _: &RequestContext,
            _: Action,
            r: &[ResourceRef],
        ) -> Result<Vec<StageDecision>> {
            Ok(r.iter().map(|_| self.run()).collect())
        }
    }

    #[async_trait]
    impl BarrierService for Spy {
        async fn evaluate(&self, _: &RequestContext, _: &ResourceRef) -> Result<StageDecision> {
            Ok(self.run())
        }
        async fn allowed_barrier_tokens(&self, _: &RequestContext) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl ClassificationService for Spy {
        async fn evaluate(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(self.run())
        }
    }

    #[async_trait]
    impl DlpService for Spy {
        async fn evaluate(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(self.run())
        }
    }

    #[async_trait]
    impl RetentionService for Spy {
        async fn evaluate(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
        ) -> Result<StageDecision> {
            Ok(self.run())
        }
    }

    /// Records what was audited, so "every outcome is audited" is testable rather than asserted.
    #[derive(Debug, Default)]
    struct RecordingAudit {
        allows: Mutex<Vec<Obligations>>,
        denials: Mutex<Vec<(Stage, ReasonCode)>>,
    }

    #[async_trait]
    impl PolicyAuditSink for RecordingAudit {
        async fn record_allow(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
            o: &Obligations,
        ) -> Result<()> {
            self.allows.lock().expect("audit log").push(o.clone());
            Ok(())
        }
        async fn record_deny(
            &self,
            _: &RequestContext,
            _: Action,
            _: &ResourceRef,
            s: Stage,
            c: ReasonCode,
        ) -> Result<()> {
            self.denials.lock().expect("audit log").push((s, c));
            Ok(())
        }
    }

    fn ctx(tenant: TenantId) -> RequestContext {
        RequestContext::system(tenant)
    }

    fn resource(tenant: TenantId) -> ResourceRef {
        ResourceRef::new(tenant, ResourceKind::File, uuid::Uuid::nil())
    }

    const ACTION: Action = Action::File(FileAction::Download);

    /// Builds an engine whose stages all allow, with a shared call log.
    fn all_allow(log: &Arc<Mutex<Vec<Stage>>>, audit: Arc<dyn PolicyAuditSink>) -> PolicyEngine {
        PolicyEngine::new(
            Spy::allow(Stage::ConditionalAccess, log),
            Spy::allow(Stage::Authorization, log),
            Spy::allow(Stage::Barriers, log),
            Spy::allow(Stage::Classification, log),
            Spy::allow(Stage::Dlp, log),
            Spy::allow(Stage::Retention, log),
            audit,
        )
    }

    #[tokio::test]
    async fn the_chain_runs_every_stage_in_the_canonical_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let engine = all_allow(&log, Arc::new(DiscardingAuditSink));
        let tenant = TenantId::new_v7();

        // Bound rather than dropped: PolicyDecision is #[must_use], and a test that discards one
        // would be modelling exactly the mistake the attribute exists to prevent.
        let decision =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect("allow");
        assert!(decision.obligations().is_empty(), "no stub attached an obligation");

        // Tenant isolation is asserted by the engine itself and never reaches a spy, so the
        // expected order is Stage::ORDER minus its first element.
        let expected: Vec<Stage> = Stage::ORDER.into_iter().skip(1).collect();
        assert_eq!(*log.lock().expect("log"), expected, "the chain ran out of order");
    }

    #[tokio::test]
    async fn a_denial_short_circuits_and_no_later_stage_runs() {
        // Every stage in turn is made to deny; the stages after it must never be reached. A chain
        // that keeps evaluating after a denial is one where a later stage could overwrite it.
        let stages = [
            Stage::ConditionalAccess,
            Stage::Authorization,
            Stage::Barriers,
            Stage::Classification,
            Stage::Dlp,
            Stage::Retention,
        ];

        for (index, denier) in stages.iter().enumerate() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let audit = Arc::new(RecordingAudit::default());
            let mk = |s: Stage| -> Arc<Spy> {
                if s == *denier {
                    Spy::deny(s, &log, ReasonCode::AccessDenied)
                } else {
                    Spy::allow(s, &log)
                }
            };
            let engine = PolicyEngine::new(
                mk(Stage::ConditionalAccess),
                mk(Stage::Authorization),
                mk(Stage::Barriers),
                mk(Stage::Classification),
                mk(Stage::Dlp),
                mk(Stage::Retention),
                Arc::clone(&audit) as Arc<dyn PolicyAuditSink>,
            );

            let tenant = TenantId::new_v7();
            let error = engine
                .enforce(&ctx(tenant), ACTION, &resource(tenant))
                .await
                .expect_err("must deny");
            assert!(matches!(error, Error::PolicyDenied { .. }), "{denier}: {error:?}");

            let ran = log.lock().expect("log").clone();
            assert_eq!(ran, stages[..=index], "{denier}: wrong stages ran");

            let denials = audit.denials.lock().expect("audit").clone();
            assert_eq!(denials, vec![(*denier, ReasonCode::AccessDenied)], "{denier}: not audited");
            assert!(audit.allows.lock().expect("audit").is_empty(), "{denier}: audited an allow");
        }
    }

    #[tokio::test]
    async fn a_cross_tenant_resource_is_not_found_rather_than_forbidden() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let audit = Arc::new(RecordingAudit::default());
        let engine = all_allow(&log, Arc::clone(&audit) as Arc<dyn PolicyAuditSink>);

        let caller = TenantId::new_v7();
        let other = TenantId::new_v7();
        let error =
            engine.enforce(&ctx(caller), ACTION, &resource(other)).await.expect_err("must refuse");

        // A 403 would confirm the resource exists in another tenant (docs/06 §24, test T1).
        assert!(matches!(error, Error::NotFound), "expected NotFound, got {error:?}");
        assert!(log.lock().expect("log").is_empty(), "a stage ran despite the tenant mismatch");
        assert_eq!(
            audit.denials.lock().expect("audit").first().map(|(s, _)| *s),
            Some(Stage::TenantIsolation),
            "the cross-tenant attempt was not audited"
        );
    }

    #[tokio::test]
    async fn obligations_from_every_stage_reach_the_caller() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let audit = Arc::new(RecordingAudit::default());
        let engine = PolicyEngine::new(
            Spy::allow_with(Stage::ConditionalAccess, &log, Obligation::NoDownload),
            Spy::allow(Stage::Authorization, &log),
            Spy::allow(Stage::Barriers, &log),
            Spy::allow_with(Stage::Classification, &log, Obligation::Watermark),
            Spy::allow_with(Stage::Dlp, &log, Obligation::RequireJustification),
            Spy::allow(Stage::Retention, &log),
            Arc::clone(&audit) as Arc<dyn PolicyAuditSink>,
        );

        let tenant = TenantId::new_v7();
        let decision =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect("allow");

        let obligations = decision.obligations();
        for expected in
            [Obligation::NoDownload, Obligation::Watermark, Obligation::RequireJustification]
        {
            assert!(obligations.contains(&expected), "{expected:?} was dropped by the engine");
        }

        // And the audit record carries them too — an allow that quietly shed its obligations would
        // otherwise be indistinguishable in the log from an unconditional one.
        let audited = audit.allows.lock().expect("audit").clone();
        assert_eq!(audited.len(), 1);
        assert_eq!(audited[0], *obligations);
    }

    #[tokio::test]
    async fn an_evaluation_failure_is_not_silently_converted_into_a_denial() {
        // A stage that cannot evaluate is not a stage that said no. Collapsing the two would let a
        // database outage read as "access denied" and hide an incident behind a plausible message.
        #[derive(Debug)]
        struct Broken;

        #[async_trait]
        impl ConditionalAccessService for Broken {
            async fn evaluate(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
            ) -> Result<StageDecision> {
                Err(Error::NotFound)
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let audit = Arc::new(RecordingAudit::default());
        let engine = PolicyEngine::new(
            Arc::new(Broken),
            Spy::allow(Stage::Authorization, &log),
            Spy::allow(Stage::Barriers, &log),
            Spy::allow(Stage::Classification, &log),
            Spy::allow(Stage::Dlp, &log),
            Spy::allow(Stage::Retention, &log),
            Arc::clone(&audit) as Arc<dyn PolicyAuditSink>,
        );

        let tenant = TenantId::new_v7();
        let error =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect_err("must fail");
        assert!(matches!(error, Error::NotFound), "evaluation failure was rewritten: {error:?}");
        assert!(
            audit.denials.lock().expect("audit").is_empty(),
            "a failure was audited as a denial"
        );
    }

    #[tokio::test]
    async fn the_default_stubs_refuse_everything() {
        // plans/M0-FOUNDATIONS.md D8. If this test ever fails, a placeholder has started saying yes.
        let engine = PolicyEngine::new(
            Arc::new(stub::DenyAll),
            Arc::new(stub::DenyAll),
            Arc::new(stub::DenyAll),
            Arc::new(stub::DenyAll),
            Arc::new(stub::DenyAll),
            Arc::new(stub::DenyAll),
            Arc::new(DiscardingAuditSink),
        );

        let tenant = TenantId::new_v7();
        let error =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect_err("must deny");
        assert!(matches!(error, Error::PolicyDenied { .. }), "{error:?}");
    }

    #[test]
    fn the_canonical_order_matches_the_specification() {
        // docs/02-HLD.md §14. If someone reorders the enum, this fails before the chain does.
        let names: Vec<&str> = Stage::ORDER.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            names,
            [
                "tenant_isolation",
                "conditional_access",
                "authorization",
                "barriers",
                "classification",
                "dlp",
                "retention",
            ]
        );
    }
}
