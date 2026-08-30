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
use crate::policy::{FactsSnapshot, Obligations, PolicyDecision};

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
    /// Evaluates DLP policy for this action on this resource, against the facts the engine
    /// gathered for it.
    ///
    /// # Why the snapshot is a parameter and not something an implementation fetches
    ///
    /// D26 (`plans/M4-GOVERNANCE.md`). An implementation holding its own reader could observe
    /// *different* facts from the stage before it — a scan completing mid-chain — and the request
    /// would then be decided against two views of one document, with the audit row recording one
    /// of them. Taking the value as an argument is what makes that unwriteable rather than merely
    /// discouraged: there is no provider on this trait to call twice.
    ///
    /// # Errors
    ///
    /// Evaluation failures. When security facts are missing, implementations route through
    /// [`FactsSnapshot::require`] rather than defaulting to allow (`docs/06 §12`).
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> Result<StageDecision>;
}

/// Where the chain's [`FactsSnapshot`] comes from.
///
/// The second port in this module, and it exists for the reason [`PolicyAuditSink`] does: reading
/// `security_facts` is a database concern, `core` owns no I/O, and the dependency has to keep
/// pointing inward.
///
/// **Called exactly once per [`PolicyEngine::enforce`]**, before any stage runs. That is D26 in the
/// one place it can be enforced rather than asserted — a stage receives a `&FactsSnapshot` and has
/// nothing to call a second time.
#[async_trait]
pub trait SecurityFactsProvider: Send + Sync + std::fmt::Debug {
    /// Reads everything the chain will need to know about this resource's content, once.
    ///
    /// `action` is supplied so an implementation can skip the read entirely for actions no policy
    /// inspects content for — a tenant-administration call has no version to have facts about. It
    /// is *not* a licence to vary the answer by action: two actions on one resource in one request
    /// must not see different facts.
    ///
    /// # Errors
    ///
    /// Read failures. A failure is not "no facts": returning [`FactsSnapshot::missing`] on a
    /// database error would convert an outage into a policy answer, and under `FAIL_OPEN_AUDIT`
    /// that answer is *allow*. Propagate instead.
    async fn gather(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<FactsSnapshot>;
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
    facts: std::sync::Arc<dyn SecurityFactsProvider>,
}

impl PolicyEngine {
    /// Assembles the chain.
    ///
    /// Every service is required. There is no builder with optional stages, because a chain with a
    /// stage left out compiles just as happily as one with all of them and fails only in the
    /// situation the stage existed for.
    ///
    /// The facts provider is the exception, and [`Self::with_facts`] says why: unlike a stage, its
    /// default cannot allow anything.
    pub fn new(
        conditional_access: std::sync::Arc<dyn ConditionalAccessService>,
        authorization: std::sync::Arc<dyn AuthorizationService>,
        barriers: std::sync::Arc<dyn BarrierService>,
        classification: std::sync::Arc<dyn ClassificationService>,
        dlp: std::sync::Arc<dyn DlpService>,
        retention: std::sync::Arc<dyn RetentionService>,
        audit: std::sync::Arc<dyn PolicyAuditSink>,
    ) -> Self {
        Self {
            conditional_access,
            authorization,
            barriers,
            classification,
            dlp,
            retention,
            audit,
            facts: std::sync::Arc::new(stub::NoSecurityFacts),
        }
    }

    /// Supplies the reader that gathers [`FactsSnapshot`]s.
    ///
    /// A builder step rather than an eighth constructor argument, and for the same reason
    /// `ApiState::with_edge` is one: the default is safe in the direction that cannot be exploited.
    /// [`stub::NoSecurityFacts`] reports every resource as unscanned under [`FactsPolicy`]'s
    /// fail-closed default, so a deployment that forgets this call runs a DLP stage that refuses
    /// every rule it cannot evaluate rather than one that waves it through.
    ///
    /// [`FactsPolicy`]: crate::policy::FactsPolicy
    #[must_use]
    pub fn with_facts(mut self, facts: std::sync::Arc<dyn SecurityFactsProvider>) -> Self {
        self.facts = facts;
        self
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

        // D26, at the single point it can be structural. Facts enter the request here — once,
        // before any stage runs — and every stage that needs them receives *this* value.
        //
        // Gathering before the first stage rather than just before DLP is deliberate: it makes the
        // fetch point independent of control flow, so no stage can be the first to see facts and
        // no reordering can change which facts a decision was taken against. The cost is a read on
        // a request a later stage will deny, which is the price of a decision that can be
        // reconstructed from its audit row.
        let facts = self.facts.gather(ctx, action, resource).await?;

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
        stage!(Stage::Dlp, self.dlp.evaluate(ctx, action, resource, &facts));
        stage!(Stage::Retention, self.retention.evaluate(ctx, action, resource));

        self.audit.record_allow(ctx, action, resource, &obligations).await?;
        Ok(PolicyDecision::allow(obligations))
    }

    /// The whole chain over a set of resources, in the same order, auditing every one
    /// (`ENC-923`).
    ///
    /// # What this replaces, and why that was a rule-2 defect
    ///
    /// A delete cascade addressed one node and decided the rest with
    /// [`AuthorizationService::authorize_many`] — the ACL stage **on its own**. Barriers,
    /// classification and DLP never ran for a descendant, and no audit row was written for the
    /// allowed ones: a five-hundred-node cascade left a single `file.delete` ALLOW in the log. Rule
    /// 2 says the chain's order is fixed, and a path that runs one stage of it is not a shortened
    /// chain, it is a different one.
    ///
    /// It cost nothing to be wrong for as long as barriers and classification were
    /// `Unconfigured` in every deployment, which is exactly why it needed closing before they are
    /// not. `ENC-961`'s audit reader made the second half visible from outside: an administrator
    /// can now open the log, delete a folder of twenty files, and count one row.
    ///
    /// # Why this is not a loop over [`Self::enforce`]
    ///
    /// Authorization is the stage with a real batch form, and it exists because the ACL read is the
    /// expensive one — `authorize_many` asks once for the whole set. Calling `enforce` in a loop
    /// would give up that batching and issue one ACL round trip per node. Every other stage is
    /// evaluated per resource here exactly as `enforce` evaluates it, in the same order, so this is
    /// the same chain with one stage batched rather than a second chain that resembles it.
    ///
    /// Conditional access is still evaluated per resource even though every implementation in the
    /// tree ignores the `ResourceRef` it is handed. Skipping it on that basis would encode a
    /// property of today's implementations into the engine, and the engine is the one place that
    /// must not assume what a stage does.
    ///
    /// # The first denial ends it
    ///
    /// A cascade is one operation. A partially applied delete — some descendants trashed, one
    /// refused — is a worse outcome than a refusal, so this returns the first denial rather than a
    /// per-resource verdict, and the denial is audited by the stage that raised it exactly as it
    /// would be in [`Self::enforce`]. Callers that want a per-row answer are asking a different
    /// question and want `authorize_many` plus their own trimming, which is what the listings do.
    ///
    /// # Errors
    ///
    /// The first stage denial, as [`Error::denied`]; [`Error::NotFound`] for a cross-tenant
    /// resource (rule 7); or a stage's own failure.
    pub async fn enforce_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> Result<PolicyDecision> {
        // Binds the first resource as well as answering the empty case, so the batch-mismatch
        // branch below has a resource to audit against rather than an `Option` it would have to
        // refuse on. A refusal with nowhere to record it is precisely what `audit-coverage` exists
        // to stop, and this method is on that gate's inline-auditing list on the strength of every
        // refusal path here recording first.
        let Some(first) = resources.first() else {
            return Ok(PolicyDecision::allow(Obligations::none()));
        };

        // Stage 1, per resource and before anything else reads, for the same reason `enforce` does
        // it first: a resource from another tenant must not reach a stage that could disclose it.
        for resource in resources {
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
        }

        let mut obligations = Obligations::none();

        macro_rules! stage_for {
            ($resource:expr, $stage:expr, $call:expr) => {{
                let decision = $call.await?;
                if let StageOutcome::Deny(code) = *decision.outcome() {
                    self.audit.record_deny(ctx, action, $resource, $stage, code).await?;
                    return Err(Error::denied(code));
                }
                obligations.merge(decision.ensure_allowed()?);
            }};
        }

        // Stage 3, per resource. See the note above on why this is not skipped.
        for resource in resources {
            stage_for!(
                resource,
                Stage::ConditionalAccess,
                self.conditional_access.evaluate(ctx, action, resource)
            );
        }

        // Stage 4, batched — the one stage that has a batch form, and the reason this method
        // exists rather than a loop.
        let decisions = self.authorization.authorize_many(ctx, action, resources).await?;
        if decisions.len() != resources.len() {
            // A batch that does not line up with what it was asked about cannot be read
            // positionally, and reading it positionally anyway is how a node nobody decided about
            // gets deleted. The whole operation is refused, and the first resource carries the
            // denial into the log.
            self.audit
                .record_deny(ctx, action, first, Stage::Authorization, ReasonCode::AccessDenied)
                .await?;
            return Err(Error::denied(ReasonCode::AccessDenied));
        }
        for (resource, decision) in resources.iter().zip(decisions) {
            if let StageOutcome::Deny(code) = *decision.outcome() {
                self.audit.record_deny(ctx, action, resource, Stage::Authorization, code).await?;
                return Err(Error::denied(code));
            }
            obligations.merge(decision.ensure_allowed()?);
        }

        // Stages 5 to 8, per resource, in the chain's order.
        for resource in resources {
            let facts = self.facts.gather(ctx, action, resource).await?;
            stage_for!(resource, Stage::Barriers, self.barriers.evaluate(ctx, resource));
            stage_for!(
                resource,
                Stage::Classification,
                self.classification.evaluate(ctx, action, resource)
            );
            stage_for!(resource, Stage::Dlp, self.dlp.evaluate(ctx, action, resource, &facts));
            stage_for!(resource, Stage::Retention, self.retention.evaluate(ctx, action, resource));
        }

        // One row per resource. This is the half of `ENC-923` that was visible from outside: the
        // audit log recorded a cascade as a single event, so the record of a five-hundred-node
        // deletion named one file.
        for resource in resources {
            self.audit.record_allow(ctx, action, resource, &obligations).await?;
        }
        Ok(PolicyDecision::allow(obligations))
    }

    /// Re-runs tenant isolation and **conditional access alone**, for a caller that has a principal
    /// and no resource operation to authorize.
    ///
    /// # The one caller, and why it is not [`Self::enforce`]
    ///
    /// Session refresh (`docs/03-LLD.md §5.3` rule 3, leakage row `K6`). A refresh is not an
    /// operation on a resource: nothing is read, nothing is written, and the stages after this one
    /// have nothing to decide about it. Authorization would be asked whether the caller may `read`
    /// itself, barriers and classification would be asked about a principal rather than a document,
    /// and DLP would be asked to inspect content that does not exist. Answers to questions nobody
    /// asked are not extra safety; they are four more places for a refusal to come from that no
    /// operator could explain.
    ///
    /// What *is* true of a refresh is the second stage: the rules that decide whether this
    /// principal may be reached from this network, on this device, at this authentication strength.
    /// Rule 3 exists because those rules change while a session is alive, and a session that never
    /// re-asks them outlives them by the whole refresh lifetime.
    ///
    /// # Why it lives here rather than in the caller
    ///
    /// `CLAUDE.md` rule 10: audit happens inside the policy engine, for denials as well as allows.
    /// A caller holding [`ConditionalAccessService`] and an audit sink separately could take this
    /// decision and forget to record it — and a refusal nobody can find in `audit_events` is the
    /// defect `crates/api/src/refusal.rs` was written about. Neither collaborator is reachable from
    /// outside this type, so "the refusal is recorded" is a property of the method rather than of a
    /// review.
    ///
    /// It is **not** a fast path around the chain, and it cannot become one: it takes no `Action`
    /// that reads bytes to a useful conclusion, it returns the stage's obligations rather than
    /// discharging them, and `xtask policy-routing` still requires every route handler to reach
    /// [`Self::enforce`]. A handler that called this instead would fail that lint.
    ///
    /// # Errors
    ///
    /// * [`Error::NotFound`] when the resource belongs to another tenant, exactly as
    ///   [`Self::enforce`] answers it.
    /// * [`Error::PolicyDenied`] when conditional access refuses.
    /// * Whatever the stage's own evaluation failed with. **An evaluation failure is not an
    ///   allow.** `TenantConditionalAccess::policies_for` propagates a database failure and a rule
    ///   it cannot decode rather than substituting an empty rule set, so a store that cannot answer
    ///   ends the refresh here instead of granting fourteen more days of session.
    pub async fn reevaluate_conditional_access(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<PolicyDecision> {
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

        let decision = self.conditional_access.evaluate(ctx, action, resource).await?;
        if let StageOutcome::Deny(code) = *decision.outcome() {
            self.audit.record_deny(ctx, action, resource, Stage::ConditionalAccess, code).await?;
            return Err(Error::denied(code));
        }

        let obligations = decision.ensure_allowed()?;
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
        ConditionalAccessService, DlpService, FactsSnapshot, Obligations, PolicyAuditSink,
        ReasonCode, RequestContext, ResourceRef, Result, RetentionService, SecurityFactsProvider,
        Stage, StageDecision,
    };
    use crate::policy::{Exposure, FactsPolicy, ResourceState};

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
            _facts: &FactsSnapshot,
        ) -> Result<StageDecision> {
            Ok(StageDecision::deny(ReasonCode::DlpBlocked))
        }
    }

    /// Reports every resource as unscanned, under the fail-closed default.
    ///
    /// The honest state of a deployment whose `security_facts` rows nothing writes yet, rather than
    /// a stand-in for one: no scanner has run, so no version has facts, and a policy that needs
    /// them cannot be evaluated. What that *means* is then the tenant's `facts_unavailable` policy
    /// to say — and the default it is asked under here is `FAIL_CLOSED`.
    ///
    /// Note which direction the default leans. A provider that answered "facts, all counts zero"
    /// would be the dangerous stub: every DLP rule would evaluate cleanly and permit, and nothing
    /// would report an error. Reporting *absence* makes the same deployment refuse, which is loud.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct NoSecurityFacts;

    #[async_trait]
    impl SecurityFactsProvider for NoSecurityFacts {
        async fn gather(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> Result<FactsSnapshot> {
            Ok(FactsSnapshot::missing(
                FactsPolicy::fail_closed(),
                ResourceState::new(Exposure::Internal, None),
            ))
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

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::stub::DiscardingAuditSink;
    use super::*;
    use crate::action::{FileAction, ResourceKind};
    use crate::id::TenantId;
    use crate::policy::{Exposure, FactsPolicy, FactsStaleness, Obligation, ResourceState};

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
            _: &FactsSnapshot,
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

    /// D26 — facts enter the request once, before any stage, and the DLP stage decides against
    /// *that* value.
    ///
    /// The count is the assertion. A chain where each stage fetched its own would still allow the
    /// same requests and still audit them; what it would lose is the property that the row records
    /// the facts the decision was taken against. That is not observable from the outcome, so it
    /// has to be observed from the call.
    #[tokio::test]
    async fn security_facts_are_gathered_exactly_once_per_request() {
        /// Counts `gather` calls and stamps each snapshot with a distinguishable exposure.
        #[derive(Debug, Default)]
        struct CountingFacts {
            calls: AtomicUsize,
        }

        #[async_trait]
        impl SecurityFactsProvider for CountingFacts {
            async fn gather(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
            ) -> Result<FactsSnapshot> {
                let _previous = self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(FactsSnapshot::missing(
                    FactsPolicy::fail_closed(),
                    ResourceState::new(Exposure::External, None),
                ))
            }
        }

        /// Records what the DLP stage was handed, so "the same value" is checked rather than
        /// assumed.
        #[derive(Debug, Default)]
        struct FactsWatchingDlp {
            seen: Mutex<Vec<Exposure>>,
        }

        #[async_trait]
        impl DlpService for FactsWatchingDlp {
            async fn evaluate(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
                facts: &FactsSnapshot,
            ) -> Result<StageDecision> {
                self.seen.lock().expect("dlp log").push(facts.exposure());
                Ok(StageDecision::allow())
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let provider = Arc::new(CountingFacts::default());
        let dlp = Arc::new(FactsWatchingDlp::default());
        let engine = PolicyEngine::new(
            Spy::allow(Stage::ConditionalAccess, &log),
            Spy::allow(Stage::Authorization, &log),
            Spy::allow(Stage::Barriers, &log),
            Spy::allow(Stage::Classification, &log),
            Arc::clone(&dlp) as Arc<dyn DlpService>,
            Spy::allow(Stage::Retention, &log),
            Arc::new(DiscardingAuditSink),
        )
        .with_facts(Arc::clone(&provider) as Arc<dyn SecurityFactsProvider>);

        let tenant = TenantId::new_v7();
        let decision =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect("allow");
        assert!(decision.obligations().is_empty());

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1, "facts were read more than once");
        assert_eq!(
            *dlp.seen.lock().expect("dlp log"),
            vec![Exposure::External],
            "the DLP stage did not receive the snapshot the engine gathered"
        );

        // A second request reads again — the snapshot is per request, not a cache. Without this
        // the count above would also pass against a provider consulted once per *process*, which
        // would be a decision taken against last week's facts.
        let decision =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect("allow");
        assert!(decision.obligations().is_empty());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    /// A cross-tenant attempt must not read the other tenant's facts on its way to `404`.
    #[tokio::test]
    async fn a_cross_tenant_attempt_never_reaches_the_facts_reader() {
        #[derive(Debug)]
        struct NeverCalled;

        #[async_trait]
        impl SecurityFactsProvider for NeverCalled {
            async fn gather(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
            ) -> Result<FactsSnapshot> {
                panic!("facts were read for a resource in another tenant")
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let engine = all_allow(&log, Arc::new(DiscardingAuditSink))
            .with_facts(Arc::new(NeverCalled) as Arc<dyn SecurityFactsProvider>);

        let error = engine
            .enforce(&ctx(TenantId::new_v7()), ACTION, &resource(TenantId::new_v7()))
            .await
            .expect_err("must refuse");
        assert!(matches!(error, Error::NotFound), "{error:?}");
    }

    /// A facts read that *failed* is not a facts read that found nothing.
    ///
    /// Collapsing the two would turn a database outage into a policy answer — and under
    /// `FAIL_OPEN_AUDIT` that answer is *allow*, which is an outage that silently disables DLP.
    #[tokio::test]
    async fn a_facts_read_failure_is_propagated_rather_than_read_as_no_facts() {
        #[derive(Debug)]
        struct Broken;

        #[async_trait]
        impl SecurityFactsProvider for Broken {
            async fn gather(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
            ) -> Result<FactsSnapshot> {
                Err(Error::Upstream {
                    dependency: crate::error::Dependency::Postgres,
                    retryable: true,
                })
            }
        }

        let log = Arc::new(Mutex::new(Vec::new()));
        let audit = Arc::new(RecordingAudit::default());
        let engine = all_allow(&log, Arc::clone(&audit) as Arc<dyn PolicyAuditSink>)
            .with_facts(Arc::new(Broken) as Arc<dyn SecurityFactsProvider>);

        let tenant = TenantId::new_v7();
        let error =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect_err("must fail");
        assert!(matches!(error, Error::Upstream { .. }), "rewritten: {error:?}");
        assert!(log.lock().expect("log").is_empty(), "a stage ran on facts that could not be read");
        assert!(audit.denials.lock().expect("audit").is_empty(), "a failure was audited as a deny");
        assert!(
            audit.allows.lock().expect("audit").is_empty(),
            "a failure was audited as an allow"
        );
    }

    /// The default provider fails closed rather than reporting a clean document.
    #[tokio::test]
    async fn an_engine_built_without_a_facts_reader_reports_the_resource_as_unscanned() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));

        #[derive(Debug)]
        struct Recording(Arc<Mutex<Vec<FactsStaleness>>>);

        #[async_trait]
        impl DlpService for Recording {
            async fn evaluate(
                &self,
                _: &RequestContext,
                _: Action,
                _: &ResourceRef,
                facts: &FactsSnapshot,
            ) -> Result<StageDecision> {
                self.0.lock().expect("log").push(facts.staleness());
                Ok(StageDecision::allow())
            }
        }

        let engine = PolicyEngine::new(
            Spy::allow(Stage::ConditionalAccess, &log),
            Spy::allow(Stage::Authorization, &log),
            Spy::allow(Stage::Barriers, &log),
            Spy::allow(Stage::Classification, &log),
            Arc::new(Recording(Arc::clone(&seen))),
            Spy::allow(Stage::Retention, &log),
            Arc::new(DiscardingAuditSink),
        );

        let tenant = TenantId::new_v7();
        let decision =
            engine.enforce(&ctx(tenant), ACTION, &resource(tenant)).await.expect("allow");
        assert!(decision.obligations().is_empty());
        assert_eq!(*seen.lock().expect("log"), vec![FactsStaleness::Missing]);
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
