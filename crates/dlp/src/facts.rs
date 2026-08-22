//! The [`SecurityFactsProvider`] a running deployment uses — `ENC-594`.
//!
//! `enclave_core::stub::NoSecurityFacts` reports every resource unscanned, which is the honest
//! state of a deployment with no `security_facts` table and is not a state to ship. This reads the
//! table (`migrations/0020_security_facts.sql`) through `enclave-db`'s `TenantScoped` wrapper, and
//! gathers the two properties of the **resource** that travel beside the facts.
//!
//! # What one call gathers, and why it is one call
//!
//! D26 (`plans/M4-GOVERNANCE.md`), and `enclave_core::PolicyEngine` makes it structural: `gather`
//! is called once, before the chain's first stage, and every stage receives the resulting
//! `&FactsSnapshot`. There is no provider on the `DlpService` trait to call a second time. So
//! everything a decision needs about the resource is read here, in **one transaction**, and is
//! therefore as of one instant:
//!
//!   1. the facts the scan left, if any;
//!   2. the label the resource carries — see the gap recorded below;
//!   3. whether anything already reaches outside the tenant over it (`docs/06 §12.1`).
//!
//! Two and three are properties of the resource rather than of the scan, and `ENC-591`/`ENC-588`
//! are what happens when either is asked of the scan instead: the escalation is asked about an
//! unknown value in exactly the case it exists for.
//!
//! # Freshness is settled by `FactsSnapshot::gathered`, not here
//!
//! This type holds the **active** [`DetectorSetVersion`] and hands it to
//! [`FactsSnapshot::gathered`], which answers the freshness question once. It is deliberately not
//! answered here and never as an ordering: the column is an opaque build identifier, and any
//! ordering invented over somebody else's string fails one-directionally — a version that sorts
//! unexpectedly high reads as *fresh*, so stale facts decide a request that believes it saw the
//! current rules (`ENC-581`, and `enclave_core::DetectorSetVersion`).
//!
//! # A read failure is never "no facts"
//!
//! `docs/06 §12.2`: returning `missing` on a database error converts an outage into a policy
//! answer, and under `FAIL_OPEN_AUDIT` that answer is *allow*. Every failure below propagates.
//!
//! # The gap this provider has, recorded rather than left to be discovered
//!
//! [`ResourceState`]'s classification is always `None` today, because `classifications` is created
//! by no migration — there is no table to resolve `files.classification_id` into a rank against,
//! and nothing writes that column either. The consequence is precise and worth stating: D27's
//! mandatory `FAIL_CLOSED` escalation *for `RESTRICTED`* cannot fire in a running deployment, while
//! the external-sharing half of the same rule can, because exposure has a table. It is `ENC-614`,
//! and it is the row whoever lands `classifications` has to close in the same change.

use async_trait::async_trait;
use enclave_core::{
    Action, DetectorSetVersion, Error, Exposure, FactsPolicy, FactsSnapshot, RequestContext,
    ResourceRef, ResourceState, Result, SecurityFactsProvider,
};
use enclave_db::{external_exposure, load_facts, resolve_content, DbPool};

/// Security facts read from PostgreSQL, under the tenant's `facts_unavailable` policy.
///
/// Cheap to clone; the pool is shared. Construct once at start-up, from the same
/// `enclave_config::DlpConfig` the [`crate::DlpMode`] comes from — the mode decides whether a
/// conclusion is acted on and the policy decides what an evaluation without facts *concludes*, and
/// `docs/06 §9.2` is the argument for why those are different questions.
#[derive(Debug, Clone)]
pub struct PgSecurityFacts {
    pool: DbPool,
    active_set: DetectorSetVersion,
    policy: FactsPolicy,
}

impl PgSecurityFacts {
    /// Builds the provider over a pool, the detector set this deployment is running, and the
    /// tenant policy for evaluating without usable facts.
    ///
    /// `active_set` is a value rather than something discovered from the rows: the question a fact
    /// row has to answer is "were you produced by the detectors running *now*", and a set inferred
    /// from the rows themselves would answer "were you produced by the detectors that produced
    /// you". `crate::builtin_set().version()` is what a deployment on the shipped detectors passes.
    #[must_use]
    pub fn new(pool: DbPool, active_set: DetectorSetVersion, policy: FactsPolicy) -> Self {
        Self { pool, active_set, policy }
    }

    /// The detector set fact rows are compared against.
    #[must_use]
    pub const fn active_set(&self) -> &DetectorSetVersion {
        &self.active_set
    }

    /// The tenant policy this provider stamps every snapshot with.
    #[must_use]
    pub const fn policy(&self) -> FactsPolicy {
        self.policy
    }

    /// What the chain sees for a resource that has no content to have facts about.
    ///
    /// Unscanned, internal, unlabelled — and note that this is *not* a permissive answer:
    /// `FactsSnapshot::require` still applies the tenant's policy to it, so under `FAIL_CLOSED` a
    /// rule that governs the action refuses. `enclave_dlp::policy::RuleSet::evaluate` is what stops
    /// that becoming "everything is refused while a scan backlog drains": it settles whether any
    /// rule governs the action *before* it asks for facts (`docs/06 §9.3`).
    fn unscanned(&self) -> FactsSnapshot {
        FactsSnapshot::missing(self.policy, ResourceState::new(Exposure::Internal, None))
    }
}

#[async_trait]
impl SecurityFactsProvider for PgSecurityFacts {
    /// Reads this request's facts, once, under **its own tenant's** row-level-security context.
    ///
    /// The tenant comes from [`RequestContext`], which is built from the verified token or from
    /// custom-domain routing and never from anything the client sent (`CLAUDE.md` rule 3). It is
    /// the argument to `DbPool::begin`, so one tenant's facts are read under that tenant's context
    /// and another tenant's rows are not visible to the statements at all — the second layer behind
    /// the `tenant_id = $1` predicates the statements also carry (`docs/04 §3`).
    ///
    /// `action` is not consulted. It is on the trait so an implementation *may* skip a read for
    /// actions no policy inspects content for, and skipping by action here would be a way for two
    /// actions on one resource to see different facts. What is skipped instead is per **resource**:
    /// a resource with no content resolves to no version without a query at all.
    ///
    /// # Errors
    ///
    /// Any database failure, and any fact row that cannot be decoded. Neither becomes "no facts".
    async fn gather(
        &self,
        ctx: &RequestContext,
        _action: Action,
        resource: &ResourceRef,
    ) -> Result<FactsSnapshot> {
        let mut tx = self.pool.begin(ctx.tenant_id).await.map_err(Error::from)?;

        let resolved =
            resolve_content(&mut tx, resource.kind, resource.id).await.map_err(Error::from)?;

        let Some((file, version)) = resolved else {
            tx.commit().await.map_err(Error::from)?;
            return Ok(self.unscanned());
        };

        // All three reads share one transaction, so the exposure and the facts are as of one
        // instant. A share created between them would otherwise be visible to one and not the
        // other, which is the same class of split view D26 exists to prevent between two stages.
        let facts = load_facts(&mut tx, file, version).await.map_err(Error::from)?;
        let exposure = if external_exposure(&mut tx, file).await.map_err(Error::from)? {
            Exposure::External
        } else {
            Exposure::Internal
        };
        tx.commit().await.map_err(Error::from)?;

        // `ENC-614`: the label is `None` until `classifications` exists. See the module header for
        // what that costs and which escalation it disables.
        let state = ResourceState::new(exposure, None);

        Ok(match facts {
            Some(facts) => FactsSnapshot::gathered(facts, &self.active_set, self.policy, state),
            None => FactsSnapshot::missing(self.policy, state),
        })
    }
}
