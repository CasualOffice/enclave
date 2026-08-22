//! Conditional access decided from a tenant's **stored** rules — `ENC-590`.
//!
//! [`crate::ConfiguredConditionalAccess`] holds one [`PolicySet`] and serves every tenant from it.
//! That is right for a policy an operator writes in `enclave.yaml` and wrong for a rule, because a
//! rule is tenant data: `docs/06 §7` has an administrator writing rules against their own tenant,
//! and one `enclave.yaml` serves every tenant on a host. This type reads each tenant's rules from
//! `conditional_access_rules` instead.
//!
//! Zone *definitions* stay in configuration, where `ENC-583` put them, and are shared by every
//! tenant on the host. A zone names the deployment's networks — "Datacenter", "VPN" — which is an
//! operator's fact. It is also the fact `crates/api/src/edge.rs` resolves `NetworkContext::zones`
//! from, before any tenant is known, so a per-tenant zone map would be resolved after the zones had
//! already been computed.
//!
//! # Caching, and the staleness that would be a defect rather than a slow path
//!
//! This stage runs on **every** request in the chain, so the rules are read on every request. A
//! query per request is a round trip and a pool checkout in front of every operation the product
//! performs, before authorization has even run.
//!
//! So the rule set is cached per tenant, for [`DEFAULT_CACHE_TTL`], and the direction of the risk
//! decides everything about how:
//!
//! * **A stale rule set is permissive, not restrictive.** There is no `ALLOW` effect
//!   (`docs/06 §7.4`), so every rule this stage holds *denies* or *constrains*. A cache that has
//!   missed the newest rule therefore allows something the administrator has forbidden — and an
//!   administrator tightening a rule during an incident is precisely the case that must not wait.
//!   That is why the staleness is **bounded and short** rather than "until something evicts it".
//! * **The bound is a time, not an invalidation message.** [`TenantConditionalAccess::invalidate`]
//!   exists and the admin write path should call it, but it can only reach the process it runs in.
//!   A deployment is several replicas; an invalidation that is only sometimes delivered is worse
//!   than one that is never delivered, because it is not something an operator can reason about.
//!   The TTL holds on every replica whether or not any message arrives, and
//!   [`TenantConditionalAccess::cache_ttl`] is the number to quote when asked how long a tightening
//!   takes to apply everywhere.
//! * **A failure to load is never an empty rule set.** [`TenantConditionalAccess::policies_for`]
//!   returns the error, and the request fails. Falling back to "no rules" on a database blip would
//!   turn an outage into an open door, silently, at exactly the moment nobody is reading logs.
//!   For the same reason, a rule that cannot be decoded fails the whole set rather than being
//!   skipped (`crate::store::decode_rules`).
//!
//! A `Duration::ZERO` TTL disables caching entirely — every request loads. It exists because it is
//! the honest way to test that the cache is what makes the difference, and because a deployment
//! that would rather pay the round trip should be able to say so.

use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use enclave_core::{
    Action, ConditionalAccessService, RequestContext, ResourceRef, Result, StageDecision, TenantId,
};
use enclave_db::{load_rules, DbPool};

use crate::policy::{BreakGlass, PolicySet};
use crate::store::{decode_rules, Rule};
use crate::zone::ZoneMap;

/// How long a tenant's rules are reused before being read again.
///
/// Fifteen seconds, and the number is chosen from the failure it bounds rather than from a cache
/// hit rate: an administrator who tightens a rule and then checks whether it applied must find that
/// it did. Fifteen seconds is shorter than the round trip through a browser refresh, and it bounds
/// the window in which an incident-response tightening is still being evaluated against yesterday's
/// policy — on **every** replica, without any of them having to be told.
///
/// It is not configurable from `enclave.yaml` today: `enclave_config::ConditionalAccessConfig`
/// carries only the zones, and adding a key touches a file another change owns. `ENC-602`.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(15);

/// One tenant's rules, and when they were read.
#[derive(Debug, Clone)]
struct Cached {
    policies: Arc<PolicySet>,
    loaded_at: Instant,
}

/// Conditional access evaluated against each tenant's stored rules.
///
/// Cloneable, and clones share one cache: the `Arc` is inside, so two clones handed to two routers
/// do not each keep their own idea of a tenant's rules.
#[derive(Debug, Clone)]
pub struct TenantConditionalAccess {
    pool: DbPool,
    zones: ZoneMap,
    break_glass: Option<BreakGlass>,
    ttl: Duration,
    cache: Arc<RwLock<HashMap<TenantId, Cached>>>,
}

impl TenantConditionalAccess {
    /// Builds the stage over a pool and the deployment's zone definitions.
    #[must_use]
    pub fn new(pool: DbPool, zones: ZoneMap) -> Self {
        Self {
            pool,
            zones,
            break_glass: Some(BreakGlass::default_scope()),
            ttl: DEFAULT_CACHE_TTL,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Changes how long a tenant's rules are reused.
    ///
    /// `Duration::ZERO` reads on every request. See the module header for what the bound means and
    /// why it is a time rather than a message.
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Changes how a break-glass session is recognised, or turns the exemption off.
    ///
    /// Deployment configuration rather than tenant data, deliberately: the scope comes from a
    /// verified token, so the deployment's issuer decides who holds it (`policy::BreakGlass`). A
    /// tenant-editable break-glass definition would be a tenant-editable way out of the tenant's
    /// own rules.
    #[must_use]
    pub fn with_break_glass(mut self, break_glass: Option<BreakGlass>) -> Self {
        self.break_glass = break_glass;
        self
    }

    /// How long a tightened rule can still be evaluated in its old form, anywhere.
    #[must_use]
    pub const fn cache_ttl(&self) -> Duration {
        self.ttl
    }

    /// Forgets one tenant's cached rules, so the next request reads them again.
    ///
    /// The admin write path calls this after a change. It reaches this process only — the TTL is
    /// what holds on the replicas that were not told, which is why the TTL is the number quoted to
    /// an administrator rather than this.
    pub fn invalidate(&self, tenant: TenantId) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        cache.remove(&tenant);
    }

    /// Forgets every tenant's cached rules.
    pub fn invalidate_all(&self) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        cache.clear();
    }

    /// This tenant's rules, from the cache if they are still fresh and from PostgreSQL otherwise.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored rule that cannot be decoded. Neither is turned into an empty
    /// rule set; see the module header.
    pub async fn policies_for(&self, tenant: TenantId) -> Result<Arc<PolicySet>> {
        if let Some(fresh) = self.fresh(tenant) {
            return Ok(fresh);
        }

        // Loaded outside every lock. Two requests for the same cold tenant may both read — the cost
        // is a duplicated query, and the alternative is holding a lock across a database round trip,
        // which converts a slow query into a stalled process.
        let rules = self.load(tenant).await?;
        let policies = Arc::new(self.assemble(rules));
        self.remember(tenant, Arc::clone(&policies));
        Ok(policies)
    }

    /// The cached rules, if they are within the TTL.
    fn fresh(&self, tenant: TenantId) -> Option<Arc<PolicySet>> {
        if self.ttl.is_zero() {
            return None;
        }
        // `PoisonError::into_inner` rather than a propagated failure: a poisoned lock means some
        // other thread panicked while holding it, and what it was holding is a cache of rows that
        // are still in the database. Refusing every request in the process because a cache entry
        // was being written during an unrelated panic would be a self-inflicted outage.
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        let entry = cache.get(&tenant)?;
        (entry.loaded_at.elapsed() < self.ttl).then(|| Arc::clone(&entry.policies))
    }

    /// Stores a freshly loaded rule set, and drops entries nothing has asked for since they expired.
    ///
    /// The sweep is what keeps the map bounded by the tenants a host is *actively* serving rather
    /// than by every tenant it has ever served. It runs only on a miss, over a map whose size is the
    /// number of active tenants on this replica.
    fn remember(&self, tenant: TenantId, policies: Arc<PolicySet>) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        if !self.ttl.is_zero() {
            cache.retain(|_, entry| entry.loaded_at.elapsed() < self.ttl);
            cache.insert(tenant, Cached { policies, loaded_at: Instant::now() });
        }
    }

    /// Reads and decodes one tenant's rules.
    async fn load(&self, tenant: TenantId) -> Result<Vec<Rule>> {
        let mut tx = self.pool.begin(tenant).await.map_err(enclave_core::Error::from)?;
        let rows = load_rules(&mut tx).await.map_err(enclave_core::Error::from)?;
        tx.commit().await.map_err(enclave_core::Error::from)?;
        Ok(decode_rules(&rows)?)
    }

    /// Assembles a policy set from decoded rules, the deployment's zones and its break-glass scope.
    fn assemble(&self, rules: Vec<Rule>) -> PolicySet {
        let mut human = Vec::new();
        let mut machine = Vec::new();
        for rule in rules {
            match rule {
                Rule::Human(rule) => human.push(rule),
                Rule::Machine(rule) => machine.push(rule),
            }
        }
        PolicySet::empty()
            .with_zones(self.zones.clone())
            .with_break_glass(self.break_glass.clone())
            .with_human_rules(human)
            .with_machine_rules(machine)
    }
}

#[async_trait]
impl ConditionalAccessService for TenantConditionalAccess {
    /// Evaluates this request against its **own tenant's** rules.
    ///
    /// The tenant comes from `RequestContext`, which is built from the verified token or from
    /// custom-domain routing and never from anything the client sent (`CLAUDE.md` rule 3). It is
    /// then the key of the cache and the argument to `TenantScoped::begin`, so one tenant's rules
    /// are loaded under that tenant's row-level-security context and cannot be reached from
    /// another's request.
    ///
    /// The resource is ignored, for the reason [`crate::ConfiguredConditionalAccess`] documents at
    /// length: this stage runs before authorization so that its refusal cannot depend on anything
    /// about a resource the caller has not been permitted to know exists.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        let policies = self.policies_for(ctx.tenant_id).await?;
        let evaluation = policies.evaluate(ctx, action);

        if !evaluation.simulated_rules().is_empty() {
            tracing::info!(
                %ctx.request_id,
                %ctx.tenant_id,
                rules = ?evaluation.simulated_rules(),
                action = action.verb(),
                "conditional access rules matched in simulation"
            );
        }

        // High severity by design: `docs/11 §5.6` requires break-glass use to raise an immediate
        // alert to the security contact.
        if evaluation.break_glass_applied() {
            tracing::warn!(
                %ctx.request_id,
                %ctx.tenant_id,
                action = action.verb(),
                "break-glass session waived network conditional-access rules"
            );
        }

        Ok(evaluation.decision())
    }
}
