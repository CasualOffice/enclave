//! DLP decided from a tenant's **stored** rules — `ENC-615`.
//!
//! [`crate::ModedDlp`] holds one [`RuleSet`] and serves every tenant from it. That is right for a
//! rule set a test constructs and wrong for a deployment, because a rule is tenant data:
//! `docs/06 §8` has a security administrator writing detectors and thresholds against their own
//! tenant, and one `enclave.yaml` serves every tenant on a host. This type reads each tenant's rules
//! from `dlp_rules` instead (`migrations/0021_dlp_rules.sql`).
//!
//! The **mode** does not come from the table, and its absence there is the milestone's structural
//! guarantee rather than an oversight — see `crate::store` and D28. It is
//! `enclave_config::DlpConfig::default_mode`, read once at start-up and held here beside the pool.
//! What that costs is written down rather than implied: a tenant cannot walk `docs/06 §9`'s rollout
//! ladder at its own pace while its neighbour stays behind. `ENC-632` is the row for a tenant-level
//! mode that keeps the mode *outside* the rule.
//!
//! # Caching, and which direction staleness fails in
//!
//! This stage runs on every request the chain decides, so a query per request is a round trip and a
//! pool checkout in front of every operation. The rule set is therefore cached per tenant for
//! [`DEFAULT_CACHE_TTL`], and — as `ENC-590` did for conditional access — the direction of the risk
//! decides everything about how. It was worth re-deriving rather than copying, because DLP has an
//! `ALLOW` action and conditional access has no `ALLOW` effect, which looks at first like the
//! opposite direction:
//!
//! * **A stale DLP rule set is permissive, not restrictive** — the same direction after all. Every
//!   *storable* action either refuses, constrains or records; `ALLOW` is not storable, because
//!   `Verdict::blocking_code` scans past it to the next refusal and it would be an exception that
//!   fires and changes nothing (`crate::store`, `migrations/0021`, `ENC-631`). So a cache that has
//!   missed the newest rule permits something the administrator has forbidden, and a security
//!   administrator adding a rule during an incident is the case that must not wait.
//! * **The bound is a time, not an invalidation message.** [`TenantDlp::invalidate`] exists and an
//!   admin write path should call it, but it reaches only the process it runs in, and a deployment
//!   is several replicas. An invalidation that is *sometimes* delivered is worse than one that
//!   never is, because it is not something an operator can reason about. The TTL holds everywhere
//!   whether or not any message arrives, and [`TenantDlp::cache_ttl`] is the number to quote when
//!   asked how long a new rule takes to apply.
//! * **Fifteen seconds, the same as conditional access**, deliberately: it bounds the same failure,
//!   and two windows on two stages are two numbers an operator has to hold while deciding whether
//!   the rule they just wrote is live yet.
//! * **The rollout ladder does not go through this cache at all.** Moving a tenant from
//!   `SIMULATION` to `ENFORCE` is a configuration change and a restart, not a rule change — so the
//!   one transition an administrator most wants to be immediate is not subject to the TTL.
//! * **A withdrawal is the restrictive direction, and it is the loud one.** A withdrawn rule that
//!   keeps refusing for up to the TTL produces a complaint; a new rule that has not started
//!   refusing produces nothing at all. That asymmetry is why the bound is short rather than why it
//!   is absent.
//! * **A failure to load is never an empty rule set.** [`TenantDlp::rules_for`] returns the error
//!   and the request fails. This is the whole of `ENC-615`: an empty rule set makes
//!   `RuleSet::evaluate` return `NotGoverned` for every action, so `ENFORCE` over one refuses
//!   exactly as much as `DISABLED` — a database blip would silently disable content inspection, at
//!   the moment nobody is reading logs. For the same reason a rule that cannot be decoded fails the
//!   whole set rather than being skipped (`crate::store::decode_rules`), and a failed load is not
//!   cached: the next request tries again rather than inheriting the failure for the TTL.
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
    Action, DlpService, Error, FactsSnapshot, RequestContext, ResourceRef, Result, StageDecision,
    TenantId,
};
use enclave_db::{load_dlp_rules, DbPool};

use crate::mode::DlpMode;
use crate::observation::{Observation, ObservationSink};
use crate::policy::RuleSet;
use crate::service::decide;
use crate::store::decode_rules;

/// How long a tenant's rules are reused before being read again.
///
/// Fifteen seconds, chosen from the failure it bounds rather than from a cache hit rate: a security
/// administrator who writes a rule and then tests it must find that it applied. It is the same
/// number `enclave_conditional_access::DEFAULT_CACHE_TTL` uses, and the sameness is the point — the
/// two stages bound the same failure, and an operator asking "how long until my change is live"
/// should not get two answers.
///
/// It is not configurable from `enclave.yaml` today: `enclave_config::DlpConfig` carries the mode
/// and the `facts_unavailable` policy, and adding a key touches a file another change owns.
/// `ENC-602` covers both stages.
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(15);

/// One tenant's rules, and when they were read.
#[derive(Debug, Clone)]
struct Cached {
    rules: Arc<RuleSet>,
    loaded_at: Instant,
}

/// The DLP stage, evaluating each tenant's stored rules in the deployment's configured mode.
///
/// Cloneable, and clones share one cache: the `Arc` is inside, so two clones handed to two routers
/// do not each keep their own idea of a tenant's rules.
#[derive(Debug, Clone)]
pub struct TenantDlp {
    pool: DbPool,
    mode: DlpMode,
    sink: Arc<dyn ObservationSink>,
    ttl: Duration,
    cache: Arc<RwLock<HashMap<TenantId, Cached>>>,
}

impl TenantDlp {
    /// Builds the stage over a pool, the configured mode and an observation sink.
    ///
    /// The sink is required rather than optional, for the reason [`ObservationSink`] gives: a mode
    /// whose only output is a record needs somewhere to put it, and defaulting to a discard would
    /// make `MONITOR` and `SIMULATION` indistinguishable from `DISABLED` in a way nothing reports.
    #[must_use]
    pub fn new(pool: DbPool, mode: DlpMode, sink: Arc<dyn ObservationSink>) -> Self {
        Self {
            pool,
            mode,
            sink,
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

    /// The mode in force, for the start-up banner and for an admin surface.
    #[must_use]
    pub const fn mode(&self) -> DlpMode {
        self.mode
    }

    /// How long a newly written rule can still be absent from an evaluation, anywhere.
    #[must_use]
    pub const fn cache_ttl(&self) -> Duration {
        self.ttl
    }

    /// Forgets one tenant's cached rules, so the next request reads them again.
    ///
    /// An admin write path calls this after a change. It reaches this process only — the TTL is
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
    /// A database failure, or a stored rule that cannot be decoded. **Neither is turned into an
    /// empty rule set**, and neither is cached; see the module header for why that is the whole
    /// point of this type.
    pub async fn rules_for(&self, tenant: TenantId) -> Result<Arc<RuleSet>> {
        if let Some(fresh) = self.fresh(tenant) {
            return Ok(fresh);
        }

        // Loaded outside every lock. Two requests for the same cold tenant may both read — the cost
        // is a duplicated query, and the alternative is holding a lock across a database round
        // trip, which converts a slow query into a stalled process.
        let rules = Arc::new(self.load(tenant).await?);
        self.remember(tenant, Arc::clone(&rules));
        Ok(rules)
    }

    /// The cached rules, if they are within the TTL.
    fn fresh(&self, tenant: TenantId) -> Option<Arc<RuleSet>> {
        if self.ttl.is_zero() {
            return None;
        }
        // `PoisonError::into_inner` rather than a propagated failure: a poisoned lock means some
        // other thread panicked while holding it, and what it was holding is a cache of rows that
        // are still in the database. Refusing every request in the process because a cache entry
        // was being written during an unrelated panic would be a self-inflicted outage.
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        let entry = cache.get(&tenant)?;
        (entry.loaded_at.elapsed() < self.ttl).then(|| Arc::clone(&entry.rules))
    }

    /// Stores a freshly loaded rule set, and drops entries nothing has asked for since they expired.
    ///
    /// The sweep is what keeps the map bounded by the tenants a host is *actively* serving rather
    /// than by every tenant it has ever served. It runs only on a miss, over a map whose size is
    /// the number of active tenants on this replica.
    fn remember(&self, tenant: TenantId, rules: Arc<RuleSet>) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        if !self.ttl.is_zero() {
            cache.retain(|_, entry| entry.loaded_at.elapsed() < self.ttl);
            cache.insert(tenant, Cached { rules, loaded_at: Instant::now() });
        }
    }

    /// Reads and decodes one tenant's rules, under that tenant's row-level-security context.
    async fn load(&self, tenant: TenantId) -> Result<RuleSet> {
        let mut tx = self.pool.begin(tenant).await.map_err(Error::from)?;
        let rows = load_dlp_rules(&mut tx).await.map_err(Error::from)?;
        tx.commit().await.map_err(Error::from)?;
        Ok(decode_rules(&rows)?)
    }

    /// Evaluates this tenant's stored rules, records, and returns what the mode decided.
    ///
    /// Split out from the trait method so a test can hold the [`Observation`] rather than only the
    /// [`StageDecision`] — the recorded decision is what D28 compares, and it is not recoverable
    /// from the decision alone.
    ///
    /// # Errors
    ///
    /// As [`TenantDlp::rules_for`]. Note what does *not* happen on that path: no observation is
    /// recorded, because nothing was evaluated, and a record of an evaluation that did not happen
    /// is worse than no record at all.
    pub async fn evaluate_recording(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> Result<Observation> {
        let rules = self.rules_for(ctx.tenant_id).await?;
        Ok(decide(self.mode, &rules, self.sink.as_ref(), action, resource, facts))
    }
}

#[async_trait]
impl DlpService for TenantDlp {
    /// Evaluates this request against its **own tenant's** rules.
    ///
    /// The tenant comes from [`RequestContext`], which is built from the verified token or from
    /// custom-domain routing and never from anything the client sent (`CLAUDE.md` rule 3). It is
    /// then the key of the cache and the argument to `DbPool::begin`, so one tenant's rules are
    /// loaded under that tenant's row-level-security context and cannot be reached from another's
    /// request.
    ///
    /// The facts are the ones the engine gathered once, before the chain's first stage (D26). This
    /// stage does not re-read them, and the rule load deliberately does not join them: a second
    /// transaction here would be a second view of the resource, which is the split D26 exists to
    /// prevent.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> Result<StageDecision> {
        let observation = self.evaluate_recording(ctx, action, resource, facts).await?;
        Ok(observation.applied().clone().into_stage_decision())
    }
}
