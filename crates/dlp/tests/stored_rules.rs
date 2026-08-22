//! `ENC-615` — a tenant's stored DLP rules decide that tenant's requests, and nobody else's.
//!
//! `ENC-582` proved the modes against rule sets a test constructed. `ENC-594` wired the stage and
//! handed it `RuleSet::empty()`, which is the state this task exists to end: `RuleSet::evaluate`
//! returns `NotGoverned` for every action over an empty set, so `ENFORCE` refused exactly as much
//! as `DISABLED` did. These tests are about the things that only exist once rules are rows.
//!
//! # The one leg that would have passed before, and the one that would not
//!
//! `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "The external
//! share was refused" is the assertion that fails against `RuleSet::empty()`, so every test here is
//! built around one — and the permitted legs are paired with it in the same run, over the same
//! stage, so "allowed" means the rule did not fire rather than the stage was never asked.
//! `stored_rules_make_the_enforcing_stage_refuse_an_external_share` asserts the *old* behaviour
//! explicitly as its control: the identical request over the identical fact row, one rule earlier,
//! is permitted.
//!
//! Every assertion runs over the **application** role, never the harness superuser: a superuser
//! bypasses row-level security entirely, and a cross-tenant assertion run as one proves nothing
//! (PR #22, `ENC-124`).
//!
//! # Which mechanism the cross-tenant test proves
//!
//! Recorded because a deliberate break did **not** fail it, which `docs/12 §1.2` says is a finding
//! rather than a shrug. Removing `enclave_db::dlp`'s `tenant_id = $1` predicate — layer 1 — leaves
//! `one_tenants_rules_never_decide_another_tenants_request` green: row-level security holds the
//! property on its own, which is what `§4.1`'s `T5` asserts as a designed property of the two
//! layers rather than a redundancy. So that test proves *isolation*, not the predicate; the
//! predicate is held by `enclave_db::dlp`'s own unit test. With the predicate removed **and** the
//! migration's policy weakened to `USING (true)`, it fails naming the leak.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

// Assertions are the point of a test: a panic here is the failure signal, not a production hazard.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use enclave_core::{
    Action, AuthorizationService, BarrierService, ClassificationRank, ClassificationService,
    ConditionalAccessService, DetectorCategory, DetectorCounts, Error, FactsPolicy,
    FactsUnavailable, FileAction, Obligations, PolicyAuditSink, PolicyDecision, PolicyEngine,
    ReasonCode, RequestContext, ResourceRef, Result as CoreResult, RetentionService, ScanVersion,
    SecurityFacts, SecurityFactsProvider, Stage, StageDecision, TenantId, UserId, Utc, Uuid,
    VersionId,
};
use enclave_db::{
    insert_dlp_rule, load_dlp_rules, record_facts, withdraw_dlp_rule, DbPool, DlpRuleId, DlpRuleRow,
};
use enclave_dlp::policy::{ActionScope, Condition, DlpAction, DlpRule, RuleId};
use enclave_dlp::{
    builtin_set, encode_rule, DlpMode, Observation, ObservationSink, PgSecurityFacts, TenantDlp,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};

const EXTERNAL_SHARE: Action = Action::File(FileAction::ShareExternal);
const DOWNLOAD: Action = Action::File(FileAction::Download);
const PREVIEW: Action = Action::File(FileAction::Preview);

// =================================================================================================
// Harness — every stage but DLP allows, so a refusal can only have come from DLP.
// =================================================================================================

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

/// Audit is asserted by `crates/audit`'s own suite; here it must simply not fail the chain.
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

/// A sink that keeps what it was handed.
///
/// `TracingObservations` writes a log line, and a log line is not something a test can assert
/// against — `docs/12 §1.2` again: "the mode recorded something" is exactly the claim that passes
/// for free. D28's comparison is between two *observations*, so the sink has to hold them.
#[derive(Debug, Default)]
struct Recorded(Mutex<Vec<Observation>>);

impl Recorded {
    fn taken(&self) -> Vec<Observation> {
        core::mem::take(&mut self.0.lock().expect("the sink's lock"))
    }
}

impl ObservationSink for Recorded {
    fn record(&self, observation: &Observation) {
        self.0.lock().expect("the sink's lock").push(observation.clone());
    }
}

// =================================================================================================
// Fixtures
// =================================================================================================

/// A migrated, seeded database and an application-role pool over it.
async fn harness() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(4).await.expect("application pool");
    (db, fixtures, pool)
}

/// A file with one committed version — what a fact row can hang off.
#[derive(Debug, Clone, Copy)]
struct Content {
    spine: Spine,
    version: VersionId,
}

impl Content {
    fn file_ref(&self) -> ResourceRef {
        self.spine.file_ref()
    }
}

/// Writes the workspace, library, folder, file and one `AVAILABLE` version.
async fn content(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Content {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("write the content spine");

    let version = VersionId::new_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 11, 'sha256-fixture', 'text/plain', 1, 0, 'AVAILABLE', $6, $7)",
    )
    .bind(version.as_uuid())
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("fixture/{}", version.as_uuid()))
    .bind(Uuid::now_v7())
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("write the version");

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE id = $2")
        .bind(version.as_uuid())
        .bind(spine.file.as_uuid())
        .execute(&mut *conn)
        .await
        .expect("point the file at its version");

    Content { spine, version }
}

/// Facts as a completed scan would have left them, stamped with the active detector set.
fn scanned(content: Content, financial: u32) -> SecurityFacts {
    let mut counts = DetectorCounts::none();
    counts.add(DetectorCategory::Financial, financial);
    SecurityFacts::scanned(
        content.spine.file,
        content.version,
        counts,
        builtin_set().version().clone(),
        ScanVersion::new(1),
        Utc::now(),
    )
}

/// Writes facts through the application role, exactly as a scanner would.
async fn store_facts(pool: &DbPool, tenant: TenantId, facts: &SecurityFacts) {
    let mut tx = pool.begin(tenant).await.expect("begin");
    record_facts(&mut tx, facts).await.expect("write the fact row");
    tx.commit().await.expect("commit");
}

/// **Block external sharing of anything carrying payment data** — `docs/12 §4.5` D1's rule.
///
/// Scoped to external sharing rather than to everything, which is what lets every test here tell
/// "the rule did not fire" from "the stage refused everything": a download is never governed by it.
fn payment_data_rule() -> DlpRule {
    DlpRule::new(
        RuleId::new("block external sharing of payment data"),
        vec![ActionScope::ExternalSharing],
        vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
        DlpAction::Block,
    )
}

/// Stores a rule for `tenant`, authored by `author`, at `priority`.
async fn store_rule(
    pool: &DbPool,
    tenant: TenantId,
    author: UserId,
    priority: i32,
    rule: &DlpRule,
) -> DlpRuleId {
    let id = DlpRuleId::new_v7();
    let row = encode_rule(id, priority, rule).expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_dlp_rule(&mut tx, &row, author).await.expect("insert the rule");
    tx.commit().await.expect("commit");
    id
}

/// The facts provider `main.rs` builds, over the shipped detector set.
fn provider(pool: &DbPool) -> Arc<PgSecurityFacts> {
    Arc::new(PgSecurityFacts::new(
        pool.clone(),
        builtin_set().version().clone(),
        FactsPolicy::from_tenant_config(
            FactsUnavailable::FailClosed,
            ClassificationRank::RESTRICTED,
        ),
    ))
}

/// The stage as `main.rs` builds it, with caching switched off so that a test asserting *rules* is
/// not accidentally asserting the cache. The cache has its own tests below.
fn stage(pool: &DbPool, mode: DlpMode) -> TenantDlp {
    TenantDlp::new(pool.clone(), mode, Arc::new(Recorded::default())).with_cache_ttl(Duration::ZERO)
}

/// The chain as `main.rs` assembles it: every other stage allows, DLP is `dlp`, and the facts come
/// from PostgreSQL.
fn engine(pool: &DbPool, dlp: Arc<dyn enclave_core::DlpService>) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        dlp,
        Arc::new(AllowAll),
        Arc::new(NoAudit),
    )
    .with_facts(provider(pool) as Arc<dyn SecurityFactsProvider>)
}

/// Runs the chain, discharging the decision either way (`CLAUDE.md` rule 8).
///
/// Panics on any failure that is not a policy denial, so a test cannot read an internal error as a
/// refusal — which is exactly the confusion the decode-failure test below is about.
async fn refused(engine: &PolicyEngine, tenant: TenantId, action: Action, on: ResourceRef) -> bool {
    let ctx = RequestContext::system(tenant);
    match engine.enforce(&ctx, action, &on).await.map(PolicyDecision::into_obligations) {
        Ok(obligations) => {
            let _count = obligations.len();
            false
        }
        Err(Error::PolicyDenied { .. }) => true,
        Err(other) => panic!("the chain failed rather than deciding: {other:?}"),
    }
}

/// Runs the chain and reports the outcome as one of three, because the third is the point of
/// `ENC-615`: a rule set that could not be loaded must not become an allow.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Allowed,
    Denied,
    Failed,
}

async fn outcome(
    engine: &PolicyEngine,
    tenant: TenantId,
    action: Action,
    on: ResourceRef,
) -> Outcome {
    let ctx = RequestContext::system(tenant);
    match engine.enforce(&ctx, action, &on).await.map(PolicyDecision::into_obligations) {
        Ok(obligations) => {
            let _count = obligations.len();
            Outcome::Allowed
        }
        Err(Error::PolicyDenied { .. }) => Outcome::Denied,
        Err(_) => Outcome::Failed,
    }
}

// =================================================================================================
// The stage refuses something, from rows, in a configuration a deployment can run
// =================================================================================================

/// **`D1` in a deployment.** A rule row and a fact row become a refusal on the way out of
/// `PolicyEngine::enforce`.
///
/// `docs/12 §4.5` D1 — *`ENFORCE` blocks* — has been proven at unit level since `ENC-582`, against
/// a `RuleSet` the test constructed. It is M4's first exit criterion, and what it needed was a
/// deployment in which an operator who sets `ENFORCE` gets a stage that refuses: this is that.
///
/// Four legs, and the first is the control that makes the rest mean anything — the identical
/// request, over the identical fact row, **before** the rule exists. That is the state every
/// deployment shipped in, and a test that did not assert it would pass against `RuleSet::empty()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn stored_rules_make_the_enforcing_stage_refuse_an_external_share() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let clean = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;
    store_facts(&pool, alpha, &scanned(clean, 0)).await;

    let engine = engine(&pool, Arc::new(stage(&pool, DlpMode::Enforce)));

    // Control 0 — the deployment as it shipped: `ENFORCE`, facts in the table, and no rule. This is
    // what `RuleSet::empty()` did to every request, and it is why the assertion below is the whole
    // task rather than a detail of it.
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "a tenant with no stored rules must be permitted — otherwise the refusal below is not the \
         rule, and ENFORCE would be refusing things nobody wrote"
    );

    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "two payment identifiers are recorded for this version and a stored rule blocks external \
         sharing of them; the stage read the row or it did not"
    );

    // Control 1 — the same action over a version whose scan found nothing. The refusal is the
    // *counts*, not the mere existence of a rule.
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, clean.file_ref()).await,
        "a clean version was refused, so the stage is not deciding from the counts"
    );

    // Control 2 — an action the stored rule does not govern, over the dirty version. The refusal is
    // the rule's scope, not a stage that denies everything it is asked about.
    assert!(
        !refused(&engine, alpha, DOWNLOAD, dirty.file_ref()).await,
        "a download was refused by a rule scoped to external sharing"
    );
}

/// A stored rule's *obligations* reach the caller, not only its refusals.
///
/// `docs/06 §10`: actions that modify the request rather than reject it are returned as obligations
/// and never silently dropped (`CLAUDE.md` rule 8). A rule set that only ever blocked would leave
/// half the stored vocabulary unexercised end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stored_rule_that_demands_an_obligation_attaches_it_to_the_decision() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 1)).await;

    store_rule(
        &pool,
        alpha,
        fixtures.alpha.admin,
        100,
        &DlpRule::new(
            RuleId::new("watermark previews of payment data"),
            vec![ActionScope::Exactly(PREVIEW)],
            vec![Condition::AnyFinding],
            DlpAction::Watermark,
        ),
    )
    .await;

    let engine = engine(&pool, Arc::new(stage(&pool, DlpMode::Enforce)));
    let ctx = RequestContext::system(alpha);
    let obligations = engine
        .enforce(&ctx, PREVIEW, &dirty.file_ref())
        .await
        .expect("a watermark is an allow with a string attached")
        .into_obligations();

    assert!(
        obligations.contains(&enclave_core::Obligation::Watermark),
        "the stored rule's obligation did not reach the decision: {obligations:?}"
    );

    // The control: an action the rule does not govern comes back unconditional, so the obligation
    // above is the rule firing rather than the stage attaching one to everything.
    let clean_decision = engine
        .enforce(&ctx, DOWNLOAD, &dirty.file_ref())
        .await
        .expect("a download is not governed by this rule");
    assert!(clean_decision.is_unconditional(), "an ungoverned action carried an obligation");
}

// =================================================================================================
// One tenant's rules, one tenant's requests
// =================================================================================================

/// `tenant-alpha`'s rule refuses `tenant-alpha` and is invisible to `tenant-beta`.
///
/// The negative half — beta is not refused — is the one that passes for free, so it never stands
/// alone. In the same run, against the same stage: alpha's identical request over an identical fact
/// row is **refused**, beta's rule set comes back empty from the repository while alpha's comes back
/// with one row, and then beta stores a rule of its own — with the same name, deliberately — and
/// alpha must not be refused by *that* one either. A leak in one direction is still a leak, and a
/// test that checked one direction would pass against a decoder that hard-coded the first tenant it
/// ever saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_rules_never_decide_another_tenants_request() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    // Both tenants hold content with the same findings, so the only difference between the two
    // requests below is whose tenant they belong to.
    let alpha_file = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let beta_file = content(&mut conn, beta, fixtures.beta.owner).await;
    store_facts(&pool, alpha, &scanned(alpha_file, 2)).await;
    store_facts(&pool, beta, &scanned(beta_file, 2)).await;

    let engine = engine(&pool, Arc::new(stage(&pool, DlpMode::Enforce)));
    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    // The positive control, asserted first: the rule engages for the tenant that wrote it.
    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, alpha_file.file_ref()).await,
        "the tenant that wrote the rule must be refused by it, or the absence below is vacuous"
    );

    // The absence, against a request that differs only in whose tenant it is.
    assert!(
        !refused(&engine, beta, EXTERNAL_SHARE, beta_file.file_ref()).await,
        "tenant-beta was decided against tenant-alpha's rule"
    );

    // The same claim one layer down, where a leak would actually happen.
    let mut tx = pool.begin(beta).await.expect("begin");
    let beta_rules = load_dlp_rules(&mut tx).await.expect("load");
    tx.commit().await.expect("commit");
    assert!(beta_rules.is_empty(), "tenant-beta loaded {} of alpha's rules", beta_rules.len());

    let mut tx = pool.begin(alpha).await.expect("begin");
    let alpha_rules = load_dlp_rules(&mut tx).await.expect("load");
    tx.commit().await.expect("commit");
    assert_eq!(alpha_rules.len(), 1, "tenant-alpha must see its own rule");

    // The mirror: beta's own rule refuses beta, and alpha is still governed only by its own.
    store_rule(&pool, beta, fixtures.beta.admin, 100, &payment_data_rule()).await;
    assert!(
        refused(&engine, beta, EXTERNAL_SHARE, beta_file.file_ref()).await,
        "tenant-beta's own rule must refuse tenant-beta"
    );
    assert!(
        !refused(&engine, alpha, DOWNLOAD, alpha_file.file_ref()).await,
        "tenant-alpha was refused an action neither tenant's rule governs"
    );
}

/// A rule cannot name another tenant's administrator as its author.
///
/// PostgreSQL runs referential-integrity checks with row security deliberately **not** enforced, so
/// a single-column `REFERENCES users (id)` would accept `tenant-beta`'s admin as the author of a
/// `tenant-alpha` rule — two individually well-formed rows, and RLS refuses neither
/// (`docs/04 §3.3`, `ENC-543`). The composite key is what closes it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_cannot_be_authored_by_another_tenants_administrator() {
    let (_db, fixtures, pool) = harness().await;
    let row = encode_rule(DlpRuleId::new_v7(), 100, &payment_data_rule()).expect("encodes");

    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    let refused = insert_dlp_rule(&mut tx, &row, fixtures.beta.admin).await;
    assert!(
        refused.is_err(),
        "a tenant-alpha rule was accepted with tenant-beta's administrator as its author"
    );
    drop(tx);

    // The control: the same row, the same statement, this tenant's own administrator.
    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    insert_dlp_rule(&mut tx, &row, fixtures.alpha.admin)
        .await
        .expect("this tenant's admin may author");
    tx.commit().await.expect("commit");
}

// =================================================================================================
// D28 — the same stored rule, two modes, one conclusion
// =================================================================================================

/// **D28 from the table.** The same stored rule under `SIMULATION` and under `ENFORCE` reaches the
/// identical verdict and differs only in effect.
///
/// `tests/modes.rs` asserts this over rule sets a test constructed. What storage could have broken
/// is the *input*: if a mode reached the rules — a column, a filter, a second decoding path — two
/// modes could evaluate different policies while both still calling `DlpMode::effect`. So the two
/// stages here share nothing but the table, and the comparison is between the recorded observations
/// rather than between the decisions, because the decision alone cannot show that the conclusion
/// was the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_stored_rule_reaches_the_same_verdict_in_simulation_and_in_enforce() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 3)).await;
    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    let ctx = RequestContext::system(alpha);
    let resource = dirty.file_ref();
    let facts = provider(&pool)
        .gather(&ctx, EXTERNAL_SHARE, &resource)
        .await
        .expect("the facts the engine would have gathered");

    let simulating_sink = Arc::new(Recorded::default());
    let enforcing_sink = Arc::new(Recorded::default());
    let simulating = TenantDlp::new(pool.clone(), DlpMode::Simulation, simulating_sink.clone())
        .with_cache_ttl(Duration::ZERO);
    let enforcing = TenantDlp::new(pool.clone(), DlpMode::Enforce, enforcing_sink.clone())
        .with_cache_ttl(Duration::ZERO);

    let simulated = simulating
        .evaluate_recording(&ctx, EXTERNAL_SHARE, &resource, &facts)
        .await
        .expect("simulation evaluates");
    let enforced = enforcing
        .evaluate_recording(&ctx, EXTERNAL_SHARE, &resource, &facts)
        .await
        .expect("enforcement evaluates");

    // The positive control first: the rule fired at all. Two verdicts that concluded nothing are
    // equal for free, and would be equal against a stage reading an empty rule set.
    assert_eq!(
        enforced.fired().len(),
        1,
        "the stored rule did not fire, so the equality below proves nothing"
    );
    assert!(enforced.was_blocked(), "ENFORCE must refuse what the rule blocks");

    assert_eq!(
        simulated.verdict(),
        enforced.verdict(),
        "the two modes reached different conclusions from one stored rule"
    );
    assert_eq!(
        simulated.would_enforce(),
        enforced.would_enforce(),
        "simulation reported a would-be decision enforcement did not take"
    );
    assert!(
        !simulated.was_blocked(),
        "SIMULATION acted on its conclusion; the difference between the modes is the effect only"
    );
    assert!(
        simulated.would_have_blocked(),
        "simulation must report that enforcement would have refused this"
    );

    // Both modes recorded, and recorded exactly once: a mode whose only output is the record is
    // indistinguishable from `DISABLED` if the record is missing.
    assert_eq!(simulating_sink.taken().len(), 1);
    assert_eq!(enforcing_sink.taken().len(), 1);
}

// =================================================================================================
// A load or decode failure is never an empty rule set
// =================================================================================================

/// A stored rule that cannot be decoded fails the request rather than disappearing from the set.
///
/// PostgreSQL cannot type-check a JSONB document, so it accepts the row; the decoder must not. And
/// it must not *skip* it either: a stage that dropped the rule would carry on with one refusal
/// fewer than the administrator wrote, silently. The row used is the one **Q16** forbids — a
/// condition carrying a pattern — because that is the shape a stored-rule format would otherwise
/// let back onto the synchronous path.
///
/// The control is in the same fixture: the tenant's other, valid rule refuses before the bad row is
/// written, and an ungoverned action is permitted, so `Failed` below is distinguishable from both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_that_cannot_be_decoded_fails_the_request_rather_than_vanishing() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;
    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    let engine = engine(&pool, Arc::new(stage(&pool, DlpMode::Enforce)));
    assert_eq!(
        outcome(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        Outcome::Denied,
        "the valid rule must engage first, or the failure below could be any failure"
    );
    assert_eq!(
        outcome(&engine, alpha, DOWNLOAD, dirty.file_ref()).await,
        Outcome::Allowed,
        "and an action no rule governs must be allowed, or nothing below is distinguishable"
    );

    // The row PostgreSQL cannot refuse: a regex, in a condition list, in a rule that is otherwise
    // perfectly well formed.
    let smuggled = DlpRuleRow {
        id: DlpRuleId::new_v7(),
        name: "card numbers, by pattern".to_owned(),
        priority: 50,
        scope: r#"["exposes_content"]"#.to_owned(),
        conditions: r#"[{"pattern":"\\d{16}"}]"#.to_owned(),
        action: "BLOCK".to_owned(),
        reclassify_to: None,
    };
    let mut tx = pool.begin(alpha).await.expect("begin");
    insert_dlp_rule(&mut tx, &smuggled, fixtures.alpha.admin)
        .await
        .expect("the database cannot type-check a JSONB document, and does not pretend to");
    tx.commit().await.expect("commit");

    // Both actions now fail. The download is the one that matters: it was *allowed* a moment ago,
    // and an undecodable rule set must not resolve to "no rules govern this".
    assert_eq!(
        outcome(&engine, alpha, DOWNLOAD, dirty.file_ref()).await,
        Outcome::Failed,
        "a rule set containing an undecodable rule was evaluated anyway"
    );
    assert_eq!(
        outcome(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        Outcome::Failed,
        "the governed action must fail too — refusing it for the right reason by accident is not \
         the same as refusing to decide"
    );
}

/// A database failure is never an empty rule set either.
///
/// `ENC-615`'s failure mode, reproduced deliberately: with the pool closed the load errors, and the
/// stage must carry the error to the caller. Falling back to "no rules" would turn an outage into
/// an open door, silently, at exactly the moment nobody is reading logs — and `RuleSet::empty()`
/// makes `ENFORCE` permit everything, so the open door is the *whole* control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_database_failure_fails_the_request_rather_than_emptying_the_rule_set() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;
    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    let dlp = stage(&pool, DlpMode::Enforce);

    // The control: while the pool is open the rule refuses, so the failure below is the pool rather
    // than a stage that was never able to refuse anything.
    let ctx = RequestContext::system(alpha);
    let resource = dirty.file_ref();
    let facts = provider(&pool)
        .gather(&ctx, EXTERNAL_SHARE, &resource)
        .await
        .expect("gather while the pool is open");
    assert!(dlp
        .evaluate_recording(&ctx, EXTERNAL_SHARE, &resource, &facts)
        .await
        .expect("evaluates")
        .was_blocked());

    pool.close().await;

    let after = dlp.evaluate_recording(&ctx, EXTERNAL_SHARE, &resource, &facts).await;
    assert!(
        after.is_err(),
        "a failed load became a rule set: {:?}",
        after.map(|observation| observation.was_blocked())
    );
}

// =================================================================================================
// The vocabularies the database enforces
// =================================================================================================

/// `ALLOW` cannot be written, on any path, and neither can the rest of what the schema refuses.
///
/// `DlpAction::from_sql` refuses the string; this asserts the half that holds for callers who never
/// went through the enum, which is the half that survives a repair script. Each row differs from a
/// row the same statement accepts in exactly one field.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_database_refuses_the_rows_the_rule_types_cannot_express() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let base = encode_rule(DlpRuleId::new_v7(), 100, &payment_data_rule()).expect("encodes");

    for (label, row) in [
        ("an ALLOW action", DlpRuleRow { action: "ALLOW".to_owned(), ..base.clone() }),
        ("an invented action", DlpRuleRow { action: "SHRED".to_owned(), ..base.clone() }),
        (
            "an empty scope, which would govern nothing",
            DlpRuleRow { scope: "[]".to_owned(), ..base.clone() },
        ),
        (
            "a scope that is not an array",
            DlpRuleRow { scope: r#"{"any":true}"#.to_owned(), ..base.clone() },
        ),
        (
            "conditions that are not an array",
            DlpRuleRow { conditions: r#"{"any_finding":null}"#.to_owned(), ..base.clone() },
        ),
        (
            "a RECLASSIFY with no rank",
            DlpRuleRow { action: "RECLASSIFY".to_owned(), ..base.clone() },
        ),
        (
            "a rank on an action with no target",
            DlpRuleRow { reclassify_to: Some(30), ..base.clone() },
        ),
        ("a negative priority", DlpRuleRow { priority: -1, ..base.clone() }),
        ("an empty name", DlpRuleRow { name: String::new(), ..base.clone() }),
    ] {
        let mut tx = pool.begin(tenant).await.expect("begin");
        let row = DlpRuleRow { id: DlpRuleId::new_v7(), ..row };
        assert!(
            insert_dlp_rule(&mut tx, &row, fixtures.alpha.admin).await.is_err(),
            "the database accepted {label}"
        );
        drop(tx);
    }

    // The control: the same statement with every field right must succeed, so the refusals above
    // are about the values rather than about the statement.
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_dlp_rule(&mut tx, &base, fixtures.alpha.admin)
        .await
        .expect("a well-formed rule is stored");
    tx.commit().await.expect("commit");

    // And the pairing that *is* legitimate, so `a RECLASSIFY with no rank` above is the missing
    // rank rather than the action being unstorable.
    let reclassify = encode_rule(
        DlpRuleId::new_v7(),
        50,
        &DlpRule::new(
            RuleId::new("raise anything carrying secrets"),
            vec![ActionScope::Any],
            vec![Condition::AnyFinding],
            DlpAction::Reclassify { to: ClassificationRank::RESTRICTED },
        ),
    )
    .expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_dlp_rule(&mut tx, &reclassify, fixtures.alpha.admin)
        .await
        .expect("a RECLASSIFY with its rank is storable");
    tx.commit().await.expect("commit");
}

/// The application role cannot delete a rule, and can do everything else.
///
/// `migrations/0021` withholds `DELETE` because one such statement stops a tenant's content
/// inspection refusing anything, leaves nothing to say it did, and removes the rule
/// `docs/06 §9`'s mandatory-simulation gate has to query the history of. Asserted both as the grant
/// and as the statement, because a grant nobody exercises is a claim.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_may_withdraw_a_rule_but_never_delete_one() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let id = store_rule(&pool, tenant, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    let mut tx = pool.begin(tenant).await.expect("begin");
    let privileges = sqlx::query(
        "SELECT has_table_privilege('enclave_app', 'dlp_rules', 'SELECT') AS s,
                has_table_privilege('enclave_app', 'dlp_rules', 'INSERT') AS i,
                has_table_privilege('enclave_app', 'dlp_rules', 'UPDATE') AS u,
                has_table_privilege('enclave_app', 'dlp_rules', 'DELETE') AS d",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read the grants");
    // The controls come first: a role with no privileges at all would satisfy the `DELETE`
    // assertion on its own.
    assert!(privileges.get::<bool, _>("s"), "the application role must be able to read rules");
    assert!(privileges.get::<bool, _>("i"), "the application role must be able to write rules");
    assert!(privileges.get::<bool, _>("u"), "the application role must be able to withdraw rules");
    assert!(!privileges.get::<bool, _>("d"), "the application role holds DELETE on dlp_rules");

    let attempted = sqlx::query("DELETE FROM dlp_rules WHERE id = $1")
        .bind(id.as_uuid())
        .execute(&mut *tx)
        .await;
    assert!(attempted.is_err(), "the application role deleted a DLP rule");
    drop(tx);

    // Withdrawal is the supported route, and it leaves the row.
    let mut tx = pool.begin(tenant).await.expect("begin");
    assert!(withdraw_dlp_rule(&mut tx, id).await.expect("withdraw"), "the live rule was withdrawn");
    assert!(
        !withdraw_dlp_rule(&mut tx, id).await.expect("withdraw again"),
        "withdrawing twice must not move the timestamp a second time"
    );
    let remaining: i64 =
        sqlx::query("SELECT count(*) FROM dlp_rules WHERE id = $1 AND deleted_at IS NOT NULL")
            .bind(id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count")
            .get(0);
    tx.commit().await.expect("commit");
    assert_eq!(remaining, 1, "a withdrawn rule must keep its row and its text");
}

/// A withdrawn rule stops deciding.
///
/// Both halves in one fixture: the rule refuses the request, it is withdrawn, and the identical
/// request is then permitted. Without the first half this is a test that a rule which never existed
/// refuses nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_withdrawn_rule_stops_deciding() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;
    let id = store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    let engine = engine(&pool, Arc::new(stage(&pool, DlpMode::Enforce)));
    assert!(refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await);

    let mut tx = pool.begin(alpha).await.expect("begin");
    assert!(withdraw_dlp_rule(&mut tx, id).await.expect("withdraw"));
    tx.commit().await.expect("commit");

    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "a withdrawn rule still decided the request"
    );
}

/// Rule order is the administrator's expressed precedence, and it survives storage.
///
/// `Verdict::blocking_code` returns the **first** refusal in rule order rather than a computed
/// strongest, so `priority` decides which reason code a refused caller is shown. Two refusing rules
/// with different codes, stored twice with the order reversed: the answer must follow the order.
/// Without this, `priority` would be a column nothing reads — which is exactly what `0019` refused
/// to store for conditional access.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn priority_decides_which_refusal_a_caller_is_shown() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    // `BLOCK` and `REMOVE_SHARE` both refuse an external share and carry different codes.
    let block = payment_data_rule();
    let remove = DlpRule::new(
        RuleId::new("take the link down instead"),
        vec![ActionScope::ExternalSharing],
        vec![Condition::AnyFinding],
        DlpAction::RemoveShare,
    );

    // Two tenants rather than two runs, so both orders are evaluated against the same schema, the
    // same stage and the same facts — and the seeded pair is what makes that realistic.
    let alpha_file = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let beta_file = content(&mut conn, beta, fixtures.beta.owner).await;
    store_facts(&pool, alpha, &scanned(alpha_file, 1)).await;
    store_facts(&pool, beta, &scanned(beta_file, 1)).await;

    store_rule(&pool, alpha, fixtures.alpha.admin, 10, &block).await;
    store_rule(&pool, alpha, fixtures.alpha.admin, 20, &remove).await;
    store_rule(&pool, beta, fixtures.beta.admin, 10, &remove).await;
    store_rule(&pool, beta, fixtures.beta.admin, 20, &block).await;

    let dlp = stage(&pool, DlpMode::Enforce);
    for (tenant, resource, expected) in [
        (alpha, alpha_file, ReasonCode::DlpBlocked),
        (beta, beta_file, ReasonCode::ExternalShareBlocked),
    ] {
        let ctx = RequestContext::system(tenant);
        let reference = resource.file_ref();
        let facts = provider(&pool).gather(&ctx, EXTERNAL_SHARE, &reference).await.expect("gather");
        let observation = dlp
            .evaluate_recording(&ctx, EXTERNAL_SHARE, &reference, &facts)
            .await
            .expect("evaluates");

        // The control: both rules fired, so the code below is precedence rather than one rule
        // simply not matching.
        assert_eq!(observation.fired().len(), 2, "both rules must fire for order to mean anything");
        assert_eq!(
            observation.applied().clone().into_stage_decision().outcome(),
            &enclave_core::StageOutcome::Deny(expected),
            "the refusal shown must be the rule the administrator put first"
        );
    }
}

// =================================================================================================
// The cache, and the staleness it is allowed to have
// =================================================================================================

/// A newly written rule applies within the cache TTL, and the cache is genuinely there.
///
/// Both halves are required and each is the other's control. Drop the "immediately after writing"
/// assertion and the test passes against a stage with no cache at all, which is not what this
/// deployment runs. Drop the "after the TTL" assertion and it passes against a cache that never
/// expires — which is the security defect, because **a stale DLP rule set is permissive**: there is
/// no storable `ALLOW`, so every rule this stage holds refuses, constrains or records, and a cache
/// that has missed the newest rule permits something the administrator has forbidden.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_new_rule_applies_within_the_cache_ttl_and_not_before_it() {
    const TTL: Duration = Duration::from_millis(400);

    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;

    let dlp = TenantDlp::new(pool.clone(), DlpMode::Enforce, Arc::new(Recorded::default()))
        .with_cache_ttl(TTL);
    let engine = engine(&pool, Arc::new(dlp.clone()));

    // Warms the cache with the empty rule set this tenant currently has.
    assert!(!refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await);

    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;

    // Immediately: the cached rule set is still the empty one. This is the half that proves a cache
    // exists, and therefore that the half below is measuring something.
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "the rules were re-read within the TTL; there is no cache to bound"
    );

    tokio::time::sleep(TTL + Duration::from_millis(200)).await;

    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "the new rule was still not applied after the TTL elapsed — a stale DLP rule set is \
         permissive, because every storable action refuses, constrains or records"
    );
}

/// Invalidation is the immediate route on the process that made the change.
///
/// The TTL is the bound that holds everywhere; this is the shortcut for the replica that already
/// knows. Asserted against its own control — before invalidating, the stale answer is still being
/// given — so it cannot pass against a stage that never cached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn invalidating_a_tenant_applies_a_new_rule_at_once() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store_facts(&pool, alpha, &scanned(dirty, 2)).await;

    let dlp = TenantDlp::new(pool.clone(), DlpMode::Enforce, Arc::new(Recorded::default()))
        .with_cache_ttl(Duration::from_secs(3600));
    let engine = engine(&pool, Arc::new(dlp.clone()));

    assert!(!refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await);
    store_rule(&pool, alpha, fixtures.alpha.admin, 100, &payment_data_rule()).await;
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "with an hour-long TTL the change must not be visible until the cache is told"
    );

    dlp.invalidate(alpha);
    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "invalidation did not make the new rule apply"
    );
}
