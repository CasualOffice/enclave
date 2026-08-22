//! `ENC-633` — the administrative surface for DLP rules, over HTTP and a real database.
//!
//! `crates/api/src/admin/dlp.rs`'s unit tests cover the decisions that are pure: which field a
//! refusal names, what a lockout is, what `ALLOW` is told. These are the ones that need the whole
//! path — the router, the policy chain, `TenantScoped`, row-level security, and the loader that
//! reads the row back and decides the next request with it.
//!
//! # The chain here is the real one, including its authorization stage
//!
//! `ENC-603`'s tests substituted a double for authorization because no deployment could answer an
//! `Action::Admin`. `ENC-619` landed in the same change as this one, so these run the **real**
//! [`AdminAuthorization`] over the **real** `users.is_admin` of the seeded fixtures. That is worth
//! stating precisely: every `403` below is the deployment's own answer, and the administrator who
//! succeeds is an administrator because a row says so.
//!
//! # Every assertion is watched against its control
//!
//! `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "beta could not
//! withdraw alpha's rule" is true of a surface that refuses every withdrawal, of a fixture whose
//! rule was never written, and of a router that never matched the path. So every refusal here is
//! paired, in the same run and against the same fixture, with the operation succeeding for the
//! tenant that owns the rule.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::{AdminAuthorization, PgAdminRoles, SelfServiceAuthorization};
use enclave_core::{
    Action, ActorKind, ClassificationRank, ClientType, DetectorCategory, DetectorCounts,
    DlpService as _, Exposure, FactsPolicy, FactsSnapshot, FileAction, FileId, PolicyEngine,
    ReasonCode, RequestContext, ResourceRef, ResourceState, ScanVersion, SecurityFacts,
    StageDecision, StageOutcome, TenantId, UserId, VersionId,
};
use enclave_db::{insert_dlp_rule, withdraw_dlp_rule, DbPool, DlpRuleId};
use enclave_dlp::{encode_rule, ActionScope, Condition, DlpAction, DlpMode, DlpRule, RuleId};
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";
const RULES: &str = "/api/v1/admin/dlp/rules";

/// An hour, so that nothing here can pass by cache expiry.
///
/// `ENC-615`'s TTL is the bound and `invalidate` is the shortcut; a test that let the TTL elapse
/// would prove the bound over again and say nothing about whether the write path called anything.
const LONG_TTL: Duration = Duration::from_secs(3600);

// --- Harness --------------------------------------------------------------------------------------

/// A rule cache that counts what it was told, for the assertion that the write path tells it.
#[derive(Debug)]
struct CountingCache {
    inner: enclave_dlp::TenantDlp,
    invalidations: AtomicUsize,
}

impl enclave_api::admin::dlp::DlpRuleCache for CountingCache {
    fn invalidate(&self, tenant: TenantId) {
        self.invalidations.fetch_add(1, Ordering::SeqCst);
        enclave_dlp::TenantDlp::invalidate(&self.inner, tenant);
    }
}

/// The app, the signing key, the stage the chain holds, and the cache the handlers talk to.
struct Harness {
    client: Client,
    key: PrivateSigningKey,
    stage: enclave_dlp::TenantDlp,
    cache: Arc<CountingCache>,
}

/// One router, and the three calls this surface offers.
struct Client {
    app: axum::Router,
}

impl Client {
    async fn send(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.expect("body");
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).expect("a JSON body")
        };
        (status, json)
    }

    async fn get(&self, token: &str) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::GET, RULES, token, None)).await
    }

    async fn post(&self, token: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::POST, RULES, token, Some(body))).await
    }

    async fn delete(&self, token: &str, id: &str) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::DELETE, &format!("{RULES}/{id}"), token, None)).await
    }
}

fn signed(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    match body {
        Some(body) => builder.body(Body::from(body.to_string())).expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    }
}

/// The policy chain a deployment runs, with DLP reading this tenant's stored rules.
///
/// Deliberately **not** `.with_facts(...)`: the engine's own `NoSecurityFacts` reports every
/// resource unscanned under `FAIL_CLOSED`, which is the honest state of a deployment whose
/// `security_facts` rows nothing has written — and it is the state that makes
/// `an_any_scoped_rule_locks_the_tenant_out_of_its_own_admin_surface` a real demonstration rather
/// than a hypothetical.
fn engine(pool: &DbPool, stage: enclave_dlp::TenantDlp) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(AdminAuthorization::new(
            Arc::new(PgAdminRoles::new(pool.clone())),
            Arc::new(SelfServiceAuthorization),
        )),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(stage),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    )
}

/// A migrated, seeded database; the router over it; and the DLP rule cache the router talks to.
async fn harness() -> (TestDb, Fixtures, DbPool, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(6).await.expect("application pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // `ENFORCE`, because a stage that cannot refuse cannot demonstrate that a rule written through
    // this API decides anything. Clones share one cache, which is what lets the handler's
    // invalidation reach the copy the chain evaluates against.
    let stage = enclave_dlp::TenantDlp::new(
        pool.clone(),
        DlpMode::Enforce,
        Arc::new(enclave_dlp::TracingObservations),
    )
    .with_cache_ttl(LONG_TTL);
    let cache =
        Arc::new(CountingCache { inner: stage.clone(), invalidations: AtomicUsize::new(0) });

    let state = ApiState::new(
        engine(&pool, stage.clone()),
        pool.clone(),
        ISSUER,
        AUDIENCE,
        KeySet::new([key.public().clone()]),
    )
    .with_dlp_rule_cache(Arc::clone(&cache) as Arc<dyn enclave_api::admin::dlp::DlpRuleCache>);

    let client = Client { app: router(state, enclave_api::Delivery::unconfigured()) };
    (db, fixtures, pool, Harness { client, key, stage, cache })
}

/// The same surface, serving `tenant-beta`.
///
/// A second router rather than a cleverer harness: the point of the cross-tenant test is that
/// beta's administrator is a legitimate administrator *of beta*, refused only because the rule is
/// not theirs. Both routers run the same real authorization stage over the same seeded rows.
fn beta_app(pool: &DbPool, key: &PrivateSigningKey) -> Client {
    let stage = enclave_dlp::TenantDlp::new(
        pool.clone(),
        DlpMode::Enforce,
        Arc::new(enclave_dlp::TracingObservations),
    );
    let state = ApiState::new(
        engine(pool, stage),
        pool.clone(),
        ISSUER,
        AUDIENCE,
        KeySet::new([key.public().clone()]),
    );
    Client { app: router(state, enclave_api::Delivery::unconfigured()) }
}

/// A real access token: signed, with the real claim set, verified by the real verifier.
fn token(
    key: &PrivateSigningKey,
    tenant: TenantId,
    subject: UserId,
    kind: ActorKind,
    acr: Acr,
    authenticated: chrono::DateTime<Utc>,
) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: subject.as_uuid(),
        tid: tenant.as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: kind,
        scp: Vec::new(),
        amr: vec![AuthMethod::Pwd, AuthMethod::Totp],
        auth_time: authenticated,
        acr,
        dev: None,
        cli: ClientType::Web,
        epoch: 1,
        max_cls: None,
    };
    AccessTokenIssuer::new(ISSUER, AUDIENCE)
        .issue(key, template, now, chrono::Duration::minutes(10))
        .expect("issue")
        .token
}

/// A person who authenticated with a second factor, just now.
fn person_token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    token(key, tenant, user, ActorKind::User, Acr::MultiFactor, Utc::now())
}

/// A rule blocking external sharing of anything carrying payment data — `docs/06 §8`'s example.
///
/// Scoped to external sharing rather than to everything, deliberately: it is what lets a test tell
/// *the rule fired* from *the stage refuses everything*, and it is the scope
/// `a_rule_that_would_govern_its_own_withdrawal_is_refused` exists to keep administrators using.
fn payment_rule(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "scope": ["external_sharing"],
        "conditions": [{ "category_at_least": { "category": "FINANCIAL", "count": 1 } }],
        "action": "BLOCK",
    })
}

/// Facts as a completed scan finding `count` payment identifiers would have left them.
fn scanned(count: u32) -> FactsSnapshot {
    let mut counts = DetectorCounts::none();
    counts.add(DetectorCategory::Financial, count);
    let facts = SecurityFacts::scanned(
        FileId::new_v7(),
        VersionId::new_v7(),
        counts,
        enclave_dlp::builtin_set().version().clone(),
        ScanVersion::new(1),
        Utc::now(),
    );
    FactsSnapshot::gathered(
        facts,
        enclave_dlp::builtin_set().version(),
        FactsPolicy::fail_closed(),
        ResourceState::new(Exposure::Internal, Some(ClassificationRank::new(20))),
    )
}

/// Every row of the table, whatever tenant it belongs to and whether or not it is live.
///
/// Read over the harness's superuser connection *deliberately*: this is inspection, not the claim.
/// Every assertion about isolation is made against operations the API performed over the
/// application role, and this is how a test sees the rows those operations did or did not leave.
async fn rows(db: &TestDb) -> Vec<(uuid::Uuid, String, String, Option<chrono::DateTime<Utc>>)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as("SELECT tenant_id, name, action, deleted_at FROM dlp_rules ORDER BY name")
        .fetch_all(&mut conn)
        .await
        .expect("read the rules table")
}

fn denied(decision: &StageDecision) -> Option<ReasonCode> {
    match decision.outcome() {
        StageOutcome::Deny(code) => Some(*code),
        StageOutcome::Allow => None,
    }
}

/// A person in `tenant`, as the chain would see one.
fn person(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = enclave_core::Actor::User(user);
    ctx.client = ClientType::Web;
    ctx
}

/// Writes a rule the way a `psql` session would — the route this row exists to replace.
async fn store_directly(
    pool: &DbPool,
    tenant: TenantId,
    author: UserId,
    rule: &DlpRule,
) -> DlpRuleId {
    let id = DlpRuleId::new_v7();
    let row = encode_rule(id, 100, rule).expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_dlp_rule(&mut tx, &row, author).await.expect("insert");
    tx.commit().await.expect("commit");
    id
}

// --- The loop this row exists to close --------------------------------------------------------------

/// A rule written over HTTP is stored, decides, and reaches this replica's cache at once.
///
/// `ENC-615` built a write path nothing called, so the assertion is the loop rather than the
/// endpoint. Three halves, each the others' control:
///
/// 1. **Before**, the same stage permits the same external share — so the refusal afterwards cannot
///    be a stage that refuses everything, or a rule some other test left behind.
/// 2. **After**, it refuses, and with the code the rule demands. The rule was written by the API
///    and read by the loader.
/// 3. The TTL is an hour, so (2) can only happen if the write path *invalidated*. The counter is
///    asserted too, because a cache that expired for an unrelated reason would satisfy (2).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_written_through_the_api_is_stored_decides_and_invalidates_this_replicas_cache() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let ctx = person(fixtures.alpha.id, fixtures.alpha.member);
    let file = ResourceRef::file(fixtures.alpha.id, FileId::new_v7());
    let share = Action::File(FileAction::ShareExternal);
    let facts = scanned(2);

    // 1. The control, and it also warms the cache the write must then invalidate.
    let before = harness.stage.evaluate(&ctx, share, &file, &facts).await.expect("evaluate");
    assert_eq!(denied(&before), None, "no rule exists yet, so nothing refuses");

    let (status, body) = harness.client.post(&admin, payment_rule("no payment data leaves")).await;
    assert_eq!(status, StatusCode::CREATED, "the rule was not accepted: {body}");
    assert_eq!(body["name"], "no payment data leaves", "the name is operator-facing and returned");
    assert_eq!(body["priority"], 100, "the migration's default, echoed rather than left to guess");
    assert_eq!(body["decodes"], true);

    // 2 and 3.
    let after = harness.stage.evaluate(&ctx, share, &file, &facts).await.expect("evaluate");
    assert_eq!(
        denied(&after),
        Some(ReasonCode::DlpBlocked),
        "a rule written through the API must decide the next request, not the one an hour from now"
    );
    assert_eq!(
        harness.cache.invalidations.load(Ordering::SeqCst),
        1,
        "the write path tells this replica's cache; the TTL is the bound, not the mechanism"
    );

    // The rule's *conditions* are what refused, not merely its scope: the identical request over a
    // document the scan found nothing in is permitted by the same rule set.
    let clean = harness.stage.evaluate(&ctx, share, &file, &scanned(0)).await.expect("evaluate");
    assert_eq!(denied(&clean), None, "a clean document is not refused by a rule about findings");

    let stored = rows(&db).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0, fixtures.alpha.id.as_uuid(), "written into the caller's own tenant");
    assert!(stored[0].3.is_none(), "a created rule is live");

    // What is in the columns is the *decoded* rule's document. As `ENC-603` recorded, this is a
    // value assertion rather than a proof that the re-encode is load-bearing: `jsonb` normalises
    // key order, and `decode_rule` is what refuses.
    let mut conn = db.connect().await.expect("connect");
    let (scope, conditions): (String, String) =
        sqlx::query_as("SELECT scope::text, conditions::text FROM dlp_rules")
            .fetch_one(&mut conn)
            .await
            .expect("read the documents");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&scope).expect("json"),
        serde_json::json!(["external_sharing"])
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&conditions).expect("json"),
        serde_json::json!([{ "category_at_least": { "category": "FINANCIAL", "count": 1 } }])
    );

    // The chain's own row for the write, which is what an investigation reconstructs a policy
    // change from. The handler's log line carries the rule's name; the audit row carries the action.
    let allows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE action = 'admin.manage_policy' AND outcome = 'ALLOW'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("count");
    assert_eq!(allows, 1, "writing a DLP rule must be on the record");
}

// --- The strictness of the decoder, at the HTTP boundary ---------------------------------------------

/// **Q16 at the API boundary.** A condition may not carry a pattern, and the refusal names it.
///
/// The control is in the same test: the *identical* rule without the pattern is created, so this
/// cannot pass against a handler that refuses every body — and the row count afterwards is `1`,
/// which is what proves the refusal wrote nothing.
///
/// This is the assertion `ENC-615`'s deliberate break aimed at: dropping `deny_unknown_fields` from
/// `Condition` lets the third document decode as an ordinary count comparison **with the pattern
/// silently discarded**, and no error appears anywhere.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_condition_carrying_a_pattern_is_refused_by_name_and_stores_nothing() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    for smuggled in [
        serde_json::json!([{ "pattern": "\\d{16}" }]),
        serde_json::json!([{ "regex": "[A-Z]{2}\\d{2}" }]),
        serde_json::json!([{ "category_at_least": {
            "category": "FINANCIAL", "count": 1, "pattern": "x" } }]),
    ] {
        let (status, body) = harness
            .client
            .post(
                &admin,
                serde_json::json!({
                    "name": "custom expression",
                    "scope": ["exposes_content"],
                    "conditions": smuggled,
                    "action": "BLOCK",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
        assert_eq!(body["error"]["details"][0]["field"], "conditions");
        let detail = body["error"]["details"][0]["detail"].as_str().expect("a detail");
        assert!(
            detail.contains("unknown variant") || detail.contains("unknown field"),
            "the refused clause is the whole diagnostic value of a closed decoder: {detail}"
        );
        assert!(
            !body.to_string().contains("custom expression"),
            "the rule's name belongs in the response and in no error"
        );
    }

    // The control: the same shape, with a condition this stage does have.
    let (status, body) = harness.client.post(&admin, payment_rule("no payment data leaves")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(rows(&db).await.len(), 1, "the refused documents must not have been stored");
}

/// `ALLOW` is refused, with the reason it cannot be stored rather than a bare rejection.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_allow_action_is_refused_with_the_reason_and_stores_nothing() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "name": "an exception above the block",
                "scope": ["external_sharing"],
                "conditions": [],
                "action": "ALLOW",
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "action");
    let detail = body["error"]["details"][0]["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("scans past"),
        "an administrator must be told why an ALLOW would do nothing, not merely that it is \
         refused — otherwise they write it again: {detail}"
    );

    // The control: the same request with an action that exists.
    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "name": "an exception above the block",
                "scope": ["external_sharing"],
                "conditions": [],
                "action": "AUDIT",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(rows(&db).await.len(), 1);
}

/// A body carrying a field this endpoint does not read is refused, `mode` above all.
///
/// D28's guarantee is that `RuleSet::evaluate` takes no mode, so a DLP rule has none. A body
/// carrying one, accepted and ignored, would be an administrator believing a rule rehearses while
/// it decides — the exact inversion `plans/M4-GOVERNANCE.md §2` is written against.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_body_naming_a_mode_is_refused_rather_than_silently_ignored() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let mut body = payment_rule("no payment data leaves");
    body["mode"] = serde_json::json!("SIMULATION");
    let (status, response) = harness.client.post(&admin, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["details"][0]["field"], "body");
    assert!(rows(&db).await.is_empty(), "nothing was stored");

    // The control: the identical body without the field.
    let (status, response) =
        harness.client.post(&admin, payment_rule("no payment data leaves")).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
}

// --- The lockout -------------------------------------------------------------------------------------

/// A rule scoped to every action would put the admin surface inside its own blast radius, and both
/// halves of that sentence are asserted.
///
/// The check is refused **by name** at the API, and — separately, through the route this row
/// exists to replace — the lockout it prevents is demonstrated: a rule written straight into the
/// table by a repository call makes `GET /admin/dlp/rules` answer `403`, because the DLP stage now
/// governs `admin.read_config`, the tenant has no content and therefore no security facts, and the
/// default `facts_unavailable` policy is `FAIL_CLOSED`. Note what did *not* have to happen for
/// that: the rule's conditions were never evaluated.
///
/// Without the second half this test would assert that a check refuses something, with no evidence
/// that what it refuses is harmful.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_any_scoped_rule_locks_the_tenant_out_of_its_own_admin_surface_and_is_refused() {
    let (db, fixtures, pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    // The API refuses it, by name and with the field.
    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "name": "watch everything",
                "scope": ["any"],
                "conditions": [{ "any_finding": null }],
                "action": "NOTIFY_SECURITY",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL");
    assert_eq!(body["error"]["details"][0]["field"], "scope");
    assert!(rows(&db).await.is_empty(), "nothing was stored");

    // The control: the same rule, scoped to the actions it is actually about.
    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "name": "watch everything",
                "scope": ["exposes_content"],
                "conditions": [{ "any_finding": null }],
                "action": "NOTIFY_SECURITY",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let narrow = body["id"].as_str().expect("an id").to_owned();

    // And the surface still works with that rule live, which is what makes the next half about the
    // scope rather than about having any rule at all.
    let (status, _body) = harness.client.get(&admin).await;
    assert_eq!(status, StatusCode::OK);

    // Now the lockout, written the way `psql` would write it — the route this row replaces.
    let sweeping = DlpRule::new(
        RuleId::new("watch literally everything"),
        vec![ActionScope::Any],
        vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 99 }],
        DlpAction::Audit,
    );
    let id = store_directly(&pool, fixtures.alpha.id, fixtures.alpha.admin, &sweeping).await;
    harness.stage.invalidate(fixtures.alpha.id);

    let (status, body) = harness.client.get(&admin).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a rule scoped to every action must be shown to refuse the surface that withdraws it, or \
         the check above is refusing something harmless: {body}"
    );
    assert_eq!(body["error"]["code"], "DLP_BLOCKED");

    // Undone only from outside the product — which is the support incident the refusal prevents.
    {
        let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
        assert!(withdraw_dlp_rule(&mut tx, id).await.expect("withdraw"));
        tx.commit().await.expect("commit");
    }
    harness.stage.invalidate(fixtures.alpha.id);

    let (status, body) = harness.client.get(&admin).await;
    assert_eq!(status, StatusCode::OK, "and the surface comes back: {body}");
    assert_eq!(body["items"][0]["id"], narrow, "the narrow rule is still there");
}

// --- Cross-tenant ------------------------------------------------------------------------------------

/// One tenant's administrator can neither read, nor withdraw, another tenant's rule.
///
/// The assertion that matters most here, and an assertion about an absence — so every refusal is
/// paired with alpha performing the identical operation on the identical row and succeeding. Both
/// tenants hold a rule of the **same name**, because the seeded fixtures mirror each other on
/// purpose, and the mirror is asserted in both directions: a leak one way is still a leak.
///
/// `403` is asserted *against*: it would confirm the rule exists (`CLAUDE.md` rule 7).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_administrator_can_neither_read_nor_withdraw_anothers_rule() {
    let (db, fixtures, pool, harness) = harness().await;
    let beta = beta_app(&pool, &harness.key);
    let alpha_token = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let beta_token = person_token(&harness.key, fixtures.beta.id, fixtures.beta.admin);

    let (status, body) = harness.client.post(&alpha_token, payment_rule("no payment data")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let alpha_id = body["id"].as_str().expect("an id").to_owned();

    let (status, body) = beta.post(&beta_token, payment_rule("no payment data")).await;
    assert_eq!(status, StatusCode::CREATED, "beta's administrator is a real administrator: {body}");
    let beta_id = body["id"].as_str().expect("an id").to_owned();

    // Each sees exactly one rule, and it is their own.
    for (client, token, expected) in
        [(&harness.client, &alpha_token, &alpha_id), (&beta, &beta_token, &beta_id)]
    {
        let (status, body) = client.get(token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "a tenant sees its own rules and no others: {body}");
        assert_eq!(items[0]["id"], expected.as_str());
    }

    // Neither can withdraw the other's, and both are told the same thing an unknown id is told.
    let (status, body) = beta.delete(&beta_token, &alpha_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a 403 would confirm the rule exists: {body}");
    let (status, body) = harness.client.delete(&alpha_token, &beta_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Nothing either of them did touched the other's row.
    let stored = rows(&db).await;
    assert_eq!(stored.len(), 2);
    for (_tenant, name, _action, deleted) in stored {
        assert_eq!(name, "no payment data");
        assert!(deleted.is_none(), "no rule was withdrawn in this test");
    }

    // The control for the withdrawal refusals: each withdraws its own, and it works.
    assert_eq!(harness.client.delete(&alpha_token, &alpha_id).await.0, StatusCode::NO_CONTENT);
    assert_eq!(beta.delete(&beta_token, &beta_id).await.0, StatusCode::NO_CONTENT);
}

// --- Withdrawal --------------------------------------------------------------------------------------

/// Withdrawal stops the rule deciding, keeps the row and its text, and is idempotent.
///
/// `migrations/0021` grants the application role no `DELETE`, for two reasons — one every policy
/// table has, and one that is DLP's alone: `docs/06 §9`'s mandatory-simulation gate is a query over
/// history that names a rule, so a deleted rule is one whose rehearsal cannot be found. The
/// assertion that the row survives is what makes "the edge's `DELETE` is an `UPDATE`" a fact rather
/// than a comment.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn withdrawal_stops_the_rule_deciding_and_leaves_the_row_behind() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let ctx = person(fixtures.alpha.id, fixtures.alpha.member);
    let file = ResourceRef::file(fixtures.alpha.id, FileId::new_v7());
    let share = Action::File(FileAction::ShareExternal);
    let facts = scanned(2);

    let (status, body) = harness.client.post(&admin, payment_rule("no payment data leaves")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().expect("an id").to_owned();

    // The control: it is deciding before it is withdrawn.
    let before = harness.stage.evaluate(&ctx, share, &file, &facts).await.expect("evaluate");
    assert_eq!(denied(&before), Some(ReasonCode::DlpBlocked));

    assert_eq!(harness.client.delete(&admin, &id).await.0, StatusCode::NO_CONTENT);

    let after = harness.stage.evaluate(&ctx, share, &file, &facts).await.expect("evaluate");
    assert_eq!(denied(&after), None, "a withdrawn rule decides nothing");
    assert_eq!(
        harness.cache.invalidations.load(Ordering::SeqCst),
        2,
        "the withdrawal tells the cache too; without it the rule keeps refusing for the TTL"
    );

    let (status, listed) = harness.client.get(&admin).await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["items"].as_array().expect("items").is_empty(), "and is not listed");

    // The row, and its text, are still there — which a `DELETE` would not have left.
    let stored = rows(&db).await;
    assert_eq!(stored.len(), 1, "withdrawal is an UPDATE; the history is what §9's gate queries");
    assert_eq!(stored[0].1, "no payment data leaves");
    assert!(stored[0].3.is_some(), "and it carries when it stopped applying");

    // Withdrawing it again moves no row, and says exactly what withdrawing a stranger's rule says.
    assert_eq!(harness.client.delete(&admin, &id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(rows(&db).await[0].3, stored[0].3, "the timestamp is written once");
}

// --- The controls beside the chain -------------------------------------------------------------------

/// A live name is unique per tenant, and the collision is a `409` that names no rule.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn two_live_rules_may_not_share_a_name() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    assert_eq!(
        harness.client.post(&admin, payment_rule("no payment data leaves")).await.0,
        StatusCode::CREATED
    );
    let (status, body) = harness.client.post(&admin, payment_rule("no payment data leaves")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "RULE_NAME_IN_USE");
    assert!(
        !body.to_string().contains("no payment data leaves"),
        "a collision report must not name a rule the caller has not been shown"
    );
    assert_eq!(rows(&db).await.len(), 1);

    // The control: the name is reusable once the rule holding it is withdrawn.
    let (_status, listed) = harness.client.get(&admin).await;
    let id = listed["items"][0]["id"].as_str().expect("an id").to_owned();
    assert_eq!(harness.client.delete(&admin, &id).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        harness.client.post(&admin, payment_rule("no payment data leaves")).await.0,
        StatusCode::CREATED
    );
}

/// Writing a rule needs recent multi-factor authentication; reading does not (`docs/06 §22`).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_change_needs_a_recent_second_factor() {
    let (db, fixtures, _pool, harness) = harness().await;
    let single = token(
        &harness.key,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        ActorKind::User,
        Acr::SingleFactor,
        Utc::now(),
    );
    let stale = token(
        &harness.key,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        ActorKind::User,
        Acr::MultiFactor,
        Utc::now() - chrono::TimeDelta::hours(2),
    );

    for weak in [&single, &stale] {
        let (status, body) = harness.client.post(weak, payment_rule("no payment data")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["code"], "STEP_UP_REQUIRED");
    }
    assert!(rows(&db).await.is_empty());

    // Both controls: a single-factor *read* is allowed, and the same caller over recent `mfa`
    // writes successfully.
    assert_eq!(harness.client.get(&single).await.0, StatusCode::OK, "reading is not privileged");
    let fresh = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    assert_eq!(
        harness.client.post(&fresh, payment_rule("no payment data")).await.0,
        StatusCode::CREATED
    );
}

/// A caller the chain refuses is refused before the body is read.
///
/// The body is deliberately malformed. A handler that parsed first would answer `400` and tell a
/// caller who may not manage policy what shape the endpoint expects.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_member_is_refused_before_the_body_is_read() {
    let (db, fixtures, _pool, harness) = harness().await;
    let member = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.member);

    let (status, body) = harness
        .client
        .send(signed(Method::POST, RULES, &member, Some(serde_json::json!({ "nonsense": 1 }))))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "ACCESS_DENIED");
    assert!(
        !body.to_string().contains("nonsense") && !body.to_string().contains("unknown field"),
        "a refused caller learns nothing about the request schema: {body}"
    );
    assert!(rows(&db).await.is_empty());

    // The control: the identical malformed body, from an administrator, *is* read and refused for
    // being malformed — so the `403` above is about the caller rather than about the body.
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let (status, body) = harness
        .client
        .send(signed(Method::POST, RULES, &admin, Some(serde_json::json!({ "nonsense": 1 }))))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "body");
}

/// A machine principal may not administer, and the refusal is the chain's (`ENC-619`).
///
/// Everything about this token is as strong as the administrator's — `MultiFactor`, issued now,
/// **the same subject id** — so the only thing that differs is `typ`. `is_admin` is a column on
/// `users`, and a service account has no row there.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_machine_principal_holding_the_administrators_subject_id_is_refused() {
    let (db, fixtures, _pool, harness) = harness().await;
    let machine = token(
        &harness.key,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        ActorKind::ServiceAccount,
        Acr::MultiFactor,
        Utc::now(),
    );

    let (status, body) = harness.client.post(&machine, payment_rule("no payment data")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "ACCESS_DENIED");
    assert_eq!(harness.client.get(&machine).await.0, StatusCode::FORBIDDEN);
    assert!(rows(&db).await.is_empty());

    // The control: the same subject, as a person.
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    assert_eq!(
        harness.client.post(&admin, payment_rule("no payment data")).await.0,
        StatusCode::CREATED
    );
}

/// A stored row that no longer decodes is listed rather than hidden — **and the tenant cannot
/// reach the list that would show it**, which is the finding this test records.
///
/// `enclave_dlp::store::decode_rules` fails the whole set on one undecodable row, so every request
/// in the tenant errors while such a row is live. The list handler decodes each row individually so
/// that it can be used to repair that. It is not enough, for exactly the reason `ENC-623` records
/// one stage over: the *chain* runs first, its DLP stage loads the same rows and fails on the same
/// one, so `GET` answers `500` and never reaches the list.
///
/// That is asserted rather than worked around, because both alternatives are worse than the bug: a
/// route that skipped the stage would be `CLAUDE.md` rule 1, and a stage that returned "no rules"
/// on a decode failure would be the permissive failure `ENC-615` exists to prevent. `ENC-651`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_undecodable_stored_row_puts_the_tenants_repair_surface_inside_its_blast_radius() {
    let (db, fixtures, pool, harness) = harness().await;
    let admin = person_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    // The control: the surface works before the hostile row exists.
    assert_eq!(harness.client.get(&admin).await.0, StatusCode::OK);

    // A row only a repair script or a `psql` session could have written: the API refuses this
    // document, and the repository holds no opinion about what a condition means.
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO dlp_rules
           (tenant_id, id, name, priority, scope, conditions, action, created_by,
            created_at, updated_at)
         VALUES ($1, $2, 'written by psql', 100, '[\"exposes_content\"]'::jsonb,
                 '[{\"pattern\":\"\\\\d{16}\"}]'::jsonb, 'BLOCK', $3, now(), now())",
    )
    .bind(fixtures.alpha.id.as_uuid())
    .bind(uuid::Uuid::now_v7())
    .bind(fixtures.alpha.admin.as_uuid())
    .execute(&mut conn)
    .await
    .expect("write a row the API would have refused");
    harness.stage.invalidate(fixtures.alpha.id);

    let (status, body) = harness.client.get(&admin).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the chain's DLP stage fails on the same row the list would have shown: {body}"
    );

    // And the handler itself, given the chance, *would* report it: the row is listed with the
    // clause named once the stage is no longer failing on it. Asserted through the repository
    // rather than through a router with the stage removed, because a router that skipped the
    // stage is the thing this test exists to say we did not build.
    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    let stored = enclave_db::load_dlp_rules(&mut tx).await.expect("the rows are readable");
    tx.commit().await.expect("commit");
    assert_eq!(stored.len(), 1);
    assert!(
        enclave_dlp::decode_rule(&stored[0]).is_err(),
        "the row the list would mark `decodes: false`"
    );
}
