//! `ENC-603` — the administrative surface for conditional-access rules, over HTTP and a real
//! database.
//!
//! `crates/api/src/admin/conditional_access.rs`'s unit tests cover the decisions that are pure:
//! which clause a refusal names, what a lockout is, what a step-up refusal says. These are the ones
//! that need the whole path — the router, the policy chain, `TenantScoped`, row-level security and
//! the loader that reads the row back.
//!
//! # Every assertion here is watched against its control
//!
//! `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "`tenant-beta`'s
//! administrator could not withdraw `tenant-alpha`'s rule" is true of a surface that refuses every
//! withdrawal, of a fixture whose rule was never written, and of a router that never matched the
//! path at all. So every refusal here is paired, in the same test and against the same fixture,
//! with the operation *succeeding* for the tenant that owns the rule.
//!
//! # What the authorization double proves, and what it cannot
//!
//! The chain is the real `PolicyEngine`, with one substitution: [`AdminOnly`] stands in for the
//! authorization stage, allowing `Action::Admin` for the tenant's seeded administrator and refusing
//! everything else. That is not a shortcut around rule 1 — the handlers call
//! `PolicyEngine::enforce` and the double is what the stage *answers* — but it is worth being exact
//! about the claim: these tests prove the surface consults the chain and obeys it. They do not
//! prove that a deployment authorizes an administrator, because no deployment does yet:
//! `crates/api/src/main.rs` wires `SelfServiceAuthorization`, which refuses every `Admin` action,
//! so this surface is closed in the binary until `ENC-619` lands. `a_member_is_refused_before_the
//! _body_is_read` is the half of that which *is* proved here: when the stage says no, the handler
//! stops.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_conditional_access::{TenantConditionalAccess, ZoneMap};
use enclave_core::{
    Action, ActorKind, AuthorizationService, ClientType, ConditionalAccessService, FileAction,
    FileId, PolicyEngine, ReasonCode, RequestContext, ResourceRef, StageDecision, StageOutcome,
    TenantId, UserId,
};
use enclave_db::{DbPool, RuleId, RuleRow};
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";
const RULES: &str = "/api/v1/admin/conditional-access/rules";

/// An hour, so that nothing in these tests can pass by cache expiry.
///
/// `ENC-590`'s TTL is the bound and `invalidate` is the shortcut; a test that let the TTL elapse
/// would prove the bound over again and say nothing about whether the write path called anything.
const LONG_TTL: Duration = Duration::from_secs(3600);

// --- Harness --------------------------------------------------------------------------------------

/// The authorization stage, standing in for one that can answer an administrative question.
///
/// Deliberately narrow: `Action::Admin` for one named user, and a refusal for everything else,
/// including the same user on a file. A double that allowed everything would make
/// `a_member_is_refused_before_the_body_is_read` vacuous.
#[derive(Debug)]
struct AdminOnly {
    admin: UserId,
}

#[async_trait]
impl AuthorizationService for AdminOnly {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        _resource: &ResourceRef,
    ) -> enclave_core::Result<StageDecision> {
        let is_admin = ctx.actor.subject_id() == Some(self.admin.as_uuid())
            && ctx.actor.kind() == ActorKind::User;
        if matches!(action, Action::Admin(_)) && is_admin {
            Ok(StageDecision::allow())
        } else {
            Ok(StageDecision::deny(ReasonCode::AccessDenied))
        }
    }

    async fn authorize_many(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        resources: &[ResourceRef],
    ) -> enclave_core::Result<Vec<StageDecision>> {
        Ok(resources.iter().map(|_| StageDecision::deny(ReasonCode::AccessDenied)).collect())
    }
}

/// A rule cache that counts what it was told, for the assertion that the write path tells it.
#[derive(Debug, Default)]
struct CountingCache {
    inner: Option<TenantConditionalAccess>,
    invalidations: AtomicUsize,
}

impl enclave_api::admin::conditional_access::RuleCache for CountingCache {
    fn invalidate(&self, tenant: TenantId) {
        self.invalidations.fetch_add(1, Ordering::SeqCst);
        if let Some(inner) = self.inner.as_ref() {
            inner.invalidate(tenant);
        }
    }
}

/// The app, the signing key, the stage the chain holds, and the cache the handlers talk to.
struct Harness {
    client: Client,
    key: PrivateSigningKey,
    stage: TenantConditionalAccess,
    cache: Arc<CountingCache>,
}

/// One router, and the four calls this surface offers.
struct Client {
    app: axum::Router,
}

impl Client {
    /// Sends one request and returns its status and body.
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

    async fn patch(
        &self,
        token: &str,
        id: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::PATCH, &format!("{RULES}/{id}"), token, Some(body))).await
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

/// A migrated, seeded database; the router over it; and the rule cache the router talks to.
async fn harness() -> (TestDb, Fixtures, DbPool, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(6).await.expect("application pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // The real stage, reading the real rows. Cloned into the engine and into the cache: clones
    // share one cache (`TenantConditionalAccess`), which is what lets the handler's invalidation
    // reach the copy the chain evaluates against.
    let stage =
        TenantConditionalAccess::new(pool.clone(), ZoneMap::empty()).with_cache_ttl(LONG_TTL);
    let cache =
        Arc::new(CountingCache { inner: Some(stage.clone()), invalidations: AtomicUsize::new(0) });

    // Both tenants' administrators are the same seeded local part, and both must be able to
    // administer *their own* tenant — otherwise the cross-tenant test would be asserting that a
    // caller the double refuses is refused, which is not the claim.
    let admins = AdminOnly { admin: fixtures.alpha.admin };
    let policy = PolicyEngine::new(
        Arc::new(stage.clone()),
        Arc::new(admins),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, pool.clone(), ISSUER, AUDIENCE, KeySet::new([key.public().clone()]))
            .with_rule_cache(
                Arc::clone(&cache) as Arc<dyn enclave_api::admin::conditional_access::RuleCache>
            );

    let client = Client { app: router(state, enclave_api::Delivery::unconfigured()) };
    (db, fixtures, pool, Harness { client, key, stage, cache })
}

/// The same harness, with `tenant-beta`'s administrator authorized instead.
///
/// A second engine rather than a cleverer double: the point of the cross-tenant test is that beta's
/// administrator is a legitimate administrator *of beta*, refused only because the rule is not
/// theirs. A double that refused them outright would make the `404` unremarkable.
fn beta_app(db_pool: &DbPool, key: &PrivateSigningKey, fixtures: &Fixtures) -> Client {
    let stage = TenantConditionalAccess::new(db_pool.clone(), ZoneMap::empty());
    let policy = PolicyEngine::new(
        Arc::new(stage),
        Arc::new(AdminOnly { admin: fixtures.beta.admin }),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(
            db_pool.clone(),
            enclave_audit::ChainMode::Enabled,
        )),
    );
    let state = ApiState::new(
        policy,
        db_pool.clone(),
        ISSUER,
        AUDIENCE,
        KeySet::new([key.public().clone()]),
    );
    Client { app: router(state, enclave_api::Delivery::unconfigured()) }
}

/// The same surface, with the conditional-access stage *unconfigured*.
///
/// The only way to reach the list handler while an undecodable row is live — see
/// `an_undecodable_stored_row_is_listed_so_that_it_can_be_withdrawn`, which records why that is a
/// finding rather than a convenience.
fn repair_app(db_pool: &DbPool, key: &PrivateSigningKey, fixtures: &Fixtures) -> Client {
    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(AdminOnly { admin: fixtures.alpha.admin }),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(
            db_pool.clone(),
            enclave_audit::ChainMode::Enabled,
        )),
    );
    let state = ApiState::new(
        policy,
        db_pool.clone(),
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
    user: UserId,
    acr: Acr,
    authenticated: chrono::DateTime<Utc>,
) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: ActorKind::User,
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

/// An administrator who authenticated with a second factor, just now.
fn admin_token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    token(key, tenant, user, Acr::MultiFactor, Utc::now())
}

/// A rule denying downloads, which no administrative action matches — so it is enforceable from
/// anywhere, and every test that is not about the lockout check uses it.
fn download_rule(name: &str, mode: &str) -> serde_json::Value {
    serde_json::json!({
        "audience": "HUMAN",
        "name": name,
        "effect": "BLOCK",
        "mode": mode,
        "when": [{ "action_is": [{ "resource": "file", "action": "download" }] }],
    })
}

/// Every row of the table, whatever tenant it belongs to and whether or not it is live.
///
/// Read over the harness's superuser connection *deliberately*: this is inspection, not the claim.
/// Every assertion about isolation is made against operations the API performed over the
/// application role, and this is how a test sees the rows those operations did or did not leave.
async fn rows(db: &TestDb) -> Vec<(uuid::Uuid, String, String, Option<chrono::DateTime<Utc>>)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT tenant_id, name, mode, deleted_at FROM conditional_access_rules ORDER BY name",
    )
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
    ctx.network.source_ip = "192.0.2.44".parse().expect("a fixture address");
    ctx
}

// --- The loop this row exists to close --------------------------------------------------------------

/// A rule written over HTTP is stored, decided against, and reaches this replica's cache at once.
///
/// This is `ENC-603`'s whole subject: `ENC-590` built a write path nothing called, so the assertion
/// is that an administrator's `POST` now changes what the policy chain decides.
///
/// Three halves, each the others' control:
///
/// 1. **Before**, the same stage allows the same download — so the denial afterwards cannot be a
///    stage that denies everything, or a rule some other test left behind.
/// 2. **After**, it denies. The rule was written by the API and read by the loader.
/// 3. The TTL is an hour, so (2) can only happen if the write path *invalidated*. The counter is
///    asserted as well, because a cache that expired for an unrelated reason would satisfy (2).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_written_through_the_api_is_stored_decides_and_invalidates_this_replicas_cache() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let ctx = person(fixtures.alpha.id, fixtures.alpha.member);
    let file = ResourceRef::file(fixtures.alpha.id, FileId::new_v7());
    let download = Action::File(FileAction::Download);

    // 1. The control, and it also warms the cache the write must then invalidate.
    let before = harness.stage.evaluate(&ctx, download, &file).await.expect("evaluate");
    assert_eq!(denied(&before), None, "no rule exists yet, so nothing refuses");

    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "ENFORCE")).await;
    assert_eq!(status, StatusCode::CREATED, "the rule was not accepted: {body}");
    assert_eq!(body["name"], "no downloads", "the rule's name is operator-facing and is returned");
    assert_eq!(body["mode"], "ENFORCE");
    assert_eq!(body["decodes"], true);

    // 2 and 3.
    let after = harness.stage.evaluate(&ctx, download, &file).await.expect("evaluate");
    assert_eq!(
        denied(&after),
        Some(ReasonCode::AccessDenied),
        "a rule written through the API must decide the next request, not the one an hour from now"
    );
    assert_eq!(
        harness.cache.invalidations.load(Ordering::SeqCst),
        1,
        "the write path tells this replica's cache; the TTL is the bound, not the mechanism"
    );

    let stored = rows(&db).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0, fixtures.alpha.id.as_uuid(), "written into the caller's own tenant");
    assert!(stored[0].3.is_none(), "a created rule is live");

    // What is in the column is the *decoded* rule's document, not the bytes the caller sent — the
    // body above writes `action` before `resource`, and `Action`'s own encoding writes `resource`
    // first.
    //
    // Recorded because a deliberate break here **failed nothing** (`docs/12 §1.2`): storing
    // `request.when` verbatim instead of `encode_rule`'s output leaves all eleven tests green. Two
    // mechanisms hold the property between them and neither is the re-encode. `decode_rule` is what
    // refuses a clause the types cannot express — every strictness test above fails when *it* is
    // weakened — and PostgreSQL's `jsonb` is what normalises the rest: it sorts keys by length and
    // drops whitespace, so a document that decoded is stored identically whichever of the two
    // values reaches it. The stored form is therefore asserted as a *value*, which is what can
    // honestly be asserted; the re-encode stays because the guarantee should not rest on the
    // storage engine's normalisation, and would stop being true the day the body is carried as a
    // raw string rather than parsed into `serde_json::Value`.
    let mut conn = db.connect().await.expect("connect");
    let document: String =
        sqlx::query_scalar("SELECT conditions::text FROM conditional_access_rules")
            .fetch_one(&mut conn)
            .await
            .expect("read the document");
    let stored_document: serde_json::Value = serde_json::from_str(&document).expect("json");
    assert_eq!(
        stored_document,
        serde_json::json!([{ "action_is": [{ "resource": "file", "action": "download" }] }]),
        "the column holds the rule that was decoded"
    );
}

// --- The strictness of the decoder, at the HTTP boundary ---------------------------------------------

/// A machine rule may not name a posture condition, and the refusal names the clause.
///
/// The control is in the same test: the *identical* document under `HUMAN` is accepted, so this
/// cannot pass against a handler that refuses every body — and the row count afterwards is `1`,
/// not `2`, which is what proves the refusal wrote nothing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_machine_rule_naming_a_posture_condition_is_refused_by_name_and_stores_nothing() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let posture = serde_json::json!([{ "posture_below": "MANAGED" }]);
    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "audience": "MACHINE",
                "name": "managed devices only",
                "effect": "BLOCK",
                "when": posture,
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"][0]["field"], "when");
    let detail = body["error"]["details"][0]["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("posture_below"),
        "the refused clause is the whole diagnostic value of a strict decoder: {detail}"
    );
    assert!(
        !body.to_string().contains("managed devices only"),
        "the rule's name belongs in the response and in no error"
    );

    // The control: the same document, under the audience whose type has that variant.
    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "audience": "HUMAN",
                "name": "managed devices only",
                "effect": "BLOCK",
                "when": posture,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let stored = rows(&db).await;
    assert_eq!(stored.len(), 1, "the refused document must not have been stored");
}

/// `ALLOW` is refused, with the reason it does not exist rather than a bare rejection.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_allow_effect_is_refused_with_the_reason_and_stores_nothing() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "audience": "HUMAN",
                "name": "auditors from anywhere",
                "effect": "ALLOW",
                "when": [],
            }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "effect");
    let detail = body["error"]["details"][0]["detail"].as_str().expect("a detail");
    assert!(
        detail.contains("most restrictive"),
        "an administrator who is told only `rejected` writes it again: {detail}"
    );

    // The control: an effect that exists, with everything else identical.
    let (status, _body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "audience": "HUMAN",
                "name": "auditors from anywhere",
                "effect": "REQUIRE_MFA",
                "when": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(rows(&db).await.len(), 1, "only the accepted rule was stored");
}

/// A misspelled `mode` does not silently rehearse.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_body_carrying_an_unknown_field_is_refused_rather_than_partly_applied() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let (status, body) = harness
        .client
        .post(
            &admin,
            serde_json::json!({
                "audience": "HUMAN",
                "name": "night shift",
                "effect": "BLOCK",
                "mdoe": "ENFORCE",
                "when": [],
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "body");
    assert!(rows(&db).await.is_empty());

    // The control: the same body, spelled correctly, is accepted — so this is not a handler that
    // refuses every create.
    let (status, body) =
        harness.client.post(&admin, download_rule("night shift", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["mode"], "SIMULATION");
}

// --- Cross-tenant ------------------------------------------------------------------------------------

/// `tenant-beta`'s administrator can neither read, enforce nor withdraw `tenant-alpha`'s rule, and
/// is told `404` rather than `403` (`CLAUDE.md` rule 7).
///
/// Every refusal is paired with the same operation succeeding for alpha's own administrator, over
/// the same row in the same run. Without those, each assertion here holds against a surface that
/// refuses everything, and the `404` holds against a route that does not exist.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_administrator_can_neither_read_enforce_nor_withdraw_anothers_rule() {
    let (db, fixtures, pool, harness) = harness().await;
    let alpha = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let beta_harness = beta_app(&pool, &harness.key, &fixtures);
    let beta = admin_token(&harness.key, fixtures.beta.id, fixtures.beta.admin);

    // Alpha writes a rule. Beta writes one of the *same name*, because the seeded tenants mirror
    // each other on purpose (`docs/12 §3`) and a test that passed only because the names differed
    // would prove nothing.
    let (status, alpha_rule) =
        harness.client.post(&alpha, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{alpha_rule}");
    let alpha_id = alpha_rule["id"].as_str().expect("an id").to_owned();

    let (status, beta_rule) =
        beta_harness.post(&beta, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a name is unique within a tenant, not across: {beta_rule}"
    );
    let beta_id = beta_rule["id"].as_str().expect("an id").to_owned();
    assert_ne!(alpha_id, beta_id);

    // Read: each administrator sees exactly their own tenant's rule.
    let (status, listed) = beta_harness.get(&beta).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![beta_id.as_str()], "beta's list holds beta's rule and only beta's");

    let (status, listed) = harness.client.get(&alpha).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![alpha_id.as_str()], "and the mirror: alpha's list holds alpha's");

    // Enforce: beta names alpha's id.
    let (status, body) =
        beta_harness.patch(&beta, &alpha_id, serde_json::json!({"mode": "ENFORCE"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a 403 would confirm the rule exists: {body}");
    assert_eq!(body["error"]["code"], "NOT_FOUND");

    // The control: alpha does the identical thing to the identical row and it works.
    let (status, body) =
        harness.client.patch(&alpha, &alpha_id, serde_json::json!({"mode": "ENFORCE"})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mode"], "ENFORCE");

    // Withdraw: beta names alpha's id.
    let (status, body) = beta_harness.delete(&beta, &alpha_id).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // And the mirror, so a leak in one direction only is still caught.
    let (status, body) =
        harness.client.patch(&alpha, &beta_id, serde_json::json!({"mode": "ENFORCE"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Nothing beta did touched alpha's row, and nothing alpha did touched beta's.
    let stored = rows(&db).await;
    assert_eq!(stored.len(), 2);
    for (tenant, name, mode, deleted) in stored {
        assert_eq!(name, "no downloads");
        assert!(deleted.is_none(), "no rule was withdrawn in this test");
        if tenant == fixtures.alpha.id.as_uuid() {
            assert_eq!(mode, "ENFORCE", "alpha enforced its own rule");
        } else {
            assert_eq!(mode, "SIMULATION", "beta's rule was never touched");
        }
    }

    // The control for the withdrawal refusal: alpha withdraws its own rule and it works.
    let (status, _body) = harness.client.delete(&alpha, &alpha_id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// --- Withdrawal --------------------------------------------------------------------------------------

/// Withdrawal keeps the row and its text, and is idempotent in the only direction that matters.
///
/// `migrations/0019` grants the application role no `DELETE`, because one such statement lifts every
/// network restriction a tenant has and leaves nothing to say it existed. The assertion that the row
/// survives is what makes "the edge's `DELETE` is an `UPDATE`" a fact rather than a comment.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn withdrawal_stops_the_rule_deciding_and_leaves_the_row_behind() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let ctx = person(fixtures.alpha.id, fixtures.alpha.member);
    let file = ResourceRef::file(fixtures.alpha.id, FileId::new_v7());
    let download = Action::File(FileAction::Download);

    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "ENFORCE")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().expect("an id").to_owned();

    // The control: it is deciding before it is withdrawn.
    let before = harness.stage.evaluate(&ctx, download, &file).await.expect("evaluate");
    assert_eq!(denied(&before), Some(ReasonCode::AccessDenied));

    let (status, _body) = harness.client.delete(&admin, &id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let after = harness.stage.evaluate(&ctx, download, &file).await.expect("evaluate");
    assert_eq!(denied(&after), None, "a withdrawn rule decides nothing");

    let (status, listed) = harness.client.get(&admin).await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["items"].as_array().expect("items").is_empty(), "and is not listed");

    // The row, and its text, are still there — which a `DELETE` would not have left.
    let stored = rows(&db).await;
    assert_eq!(stored.len(), 1, "withdrawal is an UPDATE; the history is audit evidence");
    assert_eq!(stored[0].1, "no downloads");
    assert!(stored[0].3.is_some(), "and it carries when it stopped applying");

    // Withdrawing it again moves no row, and says exactly what withdrawing a stranger's rule says.
    let (status, _body) = harness.client.delete(&admin, &id).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(rows(&db).await[0].3, stored[0].3, "the timestamp is written once");
}

// --- The controls that sit beside the chain -----------------------------------------------------------

/// A privileged mutation needs recent multi-factor authentication (`docs/06 §22`).
///
/// Both halves, because "the single-factor caller was refused" passes against a surface that
/// refuses every write: the same caller, with the same rights, over `mfa`, succeeds.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_change_needs_a_recent_second_factor() {
    let (db, fixtures, _pool, harness) = harness().await;

    let single =
        token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin, Acr::SingleFactor, Utc::now());
    let (status, body) =
        harness.client.post(&single, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "STEP_UP_REQUIRED");
    assert!(rows(&db).await.is_empty(), "and nothing was written");

    let stale = token(
        &harness.key,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        Acr::MultiFactor,
        Utc::now() - chrono::Duration::hours(2),
    );
    let (status, body) =
        harness.client.post(&stale, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a second factor two hours ago is not recent: {body}"
    );

    // Reading is not a privileged mutation, so a single factor may list. `docs/05 §14` scopes the
    // requirement to the mutations `docs/06 §22` names.
    let (status, _body) = harness.client.get(&single).await;
    assert_eq!(status, StatusCode::OK);

    // The control.
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let (status, _body) =
        harness.client.post(&admin, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED);
}

/// A caller the chain refuses is refused before the body is read.
///
/// The body is deliberately malformed. A handler that parsed first would answer `400` and tell a
/// caller who may not manage policy what shape the endpoint expects; this asserts the `403`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_member_is_refused_before_the_body_is_read() {
    let (db, fixtures, _pool, harness) = harness().await;
    let member = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.member);

    let (status, body) = harness.client.post(&member, serde_json::json!({"nonsense": true})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the chain decides before the body is looked at: {body}"
    );
    assert_eq!(body["error"]["code"], "ACCESS_DENIED");

    let (status, _body) = harness.client.get(&member).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "and a member may not read the tenant's rules either"
    );
    assert!(rows(&db).await.is_empty());

    // The control: the administrator's identical malformed body reaches the parser and is told so.
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);
    let (status, body) = harness.client.post(&admin, serde_json::json!({"nonsense": true})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// A rule that would refuse its author's own session cannot be made to decide.
///
/// `plans/M4-GOVERNANCE.md §5`: a zone rule that denies the network an administrator is on is a
/// control that cannot be undone through the product. Three halves: the enforcing create is
/// refused, the same rule rehearses happily, and promoting it is refused by the same check — with
/// a narrower rule enforced in the same run as the control that says the check is not simply
/// refusing everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_that_would_deny_its_author_cannot_be_enforced_but_may_be_rehearsed() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    // No zones are configured in this harness, so the caller is outside every one of them — which
    // is exactly the administrator writing "corporate network only" from home.
    let lockout = |mode: &str| {
        serde_json::json!({
            "audience": "HUMAN",
            "name": "corporate network only",
            "effect": "BLOCK",
            "mode": mode,
            "when": [{ "outside_every_zone": ["corporate"] }],
        })
    };

    let (status, body) = harness.client.post(&admin, lockout("ENFORCE")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "RULE_WOULD_DENY_ITS_AUTHOR");
    assert!(rows(&db).await.is_empty(), "and it was not stored");

    // Rehearsing it is free, which is what keeps the refusal from blocking legitimate work.
    let (status, body) = harness.client.post(&admin, lockout("SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().expect("an id").to_owned();

    // Promoting it is the same question asked again.
    let (status, body) =
        harness.client.patch(&admin, &id, serde_json::json!({"mode": "ENFORCE"})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(rows(&db).await[0].2, "SIMULATION", "and the stored mode did not move");

    // The control: a rule that does not match an administrative action is enforced without
    // argument, through the same handler and the same check.
    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "ENFORCE")).await;
    assert_eq!(status, StatusCode::CREATED, "the check is narrow, not a blanket refusal: {body}");
}

/// A live name is unique per tenant, and the collision is a `409` that names no rule.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn two_live_rules_may_not_share_a_name() {
    let (db, fixtures, _pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().expect("an id").to_owned();

    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "RULE_NAME_IN_USE");
    assert!(!body.to_string().contains("no downloads"), "no error names a rule");
    assert_eq!(rows(&db).await.len(), 1);

    // The control, and the property the partial index exists for: a name is reusable once the rule
    // holding it has been withdrawn.
    let (status, _body) = harness.client.delete(&admin, &id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) =
        harness.client.post(&admin, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(rows(&db).await.len(), 2, "the withdrawn row stays beside its replacement");
}

/// A stored row that no longer decodes is listed rather than hidden — **and the tenant cannot
/// currently reach the list that would show it**, which is the finding this test records.
///
/// `ENC-590` makes one undecodable rule fail the **whole** set, so every request in the tenant
/// errors while such a row is live (`docs/12 §4.11` C9). The list handler was written to survive
/// that — it decodes each row individually and reports the outcome per rule — because a repair
/// surface that failed the way the loader does could not be used to repair anything: the
/// administrator could not learn which rule to withdraw, or its id, because listing them is what
/// failed.
///
/// It is not enough. The *chain* runs before the handler, and its conditional-access stage loads
/// the same rules and fails on the same row — so `GET` answers `500` and never reaches the list.
/// That is asserted here rather than worked around, because the alternatives are both worse than
/// the bug: an admin route that skipped the stage would be `CLAUDE.md` rule 1, and a stage that
/// returned "no rules" on a decode failure would be `ENC-590`'s permissive failure. The fix belongs
/// in `crates/conditional_access` and is `ENC-623`.
///
/// So the handler's behaviour is exercised through a router whose conditional-access stage is
/// unconfigured, which is the only way to reach it today, and each half is asserted separately:
/// what the stage does, what the chain therefore answers, and what the handler does when it is
/// reached.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_undecodable_stored_row_is_listed_so_that_it_can_be_withdrawn() {
    let (db, fixtures, pool, harness) = harness().await;
    let admin = admin_token(&harness.key, fixtures.alpha.id, fixtures.alpha.admin);

    // A row the API would have refused, written the way a repair script writes one. PostgreSQL
    // cannot type-check the document and does not pretend to.
    let hostile = RuleRow {
        id: RuleId::new_v7(),
        audience: "MACHINE".to_owned(),
        name: "posture for a service account".to_owned(),
        conditions: r#"[{"posture_below":"MANAGED"}]"#.to_owned(),
        effect: "BLOCK".to_owned(),
        mode: "ENFORCE".to_owned(),
    };
    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    enclave_db::insert_rule(&mut tx, &hostile, fixtures.alpha.admin).await.expect("insert");
    tx.commit().await.expect("commit");

    // The state this repairs: the stage refuses to decide at all.
    let ctx = person(fixtures.alpha.id, fixtures.alpha.member);
    let file = ResourceRef::file(fixtures.alpha.id, FileId::new_v7());
    assert!(
        harness.stage.evaluate(&ctx, Action::File(FileAction::Download), &file).await.is_err(),
        "an undecodable rule fails the request rather than quietly leaving the set"
    );

    // The finding: the administration surface is inside that blast radius.
    let (status, _body) = harness.client.get(&admin).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "ENC-623: if this is no longer a 500, the chain has been taught to let the repair surface \
         through and this test should assert the repair rather than the hole"
    );

    // The handler itself, reached the only way it can be today.
    let repair = repair_app(&pool, &harness.key, &fixtures);
    let (status, listed) = repair.get(&admin).await;
    assert_eq!(status, StatusCode::OK);
    let item = &listed["items"][0];
    assert_eq!(item["decodes"], false);
    assert!(item["decodeError"].as_str().expect("a reason").contains("posture_below"));
    assert_eq!(item["name"], "posture for a service account", "and it names the rule to withdraw");

    let id = item["id"].as_str().expect("an id").to_owned();
    let (status, _body) = repair.delete(&admin, &id).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(rows(&db).await[0].3.is_some(), "withdrawn, not deleted");

    // And the tenant is decidable again — the whole point of being able to see the row. The
    // invalidation is explicit because the repair router has no cache handle wired; the real one
    // would have been told by the write path.
    harness.stage.invalidate(fixtures.alpha.id);
    assert!(harness.stage.evaluate(&ctx, Action::File(FileAction::Download), &file).await.is_ok());

    // The control: a good row lists as decoding, so `decodes: false` is not this handler's only
    // answer.
    let (status, body) = repair.post(&admin, download_rule("no downloads", "SIMULATION")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["decodes"], true);
}
