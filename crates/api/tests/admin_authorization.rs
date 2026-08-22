//! `ENC-619` — an administrative action is authorized by the deployment, through the chain.
//!
//! `ENC-603` built four conditional-access admin routes enforcing `Admin(ReadConfig)` and
//! `Admin(ManagePolicy)`, and shipped them **closed**: `crates/api/src/main.rs` handed the engine
//! `SelfServiceAuthorization`, which allows a principal to read itself and refuses everything else,
//! so every route under `/api/v1/admin/**` was refused whoever the caller was. That was the right
//! direction — an admin surface that authorized itself would be a second permission model beside
//! the chain — and it was not usable.
//!
//! # What these tests have to prove, and the shape that would prove nothing
//!
//! *"An administrator can list the tenant's conditional-access rules"* is a claim about a change
//! only if the same request, over the same fixtures, was refused before. So the pivotal test builds
//! **two routers over one database**: one wired the way `main.rs` was, one wired the way it now is,
//! and asserts each answers differently for the identical signed token. A test that only exercised
//! the new wiring would have passed against a handler that authorized itself, against a chain that
//! allowed everything, and against `AdminAuthorization` returning allow unconditionally.
//!
//! The refusals are then paired the same way, in the same run: the member, the machine principal
//! and the suspended administrator are each refused *while the administrator succeeds*.
//!
//! Ignored by default because they need a live PostgreSQL and the seeded fixtures — `users.is_admin`
//! is where the grant comes from, so there is nothing to assert without rows. CI runs them with
//! `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::{AdminAuthorization, PgAdminRoles, SelfServiceAuthorization};
use enclave_core::{ActorKind, AuthorizationService, ClientType, PolicyEngine, TenantId, UserId};
use enclave_db::DbPool;
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// `ENC-603`'s surface, which is the one this row exists to open.
const CONDITIONAL_ACCESS: &str = "/api/v1/admin/conditional-access/rules";

/// `ENC-633`'s surface, asserted alongside so the grant is shown to reach both.
const DLP: &str = "/api/v1/admin/dlp/rules";

/// A router over `pool`, with `authorization` as the chain's authorization stage.
///
/// Every other stage is the unconfigured one, deliberately: this file is about exactly one stage,
/// and a refusal that could have come from conditional access or DLP would not name it.
fn app(
    pool: &DbPool,
    key: &PrivateSigningKey,
    authorization: Arc<dyn AuthorizationService>,
) -> axum::Router {
    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );
    let state =
        ApiState::new(policy, pool.clone(), ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    router(state, enclave_api::Delivery::unconfigured())
}

/// The authorization stage `main.rs` handed the engine before this row.
fn as_shipped_before() -> Arc<dyn AuthorizationService> {
    Arc::new(SelfServiceAuthorization)
}

/// The authorization stage `main.rs` hands the engine now.
fn as_shipped_now(pool: &DbPool) -> Arc<dyn AuthorizationService> {
    Arc::new(AdminAuthorization::new(
        Arc::new(PgAdminRoles::new(pool.clone())),
        Arc::new(SelfServiceAuthorization),
    ))
}

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.expect("body");
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).expect("a JSON body")
    };
    (status, json)
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

fn post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// A signed access token with the real claim set.
fn token(key: &PrivateSigningKey, tenant: TenantId, subject: UserId, kind: ActorKind) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: subject.as_uuid(),
        tid: tenant.as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: kind,
        scp: Vec::new(),
        amr: vec![AuthMethod::Pwd, AuthMethod::Totp],
        auth_time: now,
        acr: Acr::MultiFactor,
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

/// A conditional-access rule about downloads, which no administrative action matches — so nothing
/// in these tests can be refused by the rule they write.
fn download_rule(name: &str) -> serde_json::Value {
    serde_json::json!({
        "audience": "HUMAN",
        "name": name,
        "effect": "BLOCK",
        "mode": "SIMULATION",
        "when": [{ "action_is": [{ "resource": "file", "action": "download" }] }],
    })
}

async fn fixtures() -> (TestDb, Fixtures, DbPool, PrivateSigningKey) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let seeded = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(6).await.expect("application pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");
    (db, seeded, pool, key)
}

/// **The pivot.** The same token, the same route, two wirings, two answers.
///
/// The `403` leg is what stops the `200` leg from being a claim about nothing: it is the answer the
/// binary gave before this row, reproduced here against the same database and the same seeded
/// administrator. The read and the write are both asserted, because they are authorized as
/// *different actions* — `Admin(ReadConfig)` and `Admin(ManagePolicy)` — and a grant model that
/// answered only one of them would leave half the surface closed.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_admin_surface_is_closed_under_the_old_wiring_and_open_under_the_new_one() {
    let (_db, fixtures, pool, key) = fixtures().await;
    let admin = token(&key, fixtures.alpha.id, fixtures.alpha.admin, ActorKind::User);

    let before = app(&pool, &key, as_shipped_before());
    let (status, body) = send(&before, get(CONDITIONAL_ACCESS, &admin)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "SelfServiceAuthorization refuses every Admin action, which is why ENC-603's surface was \
         closed in the binary: {body}"
    );
    assert_eq!(body["error"]["code"], "ACCESS_DENIED");
    let (status, _body) =
        send(&before, post(CONDITIONAL_ACCESS, &admin, download_rule("no downloads"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let now = app(&pool, &key, as_shipped_now(&pool));
    let (status, body) = send(&now, get(CONDITIONAL_ACCESS, &admin)).await;
    assert_eq!(status, StatusCode::OK, "an administrator may read the tenant's rules: {body}");
    assert!(body["items"].as_array().expect("items").is_empty(), "and there are none yet");

    let (status, body) =
        send(&now, post(CONDITIONAL_ACCESS, &admin, download_rule("no downloads"))).await;
    assert_eq!(status, StatusCode::CREATED, "and may write one: {body}");

    // The same grant reaches the other administrative surface, which is authorized identically.
    let (status, body) = send(&now, get(DLP, &admin)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Being able to sign in is not being able to administer.
///
/// The three principals here are refused for three different reasons — no grant, a kind that cannot
/// hold one, and a lifecycle state that has taken it away — and each is paired with the
/// administrator succeeding at the identical request in the same run.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn everyone_who_is_not_an_administrator_is_still_refused() {
    let (db, fixtures, pool, key) = fixtures().await;
    let app = app(&pool, &key, as_shipped_now(&pool));
    let admin = token(&key, fixtures.alpha.id, fixtures.alpha.admin, ActorKind::User);

    // The control first, so every refusal below is a refusal of *that* caller rather than of this
    // surface.
    assert_eq!(send(&app, get(CONDITIONAL_ACCESS, &admin)).await.0, StatusCode::OK);

    for (label, user) in [
        ("a member", fixtures.alpha.member),
        ("a workspace owner", fixtures.alpha.owner),
        // `docs/01-PRD.md §4`'s Auditor persona may read the audit log and change nothing. There is
        // no assignment table to say so, so today they are refused like anyone else — recorded
        // rather than left to be discovered (`ENC-650`).
        ("an auditor", fixtures.alpha.auditor),
    ] {
        let their = token(&key, fixtures.alpha.id, user, ActorKind::User);
        let (status, body) = send(&app, get(CONDITIONAL_ACCESS, &their)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label} administered the tenant: {body}");
        assert_eq!(send(&app, get(DLP, &their)).await.0, StatusCode::FORBIDDEN, "{label}");
    }

    // A machine principal carrying the administrator's own subject id. Everything about this token
    // is as strong as the control's; the only difference is `typ`.
    let machine = token(&key, fixtures.alpha.id, fixtures.alpha.admin, ActorKind::ServiceAccount);
    assert_eq!(send(&app, get(CONDITIONAL_ACCESS, &machine)).await.0, StatusCode::FORBIDDEN);

    // And the administrator, suspended. The token is unchanged and still valid; the grant is gone
    // because the row says so, which is the property that makes an incident response effective
    // before the token expires.
    let mut conn = db.connect().await.expect("admin connection");
    sqlx::query("UPDATE users SET status = 'SUSPENDED' WHERE tenant_id = $1 AND id = $2")
        .bind(fixtures.alpha.id.as_uuid())
        .bind(fixtures.alpha.admin.as_uuid())
        .execute(&mut conn)
        .await
        .expect("suspend the administrator");

    let (status, body) = send(&app, get(CONDITIONAL_ACCESS, &admin)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a suspended administrator's outstanding token still administered the tenant: {body}"
    );
}

/// An administrator of one tenant administers nothing in another, and is told `404`.
///
/// The token carries the tenant, so the interesting case is not "beta's admin calls alpha's route"
/// — there is no such call — but a token whose `tid` is alpha's carrying beta's administrator as
/// its subject. That is the shape a stolen or mis-minted token has, and the answer must be a
/// refusal rather than a grant resolved from the other tenant's row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_administrator_of_another_tenant_is_not_an_administrator_here() {
    let (_db, fixtures, pool, key) = fixtures().await;
    let app = app(&pool, &key, as_shipped_now(&pool));

    // The control, both ways round: each administrator administers their own tenant.
    for (tenant, admin) in
        [(fixtures.alpha.id, fixtures.alpha.admin), (fixtures.beta.id, fixtures.beta.admin)]
    {
        let their = token(&key, tenant, admin, ActorKind::User);
        assert_eq!(send(&app, get(CONDITIONAL_ACCESS, &their)).await.0, StatusCode::OK);
    }

    // And neither administers the other's, in both directions.
    for (tenant, foreign) in
        [(fixtures.alpha.id, fixtures.beta.admin), (fixtures.beta.id, fixtures.alpha.admin)]
    {
        let crossed = token(&key, tenant, foreign, ActorKind::User);
        let (status, body) = send(&app, get(CONDITIONAL_ACCESS, &crossed)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}

/// The one route `SelfServiceAuthorization` exists for still works.
///
/// `AdminAuthorization` **wraps** rather than replaces, and the way to find out that the wrapper
/// swallowed the inner service is `GET /api/v1/me` answering `403` in a deployment. Asserted under
/// both wirings, because "it still works" is only meaningful beside "it worked before".
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn wrapping_the_self_read_service_does_not_swallow_it() {
    let (_db, fixtures, pool, key) = fixtures().await;
    let member = token(&key, fixtures.alpha.id, fixtures.alpha.member, ActorKind::User);

    for authorization in [as_shipped_before(), as_shipped_now(&pool)] {
        let app = app(&pool, &key, authorization);
        let (status, body) = send(&app, get("/api/v1/me", &member)).await;
        assert_eq!(status, StatusCode::OK, "a principal may still read itself: {body}");
        assert_eq!(body["id"], fixtures.alpha.member.as_uuid().to_string());
    }
}
