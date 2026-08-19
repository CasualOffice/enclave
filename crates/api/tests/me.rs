//! ENC-124 — the M0 exit criterion, demonstrated rather than asserted.
//!
//! > One end-to-end request: login → JWT → `enforce` → tenant-scoped query → audit row.
//!
//! Every component was built and unit-tested in M0. None of them had ever run together, which is
//! why gate G0 recorded that criterion as *partial*. This test is what closes it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_core::{ClientType, PolicyEngine, TenantId, UserId};
use enclave_testing::TestDb;
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// Builds the app over a freshly migrated, seeded database.
async fn app(db: &TestDb) -> (axum::Router, PrivateSigningKey) {
    let pool = db.pool().await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    // `/me` touches no delivery path; the unconfigured delivery is what a deployment without
    // storage would carry, and using it here keeps the test honest about that.
    (router(state, enclave_api::Delivery::unconfigured()), key)
}

/// Mints a real access token — signed, with the real claim set, verified by the real verifier.
fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: enclave_core::ActorKind::User,
        scp: Vec::new(),
        amr: vec![AuthMethod::Pwd],
        auth_time: now,
        acr: Acr::SingleFactor,
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

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_request_traverses_authentication_the_chain_the_database_and_audit() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(
                    "authorization",
                    format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner)),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK, "the happy path must reach the database");

    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("body");
    let me: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(me["id"], fixtures.alpha.owner.as_uuid().to_string());
    assert_eq!(me["tenantId"], fixtures.alpha.id.as_uuid().to_string());
    assert_eq!(me["capabilities"]["readSelf"], true);

    // The audit row is the half of the criterion that is easiest to believe without checking.
    let mut conn = db.connect().await.expect("connect");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND outcome = 'ALLOW'",
    )
    .bind(fixtures.alpha.id.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("count audit rows");
    assert_eq!(audited, 1, "an allowed request must leave exactly one audit row");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_request_without_a_token_is_refused_and_reaches_no_database() {
    let db = TestDb::start().await.expect("start");
    db.seed().await.expect("seed");
    let (app, _key) = app(&db).await;

    let response = app
        .oneshot(Request::builder().uri("/api/v1/me").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Authentication precedes the chain, so nothing should have been audited — there is no
    // authenticated actor to attribute an event to.
    let mut conn = db.connect().await.expect("connect");
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(audited, 0);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_token_for_another_tenant_learns_nothing_about_the_subject() {
    // A genuine, correctly signed token — only its tenant differs. The interesting part is *which*
    // layer stops it, and it is not the one you would guess.
    //
    // The policy chain ALLOWS this request. `tid` is beta, so the context and the resource are both
    // beta and the engine's tenant assertion passes; the subject is the caller, so self-read
    // authorization permits it. Every stage says yes.
    //
    // The row is still not returned, because `TenantScoped` set `app.tenant_id` to beta and
    // row-level security makes alpha's user invisible to the transaction. Not filtered — invisible.
    // That is the second layer in `docs/04-DATA-MODEL.md §3` doing exactly the job it exists for:
    // catching what the application layer waved through.
    //
    // The caller gets 404. Not 403 — a 403 would confirm the subject exists somewhere (test T1).
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(
                    "authorization",
                    // beta's tenant, alpha's user.
                    format!("Bearer {}", token(&key, fixtures.beta.id, fixtures.alpha.owner)),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a cross-tenant subject must be indistinguishable from one that does not exist"
    );

    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("body");
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains(&fixtures.alpha.owner.as_uuid().to_string()),
        "the response must not echo a subject id from another tenant: {text}"
    );

    // Confirm the claim above rather than asserting it in a comment: the chain allowed, so there is
    // an ALLOW row. If a future change makes authorization deny this instead, this assertion fails
    // and someone re-reads which layer is carrying the isolation.
    let mut conn = db.connect().await.expect("connect");
    let allowed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE outcome = 'ALLOW'")
            .fetch_one(&mut conn)
            .await
            .expect("count");
    assert_eq!(allowed, 1, "the policy chain allowed; RLS is what stopped the read");
}
