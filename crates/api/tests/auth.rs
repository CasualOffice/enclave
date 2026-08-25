//! `ENC-685` — the authentication surface, driven end to end.
//!
//! Every test here runs the real router against a real PostgreSQL with the real
//! `EnclaveTokenService` behind it. Nothing about a password, a rotation or a revocation is faked;
//! what is substituted is storage — the in-memory refresh store and denylist `crates/auth` exports
//! — because there is no Postgres-backed `RefreshTokenStore` yet (`ENC-687`).
//!
//! # What each test is watching for
//!
//! `docs/12-TESTING.md §1.2`: an assertion about an absence passes for free. Three of the
//! properties here are absences — the refresh token is not in the body, a beta user cannot
//! authenticate into alpha, a session that is not yours cannot be revoked — so each is paired with
//! the positive control that makes it mean something: the token *is* in the cookie, the alpha user
//! *does* authenticate, the caller's *own* session *is* revocable.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use enclave_api::routes::auth::{AuthSurface, MfaMethod, MfaVerifier};
use enclave_api::{router, ApiState};
use enclave_auth::{
    Argon2Params, AuthConfig, AuthError, InMemoryDenylist, InMemoryRefreshStore,
    LocalFileKeyProvider, PasswordHasher, PasswordPolicy, RefreshCookieConfig, RefreshRecord,
    SessionFacts, SessionFactsProvider, TokenService, UnrestrictedRefreshGuard,
};
use enclave_core::{PolicyEngine, ScopeSet, TenantId, UserId};
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The password every seeded account is given by [`seed_credentials`].
///
/// Assembled at run time rather than written as a literal, for `CLAUDE.md` rule 11's reason in
/// miniature: a test that greps a response body for its own password must not find the needle in
/// its own source.
fn fixture_password() -> String {
    format!("correct-horse-{}-battery", 42)
}

/// Argon2 at the cheapest parameters it accepts.
///
/// The production defaults are 64 MiB and three passes, which is right for production and turns a
/// suite that signs in a dozen times into a suite nobody runs locally. Cost is not what these tests
/// are asserting — `crates/auth`'s own tests hold the parameters — so it is bought down here and
/// the reason is written where somebody would otherwise "fix" it.
fn cheap_policy() -> PasswordPolicy {
    PasswordPolicy {
        // The floor `AuthConfig::validate` enforces; only the Argon2 cost is bought down.
        min_length: 12,
        max_length: 128,
        argon2: Argon2Params { memory_kib: 8, iterations: 1, parallelism: 1 },
    }
}

/// Session facts that never change: enough to rotate a token, and nothing this suite asserts.
#[derive(Debug)]
struct FixedFacts;

#[async_trait]
impl SessionFactsProvider for FixedFacts {
    async fn facts_for(&self, _record: &RefreshRecord) -> Result<SessionFacts, AuthError> {
        Ok(SessionFacts {
            scopes: ScopeSet::empty(),
            methods: vec![enclave_auth::AuthMethod::Pwd],
            auth_time: Utc::now(),
            epoch: 1,
            max_classification: None,
        })
    }
}

/// An MFA verifier that accepts one code. Stands in for the TOTP and WebAuthn work of `ENC-688`;
/// what this suite asserts is the *challenge lifecycle*, which is real.
#[derive(Debug)]
struct StubMfa {
    accepted: String,
}

#[async_trait]
impl MfaVerifier for StubMfa {
    async fn verify(
        &self,
        _tenant_id: TenantId,
        _subject: UserId,
        _method: MfaMethod,
        code: &str,
    ) -> Result<bool, AuthError> {
        Ok(code == self.accepted)
    }
}

/// The app, the fixtures, and a handle on the database for direct assertions.
struct Harness {
    app: axum::Router,
    fixtures: Fixtures,
    db: TestDb,
    tokens: Arc<dyn TokenService>,
}

/// Builds the router with a fully wired authentication surface.
///
/// The platform URL is the test database's own DSN. `resolve_routed_tenant` needs a connection that
/// row-level security does not apply to, because `tenants` is a table the application role has no
/// grant on at all — see `crates/db/src/routing.rs`.
async fn harness(mfa: Option<StubMfa>) -> Harness {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");

    let config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(db.url()))
        .with_application_role("enclave_app")
        .with_platform_url(enclave_db::ConnectionUrl::new(db.url()));
    let pool = enclave_db::DbPool::connect(&config).await.expect("pool");

    seed_domains(&db, &fixtures).await;
    seed_credentials(&db, &fixtures).await;

    let key_dir = std::env::temp_dir().join(format!("enclave-auth-keys-{}", Uuid::new_v4()));
    let keys = LocalFileKeyProvider::new(&key_dir);
    let verification = enclave_auth::KeyProvider::verification_keys(&keys)
        .await
        .expect("the provider generates its first key on demand");
    let key_set = enclave_auth::KeySet::new(verification);

    let auth_config = AuthConfig {
        access_token: enclave_auth::AccessTokenConfig {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            ..Default::default()
        },
        refresh_token: enclave_auth::RefreshTokenConfig::default(),
        password: cheap_policy(),
    };

    let service = enclave_auth::EnclaveTokenService::new(
        auth_config,
        keys,
        InMemoryRefreshStore::new(),
        InMemoryDenylist::new(),
        UnrestrictedRefreshGuard,
        FixedFacts,
    )
    .expect("valid auth configuration");
    let tokens: Arc<dyn TokenService> = Arc::new(service);

    let mut surface = AuthSurface::new(
        Arc::clone(&tokens),
        PasswordHasher::new(cheap_policy()).expect("hasher"),
        RefreshCookieConfig::default(),
        Duration::days(14),
    );
    if let Some(mfa) = mfa {
        surface = surface.with_mfa(Arc::new(mfa));
    }

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, key_set).with_auth(surface);
    Harness { app: router(state, enclave_api::Delivery::unconfigured()), fixtures, db, tokens }
}

/// Gives each tenant a routable hostname. Both get one, so a test that resolves alpha is not
/// passing because beta was unresolvable.
async fn seed_domains(db: &TestDb, _fixtures: &Fixtures) {
    // Nothing to insert: routing reads `tenants.slug`, which the fixtures already set. The function
    // exists so the *reason* is recorded where somebody looks for the domain seeding they expected
    // — `tenant_domains` is not readable by any role this deployment holds (`ENC-686`).
    let _ = db;
}

/// Gives every seeded user a password credential.
async fn seed_credentials(db: &TestDb, fixtures: &Fixtures) {
    let hasher = PasswordHasher::new(cheap_policy()).expect("hasher");
    let hash = hasher.hash(&fixture_password()).expect("hash");
    let mut conn = db.connect().await.expect("connect");

    for tenant in [&fixtures.alpha, &fixtures.beta] {
        for user in [tenant.owner, tenant.member, tenant.admin] {
            sqlx::query(
                "INSERT INTO user_credentials (user_id, tenant_id, password_hash, changed_at)
                 VALUES ($1, $2, $3, now())
                 ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash",
            )
            .bind(user.as_uuid())
            .bind(tenant.id.as_uuid())
            .bind(&hash)
            .execute(&mut conn)
            .await
            .expect("seed credential");
        }
    }
}

fn host_for(slug: &str) -> String {
    format!("{slug}.enclave.test")
}

fn login_request(slug: &str, email: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("host", host_for(slug))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({ "email": email, "password": password }).to_string()))
        .expect("request")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024).await.expect("body");
    if bytes.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_slice(&bytes).expect("json")
}

/// Every `Set-Cookie` on a response, as strings.
fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

fn cookie_named<'a>(cookies: &'a [String], name: &str) -> Option<&'a str> {
    cookies.iter().map(String::as_str).find(|cookie| cookie.starts_with(&format!("{name}=")))
}

fn cookie_value(cookie: &str) -> &str {
    cookie.split(';').next().unwrap_or_default().split_once('=').map_or("", |(_, value)| value)
}

// ---------------------------------------------------------------------------------------------
// The happy path, and the two absences it is the positive control for
// ---------------------------------------------------------------------------------------------

/// K11 — a password login issues a token, and the refresh token leaves only in the cookie.
///
/// The absence being asserted is "no refresh token in the body". On its own that passes against a
/// handler that returns an empty body, so the positive control is in the same test: the cookie
/// **does** carry a token, it is `HttpOnly`, and the body carries a usable access token.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k11_a_password_login_returns_an_access_token_and_a_refresh_cookie() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let response = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK, "the seeded password must be accepted");
    let cookies = set_cookies(&response);
    let body = json_body(response).await;

    // The positive controls.
    assert_eq!(body["tokenType"], "Bearer");
    assert!(
        body["accessToken"].as_str().is_some_and(|token| token.split('.').count() == 3),
        "the body must carry a compact JWS: {body}"
    );
    assert_eq!(body["user"]["id"], alpha.owner.as_uuid().to_string());
    assert_eq!(body["user"]["isAdmin"], false);
    assert!(body["expiresIn"].as_i64().is_some_and(|secs| secs > 0), "{body}");
    assert!(Uuid::parse_str(body["sessionId"].as_str().unwrap_or_default()).is_ok(), "{body}");

    let refresh = cookie_named(&cookies, "enclave_rt").expect("a refresh cookie must be set");
    assert!(!cookie_value(refresh).is_empty(), "the cookie must carry a token: {refresh}");
    assert!(refresh.contains("HttpOnly"), "{refresh}");
    assert!(refresh.contains("Secure"), "{refresh}");
    assert!(refresh.contains("SameSite=Strict"), "{refresh}");
    assert!(refresh.contains("Path=/api/v1/auth"), "{refresh}");

    // The absence, now meaningful: that same token value is nowhere in the body.
    let rendered = body.to_string();
    assert!(
        !rendered.contains(cookie_value(refresh)),
        "the refresh token reached the response body, where any script on the page can read it"
    );
    assert!(rendered.contains("accessToken"), "positive control: the body is not empty");

    // The CSRF cookie is set beside it, and is the one cookie a script must be able to read.
    let csrf = cookie_named(&cookies, "enclave_csrf").expect("a CSRF cookie must be set");
    assert!(!csrf.contains("HttpOnly"), "the SPA has to echo this one back: {csrf}");
}

/// The access token a login returns is one the rest of the API accepts.
///
/// Without this, every assertion above could hold for a token nothing can verify — which is the
/// exact shape of a test that proves the renderer rather than the system.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_issued_token_is_accepted_by_another_endpoint() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let response = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let body = json_body(response).await;
    let token = body["accessToken"].as_str().expect("token").to_owned();

    let me = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(me.status(), StatusCode::OK, "the login endpoint must mint a usable token");
    let me = json_body(me).await;
    assert_eq!(me["id"], alpha.owner.as_uuid().to_string());
}

// ---------------------------------------------------------------------------------------------
// Enumeration and cross-tenant
// ---------------------------------------------------------------------------------------------

/// K12 — an unknown address and a wrong password are the same answer.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k12_an_unknown_address_and_a_wrong_password_are_indistinguishable() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let unknown = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            "nobody-at-all@tenant-alpha.example",
            &fixture_password(),
        ))
        .await
        .expect("response");
    let unknown_status = unknown.status();
    let unknown_body = json_body(unknown).await;

    let wrong = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            "not-the-password-at-all",
        ))
        .await
        .expect("response");
    let wrong_status = wrong.status();
    let wrong_body = json_body(wrong).await;

    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_status, unknown_status);
    assert_eq!(unknown_body["error"]["code"], "INVALID_CREDENTIALS");
    assert_eq!(wrong_body["error"]["code"], unknown_body["error"]["code"]);
    assert_eq!(wrong_body["error"]["message"], unknown_body["error"]["message"]);
    assert_eq!(wrong_body["error"]["remediation"], unknown_body["error"]["remediation"]);
    // The one field that legitimately differs, and the control that the bodies are not simply
    // empty: each carries its own correlation id.
    assert_ne!(unknown_body["error"]["requestId"], wrong_body["error"]["requestId"]);
    assert!(unknown_body["error"]["requestId"].as_str().is_some());
}

/// K13 — a `tenant-beta` user cannot authenticate on `tenant-alpha`'s host.
///
/// The fixtures give both tenants the same local parts and the same password, so the only thing
/// that can refuse this is tenancy. The positive control is in the same test: the *same* credential
/// on beta's own host succeeds.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k13_a_beta_user_cannot_authenticate_on_alphas_host() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let beta = &harness.fixtures.beta;
    let beta_email = format!("owner@{}.example", beta.slug);

    let crossed = harness
        .app
        .clone()
        .oneshot(login_request(&alpha.slug, &beta_email, &fixture_password()))
        .await
        .expect("response");
    assert_eq!(
        crossed.status(),
        StatusCode::UNAUTHORIZED,
        "a beta credential must not authenticate into alpha"
    );

    let own = harness
        .app
        .clone()
        .oneshot(login_request(&beta.slug, &beta_email, &fixture_password()))
        .await
        .expect("response");
    assert_eq!(
        own.status(),
        StatusCode::OK,
        "positive control: the same credential on beta's own host must work, or the refusal above \
         proves nothing about tenancy"
    );
    let own = json_body(own).await;
    assert_eq!(own["user"]["id"], beta.owner.as_uuid().to_string());
}

/// A host that routes no tenant is a `404`, not a `400` and not a `401`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unrouted_host_cannot_be_used_to_sign_in() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let response = harness
        .app
        .clone()
        .oneshot(login_request(
            "tenant-that-does-not-exist",
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "an unrouted host must not be a 400");
}

/// T6 — a token presented on a host routed to a different tenant is refused.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn t6_a_token_is_not_valid_on_another_tenants_host() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let beta = &harness.fixtures.beta;

    let login = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let token = json_body(login).await["accessToken"].as_str().expect("token").to_owned();

    let elsewhere = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&beta.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(elsewhere.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(elsewhere).await["error"]["code"], "TOKEN_NOT_VALID_HERE");

    // The positive control: the same token on its own host is accepted.
    let here = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(here.status(), StatusCode::OK, "the token must work on the host it was issued on");
}

// ---------------------------------------------------------------------------------------------
// MFA
// ---------------------------------------------------------------------------------------------

/// K14 — an account with a confirmed second factor gets `MFA_REQUIRED` and **no token**.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k14_an_enrolled_account_is_challenged_and_receives_no_token() {
    let code = format!("{}{}", 123, 456);
    let harness = harness(Some(StubMfa { accepted: code.clone() })).await;
    let alpha = &harness.fixtures.alpha;
    enrol_totp(&harness.db, alpha.id, alpha.member).await;

    let response = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("member@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let cookies = set_cookies(&response);
    let body = json_body(response).await;

    assert_eq!(body["error"]["code"], "MFA_REQUIRED");
    assert_eq!(body["error"]["methods"], serde_json::json!(["TOTP"]));
    let challenge = body["error"]["challengeId"].as_str().expect("a challenge id").to_owned();

    // The absence, with the positive control beside it: no token anywhere, and no refresh cookie.
    assert!(body["accessToken"].is_null(), "a challenged login must not carry a token: {body}");
    assert!(
        cookie_named(&cookies, "enclave_rt").is_none(),
        "a challenged login must not set a refresh cookie"
    );

    // Completing the challenge does produce both — which is what makes the two absences above mean
    // "withheld" rather than "never produced by this endpoint at all".
    let verified = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/verify")
                .header("host", host_for(&alpha.slug))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "challengeId": challenge, "code": code }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(verified.status(), StatusCode::OK);
    assert!(cookie_named(&set_cookies(&verified), "enclave_rt").is_some());
    assert!(json_body(verified).await["accessToken"].as_str().is_some());
}

/// A challenge is one attempt. The wrong code spends it, so guessing costs a whole login.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_wrong_code_spends_the_challenge() {
    let code = format!("{}{}", 123, 456);
    let harness = harness(Some(StubMfa { accepted: code.clone() })).await;
    let alpha = &harness.fixtures.alpha;
    enrol_totp(&harness.db, alpha.id, alpha.member).await;

    let challenged = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("member@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let challenge = json_body(challenged).await["error"]["challengeId"]
        .as_str()
        .expect("a challenge id")
        .to_owned();

    let verify = |code: String| {
        let app = harness.app.clone();
        let challenge = challenge.clone();
        let slug = alpha.slug.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/mfa/verify")
                    .header("host", host_for(&slug))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "challengeId": challenge, "code": code }).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response")
        }
    };

    let wrong = verify("000000".to_owned()).await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    // The right code, on the same challenge, now fails too — because the challenge is gone.
    let retried = verify(code).await;
    assert_eq!(
        retried.status(),
        StatusCode::UNAUTHORIZED,
        "a spent challenge must not be usable, even with the right code"
    );
}

// ---------------------------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------------------------

/// Rotation over the wire: the cookie is exchanged for a new one and a new access token.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_refresh_rotates_the_cookie_and_a_replay_is_refused() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let login = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let cookies = set_cookies(&login);
    let refresh_cookie =
        cookie_value(cookie_named(&cookies, "enclave_rt").expect("refresh")).to_owned();
    let csrf = cookie_value(cookie_named(&cookies, "enclave_csrf").expect("csrf")).to_owned();
    let _ = json_body(login).await;

    let rotate = |token: String, csrf: String| {
        let app = harness.app.clone();
        let slug = alpha.slug.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .header("host", host_for(&slug))
                    .header("cookie", format!("enclave_rt={token}; enclave_csrf={csrf}"))
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
        }
    };

    let rotated = rotate(refresh_cookie.clone(), csrf.clone()).await;
    assert_eq!(rotated.status(), StatusCode::OK, "the first rotation must succeed");
    let rotated_cookies = set_cookies(&rotated);
    let successor =
        cookie_value(cookie_named(&rotated_cookies, "enclave_rt").expect("refresh")).to_owned();
    assert_ne!(successor, refresh_cookie, "rotation must issue a *different* token");
    assert!(json_body(rotated).await["accessToken"].as_str().is_some());

    // K4 over the wire: presenting the consumed token is theft.
    let replayed = rotate(refresh_cookie, csrf).await;
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(replayed).await["error"]["code"], "SESSION_REPLAY");
}

/// K15 — a refresh without the double-submit header is refused.
///
/// The positive control is the same request *with* the header, which succeeds — so this is not
/// passing because the endpoint refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k15_a_refresh_without_the_csrf_header_is_refused() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let login = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let cookies = set_cookies(&login);
    let refresh_cookie =
        cookie_value(cookie_named(&cookies, "enclave_rt").expect("refresh")).to_owned();
    let csrf = cookie_value(cookie_named(&cookies, "enclave_csrf").expect("csrf")).to_owned();
    let _ = json_body(login).await;

    let without = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("host", host_for(&alpha.slug))
                .header("cookie", format!("enclave_rt={refresh_cookie}; enclave_csrf={csrf}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(without.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(without).await["error"]["code"], "CSRF_TOKEN_INVALID");

    // A header that does not match the cookie is refused the same way.
    let mismatched = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("host", host_for(&alpha.slug))
                .header("cookie", format!("enclave_rt={refresh_cookie}; enclave_csrf={csrf}"))
                .header("x-csrf-token", "a-value-the-attacker-chose")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);

    // The positive control: with the matching header the same cookie rotates.
    let with = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("host", host_for(&alpha.slug))
                .header("cookie", format!("enclave_rt={refresh_cookie}; enclave_csrf={csrf}"))
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(with.status(), StatusCode::OK, "the CSRF check must not refuse a correct request");
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

/// K16 — a caller may end their own session family and nobody else's.
///
/// The absence — "another tenant's family cannot be revoked" — is paired with the positive control
/// that the caller's own family *is* revocable through the same endpoint.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k16_a_session_that_is_not_yours_cannot_be_revoked_and_is_not_confirmed_to_exist() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let beta = &harness.fixtures.beta;

    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let somebody_elses = Uuid::new_v4();
    seed_family(&harness.db, alpha.id, alpha.owner, mine).await;
    seed_family(&harness.db, beta.id, beta.owner, theirs).await;
    seed_family(&harness.db, alpha.id, alpha.member, somebody_elses).await;

    let token = sign_in(&harness, alpha).await;
    let delete = |sid: Uuid| {
        let app = harness.app.clone();
        let slug = alpha.slug.clone();
        let token = token.clone();
        async move {
            app.oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/auth/sessions/{sid}"))
                    .header("host", host_for(&slug))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
        }
    };

    for (sid, whose) in [(theirs, "another tenant's"), (somebody_elses, "another user's")] {
        let response = delete(sid).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{whose} session must be indistinguishable from one that does not exist"
        );
    }

    // A session id nobody holds answers identically, which is the property rule 7 asks for.
    assert_eq!(delete(Uuid::new_v4()).await.status(), StatusCode::NOT_FOUND);

    // The positive control: the caller's own family is revocable, so the `404`s above are about
    // ownership rather than about the endpoint refusing everything.
    assert_eq!(delete(mine).await.status(), StatusCode::NO_CONTENT);
}

/// The session list shows the caller's families and nobody else's.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_session_list_is_the_callers_own_and_carries_the_documented_fields() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let beta = &harness.fixtures.beta;

    let mine = Uuid::new_v4();
    seed_family(&harness.db, alpha.id, alpha.owner, mine).await;
    seed_family(&harness.db, alpha.id, alpha.member, Uuid::new_v4()).await;
    seed_family(&harness.db, beta.id, beta.owner, Uuid::new_v4()).await;

    let token = sign_in(&harness, alpha).await;
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let items = body["items"].as_array().expect("items").clone();

    // The positive control: the caller's own seeded family is there.
    assert!(
        items.iter().any(|item| item["id"] == mine.to_string()),
        "the caller's own family must be listed: {body}"
    );
    // And nothing else is — neither the other user's nor the other tenant's.
    assert_eq!(items.len(), 1, "only the caller's families may be listed: {body}");
    assert_eq!(items[0]["client"], "web");
    assert!(items[0]["issuedAt"].as_str().is_some(), "{body}");
    assert_eq!(body["page"]["hasMore"], false);
}

/// `logout-all` bumps `token_epoch`, which is the only mechanism that reaches tokens already issued.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn logout_all_bumps_the_revocation_epoch() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let token = sign_in(&harness, alpha).await;

    let before = token_epoch(&harness.db, alpha.owner).await;

    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout-all")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        token_epoch(&harness.db, alpha.owner).await,
        before + 1,
        "logout-all must bump token_epoch, or the user's live access tokens keep working"
    );

    // The cookies are cleared with the same attributes they were set with, or the browser keeps
    // the original and the user is not logged out at all.
    let cookies = set_cookies(&response);
    let cleared = cookie_named(&cookies, "enclave_rt").expect("a clearing cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(cleared.contains("Path=/api/v1/auth"), "{cleared}");
    assert!(cleared.contains("HttpOnly"), "{cleared}");
}

/// A logout revokes the family, so the refresh cookie it was holding stops working.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_logout_ends_the_family_it_was_called_from() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;

    let login = harness
        .app
        .clone()
        .oneshot(login_request(
            &alpha.slug,
            &format!("owner@{}.example", alpha.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    let cookies = set_cookies(&login);
    let refresh_cookie =
        cookie_value(cookie_named(&cookies, "enclave_rt").expect("refresh")).to_owned();
    let csrf = cookie_value(cookie_named(&cookies, "enclave_csrf").expect("csrf")).to_owned();
    let token = json_body(login).await["accessToken"].as_str().expect("token").to_owned();

    let logout = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);

    let after = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("host", host_for(&alpha.slug))
                .header("cookie", format!("enclave_rt={refresh_cookie}; enclave_csrf={csrf}"))
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "a refresh token from a logged-out family must not rotate"
    );
}

/// An authenticated auth route leaves the chain's audit row behind it.
///
/// `CLAUDE.md` rule 10: the chain audits allows as well as denials, and these routes are inside it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_authenticated_auth_route_is_audited_by_the_chain() {
    let harness = harness(None).await;
    let alpha = &harness.fixtures.alpha;
    let token = sign_in(&harness, alpha).await;

    let before = allow_rows(&harness.db, alpha.id).await;

    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        allow_rows(&harness.db, alpha.id).await,
        before + 1,
        "an allowed request through an auth route must leave exactly one chain row"
    );
}

// ---------------------------------------------------------------------------------------------
// Direct-SQL helpers
// ---------------------------------------------------------------------------------------------

async fn enrol_totp(db: &TestDb, tenant: TenantId, user: UserId) {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO user_mfa_methods
           (id, tenant_id, user_id, kind, confirmed_at, created_at)
         VALUES ($1, $2, $3, 'TOTP', now(), now())",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .execute(&mut conn)
    .await
    .expect("enrol");
}

/// Seeds one live refresh family.
///
/// Written straight into `refresh_tokens` because the wired store is the in-memory one, and the
/// session endpoints read the table. That seam is the whole of `ENC-687`: once the store is
/// Postgres-backed the two are one source of truth and this helper becomes a login.
async fn seed_family(db: &TestDb, tenant: TenantId, user: UserId, session: Uuid) {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO refresh_tokens
           (id, tenant_id, session_id, actor_id, actor_type, token_hash, client_type,
            issued_at, expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, 'USER', $5, 'web', now(), now() + interval '14 days',
                 now() + interval '90 days')",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(session)
    .bind(user.as_uuid())
    .bind(Uuid::new_v4().to_string())
    .execute(&mut conn)
    .await
    .expect("seed family");
}

async fn token_epoch(db: &TestDb, user: UserId) -> i32 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar("SELECT token_epoch FROM users WHERE id = $1")
        .bind(user.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("read epoch")
}

async fn allow_rows(db: &TestDb, tenant: TenantId) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND outcome = 'ALLOW'",
    )
    .bind(tenant.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("count")
}

/// Signs the tenant's owner in and returns the access token.
async fn sign_in(harness: &Harness, tenant: &enclave_testing::TenantFixture) -> String {
    let response = harness
        .app
        .clone()
        .oneshot(login_request(
            &tenant.slug,
            &format!("owner@{}.example", tenant.slug),
            &fixture_password(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "the harness must be able to sign in");
    json_body(response).await["accessToken"].as_str().expect("token").to_owned()
}

/// Keeps `tokens` reachable for a future test that needs to drive the service directly, and keeps
/// the field from being dead code in the meantime.
#[allow(dead_code)]
fn service_of(harness: &Harness) -> &Arc<dyn TokenService> {
    &harness.tokens
}
