//! `ENC-687` — the authentication surface over the **PostgreSQL** stores.
//!
//! `crates/api/tests/auth.rs` is `ENC-685`'s suite and substitutes `InMemoryRefreshStore` and
//! `InMemoryDenylist`, because when it was written there was no other implementation. Its own
//! header says so: *"there is no Postgres-backed `RefreshTokenStore` yet (`ENC-687`)"*. Everything
//! it asserts about rotation and revocation therefore held against a `Mutex<Vec<_>>`.
//!
//! This suite is the same properties over `PgRefreshTokenStore`, `PgDenylist` and `PgSessionFacts`,
//! against a live database, and it exists to catch the class of defect the in-memory stores cannot
//! express:
//!
//! * a `rotate` that is not one transaction — the in-memory one is atomic because a `Mutex` makes
//!   it so, which proves nothing about the real one;
//! * a row whose `actor_type` or `client_type` the reader cannot decode, because the writer and the
//!   column's `CHECK` constraint disagree about the vocabulary;
//! * an epoch that is copied forward across a rotation instead of re-read, which is what makes
//!   `logout-all` mean anything;
//! * a family revocation that does not reach the table the session list reads.
//!
//! # The one thing this cannot assert
//!
//! That the *binary* wires these. A `main` is not callable from a test, and the wiring is held by
//! the compiler instead — `crates/api/src/main.rs` names `PgRefreshTokenStore` in one place and
//! `ApiState::with_auth` in one place, both in the same function. The behavioural proof that the
//! deployed process signs a user in is the transcript in `ENC-687`'s tracker row.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use enclave_api::routes::auth::AuthSurface;
use enclave_api::{router, ApiState};
use enclave_auth::{
    Argon2Params, AuthConfig, KeyProvider as _, LocalFileKeyProvider, PasswordHasher,
    PasswordPolicy, RefreshCookieConfig, TokenService, UnrestrictedRefreshGuard,
};
use enclave_core::PolicyEngine;
use enclave_db::{PgDenylist, PgRefreshTokenStore, PgSessionFacts};
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The absolute refresh lifetime this suite runs with.
///
/// Named once because it is written into `absolute_expires_at` by the issuer *and* used as the
/// divisor that recovers `auth_time` by `PgSessionFacts`. Two different values would be an
/// authentication time that never happened, and one of the tests below is exactly that assertion.
const ABSOLUTE_TTL_SECS: i64 = 90 * 86_400;

/// The password every seeded account is given.
///
/// Assembled at run time rather than written as a literal, for `CLAUDE.md` rule 11's reason in
/// miniature: a test that greps a response for its own password must not find the needle in its own
/// source.
fn fixture_password() -> String {
    format!("correct-horse-{}-battery", 42)
}

/// Argon2 at the cheapest parameters the policy accepts.
///
/// The production defaults are 64 MiB and three passes, which is right for production and turns a
/// suite that signs in a dozen times into one nobody runs. Cost is not what is being asserted here.
fn cheap_policy() -> PasswordPolicy {
    PasswordPolicy {
        min_length: 12,
        max_length: 128,
        argon2: Argon2Params { memory_kib: 8, iterations: 1, parallelism: 1 },
    }
}

struct Harness {
    app: axum::Router,
    fixtures: Fixtures,
    db: TestDb,
    tokens: Arc<dyn TokenService>,
    /// The store itself, for the one test whose property is the store's and not the service's.
    ///
    /// `k3_two_concurrent_rotations…` has to hold a barrier open *between* the lookup and the
    /// write, and `TokenService::refresh` does both inside one call. Reaching for the store there
    /// is not a shortcut around the service; it is the only place the window exists.
    store: Arc<PgRefreshTokenStore>,
}

/// Builds the router with the PostgreSQL stores behind it.
async fn harness() -> Harness {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");

    // The platform URL is the test database's own DSN: `resolve_routed_tenant` needs a connection
    // row-level security does not apply to, because `tenants` is a table the application role has
    // no grant on at all. `PgRefreshTokenStore`'s three cross-tenant statements need the same
    // connection, for the reason its module documents.
    let config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(db.url()))
        .with_application_role("enclave_app")
        .with_platform_url(enclave_db::ConnectionUrl::new(db.url()));
    let pool = enclave_db::DbPool::connect(&config).await.expect("pool");

    seed_credentials(&db, &fixtures).await;

    let key_dir = std::env::temp_dir().join(format!("enclave-pg-auth-keys-{}", Uuid::new_v4()));
    let keys = LocalFileKeyProvider::new(&key_dir);
    let key_set = enclave_auth::KeySet::new(
        keys.verification_keys().await.expect("the provider generates its first key on demand"),
    );

    let auth_config = AuthConfig {
        access_token: enclave_auth::AccessTokenConfig {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            ..Default::default()
        },
        refresh_token: enclave_auth::RefreshTokenConfig {
            idle_ttl_secs: 14 * 86_400,
            absolute_ttl_secs: ABSOLUTE_TTL_SECS,
        },
        password: cheap_policy(),
    };

    let service = enclave_auth::EnclaveTokenService::new(
        auth_config,
        keys,
        PgRefreshTokenStore::new(pool.clone()),
        PgDenylist::new(pool.clone()),
        UnrestrictedRefreshGuard,
        PgSessionFacts::new(pool.clone(), Duration::seconds(ABSOLUTE_TTL_SECS)),
    )
    .expect("valid auth configuration");
    let tokens: Arc<dyn TokenService> = Arc::new(service);

    let surface = AuthSurface::new(
        Arc::clone(&tokens),
        PasswordHasher::new(cheap_policy()).expect("hasher"),
        RefreshCookieConfig::default(),
        Duration::days(14),
    );

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(enclave_authorization::SelfServiceAuthorization),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let store = Arc::new(PgRefreshTokenStore::new(pool.clone()));
    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, key_set).with_auth(surface);
    Harness {
        app: router(state, enclave_api::Delivery::unconfigured()),
        fixtures,
        db,
        tokens,
        store,
    }
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

/// One signed-in session: the access token, the refresh cookie value and the CSRF value.
struct Session {
    access_token: String,
    refresh: String,
    csrf: String,
    session_id: String,
}

async fn sign_in(harness: &Harness, slug: &str, email: &str) -> Session {
    let response = harness
        .app
        .clone()
        .oneshot(login_request(slug, email, &fixture_password()))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "the seeded password must be accepted");

    let cookies = set_cookies(&response);
    let refresh =
        cookie_value(cookie_named(&cookies, "enclave_rt").expect("a refresh cookie")).to_owned();
    let csrf =
        cookie_value(cookie_named(&cookies, "enclave_csrf").expect("a CSRF cookie")).to_owned();
    let body = json_body(response).await;

    Session {
        access_token: body["accessToken"].as_str().expect("an access token").to_owned(),
        refresh,
        csrf,
        session_id: body["sessionId"].as_str().expect("a session id").to_owned(),
    }
}

fn refresh_request(slug: &str, session: &Session) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/refresh")
        .header("host", host_for(slug))
        .header("cookie", format!("enclave_rt={}; enclave_csrf={}", session.refresh, session.csrf))
        .header("x-csrf-token", &session.csrf)
        .body(Body::empty())
        .expect("request")
}

// ---------------------------------------------------------------------------------------------
// The property everything else rests on
// ---------------------------------------------------------------------------------------------

/// **The one that was broken.** A password login writes a real row and issues a usable token.
///
/// The absence being closed is "no refresh row was ever written to PostgreSQL", so the positive
/// control is the row itself: the session id in the response body is a `refresh_tokens` row in the
/// database, with the tenant, the actor and the client the login established.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_login_writes_a_refresh_row_and_issues_a_token_that_another_endpoint_accepts() {
    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let session = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;

    let mut conn = harness.db.connect().await.expect("connect");
    let row = sqlx::query(
        "SELECT tenant_id, actor_id, actor_type, client_type, consumed_at, revoked_at
         FROM refresh_tokens WHERE session_id = $1",
    )
    .bind(Uuid::parse_str(&session.session_id).expect("a uuid"))
    .fetch_one(&mut conn)
    .await
    .expect("the login must have written a refresh row; this is the whole of ENC-687");

    use sqlx::Row as _;
    assert_eq!(row.get::<Uuid, _>("tenant_id"), alpha.id.as_uuid());
    assert_eq!(row.get::<Uuid, _>("actor_id"), alpha.owner.as_uuid());
    // The vocabulary the column's `CHECK` accepts, not `ActorKind`'s canonical spelling. A writer
    // that used the latter would insert `user` and be refused by the constraint.
    assert_eq!(row.get::<String, _>("actor_type"), "USER");
    assert_eq!(row.get::<String, _>("client_type"), "web");
    assert!(row.get::<Option<chrono::DateTime<Utc>>, _>("consumed_at").is_none());
    assert!(row.get::<Option<chrono::DateTime<Utc>>, _>("revoked_at").is_none());

    // And the token is one the rest of the API accepts, which is what makes the row worth writing.
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {}", session.access_token))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let me = json_body(response).await;
    assert_eq!(me["id"], alpha.owner.as_uuid().to_string());
}

// ---------------------------------------------------------------------------------------------
// Rotation, against a real transaction rather than a `Mutex`
// ---------------------------------------------------------------------------------------------

/// K3 — a refresh consumes the presented row and inserts its successor, in one transaction.
///
/// Both halves are asserted in the database rather than inferred from the response, because a
/// `rotate` that committed the insert and not the update returns exactly the same `200`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k3_a_rotation_consumes_the_old_row_and_inserts_the_successor() {
    use sqlx::Row as _;

    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let session = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;

    let response = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &session))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK, "a live refresh token must rotate");
    let rotated = set_cookies(&response);
    let successor =
        cookie_value(cookie_named(&rotated, "enclave_rt").expect("a new refresh cookie"));
    assert_ne!(successor, session.refresh, "rotation means a *different* token");

    let mut conn = harness.db.connect().await.expect("connect");
    let rows = sqlx::query(
        "SELECT consumed_at, parent_id, id FROM refresh_tokens
         WHERE session_id = $1 ORDER BY issued_at",
    )
    .bind(Uuid::parse_str(&session.session_id).expect("a uuid"))
    .fetch_all(&mut conn)
    .await
    .expect("query");

    assert_eq!(rows.len(), 2, "one family, two rows: the consumed one and its successor");
    let first_id: Uuid = rows[0].get("id");
    assert!(
        rows[0].get::<Option<chrono::DateTime<Utc>>, _>("consumed_at").is_some(),
        "the presented token must be consumed, or two tokens in the family are live at once"
    );
    assert!(
        rows[1].get::<Option<chrono::DateTime<Utc>>, _>("consumed_at").is_none(),
        "the successor must be usable"
    );
    assert_eq!(
        rows[1].get::<Option<Uuid>, _>("parent_id"),
        Some(first_id),
        "the rotation chain is what makes a replay attributable to a point in the family"
    );
}

/// **K3's real content.** Two rotations that both read the token before either writes.
///
/// This is the property the in-memory store cannot say anything about, and the reason
/// `InMemoryRefreshStore` documents itself as *"not a substitute for the PostgreSQL
/// implementation: `rotate` here is atomic because a `Mutex` makes it so, which proves nothing
/// about the transaction the real store must use."*
///
/// # Why the barrier is where it is
///
/// The first version of this test raced two `TokenService::refresh` calls and **passed against a
/// broken store** — because `refresh` looks the token up and then rotates it, so the loser's
/// lookup saw `consumed_at` already set and `classify` refused it before `rotate` was ever
/// reached. It was measuring the classification, which is pure Rust, and the sequential tests
/// already cover that.
///
/// So both contenders look the row up *first*, meet at a barrier, and only then call `rotate`.
/// That is `docs/12-TESTING.md §4.4` H3's arrangement — *the difference between a concurrency test
/// and a sequential one wearing `tokio::spawn`* — and it puts the barrier in the one window where
/// the store is the only thing deciding.
///
/// What decides is the `consumed_at IS NULL` predicate inside the `UPDATE`: the second transaction
/// blocks on the row lock, re-evaluates the predicate against the committed value, and matches zero
/// rows. Delete that predicate and both callers commit a successor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k3_two_concurrent_rotations_of_one_token_produce_exactly_one_successor() {
    use enclave_auth::RefreshTokenStore as _;

    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;

    let pair = harness
        .tokens
        .issue_pair(&enclave_auth::AuthContext {
            tenant_id: alpha.id,
            actor: enclave_core::Actor::User(alpha.owner),
            session_id: None,
            client: enclave_core::ClientType::Web,
            device_id: None,
            scopes: enclave_core::ScopeSet::empty(),
            methods: vec![enclave_auth::AuthMethod::Pwd],
            auth_time: Utc::now(),
            epoch: 1,
            max_classification: None,
        })
        .await
        .expect("issue");
    let presented = pair.refresh_token.expect("a web session gets a refresh token");
    let digest = presented.digest().to_hex();
    let family = pair.session_id;

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0_u8..2 {
        let store = Arc::clone(&harness.store);
        let digest = digest.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            // Both contenders read the row while it is still unconsumed. Nothing in Rust separates
            // them from here on.
            let record = store
                .find_by_hash(&digest)
                .await
                .expect("the lookup must succeed")
                .expect("the row this test just wrote");
            assert!(record.consumed_at.is_none(), "both contenders must read a live row");

            let successor = enclave_auth::RefreshRecord {
                id: Uuid::new_v4(),
                token_hash: enclave_auth::RefreshToken::generate()
                    .expect("entropy")
                    .digest()
                    .to_hex(),
                parent_id: Some(record.id),
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::days(14),
                ..record.clone()
            };

            barrier.wait().await;
            store.rotate(record.id, successor, Utc::now()).await.is_ok()
        }));
    }

    let mut succeeded = 0_u8;
    for handle in handles {
        if handle.await.expect("the task must not panic") {
            succeeded += 1;
        }
    }
    assert_eq!(
        succeeded, 1,
        "exactly one of two concurrent rotations may succeed: two would leave two live tokens in \
         one family, which is the state reuse detection exists to be able to rule out"
    );

    let mut conn = harness.db.connect().await.expect("connect");
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens
         WHERE session_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("query");
    assert_eq!(live, 1, "{live} tokens are live in one family after a concurrent rotation");

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE session_id = $1")
        .bind(family.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("query");
    assert_eq!(
        rows, 2,
        "the loser must have inserted nothing: the original and exactly one successor"
    );

    // The positive control for both counts: the presented row *was* consumed, so this is not
    // passing against a race in which neither contender did anything.
    let consumed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND consumed_at IS NOT NULL",
    )
    .bind(family.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("query");
    assert_eq!(consumed, 1, "the presented token was consumed exactly once");
}

/// K4 — presenting a consumed token destroys the family, and does so in the database.
///
/// The response half of this is `crates/api/tests/auth.rs`'s. What is new here is the *state*: the
/// in-memory store could report a replay and leave the family intact in PostgreSQL, because
/// PostgreSQL held no family at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn k4_a_replayed_token_revokes_every_row_in_the_family() {
    use sqlx::Row as _;

    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let session = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;

    // Rotate once, so the presented token is consumed rather than unknown.
    let first = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &session))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::OK, "positive control: the first refresh succeeds");

    let replay = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &session))
        .await
        .expect("response");
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(replay).await;
    assert_eq!(body["error"]["code"], "SESSION_REPLAY", "{body}");

    let family = Uuid::parse_str(&session.session_id).expect("a uuid");
    let mut conn = harness.db.connect().await.expect("connect");

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens
         WHERE session_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL",
    )
    .bind(family)
    .fetch_one(&mut conn)
    .await
    .expect("query");
    assert_eq!(live, 0, "a detected theft must leave nothing in the family usable");

    // The reason is recorded, so incident response can tell a theft from a logout.
    let reasons: Vec<String> = sqlx::query(
        "SELECT revoke_reason FROM refresh_tokens WHERE session_id = $1 AND revoke_reason IS NOT NULL",
    )
    .bind(family)
    .fetch_all(&mut conn)
    .await
    .expect("query")
    .iter()
    .map(|row| row.get::<String, _>("revoke_reason"))
    .collect();
    assert!(reasons.contains(&"SESSION_REPLAY".to_owned()), "{reasons:?}");

    // And the access tokens the family issued are denied by `sid`, which is `PgDenylist`'s
    // `deny_session`. Without this the refresh family is dead and its ten-minute access token is
    // not.
    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM token_revocations WHERE tenant_id = $1 AND jti = $2",
    )
    .bind(alpha.id.as_uuid())
    .bind(family)
    .fetch_one(&mut conn)
    .await
    .expect("query");
    assert_eq!(denied, 1, "the family's outstanding access tokens must be denylisted");
}

// ---------------------------------------------------------------------------------------------
// What a rotation re-resolves rather than copying
// ---------------------------------------------------------------------------------------------

/// The epoch is **re-read** at rotation, not carried forward.
///
/// This is what makes `logout-all` mean anything: it bumps `users.token_epoch`, and every token
/// minted afterwards has to carry the new value or the bump revokes nothing. The in-memory
/// `SessionFactsProvider` in `ENC-685`'s suite returns a constant, so this property had no test.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_token_epoch_is_re_read_at_rotation_rather_than_copied_forward() {
    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let session = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;
    assert_eq!(epoch_claim(&session.access_token), 1, "the seeded epoch");

    // Bump it behind the session's back, the way `POST /auth/logout-all` does.
    let mut conn = harness.db.connect().await.expect("connect");
    sqlx::query("UPDATE users SET token_epoch = token_epoch + 1 WHERE id = $1")
        .bind(alpha.owner.as_uuid())
        .execute(&mut conn)
        .await
        .expect("bump");

    let response = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &session))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let rotated = body["accessToken"].as_str().expect("an access token");

    assert_eq!(
        epoch_claim(rotated),
        2,
        "the rotated token carries the epoch it was minted under, not the one the family started \
         with — otherwise a refresh chain is immune to mass revocation"
    );
}

/// `auth_time` survives a rotation unchanged, because a max-age policy measures from the
/// authentication and not from the last rotation.
///
/// `refresh_tokens` stores no `auth_time`; `PgSessionFacts` recovers it as
/// `absolute_expires_at - absolute_ttl`, and this is the assertion that the two agree about the
/// lifetime. A provider configured with a different `absolute_ttl` than the issuer would report an
/// authentication time that never happened, and nothing else would notice.
///
/// # It takes an aged family *and* two rotations, and both are the point
///
/// This test was written twice before it held anything, and both failures are worth recording
/// because they are the same mistake in two disguises.
///
/// 1. A sign-in followed immediately by one rotation cannot distinguish `auth_time` from anything:
///    the authentication, the row's `issued_at` and the current instant are all the same second. It
///    passed against a provider returning `record.issued_at`.
/// 2. Ageing the family fixes the *instant* but not the *row*: on a **first** rotation the
///    presented row is the original one, whose `issued_at` genuinely is the authentication. Ageing
///    moves both together, so `record.issued_at` was still the right answer by accident.
///
/// The difference only exists from the second rotation onwards, where the presented row is a
/// successor issued long after the login. So: age the family by an hour, rotate once — producing a
/// successor stamped *now* — and rotate again. Now `record.issued_at` is an hour away from the
/// authentication and only one of the two candidate values is correct.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn auth_time_is_unchanged_by_a_rotation() {
    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let session = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;
    let at_login = claim_i64(&session.access_token, "auth_time");

    // Age the whole family by an hour, consistently: `absolute_expires_at` is anchored to the
    // authentication, so a fixture that moved one and not the other would be asserting against a
    // row the issuer could not have written.
    let mut conn = harness.db.connect().await.expect("connect");
    sqlx::query(
        "UPDATE refresh_tokens
            SET issued_at = issued_at - interval '1 hour',
                absolute_expires_at = absolute_expires_at - interval '1 hour'
          WHERE session_id = $1",
    )
    .bind(Uuid::parse_str(&session.session_id).expect("a uuid"))
    .execute(&mut conn)
    .await
    .expect("age the family");

    // First rotation: the presented row is the original, whose `issued_at` *is* the authentication.
    // Its successor is stamped now, an hour later.
    let first = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &session))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::OK, "positive control: the aged family still refreshes");
    let cookies = set_cookies(&first);
    let second_session = Session {
        access_token: String::new(),
        refresh: cookie_value(cookie_named(&cookies, "enclave_rt").expect("a refresh cookie"))
            .to_owned(),
        csrf: cookie_value(cookie_named(&cookies, "enclave_csrf").expect("a CSRF cookie"))
            .to_owned(),
        session_id: session.session_id.clone(),
    };

    // Second rotation: the presented row is that successor, and the two candidate values are now
    // an hour apart.
    let response = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &second_session))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let rotated = body["accessToken"].as_str().expect("an access token");
    let after = claim_i64(rotated, "auth_time");

    // An hour before the sign-in claim, because that is where the fixture put the authentication.
    // One second of tolerance: both values are derived from timestamps PostgreSQL rounded to
    // microseconds, so exact equality would be asserting the driver's precision.
    let expected = at_login - 3_600;
    let issued = claim_i64(rotated, "iat");
    assert!(
        (after - expected).abs() <= 1,
        "auth_time is {after}, expected {expected}: a rotation must report the authentication and \
         not the rotation. A provider returning the presented row's issued_at would report a value \
         near iat, which is {issued}"
    );

    // The positive control, so the assertion above is not passing against a token with no claims:
    // `iat` is *now* and therefore about an hour later than `auth_time`, which is the whole
    // distinction being drawn.
    assert!(
        issued - after >= 3_500,
        "iat {issued} and auth_time {after} must be an hour apart, or the fixture did not age \
         anything and this test proves nothing"
    );
}

// ---------------------------------------------------------------------------------------------
// Revocation reaches the table
// ---------------------------------------------------------------------------------------------

/// `revoke_all_for_user` revokes every family the subject holds — across sessions, in one call.
///
/// Driven through the `TokenService` rather than the route, because the route needs a bearer token
/// per session and what is under test is the store's cross-tenant statement.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn revoking_a_subject_reaches_every_family_and_leaves_other_subjects_alone() {
    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;

    let owner_a = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;
    let owner_b = sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug)).await;
    let member = sign_in(&harness, &alpha.slug, &format!("member@{}.example", alpha.slug)).await;

    harness
        .tokens
        .revoke_all_for_user(alpha.owner, enclave_auth::RevokeReason::LogoutAll)
        .await
        .expect("revoke");

    for ended in [&owner_a, &owner_b] {
        let response = harness
            .app
            .clone()
            .oneshot(refresh_request(&alpha.slug, ended))
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "every one of the subject's families must be gone"
        );
    }

    // The positive control, and the one that makes the two refusals mean something: another
    // subject's family is untouched. A `revoke_all_for_subject` that dropped its `WHERE actor_id`
    // predicate would pass the first half of this test and fail here.
    let response =
        harness.app.clone().oneshot(refresh_request(&alpha.slug, &member)).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK, "a different subject's session must survive");
}

/// A refresh token's tenancy comes from its stored row, never from the host it was presented on.
///
/// This is the property that makes [`enclave_db::PgRefreshTokenStore::find_by_hash`] safe despite
/// running on the connection row-level security does not apply to. The lookup is keyed on the
/// digest of a token the server minted, so it resolves the row *and its tenant*; the routed host is
/// not an input to it at all.
///
/// # What this test found, and deliberately records rather than fixes
///
/// The first version asserted that the resulting token was refused on alpha's host. It is not, and
/// the reason is `ENC-689`: `crate::auth::Authenticated` — which serves `GET /api/v1/me` and every
/// other route — does **not** compare the token's `tid` against the routed host. Only
/// `routes::auth::AuthenticatedHere` does, and it covers the four session-management routes.
///
/// That is not a tenancy leak, and the assertions below are what say so: the beta token acts as
/// *beta*, wherever it is presented. `Host` is a client-supplied header, so a caller who could move
/// tenants by changing it would be choosing their own tenancy — non-negotiable rule 3 — and what
/// actually happens is that the header is ignored and `tid` decides. The cost is a diagnostic one
/// and `ENC-689` owns it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_refresh_tokens_tenancy_comes_from_its_row_and_not_from_the_host() {
    let harness = harness().await;
    let alpha = &harness.fixtures.alpha;
    let beta = &harness.fixtures.beta;

    let beta_session = sign_in(&harness, &beta.slug, &format!("owner@{}.example", beta.slug)).await;

    // Presented on alpha's host. The row exists and the digest matches.
    let response = harness
        .app
        .clone()
        .oneshot(refresh_request(&alpha.slug, &beta_session))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = json_body(response).await;
    let token = body["accessToken"].as_str().expect("an access token").to_owned();
    assert_eq!(
        claim_str(&token, "tid"),
        beta.id.as_uuid().to_string(),
        "the token was minted for beta, because the stored row says beta"
    );
    // The absence that matters, stated directly: alpha's id is nowhere in it.
    assert_ne!(claim_str(&token, "tid"), alpha.id.as_uuid().to_string());

    // And it acts as beta wherever it is presented. `GET /api/v1/me` on alpha's host answers with
    // beta's user and beta's tenant — the host is not consulted, so it cannot move anybody.
    let me = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(me.status(), StatusCode::OK);
    let me = json_body(me).await;
    assert_eq!(
        me["tenantId"],
        beta.id.as_uuid().to_string(),
        "a beta token on alpha's host must still be inside beta"
    );
    assert_eq!(me["id"], beta.owner.as_uuid().to_string());

    // The session-management routes *do* compare the two, which is what makes the paragraph above
    // a scope statement rather than an excuse. `GET /api/v1/auth/sessions` uses
    // `AuthenticatedHere`.
    let sessions = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&alpha.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        sessions.status(),
        StatusCode::UNAUTHORIZED,
        "the routes that check the routed host against `tid` must refuse this"
    );

    // The positive control for that refusal: the same request on beta's own host is allowed, so it
    // is the host disagreeing and not the token being bad.
    let same = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/sessions")
                .header("host", host_for(&beta.slug))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(same.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Claim helpers
// ---------------------------------------------------------------------------------------------

/// One claim out of a compact JWS, without verifying it.
///
/// Reading an unverified payload is fine *in a test asserting what was minted* — the signature is
/// what `crates/auth` verifies, and every test above that uses a token also uses it against a route
/// that does verify.
fn claims(token: &str) -> serde_json::Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("a compact JWS has three segments");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("the payload is base64url");
    serde_json::from_slice(&bytes).expect("the payload is JSON")
}

fn claim_i64(token: &str, name: &str) -> i64 {
    claims(token)[name].as_i64().unwrap_or_else(|| panic!("no `{name}` claim"))
}

fn claim_str(token: &str, name: &str) -> String {
    claims(token)[name].as_str().unwrap_or_else(|| panic!("no `{name}` claim")).to_owned()
}

fn epoch_claim(token: &str) -> i64 {
    claim_i64(token, "epoch")
}
