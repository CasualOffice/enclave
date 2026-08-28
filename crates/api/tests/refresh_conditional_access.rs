//! `ENC-709` — a refresh is decided against the request it is actually on, not the one that created
//! the session.
//!
//! `docs/03-LLD.md §5.3` rule 3 and leakage row `K6`: *a user who moves outside an allowed network
//! zone loses access within one access-token lifetime, and refresh is where that is noticed.* Until
//! this suite, `crates/api/src/main.rs` wired `UnrestrictedRefreshGuard` — every rotation was
//! permitted — so the bound was the refresh lifetime, fourteen days.
//!
//! # The test that is the bug
//!
//! [`a_session_stops_refreshing_when_the_rule_that_allowed_it_is_tightened`]. Sign in from an
//! address the tenant permits, *then* store a rule that no longer permits it, then refresh from the
//! same address. A test that only refused a refresh from an already-blocked address would prove
//! nothing about re-evaluation, because a session could never have been created from there in the
//! first place.
//!
//! # Every refusal here is paired with a positive control, in the same run
//!
//! `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "The refresh was
//! refused" is satisfied by a bad cookie, a missing CSRF header, a store that is down, a route that
//! was never registered, and a guard that refuses everything. So each refusal is asserted beside a
//! *successful* refresh of the **same session**, through the **same handler**, differing only in the
//! address the request arrived from — the one variable under test.
//!
//! # Which layer each cross-tenant assertion proves
//!
//! [`one_tenants_rule_does_not_refuse_another_tenants_refresh`] proves **isolation of the rule
//! load**, and it proves it at the layer `TenantConditionalAccess::load` sits on: `pool.begin(tenant)`
//! opens the transaction under that tenant's row-level-security context, and
//! `enclave_db::load_rules` carries its own `tenant_id` predicate. Removing the predicate alone
//! leaves this test green, because RLS holds the property on its own — that is `docs/12 §4.1`'s `T5`
//! as a designed property of two layers, and it is why the predicate has its own unit test in
//! `enclave_db::conditional_access` rather than being asserted from here. What this test *can*
//! catch is the leak: with the predicate removed **and** the migration's policy weakened, beta's
//! refresh is refused by alpha's rule and it fails.
//!
//! It does not prove RLS at the refresh-token layer. `refresh_tokens` is looked up by digest across
//! tenants deliberately (`crates/db/src/auth_tokens.rs`), and the tenant a refusal is audited
//! against is read from the stored row rather than from anything a caller sent.
//!
//! # The superuser trap
//!
//! The pool is opened with `application_role = enclave_app`, never as the harness superuser, which
//! bypasses row-level security entirely. A cross-tenant assertion run as a superuser proves nothing
//! (PR #22, `ENC-124`).
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::net::SocketAddr;
use core::time::Duration as StdDuration;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::Duration;
use enclave_api::routes::auth::AuthSurface;
use enclave_api::{router, ApiState, ChainRefreshGuard, Edge};
use enclave_auth::{
    Argon2Params, AuthConfig, KeyProvider as _, LocalFileKeyProvider, PasswordHasher,
    PasswordPolicy, RefreshCookieConfig,
};
use enclave_conditional_access::{
    encode_human, Effect, HumanCondition, HumanRule, NetworkZone, ProxyTrust,
    TenantConditionalAccess, ZoneMap,
};
use enclave_config::TrustedProxy;
use enclave_core::{ClientType, PolicyEngine, TenantId, UserId};
use enclave_db::{insert_rule, PgDenylist, PgRefreshTokenStore, PgSessionFacts, RuleId};
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";
const ABSOLUTE_TTL_SECS: i64 = 90 * 86_400;

/// The zone this deployment defines. Rules refer to it by name; addresses fall inside it or do not.
const DATACENTRE: &str = "Datacenter";

/// Inside [`DATACENTRE`].
const PERMITTED: &str = "198.51.100.7";

/// Outside every zone — and the address every session in this file is *created* from, which is the
/// whole point: it has to be permitted at sign-in and refused after the tightening.
const ORDINARY: &str = "203.0.113.10";

/// The proxy address the forwarding tests connect from.
const PROXY: &str = "10.0.0.7";

/// Assembled at run time rather than written as a literal, for `CLAUDE.md` rule 11's reason in
/// miniature: a test that greps a response for its own password must not find the needle in its own
/// source.
fn fixture_password() -> String {
    format!("correct-horse-{}-battery", 42)
}

/// Argon2 at the cheapest parameters the policy accepts. Cost is not what is being asserted here.
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
    pool: enclave_db::DbPool,
}

/// The composed surface, with the **real** conditional-access stage behind the refresh guard.
///
/// Two deliberate choices:
///
/// * The cache TTL is `ZERO`, so a stored rule applies to the very next request. A suite asserting
///   *rules* must not accidentally be asserting the cache — `crates/conditional_access/tests/
///   stored_rules.rs` makes the same choice and tests the cache separately. What the production
///   default means for a tightening (fifteen seconds, on every replica) is documented at
///   `TenantConditionalAccess::cache_ttl` and in `crates/api/src/refresh_guard.rs`.
/// * Every stage *after* conditional access is `DenyAll`. That is the control for the claim that a
///   refresh runs one stage and not the chain: if `reevaluate_conditional_access` ever grew into
///   `enforce`, every successful refresh in this file would fail with `ACCESS_DENIED` from
///   authorization.
async fn harness(edge: Edge) -> Harness {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");

    let config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(db.url()))
        .with_application_role("enclave_app")
        .with_platform_url(enclave_db::ConnectionUrl::new(db.url()));
    let pool = enclave_db::DbPool::connect(&config).await.expect("pool");

    seed_credentials(&db, &fixtures).await;

    let key_dir = std::env::temp_dir().join(format!("enclave-refresh-ca-keys-{}", Uuid::new_v4()));
    let keys = LocalFileKeyProvider::new(&key_dir);
    let key_set = enclave_auth::KeySet::new(
        keys.verification_keys().await.expect("the provider generates its first key on demand"),
    );

    let policy = PolicyEngine::new(
        Arc::new(
            TenantConditionalAccess::new(pool.clone(), zones()).with_cache_ttl(StdDuration::ZERO),
        ),
        Arc::new(enclave_core::engine::stub::DenyAll),
        Arc::new(enclave_core::engine::stub::DenyAll),
        Arc::new(enclave_core::engine::stub::DenyAll),
        Arc::new(enclave_core::engine::stub::DenyAll),
        Arc::new(enclave_core::engine::stub::DenyAll),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
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
        // The subject of this suite. `main.rs` wires the same type over the same engine.
        ChainRefreshGuard::new(policy.clone()),
        PgSessionFacts::new(pool.clone(), Duration::seconds(ABSOLUTE_TTL_SECS)),
    )
    .expect("valid auth configuration");

    let surface = AuthSurface::new(
        Arc::new(service),
        PasswordHasher::new(cheap_policy()).expect("hasher"),
        RefreshCookieConfig::default(),
        Duration::days(14),
    );

    let state = ApiState::new(policy, pool.clone(), ISSUER, AUDIENCE, key_set)
        .with_edge(edge)
        .with_auth(surface);

    Harness { app: router(state, enclave_api::Delivery::unconfigured()), fixtures, db, pool }
}

fn zones() -> ZoneMap {
    ZoneMap::new([NetworkZone::new(
        DATACENTRE,
        ["198.51.100.0/24".parse().expect("a fixture prefix")],
    )])
}

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

/// Stores one human rule for `tenant`. This is the "administrator tightens the rules" step.
async fn store_rule(
    pool: &enclave_db::DbPool,
    tenant: TenantId,
    author: UserId,
    rule: &HumanRule,
) -> RuleId {
    let id = RuleId::new_v7();
    let row = encode_human(id, rule).expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_rule(&mut tx, &row, author).await.expect("insert the rule");
    tx.commit().await.expect("commit");
    id
}

/// *"Web sessions must be on the datacenter network."*
///
/// Two conditions would be one too many here: the rule has to fire on the refresh's own action
/// (`container.read` against the caller's own principal), and a rule scoped to file actions could
/// not. `ClientIs([Web])` is what keeps it from being a rule that refuses literally everything —
/// an API or MCP caller is unaffected, which is visible in the machine/human split rather than
/// asserted here.
fn datacentre_only() -> HumanRule {
    HumanRule::new(
        "web sessions must be on the datacenter network",
        vec![HumanCondition::ClientIs(vec![ClientType::Web])],
        Effect::RequireTrustedNetwork,
    )
}

fn host_for(slug: &str) -> String {
    format!("{slug}.enclave.test")
}

/// A request that arrived on a real socket from `peer`.
///
/// `ConnectInfo` is what `Edge::network_context` reads; a router driven by `oneshot` has none
/// unless it is put there, and without it every address is `NetworkContext::unknown` and every
/// network rule refuses — which would make every refusal in this file pass for free.
fn from_peer(mut request: Request<Body>, peer: &str) -> Request<Body> {
    let addr: SocketAddr = format!("{peer}:51000").parse().expect("a fixture socket address");
    let _ = request.extensions_mut().insert(ConnectInfo(addr));
    request
}

fn login_request(slug: &str, email: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("host", host_for(slug))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "email": email, "password": fixture_password() }).to_string(),
        ))
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

/// One signed-in session.
#[derive(Clone)]
struct Session {
    refresh: String,
    csrf: String,
    session_id: String,
}

/// Signs in from `peer`, which is the address the session is *created* from.
async fn sign_in(harness: &Harness, slug: &str, email: &str, peer: &str) -> Session {
    let response = harness
        .app
        .clone()
        .oneshot(from_peer(login_request(slug, email), peer))
        .await
        .expect("response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the session has to be creatable from {peer}, or the tightening below proves nothing"
    );

    let cookies = set_cookies(&response);
    let refresh =
        cookie_value(cookie_named(&cookies, "enclave_rt").expect("a refresh cookie")).to_owned();
    let csrf =
        cookie_value(cookie_named(&cookies, "enclave_csrf").expect("a CSRF cookie")).to_owned();
    let body = json_body(response).await;

    Session {
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

/// Refreshes from `peer`, returning the whole response so a test can read the status *and* the
/// envelope.
async fn refresh_from(
    harness: &Harness,
    slug: &str,
    session: &Session,
    peer: &str,
) -> axum::response::Response {
    harness
        .app
        .clone()
        .oneshot(from_peer(refresh_request(slug, session), peer))
        .await
        .expect("response")
}

/// The successor cookies a successful refresh set, so a test can carry the session forward.
fn rotate(session: &Session, response: &axum::response::Response) -> Session {
    let cookies = set_cookies(response);
    Session {
        refresh: cookie_named(&cookies, "enclave_rt")
            .map_or_else(|| session.refresh.clone(), |c| cookie_value(c).to_owned()),
        csrf: cookie_named(&cookies, "enclave_csrf")
            .map_or_else(|| session.csrf.clone(), |c| cookie_value(c).to_owned()),
        session_id: session.session_id.clone(),
    }
}

/// The conditional-access denials recorded for one tenant, newest last.
async fn denials(harness: &Harness, tenant: TenantId) -> Vec<(String, String, Option<String>)> {
    use sqlx::Row as _;
    let mut conn = harness.db.connect().await.expect("connect");
    sqlx::query(
        "SELECT outcome, reason_code, policy_refs::text AS refs, detail::text AS detail
           FROM audit_events
          WHERE tenant_id = $1 AND outcome = 'DENY'
          ORDER BY occurred_at, sequence",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read audit_events")
    .into_iter()
    .map(|row| {
        (
            row.get::<String, _>("outcome"),
            row.get::<Option<String>, _>("reason_code").unwrap_or_default(),
            row.get::<Option<String>, _>("refs"),
        )
    })
    .collect()
}

// ---------------------------------------------------------------------------------------------
// The one that is the bug
// ---------------------------------------------------------------------------------------------

/// **K6.** A session created from a permitted address stops refreshing once the rule that permitted
/// it is tightened — and the *same* session, refreshing from an address the new rule permits,
/// still succeeds in the same run.
///
/// The sequence is the defect written out:
///
/// 1. sign in from `203.0.113.10`, which no rule forbids because there are no rules;
/// 2. refresh from the same address — this succeeds, and it is what makes step 4 mean
///    "re-evaluation happened" rather than "refresh is broken";
/// 3. an administrator stores `RequireTrustedNetwork` for web clients;
/// 4. refresh from `203.0.113.10` again — **now refused**, `403 NETWORK_NOT_ALLOWED`;
/// 5. refresh with the very same token from `198.51.100.7`, inside the zone — accepted.
///
/// Step 5 is doing three jobs. It is the positive control for step 4; it proves the refusal did not
/// consume the token, so a transient policy change cannot log a user out permanently; and it proves
/// the decision is taken against *this request's* address rather than against anything stored on
/// the session.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_session_stops_refreshing_when_the_rule_that_allowed_it_is_tightened() {
    let harness = harness(Edge::new(ProxyTrust::none(), zones())).await;
    let alpha = harness.fixtures.alpha.clone();

    let session =
        sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug), ORDINARY).await;

    // 2. Before the tightening. This is the control the whole test rests on.
    let before = refresh_from(&harness, &alpha.slug, &session, ORDINARY).await;
    assert_eq!(
        before.status(),
        StatusCode::OK,
        "with no rule stored, a refresh from {ORDINARY} must succeed — otherwise the refusal \
         below is not evidence of anything"
    );
    let session = rotate(&session, &before);

    // 3. The administrator tightens.
    let _rule = store_rule(&harness.pool, alpha.id, alpha.admin, &datacentre_only()).await;

    // 4. The defect, closed.
    let after = refresh_from(&harness, &alpha.slug, &session, ORDINARY).await;
    assert_eq!(
        after.status(),
        StatusCode::FORBIDDEN,
        "ENC-709: the session was created from an address the tenant now forbids, and the \
         rotation renewed it anyway"
    );
    let body = json_body(after).await;
    assert_eq!(body["error"]["code"], "NETWORK_NOT_ALLOWED", "docs/05-API.md §3.2: {body}");

    // The refusal names a class, never the rule. `docs/05 §5`: denials do not disclose which policy
    // matched.
    let rendered = body.to_string();
    assert!(
        !rendered.contains("datacenter network"),
        "the refusal disclosed the rule that produced it: {rendered}"
    );
    assert!(
        !rendered.contains(&session.refresh),
        "the refusal echoed the presented refresh token: CLAUDE.md rule 10"
    );

    // 5. The positive control: same session, same handler, an address the new rule permits.
    let permitted = refresh_from(&harness, &alpha.slug, &session, PERMITTED).await;
    assert_eq!(
        permitted.status(),
        StatusCode::OK,
        "the same unconsumed token must still rotate from inside the zone — a refusal that \
         destroyed the session would make this test pass for the wrong reason"
    );
    assert!(
        cookie_named(&set_cookies(&permitted), "enclave_rt").is_some(),
        "a successful refresh issues a successor cookie"
    );
}

/// **Rule 10.** The refusal is in `audit_events`, as a `DENY` attributed to the conditional-access
/// stage, against the tenant the *stored family* named — and it carries no credential.
///
/// Asserted separately from the behaviour above because the two fail independently: a guard could
/// refuse correctly and record nothing, which is exactly the `ENC-606` defect one layer along, and
/// `xtask audit-coverage` named this refusal as the gap `ENC-710` owned.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_refusal_is_recorded_as_a_denial_and_carries_no_credential() {
    let harness = harness(Edge::new(ProxyTrust::none(), zones())).await;
    let alpha = harness.fixtures.alpha.clone();

    let session =
        sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug), ORDINARY).await;
    assert!(
        denials(&harness, alpha.id).await.is_empty(),
        "nothing has been refused yet; a row here would make the assertion below vacuous"
    );

    let _rule = store_rule(&harness.pool, alpha.id, alpha.admin, &datacentre_only()).await;
    let refused = refresh_from(&harness, &alpha.slug, &session, ORDINARY).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    let rows = denials(&harness, alpha.id).await;
    assert_eq!(rows.len(), 1, "exactly one denial should have been recorded: {rows:?}");
    let (outcome, reason, refs) = &rows[0];
    assert_eq!(outcome, "DENY");
    assert_eq!(reason, "NETWORK_NOT_ALLOWED", "the row and the caller must read the same word");
    assert!(
        refs.as_deref().unwrap_or_default().contains("conditional_access"),
        "the denial must be attributed to the stage that took it: {refs:?}"
    );

    // Nothing in the tenant's whole audit trail carries the credential.
    use sqlx::Row as _;
    let mut conn = harness.db.connect().await.expect("connect");
    let dump: Vec<String> = sqlx::query(
        "SELECT coalesce(detail::text, '') || coalesce(policy_refs::text, '') AS blob
           FROM audit_events WHERE tenant_id = $1",
    )
    .bind(alpha.id.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read audit_events")
    .into_iter()
    .map(|row| row.get::<String, _>("blob"))
    .collect();
    assert!(!dump.is_empty(), "there are rows to search, or the search below proves nothing");
    for blob in &dump {
        assert!(!blob.contains(&session.refresh), "an audit row carried the refresh token");
        assert!(!blob.contains(&session.csrf), "an audit row carried the CSRF token");
    }
}

// ---------------------------------------------------------------------------------------------
// Cross-tenant
// ---------------------------------------------------------------------------------------------

/// One tenant's rule refuses that tenant's refresh and is invisible to the other's.
///
/// The negative half — beta is not refused — passes for free against a guard that refuses nothing,
/// so alpha's identical refresh is refused in the same run, from the same address, through the same
/// router. Both fixtures are the seeded `tenant-alpha`/`tenant-beta` pair.
///
/// Layer: this is the rule *load*, under `enclave_app` with row-level security in force. See the
/// module header for what each of the two layers holds on its own.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_rule_does_not_refuse_another_tenants_refresh() {
    let harness = harness(Edge::new(ProxyTrust::none(), zones())).await;
    let alpha = harness.fixtures.alpha.clone();
    let beta = harness.fixtures.beta.clone();

    let alpha_session =
        sign_in(&harness, &alpha.slug, &format!("owner@{}.example", alpha.slug), ORDINARY).await;
    let beta_session =
        sign_in(&harness, &beta.slug, &format!("owner@{}.example", beta.slug), ORDINARY).await;

    store_rule(&harness.pool, alpha.id, alpha.admin, &datacentre_only()).await;

    // The positive control first: the tenant that wrote the rule is refused by it.
    let alpha_refresh = refresh_from(&harness, &alpha.slug, &alpha_session, ORDINARY).await;
    assert_eq!(
        alpha_refresh.status(),
        StatusCode::FORBIDDEN,
        "the tenant that wrote the rule must be refused by it, or the absence below is vacuous"
    );

    // The absence, against a request that differs only in whose tenant it is.
    let beta_refresh = refresh_from(&harness, &beta.slug, &beta_session, ORDINARY).await;
    let beta_status = beta_refresh.status();
    let beta_session = rotate(&beta_session, &beta_refresh);
    assert_eq!(
        beta_status,
        StatusCode::OK,
        "tenant-beta's refresh was decided against tenant-alpha's rule: {:?}",
        json_body(beta_refresh).await
    );

    // The mirror. A leak in one direction only is still a leak, and a test that checked one
    // direction would pass against a decoder that pinned the first tenant it ever saw.
    store_rule(&harness.pool, beta.id, beta.admin, &datacentre_only()).await;
    let beta_now = refresh_from(&harness, &beta.slug, &beta_session, ORDINARY).await;
    assert_eq!(
        beta_now.status(),
        StatusCode::FORBIDDEN,
        "tenant-beta's own rule must refuse tenant-beta"
    );
    let alpha_inside = refresh_from(&harness, &alpha.slug, &alpha_session, PERMITTED).await;
    assert_eq!(
        alpha_inside.status(),
        StatusCode::OK,
        "tenant-alpha was refused from inside its own zone by tenant-beta's rule"
    );

    // And the denials landed in the two tenants' own chains, one each.
    assert_eq!(denials(&harness, alpha.id).await.len(), 1);
    assert_eq!(denials(&harness, beta.id).await.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Where the address comes from — `CLAUDE.md` rule 3, in both configurations
// ---------------------------------------------------------------------------------------------

/// With `server.trusted_proxies` empty — the default, which the binary warns about — the socket peer
/// is the client address and `X-Forwarded-For` is not read.
///
/// The refusal is paired with its control in the same run: the identical header, with the identical
/// peer, is honoured once the peer is a configured proxy. A resolver that ignored the header
/// unconditionally would pass the first half and fail the second; one that believed it
/// unconditionally would fail the first.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_forwarded_address_cannot_buy_a_refresh_a_zone_it_is_not_in() {
    // Configuration 1: no trusted proxy. The peer is a proxy address, and the header claims to be
    // inside the datacentre.
    let untrusting = harness(Edge::new(ProxyTrust::none(), zones())).await;
    let alpha = untrusting.fixtures.alpha.clone();
    let session =
        sign_in(&untrusting, &alpha.slug, &format!("owner@{}.example", alpha.slug), ORDINARY).await;
    store_rule(&untrusting.pool, alpha.id, alpha.admin, &datacentre_only()).await;

    let forged = untrusting
        .app
        .clone()
        .oneshot(from_peer(
            {
                let mut request = refresh_request(&alpha.slug, &session);
                let _ = request
                    .headers_mut()
                    .insert("x-forwarded-for", PERMITTED.parse().expect("a header value"));
                request
            },
            ORDINARY,
        ))
        .await
        .expect("response");
    assert_eq!(
        forged.status(),
        StatusCode::FORBIDDEN,
        "a caller named its own network origin and was believed"
    );

    // Configuration 2: the same header, the same claimed address, believed — because the peer is a
    // configured proxy one hop out.
    let trusting = harness(Edge::new(
        ProxyTrust::new([TrustedProxy {
            cidr: "10.0.0.0/8".parse().expect("a fixture CIDR"),
            hops: 1,
        }]),
        zones(),
    ))
    .await;
    let alpha = trusting.fixtures.alpha.clone();
    let session =
        sign_in(&trusting, &alpha.slug, &format!("owner@{}.example", alpha.slug), PROXY).await;
    store_rule(&trusting.pool, alpha.id, alpha.admin, &datacentre_only()).await;

    let relayed = trusting
        .app
        .clone()
        .oneshot(from_peer(
            {
                let mut request = refresh_request(&alpha.slug, &session);
                let _ = request
                    .headers_mut()
                    .insert("x-forwarded-for", PERMITTED.parse().expect("a header value"));
                request
            },
            PROXY,
        ))
        .await
        .expect("response");
    assert_eq!(
        relayed.status(),
        StatusCode::OK,
        "a trusted proxy's forwarded address was not honoured, so a real deployment behind a load \
         balancer would refuse everyone: {:?}",
        json_body(relayed).await
    );

    // The control for that control: from the same trusted proxy with **no** header, the peer is the
    // address, the peer is not in the zone, and the refresh is refused.
    let session_two =
        sign_in(&trusting, &alpha.slug, &format!("member@{}.example", alpha.slug), PROXY).await;
    let bare = refresh_from(&trusting, &alpha.slug, &session_two, PROXY).await;
    assert_eq!(
        bare.status(),
        StatusCode::FORBIDDEN,
        "with no forwarding header the proxy's own address is the client address, and it is \
         outside the zone"
    );
}
