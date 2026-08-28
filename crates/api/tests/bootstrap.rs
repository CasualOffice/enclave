//! `GET /api/v1/bootstrap` — the file `crates/api/src/routes/bootstrap.rs` has been promising.
//!
//! That module's documentation named this file three times, in the present tense, as the thing
//! that proves its central claim. **It did not exist.** The handler was written, documented,
//! reviewed and registered on no router; the tests it cited were prose. Both halves of that are
//! fixed in the same commit (`ENC-725`), and this header records the shape because it is the
//! failure mode `docs/12-TESTING.md §1.2` is about: a claim that reads like a check.
//!
//! # What each test here is actually asserting, and against what
//!
//! The endpoint's security content is a *split*: an anonymous caller must not learn what a
//! deployment enforces, and the authenticated half must be unreachable without a verified context.
//! Every assertion in that sentence is an assertion about an **absence**, and `docs/12 §1.2` is
//! blunt about what those are worth on their own — `session` is absent from a handler returning
//! `{}`, from a route that 404s, and from a request nobody sent. Three of them pass against a
//! deleted endpoint.
//!
//! So no absence is asserted alone here. Each one is paired, **in the same test function and
//! against the same running app**, with the positive control that makes it mean something:
//!
//! | Test | The absence | The control that makes it non-vacuous |
//! |---|---|---|
//! | [`the_anonymous_half_has_no_session_and_the_authenticated_half_does`] | no `session`, no tenant id, no user id, never `source: user`/`tenant` | the same app answers the authenticated caller with all four, carrying real values |
//! | [`the_public_half_is_identical_for_every_host`] | three hosts, one byte-for-byte answer | a fourth request that varies something the handler *is* meant to vary on comes back different |
//! | [`a_caller_the_chain_refuses_gets_a_refusal_and_not_the_public_payload`] | the refusal carries no payload | the identical request against the allowing composition is a `200` with a session |
//! | [`each_tenant_reads_its_own_row_and_not_whichever_row_came_first`] | — | two tenants, two answers; one predicate holds it and nothing else does |
//!
//! # Two hosts, and why `Host` is never allowed to become a tenant
//!
//! `crates/db/src/routing.rs` can turn `tenant-alpha.enclave.test` into a `TenantId`, and
//! `POST /auth/login` does exactly that. Bootstrap deliberately does not, and
//! [`the_public_half_is_identical_for_every_host`] is what holds it to that: if the anonymous
//! response ever varied by `Host`, an unauthenticated caller would have a tenant-enumeration oracle
//! — vary the header, diff the body, read off the customer list. `CLAUDE.md` rule 3 forbids taking
//! tenancy from a header; this endpoint goes one step further and does not take it from the routed
//! host either, because it has nothing it could honestly say about a tenant to someone who has not
//! authenticated.
//!
//! # Running it
//!
//! `DATABASE_URL` must name a PostgreSQL that databases can be created on. `#[ignore]` for the
//! reason every integration test in this directory carries it — CI runs them with
//! `--include-ignored` — and not as a quarantine.

// Assertions are the point of a test; the workspace warns on these in non-test code.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_core::{
    Action, AuthorizationService, ClientType, PolicyEngine, ReasonCode, RequestContext,
    ResourceRef, Result as CoreResult, StageDecision, TenantId, UserId,
};
use enclave_testing::TestDb;
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";
const BOOTSTRAP: &str = "/api/v1/bootstrap";

/// Alpha's routed authority, spelled the way `crates/api/tests/reachability.rs` spells it.
const ALPHA_HOST: &str = "tenant-alpha.enclave.test";
/// Beta's. A real tenant, seeded, resolvable — which is what makes the byte comparison a claim
/// about this handler's *choice* rather than about a lookup that would have failed anyway.
const BETA_HOST: &str = "tenant-beta.enclave.test";
/// A host no tenant is reachable at.
const UNKNOWN_HOST: &str = "not-a-tenant.enclave.test";

// ---------------------------------------------------------------------------------------------
// The two compositions
// ---------------------------------------------------------------------------------------------

/// An authorization stage that refuses everything, with the reason code a real denial carries.
///
/// A test double rather than a real stage bent into refusing, because the claim under test is not
/// *why* the chain refused — it is that this handler asks and then obeys. `crates/authorization`
/// keeps an `AllowsEverything` of the same shape for the mirror-image reason.
///
/// It is the only stage swapped. Everything upstream of authorization in `docs/03-LLD.md §12`'s
/// fixed order — tenant isolation, auth, conditional access — runs exactly as it does in the
/// allowing composition, so a refusal here is a refusal taken *at the right point in the chain*
/// and not by a short-circuit bolted to the front of it.
#[derive(Debug, Clone, Copy)]
struct RefusesEverything;

#[async_trait]
impl AuthorizationService for RefusesEverything {
    async fn authorize(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::deny(ReasonCode::AccessDenied))
    }

    async fn authorize_many(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        Ok(resources.iter().map(|_| StageDecision::deny(ReasonCode::AccessDenied)).collect())
    }
}

/// Builds the app over a freshly migrated, seeded database.
///
/// `authorization` is a parameter so that the allowing and refusing compositions differ in exactly
/// one stage and in nothing else — same router, same database, same key, same everything upstream.
/// A refusal test that also changed the database or the token would not be able to say which change
/// produced the refusal.
async fn app(
    db: &TestDb,
    authorization: Arc<dyn AuthorizationService>,
) -> (axum::Router, PrivateSigningKey) {
    let pool = db.pool().await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    // Bootstrap touches no delivery path. The unconfigured delivery is what a deployment without
    // object storage carries, and using it keeps this test honest about that.
    (router(state, enclave_api::Delivery::unconfigured()), key)
}

/// The allowing composition — the one `crates/api/src/main.rs` builds for a self-read.
fn allowing() -> Arc<dyn AuthorizationService> {
    Arc::new(enclave_authorization::SelfServiceAuthorization)
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

// ---------------------------------------------------------------------------------------------
// Sending one request
// ---------------------------------------------------------------------------------------------

/// One answer, kept as **bytes as well as JSON**.
///
/// The byte-identity test cannot use the parsed form: `serde_json::Value` sorts object keys and
/// would call two responses equal that a client would see as different.
struct Answer {
    status: StatusCode,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {}", self.text()))
    }
}

/// `GET /api/v1/bootstrap` with whatever headers the caller wants and nothing it does not.
async fn get(app: &axum::Router, headers: &[(&str, &str)]) -> Answer {
    let mut request = Request::builder().uri(BOOTSTRAP);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response =
        app.clone().oneshot(request.body(Body::empty()).expect("request")).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("body").to_vec();
    Answer { status, body }
}

/// Sets `users.locale`, which nothing else in the fixture set does.
///
/// Needed for the positive control in the first test: without a stored locale, step 1 of
/// `docs/14 §3` never fires and `source` reads `fallback` for the authenticated caller too — which
/// would make "the anonymous caller never sees `source: user`" true for a reason that has nothing
/// to do with the split.
async fn set_locale(db: &TestDb, user: UserId, locale: &str) {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query("UPDATE users SET locale = $1 WHERE id = $2")
        .bind(locale)
        .bind(user.as_uuid())
        .execute(&mut conn)
        .await
        .expect("set the fixture user's locale");
}

// ---------------------------------------------------------------------------------------------
// 1. The split
// ---------------------------------------------------------------------------------------------

/// The anonymous caller learns nothing tenant-scoped; the authenticated caller learns all of it.
///
/// **The two halves are one test on purpose.** Split into two functions, the negative half would be
/// green against a `bootstrap` that returned `{}` — and against no route at all, since a `404`
/// body contains no `session` either. Run together against one app, the positive half establishes
/// that this code path *can* emit a tenant id, a user id and `source: "user"`, and only then does
/// the negative half's silence mean the split refused to.
///
/// What it proves: the *type-level* split in `crates/api/src/routes/bootstrap.rs` — `Session` has
/// one private constructor taking a `&RequestContext`. It does not prove the chain was consulted;
/// that is [`a_caller_the_chain_refuses_gets_a_refusal_and_not_the_public_payload`].
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_anonymous_half_has_no_session_and_the_authenticated_half_does() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    set_locale(&db, fixtures.alpha.owner, "en-GB").await;
    let (app, key) = app(&db, allowing()).await;

    // --- the positive control, first, so a failure here is not read as a leak -----------------
    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let session = get(&app, &[("host", ALPHA_HOST), ("authorization", &bearer)]).await;
    assert_eq!(session.status, StatusCode::OK, "the authenticated half: {}", session.text());

    let body = session.json();
    let tenant_id = fixtures.alpha.id.as_uuid().to_string();
    let user_id = fixtures.alpha.owner.as_uuid().to_string();
    assert_eq!(body["session"]["tenantId"], tenant_id, "{body}");
    assert_eq!(body["session"]["userId"], user_id, "{body}");
    assert_eq!(body["session"]["tenant"]["displayName"], "tenant-alpha", "{body}");
    assert_eq!(body["session"]["tenant"]["status"], "ACTIVE", "{body}");
    // Step 1 of `docs/14 §3` fired, which is what makes `source` a field with something to hide.
    assert_eq!(body["locale"]["source"], "user", "{body}");
    assert_eq!(body["locale"]["resolved"], "en-GB", "{body}");
    // The embedded public half is present too, so the authenticated response is a superset rather
    // than a different shape.
    assert_eq!(body["apiVersion"], "v1", "{body}");

    // --- and now the absence, on the same app, over the same code path ------------------------
    let anonymous = get(&app, &[("host", ALPHA_HOST)]).await;
    assert_eq!(anonymous.status, StatusCode::OK, "the anonymous half: {}", anonymous.text());

    let public = anonymous.json();
    // A body, not an empty object. Without this the four assertions below hold against `{}`.
    assert_eq!(public["apiVersion"], "v1", "the anonymous half returned no payload: {public}");
    assert!(public["locale"]["resolved"].is_string(), "{public}");

    assert!(public.get("session").is_none(), "the anonymous caller received a session: {public}");
    assert!(public.get("tenantId").is_none(), "{public}");
    assert!(public.get("userId").is_none(), "{public}");
    // `source` is a field on the public half — what an anonymous caller must never see is a *value*
    // that only a tenant or a user record could have produced. Reaching either means a tenant was
    // resolved for a caller who presented nothing.
    let source = public["locale"]["source"].as_str().unwrap_or_default();
    assert!(
        source == "accept-language" || source == "fallback",
        "the anonymous locale resolved from `{source}`, which is a step of docs/14 §3 that needs a \
         tenant or a user record. An anonymous caller has neither: {public}"
    );

    // The strings themselves, not the keys — a leak does not have to arrive under the name the
    // schema gives it. The control is that all three appear in the authenticated body above, so
    // this is not a search for values that never exist.
    let text = anonymous.text();
    for (label, needle) in [
        ("the tenant id", &tenant_id),
        ("the user id", &user_id),
        ("the tenant's name", &"tenant-alpha".to_owned()),
    ] {
        assert!(
            !text.contains(needle.as_str()),
            "{label} reached an unauthenticated caller: {text}"
        );
        assert!(
            session.text().contains(needle.as_str()),
            "{label} is not in the authenticated response either, so the assertion above proves \
             nothing: {}",
            session.text()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 2. The public half does not vary by host
// ---------------------------------------------------------------------------------------------

/// Three hosts, one answer, byte for byte.
///
/// Which layer this proves: **the handler's own choice, and nothing else.** It is not held by RLS
/// (nothing is queried), not by the policy chain (no decision is taken on this branch), and not by
/// the absence of a resolver — `enclave_db::resolve_routed_tenant` exists and works, and
/// `POST /auth/login` calls it two files away. The only thing standing between a `Host` header and
/// this response is that `bootstrap` does not ask. That makes this exactly the kind of property
/// that regresses quietly when someone adds branding to the sign-in page, and exactly the kind that
/// a test is worth having for.
///
/// The fourth request is the control. A byte comparison over three responses passes trivially if
/// the endpoint is broken in a way that makes every response identical — `404 Not Found`, an empty
/// body, a constant error. So the same app is asked to vary on the one input it *is* specified to
/// vary on (`Accept-Language`, `docs/14 §3` step 3), and that answer must differ.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_public_half_is_identical_for_every_host() {
    let db = TestDb::start().await.expect("start");
    db.seed().await.expect("seed");
    let (app, _key) = app(&db, allowing()).await;

    let alpha = get(&app, &[("host", ALPHA_HOST)]).await;
    let beta = get(&app, &[("host", BETA_HOST)]).await;
    let unknown = get(&app, &[("host", UNKNOWN_HOST)]).await;

    for (label, answer) in [("alpha", &alpha), ("beta", &beta), ("unknown", &unknown)] {
        assert_eq!(answer.status, StatusCode::OK, "{label}: {}", answer.text());
    }

    assert_eq!(
        alpha.text(),
        beta.text(),
        "the anonymous response differs between two seeded tenants' hosts. An unauthenticated \
         caller can now enumerate this deployment's tenants by varying a header it controls \
         (CLAUDE.md rule 3, and the module header of crates/api/src/routes/bootstrap.rs)"
    );
    assert_eq!(
        alpha.text(),
        unknown.text(),
        "the anonymous response distinguishes a host that routes a tenant from one that does not, \
         which is a tenant-existence oracle for a caller holding nothing"
    );

    // The control: this comparison can tell two responses apart.
    let negotiated = get(&app, &[("host", ALPHA_HOST), ("accept-language", "en-GB")]).await;
    assert_eq!(negotiated.status, StatusCode::OK, "{}", negotiated.text());
    assert_ne!(
        alpha.text(),
        negotiated.text(),
        "the response did not change when `Accept-Language` did, so the three comparisons above \
         are comparing an endpoint that answers the same thing to everything — including, \
         possibly, nothing at all: {}",
        alpha.text()
    );
    assert_eq!(negotiated.json()["locale"]["resolved"], "en-GB", "{}", negotiated.text());
}

// ---------------------------------------------------------------------------------------------
// 3. The chain decides the authenticated half
// ---------------------------------------------------------------------------------------------

/// A refused caller receives a refusal — not the public payload with a different status.
///
/// This is the assertion `xtask policy-routing` cannot make. That lint proves `enforce` is
/// *reachable* from the handler; it cannot prove `enforce` **dominates** the authenticated branch,
/// because dominance needs MIR. So the property is carried here: swap one stage for one that
/// refuses, and the authenticated request must come back as a refusal of the shape
/// `docs/05-API.md §5` specifies, carrying no bootstrap payload at all.
///
/// The failure mode it is really guarding against is the plausible-looking one: a handler that
/// catches the refusal and degrades to the anonymous response, on the reasoning that bootstrap
/// should always answer something. That would hand a refused caller a `200` and a signed-out shell,
/// and would pass any test that only checked the response was not a session.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_the_chain_refuses_gets_a_refusal_and_not_the_public_payload() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");

    // Two apps over one database, differing in exactly one stage.
    let (refusing_app, key) = app(&db, Arc::new(RefusesEverything)).await;
    let (allowing_app, allowing_key) = app(&db, allowing()).await;

    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let refused = get(&refusing_app, &[("host", ALPHA_HOST), ("authorization", &bearer)]).await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());

    // The envelope of `docs/05-API.md §5`, field by field.
    let body = refused.json();
    assert_eq!(body["error"]["code"], "ACCESS_DENIED", "{body}");
    assert!(body["error"]["message"].as_str().is_some_and(|m| !m.is_empty()), "{body}");
    assert!(body["error"]["requestId"].as_str().is_some_and(|id| !id.is_empty()), "{body}");
    assert!(body["error"]["remediation"].is_string(), "{body}");
    // A refusal is not the anonymous payload wearing a 403.
    assert!(body.get("apiVersion").is_none(), "{body}");
    assert!(body.get("locale").is_none(), "{body}");
    assert!(body.get("session").is_none(), "{body}");
    assert!(
        !refused.text().contains(&fixtures.alpha.id.as_uuid().to_string()),
        "the refusal echoed the tenant id: {}",
        refused.text()
    );

    // Rule 10: the denial is audited, inside the engine, as a denial.
    let mut conn = db.connect().await.expect("connect");
    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND outcome <> 'ALLOW'",
    )
    .bind(fixtures.alpha.id.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("count audit rows");
    assert_eq!(denied, 1, "a denial must leave an audit row, and exactly one");
    drop(conn);

    // The control. Same request, same database, same fixture — only the stage differs. Without
    // this, a `403` from a handler that had been deleted, misrouted or broken in any other way
    // would read as proof that the chain refused it.
    let bearer =
        format!("Bearer {}", token(&allowing_key, fixtures.alpha.id, fixtures.alpha.owner));
    let allowed = get(&allowing_app, &[("host", ALPHA_HOST), ("authorization", &bearer)]).await;
    assert_eq!(
        allowed.status,
        StatusCode::OK,
        "the identical request is refused by the allowing composition too, so the 403 above is not \
         evidence that the chain decided anything: {}",
        allowed.text()
    );
    assert_eq!(
        allowed.json()["session"]["tenantId"],
        fixtures.alpha.id.as_uuid().to_string(),
        "{}",
        allowed.text()
    );
}

// ---------------------------------------------------------------------------------------------
// 4. The one query in this handler that row-level security does not cover
// ---------------------------------------------------------------------------------------------

/// Each tenant's session reports **its own** `tenants` row.
///
/// **Which layer this proves: the query predicate, and only the query predicate.** It is stated
/// this plainly because the opposite mistake has been made nine times in this repository — a
/// cross-tenant test that stayed green with the `tenant_id` predicate deleted, because row-level
/// security held the property alone and the test could not tell the two apart.
///
/// `tenants` is one of the two tables `migrations/0002_rls_policies.sql` deliberately leaves
/// unpolicied: its tenant key is `id`, not `tenant_id`, and it must be readable during tenant
/// resolution before any context exists. So RLS contributes **nothing** here, and the
/// `WHERE id = $1` in `bootstrap` is not the second of two layers — it is the only one. Delete it
/// and the handler serves whichever row PostgreSQL returns first.
///
/// That is what makes the assertion below deterministic rather than lucky: it is not "alpha does
/// not see beta's row" (which a single-row database satisfies for free) but "alpha sees alpha's and
/// beta sees beta's, in one run". A predicate-free `SELECT … FROM tenants LIMIT 1` answers both
/// callers with the *same* row, so at least one of the two assertions fails whichever row that is.
///
/// Both callers are legitimate holders of their own tokens; nothing here is an attempted
/// cross-tenant access, and the policy chain allows both. That is deliberate — a refused request
/// would never reach the query this test is about.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn each_tenant_reads_its_own_row_and_not_whichever_row_came_first() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db, allowing()).await;

    for (label, tenant) in [("alpha", &fixtures.alpha), ("beta", &fixtures.beta)] {
        let bearer = format!("Bearer {}", token(&key, tenant.id, tenant.owner));
        // The `Host` header names alpha in both legs, deliberately: the tenant must come from the
        // verified token and from nothing else (`CLAUDE.md` rule 3). If beta's caller were served
        // alpha's row here, the host would be the reason.
        let answer = get(&app, &[("host", ALPHA_HOST), ("authorization", &bearer)]).await;
        assert_eq!(answer.status, StatusCode::OK, "{label}: {}", answer.text());

        let body = answer.json();
        assert_eq!(
            body["session"]["tenantId"],
            tenant.id.as_uuid().to_string(),
            "{label} was told it is inside another tenant: {body}"
        );
        assert_eq!(
            body["session"]["tenant"]["displayName"],
            tenant.slug.as_str(),
            "{label} received another tenant's row. `tenants` carries no row-level-security \
             policy — its tenant key is `id`, not `tenant_id` — so the `WHERE id = $1` predicate \
             in `bootstrap` is the only thing that scopes this read: {body}"
        );
    }
}

/// A verified token naming another tenant's subject answers `404`, never `403`.
///
/// **Which layer this proves: row-level security on `users`, not the chain and not a predicate.**
/// Said out loud because it is the *weak* half, and `crates/api/tests/me.rs` records the same
/// finding for the same request: the policy chain **allows** this. `tid` is beta, so the context
/// and the resource are both beta and the engine's tenant assertion passes; the subject is the
/// caller's own, so self-read authorization permits it. Every stage says yes.
///
/// The row is not returned because `TenantScoped` set `app.tenant_id` to beta and alpha's user is
/// invisible to the transaction. Deleting a predicate from `bootstrap`'s `users` query would not
/// fail this test — there is no predicate to delete, and RLS would hold it anyway. The assertion
/// that the chain allowed is included below so that a future change which starts *denying* this
/// instead fails here and makes someone re-read which layer is carrying the isolation.
///
/// Rule 7 is the part with teeth: `404`, so the response cannot confirm that the subject exists
/// somewhere.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_token_pairing_one_tenant_with_another_tenants_subject_is_absent_not_forbidden() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db, allowing()).await;

    // beta's tenant, alpha's user — a correctly signed token whose two halves disagree.
    let bearer = format!("Bearer {}", token(&key, fixtures.beta.id, fixtures.alpha.owner));
    let answer = get(&app, &[("host", ALPHA_HOST), ("authorization", &bearer)]).await;

    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "a cross-tenant subject must be indistinguishable from one that does not exist \
         (CLAUDE.md rule 7, docs/12-TESTING.md §4 T1): {}",
        answer.text()
    );
    assert!(
        !answer.text().contains(&fixtures.alpha.owner.as_uuid().to_string()),
        "the refusal echoed a subject id from another tenant: {}",
        answer.text()
    );

    // The control, and the statement of which layer held it: an ALLOW row means the chain passed
    // this request and the database refused it.
    let mut conn = db.connect().await.expect("connect");
    let allowed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE outcome = 'ALLOW'")
            .fetch_one(&mut conn)
            .await
            .expect("count");
    assert_eq!(allowed, 1, "the policy chain allowed; row-level security is what stopped the read");
}
