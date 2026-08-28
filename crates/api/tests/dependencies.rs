//! `GET /health/dependencies` — the summary/detail split, and what neither half may disclose.
//!
//! `ENC-726`. `docs/05-API.md §19` gives the contract in six words — *unauthenticated summary,
//! authenticated detail* — and the reason the two halves differ is that a dependency report is a
//! description of a deployment's internals. `docs/06-SECURITY-DLP-ACCESS.md §1` assumes the caller
//! is hostile, and an unauthenticated endpoint is the most hostile of all.
//!
//! # The three claims, and the control each one needs
//!
//! Every claim this endpoint makes is negative — *the summary does not say which component*, *no
//! address appears*, *nothing is omitted* — and `docs/12-TESTING.md §1.2` is explicit that an
//! assertion about an absence passes for free. Against a `404`, against `{}`, against a request
//! that was never sent. So:
//!
//! 1. **The summary is one word.** Control: the authenticated detail, in the same test run, over
//!    the same app, carries the component list the summary withheld.
//! 2. **No host, port, DSN, bucket or version reaches either half.** Control: the needles are
//!    asserted to be present in the DSN the server was actually handed, first. A scan for strings
//!    that appear nowhere in the deployment proves nothing about the response.
//! 3. **An unprobed dependency is reported `unknown`/`none`, never omitted** — because an absent
//!    dependency reads as a healthy one, and that is the failure this list exists to prevent
//!    (`ENC-729`). Control: the set of names is compared for *equality*, not containment, so a
//!    dependency dropped from the report fails here rather than shrinking the expectation with it.
//!
//! # What is not asserted here, and is not asserted anywhere
//!
//! **The degraded verdict.** Producing one means making PostgreSQL stop answering mid-test, and the
//! only handle this harness has on that is the pool it shares with the assertions themselves. So
//! `Health::Degraded` and the whole of `health::reason` — the `match` on the [`DbError`] variant
//! that is the single thing standing between `sqlx::Error`'s `Display` and the caller — have **no
//! test at all**, here or in `crates/api/src/health.rs`, which carries no `#[cfg(test)]` module.
//!
//! That sentence is written out rather than left implied because the defect this whole commit
//! exists to fix was documentation in the present tense about tests that did not exist. `ENC-849`
//! is the row: the mapping wants a unit test taking a constructed `DbError` and asserting the
//! returned code, which needs no database and would cover the arm an outage actually reaches.

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
const DEPENDENCIES: &str = "/health/dependencies";
const HOST: &str = "tenant-alpha.enclave.test";

/// Every component the report must name, whether or not this process can see it.
///
/// Written down here rather than read from the handler's own `UNPROBED` constant, deliberately: a
/// test that derives its expectation from the code under test cannot catch a deletion, because the
/// deletion shrinks both sides. This list is the *contract* — `ENC-729`'s row states it — and it
/// changes only when someone decides the deployment has a different set of dependencies.
const EXPECTED: &[&str] = &[
    "postgresql",
    "object_storage",
    "milvus",
    "redis",
    "nats",
    "antivirus",
    "smtp",
    "embedding_provider",
];

/// An authorization stage that refuses everything.
///
/// The same double `crates/api/tests/bootstrap.rs` uses, and duplicated rather than shared for the
/// ordinary reason that two integration-test binaries have no module in common. It is the only
/// stage swapped: everything upstream of authorization in `docs/03-LLD.md §12`'s fixed order runs
/// exactly as it does in the allowing composition, so a refusal is taken at the right point in the
/// chain rather than by a short-circuit in front of it.
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

/// The app the composed binary builds for a self-read.
async fn app(db: &TestDb) -> (axum::Router, PrivateSigningKey) {
    app_with(db, Arc::new(enclave_authorization::SelfServiceAuthorization)).await
}

async fn app_with(
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
    (router(state, enclave_api::Delivery::unconfigured()), key)
}

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

async fn get(app: &axum::Router, headers: &[(&str, &str)]) -> Answer {
    let mut request = Request::builder().uri(DEPENDENCIES);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response =
        app.clone().oneshot(request.body(Body::empty()).expect("request")).await.expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("body").to_vec();
    Answer { status, body }
}

// ---------------------------------------------------------------------------------------------
// 1. The split
// ---------------------------------------------------------------------------------------------

/// The anonymous caller gets a verdict; the authenticated caller gets the component list.
///
/// One test, both halves, one app — for the reason `crates/api/tests/bootstrap.rs` states at
/// length. "The summary has no `dependencies` key" is true of an empty body and of a route that is
/// not registered, and only the authenticated half in the same run rules those out.
///
/// What this proves: the *type-level* split in `crates/api/src/health.rs` —
/// `DependencySummary` has one field and `DependencyDetail` embeds it. It does not prove the chain
/// was consulted; [`a_caller_the_chain_refuses_learns_neither_the_verdict_nor_the_components`]
/// does that.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_summary_is_a_verdict_and_the_detail_is_the_component_list() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db).await;

    // --- the control -------------------------------------------------------------------------
    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let detail = get(&app, &[("host", HOST), ("authorization", &bearer)]).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text());

    let body = detail.json();
    assert_eq!(body["status"], "healthy", "{body}");
    let components = body["dependencies"]
        .as_array()
        .unwrap_or_else(|| panic!("the authenticated half carried no component list: {body}"));
    assert!(!components.is_empty(), "{body}");

    // --- and the absence ----------------------------------------------------------------------
    let summary = get(&app, &[("host", HOST)]).await;
    assert_eq!(summary.status, StatusCode::OK, "{}", summary.text());

    let body = summary.json();
    let object = body
        .as_object()
        .unwrap_or_else(|| panic!("the summary is not an object: {}", summary.text()));
    // Equality, not "does not contain `dependencies`". A future field added to the summary — a
    // count, a list of names with their statuses elided, "3 of 5 healthy" — leaks the shape of the
    // deployment just as surely, and each of those would pass a narrower assertion.
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        vec!["status"],
        "the unauthenticated summary carries more than a verdict: {body}"
    );
    assert_eq!(body["status"], "healthy", "{body}");

    // No component name at all, under any key. The control is that every one of them appears in
    // the authenticated body above.
    let text = summary.text();
    for name in EXPECTED {
        assert!(!text.contains(name), "the summary named the component `{name}`: {text}");
        assert!(
            detail.text().contains(name),
            "`{name}` is absent from the authenticated detail too, so the assertion above proves \
             nothing: {}",
            detail.text()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Nothing is omitted
// ---------------------------------------------------------------------------------------------

/// Every dependency is listed, and the ones nobody asked are `unknown` with `evidence: none`.
///
/// The rule from `ENC-729`'s row: **an absent dependency reads as a healthy one.** A report that
/// listed only what this process holds a client for would say *everything I could see is fine* in
/// a shape indistinguishable from *everything is fine*, and an operator reading it has no way to
/// tell which sentence they are being told.
///
/// The second half is the one that is easy to get wrong in the other direction: an unprobed
/// dependency must also not make the deployment look **degraded**, or the community profile reports
/// itself as permanently unhealthy and the field stops being read at all. So the verdict is
/// asserted `healthy` while six components are `unknown`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn no_dependency_is_omitted_and_an_unprobed_one_is_neither_up_nor_down() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db).await;

    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let detail = get(&app, &[("host", HOST), ("authorization", &bearer)]).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text());
    let body = detail.json();

    let named: Vec<String> = body["dependencies"]
        .as_array()
        .expect("a component list")
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name").to_owned())
        .collect();
    // Set equality in both directions: a component dropped from the report fails here, and one
    // added without a decision fails here too.
    assert_eq!(
        named.iter().map(String::as_str).collect::<Vec<_>>(),
        EXPECTED.to_vec(),
        "the reported components are not the ones this deployment has. A dependency that \
         disappears from this list is reported as healthy by omission, which is the whole reason \
         the list is a constant rather than built from what happens to be wired (ENC-729): {body}"
    );

    for entry in body["dependencies"].as_array().expect("a component list") {
        let name = entry["name"].as_str().expect("a name");
        let (status, evidence) = (&entry["status"], &entry["evidence"]);
        match name {
            // Held by a real handle: asked, and answered.
            "postgresql" => {
                assert_eq!(status, "up", "{entry}");
                assert_eq!(evidence, "probe", "{entry}");
            }
            // Known to be unconfigured, which is different from unreachable and different from
            // unmeasured. `Delivery::unconfigured()` is what this app was built with.
            "object_storage" => {
                assert_eq!(status, "unconfigured", "{entry}");
                assert_eq!(evidence, "configuration", "{entry}");
            }
            // Everything else lives in `enclave-worker`. This process holds no client for it.
            _ => {
                assert_eq!(status, "unknown", "`{name}` claims a status nobody measured: {entry}");
                assert_eq!(evidence, "none", "`{name}` claims evidence nobody has: {entry}");
            }
        }
        // A failure code is the only thing `reason` may ever be, and none of these failed.
        assert!(entry.get("reason").is_none(), "{entry}");
    }

    assert_eq!(
        body["status"], "healthy",
        "six unprobed components made the deployment look degraded. `unknown` is not evidence of \
         anything, and a report that is permanently degraded is a report nobody reads: {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Neither half is a map of the network
// ---------------------------------------------------------------------------------------------

/// No host, port, database name, user, DSN scheme or version reaches any caller.
///
/// `sqlx::Error`'s own `Display` carries the connection target, so the single most likely way for
/// this to regress is somebody replacing `health::reason`'s `match` on the [`DbError`] *variant*
/// with a `to_string()` on the error — at which point "PostgreSQL unreachable at 10.0.3.14:5432"
/// becomes a tenant user's to read, and an unauthenticated caller's if it reaches the summary.
///
/// **The needles are checked against the DSN first.** That is the control, and it is the whole
/// difference between this test and a test that passes because it is searching for strings this
/// deployment never had: `assert!(!body.contains("10.0.3.14"))` is true of every deployment not
/// running at that address, including one leaking its own.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn neither_half_discloses_where_anything_lives() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key) = app(&db).await;

    // The values this deployment actually has, taken from the DSN the harness handed the pool
    // rather than written down — a literal would be a credential in a test (`CLAUDE.md` rule 11)
    // and would also stop being this deployment's value the moment someone moved the database.
    let dsn = db.url().to_owned();
    let authority = dsn
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .expect("a DSN with an authority");
    let hostport = authority.rsplit('@').next().expect("an authority");
    let host = hostport.split(':').next().expect("a host").to_owned();
    let port = hostport.split(':').nth(1).unwrap_or("5432").to_owned();
    let database = dsn.rsplit('/').next().expect("a database name").to_owned();
    // The scheme, assembled rather than written: this file is scanned by the secrets gate, and a
    // test that searches for a DSN prefix must not contain one. The same practice `CLAUDE.md`
    // rule 11 prescribes for PEM banners, applied to the needle rather than to a fixture.
    let scheme = format!("post{}://", "gres");

    let needles = [("the host", host), ("the port", port), ("the database name", database)];
    for (label, needle) in &needles {
        assert!(
            dsn.contains(needle.as_str()),
            "{label} (`{needle}`) is not in the DSN this deployment was given, so searching the \
             response for it proves nothing"
        );
    }

    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let detail = get(&app, &[("host", HOST), ("authorization", &bearer)]).await;
    let summary = get(&app, &[("host", HOST)]).await;

    // The other control: both responses are real, non-empty, and say something. A body of `{}`
    // would satisfy every assertion below.
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text());
    assert_eq!(summary.status, StatusCode::OK, "{}", summary.text());
    assert!(detail.text().contains("postgresql"), "{}", detail.text());
    assert!(summary.text().contains("healthy"), "{}", summary.text());

    for (half, answer) in [("the summary", &summary), ("the detail", &detail)] {
        let text = answer.text();
        for (label, needle) in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "{half} disclosed {label} (`{needle}`). crates/api/src/health.rs states that a \
                 host, a port, a URL, a bucket, a database name, a version string and a provider \
                 error message never appear on this type: {text}"
            );
        }
        assert!(!text.contains(&scheme), "{half} disclosed a connection string: {text}");
        assert!(!text.contains(&dsn), "{half} disclosed the whole DSN: {text}");
        // A version string would let a caller pick an exploit off a shelf. Neither half has a
        // field for one; this is the assertion that keeps it that way.
        assert!(!text.contains("version"), "{half} disclosed a version: {text}");
    }
}

// ---------------------------------------------------------------------------------------------
// 4. The chain decides the detailed half
// ---------------------------------------------------------------------------------------------

/// A refused caller receives the refusal envelope and no report at all — not even the verdict.
///
/// The tempting degradation is to answer a refused caller with the anonymous summary, on the
/// reasoning that they were entitled to it anyway. `docs/05-API.md §5` does not work that way: a
/// presented credential that the chain refuses is an error, and an endpoint that quietly downgrades
/// it hands the caller a `200` at the exact moment their access ended.
///
/// The control is the allowing composition in the same test, over the same database.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_the_chain_refuses_learns_neither_the_verdict_nor_the_components() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (refusing_app, key) = app_with(&db, Arc::new(RefusesEverything)).await;
    let (app, allowing_key) = app(&db).await;

    let bearer = format!("Bearer {}", token(&key, fixtures.alpha.id, fixtures.alpha.owner));
    let refused = get(&refusing_app, &[("host", HOST), ("authorization", &bearer)]).await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text());
    let body = refused.json();
    assert_eq!(body["error"]["code"], "ACCESS_DENIED", "{body}");
    assert!(body["error"]["requestId"].as_str().is_some_and(|id| !id.is_empty()), "{body}");
    assert!(body.get("status").is_none(), "the refusal carried the verdict: {body}");
    assert!(body.get("dependencies").is_none(), "the refusal carried the component list: {body}");
    for name in EXPECTED {
        assert!(!refused.text().contains(name), "the refusal named `{name}`: {}", refused.text());
    }

    // Rule 10: refusals are audited, not only allows.
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

    // The control: the identical request against a composition that differs in exactly one stage.
    let bearer =
        format!("Bearer {}", token(&allowing_key, fixtures.alpha.id, fixtures.alpha.owner));
    let allowed = get(&app, &[("host", HOST), ("authorization", &bearer)]).await;
    assert_eq!(
        allowed.status,
        StatusCode::OK,
        "the allowing composition refuses this caller too, so the 403 above is not evidence that a \
         decision was taken: {}",
        allowed.text()
    );
    assert!(allowed.json()["dependencies"].is_array(), "{}", allowed.text());
}
