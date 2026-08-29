//! `POST /workspaces/{id}/libraries`, end to end, over a real PostgreSQL.
//!
//! # What this file is actually for
//!
//! Not "the handler returns 201". `crates/libraries` has had a tested [`LibraryRepository::create`]
//! since M1 and it was never the thing that was broken; what was broken is that **nothing called
//! it**, so a tenant with no library had no way to obtain one and `POST /uploads` and
//! `POST /libraries/{id}/folders` both had nothing to aim at. The test that matters here is
//! therefore [`a_library_created_here_can_immediately_be_listed_and_written_into`], which does not
//! stop at the response: it lists the new library through the endpoint a client would, and then
//! creates a folder inside it through the endpoint a client would. Those two calls are the claim.
//! A `201` on its own would have been true of this route on the day the repository was written.
//!
//! # The inheritance property, and why it is asserted through two other endpoints
//!
//! A library is created with `inherit_permissions = TRUE`, which is what makes
//! `LIBRARY_CHAIN_SQL` (`crates/authorization/src/repo.rs`) walk it to its workspace. Every grant in
//! this file is written on the **workspace** and none on the library, so a library that did not
//! inherit would resolve to a one-node chain with no entries — refusing the browse, refusing the
//! folder, and refusing the caller who just created it. The listing and the folder are consequently
//! not incidental coverage; they are the only way to observe from outside that the flag was written,
//! short of reading the column, and reading the column would assert the `INSERT` rather than the
//! consequence anybody cares about.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the nine prior instances in this repository where deleting a
//! `tenant_id` predicate *failed to fail* because row-level security held the property alone. A
//! cross-tenant assertion cannot distinguish "the authorization stage refused" from "RLS made the
//! row invisible", so on its own it proves nothing about the code this work added.
//!
//! * **Authorization.** [`a_caller_without_the_grant_cannot_create_and_is_told_nothing`] uses a
//!   **same-tenant** caller — `fixtures.alpha.member`, against alpha's own workspace, where RLS has
//!   nothing to say because every row involved is this tenant's to read. Only the chain can refuse
//!   it. That is the one test here that proves anything about this route's security.
//! * **Isolation.** [`another_tenants_workspace_is_absent_and_looks_like_a_typo`] is asserted
//!   because `T1` is documented behaviour, **not** because it isolates anything this handler does.
//!   It would pass with the whole authorization stage deleted.
//!
//! # Every absence is paired with its positive control
//!
//! "The caller was refused" and "no library row exists" both pass for free against a handler that
//! refuses everything, against a broken fixture, and against a route that was never registered. So
//! each refusal below is paired, **in the same test and against the same caller**, with the request
//! that succeeds — and where the difference between the two is a single ACL entry, the test grants
//! it and asserts the `201`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, ContainerAction, PolicyEngine, TenantId, UserId, WorkspaceId,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's workspace, and nothing below it.
///
/// Deliberately shallower than `tests/folders.rs`'s `Spine`: the library under test is the one the
/// route makes, and a fixture library written beside it would be a second thing the listing
/// assertions had to account for. What is left is the parent the composite foreign key proves.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
}

impl Spine {
    fn new(tenant: TenantId) -> Self {
        Self { tenant, workspace: WorkspaceId::new_v7() }
    }

    /// Written directly rather than through any route: a fixture built by the surface being tested
    /// cannot be trusted to exist when the surface is broken.
    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, description, visibility, created_by, created_at,
                updated_at)
             VALUES ($1, $2, 'Engineering', $3, 'a description', 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert workspace");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Grants one action on one resource to one user.
async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource_id: Uuid,
    user: UserId,
    action: Action,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, 'USER', $5, $6, 'ALLOW', $7, $8, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    .bind(user.as_uuid())
    .bind(action.to_string())
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Grants `container.create` **and** `container.read` on alpha's **workspace** to one user.
///
/// On the workspace and nowhere else, which is the whole point of this file: every capability the
/// tests below exercise on the *library* has to arrive through inheritance, or not at all.
///
/// Both actions, because the `201` response resolves the new library's capabilities through the same
/// authorization stage, and a caller who could create a library they could not then read would make
/// the response's `capabilities` object the interesting part of an unrelated failure.
async fn grant_workspace(db: &TestDb, spine: &Spine, user: UserId) {
    let mut admin = db.connect().await.expect("admin connection");
    for action in [ContainerAction::Create, ContainerAction::Read] {
        grant(
            &mut admin,
            spine.tenant,
            "WORKSPACE",
            spine.workspace.as_uuid(),
            user,
            Action::Container(action),
        )
        .await;
    }
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");

    // `SelfServiceOr` over the real resolver: the composition `crates/api/src/main.rs` ships. The
    // ACL resolver alone would answer every question here, but wiring it alone would leave this
    // suite exercising a composition no deployment runs (`ENC-746`).
    let authorization =
        Arc::new(enclave_authorization::SelfServiceOr::new(PgAclAuthorization::new(authz_pool)));

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, state_pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    Harness { app: router(state, enclave_api::Delivery::unconfigured()), key }
}

fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: Uuid::new_v4(),
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

/// Issues one request against the router and returns the status and the parsed body.
///
/// One helper for every verb and path in this file rather than one per endpoint, because three of
/// the tests below span two endpoints and a per-endpoint helper would hide which of them answered.
async fn call(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
        .header("content-type", "application/json");
    let request = match body {
        Some(json) => request.body(Body::from(json.to_string())).expect("request"),
        None => request.body(Body::empty()).expect("request"),
    };

    let response = harness.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, json)
}

/// `POST /workspaces/{workspace}/libraries`.
async fn create_library(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    workspace: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    call(
        harness,
        tenant,
        user,
        "POST",
        &format!("/api/v1/workspaces/{workspace}/libraries"),
        Some(body),
    )
    .await
}

/// How many live libraries the tenant holds, by slug.
///
/// Read over the superuser connection on purpose: an assertion that a row was **not** created must
/// not be able to pass because the reader could not see it.
async fn library_count(db: &TestDb, tenant: TenantId, slug: &str) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM libraries
          WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(slug)
    .fetch_one(&mut conn)
    .await
    .expect("count libraries")
}

/// The audit rows for one tenant, as `(action, outcome)`.
async fn audit_rows(db: &TestDb, tenant: TenantId) -> Vec<(String, String)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT action, outcome FROM audit_events WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

/// Both tenants seeded, both workspaces written, and **no** grants yet.
///
/// The grant is left to each test so that the test which needs a caller *without* one does not have
/// to undo it — an ACL entry deleted mid-test is a fixture that has been in two states, and the
/// second state is the one nobody checks.
async fn setup() -> (TestDb, Fixtures, Spine, Spine) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let alpha = Spine::new(fixtures.alpha.id);
    let beta = Spine::new(fixtures.beta.id);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    beta.insert(&mut admin, fixtures.beta.owner).await;

    (db, fixtures, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// The registration itself
// ---------------------------------------------------------------------------------------------

/// The handler can be mounted, on the path and verb `crates/api/src/lib.rs` has to carry.
///
/// Every other test in this file goes through [`router`] and would fail identically for a route
/// that was never registered and for a route that was registered and broken — a `404` from the
/// router looks exactly like a `404` from `conceal`. This one separates those: it needs no database,
/// it fails at compile time rather than at run time, and it fails for the two mistakes that
/// `cargo check` on the crate alone cannot see, because nothing in the library ever passes the
/// function to `post`. An extractor ordered after the body consumer and a return type that is not
/// `IntoResponse` are both accepted by the function definition and rejected here.
///
/// It deliberately does **not** assert that the real router carries the path, because that assertion
/// belongs to the file this test cannot edit and would be a second, weaker copy of the line the
/// integrator adds.
#[test]
fn the_handler_can_be_mounted_on_the_path_the_router_must_carry() {
    let _mounted: axum::Router<ApiState> = axum::Router::new().route(
        "/api/v1/workspaces/{id}/libraries",
        axum::routing::post(enclave_api::routes::libraries::create),
    );
}

// ---------------------------------------------------------------------------------------------
// The journey — the reason this route exists
// ---------------------------------------------------------------------------------------------

/// A library created through this route can be listed and written into, with no ACL entry of its
/// own.
///
/// This is the test the work exists for. `POST /workspaces/{id}/libraries` →
/// `GET /workspaces/{id}/libraries` → `POST /libraries/{id}/folders`, one caller, one grant, and the
/// grant is on the **workspace**. Each leg would pass on its own against a library that was never
/// reachable — the create returns before anything reads the ACL, and the listing and the folder
/// route were both already registered — so the three of them in sequence are the assertion, not any
/// one of them.
///
/// If `inherit_permissions` were ever written `FALSE` here, the second call returns an empty page
/// and the third a `404`, and this fails at the line that says so.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_created_here_can_immediately_be_listed_and_written_into() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_workspace(&db, &alpha, user).await;

    // --- leg 1: create ---
    let (status, created) = create_library(
        &harness,
        alpha.tenant,
        user,
        &alpha.workspace.to_string(),
        serde_json::json!({ "name": "Specifications", "slug": "specifications" }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Specifications", "{created}");
    assert_eq!(created["slug"], "specifications", "{created}");
    assert_eq!(created["workspaceId"], alpha.workspace.to_string(), "{created}");
    assert_eq!(created["revision"], 1, "a create's ETag must be usable as an If-Match: {created}");
    // Resolved against the new library, through the same stage the chain will consult. `true` here
    // is the first observation that inheritance reached it.
    assert_eq!(created["capabilities"]["read"], true, "{created}");
    assert_eq!(created["capabilities"]["create"], true, "{created}");
    let library = created["id"].as_str().expect("id").to_owned();

    // --- leg 2: the caller can find it again through the listing a client would use ---
    let (status, page) = call(
        &harness,
        alpha.tenant,
        user,
        "GET",
        &format!("/api/v1/workspaces/{}/libraries", alpha.workspace),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{page}");
    let items = page["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the new library must survive the listing's trim: {page}");
    assert_eq!(items[0]["id"], library, "{page}");

    // --- leg 3: and it is a place a file can go ---
    let (status, folder) = call(
        &harness,
        alpha.tenant,
        user,
        "POST",
        &format!("/api/v1/libraries/{library}/folders"),
        Some(serde_json::json!({ "name": "Q3" })),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the workspace grant must reach the new library's contents: {folder}"
    );
    assert_eq!(folder["libraryId"], library, "{folder}");
    assert_eq!(folder["type"], "FOLDER", "{folder}");
}

// ---------------------------------------------------------------------------------------------
// Authorization — the same-tenant test, the only one that proves this route's security
// ---------------------------------------------------------------------------------------------

/// **Authorization layer.** A same-tenant caller with no grant is refused, and told nothing.
///
/// The caller is `fixtures.alpha.member` and the workspace is alpha's, so row-level security admits
/// every row involved — deleting a `tenant_id` predicate would not make this test fail, and it is
/// not trying to. What it proves is that the chain refuses, that `CLAUDE.md` rule 7 turns the
/// refusal into a `404` rather than a `403` that would confirm the workspace exists, that the
/// denial is audited by the engine rather than by the handler (rule 10), and that **no row was
/// written**.
///
/// The positive control is the same caller, the same workspace and the same body after the ACL
/// entries are added: without it, every assertion here passes against a route that refuses
/// everybody, and against a route that was never registered at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_without_the_grant_cannot_create_and_is_told_nothing() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    let body = serde_json::json!({ "name": "Specifications", "slug": "specifications" });

    let (status, refused) =
        create_library(&harness, alpha.tenant, user, &alpha.workspace.to_string(), body.clone())
            .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: a 403 would confirm the workspace exists");
    assert_eq!(refused["error"]["code"], "NOT_FOUND", "{refused}");
    assert_eq!(
        library_count(&db, alpha.tenant, "specifications").await,
        0,
        "a refused creation must write no row"
    );

    let rows = audit_rows(&db, alpha.tenant).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "container.create" && outcome == "DENY"),
        "the denial must be audited: {rows:?}"
    );

    // --- the positive control: the ACL entries are the whole difference ---
    grant_workspace(&db, &alpha, user).await;

    let (status, created) =
        create_library(&harness, alpha.tenant, user, &alpha.workspace.to_string(), body).await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(
        library_count(&db, alpha.tenant, "specifications").await,
        1,
        "the granted creation must write exactly one row"
    );
}

// ---------------------------------------------------------------------------------------------
// The repository's own answers, surfaced
// ---------------------------------------------------------------------------------------------

/// A slug already live in this workspace is `409`, and the response does not echo it.
///
/// The status is the load-bearing assertion. `enclave_libraries` classifies only the composite
/// foreign key (`parent_aware`), so `uq_library_slug`'s `23505` arrives as
/// `LibraryError::Database` — which converts to `Error::Internal` and a **`500`**. A handler that
/// let the blanket conversion run would tell a caller who picked a taken short name that the server
/// was broken, and this fails.
///
/// The first `201` is the positive control: without it, "the second request is refused" would pass
/// against a route that refuses every request.
///
/// The second half is the same collision reached through folding rather than through an exact
/// match, because `normalize_slug` lowercases and the index is over the folded value — so
/// `"Specifications"` and `"specifications"` are one slug, and a client told otherwise would build a
/// picker with two entries that are the same library.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_slug_already_live_in_this_workspace_is_a_conflict() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_workspace(&db, &alpha, user).await;

    let (status, first) = create_library(
        &harness,
        alpha.tenant,
        user,
        &alpha.workspace.to_string(),
        serde_json::json!({ "name": "Specifications", "slug": "specifications" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    // A different display name, the same slug: the index is over the slug and so is the answer.
    let (status, second) = create_library(
        &harness,
        alpha.tenant,
        user,
        &alpha.workspace.to_string(),
        serde_json::json!({ "name": "Specs (old)", "slug": "SPECIFICATIONS" }),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT, "§5: a name collision is 409, never 400 or 500");
    assert_eq!(second["error"]["code"], "NAME_IN_USE", "{second}");
    assert_eq!(second["error"]["details"][0]["field"], "slug", "{second}");

    let rendered = second.to_string();
    assert!(
        !rendered.contains("Specs (old)") && !rendered.contains("SPECIFICATIONS"),
        "a collision report must not echo what the caller sent: {rendered}"
    );
    assert_eq!(
        library_count(&db, alpha.tenant, "specifications").await,
        1,
        "the refused second write must leave exactly the first row"
    );
}

/// A name or slug the column will not hold is `400`, and it says which field.
///
/// Asked **after** the chain has allowed, which is the ordering that matters: a caller with no grant
/// must not be able to tell a workspace that exists from one that does not by sending a body they
/// know is invalid and watching for a `400` instead of a `404`. The second half of this test is that
/// assertion — the same invalid body, from a caller without the grant, is the ordinary `404`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unusable_name_is_a_validation_failure_and_only_after_the_chain_has_allowed() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let granted = fixtures.alpha.member;
    let stranger = fixtures.alpha.viewer;
    grant_workspace(&db, &alpha, granted).await;
    let body = serde_json::json!({ "name": "  ", "slug": "not a slug" });

    let (status, refused) =
        create_library(&harness, alpha.tenant, granted, &alpha.workspace.to_string(), body.clone())
            .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let details = refused["error"]["details"].as_array().expect("details");
    assert_eq!(details.len(), 2, "both fields must be reported in one answer: {refused}");
    assert_eq!(details[0]["field"], "name", "{refused}");
    assert_eq!(details[0]["code"], "REQUIRED", "{refused}");
    assert_eq!(details[1]["field"], "slug", "{refused}");
    assert_eq!(details[1]["code"], "INVALID_FORMAT", "{refused}");

    // The same body, a caller with no grant on this workspace: `404`, and not the `400` that would
    // have told them the workspace is there to be validated against.
    let (status, concealed) =
        create_library(&harness, alpha.tenant, stranger, &alpha.workspace.to_string(), body).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "validation must not run before the chain, or it is an existence oracle: {concealed}"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation — documented behaviour, and it proves nothing about the chain
// ---------------------------------------------------------------------------------------------

/// **Isolation layer**, asserted because `T1` is documented and *not* because it isolates anything
/// this handler does.
///
/// Row-level security, the tenant predicate in every statement, the composite foreign key on
/// `libraries` and the chain's stage-1 comparison each refuse this independently. It would pass with
/// the authorization stage deleted entirely, which is precisely why the same-tenant test above
/// exists.
///
/// What it does add is the *indistinguishability*: another tenant's workspace and a string that is
/// not a UUID at all produce the same status and the same body. An id that does not parse answered
/// `400` would be a `400`/`404` oracle — a probe could sort real ids from fabricated ones without
/// ever holding a grant.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_workspace_is_absent_and_looks_like_a_typo() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_workspace(&db, &alpha, user).await;
    let body = serde_json::json!({ "name": "Exfiltrated", "slug": "exfiltrated" });

    // Alpha's token, beta's workspace id.
    let (foreign_status, mut foreign) =
        create_library(&harness, alpha.tenant, user, &beta.workspace.to_string(), body.clone())
            .await;

    assert_eq!(
        foreign_status,
        StatusCode::NOT_FOUND,
        "rule 7: cross-tenant is 404, never 403: {foreign}"
    );
    assert_eq!(
        library_count(&db, beta.tenant, "exfiltrated").await,
        0,
        "nothing may be written into another tenant"
    );

    // A string that is not a UUID, and a UUID that names nothing.
    let (garbage_status, mut garbage) =
        create_library(&harness, alpha.tenant, user, "not-a-workspace", body.clone()).await;
    let (absent_status, mut absent) =
        create_library(&harness, alpha.tenant, user, &Uuid::now_v7().to_string(), body.clone())
            .await;

    assert_eq!(garbage_status, foreign_status, "an unparseable id must not be a distinct status");
    assert_eq!(absent_status, foreign_status, "an absent id must not be a distinct status");

    // `requestId` is per-request by construction and is the one field that must differ; everything
    // else has to be identical, or the difference is the oracle.
    for envelope in [&mut foreign, &mut garbage, &mut absent] {
        let error = envelope["error"].as_object_mut().expect("error object");
        let _removed = error.remove("requestId");
    }
    assert_eq!(garbage, foreign, "a typo and another tenant's id must be one answer");
    assert_eq!(absent, foreign, "an absence and another tenant's id must be one answer");

    // The positive control, in the same test and against the same caller: the identical request
    // against alpha's own workspace succeeds. Without it this test passes against a route that
    // refuses every creation.
    let (status, created) =
        create_library(&harness, alpha.tenant, user, &alpha.workspace.to_string(), body).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(library_count(&db, alpha.tenant, "exfiltrated").await, 1);
}
