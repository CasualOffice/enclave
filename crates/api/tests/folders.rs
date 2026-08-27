//! `ENC-788` — `POST /libraries/{id}/folders`, end to end, over a real PostgreSQL.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the **eight** prior instances in this repository where deleting a
//! `tenant_id` predicate *failed to fail* because row-level security held the property alone. A
//! cross-tenant assertion cannot distinguish "the authorization stage refused" from "RLS made the
//! row invisible", so on its own it proves nothing about the code this work added.
//!
//! Every test below therefore says which layer it is about:
//!
//! * **Authorization.** [`a_caller_without_the_grant_cannot_create_and_is_told_nothing`] and
//!   [`the_named_parent_is_the_container_the_chain_decides_against`] both use a **same-tenant**
//!   caller — `fixtures.alpha.member`, reading alpha's own rows, where RLS has nothing to say
//!   because every row involved is this tenant's to read. Only the trim can refuse them. These are
//!   the two tests that prove anything about this route's security.
//! * **Isolation.** [`another_tenants_library_is_absent_rather_than_forbidden`] is asserted because
//!   `T1` is documented behaviour, **not** because it isolates anything this handler does. It would
//!   pass with the whole authorization stage deleted.
//!
//! # Every absence is paired with its positive control
//!
//! "The caller was refused" and "no folder row exists" both pass for free against a handler that
//! refuses everything, against a broken fixture, and against a route that was never registered. So
//! each refusal below is paired, **in the same test and against the same caller**, with the request
//! that succeeds — and where the difference between the two is a single ACL entry, the test grants
//! it and asserts the `201`.
//!
//! # The sharpest test here is the second one
//!
//! [`the_named_parent_is_the_container_the_chain_decides_against`] is the one that would catch the
//! plausible wrong implementation. A handler that always enforced against the *library* — the id in
//! the path, the obvious reading — passes every other test in this file: the caller holds
//! `container.create` on the library, so creating at the root works, a collision still collides, and
//! a stranger is still refused. It differs only for a folder that has broken inheritance, which is
//! exactly the `ENC-141` shape: a flag flip that truncates the resolver's ancestor walk, where the
//! failure direction is **gained** privilege rather than lost.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, ContainerAction, FileId, LibraryId, PolicyEngine, TenantId, UserId,
    WorkspaceId,
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

/// One tenant's container spine, plus the one folder that makes the parent question decidable.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    /// Granted to the caller, in `workspace`, inheriting.
    library: LibraryId,
    /// In `library`, with `inherit_permissions = FALSE` and no entries of its own.
    ///
    /// The library's grant stops **at** it (`crates/authorization/src/repo.rs`), so a caller who may
    /// create at the library root may not create inside this folder. It is the only fixture that can
    /// tell "the chain was asked about the parent" from "the chain was asked about the library".
    detached_folder: FileId,
}

impl Spine {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            detached_folder: FileId::new_v7(),
        }
    }

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

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, sync_enabled, mcp_visible, ai_indexing_enabled, require_checkout,
                require_approval, created_at, updated_at)
             VALUES ($1, $2, $3, 'Specifications', $4, TRUE, 'MAJOR_MINOR', 'EXISTING_GUESTS', TRUE,
                     FALSE, TRUE, TRUE, FALSE, $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert library");

        // Written directly rather than through the route under test: a fixture built by the thing
        // being tested cannot be trusted to exist when the thing is broken.
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, status, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, NULL, 'FOLDER', 'Compensation Bands', 'compensation bands',
                     'application/vnd.enclave.folder', 'AVAILABLE', FALSE, $5, $5, $6, $6)",
        )
        .bind(self.detached_folder.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert detached folder");
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

/// Issues one folder-creation request and returns the status and the parsed body.
async fn create_folder(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    library: LibraryId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/libraries/{library}/folders"))
                .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, json)
}

/// How many live folders the tenant holds, by name.
///
/// Read over the superuser connection on purpose: an assertion that a row was **not** created must
/// not be able to pass because the reader could not see it.
async fn folder_count(db: &TestDb, tenant: TenantId, name: &str) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM files
          WHERE tenant_id = $1 AND name = $2 AND node_type = 'FOLDER' AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(name)
    .fetch_one(&mut conn)
    .await
    .expect("count folders")
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

/// Both tenants seeded, both spines written, and **no** grants yet.
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

/// Grants `container.create` **and** `container.read` on alpha's library to alpha's member.
///
/// Both, because the `201` response resolves the new folder's capabilities through the same
/// authorization stage, and a caller who could create a folder they could not then read would make
/// the response's `capabilities` object the interesting part of an unrelated failure.
async fn grant_library(db: &TestDb, alpha: &Spine, user: UserId) {
    let mut admin = db.connect().await.expect("admin connection");
    for action in [ContainerAction::Create, ContainerAction::Read] {
        grant(
            &mut admin,
            alpha.tenant,
            "LIBRARY",
            alpha.library.as_uuid(),
            user,
            Action::Container(action),
        )
        .await;
    }
}

// ---------------------------------------------------------------------------------------------
// Authorization — the same-tenant tests, the only ones that prove this route's security
// ---------------------------------------------------------------------------------------------

/// **Authorization layer.** A same-tenant caller with no grant is refused, and told nothing.
///
/// The caller is `fixtures.alpha.member` and the library is alpha's, so row-level security admits
/// every row involved — deleting a `tenant_id` predicate would not make this test fail, and it is
/// not trying to. What it proves is that the trim refuses, that `CLAUDE.md` rule 7 turns the refusal
/// into a `404` rather than a `403` that would confirm the library exists, and that **no row was
/// written**.
///
/// The positive control is the same caller, the same library and the same body after one ACL entry
/// is added: without it, every assertion here passes against a route that refuses everybody, and
/// against a route that was never registered at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_without_the_grant_cannot_create_and_is_told_nothing() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    let body = serde_json::json!({ "name": "Quarterly Reports" });

    let (status, refused) =
        create_folder(&harness, alpha.tenant, user, alpha.library, body.clone()).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: a 403 would confirm the library exists");
    assert_eq!(refused["error"]["code"], "NOT_FOUND", "{refused}");
    assert_eq!(
        folder_count(&db, alpha.tenant, "Quarterly Reports").await,
        0,
        "a refused creation must write no row"
    );

    // The refusal is audited, as a DENY, by the chain rather than by the handler (rule 10).
    let rows = audit_rows(&db, alpha.tenant).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "container.create" && outcome == "DENY"),
        "the denial must be audited: {rows:?}"
    );

    // --- the positive control: one ACL entry is the whole difference ---
    grant_library(&db, &alpha, user).await;

    let (status, created) = create_folder(&harness, alpha.tenant, user, alpha.library, body).await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Quarterly Reports", "{created}");
    assert_eq!(created["type"], "FOLDER", "{created}");
    assert_eq!(created["libraryId"], alpha.library.to_string(), "{created}");
    assert!(created["parentId"].is_null(), "a root folder has no parent: {created}");
    assert_eq!(
        folder_count(&db, alpha.tenant, "Quarterly Reports").await,
        1,
        "the granted creation must write exactly one row"
    );
}

/// **Authorization layer.** The chain is asked about the **named parent**, not the library in the
/// path.
///
/// This is the test that catches the plausible wrong implementation — see the module documentation.
/// `detached_folder` has `inherit_permissions = FALSE`, so the resolver's ancestor walk stops at it
/// and the library grant does not reach it. A handler enforcing against the library would answer
/// `201` here.
///
/// Both halves run against **one** caller holding **one** grant, so the difference between the two
/// requests is the `parentId` field and nothing else. The `201` is the positive control: an
/// implementation that refused every `parentId` outright would pass the first assertion and fail
/// the second.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_named_parent_is_the_container_the_chain_decides_against() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_library(&db, &alpha, user).await;

    // Into the folder the library's grant does not reach.
    let (status, refused) = create_folder(
        &harness,
        alpha.tenant,
        user,
        alpha.library,
        serde_json::json!({ "name": "Band 7", "parentId": alpha.detached_folder.to_string() }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the library's grant must not reach through a folder that broke inheritance: {refused}"
    );
    assert_eq!(
        folder_count(&db, alpha.tenant, "Band 7").await,
        0,
        "nothing may be written inside a container the caller cannot create in"
    );

    // --- the positive control: same caller, same grant, no `parentId` ---
    let (status, created) = create_folder(
        &harness,
        alpha.tenant,
        user,
        alpha.library,
        serde_json::json!({ "name": "Band 7" }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "the library root is grantable and granted: {created}");
    assert_eq!(folder_count(&db, alpha.tenant, "Band 7").await, 1);
}

/// A folder created inside a folder the caller *may* create in carries that parent.
///
/// The tree half of the property above: `container.create` reaching a folder must actually place
/// the child there, rather than silently landing it at the library root — which is the failure
/// `ENC-788` describes for uploads and would be no better here.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_folder_may_be_created_inside_a_folder_the_caller_can_create_in() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_library(&db, &alpha, user).await;

    let (status, parent) = create_folder(
        &harness,
        alpha.tenant,
        user,
        alpha.library,
        serde_json::json!({ "name": "Reports" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{parent}");
    let parent_id = parent["id"].as_str().expect("id").to_owned();

    // The new folder inherits, so the library's grant reaches it and this must be allowed.
    let (status, child) = create_folder(
        &harness,
        alpha.tenant,
        user,
        alpha.library,
        serde_json::json!({ "name": "2026", "parentId": parent_id }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{child}");
    assert_eq!(child["parentId"], parent_id, "the child must be placed in the parent: {child}");
    assert_eq!(child["libraryId"], alpha.library.to_string(), "{child}");
}

/// A duplicate name in one parent is `409`, and the response does not name what collided.
///
/// `docs/05-API.md §5` lists "name collision" among exactly four `409` cases. The status assertion
/// is load-bearing: `crates/files` maps `NameTaken` onto `Error::Validation`, which is a `400`, so a
/// handler that let the blanket conversion run would answer `400` and this fails. The *absence* of
/// the name is asserted because a collision report is the one place a folder the caller has not been
/// shown could be named to them.
///
/// The first `201` is the positive control: without it, "the second request is refused" would pass
/// against a route that refuses every request.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_duplicate_name_in_one_parent_is_a_conflict() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_library(&db, &alpha, user).await;
    let body = serde_json::json!({ "name": "Severance Packages" });

    let (status, first) =
        create_folder(&harness, alpha.tenant, user, alpha.library, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let (status, second) = create_folder(&harness, alpha.tenant, user, alpha.library, body).await;

    assert_eq!(status, StatusCode::CONFLICT, "§5: a name collision is 409, never 400: {second}");
    assert_eq!(second["error"]["code"], "NAME_IN_USE", "{second}");

    let rendered = second.to_string();
    assert!(
        !rendered.contains("Severance Packages"),
        "a collision report must not echo the name: {rendered}"
    );
    assert_eq!(
        folder_count(&db, alpha.tenant, "Severance Packages").await,
        1,
        "the refused second write must leave exactly the first row"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation — documented behaviour, and it proves nothing about the trim
// ---------------------------------------------------------------------------------------------

/// **Isolation layer**, asserted because `T1` is documented and *not* because it isolates anything
/// this handler does.
///
/// Row-level security, the tenant predicate in every statement, and the chain's stage-1 comparison
/// each refuse this independently. It would pass with the authorization stage deleted entirely,
/// which is precisely why the two tests above exist and use a same-tenant caller.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_library_is_absent_rather_than_forbidden() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;
    let user = fixtures.alpha.member;
    grant_library(&db, &alpha, user).await;

    // Alpha's token, beta's library id.
    let (status, refused) = create_folder(
        &harness,
        alpha.tenant,
        user,
        beta.library,
        serde_json::json!({ "name": "Exfiltrated" }),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: cross-tenant is 404, never 403: {refused}");
    assert_eq!(
        folder_count(&db, beta.tenant, "Exfiltrated").await,
        0,
        "nothing may be written into another tenant"
    );

    // The positive control, in the same test and against the same caller: the identical request
    // against alpha's own library succeeds. Without it this test passes against a route that
    // refuses every creation.
    let (status, created) = create_folder(
        &harness,
        alpha.tenant,
        user,
        alpha.library,
        serde_json::json!({ "name": "Exfiltrated" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(folder_count(&db, alpha.tenant, "Exfiltrated").await, 1);
}
