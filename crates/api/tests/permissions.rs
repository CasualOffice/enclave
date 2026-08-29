//! The permissions surface, end to end, over a real PostgreSQL — `ENC-917`.
//!
//! # What was actually missing
//!
//! `enclave_authorization::grant` could write an `acl_entries` row from the day it landed, and its
//! only caller in any binary was the founding grant `POST /admin/workspaces` writes over the
//! workspace it has just made. So every workspace this product could provision was **permanently
//! single-occupant**: the founder held `container.manage_permissions`, every container endpoint
//! reported `managePermissions: true`, and no request in the surface acted on it.
//!
//! [`an_admin_grants_a_second_user_read_and_that_user_can_now_open_the_workspace`] is therefore not
//! a test of a new endpoint so much as the test of whether more than one person can use this
//! product. It is written first because it is the one that fails if the whole feature is absent.
//!
//! # The routes are registered here, and that is a limitation this suite states rather than hides
//!
//! `crates/api/src/lib.rs` is not a file `ENC-917` owns, so the five registrations are made below,
//! with the same paths and the same handlers the integrator must add. What that costs is real and
//! is worth naming: **this suite cannot prove that the shipped router serves these paths.** It
//! proves the handlers, the policy decisions and the writes; a missing line in `router()` would
//! leave every test here green and every request in production a `404`, which is exactly the
//! `ENC-170` shape. `crates/api/tests/reachability.rs` is where that gap is closed once the lines
//! land.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the eleven prior crates in this repository where deleting a
//! `tenant_id` predicate *failed to fail* because row-level security held the property alone.
//!
//! * **Authorization.** [`a_caller_without_manage_permissions_is_refused_and_writes_no_row`] uses
//!   `fixtures.alpha.member` against `fixtures.alpha`'s own workspace, where row-level security has
//!   nothing to say — both principals are alpha's and the workspace row is alpha's — so only the
//!   ACL resolver reading `acl_entries` can tell the two callers apart. That is the test that proves
//!   this surface's security.
//! * **Self-lockout.** [`a_replace_that_would_remove_the_callers_own_management_changes_nothing`] is
//!   the one that cannot be held by any layer below the handler: the caller is permitted, the write
//!   is legal, the rows are all alpha's, and the only thing that refuses is the resolver being asked
//!   about the state the transaction has just written. Its subject is deliberately
//!   `fixtures.alpha.admin`, because a tenant administrator holds `admin.*` and *not*
//!   `container.manage_permissions`, so an implementation that exempted administrators would pass
//!   every other test here and lock the tenant's administrator out of their own workspace.
//! * **Isolation.** [`another_tenants_resource_is_indistinguishable_from_a_malformed_id`] is
//!   asserted because `T1` is documented behaviour, **not** because it isolates anything this
//!   module does: the handler writes no SQL of its own, so what it exercises is the resolver's
//!   predicates and the engine's tenant check. Both tenants are seeded with the same fixture shape
//!   and this test gives them the same workspace name and slug, so it cannot pass merely because
//!   the other tenant's row was called something else.
//! * **Inheritance.** [`a_library_reports_its_own_entries_separately_from_the_ones_above_it`] and
//!   [`breaking_inheritance_detaches_the_child_from_later_changes_to_its_parent`] are about the
//!   chain, and the second carries a control the first cannot: a *second* library in the same
//!   workspace that did not break inheritance, so "the parent's change no longer reaches the child"
//!   is measured against a child it demonstrably still reaches.
//!
//! # Every absence is paired with its positive control
//!
//! "The caller was refused" and "no row was written" both pass for free against a handler that
//! refuses everything, against a broken fixture, and against a route nobody registered. So every
//! refusal below is paired, in the same test and the same run, with the request that succeeds.
//!
//! # Where each assertion reads from
//!
//! The application runs on [`enclave_testing::TestDb::pool_with_connections`], which `SET ROLE
//! enclave_app`s — the composition a deployment runs, with forced row-level security in force.
//! Every assertion about what is **stored** reads over [`enclave_testing::TestDb::connect`], the
//! harness's own superuser connection, for one reason: an assertion that a row was *not* written
//! must not be able to pass because the reader could not see it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::{AdminAuthorization, PgAclAuthorization, PgAdminRoles, SelfServiceOr};
use enclave_core::{ClientType, PolicyEngine, TenantId, UserId};
use enclave_db::DbPool;
use enclave_testing::{Fixtures, TestDb};
use serde_json::{json, Value};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: Router,
    key: PrivateSigningKey,
}

/// A migrated, seeded database and the router over it.
///
/// No workspace fixture is written: the surface under test is reached from a workspace this suite
/// provisions through `POST /admin/workspaces`, which is the state a real installation is in and
/// the only way a workspace acquires its founding grant.
async fn setup() -> (TestDb, Fixtures, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");

    // Eight, as `tests/workspace_create.rs`: a provisioning holds one connection for its whole
    // transaction and resolves capabilities on a second after it commits, and the permissions
    // handlers do the same. A narrow pool deadlocks this suite for a reason unrelated to anything
    // it asserts.
    let pool = db.pool_with_connections(8).await.expect("application pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization(&pool),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, pool.clone(), ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    let harness = Harness { app: app(state), key };
    (db, fixtures, harness)
}

/// The shipped router, plus the five registrations `ENC-917` adds to it.
///
/// Written out here rather than composed, so that the lines the integrator must add to
/// `crates/api/src/lib.rs` are visible in one place and can be compared against it character by
/// character. See the module header for what this arrangement cannot prove.
/// The shipped router, and nothing beside it.
///
/// This function existed to `merge` a local `Router` carrying the five permission routes, because
/// the task that wrote these tests did not own `crates/api/src/lib.rs`. That shim is deleted now
/// that the registrations have landed, and deleting it is the point rather than tidiness: a suite
/// that mounts its own handlers proves the handlers work and says nothing about whether any request
/// can reach them. This repository has shipped that exact shape a dozen times — a complete, tested,
/// green component the composed binary never calls — and `crates/api/tests/reachability.rs` exists
/// because of it. If a `.route` line for these paths is ever dropped from `router()`, every test
/// below must go red.
fn app(state: ApiState) -> Router {
    router(state, enclave_api::Delivery::unconfigured())
}

/// The authorization stack `crates/api/src/main.rs` composes.
///
/// All three layers are load-bearing here. `PgAdminRoles` decides the `admin.write_config` that
/// provisions the workspace these tests start from; `PgAclAuthorization` decides every
/// `manage_permissions` below; `SelfServiceOr` answers `container.read` on a caller's own `users`
/// row, which `GET /workspaces` enforces against. Wiring one alone would exercise a composition no
/// deployment runs (`ENC-746`) — and, worse, would decide the lockout check by a different stack
/// from the one that will refuse the caller afterwards.
fn authorization(pool: &DbPool) -> Arc<dyn enclave_core::AuthorizationService> {
    Arc::new(AdminAuthorization::new(
        Arc::new(PgAdminRoles::new(pool.clone())),
        Arc::new(SelfServiceOr::new(PgAclAuthorization::new(pool.clone()))),
    ))
}

/// A bearer token. Every call presents a second factor, because provisioning the workspace these
/// tests start from is an administrative mutation and `docs/05-API.md §14` requires one for that.
fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: Uuid::new_v4(),
        typ: enclave_core::ActorKind::User,
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

async fn send(harness: &Harness, request: Request<Body>) -> (StatusCode, Value) {
    let response = harness.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let json =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
    (status, json)
}

async fn get(harness: &Harness, tenant: TenantId, user: UserId, uri: &str) -> (StatusCode, Value) {
    send(
        harness,
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

async fn post(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    send(
        harness,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

async fn put(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    send(
        harness,
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------------------------

/// Provisions a workspace and returns its id.
async fn workspace(harness: &Harness, tenant: TenantId, admin: UserId, slug: &str) -> String {
    let (status, created) = post(
        harness,
        tenant,
        admin,
        "/api/v1/admin/workspaces",
        json!({ "name": "Engineering", "slug": slug }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the suite's own fixture must provision: {created}");
    created["id"].as_str().expect("an id").to_owned()
}

/// Creates a library inside a workspace and returns its id.
async fn library(
    harness: &Harness,
    tenant: TenantId,
    founder: UserId,
    workspace: &str,
    slug: &str,
) -> String {
    let (status, created) = post(
        harness,
        tenant,
        founder,
        &format!("/api/v1/workspaces/{workspace}/libraries"),
        json!({ "name": "Documents", "slug": slug }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the suite's own fixture must create: {created}");
    created["id"].as_str().expect("an id").to_owned()
}

/// The resource's explicit ACL, as a `PUT` body that would leave it exactly as it is.
///
/// This is what a permissions dialog does — read the set, change one row, send the whole thing back
/// — and it is why the tests below never restate `routes::workspaces::FOUNDING_GRANT`. A suite that
/// hard-coded the founder's thirteen actions would have to be edited every time that grant changed,
/// and would silently stop asserting anything the day the two lists drifted.
fn resend(view: &Value) -> Vec<Value> {
    view["explicit"]
        .as_array()
        .expect("an explicit list")
        .iter()
        .map(|entry| {
            json!({
                "principal": entry["principal"],
                "action": entry["action"],
                "effect": entry["effect"],
                "expiresAt": entry["expiresAt"],
            })
        })
        .collect()
}

/// One declared entry naming a user.
fn allow(user: UserId, action: &str) -> Value {
    json!({
        "principal": { "kind": "USER", "id": user.as_uuid() },
        "action": action,
        "effect": "ALLOW",
        "expiresAt": Value::Null,
    })
}

/// The set `view` holds, with `extra` appended.
/// The same, refusing instead of granting.
///
/// A companion to [`allow`] rather than a parameter on it, because every call site that writes a
/// `DENY` is making a different kind of statement and should read like one.
fn deny(user: UserId, action: &str) -> Value {
    serde_json::json!({
        "principal": { "kind": "USER", "id": user.to_string() },
        "action": action,
        "effect": "DENY",
    })
}

fn plus(view: &Value, extra: Value) -> Value {
    let mut entries = resend(view);
    entries.push(extra);
    json!({ "entries": entries })
}

/// The set `view` holds, minus every entry naming `action`.
fn without(view: &Value, action: &str) -> Value {
    let entries: Vec<Value> =
        resend(view).into_iter().filter(|entry| entry["action"] != action).collect();
    json!({ "entries": entries })
}

/// The set `view` holds, minus every entry naming `user`.
fn without_user(view: &Value, user: UserId) -> Value {
    let id = json!(user.as_uuid());
    let entries: Vec<Value> =
        resend(view).into_iter().filter(|entry| entry["principal"]["id"] != id).collect();
    json!({ "entries": entries })
}

// ---------------------------------------------------------------------------------------------
// Reading what is stored, over the connection that can see everything
// ---------------------------------------------------------------------------------------------

/// Every `acl_entries` row on one resource, as `(principal_id, action, effect)`, sorted.
///
/// Read over the harness's superuser connection on purpose: an assertion that a row was **not**
/// written must not be able to pass because the reader could not see it.
async fn stored(db: &TestDb, tenant: TenantId, kind: &str, id: &str) -> Vec<(String, String)> {
    let mut conn = db.connect().await.expect("connect");
    let rows: Vec<(Option<Uuid>, String, String)> = sqlx::query_as(
        "SELECT principal_id, action, effect FROM acl_entries
          WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
          ORDER BY principal_id NULLS FIRST, action",
    )
    .bind(tenant.as_uuid())
    .bind(kind)
    .bind(id.parse::<Uuid>().expect("a resource id"))
    .fetch_all(&mut conn)
    .await
    .expect("read acl entries");

    rows.into_iter()
        .map(|(principal, action, effect)| {
            (
                format!(
                    "{}/{action}",
                    principal.map_or_else(|| "EVERYONE".to_owned(), |p| p.to_string())
                ),
                effect,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The journey this whole item exists for
// ---------------------------------------------------------------------------------------------

/// An administrator provisions a workspace, lets a second user in, and that user can open it.
///
/// **The test `ENC-917` exists for.** Before it, `routes::workspaces::create` wrote the founding
/// grant and nothing in the product could ever write a second one, so `fixtures.alpha.member` below
/// could not have been admitted to this workspace by any sequence of HTTP requests whatsoever.
///
/// The `404` before the grant is the positive control for the `200` after it, and it has to be in
/// the same run: on its own, "the member can read it" passes against a `container.read` that admits
/// everybody, and "the member cannot read it" passes against a workspace that was never created.
/// The pair can only both hold if the `PUT` in between did something.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_admin_grants_a_second_user_read_and_that_user_can_now_open_the_workspace() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;

    // Before: the founding grant names the founder alone, so the workspace does not exist as far as
    // anybody else in the tenant is concerned (`CLAUDE.md` rule 7).
    let (status, refused) =
        get(&harness, tenant, member, &format!("/api/v1/workspaces/{workspace}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the single-occupant state: {refused}");

    let (status, before) =
        get(&harness, tenant, founder, &format!("/api/v1/workspaces/{workspace}/permissions"))
            .await;
    assert_eq!(status, StatusCode::OK, "{before}");

    let (status, changed) = put(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/workspaces/{workspace}/permissions"),
        plus(&before, allow(member, "container.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["added"], 1, "exactly one entry is new: {changed}");
    assert_eq!(changed["removed"], 0, "the founder's own entries were re-sent: {changed}");

    // After: the same request, from the same user, now succeeds. This line is the item.
    let (status, opened) =
        get(&harness, tenant, member, &format!("/api/v1/workspaces/{workspace}")).await;
    assert_eq!(status, StatusCode::OK, "the second user must now be able to open it: {opened}");
    assert_eq!(opened["id"], workspace, "{opened}");
    assert_eq!(
        opened["capabilities"]["read"], true,
        "the capability object must agree with the grant that was just written: {opened}"
    );
    assert_eq!(
        opened["capabilities"]["managePermissions"], false,
        "read is one action; a grant of it must not confer the action that grants: {opened}"
    );

    // And the row is on the workspace, over the connection that can see every row in the cluster.
    let rows = stored(&db, tenant, "WORKSPACE", &workspace).await;
    assert!(
        rows.contains(&(format!("{}/container.read", member.as_uuid()), "ALLOW".to_owned())),
        "the entry must be stored, not merely reported: {rows:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Authorization — the same-tenant test, the only one that proves this surface's security
// ---------------------------------------------------------------------------------------------

/// A caller who does not hold `manage_permissions` is answered `404`, and writes nothing.
///
/// Both principals are alpha's and the workspace is alpha's, so row-level security admits every row
/// involved and would not notice a missing predicate. What this proves is that the authorization
/// stage refuses a caller with no `container.manage_permissions` entry, that the refusal is a `404`
/// rather than a `403` — a `403` would confirm the workspace exists — and that the ACL is unchanged
/// afterwards.
///
/// The positive control is the identical request from the founder.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_without_manage_permissions_is_refused_and_writes_no_row() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;
    let before = stored(&db, tenant, "WORKSPACE", &workspace).await;

    // The read is refused too, and with the same status: an ACL is a list of who is in a room, and
    // a caller who may not manage it may not enumerate it either.
    let (status, refused) =
        get(&harness, tenant, member, &format!("/api/v1/workspaces/{workspace}/permissions")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: a 403 would confirm it exists: {refused}");
    assert_eq!(refused["error"]["code"], "NOT_FOUND", "{refused}");

    let (status, refused) = put(
        &harness,
        tenant,
        member,
        &format!("/api/v1/workspaces/{workspace}/permissions"),
        json!({ "entries": [allow(member, "container.manage_permissions")] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");
    assert_eq!(
        stored(&db, tenant, "WORKSPACE", &workspace).await,
        before,
        "a refused replace must write nothing at all"
    );

    // --- the positive control: the same two requests, from the founder ---
    let (status, view) =
        get(&harness, tenant, founder, &format!("/api/v1/workspaces/{workspace}/permissions"))
            .await;
    assert_eq!(status, StatusCode::OK, "{view}");

    let (status, changed) = put(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/workspaces/{workspace}/permissions"),
        plus(&view, allow(member, "container.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_ne!(
        stored(&db, tenant, "WORKSPACE", &workspace).await,
        before,
        "the control must actually change something, or the assertion above proves nothing"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------------------------

/// A `tenant-beta` workspace id and a malformed one are the same answer to an alpha caller.
///
/// Both tenants are provisioned with the same name and the same slug, so this cannot pass merely
/// because beta's row was called something else. The two refusals are compared field by field
/// rather than only by status: a body that differed — a distinct code, a populated `details` — would
/// tell an attacker which of their guesses was a well-formed identifier and which named a real
/// resource, which is the enumeration oracle rule 7 exists to close.
///
/// The positive control is alpha's own workspace, without which every assertion here passes against
/// a handler that answers `404` to everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_resource_is_indistinguishable_from_a_malformed_id() {
    let (_db, fixtures, harness) = setup().await;

    let mine = workspace(&harness, fixtures.alpha.id, fixtures.alpha.admin, "engineering").await;
    let theirs = workspace(&harness, fixtures.beta.id, fixtures.beta.admin, "engineering").await;
    assert_ne!(mine, theirs, "the two tenants must hold two different workspaces");

    let caller = fixtures.alpha.admin;
    let (foreign_status, mut foreign) = get(
        &harness,
        fixtures.alpha.id,
        caller,
        &format!("/api/v1/workspaces/{theirs}/permissions"),
    )
    .await;
    let (garbage_status, mut garbage) = get(
        &harness,
        fixtures.alpha.id,
        caller,
        "/api/v1/workspaces/not-a-workspace-id/permissions",
    )
    .await;

    assert_eq!(foreign_status, StatusCode::NOT_FOUND, "{foreign}");
    assert_eq!(garbage_status, StatusCode::NOT_FOUND, "{garbage}");

    // The request id is the one field that must differ, so it is removed before the comparison and
    // asserted to have been there.
    for body in [&mut foreign, &mut garbage] {
        assert!(
            body["error"]["requestId"].is_string(),
            "every refusal carries a correlation id: {body}"
        );
        let _removed = body["error"]
            .as_object_mut()
            .expect("an error object")
            .remove("requestId")
            .expect("a request id");
    }
    assert_eq!(
        foreign, garbage,
        "another tenant's id and a malformed one must be one answer, byte for byte"
    );

    // --- the positive control: alpha's own workspace, to the same caller ---
    let (status, view) =
        get(&harness, fixtures.alpha.id, caller, &format!("/api/v1/workspaces/{mine}/permissions"))
            .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["resource"]["id"], mine, "{view}");
}

// ---------------------------------------------------------------------------------------------
// The lockout check — the property no layer below the handler can hold
// ---------------------------------------------------------------------------------------------

/// A replace that would remove the caller's own `manage_permissions` is refused, and changes
/// nothing.
///
/// The subject is `fixtures.alpha.admin` deliberately. A tenant administrator holds `admin.*` from
/// `users.is_admin` and holds **no** `container.manage_permissions` from it, so an implementation
/// that exempted administrators from this check — a plausible-looking kindness — would let the one
/// principal who cannot be rescued by anybody else write the set that locks them out. Every other
/// test in this file would still pass.
///
/// "Changes nothing" is asserted against the stored rows rather than against the response, because
/// the failure this catches is a replace that committed and *then* failed its safety check: the
/// caller sees a `409` and the workspace is gone regardless.
///
/// The positive control is a replace that removes a *different* action from the same caller in the
/// same run, which must succeed — without it, this passes against a `PUT` that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_replace_that_would_remove_the_callers_own_management_changes_nothing() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let uri = {
        let workspace = workspace(&harness, tenant, founder, "engineering").await;
        format!("/api/v1/workspaces/{workspace}/permissions")
    };
    let workspace_id =
        uri.trim_start_matches("/api/v1/workspaces/").trim_end_matches("/permissions").to_owned();

    let (status, view) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    let before = stored(&db, tenant, "WORKSPACE", &workspace_id).await;

    let (status, refused) =
        put(&harness, tenant, founder, &uri, without(&view, "container.manage_permissions")).await;
    assert_eq!(status, StatusCode::CONFLICT, "a rejected state is a 409, not a 403: {refused}");
    assert_eq!(refused["error"]["code"], "WOULD_REMOVE_OWN_MANAGE_PERMISSIONS", "{refused}");
    assert_eq!(
        stored(&db, tenant, "WORKSPACE", &workspace_id).await,
        before,
        "the write and its safety check share one transaction; a refusal must leave the ACL whole"
    );

    // The caller is still able to manage the workspace, which is the thing the refusal protected.
    let (status, again) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["explicit"], view["explicit"], "the set the caller reads back is unchanged");

    // --- the positive control: dropping an action that is not the one that grants ---
    let (status, changed) =
        put(&harness, tenant, founder, &uri, without(&view, "file.download")).await;
    assert_eq!(status, StatusCode::OK, "an ordinary narrowing must proceed: {changed}");
    assert_eq!(changed["removed"], 1, "exactly the omitted entry went: {changed}");
    let after = stored(&db, tenant, "WORKSPACE", &workspace_id).await;
    assert_eq!(after.len(), before.len() - 1, "one row fewer: {after:?}");
}

// ---------------------------------------------------------------------------------------------
// A replace is a replace
// ---------------------------------------------------------------------------------------------

/// An entry omitted from the body is gone afterwards, and the caller stops being able to see the
/// resource.
///
/// The observable half matters more than the row count: an implementation that merged rather than
/// replaced would leave the member's `container.read` in place, report a plausible response, and
/// only be caught by asking the member. So the assertion is made twice, once against the stored
/// rows and once against a request the member makes.
///
/// The positive control is the founder's own entries, which must survive the same `PUT` — without
/// it, "the member's row is gone" passes against a replace that deletes everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_entry_omitted_from_the_body_is_gone_afterwards() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;
    let uri = format!("/api/v1/workspaces/{workspace}/permissions");

    let (_, view) = get(&harness, tenant, founder, &uri).await;
    let founder_rows = stored(&db, tenant, "WORKSPACE", &workspace).await.len();

    let (status, changed) =
        put(&harness, tenant, founder, &uri, plus(&view, allow(member, "container.read"))).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    let (status, opened) =
        get(&harness, tenant, member, &format!("/api/v1/workspaces/{workspace}")).await;
    assert_eq!(status, StatusCode::OK, "the grant must take effect first: {opened}");

    // Now send the set back without the member. Nothing says "remove"; the omission is the removal.
    let (_, current) = get(&harness, tenant, founder, &uri).await;
    let (status, changed) =
        put(&harness, tenant, founder, &uri, without_user(&current, member)).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["removed"], 1, "the omitted entry is the one that went: {changed}");

    let rows = stored(&db, tenant, "WORKSPACE", &workspace).await;
    assert!(
        !rows.iter().any(|(key, _)| key.starts_with(&member.as_uuid().to_string())),
        "the member's entry must be gone from storage: {rows:?}"
    );
    assert_eq!(rows.len(), founder_rows, "and the founder's own entries must all still be there");

    let (status, refused) =
        get(&harness, tenant, member, &format!("/api/v1/workspaces/{workspace}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the member must lose access, not merely a row: {refused}"
    );
}

// ---------------------------------------------------------------------------------------------
// Inheritance
// ---------------------------------------------------------------------------------------------

/// A library reports the entries stored on it separately from the ones that reach it from above.
///
/// This is the distinction a permissions screen is *for*: "Finance has read here" and "Finance has
/// read on the workspace above" are different facts with different remedies, and a response that
/// collapsed them would leave a client unable to explain either.
///
/// Both directions are asserted in one run, which is what makes them mean anything: `explicit` is
/// empty while `effective` is not, and then — after one entry is written on the library itself —
/// `explicit` holds exactly that entry while `effective` still holds the workspace's.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_reports_its_own_entries_separately_from_the_ones_above_it() {
    let (_db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;
    let library = library(&harness, tenant, founder, &workspace, "documents").await;
    let uri = format!("/api/v1/libraries/{library}/permissions");

    let (status, view) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["resource"]["kind"], "LIBRARY", "{view}");
    assert_eq!(view["inherits"], true, "a fresh library inherits from its workspace: {view}");
    assert!(
        view["explicit"].as_array().expect("explicit").is_empty(),
        "nothing has been written on the library itself: {view}"
    );

    let effective = view["effective"].as_array().expect("effective");
    assert!(
        !effective.is_empty(),
        "the founder reaches this library through the workspace, and that has to be visible: {view}"
    );
    assert!(
        effective.iter().all(|entry| entry["source"]["kind"] == "WORKSPACE"),
        "every entry reaching it is the workspace's, and each says so: {view}"
    );
    assert!(
        effective.iter().any(|entry| entry["source"]["id"] == workspace.as_str()
            && entry["action"] == "container.manage_permissions"),
        "including the one that authorised this very request: {view}"
    );

    // Now write one entry on the library itself.
    let (status, changed) =
        put(&harness, tenant, founder, &uri, json!({ "entries": [allow(member, "container.read"), allow(founder, "container.manage_permissions")] })).await;
    assert_eq!(status, StatusCode::OK, "{changed}");

    let (status, view) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    let explicit = view["explicit"].as_array().expect("explicit");
    assert_eq!(explicit.len(), 2, "the library now holds exactly what was declared: {view}");
    assert!(
        explicit.iter().all(|entry| entry["source"]["id"] == library.as_str()),
        "an explicit entry is stored on the resource itself: {view}"
    );
    assert!(
        view["effective"].as_array().expect("effective").len() > explicit.len(),
        "the workspace's entries still reach it, so effective is the larger set: {view}"
    );
}

/// Breaking inheritance copies the effective set down, and a later change above no longer reaches.
///
/// `ENC-141` is why the copy has to happen: flipping `inherit_permissions` alone truncates the
/// resolver's walk, so an ancestor `DENY` stops applying and *breaking* inheritance **gains**
/// privilege. The neutrality assertion below — the member can still open the library immediately
/// afterwards — is the observable form of that.
///
/// The control is a **second** library in the same workspace that did not break inheritance. Without
/// it, "the parent's change no longer reaches the child" passes against a workspace `PUT` that did
/// nothing at all; with it, the same change is measured against a child it demonstrably still
/// reaches, in the same run and through the same request.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn breaking_inheritance_detaches_the_child_from_later_changes_to_its_parent() {
    let (_db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;
    let detached = library(&harness, tenant, founder, &workspace, "detached").await;
    let attached = library(&harness, tenant, founder, &workspace, "attached").await;
    let workspace_acl = format!("/api/v1/workspaces/{workspace}/permissions");

    // The member is let into the workspace, and therefore into both libraries beneath it.
    let (_, view) = get(&harness, tenant, founder, &workspace_acl).await;
    let (status, changed) = put(
        &harness,
        tenant,
        founder,
        &workspace_acl,
        plus(&view, allow(member, "container.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    for library in [&detached, &attached] {
        let (status, opened) =
            get(&harness, tenant, member, &format!("/api/v1/libraries/{library}")).await;
        assert_eq!(status, StatusCode::OK, "inheritance must reach {library} first: {opened}");
    }

    // Break one of them.
    let (status, broken) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/libraries/{detached}/permissions/break-inheritance"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{broken}");
    assert_eq!(broken["inherits"], false, "the flag is flipped: {broken}");

    let explicit = broken["explicit"].as_array().expect("explicit");
    assert!(
        explicit.iter().any(|entry| entry["principal"]["id"] == json!(member.as_uuid())
            && entry["action"] == "container.read"),
        "the entries that were in force are now stored on the library: {broken}"
    );
    assert!(
        explicit.iter().any(|entry| entry["inheritedFrom"] == workspace.as_str()),
        "and a copied entry says where it came from, so the break is auditable: {broken}"
    );

    // Neutral by construction: nobody's access changed.
    let (status, opened) =
        get(&harness, tenant, member, &format!("/api/v1/libraries/{detached}")).await;
    assert_eq!(status, StatusCode::OK, "a break must grant and revoke nothing: {opened}");

    // Now take the member back out of the workspace.
    let (_, current) = get(&harness, tenant, founder, &workspace_acl).await;
    let (status, changed) =
        put(&harness, tenant, founder, &workspace_acl, without_user(&current, member)).await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert_eq!(changed["removed"], 1, "{changed}");

    // The control and the claim, from the same change.
    let (status, refused) =
        get(&harness, tenant, member, &format!("/api/v1/libraries/{attached}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the library that still inherits must lose access with the workspace: {refused}"
    );
    let (status, still) =
        get(&harness, tenant, member, &format!("/api/v1/libraries/{detached}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the library that broke inheritance keeps the entries it materialised: {still}"
    );

    // And a second break is refused rather than silently repeated: two callers who both believe
    // they are establishing this library's ACL must not both be told they succeeded.
    let (status, again) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/libraries/{detached}/permissions/break-inheritance"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");
}

// ---------------------------------------------------------------------------------------------
// The content half of the surface
// ---------------------------------------------------------------------------------------------

/// A folder is managed under `file.manage_permissions`, and its entries are stored as `FOLDER`.
///
/// Three properties that only the content path can hold, and each of them is a real defect if it is
/// wrong:
///
/// * **The action is the file one.** `crates/authorization/src/repo.rs` matches the action column by
///   string equality, so a folder decided by `container.manage_permissions` would resolve against
///   rows nobody has written. The founding grant proves the split is real rather than pedantic: it
///   confers the whole container vocabulary and **no** `file.manage_permissions`, so the founder of
///   this workspace starts out unable to manage the folder inside it, and has to grant themselves
///   that action first. That is the first assertion below.
/// * **The rows are written under `FOLDER`.** `("FILE", folder_id)` satisfies the `resource_type`
///   `CHECK`, is accepted by `uq_acl_entry`, and resolves against nothing — a replace that reported
///   success and granted nobody anything. The stored rows are read back over the superuser
///   connection under the exact spelling.
/// * **The lockout check is about the effective answer.** The `PUT` below declares one entry, for
///   somebody else, and does not name the caller at all — and it must succeed, because the
///   workspace above still grants the caller `file.manage_permissions`. An implementation that
///   asked "did an explicit row naming me survive" would refuse this, and would make it impossible
///   to hand a folder over to somebody without first pinning yourself to it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_folder_is_managed_under_the_file_action_and_its_entries_are_stored_as_a_folder() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;
    let member = fixtures.alpha.member;

    let workspace = workspace(&harness, tenant, founder, "engineering").await;
    let library = library(&harness, tenant, founder, &workspace, "documents").await;
    let (status, created) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/libraries/{library}/folders"),
        json!({ "name": "Board" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the suite's own fixture must create: {created}");
    let folder = created["id"].as_str().expect("an id").to_owned();
    let uri = format!("/api/v1/files/{folder}/permissions");

    // The founding grant confers `container.manage_permissions` and not the file action, so the
    // founder cannot yet manage this folder — and is told so with the answer that confirms nothing.
    let (status, refused) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "container.manage_permissions must not imply file.manage_permissions: {refused}"
    );

    // So they grant it to themselves on the workspace, which is a thing they *do* hold.
    let workspace_acl = format!("/api/v1/workspaces/{workspace}/permissions");
    let (_, view) = get(&harness, tenant, founder, &workspace_acl).await;
    let (status, changed) = put(
        &harness,
        tenant,
        founder,
        &workspace_acl,
        plus(&view, allow(founder, "file.manage_permissions")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");

    let (status, view) = get(&harness, tenant, founder, &uri).await;
    assert_eq!(status, StatusCode::OK, "the grant must reach the folder by inheritance: {view}");
    assert_eq!(
        view["resource"]["kind"], "FOLDER",
        "a `/files/{{id}}` path resolves its kind: {view}"
    );
    assert_eq!(view["resource"]["id"], folder, "{view}");
    assert!(
        view["aclRevision"].is_i64(),
        "a content node carries the counter the index reads: {view}"
    );
    assert!(
        view["explicit"].as_array().expect("explicit").is_empty(),
        "nothing has been written on the folder itself: {view}"
    );
    assert!(
        view["effective"]
            .as_array()
            .expect("effective")
            .iter()
            .any(|entry| entry["action"] == "file.manage_permissions"),
        "the entry that authorised this request must be visible in the effective set: {view}"
    );

    // The member cannot open it yet — the positive control for the request that follows.
    let (status, refused) = get(&harness, tenant, member, &format!("/api/v1/files/{folder}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{refused}");

    // One entry, naming somebody else and not the caller. It must succeed: the caller's own
    // management is inherited from the workspace and survives a set that does not mention them.
    let (status, changed) = put(
        &harness,
        tenant,
        founder,
        &uri,
        json!({ "entries": [allow(member, "file.metadata_read")] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "inheritance still grants the caller manage_permissions, so this is not a lockout: {changed}"
    );
    assert_eq!(changed["added"], 1, "{changed}");

    let rows = stored(&db, tenant, "FOLDER", &folder).await;
    assert_eq!(
        rows,
        vec![(format!("{}/file.metadata_read", member.as_uuid()), "ALLOW".to_owned())],
        "the row must be stored under FOLDER, which is the spelling the resolver joins back on"
    );

    let (status, opened) = get(&harness, tenant, member, &format!("/api/v1/files/{folder}")).await;
    assert_eq!(status, StatusCode::OK, "the member must now be able to open it: {opened}");

    // And the content half of the break, which is the one `docs/05-API.md §7` names.
    let (status, broken) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/files/{folder}/permissions/break-inheritance"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{broken}");
    assert_eq!(broken["inherits"], false, "{broken}");
    assert!(
        broken["explicit"]
            .as_array()
            .expect("explicit")
            .iter()
            .any(|entry| entry["inheritedFrom"] == workspace.as_str()),
        "the workspace's entries are now stored on the folder, and say where they came from: {broken}"
    );
}

/// **A stored `DENY` can be lifted to an `ALLOW` in one `PUT`.**
///
/// `enclave_authorization::grant::grant` refuses to overwrite a `DENY` — `GrantError::DenyInPlace`,
/// and that refusal is right where it lives: a grant is an *incremental* act, and erasing a decisive
/// denial as a side effect of one is the weakening `ENC-916` refused to ship.
///
/// A replace is not incremental. It is a caller holding `manage_permissions` stating the complete
/// intended set, and if it inherited that refusal then a `DENY` would be unremovable by any route
/// this product serves — a permissions screen could show one and never lift it.
///
/// The failure this catches is narrow, which is exactly why it needs a test rather than an argument:
/// *omitting* the deny already removed it, so only changing one to an allow in a single call broke,
/// and it broke with a `409` rather than by wrongly granting. Nothing about the response would have
/// looked like a defect.
///
/// The positive control is the last leg: the lifted entry must actually *work*, resolved through the
/// chain rather than merely stored, because a row that says `ALLOW` and does not admit anybody is
/// the same bug one layer down.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stored_deny_can_be_lifted_to_an_allow_in_one_replace() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let admin = fixtures.alpha.admin;
    let other = fixtures.alpha.member;
    let id = workspace(&harness, tenant, admin, "deny-lift").await;

    // A deny is written, and it bites: `DENY` beats every `ALLOW` in the chain, so the member is
    // refused even though the same call grants them `container.read`.
    let (status, view) =
        get(&harness, tenant, admin, &format!("/api/v1/workspaces/{id}/permissions")).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    // Built by hand rather than by nesting `plus`: that helper takes a GET *view* and returns a PUT
    // *body*, so feeding one to the other looks for an `explicit` key a body does not have.
    let mut both = resend(&view);
    both.push(allow(other, "container.read"));
    both.push(deny(other, "container.read"));
    let denied = json!({ "entries": both });
    // The two entries above name one `(principal, action)` slot with different content, which the
    // engine refuses outright rather than resolving by a rule.
    let (status, refusal) =
        put(&harness, tenant, admin, &format!("/api/v1/workspaces/{id}/permissions"), denied).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a self-contradictory set is refused: {refusal}");

    // So: deny alone.
    let (status, written) = put(
        &harness,
        tenant,
        admin,
        &format!("/api/v1/workspaces/{id}/permissions"),
        plus(&view, deny(other, "container.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{written}");
    let (status, _) = get(&harness, tenant, other, &format!("/api/v1/workspaces/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the deny must actually refuse before it is lifted");

    // The lift, in one call. This is the leg that answered `409 DENY_IN_PLACE` before `ENC-917`.
    let (status, lifted) = put(
        &harness,
        tenant,
        admin,
        &format!("/api/v1/workspaces/{id}/permissions"),
        plus(&view, allow(other, "container.read")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a replace must be able to lift a stored deny: {lifted}");

    let stored_now = stored(&db, tenant, "WORKSPACE", &id).await;
    assert!(
        stored_now
            .iter()
            .any(|(slot, effect)| slot.ends_with("/container.read") && effect == "ALLOW"),
        "the slot must now hold the allow: {stored_now:?}"
    );
    assert!(
        !stored_now
            .iter()
            .any(|(slot, effect)| slot.ends_with("/container.read") && effect == "DENY"),
        "and not both — `uq_acl_entry` has room for one: {stored_now:?}"
    );

    // The positive control: stored is not the same as effective.
    let (status, opened) = get(&harness, tenant, other, &format!("/api/v1/workspaces/{id}")).await;
    assert_eq!(status, StatusCode::OK, "the lifted entry must admit the caller it names: {opened}");
}
