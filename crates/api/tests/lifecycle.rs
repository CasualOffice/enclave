//! The file lifecycle, end to end, over a real PostgreSQL — `ENC-807`.
//!
//! # What was actually missing
//!
//! `FileRepository::rename`, `reparent`, `trash` and `restore` have existed since M1 — with the
//! composite keys, the recursive cycle guard, the cascade and the exact-timestamp restore
//! discriminator — and **none of them had a caller in any binary**. So every folder
//! `POST /libraries/{id}/folders` could create was permanent: it could not be renamed, could not be
//! moved, and could not be deleted by any sequence of HTTP requests whatsoever.
//!
//! [`a_folder_can_be_renamed_moved_trashed_and_restored_and_is_browsable_at_the_end`] is therefore
//! not a test of three new endpoints so much as the test of whether this product can be used as a
//! document repository at all. It is written first because it is the one that fails if the whole
//! feature is absent.
//!
//! # The routes under test are the shipped ones
//!
//! [`setup`] builds [`enclave_api::router`] and nothing beside it — there is no local `Router`, no
//! `merge`, and no registration in this file. A suite that mounted its own handlers would prove the
//! handlers work and say nothing about whether any request can reach them; this repository has
//! shipped that exact shape a dozen times, and `crates/api/tests/reachability.rs` exists because of
//! it. **That is not a claim, it is measured**: against `crates/api/src/lib.rs` as it stands before
//! the three registrations land, every test in this file answers `405` and fails. If a `.route`
//! line for these paths is ever dropped again, all nine go red the same way.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the eleven prior instances in this repository where deleting a
//! `tenant_id` predicate *failed to fail* because row-level security held the property alone. The
//! integration harness connects the application as `enclave_app` with forced RLS, but every
//! assertion about what is **stored** reads over the harness's superuser connection, where nothing
//! is filtered — so an assertion that a row did *not* change cannot pass because the reader could
//! not see it.
//!
//! * **Authorization — the escalation.**
//!   [`a_move_into_a_container_the_caller_cannot_write_to_is_refused_and_moves_nothing`] is the test
//!   that matters most. Both the file and the destination are alpha's, and the caller is alpha's own
//!   founder, so row-level security has nothing to say and only the `container.create` question
//!   asked of the *destination* can refuse it. Delete that question from `routes::lifecycle::update`
//!   and the request answers `200`, the file lands in a folder the caller cannot write to, and this
//!   is the only test in the file that notices.
//! * **Authorization — the cascade.**
//!   [`trashing_a_folder_whose_child_denies_delete_refuses_the_whole_subtree`] is the second. It
//!   builds `ENC-141`'s shape on purpose: a child with `inherit_permissions = FALSE` and an explicit
//!   `DENY`, so the grant that admits the parent does not reach it. Authorizing only the addressed
//!   node answers `200` and trashes a document the caller holds no `file.delete` on.
//! * **Concurrency.** [`a_rename_without_an_if_match_changes_nothing`] and
//!   [`a_rename_with_a_stale_if_match_changes_nothing`] are held by nothing below the handler:
//!   `Mutation::expected_revision` is an `Option` and the repository will happily write
//!   unconditionally when handed `None`.
//! * **Isolation.** [`another_tenants_file_is_indistinguishable_from_a_malformed_id`] is asserted
//!   because `T1` is documented behaviour, **not** because it isolates anything these handlers do:
//!   what it exercises is the resolver's predicates and the engine's tenant check. Both tenants are
//!   given the same workspace slug, the same library slug and the same folder names, so it cannot
//!   pass merely because the other tenant's rows were called something else.
//!
//! # Every absence is paired with its positive control
//!
//! "The caller was refused" and "nothing moved" both pass for free against a handler that refuses
//! everything, against a broken fixture, and against a route nobody registered. So every refusal
//! below is paired, in the same test and the same run, with the request that succeeds.
//!
//! # The fixtures are built through the shipped surface
//!
//! Workspaces, libraries, folders and every ACL change below are made with `POST /admin/workspaces`,
//! `POST /workspaces/{id}/libraries`, `POST /libraries/{id}/folders`,
//! `PUT /{resource}/permissions` and `POST /files/{id}/permissions/break-inheritance`. Nothing is
//! inserted by hand. That is slower than writing rows and it is what makes the `DENY` fixture
//! meaningful: a permission this product cannot express through its own API is not a permission any
//! tenant will ever hold.
//!
//! One consequence is worth stating, because it is a finding rather than a detail:
//! `routes::workspaces::FOUNDING_GRANT` contains **neither `file.move` nor `file.restore` nor
//! `file.manage_permissions`**, so a founder cannot move, restore or re-permission anything in the
//! workspace they just made. [`arm`] grants the three at the workspace, through
//! `PUT /workspaces/{id}/permissions`, which is the only route by which a real deployment could do
//! it either.

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
/// No workspace fixture is written: everything these tests act on is reached from a workspace the
/// suite provisions through `POST /admin/workspaces`, which is the state a real installation is in
/// and the only way a workspace acquires its founding grant.
async fn setup() -> (TestDb, Fixtures, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");

    // Eight, as `tests/permissions.rs` and `tests/workspace_create.rs`: a mutation holds one
    // connection for its transaction and resolves capabilities on a second afterwards, and the
    // trash holds its transaction open *while* the authorization stage resolves the subtree on a
    // connection of its own. A narrow pool deadlocks this suite for a reason unrelated to anything
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
    let harness = Harness { app: router(state, enclave_api::Delivery::unconfigured()), key };
    (db, fixtures, harness)
}

/// The authorization stack `crates/api/src/main.rs` composes.
///
/// All three layers are load-bearing here. `PgAdminRoles` decides the `admin.write_config` that
/// provisions the workspace these tests start from; `PgAclAuthorization` decides every `file.*` and
/// `container.*` question below, including the subtree pass a delete makes; `SelfServiceOr` answers
/// `container.read` on a caller's own `users` row. Wiring one alone would exercise a composition no
/// deployment runs (`ENC-746`).
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

/// The status, the body, and the `ETag` if there was one.
struct Answer {
    status: StatusCode,
    body: Value,
    etag: Option<String>,
}

async fn send(harness: &Harness, request: Request<Body>) -> Answer {
    let response = harness.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let body =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
    Answer { status, body, etag }
}

/// One request, with an optional `If-Match` and an optional JSON body.
async fn call(
    harness: &Harness,
    method: &str,
    tenant: TenantId,
    user: UserId,
    uri: &str,
    if_match: Option<&str>,
    body: Option<Value>,
) -> Answer {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)));
    if let Some(revision) = if_match {
        builder = builder.header("if-match", revision);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
    send(harness, request).await
}

async fn get(harness: &Harness, tenant: TenantId, user: UserId, uri: &str) -> Answer {
    call(harness, "GET", tenant, user, uri, None, None).await
}

async fn post(harness: &Harness, tenant: TenantId, user: UserId, uri: &str, body: Value) -> Answer {
    call(harness, "POST", tenant, user, uri, None, Some(body)).await
}

/// `PATCH /files/{id}`, the endpoint most of this suite is about.
async fn patch(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    file: &str,
    if_match: Option<&str>,
    body: Value,
) -> Answer {
    call(harness, "PATCH", tenant, user, &format!("/api/v1/files/{file}"), if_match, Some(body))
        .await
}

async fn delete(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    file: &str,
    if_match: &str,
) -> Answer {
    call(harness, "DELETE", tenant, user, &format!("/api/v1/files/{file}"), Some(if_match), None)
        .await
}

async fn restore(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    file: &str,
    if_match: &str,
) -> Answer {
    call(
        harness,
        "POST",
        tenant,
        user,
        &format!("/api/v1/files/{file}/restore"),
        Some(if_match),
        None,
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Fixture builders — every one of them through the shipped surface
// ---------------------------------------------------------------------------------------------

/// One tenant's container spine, as this suite builds it.
struct Spine {
    tenant: TenantId,
    founder: UserId,
    library: String,
}

/// Provisions a workspace, arms its founder, and creates a library in it.
async fn spine(harness: &Harness, tenant: TenantId, admin: UserId) -> Spine {
    let created = post(
        harness,
        tenant,
        admin,
        "/api/v1/admin/workspaces",
        json!({ "name": "Engineering", "slug": "engineering" }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "the fixture must provision: {}", created.body);
    let workspace = created.body["id"].as_str().expect("an id").to_owned();

    arm(harness, tenant, admin, &workspace).await;

    let created = post(
        harness,
        tenant,
        admin,
        &format!("/api/v1/workspaces/{workspace}/libraries"),
        json!({ "name": "Documents", "slug": "documents" }),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "the fixture must create: {}", created.body);
    let library = created.body["id"].as_str().expect("an id").to_owned();

    Spine { tenant, founder: admin, library }
}

/// Grants the founder file-level `manage_permissions`, which the founding grant deliberately omits.
///
/// It granted three actions in the first draft of this suite, and that was a **finding rather than
/// a convenience**: `routes::workspaces::FOUNDING_GRANT` held neither `file.move` nor
/// `file.restore`, so a founder could trash a folder and the product served no request that brought
/// it back — a one-way door on every fresh install, hidden by exactly this helper. Both are in the
/// grant now (`ENC-807`), and the fact that every test below still passes with only the third entry
/// here is what says so.
///
/// `file.manage_permissions` stays out of the grant on purpose and stays here: it is the right to
/// hand rights to somebody else at the file level, and a founder holds the container-level one
/// already. This suite needs it only to build the fixtures that *deny* something to a child, which
/// is a thing no ordinary founder does and every escalation test must.
async fn arm(harness: &Harness, tenant: TenantId, founder: UserId, workspace: &str) {
    let view =
        get(harness, tenant, founder, &format!("/api/v1/workspaces/{workspace}/permissions")).await;
    assert_eq!(view.status, StatusCode::OK, "the founder holds manage_permissions: {}", view.body);

    let mut entries = resend(&view.body);
    entries.push(allow(founder, "file.manage_permissions"));

    let replaced = call(
        harness,
        "PUT",
        tenant,
        founder,
        &format!("/api/v1/workspaces/{workspace}/permissions"),
        None,
        Some(json!({ "entries": entries })),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "the fixture grant must land: {}", replaced.body);
}

/// Creates a folder and returns `(id, revision)`.
async fn folder(
    harness: &Harness,
    spine: &Spine,
    name: &str,
    parent: Option<&str>,
) -> (String, i64) {
    let mut body = json!({ "name": name });
    if let Some(parent) = parent {
        body["parentId"] = json!(parent);
    }
    let created = post(
        harness,
        spine.tenant,
        spine.founder,
        &format!("/api/v1/libraries/{}/folders", spine.library),
        body,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "the fixture must create: {}", created.body);
    (
        created.body["id"].as_str().expect("an id").to_owned(),
        created.body["revision"].as_i64().expect("a revision"),
    )
}

/// Breaks a folder's inheritance and denies the founder the named actions on it.
///
/// The two steps happen in this order and through these routes: breaking inheritance copies the
/// effective set down, so the folder keeps exactly the access it had and the walk now stops at it,
/// and the `PUT` then states the one thing that is different. Building the ACL by hand in SQL would
/// produce a permission no sequence of requests could have produced, which is the fixture a suite
/// learns nothing from.
///
/// **The refusal has to be an explicit `DENY` rather than an omission, and that is a finding rather
/// than a taste.** `routes::permissions::write_desired_set` never revokes a row carrying
/// `inherited_from` — "it is not part of the set this operation replaces" — so an entry that a break
/// of inheritance materialised **cannot be removed by a replace**. Simply leaving `container.create`
/// out of the `PUT` body therefore leaves it in force, which is exactly how the first version of
/// [`a_move_into_a_container_the_caller_cannot_write_to_is_refused_and_moves_nothing`] failed: the
/// move was permitted, by a grant the suite believed it had removed. A `DENY` overwrites the
/// materialised row and clears `inherited_from`, which is the one operation that does reach it.
async fn detach(harness: &Harness, spine: &Spine, file: &str, denied: &[&str]) {
    let broken = post(
        harness,
        spine.tenant,
        spine.founder,
        &format!("/api/v1/files/{file}/permissions/break-inheritance"),
        Value::Null,
    )
    .await;
    assert_eq!(
        broken.status,
        StatusCode::OK,
        "the fixture must break inheritance: {}",
        broken.body
    );

    let mut entries: Vec<Value> = resend(&broken.body)
        .into_iter()
        .filter(|entry| !denied.iter().any(|action| entry["action"] == *action))
        .collect();
    entries.extend(denied.iter().map(|action| deny(spine.founder, action)));
    let replaced = call(
        harness,
        "PUT",
        spine.tenant,
        spine.founder,
        &format!("/api/v1/files/{file}/permissions"),
        None,
        Some(json!({ "entries": entries })),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK, "the fixture ACL must land: {}", replaced.body);
}

/// A resource's explicit ACL, as a `PUT` body that would leave it exactly as it is.
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

fn allow(user: UserId, action: &str) -> Value {
    json!({
        "principal": { "kind": "USER", "id": user.as_uuid() },
        "action": action,
        "effect": "ALLOW",
        "expiresAt": Value::Null,
    })
}

fn deny(user: UserId, action: &str) -> Value {
    json!({
        "principal": { "kind": "USER", "id": user.as_uuid() },
        "action": action,
        "effect": "DENY",
        "expiresAt": Value::Null,
    })
}

// ---------------------------------------------------------------------------------------------
// Reading what is stored, over the connection that can see everything
// ---------------------------------------------------------------------------------------------

/// One node's `(name, parent_id, revision, deleted_at is null)`, read past row-level security.
///
/// An assertion that a rename did **not** happen must not be able to pass because the reader could
/// not see the row.
async fn stored(db: &TestDb, tenant: TenantId, file: &str) -> (String, Option<Uuid>, i64, bool) {
    let mut conn = db.connect().await.expect("connect");
    let row: (String, Option<Uuid>, i64, bool) = sqlx::query_as(
        "SELECT name, parent_id, revision, deleted_at IS NULL
           FROM files WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(file.parse::<Uuid>().expect("a file id"))
    .fetch_one(&mut conn)
    .await
    .expect("read the node");
    row
}

async fn name_of(db: &TestDb, tenant: TenantId, file: &str) -> String {
    stored(db, tenant, file).await.0
}

async fn parent_of(db: &TestDb, tenant: TenantId, file: &str) -> Option<Uuid> {
    stored(db, tenant, file).await.1
}

async fn revision_of(db: &TestDb, tenant: TenantId, file: &str) -> i64 {
    stored(db, tenant, file).await.2
}

async fn is_live(db: &TestDb, tenant: TenantId, file: &str) -> bool {
    stored(db, tenant, file).await.3
}

/// The ids a browse of one container returns, as the caller sees them.
async fn browse(harness: &Harness, spine: &Spine, parent: Option<&str>) -> Vec<String> {
    let uri = match parent {
        Some(folder) => format!("/api/v1/libraries/{}/items?parentId={folder}", spine.library),
        None => format!("/api/v1/libraries/{}/items", spine.library),
    };
    let page = get(harness, spine.tenant, spine.founder, &uri).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    page.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["id"].as_str().map(str::to_owned))
        .collect()
}

/// The `(action, outcome)` pairs one tenant's audit log holds.
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

/// The `ETag` a response carried, as an `If-Match` for the next request.
fn precondition(answer: &Answer) -> String {
    answer.etag.clone().unwrap_or_else(|| {
        panic!("every response that reports a file must carry an ETag: {}", answer.body)
    })
}

// ---------------------------------------------------------------------------------------------
// The journey this whole item exists for
// ---------------------------------------------------------------------------------------------

/// A folder is created, renamed, moved, trashed, restored — and is browsable at the end.
///
/// **The test `ENC-807` exists for.** Before it, none of the four repository functions had a caller
/// in any binary, so a folder this product created could not be renamed, moved or deleted by any
/// sequence of HTTP requests. Every step below is a shipped route, in the order a person would use
/// them, and the last assertion is the one that makes the sequence mean something: the item is back
/// in the listing, under its new name, in its new parent.
///
/// The `ETag` chain is load-bearing rather than decorative. Each request's `If-Match` is the header
/// the previous response returned, which is the round trip `docs/05-API.md §4` describes — and a
/// response that failed to carry one would fail this test at [`precondition`] rather than silently
/// making the next request unconditional.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_folder_can_be_renamed_moved_trashed_and_restored_and_is_browsable_at_the_end() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (source, _) = folder(&harness, &spine, "Drafts", None).await;
    let (target, _) = folder(&harness, &spine, "Published", None).await;
    let (paper, revision) = folder(&harness, &spine, "Q3 Notes", Some(&source)).await;

    // --- rename ---
    let renamed = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{revision}\"")),
        json!({ "name": "Q3 Board Notes" }),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    assert_eq!(renamed.body["name"], "Q3 Board Notes", "{}", renamed.body);
    assert_eq!(name_of(&db, spine.tenant, &paper).await, "Q3 Board Notes");

    // --- move ---
    let moved = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&precondition(&renamed)),
        json!({ "parentId": target }),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.body);
    assert_eq!(moved.body["parentId"], target, "{}", moved.body);
    assert_eq!(
        parent_of(&db, spine.tenant, &paper).await,
        Some(target.parse::<Uuid>().expect("an id")),
        "the move must reach the row, not only the response"
    );
    assert!(browse(&harness, &spine, Some(&target)).await.contains(&paper));
    assert!(!browse(&harness, &spine, Some(&source)).await.contains(&paper));

    // --- trash ---
    let trashed =
        delete(&harness, spine.tenant, spine.founder, &paper, &precondition(&moved)).await;
    assert_eq!(trashed.status, StatusCode::OK, "{}", trashed.body);
    assert_eq!(trashed.body["affected"], 1, "a leaf is its own subtree: {}", trashed.body);
    assert!(!is_live(&db, spine.tenant, &paper).await, "the row must carry deleted_at");
    assert!(
        !browse(&harness, &spine, Some(&target)).await.contains(&paper),
        "a trashed node must be gone from the listing"
    );

    // --- restore ---
    let back =
        restore(&harness, spine.tenant, spine.founder, &paper, &precondition(&trashed)).await;
    assert_eq!(back.status, StatusCode::OK, "{}", back.body);
    assert_eq!(back.body["affected"], 1, "{}", back.body);

    // The assertion the whole sequence is for: browsable again, under the new name, in the new
    // parent. A restore that answered `200` and left the row invisible would pass every assertion
    // above and fail here.
    assert!(is_live(&db, spine.tenant, &paper).await);
    assert!(
        browse(&harness, &spine, Some(&target)).await.contains(&paper),
        "the restored folder must be browsable where it was moved to"
    );
    let listed = get(
        &harness,
        spine.tenant,
        spine.founder,
        &format!("/api/v1/libraries/{}/items?parentId={target}", spine.library),
    )
    .await;
    let names: Vec<&str> = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|i| i["name"].as_str())
        .collect();
    assert!(names.contains(&"Q3 Board Notes"), "the rename must have survived the round trip");
}

// ---------------------------------------------------------------------------------------------
// The precondition
// ---------------------------------------------------------------------------------------------

/// A rename with no `If-Match` is refused, and the name does not change.
///
/// Held by nothing below the handler: `Mutation::expected_revision` is an `Option` and the
/// repository writes unconditionally when handed `None`, so a handler that defaulted it would
/// overwrite whatever changed in between and every other test here would still pass.
///
/// The status is `400` rather than `428`, and that is asserted rather than incidental —
/// `docs/05-API.md §5`'s status table is the vocabulary this API answers in and it has no `428` row.
///
/// The positive control is the same request carrying the revision: without it, this passes against
/// a `PATCH` that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rename_without_an_if_match_changes_nothing() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;
    let (paper, revision) = folder(&harness, &spine, "Q3 Notes", None).await;

    let refused =
        patch(&harness, spine.tenant, spine.founder, &paper, None, json!({ "name": "Renamed" }))
            .await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["error"]["code"], "IF_MATCH_REQUIRED", "{}", refused.body);
    assert_eq!(
        name_of(&db, spine.tenant, &paper).await,
        "Q3 Notes",
        "a refused rename must not reach the row"
    );

    // --- the positive control ---
    let accepted = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{revision}\"")),
        json!({ "name": "Renamed" }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    assert_eq!(name_of(&db, spine.tenant, &paper).await, "Renamed");
}

/// A rename with a stale `If-Match` is refused with `409`, and the name does not change.
///
/// `docs/05-API.md §4` fixes the status for a mismatch — "Optimistic concurrency; `409` on mismatch"
/// — and `§5` gives `409` to "revision conflict" by name, which is why this is not `412`. The body
/// carries the revision the row actually holds, so a client can re-read and retry without a round
/// trip to discover it.
///
/// The stale value is the revision the folder had **before** the first rename, which is the real
/// shape of the failure: two clients editing what they both believe is the current row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rename_with_a_stale_if_match_changes_nothing() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;
    let (paper, first) = folder(&harness, &spine, "Q3 Notes", None).await;

    let accepted = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{first}\"")),
        json!({ "name": "Q3 Board Notes" }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);

    // The second client still holds the revision it read before the first one wrote.
    let refused = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{first}\"")),
        json!({ "name": "Something Else" }),
    )
    .await;

    assert_eq!(refused.status, StatusCode::CONFLICT, "§4: a mismatch is 409: {}", refused.body);
    assert_eq!(refused.body["error"]["code"], "REVISION_CONFLICT", "{}", refused.body);
    assert_eq!(
        name_of(&db, spine.tenant, &paper).await,
        "Q3 Board Notes",
        "a refused rename must not reach the row"
    );

    let current = revision_of(&db, spine.tenant, &paper).await;
    assert!(
        refused.body["error"]["message"]
            .as_str()
            .expect("a message")
            .contains(&current.to_string()),
        "the refusal must tell the client what to retry with: {}",
        refused.body
    );
}

// ---------------------------------------------------------------------------------------------
// The escalation
// ---------------------------------------------------------------------------------------------

/// **A move into a container the caller may not write to is `404`, and moves nothing.**
///
/// The test this item turns on. `file.move` on the *source* says the caller may relocate this
/// document; it says nothing whatever about where. Without the `container.create` question asked of
/// the destination, a caller holding `file.move` can place content into any folder in the library —
/// including one whose inheritance is broken precisely so that they cannot write there — and the
/// content arrives carrying that folder's inherited ACL. That is `CLAUDE.md` rule 6's split
/// collapsed, and `ENC-141`'s failure direction: a truncated walk *gaining* privilege.
///
/// The destination is a folder with `inherit_permissions = FALSE` whose own ACL denies the caller
/// `container.create`, built through `POST …/break-inheritance` and `PUT …/permissions` — see
/// [`detach`] for why the refusal has to be an explicit `DENY` and what that discovered. The
/// caller is alpha's own founder acting on alpha's own rows, so row-level security has nothing to
/// say here and deleting a `tenant_id` predicate would not make this fail: **only the destination
/// question can refuse it.**
///
/// `404` and not `403`, per rule 7: a `403` would confirm that the folder exists.
///
/// The positive control is the same move into a sibling folder that still inherits. Without it this
/// passes against a handler that refuses every move.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_move_into_a_container_the_caller_cannot_write_to_is_refused_and_moves_nothing() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (paper, revision) = folder(&harness, &spine, "Q3 Notes", None).await;
    let (sealed, _) = folder(&harness, &spine, "Compensation Bands", None).await;
    let (open, _) = folder(&harness, &spine, "Published", None).await;

    // The destination the caller may read but may not write into.
    detach(&harness, &spine, &sealed, &["container.create"]).await;

    let refused = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{revision}\"")),
        json!({ "parentId": sealed }),
    )
    .await;

    assert_eq!(
        refused.status,
        StatusCode::NOT_FOUND,
        "rule 7: a 403 would confirm the folder exists: {}",
        refused.body
    );
    assert_eq!(
        parent_of(&db, spine.tenant, &paper).await,
        None,
        "a refused move must leave the node exactly where it was"
    );
    assert!(
        !browse(&harness, &spine, Some(&sealed)).await.contains(&paper),
        "and it must not be inside the container that refused it"
    );

    let rows = audit_rows(&db, spine.tenant).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "container.create" && outcome == "DENY"),
        "the destination denial must be audited by the chain: {rows:?}"
    );

    // --- the positive control: the same move, into a folder that still inherits ---
    let accepted = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{revision}\"")),
        json!({ "parentId": open }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    assert_eq!(
        parent_of(&db, spine.tenant, &paper).await,
        Some(open.parse::<Uuid>().expect("an id"))
    );
}

/// **A rename is permitted where a move is denied**, because they are two actions.
///
/// `CLAUDE.md` rule 6 on the file surface. `crates/authorization/src/repo.rs` matches
/// `a.action = ANY($2::text[])` — string equality, with no implication from one verb to another — so
/// a `PATCH` that asked one `file.edit` question for both would let a caller who may correct a typo
/// relocate the document into a folder with a different inherited ACL, which is the entire reason
/// `Move` is a separate verb ("Relocate, which changes inherited permissions").
///
/// The two halves are asserted in one run against one file and one caller, and that is what makes
/// the test discriminating: the same request differs only in which field it sets. Deleting the
/// `file.move` question from `routes::lifecycle::update` leaves the rename half green and turns this
/// half `200`.
///
/// The denial is on the file itself, and the caller is alpha's own founder acting on alpha's own
/// rows, so row-level security has nothing to say here either.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rename_is_permitted_where_a_move_is_denied() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (paper, _) = folder(&harness, &spine, "Q3 Notes", None).await;
    let (target, _) = folder(&harness, &spine, "Published", None).await;
    detach(&harness, &spine, &paper, &["file.move"]).await;

    // The permitted half. Read the revision back, because breaking inheritance and replacing the
    // ACL bump `acl_revision` rather than `revision` — but reading it is what keeps this test about
    // the action rather than about the precondition.
    let revision = revision_of(&db, spine.tenant, &paper).await;
    let renamed = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&format!("\"{revision}\"")),
        json!({ "name": "Q3 Board Notes" }),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "file.edit is granted: {}", renamed.body);
    assert_eq!(name_of(&db, spine.tenant, &paper).await, "Q3 Board Notes");

    // The refused half: the same file, the same caller, the same endpoint.
    let refused = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &paper,
        Some(&precondition(&renamed)),
        json!({ "parentId": target }),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::NOT_FOUND,
        "rule 6: an edit is not a relocation, and rule 7 conceals the refusal: {}",
        refused.body
    );
    assert_eq!(
        parent_of(&db, spine.tenant, &paper).await,
        None,
        "a refused move must leave the node where it was"
    );

    let rows = audit_rows(&db, spine.tenant).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "file.move" && outcome == "DENY"),
        "the denial must be audited by the chain, under the action that was refused: {rows:?}"
    );
}

/// A move that would make a folder its own ancestor is `422`, and the handler surfaces it.
///
/// The engine detects the cycle — it is a recursive `WITH` inside the `UPDATE`'s own `WHERE`, so two
/// concurrent moves cannot together produce one — and what this asserts is that the refusal reaches
/// the caller as `docs/05-API.md §5`'s "well-formed but semantically rejected (e.g. circular folder
/// move)" rather than as the `400` the files crate's blanket conversion produces or the `500` an
/// unmapped error would. `ENC-808` records the same mismatch for a name collision.
///
/// The positive control is the reverse move, which is legal: without it, "a cycle is refused" passes
/// against a handler that refuses every move into a folder.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_move_that_would_create_a_cycle_is_refused_as_unprocessable() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (outer, outer_revision) = folder(&harness, &spine, "Drafts", None).await;
    let (inner, inner_revision) = folder(&harness, &spine, "Q3", Some(&outer)).await;

    let refused = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &outer,
        Some(&format!("\"{outer_revision}\"")),
        json!({ "parentId": inner }),
    )
    .await;

    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "§5 names a circular folder move as the example of a 422: {}",
        refused.body
    );
    assert_eq!(refused.body["error"]["code"], "CIRCULAR_MOVE", "{}", refused.body);
    assert_eq!(
        parent_of(&db, spine.tenant, &outer).await,
        None,
        "a refused move must leave the node where it was"
    );

    // --- the positive control: the same two folders, moved the way round that is legal ---
    let accepted = patch(
        &harness,
        spine.tenant,
        spine.founder,
        &inner,
        Some(&format!("\"{inner_revision}\"")),
        json!({ "parentId": null }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "a move to the library root: {}", accepted.body);
    assert_eq!(parent_of(&db, spine.tenant, &inner).await, None);
}

// ---------------------------------------------------------------------------------------------
// The cascade
// ---------------------------------------------------------------------------------------------

/// **Trashing a folder whose descendant denies `file.delete` refuses the whole subtree.**
///
/// `FileRepository::trash` moves the whole subtree with one `deleted_at`. Authorizing only the
/// addressed folder would let this caller trash a document they hold no `file.delete` on, and it is
/// reachable the moment a descendant carries `inherit_permissions = FALSE`: the resolver's walk
/// stops there, so the grant that admitted the parent does not reach the child. `ENC-141`'s shape,
/// failing towards *gained* privilege.
///
/// The child here is built with a break of inheritance **and** an explicit `DENY`, so both halves of
/// the refusal are real: the walk stops, and what it finds when it stops is a denial. Everything is
/// alpha's, so row-level security has nothing to say and only the subtree pass can refuse this.
///
/// Nothing partial: both rows are asserted still live, which is what fails if the check ever moves
/// after the commit.
///
/// The positive control is a sibling folder with a child that inherits normally, trashed in the same
/// run. Without it, this passes against a `DELETE` that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn trashing_a_folder_whose_child_denies_delete_refuses_the_whole_subtree() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (parent, parent_revision) = folder(&harness, &spine, "Drafts", None).await;
    let (child, _) = folder(&harness, &spine, "Compensation Bands", Some(&parent)).await;

    // The descendant the caller may see and may not delete.
    detach(&harness, &spine, &child, &["file.delete"]).await;

    let refused =
        delete(&harness, spine.tenant, spine.founder, &parent, &format!("\"{parent_revision}\""))
            .await;

    // `404`, not `403`, and the difference is rule 7 rather than taste. The chain allowed the
    // folder — a `GET` on it answers `200` in this same run — so a `403` here would say *something
    // inside this folder is walled off from you*, about a child the caller may hold no
    // `file.metadata_read` on and that no listing would ever have shown them. The refusal is
    // concealed for the same reason a cross-tenant denial is.
    assert_eq!(
        refused.status,
        StatusCode::NOT_FOUND,
        "a subtree refusal must not confirm that the folder contains something hidden: {}",
        refused.body
    );
    assert_eq!(refused.body["error"]["code"], "NOT_FOUND", "{}", refused.body);
    // The control that makes the concealment meaningful rather than a blanket refusal: the folder
    // the caller was just told does not exist for the purpose of deletion is readable in the same
    // breath. Without this, the assertion above passes against a handler that 404s everything.
    let readable =
        get(&harness, spine.tenant, spine.founder, &format!("/api/v1/files/{parent}")).await;
    assert_eq!(
        readable.status,
        StatusCode::OK,
        "the addressed folder is visible; only the delete is refused: {}",
        readable.body
    );
    assert!(
        is_live(&db, spine.tenant, &parent).await,
        "nothing partial: the addressed folder must still be live"
    );
    assert!(is_live(&db, spine.tenant, &child).await, "and so must the descendant that refused it");
    assert!(browse(&harness, &spine, None).await.contains(&parent));

    let rows = audit_rows(&db, spine.tenant).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "file.delete" && outcome == "DENY"),
        "the subtree denial must leave an audit row an investigator can find: {rows:?}"
    );

    // --- the positive control: the same shape, with a child that inherits ---
    let (ordinary, ordinary_revision) = folder(&harness, &spine, "Published", None).await;
    let (leaf, _) = folder(&harness, &spine, "Q3 Notes", Some(&ordinary)).await;

    let accepted = delete(
        &harness,
        spine.tenant,
        spine.founder,
        &ordinary,
        &format!("\"{ordinary_revision}\""),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    assert_eq!(
        accepted.body["affected"], 2,
        "the cascade reports the whole subtree: {}",
        accepted.body
    );
    assert!(!is_live(&db, spine.tenant, &ordinary).await);
    assert!(!is_live(&db, spine.tenant, &leaf).await, "the cascade must reach the child");
}

/// A trashed subtree leaves the listing, comes back whole, and cannot be restored under a parent
/// that is still in the trash.
///
/// Three properties in one run because they are one story and the intermediate states are what make
/// each of them meaningful.
///
/// The refusal in the middle is the one worth reading carefully. Restoring a child while its parent
/// is still in the trash would produce a live node inside a deleted folder: absent from every
/// listing, and — because the ACL walk stops at a deleted ancestor — permanently unresolvable. It is
/// answered `404` rather than the `422` `FilesError::ParentInTrash` would give, and that is a
/// consequence of where the question is asked rather than an accident: a restore is decided against
/// the container the node returns into, and a container that is itself trashed has no inheritance
/// chain, so the chain can only answer "not granted". Both refuse and neither writes; the module
/// documentation carries the argument.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_subtree_leaves_the_listing_and_only_comes_back_from_the_top() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;

    let (parent, parent_revision) = folder(&harness, &spine, "Drafts", None).await;
    let (child, _) = folder(&harness, &spine, "Q3 Notes", Some(&parent)).await;

    let trashed =
        delete(&harness, spine.tenant, spine.founder, &parent, &format!("\"{parent_revision}\""))
            .await;
    assert_eq!(trashed.status, StatusCode::OK, "{}", trashed.body);
    assert_eq!(trashed.body["affected"], 2, "{}", trashed.body);
    assert!(
        !browse(&harness, &spine, None).await.contains(&parent),
        "a trashed folder must be gone from the listing"
    );

    // --- the refusal: the child, while its parent is still in the trash ---
    let child_revision = revision_of(&db, spine.tenant, &child).await;
    let refused =
        restore(&harness, spine.tenant, spine.founder, &child, &format!("\"{child_revision}\""))
            .await;
    assert_eq!(
        refused.status,
        StatusCode::NOT_FOUND,
        "a restore into a trashed container cannot be decided, so it is refused: {}",
        refused.body
    );
    assert!(
        !is_live(&db, spine.tenant, &child).await,
        "a refused restore must leave the row in the trash"
    );

    // --- the positive control: the same subtree, restored from its top ---
    let back =
        restore(&harness, spine.tenant, spine.founder, &parent, &precondition(&trashed)).await;
    assert_eq!(back.status, StatusCode::OK, "{}", back.body);
    assert_eq!(back.body["affected"], 2, "the cascade comes back whole: {}", back.body);
    assert!(is_live(&db, spine.tenant, &parent).await);
    assert!(is_live(&db, spine.tenant, &child).await, "the descendant must come back too");
    assert!(browse(&harness, &spine, None).await.contains(&parent));
    assert!(browse(&harness, &spine, Some(&parent)).await.contains(&child));
}

// ---------------------------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------------------------

/// Another tenant's file is `404`, and indistinguishable from an id that is not an id.
///
/// `T1`. Both tenants are given the same workspace slug, the same library slug and the same folder
/// name, so this cannot pass merely because beta's rows were called something else. The two
/// responses are compared field by field, `requestId` excepted — a difference in the code or the
/// message is exactly the oracle rule 7 exists to close, and a `400` on the malformed id would be
/// one, which is why the id is parsed before the precondition is read.
///
/// The positive control is alpha's own folder, patched in the same run with the same body: without
/// it, this passes against a `PATCH` that answers `404` to everybody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_file_is_indistinguishable_from_a_malformed_id() {
    let (db, fixtures, harness) = setup().await;
    let alpha = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;
    let beta = spine(&harness, fixtures.beta.id, fixtures.beta.admin).await;

    let (theirs, theirs_revision) = folder(&harness, &beta, "Q3 Notes", None).await;
    let (ours, ours_revision) = folder(&harness, &alpha, "Q3 Notes", None).await;

    let cross_tenant = patch(
        &harness,
        alpha.tenant,
        alpha.founder,
        &theirs,
        Some(&format!("\"{theirs_revision}\"")),
        json!({ "name": "Renamed" }),
    )
    .await;
    let malformed = patch(
        &harness,
        alpha.tenant,
        alpha.founder,
        "not-a-file-id",
        Some("\"1\""),
        json!({ "name": "Renamed" }),
    )
    .await;

    assert_eq!(cross_tenant.status, StatusCode::NOT_FOUND, "{}", cross_tenant.body);
    assert_eq!(malformed.status, StatusCode::NOT_FOUND, "{}", malformed.body);
    assert_eq!(
        cross_tenant.body["error"]["code"], malformed.body["error"]["code"],
        "the two must not be distinguishable"
    );
    assert_eq!(
        cross_tenant.body["error"]["message"], malformed.body["error"]["message"],
        "the two must not be distinguishable"
    );
    assert_eq!(
        name_of(&db, beta.tenant, &theirs).await,
        "Q3 Notes",
        "the other tenant's row must not have been touched"
    );

    // The same, for the two paths that take no body.
    let trashing =
        delete(&harness, alpha.tenant, alpha.founder, &theirs, &format!("\"{theirs_revision}\""))
            .await;
    assert_eq!(trashing.status, StatusCode::NOT_FOUND, "{}", trashing.body);
    assert!(is_live(&db, beta.tenant, &theirs).await, "and it must still be live");

    let restoring =
        restore(&harness, alpha.tenant, alpha.founder, &theirs, &format!("\"{theirs_revision}\""))
            .await;
    assert_eq!(restoring.status, StatusCode::NOT_FOUND, "{}", restoring.body);

    // --- the positive control ---
    let accepted = patch(
        &harness,
        alpha.tenant,
        alpha.founder,
        &ours,
        Some(&format!("\"{ours_revision}\"")),
        json!({ "name": "Renamed" }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    assert_eq!(name_of(&db, alpha.tenant, &ours).await, "Renamed");
}

/// **`DELETE` and `restore` require `If-Match` too, and nothing proved it until now.**
///
/// `a_rename_without_an_if_match_changes_nothing` covers `PATCH`, and the unit test on
/// `expected_revision` covers the parser — neither says anything about the *other two call sites*,
/// which are the ones that destroy and resurrect a subtree. `Mutation::expected_revision`'s own doc
/// is the requirement: *"`None` is for server-initiated maintenance, not for handlers: a user-facing
/// write that skips this silently overwrites whatever changed in between."* A delete that skipped it
/// would trash a folder a colleague had just moved something into.
///
/// Each half ends on the succeeding call with the header present, because "it refused" is satisfied
/// for free by a route that refuses everything — including one that is not registered at all, which
/// answers `405` and would otherwise read as a pass.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn neither_a_delete_nor_a_restore_proceeds_without_an_if_match() {
    let (db, fixtures, harness) = setup().await;
    let spine = spine(&harness, fixtures.alpha.id, fixtures.alpha.admin).await;
    let (target, revision) = folder(&harness, &spine, "Unconditional", None).await;

    // --- the delete half ---
    let bare = call(
        &harness,
        "DELETE",
        spine.tenant,
        spine.founder,
        &format!("/api/v1/files/{target}"),
        None,
        None,
    )
    .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST, "{}", bare.body);
    assert_eq!(bare.body["error"]["code"], "IF_MATCH_REQUIRED", "{}", bare.body);
    assert!(
        is_live(&db, spine.tenant, &target).await,
        "a delete refused for a missing precondition must not have trashed anything"
    );

    // The control: the same request, with the header.
    let deleted =
        delete(&harness, spine.tenant, spine.founder, &target, &format!("\"{revision}\"")).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.body);
    assert!(!is_live(&db, spine.tenant, &target).await);

    // --- the restore half, against the row the delete just produced ---
    let bare = call(
        &harness,
        "POST",
        spine.tenant,
        spine.founder,
        &format!("/api/v1/files/{target}/restore"),
        None,
        None,
    )
    .await;
    assert_eq!(bare.status, StatusCode::BAD_REQUEST, "{}", bare.body);
    assert_eq!(bare.body["error"]["code"], "IF_MATCH_REQUIRED", "{}", bare.body);
    assert!(
        !is_live(&db, spine.tenant, &target).await,
        "a restore refused for a missing precondition must not have restored anything"
    );

    // The control again: with the revision the trash write left behind.
    let revision = revision_of(&db, spine.tenant, &target).await;
    let restored =
        restore(&harness, spine.tenant, spine.founder, &target, &format!("\"{revision}\"")).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
    assert!(is_live(&db, spine.tenant, &target).await);
}
