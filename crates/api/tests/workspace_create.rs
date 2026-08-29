//! `POST /api/v1/admin/workspaces`, end to end, over a real PostgreSQL.
//!
//! # What was actually missing
//!
//! `WorkspaceRepository::create` has existed since M1 and had **no caller in any binary**, and
//! `enclave-cli seed` writes tenants, users and groups and no workspace. So a freshly installed
//! deployment answered `GET /workspaces` with an empty page and offered no way to make it
//! non-empty — and every write below a workspace (libraries, folders, uploads, shares) needs one to
//! exist. These tests are therefore not only about a new endpoint; two of them are about whether the
//! product can be started at all.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the eight prior instances in this repository where deleting a
//! `tenant_id` predicate *failed to fail* because row-level security held the property alone. A
//! cross-tenant assertion cannot distinguish "the authorization stage refused" from "RLS made the
//! row invisible", so on its own it proves nothing about the code this work added.
//!
//! * **Authorization.** [`a_caller_who_is_not_an_administrator_cannot_provision_a_workspace`] uses
//!   `fixtures.alpha.member` against `fixtures.alpha`'s own tenant, where RLS has nothing to say —
//!   both principals are alpha's, the tenant row is alpha's, and only `AdminAuthorization` reading
//!   `users.is_admin` can tell them apart. That is the one test here that proves this route's
//!   security.
//! * **Reachability.** [`an_administrator_creates_a_workspace_and_may_immediately_manage_it`] and
//!   [`the_creator_can_read_the_new_workspace_and_it_appears_in_their_listing`] are the pair that
//!   catch the failure this repository keeps producing: an endpoint that is built, tested, green,
//!   and hands back something no caller can subsequently use. Deleting the ACL grant from
//!   `routes::workspaces::provision` leaves the `201` intact, leaves the row in `workspaces`
//!   intact, and turns both of these red — which is exactly the discrimination they exist for.
//! * **Isolation.** [`a_workspace_provisioned_in_beta_is_invisible_to_alpha`] is asserted because
//!   `T1` is documented behaviour, **not** because it isolates anything this handler does. Both
//!   tenants are seeded with the same fixture shape and this test gives them the same workspace
//!   name and the same slug, so it cannot pass merely because the other tenant's row was called
//!   something else.
//!
//! # Every absence is paired with its positive control
//!
//! "The caller was refused" and "no workspace row exists" both pass for free against a handler that
//! refuses everything, against a broken fixture, and against a route that was never registered. So
//! each refusal below is paired, in the same test, with the request that succeeds.
//!
//! # The composition is the shipped one
//!
//! `AdminAuthorization(PgAdminRoles, SelfServiceOr(PgAclAuthorization))` — the three-layer stack
//! `crates/api/src/main.rs` builds, and all three layers are load-bearing here. `PgAdminRoles`
//! decides `admin.write_config`; `PgAclAuthorization` resolves the founding grant that the `201`'s
//! `capabilities` object reports; `SelfServiceOr` answers `container.read` on the caller's own
//! `users` row, which is what `GET /workspaces` enforces against. Wiring any one of them alone
//! would leave this suite exercising a composition no deployment runs (`ENC-746`), and — worse —
//! would make [`the_creator_can_read_the_new_workspace_and_it_appears_in_their_listing`] pass or
//! fail for a reason that has nothing to do with the grant it is about.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::{AdminAuthorization, PgAclAuthorization, PgAdminRoles, SelfServiceOr};
use enclave_core::{ClientType, PolicyEngine, TenantId, UserId};
use enclave_db::DbPool;
use enclave_testing::{Fixtures, TestDb};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
}

/// A migrated, seeded database and the router over it.
///
/// No workspace fixture is written. That is deliberate and it is the state a real installation is
/// in: the point of this endpoint is that a tenant with no workspaces can acquire one, and a suite
/// that started from a seeded spine would never exercise it.
async fn setup() -> (TestDb, Fixtures, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");

    // One pool, wide enough for the four consumers below plus the transaction the handler holds
    // while it inserts and grants. A create resolves capabilities on a *second* connection after it
    // commits (see `routes::workspaces::create`), so a pool of two deadlocks under this suite for a
    // reason unrelated to anything it asserts.
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

/// The authorization stack `crates/api/src/main.rs` composes. See the module documentation for why
/// all three layers have to be present for this suite to mean anything.
fn authorization(pool: &DbPool) -> Arc<dyn enclave_core::AuthorizationService> {
    Arc::new(AdminAuthorization::new(
        Arc::new(PgAdminRoles::new(pool.clone())),
        Arc::new(SelfServiceOr::new(PgAclAuthorization::new(pool.clone()))),
    ))
}

/// A bearer token, parameterised by authentication strength.
///
/// `acr` is a parameter rather than a constant because provisioning is an administrative mutation
/// and `docs/05-API.md §14` requires a recent second factor for one. Every call below passes
/// `Acr::MultiFactor` — a fixture that could not present one would make every test here assert the
/// step-up refusal rather than the behaviour it is named for — and exactly one test passes
/// `Acr::SingleFactor`, which is the positive control that the requirement is real.
fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId, acr: Acr) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: Uuid::new_v4(),
        typ: enclave_core::ActorKind::User,
        scp: Vec::new(),
        amr: match acr {
            Acr::MultiFactor => vec![AuthMethod::Pwd, AuthMethod::Totp],
            _ => vec![AuthMethod::Pwd],
        },
        auth_time: now,
        acr,
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

/// How many `acl_entries` rows one provisioning writes.
///
/// Six container actions and nine file actions — `routes::workspaces::FOUNDING_GRANT`, which this
/// suite cannot import because it is private to the crate. The split is the point rather than the
/// total: the container half is what lets the creator finish setting the workspace up, and the file
/// half is what lets them open the first thing they put in it. Granting only the first was a real
/// defect, and `a_founder_can_walk_from_an_empty_tenant_to_a_file_they_can_open` is what catches its
/// return. If this number changes, that test and the rule-6 deny-list beside `FOUNDING_GRANT` are
/// the two places to look before changing it here.
const FOUNDING_GRANT_ROWS: i64 = 15;

/// Issues one `POST /api/v1/admin/workspaces` and returns the status and the parsed body.
async fn create_workspace(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        harness,
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/workspaces")
            .header(
                "authorization",
                format!("Bearer {}", token(&harness.key, tenant, user, Acr::MultiFactor)),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

/// The same, for the read paths the creator is expected to be able to use afterwards.
async fn get(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
) -> (StatusCode, serde_json::Value) {
    send(
        harness,
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(
                "authorization",
                format!("Bearer {}", token(&harness.key, tenant, user, Acr::MultiFactor)),
            )
            .body(Body::empty())
            .expect("request"),
    )
    .await
}

/// A `POST` the founder makes *after* provisioning, using only the rights the founding grant gave.
async fn post(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    send(
        harness,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(
                "authorization",
                format!("Bearer {}", token(&harness.key, tenant, user, Acr::MultiFactor)),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
}

async fn send(harness: &Harness, request: Request<Body>) -> (StatusCode, serde_json::Value) {
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

/// How many live workspaces one tenant holds under a folded slug.
///
/// Read over the superuser connection on purpose: an assertion that a row was **not** created must
/// not be able to pass because the reader could not see it.
async fn workspace_count(db: &TestDb, tenant: TenantId, slug: &str) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM workspaces
          WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(slug)
    .fetch_one(&mut conn)
    .await
    .expect("count workspaces")
}

/// How many ACL entries hang on one workspace, over the same superuser connection and for the same
/// reason.
async fn acl_count(db: &TestDb, tenant: TenantId, workspace: &str) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM acl_entries
          WHERE tenant_id = $1 AND resource_type = 'WORKSPACE' AND resource_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(workspace.parse::<Uuid>().expect("a workspace id"))
    .fetch_one(&mut conn)
    .await
    .expect("count acl entries")
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

fn body(name: &str, slug: &str) -> serde_json::Value {
    serde_json::json!({ "name": name, "slug": slug })
}

// ---------------------------------------------------------------------------------------------
// Authorization — the same-tenant test, the only one that proves this route's security
// ---------------------------------------------------------------------------------------------

/// **Authorization layer.** An ordinary member of the tenant may not provision a workspace.
///
/// The caller is `fixtures.alpha.member` and the tenant is alpha's own, so row-level security admits
/// every row involved — deleting a `tenant_id` predicate would not make this test fail, and it is
/// not trying to. What it proves is that `AdminAuthorization` refuses a caller whose `users.is_admin`
/// is `false`, that **no row was written**, and that the denial was audited by the chain rather than
/// by the handler (`CLAUDE.md` rule 10).
///
/// The status is `403` and not `404`, and that is asserted rather than incidental. `CLAUDE.md`
/// rule 7 conceals resources whose *existence* is the secret; the resource here is the caller's own
/// tenant, which their token already names, and a `404` would tell an ordinary member that the
/// endpoint does not exist rather than that it is not theirs.
///
/// The positive control is the same request from `fixtures.alpha.admin`: without it, every assertion
/// above passes against a route that refuses everybody and against a route that was never
/// registered at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_who_is_not_an_administrator_cannot_provision_a_workspace() {
    let (db, fixtures, harness) = setup().await;
    let request = body("Engineering", "engineering");

    let (status, refused) =
        create_workspace(&harness, fixtures.alpha.id, fixtures.alpha.member, request.clone()).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["error"]["code"], "ACCESS_DENIED", "{refused}");
    assert_eq!(
        workspace_count(&db, fixtures.alpha.id, "engineering").await,
        0,
        "a refused provisioning must write no row"
    );

    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "admin.write_config" && outcome == "DENY"),
        "the denial must be audited by the chain: {rows:?}"
    );

    // --- the positive control: the same request, from the tenant's administrator ---
    let (status, created) =
        create_workspace(&harness, fixtures.alpha.id, fixtures.alpha.admin, request).await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(workspace_count(&db, fixtures.alpha.id, "engineering").await, 1);
}

// ---------------------------------------------------------------------------------------------
// Reachability — the pair that catch a workspace its own creator cannot open
// ---------------------------------------------------------------------------------------------

/// A `201` whose `capabilities` object says the creator may now read **and** manage what they made.
///
/// This is the assertion that fails if the founding grant is dropped. `capabilities` is resolved by
/// the same authorization stage that will enforce the actions (`docs/05-API.md §7`), and being a
/// tenant administrator answers `Action::Admin` and says nothing whatever about `container.read` —
/// so with no ACL entry every field here comes back `false` and the `201` describes a workspace its
/// own creator cannot open.
///
/// The row count in `acl_entries` is asserted beside it, because the two claims are different: the
/// capabilities object could in principle be right for the wrong reason — a resolver change, a
/// self-service rule — and six rows on the workspace is the fact this endpoint is responsible for.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_administrator_creates_a_workspace_and_may_immediately_manage_it() {
    let (db, fixtures, harness) = setup().await;

    let (status, created) = create_workspace(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        serde_json::json!({
            "name": "Engineering",
            "slug": "Engineering",
            "description": "Platform and infrastructure",
            "visibility": "MEMBERS_ONLY",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Engineering", "{created}");
    assert_eq!(created["slug"], "engineering", "the stored slug is folded: {created}");
    assert_eq!(created["description"], "Platform and infrastructure", "{created}");
    assert_eq!(created["visibility"], "MEMBERS_ONLY", "{created}");
    assert_eq!(created["revision"], 1, "a create returns a usable If-Match: {created}");

    for capability in ["read", "create", "update", "delete", "manageMembers", "managePermissions"] {
        assert_eq!(
            created["capabilities"][capability],
            serde_json::Value::Bool(true),
            "the creator must hold `{capability}` on what they just made: {created}"
        );
    }

    let id = created["id"].as_str().expect("an id").to_owned();
    assert_eq!(
        acl_count(&db, fixtures.alpha.id, &id).await,
        FOUNDING_GRANT_ROWS,
        "the founding grant is one row per granted action, written with the workspace"
    );
}

/// The creator can immediately `GET` the workspace, and it appears in their own listing.
///
/// The test that proves the grant **landed and committed**, rather than that the handler computed a
/// pleasing response. Both reads run on connections the create's transaction has long since
/// released, and both enforce `container.read` through `PgAclAuthorization` against
/// `acl_entries` — so a grant written outside the transaction, rolled back with it, or resolved
/// before it committed shows up here as a `404` and an empty page.
///
/// The listing half is the sharper of the two: `GET /workspaces` returns every live workspace in the
/// tenant from the repository and is made safe **entirely** by its ACL trim, so a workspace missing
/// from it is a workspace the trim refused.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_creator_can_read_the_new_workspace_and_it_appears_in_their_listing() {
    let (_db, fixtures, harness) = setup().await;
    let creator = fixtures.alpha.admin;

    let (status, created) =
        create_workspace(&harness, fixtures.alpha.id, creator, body("Engineering", "engineering"))
            .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an id").to_owned();

    let (status, read) =
        get(&harness, fixtures.alpha.id, creator, &format!("/api/v1/workspaces/{id}")).await;
    assert_eq!(status, StatusCode::OK, "the creator must be able to open it: {read}");
    assert_eq!(read["id"], id, "{read}");
    assert_eq!(
        read["capabilities"], created["capabilities"],
        "a create and a read of one workspace must not describe two different things"
    );

    let (status, page) = get(&harness, fixtures.alpha.id, creator, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let listed: Vec<&str> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(listed.contains(&id.as_str()), "the new workspace must survive the trim: {page}");

    // The negative half of the same property, and it is what stops the assertion above passing
    // against a trim that admits everything: the tenant's ordinary member was granted nothing, so
    // the same workspace must be absent from *their* listing and `404` on a direct read.
    let member = fixtures.alpha.member;
    let (status, page) = get(&harness, fixtures.alpha.id, member, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page["items"].as_array().expect("items").is_empty(),
        "the founding grant names the creator alone: {page}"
    );

    let (status, refused) =
        get(&harness, fixtures.alpha.id, member, &format!("/api/v1/workspaces/{id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: a 403 would confirm it exists: {refused}");
}

// ---------------------------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------------------------

/// A duplicate slug is `409`, and the response does not echo the slug.
///
/// The status assertion is load-bearing: `WorkspaceError::SlugTaken` maps onto `Error::Validation`,
/// which is a `400`, so a handler that let the blanket conversion run answers `400` and this fails.
/// The absence of the value is asserted because a collision report is the one place a workspace the
/// caller has not been shown could be named to them — and here the refusal is itself proof that a
/// live workspace in the tenant holds exactly that slug.
///
/// The first `201` is the positive control, and the differing display name is deliberate: the
/// collision is on the folded **slug**, not on the name, so a handler that had guarded the wrong
/// column would answer `201` twice.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_duplicate_slug_is_a_conflict() {
    let (db, fixtures, harness) = setup().await;
    let admin = fixtures.alpha.admin;

    let (status, first) =
        create_workspace(&harness, fixtures.alpha.id, admin, body("Engineering", "engineering"))
            .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    // A different name, the same slug in a different case — which `normalize_slug` folds onto the
    // one already stored.
    let (status, second) =
        create_workspace(&harness, fixtures.alpha.id, admin, body("Platform", "Engineering")).await;

    assert_eq!(status, StatusCode::CONFLICT, "§5: a slug collision is 409, never 400: {second}");
    assert_eq!(second["error"]["code"], "NAME_IN_USE", "{second}");
    assert_eq!(second["error"]["details"][0]["field"], "slug", "{second}");
    assert_eq!(second["error"]["details"][0]["code"], "NOT_UNIQUE", "{second}");

    let rendered = second.to_string();
    assert!(
        !rendered.contains("Platform"),
        "a collision report must not echo what the caller sent: {rendered}"
    );
    assert_eq!(
        workspace_count(&db, fixtures.alpha.id, "engineering").await,
        1,
        "the refused second write must leave exactly the first row"
    );
}

/// A body that will not decode is `400` inside `docs/05-API.md §5`'s envelope.
///
/// Two shapes, because they fail in two different places and both must land in the envelope: bytes
/// that are not JSON at all, and well-formed JSON missing a required field. Neither may reach the
/// caller as axum's plain-text extractor rejection, which carries no `error` object and no code a
/// client can switch on.
///
/// The `201` at the end is the positive control, and it is the reason the caller is an
/// administrator throughout: a `400` from a route that refuses every request would satisfy both
/// assertions above.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_body_that_will_not_decode_is_a_validation_failure() {
    let (db, fixtures, harness) = setup().await;
    let admin = fixtures.alpha.admin;

    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/workspaces")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(&harness.key, fixtures.alpha.id, admin, Acr::MultiFactor)
                    ),
                )
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let refused: serde_json::Value = serde_json::from_slice(&bytes)
        .expect("a malformed body must still be answered inside §5's envelope");

    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"]["code"], "VALIDATION_FAILED", "{refused}");
    assert_eq!(refused["error"]["details"][0]["field"], "body", "{refused}");

    // Well-formed JSON, missing `slug`. Same status and same envelope, and it names the field the
    // caller left out rather than the body — the reason every field on `CreateWorkspaceRequest`
    // carries `#[serde(default)]`. A `details` entry saying `body` here would be useless to a form.
    let (status, refused) = create_workspace(
        &harness,
        fixtures.alpha.id,
        admin,
        serde_json::json!({ "name": "Engineering" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"]["code"], "VALIDATION_FAILED", "{refused}");
    assert_eq!(refused["error"]["details"][0]["field"], "slug", "{refused}");
    assert_eq!(refused["error"]["details"][0]["code"], "REQUIRED", "{refused}");

    // --- the positive control ---
    let (status, created) =
        create_workspace(&harness, fixtures.alpha.id, admin, body("Engineering", "engineering"))
            .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(workspace_count(&db, fixtures.alpha.id, "engineering").await, 1);
}

// ---------------------------------------------------------------------------------------------
// Isolation — documented behaviour, and it proves nothing about the admin decision
// ---------------------------------------------------------------------------------------------

/// **Isolation layer**, asserted because `T1` is documented and *not* because it isolates anything
/// this handler does.
///
/// Row-level security, the tenant predicate in every statement, and the chain's stage-1 comparison
/// each refuse this independently. It would pass with the whole authorization stage deleted, which
/// is precisely why the same-tenant test above exists.
///
/// What makes it worth writing anyway is the shape of the fixture: beta's administrator provisions a
/// workspace with the **same name and the same slug** alpha uses, so nothing here can pass because
/// the two tenants' rows were called different things. Both rows exist — that is asserted over the
/// superuser connection — and the slug index is per tenant, so the second create is a `201` and not
/// a collision.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_workspace_provisioned_in_beta_is_invisible_to_alpha() {
    let (db, fixtures, harness) = setup().await;

    let (status, beta) = create_workspace(
        &harness,
        fixtures.beta.id,
        fixtures.beta.admin,
        body("Engineering", "engineering"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "beta's administrator is one of beta's: {beta}");
    let beta_id = beta["id"].as_str().expect("an id").to_owned();

    let (status, alpha) = create_workspace(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        body("Engineering", "engineering"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the slug index is per tenant: {alpha}");
    let alpha_id = alpha["id"].as_str().expect("an id").to_owned();
    assert_ne!(alpha_id, beta_id);

    // Both rows really are there, so the absences below are absences and not an empty database.
    assert_eq!(workspace_count(&db, fixtures.beta.id, "engineering").await, 1);
    assert_eq!(workspace_count(&db, fixtures.alpha.id, "engineering").await, 1);

    // Alpha's token, beta's workspace id.
    let (status, refused) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.admin,
        &format!("/api/v1/workspaces/{beta_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "rule 7: cross-tenant is 404, never 403: {refused}");

    // And alpha's own listing holds alpha's workspace and only alpha's — the positive control and
    // the negative one in a single assertion.
    let (status, page) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.admin, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let listed: Vec<&str> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert_eq!(
        listed,
        vec![alpha_id.as_str()],
        "alpha must see its own workspace and no other: {page}"
    );

    // Beta's founding grant is beta's. Nothing alpha's administrator did wrote a row into it.
    assert_eq!(acl_count(&db, fixtures.beta.id, &beta_id).await, FOUNDING_GRANT_ROWS);
    assert_eq!(acl_count(&db, fixtures.alpha.id, &beta_id).await, 0);
}

/// **The journey, end to end, on nothing but what provisioning granted.**
///
/// This is the test the rest of this file exists to make possible, and it is the one that would
/// have caught the defect the first version of `FOUNDING_GRANT` shipped with. That grant was the
/// six `container.*` actions and nothing else, which is enough to create a library, enough to
/// create a folder, and enough to upload — `POST /uploads` enforces
/// `Action::Container(ContainerAction::Create)` — and then **not** enough to open what was just
/// written, because `content::file_metadata` enforces `Action::File(FileAction::MetadataRead)` and
/// `repo::acl_entries_by_action` matches action strings literally, with no implication from
/// `container.*` to `file.*`.
///
/// Every leg below passed under that grant except the last. A test that stopped at leg 3 — as the
/// library suite's does, and correctly, since it is testing a different route — would have reported
/// this whole slice as working.
///
/// A folder rather than an uploaded file, deliberately: a folder is a row in `files` like any
/// other, so it exercises the same `FileAction::MetadataRead` decision without requiring object
/// storage, antivirus or a running worker. What is being proved is the reach of an ACL entry, and
/// that does not depend on there being bytes behind it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_founder_can_walk_from_an_empty_tenant_to_a_file_they_can_open() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let founder = fixtures.alpha.admin;

    // --- leg 1: provision, which is the only act that writes the founding grant ---
    let (status, workspace) =
        create_workspace(&harness, tenant, founder, body("Field Notes", "field-notes")).await;
    assert_eq!(status, StatusCode::CREATED, "{workspace}");
    let workspace_id = workspace["id"].as_str().expect("id").to_owned();

    // --- leg 2: a library, authorized by `container.create` on the workspace just made ---
    let (status, library) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/workspaces/{workspace_id}/libraries"),
        serde_json::json!({ "name": "Interviews", "slug": "interviews" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the founding grant must reach a library: {library}");
    let library_id = library["id"].as_str().expect("id").to_owned();

    // --- leg 3: a folder, authorized by inheritance down to the library's contents ---
    let (status, folder) = post(
        &harness,
        tenant,
        founder,
        &format!("/api/v1/libraries/{library_id}/folders"),
        serde_json::json!({ "name": "2026-Q3" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the grant must reach the library's contents: {folder}"
    );
    let folder_id = folder["id"].as_str().expect("id").to_owned();

    // --- leg 4: and the founder can open it. This is the leg that used to 404. ---
    let (status, opened) =
        get(&harness, tenant, founder, &format!("/api/v1/files/{folder_id}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the founder created this and cannot open it — `FOUNDING_GRANT` is missing the file half: \
         {opened}"
    );
    assert_eq!(opened["id"], folder_id, "{opened}");

    // --- and the listing a client would actually draw shows it ---
    let (status, items) =
        get(&harness, tenant, founder, &format!("/api/v1/libraries/{library_id}/items")).await;
    assert_eq!(status, StatusCode::OK, "{items}");
    let rows = items["items"].as_array().expect("items");
    assert_eq!(rows.len(), 1, "the folder must survive the listing's ACL trim: {items}");
    assert_eq!(rows[0]["id"], folder_id, "{items}");

    drop(db);
}

/// **The positive control for the step-up requirement.**
///
/// Every other test in this file presents a second factor, which means every other test would pass
/// unchanged if `require_step_up` were deleted from the handler. This is the one that would not.
/// `docs/05-API.md §14` requires recent multi-factor authentication for a privileged mutation, and
/// provisioning writes a container *and* the founding grant over it in one transaction, so it is
/// one.
///
/// The refusal must also leave nothing behind: a step-up check that ran after the write would
/// answer `403` over a workspace that now exists.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_single_factor_administrator_is_refused_and_provisions_nothing() {
    let (db, fixtures, harness) = setup().await;
    let tenant = fixtures.alpha.id;

    let (status, refusal) = send(
        &harness,
        Request::builder()
            .method("POST")
            .uri("/api/v1/admin/workspaces")
            .header(
                "authorization",
                format!(
                    "Bearer {}",
                    token(&harness.key, tenant, fixtures.alpha.admin, Acr::SingleFactor)
                ),
            )
            .header("content-type", "application/json")
            .body(Body::from(body("Single Factor", "single-factor").to_string()))
            .expect("request"),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{refusal}");
    assert_eq!(refusal["error"]["code"], "STEP_UP_REQUIRED", "{refusal}");
    assert_eq!(
        workspace_count(&db, tenant, "single-factor").await,
        0,
        "a request refused for want of a second factor must not have provisioned anything"
    );
}
