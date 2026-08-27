//! `ENC-791` — the workspace and library read paths, end to end, over a real PostgreSQL.
//!
//! # What these prove that the unit tests in `crates/api/src/routes/` cannot
//!
//! Those prove the *shape*: that a page carries no total, that an `ACCESS_DENIED` becomes a `404`,
//! that a `ReadOnly` obligation only ever subtracts a capability. None of that is the property the
//! endpoints exist to hold. That property is **a listing must not become a way to enumerate what
//! you cannot see**, and it is a claim about what the ACL resolver, row-level security and the trim
//! do *together*, under the `enclave_app` role, with the tenant context the token established.
//!
//! So every request below is a real HTTP request through the real router, carrying a real signed
//! token, against a freshly migrated database, resolved by the real `PgAclAuthorization`. The
//! fixtures are written over the harness's superuser connection because they are setup; every read
//! under test goes through [`TestDb::pool`], which `SET ROLE enclave_app`s.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! `docs/12-TESTING.md §1.2`, and the seven prior instances in this repository where deleting a
//! `tenant_id` predicate **failed to fail** because row-level security held the property alone. A
//! cross-tenant assertion cannot distinguish "the authorization stage refused" from "RLS made the
//! row invisible", so on its own it proves nothing about the code this work added.
//!
//! Every test below therefore says which layer it is about:
//!
//! * **Authorization** — a *second member of the caller's own tenant*'s container, where RLS has
//!   nothing to say because the rows are the caller's tenant's to read. Only the trim can refuse
//!   them. [`Spine::unshared_workspace`] and [`Spine::detached_library`] are those rows, and they
//!   are what [`a_workspace_listing_shows_only_what_the_caller_may_see`] and
//!   [`a_library_listing_shows_only_what_the_caller_may_see`] assert about.
//! * **Isolation** — `tenant-beta`'s workspace and library, which RLS *and* the tenant predicate
//!   *and* the chain's stage-1 comparison all refuse independently. Asserted because it is the
//!   documented behaviour (`T1`), not because it isolates anything.
//!
//! # An absence needs a positive control
//!
//! "The row the caller may not see is not in the response" passes for free against a handler that
//! returns an empty list, against a broken fixture, and against a listing endpoint that was deleted.
//! Every negative assertion here is therefore paired, **in the same test and against the same
//! caller**, with the row that *is* returned — and where the difference between the two is a single
//! ACL entry, the test grants it and asserts the row appears
//! ([`the_same_caller_with_the_grant_sees_the_workspace_that_was_absent`]).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, Actor, AuthorizationService as _, ClientType, ContainerAction, LibraryId, PolicyEngine,
    RequestContext, ResourceRef, TenantId, UserId, WorkspaceId,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::{Connection as _, PgConnection};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's container spine.
///
/// Two workspaces and four libraries, and the two rows the whole suite turns on are the ones the
/// caller is **not** granted:
///
/// * `unshared_workspace` is an ordinary workspace in the caller's own tenant, created by the same
///   owner, differing from `workspace` only in that no ACL entry reaches it. Row-level security has
///   nothing to say about it — it is this tenant's row — so if it appears in a listing, the trim is
///   what failed.
/// * `detached_library` sits *inside* the granted workspace with `inherit_permissions = FALSE` and
///   no entries of its own, so the workspace's grant stops at it. It is the case that proves the
///   per-row trim is not redundant with the workspace check: the caller may read the container it
///   is in and may not read it.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    /// Granted to the caller.
    workspace: WorkspaceId,
    /// Same tenant, no grant. The authorization-layer control.
    unshared_workspace: WorkspaceId,
    /// In `workspace`, inherits, granted.
    library: LibraryId,
    /// In `workspace`, inherits, granted. A second one so a page of one has somewhere to go next.
    also_library: LibraryId,
    /// In `workspace`, inheritance broken, no entries. Invisible by construction.
    detached_library: LibraryId,
    /// In `unshared_workspace`. Only reachable by someone who can reach that workspace.
    unshared_library: LibraryId,
}

impl Spine {
    /// Builds the ids in listing order.
    ///
    /// Both listings order by `id`, which is a UUIDv7 and therefore creation order, so generating
    /// them in this sequence makes the expected page order deterministic rather than incidental.
    /// `detached_library` is minted **between** the two granted ones on purpose: a page of one that
    /// lands on the trimmed row is the interesting cursor case, and it can only occur in the middle.
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            unshared_workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            detached_library: LibraryId::new_v7(),
            also_library: LibraryId::new_v7(),
            unshared_library: LibraryId::new_v7(),
        }
    }

    /// The libraries in `workspace` the granted caller is meant to see, in listing order.
    fn readable_libraries(&self) -> [LibraryId; 2] {
        [self.library, self.also_library]
    }

    /// Writes both workspaces and all four libraries.
    ///
    /// Columns are spelled as `docs/04-DATA-MODEL.md §7` defines them, so a migration that drifts
    /// from the document fails here rather than later.
    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        // The names are distinctive, because several assertions below are "this string does not
        // appear in the response" and a name shared with a readable sibling would make them pass
        // for the wrong reason.
        self.insert_workspace(conn, self.workspace, "Engineering", owner).await;
        self.insert_workspace(conn, self.unshared_workspace, "Severance Planning", owner).await;

        self.insert_library(conn, self.library, self.workspace, "Specifications", true).await;
        self.insert_library(conn, self.also_library, self.workspace, "Runbooks", true).await;
        // Inside the workspace the caller *can* read, and still not readable.
        self.insert_library(
            conn,
            self.detached_library,
            self.workspace,
            "Compensation Bands",
            false,
        )
        .await;
        self.insert_library(
            conn,
            self.unshared_library,
            self.unshared_workspace,
            "Exit Packages",
            true,
        )
        .await;
    }

    async fn insert_workspace(
        &self,
        conn: &mut PgConnection,
        id: WorkspaceId,
        name: &str,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, description, visibility, created_by, created_at,
                updated_at)
             VALUES ($1, $2, $3, $4, 'a description', 'PRIVATE', $5, $6, $6)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(name)
        .bind(format!("ws-{}", id.as_uuid()))
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert workspace");
    }

    async fn insert_library(
        &self,
        conn: &mut PgConnection,
        id: LibraryId,
        workspace: WorkspaceId,
        name: &str,
        inherit: bool,
    ) {
        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, sync_enabled, mcp_visible, ai_indexing_enabled, require_checkout,
                require_approval, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'MAJOR_MINOR', 'EXISTING_GUESTS', TRUE, FALSE, TRUE,
                     TRUE, FALSE, $7, $7)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(workspace.as_uuid())
        .bind(name)
        .bind(format!("lib-{}", id.as_uuid()))
        .bind(inherit)
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert library");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Grants one action on one resource to one user.
///
/// The action is spelled with `Action`'s own `Display` — `container.read` — which is also the form
/// audit rows carry.
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

/// The app, the signing key, and the authorization service the engine will actually consult.
///
/// The service is returned so a test can ask it the same question the response claims to answer.
/// That is the only way to assert `docs/05-API.md §7`'s promise about `capabilities` — "computed by
/// the same policy engine that will enforce the action" — rather than asserting that the handler's
/// own arithmetic is self-consistent.
struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
    authz: Arc<PgAclAuthorization>,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // Three pools rather than one. Each is deliberately tiny (`TestDb::pool` caps at two), and a
    // request that resolves an ACL while holding an audit connection would otherwise compete with
    // itself for the last one.
    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let probe_pool = db.pool().await.expect("probe pool");
    let audit_pool = db.pool().await.expect("audit pool");

    // Two resolvers over the same database rather than one shared behind an `Arc`: `SelfServiceOr`
    // takes its inner service by value, and `PgAclAuthorization` is a pool handle and a set of
    // rules with no state of its own, so the two are the same resolver in every sense that matters.
    // The second one is what a test asks directly, so `capabilities` can be compared against the
    // stage's own answer rather than against the handler's arithmetic.
    let authz = Arc::new(PgAclAuthorization::new(probe_pool));

    // `SelfServiceOr` and not `PgAclAuthorization` alone, because `GET /workspaces` enforces
    // `container.read` on the caller's own `users` row (`ENC-795`) and the ACL resolver correctly
    // calls a `User` resource unsupported. This is the composition `crates/api/src/main.rs` ships;
    // wiring the resolver alone here would make every workspace listing `404` for a reason the
    // deployed binary does not have.
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
    // Navigation reaches no delivery path.
    Harness { app: router(state, enclave_api::Delivery::unconfigured()), key, authz }
}

/// Mints a real access token — signed, with the real claim set, verified by the real verifier.
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

/// Issues one `GET` and returns the status and the parsed body.
async fn get(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
) -> (StatusCode, serde_json::Value) {
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
                .body(Body::empty())
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

/// The audit rows for one tenant, as `(action, outcome, resource_id)`.
async fn audit_rows(db: &TestDb, tenant: TenantId) -> Vec<(String, String, Option<Uuid>)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT action, outcome, resource_id FROM audit_events WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

fn ids(page: &serde_json::Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect()
}

fn ctx(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx
}

/// A database with both tenants seeded, both spines written, and alpha's member granted
/// `container.read` on alpha's *first* workspace only.
///
/// Beta gets the identical structure and no grants for alpha's user, which is what makes the
/// cross-tenant assertions realistic rather than assertions about an empty tenant.
async fn setup() -> (TestDb, Fixtures, Spine, Spine) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let alpha = Spine::new(fixtures.alpha.id);
    let beta = Spine::new(fixtures.beta.id);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    beta.insert(&mut admin, fixtures.beta.owner).await;

    let user = fixtures.alpha.member;
    // One entry, on one workspace. Everything the caller can see follows from it by inheritance,
    // and everything they cannot see is a row this entry does not reach.
    grant(
        &mut admin,
        alpha.tenant,
        "WORKSPACE",
        alpha.workspace.as_uuid(),
        user,
        Action::Container(ContainerAction::Read),
    )
    .await;
    let _ignored = admin.close().await;

    (db, fixtures, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// The workspace listing
// ---------------------------------------------------------------------------------------------

/// **The central claim, at the authorization layer.**
///
/// `unshared_workspace` is in the caller's own tenant, created by the same owner, and differs from
/// the one they can see in exactly one ACL entry. Row-level security cannot refuse it — it is this
/// tenant's row, visible to the `enclave_app` role under this tenant's context — so the only thing
/// that can keep it out of the response is the trim in `routes::workspaces::readable_workspaces`.
/// This is the test that fails when that trim is deleted, and it is deliberately **not** a
/// cross-tenant assertion, because seven prior instances in this repository have shown that a
/// cross-tenant assertion stays green with the application layer removed.
///
/// The positive control is in the same response: the workspace the caller *can* see is asserted
/// present, so an endpoint that answered `{"items": []}` fails here rather than passing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_workspace_listing_shows_only_what_the_caller_may_see() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/workspaces").await;

    assert_eq!(status, StatusCode::OK);

    // The positive control, first: the listing is not empty and names the right row.
    assert_eq!(ids(&body), vec![alpha.workspace.to_string()], "the granted workspace must be here");

    // The negative: the same-tenant workspace the caller holds no entry for is absent by id *and*
    // by name. Two assertions because they fail for different reasons — an id leak is a broken
    // trim, a name leak with no id is a partially rendered row.
    let text = serde_json::to_string(&body).expect("render");
    assert!(
        !text.contains(&alpha.unshared_workspace.to_string()),
        "an ungranted same-tenant workspace id reached the caller: {text}"
    );
    assert!(
        !text.contains("Severance Planning"),
        "an ungranted same-tenant workspace name reached the caller: {text}"
    );

    // The trim is invisible: nothing says two rows were read and one was dropped.
    let page = body["page"].as_object().expect("page");
    assert_eq!(page["hasMore"], false);
    assert_eq!(page["limit"], 50, "docs/05-API.md §6 fixes the default at 50");
    for leak in ["total", "totalCount", "count", "trimmed", "filtered"] {
        assert!(!page.contains_key(leak), "{leak} would say how much the caller cannot see");
    }

    // One request, one decision, one row — and *not* one row per candidate. The trim goes through
    // the authorization stage directly, which decides without auditing; auditing it would record
    // reads the caller never asked for.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "container.read");
    assert_eq!(rows[0].1, "ALLOW");
    // `ENC-795`: the audited resource of a workspace listing is the caller, not a workspace.
    assert_eq!(rows[0].2, Some(fixtures.alpha.member.as_uuid()));
}

/// The positive control for the absence above, as its own test: one ACL entry is the whole
/// difference.
///
/// Without this, `a_workspace_listing_shows_only_what_the_caller_may_see` would also pass against a
/// deployment in which `unshared_workspace` was invisible for some *other* reason — a fixture that
/// silently failed to insert it, a repository that filtered by visibility, a cursor that skipped it.
/// Granting the same caller `container.read` on that same workspace and watching it appear proves
/// the row exists, is reachable, and was withheld by the authorization stage and nothing else.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_same_caller_with_the_grant_sees_the_workspace_that_was_absent() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (_, before) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/workspaces").await;
    assert_eq!(ids(&before).len(), 1, "the fixture must start with exactly one visible workspace");

    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        alpha.tenant,
        "WORKSPACE",
        alpha.unshared_workspace.as_uuid(),
        fixtures.alpha.member,
        Action::Container(ContainerAction::Read),
    )
    .await;
    let _ignored = admin.close().await;

    let (status, after) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK);

    let mut returned = ids(&after);
    returned.sort();
    let mut expected = vec![alpha.workspace.to_string(), alpha.unshared_workspace.to_string()];
    expected.sort();
    assert_eq!(returned, expected, "the grant is the only thing that changed");
    assert!(
        serde_json::to_string(&after).expect("render").contains("Severance Planning"),
        "the row that was withheld is the row that now appears"
    );
}

/// **Isolation, not authorization.** Beta's workspaces never appear in alpha's listing.
///
/// Stated plainly because it is the weaker of the two claims: three independent mechanisms refuse
/// this — the `tenant_id` predicate in `WorkspaceRepository::list_by_tenant`, row-level security on
/// the scoped connection, and `classify`'s tenant comparison in the resolver — so removing any one
/// of them leaves this test green. It is here because `docs/12-TESTING.md` `T1` requires it, and
/// the row that actually exercises the code this work added is
/// `a_workspace_listing_shows_only_what_the_caller_may_see`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_workspaces_are_absent_from_the_listing() {
    let (db, fixtures, _alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK);

    let text = serde_json::to_string(&body).expect("render");
    for absent in [beta.workspace, beta.unshared_workspace] {
        assert!(!text.contains(&absent.to_string()), "a beta workspace id reached alpha: {text}");
    }

    // Beta's listing, for beta's own member, is the control that the beta fixture is real: without
    // it "alpha cannot see beta's rows" would also hold if beta had none.
    let (status, beta_body) =
        get(&harness, fixtures.beta.id, fixtures.beta.member, "/api/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ids(&beta_body).is_empty(),
        "beta's member holds no grant either, which is what makes the fixture symmetric"
    );
    assert!(
        serde_json::to_string(&beta_body).expect("render").contains("\"items\":[]"),
        "and the endpoint answers a trimmed listing rather than refusing"
    );
}

// ---------------------------------------------------------------------------------------------
// Reading one workspace
// ---------------------------------------------------------------------------------------------

/// A same-tenant workspace with no grant, another tenant's workspace, and an id that never existed
/// are **one answer**.
///
/// `CLAUDE.md` rule 7 and `docs/12-TESTING.md` `T1`. The first of the three is the one that proves
/// the code: it is alpha's own row, so row-level security admits it and only `conceal` can turn the
/// authorization stage's `ACCESS_DENIED` into an absence. The granted workspace is read in the same
/// test, so a handler that answered `404` to everything fails here.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_workspace_the_caller_cannot_see_is_absent_and_never_forbidden() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    // The positive control.
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}", alpha.workspace),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Engineering");
    assert_eq!(body["visibility"], "PRIVATE");
    assert_eq!(body["capabilities"]["read"], true);

    let unknown = WorkspaceId::new_v7();
    for (label, id) in [
        // Same tenant, no grant. RLS has nothing to say; only the chain can refuse it.
        ("an ungranted same-tenant workspace", alpha.unshared_workspace),
        ("another tenant's workspace", beta.workspace),
        ("an id that names nothing", unknown),
    ] {
        let (status, body) = get(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            &format!("/api/v1/workspaces/{id}"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label} answered {status}");
        assert_eq!(body["error"]["code"], "NOT_FOUND", "{label} named its own refusal: {body}");
        // The body must not differ between the three, or the status is the only thing that agrees.
        assert_eq!(body["error"]["remediation"], "", "{label} carried a remediation: {body}");
    }

    // A malformed id is the same answer as well: `GET /workspaces/<garbage>` and
    // `GET /workspaces/<another tenant's id>` must not be distinguishable.
    let (status, _) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/workspaces/not-a-uuid")
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// The library listing
// ---------------------------------------------------------------------------------------------

/// **The per-row trim is not redundant with the workspace check.**
///
/// `detached_library` is inside the workspace the caller *can* read, created by the same fixture,
/// differing from its siblings only in `inherit_permissions = FALSE` — which stops the workspace's
/// grant at it (`docs/04-DATA-MODEL.md §9`). So the caller passes the container check on the
/// workspace and must still not see this library. Nothing about tenancy is involved: this is the
/// authorization layer alone, and it is the row that fails if `readable_libraries` is deleted.
///
/// The positive control is the two siblings, asserted present in the same response.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_listing_shows_only_what_the_caller_may_see() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}/libraries", alpha.workspace),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let expected: Vec<String> =
        alpha.readable_libraries().iter().map(ToString::to_string).collect();
    assert_eq!(ids(&body), expected, "the listing must be exactly the inheriting libraries");

    let text = serde_json::to_string(&body).expect("render");
    assert!(
        !text.contains(&alpha.detached_library.to_string()),
        "a library whose inheritance is broken reached the caller: {text}"
    );
    assert!(
        !text.contains("Compensation Bands"),
        "the detached library's name reached the caller: {text}"
    );

    // The settings a client renders from are on the wire; the three internal references are not.
    let first = &body["items"][0];
    assert_eq!(first["settings"]["versioningMode"], "MAJOR_MINOR");
    assert_eq!(first["settings"]["externalSharing"], "EXISTING_GUESTS");
    assert_eq!(first["settings"]["syncEnabled"], true);
    assert_eq!(first["workspaceId"], alpha.workspace.to_string());
    for absent in ["storageProfileId", "retentionPolicyId", "defaultClassificationId"] {
        assert!(!text.contains(absent), "{absent} reached the wire: {text}");
    }

    // One decision, one row — on the *workspace*, which is the container being listed.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "container.read");
    assert_eq!(rows[0].1, "ALLOW");
    assert_eq!(rows[0].2, Some(alpha.workspace.as_uuid()));
}

/// The libraries of a workspace the caller cannot see are not counted, named or refused — the
/// workspace itself is absent.
///
/// Both legs are same-tenant except the last: `unshared_workspace` holds a real library, so a
/// handler that leaked a count or an empty page would be telling the caller the workspace exists.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn listing_libraries_of_an_unreadable_workspace_is_the_same_404_as_one_that_is_not_there() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    for (label, workspace) in [
        ("an ungranted same-tenant workspace", alpha.unshared_workspace),
        ("another tenant's workspace", beta.workspace),
        ("an id that names nothing", WorkspaceId::new_v7()),
    ] {
        let (status, body) = get(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            &format!("/api/v1/workspaces/{workspace}/libraries"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label} answered {status}");
        assert_eq!(body["error"]["code"], "NOT_FOUND", "{label}: {body}");
    }

    // The name of the library inside the unreadable workspace never appears anywhere, including in
    // the granted workspace's own listing.
    let (_, granted) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}/libraries", alpha.workspace),
    )
    .await;
    assert!(!serde_json::to_string(&granted).expect("render").contains("Exit Packages"));

    // Every refusal above wrote a `DENY` row. A denial that reaches a caller with no audit row is
    // the failure `CLAUDE.md` rule 10 is about, and it is the one an investigator most needs.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    let denials = rows.iter().filter(|(_, outcome, _)| outcome == "DENY").count();
    assert_eq!(denials, 3, "each of the three refusals must be recorded: {rows:?}");
}

/// Reading one library: granted, detached, cross-tenant, absent.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_the_caller_cannot_see_is_absent_and_never_forbidden() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}", alpha.library),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Specifications");
    assert_eq!(body["workspaceId"], alpha.workspace.to_string());
    assert_eq!(body["capabilities"]["read"], true);
    assert_eq!(body["settings"]["requireCheckout"], true);

    for (label, library) in [
        // Same tenant, same workspace, inheritance broken. The authorization layer alone.
        ("a detached library in a readable workspace", alpha.detached_library),
        ("a library in an unreadable workspace", alpha.unshared_library),
        ("another tenant's library", beta.library),
        ("an id that names nothing", LibraryId::new_v7()),
    ] {
        let (status, body) = get(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            &format!("/api/v1/libraries/{library}"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{label} answered {status}");
        assert_eq!(body["error"]["code"], "NOT_FOUND", "{label}: {body}");
    }
}

// ---------------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------------

/// `limit=1` forces the interesting case: the page whose single row is the trimmed one comes back
/// **empty with `hasMore: true`**.
///
/// A client that stopped at the first short page would miss every library after `detached_library`,
/// and a cursor built from the last *surviving* row rather than the last row read would skip them
/// permanently. Both bugs fail here. The fixture mints the detached library between the two granted
/// ones precisely so this page exists.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn paging_a_library_listing_visits_every_readable_library_exactly_once() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut empty_pages = 0;
    let mut requests = 0;

    loop {
        requests += 1;
        assert!(requests <= 10, "the paging loop did not terminate; seen so far: {seen:?}");

        let uri = match cursor.as_deref() {
            Some(cursor) => {
                format!("/api/v1/workspaces/{}/libraries?limit=1&cursor={cursor}", alpha.workspace)
            }
            None => format!("/api/v1/workspaces/{}/libraries?limit=1", alpha.workspace),
        };
        let (status, body) = get(&harness, fixtures.alpha.id, fixtures.alpha.member, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["page"]["limit"], 1);

        let page = ids(&body);
        if page.is_empty() {
            empty_pages += 1;
            assert_eq!(
                body["page"]["hasMore"], true,
                "an empty page that is also the last page would end a client's loop early: {body}"
            );
        }
        seen.extend(page);

        match body["page"]["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }

    let expected: Vec<String> =
        alpha.readable_libraries().iter().map(ToString::to_string).collect();
    assert_eq!(seen, expected, "paging must visit every readable library exactly once");
    assert_eq!(
        empty_pages, 1,
        "the trimmed row must produce exactly one short page; if it produced none the fixture is \
         not exercising the case this test exists for"
    );
    assert!(
        !seen.contains(&alpha.detached_library.to_string()),
        "the trimmed library reappeared while paging"
    );
}

/// A cursor issued in one tenant is refused in another (`docs/12-TESTING.md` `T3`).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_cursor_from_one_tenant_is_not_usable_in_another() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    // Beta's member must be able to read beta's workspace, or the cursor below would never be
    // issued and this test would assert nothing.
    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        beta.tenant,
        "WORKSPACE",
        beta.workspace.as_uuid(),
        fixtures.beta.member,
        Action::Container(ContainerAction::Read),
    )
    .await;
    grant(
        &mut admin,
        alpha.tenant,
        "WORKSPACE",
        alpha.unshared_workspace.as_uuid(),
        fixtures.alpha.member,
        Action::Container(ContainerAction::Read),
    )
    .await;
    let _ignored = admin.close().await;

    let (status, page) = get(
        &harness,
        fixtures.beta.id,
        fixtures.beta.member,
        &format!("/api/v1/workspaces/{}/libraries?limit=1", beta.workspace),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cursor =
        page["page"]["nextCursor"].as_str().expect("beta must have a next page").to_owned();

    // The same cursor, presented by alpha against alpha's own workspace.
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}/libraries?limit=1&cursor={cursor}", alpha.workspace),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a foreign cursor was accepted: {body}");
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"][0]["field"], "cursor");

    // The control: alpha's own listing pages normally, so the refusal is about the cursor's
    // provenance and not about cursors being broken.
    let (status, _) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}/libraries?limit=1", alpha.workspace),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------------------------

/// `capabilities` is the engine's answer, asked of the engine — and it differs per row.
///
/// `docs/05-API.md §7`: *"computed by the same policy engine that will enforce the action"*. So the
/// assertion is not that the object is self-consistent but that it **equals what the authorization
/// service says** when the test asks it directly, for every action and every row.
///
/// The fixture makes the six answers non-uniform on purpose — `container.update` is granted on one
/// library and nothing else — because an object where every field carried the same value would pass
/// against a handler that ignored the resource entirely.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rows_capabilities_are_what_the_authorization_stage_answers_for_that_row() {
    let (db, fixtures, alpha, _beta) = setup().await;

    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        alpha.tenant,
        "LIBRARY",
        alpha.library.as_uuid(),
        fixtures.alpha.member,
        Action::Container(ContainerAction::Update),
    )
    .await;
    let _ignored = admin.close().await;

    let harness = harness(&db).await;
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/workspaces/{}/libraries", alpha.workspace),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let ctx = ctx(fixtures.alpha.id, fixtures.alpha.member);
    let wire_names = [
        ("read", ContainerAction::Read),
        ("create", ContainerAction::Create),
        ("update", ContainerAction::Update),
        ("delete", ContainerAction::Delete),
        ("manageMembers", ContainerAction::ManageMembers),
        ("managePermissions", ContainerAction::ManagePermissions),
    ];

    let mut differed = false;
    for (index, library) in alpha.readable_libraries().iter().enumerate() {
        let row = &body["items"][index];
        assert_eq!(row["id"], library.to_string());
        let resource = ResourceRef::library(alpha.tenant, *library);
        for (name, action) in wire_names {
            let decision = harness
                .authz
                .authorize(&ctx, Action::Container(action), &resource)
                .await
                .expect("resolve");
            assert_eq!(
                row["capabilities"][name],
                serde_json::Value::Bool(decision.is_allowed()),
                "capabilities.{name} on {library} disagrees with the stage that will enforce it"
            );
        }
        if row["capabilities"]["update"] != body["items"][0]["capabilities"]["update"] {
            differed = true;
        }
    }

    assert!(
        differed,
        "the fixture must not be uniform: a page where every row answers identically passes \
         against a handler that resolves once and copies the verdict across the page"
    );
    // And the specific asymmetry, named, so a fixture that stopped creating it is visible.
    assert_eq!(body["items"][0]["capabilities"]["update"], true, "{body}");
    assert_eq!(body["items"][1]["capabilities"]["update"], false, "{body}");

    // The single-resource endpoint answers exactly as the row did — the property that stops a UI
    // changing its mind about what a user may do because they clicked into the library.
    let (status, single) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}", alpha.library),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(single["capabilities"], body["items"][0]["capabilities"]);
    assert_eq!(single["obligations"], body["items"][0]["obligations"]);
}
