//! `GET /api/v1/me/recent`, end to end, over a real PostgreSQL.
//!
//! # What is actually being proved
//!
//! Two things, and they are only interesting together. `recent_files` is written by the read paths
//! and read by one endpoint, so a suite that seeded the table directly would prove the endpoint
//! renders rows and say nothing about whether anything in this product ever writes one — this
//! repository's signature failure, a complete engine nothing calls.
//! [`opening_a_file_puts_it_in_the_callers_recent_list`] is therefore written first and does it the
//! long way round: it opens a file through `GET /files/{id}` and then asks the home screen's
//! endpoint what it has. **Nothing in this file inserts a `recent_files` row.**
//!
//! The second thing is that a stored row is not a permission. A recency list is a list of things
//! you *used* to be able to open, and the gap between the touch and the read is where an ACL is
//! revoked, a file is moved and a barrier is declared.
//! [`a_file_the_caller_may_no_longer_read_is_dropped_and_counted_rather_than_refused`] builds that
//! gap on purpose.
//!
//! # The routes under test are the shipped ones
//!
//! [`setup`] builds [`enclave_api::router`] and nothing beside it — there is no local `Router`, no
//! `merge`, and no registration in this file. A suite that mounted its own handler would prove the
//! handler works and say nothing about whether any request can reach it;
//! `crates/api/tests/reachability.rs` exists because this repository has shipped that shape a dozen
//! times. Measured rather than claimed: against `crates/api/src/lib.rs` as it stands before the
//! registration lands, every test here answers `404` and fails.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! The application runs as `enclave_app` with forced row-level security; every assertion about what
//! is *stored* reads over the harness's superuser connection, so an assertion that a row was not
//! written cannot pass because the reader could not see it.
//!
//! * **Per-user isolation.** [`a_file_another_user_opened_is_not_in_this_users_list`] is the one no
//!   database control holds. Both users are alpha's, both files are alpha's, and row-level security
//!   is blind to which colleague in a tenant a row belongs to — `r.user_id = $2` in
//!   `crates/db/src/recent.rs` is the only thing separating one person's reading history from
//!   another's, and this is the behavioural half of the assertion `crates/db/tests/recent.rs` makes
//!   where RLS is inert.
//! * **Authorization.**
//!   [`a_file_the_caller_may_no_longer_read_is_dropped_and_counted_rather_than_refused`] is the
//!   security test. Both files are alpha's and the caller is alpha's own member, so RLS has nothing
//!   to say and only the `file.metadata_read` batch can tell the two rows apart. Delete that batch
//!   and the endpoint serves a file the caller can no longer open, with a `200`.
//! * **Isolation.** [`another_tenants_file_never_appears_for_an_alpha_caller`] is asserted because
//!   `T1` is documented behaviour, **not** because the handler isolates anything itself: what holds
//!   it is the tenant on the scoped transaction, which comes from the verified token and from
//!   nowhere else. Both tenants are given a file with the same name, so it cannot pass merely
//!   because the other tenant's row was called something different.
//!
//! # Every absence is paired with its positive control
//!
//! "The row is not in the list" passes for free against an endpoint that returns nothing, against a
//! recency write that never happened, and against a route nobody registered. So every absence below
//! is asserted in the same run as the presence that makes it meaningful.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::{AdminAuthorization, PgAclAuthorization, PgAdminRoles, SelfServiceOr};
use enclave_core::{
    Action, ClassificationId, ClientType, ContainerAction, FileAction, FileId, LibraryId,
    PolicyEngine, TenantId, UserId, WorkspaceId,
};
use enclave_db::DbPool;
use enclave_testing::{Fixtures, TestDb};
use serde_json::Value;
use sqlx::{Connection as _, PgConnection};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The number of rows `GET /me/recent` will never exceed, whatever `limit` asks for.
///
/// Restated here rather than imported so that a change to `routes::recent::MAX_LIMIT` has to be
/// made twice — once in the code and once in a test that fails until somebody agrees with it.
const CAP: usize = 8;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's content spine: a workspace, a library, a folder, and twelve files.
///
/// Twelve because the cap is eight and a cap cannot be observed with fewer rows than it refuses.
/// The first two are the ones the narrative tests use and they are deliberately different from each
/// other: `nested` sits inside a folder and carries a classification, `rooted` sits at the library
/// root and carries none — which is the whole of the contract's `parentFolderId: null` and
/// `classification: null`.
#[derive(Debug, Clone)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    label: ClassificationId,
    folder: FileId,
    /// Inside `folder`, labelled `INTERNAL`.
    nested: FileId,
    /// At the library root, unlabelled.
    rooted: FileId,
    /// Ten more at the library root, for the cap.
    bulk: Vec<FileId>,
}

impl Spine {
    /// Builds the ids in creation order, which is also `FileId`'s own order (UUIDv7).
    ///
    /// `nested` is generated **before** `rooted` on purpose, and
    /// [`the_list_is_most_recent_first_even_when_the_ids_disagree`] is why: the recency read breaks
    /// a timestamp tie by `file_id DESC`, so opening the lower id last is what makes that test an
    /// assertion about the clock rather than about the ids.
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            label: ClassificationId::new_v7(),
            folder: FileId::new_v7(),
            nested: FileId::new_v7(),
            rooted: FileId::new_v7(),
            bulk: (0..10).map(|_| FileId::new_v7()).collect(),
        }
    }

    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
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
                external_sharing, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert library");

        // The label the chip renders. `INTERNAL` / 20 is the shipped set's second rank
        // (`docs/01-PRD.md §17`), so the three fields the contract carries are all distinct values
        // and a response that mixed two of them up would be visible.
        sqlx::query(
            "INSERT INTO classifications (id, tenant_id, key, label, rank, created_at, updated_at)
             VALUES ($1, $2, 'INTERNAL', 'Internal', 20, $3, $3)",
        )
        .bind(self.label.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert classification");

        self.node(conn, self.folder, "FOLDER", "Reports", None, None, owner).await;
        self.node(
            conn,
            self.nested,
            "FILE",
            "Quarterly Plan.pdf",
            Some(self.folder),
            Some(self.label),
            owner,
        )
        .await;
        self.node(conn, self.rooted, "FILE", "fox.txt", None, None, owner).await;
        for (index, file) in self.bulk.iter().enumerate() {
            self.node(conn, *file, "FILE", &format!("bulk-{index}.txt"), None, None, owner).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        node_type: &str,
        name: &str,
        parent: Option<FileId>,
        label: Option<ClassificationId>,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, status, inherit_permissions, classification_id,
                created_by, modified_by, created_at, modified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'AVAILABLE', TRUE, $10, $11, $11, $12,
                     $12)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(parent.map(|id| id.as_uuid()))
        .bind(node_type)
        .bind(name)
        .bind(name.to_lowercase())
        .bind(if name.ends_with(".pdf") { "application/pdf" } else { "text/plain" })
        .bind(label.map(|id| id.as_uuid()))
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert file node");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Grants one action on one resource to one user.
///
/// Spelled with `Action`'s own `Display`, which is the form `acl_entries.action` stores and the
/// resolver matches by string equality.
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

/// Stops a file inheriting, which — with no entries of its own — makes it unreadable to everybody.
///
/// This is how the gap between the touch and the read is built. The caller opened the file while
/// the library's grant reached it; afterwards the resolver's walk stops at the file itself and finds
/// nothing, which is what a revoked grant looks like from the endpoint's side.
async fn detach(conn: &mut PgConnection, tenant: TenantId, file: FileId) {
    let changed = sqlx::query(
        "UPDATE files SET inherit_permissions = FALSE WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("detach the file")
    .rows_affected();
    assert_eq!(changed, 1, "the fixture must have detached exactly one file");
}

/// Every `recent_files` row for one user, read over the connection nothing is filtered on.
///
/// An assertion that a row was **not** written must not be able to pass because the reader could
/// not see it.
async fn stored(db: &TestDb, tenant: TenantId, user: UserId) -> Vec<Uuid> {
    let mut conn = db.connect().await.expect("connect");
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT file_id FROM recent_files
          WHERE tenant_id = $1 AND user_id = $2
          ORDER BY last_accessed_at DESC, file_id DESC",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read recency");
    let _ignored = conn.close().await;
    rows.into_iter().map(|(id,)| id).collect()
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: Router,
    key: PrivateSigningKey,
}

/// A migrated, seeded database, both spines written, and alpha's member and viewer each granted the
/// two read actions on alpha's library.
///
/// Beta gets the identical structure — including a file with the same name — and no grant for any
/// of alpha's users, which is what makes the cross-tenant assertion realistic rather than an
/// assertion about an empty tenant.
async fn setup() -> (TestDb, Fixtures, Spine, Spine, Harness) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");

    let alpha = Spine::new(fixtures.alpha.id);
    let beta = Spine::new(fixtures.beta.id);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    beta.insert(&mut admin, fixtures.beta.owner).await;

    for (spine, user) in [
        (&alpha, fixtures.alpha.member),
        (&alpha, fixtures.alpha.viewer),
        (&beta, fixtures.beta.member),
    ] {
        for action in
            [Action::Container(ContainerAction::Read), Action::File(FileAction::MetadataRead)]
        {
            grant(&mut admin, spine.tenant, "LIBRARY", spine.library.as_uuid(), user, action).await;
        }
    }
    let _ignored = admin.close().await;

    // Eight connections on one pool, as `tests/permissions.rs`: a request reads its recency in one
    // transaction, closes it, and then resolves capabilities on another connection from the same
    // pool. A narrow pool would deadlock this suite for a reason unrelated to anything it asserts.
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

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    let harness = Harness { app: router(state, enclave_api::Delivery::unconfigured()), key };

    (db, fixtures, alpha, beta, harness)
}

/// The authorization stack `crates/api/src/main.rs` composes.
///
/// All three layers are load-bearing here, and the middle one especially: `GET /me/recent` asks
/// `container.read` on the caller's **own user row**, which no `acl_entries` row names and which
/// only `SelfServiceOr` answers. Composing `PgAclAuthorization` alone would refuse every request in
/// this file — and would be a composition no deployment runs (`ENC-746`).
fn authorization(pool: &DbPool) -> Arc<dyn enclave_core::AuthorizationService> {
    Arc::new(AdminAuthorization::new(
        Arc::new(PgAdminRoles::new(pool.clone())),
        Arc::new(SelfServiceOr::new(PgAclAuthorization::new(pool.clone()))),
    ))
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

async fn get(harness: &Harness, tenant: TenantId, user: UserId, uri: &str) -> (StatusCode, Value) {
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let body =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
    (status, body)
}

/// Opens a file the way a person does, and insists it worked.
///
/// Every recency row in this suite is written by this call and by nothing else. If
/// `crate::content::file_metadata` stopped recording, every test below goes red — which is the
/// property that makes them tests of the feature rather than of the renderer.
async fn open(harness: &Harness, tenant: TenantId, user: UserId, file: FileId) {
    let (status, body) = get(harness, tenant, user, &format!("/api/v1/files/{file}")).await;
    assert_eq!(status, StatusCode::OK, "the fixture must be able to open {file}: {body}");
}

/// `GET /me/recent`, with an optional `limit`.
async fn recent(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    limit: Option<u32>,
) -> (StatusCode, Value) {
    let uri = limit
        .map_or_else(|| "/api/v1/me/recent".to_owned(), |n| format!("/api/v1/me/recent?limit={n}"));
    get(harness, tenant, user, &uri).await
}

/// The `fileId`s of a page, in the order they were served.
fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("an items array")
        .iter()
        .map(|item| item["fileId"].as_str().expect("a fileId").to_owned())
        .collect()
}

fn filtered(page: &Value) -> u64 {
    page["filteredCount"].as_u64().expect("a filteredCount")
}

// ---------------------------------------------------------------------------------------------
// The journey this whole item exists for
// ---------------------------------------------------------------------------------------------

/// A user opens a file, and the home screen can bring them back to it.
///
/// **The test this item exists for.** Before it, `recent_files` had no writer in any binary and no
/// reader in any route, so the *Continue working* list `web/design-system/specs/home.md` §C
/// specifies could not have been populated by any sequence of HTTP requests whatsoever.
///
/// The empty list before the open is the positive control for the populated one after it, and it
/// has to be in the same run: on its own, "the file is in the list" passes against an endpoint that
/// returns every file in the tenant, and "the list is empty" passes against a route that returns
/// nothing at all. The pair can only both hold if the `GET /files/{id}` in between wrote something.
///
/// Every field of the contract is asserted here rather than spread across the file, because the
/// mapping is the thing a client codes against and a single wrong field — `libraryId` where
/// `parentFolderId` was meant — is invisible in a test that only counts rows.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn opening_a_file_puts_it_in_the_callers_recent_list() {
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    // Before: nothing has been opened, and the two empty states `docs/09 §11` distinguishes are
    // "no recent files" — an empty list with nothing filtered.
    let (status, before) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "the endpoint must answer: {before}");
    assert!(ids(&before).is_empty(), "nothing has been opened yet: {before}");
    assert_eq!(filtered(&before), 0, "and nothing was withheld either: {before}");
    assert!(stored(&db, tenant, member).await.is_empty(), "no row can exist before the open");

    open(&harness, tenant, member, alpha.nested).await;

    let (status, after) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(ids(&after), vec![alpha.nested.to_string()], "the file just opened: {after}");
    assert_eq!(filtered(&after), 0, "nothing was withheld: {after}");
    assert_eq!(
        stored(&db, tenant, member).await,
        vec![alpha.nested.as_uuid()],
        "the read path wrote exactly one row, and the endpoint is reading it"
    );

    let item = &after["items"][0];
    assert_eq!(item["name"], "Quarterly Plan.pdf");
    assert_eq!(item["extension"], "pdf", "derived at the edge, not in SQL");
    assert_eq!(item["mimeType"], "application/pdf");
    assert_eq!(item["libraryId"], alpha.library.to_string());
    assert_eq!(
        item["parentFolderId"],
        alpha.folder.to_string(),
        "this file is inside a folder, and the client links through it"
    );
    assert_eq!(item["classification"]["key"], "INTERNAL");
    assert_eq!(item["classification"]["label"], "Internal");
    assert_eq!(item["classification"]["rank"], 20);
    assert!(
        item["lastAccessedAt"].as_str().expect("an instant").ends_with('Z'),
        "RFC3339, in UTC: {item}"
    );

    // The twelve-key object `GET /files/{id}` returns, from the one function that builds it. The
    // count is asserted rather than a sample of the keys, because the failure this catches is a
    // second copy of the object drifting from the first (`ENC-929`).
    let capabilities = item["capabilities"].as_object().expect("a capabilities object");
    assert_eq!(capabilities.len(), 12, "the shape must be the file endpoint's: {item}");
    assert_eq!(capabilities["metadataRead"], true, "the caller demonstrably has this one");
    assert_eq!(
        item["capabilities"],
        get(&harness, tenant, member, &format!("/api/v1/files/{}", alpha.nested)).await.1
            ["capabilities"],
        "a Recent row and the file it links to must not disagree about what the caller may do"
    );

    // `parentFolderId` is `null` for a file at the library root — the other half of the mapping,
    // and the one a client renders differently.
    open(&harness, tenant, member, alpha.rooted).await;
    let (_status, page) = recent(&harness, tenant, member, None).await;
    let rooted = &page["items"][0];
    assert_eq!(rooted["fileId"], alpha.rooted.to_string(), "most recent first: {page}");
    assert_eq!(rooted["parentFolderId"], Value::Null, "a file at the library root: {rooted}");
    assert_eq!(rooted["classification"], Value::Null, "this one carries no label: {rooted}");
    assert_eq!(rooted["extension"], "txt");
}

// ---------------------------------------------------------------------------------------------
// Per-user isolation — the half no database control holds
// ---------------------------------------------------------------------------------------------

/// One colleague's reading history is not another's.
///
/// Both users are alpha's, both files are alpha's, and both users hold the same grants — so
/// row-level security, which is blind to which user in a tenant a row belongs to, cannot tell these
/// two lists apart. `r.user_id = $2` is the only predicate that can, and it is the one predicate in
/// `crates/db/src/recent.rs` with no second layer behind it.
///
/// Asserted in both directions in one run. "The member does not see the viewer's file" passes on
/// its own against an endpoint that returns nothing; only the paired assertion that each user *does*
/// see their own can distinguish isolation from emptiness.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_another_user_opened_is_not_in_this_users_list() {
    let (_db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;
    let viewer = fixtures.alpha.viewer;

    open(&harness, tenant, member, alpha.nested).await;
    open(&harness, tenant, viewer, alpha.rooted).await;

    let (status, mine) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(ids(&mine), vec![alpha.nested.to_string()], "only what I opened: {mine}");
    assert_eq!(filtered(&mine), 0, "the colleague's row is not mine and is not withheld: {mine}");

    let (status, theirs) = recent(&harness, tenant, viewer, None).await;
    assert_eq!(status, StatusCode::OK, "{theirs}");
    assert_eq!(ids(&theirs), vec![alpha.rooted.to_string()], "only what they opened: {theirs}");
    assert_eq!(filtered(&theirs), 0, "{theirs}");
}

// ---------------------------------------------------------------------------------------------
// Authorization — the gap between the touch and the read
// ---------------------------------------------------------------------------------------------

/// A file the caller may no longer open is dropped from the list and counted, never refused.
///
/// The security test. Both files are alpha's, the caller is alpha's own member, both rows are in
/// `recent_files` because the caller genuinely opened both — and between then and now the grant on
/// one of them stopped reaching it. Delete the `file.metadata_read` batch from
/// `routes::recent::admit` and this answers `200` with a document the caller can no longer open, and
/// no other test in this file notices.
///
/// The file that is *still* readable is the positive control, and it is what makes the assertion
/// about the count meaningful: `filteredCount: 1` beside an empty list would also be produced by an
/// endpoint that refuses everything.
///
/// The status is `200` and not `403` or `404` (`CLAUDE.md` rule 7). The caller learns how many rows
/// they cannot see; nothing in the response says which, and the name of the detached file must not
/// appear anywhere in the body.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_the_caller_may_no_longer_read_is_dropped_and_counted_rather_than_refused() {
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    open(&harness, tenant, member, alpha.nested).await;
    open(&harness, tenant, member, alpha.rooted).await;

    // Both are stored and both are served, which is the state the assertion below is measured
    // against.
    let (status, both) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{both}");
    assert_eq!(ids(&both).len(), 2, "both were opened and both are readable: {both}");
    assert_eq!(filtered(&both), 0, "{both}");

    // The grant stops reaching `nested`. Nothing about `recent_files` changes.
    let mut conn = db.connect().await.expect("connect");
    detach(&mut conn, tenant, alpha.nested).await;
    let _ignored = conn.close().await;
    assert_eq!(
        stored(&db, tenant, member).await.len(),
        2,
        "the recency rows are untouched; only the answer to `may I see it` changed"
    );

    let (status, page) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "a dropped row is never a refusal (rule 7): {page}");
    assert_eq!(ids(&page), vec![alpha.rooted.to_string()], "the positive control survives: {page}");
    assert_eq!(filtered(&page), 1, "and the one that did not is counted: {page}");

    let rendered = page.to_string();
    assert!(
        !rendered.contains("Quarterly Plan"),
        "the name of a file the caller may not read must not appear: {rendered}"
    );
    assert!(
        !rendered.contains(&alpha.nested.to_string()),
        "nor its id — the count says how many, never which: {rendered}"
    );

    // And the file endpoint agrees about the same file, which is what says the drop was the policy
    // chain's answer rather than this endpoint's own arithmetic.
    let (status, _body) =
        get(&harness, tenant, member, &format!("/api/v1/files/{}", alpha.nested)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the file itself is now invisible to this caller");
}

// ---------------------------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------------------------

/// A file another tenant's user opened never appears for an alpha caller.
///
/// Both tenants hold a file called `fox.txt`, opened by their own member, so this cannot pass
/// because the other tenant's row was named differently or because beta was empty. The alpha
/// caller's own row is the positive control in the same run.
///
/// What holds this is the tenant on the scoped transaction, which comes from the verified token and
/// from nowhere else (`CLAUDE.md` rule 3) — plus row-level security and
/// `crates/db/src/recent.rs`'s own predicates behind it. The handler contributes no tenant filter of
/// its own and this test does not claim otherwise; it asserts `T1`'s documented behaviour at the
/// surface a client actually calls.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_file_never_appears_for_an_alpha_caller() {
    let (_db, fixtures, alpha, beta, harness) = setup().await;

    open(&harness, fixtures.beta.id, fixtures.beta.member, beta.rooted).await;
    open(&harness, fixtures.alpha.id, fixtures.alpha.member, alpha.rooted).await;

    let (status, mine) = recent(&harness, fixtures.alpha.id, fixtures.alpha.member, None).await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(
        ids(&mine),
        vec![alpha.rooted.to_string()],
        "exactly alpha's file, and only it: {mine}"
    );
    assert_eq!(filtered(&mine), 0, "beta's row is not a withheld row, it is not a row at all");
    assert!(
        !mine.to_string().contains(&beta.rooted.to_string()),
        "beta's file id must not appear in alpha's page: {mine}"
    );

    // The mirror, so that "alpha cannot see beta's" is not passing because beta's open failed.
    let (status, theirs) = recent(&harness, fixtures.beta.id, fixtures.beta.member, None).await;
    assert_eq!(status, StatusCode::OK, "{theirs}");
    assert_eq!(ids(&theirs), vec![beta.rooted.to_string()], "beta's own row is there: {theirs}");
}

// ---------------------------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------------------------

/// `limit` is honoured below the cap and clamped above it.
///
/// Twelve files are opened, which is why the spine carries ten spares: a cap of eight cannot be
/// observed against a history with fewer than nine rows in it, and a test that opened eight and
/// asked for a hundred would pass against an endpoint with no cap at all.
///
/// The `limit=3` case is the positive control for the clamp. Without it, "a large `limit` returns
/// eight" passes against a handler that ignores the parameter entirely and always serves eight.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_limit_is_honoured_below_the_cap_and_clamped_above_it() {
    let (_db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    open(&harness, tenant, member, alpha.nested).await;
    open(&harness, tenant, member, alpha.rooted).await;
    for file in &alpha.bulk {
        open(&harness, tenant, member, *file).await;
    }

    let (status, small) = recent(&harness, tenant, member, Some(3)).await;
    assert_eq!(status, StatusCode::OK, "{small}");
    assert_eq!(ids(&small).len(), 3, "a smaller page is honoured rather than padded: {small}");

    let (status, capped) = recent(&harness, tenant, member, Some(500)).await;
    assert_eq!(status, StatusCode::OK, "{capped}");
    assert_eq!(ids(&capped).len(), CAP, "clamped to the cap rather than refused: {capped}");

    let (status, defaulted) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{defaulted}");
    assert_eq!(ids(&defaulted).len(), CAP, "the default is the cap: {defaulted}");

    // Nothing was withheld from any of the three: a page cut short because it was full is not a page
    // the chain filtered, and reporting it as one would tell this user documents were kept from
    // them.
    for page in [&small, &capped, &defaulted] {
        assert_eq!(filtered(page), 0, "a full page is not a filtered one: {page}");
    }

    // Only a value that is not a number is a client error.
    let (status, refused) = get(&harness, tenant, member, "/api/v1/me/recent?limit=eight").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused.to_string().contains("limit"), "the refusal names the field: {refused}");
}

/// The list is most-recently-opened first, even when the file ids say otherwise.
///
/// The two files are opened in the opposite order to their ids, and the recency read breaks a
/// timestamp tie by `file_id DESC` — so an implementation that ordered by id, or one that lost the
/// ordering while trimming or while resolving capabilities, produces exactly the reverse of what is
/// asserted here rather than something that happens to look similar.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_list_is_most_recent_first_even_when_the_ids_disagree() {
    let (_db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    assert!(
        alpha.nested.as_uuid() < alpha.rooted.as_uuid(),
        "the fixture's premise: the file opened second has the lower id"
    );

    open(&harness, tenant, member, alpha.rooted).await;
    open(&harness, tenant, member, alpha.nested).await;

    let (status, page) = recent(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        ids(&page),
        vec![alpha.nested.to_string(), alpha.rooted.to_string()],
        "the last one opened is first, and the ids would have said the opposite: {page}"
    );

    // And the instants agree with the order, so this cannot pass on an ordering the handler
    // imposed over rows whose timestamps say something else.
    let first = page["items"][0]["lastAccessedAt"].as_str().expect("an instant");
    let second = page["items"][1]["lastAccessedAt"].as_str().expect("an instant");
    assert!(first > second, "the rendered instants must be descending: {first} then {second}");
}
