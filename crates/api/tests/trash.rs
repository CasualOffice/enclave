//! `GET /api/v1/trash`, end to end, over a real PostgreSQL.
//!
//! # What is actually being proved
//!
//! That a document deleted through this product can be found again and brought back **without
//! anybody having written its UUID down first**. `ENC-807` shipped `DELETE /api/v1/files/{id}` and
//! `POST /api/v1/files/{id}/restore` and nothing that listed the trash, so the restore endpoint was
//! real and unreachable: `GET /libraries/{id}/items` filters trashed rows out, and the only other
//! reader of a trashed row resolves an id the caller already holds.
//!
//! [`deleting_a_file_puts_it_in_the_recycle_bin_and_the_listing_carries_what_the_restore_needs`] is
//! therefore written first and does it the long way round — delete over HTTP, list, restore using
//! **the revision this listing served** — because that revision is the whole reason the contract
//! carries one. `POST /restore` requires `If-Match`, and a trashed file answers `404` to the `GET`
//! a client would otherwise read its `ETag` from, so a listing without a revision would show a
//! caller a document they cannot restore. **Nothing in this file sets `deleted_at` by hand except
//! the one fixture that is explicitly attributed to another user**, and that one says so.
//!
//! # The routes under test are the shipped ones
//!
//! [`setup`] builds [`enclave_api::router`] and nothing beside it — there is no local `Router`, no
//! `merge`, and no registration in this file. A suite that mounted its own handler would prove the
//! handler works and say nothing about whether any request can reach it;
//! `crates/api/tests/reachability.rs` exists because this repository has shipped that shape a dozen
//! times. The single line in `crates/api/src/lib.rs` that registers `/api/v1/trash` is therefore
//! load-bearing for all five tests below: without it axum answers `404`, every `assert_eq!(status,
//! StatusCode::OK)` here fails, and that is the property that makes this a suite about an endpoint
//! rather than about a function.
//!
//! # Which layer each test proves, stated rather than assumed
//!
//! The application runs as `enclave_app` with forced row-level security; every assertion about what
//! is *stored* reads over the harness's superuser connection, so an assertion that a row was not
//! written cannot pass because the reader could not see it.
//!
//! * **Authorization.** [`a_deletion_this_caller_cannot_restore_is_dropped_and_counted`] is the
//!   security test. Both deletions are alpha's and the caller is alpha's own member, so RLS has
//!   nothing to say and only the `file.restore` batch in `routes::trash::admit` can tell the two
//!   rows apart. Delete that batch and the endpoint serves a listing of every deletion in the
//!   tenant — including documents in folders this caller has never been able to open — with a
//!   `200`.
//! * **The action, not merely the presence of one.** The same test is also what separates
//!   `file.restore` from `file.metadata_read`: the walled folder's ACL is broken for *every* action,
//!   so it would fail either way — which is why
//!   [`a_trashed_folder_appears_once_and_not_once_per_document_inside_it`] and the journey test
//!   assert the `capabilities.restore` key that the row is admitted by. A listing decided by
//!   metadata_read would show rows whose restore then refuses, and the journey test is what catches
//!   that: it uses the served row to make the very next request.
//! * **Isolation.** [`another_tenants_deletion_never_appears_for_an_alpha_caller`] is asserted
//!   because `T1` is documented behaviour, **not** because the handler isolates anything itself:
//!   what holds it is the tenant on the scoped transaction, which comes from the verified token and
//!   from nowhere else (`CLAUDE.md` rule 3), plus `crates/db/src/trash.rs`'s own predicate behind
//!   it. The mutation-sensitive half of that claim lives in `crates/db/tests/trash.rs`, which runs
//!   where RLS is inert; deleting the predicate cannot fail *this* test, and this comment says so
//!   rather than letting a reader assume otherwise. Both tenants delete a file with the same name,
//!   so it cannot pass because the other tenant's row was called something different.
//!
//! # Every absence is paired with its positive control
//!
//! "The row is not in the bin" passes for free against an endpoint that returns nothing, against a
//! delete that never happened, and against a route nobody registered. So every absence below is
//! asserted in the same run as the presence that makes it meaningful.

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
    Action, ClientType, ContainerAction, FileAction, FileId, LibraryId, PolicyEngine, TenantId,
    UserId, WorkspaceId,
};
use enclave_db::DbPool;
use enclave_testing::{Fixtures, TestDb};
use serde_json::Value;
use sqlx::{Connection as _, PgConnection};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The number of rows `GET /trash` will never exceed, whatever `limit` asks for.
///
/// Restated here rather than imported so that a change to `routes::trash::MAX_LIMIT` has to be made
/// twice — once in the code and once in a test that fails until somebody agrees with it.
const CAP: usize = 50;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's content spine, shaped by the three things this endpoint has to get right.
///
/// * `folder` holds `nested` — the cascade, so a trashed folder can be shown to be **one** row.
/// * `rooted` sits at the library root, so `parentFolderId: null` and the library-as-container case
///   are both exercised.
/// * `walled` has `inherit_permissions = FALSE` and no entries of its own, so the ACL walk stops
///   there and finds nothing. `sealed` is the document inside it: the deletion this caller must not
///   be offered a restore for.
#[derive(Debug, Clone)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    /// A live folder, with `nested` inside it.
    folder: FileId,
    /// Inside `folder`.
    nested: FileId,
    /// A second document inside `folder`, so the cascade is more than one row deep.
    nested_sibling: FileId,
    /// At the library root.
    rooted: FileId,
    /// A folder nobody inherits into.
    walled: FileId,
    /// Inside `walled`. Unreachable to every caller in this suite.
    sealed: FileId,
}

impl Spine {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            folder: FileId::new_v7(),
            nested: FileId::new_v7(),
            nested_sibling: FileId::new_v7(),
            rooted: FileId::new_v7(),
            walled: FileId::new_v7(),
            sealed: FileId::new_v7(),
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

        self.node(conn, self.folder, "FOLDER", "Reports", None, true, owner).await;
        self.node(conn, self.nested, "FILE", "Quarterly Plan.pdf", Some(self.folder), true, owner)
            .await;
        self.node(
            conn,
            self.nested_sibling,
            "FILE",
            "Appendix.pdf",
            Some(self.folder),
            true,
            owner,
        )
        .await;
        self.node(conn, self.rooted, "FILE", "fox.txt", None, true, owner).await;

        // The walled branch. `inherit_permissions = FALSE` with no `acl_entries` of its own is how
        // this suite builds a container the caller has no answer for — the resolver's walk stops at
        // the folder and finds nothing, which is what a revoked grant looks like from the endpoint's
        // side. `crates/api/tests/recent.rs::detach` builds the same shape for the same reason.
        self.node(conn, self.walled, "FOLDER", "Board", None, false, owner).await;
        self.node(conn, self.sealed, "FILE", "Board Minutes.pdf", Some(self.walled), true, owner)
            .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        node_type: &str,
        name: &str,
        parent: Option<FileId>,
        inherit: bool,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, status, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'AVAILABLE', $10, $11, $11, $12, $12)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(parent.map(|id| id.as_uuid()))
        .bind(node_type)
        .bind(name)
        .bind(name.to_lowercase())
        .bind(if node_type == "FOLDER" {
            "inode/directory"
        } else if name.ends_with(".pdf") {
            "application/pdf"
        } else {
            "text/plain"
        })
        .bind(inherit)
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

/// Moves a node to the trash **outside** the product, attributed to someone else.
///
/// Used once, by [`a_deletion_this_caller_cannot_restore_is_dropped_and_counted`], and only for the
/// document inside the walled folder — which by construction *no* caller in this suite can delete
/// over HTTP, because the same broken inheritance that makes its restore unanswerable makes its
/// `file.delete` unanswerable too. That is the fixture the test needs: a deletion made by another
/// user, in a place this caller cannot reach.
///
/// Every other deletion in this file goes through `DELETE /api/v1/files/{id}`.
async fn trash_outside_the_product(
    conn: &mut PgConnection,
    tenant: TenantId,
    node: FileId,
    by: UserId,
) {
    let changed = sqlx::query(
        "UPDATE files
            SET deleted_at = now(), purge_after = now() + interval '30 days',
                revision = revision + 1, modified_by = $3, modified_at = now()
          WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(node.as_uuid())
    .bind(by.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("trash a node as another user")
    .rows_affected();
    assert_eq!(changed, 1, "the fixture must have trashed exactly one node");
}

/// Every trashed node in one tenant, read over the connection nothing is filtered on.
///
/// An assertion that the endpoint *hid* a row must not be able to pass because the row was never
/// written.
async fn trashed(db: &TestDb, tenant: TenantId) -> Vec<Uuid> {
    let mut conn = db.connect().await.expect("connect");
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM files
          WHERE tenant_id = $1 AND deleted_at IS NOT NULL
          ORDER BY deleted_at DESC, id DESC",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read the trashed rows");
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

/// A migrated, seeded database, both spines written, and alpha's member and beta's member each
/// granted the four actions this suite needs on their own library.
///
/// `file.delete` and `file.restore` are the two the surface is about; `container.read` and
/// `file.metadata_read` are what let the tests read a file back to obtain its revision and to prove
/// a restore worked. The grants are on the **library**, so they reach `folder`, `nested` and
/// `rooted` by inheritance and stop dead at `walled`.
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

    for (spine, user) in [(&alpha, fixtures.alpha.member), (&beta, fixtures.beta.member)] {
        for action in [
            Action::Container(ContainerAction::Read),
            Action::File(FileAction::MetadataRead),
            Action::File(FileAction::Delete),
            Action::File(FileAction::Restore),
        ] {
            grant(&mut admin, spine.tenant, "LIBRARY", spine.library.as_uuid(), user, action).await;
        }
    }
    let _ignored = admin.close().await;

    // Eight connections on one pool, as `tests/recent.rs`: a request reads the bin in one
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
/// All three layers are load-bearing, and the middle one especially: `GET /trash` asks
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

/// One request, with a bearer token and an optional `If-Match`.
async fn send(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    method: &str,
    uri: &str,
    if_match: Option<i64>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)));
    if let Some(revision) = if_match {
        builder = builder.header("if-match", format!("\"{revision}\""));
    }
    let response = harness
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let body =
        if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
    (status, body)
}

async fn get(harness: &Harness, tenant: TenantId, user: UserId, uri: &str) -> (StatusCode, Value) {
    send(harness, tenant, user, "GET", uri, None).await
}

/// `GET /api/v1/trash`, with an optional `limit`.
async fn bin(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    limit: Option<u32>,
) -> (StatusCode, Value) {
    let uri =
        limit.map_or_else(|| "/api/v1/trash".to_owned(), |n| format!("/api/v1/trash?limit={n}"));
    get(harness, tenant, user, &uri).await
}

/// The revision a file currently carries, read the way a client would.
async fn revision(harness: &Harness, tenant: TenantId, user: UserId, file: FileId) -> i64 {
    let (status, body) = get(harness, tenant, user, &format!("/api/v1/files/{file}")).await;
    assert_eq!(status, StatusCode::OK, "the fixture must be able to read {file}: {body}");
    body["revision"].as_i64().expect("a revision")
}

/// Deletes a node the way a person does, and insists it worked.
///
/// Every trashed row in this suite except the walled one is written by this call. If
/// `routes::lifecycle::trash` stopped cascading, or stopped stamping `modified_by`, the assertions
/// below go red — which is the property that makes them tests of the feature rather than of a
/// renderer.
async fn delete(harness: &Harness, tenant: TenantId, user: UserId, file: FileId) -> Value {
    let expected = revision(harness, tenant, user, file).await;
    let (status, body) =
        send(harness, tenant, user, "DELETE", &format!("/api/v1/files/{file}"), Some(expected))
            .await;
    assert_eq!(status, StatusCode::OK, "the fixture must be able to delete {file}: {body}");
    body
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

fn row(page: &Value, file: FileId) -> &Value {
    page["items"]
        .as_array()
        .expect("an items array")
        .iter()
        .find(|item| item["fileId"] == file.to_string())
        .unwrap_or_else(|| panic!("{file} must be in the recycle bin: {page}"))
}

// ---------------------------------------------------------------------------------------------
// The journey this whole item exists for
// ---------------------------------------------------------------------------------------------

/// A user deletes a document, finds it in the recycle bin, and restores it with the revision the
/// listing served.
///
/// **The test this item exists for.** Before it, a file deleted through the product left every
/// listing in it and `POST /files/{id}/restore` could be reached only by a caller who had recorded
/// the UUID beforehand — a restore endpoint that was real and unreachable.
///
/// The empty bin before the delete is the positive control for the populated one after it, and it
/// has to be in the same run: on its own, "the file is in the bin" passes against an endpoint that
/// lists every file in the tenant, and "the bin is empty" passes against a route that returns
/// nothing at all. The pair can only both hold if the `DELETE` in between did something.
///
/// mapping is what a client codes against and a single wrong field — `libraryId` where
/// `parentFolderId` was meant — is invisible in a test that only counts rows.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn deleting_a_file_puts_it_in_the_recycle_bin_and_the_listing_carries_what_the_restore_needs()
{
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    let (status, before) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "the endpoint must answer: {before}");
    assert!(ids(&before).is_empty(), "nothing has been deleted yet: {before}");
    assert_eq!(filtered(&before), 0, "and nothing was withheld either: {before}");
    assert!(trashed(&db, tenant).await.is_empty(), "no row can be in the trash before the delete");

    delete(&harness, tenant, member, alpha.nested).await;

    let (status, after) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(ids(&after), vec![alpha.nested.to_string()], "the file just deleted: {after}");
    assert_eq!(filtered(&after), 0, "nothing was withheld: {after}");
    assert_eq!(
        trashed(&db, tenant).await,
        vec![alpha.nested.as_uuid()],
        "the delete moved exactly one row, and the endpoint is reading it"
    );

    let item = &after["items"][0];
    assert_eq!(item["name"], "Quarterly Plan.pdf");
    assert_eq!(item["nodeType"], "FILE");
    assert_eq!(item["mimeType"], "application/pdf");
    assert_eq!(item["libraryId"], alpha.library.to_string());
    assert_eq!(
        item["parentFolderId"],
        alpha.folder.to_string(),
        "the folder it will return into, which is also the container its restore is decided against"
    );
    assert_eq!(
        item["deletedBy"]["id"],
        member.to_string(),
        "`deletedBy` is files.modified_by, which the trash write stamps"
    );
    assert_eq!(item["deletedBy"]["displayName"], "member");
    assert!(
        item["deletedAt"].as_str().expect("an instant").ends_with('Z'),
        "RFC3339, in UTC: {item}"
    );
    assert!(
        item["purgeAfter"].as_str().expect("a retention instant").ends_with('Z'),
        "how long is left is on the wire: {item}"
    );

    // The twelve-key object `GET /files/{id}` returns, from the one function that builds it. The
    // count is asserted rather than a sample of the keys, because the failure this catches is a
    // second copy of the object drifting from the first (`ENC-929`).
    let capabilities = item["capabilities"].as_object().expect("a capabilities object");
    assert_eq!(capabilities.len(), 12, "the shape must be the file endpoint's: {item}");
    assert_eq!(
        capabilities["restore"], true,
        "the one key a trash row is rendered from must be true — it is the answer the row was \
         admitted by, and the next request is about to prove it"
    );

    // The restore, driven by the revision this listing served and by nothing else.
    let served = item["revision"].as_i64().expect("a revision");
    let (status, restored) = send(
        &harness,
        tenant,
        member,
        "POST",
        &format!("/api/v1/files/{}/restore", alpha.nested),
        Some(served),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the revision the recycle bin served must be the one `If-Match` accepts; a 409 here means \
         the listing carried the pre-delete number and no client could restore anything: {restored}"
    );

    let (status, emptied) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{emptied}");
    assert!(ids(&emptied).is_empty(), "a restored file leaves the bin: {emptied}");
    assert_eq!(filtered(&emptied), 0, "and it was not withheld, it was returned: {emptied}");
    assert!(trashed(&db, tenant).await.is_empty(), "and nothing is left in the trash");

    let (status, _body) =
        get(&harness, tenant, member, &format!("/api/v1/files/{}", alpha.nested)).await;
    assert_eq!(status, StatusCode::OK, "the document is readable again, which is the point");
}

// ---------------------------------------------------------------------------------------------
// One row per restore
// ---------------------------------------------------------------------------------------------

/// A trashed folder is one entry in the bin, not one per document inside it.
///
/// `DELETE /files/{id}` cascades and `POST /files/{id}/restore` brings back exactly the subtree that
/// shares the instant. So a bin listing every trashed row would show a folder and its two documents
/// as three entries, and a restore on either child would silently restore the other two — a partial
/// restore of somebody's folder that they were never told about.
///
/// The count read over the superuser connection is the control that makes this an assertion about
/// the *listing*: three rows really are in the trash, and the endpoint is hiding two of them on
/// purpose. The file deleted separately at the library root is the second control, in the same run:
/// without it, "the bin holds one row" is equally true of an endpoint that serves the first row it
/// finds.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_folder_appears_once_and_not_once_per_document_inside_it() {
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    let deleted = delete(&harness, tenant, member, alpha.folder).await;
    assert_eq!(
        deleted["affected"], 3,
        "the fixture's premise: the cascade moved the folder and both documents: {deleted}"
    );
    delete(&harness, tenant, member, alpha.rooted).await;

    assert_eq!(
        trashed(&db, tenant).await.len(),
        4,
        "four rows are in the trash — if they are not, the assertion below is about a bin that was \
         always this size"
    );

    let (status, page) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        ids(&page),
        vec![alpha.rooted.to_string(), alpha.folder.to_string()],
        "the bin holds the two nodes somebody actually deleted, most recent first: {page}"
    );
    assert_eq!(filtered(&page), 0, "the hidden children are not withheld rows, they are not rows");

    let folder = row(&page, alpha.folder);
    assert_eq!(
        folder["nodeType"], "FOLDER",
        "a folder must be reported as one: its restore cascades and the confirmation has to say so"
    );
    assert_eq!(folder["parentFolderId"], Value::Null, "this folder sat at the library root");
    assert_eq!(folder["capabilities"]["restore"], true);

    let rendered = page.to_string();
    for child in [alpha.nested, alpha.nested_sibling] {
        assert!(
            !rendered.contains(&child.to_string()),
            "a document inside a trashed folder is not its own restore: {rendered}"
        );
    }

    // And restoring the folder brings its documents with it, which is why they were not offered
    // separately.
    let served = folder["revision"].as_i64().expect("a revision");
    let (status, restored) = send(
        &harness,
        tenant,
        member,
        "POST",
        &format!("/api/v1/files/{}/restore", alpha.folder),
        Some(served),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert_eq!(restored["affected"], 3, "the whole subtree came back together: {restored}");
}

// ---------------------------------------------------------------------------------------------
// Authorization — a row this caller cannot restore
// ---------------------------------------------------------------------------------------------

/// A deletion this caller cannot restore is dropped from the bin and counted, never refused.
///
/// The security test. Both deletions are alpha's and the caller is alpha's own member, so row-level
/// security has nothing to say; only the `file.restore` batch in `routes::trash::admit` can tell
/// them apart. The read model is tenant-wide by design, so without that batch this endpoint serves
/// every deletion in the tenant — including documents from folders this caller has never been able
/// to open — with a `200`.
///
/// The document the caller *did* delete is the positive control, and it is what makes the count
/// meaningful: `filteredCount: 1` beside an empty list would also be produced by an endpoint that
/// refuses everything.
///
/// The status is `200` and not `403` or `404` (`CLAUDE.md` rule 7). The caller learns how many rows
/// they cannot restore; nothing in the response says which, and neither the name nor the id of the
/// withheld document appears anywhere in the body.
///
/// The final assertion is what ties the drop to the policy chain rather than to this endpoint's own
/// arithmetic: `POST /restore` on the withheld id answers `404` for the same caller, which is the
/// same answer the same question gives one layer down.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_deletion_this_caller_cannot_restore_is_dropped_and_counted() {
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    // The caller's own deletion, through the product.
    delete(&harness, tenant, member, alpha.rooted).await;

    // Somebody else's, inside a folder this caller cannot reach. It has to be written outside the
    // product because the broken inheritance that makes its restore unanswerable makes its
    // `file.delete` unanswerable too — which is precisely the situation being tested.
    let mut admin = db.connect().await.expect("connect");
    trash_outside_the_product(&mut admin, tenant, alpha.sealed, fixtures.alpha.owner).await;
    let _ignored = admin.close().await;

    assert_eq!(
        trashed(&db, tenant).await.len(),
        2,
        "both deletions are in the trash; only the answer to `may I restore it` differs"
    );

    let (status, page) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "a dropped row is never a refusal (rule 7): {page}");
    assert_eq!(ids(&page), vec![alpha.rooted.to_string()], "the positive control survives: {page}");
    assert_eq!(filtered(&page), 1, "and the one that did not is counted: {page}");

    let rendered = page.to_string();
    assert!(
        !rendered.contains("Board Minutes"),
        "the name of a document the caller may not restore must not appear: {rendered}"
    );
    assert!(
        !rendered.contains(&alpha.sealed.to_string()),
        "nor its id — the count says how many, never which: {rendered}"
    );
    assert!(
        !rendered.contains(&alpha.walled.to_string()),
        "nor the folder it sits in, which would say where: {rendered}"
    );

    // The restore agrees about the same node, which is what says the drop was the policy chain's
    // answer and not this endpoint's own arithmetic.
    let (status, refused) = send(
        &harness,
        tenant,
        member,
        "POST",
        &format!("/api/v1/files/{}/restore", alpha.sealed),
        Some(2),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the row was withheld because the restore itself is refused: {refused}"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation
// ---------------------------------------------------------------------------------------------

/// A deletion in another tenant never appears for an alpha caller.
///
/// Both tenants delete a file called `fox.txt`, through the product, by their own member — so this
/// cannot pass because the other tenant's row was named differently or because beta was empty. The
/// alpha caller's own deletion is the positive control in the same run, and beta's own bin is
/// asserted afterwards so that "alpha cannot see beta's" is not passing because beta's delete
/// failed.
///
/// What holds this is the tenant on the scoped transaction, which comes from the verified token and
/// from nowhere else (`CLAUDE.md` rule 3) — plus row-level security and `crates/db/src/trash.rs`'s
/// own predicate behind it. **Deleting that predicate cannot fail this test**, because the
/// application connects as `enclave_app` with RLS forced; the half of the claim that is sensitive to
/// the mutation is `crates/db/tests/trash.rs`, which runs where RLS is inert. Said here rather than
/// left for a reader to assume, because assuming it is `ENC-124`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_deletion_never_appears_for_an_alpha_caller() {
    let (_db, fixtures, alpha, beta, harness) = setup().await;

    delete(&harness, fixtures.beta.id, fixtures.beta.member, beta.rooted).await;
    delete(&harness, fixtures.alpha.id, fixtures.alpha.member, alpha.rooted).await;

    let (status, mine) = bin(&harness, fixtures.alpha.id, fixtures.alpha.member, None).await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(
        ids(&mine),
        vec![alpha.rooted.to_string()],
        "exactly alpha's deletion, and only it: {mine}"
    );
    assert_eq!(filtered(&mine), 0, "beta's row is not a withheld row, it is not a row at all");
    assert!(
        !mine.to_string().contains(&beta.rooted.to_string()),
        "beta's file id must not appear in alpha's bin: {mine}"
    );

    let (status, theirs) = bin(&harness, fixtures.beta.id, fixtures.beta.member, None).await;
    assert_eq!(status, StatusCode::OK, "{theirs}");
    assert_eq!(ids(&theirs), vec![beta.rooted.to_string()], "beta's own row is there: {theirs}");
}

// ---------------------------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------------------------

/// A live file never appears in the recycle bin, and `limit` is honoured and clamped.
///
/// The two claims share a fixture because they share a premise: the tenant holds six live nodes and
/// exactly one deletion, so "the bin holds one row" is simultaneously the strongest statement that
/// the five live ones are absent and the positive control for the clamping below. An endpoint that
/// leaked live rows would fail the first assertion; one that ignored `limit` would fail the second.
///
/// Only a `limit` that is not a number is a client error — an appetite larger than the cap is
/// clamped, because refusing it teaches a client nothing the answer could not have told it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_live_file_never_appears_and_a_limit_is_honoured_and_clamped() {
    let (db, fixtures, alpha, _beta, harness) = setup().await;
    let tenant = fixtures.alpha.id;
    let member = fixtures.alpha.member;

    delete(&harness, tenant, member, alpha.rooted).await;
    assert_eq!(trashed(&db, tenant).await.len(), 1, "one deletion, five live nodes beside it");

    let (status, page) = bin(&harness, tenant, member, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        ids(&page),
        vec![alpha.rooted.to_string()],
        "the recycle bin is the trash, not the library: the folder, its two documents, the walled \
         folder and the document inside it are all live and none of them is a deletion anybody can \
         undo: {page}"
    );

    let (status, capped) = bin(&harness, tenant, member, Some(5_000)).await;
    assert_eq!(status, StatusCode::OK, "{capped}");
    assert!(ids(&capped).len() <= CAP, "clamped to the cap rather than refused: {capped}");

    let (status, small) = bin(&harness, tenant, member, Some(1)).await;
    assert_eq!(status, StatusCode::OK, "{small}");
    assert_eq!(ids(&small).len(), 1, "a smaller page is honoured rather than padded: {small}");

    let (status, refused) = get(&harness, tenant, member, "/api/v1/trash?limit=fifty").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused.to_string().contains("limit"), "the refusal names the field: {refused}");
}
