//! ENC-133 — the content read paths, end to end, over a real PostgreSQL.
//!
//! # Why these run against a database and a real token
//!
//! The unit tests in `crates/api/src/content.rs` prove the *shape*: that a page carries no total,
//! that an `ACCESS_DENIED` becomes a `404`, that an obligation only ever subtracts a capability.
//! None of that is the property the endpoints exist to hold. That property is **a listing must not
//! become a way to enumerate what you cannot read**, and it is a claim about what the ACL resolver,
//! row-level security and the trim do together, under the `enclave_app` role, with the tenant
//! context the token established.
//!
//! So every request below is a real HTTP request through the real router, carrying a real signed
//! token, against a freshly migrated database, resolved by the real `PgAclAuthorization`. The
//! fixtures are written over the harness's superuser connection because they are setup; every read
//! under test goes through [`TestDb::pool`], which `SET ROLE enclave_app`s. That distinction is the
//! whole lesson of PR #22: the policies had been correct for months and nothing had ever executed
//! as the application role, so nothing had ever proved it.
//!
//! # What is asserted beyond the status code
//!
//! Every test also reads `audit_events`. A read path that answers correctly and leaves no audit row
//! has failed `CLAUDE.md` rule 10 just as surely as one that answers wrongly, and a denial that
//! leaves no row is worse — the one event an investigator needs is the one that was refused. The
//! counts here are exact, not lower bounds: a handler that quietly audited its capability probes as
//! nine speculative allows would fill the log with actions nobody attempted, and an exact count is
//! what catches that.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, Actor, AuthorizationService as _, ClientType, FileAction, FileId, LibraryId,
    PolicyEngine, RequestContext, ResourceRef, TenantId, UserId, VersionId, WorkspaceId,
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

/// One tenant's content spine: a workspace, a library, and four children of the library root.
///
/// `hidden` is the point of the fixture. It is an ordinary file in the same folder as the others,
/// with `inherit_permissions = FALSE` and no ACL entry of its own, so the grant on the library —
/// which reaches every sibling — stops at it. Everything these tests claim about enumeration is a
/// claim about whether `hidden` can be observed, and there is no way to observe it that is not also
/// a way to observe a file someone was actually meant to be denied.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    /// A folder at the library root, granted.
    folder: FileId,
    /// A file at the library root, granted.
    visible: FileId,
    /// A second granted file, so a page of one has somewhere to go next.
    also_visible: FileId,
    /// Inheritance broken, no entries. Invisible to the granted user by construction.
    hidden: FileId,
}

impl Spine {
    /// Builds the ids in listing order.
    ///
    /// `files` is ordered by `id`, which is a UUIDv7 and therefore creation order, so generating
    /// them in this sequence makes the expected page order deterministic rather than incidental.
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            folder: FileId::new_v7(),
            visible: FileId::new_v7(),
            also_visible: FileId::new_v7(),
            hidden: FileId::new_v7(),
        }
    }

    /// Every child of the library root that the granted user is meant to see.
    fn readable(&self) -> [FileId; 3] {
        [self.folder, self.visible, self.also_visible]
    }

    /// Writes the containers and the nodes. Columns are spelled as `docs/04-DATA-MODEL.md §7`/`§8`
    /// defines them, so a migration that drifts from the document fails here rather than later.
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

        self.insert_node(conn, self.folder, "FOLDER", "Reports", true, owner).await;
        self.insert_node(conn, self.visible, "FILE", "Quarterly Plan.pdf", true, owner).await;
        self.insert_node(conn, self.also_visible, "FILE", "Team Handbook.pdf", true, owner).await;
        // The same *names* in both tenants would be the stronger fixture, and `enclave-testing`
        // already mirrors alpha and beta that way. Here the name has to be distinctive instead,
        // because several assertions below are "this string does not appear in the response" and a
        // name shared with a readable sibling would make them pass for the wrong reason.
        self.insert_node(conn, self.hidden, "FILE", "Redundancy List Q3.xlsx", false, owner).await;
    }

    async fn insert_node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        node_type: &str,
        name: &str,
        inherit: bool,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, status, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, 'application/pdf', 'AVAILABLE', $8, $9, $9,
                     $10, $10)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(node_type)
        .bind(name)
        .bind(name.to_lowercase())
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
/// The action is spelled with `Action`'s own `Display` — `container.read`, `file.metadata_read` —
/// which is also the form audit rows carry. An ACL and an audit trail that name the same action the
/// same way is what makes a denial explicable after the fact.
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

/// Writes one version row for a file.
async fn insert_version(
    conn: &mut PgConnection,
    spine: &Spine,
    file: FileId,
    id: VersionId,
    major: i32,
    minor: i32,
    status: &str,
    av_status: &str,
    owner: UserId,
) {
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, encryption_mode, created_by, created_at,
            comment)
         VALUES ($1, $2, $3, $4, $5, 1024, $6, 'application/pdf', $7, $8, $9, $10, 'PROVIDER', $11,
                 $12, 'a comment')",
    )
    .bind(id.as_uuid())
    .bind(spine.tenant.as_uuid())
    .bind(file.as_uuid())
    // The value every "does the object key reach the wire" assertion below searches for.
    .bind(format!("tenants/{}/blobs/{}", spine.tenant.as_uuid(), id.as_uuid()))
    .bind(Uuid::new_v4())
    .bind("0".repeat(64))
    .bind(major)
    .bind(minor)
    .bind(status)
    .bind(av_status)
    .bind(owner.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert version");
}

/// Points `files.current_version_id` at a version.
async fn set_current_version(conn: &mut PgConnection, file: FileId, version: VersionId) {
    sqlx::query("UPDATE files SET current_version_id = $2 WHERE id = $1")
        .bind(file.as_uuid())
        .bind(version.as_uuid())
        .execute(&mut *conn)
        .await
        .expect("point at current version");
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// The app, the signing key, and the authorization service the engine will actually consult.
///
/// The service is returned so that a test can ask it the same question the response claims to
/// answer. That is the only way to assert the promise `docs/05-API.md §7` makes about
/// `capabilities` — "computed by the same policy engine that will enforce the action" — rather than
/// asserting that the handler's own arithmetic is self-consistent.
struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
    authz: Arc<PgAclAuthorization>,
}

/// A preview pipeline that renders whatever it is handed.
///
/// It exists so that a served preview is a **`200` carrying bytes** rather than merely "not a
/// `404`". `UnconfiguredPipeline` answers `503` for a readable version and `404` for an unreadable
/// one, so an agreement test written against not-404 does pass with it — and it passes while
/// nothing has ever rendered, which makes the interesting half of the assertion untested. Checked
/// rather than assumed: composing the unconfigured pipeline here was tried, and the version of this
/// test that only distinguished `404` from everything else went green against it.
///
/// Nothing here decides readability. The pipeline is only reached through
/// `enclave_preview::ReadableVersion`, whose one constructor applies the predicate — so a stub that
/// renders everything still cannot render an unscanned version, and rule 9 is what this test
/// observes rather than something it has to arrange.
#[derive(Debug)]
struct AlwaysRenders;

#[async_trait::async_trait]
impl enclave_preview::PreviewPipeline for AlwaysRenders {
    async fn deliver(
        &self,
        _conn: &mut sqlx::PgConnection,
        _tenant: TenantId,
        _version: &enclave_preview::ReadableVersion,
        _profile: enclave_preview::RenditionProfile,
        _now: DateTime<Utc>,
    ) -> enclave_preview::Result<enclave_preview::Delivery> {
        let canvas = image::RgbaImage::from_pixel(64, 64, image::Rgba([255, 255, 255, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(canvas)
            .write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encode the stub rendition");
        Ok(enclave_preview::Delivery::Available {
            bytes,
            media_type: "image/png".to_owned(),
            page_count: Some(1),
        })
    }
}

async fn harness(db: &TestDb) -> Harness {
    build(db, enclave_api::Delivery::unconfigured()).await
}

/// The same app with a pipeline that can actually answer, for the tests that compare this module's
/// answers against a delivery route's.
///
/// The blob store stays unconfigured: the preview handler never touches one — the pipeline holds
/// it — so composing a real store here would add a dependency the path under test does not have.
async fn harness_that_renders(db: &TestDb) -> Harness {
    build(
        db,
        enclave_api::Delivery {
            store: Arc::new(enclave_storage::UnconfiguredBlobStore),
            preview: Arc::new(AlwaysRenders),
        },
    )
    .await
}

async fn build(db: &TestDb, delivery: enclave_api::Delivery) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // Three pools rather than one. Each is deliberately tiny (`TestDb::pool` caps at two, so that
    // the contention tests stay meaningful), and a request that resolves an ACL while holding an
    // audit connection would otherwise be competing with itself for the last one.
    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");

    let authz = Arc::new(PgAclAuthorization::new(authz_pool));

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        // The real resolver, not `SelfServiceAuthorization`: these endpoints are the first ones
        // whose answers are ACL answers, and a test composed with the placeholder would assert
        // nothing about inheritance, broken inheritance or the trim.
        Arc::clone(&authz) as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, state_pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    Harness { app: router(state, delivery), key, authz }
}

/// Issues one `GET` and returns only the status.
///
/// Separate from [`get`] because a preview answers PNG bytes, and parsing those as JSON panics —
/// which would report a *successful* render as a test harness failure.
/// The status **and** what came back with it.
///
/// `status_of` on its own cannot tell a `200` that rendered from a `200` that did not, and
/// `docs/12 §1.2` has this project's own history of exactly that: an agreement test that never
/// looked at a body passed while nothing had been rendered at all.
async fn fetch(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    uri: &str,
) -> (StatusCode, Option<String>, Vec<u8>) {
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
    let media_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read the body")
        .to_vec();
    (status, media_type, bytes)
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
    sqlx::query_as("SELECT action, outcome, resource_id FROM audit_events WHERE tenant_id = $1 ORDER BY sequence")
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

/// A database with both tenants seeded, both spines written, and alpha's member granted the two
/// read actions on alpha's library.
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
    for action in [
        Action::Container(enclave_core::ContainerAction::Read),
        Action::File(FileAction::MetadataRead),
        Action::File(FileAction::VersionRead),
    ] {
        grant(&mut admin, alpha.tenant, "LIBRARY", alpha.library.as_uuid(), user, action).await;
    }
    let _ignored = admin.close().await;

    (db, fixtures, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// Browse
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listing_returns_only_the_children_the_caller_may_read() {
    // The central claim. `hidden` sits in the same folder, was created by the same owner, and
    // differs from its siblings only in that the library's grant does not reach it. If the trim is
    // removed, this test fails on the count *and* on the name — the two ways an enumeration oracle
    // shows up, one as a number and one as a string.
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items", alpha.library),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let returned = ids(&body);
    let mut expected: Vec<String> =
        alpha.readable().iter().map(std::string::ToString::to_string).collect();
    expected.sort();
    let mut sorted = returned.clone();
    sorted.sort();
    assert_eq!(sorted, expected, "the listing must be exactly the granted children");

    let text = serde_json::to_string(&body).expect("render");
    assert!(!text.contains(&alpha.hidden.to_string()), "the hidden id reached the caller: {text}");
    assert!(!text.contains("Redundancy List"), "the hidden name reached the caller: {text}");

    // The trim is invisible: nothing says four rows were read and one was dropped.
    assert_eq!(body["page"]["hasMore"], false);
    assert_eq!(body["page"]["limit"], 50, "docs/05-API.md §6 fixes the default at 50");
    let page = body["page"].as_object().expect("page");
    for leak in ["total", "totalCount", "count", "trimmed", "filtered"] {
        assert!(!page.contains_key(leak), "{leak} would say how much the caller cannot see");
    }

    // One request, one decision, one row — and *not* one row per child. The trim runs through the
    // authorization stage directly, which decides without auditing; auditing it would record three
    // reads the caller never asked for.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "container.read");
    assert_eq!(rows[0].1, "ALLOW");
    assert_eq!(rows[0].2, Some(alpha.library.as_uuid()));
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn paging_with_a_cursor_visits_every_readable_child_exactly_once() {
    // `limit=1` forces the interesting case: the page whose single row is the trimmed one comes
    // back empty with `hasMore: true`. A client that stopped at the first short page would miss
    // every child after `hidden`, and a cursor built from the last *surviving* row rather than the
    // last row read would skip them permanently. Both bugs fail here.
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let mut seen: Vec<String> = Vec::new();
    let mut pages = 0;
    let mut uri = format!("/api/v1/libraries/{}/items?limit=1", alpha.library);

    loop {
        let (status, body) = get(&harness, fixtures.alpha.id, fixtures.alpha.member, &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["page"]["limit"], 1);
        seen.extend(ids(&body));
        pages += 1;
        assert!(pages < 20, "paging did not terminate");

        match body["page"]["nextCursor"].as_str() {
            Some(cursor) => {
                uri = format!(
                    "/api/v1/libraries/{}/items?limit=1&cursor={}",
                    alpha.library,
                    urlencoding(cursor)
                );
            }
            None => {
                assert_eq!(body["page"]["hasMore"], false, "no cursor but more to come");
                break;
            }
        }
    }

    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), seen.len(), "a row was returned twice: {seen:?}");

    let mut expected: Vec<String> =
        alpha.readable().iter().map(std::string::ToString::to_string).collect();
    expected.sort();
    assert_eq!(sorted, expected);
    assert!(
        pages >= 4,
        "the trimmed row must still consume a page — otherwise the cursor skipped it, {pages}"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_oversized_limit_is_clamped_rather_than_refused() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items?limit=100000", alpha.library),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "a greedy client gets a full page, not a 400");
    assert_eq!(body["page"]["limit"], 500, "docs/05-API.md §6 fixes the maximum at 500");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_cursor_from_another_tenant_is_refused_without_saying_why() {
    // `docs/12-TESTING.md` T3. Beta's user pages their own library, then alpha's user presents that
    // cursor against alpha's. The cursor decodes to a position, but it is bound to beta's tenant and
    // to beta's filter set, and `Cursor::decode` is the only way to get the position back out.
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let mut admin = db.connect().await.expect("admin connection");
    for action in [
        Action::Container(enclave_core::ContainerAction::Read),
        Action::File(FileAction::MetadataRead),
    ] {
        grant(
            &mut admin,
            beta.tenant,
            "LIBRARY",
            beta.library.as_uuid(),
            fixtures.beta.member,
            action,
        )
        .await;
    }
    let _ignored = admin.close().await;

    let (status, body) = get(
        &harness,
        fixtures.beta.id,
        fixtures.beta.member,
        &format!("/api/v1/libraries/{}/items?limit=1", beta.library),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cursor = body["page"]["nextCursor"].as_str().expect("a next cursor").to_owned();

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!(
            "/api/v1/libraries/{}/items?limit=1&cursor={}",
            alpha.library,
            urlencoding(&cursor)
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"][0]["field"], "cursor");
    // The envelope names the field and nothing else. Which check failed — wrong tenant, wrong
    // filter, wrong length — stays inside `Cursor::decode`, because a cursor that reported *why* it
    // was rejected is an oracle.
    let text = serde_json::to_string(&body).expect("render");
    for leak in ["tenant", "filter", "beta"] {
        assert!(!text.to_lowercase().contains(leak), "{leak} leaked: {text}");
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn browsing_into_a_folder_that_belongs_to_another_library_is_not_found() {
    // `libraryId` in the path and `parentId` in the query must describe the same container. If they
    // are allowed to disagree, the path segment becomes decoration and the real container arrives
    // in a query parameter — which is how an authorization check ends up being made about one thing
    // and a listing produced from another.
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (status, _body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items?parentId={}", beta.library, alpha.folder),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Cross-tenant — docs/12-TESTING.md T1
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_file_is_indistinguishable_from_one_that_never_existed() {
    // T1, stated as strictly as it can be: not merely "both are 404", but "the two responses differ
    // in nothing except the request id". A status code is the coarsest channel; a message, a
    // remediation or a `details` entry that differed would be just as good an oracle.
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (cross_status, cross_body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}", beta.visible),
    )
    .await;
    let (absent_status, absent_body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}", FileId::new_v7()),
    )
    .await;
    // The third case: a file that does exist in the caller's own tenant, in a library they can
    // read, whose inheritance is broken. It must be indistinguishable from both of the above.
    let (ungranted_status, ungranted_body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}", alpha.hidden),
    )
    .await;

    assert_eq!(cross_status, StatusCode::NOT_FOUND, "never 403 — a 403 confirms existence");
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(ungranted_status, StatusCode::NOT_FOUND);

    let strip = |mut body: serde_json::Value| {
        body["error"]["requestId"] = serde_json::Value::Null;
        body
    };
    assert_eq!(strip(cross_body.clone()), strip(absent_body));
    assert_eq!(strip(cross_body.clone()), strip(ungranted_body));

    let text = serde_json::to_string(&cross_body).expect("render");
    assert!(!text.contains(&beta.visible.to_string()));
    assert!(!text.contains("Quarterly Plan"));

    // Every refusal is audited, with the real reason, where an investigator can see it and the
    // caller cannot. Three requests, three denials.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows
        .iter()
        .all(|(action, outcome, _)| action == "file.metadata_read" && outcome == "DENY"));
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_library_cannot_be_browsed_or_distinguished_from_an_absent_one() {
    let (db, fixtures, _alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (cross_status, cross_body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items", beta.library),
    )
    .await;
    let (absent_status, absent_body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items", LibraryId::new_v7()),
    )
    .await;

    assert_eq!(cross_status, StatusCode::NOT_FOUND);
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(cross_body["error"]["code"], absent_body["error"]["code"]);
    assert_eq!(cross_body["error"]["message"], absent_body["error"]["message"]);

    // Beta's own rows are untouched by alpha's attempt: the denial is recorded against the tenant
    // that made the request, never against the one that owns the id.
    assert!(audit_rows(&db, fixtures.beta.id).await.is_empty());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unparseable_id_answers_exactly_as_an_unknown_one_does() {
    // A `400` here would be a distinction: "that is not a UUID" versus "that is a UUID I will not
    // discuss" is one bit, and one bit is how enumeration starts.
    let (db, fixtures, _alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (garbage, _) =
        get(&harness, fixtures.alpha.id, fixtures.alpha.member, "/api/v1/files/not-a-uuid").await;
    assert_eq!(garbage, StatusCode::NOT_FOUND);

    let (garbage_library, _) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        "/api/v1/libraries/not-a-uuid/items",
    )
    .await;
    assert_eq!(garbage_library, StatusCode::NOT_FOUND);

    // Nothing reached the chain, so nothing was audited: there was no resource to attribute an
    // event to.
    assert!(audit_rows(&db, fixtures.alpha.id).await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// File metadata and capabilities
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn capabilities_are_the_answers_the_engine_itself_would_give() {
    // `docs/05-API.md §7`: capabilities are "computed by the same policy engine that will enforce
    // the action — a UI hint derived from the real decision, not a parallel implementation". This
    // asserts that as an equality: for every action in the object, what the response says and what
    // the engine's own authorization stage says are the same boolean. A second resolver alongside
    // the engine would pass on the day it was written and fail here the first time the two drifted.
    let (db, fixtures, alpha, _beta) = setup().await;

    // Preview is granted directly on the file; download deliberately is not. `CLAUDE.md` rule 6:
    // these are two different exposures and a capabilities object that cannot say
    // "preview yes, download no" is the wrong shape.
    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        alpha.tenant,
        "FILE",
        alpha.visible.as_uuid(),
        fixtures.alpha.member,
        Action::File(FileAction::Preview),
    )
    .await;
    let version = VersionId::new_v7();
    insert_version(
        &mut admin,
        &alpha,
        alpha.visible,
        version,
        3,
        0,
        "AVAILABLE",
        "CLEAN",
        fixtures.alpha.owner,
    )
    .await;
    set_current_version(&mut admin, alpha.visible, version).await;
    let _ignored = admin.close().await;

    let harness = harness(&db).await;
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}", alpha.visible),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], alpha.visible.to_string());
    assert_eq!(body["name"], "Quarterly Plan.pdf");
    assert_eq!(body["currentVersion"]["id"], version.to_string());
    assert_eq!(body["currentVersion"]["major"], 3);
    assert_eq!(body["capabilities"]["metadataRead"], true);
    assert_eq!(body["capabilities"]["preview"], true);
    assert_eq!(body["capabilities"]["download"], false, "preview must not imply download");

    // Now the equality that matters. Same context, same resource, same service instance the router
    // holds — asked directly rather than through HTTP.
    let ctx = ctx(fixtures.alpha.id, fixtures.alpha.member);
    let resource = ResourceRef::file(fixtures.alpha.id, alpha.visible);
    for (name, action) in [
        ("preview", FileAction::Preview),
        ("download", FileAction::Download),
        ("print", FileAction::Print),
        ("export", FileAction::Export),
        ("edit", FileAction::Edit),
        ("share", FileAction::Share),
        ("shareExternal", FileAction::ShareExternal),
        ("delete", FileAction::Delete),
        ("sync", FileAction::Sync),
    ] {
        let decisions = harness
            .authz
            .authorize_many(&ctx, Action::File(action), core::slice::from_ref(&resource))
            .await
            .expect("resolve");
        let engine_says = decisions.first().is_some_and(enclave_core::StageDecision::is_allowed);
        assert_eq!(
            body["capabilities"][name],
            serde_json::Value::Bool(engine_says),
            "the UI and the server disagree about {name}"
        );
    }

    // Nine capability probes and one metadata read. Exactly one audit row: a probe is a hint, not
    // an action, and recording nine speculative allows would make the audit log describe things
    // nobody did.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "file.metadata_read");
    assert_eq!(rows[0].1, "ALLOW");
}

/// Grants alpha's member a different set of file actions on each of the two visible files.
///
/// The point of the fixture is the *difference*. A listing whose rows all carry the same
/// capabilities object passes whether the batch resolves per row or resolves once and copies the
/// answer everywhere, so the only fixture that proves anything gives three rows three answers:
/// `visible` may be previewed, `also_visible` may be edited and deleted, and `folder` inherits
/// neither.
async fn grant_divergent_file_actions(db: &TestDb, fixtures: &Fixtures, alpha: &Spine) {
    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        alpha.tenant,
        "FILE",
        alpha.visible.as_uuid(),
        fixtures.alpha.member,
        Action::File(FileAction::Preview),
    )
    .await;
    for action in [FileAction::Edit, FileAction::Delete] {
        grant(
            &mut admin,
            alpha.tenant,
            "FILE",
            alpha.also_visible.as_uuid(),
            fixtures.alpha.member,
            Action::File(action),
        )
        .await;
    }
    let _ignored = admin.close().await;
}

/// The `capabilities` object of one row of a listing, by file id.
fn row_capabilities(page: &serde_json::Value, file: FileId) -> serde_json::Value {
    page["items"]
        .as_array()
        .expect("items array")
        .iter()
        .find(|item| item["id"] == serde_json::Value::String(file.to_string()))
        .unwrap_or_else(|| panic!("{file} is not in the listing: {page}"))["capabilities"]
        .clone()
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listing_answers_per_row_rather_than_per_page() {
    // ENC-152. Before this, a row carried no `capabilities` at all and a UI had two ways to draw a
    // menu for it: render every action and find out on click, or re-derive permission client side,
    // which `CLAUDE.md` forbids. The answer has to be per row — two files in one folder, one
    // previewable and one editable, is the ordinary case, not the exotic one.
    let (db, fixtures, alpha, _beta) = setup().await;
    grant_divergent_file_actions(&db, &fixtures, &alpha).await;

    let harness = harness(&db).await;
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items", alpha.library),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body).len(), 3, "the trim still runs: {body}");

    let previewable = row_capabilities(&body, alpha.visible);
    let editable = row_capabilities(&body, alpha.also_visible);
    let plain = row_capabilities(&body, alpha.folder);

    assert_ne!(previewable, editable, "every row was given the same answer");
    assert_eq!(previewable["preview"], true);
    assert_eq!(previewable["download"], false, "preview must not imply download");
    assert_eq!(previewable["edit"], false, "a neighbour's grant reached this row");
    assert_eq!(editable["edit"], true);
    assert_eq!(editable["delete"], true);
    assert_eq!(editable["preview"], false);
    // The library's grant reaches `file.metadata_read` and nothing else, so the folder row is the
    // control: it is readable, and it is readable *only*.
    assert_eq!(plain["metadataRead"], true);
    for action in [
        "preview",
        "download",
        "print",
        "export",
        "edit",
        "share",
        "shareExternal",
        "delete",
        "sync",
    ] {
        assert_eq!(plain[action], false, "{action} arrived from nowhere");
    }

    // Twenty-seven capability answers across three rows, from nine batch resolutions, and one
    // browse. Still exactly one audit row: a probe is a hint, not an action, and a listing that
    // audited its probes would describe reads nobody performed, once per row per action.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "container.read");
    assert_eq!(rows[0].1, "ALLOW");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listings_capabilities_are_exactly_what_the_file_endpoint_returns() {
    // The property that matters most, and the one the implementation is shaped around: for the same
    // file and the same caller, the row and `GET /files/{id}` must be the same object. If they can
    // differ, the UI changes its mind about what a user may do purely because they clicked into the
    // item — offering an action the server will refuse, or hiding one it would allow.
    //
    // Asserted over HTTP, on both objects the two responses share, for every row of the listing —
    // including the folder, which `GET /files/{id}` also serves.
    let (db, fixtures, alpha, _beta) = setup().await;
    grant_divergent_file_actions(&db, &fixtures, &alpha).await;

    let harness = harness(&db).await;
    let (status, listing) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/libraries/{}/items", alpha.library),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut seen: Vec<serde_json::Value> = Vec::new();
    for row in listing["items"].as_array().expect("items") {
        let id = row["id"].as_str().expect("id");
        let (status, file) =
            get(&harness, fixtures.alpha.id, fixtures.alpha.member, &format!("/api/v1/files/{id}"))
                .await;
        assert_eq!(status, StatusCode::OK, "{id}");
        assert_eq!(row["capabilities"], file["capabilities"], "the two disagree about {id}");
        assert_eq!(row["obligations"], file["obligations"], "the two disagree about {id}");
        seen.push(row["capabilities"].clone());
    }

    // Without this the equality above would hold just as well if every object were identical, which
    // is the one case that proves nothing.
    assert!(
        seen.iter().any(|capabilities| capabilities != &seen[0]),
        "the fixture produced a uniform page: {listing}"
    );
}

// ---------------------------------------------------------------------------------------------
// Version history
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn history_lists_versions_no_read_path_would_serve_but_never_their_object_keys() {
    // Two properties at once, because they pull in opposite directions and the pair is the design.
    // A quarantined version must appear — a user who cannot see that 2.0 exists and was quarantined
    // reports the file as silently corrupted — and *nothing* in the listing may point at the bytes.
    let (db, fixtures, alpha, _beta) = setup().await;

    let mut admin = db.connect().await.expect("admin connection");
    let available = VersionId::new_v7();
    let quarantined = VersionId::new_v7();
    insert_version(
        &mut admin,
        &alpha,
        alpha.visible,
        available,
        1,
        0,
        "AVAILABLE",
        "CLEAN",
        fixtures.alpha.owner,
    )
    .await;
    insert_version(
        &mut admin,
        &alpha,
        alpha.visible,
        quarantined,
        2,
        0,
        "QUARANTINED",
        "INFECTED",
        fixtures.alpha.owner,
    )
    .await;
    set_current_version(&mut admin, alpha.visible, available).await;
    let _ignored = admin.close().await;

    let harness = harness(&db).await;
    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}/versions", alpha.visible),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 2, "history hides nothing: {body}");
    // Newest first, the order `idx_versions_file` is built in.
    assert_eq!(items[0]["major"], 2);
    assert_eq!(items[0]["status"], "QUARANTINED");
    assert_eq!(items[0]["avStatus"], "INFECTED");
    assert_eq!(items[0]["isReadable"], false, "rule 9: nothing infected is servable");
    assert_eq!(items[1]["isReadable"], true);

    let text = serde_json::to_string(&body).expect("render");
    for forbidden in ["objectKey", "object_key", "tenants/", "storageProfileId", "signedUrl"] {
        assert!(!text.contains(forbidden), "{forbidden} reached the wire: {text}");
    }

    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "file.version_read");
    // Enforced on the file, not the version: `docs/12-TESTING.md` A7 makes history answer to the
    // ACL the file holds now.
    assert_eq!(rows[0].2, Some(alpha.visible.as_uuid()));
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn history_pages_and_never_reveals_a_version_of_an_unreadable_file() {
    let (db, fixtures, alpha, beta) = setup().await;

    let mut admin = db.connect().await.expect("admin connection");
    for major in 1..=3 {
        insert_version(
            &mut admin,
            &alpha,
            alpha.hidden,
            VersionId::new_v7(),
            major,
            0,
            "AVAILABLE",
            "CLEAN",
            fixtures.alpha.owner,
        )
        .await;
        insert_version(
            &mut admin,
            &alpha,
            alpha.visible,
            VersionId::new_v7(),
            major,
            0,
            "AVAILABLE",
            "CLEAN",
            fixtures.alpha.owner,
        )
        .await;
    }
    let _ignored = admin.close().await;

    let harness = harness(&db).await;

    // Paging works and reports the size it used.
    let (status, first) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}/versions?limit=2", alpha.visible),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().expect("items").len(), 2);
    assert_eq!(first["page"]["hasMore"], true);
    assert_eq!(first["page"]["limit"], 2);
    let cursor = first["page"]["nextCursor"].as_str().expect("cursor").to_owned();

    let (status, second) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}/versions?limit=2&cursor={}", alpha.visible, cursor),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"].as_array().expect("items").len(), 1);
    assert_eq!(second["page"]["hasMore"], false);

    // The file whose inheritance is broken has three versions and none of them are reachable, and
    // the answer is the same one another tenant's file gets. History is not a side door: a caller
    // who cannot read the file cannot learn how many times it changed.
    for file in [alpha.hidden, beta.visible] {
        let (status, body) = get(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            &format!("/api/v1/files/{file}/versions"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{file}");
        assert!(body["items"].is_null(), "a refusal must not carry a page: {body}");
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_malformed_history_cursor_is_a_400_that_names_only_the_field() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = get(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        &format!("/api/v1/files/{}/versions?cursor=not-a-version", alpha.visible),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["details"][0]["field"], "cursor");
    assert_eq!(body["error"]["details"][0]["code"], "INVALID_FORMAT");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_request_without_a_token_reaches_neither_the_chain_nor_the_database() {
    let (db, _fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    for uri in [
        format!("/api/v1/libraries/{}/items", alpha.library),
        format!("/api/v1/files/{}", alpha.visible),
        format!("/api/v1/files/{}/versions", alpha.visible),
    ] {
        let response = harness
            .app
            .clone()
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    // Authentication precedes the chain, so there is no authenticated actor to attribute an event
    // to and nothing should have been written.
    let mut conn = db.connect().await.expect("connect");
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(audited, 0);
}

/// Percent-encodes the handful of characters a base64url cursor can contain that a query string
/// treats specially.
///
/// Hand-rolled rather than pulled in as a dependency: base64url's alphabet is `A-Za-z0-9-_`, none
/// of which needs escaping, so this exists to make that reasoning explicit and to fail loudly if a
/// cursor encoding ever changes underneath these tests.
fn urlencoding(value: &str) -> String {
    assert!(
        value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
        "a cursor grew a character that needs escaping: {value}"
    );
    value.to_owned()
}

// ---------------------------------------------------------------------------------------------
// ENC-825 — the file response and the delivery routes must not disagree
// ---------------------------------------------------------------------------------------------

/// Every state a version can be in, as the `CHECK` constraints spell them.
///
/// Written out rather than derived from `VersionStatus::all()` so that the *test* names the
/// vocabulary independently: a migration that added a status, and a Rust enumeration that grew a
/// variant to match, would otherwise both change and this test would keep asserting over whatever
/// the code happened to know about.
const VERSION_STATES: [&str; 6] =
    ["PENDING", "SCANNING", "PROCESSING", "AVAILABLE", "QUARANTINED", "FAILED"];
const AV_STATES: [&str; 5] = ["PENDING", "CLEAN", "INFECTED", "SKIPPED", "ERROR"];

/// **The assertion this pair of rows exists for** (`ENC-825`).
///
/// `GET /files/{id}` and `GET /files/{id}/preview` must agree, for every combination of `status`
/// and `av_status`, about whether this file's content can be served. Before this change they did
/// not: `currentVersion` carried `status` and nothing else, so `AVAILABLE`/`SKIPPED` — what a
/// deployment with its antivirus engine disabled records (`ENC-828`) — was byte-for-byte identical
/// on the wire to `AVAILABLE`/`CLEAN`, while the preview route answered `404` for the first and
/// bytes for the second. A client had no way to tell them apart except by asking and being refused.
///
/// The cross-product rather than the two interesting cases, because the two interesting cases are
/// only interesting *today*. Thirty combinations cost one request pair each and they pin the whole
/// predicate, including the states — `SKIPPED`, `ERROR` and `PENDING` under an `AVAILABLE` status —
/// where "published" and "scanned" come apart, and where every version of this bug has lived.
///
/// Two controls, because agreement between two endpoints is trivially satisfiable by both of them
/// always saying no. The test asserts exactly how many combinations are served, and separately that
/// `isReadable` is rule 9's predicate rather than merely *consistent* with whatever the preview
/// route happens to do.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_file_response_and_the_preview_route_agree_about_every_version_state() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let caller = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    // Preview is granted on the file, so a `404` from that route is never an authorization answer
    // — it can only be rule 9. Without this the two endpoints would "agree" for the wrong reason.
    grant(
        &mut admin,
        alpha.tenant,
        "LIBRARY",
        alpha.library.as_uuid(),
        caller,
        Action::File(FileAction::Preview),
    )
    .await;
    let version = VersionId::new_v7();
    insert_version(
        &mut admin,
        &alpha,
        alpha.visible,
        version,
        1,
        0,
        "SCANNING",
        "PENDING",
        fixtures.alpha.owner,
    )
    .await;
    set_current_version(&mut admin, alpha.visible, version).await;

    let harness = harness_that_renders(&db).await;
    let metadata = format!("/api/v1/files/{}", alpha.visible.as_uuid());
    let preview = format!("/api/v1/files/{}/preview", alpha.visible.as_uuid());

    let mut served = 0_usize;

    for status in VERSION_STATES {
        for av in AV_STATES {
            sqlx::query("UPDATE file_versions SET status = $1, av_status = $2 WHERE id = $3")
                .bind(status)
                .bind(av)
                .bind(version.as_uuid())
                .execute(&mut admin)
                .await
                .expect("move the version");

            let (code, body) = get(&harness, alpha.tenant, caller, &metadata).await;
            assert_eq!(code, StatusCode::OK, "{status}/{av}");
            let current = &body["currentVersion"];
            assert_eq!(current["status"], status, "{status}/{av}: the wire lost the status");
            assert_eq!(current["avStatus"], av, "{status}/{av}: the wire lost the verdict");
            let claims_readable =
                current["isReadable"].as_bool().expect("isReadable is a boolean on every response");

            let (answer, media_type, body) = fetch(&harness, alpha.tenant, caller, &preview).await;
            let would_serve = answer != StatusCode::NOT_FOUND;

            // Not-404 is not good enough on its own: `503` is also not a `404`, and a delivery
            // path that is simply broken would satisfy an agreement written that loosely. The
            // route that gets past rule 9 must produce an actual rendition — a status, a media
            // type and bytes, all three.
            if would_serve {
                assert_eq!(
                    answer,
                    StatusCode::OK,
                    "{status}/{av}: the preview route got past rule 9 but did not serve — this \
                     test cannot tell 'agreed, and content flows' from 'agreed, and the delivery \
                     path is broken for everything'"
                );
                assert_eq!(media_type.as_deref(), Some("image/png"), "{status}/{av}");
                assert!(
                    !body.is_empty() && body.starts_with(b"\x89PNG"),
                    "{status}/{av}: a 200 carrying no rendition is an absence dressed as a \
                     success, which is docs/12 §1.2's whole warning"
                );
            }

            assert_eq!(
                claims_readable, would_serve,
                "{status}/{av}: GET /files/{{id}} says isReadable={claims_readable} and \
                 GET /files/{{id}}/preview answered {answer}. The metadata endpoint and the \
                 delivery route disagree about the same version, which is the whole of ENC-825 — a \
                 client that believes the first draws a button the second refuses"
            );

            // The independent half. Agreement alone would still hold if both endpoints had adopted
            // the *same wrong* rule, so `isReadable` is also checked against rule 9 as stated here,
            // in the test, rather than against anything the code computes.
            //
            // `AVAILABLE`/`SKIPPED` is servable and `AVAILABLE`/`PENDING` is not, and the pair is
            // the whole of `ENC-828`: `status` carries the antivirus **policy's** decision and
            // `av_status` the **verdict**, so `SKIPPED` under `AVAILABLE` is "a tenant on
            // ALLOW_WITH_FLAG published content nothing inspected" — written down, deliberate, and
            // still refused at CONFIDENTIAL and above on rank. `PENDING` under `AVAILABLE` is
            // `ALLOW_AND_RESCAN` publishing before a scan *completed*, which is the clause rule 9
            // spells out and which stays refused (`ENC-646`).
            assert_eq!(
                claims_readable,
                status == "AVAILABLE" && (av == "CLEAN" || av == "SKIPPED"),
                "{status}/{av}: isReadable is not CLAUDE.md rule 9 as ENC-828 leaves it. \
                 AVAILABLE alone is not servable — PENDING and ERROR are a scan that has not \
                 completed and one that failed, and both delivery routes refuse them"
            );

            if would_serve {
                served += 1;
            }
        }
    }

    let _ignored = admin.close().await;

    // The control. Without it the agreement above is satisfied by a preview route that is broken
    // for every input and a metadata endpoint that reports nothing as readable — which is exactly
    // what an `UnconfiguredPipeline` would have produced here, silently, forever.
    assert_eq!(
        served, 2,
        "exactly two of the thirty combinations are servable — AVAILABLE/CLEAN and, since \
         ENC-828, AVAILABLE/SKIPPED — and if none is, this test agreed with itself about nothing"
    );
}

/// The other endpoint's half (`ENC-826`): both describe a version in **one** shape.
///
/// `GET /uploads/{id}` renders the same type as `version`, so a client learns to read the object
/// once. The upload path is driven end to end in `crates/api/tests/uploads.rs`; what is asserted
/// here is the field set itself, because the way these two drift apart is somebody adding a field
/// to one call site rather than to the type.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_upload_and_file_endpoints_describe_a_version_in_one_shape() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let caller = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    let version = VersionId::new_v7();
    insert_version(
        &mut admin,
        &alpha,
        alpha.visible,
        version,
        1,
        0,
        "AVAILABLE",
        "SKIPPED",
        fixtures.alpha.owner,
    )
    .await;
    set_current_version(&mut admin, alpha.visible, version).await;
    let _ignored = admin.close().await;

    let harness = harness(&db).await;
    let (code, body) =
        get(&harness, alpha.tenant, caller, &format!("/api/v1/files/{}", alpha.visible.as_uuid()))
            .await;
    assert_eq!(code, StatusCode::OK);

    let current = body["currentVersion"].as_object().expect("currentVersion");
    let mut fields: Vec<&str> = current.keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["avStatus", "id", "isReadable", "major", "minor", "status"],
        "the version object grew or lost a field. `GET /uploads/{{id}}` renders this same type as \
         `version`, and the two are one shape on purpose (ENC-825, ENC-826)"
    );

    // And the state both rows were opened for: published, unscanned, not servable.
    assert_eq!(current["status"], "AVAILABLE");
    assert_eq!(current["avStatus"], "SKIPPED");
    assert_eq!(
        current["isReadable"], false,
        "AVAILABLE without CLEAN is not readable, and reporting it as ready is what made a client \
         draw a preview button over a 404"
    );
}
