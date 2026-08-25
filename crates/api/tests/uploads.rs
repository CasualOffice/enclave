//! `ENC-690` — the upload endpoints, end to end, over a real PostgreSQL.
//!
//! # What these prove that the unit tests cannot
//!
//! `crates/api/src/routes/uploads.rs`'s unit tests prove the *shape*: that the two intents ask two
//! actions, that a malformed id is an absence, that no readable state is nameable in the module.
//! None of that is the property the endpoints exist to hold. Those properties are
//!
//! * **a refused upload never reaches the object store** — which is a claim about the *ordering* of
//!   the chain, the library's limits and the quota against a store that counts what it was asked;
//! * **a completed upload is `SCANNING` in the row**, not merely in the response body;
//! * **another tenant's library, and another tenant's session, are `404`** — decided by the ACL
//!   resolver and row-level security under the `enclave_app` role, not by a comparison in a handler.
//!
//! So every request below is a real HTTP request through the real router, carrying a real signed
//! token, against a freshly migrated database, resolved by the real `PgAclAuthorization`. Fixtures
//! are written over the harness's superuser connection because they are setup; every read under
//! test goes through [`TestDb::pool`], which `SET ROLE enclave_app`s (PR #22).
//!
//! # Every refusal here is asserted beside its positive control
//!
//! `docs/12 §1.2`: *an assertion about an absence passes for free.* "No URL is issued when the
//! caller has no grant" holds against a handler that issues no URLs at all, against a router that
//! does not register the route, and against a store that was never wired in. Each refusal below is
//! therefore run in the same fixture, against the same store, as an upload that **is** issued — and
//! the store's call count is asserted on both sides.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration as StdDuration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use enclave_api::{router, ApiState, Delivery};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, ContainerAction, LibraryId, PolicyEngine, TenantId, UserId, WorkspaceId,
};
use enclave_db::{configure_storage_quota, sql, DbPool, Enforcement, TenantScoped};
use enclave_libraries::{ExternalSharing, LibraryRepository, LibrarySettings, VersioningMode};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StoreCapabilities, Support,
    UploadRequest, UploadSession, UploadTarget,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use tower::ServiceExt as _;
use url::Url;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The SHA-256 of the empty string, and its base64 form as a store reports one.
const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const DIGEST_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

// ---------------------------------------------------------------------------------------------
// A store that counts what it was asked to do
// ---------------------------------------------------------------------------------------------

/// A `BlobStore` that records every call.
///
/// The counter is the whole point. `docs/05-API.md §8` promises that *a rejected upload never
/// consumes bandwidth*, and the only way to assert that from outside is to ask the store whether it
/// was ever told to open one — a handler that refused after minting URLs would pass every
/// assertion that reads the response body.
#[derive(Debug, Default)]
struct RecordingStore {
    state: Mutex<StoreState>,
}

#[derive(Debug, Default)]
struct StoreState {
    created: Vec<String>,
    deleted: Vec<String>,
}

impl RecordingStore {
    fn created(&self) -> usize {
        self.state.lock().expect("lock").created.len()
    }

    fn deleted(&self) -> usize {
        self.state.lock().expect("lock").deleted.len()
    }
}

#[async_trait]
impl PublicAccessCheck for RecordingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for RecordingStore {
    async fn create_upload(&self, request: UploadRequest) -> StorageResult<UploadSession> {
        self.state.lock().expect("lock").created.push(request.key.as_str().to_owned());
        Ok(UploadSession {
            key: request.key,
            content_length: request.content_length,
            target: UploadTarget::Single {
                url: Url::parse("https://store.invalid/put").expect("url"),
            },
            expires_at: Utc::now() + Duration::minutes(15),
            completed_parts: Vec::new(),
        })
    }

    async fn complete_upload(&self, session: &UploadSession) -> StorageResult<ObjectMeta> {
        Ok(ObjectMeta {
            key: session.key.clone(),
            size_bytes: session.content_length,
            etag: Some("etag".to_owned()),
            checksum_sha256: Some(DIGEST_B64.to_owned()),
            content_type: None,
            last_modified: Some(Utc::now()),
            provider_version_id: None,
            server_side_encryption: None,
        })
    }

    async fn signed_download(&self, _key: &str, _ttl: StdDuration) -> StorageResult<Url> {
        Ok(Url::parse("https://store.invalid/get").expect("url"))
    }

    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        panic!(
            "the upload path asked to stream `{key}` through this process; content bytes go from \
             the client to the store over signed URLs and must never reach the API"
        );
    }

    async fn copy(&self, from: &str, _to: &str) -> StorageResult<()> {
        panic!(
            "the upload path asked the store to copy `{from}`; bytes are staged under the key \
                the version will keep, so a commit copies nothing"
        );
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        self.state.lock().expect("lock").deleted.push(key.to_owned());
        Ok(())
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "recording-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: 5 * 1024 * 1024,
                max_part_bytes: 5 * 1024 * 1024 * 1024,
                max_parts: 10_000,
            }),
            signed_urls: true,
            single_use_signed_urls: false,
            max_signed_url_ttl: StdDuration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: false,
            server_side_copy: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
    store: Arc<RecordingStore>,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // Three pools, each capped at two connections by the harness: a request that resolves an ACL
    // while holding an audit connection would otherwise compete with itself for the last one.
    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        // The real resolver. A test composed with `SelfServiceAuthorization` would assert nothing
        // about the grant these endpoints turn on.
        Arc::new(PgAclAuthorization::new(authz_pool))
            as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, state_pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));

    let store = Arc::new(RecordingStore::default());
    let delivery = Delivery {
        store: Arc::clone(&store) as Arc<dyn BlobStore>,
        preview: Arc::new(enclave_preview::UnconfiguredPipeline),
    };

    Harness { app: router(state, delivery), key, store }
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
        .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)));

    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
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

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

async fn insert_workspace(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    slug: &str,
) -> WorkspaceId {
    let id = WorkspaceId::new_v7();
    sqlx::query(
        "INSERT INTO workspaces
           (tenant_id, id, name, slug, visibility, revision, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $3, 'PRIVATE', 1, $4, $5, $5)",
    )
    .bind(sql(tenant))
    .bind(sql(id))
    .bind(slug)
    .bind(sql(owner))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert workspace");
    id
}

fn settings(slug: &str, blocked: Option<Vec<String>>) -> LibrarySettings {
    LibrarySettings {
        name: slug.to_owned(),
        slug: slug.to_owned(),
        inherit_permissions: true,
        default_classification_id: None,
        versioning_mode: VersioningMode::MajorMinor,
        version_limit: None,
        require_checkout: false,
        require_approval: false,
        allowed_extensions: None,
        blocked_extensions: blocked,
        max_file_size_bytes: None,
        external_sharing: ExternalSharing::Disabled,
        ai_indexing_enabled: false,
        mcp_visible: false,
        sync_enabled: false,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

async fn library(
    pool: &DbPool,
    tenant: TenantId,
    owner: UserId,
    slug: &str,
    blocked: Option<Vec<String>>,
) -> LibraryId {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let workspace = insert_workspace(&mut tx, tenant, owner, slug).await;
    let library =
        LibraryRepository::create(&mut tx, tenant, workspace, &settings(slug, blocked), Utc::now())
            .await
            .expect("create library")
            .id;
    tx.commit().await.expect("commit");
    library
}

/// Grants one action on one library to one user.
async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    library: LibraryId,
    user: UserId,
    action: Action,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, 'LIBRARY', $3, 'USER', $4, $5, 'ALLOW', $6, $7, NULL)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(sql(tenant))
    .bind(sql(library))
    .bind(sql(user))
    .bind(action.to_string())
    .bind(uuid::Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

async fn set_quota(pool: &DbPool, tenant: TenantId, limit: u64, mode: Enforcement) {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    configure_storage_quota(&mut tx, limit, 80, mode).await.expect("configure the quota");
    tx.commit().await.expect("commit");
}

/// A body for `POST /api/v1/uploads`.
fn upload_body(library: LibraryId, name: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "libraryId": library.to_string(),
        "name": name,
        "sizeBytes": size,
        "mimeType": "application/pdf",
    })
}

/// Reads a session's state straight out of the column, so a test asserting "the row says SCANNING"
/// is asserting about the row and not about the crate's opinion of it.
async fn stored_state(db: &TestDb, id: &str) -> String {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar::<_, String>("SELECT state FROM upload_sessions WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(&mut conn)
        .await
        .expect("read the state column")
}

/// How many rows the two content tables hold for a tenant.
async fn content_rows(db: &TestDb, tenant: TenantId) -> (i64, i64) {
    let mut conn = db.connect().await.expect("connect");
    let files: i64 = sqlx::query_scalar("SELECT count(*) FROM files WHERE tenant_id = $1")
        .bind(sql(tenant))
        .fetch_one(&mut conn)
        .await
        .expect("count files");
    let versions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM file_versions WHERE tenant_id = $1")
            .bind(sql(tenant))
            .fetch_one(&mut conn)
            .await
            .expect("count versions");
    (files, versions)
}

/// The audit rows for one tenant, as `(action, outcome)`.
async fn audit_rows(db: &TestDb, tenant: TenantId) -> Vec<(String, String)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT action, outcome FROM audit_events WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(sql(tenant))
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

/// Two tenants, a library in each, and alpha's member granted `container.create` on alpha's.
async fn setup() -> (TestDb, Fixtures, DbPool, LibraryId, LibraryId) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("application pool");

    let alpha = library(&pool, fixtures.alpha.id, fixtures.alpha.owner, "specs", None).await;
    // The same structure in beta, so every cross-tenant assertion has a realistic counterpart
    // rather than being an assertion about an empty tenant.
    let beta = library(&pool, fixtures.beta.id, fixtures.beta.owner, "specs", None).await;

    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        fixtures.alpha.id,
        alpha,
        fixtures.alpha.member,
        Action::Container(ContainerAction::Create),
    )
    .await;
    grant(
        &mut admin,
        fixtures.alpha.id,
        alpha,
        fixtures.alpha.member,
        Action::Container(ContainerAction::Read),
    )
    .await;
    // Beta's own member is granted in beta, so beta is a populated tenant with real ACLs — the
    // cross-tenant tests below then fail for the right reason.
    grant(
        &mut admin,
        fixtures.beta.id,
        beta,
        fixtures.beta.member,
        Action::Container(ContainerAction::Create),
    )
    .await;
    let _ignored = sqlx::Connection::close(admin).await;

    (db, fixtures, pool, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// The central ordering claim, with its control.
///
/// `docs/05-API.md §8`: the chain runs **before** URLs are issued, so a rejected upload never
/// consumes bandwidth. Both halves are in one fixture against one store: the granted member is
/// issued a URL and the store is asked exactly once; the ungranted viewer is refused and the count
/// does not move. Without the first half, "the store was not called" would hold against a router
/// that had never registered the route.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_with_no_grant_is_refused_before_the_store_is_asked() {
    let (db, fixtures, _pool, alpha_library, _beta_library) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    // The control, first, so that everything below is a statement about a store that demonstrably
    // works and a route that demonstrably issues URLs.
    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Quarterly Plan.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["method"], "SINGLE");
    assert_eq!(body["uploadUrl"], "https://store.invalid/put");
    assert!(body["urls"].is_null(), "a single-shot upload carries no part list");
    assert_eq!(harness.store.created(), 1, "the granted upload reached the store exactly once");

    // The refusal. `viewer` is a real user in the same tenant with no grant on this library.
    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.viewer,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Quarterly Plan.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"]["code"], "NOT_FOUND");
    assert_eq!(
        harness.store.created(),
        1,
        "a refused upload reached the object store, so the client was invited to spend bandwidth \
         on a decision that had already gone against it"
    );

    // The denial left a row. A refusal nobody can find is the one an investigator needs
    // (`CLAUDE.md` rule 10).
    let rows = audit_rows(&db, alpha).await;
    assert!(
        rows.iter().any(|(action, outcome)| action == "container.create" && outcome == "DENY"),
        "no DENY row for the refused upload: {rows:?}"
    );
    assert!(
        rows.iter().any(|(action, outcome)| action == "container.create" && outcome == "ALLOW"),
        "no ALLOW row for the issued upload: {rows:?}"
    );
}

/// `docs/12 §4.1` T1, on the upload path: a `tenant-beta` library id offered by a `tenant-alpha`
/// caller is `404`, never `403`, and no URL is minted for it.
///
/// The id is real and the library exists — in the other tenant, with its own grants — so this is
/// not an assertion about a fabricated UUID.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_in_another_tenant_is_indistinguishable_from_one_that_does_not_exist() {
    let (db, fixtures, _pool, alpha_library, beta_library) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    // Control: the same caller, the same store, an id in their own tenant.
    let (status, _body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Own.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(harness.store.created(), 1);

    let (cross_tenant, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(beta_library, "Theirs.pdf", 64)),
    )
    .await;
    let (fabricated, _) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(LibraryId::new_v7(), "Nowhere.pdf", 64)),
    )
    .await;

    assert_eq!(
        cross_tenant,
        StatusCode::NOT_FOUND,
        "a 403 would confirm the library exists: {body}"
    );
    assert_eq!(
        cross_tenant, fabricated,
        "another tenant's library answered differently from one that never existed, which makes \
         this endpoint an existence oracle"
    );
    assert_eq!(harness.store.created(), 1, "a cross-tenant upload reached the object store");
}

/// `docs/12 §4.12` Q9 at the HTTP edge: the reserve-time preflight refuses before a URL is issued.
///
/// The control is the *same* upload against a quota with room, run first, so the refusal is a
/// statement about an exhausted quota rather than about a route that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_upload_with_no_headroom_is_refused_before_a_url_exists() {
    let (db, fixtures, pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    set_quota(&pool, alpha, 4_096, Enforcement::Block).await;

    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Fits.pdf", 1_024)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "an upload inside the limit must be issued: {body}");
    assert_eq!(harness.store.created(), 1);

    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Enormous.pdf", 8_192)),
    )
    .await;
    // A capacity quota is a refusal, not a "try again later": `403`, not `429`.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "QUOTA_EXCEEDED");
    assert_eq!(
        harness.store.created(),
        1,
        "an upload over quota reached the object store, so `docs/05-API.md §8`'s promise that a \
         rejected upload never consumes bandwidth is not being kept"
    );
}

/// A library's extension rules are applied, and applied above the store call.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_blocked_extension_is_refused_before_the_store_is_asked() {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed");
    let pool = db.pool().await.expect("pool");
    let alpha = fixtures.alpha.id;

    let library_id = library(
        &pool,
        alpha,
        fixtures.alpha.owner,
        "contracts",
        Some(vec!["exe".to_owned(), "bat".to_owned()]),
    )
    .await;

    let mut admin = db.connect().await.expect("admin connection");
    grant(
        &mut admin,
        alpha,
        library_id,
        fixtures.alpha.member,
        Action::Container(ContainerAction::Create),
    )
    .await;
    let _ignored = sqlx::Connection::close(admin).await;

    let harness = harness(&db).await;

    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(library_id, "installer.exe", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    assert_eq!(body["error"]["details"][0]["field"], "name");
    assert_eq!(harness.store.created(), 0);

    // The control. Same library, same caller, an extension it accepts — so the assertion above is
    // about the rule and not about a library that refuses everything.
    let (status, _body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(library_id, "contract.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(harness.store.created(), 1);
}

/// `CLAUDE.md` rule 9, asserted where it can actually be broken.
///
/// Three claims, and the third is what makes the first two more than a restatement of the
/// response body:
///
/// 1. the response is `202` and its `state` is `SCANNING` (`docs/05-API.md §8`);
/// 2. the **row** says `SCANNING`, read straight out of the column;
/// 3. **no `file_versions` row exists**, and none is `AVAILABLE` — a completed upload has not
///    become readable content, and cannot until antivirus has run.
///
/// The third assertion is about an absence, so it carries its own control: the file and version
/// counts are read *before* the completion as well, and the point is that they are unchanged
/// rather than that they happen to be zero.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_completed_upload_is_scanning_and_becomes_no_readable_content() {
    let (db, fixtures, _pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    let (status, issued) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Quarterly Plan.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let upload_id = issued["uploadId"].as_str().expect("uploadId").to_owned();

    let before = content_rows(&db, alpha).await;

    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/uploads/{upload_id}/complete"),
        Some(serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX })),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["state"], "SCANNING", "docs/05-API.md §8 fixes this value");
    assert!(body["fileId"].is_string(), "the response carries the identifiers the key reserved");
    assert!(body["versionId"].is_string());

    assert_eq!(
        stored_state(&db, &upload_id).await,
        "SCANNING",
        "the response said SCANNING and the row says something else"
    );

    let after = content_rows(&db, alpha).await;
    assert_eq!(
        before, after,
        "completing an upload created content rows. Nothing here may write a version: the commit \
         belongs beside the antivirus pass, which is ENC-691, and a version written here would be \
         one CLAUDE.md rule 9 has no gate in front of"
    );

    // And the poll a client makes next reports the same state, from the same column.
    let (status, progress) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{progress}");
    assert_eq!(progress["state"], "SCANNING");
    assert_eq!(progress["bytesReceived"], 64);
}

/// A size the store contradicts is a **persisted** refusal, not a warning.
///
/// The session ends `FAILED` and the client is told which field it got wrong. Retrying the same
/// completion cannot succeed, which is why the row is written rather than rolled back.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_completion_the_store_contradicts_is_persisted_as_failed() {
    let (db, fixtures, _pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    let (_status, issued) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Quarterly Plan.pdf", 64)),
    )
    .await;
    let upload_id = issued["uploadId"].as_str().expect("uploadId").to_owned();

    // The store will report 64 bytes — the declared length. The client claims 65.
    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/uploads/{upload_id}/complete"),
        Some(serde_json::json!({ "sizeBytes": 65, "sha256": DIGEST_HEX })),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "sizeBytes");
    assert_eq!(stored_state(&db, &upload_id).await, "FAILED");

    // A failed session is not resumable: the second attempt is a `409`, not a second `400`.
    let (status, _body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/uploads/{upload_id}/complete"),
        Some(serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// `DELETE` releases the staged bytes, and does it before it marks the row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn aborting_releases_the_staged_bytes_and_marks_the_row() {
    let (db, fixtures, _pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    let (_status, issued) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Abandoned.pdf", 64)),
    )
    .await;
    let upload_id = issued["uploadId"].as_str().expect("uploadId").to_owned();
    assert_eq!(harness.store.deleted(), 0, "nothing has been released yet");

    let (status, _body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "DELETE",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(harness.store.deleted(), 1, "the staged object was not released");
    assert_eq!(stored_state(&db, &upload_id).await, "ABORTED");

    // Aborting twice is a `409`: the session is no longer resumable, and reporting that as success
    // would tell a client its bytes were released a second time.
    let (status, _body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "DELETE",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(harness.store.deleted(), 1);
}

/// The three `/uploads/{id}` methods are decided by the chain, not by knowing the id.
///
/// This test exists because of a deliberate break that failed nothing (`docs/12 §1.2`). Removing
/// the `authorize` call from `abort` left every other test in this file green: the session lookup
/// is tenant-scoped, so row-level security still answered `404` across tenants, and every caller in
/// the remaining fixtures held the grant. Only `xtask policy-routing` caught it — and a structural
/// gate that proves `enforce` is *reachable* cannot prove that it *decides*.
///
/// So the missing case is a second member of the **same** tenant, holding nothing on the library.
/// RLS cannot help there: the row is theirs to read. Each refusal is paired with the same call by
/// the granted member, so none of them is a statement about a route that refuses everyone.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_session_cannot_be_completed_or_aborted_by_a_caller_the_chain_refuses() {
    let (db, fixtures, _pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    let open_session = async |name: &'static str| {
        let (status, issued) = call(
            &harness,
            alpha,
            fixtures.alpha.member,
            "POST",
            "/api/v1/uploads",
            Some(upload_body(alpha_library, name, 64)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        issued["uploadId"].as_str().expect("uploadId").to_owned()
    };

    let deletes_before = harness.store.deleted();
    let mut probed = Vec::new();

    // `viewer` is a real user in this tenant. The session row is visible to their transaction —
    // RLS has nothing to say about it — so the only thing that can refuse them is the chain.
    //
    // A fresh pair of sessions per method, because `complete` and `abort` both settle the one they
    // act on: reusing a session would make the third control a `409` rather than a success, and a
    // control that does not succeed is not a control.
    for (method, suffix) in [("GET", ""), ("POST", "/complete"), ("DELETE", "")] {
        let for_viewer = open_session("Viewer Probe.pdf").await;
        let for_member = open_session("Member Control.pdf").await;
        let body = (method == "POST")
            .then(|| serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX }));

        let (refused, response) = call(
            &harness,
            alpha,
            fixtures.alpha.viewer,
            method,
            &format!("/api/v1/uploads/{for_viewer}{suffix}"),
            body.clone(),
        )
        .await;
        assert_eq!(
            refused,
            StatusCode::NOT_FOUND,
            "{method} on a session in the caller's own tenant was not decided by the chain: \
             {response}"
        );

        let (allowed, response) = call(
            &harness,
            alpha,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/uploads/{for_member}{suffix}"),
            body,
        )
        .await;
        assert!(
            allowed.is_success(),
            "{method} did not succeed for the granted member, so the refusal above proves \
             nothing: {response}"
        );

        probed.push(for_viewer);
    }

    assert_eq!(
        harness.store.deleted(),
        deletes_before + 1,
        "exactly one delete — the granted member's — reached the store"
    );
    // Every session the viewer tried is exactly as the member left it.
    for id in probed {
        assert_eq!(stored_state(&db, &id).await, "CREATED");
    }
}

/// A session id from the other tenant is `404` on every one of the three `/uploads/{id}` methods,
/// and nothing about it reaches the store.
///
/// The session is real and belongs to a real caller in beta — created through the same endpoint,
/// so this is an assertion about isolation rather than about a UUID nobody minted.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_upload_session_is_indistinguishable_from_one_that_does_not_exist() {
    let (db, fixtures, _pool, alpha_library, beta_library) = setup().await;
    let harness = harness(&db).await;

    // Beta's own member creates a session in beta.
    let (status, issued) = call(
        &harness,
        fixtures.beta.id,
        fixtures.beta.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(beta_library, "Beta Plan.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let beta_session = issued["uploadId"].as_str().expect("uploadId").to_owned();

    // Alpha's member creates one of their own — the control, so every `404` below is a statement
    // about *whose* session it is rather than about a route that answers `404` to everyone.
    let (status, issued) = call(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        "POST",
        "/api/v1/uploads",
        Some(upload_body(alpha_library, "Alpha Plan.pdf", 64)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let alpha_session = issued["uploadId"].as_str().expect("uploadId").to_owned();

    let deletes_before = harness.store.deleted();

    for (method, suffix) in [("GET", ""), ("DELETE", ""), ("POST", "/complete")] {
        let body = (method == "POST")
            .then(|| serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX }));

        let (own, _) = call(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/uploads/{alpha_session}{suffix}"),
            body.clone(),
        )
        .await;
        assert_ne!(
            own,
            StatusCode::NOT_FOUND,
            "{method} on the caller's own session answered 404, so the cross-tenant assertion \
             below proves nothing"
        );

        let (cross, _) = call(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/uploads/{beta_session}{suffix}"),
            body.clone(),
        )
        .await;
        let (fabricated, _) = call(
            &harness,
            fixtures.alpha.id,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/uploads/{}{suffix}", uuid::Uuid::now_v7()),
            body,
        )
        .await;

        assert_eq!(cross, StatusCode::NOT_FOUND, "{method} leaked another tenant's session");
        assert_eq!(
            cross, fabricated,
            "{method} answered another tenant's session differently from one that never existed"
        );
    }

    assert_eq!(
        harness.store.deleted(),
        deletes_before + 1,
        "exactly one delete — alpha's own abort — reached the store; a cross-tenant DELETE \
         released bytes it had no claim on"
    );

    // Beta's session is untouched by everything alpha just tried.
    assert_eq!(stored_state(&db, &beta_session).await, "CREATED");
}
