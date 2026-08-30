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
use enclave_antivirus::{NoScanningPerformed, ScanPolicy};
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
    PublicAccessError, PublicAccessReport, Result as StorageResult, StorageError,
    StoreCapabilities, Support, UploadRequest, UploadSession, UploadTarget,
};
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::antivirus::{av_pass, AvCursor};
use enclave_worker::Stop;
use sqlx::{PgConnection, Row as _};
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
        // The header the client must send back, reported the way a real store reports it — this is
        // what `POST /uploads` puts in `requiredHeaders` (`ENC-820`, `ENC-821`).
        let required_headers = request
            .checksum_sha256
            .map(|_| {
                vec![enclave_storage::RequiredHeader {
                    name: "x-amz-checksum-sha256".to_owned(),
                    value: DIGEST_B64.to_owned(),
                }]
            })
            .unwrap_or_default();
        Ok(UploadSession {
            key: request.key,
            content_length: request.content_length,
            target: UploadTarget::Single {
                url: Url::parse("https://store.invalid/put").expect("url"),
                required_headers,
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
            // No cold tier: this double serves from memory (`ENC-946`).
            storage_tiers: Support::No,
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

/// A store that serves one object's bytes, for the antivirus leg only.
///
/// Separate from [`RecordingStore`] rather than a relaxation of it. That store's `read_range`
/// panics on purpose — content must never travel through the API process on an upload — and the
/// panic is an assertion this file should keep. The worker is a different process with a different
/// rule: it reads objects, so the leg that runs the worker's pass gets a store that lets it.
#[derive(Debug)]
struct ServingStore {
    key: String,
    body: Vec<u8>,
}

impl ServingStore {
    fn holding(key: &str, body: Vec<u8>) -> Self {
        Self { key: key.to_owned(), body }
    }
}

#[async_trait]
impl PublicAccessCheck for ServingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for ServingStore {
    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        panic!("the antivirus pass does not stage uploads")
    }

    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        panic!("the antivirus pass does not complete uploads")
    }

    async fn signed_download(&self, _key: &str, _ttl: StdDuration) -> StorageResult<Url> {
        panic!("the antivirus pass mints no URLs")
    }

    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        if key != self.key {
            return Err(StorageError::NotFound { key: key.to_owned() });
        }
        let body = self.body.clone();
        let length = body.len() as u64;
        Ok(ByteStream::new(
            futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }),
            Some(length),
        ))
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        panic!("nothing on this path copies")
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        panic!("the antivirus pass deletes nothing")
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            // No cold tier: this double serves from memory (`ENC-946`).
            storage_tiers: Support::No,
            backend: "serving-stub",
            multipart: None,
            signed_urls: false,
            single_use_signed_urls: false,
            max_signed_url_ttl: StdDuration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: true,
            server_side_copy: false,
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
///
/// `sha256` is required since `ENC-820` — it is the digest the object store is made to verify the
/// body against, so an upload cannot be started without one.
fn upload_body(library: LibraryId, name: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "libraryId": library.to_string(),
        "name": name,
        "sizeBytes": size,
        "mimeType": "application/pdf",
        "sha256": DIGEST_HEX,
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

/// The one version row a tenant holds, straight out of its columns.
///
/// Every value a reader would act on, read from the table rather than from the response: a `202`
/// that named identifiers off the staged key is exactly what `ENC-691` was, so a test that trusted
/// the body would have passed against the defect.
struct VersionRow {
    id: String,
    file_id: String,
    object_key: String,
    storage_profile_id: String,
    size_bytes: i64,
    checksum_sha256: String,
    mime_type: String,
    major: i32,
    minor: i32,
    status: String,
    av_status: String,
}

async fn only_version(db: &TestDb, tenant: TenantId) -> VersionRow {
    let mut conn = db.connect().await.expect("connect");
    let row = sqlx::query(
        "SELECT id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256, \
         mime_type, major, minor, status, av_status \
           FROM file_versions WHERE tenant_id = $1",
    )
    .bind(sql(tenant))
    .fetch_one(&mut conn)
    .await
    .expect("exactly one version row for this tenant");

    VersionRow {
        id: row.get::<uuid::Uuid, _>("id").to_string(),
        file_id: row.get::<uuid::Uuid, _>("file_id").to_string(),
        object_key: row.get("object_key"),
        storage_profile_id: row.get::<uuid::Uuid, _>("storage_profile_id").to_string(),
        size_bytes: row.get("size_bytes"),
        checksum_sha256: row.get("checksum_sha256"),
        mime_type: row.get("mime_type"),
        major: row.get("major"),
        minor: row.get("minor"),
        status: row.get("status"),
        av_status: row.get("av_status"),
    }
}

/// A file node's `(name, status, current_version_id, size_bytes)`.
async fn file_row(db: &TestDb, id: &str) -> (String, String, Option<String>, i64) {
    let mut conn = db.connect().await.expect("connect");
    let row = sqlx::query(
        "SELECT name, status, current_version_id, size_bytes FROM files WHERE id = $1::uuid",
    )
    .bind(id)
    .fetch_one(&mut conn)
    .await
    .expect("the file row the completion created");
    (
        row.get("name"),
        row.get("status"),
        row.get::<Option<uuid::Uuid>, _>("current_version_id").map(|id| id.to_string()),
        row.get("size_bytes"),
    )
}

/// What the tenant's stored-byte counter says.
async fn used_bytes(db: &TestDb, tenant: TenantId) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar("SELECT used_bytes FROM storage_quotas WHERE tenant_id = $1")
        .bind(sql(tenant))
        .fetch_one(&mut conn)
        .await
        .expect("the tenant has a quota row")
}

/// The index manifests queued for a tenant, as `(version_id, status)`.
async fn manifests(db: &TestDb, tenant: TenantId) -> Vec<(String, String)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query("SELECT version_id, status FROM index_manifests WHERE tenant_id = $1")
        .bind(sql(tenant))
        .fetch_all(&mut conn)
        .await
        .expect("read the index queue")
        .into_iter()
        .map(|row| (row.get::<uuid::Uuid, _>("version_id").to_string(), row.get("status")))
        .collect()
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

/// **The journey**: sign in, upload, and the file is there — `ENC-691`.
///
/// Every claim below is read out of a column, because the response body is precisely what was
/// already right when this was broken. The defect was a `202` naming a `fileId` and a `versionId`
/// for rows that did not exist, so a test that read the body passed against it.
///
/// 1. the response is `202` and its `state` is `SCANNING` (`docs/05-API.md §8`);
/// 2. the session **row** says `SCANNING`;
/// 3. a `files` row exists, under the id the staged key spent, pointing at the new version;
/// 4. a `file_versions` row exists, `SCANNING`/`PENDING`, numbered `1.0`, carrying the store's size
///    and checksum and the staged key as its object key;
/// 5. the stored-byte counter moved by exactly those bytes (`ENC-589`);
/// 6. an index manifest is queued for that version (`ENC-643`);
/// 7. **nothing is readable.** No version is `AVAILABLE` and no version is `CLEAN`.
///
/// Claim 7 is an absence, and on its own it is worthless — it held perfectly while no version was
/// created at all, which is the bug (`docs/12 §1.2`). Claims 3 to 6 are its positive control: the
/// row exists, it is complete, and what it says is `SCANNING`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_completed_upload_becomes_a_scanning_version_and_nothing_readable() {
    let (db, fixtures, pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;
    // A metered tenant, so "the quota moved" is a claim about a number rather than about `None`.
    set_quota(&pool, alpha, 1024 * 1024, Enforcement::Block).await;

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

    // `ENC-820`: the header the provider will verify the body against reaches the client, exactly
    // as the store signed it. Without it on the wire, every `PUT` fails the signature check — and
    // an upload path that issued no such header at all is the defect itself.
    assert_eq!(
        issued["requiredHeaders"]["x-amz-checksum-sha256"].as_str(),
        Some(DIGEST_B64),
        "the PUT's mandatory checksum header is not in the response: {issued}"
    );

    let before = content_rows(&db, alpha).await;
    let charged_before = used_bytes(&db, alpha).await;
    assert_eq!(
        before,
        (0, 0),
        "the tenant starts with no content, so the counts below are the delta"
    );

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

    assert_eq!(
        stored_state(&db, &upload_id).await,
        "SCANNING",
        "the response said SCANNING and the row says something else"
    );

    // 3 and 4: the rows the response names.
    assert_eq!(
        content_rows(&db, alpha).await,
        (1, 1),
        "a completed upload must produce exactly one file and one version. Nothing consumed the \
         ScanHandoff, so the 202 named two rows that did not exist (ENC-691)"
    );

    let version = only_version(&db, alpha).await;
    assert_eq!(
        body["versionId"].as_str(),
        Some(version.id.as_str()),
        "the versionId on the wire is not the version that was written"
    );
    assert_eq!(
        body["fileId"].as_str(),
        Some(version.file_id.as_str()),
        "the fileId on the wire is not the file the version belongs to"
    );

    // Rule 9, and the whole point of the row: it is not readable, and it is queued to be judged.
    assert_eq!(version.status, "SCANNING");
    assert_eq!(version.av_status, "PENDING");
    assert_ne!(version.status, "AVAILABLE", "rule 9: nothing is readable before antivirus");
    assert_ne!(version.av_status, "CLEAN");

    assert_eq!((version.major, version.minor), (1, 0), "the first version of a new file is 1.0");
    assert_eq!(version.size_bytes, 64, "the store's number, not the client's declaration");
    assert_eq!(version.checksum_sha256, DIGEST_HEX);
    assert_eq!(version.mime_type, "application/pdf", "the declared type, since one was declared");
    assert_eq!(
        version.storage_profile_id, "00000000-0000-0000-0000-000000000000",
        "no storage_profiles table exists (ENC-573), so the column carries the value a backfill \
         can find rather than a fabricated profile id"
    );
    // The staged key *is* the version key — nothing was copied on commit.
    let staged = harness.store.state.lock().expect("lock").created[0].clone();
    assert_eq!(version.object_key, staged);
    assert!(
        staged.contains(&version.file_id) && staged.contains(&version.id),
        "the object key must name the file and version rows that now exist: `{staged}`"
    );

    let (name, file_status, current, file_size) = file_row(&db, &version.file_id).await;
    assert_eq!(name, "Quarterly Plan.pdf");
    assert_eq!(current.as_deref(), Some(version.id.as_str()), "the file points at the new version");
    assert_eq!(file_size, 64);
    assert_ne!(file_status, "AVAILABLE", "a file pointing at unscanned bytes is not available");

    // 5: the charge (`ENC-589`), which happens inside the commit and nowhere else.
    assert_eq!(
        used_bytes(&db, alpha).await - charged_before,
        64,
        "the tenant was not charged for the bytes it just stored"
    );

    // 6: the index manifest (`ENC-643`), enqueued in the same transaction as the version.
    assert_eq!(
        manifests(&db, alpha).await,
        vec![(version.id.clone(), "PENDING".to_owned())],
        "the version is stored and permanently unsearchable"
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

/// The other half of the journey: **the worker's antivirus pass finds what the upload committed.**
///
/// "A `file_versions` row exists" and "the pass that has to move it can see it" are two claims, and
/// only the second is what M1's exit criterion needs. `ENC-641`'s queue keys on
/// `file_versions.av_status`, so a completed upload that wrote no version was invisible to it —
/// which is why the pass ran correctly over an empty set for four milestones and reported nothing
/// wrong.
///
/// The scanner is `NoScanningPerformed` under the policy a shipped `antivirus: { provider: none }`
/// deployment resolves to, because that is what this repository's own dev stack runs. It answers
/// `Unsupported` — it did not look — and `unsupported` is pinned to `BLOCK`, so the version is
/// quarantined `SKIPPED` and re-offered the day an engine that inspects content is configured. That
/// is the correct outcome and the loud one: rule 9 holds, and the corpus is not silently readable.
///
/// The positive control is the count: `considered` is 1 and `written` is 1. Without them,
/// "the version is not AVAILABLE afterwards" holds against a pass that found nothing at all — the
/// same trap as the row's own absence.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_antivirus_pass_finds_the_version_a_completed_upload_committed() {
    let (db, fixtures, pool, alpha_library, _beta) = setup().await;
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

    let version = only_version(&db, alpha).await;
    assert_eq!((version.status.as_str(), version.av_status.as_str()), ("SCANNING", "PENDING"));

    // The pass streams the bytes before it scans them, and `RecordingStore` refuses to serve any —
    // deliberately, because the *upload* path must never move content through this process. This
    // leg is the worker's, so it gets a store that behaves like the worker's.
    let scannable =
        Arc::new(ServingStore::holding(&version.object_key, b"quarterly plan".to_vec()));
    let scanner = NoScanningPerformed;
    let policy = ScanPolicy::from_config(&enclave_config::AntivirusConfig::default());
    let pass = av_pass(
        &pool,
        alpha,
        &scanner,
        scannable.as_ref(),
        policy,
        10,
        AvCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("the pass must not fail on a version it cannot scan");

    assert_eq!(
        pass.considered, 1,
        "the antivirus queue did not offer the version this upload just committed. That queue is \
         `av_status`, and before ENC-691 a completed upload wrote no row for it to key on"
    );
    assert_eq!(pass.written, 1, "the pass found the version and recorded no verdict against it");

    let after = only_version(&db, alpha).await;
    assert_eq!(
        (after.status.as_str(), after.av_status.as_str()),
        ("QUARANTINED", "SKIPPED"),
        "`provider: none` did not inspect the content, `unsupported` is pinned to BLOCK, and a \
         version nothing looked at must not become readable (CLAUDE.md rule 9, ENC-641)"
    );
    assert_ne!(after.status, "AVAILABLE");
}

/// A commit the database refuses must not leave a session `SCANNING` with nothing to scan.
///
/// This is `ENC-691`'s failure mode reached the other way round. The session's `SCANNING` write and
/// the version commit share one transaction, so a refusal — here a live sibling already holding the
/// name — takes both back. The session goes to the state it can be retried from, the bytes stay
/// staged under a session the reaper still counts, and no half-written journey survives.
///
/// A refused *completion* is the opposite and is asserted next door: wrong bytes are persisted as
/// `FAILED`, because retrying them cannot work. The two refusals are deliberately not the same.
///
/// The positive control is the first upload: the same fixture, the same store, the same name, and
/// it does produce a file and a version. Without it, "the second one wrote nothing" holds against
/// a completion path that writes nothing at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_refused_commit_takes_the_session_back_rather_than_stranding_it() {
    let (db, fixtures, _pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    let mut sessions = Vec::new();
    for _attempt in 0..2 {
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
        sessions.push(issued["uploadId"].as_str().expect("uploadId").to_owned());
    }

    async fn complete(
        harness: &Harness,
        at: &Fixtures,
        id: &str,
    ) -> (StatusCode, serde_json::Value) {
        call(
            harness,
            at.alpha.id,
            at.alpha.member,
            "POST",
            &format!("/api/v1/uploads/{id}/complete"),
            Some(serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX })),
        )
        .await
    }

    // The control: the first upload of that name lands.
    let (status, body) = complete(&harness, &fixtures, &sessions[0]).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(content_rows(&db, alpha).await, (1, 1));

    // The second one cannot: `uq_files_sibling_name` holds the name.
    let (status, body) = complete(&harness, &fixtures, &sessions[1]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "name", "{body}");

    assert_ne!(
        stored_state(&db, &sessions[1]).await,
        "SCANNING",
        "the refused session was left SCANNING with no version behind it — the stranded state \
         ENC-691 is about, reached from the other direction. The session's state write and the \
         commit share one transaction so that this cannot happen"
    );
    assert_eq!(content_rows(&db, alpha).await, (1, 1), "the refused commit left rows behind");
}

/// The same claim on the one refusal PostgreSQL does **not** enforce for us.
///
/// `a_refused_commit_takes_the_session_back_rather_than_stranding_it` turned out to prove less than
/// it looked like it did: a duplicate name is a constraint violation, which aborts the transaction,
/// and `COMMIT` on an aborted transaction is a rollback. Replacing the handler's `rollback` with a
/// `commit` failed nothing — so that test holds its property by accident of the database rather
/// than by the handler's choice.
///
/// A quota refusal is the case where the choice is real. `charge_storage` refuses from a statement
/// that **succeeded** — the limit is in its `WHERE` clause, so "no room" is zero rows updated, not
/// an error — and the transaction is still perfectly committable at that point. Committing it would
/// leave the session `SCANNING`, a `files` row behind it, and no version: exactly `ENC-691`'s
/// stranded state, produced deliberately.
///
/// The headroom is removed *after* the session exists, because `UploadService::create`'s preflight
/// would otherwise refuse before a URL was ever issued — which is a different refusal, asserted in
/// `an_upload_with_no_headroom_is_refused_before_a_url_exists`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_commit_the_quota_refuses_takes_the_session_back_too() {
    let (db, fixtures, pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;

    set_quota(&pool, alpha, 1024 * 1024, Enforcement::Block).await;
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

    // The tenant's headroom disappears while the bytes are in flight.
    set_quota(&pool, alpha, 8, Enforcement::Block).await;

    let (status, body) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/uploads/{upload_id}/complete"),
        Some(serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "QUOTA_EXCEEDED", "{body}");

    assert_ne!(
        stored_state(&db, &upload_id).await,
        "SCANNING",
        "the session was left SCANNING with no version behind it. A quota refusal comes back from a \
         statement that succeeded, so the transaction is still committable and only the handler's \
         rollback stops this"
    );
    assert_eq!(
        content_rows(&db, alpha).await,
        (0, 0),
        "the refused commit left a files row behind, pointing at nothing"
    );
    assert_eq!(used_bytes(&db, alpha).await, 0, "a refused charge must move no counter");
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

/// **`ENC-826`: the progress endpoint reports the end of an upload, not only its beginning.**
///
/// `GET /uploads/{id}` reported `SCANNING` from the moment `complete` returned until the session
/// was reaped, because the session's phase machine ends there and everything afterwards happens to
/// the *version*. A client polling the documented progress endpoint watched a file that had been
/// published minutes earlier, and had no way from this response to reach the file at all: for a
/// new-file upload `fileId` was never populated, so the only place it ever appeared was the
/// `complete` response.
///
/// The session's own `state` is deliberately still `SCANNING` at every step below, and that is
/// asserted rather than tolerated — it is a true, final statement about the session, and the fix
/// was to name the version's state beside it rather than to overload one field across two rows
/// with two owners and two lifetimes. See `ProgressView`'s documentation for why the antivirus pass
/// does not write this column.
///
/// The version is moved by direct `UPDATE`, which is exactly what `crates/worker`'s antivirus pass
/// does to it — this test is about what the *endpoint* reports for a given row, and composing the
/// worker here would be testing the worker.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn progress_follows_the_version_after_the_session_has_stopped_moving() {
    let (db, fixtures, pool, alpha_library, _beta) = setup().await;
    let harness = harness(&db).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, 1024 * 1024, Enforcement::Block).await;

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

    // Before the handoff there is no version, and the response must not invent one. The id is
    // knowable from the staged key here — which is precisely why naming it would be a promise
    // about a row nothing has written (`ENC-691`).
    let (status, early) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{early}");
    assert_eq!(early["state"], "CREATED");
    assert!(early.get("version").is_none(), "a version was reported before one was committed");
    assert!(
        early.get("fileId").is_none(),
        "a fileId was reported for a file the commit has not created: {early}"
    );

    let (status, completed) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/uploads/{upload_id}/complete"),
        Some(serde_json::json!({ "sizeBytes": 64, "sha256": DIGEST_HEX })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{completed}");
    let file_id = completed["fileId"].as_str().expect("fileId").to_owned();
    let version_id = completed["versionId"].as_str().expect("versionId").to_owned();

    // What the worker will do to this row, and what the endpoint must say at each step.
    //
    // `AVAILABLE`/`SKIPPED` expected `false` until `ENC-828` and now expects `true`, which is the
    // whole of that change seen from the client's side: it is what `ALLOW_WITH_FLAG` writes, and a
    // version that policy published which no delivery route would serve made the setting a no-op.
    // The default `BLOCK` writes `QUARANTINED`/`SKIPPED`, so this row cannot occur unless the
    // deployment asked for it.
    //
    // The row that carries the original lesson is now `AVAILABLE`/`PENDING`: `AVAILABLE` is
    // *published*, not *scanned*, and a client reading `status` alone would put a tick on a file
    // both delivery routes refuse. It is added here rather than left to the file endpoint's
    // cross-product, because this is the endpoint a client actually polls while it waits.
    let steps: [(&str, &str, bool); 5] = [
        ("SCANNING", "PENDING", false),
        ("PROCESSING", "CLEAN", false),
        ("AVAILABLE", "PENDING", false),
        ("AVAILABLE", "SKIPPED", true),
        ("AVAILABLE", "CLEAN", true),
    ];

    let mut conn = db.connect().await.expect("admin connection");
    for (status_value, av, readable) in steps {
        sqlx::query("UPDATE file_versions SET status = $1, av_status = $2 WHERE id = $3::uuid")
            .bind(status_value)
            .bind(av)
            .bind(&version_id)
            .execute(&mut conn)
            .await
            .expect("move the version");

        let (code, progress) = call(
            &harness,
            alpha,
            fixtures.alpha.member,
            "GET",
            &format!("/api/v1/uploads/{upload_id}"),
            None,
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{progress}");

        // The session has stopped moving, and says so honestly, at every step.
        assert_eq!(
            progress["state"], "SCANNING",
            "the session's own state is terminal at SCANNING by construction; if this changed, \
             something is writing `upload_sessions.state` after the handoff and the phase machine \
             in `enclave_uploads::state` is no longer the only writer (CLAUDE.md rule 9)"
        );

        // And the version's state is what actually answers the client's question.
        let version = &progress["version"];
        assert_eq!(version["id"], version_id, "the progress view named a different version");
        assert_eq!(version["status"], status_value);
        assert_eq!(version["avStatus"], av);
        assert_eq!(
            version["isReadable"], readable,
            "{status_value}/{av}: the upload progress endpoint disagrees with the predicate the \
             delivery routes apply. This is the report a client polls to decide whether to show \
             the file (ENC-826)"
        );

        // The way back to the file, which used to exist only in the `complete` response.
        assert_eq!(
            progress["fileId"], file_id,
            "a client that lost the completion response has no route back to its own upload"
        );
    }

    // The row this whole test exists for: `state` never changed, and the response did.
    let (_, first) = call(
        &harness,
        alpha,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(first["version"]["isReadable"], true);
    assert_eq!(first["state"], "SCANNING");

    // ---------------------------------------------------------------------------------------
    // Cross-tenant, and **which layer this proves**
    // ---------------------------------------------------------------------------------------
    // This leg proves the **policy-chain layer**: `progress` runs `container.read` against the
    // container the session lands in, and `authorize` renders an `ACCESS_DENIED` as `404`, so
    // alpha's session is indistinguishable from one that never existed when beta asks for it.
    //
    // It does **not** prove the `tenant_id` predicate in any SQL statement — including the version
    // lookup this row added. Row-level security holds that property on its own under the
    // `enclave_app` role, so deleting a `tenant_id` from a `WHERE` clause leaves this test green.
    // That has failed to fail nine times in this repository and it would fail to fail here too;
    // saying so is the point, rather than implying a coverage this assertion does not have.
    let (cross, body) = call(
        &harness,
        fixtures.beta.id,
        fixtures.beta.member,
        "GET",
        &format!("/api/v1/uploads/{upload_id}"),
        None,
    )
    .await;
    assert_eq!(cross, StatusCode::NOT_FOUND, "{body}");
    let rendered = body.to_string();
    for leaked in [file_id.as_str(), version_id.as_str(), "isReadable", "avStatus"] {
        assert!(
            !rendered.contains(leaked),
            "`{leaked}` reached another tenant through the refusal body: {rendered}"
        );
    }

    drop(conn);
}
