//! Sync over HTTP — the download/sync split, and what a delta may say about a file.
//!
//! `ENC-734`. The row this file exists for is the sync leg of `CLAUDE.md` rule 6:
//!
//! > a caller with `file.download` and without `file.sync` is refused the delta.
//!
//! `crates/api/tests/delivery.rs` proved the preview/download half of the same rule. This is the
//! third leg, and it is asserted three ways rather than on a status code:
//!
//! 1. **On the verdict.** The entry is a `TOMBSTONE` with `syncEligible: false`.
//! 2. **On the payload.** It carries no `versionId`, no `checksumSha256` and no `sizeBytes` — a
//!    tombstone that named the version would hand the refused caller the two values needed to ask
//!    for the bytes by another route.
//! 3. **Against a positive control.** A second file in the same library, same caller, same request,
//!    with the `file.sync` grant intact, comes back as an eligible `UPSERT` carrying all three. An
//!    absence proves nothing without one.
//!
//! # The chain here is the real one
//!
//! The authorization stage is [`PgAclAuthorization`] over real `acl_entries` rows, not a stub.
//! Download and sync are only *separately* deniable if something actually resolves two different
//! actions differently, and a stub that answered one question for every action would make every
//! assertion in this file vacuous.
//!
//! # Which layer each cross-tenant assertion proves
//!
//! Stated per test, because in this repository it has been got wrong six times. Removing a
//! `tenant_id` predicate from a statement has **failed to fail** in six separate crates, because
//! row-level security holds the property on its own. So:
//!
//! * [`another_tenants_library_is_not_found`] proves **tenant isolation** — the engine's stage-1
//!   comparison and RLS beneath it. It says nothing about the authorization stage.
//! * [`a_caller_in_the_same_tenant_without_the_grant_is_not_found`] proves the **authorization
//!   stage**, because both caller and resource are in one tenant and RLS has nothing to say.
//!
//! Ignored by default: they need a live PostgreSQL. CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration as StdDuration;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{sync, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, ContainerAction, FileAction, FileId, LibraryId, PolicyEngine, TenantId,
    UserId, VersionId, WorkspaceId,
};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, ObjectMeta, PublicAccessCheck, PublicAccessError,
    PublicAccessReport, Result as StorageResult, StorageError, StoreCapabilities, Support,
    UploadRequest, UploadSession,
};
use enclave_testing::TestDb;
use sqlx::PgConnection;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// A store that must never be reached by a delta.
// ---------------------------------------------------------------------------------------------

/// A [`BlobStore`] that panics on anything that would hand over original bytes.
///
/// A delta hands over metadata; it must not mint a URL or read a byte, and making that a panic
/// rather than a counter is the strongest available statement — there is no assertion to forget.
///
/// `create_upload` is the deliberate exception and returns an **error** instead. `POST /sync/reserve`
/// is entitled to begin one, so a panic there would abort the test rather than let it observe what
/// the endpoint decided; an error lets every refusal *above* the store be asserted on its own status
/// while still guaranteeing that no reservation ever completes into real storage.
#[derive(Debug)]
struct ForbiddenStore;

#[async_trait]
impl PublicAccessCheck for ForbiddenStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for ForbiddenStore {
    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        Err(StorageError::Unsupported { capability: "create_upload" })
    }
    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        panic!("a delta must never complete an upload")
    }
    async fn signed_download(&self, key: &str, _ttl: StdDuration) -> StorageResult<Url> {
        panic!("a delta must never mint a signed URL; it did for {key}")
    }
    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        panic!("a delta must never read original bytes; it did for {key}")
    }
    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        panic!("a delta must never copy an object")
    }
    async fn delete(&self, _key: &str) -> StorageResult<()> {
        panic!("a delta must never delete an object")
    }
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "forbidden-stub",
            multipart: None,
            signed_urls: true,
            single_use_signed_urls: false,
            max_signed_url_ttl: StdDuration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: true,
            server_side_copy: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A tenant, a user, a workspace and a library that permits sync.
#[derive(Debug, Clone, Copy)]
struct Tenant {
    id: TenantId,
    user: UserId,
    workspace: WorkspaceId,
    library: LibraryId,
}

impl Tenant {
    fn new() -> Self {
        Self {
            id: TenantId::new_v7(),
            user: UserId::new_v7(),
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
        }
    }

    fn scope(self) -> String {
        format!("library:{}", self.library.as_uuid())
    }

    async fn insert(self, conn: &mut PgConnection, sync_enabled: bool) {
        let now = fixed_time();
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'fixture', 'ACTIVE', $3, $3)",
        )
        .bind(self.id.as_uuid())
        .bind(format!("t-{}", self.id.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert tenant");

        sqlx::query(
            "INSERT INTO users
               (id, tenant_id, email, normalized_email, display_name, status, source,
                created_at, updated_at)
             VALUES ($1, $2, $3, $3, 'Fixture', 'ACTIVE', 'LOCAL', $4, $4)",
        )
        .bind(self.user.as_uuid())
        .bind(self.id.as_uuid())
        .bind(format!("{}@example.test", self.user.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert user");

        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.id.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(self.user.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, sync_enabled, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $6, $6)",
        )
        .bind(self.library.as_uuid())
        .bind(self.id.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(sync_enabled)
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert library");
    }
}

/// One file with one version, in whatever scan state the test needs.
#[derive(Debug, Clone, Copy)]
struct Doc {
    file: FileId,
    version: VersionId,
}

impl Doc {
    fn new() -> Self {
        Self { file: FileId::new_v7(), version: VersionId::new_v7() }
    }

    async fn insert(self, conn: &mut PgConnection, tenant: Tenant, status: &str, av: &str) {
        let now = fixed_time();
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, node_type, name, normalized_name,
                mime_type, current_version_id, size_bytes, inherit_permissions, status,
                created_by, modified_by, created_at, modified_at)
             VALUES ($1, $2, $3, $4, 'FILE', $5, $5, 'application/pdf', $6, 1024, TRUE,
                     'AVAILABLE', $7, $7, $8, $8)",
        )
        .bind(self.file.as_uuid())
        .bind(tenant.id.as_uuid())
        .bind(tenant.workspace.as_uuid())
        .bind(tenant.library.as_uuid())
        .bind(self.file.as_uuid().to_string())
        .bind(self.version.as_uuid())
        .bind(tenant.user.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert file");

        sqlx::query(
            "INSERT INTO file_versions
               (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes,
                checksum_sha256, mime_type, major, minor, status, av_status, encryption_mode,
                created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, 1024, $6, 'application/pdf', 1, 0, $7, $8, 'PROVIDER',
                     $9, $10)",
        )
        .bind(self.version.as_uuid())
        .bind(tenant.id.as_uuid())
        .bind(self.file.as_uuid())
        .bind(format!("{}/{}", tenant.id.as_uuid(), self.version.as_uuid()))
        .bind(Uuid::now_v7())
        .bind("b".repeat(64))
        .bind(status)
        .bind(av)
        .bind(tenant.user.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert version");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Writes one ACL entry, using `Action`'s own rendering — the same string the resolver reads.
async fn ace(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource: Uuid,
    user: UserId,
    action: Action,
    effect: &str,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at)
         VALUES ($1, $2, $3, $4, 'USER', $5, $6, $7, $8, $9)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource)
    .bind(user.as_uuid())
    .bind(action.to_string())
    .bind(effect)
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Grants the library-level actions a syncing caller needs, all as `ALLOW`.
///
/// Granted on the **library**, so they inherit down to every file in it. That is what lets a test
/// remove exactly one action on exactly one file with a `DENY` and have everything else hold.
async fn grant_library(conn: &mut PgConnection, tenant: Tenant, user: UserId) {
    for action in [
        Action::Container(ContainerAction::Read),
        Action::File(FileAction::MetadataRead),
        Action::File(FileAction::Download),
        Action::File(FileAction::Sync),
    ] {
        ace(conn, tenant.id, "LIBRARY", tenant.library.as_uuid(), user, action, "ALLOW").await;
    }
}

/// Builds the sync routes over a real chain.
async fn app(db: &TestDb) -> (Router, PrivateSigningKey) {
    let pool = db.pool_with_connections(6).await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        // The real resolver over real rows: download and sync must be answered separately.
        Arc::new(PgAclAuthorization::new(pool.clone())),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    let store: Arc<dyn BlobStore> = Arc::new(ForbiddenStore);

    let router = Router::new()
        .route("/api/v1/sync/delta", get(sync::delta))
        .route("/api/v1/sync/devices", get(sync::list_devices).post(sync::register_device))
        .route("/api/v1/sync/devices/{id}/wipe", post(sync::wipe_device))
        .route("/api/v1/sync/reserve", post(sync::reserve))
        .layer(Extension(store))
        .with_state(state);

    (router, key)
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

/// One response.
struct Answer {
    status: StatusCode,
    body: String,
}

impl Answer {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| {
            panic!("a JSON body was expected, got `{}`: {error}", self.body)
        })
    }

    /// The entry for one file, or `None` when the delta omitted it entirely.
    fn entry(&self, file: FileId) -> Option<serde_json::Value> {
        self.json()["entries"]
            .as_array()
            .expect("entries is an array")
            .iter()
            .find(|entry| entry["fileId"] == serde_json::json!(file.to_string()))
            .cloned()
    }
}

async fn get_delta(router: &Router, token: &str, query: &str) -> Answer {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/sync/delta?{query}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");
    let response = router.clone().oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.expect("body");
    Answer { status, body: String::from_utf8_lossy(&bytes).into_owned() }
}

async fn post_reserve(router: &Router, token: &str, body: serde_json::Value) -> Answer {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/sync/reserve")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = router.clone().oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.expect("body");
    Answer { status, body: String::from_utf8_lossy(&bytes).into_owned() }
}

// ---------------------------------------------------------------------------------------------
// Rule 6
// ---------------------------------------------------------------------------------------------

/// **The row this file exists for.** `CLAUDE.md` rule 6, `docs/10 §1`, `docs/12 §4.2`.
///
/// One caller, one request, two files. The only difference between them is a `DENY` on
/// `file.sync` for one of them; `file.download` is untouched on both. The refused file must come
/// back as a tombstone naming `ACCESS_REVOKED` and carrying nothing that could be used to fetch the
/// bytes, and the other must come back eligible — which is what proves the refusal came from the
/// sync answer and not from something refusing everybody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_who_may_download_but_not_sync_is_refused_the_content() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;

    let syncable = Doc::new();
    let refused = Doc::new();
    let pool = db.pool_with_connections(2).await.expect("pool");
    for doc in [syncable, refused] {
        // Written through the application pool so the change-feed trigger runs under RLS, exactly
        // as it does in the binary.
        let mut tx = pool.begin(tenant.id).await.expect("begin");
        doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
        tx.commit().await.expect("commit");
    }

    grant_library(&mut conn, tenant, tenant.user).await;
    // The single difference. `DENY` wins over an inherited `ALLOW` anywhere in the chain
    // (`docs/04 §9` rule 3), so this caller keeps `file.download` on this file and loses
    // `file.sync` on it alone.
    ace(
        &mut conn,
        tenant.id,
        "FILE",
        refused.file.as_uuid(),
        tenant.user,
        Action::File(FileAction::Sync),
        "DENY",
    )
    .await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);
    let answer = get_delta(&router, &token, &format!("scope={}", tenant.scope())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);

    // The positive control, first: with the grant intact the file is eligible and carries the
    // checksum a client needs to fetch it.
    let allowed = answer.entry(syncable.file).expect("the syncable file is missing from the delta");
    assert_eq!(allowed["op"], "UPSERT", "{allowed}");
    assert_eq!(allowed["syncEligible"], true, "{allowed}");
    assert_eq!(allowed["versionId"], serde_json::json!(syncable.version.to_string()));
    assert!(allowed["checksumSha256"].is_string(), "{allowed}");

    // The assertion.
    let denied = answer
        .entry(refused.file)
        .expect("a file the caller may see but not sync must be tombstoned, not omitted");
    assert_eq!(
        denied["op"], "TOMBSTONE",
        "a caller holding file.download and not file.sync was offered the content: {denied}"
    );
    assert_eq!(denied["syncEligible"], false, "{denied}");
    assert_eq!(denied["reason"], "ACCESS_REVOKED", "{denied}");
    assert!(
        denied["versionId"].is_null(),
        "the tombstone named the version, which is half of what is needed to fetch it: {denied}"
    );
    assert!(denied["checksumSha256"].is_null(), "the tombstone carried the checksum: {denied}");
    assert!(denied["sizeBytes"].is_null(), "{denied}");
}

/// `CLAUDE.md` rule 9. A sync is a read path and no read path serves `SCANNING` content.
///
/// The pair again: the same caller, the same grants, two files differing only in `av_status`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unscanned_version_is_never_offered_to_a_device() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let clean = Doc::new();
    let scanning = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    clean.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    scanning.insert(&mut tx, tenant, "SCANNING", "PENDING").await;
    tx.commit().await.expect("commit");

    grant_library(&mut conn, tenant, tenant.user).await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);
    let answer = get_delta(&router, &token, &format!("scope={}", tenant.scope())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);

    let served = answer.entry(clean.file).expect("the clean file");
    assert_eq!(served["syncEligible"], true, "the positive control is not eligible: {served}");

    let withheld = answer.entry(scanning.file).expect("the scanning file");
    assert_eq!(
        withheld["op"], "TOMBSTONE",
        "unscanned content was offered to a device: {withheld}"
    );
    assert_eq!(withheld["reason"], "QUARANTINED", "{withheld}");
    assert!(withheld["checksumSha256"].is_null(), "{withheld}");
}

/// A file the caller may not read at all is **omitted**, not tombstoned.
///
/// A tombstone carries a path. Emitting one per file would make the delta a complete contents
/// listing of the library for a caller who may browse none of it — the cheapest enumeration oracle
/// in the product. The eligible file beside it is what proves the delta is working at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_the_caller_cannot_read_is_omitted_rather_than_named() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let visible = Doc::new();
    let invisible = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    visible.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    invisible.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    grant_library(&mut conn, tenant, tenant.user).await;
    ace(
        &mut conn,
        tenant.id,
        "FILE",
        invisible.file.as_uuid(),
        tenant.user,
        Action::File(FileAction::MetadataRead),
        "DENY",
    )
    .await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);
    let answer = get_delta(&router, &token, &format!("scope={}", tenant.scope())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);

    assert!(answer.entry(visible.file).is_some(), "the readable file was not served");
    assert!(
        answer.entry(invisible.file).is_none(),
        "a file the caller may not read appeared in the delta: {}",
        answer.body
    );
    // And its name is nowhere in the response, not merely absent from the `fileId` field. The
    // fixture names each file after its id, so searching the whole body is a real check.
    assert!(
        !answer.body.contains(&invisible.file.as_uuid().to_string()),
        "the omitted file's name leaked into the response: {}",
        answer.body
    );
}

/// A library whose `sync_enabled` is `false` explains itself once, per file.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_with_sync_disabled_tombstones_its_contents_with_a_reason() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, false).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let doc = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");
    grant_library(&mut conn, tenant, tenant.user).await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);
    let answer = get_delta(&router, &token, &format!("scope={}", tenant.scope())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);

    let entry = answer.entry(doc.file).expect("the file");
    assert_eq!(entry["op"], "TOMBSTONE", "{entry}");
    assert_eq!(
        entry["reason"], "LIBRARY_SYNC_DISABLED",
        "the client cannot show \"available on the web only\" without the reason: {entry}"
    );
}

// ---------------------------------------------------------------------------------------------
// Isolation — each test says which layer it proves
// ---------------------------------------------------------------------------------------------

/// **Proves tenant isolation.** `CLAUDE.md` rule 7, `docs/12 §4.1` T1.
///
/// Alpha asks for beta's library by id and is told it does not exist. What holds this is the
/// engine's stage-1 `ctx.tenant_id != resource.tenant_id` comparison — no, in fact not even that:
/// the resource is built with *alpha's* tenant and beta's library id, so the comparison passes and
/// the ACL walk simply finds nothing, because row-level security made beta's library invisible to
/// alpha's transaction.
///
/// **This test does not prove the application predicate.** Deleting a `tenant_id` from a statement
/// in `crates/sync` leaves it green, because RLS holds the property alone — which is exactly what
/// has happened six times in this repository. For the authorization layer, see the test below.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_library_is_not_found() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let alpha = Tenant::new();
    let beta = Tenant::new();
    alpha.insert(&mut conn, true).await;
    beta.insert(&mut conn, true).await;

    let pool = db.pool_with_connections(2).await.expect("pool");
    let doc = Doc::new();
    let mut tx = pool.begin(beta.id).await.expect("begin");
    doc.insert(&mut tx, beta, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    // Beta's user is fully granted, so the only thing standing between alpha and the content is
    // the tenant boundary.
    grant_library(&mut conn, beta, beta.user).await;
    grant_library(&mut conn, alpha, alpha.user).await;

    let (router, key) = app(&db).await;

    let intruder = token(&key, alpha.id, alpha.user);
    let answer = get_delta(&router, &intruder, &format!("scope={}", beta.scope())).await;
    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "a cross-tenant scope must be indistinguishable from an absent one; got {}: {}",
        answer.status,
        answer.body
    );
    assert!(
        !answer.body.contains(&doc.file.as_uuid().to_string()),
        "the response named another tenant's file: {}",
        answer.body
    );

    // The positive control: beta's own user gets the content, so the `404` above is the boundary
    // rather than a delta that refuses everyone.
    let owner = token(&key, beta.id, beta.user);
    let own = get_delta(&router, &owner, &format!("scope={}", beta.scope())).await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert!(own.entry(doc.file).is_some(), "beta cannot read its own library: {}", own.body);
}

/// **Proves the authorization stage.**
///
/// The caller and the library are in **one tenant**, so row-level security has nothing to say: both
/// rows are visible to the transaction. The only thing that can refuse is the ACL walk finding no
/// grant — and the refusal must be `404` rather than `403`, because a `403` confirms the library
/// exists (`CLAUDE.md` rule 7).
///
/// This is the test the module header promises. It is the one that fails if the authorization stage
/// is removed, and the cross-tenant test above is not.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_in_the_same_tenant_without_the_grant_is_not_found() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;

    // A second user in the same tenant, with no grants at all.
    let stranger = UserId::new_v7();
    sqlx::query(
        "INSERT INTO users
           (id, tenant_id, email, normalized_email, display_name, status, source,
            created_at, updated_at)
         VALUES ($1, $2, $3, $3, 'Stranger', 'ACTIVE', 'LOCAL', $4, $4)",
    )
    .bind(stranger.as_uuid())
    .bind(tenant.id.as_uuid())
    .bind(format!("{}@example.test", stranger.as_uuid()))
    .bind(fixed_time())
    .execute(&mut conn)
    .await
    .expect("insert the stranger");

    let pool = db.pool_with_connections(2).await.expect("pool");
    let doc = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");
    grant_library(&mut conn, tenant, tenant.user).await;

    let (router, key) = app(&db).await;

    let refused = token(&key, tenant.id, stranger);
    let answer = get_delta(&router, &refused, &format!("scope={}", tenant.scope())).await;
    assert_eq!(
        answer.status,
        StatusCode::NOT_FOUND,
        "a same-tenant caller with no grant was answered {} rather than 404. RLS cannot help here \
         — both rows are visible to the transaction — so this is the authorization stage, and a \
         403 would confirm the library exists. Body: {}",
        answer.status,
        answer.body
    );
    assert!(
        !answer.body.contains(&doc.file.as_uuid().to_string()),
        "the refusal named the content: {}",
        answer.body
    );

    // The positive control: the granted user in the same tenant is served.
    let allowed = token(&key, tenant.id, tenant.user);
    let served = get_delta(&router, &allowed, &format!("scope={}", tenant.scope())).await;
    assert_eq!(served.status, StatusCode::OK, "{}", served.body);
    assert!(served.entry(doc.file).is_some());
}

// ---------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------

/// A malformed scope, a malformed cursor and a nonsense limit are refused in the one envelope
/// `docs/05-API.md §5` defines, naming the field.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn malformed_parameters_are_refused_in_the_documented_envelope() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    grant_library(&mut conn, tenant, tenant.user).await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);

    for (query, field) in [
        ("", "scope"),
        ("scope=notascope", "scope"),
        ("scope=folder:01937f00-0000-7000-8000-000000000000", "scope"),
    ] {
        let answer = get_delta(&router, &token, query).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "`{query}`: {}", answer.body);
        assert_eq!(answer.json()["error"]["code"], "VALIDATION_FAILED", "{}", answer.body);
        assert!(answer.body.contains(field), "the refusal did not name `{field}`: {}", answer.body);
    }

    let scope = tenant.scope();
    for query in [format!("scope={scope}&cursor=-1"), format!("scope={scope}&cursor=abc")] {
        let answer = get_delta(&router, &token, &query).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "`{query}`: {}", answer.body);
        assert!(answer.body.contains("cursor"), "{}", answer.body);
    }

    let answer = get_delta(&router, &token, &format!("scope={scope}&limit=0")).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.body);
    assert!(answer.body.contains("limit"), "{}", answer.body);

    // The positive control: the same scope with valid parameters is served, so the refusals above
    // are about the parameters rather than about the fixture.
    let ok = get_delta(&router, &token, &format!("scope={scope}&cursor=0&limit=10")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

/// A cursor the feed cannot reach is `410 CURSOR_TOO_OLD`, and the client is told to re-enumerate.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_cursor_the_feed_cannot_reach_is_gone() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    grant_library(&mut conn, tenant, tenant.user).await;

    let pool = db.pool_with_connections(2).await.expect("pool");
    let doc = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);
    let scope = tenant.scope();

    let answer = get_delta(&router, &token, &format!("scope={scope}&cursor=9999")).await;
    assert_eq!(answer.status, StatusCode::GONE, "{}", answer.body);
    assert_eq!(answer.json()["error"]["code"], "CURSOR_TOO_OLD", "{}", answer.body);

    // The positive control: a cursor the feed *can* reach is served.
    let ok = get_delta(&router, &token, &format!("scope={scope}&cursor=0")).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

// ---------------------------------------------------------------------------------------------
// Reserve
// ---------------------------------------------------------------------------------------------

/// Rule 6 on the **write** side: `file.edit` does not carry `file.sync`.
///
/// The same caller may edit this file through the web client. What they may not do is push a change
/// from a device, and `POST /sync/reserve` is where that is decided — before a single URL is issued,
/// which is why the store beside it panics on every method.
///
/// The positive control is the second file: identical grants, no `DENY`, and the reservation gets
/// past the policy chain to the version comparison (a `409`, because the fixture declares no base
/// version while the file has one). Reaching a `409` is the proof that the `403` above came from
/// the sync answer and not from a chain that refuses everybody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_caller_who_may_edit_but_not_sync_cannot_reserve_an_upload() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let refused = Doc::new();
    let permitted = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    refused.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    permitted.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    grant_library(&mut conn, tenant, tenant.user).await;
    ace(
        &mut conn,
        tenant.id,
        "LIBRARY",
        tenant.library.as_uuid(),
        tenant.user,
        Action::File(FileAction::Edit),
        "ALLOW",
    )
    .await;
    // The single difference, again.
    ace(
        &mut conn,
        tenant.id,
        "FILE",
        refused.file.as_uuid(),
        tenant.user,
        Action::File(FileAction::Sync),
        "DENY",
    )
    .await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);

    let denied = post_reserve(
        &router,
        &token,
        serde_json::json!({
            "fileId": refused.file.to_string(),
            "baseVersionId": refused.version.to_string(),
            "sizeBytes": 1024,
            // Required since `ENC-820`. Without it the body is refused as malformed at 422
            // and the request never reaches the policy chain — which makes a test that
            // asserts a *refusal* pass for the wrong reason, and one that asserts an allow
            // fail for a reason that has nothing to do with what it is testing.
            "checksumSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }),
    )
    .await;
    assert_eq!(
        denied.status,
        StatusCode::FORBIDDEN,
        "a caller holding file.edit and not file.sync was allowed to reserve an upload from a \
         device: {}",
        denied.body
    );

    // The positive control: the same request against the file with the grant intact gets past the
    // chain and is refused for a *protocol* reason instead.
    let stale = post_reserve(
        &router,
        &token,
        serde_json::json!({
            "fileId": permitted.file.to_string(),
            "sizeBytes": 1024,
            // Required since `ENC-820`. Without it the body is refused as malformed at 422
            // and the request never reaches the policy chain — which makes a test that
            // asserts a *refusal* pass for the wrong reason, and one that asserts an allow
            // fail for a reason that has nothing to do with what it is testing.
            "checksumSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }),
    )
    .await;
    assert_eq!(
        stale.status,
        StatusCode::CONFLICT,
        "the positive control did not reach the version comparison, so the 403 above proves \
         nothing about the sync grant: {}",
        stale.body
    );
}

/// A stale `baseVersionId` is `409` and names the version the server holds (`docs/10 §6`).
///
/// Without `currentVersionId` in the payload the client has to make a second call to discover what
/// it is conflicting with — a round trip on the one path already carrying a user's unsaved work.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stale_base_version_conflicts_and_names_what_the_server_holds() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let doc = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    grant_library(&mut conn, tenant, tenant.user).await;
    ace(
        &mut conn,
        tenant.id,
        "LIBRARY",
        tenant.library.as_uuid(),
        tenant.user,
        Action::File(FileAction::Edit),
        "ALLOW",
    )
    .await;

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);

    let conflict = post_reserve(
        &router,
        &token,
        serde_json::json!({
            "fileId": doc.file.to_string(),
            "baseVersionId": VersionId::new_v7().to_string(),
            "sizeBytes": 1024,
            // Required since `ENC-820`. Without it the body is refused as malformed at 422
            // and the request never reaches the policy chain — which makes a test that
            // asserts a *refusal* pass for the wrong reason, and one that asserts an allow
            // fail for a reason that has nothing to do with what it is testing.
            "checksumSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT, "{}", conflict.body);
    assert_eq!(conflict.json()["error"]["code"], "CONFLICT", "{}", conflict.body);
    assert!(
        conflict.body.contains(&doc.version.to_string()),
        "the conflict did not name the version the server holds, so the client must make a second \
         call to find out: {}",
        conflict.body
    );
}

/// A file under an editor lock is read-only to sync (`docs/10 §6`), and the holder is not named.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_locked_file_is_read_only_to_a_sync_client() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");
    let tenant = Tenant::new();
    tenant.insert(&mut conn, true).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let doc = Doc::new();
    let mut tx = pool.begin(tenant.id).await.expect("begin");
    doc.insert(&mut tx, tenant, "AVAILABLE", "CLEAN").await;
    tx.commit().await.expect("commit");

    grant_library(&mut conn, tenant, tenant.user).await;
    ace(
        &mut conn,
        tenant.id,
        "LIBRARY",
        tenant.library.as_uuid(),
        tenant.user,
        Action::File(FileAction::Edit),
        "ALLOW",
    )
    .await;

    let holder = UserId::new_v7();
    sqlx::query(
        "INSERT INTO file_locks (tenant_id, file_id, kind, holder_id, acquired_at)
         VALUES ($1, $2, 'EDITOR', $3, $4)",
    )
    .bind(tenant.id.as_uuid())
    .bind(doc.file.as_uuid())
    .bind(holder.as_uuid())
    .bind(fixed_time())
    .execute(&mut conn)
    .await
    .expect("take the lock");

    let (router, key) = app(&db).await;
    let token = token(&key, tenant.id, tenant.user);

    let locked = post_reserve(
        &router,
        &token,
        serde_json::json!({
            "fileId": doc.file.to_string(),
            "baseVersionId": doc.version.to_string(),
            "sizeBytes": 1024,
            // Required since `ENC-820`. Without it the body is refused as malformed at 422
            // and the request never reaches the policy chain — which makes a test that
            // asserts a *refusal* pass for the wrong reason, and one that asserts an allow
            // fail for a reason that has nothing to do with what it is testing.
            "checksumSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }),
    )
    .await;
    assert_eq!(locked.status, StatusCode::LOCKED, "{}", locked.body);
    assert_eq!(locked.json()["error"]["code"], "EDITOR_LOCK", "{}", locked.body);
    assert!(
        !locked.body.contains(&holder.as_uuid().to_string()),
        "the refusal named the lock holder, which is a directory fact about another user this \
         endpoint took no decision about disclosing: {}",
        locked.body
    );

    // The positive control: release the lock and the same request reaches the reservation, where
    // the fixture's store refuses it — proving the 423 above was the lock and not the grants.
    sqlx::query("DELETE FROM file_locks WHERE tenant_id = $1 AND file_id = $2")
        .bind(tenant.id.as_uuid())
        .bind(doc.file.as_uuid())
        .execute(&mut conn)
        .await
        .expect("release the lock");

    let unlocked = post_reserve(
        &router,
        &token,
        serde_json::json!({
            "fileId": doc.file.to_string(),
            "baseVersionId": VersionId::new_v7().to_string(),
            "sizeBytes": 1024,
            // Required since `ENC-820`. Without it the body is refused as malformed at 422
            // and the request never reaches the policy chain — which makes a test that
            // asserts a *refusal* pass for the wrong reason, and one that asserts an allow
            // fail for a reason that has nothing to do with what it is testing.
            "checksumSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        }),
    )
    .await;
    assert_eq!(
        unlocked.status,
        StatusCode::CONFLICT,
        "releasing the lock did not change the answer, so the 423 was not about the lock: {}",
        unlocked.body
    );
}
