//! Delivery — preview and download, and the line between them.
//!
//! `docs/12-TESTING.md §4.2` A1 is the row this file exists for:
//!
//! > `preview=ALLOW, download=DENY` yields a rendition and **no** signed original URL.
//!
//! It is asserted three ways, because a status code alone would pass on a `200` whose body carried
//! an S3 URL:
//!
//! 1. **On the body.** Every response is parsed and searched for a URL and for the object key.
//! 2. **On the store.** [`CountingStore`] records every call that could produce or move original
//!    bytes — `signed_download` and `read_range` — and the assertion is that the list is *empty*.
//!    `docs/02-HLD.md §16` says a signed URL is never *generated* under a no-download policy, not
//!    that it is generated and withheld, and the difference is only observable from the store's
//!    side.
//! 3. **On the audit log.** A denial leaves a `DENY` row, because a control that refuses silently
//!    is a control nobody can prove ran (`CLAUDE.md` rule 10).
//!
//! # Why the policy chain here is the real one
//!
//! The authorization stage is [`PgAclAuthorization`] against real `acl_entries` rows, not the
//! self-service stub `tests/me.rs` uses. Preview and download are only *separately* deniable if
//! something actually resolves two different actions differently, and a stub that answers one
//! question for every action would make every assertion in this file vacuous.
//!
//! # Why they are ignored by default
//!
//! They need a live PostgreSQL with migrations `0004`, `0005` and `0006` applied. CI runs them with
//! `--include-ignored` against the service container in `.github/workflows/ci.yml`. **No object
//! storage is required**: the store here is a fake, on purpose — the property under test is which
//! calls are made, and a real S3 can only show which calls succeeded.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration as StdDuration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{download, preview, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, DlpService, FileAction, FileId, LibraryId, Obligation, Obligations,
    PolicyEngine, RequestContext, ResourceRef, Result as CoreResult, StageDecision, TenantId,
    UserId, VersionId, WorkspaceId,
};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StorageError,
    StoreCapabilities, Support, UploadRequest, UploadSession,
};
use enclave_testing::TestDb;
use sqlx::PgConnection;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

// ---------------------------------------------------------------------------------------------
// A store that records every request for original bytes.
// ---------------------------------------------------------------------------------------------

/// A [`BlobStore`] that never returns real bytes and remembers everything it was asked for.
///
/// The two members that matter are [`BlobStore::signed_download`] — the only way to obtain an
/// original object URL — and [`BlobStore::read_range`], the only way to stream original bytes
/// through this process. A preview implementation that "temporarily" served the original would
/// reach one of them, and every assertion below would fail.
#[derive(Debug, Default)]
struct CountingStore {
    touched: Mutex<Vec<String>>,
}

impl CountingStore {
    /// Every key the store was asked to expose, in order.
    fn touched(&self) -> Vec<String> {
        self.touched.lock().expect("lock").clone()
    }

    fn record(&self, key: &str) {
        self.touched.lock().expect("lock").push(key.to_owned());
    }
}

#[async_trait]
impl PublicAccessCheck for CountingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for CountingStore {
    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        panic!("a delivery path must never begin an upload")
    }

    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        panic!("a delivery path must never complete an upload")
    }

    async fn signed_download(&self, key: &str, ttl: StdDuration) -> StorageResult<Url> {
        // Asserted here rather than only at the call site: a TTL is a revocation window, and a
        // pre-signed URL has no other one (`plans/M1-CONTENT-CORE.md` D14).
        assert!(
            ttl <= StdDuration::from_secs(120),
            "a signed URL must be short-lived, got {ttl:?}"
        );
        self.record(key);
        Ok(Url::parse("https://store.invalid/blob").expect("url"))
    }

    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        self.record(key);
        Err(StorageError::NotFound { key: key.to_owned() })
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        panic!("a delivery path must never copy an object")
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        panic!("a delivery path must never delete an object")
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "counting-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: 5 * 1024 * 1024,
                max_part_bytes: 5 * 1024 * 1024 * 1024,
                max_parts: 10_000,
            }),
            signed_urls: true,
            // As every S3-compatible backend reports it, and as the response must therefore say.
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
// A DLP stage that attaches the obligations this feature exists to honour.
// ---------------------------------------------------------------------------------------------

/// Allows every action but attaches `NO_DOWNLOAD` to a download and `WATERMARK` to a preview.
///
/// This is the shape of the policy `docs/01-PRD.md §18` describes when it arrives from DLP rather
/// than from an ACL: the chain *allows*, and the obligation is what must stop the bytes. A handler
/// that dropped it would pass every ACL-based test in this file.
#[derive(Debug)]
struct ObligingDlp;

#[async_trait]
impl DlpService for ObligingDlp {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        action: Action,
        _resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        let mut obligations = Obligations::none();
        match action {
            Action::File(FileAction::Download) => {
                let _new = obligations.insert(Obligation::NoDownload);
            }
            Action::File(FileAction::Preview) => {
                let _new = obligations.insert(Obligation::Watermark);
            }
            _ => {}
        }
        Ok(StageDecision::allow_with(obligations))
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

/// A workspace, a library, a file and one version of it.
#[derive(Debug, Clone)]
struct Content {
    tenant: TenantId,
    owner: UserId,
    workspace: WorkspaceId,
    library: LibraryId,
    file: FileId,
    version: VersionId,
    object_key: String,
}

impl Content {
    fn new(tenant: TenantId, owner: UserId) -> Self {
        let version = VersionId::new_v7();
        Self {
            tenant,
            owner,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            file: FileId::new_v7(),
            version,
            object_key: format!("{tenant}/{version}"),
        }
    }

    /// Writes the spine and one version in the given state.
    ///
    /// `status`/`av` are parameters rather than constants because "the version antivirus has not
    /// cleared" is one of the cases under test, and a fixture that could only build clean content
    /// could not express it.
    async fn insert(&self, conn: &mut PgConnection, status: &str, av: &str) {
        let now = fixed_time();

        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(self.owner.as_uuid())
        .bind(now)
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
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert library");

        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, node_type, name, normalized_name,
                mime_type, current_version_id, size_bytes, inherit_permissions, status,
                created_by, modified_by, created_at, modified_at)
             VALUES ($1, $2, $3, $4, 'FILE', 'report.pdf', 'report.pdf', 'application/pdf',
                     $5, 1024, TRUE, 'AVAILABLE', $6, $6, $7, $7)",
        )
        .bind(self.file.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(self.version.as_uuid())
        .bind(self.owner.as_uuid())
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
        .bind(self.tenant.as_uuid())
        .bind(self.file.as_uuid())
        .bind(&self.object_key)
        .bind(Uuid::now_v7())
        .bind("0".repeat(64))
        .bind(status)
        .bind(av)
        .bind(self.owner.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert version");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Writes one ACL entry for one action on the file.
async fn grant(
    conn: &mut PgConnection,
    content: &Content,
    user: UserId,
    action: FileAction,
    effect: &str,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at)
         VALUES ($1, $2, 'FILE', $3, 'USER', $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::new_v4())
    .bind(content.tenant.as_uuid())
    .bind(content.file.as_uuid())
    .bind(user.as_uuid())
    // `file.preview`, `file.download` — `Action`'s own stable rendering, which is also what the
    // audit row carries. One vocabulary, so a denial can be explained from the log alone.
    .bind(Action::File(action).to_string())
    .bind(effect)
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Builds the delivery routes over a real chain and the counting store.
///
/// The routes are registered here rather than taken from `enclave_api::router`, because this suite
/// is about two endpoints and should fail for reasons that belong to them.
async fn app(
    db: &TestDb,
    dlp: Arc<dyn DlpService>,
) -> (Router, PrivateSigningKey, Arc<CountingStore>) {
    let pool = db.pool().await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");
    let store = Arc::new(CountingStore::default());

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        // The real resolver, over real rows: preview and download must be answered separately.
        Arc::new(PgAclAuthorization::new(pool.clone())),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        dlp,
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));

    let blob: Arc<dyn BlobStore> = store.clone();
    let router = Router::new()
        .route("/api/v1/files/{id}/download", post(download::download))
        .route("/api/v1/files/{id}/preview", get(preview::preview))
        .layer(Extension(blob))
        .with_state(state);

    (router, key, store)
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

/// One response, as both a status and a body.
struct Answer {
    status: StatusCode,
    cache_control: Option<String>,
    body: String,
}

impl Answer {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("a JSON body")
    }

    /// Asserts that nothing in the response could be followed to the original bytes.
    ///
    /// The whole body is searched as text rather than field by field: a URL that leaked through a
    /// field nobody thought to check is exactly the failure this is for.
    fn carries_no_original(&self, content: &Content) {
        assert!(
            !self.body.contains("http://") && !self.body.contains("https://"),
            "a response on a denied or unimplemented delivery path must carry no URL: {}",
            self.body
        );
        assert!(
            !self.body.contains(&content.object_key),
            "a response must never carry an object key: {}",
            self.body
        );
    }
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let cache_control = response
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("body");
    Answer { status, cache_control, body: String::from_utf8_lossy(&body).into_owned() }
}

async fn get_preview(app: &Router, bearer: &str, file: FileId) -> Answer {
    let request = Request::builder()
        .uri(format!("/api/v1/files/{}/preview", file.as_uuid()))
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("request");
    send(app, request).await
}

async fn post_download(app: &Router, bearer: &str, file: FileId) -> Answer {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/files/{}/download", file.as_uuid()))
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("request");
    send(app, request).await
}

/// Counts audit rows for one action and outcome.
async fn audited(db: &TestDb, action: &str, outcome: &str) -> i64 {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(&mut conn)
        .await
        .expect("count audit rows")
}

// ---------------------------------------------------------------------------------------------
// A1 — the row this file exists for.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn preview_allowed_and_download_denied_yields_a_rendition_path_and_no_signed_url() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    grant(&mut admin, &content, user, FileAction::MetadataRead, "ALLOW").await;
    grant(&mut admin, &content, user, FileAction::Preview, "ALLOW").await;
    // Explicit, not merely absent: A1 is about a DENY, and deny-wins is a different code path from
    // nothing-matched.
    grant(&mut admin, &content, user, FileAction::Download, "DENY").await;

    let bearer = token(&key, fixtures.alpha.id, user);

    // Preview: allowed by the chain, and answered without the pipeline that does not exist.
    let preview = get_preview(&app, &bearer, content.file).await;
    assert_eq!(
        preview.status,
        StatusCode::NOT_IMPLEMENTED,
        "a permitted preview must not fall back to the original: {}",
        preview.body
    );
    let body = preview.json();
    assert_eq!(body["error"]["code"], "PREVIEW_NOT_IMPLEMENTED");
    assert_eq!(
        body["error"]["details"][0]["servesOriginal"],
        serde_json::Value::Bool(false),
        "the refusal must state that the original is not the fallback"
    );
    assert_eq!(body["error"]["details"][0]["renditionProfile"], "page-png-2x");
    preview.carries_no_original(&content);
    assert_eq!(
        preview.cache_control.as_deref(),
        Some("private, no-store"),
        "a preview response must never be cached (docs/05-API.md §9)"
    );

    // Download: denied, and the body carries no URL — the assertion a status-only test would miss.
    let download = post_download(&app, &bearer, content.file).await;
    assert_eq!(
        download.status,
        StatusCode::FORBIDDEN,
        "an explicit DENY must refuse: {}",
        download.body
    );
    assert_eq!(download.json()["error"]["code"], "ACCESS_DENIED");
    download.carries_no_original(&content);

    // The claim of `docs/02-HLD.md §16`, from the only side that can see it: the URL was never
    // generated. Not generated and withheld — never asked for.
    assert!(
        store.touched().is_empty(),
        "the store must not be reached at all on these two paths, but saw {:?}",
        store.touched()
    );

    // Both decisions are on the record, allow and deny alike.
    assert_eq!(audited(&db, "file.preview", "ALLOW").await, 1);
    assert_eq!(audited(&db, "file.download", "DENY").await, 1);
}

// ---------------------------------------------------------------------------------------------
// The obligation form of the same policy.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn a_no_download_obligation_refuses_before_any_url_is_generated() {
    // Here the ACL *allows* the download. Every stage says yes, and DLP attaches `NO_DOWNLOAD`.
    // The bytes must still not move: an obligation the handler dropped would be indistinguishable
    // from an allow, which is what `PolicyDecision` being `#[must_use]` exists to prevent.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(ObligingDlp)).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    for action in [FileAction::MetadataRead, FileAction::Preview, FileAction::Download] {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    let download = post_download(&app, &bearer, content.file).await;
    assert_eq!(download.status, StatusCode::FORBIDDEN);
    assert_eq!(
        download.json()["error"]["code"],
        "PREVIEW_ONLY",
        "the caller is told they may view but not take away: {}",
        download.body
    );
    download.carries_no_original(&content);

    // The preview of the same file carries a `WATERMARK` obligation, which the rendition pipeline
    // will satisfy. Nothing is rendered yet, so nothing is served unwatermarked.
    let preview = get_preview(&app, &bearer, content.file).await;
    assert_eq!(preview.status, StatusCode::NOT_IMPLEMENTED);
    preview.carries_no_original(&content);

    assert!(
        store.touched().is_empty(),
        "an allowed-with-obligations download must still generate no URL, saw {:?}",
        store.touched()
    );
    // The chain allowed; the handler refused. Both facts are in the log, which is what makes the
    // obligation's effect auditable rather than merely believed.
    assert_eq!(audited(&db, "file.download", "ALLOW").await, 1);
}

// ---------------------------------------------------------------------------------------------
// The permitted path, so that the refusals above are not passing vacuously.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn an_allowed_download_mints_exactly_one_short_lived_url() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    grant(&mut admin, &content, user, FileAction::Download, "ALLOW").await;

    let bearer = token(&key, fixtures.alpha.id, user);
    let download = post_download(&app, &bearer, content.file).await;

    assert_eq!(
        download.status,
        StatusCode::OK,
        "a granted download must succeed: {}",
        download.body
    );
    let body = download.json();
    assert_eq!(body["url"], "https://store.invalid/blob");
    assert_eq!(body["expiresIn"], 120, "docs/05-API.md §9 fixes the default at 120 s");
    assert_eq!(
        body["singleUse"],
        serde_json::Value::Bool(false),
        "the response reports what the provider actually supports, never what we would prefer"
    );
    assert_eq!(
        download.cache_control.as_deref(),
        Some("private, no-store"),
        "a response carrying a signed URL must not be cacheable"
    );

    // Exactly one URL, for exactly this object. One per authorized request (D14) — a handler that
    // pre-minted or cached would show up here as a different count or a different key.
    assert_eq!(store.touched(), vec![content.object_key.clone()]);
}

// ---------------------------------------------------------------------------------------------
// T1 — absence and denial are the same answer.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn a_file_in_another_tenant_is_reported_as_absent_on_both_paths() {
    // `docs/12-TESTING.md §4.1` T1. The token is genuine and alpha's; the file id is beta's. The
    // resource reference is built from the *token's* tenant (`CLAUDE.md` rule 3), so the chain's
    // tenant assertion never fires — what refuses is the ACL resolver finding no chain, and what
    // turns that refusal into a `404` is the second question the handler asks: may this caller read
    // the file's metadata? It may not, so it learns nothing.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let beta = Content::new(fixtures.beta.id, fixtures.beta.owner);
    let mut admin = db.connect().await.expect("admin connection");
    beta.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    // Beta's own owner may do everything with it. None of that reaches an alpha caller.
    for action in [FileAction::MetadataRead, FileAction::Preview, FileAction::Download] {
        grant(&mut admin, &beta, fixtures.beta.owner, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, fixtures.alpha.owner);

    for answer in
        [get_preview(&app, &bearer, beta.file).await, post_download(&app, &bearer, beta.file).await]
    {
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "a cross-tenant id must be indistinguishable from one that does not exist, not a 403: {}",
            answer.body
        );
        answer.carries_no_original(&beta);
    }

    assert!(store.touched().is_empty(), "saw {:?}", store.touched());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn a_caller_who_may_not_see_the_file_is_told_it_does_not_exist() {
    // The same-tenant half of the rule above, and the reason the metadata question is asked rather
    // than every denial being flattened to a `404`: a caller with *no* grant learns nothing, while
    // the A1 caller — who may read the file's metadata and see it in a listing — gets the
    // actionable `403`. Two callers, one file, two different truths, neither of them a leak.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;

    let bearer = token(&key, fixtures.alpha.id, fixtures.alpha.viewer);
    let download = post_download(&app, &bearer, content.file).await;

    assert_eq!(download.status, StatusCode::NOT_FOUND, "{}", download.body);
    assert_eq!(download.json()["error"]["code"], "NOT_FOUND");
    download.carries_no_original(&content);
    assert!(store.touched().is_empty(), "saw {:?}", store.touched());
}

// ---------------------------------------------------------------------------------------------
// Rule 9 — nothing is served before antivirus completes.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn content_that_antivirus_has_not_cleared_is_served_on_neither_path() {
    // Every permission granted; the version is still scanning. `CLAUDE.md` rule 9 is not a
    // permission question, which is why it is checked after the chain has already allowed — and
    // why the answer is `404` rather than "this file is being scanned", which would tell an
    // uploader's colleague that an upload happened.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "SCANNING", "PENDING").await;
    for action in [FileAction::MetadataRead, FileAction::Preview, FileAction::Download] {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    for answer in [
        get_preview(&app, &bearer, content.file).await,
        post_download(&app, &bearer, content.file).await,
    ] {
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.body);
        answer.carries_no_original(&content);
    }

    assert!(
        store.touched().is_empty(),
        "unscanned content must never reach the store, saw {:?}",
        store.touched()
    );
}

// ---------------------------------------------------------------------------------------------
// Authentication precedes the chain.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006; CI runs it with --include-ignored"]
async fn an_unauthenticated_request_reaches_neither_the_chain_nor_the_store() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, _key, store) = app(&db, Arc::new(enclave_dlp::DisabledDlp)).await;

    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;

    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/files/{}/download", content.file.as_uuid()))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("request");
    let answer = send(&app, request).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    answer.carries_no_original(&content);
    assert!(store.touched().is_empty());
    // No authenticated actor, so there is nothing to attribute an audit event to — the same
    // property `tests/me.rs` asserts for `/me`.
    assert_eq!(audited(&db, "file.download", "DENY").await, 0);
}
