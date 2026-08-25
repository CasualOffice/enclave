//! Export, print and thumbnail — the three delivery verbs, and the lines between them.
//!
//! `docs/12-TESTING.md §4.2` A2 is the row this file exists for:
//!
//! > Export, print and copy are each independently deniable.
//!
//! It had no test because it had no surface. `crates/api` registered `download` and `preview` and
//! nothing else, so "independently deniable" was true of the ACL resolver and unobservable from
//! outside — which is the shape of assertion `docs/12-TESTING.md §1.2` warns about: an absence that
//! holds for free.
//!
//! So every refusal here is paired with its positive control, in the same test, over the same
//! database:
//!
//! * a caller with `download` and **not** `export` is refused the export route — and the same
//!   caller with `export` and **not** `download` is served it and refused the download;
//! * a caller with `download` and **not** `print` is refused a print grant — and the converse;
//! * the store's call list is empty on the rendition paths — and the rendition paths return bytes,
//!   so "nothing reached the store" is not passing against a handler that did nothing at all.
//!
//! # Why the policy chain here is the real one
//!
//! [`PgAclAuthorization`] against real `acl_entries` rows. `export`, `print` and `preview` are only
//! *separately* deniable if something actually resolves three different actions differently, and a
//! stub that answered one question for every action would make every assertion in this file vacuous
//! — which is precisely what `crates/api/tests/me.rs`'s self-service stage would have done.
//!
//! # Why they are ignored by default
//!
//! They need a live PostgreSQL with the content and audit migrations applied. CI runs them with
//! `--include-ignored`. **No object storage is required**: the store is a fake on purpose — the
//! property under test is which calls are *made*, and a real S3 can only show which succeeded.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration as StdDuration;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{routes, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ClientType, DlpService, FactsSnapshot, FileAction, FileId, LibraryId, Obligation,
    Obligations, PolicyEngine, RequestContext, ResourceRef, Result as CoreResult, StageDecision,
    TenantId, UserId, VersionId, WorkspaceId,
};
use enclave_preview::{Delivery, PreviewPipeline, RenditionProfile};
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
/// through this process. An export or a thumbnail that "temporarily" served the original would
/// reach one of them.
///
/// It is attached to the router even though none of the three routes under test takes it, because
/// a store nobody can reach proves nothing until it is *there* to be reached.
#[derive(Debug, Default)]
struct CountingStore {
    touched: Mutex<Vec<String>>,
}

impl CountingStore {
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

    async fn signed_download(&self, key: &str, _ttl: StdDuration) -> StorageResult<Url> {
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
// A DLP stage that attaches the obligations these routes exist to honour.
// ---------------------------------------------------------------------------------------------

/// Allows everything and attaches one obligation per action.
///
/// This is the shape of the policy `docs/01-PRD.md §18` describes when it arrives from DLP rather
/// than from an ACL: every stage says yes, and the obligation is what must stop the artefact. A
/// handler that dropped it would pass every ACL-based test in this file.
#[derive(Debug)]
struct ObligingDlp {
    attach: Vec<(Action, Obligation)>,
}

#[async_trait]
impl DlpService for ObligingDlp {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        action: Action,
        _resource: &ResourceRef,
        _facts: &FactsSnapshot,
    ) -> CoreResult<StageDecision> {
        let mut obligations = Obligations::none();
        for (attached_to, obligation) in &self.attach {
            if *attached_to == action {
                let _new = obligations.insert(*obligation);
            }
        }
        Ok(StageDecision::allow_with(obligations))
    }
}

// ---------------------------------------------------------------------------------------------
// A pipeline that answers with bytes, and with the media type the profile implies.
// ---------------------------------------------------------------------------------------------

/// The bytes the stub serves: a real, decodable, page-sized white PNG.
///
/// Decodable and page-sized both matter, and both were learned the hard way in
/// `tests/delivery.rs`: an eight-byte PNG signature makes the watermark assertion pass because the
/// compositor *refuses* an undecodable base, and a token 8×8 canvas makes it pass because every
/// glyph falls off the edge. A stub that is not the shape of the real thing tests a path the real
/// thing never takes.
fn stub_rendition() -> Vec<u8> {
    let canvas = image::RgbaImage::from_pixel(640, 480, image::Rgba([255, 255, 255, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(canvas)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .expect("encode the stub rendition");
    out
}

/// A rendition pipeline that returns bytes, without a renderer or an object store.
///
/// It reports the media type *the profile implies*, exactly as `RenditionService` does, because the
/// watermark decision turns on it: an export as `png` can be composited and an export as `pdf`
/// cannot (`ENC-723`). A stub that reported `image/png` for everything would make the `pdf` half of
/// that pair untestable, and would make the `png` half pass for the wrong reason.
#[derive(Debug, Default)]
struct StubPipeline {
    /// Set to refuse, so the "no rendition for this version" path can be exercised too.
    unavailable: bool,
}

#[async_trait::async_trait]
impl PreviewPipeline for StubPipeline {
    async fn deliver(
        &self,
        _conn: &mut PgConnection,
        _tenant: TenantId,
        _version: &enclave_preview::ReadableVersion,
        profile: RenditionProfile,
        _now: DateTime<Utc>,
    ) -> enclave_preview::Result<Delivery> {
        if self.unavailable {
            return Ok(Delivery::Unavailable(enclave_preview::Refusal::UnsupportedFormat));
        }
        let media_type = match profile {
            RenditionProfile::Thumb | RenditionProfile::PagePng1x | RenditionProfile::PagePng2x => {
                "image/png"
            }
            RenditionProfile::PdfSanitized => "application/pdf",
            RenditionProfile::HtmlSanitized => "text/html; charset=utf-8",
        };
        Ok(Delivery::Available {
            bytes: stub_rendition(),
            media_type: media_type.to_owned(),
            page_count: Some(1),
        })
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
    .bind(Action::File(action).to_string())
    .bind(effect)
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Builds the three routes under test, plus `download`, over a real chain and the counting store.
///
/// `download` is registered because A2 is a statement about *pairs*: "export is independently
/// deniable" is only meaningful beside a download that the same caller can or cannot perform, and a
/// suite that could not exercise both halves would be asserting one action's behaviour and calling
/// it a separation.
async fn app(
    db: &TestDb,
    dlp: Arc<dyn DlpService>,
) -> (Router, PrivateSigningKey, Arc<CountingStore>) {
    let pool = db.pool().await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");
    let store = Arc::new(CountingStore::default());

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        // The real resolver, over real rows: export, print and preview must be answered separately.
        Arc::new(PgAclAuthorization::new(pool.clone())),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        dlp,
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );

    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));

    let blob: Arc<dyn BlobStore> = store.clone();
    let pipeline: Arc<dyn PreviewPipeline> = Arc::new(StubPipeline::default());
    let router = Router::new()
        .route("/api/v1/files/{id}/download", post(enclave_api::download::download))
        .route("/api/v1/files/{id}/export", post(routes::delivery::export))
        .route("/api/v1/files/{id}/print-token", post(routes::delivery::print_token))
        .route("/api/v1/files/{id}/thumbnail", get(routes::delivery::thumbnail))
        .layer(Extension(blob))
        .layer(Extension(pipeline))
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

/// One response, as a status, a body and its headers.
struct Answer {
    status: StatusCode,
    cache_control: Option<String>,
    content_type: Option<String>,
    headers: axum::http::HeaderMap,
    bytes: Vec<u8>,
    body: String,
}

impl Answer {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("a JSON body")
    }

    /// The body, in a form that is useful in a failure message.
    ///
    /// A rendition is a few hundred kilobytes of PNG, and `assert!(.., "{}", answer.body)` on one
    /// buries the assertion under it — which is how a legible failure becomes a scroll. Binary
    /// bodies are reported by size and type, which is all a reader needs: the interesting question
    /// about them is answered by the assertions, not by the bytes.
    fn snippet(&self) -> String {
        let media = self.content_type.as_deref().unwrap_or("no content type");
        if media.starts_with("image/") || media.starts_with("application/pdf") {
            return format!("<{} bytes of {media}>", self.bytes.len());
        }
        let head: String = self.body.chars().take(400).collect();
        if head.len() < self.body.len() {
            format!("{head}…")
        } else {
            head
        }
    }

    /// Asserts that nothing in the response could be followed to the original bytes.
    ///
    /// The whole body is searched as text rather than field by field: a URL that leaked through a
    /// field nobody thought to check is exactly the failure this is for.
    fn carries_no_original(&self, content: &Content) {
        assert!(
            !self.body.contains("http://") && !self.body.contains("https://"),
            "a delivery response must carry no URL: {}",
            self.snippet()
        );
        assert!(
            !self.body.contains(&content.object_key),
            "a response must never carry an object key: {}",
            self.snippet()
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
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024).await.expect("body");
    Answer {
        status,
        cache_control,
        content_type,
        headers,
        bytes: body.to_vec(),
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

async fn post_export(app: &Router, bearer: &str, file: FileId, format: &str) -> Answer {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/files/{}/export", file.as_uuid()))
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"format":"{format}"}}"#)))
        .expect("request");
    send(app, request).await
}

async fn post_print_token(app: &Router, bearer: &str, file: FileId) -> Answer {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/files/{}/print-token", file.as_uuid()))
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("request");
    send(app, request).await
}

async fn get_thumbnail(app: &Router, bearer: &str, file: FileId) -> Answer {
    let request = Request::builder()
        .uri(format!("/api/v1/files/{}/thumbnail?size=256", file.as_uuid()))
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

/// One audit row, reduced to the columns an investigation actually reads.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditRow {
    action: String,
    outcome: String,
    reason_code: Option<String>,
    policy_refs: Option<String>,
    detail: Option<String>,
}

/// Every audit row for one request, in write order.
async fn rows_for(db: &TestDb, request_id: &str) -> Vec<AuditRow> {
    use sqlx::Row as _;

    let mut conn = db.connect().await.expect("connect");
    let rows = sqlx::query(
        "SELECT action, outcome, reason_code, policy_refs::text AS refs, detail::text AS detail
         FROM audit_events WHERE request_id = $1::uuid ORDER BY sequence ASC",
    )
    .bind(request_id)
    .fetch_all(&mut conn)
    .await
    .expect("read the audit rows for one request");

    rows.iter()
        .map(|row| AuditRow {
            action: row.try_get("action").expect("action"),
            outcome: row.try_get("outcome").expect("outcome"),
            reason_code: row.try_get("reason_code").expect("reason_code"),
            policy_refs: row.try_get("refs").expect("policy_refs"),
            detail: row.try_get("detail").expect("detail"),
        })
        .collect()
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

fn disabled_dlp() -> Arc<dyn DlpService> {
    Arc::new(enclave_dlp::DisabledDlp)
}

// =============================================================================================
// A2 — export, print and download are each independently deniable.
// =============================================================================================

/// `docs/12-TESTING.md §4.2` A2, for export, in both directions.
///
/// Two callers, one file. The first holds `download` and not `export`; the second holds `export`
/// and not `download`. Each is refused exactly one of the two routes and served the other. A
/// handler that reused `Download`'s action would serve the first caller their export and refuse the
/// second theirs — and both halves would be wrong in a way no single-caller test could see.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn a2_export_is_deniable_independently_of_download() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let downloader = fixtures.alpha.member;
    let exporter = fixtures.alpha.viewer;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;

    // Both may see that the file exists, so a refusal below is an actionable `403` rather than the
    // `404` a caller with no visibility at all would get. That distinction is `CLAUDE.md` rule 7,
    // and keeping it out of the way here is what lets this test be about A2 alone.
    for user in [downloader, exporter] {
        grant(&mut admin, &content, user, FileAction::MetadataRead, "ALLOW").await;
    }
    grant(&mut admin, &content, downloader, FileAction::Download, "ALLOW").await;
    // Explicit, not merely absent: deny-wins is a different code path from nothing-matched, and A2
    // is about a policy an administrator wrote.
    grant(&mut admin, &content, downloader, FileAction::Export, "DENY").await;
    grant(&mut admin, &content, exporter, FileAction::Export, "ALLOW").await;
    grant(&mut admin, &content, exporter, FileAction::Download, "DENY").await;

    let downloader_bearer = token(&key, fixtures.alpha.id, downloader);
    let exporter_bearer = token(&key, fixtures.alpha.id, exporter);

    // The caller who may take the original away may not convert it and take that away.
    let refused = post_export(&app, &downloader_bearer, content.file, "png").await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "a caller with `download` and no `export` was served an export: {}",
        refused.snippet()
    );
    assert_eq!(refused.json()["error"]["code"], "ACCESS_DENIED");
    refused.carries_no_original(&content);

    // The positive control for that refusal: the same caller's download works, so the `403` above
    // is about the action rather than about the caller, the file or the fixture.
    let allowed = post_download(&app, &downloader_bearer, content.file).await;
    assert_eq!(
        allowed.status,
        StatusCode::OK,
        "the download control failed, so the export refusal proves nothing: {}",
        allowed.snippet()
    );

    // And the converse caller, which is the half a naive download-blocking policy misses.
    let exported = post_export(&app, &exporter_bearer, content.file, "png").await;
    assert_eq!(
        exported.status,
        StatusCode::OK,
        "a caller with `export` was refused an export: {}",
        exported.snippet()
    );
    assert_eq!(exported.content_type.as_deref(), Some("image/png"));
    assert!(
        exported.bytes == stub_rendition(),
        "the export carried something other than the rendition the pipeline produced ({} bytes)",
        exported.bytes.len()
    );
    exported.carries_no_original(&content);

    let denied_download = post_download(&app, &exporter_bearer, content.file).await;
    assert_eq!(
        denied_download.status,
        StatusCode::FORBIDDEN,
        "a caller with `export` and no `download` was served the original: {}",
        denied_download.snippet()
    );

    // One URL, minted for one authorized download, and nothing else. The export path reached the
    // store zero times — asserted as a list rather than a count, so a failure names the key.
    assert_eq!(
        store.touched(),
        vec![content.object_key.clone()],
        "the export path reached object storage"
    );

    assert_eq!(audited(&db, "file.export", "DENY").await, 1);
    assert_eq!(audited(&db, "file.export", "ALLOW").await, 1);
    assert_eq!(audited(&db, "file.download", "DENY").await, 1);
    assert_eq!(audited(&db, "file.download", "ALLOW").await, 1);
}

/// A2 for print. `FileAction::Print` exists because "may print but may not keep a copy" is a real
/// policy, and this is the test that it is expressible end to end.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn a2_print_is_deniable_independently_of_download() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let downloader = fixtures.alpha.member;
    let printer = fixtures.alpha.viewer;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;

    for user in [downloader, printer] {
        grant(&mut admin, &content, user, FileAction::MetadataRead, "ALLOW").await;
    }
    grant(&mut admin, &content, downloader, FileAction::Download, "ALLOW").await;
    grant(&mut admin, &content, downloader, FileAction::Print, "DENY").await;
    // "May print but may not keep a copy", written as two ACL rows.
    grant(&mut admin, &content, printer, FileAction::Print, "ALLOW").await;
    grant(&mut admin, &content, printer, FileAction::Download, "DENY").await;

    let downloader_bearer = token(&key, fixtures.alpha.id, downloader);
    let printer_bearer = token(&key, fixtures.alpha.id, printer);

    let refused = post_print_token(&app, &downloader_bearer, content.file).await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "a caller with `download` and no `print` was granted a print token: {}",
        refused.snippet()
    );
    assert!(
        refused.json()["token"].is_null(),
        "a refused print request still carried a token: {}",
        refused.snippet()
    );
    refused.carries_no_original(&content);

    // The control: the same caller's download works.
    let allowed = post_download(&app, &downloader_bearer, content.file).await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.snippet());

    let granted = post_print_token(&app, &printer_bearer, content.file).await;
    assert_eq!(
        granted.status,
        StatusCode::OK,
        "a caller with `print` was refused a print grant: {}",
        granted.snippet()
    );
    let grant_body = granted.json();
    assert_eq!(grant_body["expiresIn"], 120, "the grant's lifetime is its revocation window");
    assert_eq!(grant_body["singleUse"], serde_json::Value::Bool(true));
    let minted = grant_body["token"].as_str().expect("a grant carries a token").to_owned();
    assert!(!minted.is_empty());
    assert_eq!(
        granted.cache_control.as_deref(),
        Some("private, no-store"),
        "a response body that is a bearer capability must not be cached"
    );
    granted.carries_no_original(&content);

    let denied_download = post_download(&app, &printer_bearer, content.file).await;
    assert_eq!(
        denied_download.status,
        StatusCode::FORBIDDEN,
        "a caller with `print` and no `download` was served the original: {}",
        denied_download.snippet()
    );

    // Two grants for the same caller and the same file are two different capabilities. A handler
    // that returned a stable token per (file, user) would have made "single use" meaningless: the
    // second request would hand back a value the first had already spent.
    let again = post_print_token(&app, &printer_bearer, content.file).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_ne!(
        again.json()["token"].as_str().expect("a token"),
        minted,
        "two print requests produced one capability"
    );

    // The print path holds no store and no pipeline, so this list must be exactly the one download.
    assert_eq!(store.touched(), vec![content.object_key.clone()]);

    assert_eq!(audited(&db, "file.print", "DENY").await, 1);
    assert_eq!(audited(&db, "file.print", "ALLOW").await, 2);
}

/// A thumbnail is answered by `file.preview`, and that is asserted rather than assumed.
///
/// The negative half is the point: a caller with `download` and no `preview` gets nothing from this
/// route, which is what stops the smallest and most-requested delivery response in the product from
/// becoming the one that skips the preview permission.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn a_thumbnail_is_answered_by_the_preview_permission_and_no_other() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let downloader = fixtures.alpha.member;
    let viewer = fixtures.alpha.viewer;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;

    for user in [downloader, viewer] {
        grant(&mut admin, &content, user, FileAction::MetadataRead, "ALLOW").await;
    }
    // Everything except preview. If the thumbnail asked any of these questions it would be served.
    for action in [FileAction::Download, FileAction::Export, FileAction::Print] {
        grant(&mut admin, &content, downloader, action, "ALLOW").await;
    }
    grant(&mut admin, &content, downloader, FileAction::Preview, "DENY").await;
    grant(&mut admin, &content, viewer, FileAction::Preview, "ALLOW").await;

    let downloader_bearer = token(&key, fixtures.alpha.id, downloader);
    let viewer_bearer = token(&key, fixtures.alpha.id, viewer);

    let refused = get_thumbnail(&app, &downloader_bearer, content.file).await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "a caller denied `preview` was served a thumbnail — the route is asking some other \
         question: {}",
        refused.snippet()
    );
    refused.carries_no_original(&content);

    // The control, without which the assertion above would hold against a route that refuses
    // everybody.
    let served = get_thumbnail(&app, &viewer_bearer, content.file).await;
    assert_eq!(
        served.status,
        StatusCode::OK,
        "a caller with `preview` was refused a thumbnail: {}",
        served.snippet()
    );
    assert_eq!(served.content_type.as_deref(), Some("image/png"));
    assert!(
        served.bytes == stub_rendition(),
        "the thumbnail carried something other than the rendition the pipeline produced ({} bytes)",
        served.bytes.len()
    );
    assert_eq!(
        served.cache_control.as_deref(),
        Some("private, no-store"),
        "a thumbnail of PREVIEW_ONLY content in a shared cache is that content without the chain"
    );
    assert_eq!(
        served.headers.get("x-content-type-options").and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        served.headers.get(axum::http::header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()),
        Some("inline"),
        "a thumbnail is viewing, not taking away"
    );
    served.carries_no_original(&content);

    // Both thumbnail requests are recorded against `file.preview`, which is what makes the audit
    // trail readable: an auditor asking who previewed this file sees them.
    assert_eq!(audited(&db, "file.preview", "DENY").await, 1);
    assert_eq!(audited(&db, "file.preview", "ALLOW").await, 1);

    assert!(
        store.touched().is_empty(),
        "a rendition path reached object storage: {:?}",
        store.touched()
    );
}

// =============================================================================================
// No original leaves by a rendition path.
// =============================================================================================

/// The absence, with the control that makes it mean something.
///
/// A fully authorized caller — every action granted — asks for an export and a thumbnail. Both
/// return bytes, so the store's empty call list is not the empty list of a handler that refused
/// everything; and neither response carries a URL or an object key.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn no_original_url_is_generated_on_the_export_or_thumbnail_path() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    for action in [
        FileAction::MetadataRead,
        FileAction::Preview,
        FileAction::Download,
        FileAction::Export,
        FileAction::Print,
    ] {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    let export = post_export(&app, &bearer, content.file, "png").await;
    let thumbnail = get_thumbnail(&app, &bearer, content.file).await;
    let print = post_print_token(&app, &bearer, content.file).await;

    for (name, answer) in [("export", &export), ("thumbnail", &thumbnail), ("print-token", &print)]
    {
        assert_eq!(answer.status, StatusCode::OK, "{name} was refused: {}", answer.snippet());
        answer.carries_no_original(&content);
    }
    // The controls: the two rendition paths returned the pipeline's bytes, so "nothing reached the
    // store" is not the trivially true statement of a handler that produced nothing.
    assert!(export.bytes == stub_rendition(), "the export served no rendition");
    assert!(thumbnail.bytes == stub_rendition(), "the thumbnail served no rendition");

    assert!(
        store.touched().is_empty(),
        "a rendition path minted a URL or streamed an original, touching {:?}",
        store.touched()
    );

    // An export says it is a take-away, which a preview must never say.
    assert_eq!(
        export.headers.get(axum::http::header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()),
        Some("attachment")
    );
    assert_eq!(export.cache_control.as_deref(), Some("private, no-store"));
}

// =============================================================================================
// Obligations — the asymmetry, over HTTP, with its audit rows.
// =============================================================================================

/// `NO_DOWNLOAD` refuses an export and does not refuse a print grant, and both facts are logged.
///
/// Every stage allows; DLP attaches `NO_DOWNLOAD` to the export and to the print. The export must
/// refuse — `docs/06 §5.2` — and the print must not, because a grant carries no bytes and no URL.
/// The pair is asserted in one test because it is one decision about what no-download means.
///
/// `ENC-606` is the second half: the refusal happens *after* the chain has written its `ALLOW`, so
/// the request must leave two rows, and the second must be findable by `WHERE outcome = 'DENY'`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn a_no_download_obligation_refuses_an_export_and_permits_a_print_grant() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let dlp: Arc<dyn DlpService> = Arc::new(ObligingDlp {
        attach: vec![
            (Action::File(FileAction::Export), Obligation::NoDownload),
            (Action::File(FileAction::Print), Obligation::NoDownload),
        ],
    });
    let (app, key, store) = app(&db, dlp).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    for action in [FileAction::MetadataRead, FileAction::Export, FileAction::Print] {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    let export = post_export(&app, &bearer, content.file, "png").await;
    assert_eq!(
        export.status,
        StatusCode::FORBIDDEN,
        "an export is a downloadable representation and NO_DOWNLOAD must refuse it: {}",
        export.snippet()
    );
    assert_eq!(
        export.json()["error"]["code"],
        "PREVIEW_ONLY",
        "the caller is told they may view but not take away: {}",
        export.snippet()
    );
    export.carries_no_original(&content);

    let print = post_print_token(&app, &bearer, content.file).await;
    assert_eq!(
        print.status,
        StatusCode::OK,
        "a print grant carries no bytes and no URL, so NO_DOWNLOAD constrains nothing about it — \
         refusing here would be rule 6's collapse arriving through the obligation set: {}",
        print.snippet()
    );

    assert!(store.touched().is_empty(), "saw {:?}", store.touched());

    // `ENC-606`: the chain allowed and the handler refused, and both facts must be in the log.
    let refused_request = export.json()["error"]["requestId"]
        .as_str()
        .expect("the error envelope carries the request id")
        .to_owned();
    let rows = rows_for(&db, &refused_request).await;
    assert_eq!(
        rows.len(),
        2,
        "one refused export must leave the chain's decision *and* the handler's: {rows:#?}"
    );
    assert_eq!(rows[0].outcome, "ALLOW", "the chain allowed, and the row must still say so");
    assert_eq!(rows[1].outcome, "DENY", "the refusal is not in the log: {rows:#?}");
    assert_eq!(
        rows[1].action, "file.export",
        "the refusal names a different action from the decision it followed"
    );
    assert_eq!(rows[1].reason_code.as_deref(), Some("PREVIEW_ONLY"));
    let refs = rows[1].policy_refs.clone().expect("the refusal names the control that took it");
    assert!(refs.contains("handler:obligation"), "{refs}");
    let detail = rows[1].detail.clone().expect("the refusal carries its detail");
    assert!(
        detail.contains("NO_DOWNLOAD") && detail.contains("refused_by"),
        "the row does not say which obligation could not be discharged: {detail}"
    );

    // The permitted print beside it: one row, no refusal.
    assert_eq!(
        audited(&db, "file.export", "DENY").await,
        1,
        "WHERE outcome = 'DENY' does not return the export that was refused"
    );
    assert_eq!(
        audited(&db, "file.print", "DENY").await,
        0,
        "the print grant succeeded; a DENY row for it would make the trail worse, not better"
    );
    assert_eq!(audited(&db, "file.print", "ALLOW").await, 1);
}

/// A watermark obligation is burned into the pixels where it can be, and refuses where it cannot.
///
/// Both halves in one run, over one file, differing only in the format asked for:
///
/// * `format: "png"` — the compositor marks it, and the assertion is that the bytes **changed**. A
///   response equal to the stub's rendition would mean the obligation was recorded and then
///   dropped, which is the rule 8 failure a status-only check misses entirely.
/// * `format: "pdf"` — nothing in `crates/preview` marks a PDF (`ENC-723`), so the export is
///   refused rather than served unmarked, and the refusal leaves its own row.
///
/// The thumbnail is here too, because it is the artefact most likely to be too small to carry a
/// legible mark — and if it is, `CompositeRefusal::NoRoom` must refuse it rather than return it
/// untouched.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn a_watermark_obligation_is_discharged_in_the_bytes_or_refuses_the_delivery() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let dlp: Arc<dyn DlpService> = Arc::new(ObligingDlp {
        attach: vec![
            (Action::File(FileAction::Export), Obligation::Watermark),
            (Action::File(FileAction::Preview), Obligation::Watermark),
        ],
    });
    let (app, key, store) = app(&db, dlp).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    for action in [FileAction::MetadataRead, FileAction::Preview, FileAction::Export] {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    let marked = post_export(&app, &bearer, content.file, "png").await;
    assert_eq!(
        marked.status,
        StatusCode::OK,
        "a watermark is dischargeable on a raster export, so it must succeed: {}",
        marked.snippet()
    );
    assert!(
        marked.bytes != stub_rendition(),
        "the export carried the base rendition unchanged ({} bytes) — the watermark obligation \
         was recorded and then dropped",
        marked.bytes.len()
    );
    marked.carries_no_original(&content);

    let unmarkable = post_export(&app, &bearer, content.file, "pdf").await;
    assert_eq!(
        unmarkable.status,
        StatusCode::FORBIDDEN,
        "a PDF export carrying a watermark obligation was served, and nothing in crates/preview \
         can have marked it (ENC-723): {}",
        unmarkable.snippet()
    );
    unmarkable.carries_no_original(&content);

    // The refusal is a *handler* refusal, taken after the chain allowed, and it has to say so.
    let refused_request = unmarkable.json()["error"]["requestId"]
        .as_str()
        .expect("the error envelope carries the request id")
        .to_owned();
    let rows = rows_for(&db, &refused_request).await;
    assert_eq!(rows.len(), 2, "{rows:#?}");
    assert_eq!(rows[1].outcome, "DENY");
    assert_eq!(rows[1].action, "file.export");
    let detail = rows[1].detail.clone().expect("detail");
    assert!(
        detail.contains("WATERMARK"),
        "the row does not say which obligation could not be discharged: {detail}"
    );

    // The thumbnail: served marked, or refused. Never served unmarked, which is the only outcome
    // this asserts against — the artefact's size decides which of the two it is, and both are
    // correct.
    let thumbnail = get_thumbnail(&app, &bearer, content.file).await;
    match thumbnail.status {
        StatusCode::OK => assert!(
            thumbnail.bytes != stub_rendition(),
            "the thumbnail carried the base rendition unchanged ({} bytes) under a watermark \
             obligation",
            thumbnail.bytes.len()
        ),
        StatusCode::FORBIDDEN => {
            assert_eq!(thumbnail.json()["error"]["code"], "ACCESS_DENIED");
        }
        other => panic!("a watermarked thumbnail answered {other}: {}", thumbnail.snippet()),
    }

    assert!(store.touched().is_empty(), "saw {:?}", store.touched());
}

// =============================================================================================
// T1 — absence and denial are the same answer, on all three routes.
// =============================================================================================

#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn t1_a_file_in_another_tenant_is_reported_as_absent_on_all_three_routes() {
    // `docs/12-TESTING.md §4.1` T1. The token is genuine and alpha's; the file id is beta's. The
    // resource reference is built from the *token's* tenant (`CLAUDE.md` rule 3), so what refuses
    // is the ACL resolver finding no chain, and what turns that into a `404` is the second question
    // the handler asks: may this caller read the file's metadata? It may not, so it learns nothing.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let beta = Content::new(fixtures.beta.id, fixtures.beta.owner);
    let mut admin = db.connect().await.expect("admin connection");
    beta.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    // Beta's own owner may do everything with it. None of that reaches an alpha caller.
    for action in
        [FileAction::MetadataRead, FileAction::Preview, FileAction::Export, FileAction::Print]
    {
        grant(&mut admin, &beta, fixtures.beta.owner, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, fixtures.alpha.owner);

    for (name, answer) in [
        ("export", post_export(&app, &bearer, beta.file, "png").await),
        ("print-token", post_print_token(&app, &bearer, beta.file).await),
        ("thumbnail", get_thumbnail(&app, &bearer, beta.file).await),
    ] {
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{name} answered a cross-tenant id with something other than 404, so it confirms the \
             file exists: {}",
            answer.snippet()
        );
        assert_eq!(answer.json()["error"]["code"], "NOT_FOUND");
        answer.carries_no_original(&beta);
    }

    assert!(store.touched().is_empty(), "saw {:?}", store.touched());
}

// =============================================================================================
// Rule 9 — nothing is served, and nothing is granted, before antivirus completes.
// =============================================================================================

#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn content_antivirus_has_not_cleared_is_delivered_by_none_of_the_three() {
    // Every permission granted; the version is still scanning. Rule 9 is not a permission question,
    // which is why it is checked after the chain has already allowed — and why the answer is `404`
    // rather than "this file is being scanned", which would tell an uploader's colleague that an
    // upload happened.
    //
    // The print grant matters as much as the two rendition paths: a capability minted against an
    // unscanned version would be redeemable after the scan, or worse, after a quarantine.
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let (app, key, store) = app(&db, disabled_dlp()).await;

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "SCANNING", "PENDING").await;
    for action in
        [FileAction::MetadataRead, FileAction::Preview, FileAction::Export, FileAction::Print]
    {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }

    let bearer = token(&key, fixtures.alpha.id, user);

    for (name, answer) in [
        ("export", post_export(&app, &bearer, content.file, "png").await),
        ("print-token", post_print_token(&app, &bearer, content.file).await),
        ("thumbnail", get_thumbnail(&app, &bearer, content.file).await),
    ] {
        assert_eq!(
            answer.status,
            StatusCode::NOT_FOUND,
            "{name} served or granted content antivirus has not cleared: {}",
            answer.snippet()
        );
        answer.carries_no_original(&content);
    }

    assert!(
        store.touched().is_empty(),
        "unscanned content must never reach the store, saw {:?}",
        store.touched()
    );
}

// =============================================================================================
// The real router, with the real "nothing is configured" delivery (ENC-170's shape).
// =============================================================================================

/// `ENC-170` again, for the three new routes.
///
/// That defect was a route registered without the extension its handler extracts: it answered `500`
/// in the binary while every integration test passed, because the tests build their own router with
/// the extensions attached — as the ones above do. So this one uses `enclave_api::router` itself,
/// which is the only thing that proves these three registrations are wired to something.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with the content and audit migrations; CI runs it with --include-ignored"]
async fn the_real_router_serves_all_three_routes_rather_than_failing_opaquely() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let pool = db.pool().await.expect("pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(PgAclAuthorization::new(pool.clone())),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    );
    let state = ApiState::new(policy, pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));

    // The real router, and the real "nothing is configured" delivery.
    let app = enclave_api::router(state, enclave_api::Delivery::unconfigured());

    let user = fixtures.alpha.member;
    let content = Content::new(fixtures.alpha.id, fixtures.alpha.owner);
    let mut admin = db.connect().await.expect("admin connection");
    content.insert(&mut admin, "AVAILABLE", "CLEAN").await;
    for action in
        [FileAction::MetadataRead, FileAction::Preview, FileAction::Export, FileAction::Print]
    {
        grant(&mut admin, &content, user, action, "ALLOW").await;
    }
    let bearer = token(&key, fixtures.alpha.id, user);

    // Fully permitted, so nothing below is a policy refusal — the only thing missing on the two
    // rendition paths is the renderer, which is the case this test exists for.
    for (name, answer) in [
        ("export", post_export(&app, &bearer, content.file, "png").await),
        ("thumbnail", get_thumbnail(&app, &bearer, content.file).await),
    ] {
        assert_ne!(
            answer.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the {name} route answered 500 — its dependency is not wired: {}",
            answer.snippet()
        );
        assert_eq!(
            answer.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an unconfigured deployment must say the service cannot do this yet, not that the \
             file is missing: {}",
            answer.snippet()
        );
        answer.carries_no_original(&content);
    }

    // The print grant needs no renderer and no store, so it must work in a deployment that has
    // neither — which is also what proves the route is reachable at all through the real router.
    let print = post_print_token(&app, &bearer, content.file).await;
    assert_eq!(
        print.status,
        StatusCode::OK,
        "the print-token route is not reachable through the real router: {}",
        print.snippet()
    );
    assert!(print.json()["token"].as_str().is_some_and(|token| !token.is_empty()));

    drop(db);
}
