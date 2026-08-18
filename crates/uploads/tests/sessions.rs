//! The upload state machine against a real PostgreSQL.
//!
//! Every test here is `#[ignore]`d and runs under the `enclave-testing` harness — `TestDb::start`
//! plus `DATABASE_URL`, which CI provides and invokes with `--include-ignored`
//! (`.github/workflows/ci.yml`). What they assert cannot be asserted without a database: that the
//! `CHECK` constraint accepts every state this crate writes, that the compare-and-swap is atomic
//! with the write, that another tenant sees nothing, and that a completion stops at `SCANNING`
//! *in the row* and not merely in the return value.
//!
//! **They need `upload_sessions`, which arrives with migration `0006`.** This crate was written
//! against the DDL in `docs/04-DATA-MODEL.md §8`; until that migration lands these fail at the
//! first `INSERT` rather than being skipped, which is the correct behaviour — a repository whose
//! table does not exist is not passing.
//!
//! **Queries run as `enclave_app`.** `DATABASE_URL` points at a cluster superuser, because the
//! harness has to create databases, and *superusers bypass row-level security entirely*. Work goes
//! through `TestDb::pool`, which sets the application role; a test that used `TestDb::connect` for
//! its assertions would run with isolation switched off and prove nothing (PR #22).
//!
//! The object store is a recording stub rather than MinIO. What is under test is the state machine
//! and the SQL; `enclave-storage`'s own `tests/minio.rs` covers the provider. The stub does earn
//! its keep in one place — it counts calls, which is how
//! `a_refused_extension_never_reaches_the_object_store` proves the guarantee in
//! `docs/05-API.md §8` that a rejected upload consumes no bandwidth.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration as StdDuration;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId, WorkspaceId};
use enclave_db::{sql, DbPool, TenantScoped};
use enclave_libraries::{ExternalSharing, LibraryRepository, LibrarySettings, VersioningMode};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectKey, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StoreCapabilities, Support,
    UploadRequest, UploadSession, UploadTarget,
};
use enclave_testing::{Fixtures, TestDb};
use enclave_uploads::{
    Completion, LoadedSession, NewUpload, ReportedContent, UploadError, UploadIntent, UploadLimits,
    UploadRepository, UploadService, UploadState,
};
use sqlx::PgConnection;
use url::Url;

/// Reason attached to every `#[ignore]` here, so the harness is named at each one.
const NEEDS_DB: &str =
    "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with \
     --include-ignored";

/// The SHA-256 of the empty string, used wherever a well-formed digest is needed.
const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The same digest in base64, as an object store reports it.
const DIGEST_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

// ---------------------------------------------------------------------------------------------
// A recording object store.
// ---------------------------------------------------------------------------------------------

/// An in-memory `BlobStore` that remembers what it was asked to do.
#[derive(Debug, Default)]
struct RecordingStore {
    state: Mutex<StoreState>,
}

#[derive(Debug, Default)]
struct StoreState {
    created: Vec<String>,
    deleted: Vec<String>,
    /// The size `complete_upload` reports, or `None` to echo the session's declared length.
    reported_size: Option<u64>,
    /// The base64 SHA-256 `complete_upload` reports.
    reported_checksum: Option<String>,
    /// Whether `delete` should fail, for the reaper's deferral path.
    delete_fails: bool,
}

impl RecordingStore {
    fn created(&self) -> Vec<String> {
        self.state.lock().expect("lock").created.clone()
    }

    fn deleted(&self) -> Vec<String> {
        self.state.lock().expect("lock").deleted.clone()
    }

    fn report_size(&self, size: u64) {
        self.state.lock().expect("lock").reported_size = Some(size);
    }

    fn report_checksum(&self, base64: &str) {
        self.state.lock().expect("lock").reported_checksum = Some(base64.to_owned());
    }

    fn fail_deletes(&self) {
        self.state.lock().expect("lock").delete_fails = true;
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

        // Over 8 MiB is multipart, which is enough to exercise the multipart columns without
        // pretending to be any particular provider's threshold.
        let target = if request.content_length > 8 * 1024 * 1024 {
            UploadTarget::Multipart { upload_id: "test-multipart".to_owned(), parts: Vec::new() }
        } else {
            UploadTarget::Single { url: Url::parse("https://store.invalid/put").expect("url") }
        };

        Ok(UploadSession {
            key: request.key,
            content_length: request.content_length,
            target,
            expires_at: Utc::now() + Duration::minutes(15),
            completed_parts: Vec::new(),
        })
    }

    async fn complete_upload(&self, session: &UploadSession) -> StorageResult<ObjectMeta> {
        let state = self.state.lock().expect("lock");
        Ok(ObjectMeta {
            key: session.key.clone(),
            size_bytes: state.reported_size.unwrap_or(session.content_length),
            etag: Some("etag".to_owned()),
            checksum_sha256: state.reported_checksum.clone(),
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
        Err(enclave_storage::StorageError::NotFound { key: key.to_owned() })
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut state = self.state.lock().expect("lock");
        if state.delete_fails {
            return Err(enclave_storage::StorageError::AccessDenied { operation: "DeleteObject" });
        }
        state.deleted.push(key.to_owned());
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
// Fixtures.
// ---------------------------------------------------------------------------------------------

/// Starts a database, applies migrations and seeds `tenant-alpha` / `tenant-beta`.
async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("build an application-role pool");
    (db, fixtures, pool)
}

/// Inserts a workspace, as the application role.
///
/// Plain SQL rather than `enclave-workspaces`: this crate does not depend on that one, and a
/// test-only dependency to obtain a parent row would make two test suites fail together for
/// reasons that have nothing to do with either.
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

/// A library with the extension rules and ceiling the tests need.
fn settings(slug: &str, blocked: Option<Vec<String>>, max: Option<i64>) -> LibrarySettings {
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
        max_file_size_bytes: max,
        external_sharing: ExternalSharing::Disabled,
        ai_indexing_enabled: false,
        mcp_visible: false,
        sync_enabled: false,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

/// Creates a workspace and a library in `tenant`, returning both.
async fn library(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    slug: &str,
    blocked: Option<Vec<String>>,
) -> (WorkspaceId, LibraryId) {
    let workspace = insert_workspace(conn, tenant, owner, slug).await;
    let library = LibraryRepository::create(
        conn,
        tenant,
        workspace,
        &settings(slug, blocked, None),
        Utc::now(),
    )
    .await
    .expect("create library")
    .id;
    (workspace, library)
}

/// Inserts a file at a library's root, for the new-version case.
///
/// Plain SQL rather than `enclave-files` for the reason `insert_workspace` gives. `upload_sessions`
/// carries a composite foreign key to `files` (`migrations/0006`), so a new-version session needs a
/// row that actually exists — which is the point of testing that path at all.
async fn insert_file(
    conn: &mut PgConnection,
    tenant: TenantId,
    workspace: WorkspaceId,
    library_id: LibraryId,
    owner: UserId,
    name: &str,
) -> FileId {
    let id = FileId::new_v7();
    sqlx::query(
        "INSERT INTO files
           (tenant_id, id, workspace_id, library_id, node_type, name, normalized_name, mime_type,
            created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, 'FILE', $5, $5, 'application/pdf', $6, $6, $7, $7)",
    )
    .bind(sql(tenant))
    .bind(sql(id))
    .bind(sql(workspace))
    .bind(sql(library_id))
    .bind(name)
    .bind(sql(owner))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert file");
    id
}

/// A `NewUpload` for `name`, declaring `size` bytes.
fn upload(library_id: LibraryId, owner: UserId, name: &str, size: u64) -> NewUpload {
    NewUpload {
        library_id,
        parent_id: None,
        intent: UploadIntent::NewFile,
        name: name.to_owned(),
        declared_size: size,
        declared_mime: Some("application/pdf".to_owned()),
        declared_sha256: None,
        created_by: owner,
    }
}

/// What the client reports at completion.
fn reported(size: u64) -> ReportedContent {
    ReportedContent { size_bytes: size, sha256_hex: DIGEST_HEX.to_owned() }
}

/// Reads a session's state straight out of the column, bypassing the decoder — so a test asserting
/// "the row says SCANNING" is asserting about the row and not about this crate's opinion of it.
async fn stored_state(conn: &mut PgConnection, id: &str) -> String {
    sqlx::query_scalar::<_, String>("SELECT state FROM upload_sessions WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .expect("read the state column")
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_session_round_trips_through_every_column() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "  Quarterly Report.pdf  ", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create the session");

    let found = UploadService::find(&mut tx, alpha, issued.session.id()).await.expect("find");
    tx.commit().await.expect("commit");

    assert_eq!(found.state(), UploadState::Created);
    let record = found.record();
    assert_eq!(record.id, issued.session.id());
    assert_eq!(record.tenant_id, alpha);
    assert_eq!(record.library_id, library_id);
    assert_eq!(record.name, "Quarterly Report.pdf", "the name is trimmed on the way in");
    assert_eq!(record.declared_size, Some(64));
    assert_eq!(record.declared_mime.as_deref(), Some("application/pdf"));
    assert_eq!(record.bytes_received, 0);
    assert_eq!(record.created_by, fixtures.alpha.owner);
    assert_eq!(record.file_id, None, "a new file has no file_id until the commit creates it");
    assert!(record.multipart_id.is_none(), "64 bytes is a single-shot upload");
    assert_eq!(record.staged.tenant(), alpha, "the staged key is under this tenant's prefix");
    assert_eq!(store.created(), vec![record.staged.as_str().to_owned()]);
    assert!(matches!(issued.target, UploadTarget::Single { .. }));

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn another_tenants_session_is_indistinguishable_from_one_that_does_not_exist() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let err = UploadService::find(&mut tx, beta, issued.session.id()).await.unwrap_err();
    let missing =
        UploadService::find(&mut tx, beta, enclave_uploads::UploadSessionId::new_v7()).await;
    tx.commit().await.expect("commit");

    // One answer for both, so a probe cannot distinguish absence from denial (`CLAUDE.md` rule 7).
    assert!(matches!(err, UploadError::NotFound));
    assert!(matches!(missing, Err(UploadError::NotFound)));

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_verified_completion_stops_at_scanning_in_the_row() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let id = issued.session.id();

    let completion =
        UploadService::complete(&mut tx, &store, alpha, id, &reported(64), Vec::new(), Utc::now())
            .await
            .expect("complete");
    tx.commit().await.expect("commit");

    let Completion::HandedOff { session, handoff } = completion else {
        panic!("a matching size and a well-formed digest must be accepted");
    };
    assert_eq!(session.state(), UploadState::Scanning);
    assert_eq!(handoff.content.size_bytes(), 64);
    assert_eq!(handoff.content.sha256_hex(), DIGEST_HEX);
    assert!(
        !handoff.content.checksum_evidence().is_confirmed(),
        "the stub reported no digest, so the client's is not yet evidence of anything"
    );
    assert_eq!(handoff.staged.version(), issued.session.record().staged.version());

    // The row, read without going through this crate's decoder. `CLAUDE.md` rule 9: completion
    // advances to SCANNING and stops.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_size_or_checksum_mismatch_is_persisted_as_failed() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    // The store holds 65 bytes; the client declared and reports 64.
    store.report_size(65);

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let id = issued.session.id();

    let completion =
        UploadService::complete(&mut tx, &store, alpha, id, &reported(64), Vec::new(), Utc::now())
            .await
            .expect("a mismatch is an outcome, not an error");
    tx.commit().await.expect("commit");

    let Completion::Refused { session, reason } = completion else {
        panic!("a store that holds a different number of bytes must be refused");
    };
    assert_eq!(session.state(), UploadState::Failed);
    assert_eq!(reason.as_str(), "SIZE_DIFFERS_FROM_STORE");
    assert_eq!(reason.to_error().status_code(), 400);

    // The refusal survived the commit: a client retrying `complete` finds a session that says so
    // rather than one that still looks uploadable.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &id.to_string()).await, "FAILED");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let err =
        UploadService::complete(&mut tx, &store, alpha, id, &reported(64), Vec::new(), Utc::now())
            .await
            .unwrap_err();
    tx.commit().await.expect("commit");
    assert!(matches!(err, UploadError::NotResumable { state: UploadState::Failed }));

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn the_second_writer_of_a_state_change_loses_the_compare_and_swap() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let id = issued.session.id();

    // Two readers see the same `CREATED` row — which is what two concurrent requests look like.
    let first =
        UploadService::find(&mut tx, alpha, id).await.expect("find").into_resumable().unwrap();
    let second =
        UploadService::find(&mut tx, alpha, id).await.expect("find").into_resumable().unwrap();

    let now = Utc::now();
    UploadRepository::apply(&mut tx, first.begin_upload(10, now)).await.expect("the first wins");
    let err = UploadRepository::apply(&mut tx, second.begin_upload(20, now)).await.unwrap_err();
    tx.commit().await.expect("commit");

    assert!(
        matches!(
            err,
            UploadError::ConcurrentTransition {
                expected: UploadState::Created,
                attempted: UploadState::Uploading
            }
        ),
        "got: {err:?}"
    );

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn aborting_releases_the_staged_bytes_and_marks_the_row() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let id = issued.session.id();
    let key = issued.session.record().staged.as_str().to_owned();

    let aborted =
        UploadService::abort(&mut tx, &store, alpha, id, Utc::now()).await.expect("abort");
    tx.commit().await.expect("commit");

    assert_eq!(aborted.state(), UploadState::Aborted);
    assert_eq!(store.deleted(), vec![key]);

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &id.to_string()).await, "ABORTED");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn the_reaper_releases_expired_sessions_and_leaves_live_ones_alone() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let limits = UploadLimits::unrestricted_up_to(1024);

    // One session that expired an hour ago, one that has a day left.
    let stale = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "stale.pdf", 64),
        &limits,
        Duration::hours(-1),
        now,
    )
    .await
    .expect("create the stale session");
    let live = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "live.pdf", 64),
        &limits,
        Duration::hours(24),
        now,
    )
    .await
    .expect("create the live session");

    let report =
        enclave_uploads::reap_expired(&mut tx, &store, alpha, now, 100).await.expect("reap");
    tx.commit().await.expect("commit");

    assert_eq!(report.claimed, 1, "only the expired session is claimed");
    assert_eq!(report.released, 1);
    assert_eq!(report.deferred, 0);
    assert_eq!(store.deleted(), vec![stale.session.record().staged.as_str().to_owned()]);

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &stale.session.id().to_string()).await, "EXPIRED");
    assert_eq!(stored_state(&mut conn, &live.session.id().to_string()).await, "CREATED");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_store_that_refuses_a_delete_leaves_the_session_for_the_next_pass() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let stale = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "stale.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(-1),
        now,
    )
    .await
    .expect("create");

    store.fail_deletes();
    let report =
        enclave_uploads::reap_expired(&mut tx, &store, alpha, now, 100).await.expect("reap");
    tx.commit().await.expect("commit");

    assert_eq!((report.claimed, report.released, report.deferred), (1, 0, 1));

    // Still `CREATED`, so the next pass claims it again. Marking it `EXPIRED` here would have put
    // it outside `idx_uploads_expiry` and orphaned the bytes permanently.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &stale.session.id().to_string()).await, "CREATED");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_refused_extension_never_reaches_the_object_store() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", Some(vec![".exe".to_owned()]))
            .await;
    let settings = LibraryRepository::find_by_id(&mut tx, alpha, library_id)
        .await
        .expect("query")
        .expect("the library exists")
        .settings;
    let limits = UploadLimits::from_library(&settings, 1024);

    let refused = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "setup.EXE", 64),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .unwrap_err();

    let too_large = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "brief.pdf", 1025),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .unwrap_err();
    tx.commit().await.expect("commit");

    assert!(matches!(refused, UploadError::ExtensionNotAllowed { .. }), "got: {refused:?}");
    assert!(matches!(too_large, UploadError::FileTooLarge { limit: 1024 }), "got: {too_large:?}");
    // The guarantee of `docs/05-API.md §8`: no URL was minted, so no bandwidth was spent.
    assert!(store.created().is_empty(), "the object store was contacted for a refused upload");
    assert!(NEEDS_DB.contains("0006"));

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_new_version_records_its_file_and_stages_under_that_files_key() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let file_id =
        insert_file(&mut tx, alpha, workspace, library_id, fixtures.alpha.owner, "brief.pdf").await;
    let mut request = upload(library_id, fixtures.alpha.owner, "brief.pdf", 9 * 1024 * 1024);
    request.intent = UploadIntent::NewVersion(file_id);

    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &request,
        &UploadLimits::unrestricted_up_to(64 * 1024 * 1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");

    let found = UploadService::find(&mut tx, alpha, issued.session.id()).await.expect("find");
    tx.commit().await.expect("commit");

    let record = found.record();
    assert_eq!(record.file_id, Some(file_id));
    assert_eq!(record.staged.file(), file_id, "the key and the column name the same file");
    assert_eq!(record.multipart_id.as_deref(), Some("test-multipart"));
    assert_eq!(
        record.staged.key(),
        &ObjectKey::version(alpha, file_id, record.staged.version()),
        "the staged key is the canonical version key of docs/02-HLD.md §7"
    );
    assert!(matches!(found, LoadedSession::Created(_)));

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_digest_the_store_computed_is_believed_only_when_it_matches() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    store.report_checksum(DIGEST_B64);

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let limits = UploadLimits::unrestricted_up_to(1024);

    let agreeing = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "agrees.pdf", 64),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let completion = UploadService::complete(
        &mut tx,
        &store,
        alpha,
        agreeing.session.id(),
        &reported(64),
        Vec::new(),
        Utc::now(),
    )
    .await
    .expect("complete");
    let Completion::HandedOff { handoff, .. } = completion else {
        panic!("a digest the store agrees with must be accepted");
    };
    assert!(
        handoff.content.checksum_evidence().is_confirmed(),
        "the provider computed this digest, so it is evidence and must be recorded as such"
    );

    // Now the same store, disagreeing: it holds a digest of 32 zero bytes.
    store.report_checksum("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let disagreeing = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "disagrees.pdf", 64),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let completion = UploadService::complete(
        &mut tx,
        &store,
        alpha,
        disagreeing.session.id(),
        &reported(64),
        Vec::new(),
        Utc::now(),
    )
    .await
    .expect("a mismatch is an outcome, not an error");
    tx.commit().await.expect("commit");

    let Completion::Refused { reason, .. } = completion else {
        panic!("a checksum the store disagrees with must be refused, not warned about");
    };
    assert_eq!(reason.as_str(), "CHECKSUM_MISMATCH");

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &disagreeing.session.id().to_string()).await, "FAILED");

    pool.close().await;
    drop(db);
}
