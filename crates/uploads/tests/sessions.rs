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
use enclave_core::{FileId, LibraryId, TenantId, UserId, Uuid, WorkspaceId};
use enclave_db::{configure_storage_quota, sql, DbPool, Enforcement, TenantScoped};
use enclave_libraries::{ExternalSharing, LibraryRepository, LibrarySettings, VersioningMode};
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, CompletedPart, MultipartLimits, ObjectKey, ObjectMeta,
    PartTarget, PublicAccessCheck, PublicAccessError, PublicAccessReport, Result as StorageResult,
    StoreCapabilities, Support, UploadRequest, UploadSession, UploadTarget,
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

/// Lowercase hex to base64, the conversion `enclave_storage` performs on the way to the provider.
///
/// Present so the recording store can echo a digest the way a real one does. Panics on a malformed
/// input, which in a test is the right answer: it means the fixture is wrong.
fn base64_of_hex(hex: &str) -> String {
    use base64::Engine as _;

    let raw: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ascii"), 16)
                .expect("a lowercase hex digest")
        })
        .collect();
    base64::engine::general_purpose::STANDARD.encode(raw)
}

// ---------------------------------------------------------------------------------------------
// A recording object store.
// ---------------------------------------------------------------------------------------------

/// An in-memory `BlobStore` that remembers what it was asked to do.
///
/// It models a backend that *can* have the provider confirm a whole-object digest, single-shot or
/// multipart — which the [`BlobStore`] contract permits and `S3BlobStore` against MinIO cannot do
/// for the multipart half. That difference is deliberate rather than sloppy: this suite is about
/// what the upload service does with a store's answers, and the answers a real S3 backend actually
/// gives are asserted where they can be observed, in `crates/storage/tests/minio.rs`, against a
/// running MinIO. [`RecordingStore::compute_no_checksum`] is how a test here asks for the other
/// behaviour.
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
    /// The base64 SHA-256 `complete_upload` reports, overriding the digest the session asked for.
    ///
    /// `None` means *behave like a real provider*: echo back the digest `create_upload` was given,
    /// because that is exactly what S3 and MinIO do once `x-amz-checksum-sha256` is signed into
    /// the URL and the body has matched it. Before `ENC-820` the default was to report nothing,
    /// which made the stub a faithful model of the bug rather than of a store.
    reported_checksum: Option<String>,
    /// The digest `create_upload` was asked to have the provider verify, base64.
    requested_checksum: Option<String>,
    /// Whether `create_upload` should behave like a store that cannot confirm a digest.
    unverifiable: bool,
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

    /// Makes the store behave like one that computes no digest of its own — a BYO S3-compatible
    /// backend that accepts the checksum header and never reports it back.
    fn compute_no_checksum(&self) {
        let mut state = self.state.lock().expect("lock");
        state.reported_checksum = None;
        state.unverifiable = true;
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
        let mut state = self.state.lock().expect("lock");

        // Over 8 MiB is multipart, which is enough to exercise the multipart columns without
        // pretending to be any particular provider's threshold.
        let multipart = request.content_length > 8 * 1024 * 1024;

        // The contract `BlobStore::create_upload` states since `ENC-820`: a declared digest is
        // binding, and a store that cannot arrange for the provider to verify it says so instead of
        // issuing a session. Modelled here so the stub cannot be more permissive than the real one
        // — and refused *before* `created` is recorded, so `store.created().is_empty()` still means
        // "no URL was minted for this request".
        if request.checksum_sha256.is_some() && state.unverifiable {
            return Err(enclave_storage::StorageError::ChecksumUnverifiable {
                content_length: request.content_length,
                threshold: 8 * 1024 * 1024,
            });
        }
        state.created.push(request.key.as_str().to_owned());
        state.requested_checksum = request.checksum_sha256.as_deref().map(base64_of_hex);

        let target = if multipart {
            UploadTarget::Multipart { upload_id: "test-multipart".to_owned(), parts: Vec::new() }
        } else {
            UploadTarget::Single {
                url: Url::parse("https://store.invalid/put").expect("url"),
                required_headers: Vec::new(),
            }
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
            // A real provider echoes the digest it was given once the body has matched it; an
            // override is how a test asks for the disagreeing case.
            checksum_sha256: if state.unverifiable {
                None
            } else {
                state.reported_checksum.clone().or_else(|| state.requested_checksum.clone())
            },
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
// A store that refuses to be a byte pipe.
// ---------------------------------------------------------------------------------------------

/// The size M1's fifth exit criterion names.
const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;

/// The part size the multipart arithmetic below assumes — S3's minimum, and MinIO's.
const PART_BYTES: u64 = 5 * 1024 * 1024;

/// A `BlobStore` whose byte-bearing methods panic.
///
/// `ENC-144`. The only two methods on [`BlobStore`] that can put object bytes in this process are
/// `read_range`, which streams them here, and `copy`, which is server-side but is the operation
/// [`enclave_uploads::StagedObject`]'s documentation rules out for the largest supported upload
/// (`CopyObject` tops out at 5 GB). Both abort the test rather than returning an error, because an
/// error is something the service under test could plausibly handle and move past — and the claim
/// being tested is not "it copes", it is "it never asks".
#[derive(Debug, Default)]
struct ByteRefusingStore;

#[async_trait]
impl PublicAccessCheck for ByteRefusingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for ByteRefusingStore {
    async fn create_upload(&self, request: UploadRequest) -> StorageResult<UploadSession> {
        // A real part list, because the part list is the only thing the API holds that grows with
        // the upload at all — and the test asserts how much. Handing back an empty one would make
        // the memory assertion vacuous.
        let count = request.content_length.div_ceil(PART_BYTES);
        let mut parts = Vec::new();
        for index in 0..count {
            let part_number = u32::try_from(index + 1).expect("part number fits");
            let offset = index * PART_BYTES;
            parts.push(PartTarget {
                part_number,
                offset,
                length: PART_BYTES.min(request.content_length - offset),
                url: Url::parse(&format!("https://store.invalid/part/{part_number}")).expect("url"),
            });
        }

        Ok(UploadSession {
            key: request.key,
            content_length: request.content_length,
            target: UploadTarget::Multipart { upload_id: "five-gib".to_owned(), parts },
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
            "the upload path asked to stream `{key}` through this process. Content bytes go from \
             the client to the store over signed URLs and must never reach the API — that is why \
             M1's 5 GB criterion is a statement about memory at all."
        );
    }

    async fn copy(&self, from: &str, _to: &str) -> StorageResult<()> {
        panic!(
            "the upload path asked the store to copy `{from}`. Bytes are staged under the key the \
             version will keep, so a commit copies nothing; a copy also cannot address the \
             criterion's 5 GB (see `staged.rs`)."
        );
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        Ok(())
    }

    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "byte-refusing-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: PART_BYTES,
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
        // Required since `ENC-820`, and the same digest the client reports at completion — which is
        // what a client that computed the digest of the bytes it sent would do.
        declared_sha256: DIGEST_HEX.to_owned(),
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
    assert_eq!(
        handoff.content.sha256_hex(),
        DIGEST_HEX,
        "the provider computed this digest and it matched, which is the only way a completion \
         reaches a handoff at all"
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

/// `ENC-820`, through the whole service rather than through `VerifiedContent` alone.
///
/// The bug was not that the comparison was wrong — it was that *no comparison happened* and the
/// completion succeeded anyway, persisting the client's word on an immutable column. So the
/// assertion has to be about the outcome of `complete`, and it needs the positive control beside
/// it: the same service, the same digest, a store that confirms it, accepted. Without that pair,
/// "refused" is indistinguishable from a completion path that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_completion_the_store_did_not_confirm_is_refused_and_the_session_fails() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let limits = UploadLimits::unrestricted_up_to(1024);

    // The control. The store echoes the digest it was asked to verify, as a real provider does
    // once the header is signed into the URL, and the completion is accepted.
    let confirmed = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "confirmed.pdf", 64),
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
        confirmed.session.id(),
        &reported(64),
        Vec::new(),
        Utc::now(),
    )
    .await
    .expect("complete");
    assert!(
        matches!(completion, Completion::HandedOff { .. }),
        "a provider-confirmed digest must still be accepted, or the refusal below proves nothing"
    );

    // And the defect. A store that computed no digest of its own leaves nothing to compare the
    // reported one against — which is exactly what MinIO does for an ordinary pre-signed `PUT`,
    // and is therefore what every upload on the shipped stack used to look like.
    store.compute_no_checksum();
    let session_id = confirmed.session.id();
    let unconfirmed = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "unconfirmed.pdf", 64),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await;

    // The refusal comes at `create` on this store, because it declares up front that it cannot
    // confirm — the client is told before it spends a byte, which is `docs/05-API.md §8`.
    let refused = unconfirmed.expect_err("a store that cannot confirm must not issue a session");
    assert!(matches!(refused, UploadError::ChecksumUnverifiable { .. }), "got: {refused:?}");
    assert_eq!(
        store.created().len(),
        1,
        "a session was staged for an upload whose digest nothing can confirm"
    );

    tx.commit().await.expect("commit");
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &session_id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}

/// The other half: a store that issued a session and then reported no digest at completion.
///
/// Reachable when a backend's behaviour differs between the two calls — a BYO S3-compatible store
/// that accepts `x-amz-checksum-sha256` and does not return it on `HeadObject`. The completion is
/// refused and the session is written `FAILED`, because retrying it against the same store cannot
/// succeed and the alternative is to record an unverified digest forever.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_store_that_reports_no_digest_at_completion_fails_the_session() {
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
        &upload(library_id, fixtures.alpha.owner, "silent.pdf", 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");

    // The session exists; the store goes quiet between `create_upload` and `complete_upload`.
    store.compute_no_checksum();
    let completion = UploadService::complete(
        &mut tx,
        &store,
        alpha,
        issued.session.id(),
        &reported(64),
        Vec::new(),
        Utc::now(),
    )
    .await
    .expect("an unconfirmable digest is a persisted outcome, not an error");
    tx.commit().await.expect("commit");

    let Completion::Refused { reason, .. } = completion else {
        panic!(
            "a digest the store did not confirm was accepted. This is ENC-820: the value goes on \
             an immutable column that a later integrity check reads as evidence"
        );
    };
    assert_eq!(reason.as_str(), "CHECKSUM_UNCONFIRMED");
    // Not a `400` blaming the client's `sha256`: nothing the client sent was wrong.
    assert_eq!(reason.to_error().status_code(), 503);

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &issued.session.id().to_string()).await, "FAILED");

    pool.close().await;
    drop(db);
}

/// `ENC-144` — M1's fifth exit criterion, exercised rather than argued.
///
/// The criterion is "5 GB resumable upload with flat API memory", and until now it was true by
/// construction and untested: nothing would have caught a change that started routing content
/// through the API. This drives a session declared at the criterion's full size through the whole
/// machine — create, resume, complete, hand off to antivirus — against a store whose two
/// byte-bearing methods abort the test.
///
/// It moves no data, and that is the point. The assertion is not about volume, which CI cannot
/// afford and which would pass just as well against an implementation that streamed 5 GB through
/// this process in small pieces. It is about *who touches the bytes*: if the answer is ever "we
/// do", `ByteRefusingStore` panics and names the call.
///
/// `src/lib.rs`'s `flat_memory` module holds the other half — that no type in the crate can carry
/// a run of content bytes in the first place.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_five_gigabyte_upload_is_completed_without_the_api_touching_a_byte() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = ByteRefusingStore;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "archives", None).await;

    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "backup.pdf", FIVE_GIB),
        &UploadLimits::unrestricted_up_to(FIVE_GIB),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create a session for the size the exit criterion names");
    let id = issued.session.id();

    // What the API hands the client is addresses. There is no arm of `UploadTarget` that could
    // carry content, so this is also where the type-level half of the claim shows up at runtime.
    let UploadTarget::Multipart { parts, .. } = &issued.target else {
        panic!("five gigabytes cannot be a single PUT; the store must have returned parts");
    };
    assert_eq!(parts.len(), 1024, "5 GiB in 5 MiB parts");

    // Everything the API retains for this upload, counted rather than asserted about in prose: the
    // part list, its URLs, the staging key and the file name. The bound is one megabyte — *below a
    // single part* — so a regression that buffered even one 5 MiB chunk fails here, never mind one
    // that held the object.
    let retained: usize = parts
        .iter()
        .map(|part| std::mem::size_of::<PartTarget>() + part.url.as_str().len())
        .sum::<usize>()
        + issued.session.record().staged.as_str().len()
        + issued.session.record().name.len();
    assert!(
        retained < 1024 * 1024,
        "the API retained {retained} bytes for a {FIVE_GIB}-byte upload; that is no longer flat"
    );

    // The client reports progress across the whole object, which is the resumable half of the
    // criterion. It is a counter — `bytes_received` — and never the bytes themselves.
    UploadService::record_progress(&mut tx, alpha, id, FIVE_GIB, Utc::now())
        .await
        .expect("record progress across five gigabytes");

    let reported_parts: Vec<CompletedPart> = parts
        .iter()
        .map(|part| CompletedPart {
            part_number: part.part_number,
            etag: format!("etag-{}", part.part_number),
        })
        .collect();

    let completion = UploadService::complete(
        &mut tx,
        &store,
        alpha,
        id,
        &reported(FIVE_GIB),
        reported_parts,
        Utc::now(),
    )
    .await
    .expect("complete");
    tx.commit().await.expect("commit");

    let Completion::HandedOff { session, handoff } = completion else {
        panic!("a five-gigabyte upload whose size and digest agree must be accepted");
    };
    assert_eq!(session.state(), UploadState::Scanning);
    assert_eq!(
        handoff.content.size_bytes(),
        FIVE_GIB,
        "the size on the handoff is the store's number for the whole object"
    );

    // `CLAUDE.md` rule 9 still applies at this size: the row stops at SCANNING.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}

// ---------------------------------------------------------------------------------------------
// The reserve-time quota preflight — `ENC-589`, `docs/12-TESTING.md §4.12` Q9.
//
// `docs/05-API.md §8` and `docs/10-SYNC-AND-EDITING.md §5` both ask for a quota answer *before* a
// URL is issued, so a device does not spend gigabytes to be told no at commit. What they ask for is
// bandwidth, not capacity — and `crates/uploads/src/quota.rs` says at length why this read is not
// the enforcement. The second test below is the one that makes that visible rather than merely
// documented.
// ---------------------------------------------------------------------------------------------

/// Writes a quota row for `tenant`, over the application role and in its own transaction.
async fn set_quota(pool: &DbPool, tenant: TenantId, limit: u64, mode: Enforcement) {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    configure_storage_quota(&mut tx, limit, 80, mode).await.expect("configure the quota");
    tx.commit().await.expect("commit");
}

/// An upload that cannot fit is refused, and the store is never asked for a URL.
///
/// The control is in the same fixture and runs after: an upload that *does* fit is issued and the
/// store *is* called once. Without it, "the store was not contacted" holds against a `create` that
/// refuses everything, and `docs/12 §1.2` names that shape as the one that passes for free.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migrations 0006 and 0018; CI runs it with --include-ignored"]
async fn an_upload_with_no_headroom_is_refused_before_any_url_is_issued() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    set_quota(&pool, alpha, 1_024, Enforcement::Block).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    // Well above the declared sizes, so the per-file ceiling cannot be what refuses either one.
    let limits = UploadLimits::unrestricted_up_to(1024 * 1024);

    let refused = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "too-big.pdf", 4_096),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(refused, UploadError::StorageQuotaExceeded { limit_bytes: 1_024 }),
        "got: {refused:?}"
    );
    assert!(
        store.created().is_empty(),
        "a rejected upload must never consume bandwidth (docs/05-API.md §8)"
    );
    // And it renders as a quota refusal rather than a server error.
    assert_eq!(
        enclave_core::Error::from(UploadError::StorageQuotaExceeded { limit_bytes: 1_024 })
            .status_code(),
        403
    );

    // The control: the same library, the same limits, a size that fits.
    let issued = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "fits.pdf", 512),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("an upload inside the headroom is issued");
    tx.commit().await.expect("commit");

    assert_eq!(store.created().len(), 1, "and that one did reach the store");
    assert_eq!(issued.session.record().declared_size, Some(512));

    pool.close().await;
    drop(db);
}

/// **A preflight pass is not a reservation, and this is where that decision is visible.**
///
/// Two sessions that each fit the remaining headroom are both issued, even though together they
/// exceed it. That is the cost of charging at version commit rather than at reservation, and it is
/// deliberate: `storage_quotas` has one counter and no reservation column, and a charge raised
/// against a staged object has no `file_versions` row for the nightly reconciliation to measure —
/// so it would be subtracted as drift on the first pass.
///
/// What bounds the tenant is the charge at commit, which is asserted in
/// `crates/versions/tests/versions.rs`. If this test ever starts failing because the second session
/// is refused, someone has made the preflight binding, and that is a change to which statement
/// enforces the quota — `plans/M4-GOVERNANCE.md` D31 — rather than a bug fix.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migrations 0006 and 0018; CI runs it with --include-ignored"]
async fn two_sessions_that_each_fit_the_headroom_are_both_issued() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let store = RecordingStore::default();
    set_quota(&pool, alpha, 4_096, Enforcement::Block).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let limits = UploadLimits::unrestricted_up_to(1024 * 1024);

    for name in ["first.pdf", "second.pdf"] {
        let issued = UploadService::create(
            &mut tx,
            &store,
            alpha,
            &upload(library_id, fixtures.alpha.owner, name, 3_000),
            &limits,
            Duration::hours(24),
            Utc::now(),
        )
        .await
        .expect("each declared size fits the headroom on its own");
        assert_eq!(issued.session.record().declared_size, Some(3_000));
    }

    // Third, at a size that cannot fit however the race goes — so the preflight is shown to be
    // engaged at all, rather than inert.
    let refused = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(library_id, fixtures.alpha.owner, "third.pdf", 8_192),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .unwrap_err();
    tx.commit().await.expect("commit");

    assert!(matches!(refused, UploadError::StorageQuotaExceeded { .. }), "got: {refused:?}");
    assert_eq!(store.created().len(), 2, "6 000 bytes of sessions against 4 096 of quota");

    pool.close().await;
    drop(db);
}

/// `MONITOR` and an absent quota row never refuse a session; `BLOCK` refuses the identical one.
///
/// The refusal is asserted first, so the two "not refused" legs are statements about a preflight
/// that demonstrably engages. `tenant-beta` carries the unmetered case, with the same library name
/// and the same declared size as alpha's refusal.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migrations 0006 and 0018; CI runs it with --include-ignored"]
async fn monitor_and_unmetered_tenants_are_never_refused_at_creation() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let store = RecordingStore::default();
    let limits = UploadLimits::unrestricted_up_to(1024 * 1024);

    set_quota(&pool, alpha, 1_024, Enforcement::Block).await;
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, alpha_library) =
        library(&mut tx, alpha, fixtures.alpha.owner, "contracts", None).await;
    let refused = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(alpha_library, fixtures.alpha.owner, "brief.pdf", 4_096),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(refused, UploadError::StorageQuotaExceeded { .. }), "got: {refused:?}");

    // Same tenant, same size, enforcement lowered: counted, never refused.
    set_quota(&pool, alpha, 1_024, Enforcement::Monitor).await;
    let monitored = UploadService::create(
        &mut tx,
        &store,
        alpha,
        &upload(alpha_library, fixtures.alpha.owner, "monitored.pdf", 4_096),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("MONITOR promises not to refuse");
    assert_eq!(monitored.session.record().declared_size, Some(4_096));
    tx.commit().await.expect("commit");

    // And a tenant with no quota row at all is unmetered rather than refused: provisioning order
    // must not be the difference between a working deployment and a read-only one.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
    let (_workspace, beta_library) =
        library(&mut tx, beta, fixtures.beta.owner, "contracts", None).await;
    let unmetered = UploadService::create(
        &mut tx,
        &store,
        beta,
        &upload(beta_library, fixtures.beta.owner, "brief.pdf", 4_096),
        &limits,
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("an unconfigured tenant is unmetered");
    assert_eq!(unmetered.session.record().declared_size, Some(4_096));
    tx.commit().await.expect("commit");

    assert_eq!(store.created().len(), 2, "one refusal, two issues");

    pool.close().await;
    drop(db);
}

// ---------------------------------------------------------------------------------------------
// `ENC-787` — reclaiming sessions stranded in `SCANNING`
// ---------------------------------------------------------------------------------------------

/// Drives one session to `SCANNING` and returns its id and staged key.
///
/// Goes through `UploadService::complete` rather than writing `'SCANNING'` into the column, because
/// the property under test is about sessions the real completion path produced. A fixture written by
/// hand could carry a state combination the machine cannot reach, and a reclaim tested only against
/// those would be a reclaim tested against nothing that exists.
async fn scanning_session(
    tx: &mut TenantScoped,
    store: &RecordingStore,
    tenant: TenantId,
    owner: UserId,
    library_id: LibraryId,
    name: &str,
) -> (enclave_uploads::UploadSessionId, String) {
    let issued = UploadService::create(
        tx,
        store,
        tenant,
        &upload(library_id, owner, name, 64),
        &UploadLimits::unrestricted_up_to(1024),
        Duration::hours(24),
        Utc::now(),
    )
    .await
    .expect("create");
    let id = issued.session.id();
    let key = issued.session.record().staged.as_str().to_owned();

    let completion =
        UploadService::complete(tx, store, tenant, id, &reported(64), Vec::new(), Utc::now())
            .await
            .expect("complete");
    assert!(matches!(completion, Completion::HandedOff { .. }), "the session must reach SCANNING");
    (id, key)
}

/// Writes the `files` and `file_versions` rows a *correctly completed* upload would have left.
///
/// This is the whole point of the control: `ENC-691` makes the staged key the version's `object_key`
/// verbatim, so this row is what stands between the reclaim and a live file's only copy of its
/// bytes.
async fn commit_version_for(
    conn: &mut PgConnection,
    tenant: TenantId,
    workspace: WorkspaceId,
    library_id: LibraryId,
    owner: UserId,
    object_key: &str,
    name: &str,
) {
    let file = FileId::new_v7();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, status, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, NULL, 'FILE', $5, $6, 'application/pdf', 'PROCESSING', $7, $7,
                 $8, $8)",
    )
    .bind(sql(file))
    .bind(sql(tenant))
    .bind(sql(workspace))
    .bind(sql(library_id))
    .bind(name)
    .bind(name.to_lowercase())
    .bind(sql(owner))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert the file row");

    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 64, $6, 'application/pdf', 1, 0, 'SCANNING', 'PENDING', $7,
                 $8)",
    )
    .bind(Uuid::now_v7())
    .bind(sql(tenant))
    .bind(sql(file))
    .bind(object_key)
    .bind(Uuid::nil())
    .bind(DIGEST_HEX)
    .bind(sql(owner))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert the version row");
}

/// Ages a session's `updated_at` an hour into the past, so the grace period has passed for it.
async fn age_one_hour(conn: &mut PgConnection, id: enclave_uploads::UploadSessionId) {
    sqlx::query("UPDATE upload_sessions SET updated_at = now() - interval '1 hour' WHERE id = $1")
        .bind(sql(id))
        .execute(&mut *conn)
        .await
        .expect("age the session");
}

/// The property `ENC-787` exists for, and the controls that make it mean something.
///
/// Three `SCANNING` sessions, produced by the same code path, differing only in the two facts the
/// claim looks at:
///
/// * **stranded** — idle, no version behind it. Must be collected.
/// * **committed** — idle, *with* a version naming its staged key. Must **not** be collected, and
///   this is the assertion that matters most: the staged key is the version's `object_key`, so
///   collecting it would delete a live file's only copy while leaving the row pointing at it.
/// * **fresh** — no version, but handed off within the grace period. Must not be collected, because
///   a completion that is genuinely in flight looks exactly like a stranded one for a moment.
///
/// "No live session is collected" passes for free against a pass that collects nothing, so the
/// stranded session is the positive control and its `reclaimed: 1` is asserted in the same run — and
/// the store's delete list is asserted to be *exactly* the stranded key, which is the assertion that
/// fails if the pass over-collects rather than under-collects.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_stranded_session_is_reclaimed_and_a_committed_one_is_never_touched() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (workspace, library_id) = library(&mut tx, alpha, owner, "contracts", None).await;

    let (stranded_id, stranded_key) =
        scanning_session(&mut tx, &store, alpha, owner, library_id, "stranded.pdf").await;
    let (committed_id, committed_key) =
        scanning_session(&mut tx, &store, alpha, owner, library_id, "committed.pdf").await;
    let (fresh_id, fresh_key) =
        scanning_session(&mut tx, &store, alpha, owner, library_id, "fresh.pdf").await;

    commit_version_for(
        &mut tx,
        alpha,
        workspace,
        library_id,
        owner,
        &committed_key,
        "committed.pdf",
    )
    .await;
    tx.commit().await.expect("commit the fixtures");

    // All three were handed off just now. Age the first two an hour into the past so the grace
    // period separates them from `fresh`, leaving the *version* as the only difference between
    // `stranded` and `committed`.
    let mut conn = db.connect().await.expect("connect");
    age_one_hour(&mut conn, stranded_id).await;
    age_one_hour(&mut conn, committed_id).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let report = enclave_uploads::reclaim_stranded(
        &mut tx,
        &store,
        alpha,
        Utc::now(),
        Duration::minutes(30),
        100,
    )
    .await
    .expect("reclaim");
    tx.commit().await.expect("commit the reclaim");

    assert_eq!(
        (report.found, report.reclaimed, report.deferred),
        (1, 1, 0),
        "exactly the stranded session, and it was actually collected"
    );

    // The delete list is the sharp assertion: it fails if the pass collected too much as well as if
    // it collected too little.
    assert_eq!(
        store.deleted(),
        vec![stranded_key],
        "only the stranded session's object may be deleted"
    );
    assert!(
        !store.deleted().contains(&committed_key),
        "deleting a committed session's object destroys a live file's only copy"
    );
    assert!(!store.deleted().contains(&fresh_key), "a session still in flight keeps its bytes");

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &stranded_id.to_string()).await, "EXPIRED");
    assert_eq!(
        stored_state(&mut conn, &committed_id.to_string()).await,
        "SCANNING",
        "a session with a version behind it is antivirus's, not the reaper's"
    );
    assert_eq!(stored_state(&mut conn, &fresh_id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}

/// A store that refuses the delete leaves the row `SCANNING` for the next pass.
///
/// The mirror of [`a_store_that_refuses_a_delete_leaves_the_session_for_the_next_pass`], and it
/// matters more here: `claim_stranded`'s predicate is `state = 'SCANNING'`, so a row marked
/// `EXPIRED` before a successful delete is *permanently* invisible to this pass — unlike the
/// ordinary reaper's rows, there is no broader index predicate that would ever surface it again.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_refused_delete_leaves_a_stranded_session_claimable_again() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (_workspace, library_id) = library(&mut tx, alpha, owner, "contracts", None).await;
    let (id, _key) =
        scanning_session(&mut tx, &store, alpha, owner, library_id, "stranded.pdf").await;
    tx.commit().await.expect("commit");

    let mut conn = db.connect().await.expect("connect");
    age_one_hour(&mut conn, id).await;

    store.fail_deletes();
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let report = enclave_uploads::reclaim_stranded(
        &mut tx,
        &store,
        alpha,
        Utc::now(),
        Duration::minutes(30),
        100,
    )
    .await
    .expect("reclaim");
    tx.commit().await.expect("commit");

    assert_eq!((report.found, report.reclaimed, report.deferred), (1, 0, 1));

    // Still `SCANNING`. Marking it `EXPIRED` here would put it outside this pass's only predicate
    // and orphan the bytes for good.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}

/// Another tenant's stranded session is invisible, and this tenant's is collected in the same run.
///
/// **Isolation layer**, and stated as such: row-level security, the `tenant_id = $1` predicate and
/// the `TenantScoped` context each refuse this independently, so it would pass with any one of them
/// removed. It is asserted because a sweep that *deletes object bytes* is the worst possible place
/// for a tenant predicate to be missing, not because this test proves the predicate is what stops
/// it. The same-run positive control is what keeps it from passing against a pass that collects
/// nothing at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and migration 0006 (upload_sessions); CI runs it with --include-ignored"]
async fn a_reclaim_scoped_to_one_tenant_cannot_see_anothers_stranded_session() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let store = RecordingStore::default();

    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let (_ws, beta_library) = library(&mut tx, beta, fixtures.beta.owner, "beta", None).await;
    let (beta_id, beta_key) =
        scanning_session(&mut tx, &store, beta, fixtures.beta.owner, beta_library, "beta.pdf")
            .await;
    tx.commit().await.expect("commit beta");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let (_ws, alpha_library) = library(&mut tx, alpha, fixtures.alpha.owner, "alpha", None).await;
    let (alpha_id, alpha_key) =
        scanning_session(&mut tx, &store, alpha, fixtures.alpha.owner, alpha_library, "alpha.pdf")
            .await;
    tx.commit().await.expect("commit alpha");

    let mut conn = db.connect().await.expect("connect");
    age_one_hour(&mut conn, alpha_id).await;
    age_one_hour(&mut conn, beta_id).await;

    // Alpha's sweep. Beta's session differs in no way that matters — it is another tenant's.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let report = enclave_uploads::reclaim_stranded(
        &mut tx,
        &store,
        alpha,
        Utc::now(),
        Duration::minutes(30),
        100,
    )
    .await
    .expect("reclaim");
    tx.commit().await.expect("commit");

    assert_eq!((report.found, report.reclaimed), (1, 1), "alpha's own, and only alpha's");
    assert_eq!(store.deleted(), vec![alpha_key], "beta's object must not be touched");
    assert!(!store.deleted().contains(&beta_key));

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(stored_state(&mut conn, &alpha_id.to_string()).await, "EXPIRED");
    assert_eq!(stored_state(&mut conn, &beta_id.to_string()).await, "SCANNING");

    pool.close().await;
    drop(db);
}
