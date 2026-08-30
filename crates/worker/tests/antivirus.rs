//! The antivirus pass, end to end against a real database — `ENC-641`.
//!
//! # What these tests are about, and what they are not
//!
//! `docs/12 §1.1`: whether ClamAV detects malware is ClamAV's problem, settled by its own suite and
//! by `crates/antivirus/tests/eicar.rs` against a real clamd. Ours is the wiring — that a *verdict*
//! moves `av_status` and `status` correctly, that an infected version never becomes readable, and
//! that a clean one does.
//!
//! So the engine here is a fake, and that is the design rather than a concession to there being no
//! clamd on a laptop: the subject is the transition, and a fake verdict is the only way to exercise
//! all five of them — `Clean`, `Infected`, `Unsupported`, and both legs of `Error` —
//! deterministically and in one run. There is also no clamd on a laptop, and a test suite that could
//! only run where one is installed is a suite nobody watches fail.
//!
//! The *infected* fixture is still [`eicar_test_file`], the industry-standard harmless probe, and the
//! fake matches it the way a real engine does — anywhere in the object — rather than by a magic
//! string this file invented.
//!
//! # The absence that must not pass for free
//!
//! `docs/12 §1.2`, and this file is the live example the rule warns about. **"An infected file is
//! never served" passed for free against every build of this product until this task**, because
//! nothing was ever served: `readable_version` answered `None` for every version in every tenant.
//! Every negative assertion below is therefore paired, in the same test and over the same pass, with
//! a clean control that *does* become readable.
//!
//! # Why the store is a fake and the database is not
//!
//! `tests/scan.rs`'s reason, unchanged: only a real PostgreSQL can answer "what does
//! `file_versions` say now", and the store is being asked "were you read", which a recording fake
//! answers better than MinIO does. This one is keyed by object key, because half of these tests need
//! two versions with different bytes inside one pass.
//!
//! `#[ignore]`d because they need PostgreSQL; CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_antivirus::{
    eicar_test_file, AntivirusScanner, EngineInfo, NoScanningPerformed, Result as AvResult,
    ScanHint, ScanPolicy, ScanVerdict,
};
use enclave_config::UnavailablePolicy;
use enclave_core::{FileId, TenantId, VersionId};
use enclave_db::DbPool;
use enclave_preview::repo::readable_version;
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StorageError,
    StoreCapabilities, Support, UploadRequest, UploadSession,
};
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::antivirus::{av_pass, AvCursor, AvPass};
use enclave_worker::Stop;
use futures::StreamExt as _;
use sqlx::{PgConnection, Row as _};
use url::Url;

mod common;
use common::{a_file_on_a_spine, a_version};

// =================================================================================================
// Fixtures
// =================================================================================================

/// A blob store that serves a different body per key and can be told a key is missing.
///
/// Keyed, unlike `common::RecordingStore`, because the shape of almost every test here is *two*
/// versions in one pass — the infected one and the control — and one body for both would make the
/// control meaningless.
#[derive(Default)]
struct KeyedStore {
    bodies: Mutex<HashMap<String, Vec<u8>>>,
    reads: Mutex<Vec<String>>,
}

impl KeyedStore {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Puts `body` at the key the version fixture derives from an id.
    fn put(&self, version: VersionId, body: Vec<u8>) {
        self.bodies
            .lock()
            .expect("not poisoned")
            .insert(format!("objects/{}", version.as_uuid()), body);
    }

    fn reads(&self) -> Vec<String> {
        self.reads.lock().expect("not poisoned").clone()
    }

    fn read_count(&self, version: VersionId) -> usize {
        let key = format!("objects/{}", version.as_uuid());
        self.reads().iter().filter(|read| **read == key).count()
    }
}

#[async_trait]
impl PublicAccessCheck for KeyedStore {
    async fn verify_not_public(
        &self,
    ) -> core::result::Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for KeyedStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            // No cold tier: this double serves from memory (`ENC-946`).
            storage_tiers: Support::No,
            backend: "keyed-stub",
            multipart: Some(MultipartLimits {
                min_part_bytes: 5 * 1024 * 1024,
                max_part_bytes: 5 * 1024 * 1024 * 1024,
                max_parts: 10_000,
            }),
            signed_urls: true,
            single_use_signed_urls: false,
            max_signed_url_ttl: Duration::from_secs(900),
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: true,
            server_side_copy: true,
        }
    }

    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        unreachable!("the antivirus pass never uploads")
    }

    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        unreachable!("the antivirus pass never uploads")
    }

    async fn signed_download(&self, _key: &str, _ttl: Duration) -> StorageResult<Url> {
        // Not merely unimplemented: a signed URL for an original has no business being minted while
        // scanning, and a panic here would name that if one ever appeared.
        unreachable!("the antivirus pass never mints a download URL")
    }

    /// Honours the range, which `common::RecordingStore` does not.
    ///
    /// That is the whole point of this fake existing beside that one: the property under test in
    /// `the_engine_is_handed_the_whole_object_and_not_a_prefix` is that the pass asks for the *whole*
    /// object, and a store that served everything whatever it was asked would make that assertion
    /// pass against a pass that asked for the first kilobyte.
    async fn read_range(&self, key: &str, range: ByteRange) -> StorageResult<ByteStream> {
        self.reads.lock().expect("not poisoned").push(key.to_owned());
        let whole = self
            .bodies
            .lock()
            .expect("not poisoned")
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound { key: key.to_owned() })?;

        let start = usize::try_from(range.start()).unwrap_or(usize::MAX).min(whole.len());
        let end = range
            .end_inclusive()
            .and_then(|end| usize::try_from(end).ok())
            .map_or(whole.len(), |end| end.saturating_add(1).min(whole.len()));
        let body = whole[start..end.max(start)].to_vec();
        let length = body.len() as u64;
        Ok(ByteStream::new(
            futures::stream::once(async move { Ok(bytes::Bytes::from(body)) }),
            Some(length),
        ))
    }

    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        unreachable!("the antivirus pass never copies")
    }

    async fn delete(&self, _key: &str) -> StorageResult<()> {
        unreachable!("the antivirus pass never deletes")
    }
}

/// An engine that reads the whole stream and reports EICAR the way a real one would.
///
/// It matches the signature **anywhere** in the object rather than requiring the object to *be*
/// EICAR, which is both what a real engine does and what makes
/// `the_engine_is_handed_the_whole_object_and_not_a_prefix` an assertion: a scan that read only the
/// first N bytes of a padded file would report it clean, and that file would be published.
#[derive(Debug, Default)]
struct FakeEngine;

#[async_trait]
impl AntivirusScanner for FakeEngine {
    async fn scan(&self, mut stream: ByteStream, _hint: ScanHint) -> AvResult<ScanVerdict> {
        let mut seen = Vec::new();
        while let Some(chunk) = stream.next().await {
            seen.extend_from_slice(&chunk?);
        }
        let signature = eicar_test_file();
        let found = seen.windows(signature.len()).any(|window| window == signature.as_slice());
        Ok(if found {
            ScanVerdict::Infected { signature: "Win.Test.EICAR_HDB-1".to_owned() }
        } else {
            ScanVerdict::Clean
        })
    }

    async fn engine_info(&self) -> AvResult<EngineInfo> {
        Ok(EngineInfo {
            engine: "FakeAV 1.0".to_owned(),
            signature_version: Some("27621".to_owned()),
            scans_content: true,
        })
    }
}

/// An engine that is not there: every scan is a retryable outage.
///
/// Exactly what `crates/antivirus` says a refused connection produces — a *verdict*, not an error,
/// so that `av.unavailable_policy` is applied to it.
#[derive(Debug, Default)]
struct EngineDown;

#[async_trait]
impl AntivirusScanner for EngineDown {
    async fn scan(&self, _stream: ByteStream, _hint: ScanHint) -> AvResult<ScanVerdict> {
        Ok(ScanVerdict::Error { retryable: true })
    }

    async fn engine_info(&self) -> AvResult<EngineInfo> {
        Err(enclave_antivirus::AntivirusError::Unreachable)
    }
}

/// An engine that identifies itself and then fails every scan — a flapping clamd.
///
/// Distinct from [`EngineDown`], and the distinction is load-bearing: an engine that cannot be
/// identified is treated as non-scanning, so the `SKIPPED` half of the queue is not offered to it at
/// all. Reaching "a rescan during an outage" therefore needs an engine that answers `engine_info`
/// and not `scan`.
#[derive(Debug, Default)]
struct ScanningFails;

#[async_trait]
impl AntivirusScanner for ScanningFails {
    async fn scan(&self, _stream: ByteStream, _hint: ScanHint) -> AvResult<ScanVerdict> {
        Ok(ScanVerdict::Error { retryable: true })
    }

    async fn engine_info(&self) -> AvResult<EngineInfo> {
        Ok(EngineInfo {
            engine: "FakeAV 1.0".to_owned(),
            signature_version: Some("27621".to_owned()),
            scans_content: true,
        })
    }
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(4).await.expect("pool");
    (db, fixtures, pool)
}

/// One pass over `tenant`, from the start of the sweep, under **the policy a shipped deployment
/// resolves to**.
///
/// `ScanPolicy::from_config` of an unmodified `antivirus:` section rather than
/// `ScanPolicy::default()`, even though the two are equal today. The equality is the property worth
/// testing: an `unsupported_policy` key added to configuration would make these tests run under a
/// policy no deployment has, and every one of them would keep passing.
async fn sweep(
    pool: &DbPool,
    tenant: TenantId,
    scanner: &dyn AntivirusScanner,
    store: &KeyedStore,
) -> AvPass {
    let shipped = ScanPolicy::from_config(&enclave_config::AntivirusConfig::default());
    sweep_with(pool, tenant, scanner, store, shipped).await
}

async fn sweep_with(
    pool: &DbPool,
    tenant: TenantId,
    scanner: &dyn AntivirusScanner,
    store: &KeyedStore,
    policy: ScanPolicy,
) -> AvPass {
    av_pass(pool, tenant, scanner, store, policy, 10, AvCursor::start(), &Stop::new())
        .await
        .expect("the pass must not fail on a version it cannot scan")
}

/// The `(status, av_status)` pair a version's row now carries.
async fn state(conn: &mut PgConnection, version: VersionId) -> (String, String) {
    let row = sqlx::query("SELECT status, av_status FROM file_versions WHERE id = $1")
        .bind(version.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("the version row is still there");
    (row.try_get("status").expect("status"), row.try_get("av_status").expect("av_status"))
}

/// The provenance columns `docs/06 §6.2` requires beside a verdict.
async fn provenance(
    conn: &mut PgConnection,
    version: VersionId,
) -> (Option<String>, Option<String>, Option<DateTime<Utc>>) {
    let row = sqlx::query(
        "SELECT av_engine, av_signature_version, av_scanned_at FROM file_versions WHERE id = $1",
    )
    .bind(version.as_uuid())
    .fetch_one(&mut *conn)
    .await
    .expect("the version row is still there");
    (
        row.try_get("av_engine").expect("av_engine"),
        row.try_get("av_signature_version").expect("av_signature_version"),
        row.try_get("av_scanned_at").expect("av_scanned_at"),
    )
}

async fn file_status(conn: &mut PgConnection, file: FileId) -> String {
    sqlx::query("SELECT status FROM files WHERE id = $1")
        .bind(file.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("the file row")
        .try_get("status")
        .expect("status")
}

/// Whether **the control** — the one every read path uses — will serve this version.
///
/// `readable_version` and not a re-derived predicate: a second query deciding what is readable is
/// the one that drifts, and it would drift in the direction of agreeing with whatever this pass
/// happened to write.
async fn is_readable(pool: &DbPool, tenant: TenantId, version: VersionId) -> bool {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let readable = readable_version(&mut tx, tenant, version).await.expect("lookup");
    tx.commit().await.expect("commit");
    readable.is_some()
}

/// Points a file at a version and leaves it `PROCESSING`, exactly as `VersionService::commit` does.
///
/// Without this the file's fixture status is `AVAILABLE` and `current_version_id` is `NULL`, so the
/// `files` half of every assertion below would be about a row the pass correctly refuses to touch.
async fn commit_pointer(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    version: VersionId,
) {
    sqlx::query(
        "UPDATE files SET current_version_id = $3, status = 'PROCESSING' \
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(version.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("point the file at its version");
}

/// A freshly committed version: `SCANNING` / `PENDING`, its file pointing at it and `PROCESSING`.
async fn an_upload(
    conn: &mut PgConnection,
    fixtures: &Fixtures,
    tenant: TenantId,
    store: &KeyedStore,
    body: Vec<u8>,
) -> (FileId, VersionId) {
    let owner =
        if tenant == fixtures.alpha.id { fixtures.alpha.owner } else { fixtures.beta.owner };
    let (spine, version) =
        a_file_on_a_spine(conn, tenant, owner, "SCANNING", "PENDING", "text/plain").await;
    commit_pointer(conn, tenant, spine.file, version).await;
    store.put(version, body);
    (spine.file, version)
}

// =================================================================================================
// The assertion this whole row exists for
// =================================================================================================

/// **Upload → scan → `AVAILABLE` → readable.** Rule 9's loop, closed.
///
/// This is the test that would have caught `ENC-641`: before this task every one of these assertions
/// failed, because nothing moved the version and `readable_version` answered `None` forever.
///
/// It asserts the provenance columns too, and that is not thoroughness — `docs/06 §6.2` requires the
/// engine and signature generation beside the verdict, because a clean result recorded without them
/// cannot be re-judged when the signature database moves on, and a signature-update sweep would have
/// no way to tell what was scanned by which generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_upload_becomes_readable_once_the_engine_has_cleared_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();
    let (file, version) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"an ordinary document".to_vec()).await;

    assert!(!is_readable(&pool, alpha, version).await, "a fresh upload must not be readable");

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;

    assert_eq!(pass.considered, 1);
    assert_eq!(pass.cleared, 1, "a clean version was not cleared");
    assert_eq!(pass.written, 1);
    assert_eq!(store.read_count(version), 1, "the object was read exactly once");

    assert_eq!(state(&mut conn, version).await, ("AVAILABLE".to_owned(), "CLEAN".to_owned()));
    assert_eq!(file_status(&mut conn, file).await, "AVAILABLE", "the file still says PROCESSING");
    assert!(is_readable(&pool, alpha, version).await, "a cleared version is still not served");

    let (engine, signatures, scanned_at) = provenance(&mut conn, version).await;
    assert_eq!(engine.as_deref(), Some("FakeAV 1.0"));
    assert_eq!(
        signatures.as_deref(),
        Some("27621"),
        "a verdict with no signature generation \
                                                      cannot be re-judged when signatures move on"
    );
    assert!(scanned_at.is_some());

    drop(db);
}

/// An infected version is quarantined and never becomes readable — **and a clean one under the same
/// pass does**.
///
/// The pairing is the whole test (`docs/12 §1.2`). "The infected version is not readable" is an
/// assertion about an absence and held for free against every build before this one, so the control
/// is in the same tenant, the same pass and the same engine: if the pass did nothing, the control
/// fails and names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_infected_version_is_quarantined_while_a_clean_one_beside_it_becomes_readable() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    let (bad_file, infected) =
        an_upload(&mut conn, &fixtures, alpha, &store, eicar_test_file()).await;
    let (good_file, clean) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"a harmless memo".to_vec()).await;

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 2);
    assert_eq!(pass.quarantined, 1);
    assert_eq!(pass.cleared, 1);

    assert_eq!(state(&mut conn, infected).await, ("QUARANTINED".to_owned(), "INFECTED".to_owned()));
    assert!(!is_readable(&pool, alpha, infected).await, "malware became readable");
    assert_eq!(file_status(&mut conn, bad_file).await, "QUARANTINED");

    // The positive control. Without it every assertion above passes against a pass that writes
    // nothing at all — which is exactly the implementation `ENC-641` describes.
    assert_eq!(state(&mut conn, clean).await, ("AVAILABLE".to_owned(), "CLEAN".to_owned()));
    assert!(is_readable(&pool, alpha, clean).await);
    assert_eq!(file_status(&mut conn, good_file).await, "AVAILABLE");

    drop(db);
}

/// The evidence of a detection survives, in the row rather than in a log line somebody rotated.
///
/// Deleting the version would have been the tempting answer and it is the wrong one: an
/// administrator investigating an incident needs to know it happened, which version it was, when it
/// was found and by which engine and signature generation. All five are columns of the row that is
/// still there.
///
/// What is **not** recorded is the signature *name*, because `file_versions` has no column for it.
/// That is a gap and it is logged as `ENC-645` rather than papered over; this test pins what is
/// stored today so that closing that row has to change a line here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_detection_leaves_evidence_an_administrator_can_find() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();
    let (_file, infected) = an_upload(&mut conn, &fixtures, alpha, &store, eicar_test_file()).await;

    sweep(&pool, alpha, &FakeEngine, &store).await;

    let row = sqlx::query("SELECT count(*) AS n FROM file_versions WHERE id = $1")
        .bind(infected.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("count");
    assert_eq!(row.try_get::<i64, _>("n").expect("n"), 1, "the infected version was deleted");

    let (engine, signatures, scanned_at) = provenance(&mut conn, infected).await;
    assert_eq!(engine.as_deref(), Some("FakeAV 1.0"), "nothing records which engine found it");
    assert_eq!(signatures.as_deref(), Some("27621"));
    assert!(scanned_at.is_some(), "nothing records when it was found");

    drop(db);
}

// =================================================================================================
// The scanner is not available
// =================================================================================================

/// G6, end to end: with the engine down and `HOLD`, the version waits in `SCANNING` and is not
/// readable — **and the same fixture becomes readable the moment an engine answers.**
///
/// The second half is what makes the first mean anything. "Still `SCANNING`" is the state every
/// version in this product was already in, so without the control this test passes against a pass
/// that was never called.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_engine_that_is_down_holds_the_version_and_an_engine_that_answers_releases_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();
    let (file, version) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"an ordinary document".to_vec()).await;

    let hold = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };
    let pass = sweep_with(&pool, alpha, &EngineDown, &store, hold).await;

    assert_eq!(pass.held, 1, "an outage must be counted so somebody can see it");
    assert_eq!(pass.written, 0, "an outage recorded a verdict it did not reach");
    assert_eq!(state(&mut conn, version).await, ("SCANNING".to_owned(), "PENDING".to_owned()));
    assert_eq!(file_status(&mut conn, file).await, "PROCESSING", "the file moved during an outage");
    assert!(!is_readable(&pool, alpha, version).await);
    assert!(pass.backlog(Utc::now()).is_some(), "the stuck backlog must be reportable");

    // And the version is still in the queue, so the outage ending is all it takes.
    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.cleared, 1, "the held version was not re-offered once the engine came back");
    assert!(is_readable(&pool, alpha, version).await);

    drop(db);
}

/// A version whose object is missing is recorded `ERROR`, and the version ordered behind it is still
/// scanned in the same pass.
///
/// The starvation case. The queue is a query with no claim column, so a version that raised an error
/// would be re-selected first on every sweep forever and nothing behind it would ever be reached —
/// the whole tenant unreadable because of one absent object. Recording `ERROR` takes it out of the
/// queue and leaves it unreadable, which is both halves of the right answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_missing_object_is_recorded_and_does_not_starve_the_version_behind_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    // Created first, so it is first in the `(created_at, id)` order the queue uses. No body is put
    // in the store for it.
    let (spine, missing) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "SCANNING",
        "PENDING",
        "text/plain",
    )
    .await;
    commit_pointer(&mut conn, alpha, spine.file, missing).await;

    let (_file, behind) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"a harmless memo".to_vec()).await;

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 2);
    assert_eq!(pass.errored, 1);
    assert_eq!(pass.cleared, 1, "the version behind the broken one was starved");
    assert!(is_readable(&pool, alpha, behind).await);

    assert_eq!(state(&mut conn, missing).await, ("SCANNING".to_owned(), "ERROR".to_owned()));
    assert!(!is_readable(&pool, alpha, missing).await);

    // And a second sweep does not offer it again, which is what stops it consuming a slot forever.
    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 0, "a version recorded ERROR was re-offered");

    // The control for that absence: a version that *is* pending is still offered by the same query.
    let (_file, fresh) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"another memo".to_vec()).await;
    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 1, "the queue stopped offering anything at all");
    assert!(is_readable(&pool, alpha, fresh).await);

    drop(db);
}

// =================================================================================================
// `AntivirusProvider::None`
// =================================================================================================

/// A deployment that turned antivirus off publishes **nothing**, and its corpus is recovered when an
/// engine arrives.
///
/// Both halves are decisions rather than consequences, and both are the ones a permissive reading
/// would get wrong.
///
/// `NoScanningPerformed` answers `Unsupported` — never `Clean`, because it did not look — so
/// `decide` sends it down the unsupported-content path, where `ScanPolicy::from_config` has pinned
/// `BLOCK`. Every version is therefore `QUARANTINED` / `SKIPPED` and unreadable, which is the
/// correct answer to "you turned off antivirus and did not say what should happen instead".
///
/// The second half is what makes that liveable: `SKIPPED` is re-offered the moment an engine that
/// actually inspects content is configured, so `provider: none` is loud rather than terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_disabled_provider_publishes_nothing_and_an_engine_arriving_recovers_the_corpus() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();
    let (file, version) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"an ordinary document".to_vec()).await;

    let disabled = NoScanningPerformed::new();
    let pass = sweep(&pool, alpha, &disabled, &store).await;

    assert_eq!(pass.quarantined, 1, "a deployment with no engine published something");
    assert_eq!(pass.cleared, 0);
    assert_eq!(state(&mut conn, version).await, ("QUARANTINED".to_owned(), "SKIPPED".to_owned()));
    assert!(!is_readable(&pool, alpha, version).await, "unscanned content became readable");
    assert_eq!(file_status(&mut conn, file).await, "QUARANTINED");

    // A second pass with the same disabled provider changes nothing and — crucially — does not
    // re-read the object: the `SKIPPED` half of the queue is gated on the engine scanning content.
    let reads_before = store.read_count(version);
    let pass = sweep(&pool, alpha, &disabled, &store).await;
    assert_eq!(pass.considered, 0, "a non-scanning engine was offered its own SKIPPED corpus");
    assert_eq!(store.read_count(version), reads_before);

    // And the recovery: an engine that does inspect content is offered the same version again and
    // clears it.
    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 1, "a real engine was not offered the skipped corpus");
    assert_eq!(pass.cleared, 1);
    assert_eq!(state(&mut conn, version).await, ("AVAILABLE".to_owned(), "CLEAN".to_owned()));
    assert!(is_readable(&pool, alpha, version).await);
    assert_eq!(file_status(&mut conn, file).await, "AVAILABLE");

    drop(db);
}

/// A recovery sweep that runs while the engine is down leaves the earlier verdict standing.
///
/// The `SKIPPED` half of the queue means an outage now lands on rows that already carry a verdict,
/// and the wrong answer is available and tempting: record what this attempt concluded, which is
/// "nothing". That would replace `QUARANTINED` / `SKIPPED` with `SCANNING` / `PENDING` — the evidence
/// that a version was once refused, deleted in order to record that an attempt did not happen, and
/// the file dragged out of `QUARANTINED` with it.
///
/// Added because breaking this rule failed **no integration test at all**: the unit test over
/// `Target::of` caught it and nothing that touched a database did, since no other test here rescans
/// during an outage (`docs/12 §1.2`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rescan_during_an_outage_leaves_the_earlier_verdict_standing() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    let (spine, skipped) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "QUARANTINED",
        "SKIPPED",
        "text/plain",
    )
    .await;
    commit_pointer(&mut conn, alpha, spine.file, skipped).await;
    sqlx::query("UPDATE files SET status = 'QUARANTINED' WHERE id = $1")
        .bind(spine.file.as_uuid())
        .execute(&mut conn)
        .await
        .expect("the file follows its quarantined current version");
    store.put(skipped, b"harmless".to_vec());

    // `EngineDown` reports `scans_content: false` only because it cannot be identified at all; the
    // queue treats an unidentifiable engine as non-scanning, so the SKIPPED row is not even offered.
    // The state that matters is therefore reached with an engine that *is* identified and whose
    // scans fail — which is a flapping clamd, and is what `ScanningFails` is.
    let hold = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };
    let pass = sweep_with(&pool, alpha, &ScanningFails, &store, hold).await;

    assert_eq!(pass.considered, 1, "the recovery sweep did not offer the skipped version");
    assert_eq!(pass.held, 1);
    assert_eq!(pass.written, 0, "an outage overwrote a recorded verdict");
    assert_eq!(state(&mut conn, skipped).await, ("QUARANTINED".to_owned(), "SKIPPED".to_owned()));
    assert_eq!(file_status(&mut conn, spine.file).await, "QUARANTINED");
    assert!(!is_readable(&pool, alpha, skipped).await);

    // The positive control: the same fixture, the same sweep, an engine that answers — the verdict
    // does move. Without it every assertion above passes against a pass that considered nothing.
    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.cleared, 1);
    assert!(is_readable(&pool, alpha, skipped).await);
    assert_eq!(file_status(&mut conn, spine.file).await, "AVAILABLE");

    drop(db);
}

/// The recovery sweep re-offers `SKIPPED` and never `INFECTED`.
///
/// The dangerous direction of the test above. `SKIPPED` means nobody looked, so looking again is
/// right; `INFECTED` means somebody looked and found malware, and the bytes are immutable, so a
/// sweep that re-offered it would be one bug away from un-quarantining known malware.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rescan_never_re_offers_a_version_that_was_found_infected() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    // Quarantined and INFECTED, exactly as a detection leaves it — but with harmless bytes in the
    // store, so that a pass which *did* re-offer it would find it clean and publish it. That is the
    // failure this test is looking for, and against EICAR bytes it would be invisible.
    let (spine, infected) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "QUARANTINED",
        "INFECTED",
        "text/plain",
    )
    .await;
    commit_pointer(&mut conn, alpha, spine.file, infected).await;
    store.put(infected, b"harmless now".to_vec());

    // The control, in the same pass: a SKIPPED version *is* re-offered and does clear.
    let (_spine, skipped) = {
        let (spine, version) = a_file_on_a_spine(
            &mut conn,
            alpha,
            fixtures.alpha.owner,
            "QUARANTINED",
            "SKIPPED",
            "text/plain",
        )
        .await;
        commit_pointer(&mut conn, alpha, spine.file, version).await;
        store.put(version, b"harmless".to_vec());
        (spine, version)
    };

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;

    assert_eq!(pass.considered, 1, "the rescan offered a version that already had a verdict");
    assert_eq!(store.read_count(infected), 0, "an infected version's bytes were re-read");
    assert_eq!(state(&mut conn, infected).await, ("QUARANTINED".to_owned(), "INFECTED".to_owned()));
    assert!(!is_readable(&pool, alpha, infected).await);

    assert_eq!(pass.cleared, 1, "the SKIPPED control was not re-offered either");
    assert!(is_readable(&pool, alpha, skipped).await);

    drop(db);
}

// =================================================================================================
// Ordering, isolation and the file pointer
// =================================================================================================

/// A version that is already `CLEAN` is never offered again.
///
/// This is the ordering guarantee against the two content passes stated as a property of the queue.
/// [`crate::indexing`] and [`crate::scan`] read a version once it is `CLEAN`; if this pass could
/// re-offer a `CLEAN` version it could also move it to `INFECTED` afterwards, leaving excerpts in the
/// index for content no read path would serve. It cannot, because the queue does not offer it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_version_that_has_been_cleared_is_never_scanned_again() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();
    let (_file, version) =
        an_upload(&mut conn, &fixtures, alpha, &store, b"an ordinary document".to_vec()).await;

    assert_eq!(sweep(&pool, alpha, &FakeEngine, &store).await.cleared, 1);
    let reads = store.read_count(version);

    let again = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(again.considered, 0, "a cleared version was offered a second verdict");
    assert_eq!(store.read_count(version), reads, "a cleared version's bytes were read again");
    assert!(is_readable(&pool, alpha, version).await);

    drop(db);
}

/// A pass for one tenant never reads or moves another tenant's versions.
///
/// `tenant-beta` exists so cross-tenant assertions are realistic. Both halves in one test: beta's
/// version is untouched by alpha's pass, and beta's own pass clears it — so the first assertion is
/// isolation rather than a pass that did nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_pass_for_one_tenant_never_moves_another_tenants_versions() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    let (_a_file, mine) = an_upload(&mut conn, &fixtures, alpha, &store, b"mine".to_vec()).await;
    let (_b_file, theirs) = an_upload(&mut conn, &fixtures, beta, &store, b"theirs".to_vec()).await;

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 1, "alpha's pass considered a version it does not own");
    assert_eq!(store.read_count(theirs), 0, "another tenant's bytes were read");
    assert_eq!(state(&mut conn, theirs).await, ("SCANNING".to_owned(), "PENDING".to_owned()));
    assert!(!is_readable(&pool, beta, theirs).await);
    assert!(is_readable(&pool, alpha, mine).await);

    // The control: beta's own pass does clear it, so the isolation above is a predicate working and
    // not a queue that is broken.
    assert_eq!(sweep(&pool, beta, &FakeEngine, &store).await.cleared, 1);
    assert!(is_readable(&pool, beta, theirs).await);

    drop(db);
}

/// Quarantining a superseded version does not take a file whose current version is clean offline.
///
/// The `current_version_id` guard, and the fixture is arranged so that guard is the **only** thing
/// holding the property. The first version of this test had both versions pending in one pass, and
/// it passed with the predicate deleted: the queue is ordered oldest-first, so the *current* version
/// was written last and its `AVAILABLE` simply overwrote the other's `QUARANTINED`. The assertion
/// was true because of the ordering, not because of the guard — `docs/12 §1.2`, found by breaking it.
///
/// So the current version is already `CLEAN` and out of the queue, and the superseded one is
/// `SKIPPED` — a version from a `provider: none` era, which the recovery sweep re-offers. It is the
/// only version the pass touches, and its bytes turn out to have been malware all along. Without the
/// predicate the file goes to `QUARANTINED` and a tenant's live document disappears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn quarantining_a_superseded_version_leaves_the_files_current_content_alone() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    let (spine, superseded) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "QUARANTINED",
        "SKIPPED",
        "text/plain",
    )
    .await;
    store.put(superseded, eicar_test_file());

    let current = a_version(
        &mut conn,
        alpha,
        &spine,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;
    store.put(current, b"the good version".to_vec());
    commit_pointer(&mut conn, alpha, spine.file, current).await;
    sqlx::query("UPDATE files SET status = 'AVAILABLE' WHERE id = $1")
        .bind(spine.file.as_uuid())
        .execute(&mut conn)
        .await
        .expect("the file is serving its current version");

    let pass = sweep(&pool, alpha, &FakeEngine, &store).await;
    assert_eq!(pass.considered, 1, "the cleared current version was offered a second verdict");
    assert_eq!(pass.quarantined, 1);

    assert_eq!(
        state(&mut conn, superseded).await,
        ("QUARANTINED".to_owned(), "INFECTED".to_owned())
    );
    assert!(!is_readable(&pool, alpha, superseded).await);
    assert!(is_readable(&pool, alpha, current).await);
    assert_eq!(
        file_status(&mut conn, spine.file).await,
        "AVAILABLE",
        "a superseded infected version took the file's clean current content offline"
    );

    drop(db);
}

/// The engine is handed the whole object, not a prefix of it.
///
/// `AntivirusScanner::scan` promises a verdict about the whole stream, and a bounded read — the one
/// both extraction passes use — would make that a header-only scan: the letter of rule 9 satisfied
/// by exactly the shortcut it exists to prevent.
///
/// The signature sits after four megabytes of padding, comfortably past `RenderBudget::DEFAULT`'s
/// output cap, so a pass that collected a bounded prefix reports this file clean and publishes it.
/// The control beside it is a file of the same size with no signature in it, so the test cannot pass
/// by an engine that calls everything large infected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_engine_is_handed_the_whole_object_and_not_a_prefix() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let store = KeyedStore::new();

    let mut hidden = vec![b'.'; 4 * 1024 * 1024];
    hidden.extend_from_slice(&eicar_test_file());
    let (_bad_file, buried) = an_upload(&mut conn, &fixtures, alpha, &store, hidden).await;

    let harmless = vec![b'.'; 4 * 1024 * 1024];
    let (_good_file, large) = an_upload(&mut conn, &fixtures, alpha, &store, harmless).await;

    sweep(&pool, alpha, &FakeEngine, &store).await;

    assert_eq!(
        state(&mut conn, buried).await,
        ("QUARANTINED".to_owned(), "INFECTED".to_owned()),
        "a signature past the first few kilobytes was not seen, so the scan read a prefix"
    );
    assert!(!is_readable(&pool, alpha, buried).await);

    // The control: an object of the same size with nothing in it is clean and readable, so the
    // assertion above is about the whole object being scanned rather than about size alone.
    assert_eq!(state(&mut conn, large).await, ("AVAILABLE".to_owned(), "CLEAN".to_owned()));
    assert!(is_readable(&pool, alpha, large).await);

    drop(db);
}
