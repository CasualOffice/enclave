//! The rendition cache against a real database, and the guarantee that keeps parsers off unscanned
//! bytes.
//!
//! Two properties are worth a live PostgreSQL rather than a mock:
//!
//! 1. **`ReadableVersion` cannot be obtained for content that is not `AVAILABLE` *and* `CLEAN`.**
//!    That is `CLAUDE.md` rule 9 on the read path where it matters most, and it is a `WHERE` clause
//!    — so only the database can confirm it.
//! 2. **A generator change is a cache miss.** The predicate carries `generator_version`, which is
//!    what makes an upgrade take effect without anyone remembering to purge.
//!
//! Everything runs through the harness pool, which `SET ROLE enclave_app`s. A test that connected
//! as the cluster superuser would be testing PostgreSQL's RLS bypass, which is what PR #22 found.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{TenantId, VersionId};
use enclave_db::TenantScoped;
use enclave_preview::repo;
use enclave_preview::{
    GeneratorVersion, Kept, PreviewOutcome, Refusal, RenderBudget, RenderOutcome, RenderRequest,
    RenderedArtifact, Renderer, RenditionObject, RenditionProfile, RenditionService, RenditionSink,
    Result, SourceReader,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// A renderer that always succeeds and counts its attempts.
///
/// The count is what makes a cache test about the cache: "the second call returned the same key" is
/// also true of an implementation that re-rendered and wrote the same key again, which is exactly
/// the bug a cache is meant not to have.
struct Always(GeneratorVersion, Arc<AtomicUsize>);

impl Always {
    fn new(generator: &'static str) -> Self {
        Self(GeneratorVersion::new(generator), Arc::new(AtomicUsize::new(0)))
    }
}

#[async_trait]
impl Renderer for Always {
    fn generator_version(&self) -> GeneratorVersion {
        self.0
    }

    fn supports(&self, _profile: RenditionProfile) -> bool {
        true
    }

    async fn render(&self, _request: RenderRequest) -> Result<RenderOutcome> {
        let _previous = self.1.fetch_add(1, Ordering::Relaxed);
        Ok(RenderOutcome::Rendered(RenderedArtifact {
            bytes: vec![0x89, b'P', b'N', b'G'],
            media_type: "image/png".to_owned(),
            page_count: Some(1),
        }))
    }
}

/// Bytes without an object store.
struct Bytes;

#[async_trait]
impl SourceReader for Bytes {
    async fn read(&self, _object_key: &str) -> Result<Vec<u8>> {
        Ok(vec![b'%', b'P', b'D', b'F'])
    }
}

/// A sink that keeps what it is given, so the cache has something behind its rows.
///
/// The deployment's own sink keeps nothing (`ENC-802`), which would make every one of these tests
/// pass for the wrong reason — a cache that never records is a cache that never serves a stale
/// artefact, never strands a generation, and never has to be invalidated. What is under test here
/// is the behaviour of a pipeline that *can* keep one.
#[derive(Debug, Default, Clone)]
struct Keeps(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl Keeps {
    fn written(&self) -> Vec<String> {
        let mut keys: Vec<String> =
            self.0.lock().expect("the sink's map").keys().cloned().collect();
        keys.sort();
        keys
    }
}

#[async_trait]
impl RenditionSink for Keeps {
    async fn keep(&self, object: &RenditionObject, bytes: &[u8]) -> Result<Kept> {
        let _previous = self
            .0
            .lock()
            .expect("the sink's map")
            .insert(object.as_str().to_owned(), bytes.to_vec());
        Ok(Kept::Stored)
    }

    async fn load(&self, object: &RenditionObject) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().expect("the sink's map").get(object.as_str()).cloned())
    }
}

async fn start() -> (TestDb, Fixtures, enclave_db::DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

/// Writes a version row directly, so the test controls `status` and `av_status` exactly.
///
/// Deliberately not via `enclave-versions`: the commit path only ever writes the safe states, and
/// the point here is to prove the *reader* refuses the unsafe ones.
async fn insert_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    spine: &Spine,
    status: &str,
    av_status: &str,
    now: DateTime<Utc>,
) -> VersionId {
    let id = VersionId::new_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $13, $9, $10, $11, $12)",
    )
    .bind(id.as_uuid())
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("enclave/{tenant}/files/{}/versions/{id}", spine.file))
    .bind(Uuid::now_v7())
    .bind(4_096_i64)
    .bind("e3b0c44298fc1c149afbf4c8996fb924")
    .bind("application/pdf")
    .bind(status)
    .bind(av_status)
    .bind(Uuid::nil())
    .bind(now)
    // `uq_version_number` is unique per `(file, major, minor)`, so a test that writes several
    // versions of one file has to number them. A counter rather than a random value: a collision
    // here would surface as an opaque 23505 rather than as the thing the test is about.
    .bind(next_minor())
    .execute(&mut *conn)
    .await
    .expect("insert version");
    id
}

/// A distinct minor version for each row written in this binary.
fn next_minor() -> i32 {
    use core::sync::atomic::{AtomicI32, Ordering};
    static MINOR: AtomicI32 = AtomicI32::new(0);
    MINOR.fetch_add(1, Ordering::Relaxed)
}

/// A pipeline, plus handles on the two things a cache test has to be able to count: what the sink
/// was asked to keep, and how many times the renderer ran.
fn service(
    generator: &'static str,
) -> (RenditionService<Always, Bytes, Keeps>, Keeps, Arc<AtomicUsize>) {
    let renderer = Always::new(generator);
    let renders = Arc::clone(&renderer.1);
    let sink = Keeps::default();
    let service = RenditionService::new(renderer, Bytes, sink.clone(), RenderBudget::DEFAULT);
    (service, sink, renders)
}

/// The cache does what a cache does — and the second request does not re-render.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn a_miss_generates_and_a_hit_serves_what_the_miss_wrote() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version = insert_version(&mut tx, alpha, &spine, "AVAILABLE", "CLEAN", now).await;

    let readable = repo::readable_version(&mut tx, alpha, version)
        .await
        .expect("query")
        .expect("an AVAILABLE, CLEAN version is readable");

    let (service, sink, renders) = service("preview/1.0");
    let first = service
        .base_rendition(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("generate");
    let PreviewOutcome::Available(generated) = first else { panic!("the miss did not render") };
    let generated = generated.cached.expect("a sink that keeps must produce a row");

    let second = service
        .base_rendition(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("serve from cache");
    let PreviewOutcome::Available(hit) = second else { panic!("the hit did not serve") };
    let cached = hit.cached.expect("the hit came from a row");

    // The load-bearing count. Without it, "the second call returned the same key" would also hold
    // against a pipeline that re-rendered every time and wrote the same key again — which is a
    // cache that costs a render and provides nothing.
    assert_eq!(renders.load(Ordering::Relaxed), 1, "the cache hit re-rendered");
    assert_eq!(sink.written(), vec![generated.object_key.clone()], "one artefact, written once");
    assert_eq!(hit.bytes, vec![0x89, b'P', b'N', b'G'], "the hit served the artefact's bytes");

    assert_eq!(cached.object_key, generated.object_key);
    assert_eq!(cached.generator_version, "preview/1.0");
    // The object key names the version, the profile and nothing else. If a viewer's identity could
    // reach it, a cached artifact would be per-user and the watermark split of `docs/06 §5.1`
    // would be decorative.
    assert!(cached.object_key.contains(&version.to_string()));
    assert!(cached.object_key.contains("thumb"));
    for principal in [fixtures.alpha.owner.to_string(), fixtures.alpha.member.to_string()] {
        assert!(
            !cached.object_key.contains(&principal),
            "a principal reached the rendition key: {}",
            cached.object_key
        );
    }

    tx.commit().await.expect("commit");
    drop(db);
}

/// Upgrading the pipeline invalidates the cache without anyone purging it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn a_row_from_another_generator_is_a_miss() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version = insert_version(&mut tx, alpha, &spine, "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, version).await.expect("query").expect("readable");

    service("preview/1.0")
        .0
        .base_rendition(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("generate under 1.0");

    // The old row is still there, and is invisible to the new generator.
    let old_key = enclave_preview::RenditionKey::new(
        version,
        RenditionProfile::Thumb,
        GeneratorVersion::new("preview/1.0"),
    );
    assert!(repo::find(&mut tx, alpha, old_key).await.expect("find").is_some());

    let new_key = enclave_preview::RenditionKey::new(
        version,
        RenditionProfile::Thumb,
        GeneratorVersion::new("preview/1.1"),
    );
    assert!(
        repo::find(&mut tx, alpha, new_key).await.expect("find").is_none(),
        "an artifact from the previous generator was served to the new one — an upgrade that \
         fixed a mis-sanitizing renderer would keep serving its output"
    );

    // And generating under 1.1 replaces rather than accumulates: the primary key does not carry
    // the generator, so there is exactly one row per (version, profile).
    service("preview/1.1")
        .0
        .base_rendition(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("generate under 1.1");

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM renditions WHERE tenant_id = $1 AND version_id = $2",
    )
    .bind(alpha.as_uuid())
    .bind(version.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(rows, 1, "the upgrade stranded a row nothing will ever evict");
    assert!(repo::find(&mut tx, alpha, old_key).await.expect("find").is_none());

    tx.commit().await.expect("commit");
    drop(db);
}

/// Rule 9 on the rendering path: no unscanned version can be handed to a parser.
///
/// The states are asserted as a set rather than one at a time, because the interesting failure is
/// a filter that checks `status` and forgets `av_status` — which would admit `AVAILABLE`/`SKIPPED`
/// and `AVAILABLE`/`ERROR`, the two states that mean *nobody looked*.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn no_version_that_is_not_available_and_clean_can_be_rendered() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");

    let refused = [
        ("PENDING", "PENDING", "the bytes do not exist yet"),
        ("SCANNING", "PENDING", "antivirus has not finished"),
        ("PROCESSING", "CLEAN", "scanned, but not yet servable"),
        ("QUARANTINED", "INFECTED", "malware — the case that must never reach a parser"),
        ("AVAILABLE", "SKIPPED", "deliberately not scanned: nobody looked"),
        ("AVAILABLE", "ERROR", "the scan itself failed: nobody looked"),
        ("AVAILABLE", "PENDING", "available before the scan finished"),
        ("FAILED", "CLEAN", "processing failed terminally"),
    ];

    for (status, av_status, why) in refused {
        let version = insert_version(&mut tx, alpha, &spine, status, av_status, now).await;
        let readable = repo::readable_version(&mut tx, alpha, version).await.expect("query");
        assert!(readable.is_none(), "{status}/{av_status} produced a ReadableVersion — {why}");
    }

    // The control: without it, a query that returned `None` for everything would pass.
    let good = insert_version(&mut tx, alpha, &spine, "AVAILABLE", "CLEAN", now).await;
    assert!(
        repo::readable_version(&mut tx, alpha, good).await.expect("query").is_some(),
        "nothing is readable at all, so the assertions above mean nothing"
    );

    tx.commit().await.expect("commit");
    drop(db);
}

/// A version belonging to another tenant is not readable, and is not distinguishable from absent.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn another_tenants_version_is_never_rendered() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version = insert_version(&mut tx, alpha, &spine, "AVAILABLE", "CLEAN", now).await;
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
    let seen = repo::readable_version(&mut tx, beta, version).await.expect("query");
    assert!(seen.is_none(), "beta obtained a ReadableVersion for one of alpha's versions");

    // And a fabricated id is the same answer, so the absence above leaks nothing about existence.
    let nobodys = VersionId::new_v7();
    assert!(repo::readable_version(&mut tx, beta, nobodys).await.expect("query").is_none());
    tx.commit().await.expect("commit");

    drop(db);
}

/// A source larger than the budget is refused before the object store is touched.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn an_oversized_version_is_refused_without_a_storage_read() {
    /// Fails if it is ever called, which is the assertion.
    struct NeverRead;

    #[async_trait]
    impl SourceReader for NeverRead {
        async fn read(&self, _object_key: &str) -> Result<Vec<u8>> {
            panic!("the source was fetched for a version already over the input cap");
        }
    }

    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version = insert_version(&mut tx, alpha, &spine, "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, version).await.expect("query").expect("readable");

    // The row says 4 KiB; the budget allows 1 KiB.
    let service = RenditionService::new(
        Always::new("preview/1.0"),
        NeverRead,
        Keeps::default(),
        RenderBudget { max_input_bytes: 1024, ..RenderBudget::DEFAULT },
    );

    let outcome = service
        .base_rendition(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("an oversized source is a verdict, not an error");
    assert_eq!(outcome, PreviewOutcome::Unavailable(Refusal::InputTooLarge));

    tx.commit().await.expect("commit");
    drop(db);
}
