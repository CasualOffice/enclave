//! The composition a deployment runs, against a real database (`ENC-798`).
//!
//! `tests/raster.rs` proves the renderer, `tests/cache.rs` proves the cache, and both do it against
//! stubs standing in for the other half. This file is about the assembly: `RasterRenderer` behind
//! `Bounded`, a source reader, `NoRenditionSink`, and `ReadableVersion` in front of all of it — the
//! shape `crates/api/src/main.rs` builds, with the object store replaced by a `Vec<u8>` so that
//! what is under test is our wiring rather than MinIO's correctness (`docs/12-TESTING.md §1.1`).
//!
//! # The two assertions that pass for free against the pipeline that shipped before this
//!
//! Until `ENC-798` the only `PreviewPipeline` in the workspace was `UnconfiguredPipeline`, which
//! renders nothing. Against it, "a `SCANNING` version produces no rendition" and "no original ever
//! leaves by this path" are both true and both meaningless — `docs/12-TESTING.md §1.2`'s recurring
//! shape, an assertion about an absence. Every such assertion below is therefore paired with the
//! positive control in the same test: the same file, the same call, in the state where bytes *must*
//! come back.
//!
//! # Why the budget is `UNTIMED`
//!
//! `ENC-550`: a 30-second wall clock passed locally and timed out in CI, and a test that is about a
//! round trip must not fail because a shared runner was busy. These tests use a wall clock nothing
//! can exceed; `tests/bounds.rs` is where the clock itself is the subject, with a paused runtime.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{TenantId, VersionId};
use enclave_db::TenantScoped;
use enclave_preview::{
    repo, Delivery, Kept, NoRenditionSink, PreviewPipeline, RenderBudget, RenditionObject,
    RenditionProfile, RenditionService, RenditionSink, Result, SourceReader,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// A real 2000×1200 PNG — the same fixture `tests/raster.rs` renders.
const LANDSCAPE_PNG: &[u8] = include_bytes!("fixtures/landscape-2000x1200.png");

/// A budget that bounds everything except time.
///
/// See the module header. The output and input caps are the defaults, because those *are* asserted
/// here — a source over the cap must be refused whatever the machine is doing.
const UNTIMED: RenderBudget =
    RenderBudget { wall_clock: Duration::from_secs(86_400), ..RenderBudget::DEFAULT };

/// The source bytes, and a count of how often they were asked for.
///
/// The count is what makes "an unscanned version is never rendered" mean something: the interesting
/// failure is not a wrong answer, it is the *fetch* — the version's bytes leaving the store and
/// reaching a decoder before anyone checked whether antivirus had cleared them.
#[derive(Debug, Clone)]
struct Source {
    bytes: Vec<u8>,
    reads: Arc<AtomicUsize>,
}

impl Source {
    fn new(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec(), reads: Arc::new(AtomicUsize::new(0)) }
    }
}

#[async_trait]
impl SourceReader for Source {
    async fn read(&self, _object_key: &str) -> Result<Vec<u8>> {
        let _previous = self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.bytes.clone())
    }
}

/// A sink that records what it was asked to keep and then keeps nothing.
///
/// Reports [`Kept::Discarded`], exactly as the deployed [`NoRenditionSink`] does, so the pipeline
/// under test behaves as the one in `main.rs` — but it remembers the call, which the deployed one
/// cannot be asked about.
#[derive(Debug, Default, Clone)]
struct Watched(Arc<Mutex<Vec<String>>>);

impl Watched {
    fn offered(&self) -> Vec<String> {
        self.0.lock().expect("the sink's list").clone()
    }
}

#[async_trait]
impl RenditionSink for Watched {
    async fn keep(&self, object: &RenditionObject, _bytes: &[u8]) -> Result<Kept> {
        self.0.lock().expect("the sink's list").push(object.as_str().to_owned());
        Ok(Kept::Discarded)
    }

    async fn load(&self, _object: &RenditionObject) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

async fn start() -> (TestDb, Fixtures, enclave_db::DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

/// Writes a version row directly, so the test controls `status`, `av_status` and the media type.
///
/// Deliberately not via `enclave-versions`: the commit path only ever writes the safe states, and
/// what is under test is that the *reader* refuses the unsafe ones.
async fn insert_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    spine: &Spine,
    media_type: &str,
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
    .bind(format!("tenant/{tenant}/files/{}/versions/{id}", spine.file))
    .bind(Uuid::now_v7())
    .bind(i64::try_from(LANDSCAPE_PNG.len()).expect("the fixture fits in an i64"))
    .bind("e3b0c44298fc1c149afbf4c8996fb924")
    .bind(media_type)
    .bind(status)
    .bind(av_status)
    .bind(Uuid::nil())
    .bind(now)
    .bind(next_minor())
    .execute(&mut *conn)
    .await
    .expect("insert version");
    id
}

/// A distinct minor version for each row written in this binary — `uq_version_number` is unique per
/// `(file, major, minor)`, and a collision would surface as an opaque 23505.
fn next_minor() -> i32 {
    use core::sync::atomic::AtomicI32;
    static MINOR: AtomicI32 = AtomicI32::new(0);
    MINOR.fetch_add(1, Ordering::Relaxed)
}

/// The pipeline `main.rs` composes, with the store replaced.
fn pipeline(
    source: Source,
    sink: Watched,
) -> RenditionService<enclave_preview::RasterRenderer, Source, Watched> {
    RenditionService::new(enclave_preview::RasterRenderer, source, sink, UNTIMED)
}

/// The emitted PNG's IHDR, parsed by hand rather than with the library that wrote it.
fn ihdr(png: &[u8]) -> (u32, u32) {
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "the artefact is not a PNG");
    assert_eq!(&png[12..16], b"IHDR", "the first chunk of a PNG is IHDR");
    (
        u32::from_be_bytes(png[16..20].try_into().unwrap()),
        u32::from_be_bytes(png[20..24].try_into().unwrap()),
    )
}

/// How many `renditions` rows this tenant holds for a version.
async fn rendition_rows(conn: &mut PgConnection, tenant: TenantId, version: VersionId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM renditions WHERE tenant_id = $1 AND version_id = $2")
        .bind(tenant.as_uuid())
        .bind(version.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("count renditions")
}

// ---------------------------------------------------------------------------------------------
// A request returns real bytes — and they are not the ones that went in.
// ---------------------------------------------------------------------------------------------

/// The three profiles a raster source can be served as, end to end.
///
/// The assertion that matters is the last one in each iteration: the delivered bytes **differ from
/// the source**, and their geometry is the profile's rather than the source's. A preview path that
/// had quietly become a download path would return `LANDSCAPE_PNG` unchanged and pass every status
/// check ever written about it (`CLAUDE.md` rule 6).
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn an_image_version_is_delivered_as_a_rendition_of_itself() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version =
        insert_version(&mut tx, alpha, &spine, "image/png", "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, version).await.expect("query").expect("readable");

    let source = Source::new(LANDSCAPE_PNG);
    let service = pipeline(source.clone(), Watched::default());

    // 320 for the thumbnail, 1600 for the nominal page, and 2000 — the source's own width — for the
    // 2x page, which never enlarges (`ENC-800`).
    for (profile, expected_width) in [
        (RenditionProfile::Thumb, 320),
        (RenditionProfile::PagePng1x, 1_600),
        (RenditionProfile::PagePng2x, 2_000),
    ] {
        let delivery = service
            .deliver(&mut tx, alpha, &readable, profile, now)
            .await
            .expect("the pipeline reached an answer");

        let Delivery::Available { bytes, media_type, .. } = delivery else {
            panic!("`{profile}` produced no rendition for a PNG this renderer supports");
        };

        assert_eq!(media_type, "image/png", "`{profile}`");
        // `assert!` rather than `assert_ne!`: the values here are two images, and the failure
        // message of the comparison macro is nine kilobytes of decimal bytes with the sentence that
        // matters above it. Watched to fail — see the module header — and made readable afterwards.
        assert!(
            bytes != LANDSCAPE_PNG,
            "`{profile}` delivered the source unchanged ({} bytes) — the rendition path became a \
             download path, which is the collapse CLAUDE.md rule 6 forbids",
            bytes.len()
        );
        let (width, _height) = ihdr(&bytes);
        assert_eq!(width, expected_width, "`{profile}` was served at the wrong geometry");
    }

    tx.commit().await.expect("commit");
    drop(db);
}

/// What renders here and what does not, asserted as one set.
///
/// The refusals are the honest half of the deployment: PDFium is not mounted and the office parsers
/// need D17's out-of-process worker, so `application/pdf` is routed nowhere and says so as a
/// *verdict* rather than an error. The controls are the three image types — without them, a
/// pipeline that refused everything would pass.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn the_media_types_this_deployment_renders_are_exactly_the_three_it_decodes() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");

    // The declared media type is a hint the renderer does not read — content decides. So the source
    // bytes are what varies here, and the row's `mime_type` is deliberately left lying in one case.
    let jpeg = include_bytes!("fixtures/portrait-64x96.jpg").to_vec();
    let webp = include_bytes!("fixtures/swatch-48x32.webp").to_vec();
    let pdf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF\n".to_vec();

    for (declared, bytes, renders) in [
        ("image/png", LANDSCAPE_PNG.to_vec(), true),
        ("image/jpeg", jpeg, true),
        ("image/webp", webp, true),
        // A document. Nothing in this deployment parses one, and the answer is `Unavailable`, not
        // an error: an installer or a spreadsheet has no preview and never will.
        ("application/pdf", pdf, false),
        // A PNG the uploader called a PDF still renders, and a lie in the other direction still
        // refuses — the sniffer decides, so neither claim moves the answer.
        ("application/pdf", LANDSCAPE_PNG.to_vec(), true),
    ] {
        let version =
            insert_version(&mut tx, alpha, &spine, declared, "AVAILABLE", "CLEAN", now).await;
        let readable = repo::readable_version(&mut tx, alpha, version)
            .await
            .expect("query")
            .expect("readable");
        let service = pipeline(Source::new(&bytes), Watched::default());

        let delivery = service
            .deliver(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
            .await
            .expect("a document that will not render is a verdict, never an error");

        match (delivery, renders) {
            (Delivery::Available { bytes: out, .. }, true) => {
                assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n", "`{declared}` produced a non-PNG");
            }
            (Delivery::Unavailable(refusal), false) => {
                assert_eq!(refusal, enclave_preview::Refusal::UnsupportedFormat, "`{declared}`");
            }
            (delivery, _) => panic!("`{declared}` answered {delivery:?}, which is the wrong half"),
        }
    }

    // And the two document *profiles* are refused before the source is even fetched, whatever the
    // bytes are: `NoRenderer`'s territory, reached through `Renderer::supports`.
    let version =
        insert_version(&mut tx, alpha, &spine, "image/png", "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, version).await.expect("query").expect("readable");
    let source = Source::new(LANDSCAPE_PNG);
    let service = pipeline(source.clone(), Watched::default());

    for profile in [RenditionProfile::PdfSanitized, RenditionProfile::HtmlSanitized] {
        let delivery = service.deliver(&mut tx, alpha, &readable, profile, now).await.expect("ask");
        assert!(matches!(delivery, Delivery::Unavailable(_)), "`{profile}` claimed to render");
    }
    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        0,
        "an unsupported profile cost an object-storage read: the support check must come first"
    );

    tx.commit().await.expect("commit");
    drop(db);
}

// ---------------------------------------------------------------------------------------------
// Rule 9, against a pipeline that can actually render.
// ---------------------------------------------------------------------------------------------

/// No unscanned version reaches a decoder — and the bytes are never even fetched.
///
/// This is the test the trap in `docs/12-TESTING.md §1.2` is about. `tests/cache.rs` already asserts
/// that `readable_version` returns `None` for these eight states, but until `ENC-798` there was no
/// renderer behind it, so the property "an unscanned version is not rendered" held for the same
/// reason it held for every *scanned* one: nothing was rendered at all. Two things close that here:
/// the source reader counts its calls, and the last block renders the same file for real.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn nothing_antivirus_has_not_cleared_is_rendered_or_even_fetched() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");

    let source = Source::new(LANDSCAPE_PNG);
    let sink = Watched::default();
    let service = pipeline(source.clone(), sink.clone());

    // The states that mean "the bytes exist and nobody has looked at them", including the one that
    // a filter checking only `status` would admit: `AVAILABLE`/`ERROR`.
    //
    // `AVAILABLE`/`SKIPPED` was on this list until `ENC-828` and is deliberately no longer, which
    // is a change to a security control and so is argued rather than assumed. It is the *only*
    // outcome a deployment can opt into: `docs/06-SECURITY-DLP-ACCESS.md §6.2`'s `BLOCK` — the
    // default — writes `QUARANTINED`/`SKIPPED`, so an `AVAILABLE`/`SKIPPED` row cannot exist
    // unless that deployment set `ALLOW_WITH_FLAG`, and the whole meaning of that setting is that
    // such content is served. A version it published that no route would serve made the setting a
    // no-op and the product a write-only store. The rank ceiling is untouched: unscanned content at
    // `CONFIDENTIAL` and above is blocked whatever the tenant set.
    //
    // What did *not* change is the clause of rule 9 about scans that have not finished.
    // `AVAILABLE`/`PENDING` and `AVAILABLE`/`ERROR` both still mean "nobody has looked *yet*", and
    // both are still refused below — which is why they stay on this list and why removing them
    // would be a different and much worse change.
    for (status, av_status, why) in [
        ("SCANNING", "PENDING", "antivirus has not finished"),
        ("QUARANTINED", "INFECTED", "malware — the case that must never reach a parser"),
        ("AVAILABLE", "ERROR", "the scan itself failed: nobody looked"),
        ("AVAILABLE", "PENDING", "available before the scan finished"),
    ] {
        let version =
            insert_version(&mut tx, alpha, &spine, "image/png", status, av_status, now).await;
        let witness = repo::readable_version(&mut tx, alpha, version).await.expect("query");
        assert!(
            witness.is_none(),
            "{status}/{av_status} produced the witness the pipeline takes — {why}"
        );
        assert_eq!(rendition_rows(&mut tx, alpha, version).await, 0);
    }

    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        0,
        "unscanned content was fetched from the store"
    );
    assert!(sink.offered().is_empty(), "a rendition of unscanned content was offered to the sink");

    // `ENC-828`'s half of the boundary, asserted as its own case rather than by its absence from
    // the loop: a version a deployment published unscanned **is** served, and the digits prove a
    // real render rather than merely a non-refusal.
    let unscanned =
        insert_version(&mut tx, alpha, &spine, "image/png", "AVAILABLE", "SKIPPED", now).await;
    let readable = repo::readable_version(&mut tx, alpha, unscanned)
        .await
        .expect("query")
        .expect("ALLOW_WITH_FLAG published this version, so a delivery path must serve it");
    let delivery = service
        .deliver(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("deliver");
    let Delivery::Available { bytes, .. } = delivery else {
        panic!("a published-unscanned PNG produced no rendition, so ALLOW_WITH_FLAG buys nothing")
    };
    assert_eq!(ihdr(&bytes).0, 320);
    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        1,
        "exactly the published version was fetched"
    );

    // The control. The same file, the same pipeline, one row's two columns different — and now
    // there are bytes. Without this, every assertion above holds against a pipeline that renders
    // nothing, which is precisely what shipped before `ENC-798`.
    let clean =
        insert_version(&mut tx, alpha, &spine, "image/png", "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, clean).await.expect("query").expect("readable");
    let delivery = service
        .deliver(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("deliver");
    let Delivery::Available { bytes, .. } = delivery else {
        panic!("a clean PNG produced no rendition, so nothing above proves anything about rule 9")
    };
    assert_eq!(ihdr(&bytes).0, 320);
    assert_eq!(
        source.reads.load(Ordering::Relaxed),
        2,
        "exactly the two servable versions were fetched"
    );

    tx.commit().await.expect("commit");
    drop(db);
}

// ---------------------------------------------------------------------------------------------
// What the deployed sink does, and what it therefore must not write.
// ---------------------------------------------------------------------------------------------

/// A deployment that keeps nothing records nothing (`ENC-802`).
///
/// The pairing is the point. A `renditions` row is a claim that bytes are at an object key; with no
/// server-side write verb there are none, so a row would make the file permanently unpreviewable
/// under this generator — the second request would hit the cache and fetch an object nobody wrote.
/// The control is that the *bytes* still arrive, twice, so this is not the empty row count of a
/// pipeline that refused.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0007; CI runs it with --include-ignored"]
async fn a_deployment_that_keeps_no_rendition_writes_no_row() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let version =
        insert_version(&mut tx, alpha, &spine, "image/png", "AVAILABLE", "CLEAN", now).await;
    let readable =
        repo::readable_version(&mut tx, alpha, version).await.expect("query").expect("readable");

    let sink = Watched::default();
    let service = pipeline(Source::new(LANDSCAPE_PNG), sink.clone());

    let mut delivered = Vec::new();
    for _attempt in 0..2 {
        let delivery = service
            .deliver(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
            .await
            .expect("deliver");
        let Delivery::Available { bytes, .. } = delivery else { panic!("no rendition") };
        delivered.push(bytes);
    }

    assert_eq!(delivered[0], delivered[1], "two renders of one source disagreed");
    assert_eq!(
        rendition_rows(&mut tx, alpha, version).await,
        0,
        "a row was written for an artefact nothing kept; the next request would fetch an object \
         that was never written and the file would be unpreviewable until the generator moved"
    );
    // The artefact *was* offered — the write path is wired, and it is the sink that declines. If
    // this were empty the pipeline would simply not be calling it, and swapping in a sink that
    // keeps would silently change nothing.
    assert_eq!(sink.offered().len(), 2);
    assert!(sink.offered()[0].contains("/renditions/"), "{:?}", sink.offered());

    // And the exact composition `main.rs` builds behaves the same way, which is what makes the
    // paragraph above a statement about the product rather than about this test's double.
    let deployed = RenditionService::new(
        enclave_preview::RasterRenderer,
        Source::new(LANDSCAPE_PNG),
        NoRenditionSink,
        UNTIMED,
    );
    let delivery = deployed
        .deliver(&mut tx, alpha, &readable, RenditionProfile::Thumb, now)
        .await
        .expect("deliver");
    assert!(matches!(delivery, Delivery::Available { .. }));
    assert_eq!(rendition_rows(&mut tx, alpha, version).await, 0);

    tx.commit().await.expect("commit");
    drop(db);
}
