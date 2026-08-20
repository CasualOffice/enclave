//! The coverage probe pass, against a real PostgreSQL.
//!
//! # What these tests are about
//!
//! Not "the comparison works" — `crates/search/src/health.rs` owns that, at exact numbers, without
//! a database. These are about the *wiring*: that a scheduled pass takes a reading for every tenant
//! it is given, that the reading reaches the exposition an operator scrapes, that a store which
//! cannot answer for one tenant does not blind the rest of the fleet, and — the one that guards
//! `ENC-520` — that a pass which has just found a tenant's store complete does not turn that into a
//! per-file claim in `retrieval_denylist`.
//!
//! # Why they hold a lock around the metric assertions
//!
//! The instruments in `enclave_observability::metrics` are process-wide statics, and
//! `enclave_testing`'s fixture ids are deterministic — `tenant-alpha` is the same UUID in every test
//! in this binary. Two tests probing alpha at once would each publish and then read the other's
//! numbers, and the failure would be intermittent and blamed on the database. Each test that asserts
//! on a gauge therefore publishes and reads under [`GAUGES`]. The databases need no such treatment:
//! every test starts its own.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use enclave_core::{FileId, TenantId, UserId};
use enclave_db::DbPool;
use enclave_observability::metrics::render_prometheus;
use enclave_observability::metrics::search::{
    INDEX_COVERAGE_FLOOR_PERCENT, INDEX_COVERAGE_UNKNOWN, INDEX_EXPECTED_CHUNKS,
    INDEX_OBSERVED_CHUNKS,
};
use enclave_search::health::IndexCensus;
use enclave_search::{denylist, CatchUp, SearchError, DEFAULT_COVERAGE_FLOOR};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::coverage::{self, CoverageOutcome};
use enclave_worker::Stop;
use uuid::Uuid;

/// Serialises the tests that read process-wide gauges. See the module documentation.
static GAUGES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(4).await.expect("application pool");
    (db, fixtures, pool)
}

/// A store that answers with the number the test names, or refuses to answer at all.
///
/// It records which tenants it was asked about, which is how "the pass carried on past a failure"
/// is asserted at the store rather than only at the returned counters — a pass that stopped early
/// and a pass that probed everything can produce the same `unreadable` count otherwise.
#[derive(Debug, Default)]
struct FakeCensus {
    chunks: HashMap<TenantId, u64>,
    refuses: HashSet<TenantId>,
    asked: Mutex<Vec<TenantId>>,
}

impl FakeCensus {
    fn holding(chunks: impl IntoIterator<Item = (TenantId, u64)>) -> Self {
        Self { chunks: chunks.into_iter().collect(), ..Self::default() }
    }

    fn refusing(mut self, tenant: TenantId) -> Self {
        self.refuses.insert(tenant);
        self
    }

    fn asked_about(&self) -> Vec<TenantId> {
        self.asked.lock().expect("the census log").clone()
    }
}

#[async_trait]
impl IndexCensus for FakeCensus {
    async fn chunks(&self, tenant: TenantId) -> Result<u64, SearchError> {
        self.asked.lock().expect("the census log").push(tenant);
        if self.refuses.contains(&tenant) {
            return Err(SearchError::MalformedRow {
                column: "chunk_id",
                reason: "the store refused this census",
            });
        }
        Ok(self.chunks.get(&tenant).copied().unwrap_or_default())
    }
}

/// A file, and the `index_manifests` row claiming a number of chunks were written for it.
///
/// `chunk_count` is a parameter because it is PostgreSQL's half of the reading: the difference
/// between a manifest claiming fifteen chunks and one claiming none is the difference between a
/// signal and a blind spot.
async fn indexed_file(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    owner: Uuid,
    status: &str,
    chunk_count: i32,
) -> FileId {
    let spine = Spine::new(tenant);
    spine.insert(&mut *conn, UserId::from(owner), Utc::now()).await.expect("spine");

    let version = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 1024, 'deadbeef', 'application/pdf', 1, 0, 'AVAILABLE',
                 'CLEAN', $6, $7)",
    )
    .bind(version)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("tenants/{}/blobs/{version}", tenant.as_uuid()))
    .bind(Uuid::now_v7())
    .bind(owner)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("a version for the manifest to name");

    sqlx::query(
        "INSERT INTO index_manifests
           (tenant_id, file_id, version_id, index_version, extractor_version, chunker_version,
            embedding_model, status, chunk_count, updated_at)
         VALUES ($1, $2, $3, 1, 'v1', 'v1', 'local-test', $4, $5, $6)",
    )
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(version)
    .bind(status)
    .bind(chunk_count)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("the manifest");

    spine.file
}

/// The four gauges for one tenant, as an operator's scrape would read them.
fn published(tenant: TenantId) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let label = tenant.to_string();
    (
        INDEX_EXPECTED_CHUNKS.get(&label),
        INDEX_OBSERVED_CHUNKS.get(&label),
        INDEX_COVERAGE_FLOOR_PERCENT.get(&label),
        INDEX_COVERAGE_UNKNOWN.get(&label),
    )
}

/// How much of a tenant's denylist claims a confirmed index write.
async fn catch_up(pool: &DbPool, tenant: TenantId) -> CatchUp {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let counts = denylist::catch_up(&mut tx, tenant).await.expect("catch up");
    tx.commit().await.expect("commit");
    counts
}

/// The pass takes a reading for every tenant it is given, and publishes both numbers.
///
/// The two tenants land on opposite sides of the floor deliberately. A pass that published nothing,
/// published only the store's number, or published the same reading for every tenant would satisfy
/// a single-tenant version of this test; it cannot satisfy this one.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_pass_publishes_both_numbers_for_every_tenant_it_probes() {
    let _serialised = GAUGES.lock().await;
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    let mut admin = db.connect().await.expect("admin connection");
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 10).await;
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 5).await;
    // A manifest the indexer has not finished with: its chunks are not expected of the store yet.
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "EXTRACTING", 900).await;
    indexed_file(&mut admin, beta, fixtures.beta.owner.as_uuid(), "READY", 8).await;

    // Alpha's store holds a fifth of what PostgreSQL expects; beta's holds all of it.
    let census = FakeCensus::holding([(alpha, 3), (beta, 8)]);

    let outcome =
        coverage::probe_pass(&pool, &[alpha, beta], &census, DEFAULT_COVERAGE_FLOOR, &Stop::new())
            .await;

    assert_eq!(
        outcome,
        CoverageOutcome { stocked: 1, depleted: 1, unknown: 0, unreadable: 0, stopped: false },
        "one tenant is depleted and one is stocked"
    );

    assert_eq!(
        published(alpha),
        (Some(15), Some(3), Some(50), Some(0)),
        "the depleted tenant's expectation, observation, floor and unknown flag"
    );
    assert_eq!(
        published(beta),
        (Some(8), Some(8), Some(50), Some(0)),
        "the stocked tenant is published too — a probe that only reported problems would leave \
         SearchIndexCoverageUnreported firing for a healthy fleet"
    );

    // And it is on the wire, not merely in a map: this is the series the alert names.
    let scrape = render_prometheus();
    assert!(
        scrape
            .contains(&format!("enclave_search_index_observed_chunks{{tenant_id=\"{alpha}\"}} 3")),
        "the reading never reached the exposition:\n{scrape}"
    );
}

/// A store that cannot answer for one tenant does not blind the pass for the rest.
///
/// The failing tenant is deliberately *first*. A pass that propagated the error would return before
/// beta was ever asked — which is why the assertion is made at the census as well as at the
/// counters: `unreadable: 1` alone is also what an aborted pass produces.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_tenant_the_store_cannot_answer_for_does_not_blind_the_rest_of_the_pass() {
    let _serialised = GAUGES.lock().await;
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    let mut admin = db.connect().await.expect("admin connection");
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 12).await;
    indexed_file(&mut admin, beta, fixtures.beta.owner.as_uuid(), "READY", 6).await;

    let census = FakeCensus::holding([(beta, 6)]).refusing(alpha);

    let outcome =
        coverage::probe_pass(&pool, &[alpha, beta], &census, DEFAULT_COVERAGE_FLOOR, &Stop::new())
            .await;

    assert_eq!(
        outcome,
        CoverageOutcome { stocked: 1, depleted: 0, unknown: 0, unreadable: 1, stopped: false },
        "the failure must be counted as unreadable and the healthy tenant still read"
    );
    assert_eq!(
        census.asked_about(),
        vec![alpha, beta],
        "the pass stopped at the tenant the store could not answer for"
    );
    assert_eq!(
        published(beta),
        (Some(6), Some(6), Some(50), Some(0)),
        "the tenant after the failure has no reading, so its dashboard shows the last pass's \
         numbers with nothing saying so"
    );
}

/// A failed reading is not a verdict, and not an unknown one either.
///
/// `health.rs` refuses to turn a census failure into `Depleted`, on the grounds that a broken probe
/// is not evidence about a store. The same argument forbids the softer version — recording it as
/// `unknown`, which is the state a brand-new tenant is in and the one an operator skips past.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_reading_that_failed_publishes_nothing_and_is_not_recorded_as_a_verdict() {
    let _serialised = GAUGES.lock().await;
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 40).await;

    // Publish a reading first, so "no gauge moved" is a statement about this pass rather than about
    // a metric nobody has ever set.
    let healthy = FakeCensus::holding([(alpha, 40)]);
    let first =
        coverage::probe_pass(&pool, &[alpha], &healthy, DEFAULT_COVERAGE_FLOOR, &Stop::new()).await;
    assert_eq!(first.stocked, 1);
    assert_eq!(published(alpha), (Some(40), Some(40), Some(50), Some(0)));

    let broken = FakeCensus::default().refusing(alpha);
    let outcome =
        coverage::probe_pass(&pool, &[alpha], &broken, DEFAULT_COVERAGE_FLOOR, &Stop::new()).await;

    assert_eq!(
        outcome,
        CoverageOutcome { stocked: 0, depleted: 0, unknown: 0, unreadable: 1, stopped: false },
        "a probe that could not run must not be counted as a tenant with nothing indexed"
    );
    assert_eq!(
        published(alpha),
        (Some(40), Some(40), Some(50), Some(0)),
        "a failed census published a number — a zero observed count degrades every tenant at once"
    );
}

/// [`Stop`] ends the pass at a tenant boundary, and the second half proves the first is not free.
///
/// An assertion that nothing was probed passes against a pass that never probes anything, so the
/// same tenants are handed to a pass with the signal down and must come back read.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_raised_stop_ends_the_pass_and_a_lowered_one_does_not() {
    let _serialised = GAUGES.lock().await;
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    let mut admin = db.connect().await.expect("admin connection");
    indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 4).await;
    indexed_file(&mut admin, beta, fixtures.beta.owner.as_uuid(), "READY", 4).await;

    let stopped_census = FakeCensus::holding([(alpha, 4), (beta, 4)]);
    let stop = Stop::new();
    stop.stop();
    let halted =
        coverage::probe_pass(&pool, &[alpha, beta], &stopped_census, DEFAULT_COVERAGE_FLOOR, &stop)
            .await;

    assert!(halted.stopped, "the pass did not report that it returned early");
    assert_eq!(halted.tenants(), 0, "a raised stop must be checked before the first tenant");
    assert!(
        stopped_census.asked_about().is_empty(),
        "the store was queried during a pass that was told to stop"
    );

    let running_census = FakeCensus::holding([(alpha, 4), (beta, 4)]);
    let ran = coverage::probe_pass(
        &pool,
        &[alpha, beta],
        &running_census,
        DEFAULT_COVERAGE_FLOOR,
        &Stop::new(),
    )
    .await;

    assert!(!ran.stopped);
    assert_eq!(ran.tenants(), 2, "the same pass with the signal down must read both tenants");
    assert_eq!(running_census.asked_about(), vec![alpha, beta]);
}

/// **The `ENC-520` guard.** A stocked tenant is not a confirmed removal, and the pass says nothing
/// about one.
///
/// This is the commit the module invites: the probe has just established that the store holds
/// everything PostgreSQL expects, so it looks like it is holding the answer to
/// `retrieval_denylist.indexed_seq`. It is not — a census is a `count(*)` over a tenant's partition
/// and cannot say that *this* file's chunks were removed. A pass that filled the column would put
/// an inference in a table whose `NULL` means "nobody has asserted anything", where it would be
/// indistinguishable from a claim a real removal reported.
///
/// The `stocked: 1` assertion is the positive control: without it every assertion below passes
/// against a pass that does nothing at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_coverage_pass_leaves_the_catch_up_column_unasserted() {
    let _serialised = GAUGES.lock().await;
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut admin = db.connect().await.expect("admin connection");
    let file = indexed_file(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), "READY", 9).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    denylist::suppress(&mut tx, alpha, file, "acl change", Utc::now(), None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");

    let before = catch_up(&pool, alpha).await;
    assert_eq!(before, CatchUp { unasserted: 1, behind: 0, caught_up: 0 });

    // A store holding everything the manifests claim — the reading that tempts a confirmation.
    let census = FakeCensus::holding([(alpha, 9)]);
    let outcome =
        coverage::probe_pass(&pool, &[alpha], &census, DEFAULT_COVERAGE_FLOOR, &Stop::new()).await;
    assert_eq!(
        outcome.stocked, 1,
        "the pass did not find the store complete, so it was not tempted"
    );

    assert_eq!(
        catch_up(&pool, alpha).await,
        CatchUp { unasserted: 1, behind: 0, caught_up: 0 },
        "a coverage reading was turned into a per-file claim that the index has caught up"
    );

    // And the suppression is still suppressing, which is the property the column exists beside.
    let mut tx = pool.begin(alpha).await.expect("begin");
    let still = denylist::suppressed(&mut tx, alpha, &[file]).await.expect("suppressed");
    tx.commit().await.expect("commit");
    assert!(still.contains(&file), "the probe pass lifted a suppression");
}
