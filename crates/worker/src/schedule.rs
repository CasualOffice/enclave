//! The scheduler: the clock, the tenant list, and the thing that actually runs the passes.
//!
//! `ENC-548`. Until this module existed, [`index_pass`](crate::indexing::index_pass),
//! [`invalidation::sweep`](crate::invalidation::sweep),
//! [`coverage::probe_pass`](crate::coverage::probe_pass) and
//! [`epoch::reconcile`](crate::epoch::reconcile) had exactly one caller each — their own tests. The
//! capability was built four times over and nothing drove any of it, which from outside the process
//! is identical to none of it having been built.
//!
//! Three decisions are made here rather than in a pass, and each one is argued because each one had
//! a plausible alternative.
//!
//! # 1. Where the tenant list comes from
//!
//! Every pass takes the tenants as a parameter, and `crates/worker/src/lib.rs` explains why: the
//! query that produces a tenant list cannot itself be tenant-scoped, so reaching it means
//! `DbPool::platform_connection`, and that is the row-level-security escape hatch. That refusal is
//! not undone here. What it says is that *housekeeping* does not enumerate; something has to, and
//! that something is the scheduler.
//!
//! It does so through [`TenantSource`], which this module defines and does not implement. The
//! production implementation is [`crate::tenants::DbTenants`], and it is three lines because the
//! query itself lives in `enclave_db::active_tenants` — inside the crate that owns the escape hatch,
//! so `platform_connection` still has no caller anywhere else in the workspace. See that function
//! for the argument.
//!
//! The trait is not indirection for its own sake. It is what lets every test below run a real
//! scheduling loop over a fixed list with no database, no platform role and no fixtures, which is
//! the difference between testing the scheduler and testing PostgreSQL.
//!
//! **The list is re-read every tick, not cached.** A cached roster is a second source of truth with
//! its own staleness window, and the window is exactly wrong: a tenant created between two
//! refreshes gets no indexing until the cache turns over, and a tenant being deleted keeps getting
//! work. The query is one indexed read of a table with one row per tenant, and the loops that ask
//! for it most often are the ones bounded by an idle interval.
//!
//! # 2. One task per pass, not one loop running everything
//!
//! A single loop is simpler and it is wrong here, for two reasons that are not about elegance.
//!
//! **The cadences differ by two orders of magnitude and the costs differ more.** Indexing is the
//! only pass with a backlog: it should run flat out while there is work and stop when there is not.
//! The sweep is one `DELETE` per tenant against rows that already stopped suppressing anything, the
//! reconciler is a bounded `UPDATE`, and the coverage probe is a network round trip to the vector
//! store per tenant. One interval for all four is either a probe hammering the store every few
//! seconds or an index queue sitting idle for a minute at a time; there is no value that is not one
//! of those.
//!
//! **A pass that fails must not starve the others.** `sweep` returns an error at the first tenant it
//! cannot sweep, and `index_pass` at the first storage failure — both correct, both the caller's
//! problem. Inside one loop, one broken dependency stops the other three passes as well, and the
//! symptom is a metric going quiet, which `docs/11-OPERATIONS.md §5.7` is entirely about not
//! misreading. Separate tasks fail separately.
//!
//! # 3. What is *not* scheduled, and why that is loud
//!
//! Both [`Scheduler::with_indexing`] and [`Scheduler::with_coverage`] are optional, and a pass whose
//! dependency is absent is **not scheduled at all** rather than scheduled and left to fail. For
//! indexing that distinction is not cosmetic: [`claim`](enclave_indexing::claim) commits before the
//! bytes are read, so a pass run against a store that cannot answer would move manifests into a
//! working state and increment `attempts` on every file it touched — burning the retry budget that
//! is the only thing quarantining a genuinely poisoned document, on a deployment whose only problem
//! is that nobody configured a bucket. Deny-by-default (`plans/M3-DISCOVERY.md` D24) means the
//! absent capability does nothing and says so, not that it half-runs.
//!
//! [`Scheduler::scheduled`] is that decision made readable: it reports what this process will
//! actually run, the binary logs it at start-up, and the tests assert on it.

use core::fmt;
use core::future::Future;
use core::time::Duration;

use async_trait::async_trait;
use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_indexing::{BuildVersions, ChunkerVersion, Extractor, ExtractorVersion, Pipeline};
use enclave_preview::RenderBudget;
use enclave_search::health::{CoverageFloor, IndexCensus};
use enclave_storage::BlobStore;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::epoch::ReconcilerConfig;
use crate::indexing::{index_pass, IndexPass, VectorStage};
use crate::ocr::MountedOcr;
use crate::{coverage, epoch, invalidation, Result, Stop, Woke};

/// The names [`Scheduler::scheduled`] reports and the loops log under.
///
/// Constants rather than literals at three call sites, because the binary's start-up line, the
/// per-loop log field and the tests all have to agree for any of them to be worth reading.
pub const INDEXING: &str = "indexing";
/// See [`INDEXING`].
pub const INVALIDATION: &str = "invalidation";
/// See [`INDEXING`].
pub const EPOCH: &str = "epoch";
/// See [`INDEXING`].
pub const COVERAGE: &str = "coverage";

/// How long each loop waits after a tick that found nothing to do.
///
/// Every one of these is an *idle* interval, never a deadline: a tick that overruns delays the next
/// one rather than overlapping with it, so a slow pass degrades into a lower frequency instead of
/// into concurrent copies of itself competing for the same rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// How long the indexer waits when the queue is empty.
    ///
    /// Short, because this is the latency between an upload finishing its antivirus scan and its
    /// text becoming searchable, and because an empty queue costs one `SELECT … FOR UPDATE SKIP
    /// LOCKED` per tenant. A tick that indexed anything does not wait at all — see
    /// [`Tick::Progressed`].
    pub indexing_idle: Duration,
    /// How often expired suppressions are lifted.
    ///
    /// Can be minutes and could be hours: an expired row is not suppressing anything before the
    /// sweep arrives, so this interval buys index size and nothing else
    /// (`crates/worker/src/invalidation.rs`).
    pub invalidation: Duration,
    /// How often manifests whose ACL has moved on are marked for rebuild.
    ///
    /// Bounded by *recall*, not correctness: a stale manifest produces an over-permissive candidate
    /// that the post-filter drops, so lag costs candidate slots (`crates/worker/src/epoch.rs`).
    pub epoch: Duration,
    /// How often each tenant's index coverage is measured and published.
    ///
    /// Wants to be somewhat shorter than the Prometheus scrape interval, so that a scrape never
    /// reads a gauge nothing refreshed since the last one. Each tick is one round trip to the vector
    /// store per tenant, which is why it is not shorter still.
    pub coverage: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            indexing_idle: Duration::from_secs(5),
            invalidation: Duration::from_secs(300),
            epoch: Duration::from_secs(60),
            coverage: Duration::from_secs(60),
        }
    }
}

/// Where the scheduler gets the tenants to work on.
///
/// See this module's documentation for why this is a parameter of the scheduler rather than a query
/// any pass runs, and `enclave_db::active_tenants` for why the production implementation's query
/// lives in `enclave-db`.
#[async_trait]
pub trait TenantSource: Send + Sync + fmt::Debug {
    /// The tenants to work on now.
    ///
    /// # Errors
    ///
    /// Whatever reading the list failed with. An error, never an empty list: a scheduler that read
    /// "no tenants" from a broken credential would idle forever while every health check stayed
    /// green.
    async fn tenants(&self) -> Result<Vec<TenantId>>;
}

/// One tenant's share of the indexing queue, however this deployment is wired to read it.
///
/// A trait rather than the four-generic-parameter call because of what it lets the scheduler do:
/// hold the indexing capability as `Option<Arc<dyn IndexRunner>>`, so "this deployment has no object
/// storage configured" is *representable* and is reported by [`Scheduler::scheduled`], rather than
/// being a `Pipeline<E>` type parameter the binary has to name for a pass it will never run.
#[async_trait]
pub trait IndexRunner: Send + Sync + fmt::Debug {
    /// Indexes up to one batch of `tenant`'s queued files.
    ///
    /// # Errors
    ///
    /// Whatever [`index_pass`] returns: a storage or database failure, never a document that would
    /// not parse.
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<IndexPass>;
}

/// [`IndexRunner`] over a real pipeline, store and pool.
///
/// Holds the pool as well as the store so that the scheduling loop needs neither — a loop that took
/// a `DbPool` would be untestable without one, and everything it does with it is inside
/// [`index_pass`] already.
pub struct PipelineRunner<E: Extractor, S: BlobStore> {
    pool: DbPool,
    pipeline: Pipeline<E>,
    ocr: Option<MountedOcr>,
    vectors: Option<VectorStage>,
    store: S,
    extractor: ExtractorVersion,
    chunker: ChunkerVersion,
    embedding_model: String,
    budget: RenderBudget,
    batch: i64,
}

impl<E: Extractor, S: BlobStore> fmt::Debug for PipelineRunner<E, S> {
    /// Names the wiring, never its contents.
    ///
    /// A derived `Debug` would print the store, and a store prints an endpoint and whatever else its
    /// client happens to hold. This appears in a start-up log line (`CLAUDE.md` rule 10).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipelineRunner")
            .field("ocr", &self.ocr.is_some())
            .field("vectors", &self.vectors.is_some())
            .field("batch", &self.batch)
            .finish_non_exhaustive()
    }
}

impl<E: Extractor, S: BlobStore> PipelineRunner<E, S> {
    /// Assembles the indexing pass's dependencies once, for every tenant and every tick.
    ///
    /// **Takes the extractor and the chunker rather than a [`Pipeline`], so that it can read the two
    /// version markers off them and the caller cannot supply a third opinion.** A marker that
    /// disagrees with the code that produced the text is not a cosmetic mismatch: `docs/07 §3`
    /// compares it to decide what needs reindexing, so a manifest stamped with a version the
    /// extractor never had is either a rebuild that never happens or one that never converges.
    ///
    /// `embedding_model` is a [`String`] and the other two markers are not, because they are not the
    /// same kind of fact: an extractor and a chunker version name *this build's code* and are
    /// `&'static str` so a marker cannot be assembled from a runtime value, while the embedding
    /// model names a mounted artefact whose identity an operator supplies. `""` is the honest value
    /// for a deployment where nothing has embedded yet, which is every deployment today.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: DbPool,
        extractor: E,
        chunker: enclave_indexing::Chunker,
        ocr: Option<MountedOcr>,
        store: S,
        embedding_model: impl Into<String>,
        budget: RenderBudget,
        batch: i64,
    ) -> Self {
        let versions = (extractor.extractor_version(), chunker.version());
        Self {
            pool,
            pipeline: Pipeline::new(extractor, chunker),
            ocr,
            vectors: None,
            store,
            extractor: versions.0,
            chunker: versions.1,
            embedding_model: embedding_model.into(),
            budget,
            batch,
        }
    }

    /// Adds the embedding-and-vector-write stage (`ENC-557`).
    ///
    /// A builder method rather than an eleventh parameter of [`PipelineRunner::new`], for the reason
    /// [`crate::indexing`] gives about `Option`: a deployment with no embedding model and no vector
    /// store is the ordinary case and must cost nothing, including nothing to write at the call
    /// site. Without it, this runner does exactly what it did before — text into `chunk_text`, a
    /// manifest, and an `embedding_model` of `""` that honestly says nothing embedded.
    ///
    /// With it, a file that cannot be embedded is not recorded at all. That is the point rather
    /// than a side effect: a `READY` manifest over an empty collection is the state that makes a
    /// document filed, visible in the tree and absent from every search.
    #[must_use]
    pub fn with_vectors(mut self, stage: VectorStage) -> Self {
        self.vectors = Some(stage);
        self
    }
}

#[async_trait]
impl<E: Extractor, S: BlobStore> IndexRunner for PipelineRunner<E, S> {
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<IndexPass> {
        let versions = BuildVersions {
            extractor: self.extractor,
            chunker: self.chunker,
            embedding_model: &self.embedding_model,
        };
        index_pass(
            &self.pool,
            tenant,
            &self.pipeline,
            self.ocr.as_ref(),
            self.vectors.as_ref(),
            &self.store,
            versions,
            self.budget,
            self.batch,
            stop,
        )
        .await
    }
}

/// The coverage probe's two dependencies, present together or not at all.
///
/// One field would do; two exist because a floor without a census is not a half-configured probe,
/// it is nothing, and an `Option<Arc<dyn IndexCensus>>` beside a `CoverageFloor` would let those two
/// states be written separately. This is the same pairing rule
/// [`OcrMounts`](enclave_config::OcrMounts) applies to the two OCR volumes.
#[derive(Debug, Clone)]
struct CoverageProbe {
    census: Arc<dyn IndexCensus>,
    floor: CoverageFloor,
}

/// What this process runs, how often, and over which tenants.
///
/// Holds no [`DbPool`]: the pool is a parameter of [`Scheduler::run`], because what this type
/// describes is a *decision* — which passes exist in this deployment and at what cadence — and a
/// decision that needed a live database to express could not be asserted on without one. The tests
/// below exercise every branch of [`Scheduler::scheduled`] with no PostgreSQL anywhere.
#[derive(Debug, Clone)]
pub struct Scheduler {
    tenants: Arc<dyn TenantSource>,
    indexing: Option<Arc<dyn IndexRunner>>,
    coverage: Option<CoverageProbe>,
    reconciler: ReconcilerConfig,
    cadence: Cadence,
}

impl Scheduler {
    /// A scheduler running only the two passes that need nothing but PostgreSQL.
    ///
    /// The two optional ones are added by [`Scheduler::with_indexing`] and
    /// [`Scheduler::with_coverage`]. Starting from the minimum rather than from everything is the
    /// deny-by-default shape: a capability appears because something constructed it, never because
    /// a field defaulted to `Some`.
    #[must_use]
    pub fn new(tenants: Arc<dyn TenantSource>) -> Self {
        Self {
            tenants,
            indexing: None,
            coverage: None,
            reconciler: ReconcilerConfig::default(),
            cadence: Cadence::default(),
        }
    }

    /// Schedules the indexing pass. Without this call, nothing indexes.
    #[must_use]
    pub fn with_indexing(mut self, runner: Arc<dyn IndexRunner>) -> Self {
        self.indexing = Some(runner);
        self
    }

    /// Schedules the coverage probe. Without this call, the coverage gauges have no producer and
    /// `SearchIndexCoverageUnreported` keeps describing the deployment (`docs/11 §5.7` step 5).
    #[must_use]
    pub fn with_coverage(mut self, census: Arc<dyn IndexCensus>, floor: CoverageFloor) -> Self {
        self.coverage = Some(CoverageProbe { census, floor });
        self
    }

    /// Overrides the intervals.
    #[must_use]
    pub const fn with_cadence(mut self, cadence: Cadence) -> Self {
        self.cadence = cadence;
        self
    }

    /// Overrides the reconciler's batch size.
    #[must_use]
    pub const fn with_reconciler(mut self, reconciler: ReconcilerConfig) -> Self {
        self.reconciler = reconciler;
        self
    }

    /// The passes this process will actually run, in a stable order.
    ///
    /// The start-up log line and the tests both read this. It is the whole of the "what is not
    /// scheduled is not scheduled *silently*" property: a deployment missing object storage sees
    /// `indexing` absent from a line it printed on purpose, rather than inferring it from a
    /// throughput graph that never left zero.
    #[must_use]
    pub fn scheduled(&self) -> Vec<&'static str> {
        let mut passes = vec![INVALIDATION, EPOCH];
        if self.indexing.is_some() {
            passes.insert(0, INDEXING);
        }
        if self.coverage.is_some() {
            passes.push(COVERAGE);
        }
        passes
    }

    /// Runs every scheduled pass until `stop` is raised, then returns once all of them have stopped.
    ///
    /// Returning only when the last loop has returned is the point, not a detail. Each loop leaves
    /// off between transactions (`crates/worker/src/lib.rs`), so a caller that dropped this future
    /// on SIGTERM would sever whatever was in flight — `sqlx` rolls it back, so nothing is corrupt,
    /// but the work is discarded and the connection is returned mid-conversation. `crates/api/src/
    /// main.rs::shutdown` makes the same argument for in-flight requests.
    pub async fn run(self, pool: &DbPool, stop: Stop) {
        info!(passes = ?self.scheduled(), "worker passes starting");

        let mut tasks = Vec::new();

        if let Some(runner) = self.indexing.clone() {
            let (tenants, cadence, stop) =
                (Arc::clone(&self.tenants), self.cadence.indexing_idle, stop.clone());
            tasks.push(tokio::spawn(async move {
                indexing_loop(tenants.as_ref(), runner.as_ref(), cadence, &stop).await;
            }));
        }

        {
            let (pool, tenants, cadence, stop) =
                (pool.clone(), Arc::clone(&self.tenants), self.cadence.invalidation, stop.clone());
            tasks.push(tokio::spawn(async move {
                invalidation_loop(&pool, tenants.as_ref(), cadence, &stop).await;
            }));
        }

        {
            let (pool, tenants, config, cadence, stop) = (
                pool.clone(),
                Arc::clone(&self.tenants),
                self.reconciler,
                self.cadence.epoch,
                stop.clone(),
            );
            tasks.push(tokio::spawn(async move {
                epoch_loop(&pool, tenants.as_ref(), config, cadence, &stop).await;
            }));
        }

        if let Some(probe) = self.coverage.clone() {
            let (pool, tenants, cadence, stop) =
                (pool.clone(), Arc::clone(&self.tenants), self.cadence.coverage, stop.clone());
            tasks.push(tokio::spawn(async move {
                coverage_loop(&pool, tenants.as_ref(), &probe, cadence, &stop).await;
            }));
        }

        for task in tasks {
            if let Err(error) = task.await {
                // A panicking loop is a defect, and swallowing it here would leave the other three
                // running with one silently gone — the shape this whole module exists to refuse.
                tracing::error!(%error, "a worker loop panicked");
            }
        }

        info!("every worker pass has stopped");
    }
}

/// Whether a tick found work, which is the only input the idle interval takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Something was done. Go again without waiting — there may be more.
    Progressed,
    /// Nothing to do, or nothing that going again immediately would help with. Wait.
    Idle,
}

/// The loop every pass runs: tick, and either go again or wait out the interval.
///
/// Shared rather than written four times because the interesting part is the *order* — the signal is
/// checked before a tick and again instead of the wait — and four copies of an ordering are four
/// chances to get one of them wrong in a way that only shows up as a worker that will not shut down.
///
/// Generic over the tick rather than over a trait, so the tests below drive it with a counter and no
/// database at all.
async fn run_loop<F, Fut>(pass: &'static str, idle: Duration, stop: &Stop, mut tick: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Tick>,
{
    debug!(pass, ?idle, "pass started");
    while !stop.is_stopped() {
        if tick().await == Tick::Progressed {
            continue;
        }
        if stop.sleep_until_stopped(idle).await == Woke::Stopped {
            break;
        }
    }
    debug!(pass, "pass stopped");
}

/// The tenants for this tick, or `None` when the list could not be read.
///
/// Logged and skipped rather than propagated: a scheduler that returned on a failed enumeration
/// would stop every pass in the process for a transient failure of one query, and the passes are all
/// resumable by construction. The *next* tick tries again.
async fn tenants_for(pass: &'static str, source: &dyn TenantSource) -> Option<Vec<TenantId>> {
    match source.tenants().await {
        Ok(tenants) => Some(tenants),
        Err(error) => {
            warn!(pass, %error, "could not read the tenant list; skipping this tick");
            None
        }
    }
}

/// Indexes each tenant in turn, and goes straight round again while anything is being indexed.
///
/// **Deferrals do not count as progress**, and that is load-bearing rather than a nicety.
/// [`defer`](enclave_indexing::defer) returns a file to the queue because its bytes are not readable
/// *yet* — antivirus has not finished — so a tick that deferred everything it claimed would, if that
/// counted, immediately re-claim the same files and spin at the speed of PostgreSQL until the
/// scanner caught up.
async fn indexing_loop(
    tenants: &dyn TenantSource,
    runner: &dyn IndexRunner,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(INDEXING, idle, stop, move || async move {
        let Some(tenants) = tenants_for(INDEXING, tenants).await else { return Tick::Idle };

        let mut progressed = false;
        for tenant in tenants {
            if stop.is_stopped() {
                break;
            }
            match runner.run(tenant, stop).await {
                Ok(pass) => progressed |= made_progress(&pass),
                // Per tenant, and the loop continues: one tenant whose bucket is unreachable must
                // not stop the others being indexed.
                Err(error) => warn!(pass = INDEXING, tenant = %tenant, %error, "indexing failed"),
            }
        }

        if progressed {
            Tick::Progressed
        } else {
            Tick::Idle
        }
    })
    .await;
}

/// Whether an indexing pass did anything that going straight round again could build on.
///
/// A named function rather than an expression inside the loop, so the rule can be asserted directly
/// instead of being restated by a test — a restated rule is a test of the restatement, and it agrees
/// with the code exactly until somebody changes one of them.
///
/// The three dispositions counted here are the terminal ones: a file that indexed, one that failed
/// to parse and one nobody has an extractor for have all *left the queue*. `deferred` is excluded
/// and `claimed` is not used, which is the whole content of the rule — see [`indexing_loop`].
const fn made_progress(pass: &IndexPass) -> bool {
    pass.indexed + pass.failed + pass.skipped > 0
}

/// Lifts expired suppressions on a fixed cadence.
///
/// Always [`Tick::Idle`], even after a sweep that lifted thousands: what it deleted was rows that
/// had already stopped suppressing anything, so there is no backlog to drain faster and no caller
/// waiting on it (`plans/M3-DISCOVERY.md` D22).
async fn invalidation_loop(pool: &DbPool, tenants: &dyn TenantSource, idle: Duration, stop: &Stop) {
    run_loop(INVALIDATION, idle, stop, move || async move {
        let Some(tenants) = tenants_for(INVALIDATION, tenants).await else { return Tick::Idle };
        match invalidation::sweep(pool, &tenants, stop).await {
            Ok(outcome) => debug!(pass = INVALIDATION, lifted = outcome.lifted, "swept"),
            Err(error) => warn!(pass = INVALIDATION, %error, "sweep failed"),
        }
        Tick::Idle
    })
    .await;
}

/// Marks manifests whose ACL has moved on, on a fixed cadence.
///
/// Always [`Tick::Idle`]: [`reconcile`](crate::epoch::reconcile) already drains a tenant to
/// exhaustion in batches before it returns, so there is nothing left for an immediate second tick to
/// find.
async fn epoch_loop(
    pool: &DbPool,
    tenants: &dyn TenantSource,
    config: ReconcilerConfig,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(EPOCH, idle, stop, move || async move {
        let Some(tenants) = tenants_for(EPOCH, tenants).await else { return Tick::Idle };
        match epoch::reconcile(pool, &tenants, config, stop).await {
            Ok(outcome) => debug!(pass = EPOCH, marked = outcome.marked, "reconciled"),
            Err(error) => warn!(pass = EPOCH, %error, "reconcile failed"),
        }
        Tick::Idle
    })
    .await;
}

/// Publishes each tenant's index coverage on a fixed cadence.
///
/// Always [`Tick::Idle`]: this pass writes nothing and measures a level, so running it twice in a
/// row would publish the same reading twice.
async fn coverage_loop(
    pool: &DbPool,
    tenants: &dyn TenantSource,
    probe: &CoverageProbe,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(COVERAGE, idle, stop, move || async move {
        let Some(tenants) = tenants_for(COVERAGE, tenants).await else { return Tick::Idle };
        let outcome =
            coverage::probe_pass(pool, &tenants, probe.census.as_ref(), probe.floor, stop).await;
        debug!(
            pass = COVERAGE,
            depleted = outcome.depleted,
            unreadable = outcome.unreadable,
            "probed"
        );
        Tick::Idle
    })
    .await;
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::sync::atomic::{AtomicUsize, Ordering};

    use enclave_search::SearchError;

    use super::*;

    /// A fixed tenant list, or a failure, without a database.
    #[derive(Debug)]
    struct FixedTenants {
        tenants: Vec<TenantId>,
        fail: bool,
    }

    impl FixedTenants {
        fn of(count: usize) -> Arc<Self> {
            Arc::new(Self {
                tenants: (0..count).map(|_| TenantId::new_v7()).collect(),
                fail: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self { tenants: Vec::new(), fail: true })
        }
    }

    #[async_trait]
    impl TenantSource for FixedTenants {
        async fn tenants(&self) -> Result<Vec<TenantId>> {
            if self.fail {
                return Err(crate::WorkerError::MalformedRow {
                    column: "id",
                    reason: "the enumerator failed",
                });
            }
            Ok(self.tenants.clone())
        }
    }

    /// Records which tenants it was asked about, and stops the world after `stop_after` calls.
    #[derive(Debug)]
    struct RecordingRunner {
        seen: std::sync::Mutex<Vec<TenantId>>,
        stop_after: usize,
        outcome: IndexPass,
        stop: Stop,
    }

    impl RecordingRunner {
        fn new(stop: Stop, stop_after: usize, outcome: IndexPass) -> Arc<Self> {
            Arc::new(Self { seen: std::sync::Mutex::new(Vec::new()), stop_after, outcome, stop })
        }

        fn seen(&self) -> Vec<TenantId> {
            self.seen.lock().expect("the recorder was not poisoned").clone()
        }
    }

    #[async_trait]
    impl IndexRunner for RecordingRunner {
        async fn run(&self, tenant: TenantId, _stop: &Stop) -> Result<IndexPass> {
            let calls = {
                let mut seen = self.seen.lock().expect("the recorder was not poisoned");
                seen.push(tenant);
                seen.len()
            };
            if calls >= self.stop_after {
                self.stop.stop();
            }
            Ok(self.outcome)
        }
    }

    fn indexed_one() -> IndexPass {
        IndexPass { claimed: 1, indexed: 1, ..IndexPass::default() }
    }

    fn deferred_one() -> IndexPass {
        IndexPass { claimed: 1, deferred: 1, ..IndexPass::default() }
    }

    /// A pass whose dependency is absent is not scheduled, and a pass whose dependency is present
    /// is — both halves, because the first assertion passes for free against a `scheduled()` that
    /// returned nothing at all (`docs/12-TESTING.md §1.2`).
    ///
    /// The negative half is the one that matters: `index_pass` claims files in a committed
    /// transaction before it reads a byte, so scheduling it against a store that cannot answer
    /// increments `attempts` on every file it touches and eventually quarantines a corpus whose only
    /// problem is a missing bucket.
    #[test]
    fn a_capability_that_is_absent_is_not_scheduled_and_one_that_is_present_is() {
        let tenants = FixedTenants::of(1);

        let bare = Scheduler::new(tenants.clone());
        assert_eq!(bare.scheduled(), vec![INVALIDATION, EPOCH]);

        let with_indexing = Scheduler::new(tenants.clone()).with_indexing(RecordingRunner::new(
            Stop::new(),
            usize::MAX,
            indexed_one(),
        ));
        assert_eq!(with_indexing.scheduled(), vec![INDEXING, INVALIDATION, EPOCH]);

        let with_coverage = Scheduler::new(tenants)
            .with_coverage(Arc::new(SilentCensus), CoverageFloor::percent(80));
        assert_eq!(with_coverage.scheduled(), vec![INVALIDATION, EPOCH, COVERAGE]);
    }

    /// The two housekeeping passes are not optional, because neither has a dependency that could be
    /// missing: both are PostgreSQL and nothing else.
    #[test]
    fn the_two_postgresql_only_passes_are_always_scheduled() {
        let scheduler = Scheduler::new(FixedTenants::of(1));
        for pass in [INVALIDATION, EPOCH] {
            assert!(scheduler.scheduled().contains(&pass), "{pass} was not scheduled");
        }
    }

    /// The loop visits every tenant the source hands it, exactly once per tick.
    ///
    /// The interval is an hour and is never waited on, because the runner raises the signal on the
    /// last tenant of the first sweep. A regression that skipped the enumeration, or that visited
    /// the first tenant only, fails on the recorded list — not on a stopwatch.
    #[tokio::test]
    async fn the_indexing_loop_visits_every_tenant() {
        let stop = Stop::new();
        let tenants = FixedTenants::of(3);
        let runner = RecordingRunner::new(stop.clone(), 3, indexed_one());

        indexing_loop(tenants.as_ref(), runner.as_ref(), Duration::from_secs(3600), &stop).await;

        assert_eq!(runner.seen(), tenants.tenants, "every tenant, in the source's order, once");
    }

    /// A tick that only deferred is idle, so the loop waits instead of re-claiming the same files.
    ///
    /// Deferral means antivirus has not finished with those bytes. Counting it as progress makes the
    /// loop re-claim the identical rows immediately and spin at the speed of PostgreSQL until the
    /// scan completes — a hot loop whose only external symptom is database load.
    ///
    /// Both halves against the rule the loop actually applies, not a copy of it. A test that
    /// re-derived the sum would agree with a broken loop for as long as both were broken the same
    /// way.
    ///
    /// Every terminal disposition counts, including the two that are bad news: a document that
    /// failed to parse and one nobody has an extractor for have both left the queue, so there *is*
    /// more work to fetch. Only a deferral leaves the file exactly where it was.
    #[test]
    fn a_deferred_file_is_not_progress_but_every_terminal_one_is() {
        assert!(!made_progress(&deferred_one()), "a deferral would spin the loop");
        assert!(made_progress(&indexed_one()));
        assert!(made_progress(&IndexPass { claimed: 1, failed: 1, ..IndexPass::default() }));
        assert!(made_progress(&IndexPass { claimed: 1, skipped: 1, ..IndexPass::default() }));
        assert!(!made_progress(&IndexPass::default()), "an empty queue is idle");
    }

    /// A signal already raised means no tick runs at all.
    ///
    /// The check is before the tick, not after it, so a worker told to stop does not first do one
    /// more batch of work it will not be around to finish. Paired with the test above, which proves
    /// the loop does run ticks, so this cannot pass by the loop being broken.
    #[tokio::test]
    async fn a_loop_that_starts_stopped_does_no_work() {
        let stop = Stop::new();
        stop.stop();
        let calls = AtomicUsize::new(0);
        let calls = &calls;

        run_loop("test", Duration::from_secs(3600), &stop, move || async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Tick::Idle
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0, "a stopped loop ran a tick");
    }

    /// A tick that made progress goes straight round again instead of waiting out the interval.
    ///
    /// The interval is an hour, and that is what makes this an assertion rather than a hope: the
    /// first tick reports [`Tick::Progressed`], so a loop honouring it reaches the second tick
    /// immediately, and the second raises the signal. A loop that waited after progress would take
    /// an hour, so the call is bounded by a `timeout` that turns that hang into a named failure. The
    /// verdict is still the counter: thirty seconds against an expected microsecond is not a margin
    /// any machine can close.
    ///
    /// Without this branch the indexer drains its queue one batch per idle interval, which on a bulk
    /// upload is the difference between minutes and days. The other direction — that an *idle* tick
    /// does wait — is `a_sleep_that_is_not_stopped_reports_the_interval_elapsing` in `src/lib.rs`,
    /// where the sleep itself is the subject.
    #[tokio::test]
    async fn progress_skips_the_wait() {
        let stop = Stop::new();
        let calls = AtomicUsize::new(0);
        let calls = &calls;
        let signal = stop.clone();
        let signal = &signal;

        let loop_run = run_loop("test", Duration::from_secs(3600), &stop, move || async move {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                return Tick::Progressed;
            }
            signal.stop();
            Tick::Idle
        });
        tokio::time::timeout(Duration::from_secs(30), loop_run)
            .await
            .expect("the loop waited out its idle interval after a tick that made progress");

        assert_eq!(calls.load(Ordering::SeqCst), 2, "the loop did not go straight round again");
    }

    /// An enumerator that fails costs one tick, not the loop.
    ///
    /// A scheduler that propagated the failure would stop every pass in the process because one
    /// query failed once, and the passes are all resumable by construction — so the next tick simply
    /// tries again.
    #[tokio::test]
    async fn a_failed_enumeration_skips_the_tick_and_keeps_the_loop() {
        let stop = Stop::new();
        let tenants = FixedTenants::failing();
        let runner = RecordingRunner::new(stop.clone(), usize::MAX, indexed_one());

        assert!(tenants_for(INDEXING, tenants.as_ref()).await.is_none());

        // And the loop survives it: the signal is raised from outside, so the only way this returns
        // is the loop's own boundary check.
        stop.stop();
        indexing_loop(tenants.as_ref(), runner.as_ref(), Duration::from_secs(3600), &stop).await;
        assert!(runner.seen().is_empty(), "no tenant could be read, so none was indexed");
    }

    /// A census that answers nothing, for the `scheduled()` assertions, which never call it.
    #[derive(Debug)]
    struct SilentCensus;

    #[async_trait]
    impl IndexCensus for SilentCensus {
        async fn chunks(&self, _tenant: TenantId) -> core::result::Result<u64, SearchError> {
            Ok(0)
        }
    }
}
