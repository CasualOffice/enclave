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
use chrono::Utc;
use enclave_antivirus::{AntivirusScanner, ScanPolicy};
use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_indexing::{BuildVersions, ChunkerVersion, Extractor, ExtractorVersion, Pipeline};
use enclave_preview::RenderBudget;
use enclave_search::health::{CoverageFloor, IndexCensus};
use enclave_storage::BlobStore;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::antivirus::{av_pass, AvCursor, AvPass};
use crate::epoch::ReconcilerConfig;
use crate::indexing::{index_pass, IndexPass, VectorStage};
use crate::ocr::MountedOcr;
use crate::scan::{scan_pass, ScanCursor, ScanPass};
use crate::uploads::{released_a_full_batch, ReapPass};
use crate::{coverage, epoch, invalidation, print_tokens, tiering, Result, Stop, Woke};
use enclave_dlp::detector::DetectorSet;

/// The names [`Scheduler::scheduled`] reports and the loops log under.
///
/// Constants rather than literals at three call sites, because the binary's start-up line, the
/// per-loop log field and the tests all have to agree for any of them to be worth reading.
pub const INDEXING: &str = "indexing";
/// See [`INDEXING`].
pub const ANTIVIRUS: &str = "antivirus";
/// See [`INDEXING`].
pub const SCANNING: &str = "content-scan";
/// See [`INDEXING`].
pub const INVALIDATION: &str = "invalidation";
/// See [`INDEXING`].
pub const EPOCH: &str = "epoch";
/// See [`INDEXING`].
pub const COVERAGE: &str = "coverage";
/// See [`INDEXING`]. `ENC-806` — the pass that had no caller in any binary for five milestones.
pub const UPLOADS: &str = "upload-reaper";
/// See [`INDEXING`]. `ENC-724` — dead print capabilities, on every deployment.
///
/// Unconditional, like [`INVALIDATION`] and [`EPOCH`] and unlike [`UPLOADS`]: `print_tokens` is
/// written by any deployment that can mint a grant, which is all of them, whereas the upload reaper
/// exists only where object storage is configured. The reasoning is in
/// `crates/worker/src/print_tokens.rs`.
pub const PRINT_TOKENS: &str = "print-token-reaper";
/// See [`INDEXING`]. `ENC-947` — the pass that finishes a rehydration.
///
/// Conditional on object storage, like [`UPLOADS`] and unlike [`PRINT_TOKENS`]: it asks the store
/// where an object actually is, so a deployment with no store has nothing for it to ask. Absent, a
/// version marked `RESTORING` by `POST /files/{id}/rehydrate` **stays that way for ever** — the
/// bytes land and every read path goes on refusing them, which is a request that is accepted and
/// never completes. `Scheduler::scheduled` is what makes that absence a line an operator reads.
pub const TIERING: &str = "tier-reconciler";

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
    /// How long the antivirus pass waits when nothing is waiting for a verdict.
    ///
    /// The shortest of the five, because this interval **is** the latency between an upload
    /// completing and its content existing as far as every other part of the product is concerned:
    /// nothing is readable, previewable, searchable or scannable for DLP until this pass has moved
    /// the version. The indexing interval used to be described as that latency and was measuring
    /// only the second half of it (`ENC-641`).
    ///
    /// A tick that recorded any verdict does not wait at all — see [`Tick::Progressed`] and
    /// [`av_progressed`].
    pub antivirus_idle: Duration,
    /// How long the content scanner waits when nothing is due.
    ///
    /// Longer than [`Self::indexing_idle`], and the difference is not caution about cost. The scan
    /// queue is a *query* rather than a claimed work list (`crate::scan::ScanCursor`), so a version
    /// that cannot be scanned stays in it — and this interval is what turns the re-attempt of an
    /// unscannable corpus into a bounded rate rather than a spin. Re-attempting is deliberate: an
    /// unsupported media type becomes scannable the day a deployment mounts PDFium, and a textless
    /// scan becomes scannable the day it mounts OCR, with no backfill to run.
    pub scan_idle: Duration,
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
    /// How often abandoned and stranded upload sessions are swept when there are none.
    ///
    /// The longest of the six, and it is the only one where that is not a cost. A staged object
    /// nobody will ever read costs storage, never correctness: no read path can reach it, no quota
    /// counts it, no search can return it. Sweeping more often would find the same nothing more
    /// expensively, per tenant, and this interval paces *only* the empty case — a tick that emptied
    /// its batch goes straight round again ([`crate::uploads::released_a_full_batch`]), so a
    /// deployment with a real backlog drains it at the speed of the object store rather than at the
    /// speed of this number.
    ///
    /// What it must not be is hours. `ENC-806` is the row for a reaper nothing ran at all, and the
    /// first thing anyone will do with a deployment that has one is watch whether the bytes go.
    pub uploads_idle: Duration,
    /// How often dead print capabilities are deleted when there are none.
    ///
    /// Sixty seconds, and the number follows from the grant's own lifetime rather than from taste:
    /// a print token lives 120 seconds, so a tenant's dead set is bounded by its mint rate times
    /// this interval whatever it is, and sweeping at half the TTL keeps the table within one
    /// lifetime's worth of rows without a batch ever being full in steady state.
    ///
    /// It buys table size and nothing else. An expired grant is refused by
    /// `enclave_preview::print::redeem` before the sweep arrives and after it leaves, so this
    /// interval cannot be wrong in the direction that matters — only in the direction of a larger
    /// table.
    pub print_tokens: Duration,
    /// How long the tier reconciler waits after a tick that resolved nothing (`ENC-947`).
    ///
    /// Sixty seconds. The population it walks is empty on a deployment with nothing
    /// mid-transition, which is most of them most of the time, so the cost of a tick is one
    /// bounded query per tenant and no provider call at all. What sets the *upper* bound is that
    /// this interval is the tail a person waits after their file has already come back: a
    /// rehydration takes hours, and adding ten minutes of polling to the end of it would be the
    /// product wasting the one part of the wait it controls.
    pub tiering: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            indexing_idle: Duration::from_secs(5),
            antivirus_idle: Duration::from_secs(5),
            scan_idle: Duration::from_secs(30),
            invalidation: Duration::from_secs(300),
            epoch: Duration::from_secs(60),
            coverage: Duration::from_secs(60),
            uploads_idle: Duration::from_secs(600),
            print_tokens: Duration::from_secs(60),
            tiering: Duration::from_secs(60),
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

/// One tenant's share of the versions waiting for an antivirus verdict.
///
/// Its own trait for the reason [`ScanRunner`] is its own: the three content passes are
/// independently absent, and [`Scheduler::scheduled`] has to be able to say *which*. This one is the
/// most consequential absence of the three — see [`Scheduler::with_antivirus`].
#[async_trait]
pub trait AvRunner: Send + Sync + fmt::Debug {
    /// Scans up to one batch of `tenant`'s versions that have no usable antivirus verdict.
    ///
    /// # Errors
    ///
    /// Whatever [`av_pass`] returns: a database failure. Never an engine that would not answer and
    /// never an object that could not be read — both are verdicts, so that `av.unavailable_policy`
    /// decides what happens to the content instead of an error path.
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<AvPass>;
}

/// One tenant's share of the content-scan queue.
///
/// Separate from [`IndexRunner`] rather than a second method on it, because the two capabilities are
/// independently absent: a deployment can index without scanning (no detectors wired) and scan
/// without indexing. One trait with two methods would make [`Scheduler::scheduled`] unable to say
/// which of the two a process is actually running, which is the whole point of that function.
#[async_trait]
pub trait ScanRunner: Send + Sync + fmt::Debug {
    /// Scans up to one batch of `tenant`'s versions that have no usable facts.
    ///
    /// # Errors
    ///
    /// Whatever [`scan_pass`] returns: a storage or database failure, never a document that would
    /// not parse.
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<ScanPass>;
}

/// One tenant's share of the upload sessions whose staged bytes nothing will ever read — `ENC-806`.
///
/// Its own trait for the reason [`AvRunner`] and [`ScanRunner`] are: this capability is
/// independently absent, and [`Scheduler::scheduled`] has to be able to say so. It is the only pass
/// in this crate that **deletes objects**, which is why its absence must be announced rather than
/// inferred, and why it is never scheduled against a store that was not composed.
#[async_trait]
pub trait ReaperRunner: Send + Sync + fmt::Debug {
    /// Releases up to one batch each of `tenant`'s abandoned and stranded sessions.
    ///
    /// Takes no [`Stop`], unlike the three content runners. Theirs drain a tenant across many
    /// claims and have to be interruptible part-way; a reaping tick is two bounded transactions and
    /// the loop checks the flag between ticks. A stopped sweep is a shorter sweep, never a
    /// half-finished one — both predicates are self-consuming, so whatever it did not reach still
    /// matches next time.
    ///
    /// # Errors
    ///
    /// Whatever [`reap_pass`](crate::uploads::reap_pass) returns: a claim, a transaction or a commit
    /// failing. Never an object the store would not delete — that is a deferral, counted and
    /// retried next tick.
    async fn run(&self, tenant: TenantId) -> Result<ReapPass>;
}

/// [`ReaperRunner`] over a real store and pool — `ENC-806`.
///
/// # What it holds that the content runners do not
///
/// A **grace period**, and no extractor, no engine and no cursor.
///
/// No cursor because both claims are self-consuming: a released session is `EXPIRED` and matches
/// neither predicate again, so a sweep resumes from the top and finds what is left. The two passes
/// that carry cursors ([`ContentScanner`], [`VersionScanner`]) do so because their queues are
/// *queries* with no claim column and a version that produces no verdict never leaves them.
///
/// The grace period is the one knob, and it exists because of what this pass can destroy. See
/// [`UploadReaper::new`].
pub struct UploadReaper {
    pool: DbPool,
    /// `Arc<dyn BlobStore>` rather than a type parameter, unlike the three runners above. They are
    /// generic because they are constructed beside a `Pipeline<E>` whose extractor is already a type
    /// parameter; this one composes nothing and needs no concrete store, so a parameter here would
    /// be a name every caller has to write for no property it buys.
    store: Arc<dyn BlobStore>,
    grace: chrono::Duration,
    batch: usize,
}

impl fmt::Debug for UploadReaper {
    /// Names the wiring, never its contents — [`PipelineRunner`]'s reason. The grace *is* printed,
    /// because it is the number that decides whether a completion still in flight can be mistaken
    /// for a stranded one, and a start-up line is exactly where an operator should be able to read
    /// it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadReaper")
            .field("stranded_grace_hours", &self.grace.num_hours())
            .field("batch", &self.batch)
            .finish_non_exhaustive()
    }
}

impl UploadReaper {
    /// Assembles the reaping pass's dependencies once, for every tenant and every tick.
    ///
    /// `grace` is how long a session must have been claiming to scan before this pass will consider
    /// it stranded. It is a parameter and not a constant here because the honest value differs
    /// between a one-off repair somebody watches (`enclave-cli reclaim-uploads`, where an operator
    /// picks it and reads the candidate list first) and an unattended standing sweep, which must be
    /// the conservative one. `crates/worker/src/main.rs::STRANDED_GRACE` is the value this binary
    /// chooses and states why.
    ///
    /// It is deliberately **not** derived from `expires_at`. That is the upload TTL — a fact about
    /// when the session was created — and a session handed off to the scanner one minute before its
    /// TTL ran out would be a candidate a minute later
    /// (`UploadRepository::claim_stranded`).
    #[must_use]
    pub const fn new(
        pool: DbPool,
        store: Arc<dyn BlobStore>,
        grace: chrono::Duration,
        batch: usize,
    ) -> Self {
        Self { pool, store, grace, batch }
    }
}

#[async_trait]
impl ReaperRunner for UploadReaper {
    async fn run(&self, tenant: TenantId) -> Result<ReapPass> {
        crate::uploads::reap_pass(
            &self.pool,
            tenant,
            self.store.as_ref(),
            Utc::now(),
            self.grace,
            self.batch,
        )
        .await
    }
}

/// [`IndexRunner`] over a real pipeline, store and pool.
///
/// Holds the pool as well as the store so that the scheduling loop needs neither — a loop that took
/// a `DbPool` would be untestable without one, and everything it does with it is inside
/// [`index_pass`] already.
pub struct PipelineRunner<E: Extractor, S: BlobStore + ?Sized> {
    pool: DbPool,
    pipeline: Pipeline<E>,
    /// Shared rather than owned since `ENC-613`: [`ContentScanner`] runs the *same* OCR stage, and
    /// `PdfiumLibrary` is a process singleton whose `DOCUMENTS` lock is per-library — two of them
    /// would be two locks, which is no lock at all (`crate::ocr`).
    ocr: Option<Arc<MountedOcr>>,
    vectors: Option<VectorStage>,
    store: Arc<S>,
    extractor: ExtractorVersion,
    chunker: ChunkerVersion,
    embedding_model: String,
    budget: RenderBudget,
    batch: i64,
}

impl<E: Extractor, S: BlobStore + ?Sized> fmt::Debug for PipelineRunner<E, S> {
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

impl<E: Extractor, S: BlobStore + ?Sized> PipelineRunner<E, S> {
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
        ocr: Option<Arc<MountedOcr>>,
        store: Arc<S>,
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
impl<E: Extractor, S: BlobStore + ?Sized> IndexRunner for PipelineRunner<E, S> {
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
            self.ocr.as_deref(),
            self.vectors.as_ref(),
            self.store.as_ref(),
            versions,
            self.budget,
            self.batch,
            stop,
        )
        .await
    }
}

/// [`ScanRunner`] over a real pipeline, detector set, store and pool — `ENC-613`.
///
/// Takes the **same** [`Pipeline`] and the **same** [`MountedOcr`] as [`PipelineRunner`], by
/// `Arc`, so a media type that indexes is a media type that scans. See `crate::scan` for why a
/// second extraction path is the thing this design is arranged against.
///
/// # The cursor is the one piece of state a runner holds
///
/// [`scan_pass`] is a pure function of its arguments and returns where the next pass should resume;
/// this is where that answer is kept between ticks. A [`std::sync::Mutex`] rather than an async one
/// because it is held for two moves and never across an `await` — the lock guards a map lookup, not
/// the scan.
///
/// It is bounded by the tenant list: one small entry per tenant, replaced in place. A tenant that
/// disappears leaves an entry behind, which costs a `Uuid` and a timestamp and is corrected by the
/// next process restart — the cursor is a pacing aid and losing one is harmless (`crate::scan`).
pub struct ContentScanner<E: Extractor, S: BlobStore + ?Sized> {
    pool: DbPool,
    pipeline: Pipeline<E>,
    ocr: Option<Arc<MountedOcr>>,
    detectors: Arc<DetectorSet>,
    store: Arc<S>,
    budget: RenderBudget,
    batch: i64,
    cursors: std::sync::Mutex<std::collections::HashMap<TenantId, ScanCursor>>,
}

impl<E: Extractor, S: BlobStore + ?Sized> fmt::Debug for ContentScanner<E, S> {
    /// Names the wiring, never its contents — [`PipelineRunner`]'s reason, and one more: the
    /// detector set's `Debug` would print every detector, which is a list of what this deployment
    /// looks for. That is not a match value, so it is not a rule 10 violation, but a start-up line
    /// is not where it belongs either. The **version** is printed, because that is the string a
    /// stored fact row carries and the one an operator has to be able to compare.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentScanner")
            .field("detector_set", &self.detectors.version().as_str())
            .field("ocr", &self.ocr.is_some())
            .field("batch", &self.batch)
            .finish_non_exhaustive()
    }
}

impl<E: Extractor, S: BlobStore + ?Sized> ContentScanner<E, S> {
    /// Assembles the scan pass's dependencies once, for every tenant and every tick.
    ///
    /// `detectors` is an [`Arc`] because the scan itself runs on a blocking thread and the set has
    /// to outlive the call that moved it there — and because the *same* set has to be the one
    /// `crates/api` compares fact rows against. A deployment holding two sets under one version
    /// string is the failure `enclave_dlp::builtin::BUILTIN_SET_VERSION` is pinned against.
    #[must_use]
    pub fn new(
        pool: DbPool,
        extractor: E,
        chunker: enclave_indexing::Chunker,
        ocr: Option<Arc<MountedOcr>>,
        detectors: Arc<DetectorSet>,
        store: Arc<S>,
        budget: RenderBudget,
        batch: i64,
    ) -> Self {
        Self {
            pool,
            pipeline: Pipeline::new(extractor, chunker),
            ocr,
            detectors,
            store,
            budget,
            batch,
            cursors: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Where this tenant's next sweep resumes.
    ///
    /// A poisoned lock reads as [`ScanCursor::start`] rather than panicking: the cursor is pacing
    /// and not correctness, so beginning the sweep again is the worst it can cost, whereas a panic
    /// here would take down a pass for the lifetime of the process.
    fn cursor(&self, tenant: TenantId) -> ScanCursor {
        self.cursors
            .lock()
            .map(|cursors| cursors.get(&tenant).copied().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Records where the next sweep should resume.
    fn advance(&self, tenant: TenantId, cursor: ScanCursor) {
        if let Ok(mut cursors) = self.cursors.lock() {
            cursors.insert(tenant, cursor);
        }
    }
}

#[async_trait]
impl<E: Extractor, S: BlobStore + ?Sized> ScanRunner for ContentScanner<E, S> {
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<ScanPass> {
        let from = self.cursor(tenant);
        let pass = scan_pass(
            &self.pool,
            tenant,
            &self.pipeline,
            self.ocr.as_deref(),
            &self.detectors,
            self.store.as_ref(),
            self.budget,
            self.batch,
            from,
            stop,
        )
        .await?;
        // Only on success. A pass that failed part-way through a batch has no trustworthy answer
        // about where it got to, and advancing past versions it never reached would leave them
        // unscanned until the sweep came round again.
        self.advance(tenant, pass.resume);
        Ok(pass)
    }
}

/// [`AvRunner`] over a real engine, store and pool — `ENC-641`.
///
/// # What it holds that the two extraction runners do not
///
/// A [`ScanPolicy`] and no extractor. The policy is resolved once, at the composition root, from
/// `antivirus:` — see [`ScanPolicy::from_config`] for why exactly one of its two knobs comes from
/// configuration. No extractor because antivirus reads *bytes*: the object goes to the engine as a
/// stream and is never parsed, chunked or held, which is also why this pass has no
/// [`RenderBudget`] — the ceiling that applies is the engine's own `max_scan_bytes`.
///
/// The cursor is the one piece of state, exactly as in [`ContentScanner`], and for the same reason:
/// the queue is a query with no claim column, so a version that keeps producing no verdict never
/// leaves it and a sweep without a cursor would re-select the same batch forever.
pub struct VersionScanner<S: BlobStore + ?Sized> {
    pool: DbPool,
    scanner: Arc<dyn AntivirusScanner>,
    store: Arc<S>,
    policy: ScanPolicy,
    batch: i64,
    cursors: std::sync::Mutex<std::collections::HashMap<TenantId, AvCursor>>,
}

impl<S: BlobStore + ?Sized> fmt::Debug for VersionScanner<S> {
    /// Names the wiring, never its contents — [`PipelineRunner`]'s reason. The policy *is* printed,
    /// because it is two closed enumerations and it is the pair an operator most needs to see in a
    /// start-up line: it decides what happens to a version the engine could not form an opinion
    /// about, and to every version at all if the engine is down.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionScanner")
            .field("unsupported", &self.policy.unsupported)
            .field("unavailable", &self.policy.unavailable)
            .field("batch", &self.batch)
            .finish_non_exhaustive()
    }
}

impl<S: BlobStore + ?Sized> VersionScanner<S> {
    /// Assembles the antivirus pass's dependencies once, for every tenant and every tick.
    #[must_use]
    pub fn new(
        pool: DbPool,
        scanner: Arc<dyn AntivirusScanner>,
        store: Arc<S>,
        policy: ScanPolicy,
        batch: i64,
    ) -> Self {
        Self {
            pool,
            scanner,
            store,
            policy,
            batch,
            cursors: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Where this tenant's next sweep resumes.
    ///
    /// A poisoned lock reads as [`AvCursor::start`] rather than panicking: the cursor is pacing and
    /// not correctness, so beginning the sweep again is the worst it can cost — whereas a panic here
    /// would stop every version in the deployment becoming readable for the life of the process.
    fn cursor(&self, tenant: TenantId) -> AvCursor {
        self.cursors
            .lock()
            .map(|cursors| cursors.get(&tenant).copied().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Records where the next sweep should resume.
    fn advance(&self, tenant: TenantId, cursor: AvCursor) {
        if let Ok(mut cursors) = self.cursors.lock() {
            cursors.insert(tenant, cursor);
        }
    }
}

#[async_trait]
impl<S: BlobStore + ?Sized> AvRunner for VersionScanner<S> {
    async fn run(&self, tenant: TenantId, stop: &Stop) -> Result<AvPass> {
        let from = self.cursor(tenant);
        let pass = av_pass(
            &self.pool,
            tenant,
            self.scanner.as_ref(),
            self.store.as_ref(),
            self.policy,
            self.batch,
            from,
            stop,
        )
        .await?;
        // Only on success, as [`ContentScanner`] does: a pass that failed part-way has no
        // trustworthy answer about where it got to, and advancing past versions it never reached
        // would leave them unscanned — and therefore unreadable — until the sweep came round again.
        self.advance(tenant, pass.resume);
        Ok(pass)
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
#[derive(Clone)]
pub struct Scheduler {
    tenants: Arc<dyn TenantSource>,
    antivirus: Option<Arc<dyn AvRunner>>,
    indexing: Option<Arc<dyn IndexRunner>>,
    scanning: Option<Arc<dyn ScanRunner>>,
    reaping: Option<Arc<dyn ReaperRunner>>,
    /// The store the tier reconciler asks. `None` where no object storage is configured.
    tiering: Option<Arc<dyn enclave_storage::BlobStore>>,
    coverage: Option<CoverageProbe>,
    reconciler: ReconcilerConfig,
    cadence: Cadence,
}

/// Written by hand rather than derived (`ENC-947`).
///
/// `BlobStore` is not `Debug` — it is a provider client, and a bound requiring one would land on
/// every test double in the workspace to print connection state nobody wants. What a reader of this
/// type actually wants is the same thing [`Scheduler::scheduled`] reports, so that is what it
/// prints: which passes this process will run.
impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheduler")
            .field("scheduled", &self.scheduled())
            .field("cadence", &self.cadence)
            .finish_non_exhaustive()
    }
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
            antivirus: None,
            indexing: None,
            scanning: None,
            reaping: None,
            tiering: None,
            coverage: None,
            reconciler: ReconcilerConfig::default(),
            cadence: Cadence::default(),
        }
    }

    /// Schedules the antivirus pass. **Without this call, nothing in the deployment ever becomes
    /// readable.**
    ///
    /// That sentence is the whole of `ENC-641`, and it is why this builder step reads differently
    /// from the other three. `with_indexing` absent costs searchability; `with_scanning` absent
    /// costs evidence the DLP stage would have decided on. This one absent costs *the product*: every
    /// version stays `SCANNING` / `PENDING`, `readable_version` answers `None` for all of them, and
    /// the two passes below run correctly over an empty set forever.
    ///
    /// It is still optional, and for the same deny-by-default reason the others are: the pass reads
    /// object storage, so a deployment that configured none must not have it scheduled and failing.
    /// What makes that safe is that the absence is *unreadable*, never permissive —
    /// [`Scheduler::scheduled`] is what makes it visible rather than merely true, and
    /// `crates/worker/src/main.rs` logs it at start-up.
    #[must_use]
    pub fn with_antivirus(mut self, runner: Arc<dyn AvRunner>) -> Self {
        self.antivirus = Some(runner);
        self
    }

    /// Schedules the indexing pass. Without this call, nothing indexes.
    #[must_use]
    pub fn with_indexing(mut self, runner: Arc<dyn IndexRunner>) -> Self {
        self.indexing = Some(runner);
        self
    }

    /// Schedules the content scan. Without this call **nothing writes `security_facts`**, so every
    /// version stays unscanned and the DLP stage decides on the tenant's `facts_unavailable`
    /// policy rather than on evidence (`ENC-613`, `docs/06 §12`).
    ///
    /// Optional for the reason [`Scheduler::with_indexing`] is: the pass reads object storage, and
    /// a deployment that configured none must not have it scheduled and failing. That absence is
    /// safe — no row means unscanned, which is refused under `FAIL_CLOSED` and permitted with
    /// evidence under `FAIL_OPEN_AUDIT` — and [`Scheduler::scheduled`] is what makes it visible
    /// rather than merely true.
    #[must_use]
    pub fn with_scanning(mut self, runner: Arc<dyn ScanRunner>) -> Self {
        self.scanning = Some(runner);
        self
    }

    /// Schedules the upload reaper. **Without this call, no staged object is ever released**
    /// (`ENC-806`).
    ///
    /// That was the state of every deployment until this builder step existed: `reap_expired` had a
    /// full test suite and no caller outside it, so an abandoned upload kept its bytes forever —
    /// unmetered, unreferenced and unreachable by any read path.
    ///
    /// Optional for the reason the three content passes are, and more strictly. The pass *deletes
    /// objects*, so a deployment that configured no object storage must not have it scheduled and
    /// failing: a sweep that could not delete would either mark rows and orphan their bytes for good
    /// or defer every session forever while looking busy. Absent, it costs storage and nothing else
    /// — no read path, no quota and no search can reach a staged object — and
    /// [`Scheduler::scheduled`] is what makes that absence a line an operator reads rather than a
    /// bucket that quietly grows.
    #[must_use]
    pub fn with_upload_reaper(mut self, runner: Arc<dyn ReaperRunner>) -> Self {
        self.reaping = Some(runner);
        self
    }

    /// Schedules the tier reconciler (`ENC-947`).
    ///
    /// Without it, `RESTORING` is a state nothing leaves: `POST /files/{id}/rehydrate` asks the
    /// provider for bytes back, the bytes land hours later, and the row never changes — so every
    /// read path goes on refusing content that is sitting there readable. A request accepted and
    /// never completed is worse than one refused, which is why this reads more like
    /// `with_antivirus` than like `with_coverage`.
    ///
    /// It takes the store rather than a runner trait because it has one dependency and one verb.
    #[must_use]
    pub fn with_tier_reconciler(mut self, store: Arc<dyn enclave_storage::BlobStore>) -> Self {
        self.tiering = Some(store);
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
        // The three unconditional passes. `PRINT_TOKENS` is here rather than behind an `Option`
        // because `print_tokens` is written by every deployment that can mint a grant — see
        // `crates/worker/src/print_tokens.rs` for why it is not a limb of `UPLOADS`, which is not.
        let mut passes = vec![INVALIDATION, EPOCH, PRINT_TOKENS];
        if self.scanning.is_some() {
            passes.insert(0, SCANNING);
        }
        if self.indexing.is_some() {
            passes.insert(0, INDEXING);
        }
        // First, because it is first in the pipeline: nothing the other two passes read exists
        // until this one has run.
        if self.antivirus.is_some() {
            passes.insert(0, ANTIVIRUS);
        }
        if self.reaping.is_some() {
            passes.push(UPLOADS);
        }
        if self.tiering.is_some() {
            passes.push(TIERING);
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

        if let Some(runner) = self.antivirus.clone() {
            let (tenants, cadence, stop) =
                (Arc::clone(&self.tenants), self.cadence.antivirus_idle, stop.clone());
            tasks.push(tokio::spawn(async move {
                antivirus_loop(tenants.as_ref(), runner.as_ref(), cadence, &stop).await;
            }));
        }

        if let Some(runner) = self.indexing.clone() {
            let (tenants, cadence, stop) =
                (Arc::clone(&self.tenants), self.cadence.indexing_idle, stop.clone());
            tasks.push(tokio::spawn(async move {
                indexing_loop(tenants.as_ref(), runner.as_ref(), cadence, &stop).await;
            }));
        }

        if let Some(runner) = self.scanning.clone() {
            let (tenants, cadence, stop) =
                (Arc::clone(&self.tenants), self.cadence.scan_idle, stop.clone());
            tasks.push(tokio::spawn(async move {
                scanning_loop(tenants.as_ref(), runner.as_ref(), cadence, &stop).await;
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

        {
            let (pool, tenants, cadence, stop) =
                (pool.clone(), Arc::clone(&self.tenants), self.cadence.print_tokens, stop.clone());
            tasks.push(tokio::spawn(async move {
                print_tokens_loop(&pool, tenants.as_ref(), cadence, &stop).await;
            }));
        }

        if let Some(runner) = self.reaping.clone() {
            let (tenants, cadence, stop) =
                (Arc::clone(&self.tenants), self.cadence.uploads_idle, stop.clone());
            tasks.push(tokio::spawn(async move {
                uploads_loop(tenants.as_ref(), runner.as_ref(), cadence, &stop).await;
            }));
        }

        if let Some(store) = self.tiering.clone() {
            let (pool, tenants, cadence, stop) =
                (pool.clone(), Arc::clone(&self.tenants), self.cadence.tiering, stop.clone());
            tasks.push(tokio::spawn(async move {
                tiering_loop(&pool, tenants.as_ref(), &store, cadence, &stop).await;
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

/// How long a version may wait for an antivirus verdict before the loop starts saying so.
///
/// Not a timeout and not a policy: nothing changes when it elapses, and a version over it is exactly
/// as unreadable as one under it. It is the threshold at which "the queue is draining" stops being a
/// plausible reading of the same numbers, and the point of having it at all is `ENC-641` — a
/// permanently stuck `PENDING` with nothing reporting it is how that defect survived four
/// milestones. An hour is far longer than a scan and far shorter than a working day.
const STUCK_AFTER: chrono::Duration = chrono::Duration::hours(1);

/// Scans each tenant's unverdicted versions, and goes straight round again while verdicts are landing.
///
/// **Only a row that moved counts as progress**, which is [`av_progressed`] and is load-bearing in
/// the same way deferral is for [`indexing_loop`]. The queue is a query with no claim column, so a
/// version that produced no *new* verdict stays in it: a `HOLD` while the engine is down, and — under
/// the `SKIPPED` rescan sweep — an encrypted archive the engine still cannot open. Counting either as
/// progress would make the loop re-select the same batch immediately and re-send it to the engine at
/// the speed of the network, forever. Idling instead makes the re-attempt one bounded try per
/// interval, which is what makes it *useful*: it is how a corpus skipped by `antivirus.provider:
/// none` becomes scanned the day an engine is configured.
///
/// Every write moves a version towards a state the queue no longer offers, or towards one where the
/// next verdict is identical and therefore writes nothing — so "progress" cannot loop.
async fn antivirus_loop(
    tenants: &dyn TenantSource,
    runner: &dyn AvRunner,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(ANTIVIRUS, idle, stop, move || async move {
        let Some(tenants) = tenants_for(ANTIVIRUS, tenants).await else { return Tick::Idle };

        let mut progressed = false;
        for tenant in tenants {
            if stop.is_stopped() {
                break;
            }
            match runner.run(tenant, stop).await {
                Ok(pass) => {
                    report(tenant, &pass);
                    progressed |= av_progressed(&pass);
                }
                // Per tenant, and the loop continues: one tenant whose bucket is unreachable must
                // not leave every other tenant's uploads permanently unreadable.
                Err(error) => {
                    warn!(pass = ANTIVIRUS, tenant = %tenant, %error, "the antivirus pass failed");
                }
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

/// Says out loud what a pass found, when what it found is that content is not becoming readable.
///
/// Two different signals, deliberately not merged. **`held`** is this tick: versions the engine would
/// not give a verdict for, which is what an outage looks like as it starts. **The backlog** is
/// cumulative: how long the oldest version still waiting has been waiting, which is what an outage
/// nobody noticed looks like a day later — and it is the reading that would have made `ENC-641`
/// visible, because with no pass at all every version's wait grows without bound.
///
/// `warn!` rather than a gauge, and that is a stated limitation rather than a preference: metrics for
/// the content passes are `ENC-637` and `ENC-648`, and neither is this task's. A log line is what
/// ships today.
fn report(tenant: TenantId, pass: &AvPass) {
    if pass.held > 0 {
        warn!(
            pass = ANTIVIRUS,
            tenant = %tenant,
            held = pass.held,
            considered = pass.considered,
            "antivirus reached no verdict for these versions; they stay unreadable and will be \
             retried. A `held` count that does not fall is an engine that is not answering."
        );
    }

    if let Some(backlog) = pass.backlog(Utc::now()) {
        if backlog > STUCK_AFTER {
            warn!(
                pass = ANTIVIRUS,
                tenant = %tenant,
                waiting_hours = backlog.num_hours(),
                "the oldest version waiting for an antivirus verdict has been waiting for hours; \
                 nothing this tenant has uploaded since then is readable, previewable, searchable \
                 or scannable for DLP"
            );
        }
    }
}

/// Whether an antivirus pass did anything a second tick could build on.
///
/// A named function for the reason [`made_progress`] is one: so the rule can be asserted directly
/// rather than restated by a test that then agrees with a broken loop.
///
/// Rows written, and nothing else. A version re-confirmed unscannable is counted in
/// `AvPass::quarantined` and changed nothing — see [`antivirus_loop`].
const fn av_progressed(pass: &AvPass) -> bool {
    pass.written > 0
}

/// Scans each tenant in turn, and goes straight round again while facts are being written.
///
/// **Only a recorded fact counts as progress**, and that is load-bearing in the same way deferral
/// is for [`indexing_loop`], for the opposite reason. The scan queue is a query with no claim
/// column, so a version that *cannot* be scanned never leaves it (`crate::scan::ScanCursor`).
/// Counting an unscannable version as progress would make a tick that reached the end of a sweep
/// reset the cursor and immediately re-select the same documents, at the speed of extraction — a
/// worker that re-parses a corpus of encrypted archives forever. Idling instead turns that into one
/// bounded re-attempt per interval, which is what makes the re-attempt *useful*: it is how a
/// document becomes scanned the day OCR is mounted.
async fn scanning_loop(
    tenants: &dyn TenantSource,
    runner: &dyn ScanRunner,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(SCANNING, idle, stop, move || async move {
        let Some(tenants) = tenants_for(SCANNING, tenants).await else { return Tick::Idle };

        let mut progressed = false;
        for tenant in tenants {
            if stop.is_stopped() {
                break;
            }
            match runner.run(tenant, stop).await {
                Ok(pass) => progressed |= scan_progressed(&pass),
                // Per tenant, and the loop continues: one tenant whose bucket is unreachable must
                // not leave every other tenant's content unscanned.
                Err(error) => {
                    warn!(pass = SCANNING, tenant = %tenant, %error, "content scan failed");
                }
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

/// Whether a scan pass did anything a second tick could build on.
///
/// A named function for the reason [`made_progress`] is one: so the rule can be asserted directly
/// rather than restated by a test that then agrees with a broken loop.
///
/// Facts written, and nothing else. `ScanPass::unscannable` is deliberately excluded — see
/// [`scanning_loop`].
const fn scan_progressed(pass: &ScanPass) -> bool {
    pass.scanned > 0
}

/// Releases each tenant's unreferenced staged bytes, and goes round again while batches come back
/// full — `ENC-806`.
///
/// **Only a full batch that released something is progress**, which is
/// [`released_a_full_batch`] and is load-bearing in the same way deferral is for
/// [`indexing_loop`]. A session the store refused to delete is left claimable on purpose, so a full
/// batch that deferred every one of them still matches the same predicate next tick: counting it as
/// progress would turn an object-store outage into a loop re-issuing the same hundred deletes at
/// the speed of the network. Idling makes the retry one bounded attempt per interval.
///
/// A tenant is reported only when it did something or deferred something. A quiet sweep over a
/// healthy deployment is every tenant finding nothing, every ten minutes, and a line per tenant per
/// tick is a log nobody reads — which is the state in which the *interesting* line goes unnoticed.
async fn uploads_loop(
    tenants: &dyn TenantSource,
    runner: &dyn ReaperRunner,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(UPLOADS, idle, stop, move || async move {
        let Some(tenants) = tenants_for(UPLOADS, tenants).await else { return Tick::Idle };

        let mut progressed = false;
        for tenant in tenants {
            if stop.is_stopped() {
                break;
            }
            match runner.run(tenant).await {
                Ok(pass) => {
                    report_reaped(tenant, &pass);
                    progressed |= released_a_full_batch(&pass);
                }
                // Per tenant, and the loop continues: one tenant whose bucket is unreachable must
                // not leave every other tenant's abandoned uploads holding their bytes.
                Err(error) => {
                    warn!(pass = UPLOADS, tenant = %tenant, %error, "the upload reaper failed");
                }
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

/// Says out loud what a reaping tick released, when it released or refused anything.
///
/// `info!` for a release and `warn!` for a deferral, and the split is the point: bytes going is
/// routine and bytes *refusing* to go is a store an operator has to look at. A `deferred` count that
/// stays high across ticks is the signal (`ReapReport::deferred`).
///
/// Silent when a tenant had nothing, which is the steady state — see [`uploads_loop`].
fn report_reaped(tenant: TenantId, pass: &ReapPass) {
    if pass.released() > 0 {
        info!(
            pass = UPLOADS,
            tenant = %tenant,
            expired = pass.expired.released,
            stranded = pass.stranded.reclaimed,
            "released the staged bytes of upload sessions nothing will read"
        );
    }

    if pass.deferred() > 0 {
        warn!(
            pass = UPLOADS,
            tenant = %tenant,
            deferred = pass.deferred(),
            "some staged objects could not be released; they keep their rows and are retried. A \
             deferred count that does not fall is an object store refusing deletes."
        );
    }

    // Separate from the two above, and never merged into them. Since `ENC-691` a version commits in
    // the same transaction that writes `SCANNING`, so a *new* strand is unrepresentable and this
    // number should drain a historical backlog to zero and stay there. One that keeps moving is a
    // second completion path somewhere that does not commit its version with its state.
    if pass.stranded.found > 0 {
        warn!(
            pass = UPLOADS,
            tenant = %tenant,
            found = pass.stranded.found,
            "sessions were stranded in SCANNING with no version behind them (ENC-787). Since \
             ENC-691 this is a historical backlog; a count that keeps growing is a completion path \
             that does not commit its version in the same transaction as its state."
        );
    }
}

/// Resolves versions the store has finished moving, on a fixed cadence (`ENC-947`).
///
/// [`Tick::Worked`] when a full batch came back, so the loop comes straight round rather than
/// waiting a minute per thirty-two rows — the case that matters is a deployment whose lifecycle
/// rule has just moved a lot of objects at once, and a fixed idle would drain it at half a row a
/// second.
async fn tiering_loop(
    pool: &DbPool,
    tenants: &dyn TenantSource,
    store: &Arc<dyn enclave_storage::BlobStore>,
    idle: Duration,
    stop: &Stop,
) {
    run_loop(TIERING, idle, stop, move || async move {
        let Some(tenants) = tenants_for(TIERING, tenants).await else { return Tick::Idle };
        match tiering::sweep(pool, store, &tenants, stop).await {
            Ok(outcome) => {
                // At `debug` when nothing moved and `info` when something did. A restore completing
                // is the end of a wait somebody started hours ago, and it is the one event in this
                // pass an operator asked about.
                if outcome.resolved > 0 || outcome.drifted > 0 {
                    // `drifted` at `info` beside `resolved`, because they are different events an
                    // operator reads differently: a resolved transition is a wait ending, and drift
                    // is a bucket lifecycle rule this product is chasing (`ENC-951`).
                    info!(
                        pass = TIERING,
                        resolved = outcome.resolved,
                        drifted = outcome.drifted,
                        verified = outcome.verified,
                        waiting = outcome.still_waiting,
                        "storage tiers reconciled"
                    );
                } else {
                    debug!(
                        pass = TIERING,
                        waiting = outcome.still_waiting,
                        verified = outcome.verified,
                        unanswerable = outcome.unanswerable,
                        "nothing to reconcile"
                    );
                }
                if outcome.more_to_take {
                    return Tick::Progressed;
                }
            }
            Err(error) => warn!(pass = TIERING, %error, "tier reconciliation failed"),
        }
        Tick::Idle
    })
    .await;
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

/// Deletes dead print capabilities on a fixed cadence.
///
/// Unlike [`invalidation_loop`] and [`epoch_loop`] this one can report [`Tick::Progressed`], and the
/// condition is a *full batch* rather than any deletion at all: a pass that took three rows has
/// finished the work there was, and coming straight round would spend a round trip per tenant to
/// find nothing. A tenant that filled its batch has more, and draining it at the speed of the
/// database beats draining it at the speed of [`Cadence::print_tokens`].
///
/// A failure warns and idles rather than propagating: one tenant's sweep failing must not stop
/// every other tenant's table from being swept, and there is nothing to escalate — an unswept row
/// is refused by the redemption exactly as a swept one is.
async fn print_tokens_loop(pool: &DbPool, tenants: &dyn TenantSource, idle: Duration, stop: &Stop) {
    run_loop(PRINT_TOKENS, idle, stop, move || async move {
        let Some(tenants) = tenants_for(PRINT_TOKENS, tenants).await else { return Tick::Idle };
        match print_tokens::sweep(pool, &tenants, stop).await {
            Ok(outcome) => {
                debug!(pass = PRINT_TOKENS, reaped = outcome.reaped, "swept");
                if outcome.more_to_take {
                    return Tick::Progressed;
                }
            }
            Err(error) => warn!(pass = PRINT_TOKENS, %error, "the print-token sweep failed"),
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
        assert_eq!(bare.scheduled(), vec![INVALIDATION, EPOCH, PRINT_TOKENS]);

        let with_indexing = Scheduler::new(tenants.clone()).with_indexing(RecordingRunner::new(
            Stop::new(),
            usize::MAX,
            indexed_one(),
        ));
        assert_eq!(with_indexing.scheduled(), vec![INDEXING, INVALIDATION, EPOCH, PRINT_TOKENS]);

        let with_coverage = Scheduler::new(tenants)
            .with_coverage(Arc::new(SilentCensus), CoverageFloor::percent(80));
        assert_eq!(with_coverage.scheduled(), vec![INVALIDATION, EPOCH, PRINT_TOKENS, COVERAGE]);
    }

    /// The tier reconciler is scheduled with a store and absent without one (`ENC-947`).
    ///
    /// Its own test rather than a line in the one above, because the **absence** is what has to be
    /// asserted and it is the half that is easy to get backwards. A reconciler scheduled against no
    /// store would call `observed_tier` on `UnconfiguredBlobStore`, get `Unsupported` for every
    /// row, and count it as `unanswerable` for ever — a pass that runs, logs, and resolves nothing,
    /// which is indistinguishable in every dashboard from one that has nothing to do.
    ///
    /// And the presence half matters for a different reason: without this pass a version marked
    /// `RESTORING` never leaves that state, so `POST /files/{id}/rehydrate` accepts a request and
    /// never completes it.
    #[test]
    fn the_tier_reconciler_is_scheduled_only_where_there_is_a_store_to_ask() {
        let tenants = FixedTenants::of(1);

        let bare = Scheduler::new(tenants.clone());
        assert!(
            !bare.scheduled().contains(&TIERING),
            "a deployment with no object storage has no store to ask where an object is, and a \
             reconciler pointed at nothing resolves every row as unanswerable for ever"
        );

        let with_store = Scheduler::new(tenants)
            .with_tier_reconciler(Arc::new(enclave_storage::UnconfiguredBlobStore));
        assert!(
            with_store.scheduled().contains(&TIERING),
            "with a store composed the reconciler must run: without it a RESTORING row is \
             permanent and every rehydrate is a request that is accepted and never completes"
        );
    }

    /// The three housekeeping passes are not optional, because none has a dependency that could be
    /// missing: all three are PostgreSQL and nothing else.
    ///
    ///  is the newest and the one most likely to be made conditional by mistake, since
    /// the pass it sits beside in  —  — *is* conditional. It must not be:
    /// is written by every deployment that can mint a grant, and a deployment with no object storage
    /// still mints them ().
    #[test]
    fn the_postgresql_only_passes_are_always_scheduled() {
        let scheduler = Scheduler::new(FixedTenants::of(1));
        for pass in [INVALIDATION, EPOCH, PRINT_TOKENS] {
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

    /// An antivirus runner that answers a fixed pass and stops the world after `stop_after` calls.
    #[derive(Debug)]
    struct FixedAv {
        seen: std::sync::Mutex<Vec<TenantId>>,
        stop_after: usize,
        outcome: AvPass,
        stop: Stop,
    }

    impl FixedAv {
        fn new(stop: Stop, stop_after: usize, outcome: AvPass) -> Arc<Self> {
            Arc::new(Self { seen: std::sync::Mutex::new(Vec::new()), stop_after, outcome, stop })
        }

        fn seen(&self) -> Vec<TenantId> {
            self.seen.lock().expect("the recorder was not poisoned").clone()
        }
    }

    #[async_trait]
    impl AvRunner for FixedAv {
        async fn run(&self, tenant: TenantId, _stop: &Stop) -> Result<AvPass> {
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

    fn cleared_one() -> AvPass {
        AvPass { considered: 1, cleared: 1, written: 1, ..AvPass::default() }
    }

    /// The antivirus pass is scheduled when it is wired, and named first because it is first.
    ///
    /// Both halves, and the negative one is the reason the row exists: a deployment with no object
    /// storage must not have this pass scheduled and failing, and it must be able to *tell* — every
    /// version staying `SCANNING` looks identical to a running scanner with nothing to do, which is
    /// exactly how `ENC-641` survived.
    #[test]
    fn the_antivirus_pass_is_absent_until_it_is_wired_and_is_named_first_when_it_is() {
        let tenants = FixedTenants::of(1);

        let bare = Scheduler::new(tenants.clone());
        assert!(!bare.scheduled().contains(&ANTIVIRUS), "{:?}", bare.scheduled());

        let wired = Scheduler::new(tenants).with_antivirus(FixedAv::new(
            Stop::new(),
            usize::MAX,
            cleared_one(),
        ));
        assert_eq!(wired.scheduled(), vec![ANTIVIRUS, INVALIDATION, EPOCH, PRINT_TOKENS]);
    }

    /// The loop visits every tenant, once per tick.
    ///
    /// The interval is an hour and is never waited on: the runner raises the signal on the last
    /// tenant of the first sweep, so a regression that enumerated nothing, or that visited only the
    /// first tenant, fails on the recorded list rather than on a stopwatch.
    #[tokio::test]
    async fn the_antivirus_loop_visits_every_tenant() {
        let stop = Stop::new();
        let tenants = FixedTenants::of(3);
        let runner = FixedAv::new(stop.clone(), 3, cleared_one());

        antivirus_loop(tenants.as_ref(), runner.as_ref(), Duration::from_secs(3600), &stop).await;

        assert_eq!(runner.seen(), tenants.tenants, "every tenant, in the source's order, once");
    }

    /// A tick that reached no *new* verdict is idle, so the loop waits rather than re-sending the
    /// same objects to the engine.
    ///
    /// Both directions, against the rule the loop actually applies. The two idle cases are the ones
    /// that matter and they are different states: `held` is an engine that is down, and
    /// `quarantined` with nothing written is the `SKIPPED` rescan re-confirming an archive it still
    /// cannot open. Counting either as progress is a loop that re-scans a corpus at the speed of the
    /// network for as long as the condition lasts.
    #[test]
    fn only_a_verdict_that_moved_a_row_is_progress() {
        assert!(av_progressed(&cleared_one()));
        assert!(av_progressed(&AvPass {
            considered: 1,
            quarantined: 1,
            written: 1,
            ..AvPass::default()
        }));
        assert!(
            !av_progressed(&AvPass { considered: 1, held: 1, ..AvPass::default() }),
            "an engine that is down would spin the loop"
        );
        assert!(
            !av_progressed(&AvPass { considered: 1, quarantined: 1, ..AvPass::default() }),
            "a re-confirmed unscannable version changed nothing, so a second tick finds it again"
        );
        assert!(!av_progressed(&AvPass::default()), "an empty queue is idle");
    }

    /// A reaper that records the tenants it was asked about and stops the loop after `stop_after`.
    #[derive(Debug)]
    struct FixedReaper {
        seen: std::sync::Mutex<Vec<TenantId>>,
        stop: Stop,
        stop_after: usize,
        outcome: ReapPass,
    }

    impl FixedReaper {
        fn new(stop: Stop, stop_after: usize, outcome: ReapPass) -> Arc<Self> {
            Arc::new(Self { seen: std::sync::Mutex::new(Vec::new()), stop, stop_after, outcome })
        }

        fn seen(&self) -> Vec<TenantId> {
            self.seen.lock().expect("the recorder was not poisoned").clone()
        }
    }

    #[async_trait]
    impl ReaperRunner for FixedReaper {
        async fn run(&self, tenant: TenantId) -> Result<ReapPass> {
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

    fn released_one() -> ReapPass {
        ReapPass {
            expired: enclave_uploads::ReapReport { claimed: 1, released: 1, deferred: 0 },
            stranded: enclave_uploads::ReclaimReport::default(),
            batch: 100,
        }
    }

    /// The upload reaper is scheduled when it is wired, and absent — visibly — when it is not.
    ///
    /// Both halves, and the negative one is the whole of `ENC-806`. For five milestones this pass
    /// existed, was tested, and was called by nothing; a deployment with a growing bucket of
    /// abandoned uploads and a deployment with none looked identical from outside the process,
    /// because there was no line anywhere saying whether anything was reaping. `scheduled()` is that
    /// line, so the assertion that the name appears when the runner is present is as load-bearing as
    /// the one that it does not appear when the store is absent.
    #[test]
    fn the_upload_reaper_is_absent_until_it_is_wired_and_is_named_when_it_is() {
        let tenants = FixedTenants::of(1);

        let bare = Scheduler::new(tenants.clone());
        assert!(
            !bare.scheduled().contains(&UPLOADS),
            "a deployment with no object store must not have a delete pass scheduled: {:?}",
            bare.scheduled()
        );

        let wired = Scheduler::new(tenants).with_upload_reaper(FixedReaper::new(
            Stop::new(),
            usize::MAX,
            released_one(),
        ));
        assert_eq!(wired.scheduled(), vec![INVALIDATION, EPOCH, PRINT_TOKENS, UPLOADS]);
    }

    /// The loop visits every tenant, once per tick.
    ///
    /// The interval is an hour and is never waited on: the runner raises the signal on the last
    /// tenant of the first sweep, so a regression that enumerated nothing, or that swept only the
    /// first tenant, fails on the recorded list rather than on a stopwatch. That failure mode is not
    /// hypothetical here — a reaper that visited one tenant would leave every other tenant's staged
    /// bytes exactly as unreleased as no reaper at all, which is the state this row is about.
    #[tokio::test]
    async fn the_upload_reaper_loop_visits_every_tenant() {
        let stop = Stop::new();
        let tenants = FixedTenants::of(3);
        let runner = FixedReaper::new(stop.clone(), 3, released_one());

        uploads_loop(tenants.as_ref(), runner.as_ref(), Duration::from_secs(3600), &stop).await;

        assert_eq!(runner.seen(), tenants.tenants, "every tenant, in the source's order, once");
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
