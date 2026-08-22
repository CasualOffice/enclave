//! `enclave-worker` — the process that runs the housekeeping.
//!
//! Composition only, in the same shape as `crates/api/src/main.rs`: load configuration, resolve
//! secrets at the last moment, connect the pool, apply migrations, decide which implementations
//! exist, hand them to something that does the work. Every decision here is *which implementation*,
//! never what a pass may do.
//!
//! # What this process is not
//!
//! It is not a request path, so it holds no `PolicyEngine` and enforces no policy chain. That is not
//! an exemption from `CLAUDE.md` rule 1 — there is no caller to authorize. The two rules that do
//! apply to a background reader of content apply through the passes rather than through this file:
//! every statement runs inside `DbPool::begin`, so row-level security has a tenant (rule 4), and the
//! indexing pass reads a version's bytes through `enclave_preview::repo::readable_version`, which
//! answers `None` for anything that is not `AVAILABLE` and `CLEAN` (rule 9).
//!
//! The one thing it does hold that the API does not is a `BYPASSRLS` pool, for one query: the tenant
//! list. See [`enclave_db::active_tenants`] and `crates/worker/src/schedule.rs` for why that is
//! unavoidable, why it is one function, and why it lives in `enclave-db`.
//!
//! # Why it refuses to start without one
//!
//! Every pass takes tenants as a parameter. With no platform credential there is no list, so there
//! is nothing to pass and the process would run four loops that each enumerate nothing — a worker
//! that idles at 100% health while a backlog builds. `DbPool::has_platform_access` exists for
//! exactly this refusal, and the alternative is discovering it on the first tick, in a log line
//! nobody is watching at deploy time.
//!
//! # Which passes run, and what an unconfigured one costs
//!
//! All of them are wired, and three are wired to sections an operator may leave out.
//! `storage.provider: none` means no [`object_store`] and therefore none of the three content
//! passes; `search.provider: none` means no [`index_census`] and therefore no coverage probe.
//! `ENC-562` and `ENC-563` closed the gap that used to make both unconditional.
//!
//! The one whose absence is not a degradation is antivirus (`ENC-641`). It is what moves a version
//! from `SCANNING` / `PENDING` to `AVAILABLE` / `CLEAN`, and it is the only thing that does, so a
//! deployment without it has no readable content at all rather than unsearchable content. That is
//! why the missing-storage branch below logs at `error!` rather than `warn!`, and why
//! [`antivirus_scanner`] refuses to start for a provider it cannot honour instead of quietly
//! scanning nothing.
//!
//! Neither is faked. A pass whose dependency is missing is **not scheduled** — see
//! `crates/worker/src/schedule.rs` for why an indexing pass pointed at a store that cannot answer is
//! worse than no indexing pass at all — and `Scheduler::scheduled` is logged at start-up so the
//! absence is a line an operator reads rather than a graph that never leaves zero.
//!
//! A section that *is* written and cannot be honoured is the other case entirely, and the two are
//! treated differently on purpose: an unreachable bucket refuses this start-up ([`object_store`]),
//! while an unreachable Milvus does not ([`index_census`]). Each function argues its own side.

use std::sync::Arc;

use anyhow::Context as _;
use enclave_antivirus::ScanPolicy;
use enclave_indexing::{
    BoundedExtractor, ChunkBudget, Chunker, ChunkerVersion, ExtractorVersion, MediaTypeRouter,
    PdfTextExtractor, PlainTextExtractor,
};
use enclave_preview::RenderBudget;
use enclave_search::health::{CoverageFloor, IndexCensus};
use enclave_storage::S3BlobStore;
use enclave_worker::ocr::MountedOcr;
use enclave_worker::schedule::{
    AvRunner, ContentScanner, IndexRunner, PipelineRunner, ScanRunner, Scheduler, VersionScanner,
};
use enclave_worker::tenants::DbTenants;
use enclave_worker::Stop;

/// How the chunker this build ships is versioned, and how many files one claim takes.
///
/// Constants rather than configuration because both are properties of the code: a chunker version
/// assembled from a runtime value differs between two replicas of the same deployment and the
/// reindex it triggers never converges (`enclave_indexing::ChunkerVersion`), and a batch size is a
/// pacing number with no correctness content, exactly as `ReconcilerConfig::batch_size` is.
const CHUNKER: ChunkerVersion = ChunkerVersion::new("fixed/1");
/// Files claimed per tenant per indexing tick.
const INDEX_BATCH: i64 = 32;
/// Versions considered per tenant per content-scan tick.
///
/// Smaller than [`INDEX_BATCH`], and the number is the whole of the rescan's rate limit: moving the
/// active detector-set version invalidates *every* fact row in every tenant at once (equality, not
/// an ordering — `ENC-581`), so the backlog after a detector change is the entire corpus. What
/// bounds it is this batch against `Cadence::scan_idle`, per tenant, and nothing else — there is no
/// priority queue and no burst. A rescan is therefore slow by construction, and the versions it has
/// not reached are *unscanned* in the meantime, which is a state both `facts_unavailable` policies
/// already have an answer for.
const SCAN_BATCH: i64 = 16;
/// Versions sent to the antivirus engine per tenant per tick.
///
/// The same size as [`SCAN_BATCH`] and for a related reason, but the backlog it paces is a different
/// one: a fresh upload waits at most one `Cadence::antivirus_idle` for a verdict, so this bounds how
/// many objects one tenant can have in flight to the engine at once — the engine's own concurrency
/// limit is the other half, and a batch larger than clamd's `MaxThreads` only queues inside clamd.
/// It also paces the `SKIPPED` rescan sweep, which after configuring an engine on a deployment that
/// ran `antivirus.provider: none` is the tenant's entire corpus.
const AV_BATCH: i64 = 16;
/// The share of PostgreSQL's expectation a tenant's store must hold to count as stocked.
const COVERAGE_FLOOR: u32 = 90;

/// The two pacing constants, checked at compile time rather than by a test.
///
/// Both are the same class of mistake — a pacing number that silently disables the thing it paces —
/// and neither is caught anywhere else: `index_pass` with `batch = 0` returns a perfectly successful
/// pass that did nothing, and `CoverageFloor::percent(0)` reports every tenant `Stocked`, including
/// one whose collection was wiped. A `const` block because these are compile-time values: the guard
/// belongs where the mistake would be made, and a build failure is louder than a test.
const _PACING_IS_NOT_ZERO: () = {
    assert!(INDEX_BATCH > 0, "a batch of zero claims no files and reports success");
    assert!(SCAN_BATCH > 0, "a batch of zero scans nothing and leaves every version unscanned");
    assert!(AV_BATCH > 0, "a batch of zero moves no av_status, so nothing ever becomes readable");
    assert!(COVERAGE_FLOOR > 0, "a floor of zero calls an empty index stocked");
    assert!(COVERAGE_FLOOR <= 100, "a floor above 100 is unsatisfiable");
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let loaded = enclave_config::ConfigLoader::new()
        .with_file("enclave.yaml")
        .load()
        .context("load configuration")?;
    let config = loaded.config();

    enclave_observability::init(&Default::default()).context("initialise tracing")?;

    // Secrets are references in configuration and values only here, at the last moment
    // (`docs/08-BYO-INFRA.md §6`), exactly as in the API binary.
    let registry = enclave_config::SecretRegistry::local();
    let secrets = loaded.resolve_secrets(&registry).await.context("resolve secrets")?;

    let db_config = db_config_from(config, &secrets)?;
    let db = enclave_db::DbPool::connect(&db_config).await.context("connect to PostgreSQL")?;

    // Before migrations, not after, so that a deployment missing the credential gets the refusal
    // that names what to set rather than the migration runner's report that it had nothing to fall
    // back to. Both are true; only one of them says what to do about it.
    anyhow::ensure!(
        db.has_platform_access(),
        "the worker needs `database.platform_url` — the DSN of the BYPASSRLS role — because the \
         query that produces a tenant list cannot itself be scoped to a tenant, and every pass here \
         takes that list as a parameter. Without it this process would run four loops over nothing \
         while reporting healthy. See migrations/0002_rls_policies.sql, which has been granting \
         `SELECT ON tenants TO enclave_platform` for the enumerator since M0."
    );

    // As the API binary does. `sqlx` records applied versions and takes an advisory lock, so the
    // API and the worker racing during a rolling deploy serialise rather than conflict — and
    // `docs/11-OPERATIONS.md §3` puts the expand phase before either of them in any case.
    enclave_db::run_migrations(&db_config).await.context("apply migrations")?;

    // The metrics listener, if one is configured, on its own socket — `ENC-548`. Spawned before the
    // passes so that a scrape arriving during start-up gets counters at zero rather than a refused
    // connection, which are different readings (`crates/observability/src/metrics.rs`).
    //
    // `metrics.worker_port`, and the API takes `metrics.api_port`. They used to be one key, so on a
    // host running both from one file whichever started second died right here with `Address
    // already in use` (`ENC-566`).
    let stop = Stop::new();
    if let Some(addr) = config.metrics.worker_addr() {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind metrics listener on {addr}"))?;
        tracing::info!(%addr, "metrics listening");
        let shutdown = stop.clone();
        tokio::spawn(enclave_observability::exposition::serve(listener, async move {
            shutdown.stopped().await;
        }));
    } else {
        tracing::warn!(
            "metrics.worker_port is unset, so this worker serves no exposition. The coverage \
             probe's gauges are process-wide and are published here; with no socket they reach \
             nobody and `SearchIndexCoverageUnreported` cannot clear (docs/11-OPERATIONS.md §5.7 \
             step 5)."
        );
    }

    let mut scheduler = Scheduler::new(Arc::new(DbTenants::new(db.clone())));
    if let Some(passes) = content_passes(config, &registry, db.clone()).await? {
        scheduler = scheduler
            .with_antivirus(passes.antivirus)
            .with_indexing(passes.indexing)
            .with_scanning(passes.scanning);
    }
    if let Some(census) = index_census(config, &secrets)? {
        scheduler = scheduler.with_coverage(census, CoverageFloor::percent(COVERAGE_FLOOR));
    }

    // Loud, once, at start-up, and the same treatment `crates/api/src/main.rs` gives its policy
    // stages: a worker running two of four passes looks identical from the outside to one running
    // all four over an empty queue, and the difference matters enormously.
    tracing::info!(passes = ?scheduler.scheduled(), "enclave-worker starting");

    let signals = {
        let stop = stop.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received; finishing the current unit of work");
            stop.stop();
        })
    };

    scheduler.run(&db, stop).await;

    // Nothing is waiting on the handler any more; leaving it registered would keep a task alive
    // holding a signal stream after the process has decided to exit.
    signals.abort();

    // After every loop has returned, never before. `DbPool::close` waits for checked-out
    // connections, and the loops only return between transactions, so by here there are none.
    db.close().await;
    tracing::info!("enclave-worker stopped");
    Ok(())
}

/// The two passes that read a version's content, built over one extractor and one OCR stage.
///
/// Present or absent together, because they have the same dependency — object storage — and
/// because the point of `ENC-613` is that they extract the *same* text. See
/// [`content_passes`] for why they are constructed in one place.
struct ContentPasses {
    /// An antivirus verdict onto `file_versions.av_status`, and the version into `AVAILABLE`
    /// (`ENC-641`). Upstream of the other two: neither sees anything until this has run.
    antivirus: Arc<dyn AvRunner>,
    /// Text into `chunk_text` and a manifest (`ENC-527`).
    indexing: Arc<dyn IndexRunner>,
    /// Detector counts into `security_facts` (`ENC-613`).
    scanning: Arc<dyn ScanRunner>,
}

/// The content passes' wiring, or `None` when this deployment configured no object storage.
///
/// # Why one function builds both
///
/// They share the extractor and the OCR stage, and *sharing* is the requirement rather than a
/// saving. A media type registered for indexing and not for scanning is a document that is
/// searchable and permanently unscanned, with nothing reporting it — so the router is built once
/// here, wrapped in one [`BoundedExtractor`], and handed to both as an `Arc`. `PdfiumLibrary` is a
/// process singleton besides, whose `DOCUMENTS` lock is per-library (`ENC-551`), so two OCR stages
/// would be two locks and no lock at all.
///
/// # Why `None` rather than [`UnconfiguredBlobStore`](enclave_storage::UnconfiguredBlobStore)
///
/// Because the two are not the same absence. Handing the pass a store that refuses every read still
/// runs the pass: [`claim`](enclave_indexing::claim) commits before the first byte is read, so every
/// tick would move a batch of manifests into a working state and increment `attempts` on each — the
/// budget that quarantines a genuinely poisoned document — and then fail. A deployment whose only
/// problem was a missing bucket would end up with a corpus of files nothing will retry.
///
/// The scan pass has no claim to burn, so its absence costs something different and is worth
/// stating: with nothing writing `security_facts`, every version is *unscanned*, which the tenant's
/// `dlp.facts_unavailable` policy then decides the meaning of — refused under `FAIL_CLOSED`,
/// permitted with a high-visibility audit event under `FAIL_OPEN_AUDIT`. Safe in both directions,
/// and announced by `Scheduler::scheduled` rather than inferred from a table that stays empty.
///
/// # Errors
///
/// A configured-but-unloadable OCR mount, from [`MountedOcr::from_config`]. That is an outage and is
/// reported as one; see that function for why it must never read as "no OCR". Also a `storage:`
/// section that names a bucket this process cannot reach — see [`object_store`] for why that is an
/// error rather than a `None`.
async fn content_passes(
    config: &enclave_config::Config,
    registry: &enclave_config::SecretRegistry,
    pool: enclave_db::DbPool,
) -> anyhow::Result<Option<ContentPasses>> {
    // Before the store, so that a provider this build cannot honour refuses the start-up whatever
    // else is configured. An operator who wrote `provider: icap` and silently got no scanning is
    // the worst outcome available on this path, and it looks correct in every dashboard.
    let scanner = antivirus_scanner(config)?;

    let Some(store) = object_store(config, registry).await? else {
        tracing::error!(
            "no object storage is configured (`storage.provider` is `none`), so none of the three \
             content passes is scheduled. The consequence is not degraded search: **nothing will \
             move `file_versions.av_status`**, so no version ever becomes AVAILABLE/CLEAN, no read \
             path serves anything, `chunk_text` stays empty and `security_facts` stays empty. See \
             crates/worker/src/main.rs::object_store and docs/08-BYO-INFRA.md §15."
        );
        return Ok(None);
    };
    let store = Arc::new(store);

    // `engine_info` rather than a claim about the configured provider: it is the engine itself
    // saying whether it inspects content, and `NoScanningPerformed` answers `false`. Failing to
    // answer is not fatal — an unreachable clamd holds every version in SCANNING under the default
    // policy, which is correct, and refusing to start would take indexing down with it.
    match scanner.engine_info().await {
        Ok(info) if info.scans_content => tracing::info!(
            engine = %info.engine,
            signatures = info.signature_version.as_deref().unwrap_or("unknown"),
            "antivirus is enabled; uploads become readable once this engine clears them"
        ),
        Ok(info) => tracing::error!(
            engine = %info.engine,
            unsupported_policy = "BLOCK",
            "the configured antivirus provider does NOT inspect content. Every version will be \
             recorded SKIPPED and QUARANTINED under the BLOCK policy, so nothing uploaded to this \
             deployment will be readable. Configure `antivirus.provider: clamav`; the versions \
             skipped in the meantime are re-offered automatically once a scanning engine answers."
        ),
        Err(error) => tracing::warn!(
            %error,
            unavailable_policy = ?config.antivirus.unavailable_policy,
            "the antivirus engine could not be identified at start-up. Versions will follow \
             `antivirus.unavailable_policy` until it answers; under the default HOLD they wait in \
             SCANNING and are unreadable."
        ),
    }

    let chunker = Chunker::new(CHUNKER, ChunkBudget::default());
    let ocr = MountedOcr::from_config(config, chunker, RenderBudget::DEFAULT)
        .context("build the OCR stage from the mounted volumes")?
        .map(Arc::new);
    if ocr.is_none() {
        // Not a degradation — see `crates/worker/src/ocr.rs`. A scanned PDF becomes a `FAILED`
        // manifest with `no_text_extracted`, which is a file visibly unsearchable rather than
        // invisibly empty. Logged so an operator who *did* mean to mount the volumes finds out now.
        tracing::info!("no OCR volumes are mounted; scanned documents will record FAILED");
    }

    // The routing table this deployment runs, and the marker recorded for everything it indexes.
    //
    // `ENC-552`: the marker is a literal here, and `MediaTypeRouter` refuses any registration whose
    // own version has a `+`-component this string does not name. So bumping `pdf-text/1` without
    // bumping the marker `docs/07 §3` compares does not silently stop triggering a reindex — the
    // process refuses to start.
    //
    // PDF is registered only when PDFium is mounted. Registering it unconditionally would make a
    // deployment that never wanted PDF fail to start for want of a volume, and the alternative —
    // registering it and letting extraction fail — is D24's failure: every PDF a `FAILED` manifest
    // for a reason that is the deployment's, not the document's.
    let mut router = MediaTypeRouter::new(ExtractorVersion::new(ROUTER))
        .route(TEXT_TYPES, Arc::new(PlainTextExtractor))
        .context("register the plain-text extractor")?;

    if let Some(stage) = ocr.as_ref() {
        router = router
            .route(&["application/pdf"], Arc::new(PdfTextExtractor::new(stage.library())))
            .context("register the PDF text extractor")?;
        tracing::info!("PDF text extraction is enabled (PDFium is mounted)");
    } else {
        tracing::info!(
            "PDFium is not mounted, so `application/pdf` is routed nowhere and PDFs record \
             SKIPPED / unsupported_media_type rather than failing"
        );
    }

    // `BoundedExtractor` — `ENC-570`. The wall clock, the input cap, the output cap and D24's
    // empty-document conversion are applied by this wrapper *from outside* the extractor, and the
    // shipped worker was passing a bare one: every test in `crates/indexing` runs wrapped, which is
    // exactly why nothing caught it. A hostile document reaching this process was parsed under no
    // bound at all.
    //
    // `Arc<dyn Extractor>` and not two constructions: `ENC-613`. Both passes hold this exact
    // instance, so the text the DLP scan reads is the text the index holds, and the bounds above
    // are one set of numbers rather than two that agree until somebody tunes one.
    let extractor: Arc<dyn enclave_indexing::Extractor> = Arc::new(BoundedExtractor::new(router));

    let indexing = Arc::new(PipelineRunner::new(
        pool.clone(),
        Arc::clone(&extractor),
        Chunker::new(CHUNKER, ChunkBudget::default()),
        ocr.clone(),
        Arc::clone(&store),
        // Nothing embeds yet, and `""` is what `BuildVersions` documents as the honest value for
        // that. A model name written here before anything used it would be a claim about a manifest
        // that no embedding produced.
        "",
        RenderBudget::DEFAULT,
        INDEX_BATCH,
    ));

    // The detectors this deployment runs, and the version stamped onto every row they produce.
    // `enclave_dlp::builtin_set()` is the same constructor `crates/api/src/main.rs` reads the
    // active version out of, which is what makes `FactsSnapshot::gathered`'s equality check compare
    // a row against the set that would have produced it rather than against a second opinion.
    let detectors = Arc::new(enclave_dlp::builtin_set());
    tracing::info!(
        detector_set = detectors.version().as_str(),
        detectors = ?detectors.ids().map(|id| id.as_str()).collect::<Vec<_>>(),
        "content scanning is enabled; moving the detector-set version rescans every version"
    );

    let scanning = Arc::new(ContentScanner::new(
        pool.clone(),
        extractor,
        Chunker::new(CHUNKER, ChunkBudget::default()),
        ocr,
        detectors,
        Arc::clone(&store),
        RenderBudget::DEFAULT,
        SCAN_BATCH,
    ));

    let antivirus = Arc::new(VersionScanner::new(
        pool,
        scanner,
        store,
        // One knob from configuration and one deliberately not — see `ScanPolicy::from_config`.
        // `ALLOW_WITH_FLAG` is the setting that would let unscanned content become AVAILABLE, and
        // there is no key for it, so it cannot be reached from a YAML file.
        ScanPolicy::from_config(&config.antivirus),
        AV_BATCH,
    ));

    Ok(Some(ContentPasses { antivirus, indexing, scanning }))
}

/// The scanner this deployment configured, or a refusal to start.
///
/// `crates/antivirus/src/lib.rs` gives this wiring block verbatim and this is the caller it was
/// written for — `ENC-641` is that it never had one.
///
/// **`icap` and `http` refuse the start-up rather than falling through to
/// [`NoScanningPerformed`](enclave_antivirus::NoScanningPerformed).** `docs/08 §9` lists both as
/// providers and neither is implemented; an operator who configured a scanning gateway and silently
/// got no scanning is the worst outcome available here, and it would look correct in every
/// dashboard.
///
/// **`none` gets a real provider rather than no pass**, which is the decision on this path and the
/// one worth reading. `NoScanningPerformed` answers `Unsupported` for every object — never `Clean`,
/// because it did not look — so `decide` sends it down `docs/06 §6.2`'s unsupported-content path and
/// the `BLOCK` policy quarantines it. A tenant that turned antivirus off therefore publishes
/// **nothing**, loudly, instead of accumulating a corpus that silently never becomes readable. Not
/// scheduling the pass at all was the alternative and it is worse in the way that matters: it would
/// make "no antivirus" and "antivirus configured and broken" the same observation, and it would put
/// the decision in this file rather than in `decide`, where every other provider's is.
///
/// It is also recoverable: `crate::antivirus`'s queue re-offers `SKIPPED` versions the moment an
/// engine that actually scans content is configured.
///
/// # Errors
///
/// [`AntivirusError::Configuration`](enclave_antivirus::AntivirusError::Configuration) for a
/// provider with no implementation, and for `clamav` with no `antivirus.endpoint`.
fn antivirus_scanner(
    config: &enclave_config::Config,
) -> anyhow::Result<Arc<dyn enclave_antivirus::AntivirusScanner>> {
    use enclave_config::AntivirusProvider;

    let scanner: Arc<dyn enclave_antivirus::AntivirusScanner> = match config.antivirus.provider {
        AntivirusProvider::Clamav => Arc::new(enclave_antivirus::ClamavScanner::new(
            enclave_antivirus::ClamavConfig::from_config(&config.antivirus)
                .context("build the clamd client from `antivirus:`")?,
        )),
        // Warns once, from its own constructor, that this deployment does not scan.
        AntivirusProvider::None => Arc::new(enclave_antivirus::NoScanningPerformed::new()),
        provider @ (AntivirusProvider::Icap | AntivirusProvider::Http) => {
            anyhow::bail!(
                "antivirus.provider `{provider:?}` is named by docs/08-BYO-INFRA.md §9 and has no \
                 implementation in this build. Refusing to start rather than falling back to no \
                 scanning: set `antivirus.provider: clamav`, or `none` if this deployment really is \
                 to publish nothing until an engine is configured."
            );
        }
    };
    Ok(scanner)
}

/// The routing marker this deployment records for everything it indexes.
///
/// A literal, at the composition root, because `MediaTypeRouter` verifies it rather than composing
/// it — see `crates/indexing/src/route.rs`. Every `+`-component of every registered extractor's own
/// version must appear here, so bumping an extractor without bumping this refuses to start rather
/// than leaving `docs/07 §3`'s reindex trigger comparing an unchanged string.
const ROUTER: &str = "router/1+text/1+pdf-text/1+pdfium-render-0.9.3";

/// The media types the plain-text extractor is registered for.
const TEXT_TYPES: &[&str] = &["text/plain", "text/markdown"];

/// The object store this deployment configured, or `None` when it configured none.
///
/// # Why the public-access self-check runs here
///
/// [`S3BlobStore::connect_and_verify`] rather than `connect`: a bucket that is readable by the
/// world is refused, loudly, at start-up. This process only ever *reads* content, so the check buys
/// nothing for this pass directly — it is run because a worker is very often the first thing
/// deployed against a new bucket, and a public bucket discovered here is discovered before anybody
/// uploads to it (`docs/08-BYO-INFRA.md §3`, `crates/storage/src/public_access.rs`).
///
/// # Why an unreachable store is an error and not a `None`
///
/// The two absences differ, and the difference is whether an operator made a decision.
/// `provider: none` is a decision, and it produces the documented absence [`index_runner`]
/// describes: no pass, one warning, `chunk_text` stays empty. A bucket that was named and cannot be
/// reached is a broken deployment, and starting anyway would leave a worker reporting healthy while
/// the one thing it was configured to do never happens.
///
/// Credentials are dereferenced inside `connect`, from `registry`, at the last moment
/// (`docs/08-BYO-INFRA.md §6`). They are *also* enrolled in `Config::secret_refs`, so an
/// unresolvable key has already been reported by field path before this runs.
async fn object_store(
    config: &enclave_config::Config,
    registry: &enclave_config::SecretRegistry,
) -> anyhow::Result<Option<S3BlobStore>> {
    let Some(section) = config.storage.s3.as_ref() else { return Ok(None) };

    let store = S3BlobStore::connect_and_verify(
        enclave_storage::S3Config::from_operator_config(section),
        registry,
    )
    .await
    .with_context(|| {
        format!(
            "connect to the object store named by `storage.s3` (bucket `{}`, region `{}`)",
            section.bucket, section.region
        )
    })?;
    Ok(Some(store))
}

/// The vector store's census, for the coverage probe, or `None` when none is configured.
///
/// `MilvusIndex` is the only [`IndexCensus`] there is, and building one touches nothing — the
/// handle exists whether or not the store does, so a Milvus that is down degrades the probe rather
/// than refusing this start-up. That is the opposite of [`object_store`]'s treatment of an
/// unreachable bucket, deliberately: a census that cannot be taken is a *reported* gap
/// (`coverage::probe_pass` counts the tenant `unreadable`), whereas an unreadable bucket is a pass
/// that consumes its retry budget in silence.
///
/// # The dimension is not configuration
///
/// [`enclave_embeddings::model::ACTIVE`] supplies it, and `search:` deliberately has no key for it.
/// The width is fixed when the collection is created and a mismatch errors at neither end — Milvus
/// accepts the width it was made with, the model emits the width it was trained at — so the symptom
/// is silently degraded retrieval and the correction is re-embedding every chunk of every tenant
/// (`docs/07-SEARCH-INDEXING.md §9`). This is the crate `ENC-533` asks for: one that depends on both
/// `embeddings` and `search` and can therefore make them agree in one line.
///
/// # Errors
///
/// A `search.milvus.token` that resolved to something that is not UTF-8.
fn index_census(
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<Option<Arc<dyn IndexCensus>>> {
    let Some(section) = config.search.milvus.as_ref() else {
        tracing::warn!(
            "no vector store is configured (`search.provider` is `none`), so the coverage probe is \
             not scheduled and `enclave_search_index_observed_chunks` will have no series. A \
             census pointed at a URI nobody set would be worse: every tenant would count \
             `unreadable` and the gauges would report a fleet-wide outage that is really a missing \
             configuration key."
        );
        return Ok(None);
    };

    let mut milvus = enclave_search::MilvusConfig::new(
        section.uri.to_string(),
        enclave_embeddings::model::ACTIVE.dimension,
    );
    if let Some(collection) = section.collection.as_ref() {
        milvus.collection.clone_from(collection);
    }
    if let Some(token) = secrets.get("search.milvus.token") {
        milvus.token =
            Some(token.expose_str().context("search.milvus.token is not valid UTF-8")?.to_owned());
    }

    Ok(Some(Arc::new(enclave_search::MilvusIndex::new(milvus))))
}

/// Translates the configuration's database section into the `db` crate's own type.
///
/// The same function `crates/api/src/main.rs` has, plus the platform URL, which the API does not
/// need and this process cannot run without.
fn db_config_from(
    config: &enclave_config::Config,
    secrets: &enclave_config::ResolvedSecrets,
) -> anyhow::Result<enclave_db::DbConfig> {
    let url = secrets
        .get("database.url")
        .context("database.url did not resolve; set `database.url_env: DATABASE_URL` or a secret reference")?
        .expose_str()
        .context("database.url is not valid UTF-8")?;

    let mut db_config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(url))
        .with_max_connections(config.database.max_connections);

    if let Some(platform) = secrets.get("database.platform_url") {
        let platform = platform.expose_str().context("database.platform_url is not valid UTF-8")?;
        db_config = db_config.with_platform_url(enclave_db::ConnectionUrl::new(platform));
    }

    Ok(db_config)
}

/// Waits for SIGTERM or Ctrl-C.
///
/// SIGTERM as well as Ctrl-C, unlike the API binary, because it is the one that actually arrives:
/// every container runtime sends it, and a worker that ignored it would be waited on for the grace
/// period and then `SIGKILL`ed — mid-transaction, which is the case `Stop` exists to avoid.
///
/// The signal only *raises* the flag. What makes shutdown graceful is what happens next: each loop
/// returns at its own boundary, between transactions, and `main` waits for all of them. Dropping
/// them here instead would roll back whatever was in flight — `sqlx` keeps the database consistent,
/// so nothing is corrupt, but the work is discarded and the connection is returned mid-conversation.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                // Registering a handler can fail; losing Ctrl-C as well would leave no way to stop
                // the process politely at all.
                tracing::error!(%error, "could not listen for SIGTERM; Ctrl-C only");
                let _ignored = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ignored = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The shipped marker names every build it routes to.
    ///
    /// This exists because the obvious way to check it — start the binary and read the log — proves
    /// nothing: the process exits at configuration load long before it reaches the router, which is
    /// exactly what happened when this was verified by hand. The guard is real; the manual check
    /// was not.
    #[test]
    fn the_shipped_router_marker_names_every_extractor_it_registers() {
        MediaTypeRouter::new(ExtractorVersion::new(ROUTER))
            .route(TEXT_TYPES, Arc::new(PlainTextExtractor))
            .expect("the shipped marker must name the text extractor's build");
    }

    /// And refuses one it does not name.
    ///
    /// The positive control for the test above: without it, that assertion passes for free against
    /// a router that verified nothing (`docs/12 §1.2`).
    #[test]
    fn a_marker_that_does_not_name_a_build_is_refused() {
        let refused = MediaTypeRouter::new(ExtractorVersion::new("router/1"))
            .route(TEXT_TYPES, Arc::new(PlainTextExtractor));
        assert!(
            refused.is_err(),
            "a marker naming no extractor build was accepted, so bumping an extractor could \
             silently stop triggering a reindex"
        );
    }
}
