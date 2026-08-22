//! The content scan that writes `security_facts` — `ENC-613`.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §12`: *full scanning is asynchronous; synchronous decisions
//! consume precomputed facts*. `ENC-581` built the detectors, `ENC-582` threaded a `FactsSnapshot`
//! through the chain and `ENC-594` built the table and the reader. Nothing produced a row, so every
//! version in every deployment was permanently **unscanned** — refused loudly under `FAIL_CLOSED`,
//! permitted with evidence under `FAIL_OPEN_AUDIT`, and inspected under neither. This is the
//! producer.
//!
//! # Where it lives, and what "beside antivirus" turned out to mean
//!
//! `ENC-594`'s report puts the writer *"beside antivirus in the asynchronous pipeline — the same job
//! that already runs antivirus over a new version"*. Checked rather than assumed: there is no such
//! job. `enclave-antivirus` is a library with no caller in any binary — nothing in `crates/worker`
//! or `crates/api` constructs a scanner, and `file_versions.av_status` is written by
//! `crates/versions` at upload and moved by nothing. The asynchronous pipeline that does exist is
//! the **indexing pass**, and it is already downstream of rule 9: it reads a version's bytes through
//! [`readable_version`], which answers `None` for anything that is not `AVAILABLE` and `CLEAN`.
//!
//! So this pass sits beside indexing, reads content the same way, and — like it — cannot hold up an
//! upload, because nothing on a write path waits for either.
//!
//! # Extraction is reused, not rebuilt
//!
//! The detectors read text. `crates/indexing` already turns bytes into text, under
//! [`RenderBudget`], with OCR for a scanned document, through a media-type router a deployment
//! configures once. A second extraction path would drift from the first, and the one that drifts is
//! the one enforcing DLP: a media type registered for indexing and not for scanning is a document
//! that is searchable and unscanned, with nothing reporting it.
//!
//! So this pass takes the **same** [`Pipeline`] and the **same** [`MountedOcr`] the indexing pass
//! takes — the very instances, not equivalent ones: `crates/worker/src/main.rs` builds one
//! `Arc<dyn Extractor>` and lends it to both (`enclave_indexing`'s `impl Extractor for Arc<E>`).
//! The one thing this pass does not share is the *write*: it stores no chunks and touches no
//! manifest, so a deployment can scan without indexing and neither pass can move the other's rows.
//!
//! What it scans is [`Prepared::chunks`] — the chunker's output, held in memory, never the
//! `chunk_text` table. Reading the stored copy was the other candidate and is wrong twice: a
//! `NO_INDEX` classification means content never reaches that table (`docs/07 §2.3`), so the most
//! sensitive documents in a tenant would be the ones never scanned, and DLP coverage would silently
//! become a function of whether search was working.
//!
//! There is one measured cost. `ChunkBudget::overlap_chars` repeats ~360 characters of an oversized
//! segment in the next chunk, so an identifier that lands inside an overlap is counted twice. It
//! errs **upward**, which `enclave_dlp::detector::CandidateClass` already argues is the safe
//! direction for a count a threshold reads — a count that is too high denies more.
//!
//! # The budget: `RenderBudget` fits, and this says exactly which term covers what
//!
//! `plans/M4-GOVERNANCE.md §5` names the risk — *"a detector that is expensive on a large document
//! turns every write into a timeout"* — and says "reuse the budget" may not be the answer. Here it
//! is, and the reason is a property of Q16's detectors rather than a hope:
//!
//!   * **Extraction** is bounded by [`RenderBudget`] exactly as it is for indexing, from *outside*
//!     the extractor, by `BoundedExtractor` — input cap, output cap, page cap, wall clock.
//!   * **Detection** is bounded by its input, because `enclave_dlp::detector` states a cost *bound*
//!     and not an estimate: one pass per candidate class, no backtracking, nothing quadratic, work
//!     per candidate capped at `MAX_CANDIDATE_LEN`. Its runtime is a function of the text's length
//!     and nothing else — and that length is already capped by `RenderBudget::max_output_bytes`.
//!
//! So there is no second set of numbers to tune, and no wall clock over the detector pass.
//! Deliberately no wall clock: the scan is synchronous CPU work, `tokio::time::timeout` stops
//! polling a future without stopping a thread inside it (`BoundedExtractor` says so in its own
//! words), and a clock that cannot end the work it names is a promise the process does not keep. It
//! runs on [`tokio::task::spawn_blocking`] instead, so the runtime's worker threads are never held.
//!
//! # A document that cannot be scanned gets **no row**, and that is the decision in this module
//!
//! Encrypted, corrupt, an unsupported type, a scanned page on a deployment with no OCR — every one
//! of them yields no text. The tempting record is "scanned, zero counts", and it is the one
//! genuinely dangerous outcome available here: every `Condition` in `enclave_dlp::policy` is a
//! threshold over counts, a severity or a score, so a row of zeroes makes **every rule evaluate
//! cleanly and permit**, with a `scanned_at` timestamp and a current detector-set version standing
//! behind it. Nothing downstream can tell that apart from a document that was read and found clean.
//!
//! The absence of a row is *safe*: it means unscanned, which `FAIL_CLOSED` refuses and
//! `FAIL_OPEN_AUDIT` permits with a high-visibility audit event — a state the tenant chose the
//! meaning of. A false clean bill of health is not safe under either.
//!
//! So [`Unscannable`] writes nothing at all, and the only outcome that reaches
//! [`record_facts`](enclave_db::record_facts) is one where the detectors were handed the document's
//! text. A clean document with text still gets a row of zeroes — that is a real scan finding
//! nothing, and it is what stops this rule collapsing into "never write anything".
//!
//! # Counts, never content
//!
//! `CLAUDE.md` rule 10. Nothing here copies a matched value anywhere: `Candidate` borrows from the
//! chunk buffer and renders `<candidate withheld>` in `Debug`, `ScanReport` carries counts, and
//! `security_facts` has no column a match value could occupy (`migrations/0020`). The one thing
//! this module must not do is put chunk text in a log line, and it never formats one.

use core::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use enclave_core::{
    DetectorCounts, RiskScore, ScanVersion, SecurityFacts, Severity, TenantId, VersionId,
};
use enclave_db::{record_facts, DbPool};
use enclave_dlp::detector::{Confidence, DetectorSet, ScanReport};
use enclave_indexing::{ExtractRequest, Extractor, Outcome, Pipeline};
use enclave_preview::repo::readable_version;
use enclave_preview::RenderBudget;
use enclave_storage::BlobStore;
use sqlx::Row as _;
use tracing::debug;
use uuid::Uuid;

use crate::indexing::read_bounded;
use crate::ocr::MountedOcr;
use crate::{Result, Stop, WorkerError};

/// The generation of *this* pipeline, recorded in `security_facts.scan_version`.
///
/// The pipeline, not the rules: `detector_set_version` is the one a decision compares, and
/// `docs/04 §12.2` explains why only this one is indexed and ordered. Bump it when the way text
/// reaches the detectors changes — a new extractor, OCR arriving, a different chunk window — so that
/// `idx_facts_stale` can find what that change invalidated. No decision reads it, and nothing here
/// treats it as freshness.
pub const SCAN_VERSION: ScanVersion = ScanVersion::new(1);

/// Why a version produced no facts.
///
/// Every variant means the detectors were **not** shown the document's text, and every one of them
/// therefore writes nothing. See the module documentation for why "scanned, zero counts" is not
/// among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unscannable {
    /// The version's bytes may not be read: still scanning, quarantined, or superseded.
    ///
    /// `CLAUDE.md` rule 9, and the only variant that is expected to clear by itself. Not a verdict
    /// about the document — the same distinction `enclave_indexing::defer` draws for indexing.
    NotReadable,
    /// No extractor claims this media type in this deployment.
    Unsupported,
    /// The extractor refused: over the input or output cap, past the wall clock, or not the bytes
    /// the declared type promised.
    Refused,
    /// It parsed, and yielded no characters — an encrypted container, a scanned page with no OCR
    /// mounted, a document of blank pages.
    ///
    /// The variant this module exists for. It is the one that most looks like "there is nothing
    /// sensitive in here" and is in fact "nobody has read this".
    NoText,
}

impl Unscannable {
    /// A fixed label for a log field. A vocabulary, never a parser's message — the rule
    /// `enclave_indexing::Reason` states for `index_manifests.failure_reason`, and for the same
    /// reason: this is decided immediately after parsing a hostile document.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReadable => "not_readable",
            Self::Unsupported => "unsupported_media_type",
            Self::Refused => "extraction_refused",
            Self::NoText => "no_text_extracted",
        }
    }
}

impl fmt::Display for Unscannable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Where the next pass over a tenant's versions resumes.
///
/// # Why a cursor exists at all
///
/// The queue is a *query*, not a table: `security_facts` has no claim column, no `attempts` and no
/// deferral state, and `migrations/` is not this task's to extend. So "what still needs scanning"
/// is `file_versions` left-joined against the facts, and a version that cannot be scanned never
/// leaves that result set.
///
/// Without a cursor the consequence is not a hot loop — the loop always idles (see
/// [`crate::schedule`]) — it is **starvation**: a batch of unscannable documents at the oldest end
/// of the order is re-selected every tick, and nothing behind them is ever reached. With one, each
/// tick continues where the last left off and an unscannable version costs one attempt per sweep of
/// the tenant rather than every attempt forever.
///
/// # Why it is in memory and not stored
///
/// Because losing it is harmless. A restarted worker begins the sweep again from the oldest
/// version, re-selects only what is still unscanned, and converges; the cost is one repeated sweep,
/// and the alternative is a table with a schema, a migration and a staleness question of its own.
/// It is a pacing aid, never a correctness input — nothing reads it to decide whether a version was
/// scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanCursor {
    /// `(created_at, id)` of the last version considered, or `None` at the start of a sweep.
    at: Option<(DateTime<Utc>, Uuid)>,
}

impl ScanCursor {
    /// The beginning of a sweep: the oldest version this tenant has.
    #[must_use]
    pub const fn start() -> Self {
        Self { at: None }
    }

    /// Whether this cursor is at the beginning of a sweep.
    #[must_use]
    pub const fn is_start(&self) -> bool {
        self.at.is_none()
    }
}

/// What one pass over a tenant's unscanned versions did.
///
/// Counted separately rather than summed, for the reason [`crate::indexing::IndexPass`] gives about
/// its own four: `scanned` climbing is the control working, `textless` climbing is a corpus nobody
/// has read — the state an operator most needs to be able to see, because under `FAIL_OPEN_AUDIT`
/// it is permitted content and under `FAIL_CLOSED` it is refused content, and under a single total
/// it is invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanPass {
    /// Versions this pass looked at.
    pub considered: usize,
    /// Versions whose text reached the detectors and whose facts were recorded.
    pub scanned: usize,
    /// Versions whose bytes may not be read yet (rule 9).
    pub not_readable: usize,
    /// Versions no extractor in this deployment handles.
    pub unsupported: usize,
    /// Versions the extractor refused — over budget, or not what they claimed to be.
    pub refused: usize,
    /// Versions that parsed and yielded no characters.
    pub textless: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
    /// Where the next pass over this tenant should resume.
    ///
    /// Back at [`ScanCursor::start`] when this pass reached the end of the tenant's versions, which
    /// is what makes the sweep repeat rather than stop.
    pub resume: ScanCursor,
}

impl ScanPass {
    /// Versions that produced no facts, whatever the reason.
    ///
    /// Every one of them is *unscanned* to the policy chain, and that is the number a deployment
    /// rolling DLP out past `MONITOR` has to look at before it does.
    #[must_use]
    pub const fn unscannable(&self) -> usize {
        self.not_readable + self.unsupported + self.refused + self.textless
    }
}

/// The versions that have no usable facts, oldest first, from `after`.
///
/// Three things about the predicate:
///
///   * **Freshness is equality**, matching `enclave_core::DetectorSetVersion` and
///     `FactsSnapshot::gathered`. `<>` and never an ordering — the column is an opaque build
///     identifier, and an ordering invented over it reads a version that sorts unexpectedly high as
///     *fresh*. That equality is also the whole of the rescan trigger: moving the active set's
///     version puts every row in this result set at once.
///   * **`AVAILABLE` and `CLEAN`**, which is rule 9 stated in the queue as well as enforced by
///     [`readable_version`] per version. Not a duplicate check for its own sake: without it every
///     tick of every pass would select the entire scanning backlog and then discard it one row at a
///     time.
///   * **Every version, not just current ones.** Facts are per version (`migrations/0020`), and a
///     governed action can name an old one — which is why *restoring* a version needs no trigger of
///     its own: it was scanned when it arrived.
///
/// The `tenant_id = $1` predicate sits beside row-level security, the two-layer arrangement of
/// `docs/04 §3`.
const DUE_SQL: &str = "
SELECT v.id, v.created_at
  FROM file_versions v
  LEFT JOIN security_facts f
    ON  f.tenant_id  = v.tenant_id
    AND f.file_id    = v.file_id
    AND f.version_id = v.id
 WHERE v.tenant_id  = $1
   AND v.status     = 'AVAILABLE'
   AND v.av_status  = 'CLEAN'
   AND (f.version_id IS NULL OR f.detector_set_version <> $2)
   AND ($3::timestamptz IS NULL OR (v.created_at, v.id) > ($3, $4))
 ORDER BY v.created_at, v.id
 LIMIT $5
";

/// Scans up to `batch` of one tenant's versions that have no usable facts.
///
/// Returns rather than only logging, so a scheduler or a test can assert on the outcome — the same
/// reason [`crate::indexing::index_pass`] does.
///
/// # Errors
///
/// [`WorkerError`] from the first version whose *storage or database* fails. Versions already
/// scanned in this pass keep their facts: each write is its own transaction. A document that will
/// not parse is **not** an error — it is an [`Unscannable`], counted, because a hostile or broken
/// document is the ordinary case here and must not stop the queue.
#[allow(clippy::too_many_arguments)]
pub async fn scan_pass<E: Extractor, S: BlobStore + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    pipeline: &Pipeline<E>,
    ocr: Option<&MountedOcr>,
    detectors: &Arc<DetectorSet>,
    store: &S,
    budget: RenderBudget,
    batch: i64,
    from: ScanCursor,
    stop: &Stop,
) -> Result<ScanPass> {
    let mut outcome = ScanPass { resume: from, ..ScanPass::default() };

    let due = due_versions(pool, tenant, detectors, from, batch).await?;
    outcome.considered = due.len();

    // Short of a full batch means the end of this tenant's versions was reached, so the next pass
    // starts the sweep again. Decided from the *query*, before any version is skipped, so a pass
    // that stopped early does not read as having finished the sweep.
    let swept = i64::try_from(due.len()).unwrap_or(i64::MAX) < batch;

    for (version, created_at) in due {
        if stop.is_stopped() {
            outcome.stopped = true;
            // The cursor is left where the last completed version put it, so the next pass resumes
            // rather than repeating the batch. `swept` is deliberately not applied here.
            return Ok(outcome);
        }

        match scan_version(pool, tenant, pipeline, ocr, detectors, store, budget, version).await? {
            Ok(()) => outcome.scanned += 1,
            Err(reason) => {
                match reason {
                    Unscannable::NotReadable => outcome.not_readable += 1,
                    Unscannable::Unsupported => outcome.unsupported += 1,
                    Unscannable::Refused => outcome.refused += 1,
                    Unscannable::NoText => outcome.textless += 1,
                }
                // The version and the reason, never anything the extractor produced
                // (`CLAUDE.md` rule 10). An identifier and a fixed label are what an operator needs
                // to find the document; its content is not.
                debug!(
                    tenant = %tenant,
                    version = %version,
                    reason = reason.as_str(),
                    "a version produced no security facts and is therefore unscanned"
                );
            }
        }

        outcome.resume = ScanCursor { at: Some((created_at, version.as_uuid())) };
    }

    if swept {
        outcome.resume = ScanCursor::start();
    }

    debug!(
        tenant = %tenant,
        considered = outcome.considered,
        scanned = outcome.scanned,
        not_readable = outcome.not_readable,
        unsupported = outcome.unsupported,
        refused = outcome.refused,
        textless = outcome.textless,
        swept,
        stopped = outcome.stopped,
        "content scan pass complete"
    );
    Ok(outcome)
}

/// Reads the queue for one tick, in one tenant-scoped transaction.
async fn due_versions(
    pool: &DbPool,
    tenant: TenantId,
    detectors: &DetectorSet,
    from: ScanCursor,
    batch: i64,
) -> Result<Vec<(VersionId, DateTime<Utc>)>> {
    let mut tx = pool.begin(tenant).await?;
    let rows = sqlx::query(DUE_SQL)
        .bind(tenant.as_uuid())
        .bind(detectors.version().as_str())
        .bind(from.at.map(|(created_at, _)| created_at))
        .bind(from.at.map(|(_, id)| id))
        .bind(batch)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    rows.into_iter()
        .map(|row| {
            let id: Uuid = row.try_get("id").map_err(|_| WorkerError::MalformedRow {
                column: "file_versions.id",
                reason: "missing or of an unexpected type",
            })?;
            let created_at: DateTime<Utc> =
                row.try_get("created_at").map_err(|_| WorkerError::MalformedRow {
                    column: "file_versions.created_at",
                    reason: "missing or of an unexpected type",
                })?;
            Ok((VersionId::from_uuid(id), created_at))
        })
        .collect()
}

/// Scans one version, or says why it could not be.
///
/// The nested result is not an accident of style: the outer arm is *our* failure — storage, the
/// database — which stops the pass, and the inner arm is a fact about the document, which does not.
/// It is the same split [`crate::indexing::index_pass`] makes between a `WorkerError` and an
/// `Outcome`.
///
/// # Two transactions, not one
///
/// The readability lookup commits before a byte is read, and the facts are written in a second
/// transaction afterwards. `index_pass` holds one open across extraction because it must — a claim
/// it took has to survive to the manifest write — and there is no claim here, so holding a
/// connection and a snapshot open across a thirty-second parse would buy nothing and cost a
/// connection per document in flight.
///
/// What that admits is a version quarantined or superseded between the two, whose facts are then
/// written anyway. It is harmless in the direction that matters: the facts describe the bytes that
/// were read, they are only ever consulted when that version is the subject of an action, and a
/// version that has been *purged* takes its facts with it — the write fails on the foreign key
/// rather than storing facts about content that no longer exists (`migrations/0020`).
#[allow(clippy::too_many_arguments)]
async fn scan_version<E: Extractor, S: BlobStore + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    pipeline: &Pipeline<E>,
    ocr: Option<&MountedOcr>,
    detectors: &Arc<DetectorSet>,
    store: &S,
    budget: RenderBudget,
    version: VersionId,
) -> Result<core::result::Result<(), Unscannable>> {
    // Rule 9, through the one type that can express it. `ReadableVersion` has private fields and a
    // single constructor whose query carries `status = 'AVAILABLE' AND av_status = 'CLEAN'`, so a
    // scan of unscanned content is not something this function can be written to do.
    let readable = {
        let mut tx = pool.begin(tenant).await?;
        let readable = readable_version(&mut tx, tenant, version).await?;
        tx.commit().await?;
        match readable {
            Some(readable) => readable,
            None => return Ok(Err(Unscannable::NotReadable)),
        }
    };

    let source = read_bounded(store, readable.object_key(), &budget).await?;
    let mut prepared = pipeline
        .prepare(
            version,
            ExtractRequest {
                declared_media_type: readable.media_type().to_owned(),
                source,
                budget,
            },
        )
        .await?;

    // The same stage the indexing pass runs, and the same placement: only on a textless outcome,
    // and the bytes are re-read rather than kept, because a copy held for every document is a
    // permanent doubling of peak residency to serve the minority that needs it.
    if let Some(stage) = ocr {
        if matches!(prepared.outcome, Outcome::NoText(_)) {
            let source = read_bounded(store, readable.object_key(), &budget).await?;
            prepared = stage.retry(version, prepared, source).await?;
        }
    }

    match prepared.outcome {
        Outcome::Unsupported => return Ok(Err(Unscannable::Unsupported)),
        Outcome::Refused(_) => return Ok(Err(Unscannable::Refused)),
        Outcome::NoText(_) => return Ok(Err(Unscannable::NoText)),
        Outcome::Ready { .. } => {}
    }

    let report = detect(Arc::clone(detectors), prepared.chunks).await?;
    let facts = facts_from(&report, readable.file(), version, detectors);

    let mut tx = pool.begin(tenant).await?;
    record_facts(&mut tx, &facts).await?;
    tx.commit().await?;

    Ok(Ok(()))
}

/// Runs the detector set over a version's text, off the runtime's worker threads.
///
/// `spawn_blocking` because [`DetectorSet::scan`] is synchronous CPU work over a document that may
/// be hundreds of megabytes, and `CLAUDE.md` forbids blocking an async context. There is no timeout
/// around it — see this module's documentation for why a wall clock over uninterruptible work would
/// be a promise the process cannot keep, and what bounds this instead.
///
/// The chunks are **moved** in and dropped inside the closure. Nothing comes back but a
/// [`ScanReport`], which carries counts and no bytes.
async fn detect(
    detectors: Arc<DetectorSet>,
    chunks: Vec<enclave_indexing::Chunk>,
) -> Result<Vec<ScanReport>> {
    tokio::task::spawn_blocking(move || {
        chunks.iter().map(|chunk| detectors.scan(&chunk.text)).collect()
    })
    .await
    .map_err(|_joined| WorkerError::MalformedRow {
        column: "detector_scan",
        reason: "the scanning thread did not complete",
    })
}

/// Assembles the row from what the detectors reported.
///
/// Every field is a count, a severity, a version or a timestamp. There is nowhere here a matched
/// value could go, which is `migrations/0020`'s property rather than this function's care.
fn facts_from(
    reports: &[ScanReport],
    file: enclave_core::FileId,
    version: VersionId,
    detectors: &DetectorSet,
) -> SecurityFacts {
    let mut counts = DetectorCounts::none();
    for report in reports {
        let chunk_counts = report.counts();
        for &category in enclave_core::DetectorCategory::all() {
            counts.add(category, chunk_counts.get(category));
        }
    }

    let mut facts = SecurityFacts::scanned(
        file,
        version,
        counts,
        detectors.version().clone(),
        SCAN_VERSION,
        Utc::now(),
    );

    if let Some(severity) = max_severity(reports) {
        facts = facts.with_max_severity(severity);
    }

    // `RiskScore::ZERO`, and stated rather than left to be inferred. A composite risk signal
    // (`docs/06 §12`) aggregates things this pipeline does not have — proximity between a card
    // number and an expiry date, the resource's label, the tenant's incident history — and a number
    // synthesised from the counts would be the counts again, under a name `Condition::RiskAtLeast`
    // reads as independent evidence. The consequence is a real gap and is logged as `ENC-639`: a
    // rule written against `RiskAtLeast` never fires.
    facts.with_risk_score(RiskScore::ZERO)
}

/// The severity of the most serious finding, or `None` when nothing fired.
///
/// Derived from the detector's own [`Confidence`] — *how much one acceptance is worth alone*
/// (`docs/06 §8`) — and only from **triggered** detectors, so a detector that accepted two
/// instances against a minimum of five does not set a severity for findings it does not consider
/// itself to have made. That is the rule `ScanReport::counts` already applies to the counts, kept
/// consistent here rather than re-decided.
///
/// `CRITICAL` is deliberately unreachable. Nothing a structured detector reports distinguishes it
/// from `HIGH`: the difference would have to come from a count threshold, and a threshold baked
/// into the *fact* is a policy decision recorded as evidence, which is exactly what
/// `Condition::CategoryAtLeast` exists to let an administrator write instead.
///
/// `None` for a clean document, not `LOW`. `migrations/0020` says so about the column in as many
/// words — "`NULL` means the scan attached no severity … and is not the same as `LOW`" — and
/// `Condition::SeverityAtLeast` reads `None` as not-holding, so the two agree.
fn max_severity(reports: &[ScanReport]) -> Option<Severity> {
    reports
        .iter()
        .flat_map(ScanReport::triggered)
        .map(|finding| match finding.confidence() {
            Confidence::Low => Severity::Low,
            Confidence::Medium => Severity::Medium,
            Confidence::High => Severity::High,
        })
        .max()
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The queue asks for equality against the active set and never for an ordering.
    ///
    /// `ENC-581`'s rule, restated where the rescan trigger actually lives. An ordering invented over
    /// an opaque build identifier fails one-directionally — a version that sorts unexpectedly high
    /// reads as *fresh*, so a detector-set change would silently fail to enqueue the rows it
    /// invalidated and every stale fact would keep deciding requests.
    #[test]
    fn the_queue_compares_the_detector_set_for_inequality_and_never_orders_it() {
        assert!(
            DUE_SQL.contains("f.detector_set_version <> $2"),
            "a rescan is triggered by inequality with the active set"
        );
        // The column appears exactly once, so the `<>` above is the *only* comparison made over it.
        // A count rather than a search for forbidden operators, because `<>` contains `<` and the
        // first version of this assertion failed against its own correct statement.
        assert_eq!(
            DUE_SQL.matches("detector_set_version").count(),
            1,
            "the detector set is compared more than once: {DUE_SQL}"
        );
        for ordering in ["detector_set_version <=", "detector_set_version >", "ORDER BY f."] {
            assert!(
                !DUE_SQL.contains(ordering),
                "`{ordering}` orders an opaque build identifier: {DUE_SQL}"
            );
        }
        // The positive controls: the needles above are findable in statements that do order it, so
        // the three absences are this statement being right rather than the search being wrong.
        assert!("WHERE f.detector_set_version <= $2".contains("detector_set_version <="));
        assert!("WHERE f.detector_set_version > $2".contains("detector_set_version >"));
        assert!("ORDER BY f.detector_set_version".contains("ORDER BY f."));
    }

    /// Rule 9 is in the queue as well as in `readable_version`.
    ///
    /// Not belt and braces: without it every tick selects the whole scanning backlog and discards
    /// it one row at a time, so a tenant mid-bulk-upload would starve its own scannable versions.
    #[test]
    fn the_queue_offers_only_versions_antivirus_has_cleared() {
        assert!(DUE_SQL.contains("v.status     = 'AVAILABLE'"), "{DUE_SQL}");
        assert!(DUE_SQL.contains("v.av_status  = 'CLEAN'"), "{DUE_SQL}");
        assert!(DUE_SQL.contains("v.tenant_id  = $1"), "layer 1 beside RLS: {DUE_SQL}");
    }

    /// A version with no row at all is due, and so is one stamped by a set that is no longer
    /// active — both halves, because the join could be written to find only one of them.
    #[test]
    fn a_version_is_due_when_it_has_no_facts_or_facts_from_another_set() {
        assert!(DUE_SQL.contains("LEFT JOIN security_facts"), "an inner join finds only rescans");
        assert!(DUE_SQL.contains("f.version_id IS NULL OR"), "a never-scanned version is due");
    }

    /// A cursor that started at the beginning and a cursor that has moved are different values,
    /// and the pass reports which one the next tick should use.
    #[test]
    fn a_sweep_that_reached_the_end_resumes_at_the_beginning() {
        assert!(ScanCursor::start().is_start());
        let moved = ScanCursor { at: Some((Utc::now(), Uuid::now_v7())) };
        assert!(!moved.is_start());
        assert_ne!(moved, ScanCursor::start());
    }

    /// Every disposition is counted exactly once, and the four that produced no facts are
    /// reachable as one number.
    ///
    /// `unscannable()` is what a deployment reads before enabling `ENFORCE`: under `FAIL_CLOSED`
    /// every one of those versions refuses a governed action, and under `FAIL_OPEN_AUDIT` every one
    /// of them permits.
    #[test]
    fn the_dispositions_partition_the_versions_a_pass_considered() {
        let pass = ScanPass {
            considered: 5,
            scanned: 1,
            not_readable: 1,
            unsupported: 1,
            refused: 1,
            textless: 1,
            stopped: false,
            resume: ScanCursor::start(),
        };
        assert_eq!(pass.scanned + pass.unscannable(), pass.considered);
        assert_eq!(pass.unscannable(), 4);
    }

    /// A clean document produces a severity of `None`, not `LOW`.
    ///
    /// The column's own documentation says these are different facts, and
    /// `Condition::SeverityAtLeast(LOW)` would hold for every scanned document in the tenant if
    /// this returned `Low` for a report that fired nothing.
    #[test]
    fn a_report_that_fired_nothing_attaches_no_severity() {
        let set = enclave_dlp::builtin_set();
        let clean = set.scan("The quarterly review is on Tuesday at 14:30 in room 4111.");
        assert_eq!(max_severity(&[clean]), None);

        // The positive control, and it is the whole test: without it the assertion above passes
        // against a `max_severity` that returns `None` unconditionally, which is `docs/12 §1.2`'s
        // exact shape.
        let found = set.scan("Please charge 4111111111111111 for the balance.");
        assert_eq!(
            max_severity(&[found]),
            Some(Severity::High),
            "a Luhn-valid card number is a High-confidence detector firing"
        );
    }

    /// Counts are summed across chunks, so a document longer than one chunk is not scanned only in
    /// its first.
    #[test]
    fn counts_from_every_chunk_reach_the_facts() {
        let set = enclave_dlp::builtin_set();
        let reports = vec![
            set.scan("charge 4111111111111111"),
            set.scan("and also 5500005555555559"),
            set.scan("nothing here"),
        ];
        let facts = facts_from(&reports, enclave_core::FileId::new_v7(), VersionId::new_v7(), &set);
        assert_eq!(
            facts.counts().get(enclave_core::DetectorCategory::Financial),
            2,
            "a scan that only counted the first chunk answers every how-many question wrongly"
        );
    }

    /// The row is stamped with the set that produced it, which is what makes
    /// `FactsSnapshot::gathered`'s equality check mean anything.
    #[test]
    fn facts_carry_the_detector_set_that_produced_them() {
        let set = enclave_dlp::builtin_set();
        let facts = facts_from(&[], enclave_core::FileId::new_v7(), VersionId::new_v7(), &set);
        assert_eq!(facts.detector_set(), set.version());
        assert_eq!(facts.scan_version(), SCAN_VERSION);
    }

    /// Every reason a version goes unscanned has its own label, and none of them is a message.
    #[test]
    fn every_unscannable_reason_has_a_distinct_fixed_label() {
        let reasons = [
            Unscannable::NotReadable,
            Unscannable::Unsupported,
            Unscannable::Refused,
            Unscannable::NoText,
        ];
        let mut labels: Vec<&str> = reasons.iter().map(|reason| reason.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), reasons.len(), "two reasons render identically in a log");
    }
}
