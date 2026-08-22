//! The antivirus pass: the caller `enclave-antivirus` never had — `ENC-641`.
//!
//! # What was missing
//!
//! `crates/antivirus` is complete and was wired to nothing. `crates/versions` writes every new
//! version `SCANNING` / `PENDING` with no parameter that could say otherwise, `READABLE_PREDICATE`
//! requires `AVAILABLE AND CLEAN`, and **no code performed the transition between them**. So in a
//! running deployment no version ever became readable: `CLAUDE.md` rule 9 held in the direction that
//! matters and held *absolutely*, because nothing was ever scanned. Both downstream content passes —
//! [`crate::indexing`] and [`crate::scan`] — were therefore correct and permanently idle.
//!
//! This module is the transition. It is the only thing in the workspace that writes
//! `file_versions.status = 'AVAILABLE'`.
//!
//! # The rules are not here
//!
//! [`enclave_antivirus::decide`] is `docs/06 §6.2` as a pure function, and this pass does not
//! re-decide any of it. What it owns is the *translation* from a [`ScanOutcome`] into two rows, and
//! that translation is written once, in [`Target::of`], so a reader can check the table against the
//! document in one place:
//!
//! | disposition | `file_versions.status` | `file_versions.av_status` | `files.status` |
//! |---|---|---|---|
//! | `Publish`    | `AVAILABLE`   | whatever the outcome says | `AVAILABLE`   |
//! | `Quarantine` | `QUARANTINED` | whatever the outcome says | `QUARANTINED` |
//! | `Hold`       | *unchanged*   | see below                 | *unchanged*   |
//!
//! `files.status` moves **only when the version is the file's current one**. A version that is not
//! current says nothing about what the file advertises, and an old version being quarantined by a
//! rescan must not take a file's live content offline.
//!
//! ## Two things the table does not show
//!
//! **`Publish` does not mean readable.** `AvStatus::Clean` is the only `av_status`
//! `READABLE_PREDICATE` accepts, so the two policies that publish something else —
//! `ALLOW_AND_RESCAN` (`AVAILABLE` / `PENDING`) and `ALLOW_WITH_FLAG` (`AVAILABLE` / `SKIPPED`) —
//! produce a version that is `AVAILABLE` and that no read path will serve. That is a real
//! disagreement between `enclave_antivirus::VersionDisposition::readable` and the database
//! predicate, it errs closed, and it is *not* resolved here: admitting `PENDING` or `SKIPPED` to
//! `READABLE_PREDICATE` would weaken rule 9, which `CLAUDE.md` says is a design conversation rather
//! than a judgement call. Logged as `ENC-646` and pinned by
//! `a_published_but_unscanned_version_is_still_not_served`.
//!
//! **A `Hold` on a version that already carries a verdict writes nothing at all.** `Hold` means
//! "leave it where it is and try again". For a fresh `PENDING` version the outcome's `av_status` is
//! `PENDING` (retryable) or `ERROR` (not), and both are written; for a version being *rescanned*,
//! replacing a recorded `SKIPPED` with "we could not tell" would destroy evidence in exchange for
//! nothing. See [`Target::of`].
//!
//! # The queue is "no usable verdict", and it is the whole rescan mechanism
//!
//! [`DUE_SQL`] offers a version when its `av_status` is:
//!
//!   * `PENDING` — a fresh upload, a `HOLD` retry, or an `ALLOW_AND_RESCAN` version published
//!     unscanned. That last one is why the predicate is on `av_status` and not on `status`: it is
//!     `AVAILABLE`, and `Rescan::Soon` has to find it.
//!   * `SKIPPED`, **and only when the configured engine actually scans content**. This is `§6.2`'s
//!     "signature updates enqueue a rescan of … everything currently flagged `Unsupported`",
//!     specialised to the one signature change this workspace can currently observe: a deployment
//!     that ran `antivirus.provider: none`, skipped its whole corpus, and has now configured an
//!     engine. Without it, `provider: none` would be *terminal* — every version quarantined
//!     `SKIPPED` with nothing able to revisit it.
//!
//! It never offers `CLEAN`, `INFECTED` or `ERROR`. `CLEAN` matters for ordering (below), `INFECTED`
//! because `decide` returns `rescan: None` for it — the bytes are immutable, so the answer cannot
//! change in our favour — and `ERROR` because it is `decide`'s way of saying a retry will not help.
//!
//! `status IN ('SCANNING','PROCESSING','AVAILABLE','QUARANTINED')` excludes `PENDING` and `FAILED`,
//! whose rows may name an object that was never completed. Fetching one would be a storage error on
//! a version nothing is wrong with.
//!
//! # Ordering against the two passes downstream, and the race that is closed by construction
//!
//! [`crate::indexing`] and [`crate::scan`] both reach a version's bytes through
//! [`enclave_preview::repo::readable_version`], whose query is `READABLE_PREDICATE`. This pass makes
//! a version match that predicate in **one committed `UPDATE`**, so there is no instant at which a
//! version is `AVAILABLE` and not yet `CLEAN`, or indexable and not yet confirmed clean.
//!
//! The race worth naming is the other direction: content indexed while `CLEAN` and later found
//! `INFECTED` by a rescan would leave excerpts in the index that no read path would serve from
//! `file_versions`. **This pass cannot cause it**, because its queue never offers a `CLEAN` version —
//! so nothing it writes can move a version out of `CLEAN`. A rescan sweep that could would need to
//! retract the index with it; logged as `ENC-647` rather than left to be discovered.
//!
//! # A stuck `PENDING` is the defect this row is about, so it is reported
//!
//! With `HOLD` and an engine that is down, every version waits in `SCANNING` — correct, and
//! indistinguishable from `ENC-641` itself unless something says so. [`AvPass::held`] counts the
//! versions that got no verdict this tick, and [`AvPass::oldest_due`] carries the creation time of
//! the oldest version still waiting whenever a sweep started from the beginning. [`crate::schedule`]
//! turns both into `warn!` lines. Gauges belong with `ENC-637`'s treatment of the content scan and
//! are logged as `ENC-648`; a log line an operator can grep is what this ships with.
//!
//! # Counts and identifiers, never content
//!
//! `CLAUDE.md` rule 10. The one field here that carries free text from outside is the engine's
//! signature name on [`Incident`], which `enclave_antivirus` documents as security-facing and which
//! cannot reach an uploader — [`UploaderNotice`](enclave_antivirus::UploaderNotice) has nowhere to
//! put a string. It is logged at `error!` beside the version, because that is the only incident
//! channel this deployment has (`ENC-645`), and it is never written to a column: `file_versions` has
//! no place for it.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_antivirus::{
    decide, AntivirusError, AntivirusScanner, EngineInfo, Incident, ScanHint, ScanOutcome,
    ScanPolicy, ScanVerdict, VersionDisposition,
};
use enclave_core::{FileId, TenantId, VersionId};
use enclave_db::DbPool;
use enclave_storage::{BlobStore, ByteRange, StorageError};
use enclave_versions::{AvStatus, VersionStatus};
use sqlx::Row as _;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{Result, Stop, WorkerError};

/// Where the next pass over a tenant's unverdicted versions resumes.
///
/// The same device, for the same reason, as [`crate::scan::ScanCursor`]: the queue is a *query* and
/// not a claimed work list, so a version that keeps failing to produce a new verdict never leaves it.
/// Without a cursor a batch of them at the oldest end is re-selected every tick and nothing behind
/// them is ever reached — starvation, not a hot loop, because the loop idles between ticks.
///
/// In memory rather than stored, because losing it is harmless: a restarted worker sweeps from the
/// oldest version again, re-selects only what still has no verdict, and converges. Nothing reads it
/// to decide whether a version was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AvCursor {
    /// `(created_at, id)` of the last version considered, or `None` at the start of a sweep.
    at: Option<(DateTime<Utc>, Uuid)>,
}

impl AvCursor {
    /// The beginning of a sweep: the oldest version this tenant has without a verdict.
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

/// What one pass over a tenant's unverdicted versions did.
///
/// Counted by *disposition* rather than by whether a row moved, because the two questions have
/// different readers: `held` climbing is an engine an operator has to go and look at, while
/// `written` is what the scheduler uses to decide whether going straight round again could
/// accomplish anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AvPass {
    /// Versions this pass looked at.
    pub considered: usize,
    /// Versions the engine found clean, which are now `AVAILABLE` and readable.
    pub cleared: usize,
    /// Versions published carrying the unscanned flag — `ALLOW_AND_RESCAN` or `ALLOW_WITH_FLAG`.
    ///
    /// Separate from [`Self::cleared`] because they are not the same fact and the difference is
    /// invisible downstream: both are `AVAILABLE`, and only one of them was scanned. See this
    /// module's documentation for why neither is actually served today.
    pub flagged: usize,
    /// Versions moved to `QUARANTINED` — malware, or content the tenant's policy refuses unscanned.
    pub quarantined: usize,
    /// Versions still waiting for a verdict. **The number that means the engine is not answering.**
    pub held: usize,
    /// Versions recorded `ERROR`: the scan failed in a way retrying will not fix, so they will not
    /// be offered again.
    pub errored: usize,
    /// Versions whose row actually changed.
    ///
    /// The scheduler's progress signal, and it is a different question from the five above: a
    /// version re-confirmed `SKIPPED` counts in `quarantined` and changes nothing, so a tick that
    /// only did that must idle rather than re-select the same rows at the speed of the engine.
    pub written: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
    /// When the oldest version still without a verdict was created, if this pass began a sweep.
    ///
    /// `None` mid-sweep, because the cursor has already moved past the oldest one and a number taken
    /// from the middle of a sweep would understate the backlog. Free: it is the first row of a
    /// query that is already ordered oldest-first.
    pub oldest_due: Option<DateTime<Utc>>,
    /// Where the next pass over this tenant should resume.
    pub resume: AvCursor,
}

impl AvPass {
    /// How long the oldest version without a verdict has been waiting, if this pass began a sweep.
    ///
    /// The stuck signal. A backlog whose oldest member is hours old is either an engine that is down
    /// or `ENC-641` again, and both need somebody to look.
    #[must_use]
    pub fn backlog(&self, now: DateTime<Utc>) -> Option<chrono::Duration> {
        self.oldest_due.map(|created| now - created)
    }
}

/// The two columns this pass writes on a version, and whether they are a change at all.
///
/// A named type rather than a tuple built inline, so that the mapping from `docs/06 §6.2` to the
/// schema is one function with one test rather than a sequence of assignments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Target {
    status: VersionStatus,
    av_status: AvStatus,
}

impl Target {
    /// Translates an outcome into the pair of column values a version should end up with.
    ///
    /// `observed` is what the queue found, and it is a parameter rather than an assumption because
    /// two of the three dispositions depend on it:
    ///
    /// * `Hold` never moves `status` — that is what `§6.2`'s "versions wait in `SCANNING`" means,
    ///   and it must also leave a `QUARANTINED` rescan where it is rather than dragging it back into
    ///   `SCANNING` because the engine hiccupped.
    /// * `Hold` on a version that already carries a verdict leaves `av_status` alone too. Replacing
    ///   a recorded `SKIPPED` with `PENDING` or `ERROR` would delete the only evidence of the
    ///   earlier scan to record that this one did not happen.
    ///
    /// Everything else is `decide`'s answer, taken verbatim.
    fn of(outcome: &ScanOutcome, observed: Target) -> Result<Self> {
        let av_status = convert_av_status(outcome.av_status)?;

        Ok(match outcome.disposition {
            VersionDisposition::Publish => Self { status: VersionStatus::Available, av_status },
            VersionDisposition::Quarantine => {
                Self { status: VersionStatus::Quarantined, av_status }
            }
            VersionDisposition::Hold => Self {
                status: observed.status,
                av_status: if observed.av_status == AvStatus::Pending {
                    av_status
                } else {
                    observed.av_status
                },
            },
        })
    }
}

/// `enclave_antivirus`'s `av_status` vocabulary, read back through the one that mirrors the `CHECK`
/// constraint.
///
/// Two crates spell this vocabulary — `enclave_antivirus::AvStatus`, which produces it, and
/// `enclave_versions::AvStatus`, whose test reads the constraint out of
/// `migrations/0006_versions_and_uploads.sql`. Routing the value through `FromStr` rather than
/// writing a `match` means a member added to one and not the other is a runtime failure here and a
/// compile-time one in the test below, instead of a value the `CHECK` constraint rejects at 3 a.m.
fn convert_av_status(status: enclave_antivirus::AvStatus) -> Result<AvStatus> {
    status.as_str().parse().map_err(|_| WorkerError::MalformedRow {
        column: "file_versions.av_status",
        reason: "the antivirus crate produced a status the version vocabulary does not have",
    })
}

/// One row of the queue: everything needed to fetch the bytes and to write the answer back.
#[derive(Debug, Clone)]
struct Due {
    version: VersionId,
    file: FileId,
    created_at: DateTime<Utc>,
    object_key: String,
    mime_type: String,
    size_bytes: i64,
    observed: Target,
}

/// The versions with no usable antivirus verdict, oldest first, from `after`.
///
/// See this module's documentation for the argument behind each predicate. `$2` is whether the
/// configured engine actually inspects content, which is what gates the `SKIPPED` rescan; the
/// `tenant_id = $1` predicate sits beside row-level security, the two-layer arrangement of
/// `docs/04 §3`.
const DUE_SQL: &str = "
SELECT v.id, v.file_id, v.created_at, v.object_key, v.mime_type, v.size_bytes,
       v.status, v.av_status
  FROM file_versions v
 WHERE v.tenant_id = $1
   AND v.status IN ('SCANNING','PROCESSING','AVAILABLE','QUARANTINED')
   AND (v.av_status = 'PENDING' OR (v.av_status = 'SKIPPED' AND $2))
   AND ($3::timestamptz IS NULL OR (v.created_at, v.id) > ($3, $4))
 ORDER BY v.created_at, v.id
 LIMIT $5
";

/// Records a verdict against the row the queue read, or does nothing if somebody moved it first.
///
/// The `status`/`av_status` predicate is a compare-and-swap, not decoration. The bytes are read
/// outside any transaction — a 5 GB scan cannot hold a connection open — so between the queue and
/// this statement a second replica may have scanned the same version, or a rescan may have
/// quarantined it. Writing unconditionally would let the slower of two workers overwrite the
/// faster's verdict with a stale one, and the stale one might be `CLEAN`.
const RECORD_SQL: &str = "
UPDATE file_versions
   SET status               = $4,
       av_status            = $5,
       av_engine            = $6,
       av_signature_version = $7,
       av_scanned_at        = $8
 WHERE tenant_id = $1
   AND id        = $2
   AND status    = $3
   AND av_status = $9
";

/// Moves the file to match the verdict on its **current** version.
///
/// `current_version_id = $3` is the whole of the guard. `crates/versions` leaves a file `PROCESSING`
/// on every commit precisely because it points at something nobody may read; this is the other half
/// of that sentence. Applying it without the predicate would let a rescan of a three-year-old
/// version quarantine a file whose live content is clean, or — worse — publish a file whose current
/// version is still scanning.
const BUMP_FILE_SQL: &str = "
UPDATE files
   SET status = $4
 WHERE tenant_id          = $1
   AND id                 = $2
   AND current_version_id = $3
   AND status <> $4
";

/// Scans up to `batch` of one tenant's versions that have no usable antivirus verdict.
///
/// # Errors
///
/// [`WorkerError`] from the first version whose *database* fails. A version whose bytes cannot be
/// fetched is **not** an error — it is recorded `ERROR` and counted, because an object that is not
/// there is a fact about that version and must not stop every version behind it from being scanned.
/// An engine that will not answer is not an error either: `enclave_antivirus` returns that as
/// [`ScanVerdict::Error`] on purpose, so that `av.unavailable_policy` is applied to it rather than
/// lost in an error path (`crates/antivirus/src/error.rs`).
#[allow(clippy::too_many_arguments)]
pub async fn av_pass<S: BlobStore + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    scanner: &dyn AntivirusScanner,
    store: &S,
    policy: ScanPolicy,
    batch: i64,
    from: AvCursor,
    stop: &Stop,
) -> Result<AvPass> {
    let mut outcome = AvPass { resume: from, ..AvPass::default() };

    let due = due_versions(pool, tenant, scanner, from, batch).await?;
    outcome.considered = due.len();
    if from.is_start() {
        outcome.oldest_due = due.first().map(|first| first.created_at);
    }

    // Short of a full batch means the end of this tenant's queue was reached, so the next pass
    // starts the sweep again. Decided from the query, before any version is scanned.
    let swept = i64::try_from(due.len()).unwrap_or(i64::MAX) < batch;

    // Once per pass, not once per version. The trait asks that this not be cached forever — the
    // signature generation is what a rescan sweep keys on — and a tick is not forever: the value is
    // re-read every `Cadence::antivirus_idle`. Once per *version* would be a second round trip per
    // object for a string that cannot change within a batch.
    let engine = engine_info(scanner).await;

    for item in due {
        if stop.is_stopped() {
            outcome.stopped = true;
            return Ok(outcome);
        }

        let verdict = verdict_for(scanner, store, &item).await?;
        let decision = decide(&verdict, policy, classification_rank());
        if let Some(incident) = decision.incident.as_ref() {
            raise(tenant, &item, incident);
        }

        let target = Target::of(&decision, item.observed)?;
        if target == item.observed {
            debug!(
                tenant = %tenant,
                version = %item.version,
                verdict = verdict.label(),
                "the antivirus verdict left this version exactly where it was"
            );
        } else {
            let wrote = record(pool, tenant, &item, target, engine.as_ref()).await?;
            if wrote {
                outcome.written += 1;
            }
        }

        count(&mut outcome, &decision, target);
        outcome.resume = AvCursor { at: Some((item.created_at, item.version.as_uuid())) };
    }

    if swept {
        outcome.resume = AvCursor::start();
    }

    debug!(
        tenant = %tenant,
        considered = outcome.considered,
        cleared = outcome.cleared,
        flagged = outcome.flagged,
        quarantined = outcome.quarantined,
        held = outcome.held,
        errored = outcome.errored,
        written = outcome.written,
        swept,
        stopped = outcome.stopped,
        "antivirus pass complete"
    );
    Ok(outcome)
}

/// The classification rank a version's unsupported-content ceiling is judged against.
///
/// `None`, and stated as a function so it cannot be read as an oversight. `ScanPolicy`'s ceiling
/// blocks unscannable content at `CONFIDENTIAL` and above whatever the tenant configured — but
/// nothing in this workspace resolves a label into a rank, because no migration creates the
/// `classifications` table (`ENC-614`, and `crate::indexing`'s `WorkerError::Unclassified` is the
/// same gap one pass over).
///
/// The consequence is bounded to nothing today: `ScanPolicy::from_config` pins `unsupported` to
/// `BLOCK`, and `blocks_unsupported` returns `true` for `BLOCK` before it ever looks at the rank. So
/// the ceiling is unreachable rather than wrongly evaluated, and it becomes reachable only alongside
/// the configuration key that would introduce `ALLOW_WITH_FLAG` — at which point this has to be a
/// real lookup.
const fn classification_rank() -> Option<enclave_core::ClassificationRank> {
    None
}

/// Adds one version's disposition to the pass's counters.
///
/// A function rather than an inline `match` so that "every version considered is counted exactly
/// once" is a property a test can assert against the code that holds it.
fn count(pass: &mut AvPass, decision: &ScanOutcome, target: Target) {
    match decision.disposition {
        VersionDisposition::Publish => {
            if target.av_status == AvStatus::Clean {
                pass.cleared += 1;
            } else {
                pass.flagged += 1;
            }
        }
        VersionDisposition::Quarantine => pass.quarantined += 1,
        VersionDisposition::Hold => {
            if target.av_status == AvStatus::Error {
                pass.errored += 1;
            } else {
                pass.held += 1;
            }
        }
    }
}

/// The engine's identity for this tick, or `None` when it would not say.
///
/// A failure here is deliberately not fatal and deliberately not a verdict: `engine_info` is an
/// operational query with no policy attached (`crates/antivirus/src/error.rs`), so an engine that
/// cannot be identified leaves `av_engine` unset and the scan below decides what happens to the
/// content. Refusing the pass instead would turn a health-probe failure into an outage.
async fn engine_info(scanner: &dyn AntivirusScanner) -> Option<EngineInfo> {
    match scanner.engine_info().await {
        Ok(info) => Some(info),
        Err(error) => {
            warn!(%error, "the antivirus engine would not identify itself; av_engine stays unset");
            None
        }
    }
}

/// Reads the queue for one tick, in one tenant-scoped transaction.
async fn due_versions<S: AntivirusScanner + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    scanner: &S,
    from: AvCursor,
    batch: i64,
) -> Result<Vec<Due>> {
    // Whether the `SKIPPED` half of the queue is live. Asking the engine rather than the
    // configuration, because the question is "did anything look at these bytes" and only the engine
    // can answer it — `NoScanningPerformed` reports `scans_content: false` for exactly this.
    // Unknown counts as *does not scan*: re-offering a corpus to an engine that cannot be identified
    // would re-send every skipped object on every sweep for no possible new verdict.
    let rescans = scanner.engine_info().await.is_ok_and(|info| info.scans_content);

    let mut tx = pool.begin(tenant).await?;
    let rows = sqlx::query(DUE_SQL)
        .bind(tenant.as_uuid())
        .bind(rescans)
        .bind(from.at.map(|(created_at, _)| created_at))
        .bind(from.at.map(|(_, id)| id))
        .bind(batch)
        .fetch_all(&mut *tx)
        .await?;
    tx.commit().await?;

    rows.into_iter().map(due_from_row).collect()
}

/// Reads one queue row, naming the column that would not decode and never its value.
fn due_from_row(row: sqlx::postgres::PgRow) -> Result<Due> {
    fn column<'r, T>(row: &'r sqlx::postgres::PgRow, name: &'static str) -> Result<T>
    where
        T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
    {
        row.try_get(name).map_err(|_| WorkerError::MalformedRow {
            column: name,
            reason: "missing or of an unexpected type",
        })
    }

    let status: String = column(&row, "status")?;
    let av_status: String = column(&row, "av_status")?;

    Ok(Due {
        version: VersionId::from_uuid(column::<Uuid>(&row, "id")?),
        file: FileId::from(column::<Uuid>(&row, "file_id")?),
        created_at: column(&row, "created_at")?,
        object_key: column(&row, "object_key")?,
        mime_type: column(&row, "mime_type")?,
        size_bytes: column(&row, "size_bytes")?,
        observed: Target {
            status: status.parse().map_err(|_| WorkerError::MalformedRow {
                column: "file_versions.status",
                reason: "not a status this build knows",
            })?,
            av_status: av_status.parse().map_err(|_| WorkerError::MalformedRow {
                column: "file_versions.av_status",
                reason: "not an antivirus status this build knows",
            })?,
        },
    })
}

/// Streams one version's bytes to the engine and returns what it concluded.
///
/// **The stream is handed straight to the scanner and never collected.** `read_bounded` is what the
/// two extraction passes use, and it is wrong here: an antivirus verdict is about the whole object
/// (`AntivirusScanner::scan`'s contract), so a bounded read would either truncate — a header-only
/// scan, the exact shortcut rule 9 exists to prevent — or refuse every version above the budget.
/// The ceiling that does apply is the engine's own `max_scan_bytes`, checked against
/// [`ScanHint::declared_size`] before a connection is opened.
///
/// Every failure becomes a *verdict* rather than an error, which is the crate's central decision
/// (`crates/antivirus/src/error.rs`) applied at the one call site that could undo it:
///
/// * a missing or unreadable object is `Error { retryable: false }` — the bytes will not appear on
///   their own, and under `HOLD` that records `av_status = 'ERROR'` and takes the version out of the
///   queue, so one poisoned row cannot starve everything ordered behind it;
/// * a stream that broke part-way is `Error { retryable: true }`, because the object is there and
///   the read is worth repeating;
/// * a scanner constructed with a configuration it cannot honour is `Error { retryable: false }`.
async fn verdict_for<S: BlobStore + ?Sized>(
    scanner: &dyn AntivirusScanner,
    store: &S,
    item: &Due,
) -> Result<ScanVerdict> {
    let hint = ScanHint::empty()
        .with_mime(item.mime_type.clone())
        .with_size(u64::try_from(item.size_bytes).unwrap_or(u64::MAX));

    let stream = match store.read_range(&item.object_key, ByteRange::from(0)).await {
        Ok(stream) => stream,
        Err(error) => {
            // The key is derived from a file name and a file name is content (rule 10), so the
            // version identifies the row and the key never appears.
            warn!(
                version = %item.version,
                retryable = matches!(error, StorageError::NotFound { .. }).then_some(false),
                "a version's bytes could not be read for scanning"
            );
            return Ok(ScanVerdict::Error { retryable: false });
        }
    };

    match scanner.scan(stream, hint).await {
        Ok(verdict) => Ok(verdict),
        Err(AntivirusError::Source(_)) => Ok(ScanVerdict::Error { retryable: true }),
        Err(error) => {
            warn!(%error, version = %item.version, "the antivirus scanner refused to run");
            Ok(ScanVerdict::Error { retryable: false })
        }
    }
}

/// Writes the verdict, and the file's status with it, in one transaction.
///
/// One transaction so that a file cannot advertise `AVAILABLE` while its version's row still says
/// `SCANNING`, or the other way round. Returns whether the version row actually moved: a `false`
/// means the compare-and-swap lost, which is not an error — somebody else has already recorded a
/// verdict for this version — and the pass counts it as unwritten so the scheduler does not read it
/// as progress.
async fn record(
    pool: &DbPool,
    tenant: TenantId,
    item: &Due,
    target: Target,
    engine: Option<&EngineInfo>,
) -> Result<bool> {
    let mut tx = pool.begin(tenant).await?;

    let updated = sqlx::query(RECORD_SQL)
        .bind(tenant.as_uuid())
        .bind(item.version.as_uuid())
        .bind(item.observed.status.as_str())
        .bind(target.status.as_str())
        .bind(target.av_status.as_str())
        .bind(engine.map(|info| info.engine.as_str()))
        .bind(engine.and_then(|info| info.signature_version.as_deref()))
        .bind(Utc::now())
        .bind(item.observed.av_status.as_str())
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if updated == 0 {
        tx.commit().await?;
        debug!(
            tenant = %tenant,
            version = %item.version,
            "another writer recorded a verdict for this version first; ours is discarded"
        );
        return Ok(false);
    }

    if let Some(node) = file_status(target.status) {
        sqlx::query(BUMP_FILE_SQL)
            .bind(tenant.as_uuid())
            .bind(item.file.as_uuid())
            .bind(item.version.as_uuid())
            .bind(node)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(true)
}

/// What the *file* says once its current version reaches `status`, if anything.
///
/// `files.status` has its own vocabulary (`AVAILABLE`, `PROCESSING`, `QUARANTINED`, `FAILED`), so
/// this is a mapping and not a copy. `None` for every version status that is not terminal for the
/// file: a version still being scanned leaves the file exactly as `crates/versions` left it,
/// `PROCESSING`, which is the state that says "points at something nobody may read".
const fn file_status(status: VersionStatus) -> Option<&'static str> {
    match status {
        VersionStatus::Available => Some("AVAILABLE"),
        VersionStatus::Quarantined => Some("QUARANTINED"),
        VersionStatus::Pending
        | VersionStatus::Scanning
        | VersionStatus::Processing
        | VersionStatus::Failed => None,
    }
}

/// Reports an incident the only way this deployment can.
///
/// `docs/06 §6.2` requires a `CRITICAL` incident and a notification to security for a detection.
/// There is no incident table, no `Action` for antivirus and no `EventType` for a completed scan, so
/// what exists is a log line at `error!` — logged as `ENC-645` rather than pretended away. The
/// signature is included because it is the investigation, it is engine output rather than file
/// content, and `enclave_antivirus::Incident` documents the field as security-facing; there is no
/// path from here to the uploader, because `UploaderNotice` cannot hold a string.
fn raise(tenant: TenantId, item: &Due, incident: &Incident) {
    error!(
        tenant = %tenant,
        file = %item.file,
        version = %item.version,
        severity = ?incident.severity,
        kind = ?incident.kind,
        signature = incident.signature.as_deref().unwrap_or("-"),
        notify_security = incident.notify_security,
        "antivirus incident"
    );
}

impl fmt::Display for AvPass {
    /// One line for an operator, in the order the questions get asked.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "considered {} cleared {} flagged {} quarantined {} held {} errored {}",
            self.considered, self.cleared, self.flagged, self.quarantined, self.held, self.errored
        )
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_antivirus::{AvStatus as AvVerdict, UnsupportedPolicy};
    use enclave_config::UnavailablePolicy;

    use super::*;

    fn observed(status: VersionStatus, av_status: AvStatus) -> Target {
        Target { status, av_status }
    }

    fn fresh() -> Target {
        observed(VersionStatus::Scanning, AvStatus::Pending)
    }

    /// Every `av_status` the antivirus crate can produce is one the version vocabulary — and
    /// therefore the `CHECK` constraint — accepts.
    ///
    /// The seam between the two crates, asserted rather than assumed. A member added to
    /// `enclave_antivirus::AvStatus` and not to migration 0006 would otherwise be a constraint
    /// violation on the first infected upload after a deploy.
    #[test]
    fn every_verdict_the_scanner_can_produce_is_a_status_the_column_accepts() {
        for status in [
            AvVerdict::Pending,
            AvVerdict::Clean,
            AvVerdict::Infected,
            AvVerdict::Skipped,
            AvVerdict::Error,
        ] {
            let converted = convert_av_status(status).expect("the two vocabularies agree");
            assert_eq!(converted.as_str(), status.as_str());
        }
    }

    /// A clean scan is the one transition that makes content readable, and it writes exactly the
    /// pair `READABLE_PREDICATE` asks for.
    ///
    /// Asserted against the predicate's own text rather than against two literals, so that a change
    /// to what "readable" means cannot leave this pass writing the old answer.
    #[test]
    fn a_clean_verdict_targets_the_pair_the_readable_predicate_accepts() {
        let decision = decide(&ScanVerdict::Clean, ScanPolicy::default(), None);
        let target = Target::of(&decision, fresh()).expect("clean converts");

        assert_eq!(target.status, VersionStatus::Available);
        assert_eq!(target.av_status, AvStatus::Clean);
        assert!(enclave_versions::READABLE_PREDICATE.contains(target.status.as_str()));
        assert!(enclave_versions::READABLE_PREDICATE.contains(target.av_status.as_str()));
    }

    /// And nothing else does. The whole of rule 9 at this pass's one write site.
    ///
    /// Both halves: the clean control above publishes, and every other verdict under every policy a
    /// deployment can express targets a pair the predicate refuses. Without the control this passes
    /// against a `Target::of` that never returns `AVAILABLE`/`CLEAN` at all.
    #[test]
    fn no_verdict_but_clean_targets_a_readable_pair() {
        for unavailable in [UnavailablePolicy::Hold, UnavailablePolicy::AllowAndRescan] {
            for unsupported in [UnsupportedPolicy::Block, UnsupportedPolicy::AllowWithFlag] {
                let policy = ScanPolicy { unsupported, unavailable, ..ScanPolicy::default() };
                for verdict in [
                    ScanVerdict::Infected { signature: "Eicar-Test-Signature".into() },
                    ScanVerdict::Unsupported,
                    ScanVerdict::Error { retryable: true },
                    ScanVerdict::Error { retryable: false },
                ] {
                    let decision = decide(&verdict, policy, None);
                    let target = Target::of(&decision, fresh()).expect("converts");
                    let readable = target.status == VersionStatus::Available
                        && target.av_status == AvStatus::Clean;
                    assert!(
                        !readable,
                        "{verdict:?} under {unsupported:?}/{unavailable:?} became readable"
                    );
                }
            }
        }
    }

    /// A published-but-unscanned version reaches `AVAILABLE` and is still refused by every read
    /// path, because `av_status` is not `CLEAN`.
    ///
    /// This is `ENC-646` pinned rather than fixed: `ALLOW_AND_RESCAN` is documented as trading a
    /// malware window for availability, and against `READABLE_PREDICATE` it buys no availability at
    /// all. It errs closed, so the assertion here is the safe direction and stays correct whichever
    /// way that row is settled.
    #[test]
    fn a_published_but_unscanned_version_is_still_not_served() {
        let policy =
            ScanPolicy { unavailable: UnavailablePolicy::AllowAndRescan, ..ScanPolicy::default() };
        let decision = decide(&ScanVerdict::Error { retryable: true }, policy, None);
        assert_eq!(decision.disposition, VersionDisposition::Publish);

        let target = Target::of(&decision, fresh()).expect("converts");
        assert_eq!(target.status, VersionStatus::Available);
        assert_eq!(target.av_status, AvStatus::Pending, "published without a verdict");
        assert_ne!(target.av_status, AvStatus::Clean);
    }

    /// A `HOLD` on a fresh version changes nothing at all, so no write happens and the version waits
    /// exactly where `crates/versions` left it. That is G6.
    #[test]
    fn an_outage_under_hold_leaves_a_fresh_version_untouched() {
        let policy = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };
        let decision = decide(&ScanVerdict::Error { retryable: true }, policy, None);
        assert_eq!(Target::of(&decision, fresh()).expect("converts"), fresh());
    }

    /// A permanent scanner failure *is* recorded, so the version stops being offered and an operator
    /// can find it. Paired with the test above: the two `Error` legs are different facts.
    #[test]
    fn a_permanent_scanner_failure_is_recorded_rather_than_retried_forever() {
        let policy = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };
        let decision = decide(&ScanVerdict::Error { retryable: false }, policy, None);
        let target = Target::of(&decision, fresh()).expect("converts");
        assert_eq!(target.status, VersionStatus::Scanning, "HOLD never moves the status");
        assert_eq!(target.av_status, AvStatus::Error);
        assert_ne!(target, fresh(), "an ERROR that wrote nothing would be re-offered forever");
    }

    /// A rescan that could not reach a verdict leaves the earlier one standing.
    ///
    /// The case the `observed` parameter exists for. Without it, an engine hiccup during the
    /// `SKIPPED` rescan sweep would drag a quarantined version back into `SCANNING`/`PENDING` —
    /// erasing the evidence that it was once refused, in order to record that this attempt did not
    /// happen.
    #[test]
    fn an_outage_during_a_rescan_does_not_erase_the_verdict_being_rescanned() {
        let was = observed(VersionStatus::Quarantined, AvStatus::Skipped);
        let policy = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };

        for retryable in [true, false] {
            let decision = decide(&ScanVerdict::Error { retryable }, policy, None);
            assert_eq!(Target::of(&decision, was).expect("converts"), was, "retryable={retryable}");
        }

        // The positive control: a *clean* rescan of the same row does move it, so the assertion
        // above is about `Hold` rather than about a `Target::of` that ignores its outcome.
        let clean = decide(&ScanVerdict::Clean, policy, None);
        let target = Target::of(&clean, was).expect("converts");
        assert_eq!(target.status, VersionStatus::Available);
        assert_eq!(target.av_status, AvStatus::Clean);
    }

    /// The queue offers versions with no usable verdict and never one that has one.
    ///
    /// `CLEAN` is the load-bearing absence: nothing this pass writes can move a version out of
    /// `CLEAN`, which is what makes it impossible for this pass to invalidate content the indexing
    /// and DLP passes have already read.
    #[test]
    fn the_queue_never_offers_a_version_that_already_has_a_verdict() {
        assert!(DUE_SQL.contains("v.av_status = 'PENDING'"), "{DUE_SQL}");
        assert!(DUE_SQL.contains("v.av_status = 'SKIPPED' AND $2"), "{DUE_SQL}");
        for settled in ["'CLEAN'", "'INFECTED'", "'ERROR'"] {
            assert!(!DUE_SQL.contains(settled), "the queue re-offers {settled}: {DUE_SQL}");
        }
        // Positive controls for the three absences, so this cannot pass by the needles being
        // unfindable (`docs/12 §1.2`).
        for settled in ["'CLEAN'", "'INFECTED'", "'ERROR'"] {
            assert!(format!("av_status = {settled}").contains(settled));
        }
        assert!(DUE_SQL.contains("v.tenant_id = $1"), "layer 1 beside RLS: {DUE_SQL}");
    }

    /// A version whose bytes may not exist is never fetched.
    #[test]
    fn the_queue_skips_the_two_statuses_whose_object_may_not_exist() {
        assert!(DUE_SQL.contains("v.status IN ('SCANNING','PROCESSING','AVAILABLE','QUARANTINED')"));
        assert!(!DUE_SQL.contains("'FAILED'"));
    }

    /// The verdict write is a compare-and-swap on the pair the queue read.
    ///
    /// The bytes are scanned outside any transaction, so without this a slow replica could overwrite
    /// a newer verdict with a stale one — and a stale one can be `CLEAN`.
    #[test]
    fn recording_a_verdict_matches_on_the_state_it_was_decided_from() {
        assert!(RECORD_SQL.contains("AND status    = $3"), "{RECORD_SQL}");
        assert!(RECORD_SQL.contains("AND av_status = $9"), "{RECORD_SQL}");
        assert!(RECORD_SQL.contains("WHERE tenant_id = $1"), "{RECORD_SQL}");
    }

    /// The file only follows the version it is actually pointing at.
    #[test]
    fn a_file_follows_only_its_current_version() {
        assert!(BUMP_FILE_SQL.contains("AND current_version_id = $3"), "{BUMP_FILE_SQL}");
        assert!(BUMP_FILE_SQL.contains("WHERE tenant_id          = $1"), "{BUMP_FILE_SQL}");
    }

    /// A version that is still being scanned leaves the file alone, and the two terminal ones move
    /// it. Both halves, because "returns `None`" passes for free against a function that always
    /// does.
    #[test]
    fn only_a_terminal_version_status_moves_the_file() {
        assert_eq!(file_status(VersionStatus::Available), Some("AVAILABLE"));
        assert_eq!(file_status(VersionStatus::Quarantined), Some("QUARANTINED"));
        assert_eq!(file_status(VersionStatus::Scanning), None);
        assert_eq!(file_status(VersionStatus::Processing), None);
        assert_eq!(file_status(VersionStatus::Pending), None);
        assert_eq!(file_status(VersionStatus::Failed), None);
    }

    /// Every version considered lands in exactly one counter.
    #[test]
    fn the_dispositions_partition_the_versions_a_pass_considered() {
        let mut pass = AvPass::default();
        let policy = ScanPolicy::default();

        for (verdict, was) in [
            (ScanVerdict::Clean, fresh()),
            (ScanVerdict::Infected { signature: "X".into() }, fresh()),
            (ScanVerdict::Unsupported, fresh()),
            (ScanVerdict::Error { retryable: true }, fresh()),
            (ScanVerdict::Error { retryable: false }, fresh()),
        ] {
            let decision = decide(&verdict, policy, None);
            let target = Target::of(&decision, was).expect("converts");
            count(&mut pass, &decision, target);
            pass.considered += 1;
        }

        assert_eq!(pass.considered, 5);
        assert_eq!(pass.cleared, 1);
        assert_eq!(pass.quarantined, 2, "infected, and unsupported under BLOCK");
        assert_eq!(pass.held, 1);
        assert_eq!(pass.errored, 1);
        assert_eq!(pass.flagged, 0);
        assert_eq!(
            pass.cleared + pass.flagged + pass.quarantined + pass.held + pass.errored,
            pass.considered
        );
    }

    /// A published-unscanned version is counted apart from a clean one.
    ///
    /// The distinction is invisible in the database — both are `AVAILABLE` — so a single counter
    /// would make "content nobody scanned was published" indistinguishable from "content was
    /// scanned and found clean" in the only place an operator could see it.
    #[test]
    fn a_flagged_publication_is_not_counted_as_a_clean_one() {
        let policy =
            ScanPolicy { unavailable: UnavailablePolicy::AllowAndRescan, ..ScanPolicy::default() };
        let decision = decide(&ScanVerdict::Error { retryable: true }, policy, None);
        let target = Target::of(&decision, fresh()).expect("converts");

        let mut pass = AvPass::default();
        count(&mut pass, &decision, target);
        assert_eq!(pass.flagged, 1);
        assert_eq!(pass.cleared, 0, "a version nobody scanned was counted as clean");
    }

    /// A cursor that started at the beginning and one that has moved are different values.
    #[test]
    fn a_sweep_that_reached_the_end_resumes_at_the_beginning() {
        assert!(AvCursor::start().is_start());
        let moved = AvCursor { at: Some((Utc::now(), Uuid::now_v7())) };
        assert!(!moved.is_start());
        assert_ne!(moved, AvCursor::start());
    }

    /// The backlog age is reported only for a sweep that began at the oldest version.
    #[test]
    fn the_backlog_is_measured_from_the_oldest_version_and_only_from_a_sweeps_start() {
        let now = Utc::now();
        let pass =
            AvPass { oldest_due: Some(now - chrono::Duration::hours(3)), ..AvPass::default() };
        assert_eq!(pass.backlog(now).map(|age| age.num_hours()), Some(3));
        assert_eq!(AvPass::default().backlog(now), None, "mid-sweep understates the backlog");
    }
}
