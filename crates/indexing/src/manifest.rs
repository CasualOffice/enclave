//! `index_manifests` — what the index believes about each file, and the only way to change it.
//!
//! The second half of `ENC-527`. [`crate::pipeline`] decides what a version's manifest should say;
//! this writes it.
//!
//! # There is no way to set a status directly, and that is the design
//!
//! [`record`] takes an [`Outcome`], not a [`ManifestStatus`]. The status, the failure reason and the
//! chunk count are all derived from it, so the three cannot disagree — and, more importantly,
//! `READY` cannot be written by a caller who has no chunks, because `Outcome::Ready` carries a
//! `NonZeroU32` and is the only variant that maps to it.
//!
//! A `set_status(file, READY)` would undo that in one line, from a call site that looked reasonable
//! — the retry path, the backfill script, the "just mark these done" migration. So it does not
//! exist. The states a *worker* moves through on its way to an outcome ([`start`]) are a separate,
//! smaller function that cannot write a terminal state at all.
//!
//! # Claiming
//!
//! [`claim`] uses `FOR UPDATE SKIP LOCKED`, following `crates/worker`'s reconciler (`ENC-518`): two
//! workers partition the queue rather than contend on it, and a row already being worked is skipped
//! rather than waited for. `updated_at` ordering makes the queue oldest-first, so a file that keeps
//! failing does not starve the rest — it gets retried when it comes round again, with `attempts`
//! recording how often.
//!
//! # Why `attempts` increments only on failure
//!
//! A success ends the row's life as work, so counting successes would only make the column mean two
//! things. `attempts` exists so a supervisor can tell a file that failed once from one that has
//! failed forty times, which is the difference between a transient extractor error and a document
//! that will never index.

use enclave_core::{FileId, TenantId, VersionId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::chunk::ChunkerVersion;
use crate::error::IndexingError;
use crate::model::ExtractorVersion;
use crate::pipeline::{ManifestStatus, Outcome};
use crate::Result;

/// One file the worker has claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    /// The file to index.
    pub file_id: FileId,
    /// The version its manifest names.
    pub version_id: VersionId,
    /// How many times this file has already been attempted and failed.
    pub attempts: i32,
}

/// Records that a version needs indexing, leaving any existing row's history intact.
///
/// Idempotent: an outbox delivers at least once, so the second call for the same version must not
/// reset `attempts` or lose the fact that it has failed before.
///
/// A *new* version of a file replaces the old row's `version_id` and returns it to `PENDING`,
/// because the manifest describes the file's current indexed state and the previous version's is no
/// longer it.
///
/// # Errors
///
/// Storage failures.
pub async fn enqueue(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    version: VersionId,
) -> Result<()> {
    sqlx::query(ENQUEUE_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(version.as_uuid())
        .execute(&mut *conn)
        .await
        .map_err(IndexingError::Storage)?;
    Ok(())
}

/// Claims up to `limit` files for this worker, oldest first.
///
/// Rows another worker holds are skipped, not waited for. The claim marks them `EXTRACTING`, so a
/// crash between claiming and recording leaves a row visibly stuck in a working state rather than
/// silently back in the queue — a supervisor can find it, and `attempts` tells it how long it has
/// been going round.
///
/// # Errors
///
/// Storage failures.
pub async fn claim(conn: &mut PgConnection, tenant: TenantId, limit: i64) -> Result<Vec<Claimed>> {
    let rows = sqlx::query(CLAIM_SQL)
        .bind(tenant.as_uuid())
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(IndexingError::Storage)?;

    rows.into_iter()
        .map(|row| {
            let file: Uuid = row.try_get("file_id").map_err(IndexingError::Storage)?;
            let version: Uuid = row.try_get("version_id").map_err(IndexingError::Storage)?;
            let attempts: i32 = row.try_get("attempts").map_err(IndexingError::Storage)?;
            Ok(Claimed {
                file_id: FileId::from_uuid(file),
                version_id: VersionId::from_uuid(version),
                attempts,
            })
        })
        .collect()
}

/// Moves a claimed row into a non-terminal working state.
///
/// Deliberately cannot write a terminal one: [`WorkingState`] has no `Ready` or `Failed`, so the
/// only way to finish a row is [`record`], which requires an [`Outcome`].
///
/// # Errors
///
/// Storage failures.
pub async fn start(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    state: WorkingState,
) -> Result<()> {
    sqlx::query(START_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(state.status().as_str())
        .execute(&mut *conn)
        .await
        .map_err(IndexingError::Storage)?;
    Ok(())
}

/// Returns a claimed row to the queue without recording an attempt.
///
/// For the case the worker cannot act on and must not judge: a version whose antivirus scan has not
/// finished. `CLAUDE.md` rule 9 says nothing serves content before the scan completes, and indexing
/// reads content — so the file is not indexable *yet*, which is a different fact from failing to
/// index.
///
/// Recording it as `FAILED` would be wrong twice: `attempts` would climb for a file nothing is
/// wrong with, and a supervisor watching that column would eventually escalate a document that is
/// simply waiting. Leaving it `EXTRACTING` would be worse — it would never be claimed again.
///
/// `updated_at` moves, so the row goes to the back of the oldest-first queue rather than being
/// re-claimed immediately in a hot loop. That is the whole rate limit, and it is enough: the queue
/// drains in order, so a scanning file is retried once per pass at most.
///
/// # Errors
///
/// Storage failures.
pub async fn defer(conn: &mut PgConnection, tenant: TenantId, file: FileId) -> Result<()> {
    sqlx::query(DEFER_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .execute(&mut *conn)
        .await
        .map_err(IndexingError::Storage)?;
    Ok(())
}

/// The states a worker passes through, none of which is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkingState {
    /// Producing vectors from stored chunks.
    Embedding,
    /// Writing vectors to the index.
    Indexing,
}

impl WorkingState {
    /// The manifest status this working state corresponds to.
    #[must_use]
    pub const fn status(self) -> ManifestStatus {
        match self {
            Self::Embedding => ManifestStatus::Embedding,
            Self::Indexing => ManifestStatus::Indexing,
        }
    }
}

/// Records the terminal result of indexing one version.
///
/// The status, the failure reason and the chunk count all come from `outcome` — see the module
/// documentation for why this takes an outcome rather than a status.
///
/// `attempts` increments only when the outcome is not `READY`, and `indexed_at` is set only when it
/// is. A `READY` row therefore always carries the time its text became searchable, and a failing row
/// carries a count that grows.
///
/// Takes a `&mut PgConnection` so the caller can run it in the same transaction as
/// [`crate::write_chunks`]. That is not a convenience: a manifest saying `READY` over chunk text
/// that was never committed is the same confidently-wrong answer as chunk text with no manifest,
/// approached from the other side.
///
/// # Errors
///
/// Storage failures.
pub async fn record(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    version: VersionId,
    versions: BuildVersions<'_>,
    outcome: &Outcome,
) -> Result<()> {
    let status = outcome.status();
    let chunk_count = i32::try_from(outcome.chunk_count()).map_err(|_| {
        IndexingError::Storage(sqlx::Error::Protocol(
            "a chunk count too large for index_manifests.chunk_count".to_owned(),
        ))
    })?;

    sqlx::query(RECORD_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(version.as_uuid())
        .bind(status.as_str())
        .bind(chunk_count)
        .bind(outcome.reason().map(|reason| reason.as_str()))
        .bind(versions.extractor.as_str())
        .bind(versions.chunker.as_str())
        .bind(versions.embedding_model)
        .execute(&mut *conn)
        .await
        .map_err(IndexingError::Storage)?;
    Ok(())
}

/// Which builds produced this manifest, for `docs/07 §3`'s reindex trigger.
///
/// Grouped rather than passed as three strings so a call site cannot transpose the extractor and the
/// chunker — they are both short version strings, and swapping them would make every file look
/// reindexable forever while nothing was actually wrong.
#[derive(Debug, Clone, Copy)]
pub struct BuildVersions<'a> {
    /// The extractor build.
    pub extractor: ExtractorVersion,
    /// The chunker build.
    pub chunker: ChunkerVersion,
    /// The embedding model, or `""` where nothing has embedded yet.
    pub embedding_model: &'a str,
}

/// Upsert on `(tenant_id, file_id)`. A new `version_id` returns the row to `PENDING` and clears the
/// previous run's failure, because that failure was about different bytes.
const ENQUEUE_SQL: &str = "
INSERT INTO index_manifests
       (tenant_id, file_id, version_id, index_version, extractor_version, chunker_version,
        embedding_model, status, chunk_count, attempts, updated_at)
VALUES ($1, $2, $3, 1, '', '', '', 'PENDING', 0, 0, now())
ON CONFLICT (tenant_id, file_id) DO UPDATE
    SET version_id     = EXCLUDED.version_id,
        status         = CASE WHEN index_manifests.version_id = EXCLUDED.version_id
                              THEN index_manifests.status ELSE 'PENDING' END,
        attempts       = CASE WHEN index_manifests.version_id = EXCLUDED.version_id
                              THEN index_manifests.attempts ELSE 0 END,
        failure_reason = CASE WHEN index_manifests.version_id = EXCLUDED.version_id
                              THEN index_manifests.failure_reason ELSE NULL END,
        updated_at     = now()
";

/// `SKIP LOCKED` so two workers partition rather than contend (ENC-518).
///
/// `SKIPPED` is excluded as well as `READY`: it is terminal, and a file nobody has an extractor for
/// would otherwise be re-claimed on every pass forever.
const CLAIM_SQL: &str = "
WITH claimed AS (
    SELECT file_id
      FROM index_manifests
     WHERE tenant_id = $1
       AND status IN ('PENDING', 'STALE')
     ORDER BY updated_at
     LIMIT $2
       FOR UPDATE SKIP LOCKED
)
UPDATE index_manifests AS m
   SET status = 'EXTRACTING', updated_at = now()
  FROM claimed
 WHERE m.tenant_id = $1 AND m.file_id = claimed.file_id
RETURNING m.file_id, m.version_id, m.attempts
";

/// Non-terminal transitions only. Guarded on the row not already being terminal, so a late worker
/// cannot drag a finished row back into a working state.
const START_SQL: &str = "
UPDATE index_manifests
   SET status = $3, updated_at = now()
 WHERE tenant_id = $1 AND file_id = $2
   AND status NOT IN ('READY', 'SKIPPED')
";

/// Back to `PENDING`, and only from a working state: a row that has already reached a terminal
/// status is not the worker's to reopen. `attempts` is untouched — see `defer`.
const DEFER_SQL: &str = "
UPDATE index_manifests
   SET status = 'PENDING', updated_at = now()
 WHERE tenant_id = $1 AND file_id = $2
   AND status IN ('EXTRACTING', 'EMBEDDING', 'INDEXING')
";

/// The one terminal write. `attempts` grows only on failure; `indexed_at` is set only on success.
const RECORD_SQL: &str = "
UPDATE index_manifests
   SET status            = $4,
       chunk_count       = $5,
       failure_reason    = $6,
       extractor_version = $7,
       chunker_version   = $8,
       embedding_model   = $9,
       attempts          = attempts + CASE WHEN $4 = 'READY' THEN 0 ELSE 1 END,
       indexed_at        = CASE WHEN $4 = 'READY' THEN now() ELSE indexed_at END,
       updated_at        = now()
 WHERE tenant_id = $1 AND file_id = $2 AND version_id = $3
";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The public surface must offer no way to write a status directly.
    ///
    /// Asserted over this module's own source, because the guarantee is an *absence* and there is
    /// nothing to call that would prove it. A `set_status` added later — on the retry path, in a
    /// backfill, in a "just mark these done" script — is exactly how `READY` comes to sit over a
    /// file with no chunks, which is the failure `pipeline.rs` spends a type preventing.
    #[test]
    fn nothing_here_lets_a_caller_choose_a_terminal_status() {
        // Asserted over this module's own source, because the guarantee is an *absence*: there is
        // nothing to call that would prove it. A `set_status` added later — on the retry path, in a
        // backfill, in a "just mark these done" script — is exactly how READY comes to sit over a
        // file with no chunks, which is the failure `pipeline.rs` spends a type preventing.
        //
        // The needles are assembled at run time rather than written as literals. The first version
        // of this test spelled them out, so the file contained every string the test was looking
        // for and the test failed against itself — the same shape as the secrets gate's PEM-banner
        // rule in CLAUDE.md, and the same fix.
        let source = include_str!("manifest.rs");
        let status_type = format!("Manifest{}", "Status");

        for forbidden in [
            format!("pub async fn set_{}", "status"),
            format!("pub fn set_{}", "status"),
            format!("status: {status_type}"),
        ] {
            assert!(
                !source.contains(&forbidden),
                "`{forbidden}` would let a caller write a terminal status without an Outcome"
            );
        }

        // `record` is the only public function taking an Outcome, and so the only one that can
        // write a terminal state. If a second appears, this needs rethinking rather than updating.
        let takes_outcome = format!("outcome: &{}", "Outcome");
        assert_eq!(
            source.matches(&takes_outcome).count(),
            1,
            "more than one function now writes a terminal manifest state"
        );
    }

    #[test]
    fn the_working_states_are_all_non_terminal() {
        // A `WorkingState` that mapped to READY or SKIPPED would make `start` a second terminal
        // writer, bypassing `record` and the Outcome it requires.
        for state in [WorkingState::Embedding, WorkingState::Indexing] {
            assert!(
                !matches!(state.status(), ManifestStatus::Ready | ManifestStatus::Skipped),
                "{state:?} maps to a terminal status"
            );
        }
    }

    #[test]
    fn every_status_the_sql_names_is_one_the_migration_permits() {
        // The SQL writes statuses as string literals, so a typo is not a compile error — it is a
        // constraint violation at run time, on one file, on whichever path was not exercised.
        let migration = include_str!("../../../migrations/0011_search.sql");
        let check = migration
            .lines()
            .find(|line| line.contains("status IN ("))
            .expect("0011 declares index_manifests.status with a CHECK listing its values");

        for sql in [ENQUEUE_SQL, CLAIM_SQL, START_SQL, RECORD_SQL] {
            for literal in sql.split('\'').skip(1).step_by(2) {
                // Only the upper-case words are statuses; the rest are column defaults like ''.
                if !literal.is_empty()
                    && literal.chars().all(|c| c.is_ascii_uppercase() || c == '_')
                {
                    assert!(
                        check.contains(&format!("'{literal}'")),
                        "the SQL writes status '{literal}', which migration 0011 does not permit"
                    );
                }
            }
        }
    }
}
