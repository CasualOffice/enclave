//! The retrieval denylist: what makes a revocation take effect before the index hears about it.
//!
//! # Why this is not a job queue
//!
//! `docs/12-TESTING.md §4.3` S3 asks that a revoked file vanish from results **immediately**, before
//! any index update. S4 asks that S3 still hold with the invalidation worker stopped.
//!
//! Those two forbid the design everybody reaches for first — enqueue a job, let a worker remove the
//! document from the vector store. A stopped worker then means a revoked file stays findable *and
//! the search still answers*. Not an outage, which is visible: a wrong answer delivered
//! confidently, which is not.
//!
//! So a revocation writes a row here in the same transaction that changes the ACL
//! (`plans/M3-DISCOVERY.md` D22), and every search reads it. The worker's job is cleanup afterwards,
//! and its absence costs index size, never correctness. S4 is the test that a stopped worker changes
//! nothing a caller can observe.
//!
//! # This is not an access control
//!
//! Worth stating because the name invites the opposite reading. The denylist is an
//! *index-freshness* mechanism. What decides whether a caller may see a file is
//! [`crate::postfilter`], resolving against `acl_entries` — which runs whether or not this table has
//! a row, and which no amount of denylist tampering can widen.
//!
//! That is why migration 0011 grants `DELETE` here without the argument the content tables needed:
//! removing a suppression cannot reveal anything the post-filter would not have allowed anyway. It
//! can only cost freshness.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::SearchError;

/// Which of these files are currently suppressed.
///
/// Takes the candidate set rather than returning the whole denylist: a tenant that has just
/// reorganised its permissions can have a very large one, and a search's latency budget is not the
/// place to discover that.
///
/// A row whose `clears_at` has passed is *not* suppressed — the sweep that removes it is
/// housekeeping, and waiting for housekeeping to make a correct answer correct is the S4 mistake in
/// the opposite direction.
///
/// # Errors
///
/// Storage failures.
pub async fn suppressed(
    conn: &mut PgConnection,
    tenant: TenantId,
    files: &[FileId],
) -> Result<HashSet<FileId>, SearchError> {
    if files.is_empty() {
        return Ok(HashSet::new());
    }

    let ids: Vec<Uuid> = files.iter().map(|file| file.as_uuid()).collect();
    let rows =
        sqlx::query(SUPPRESSED_SQL).bind(tenant.as_uuid()).bind(&ids).fetch_all(&mut *conn).await?;

    rows.iter()
        .map(|row| {
            row.try_get::<Uuid, _>("file_id").map(FileId::from).map_err(|_| {
                SearchError::MalformedRow { column: "file_id", reason: "missing or not a uuid" }
            })
        })
        .collect()
}

/// Suppresses a file from retrieval.
///
/// **Call this in the same transaction as the ACL change that caused it.** A separate transaction
/// leaves a window in which the permission has changed and the index has not been told, and that
/// window is precisely what S3 forbids. Taking a `&mut PgConnection` rather than a pool is what
/// makes it impossible to commit separately (`plans/M1-CONTENT-CORE.md` D10).
///
/// Idempotent: suppressing an already-suppressed file refreshes the reason and the timestamp rather
/// than failing, because the second revocation is as real as the first.
///
/// # Errors
///
/// Storage failures.
pub async fn suppress(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    reason: &str,
    now: DateTime<Utc>,
    clears_at: Option<DateTime<Utc>>,
) -> Result<(), SearchError> {
    sqlx::query(SUPPRESS_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(reason)
        .bind(now)
        .bind(clears_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Lifts suppressions whose `clears_at` has passed.
///
/// The worker's housekeeping. Returns how many were lifted, so a sweep that finds nothing is
/// distinguishable in metrics from a sweep that did not run.
///
/// # Errors
///
/// Storage failures.
pub async fn lift_expired(
    conn: &mut PgConnection,
    tenant: TenantId,
    now: DateTime<Utc>,
) -> Result<u64, SearchError> {
    let lifted = sqlx::query(LIFT_SQL)
        .bind(tenant.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(lifted)
}

/// Rows still in force. A passed `clears_at` is already lifted, whether or not the sweep has run.
const SUPPRESSED_SQL: &str = "
SELECT d.file_id
  FROM retrieval_denylist d
  JOIN unnest($2::uuid[]) AS c(file_id) ON c.file_id = d.file_id
 WHERE d.tenant_id = $1
   AND (d.clears_at IS NULL OR d.clears_at > now())
";

const SUPPRESS_SQL: &str = "
INSERT INTO retrieval_denylist (tenant_id, file_id, reason, added_at, clears_at)
VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (tenant_id, file_id)
    DO UPDATE SET reason = EXCLUDED.reason,
                  added_at = EXCLUDED.added_at,
                  clears_at = EXCLUDED.clears_at
";

const LIFT_SQL: &str = "
DELETE FROM retrieval_denylist
 WHERE tenant_id = $1 AND clears_at IS NOT NULL AND clears_at <= $2
";
