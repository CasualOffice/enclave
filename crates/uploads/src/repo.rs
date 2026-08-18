//! `upload_sessions`: the only code in the workspace that writes that table.
//!
//! # The shape every function takes
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without `app.tenant_id`
//! established. Every statement *also* carries an explicit `tenant_id = $1` predicate: that is
//! layer 1 of `docs/04-DATA-MODEL.md §3`, and the pair is what makes a leak require two independent
//! failures rather than one.
//!
//! # One write path, and it is a compare-and-swap
//!
//! [`UploadRepository::apply`] is the only statement that changes a session's state, and it takes a
//! [`Transition`] — which cannot be constructed except by a transition method on a typed
//! [`Session`]. Two consequences follow:
//!
//! 1. **`state = 'AVAILABLE'` is not writable from this crate.** `apply` writes `To::STATE`, and no
//!    `Transition` exists whose `To` is a phase mapping to `AVAILABLE`, `PROCESSING` or
//!    `QUARANTINED` (`CLAUDE.md` rule 9, and see [`crate::state`]).
//! 2. **A concurrent mover loses loudly.** The `UPDATE` matches on the state the transition came
//!    from, so two requests completing the same session cannot both succeed; the second gets
//!    [`UploadError::ConcurrentTransition`] rather than overwriting the first
//!    (`docs/03-LLD.md §14`). There is no `revision` column on this table — the state *is* the
//!    concurrency token.
//!
//! Nothing here decides anything. No permission is read and no policy is evaluated: the chain runs
//! in the handler, before a domain service is reached (`plans/M1-CONTENT-CORE.md` D11).

use chrono::{DateTime, Utc};
use enclave_core::TenantId;
use enclave_db::sql;
use sqlx::PgConnection;

use crate::error::{Result, UploadError};
use crate::id::UploadSessionId;
use crate::row::session_from_row;
use crate::session::{LoadedSession, Resumable, Session};
use crate::state::{Created, Phase, Transition};

/// Reads and writes upload sessions.
#[derive(Debug, Clone, Copy, Default)]
pub struct UploadRepository;

impl UploadRepository {
    /// Inserts a freshly created session.
    ///
    /// Always `CREATED`: the state is not a parameter, because the row's first state is a property
    /// of the machine and not of the caller.
    ///
    /// # Errors
    ///
    /// Storage failures. A duplicate id is one — the identifier is a UUIDv7 minted moments earlier,
    /// so a collision is a defect rather than a condition to recover from.
    pub async fn insert(conn: &mut PgConnection, session: &Session<Created>) -> Result<()> {
        let record = session.record();
        sqlx::query(INSERT_SESSION)
            .bind(sql(record.tenant_id))
            .bind(sql(record.id))
            .bind(sql(record.library_id))
            .bind(record.parent_id.map(sql))
            .bind(record.file_id.map(sql))
            .bind(&record.name)
            .bind(record.declared_size)
            .bind(record.declared_mime.as_deref())
            .bind(record.staged.as_str())
            .bind(record.multipart_id.as_deref())
            .bind(record.bytes_received)
            .bind(sql(record.created_by))
            .bind(record.created_at)
            .bind(record.updated_at)
            .bind(record.expires_at)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Reads one session.
    ///
    /// Returns `None` for a session that does not exist *and* for one belonging to another tenant;
    /// the two are indistinguishable to the caller by design (`CLAUDE.md` rule 7).
    ///
    /// # Errors
    ///
    /// Storage failures, and [`UploadError::MalformedRow`] if the stored row will not decode.
    pub async fn find(
        conn: &mut PgConnection,
        tenant: TenantId,
        id: UploadSessionId,
    ) -> Result<Option<LoadedSession>> {
        let row = sqlx::query(SELECT_SESSION)
            .bind(sql(tenant))
            .bind(sql(id))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(session_from_row).transpose()
    }

    /// Writes a state change, or reports that someone else got there first.
    ///
    /// # Errors
    ///
    /// [`UploadError::ConcurrentTransition`] when the row is no longer in the state the transition
    /// came from — which is also what a session deleted underneath the caller looks like, and the
    /// remediation is the same: re-read it. Plus storage failures.
    pub async fn apply<To: Phase>(
        conn: &mut PgConnection,
        transition: Transition<To>,
    ) -> Result<Session<To>> {
        let expected = transition.from_state();
        let attempted = transition.to_state();
        let session = transition.into_session();
        let record = session.record();

        let result = sqlx::query(UPDATE_STATE)
            .bind(sql(record.tenant_id))
            .bind(sql(record.id))
            .bind(attempted.as_str())
            .bind(record.bytes_received)
            .bind(record.updated_at)
            .bind(expected.as_str())
            .execute(&mut *conn)
            .await?;

        if result.rows_affected() != 1 {
            return Err(UploadError::ConcurrentTransition { expected, attempted });
        }

        tracing::debug!(
            tenant_id = %record.tenant_id,
            upload_session_id = %record.id,
            from = expected.as_str(),
            to = attempted.as_str(),
            "upload session advanced"
        );

        Ok(session)
    }

    /// Claims expired sessions that still own staged bytes.
    ///
    /// `FOR UPDATE SKIP LOCKED` so that two schedulers reaping the same tenant divide the work
    /// instead of deadlocking on it, and so that a session another transaction is mid-completion on
    /// is left alone rather than expired out from under it.
    ///
    /// Only `CREATED` and `UPLOADING` are claimed. `UPLOADED` is a state no committed row holds —
    /// completion writes `UPLOADED` and `SCANNING` in the same transaction — so a reaper that
    /// looked for it would be looking for rows that exist only inside somebody else's uncommitted
    /// work.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`UploadError::MalformedRow`] if a claimed row will not decode.
    pub async fn claim_expired(
        conn: &mut PgConnection,
        tenant: TenantId,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<Resumable>> {
        let rows = sqlx::query(SELECT_EXPIRED)
            .bind(sql(tenant))
            .bind(now)
            .bind(limit)
            .fetch_all(&mut *conn)
            .await?;

        rows.iter()
            .map(|row| session_from_row(row).and_then(LoadedSession::into_resumable))
            .collect()
    }
}

/// The insert. `state` is the literal `'CREATED'` rather than a bind: a session's first state is a
/// property of the machine, and a parameter there would be a way to start one anywhere.
const INSERT_SESSION: &str = "INSERT INTO upload_sessions \
     (tenant_id, id, library_id, parent_id, file_id, name, declared_size, declared_mime, \
      staged_key, multipart_id, state, bytes_received, created_by, created_at, updated_at, \
      expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'CREATED', $11, $12, $13, $14, $15)";

/// One session by id, within a tenant.
const SELECT_SESSION: &str = "SELECT id, tenant_id, library_id, parent_id, file_id, name, \
     declared_size, declared_mime, staged_key, multipart_id, state, bytes_received, created_by, \
     created_at, updated_at, expires_at \
     FROM upload_sessions WHERE tenant_id = $1 AND id = $2";

/// The compare-and-swap. `$6` is the state the caller planned against.
const UPDATE_STATE: &str = "UPDATE upload_sessions \
     SET state = $3, bytes_received = $4, updated_at = $5 \
     WHERE tenant_id = $1 AND id = $2 AND state = $6";

/// Expired sessions that still own staged bytes.
///
/// `state NOT IN ('AVAILABLE','ABORTED')` is written out even though the `state IN (…)` that
/// follows already implies it. It is textually identical to the predicate of `idx_uploads_expiry`
/// (`docs/04-DATA-MODEL.md §8`), which is what lets the planner prove the partial index applies —
/// a reaper that sequentially scanned this table every minute would be a background job that gets
/// slower as the tenant grows.
const SELECT_EXPIRED: &str = "SELECT id, tenant_id, library_id, parent_id, file_id, name, \
     declared_size, declared_mime, staged_key, multipart_id, state, bytes_received, created_by, \
     created_at, updated_at, expires_at \
     FROM upload_sessions \
     WHERE tenant_id = $1 \
       AND expires_at <= $2 \
       AND state NOT IN ('AVAILABLE','ABORTED') \
       AND state IN ('CREATED','UPLOADING') \
     ORDER BY expires_at ASC \
     LIMIT $3 \
     FOR UPDATE SKIP LOCKED";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::SESSION_COLUMNS;
    use crate::state::UploadState;

    #[test]
    fn every_statement_carries_the_application_tenant_predicate() {
        // RLS is the other layer and neither is redundant (`docs/04-DATA-MODEL.md §3`). A query
        // that lost this would still be correct today and would stop being correct the moment
        // something ran it on a connection without a tenant context.
        for query in [SELECT_SESSION, UPDATE_STATE, SELECT_EXPIRED] {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
        assert!(INSERT_SESSION.contains("(tenant_id, id,"), "tenant_id is the first column");
    }

    #[test]
    fn the_select_lists_match_the_decoders_column_list() {
        for query in [SELECT_SESSION, SELECT_EXPIRED] {
            assert!(query.contains(SESSION_COLUMNS), "{query}");
        }
    }

    #[test]
    fn the_state_write_is_a_compare_and_swap() {
        assert!(UPDATE_STATE.contains("AND state = $6"), "{UPDATE_STATE}");
    }

    /// The reaper's predicate has to be *provably* implied by the partial index's, which means
    /// carrying the index's own clause verbatim.
    #[test]
    fn the_reaper_predicate_matches_the_partial_index() {
        assert!(SELECT_EXPIRED.contains("state NOT IN ('AVAILABLE','ABORTED')"));
        assert!(SELECT_EXPIRED.contains("FOR UPDATE SKIP LOCKED"));
    }

    /// `CLAUDE.md` rule 9 as a property of the SQL, not only of the types: no statement in this
    /// crate mentions a state that implies the content is scanned or readable.
    #[test]
    fn no_statement_can_write_a_post_scan_state() {
        for query in [INSERT_SESSION, SELECT_SESSION, UPDATE_STATE, SELECT_EXPIRED] {
            for forbidden in [
                UploadState::Available.as_str(),
                UploadState::Processing.as_str(),
                UploadState::Quarantined.as_str(),
            ] {
                let mentioned = query.contains(forbidden);
                // `SELECT_EXPIRED` names AVAILABLE only inside the index's exclusion list, which is
                // the opposite of writing it.
                let excluded = query.contains("NOT IN ('AVAILABLE','ABORTED')")
                    && forbidden == UploadState::Available.as_str();
                assert!(!mentioned || excluded, "{forbidden} appears in: {query}");
            }
        }
    }
}
