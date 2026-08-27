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
use crate::session::{LoadedSession, Resumable, Session, StrandedSession};
use crate::state::{Created, Phase, Transition, UploadState};

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

    /// Claims `SCANNING` sessions that have **no version behind them** — `ENC-787`'s repair.
    ///
    /// # What makes a session stranded, and how this statement knows
    ///
    /// Two independent predicates, and each would be sufficient for a different reason. They are
    /// both applied because they fail in opposite directions and a repair pass that deletes object
    /// bytes should not rest on one argument.
    ///
    /// **`NOT EXISTS` a `file_versions` row naming the staged key.** This is the load-bearing one.
    /// Since `ENC-691` the version is committed in the *same transaction* that writes `SCANNING`
    /// (`routes::uploads::complete` → `promote`), so under MVCC a reader sees both or neither: a
    /// committed `SCANNING` row with no version cannot be a completion in flight, because the
    /// transaction that would have made the version has already ended. It is also the predicate that
    /// makes the delete safe at all — the staged key *is* the version's `object_key`, so claiming a
    /// session that did commit would destroy a live file's only copy. See
    /// [`StrandedSession`](crate::StrandedSession).
    ///
    /// **`updated_at <= $2`, a caller-supplied cutoff.** `updated_at` is rewritten on every state
    /// change (`Session::advance`), so for a `SCANNING` row it is the instant of hand-off, and this
    /// clause reads "has been claiming to scan since before the cutoff". It is not redundant: it is
    /// what still holds if some future path ever writes `SCANNING` and commits its version in a
    /// *second* transaction, which the argument above would not survive. `expires_at` is deliberately
    /// **not** used here — that is the upload TTL, a property of when the session was created rather
    /// than of how long it has been claiming to scan, and a session handed off one minute before its
    /// TTL ran out would be collected a minute later.
    ///
    /// `FOR UPDATE SKIP LOCKED` for `claim_expired`'s reasons, and one more that matters here: a
    /// session another transaction is mid-completion on is skipped rather than waited for.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`UploadError::MalformedRow`] if a claimed row will not decode.
    pub async fn claim_stranded(
        conn: &mut PgConnection,
        tenant: TenantId,
        idle_since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<StrandedSession>> {
        let rows = sqlx::query(SELECT_STRANDED)
            .bind(sql(tenant))
            .bind(idle_since)
            .bind(limit)
            .fetch_all(&mut *conn)
            .await?;

        rows.iter()
            .map(|row| {
                // The statement's own `state = 'SCANNING'` guarantees the decode lands in
                // `Settled`; a row that decoded to anything else is schema drift, and refusing it is
                // safer than expiring a session whose state this crate has misread.
                match session_from_row(row)? {
                    LoadedSession::Settled(settled) if settled.state() == UploadState::Scanning => {
                        Ok(StrandedSession::new(settled.record().clone()))
                    }
                    other => Err(UploadError::NotResumable { state: other.state() }),
                }
            })
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

/// `SCANNING` sessions with no version behind them, idle since the cutoff.
///
/// The `NOT EXISTS` is correlated on `object_key = s.staged_key` **and** on `tenant_id`, which is not
/// redundant with row-level security: `docs/04-DATA-MODEL.md §3` makes the application predicate and
/// RLS two independent layers, and a subquery that matched a key across tenants would be the one
/// place a stranded-session sweep could be talked out of a delete by another tenant's row — or into
/// one. Both directions are bad and one predicate closes both.
const SELECT_STRANDED: &str = "SELECT s.id, s.tenant_id, s.library_id, s.parent_id, s.file_id, \
     s.name, s.declared_size, s.declared_mime, s.staged_key, s.multipart_id, s.state, \
     s.bytes_received, s.created_by, s.created_at, s.updated_at, s.expires_at \
     FROM upload_sessions s \
     WHERE s.tenant_id = $1 \
       AND s.state = 'SCANNING' \
       AND s.updated_at <= $2 \
       AND NOT EXISTS ( \
             SELECT 1 FROM file_versions v \
              WHERE v.tenant_id = s.tenant_id AND v.object_key = s.staged_key) \
     ORDER BY s.updated_at ASC \
     LIMIT $3 \
     FOR UPDATE OF s SKIP LOCKED";

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
        for query in [SELECT_SESSION, UPDATE_STATE, SELECT_EXPIRED, SELECT_STRANDED] {
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

    /// The reclaim's version check is in the **claim**, not in a caller.
    ///
    /// `ENC-787`. This is the predicate that stops the repair pass deleting a live file's content:
    /// since `ENC-691` the staged key *is* the committed version's `object_key`, so a claim that
    /// matched a session which did commit would hand `reclaim_stranded` an object it then deletes,
    /// leaving a `file_versions` row pointing at nothing. Asserted against the statement text
    /// because a check moved out to a caller is a check the next caller can forget — and the whole
    /// design of `StrandedSession` is that there is no other way in.
    ///
    /// The tenant correlation is asserted separately from the key correlation. A subquery joined on
    /// `object_key` alone would let another tenant's version row veto this tenant's reclaim, and —
    /// worse in the other direction — would be the one place a sweep reasons about a row row-level
    /// security was meant to hide from it.
    #[test]
    fn the_reclaim_cannot_claim_a_session_that_has_a_version_behind_it() {
        assert!(SELECT_STRANDED.contains("NOT EXISTS"), "{SELECT_STRANDED}");
        assert!(SELECT_STRANDED.contains("FROM file_versions v"), "{SELECT_STRANDED}");
        assert!(SELECT_STRANDED.contains("v.object_key = s.staged_key"), "{SELECT_STRANDED}");
        assert!(SELECT_STRANDED.contains("v.tenant_id = s.tenant_id"), "{SELECT_STRANDED}");

        // The two guards that make "stranded" mean something, and the lock discipline that keeps
        // two sweeps from claiming one row.
        assert!(SELECT_STRANDED.contains("s.state = 'SCANNING'"), "{SELECT_STRANDED}");
        assert!(SELECT_STRANDED.contains("s.updated_at <= $2"), "{SELECT_STRANDED}");
        assert!(SELECT_STRANDED.contains("SKIP LOCKED"), "{SELECT_STRANDED}");

        // `expires_at` is deliberately absent: it is the upload TTL, not a measure of how long the
        // session has been claiming to scan. See `claim_stranded` for why the distinction matters.
        assert!(!SELECT_STRANDED.contains("expires_at <="), "{SELECT_STRANDED}");
    }

    /// `CLAUDE.md` rule 9 as a property of the SQL, not only of the types: no statement in this
    /// crate mentions a state that implies the content is scanned or readable.
    #[test]
    fn no_statement_can_write_a_post_scan_state() {
        for query in [INSERT_SESSION, SELECT_SESSION, UPDATE_STATE, SELECT_EXPIRED, SELECT_STRANDED]
        {
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
