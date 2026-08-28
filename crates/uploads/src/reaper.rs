//! Releasing the bytes of sessions that were never finished.
//!
//! `docs/03-LLD.md §15`: *orphaned staged objects are reaped by the scheduler after
//! `upload.session_ttl` (default 24h)*. This is that reaper. It exists because the two stores
//! cannot commit together: a client that vanishes mid-upload leaves an object with no row that
//! will ever point at it, and nothing else in the system is looking for one.
//!
//! # Order of operations
//!
//! **Delete the bytes, then mark the row.** `idx_uploads_expiry` excludes `AVAILABLE` and
//! `ABORTED`, and this reaper's own predicate excludes everything except `CREATED` and
//! `UPLOADING` — so a row marked `EXPIRED` before a successful delete would never be examined
//! again and its bytes would be orphaned permanently. In the other order the worst case is a
//! delete that happens twice, and `BlobStore::delete` is idempotent for exactly this reason.
//!
//! # Scope, and why it is per-tenant
//!
//! Every statement runs inside a `TenantScoped` transaction, so the scheduler iterates tenants and
//! calls this once per tenant per batch. A cross-tenant sweep would need a connection with no
//! `app.tenant_id` — which is to say, a connection with row-level security disabled — and
//! `docs/04-DATA-MODEL.md §3` has exactly two exemptions from that, neither of them this.
//!
//! # Batch size
//!
//! `claim_expired` takes `FOR UPDATE`, so the claimed rows stay locked until the caller's
//! transaction ends, and each release is a network round trip to the object store. Keep `limit`
//! small — a hundred, not a hundred thousand — and call this repeatedly. A single enormous batch
//! would hold locks across minutes of I/O and block the completion of a session it happened to
//! claim.
//!
//! # Multipart uploads that were never completed
//!
//! Deleting the staged key removes a completed object. It does **not** abort an in-progress
//! multipart upload, whose parts are invisible to `DeleteObject` — and
//! [`BlobStore`](enclave_storage::BlobStore) exposes no abort. The compensating control is the
//! bucket lifecycle rule `AbortIncompleteMultipartUpload` (`docs/08-BYO-INFRA.md §5`); see this
//! crate's `integrator_actions` note.

use chrono::{DateTime, Duration, Utc};
use enclave_core::TenantId;
use enclave_storage::BlobStore;
use sqlx::PgConnection;

use crate::error::Result;
use crate::repo::UploadRepository;

/// What one reaping pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use = "the counts are how an operator sees a store that is refusing deletes"]
pub struct ReapReport {
    /// Sessions claimed by this pass.
    pub claimed: usize,
    /// Sessions whose bytes were released and whose row is now `EXPIRED`.
    pub released: usize,
    /// Sessions left for the next pass because the object store or the row refused.
    ///
    /// Not an error: a transient storage failure should not abandon the rest of the batch. A
    /// number that stays high across passes is the signal, and it is the operator's to act on.
    pub deferred: usize,
}

impl ReapReport {
    /// Whether this pass filled its batch, and should therefore be run again immediately.
    #[must_use]
    pub const fn is_full(&self, limit: usize) -> bool {
        self.claimed >= limit
    }
}

/// Releases the staged bytes of every expired session in one tenant, up to `limit` of them.
///
/// # Errors
///
/// Database failures from the claim itself. Failures releasing an *individual* session are counted
/// in [`ReapReport::deferred`] rather than propagated, so one unreachable object does not strand
/// the rest of the batch behind it.
pub async fn reap_expired(
    conn: &mut PgConnection,
    blob: &dyn BlobStore,
    tenant: TenantId,
    now: DateTime<Utc>,
    limit: usize,
) -> Result<ReapReport> {
    let claimed = UploadRepository::claim_expired(
        conn,
        tenant,
        now,
        i64::try_from(limit).unwrap_or(i64::MAX),
    )
    .await?;

    let mut report = ReapReport { claimed: claimed.len(), released: 0, deferred: 0 };

    for session in claimed {
        let id = session.record().id;
        let key = session.record().staged.as_str().to_owned();

        // `ENC-839`: the parts first, then the object.
        //
        // `delete` removes a *completed* object. The parts of a multipart upload that was never
        // completed are invisible to `DeleteObject` and go on being billed, so for every abandoned
        // upload over `multipart_threshold_bytes` — 16 MiB by default, which is most of what this
        // product is for — the row was marked `EXPIRED` and nothing was released.
        //
        // Order matters and is the same argument the delete-before-mark ordering below makes: abort
        // while the row still says what the provider is holding. A store that cannot abort answers
        // `Unsupported`, and that is *deferred* rather than swallowed — releasing nothing while
        // recording a release would make the parts unreachable to every later pass, which is worse
        // than the leak. The compensating control an integrator may also have configured is the
        // bucket's `AbortIncompleteMultipartUpload` lifecycle rule (`docs/08-BYO-INFRA.md §5`),
        // which nothing here can see or verify.
        if let Some(upload_id) = session.record().multipart_id.as_deref() {
            if let Err(error) = blob.abort_multipart(&key, upload_id).await {
                tracing::warn!(
                    tenant_id = %tenant,
                    upload_session_id = %id,
                    object_key = %key,
                    error = %error,
                    "could not abort an expired multipart upload, so its parts are still held; \
                     leaving the session for the next pass"
                );
                report.deferred += 1;
                continue;
            }
        }

        if let Err(error) = blob.delete(&key).await {
            // The key is safe to log: it is UUIDs, and carries no file name (`enclave_storage::key`).
            tracing::warn!(
                tenant_id = %tenant,
                upload_session_id = %id,
                object_key = %key,
                error = %error,
                "could not release an expired upload's staged bytes; leaving it for the next pass"
            );
            report.deferred += 1;
            continue;
        }

        match UploadRepository::apply(conn, session.expire(now)).await {
            Ok(_) => report.released += 1,
            Err(error) => {
                // The bytes are gone and the row is not `EXPIRED`. Harmless: the object is already
                // deleted, `delete` is idempotent, and the next pass will claim the row again.
                tracing::warn!(
                    tenant_id = %tenant,
                    upload_session_id = %id,
                    error = %error,
                    "released an expired upload's bytes but could not mark the session"
                );
                report.deferred += 1;
            }
        }
    }

    if report.released > 0 || report.deferred > 0 {
        tracing::info!(
            tenant_id = %tenant,
            claimed = report.claimed,
            released = report.released,
            deferred = report.deferred,
            "expired upload sessions reaped"
        );
    }

    Ok(report)
}

/// What one reclamation pass did, and what it left behind.
///
/// `ENC-787`'s row asks that a repair pass *"report what it found rather than delete quietly"*, and
/// this is that report. [`ReclaimReport::found`] is the number that matters to an operator: a repair
/// that silently collected nothing and a repair that was never run look identical without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use = "the counts are the point of a repair pass; a discarded report is a silent delete"]
pub struct ReclaimReport {
    /// Stranded sessions this pass claimed — `SCANNING`, idle, with no version behind them.
    pub found: usize,
    /// Sessions whose staged object was deleted and whose row is now `EXPIRED`.
    pub reclaimed: usize,
    /// Sessions left for the next pass because the object store or the row refused.
    ///
    /// Not an error, for [`ReapReport::deferred`]'s reason. A number that stays high across passes
    /// is the signal.
    pub deferred: usize,
}

impl ReclaimReport {
    /// Whether this pass filled its batch, and should therefore be run again immediately.
    #[must_use]
    pub const fn is_full(&self, limit: usize) -> bool {
        self.found >= limit
    }
}

/// Reclaims `SCANNING` sessions that have no version behind them — `ENC-787`.
///
/// # What this is for, and why the ordinary reaper cannot do it
///
/// [`reap_expired`] claims `CREATED` and `UPLOADING` only, and `UploadState::Scanning` answers
/// `false` to `holds_staged_bytes` — correctly, because for a session that *did* commit a version
/// the staged key **is** the version's `object_key`, and releasing it would delete a live file's
/// content. So a session stranded in `SCANNING` before `ENC-691` closed the completion path is
/// collected by nothing: no antivirus pass will touch it (that pass queues on
/// `file_versions.av_status`, and there is no version), no reaper will release its bytes, and no
/// quota counts them. A charge nobody can spend and an object nobody will read, indefinitely.
///
/// # Telling a stranded session from one that is legitimately mid-flight
///
/// Not by state, which is identical, and not by timing alone. The distinguishing fact lives in
/// another table and is asserted inside the claim itself — see `UploadRepository::claim_stranded`
/// for both predicates and why each is applied — and it is carried out of the claim in the type:
/// `StrandedSession` has one constructor, that statement, and it is the only value from which the
/// `SCANNING` → `EXPIRED` transition can be reached. A caller cannot get here holding a session
/// whose version was not checked.
///
/// `idle_for` is the grace period: a session is a candidate only once it has been claiming to scan
/// for at least this long. It is the caller's to choose because the honest value differs between a
/// one-off repair of a historical backlog and a standing sweep.
///
/// # Order of operations
///
/// [`reap_expired`]'s, unchanged and for its reason: **delete the bytes, then mark the row**. A row
/// marked `EXPIRED` before a successful delete is never claimed again — the statement's predicate is
/// `state = 'SCANNING'` — and its object would be orphaned permanently. In the other order the worst
/// case is a delete that runs twice, which `BlobStore::delete` is idempotent for.
///
/// # Errors
///
/// Database failures from the claim itself. Failures on an *individual* session are counted in
/// [`ReclaimReport::deferred`] rather than propagated, so one unreachable object does not strand the
/// rest of the batch behind it.
pub async fn reclaim_stranded(
    conn: &mut PgConnection,
    blob: &dyn BlobStore,
    tenant: TenantId,
    now: DateTime<Utc>,
    idle_for: Duration,
    limit: usize,
) -> Result<ReclaimReport> {
    let idle_since = now - idle_for;
    let claimed = UploadRepository::claim_stranded(
        conn,
        tenant,
        idle_since,
        i64::try_from(limit).unwrap_or(i64::MAX),
    )
    .await?;

    let mut report = ReclaimReport { found: claimed.len(), reclaimed: 0, deferred: 0 };

    for session in claimed {
        let id = session.record().id;
        let key = session.record().staged.as_str().to_owned();

        // Reported before anything is destroyed, and at `info` rather than `debug`: the row's own
        // requirement is that this pass say what it found, and a line written only on success is a
        // line missing from exactly the run an operator needs to read. The key is safe to log — it
        // is UUIDs and carries no file name (`enclave_storage::key`).
        tracing::info!(
            tenant_id = %tenant,
            upload_session_id = %id,
            object_key = %key,
            handed_off_at = %session.record().updated_at,
            "reclaiming an upload session stranded in SCANNING with no version behind it"
        );

        if let Err(error) = blob.delete(&key).await {
            tracing::warn!(
                tenant_id = %tenant,
                upload_session_id = %id,
                object_key = %key,
                error = %error,
                "could not release a stranded upload's staged bytes; leaving it for the next pass"
            );
            report.deferred += 1;
            continue;
        }

        match UploadRepository::apply(conn, session.expire(now)).await {
            Ok(_) => report.reclaimed += 1,
            Err(error) => {
                // The bytes are gone and the row is not `EXPIRED`. Harmless: `delete` is idempotent
                // and the next pass claims the row again. The interesting case is
                // `ConcurrentTransition`, which means the session moved on between the claim and
                // the write — the compare-and-swap refusing to overwrite somebody else's work.
                tracing::warn!(
                    tenant_id = %tenant,
                    upload_session_id = %id,
                    error = %error,
                    "released a stranded upload's bytes but could not mark the session"
                );
                report.deferred += 1;
            }
        }
    }

    tracing::info!(
        tenant_id = %tenant,
        found = report.found,
        reclaimed = report.reclaimed,
        deferred = report.deferred,
        "stranded upload sessions reclaimed"
    );

    Ok(report)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_full_batch_asks_to_be_run_again() {
        let report = ReapReport { claimed: 100, released: 100, deferred: 0 };
        assert!(report.is_full(100));
        assert!(!ReapReport { claimed: 3, released: 3, deferred: 0 }.is_full(100));
        assert!(!ReapReport::default().is_full(1));
    }

    /// The order the module documentation argues for, asserted against the source: reversing it
    /// would pass every functional test and would silently orphan bytes whenever a delete failed.
    #[test]
    fn the_delete_precedes_the_state_write() {
        let source = include_str!("reaper.rs");
        let body = source.split("pub async fn reap_expired(").nth(1).expect("the function exists");
        let delete = body.find("blob.delete(").expect("it deletes");
        let mark = body.find("session.expire(").expect("it marks the row");
        let abort = body.find("blob.abort_multipart(").expect("it aborts multipart uploads");
        assert!(
            abort < delete,
            "the multipart abort must precede the delete (ENC-839). `DeleteObject` cannot see the \
             parts of an upload that was never completed, and aborting after the row has been \
             marked leaves them held with nothing that will ever look again"
        );
        assert!(
            abort < mark,
            "the parts must be released before the row is marked EXPIRED (ENC-839)"
        );
        assert!(
            delete < mark,
            "the staged bytes must be released before the row is marked EXPIRED"
        );
    }

    #[test]
    fn a_full_reclaim_batch_asks_to_be_run_again() {
        assert!(ReclaimReport { found: 100, reclaimed: 100, deferred: 0 }.is_full(100));
        assert!(!ReclaimReport { found: 3, reclaimed: 3, deferred: 0 }.is_full(100));
        assert!(!ReclaimReport::default().is_full(1));
    }

    /// The repair pass has the same ordering as the reaper, asserted the same way.
    ///
    /// It matters more here, not less: `reclaim_stranded`'s claim is keyed on `state = 'SCANNING'`,
    /// so a row marked `EXPIRED` before a successful delete is *permanently* invisible to this pass
    /// — there is no later predicate that would find it again — and its object is orphaned for good.
    #[test]
    fn the_reclaim_deletes_before_it_marks_too() {
        let source = include_str!("reaper.rs");
        let body =
            source.split("pub async fn reclaim_stranded(").nth(1).expect("the function exists");
        let delete = body.find("blob.delete(").expect("it deletes");
        let mark = body.find("session.expire(").expect("it marks the row");
        assert!(delete < mark, "a stranded session's bytes go before its row is marked EXPIRED");
    }

    /// The pass reports what it found **before** it destroys anything.
    ///
    /// `ENC-787`'s row asks for a repair that reports rather than deletes quietly, and a line
    /// written after the delete is the line missing from the run where the delete is what failed.
    #[test]
    fn every_reclaimed_session_is_named_in_the_log_before_its_bytes_go() {
        let source = include_str!("reaper.rs");
        let body =
            source.split("pub async fn reclaim_stranded(").nth(1).expect("the function exists");
        let announced = body.find("stranded in SCANNING with no version").expect("it announces");
        let delete = body.find("blob.delete(").expect("it deletes");
        assert!(announced < delete, "the session is named before anything is destroyed");
    }
}
