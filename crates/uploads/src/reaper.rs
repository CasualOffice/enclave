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

use chrono::{DateTime, Utc};
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
        assert!(
            delete < mark,
            "the staged bytes must be released before the row is marked EXPIRED"
        );
    }
}
