//! Permanent deletion — **not implemented**, and this module exists so that is visible.
//!
//! `docs/03-LLD.md §18` fixes what destroying content requires:
//!
//! > Permanent deletion checks, in order: trash expiry, retention schedule, legal hold, record
//! > status. Any one of them blocking means the object is not destroyed and the attempt is audited.
//! >
//! > Purge cascades to derived state: renditions, extracted text, chunks in Milvus, sync tombstones.
//!
//! Two of those four checks cannot be made from this crate today. `retention_policies` and
//! `retention_labels` have no crate behind them, `legal_hold_items` has none either, and while
//! `files.on_legal_hold` and `files.is_record` are denormalized flags maintained *transactionally*
//! with those tables (`docs/04-DATA-MODEL.md §8`) — so reading them is not a shortcut — nothing
//! maintains them yet, because nothing writes the tables they mirror. A purge implemented against
//! those columns now would read `FALSE` for every row in the system and destroy content under
//! hold. The cascade has the same problem: no rendition store, no chunk index, no sync tombstones
//! to cascade to.
//!
//! So the function is written, documented and refuses. A refusal is recoverable and an audited
//! non-event; a purge that ran with two of its four gates missing is not.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId};
use sqlx::PgConnection;

use crate::error::{FilesError, Result};

/// Permanently destroys a trashed node. **Always fails.**
///
/// # What an implementation must check, in this order, before deleting anything
///
/// 1. **Trash expiry.** The node is in the trash (`deleted_at IS NOT NULL`) and `purge_after` is in
///    the past. A live node is never a purge candidate, whatever the caller asked for.
/// 2. **Retention schedule.** No retention policy or label in force over the node, its library, its
///    content type or its classification still requires it to be kept. This is the check that
///    cannot be inferred from `files` alone.
/// 3. **Legal hold.** No hold covers the node — `files.on_legal_hold`, and the `legal_hold_items`
///    rows it is maintained from. A hold set moments ago must win over a purge decided moments
///    before it.
/// 4. **Record status.** `files.is_record` is false, or the record's own disposition has been
///    approved. A declared record is not deletable by the ordinary trash path at all.
///
/// Any one of them blocking means **the object is not destroyed and the attempt is audited**. The
/// audit row is written for the refusal as much as for the deletion — a purge that was refused is
/// exactly the event a compliance review looks for (`CLAUDE.md` rule 10, audit inside the policy
/// chain).
///
/// # And what it must then cascade to
///
/// Renditions and previews, extracted text, the chunks in Milvus, sync tombstones, and the objects
/// in storage behind every version. The database rows are the least of it: an implementation that
/// deletes the `files` row and stops has left the content readable through search and through the
/// preview cache.
///
/// # And the accounting it must return
///
/// [`enclave_db::release_storage`], for the summed `size_bytes` of every `file_versions` row it
/// destroys, **in the same transaction as the deletion** — the mirror of the charge
/// `enclave_versions::VersionService::commit` makes when the row is written (`ENC-589`,
/// `plans/M4-GOVERNANCE.md` D31). This is the only place a release belongs, and the trash
/// ([`crate::FileRepository::trash`]) is deliberately not it: a soft delete destroys nothing, the
/// bytes are still stored and still paid for, and a release there would make the recycle bin an
/// unmetered tier.
///
/// The release cannot refuse — [`enclave_db::Released`] has no refusal variant — and that is
/// load-bearing rather than incidental. A purge that could be blocked on a quota-accounting error
/// is a tenant that cannot get back under its limit, which D31 forbids in the same breath as it
/// requires the charge.
///
/// Until this function does something, `release_storage` has **no caller outside its own tests**,
/// and `.github/scripts/unwired_report.py` says so. That is the honest state: nothing in this
/// workspace destroys stored bytes yet, so there is nothing to give back.
///
/// # Errors
///
/// Always [`FilesError::PurgeUnavailable`]. It maps to an internal error rather than to a
/// validation failure, because the caller did nothing wrong — this build cannot honour the request.
#[allow(clippy::unused_async)] // The signature is the deliverable; an implementation will need it.
pub async fn purge_permanently(
    _conn: &mut PgConnection,
    _tenant: TenantId,
    _file: FileId,
    _now: DateTime<Utc>,
) -> Result<()> {
    // Not `todo!()`. A panic in a deletion path takes the connection's transaction with it and
    // tells the caller nothing; a refusal is an outcome they can log, audit and report.
    Err(FilesError::PurgeUnavailable)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::Error as CoreError;

    use super::*;

    #[test]
    fn the_refusal_is_an_outcome_and_not_a_panic() {
        // The assertion that has to be *changed* before a real implementation can land, which is
        // the point: it makes the gap something a person removes deliberately rather than
        // something a reviewer has to notice. Calling `purge_permanently` needs a live connection,
        // so what is asserted here is the value it returns and how that value renders.
        let refusal = FilesError::PurgeUnavailable;
        assert!(!refusal.is_retryable(), "retrying will not make the missing crates exist");
        assert_eq!(CoreError::from(refusal).to_string(), "internal error");
    }
}
