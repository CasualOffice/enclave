//! The atomic version commit of `docs/03-LLD.md §15`, and restore.
//!
//! # One transaction, owned by the caller
//!
//! ```text
//! BEGIN                                  -- the caller's TenantScoped transaction
//!   UPDATE files.current_version_id, revision = revision + 1
//!   INSERT file_versions
//!   INSERT events_outbox('file.version.created')
//!   INSERT audit_events
//! COMMIT
//! ```
//!
//! Every one of those writes goes through the same `&mut PgConnection`
//! (`plans/M1-CONTENT-CORE.md` D10), which is what makes "the event, the audit row and the state
//! change commit together or not at all" a property of the signature rather than of a comment. It
//! also answers open question **Q6** in `plans/M1-CONTENT-CORE.md`: the audit row *shares* the
//! write's transaction, via [`enclave_audit::record_in_tx`], and an audit failure therefore fails
//! the commit rather than leaving an unaudited state change behind (`CLAUDE.md` rule 10).
//!
//! # Why the file is updated before the version is inserted
//!
//! `docs/03 §15` lists the insert first. This does the update first, and the difference is
//! concurrency rather than taste. The version number is computed from `MAX(major)` over the file's
//! existing versions, so two commits against one file must not compute it at the same time. Taking
//! the `files` row lock first makes the second commit wait; when it proceeds — under `READ
//! COMMITTED`, with a fresh snapshot per statement — it sees the first commit's version and numbers
//! itself after it. Both succeed, in order.
//!
//! With the insert first, the same two commits both read the same maximum and one is rejected by
//! `uq_version_number`. That rejection is still handled ([`VersionsError::VersionNumberTaken`],
//! retryable) because a stricter isolation level, or any other writer, can still produce it — the
//! index is the guarantee and the lock ordering is what stops it being reached in ordinary use.
//!
//! # What is missing, and deliberately
//!
//! `docs/03 §15` also lists `UPDATE quota_usage`. There is no `quota_usage` table yet — `quotas`
//! and `quota_usage` are `docs/04-DATA-MODEL.md §16` and no migration creates them. Rather than
//! write a plausible statement against a table that does not exist, or silently drop the step, it
//! is named here: **byte and file-count accounting is not performed by this commit**, and the
//! migration that creates the table has to add it to [`VersionService::commit`] and to
//! [`VersionService::restore`]. A commit that quietly stopped counting bytes would show up as a
//! tenant exceeding a quota that says it has headroom.
//!
//! # Nothing here decides who may do this
//!
//! The policy chain runs in the handler, before a domain service is reached
//! (`plans/M1-CONTENT-CORE.md` D11). These functions assume the caller already enforced; the audit
//! row they write records the action, not a decision they made.

use chrono::{DateTime, Utc};
use enclave_audit::{record_in_tx, AuditEvent, ChainMode, Detail, Outcome, Recorded};
use enclave_core::{
    Action, FileAction, FileId, RequestContext, ResourceRef, UserId, Uuid, VersionId,
};
use enclave_db::sql;
use enclave_events::{Event, EventType, Outbox};
use serde_json::json;
use sqlx::{PgConnection, Row as _};

use crate::error::{classify_write, Result, VersionsError};
use crate::model::{AvStatus, FileVersion, VersionBump, VersionStatus};
use crate::row::{version_columns, version_from_row};

/// The status every freshly committed version is written with.
///
/// Not a parameter, and that is the point (`plans/M1-CONTENT-CORE.md` D13). A version that has just
/// been committed has by definition not been scanned, so there is no argument a caller could pass
/// that would make `AVAILABLE` correct — and an argument that is never correct is an argument that
/// will eventually be passed. `CLAUDE.md` rule 9 becomes a property of the statement.
const COMMITTED_STATUS: VersionStatus = VersionStatus::Scanning;

/// The antivirus verdict every freshly committed version is written with.
const COMMITTED_AV_STATUS: AvStatus = AvStatus::Pending;

/// The content of a new version: bytes that are already in object storage, described.
///
/// Blob storage cannot join a SQL transaction (`docs/03-LLD.md §15`), so the bytes are staged and
/// promoted *before* this struct is built. Everything here is a description of an object that
/// already exists; nothing in this crate writes to object storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVersion {
    /// The file this becomes a version of.
    pub file_id: FileId,
    /// The promoted object's key. Globally unique by `uq_version_object`.
    pub object_key: String,
    /// Which storage profile the object lives in. A bare [`Uuid`] for the reason given on
    /// [`FileVersion::storage_profile_id`].
    pub storage_profile_id: Uuid,
    /// Size of the object, in bytes, as object storage reports it — not as the client declared it.
    pub size_bytes: i64,
    /// Lowercase hex SHA-256 of the content, computed over the bytes that were stored.
    pub checksum_sha256: String,
    /// The media type recorded for this version.
    pub mime_type: String,
    /// Whether this is a published version or a draft.
    pub bump: VersionBump,
    /// Who the version is attributed to.
    ///
    /// Explicit rather than derived from `ctx.actor`, because `Actor` has variants that carry no
    /// user id — a service account or the system can legitimately commit a version on someone's
    /// behalf, and `created_by` is `NOT NULL`. The audit row records the *principal* from the
    /// context; this records who the version belongs to. They differ on delegated paths, and
    /// collapsing them would lose exactly the distinction an auditor needs.
    pub created_by: UserId,
    /// The check-in comment, as the user typed it.
    pub comment: Option<String>,
}

/// What a commit produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommittedVersion {
    /// The new version, exactly as stored — including the number the database assigned it.
    pub version: FileVersion,
    /// The file's revision after the commit, for the caller's next `If-Match`.
    pub file_revision: i64,
    /// What the audit sink assigned the row, for correlating the response with the trail.
    pub audit: Recorded,
}

/// Commits versions.
///
/// A unit-like namespace rather than a constructed service, for the reason
/// [`enclave_events::Outbox`] is one: everything it could hold — a pool, a tenant — is exactly what
/// must not be captured, because capturing it is how a write ends up outside its transaction.
#[derive(Debug, Clone, Copy, Default)]
pub struct VersionService;

impl VersionService {
    /// Commits a new version of a file.
    ///
    /// The whole of `docs/03-LLD.md §15` in one transaction the caller owns. On return, the file
    /// points at the new version, the version is `SCANNING`, an `file.version.created` event is in
    /// the outbox, and an audit row is written — and none of it is visible to anyone until the
    /// caller commits.
    ///
    /// The file is left `PROCESSING` rather than `AVAILABLE`: its current version is one nobody may
    /// read yet, and a file that advertised itself as available while pointing at unscanned bytes
    /// is the exact shape of `CLAUDE.md` rule 9's failure. The antivirus path moves both.
    ///
    /// # Errors
    ///
    /// [`VersionsError::FileNotFound`] if the file does not exist, is in the trash, or belongs to
    /// another tenant; [`VersionsError::VersionNumberTaken`] if a concurrent commit took this
    /// number (retryable); [`VersionsError::ObjectKeyInUse`] if the key already belongs to a
    /// version; storage, event and audit failures, every one of which must fail the transaction.
    pub async fn commit(
        conn: &mut PgConnection,
        ctx: &RequestContext,
        chain: ChainMode,
        new: &NewVersion,
        at: DateTime<Utc>,
    ) -> Result<CommittedVersion> {
        Self::write(conn, ctx, chain, new, at, None).await
    }

    /// Restores an earlier version by committing a **new** one with its content.
    ///
    /// Nothing is mutated and nothing is moved: the history keeps every row it had and gains one.
    /// That is not a stylistic preference — `file_versions` rows are immutable once `AVAILABLE`
    /// (`plans/M1-CONTENT-CORE.md` D12), so "make 2.0 current again" is not an operation the
    /// database will perform, and a history that could be rewritten is not a history.
    ///
    /// `object_key` is a **new** key, and the caller must already have copied the bytes to it.
    /// Pointing the new row at the source's key is not an option a caller can take:
    /// `uq_version_object` is globally unique, so two rows naming one object is unrepresentable —
    /// which is what stops a purge of the restored version from deleting the original's bytes.
    ///
    /// The restored version starts `SCANNING` like any other, even though its source was scanned
    /// clean. The bytes are a new object, and the signature database has moved on since; treating
    /// "we scanned the original in March" as a verdict on a copy made today is the reasoning
    /// `CLAUDE.md` rule 9 exists to refuse.
    ///
    /// # Errors
    ///
    /// [`VersionsError::NotFound`] if the source version does not exist for this file;
    /// [`VersionsError::SourceNotRestorable`] if it exists but is not servable — a quarantined or
    /// still-scanning version is not a thing to make current. Otherwise as
    /// [`VersionService::commit`].
    pub async fn restore(
        conn: &mut PgConnection,
        ctx: &RequestContext,
        chain: ChainMode,
        request: &RestoreVersion,
        at: DateTime<Utc>,
    ) -> Result<CommittedVersion> {
        let source = crate::VersionRepository::find(
            &mut *conn,
            ctx.tenant_id,
            request.file_id,
            request.source,
        )
        .await?
        .ok_or(VersionsError::NotFound)?;

        // A version that is still scanning has no settled bytes, and a quarantined one has bytes
        // the system has already refused to serve. Re-publishing either under a new number would
        // launder it past every check that stopped it the first time.
        if !source.is_readable() {
            return Err(VersionsError::SourceNotRestorable);
        }

        let new = NewVersion {
            file_id: request.file_id,
            object_key: request.object_key.clone(),
            // Copied from the source rather than taken from the caller: the restored version *is*
            // the old content, and a caller that could pass a different size or checksum could
            // create a version claiming to be a restore of something it is not.
            storage_profile_id: source.storage_profile_id,
            size_bytes: source.size_bytes,
            checksum_sha256: source.checksum_sha256.clone(),
            mime_type: source.mime_type.clone(),
            bump: request.bump,
            created_by: request.restored_by,
            comment: request.comment.clone(),
        };

        Self::write(conn, ctx, chain, &new, at, Some(source.id)).await
    }

    /// The shared body of [`VersionService::commit`] and [`VersionService::restore`].
    ///
    /// One function rather than two, because a restore *is* a commit: the only differences are the
    /// audited action and one field in the event. Two copies would be two places to forget the
    /// outbox row.
    async fn write(
        conn: &mut PgConnection,
        ctx: &RequestContext,
        chain: ChainMode,
        new: &NewVersion,
        at: DateTime<Utc>,
        restored_from: Option<VersionId>,
    ) -> Result<CommittedVersion> {
        let tenant = ctx.tenant_id;
        let id = VersionId::new_v7();

        // 1. The file. First, for the row lock — see the module documentation. Also the existence
        //    check: the foreign key would catch a missing file, but not one that is in the trash,
        //    and committing a version into a trashed file is a resurrection nobody asked for.
        let bumped = sqlx::query(BUMP_FILE)
            .bind(sql(tenant))
            .bind(sql(new.file_id))
            .bind(sql(id))
            .bind(new.size_bytes)
            .bind(&new.mime_type)
            .bind(sql(new.created_by))
            .bind(at)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(VersionsError::FileNotFound)?;
        let file_revision: i64 = bumped.try_get("revision")?;

        // 2. The version. The number is computed inside the statement, from the same snapshot that
        //    inserts it — computing it in Rust would be a read and a write with a window between.
        let row = sqlx::query(INSERT_VERSION)
            .bind(sql(id))
            .bind(sql(tenant))
            .bind(sql(new.file_id))
            .bind(&new.object_key)
            .bind(new.storage_profile_id)
            .bind(new.size_bytes)
            .bind(&new.checksum_sha256)
            .bind(&new.mime_type)
            .bind(sql(new.created_by))
            .bind(at)
            .bind(new.comment.as_deref())
            .bind(new.bump.is_major())
            .bind(COMMITTED_STATUS.as_str())
            .bind(COMMITTED_AV_STATUS.as_str())
            .fetch_one(&mut *conn)
            .await
            // The revision handed to the classifier is the one the file held *before* this
            // transaction's bump, because this transaction is about to roll back.
            .map_err(|error| classify_write(error, file_revision.saturating_sub(1)))?;
        let version = version_from_row(&row)?;

        // 3. The event, in the same transaction (`plans/M0-FOUNDATIONS.md` D6). Consumers — AV,
        //    DLP, indexing, preview — key on the version id and read the row; the payload carries
        //    what they need to route, not what they need to work, which is why neither the object
        //    key nor the checksum is in it. An outbox row outlives the version it describes and is
        //    replayed; putting content-derived values in it would spread them.
        Outbox::publish(
            &mut *conn,
            &Event::new(
                tenant,
                EventType::FileVersionCreated,
                ctx.actor,
                &json!({
                    "file_id": new.file_id,
                    "version_id": version.id,
                    "major": version.number.major,
                    "minor": version.number.minor,
                    "size_bytes": version.size_bytes,
                    "mime_type": version.mime_type,
                    "status": version.status.as_str(),
                    "restored_from": restored_from,
                }),
            )?
            // The event's instant is the version's `created_at`, not "whenever the transaction got
            // here", so the event and the row it describes agree.
            .with_occurred_at(version.created_at),
        )
        .await?;

        // 4. The audit row, last and in the same transaction. Last because the two writes above are
        //    what it describes; in the same transaction because an audit row that survived a
        //    rolled-back commit would describe something that never happened.
        let audit =
            record_in_tx(&mut *conn, Self::audit_event(ctx, &version, restored_from), chain)
                .await?;

        tracing::info!(
            tenant_id = %tenant,
            file_id = %new.file_id,
            version_id = %version.id,
            version = %version.number,
            restored = restored_from.is_some(),
            "version committed"
        );

        Ok(CommittedVersion { version, file_revision, audit })
    }

    /// Builds the audit row for a commit.
    ///
    /// `file.version_restore` for a restore and `file.edit` for an ordinary commit, because they
    /// are different permissions (`docs/03-LLD.md §12`) and an auditor filtering for "who put this
    /// content back" must not have to infer it from a detail field.
    ///
    /// The detail carries the version number, the size and — for a restore — the source version.
    /// It carries no name, no object key and no checksum: `Detail` refuses credential-shaped field
    /// names structurally, and content-shaped values are kept out by not putting them there.
    fn audit_event(
        ctx: &RequestContext,
        version: &FileVersion,
        restored_from: Option<VersionId>,
    ) -> AuditEvent {
        let action = if restored_from.is_some() {
            Action::File(FileAction::VersionRestore)
        } else {
            Action::File(FileAction::Edit)
        };

        let mut detail = Detail::empty();
        // Each key is a fixed literal with no credential marker, so none of these can be refused.
        // Log rather than fail if that ever stops being true: losing a detail field is a far better
        // outcome than losing the audit row, and the same choice is made in `enclave_audit`.
        for (key, value) in [
            ("version", json!(version.number.to_string())),
            ("size_bytes", json!(version.size_bytes)),
            ("status", json!(version.status.as_str())),
            ("restored_from", json!(restored_from)),
        ] {
            if let Err(error) = detail.try_insert(key, value) {
                tracing::error!(%error, key, "a version audit detail field was dropped");
            }
        }

        AuditEvent::builder(ctx, action, Outcome::Allow)
            .resource(&ResourceRef::version(ctx.tenant_id, version.id))
            .occurred_at(version.created_at)
            .detail(detail)
            .build()
    }
}

/// A restore request: which version to bring back, and where its fresh copy already lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreVersion {
    /// The file whose history is being restored from.
    pub file_id: FileId,
    /// The version to restore. Must belong to `file_id` and be servable.
    pub source: VersionId,
    /// The key the caller has already copied the source's bytes to. A *new* key — see
    /// [`VersionService::restore`].
    pub object_key: String,
    /// Whether the restored version is published or a draft.
    pub bump: VersionBump,
    /// Who is restoring. Becomes the new version's `created_by`.
    pub restored_by: UserId,
    /// The comment, as the user typed it.
    pub comment: Option<String>,
}

/// Points the file at the new version and bumps its optimistic-concurrency revision.
///
/// `deleted_at IS NULL` because a version cannot be committed into a trashed file: the foreign key
/// would accept it, since the trash is a soft delete, and the result would be content added to
/// something the user believes they deleted.
///
/// `status = 'PROCESSING'` on every commit. The file now points at a version nobody may read, and a
/// file advertising `AVAILABLE` while its current version is `SCANNING` is precisely the state
/// `CLAUDE.md` rule 9 forbids.
const BUMP_FILE: &str = "UPDATE files \
     SET current_version_id = $3, \
         size_bytes         = $4, \
         mime_type          = $5, \
         status             = 'PROCESSING', \
         revision           = revision + 1, \
         modified_by        = $6, \
         modified_at        = $7 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
     RETURNING revision";

/// Inserts the version, numbering it from the file's existing history in the same statement.
///
/// The numbering rule, in full:
///
/// * a **major** commit takes `MAX(major) + 1` and minor `0`, so the first version of any file is
///   `1.0` and every published version after it is `n.0`;
/// * a **minor** commit stays on the current major — `MAX(major)`, or `1` when there is no history
///   yet — and takes the next minor within it.
///
/// One statement and one boolean parameter rather than two SQL strings chosen by a branch: two
/// strings are two query plans and two places for the rule to drift, and a numbering rule that
/// differs between the major and minor paths is a history with holes in it.
///
/// Every parameter is cast explicitly. In an `INSERT … SELECT` the server has to infer each
/// parameter's type from the target column, and an inference that lands on `text` where the driver
/// sends a binary `bigint` fails at execution rather than at review.
const INSERT_VERSION: &str = concat!(
    "WITH numbering AS (",
    " SELECT CASE WHEN $12 THEN COALESCE(MAX(major), 0) + 1",
    " ELSE COALESCE(MAX(major), 1) END AS major",
    " FROM file_versions WHERE tenant_id = $2::uuid AND file_id = $3::uuid",
    ") ",
    "INSERT INTO file_versions",
    " (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,",
    " mime_type, major, minor, status, av_status, created_by, created_at, comment) ",
    "SELECT $1::uuid, $2::uuid, $3::uuid, $4::text, $5::uuid, $6::bigint, $7::text, $8::text,",
    " numbering.major,",
    " CASE WHEN $12 THEN 0 ELSE COALESCE((SELECT MAX(v.minor) FROM file_versions v",
    " WHERE v.tenant_id = $2::uuid AND v.file_id = $3::uuid AND v.major = numbering.major), -1)",
    " + 1 END,",
    " $13::text, $14::text, $9::uuid, $10::timestamptz, $11::text",
    " FROM numbering ",
    "RETURNING ",
    version_columns!()
);

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn both_statements_carry_the_application_tenant_predicate() {
        // RLS is the other layer and neither is redundant (`docs/04-DATA-MODEL.md §3`).
        assert!(BUMP_FILE.contains("tenant_id = $1"));
        assert!(INSERT_VERSION.contains("tenant_id = $2::uuid"));
        // Both reads of `file_versions` inside the numbering — the outer aggregate that finds the
        // major, and the inner lookup that finds the minor within it — carry their own predicate.
        // Neither inherits one, and a numbering statement that read another tenant's history would
        // hand out a version number derived from it.
        assert_eq!(INSERT_VERSION.matches("tenant_id = $2::uuid").count(), 2);
    }

    #[test]
    fn a_commit_never_writes_an_available_version() {
        // `CLAUDE.md` rule 9, as a property of the constants rather than of a review.
        assert_eq!(COMMITTED_STATUS, VersionStatus::Scanning);
        assert_eq!(COMMITTED_AV_STATUS, AvStatus::Pending);
        assert_ne!(COMMITTED_STATUS, VersionStatus::Available);
        assert_ne!(COMMITTED_AV_STATUS, AvStatus::Clean);
        // And the statement takes the status as a bound parameter from those constants, so there
        // is no literal in the SQL that could be edited independently of them.
        assert!(!INSERT_VERSION.contains("'AVAILABLE'"));
        assert!(!INSERT_VERSION.contains("'CLEAN'"));
    }

    #[test]
    fn committing_a_version_moves_the_file_out_of_available() {
        // The other half of the same rule: the file must not advertise content it cannot serve.
        assert!(BUMP_FILE.contains("status             = 'PROCESSING'"));
        assert!(!BUMP_FILE.contains("'AVAILABLE'"));
    }

    #[test]
    fn a_trashed_file_cannot_receive_a_version() {
        assert!(BUMP_FILE.contains("deleted_at IS NULL"));
    }

    #[test]
    fn the_file_revision_is_incremented_by_the_database() {
        // Read-modify-write in the application loses a concurrent bump, and `revision` is the
        // optimistic-concurrency key every mutation checks (`docs/03-LLD.md §14`).
        assert!(BUMP_FILE.contains("revision           = revision + 1"));
        assert!(BUMP_FILE.contains("RETURNING revision"));
    }

    #[test]
    fn the_insert_returns_every_column_the_decoder_reads() {
        assert!(INSERT_VERSION.contains(crate::row::VERSION_COLUMNS));
    }

    #[test]
    fn every_parameter_of_the_insert_is_cast() {
        // An `INSERT … SELECT` infers parameter types from the target column, and a wrong inference
        // fails at execution rather than at review. Each of the fourteen appears with a cast.
        for placeholder in 1..=14 {
            let cast = format!("${placeholder}::");
            assert!(
                INSERT_VERSION.contains(&cast) || placeholder == 12,
                "${placeholder} is bound without a cast"
            );
        }
        // $12 is the bump, used only as a `CASE WHEN` condition, which forces boolean on its own.
        assert!(INSERT_VERSION.contains("CASE WHEN $12 THEN"));
    }

    #[test]
    fn the_numbering_starts_at_one_zero_for_both_bumps() {
        // With no history: a major commit takes MAX(major)+1 over an empty set = 0+1 = 1, minor 0;
        // a minor commit takes COALESCE(MAX(major), 1) = 1 and MAX(minor) over an empty set,
        // COALESCEd to -1, +1 = 0. Both land on 1.0 — asserted here as the shape of the SQL, and
        // executed against a real database in `tests/versions.rs`.
        assert!(INSERT_VERSION.contains("COALESCE(MAX(major), 0) + 1"));
        assert!(INSERT_VERSION.contains("COALESCE(MAX(major), 1)"));
        assert!(INSERT_VERSION.contains("numbering.major), -1)"));
    }

    #[test]
    fn a_restore_and_a_commit_audit_different_actions() {
        // An auditor filtering for "who put this content back" must not have to infer it.
        assert_ne!(
            Action::File(FileAction::VersionRestore),
            Action::File(FileAction::Edit),
            "the two actions this module writes must stay distinct"
        );
        assert!(Action::File(FileAction::VersionRestore).is_mutating());
        assert!(Action::File(FileAction::Edit).is_mutating());
    }
}
