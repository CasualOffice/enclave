//! Creating, completing and abandoning an upload.
//!
//! # What runs before this
//!
//! The policy chain, in the handler (`plans/M1-CONTENT-CORE.md` D11). This service is
//! *unauthorized by construction*: it reads no ACL, evaluates no policy and takes no `Actor`
//! beyond the `UserId` it records. It is safe only because the routing lint proves the caller ran
//! `PolicyEngine::enforce` first.
//!
//! What it *does* enforce is the library's own acceptance rules, and it enforces them in the one
//! order that matters: **limits first, object store second**. `docs/05-API.md §8` requires the
//! file-type and size checks to happen before URLs are issued, so a rejected upload never consumes
//! bandwidth. In [`UploadService::create`] there is exactly one call to
//! [`BlobStore::create_upload`](enclave_storage::BlobStore::create_upload) and
//! [`UploadLimits::check`] is above it.
//!
//! # Where this stops
//!
//! [`UploadService::complete`] advances a session to `SCANNING` and returns a
//! [`ScanHandoff`]. It does not create a file, does not write a version row and cannot mark
//! anything `AVAILABLE` — there is no phase for that and no flag that would produce one
//! (`CLAUDE.md` rule 9). `docs/05-API.md §8` says the same thing from the client's side: the
//! response to `complete` is `202` with `state: "SCANNING"`.
//!
//! # Transactions and the object store
//!
//! Blob storage cannot join a SQL transaction (`docs/03-LLD.md §15`), so every function here is
//! explicit about which side moves first:
//!
//! * **Create** — insert the row *after* the store call, so a session never exists without
//!   somewhere to put its bytes.
//! * **Complete** — the two state writes (`UPLOADED`, then `SCANNING`) happen in the caller's
//!   transaction after the store confirms, so a crash between them rolls back to `UPLOADING`
//!   rather than stranding a row.
//! * **Abort and reap** — delete the bytes *before* marking the row. The reverse order leaks: the
//!   reaper's index excludes `ABORTED`, so bytes orphaned after a failed delete would never be
//!   looked at again.

use chrono::{DateTime, Duration, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId};
use enclave_db::TenantScoped;
use enclave_storage::{BlobStore, CompletedPart, UploadRequest, UploadTarget};
use sqlx::PgConnection;

use crate::content::{is_lowercase_sha256_hex, FailureReason, ReportedContent, VerifiedContent};
use crate::error::{Result, UploadError};
use crate::id::UploadSessionId;
use crate::limits::UploadLimits;
use crate::quota::{preflight, Preflight};
use crate::repo::UploadRepository;
use crate::session::{LoadedSession, ScanHandoff, Session, SessionRecord};
use crate::staged::{completion_session, StagedObject};
use crate::state::{Aborted, Created, Failed, Scanning};

/// What the upload will become.
///
/// A closed choice rather than a nullable `file_id`, because the two cases differ in what the
/// commit does and a caller that passed `None` by accident would silently create a second file
/// instead of a new version of the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadIntent {
    /// The commit creates a new file, under the [`FileId`] the staged key already carries.
    NewFile,
    /// The commit adds a version to an existing file.
    NewVersion(FileId),
}

/// A request to start an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUpload {
    /// The library the content lands in, and whose limits apply.
    pub library_id: LibraryId,
    /// The folder it lands in, or `None` for the library root.
    pub parent_id: Option<FileId>,
    /// New file, or new version of one.
    pub intent: UploadIntent,
    /// The file's name. Its extension is what the library's rules are checked against.
    pub name: String,
    /// The size the client promises to send. Checked against the library's ceiling *here*, and
    /// again against the object store at completion.
    pub declared_size: u64,
    /// The declared media type. Advisory: the platform's own detection is authoritative and
    /// nothing renders from this.
    pub declared_mime: Option<String>,
    /// A lowercase hex SHA-256 the client declares up front, if it has one.
    ///
    /// Passed to the provider so a corrupted transfer is refused at the edge rather than stored.
    /// It is not persisted — `upload_sessions` has no column for it (`docs/04-DATA-MODEL.md §8`) —
    /// so completion verifies the digest the client repeats there against the store's own.
    pub declared_sha256: Option<String>,
    /// Who is uploading.
    pub created_by: UserId,
}

/// A created session and the URLs its bytes go to.
#[derive(Debug, Clone)]
#[must_use = "the URLs are the response; dropping this leaves a session nobody can upload to"]
pub struct IssuedUpload {
    /// The session, in `CREATED`.
    pub session: Session<Created>,
    /// Single-shot `PUT` or multipart, as the store decided from the declared size.
    pub target: UploadTarget,
    /// When the URLs stop working.
    ///
    /// Shorter than the session's own `expires_at` and deliberately so
    /// (`plans/M1-CONTENT-CORE.md` D14): a URL must not outlive the decision that produced it. A
    /// client that runs out of time starts a new session rather than asking for an extension.
    pub urls_expire_at: DateTime<Utc>,
}

/// The outcome of a completion attempt.
///
/// Both arms are *persisted* outcomes, which is why a verification mismatch is not an `Err`: the
/// caller commits either way, and a refusal that rolled back would invite the client to retry a
/// completion that cannot succeed. See [`crate::content`].
#[derive(Debug, Clone)]
#[must_use = "both outcomes carry a session whose state has already been written"]
pub enum Completion {
    /// Verified, written as `SCANNING`, and owed a scan.
    HandedOff {
        /// The session, in `SCANNING`. This crate offers no transition out of it.
        session: Session<Scanning>,
        /// Everything antivirus and the version commit need.
        ///
        /// Boxed because it is the larger half of a two-armed enum, and a `Completion::Refused`
        /// should not cost what a handoff costs to move.
        handoff: Box<ScanHandoff>,
    },
    /// Refused and written as `FAILED`.
    Refused {
        /// The session, in `FAILED`.
        session: Session<Failed>,
        /// Which check fired. [`FailureReason::to_error`] is the response.
        reason: FailureReason,
    },
}

/// Upload sessions, end to end.
#[derive(Debug, Clone, Copy, Default)]
pub struct UploadService;

impl UploadService {
    /// Validates, reserves a staging key, asks the store for URLs and records the session.
    ///
    /// The tenant's stored-byte quota is consulted here too, and *only* as a courtesy: see
    /// [`crate::quota`]. It refuses an upload that already cannot fit, before a URL is issued, and
    /// it admits nothing — the binding decision is the charge inside the version commit
    /// (`plans/M4-GOVERNANCE.md` D31).
    ///
    /// # Errors
    ///
    /// [`UploadError::ExtensionNotAllowed`], [`UploadError::FileTooLarge`],
    /// [`UploadError::InvalidName`], [`UploadError::InvalidDeclaredChecksum`] and
    /// [`UploadError::StorageQuotaExceeded`] — all of them *before* the object store is contacted —
    /// plus storage and database failures after it.
    pub async fn create(
        tx: &mut TenantScoped,
        blob: &dyn BlobStore,
        tenant: TenantId,
        request: &NewUpload,
        limits: &UploadLimits,
        session_ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<IssuedUpload> {
        // Every refusal that can be decided from the request happens here, above the store call.
        // Moving any of it below would spend the client's bandwidth to reach the same answer.
        limits.check(&request.name, request.declared_size)?;
        if let Some(declared) = &request.declared_sha256 {
            if !is_lowercase_sha256_hex(declared) {
                return Err(UploadError::InvalidDeclaredChecksum);
            }
        }
        // The quota read is last of the four, because it is the only one that costs a round trip
        // and the other three refuse from the request alone. It is still above the store call,
        // which is what `docs/05-API.md §8` asks for.
        if let Preflight::Refused { limit_bytes } = preflight(tx, request.declared_size).await? {
            return Err(UploadError::StorageQuotaExceeded { limit_bytes });
        }

        let file_id = match request.intent {
            UploadIntent::NewVersion(file_id) => file_id,
            UploadIntent::NewFile => FileId::new_v7(),
        };
        let staged = StagedObject::allocate(tenant, file_id);

        let mut upload = UploadRequest::new(staged.key().clone(), request.declared_size);
        if let Some(mime) = &request.declared_mime {
            upload = upload.with_content_type(mime.clone());
        }
        if let Some(digest) = &request.declared_sha256 {
            upload = upload.with_checksum_sha256(digest.clone());
        }
        let issued = blob.create_upload(upload).await?;

        let multipart_id = match &issued.target {
            UploadTarget::Single { .. } => None,
            UploadTarget::Multipart { upload_id, .. } => Some(upload_id.clone()),
        };

        let record = SessionRecord {
            id: UploadSessionId::new_v7(),
            tenant_id: tenant,
            library_id: request.library_id,
            parent_id: request.parent_id,
            file_id: match request.intent {
                UploadIntent::NewVersion(file_id) => Some(file_id),
                // Left NULL on purpose: the file does not exist yet, and writing a not-yet-created
                // id into a column that references `files` would fail the composite foreign key.
                // The identifier is not lost — it is in the staged key.
                UploadIntent::NewFile => None,
            },
            name: request.name.trim().to_owned(),
            declared_size: Some(i64::try_from(request.declared_size).unwrap_or(i64::MAX)),
            declared_mime: request.declared_mime.clone(),
            staged,
            multipart_id,
            bytes_received: 0,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
            expires_at: now + session_ttl,
        };

        let session = Session::<Created>::new(record);
        UploadRepository::insert(tx, &session).await?;

        tracing::info!(
            tenant_id = %tenant,
            upload_session_id = %session.id(),
            library_id = %request.library_id,
            declared_size = request.declared_size,
            multipart = session.record().multipart_id.is_some(),
            "upload session created"
        );

        Ok(IssuedUpload { session, target: issued.target, urls_expire_at: issued.expires_at })
    }

    /// Reads a session, in whatever state it is in.
    ///
    /// This is what `GET /uploads/{id}` reports from, which is why it returns every state rather
    /// than only the resumable ones: a client polling after `complete` is entitled to see
    /// `SCANNING`, and later `QUARANTINED`.
    ///
    /// # Errors
    ///
    /// [`UploadError::NotFound`] — which is also the answer for another tenant's session — and
    /// database failures.
    pub async fn find(
        conn: &mut PgConnection,
        tenant: TenantId,
        id: UploadSessionId,
    ) -> Result<LoadedSession> {
        UploadRepository::find(conn, tenant, id).await?.ok_or(UploadError::NotFound)
    }

    /// Records progress reported by the client.
    ///
    /// Advances `CREATED` to `UPLOADING` the first time. Progress is advisory — the number that
    /// ends up on the version comes from the object store — so this exists for the progress
    /// display and for the reaper's benefit, not as an input to any decision.
    ///
    /// # Errors
    ///
    /// [`UploadError::NotFound`], [`UploadError::NotResumable`], [`UploadError::Expired`] and
    /// database failures.
    pub async fn record_progress(
        conn: &mut PgConnection,
        tenant: TenantId,
        id: UploadSessionId,
        bytes_received: u64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let resumable = Self::find(conn, tenant, id).await?.into_resumable()?;
        if resumable.record().is_expired_at(now) {
            return Err(UploadError::Expired);
        }
        UploadRepository::apply(conn, resumable.begin_upload(bytes_received, now)).await?;
        Ok(())
    }

    /// Finalizes an upload: `UPLOADING` → `UPLOADED` → `SCANNING`, or `FAILED`.
    ///
    /// Both state writes happen in the caller's transaction, so no committed row is ever
    /// `UPLOADED` — see [`UploadRepository::claim_expired`].
    ///
    /// # Errors
    ///
    /// [`UploadError::NotFound`], [`UploadError::NotResumable`] for a session antivirus already
    /// owns, [`UploadError::Expired`], [`UploadError::ConcurrentTransition`] if another request
    /// completes it first, and object-store or database failures. A size or checksum *mismatch* is
    /// not an error here — it is [`Completion::Refused`].
    pub async fn complete(
        conn: &mut PgConnection,
        blob: &dyn BlobStore,
        tenant: TenantId,
        id: UploadSessionId,
        reported: &ReportedContent,
        reported_parts: Vec<CompletedPart>,
        now: DateTime<Utc>,
    ) -> Result<Completion> {
        let resumable = Self::find(conn, tenant, id).await?.into_resumable()?;
        if resumable.record().is_expired_at(now) {
            return Err(UploadError::Expired);
        }
        // Object storage has no row-level security, so this is where the equivalent check happens.
        // The key came from the row, and the row came from a tenant-scoped query — the assertion is
        // cheap and covers the day one of those two stops being true.
        if !resumable.record().staged.key().belongs_to(tenant) {
            return Err(UploadError::NotFound);
        }

        let declared_size = resumable.record().declared_size;
        let uploading =
            UploadRepository::apply(conn, resumable.begin_upload(reported.size_bytes, now)).await?;
        let record = uploading.record();

        let store_session = completion_session(
            &record.staged,
            u64::try_from(record.declared_size.unwrap_or_default()).unwrap_or_default(),
            record.multipart_id.as_deref(),
            reported_parts,
            record.expires_at,
        )?;
        let observed = blob.complete_upload(&store_session).await?;

        let verified = match VerifiedContent::verify(declared_size, reported, &observed) {
            Ok(verified) => verified,
            Err(reason) => {
                // Persisted, not merely returned: the staged bytes are wrong and this session can
                // never succeed, so the row has to say so once the caller commits.
                tracing::warn!(
                    tenant_id = %tenant,
                    upload_session_id = %id,
                    reason = reason.as_str(),
                    "upload completion refused"
                );
                let session = UploadRepository::apply(conn, uploading.fail(reason, now)).await?;
                return Ok(Completion::Refused { session, reason });
            }
        };

        let uploaded = UploadRepository::apply(conn, uploading.finish(verified, now)).await?;
        let scanning = UploadRepository::apply(conn, uploaded.hand_off(now)).await?;
        let handoff = scanning.handoff();

        tracing::info!(
            tenant_id = %tenant,
            upload_session_id = %id,
            version_id = %handoff.staged.version(),
            size_bytes = handoff.content.size_bytes(),
            checksum_confirmed_by_provider = handoff.content.checksum_evidence().is_confirmed(),
            "upload verified and handed to antivirus"
        );

        Ok(Completion::HandedOff { session: scanning, handoff: Box::new(handoff) })
    }

    /// Abandons a session and releases its staged bytes.
    ///
    /// The delete happens first. If it fails, the row stays claimable and the next attempt — or the
    /// reaper — tries again; if the row were marked `ABORTED` first, a failed delete would leave
    /// bytes that `idx_uploads_expiry` deliberately excludes, and nothing would ever look at them
    /// again.
    ///
    /// # Errors
    ///
    /// [`UploadError::NotFound`], [`UploadError::NotResumable`] — including for a session already
    /// aborted, which a handler may treat as a successful repeat of `DELETE` — and object-store or
    /// database failures.
    pub async fn abort(
        conn: &mut PgConnection,
        blob: &dyn BlobStore,
        tenant: TenantId,
        id: UploadSessionId,
        now: DateTime<Utc>,
    ) -> Result<Session<Aborted>> {
        let resumable = Self::find(conn, tenant, id).await?.into_resumable()?;
        if !resumable.record().staged.key().belongs_to(tenant) {
            return Err(UploadError::NotFound);
        }

        blob.delete(resumable.record().staged.as_str()).await?;
        let session = UploadRepository::apply(conn, resumable.abort(now)).await?;

        tracing::info!(
            tenant_id = %tenant,
            upload_session_id = %id,
            "upload session aborted and its staged bytes released"
        );

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    /// The one ordering `docs/05-API.md §8` is explicit about, asserted against the source rather
    /// than against behaviour: a reordering that put the store call first would still pass every
    /// functional test, and would still have spent the user's bandwidth.
    #[test]
    fn the_limit_check_precedes_the_only_call_to_the_object_store() {
        let source = include_str!("service.rs");
        let body = source.split("pub async fn create(").nth(1).expect("create exists");
        let check = body.find("limits.check(").expect("create checks the limits");
        let store = body.find("blob.create_upload(").expect("create calls the store");
        assert!(check < store, "the library's limits must be checked before any URL is issued");
        assert_eq!(body.matches("blob.create_upload(").count(), 1, "one store call, one place");
    }

    /// The same guarantee for the quota, which `docs/05-API.md §8` names alongside the file-type
    /// and size checks. Asserted against the source for the same reason as above: an upload issued
    /// URLs and *then* refused would pass every functional test and would still have let a client
    /// start sending gigabytes.
    #[test]
    fn the_quota_preflight_also_precedes_the_only_call_to_the_object_store() {
        let source = include_str!("service.rs");
        let body = source.split("pub async fn create(").nth(1).expect("create exists");
        let quota = body.find("preflight(tx,").expect("create consults the quota");
        let store = body.find("blob.create_upload(").expect("create calls the store");
        assert!(quota < store, "a rejected upload must never consume bandwidth");
    }

    /// This service reads the quota and never moves it.
    ///
    /// The charge belongs to the version commit, in the transaction that writes the row it pays
    /// for. A charge raised here would be against a staged object that the nightly reconciliation
    /// — which measures `SUM(file_versions.size_bytes)` — cannot see, so it would be subtracted as
    /// drift on the first pass. Needles assembled at run time (`docs/12 §1.2`).
    #[test]
    fn nothing_in_this_service_moves_the_counter() {
        let source = include_str!("service.rs");
        for needle in [format!("charge_{}", "storage"), format!("release_{}", "storage")] {
            assert!(
                !source.contains(&needle),
                "`{needle}` in the upload service means bytes are metered before a version row \
                 exists to account for them"
            );
        }
    }
}
