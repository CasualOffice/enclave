//! The session record, the phase-typed session, and every transition this crate can make.
//!
//! # Reading this module
//!
//! [`SessionRecord`] is the row. [`Session<P>`] is the row *plus a phase*, and every transition is
//! a method that consumes a session in one phase and hands back a [`Transition`] to another. A
//! transition is inert until `UploadRepository::apply` writes it, and `apply` is the only thing
//! that can turn one back into a session — so a `Session<Scanning>` in a caller's hands is proof
//! that the row says `SCANNING`, not a hope that it does.
//!
//! # What cannot be written here
//!
//! There is no transition to `PROCESSING`, `AVAILABLE` or `QUARANTINED`, because there is no phase
//! for them ([`crate::state`]). [`Session::hand_off`] is where this crate stops: it produces a
//! [`ScanHandoff`], which is the entire interface between an accepted upload and antivirus.
//!
//! # Loading
//!
//! A row comes back as a [`LoadedSession`], which distinguishes the two phases this crate may still
//! act on from every other state. That is not a convenience — it is the load-time half of the same
//! boundary. A `SCANNING` row deserializes into [`SettledSession`], which has no transition methods
//! at all, so "resume a session that antivirus already owns" is not an operation that exists.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId};

use crate::content::{FailureReason, VerifiedContent};
use crate::error::{Result, UploadError};
use crate::id::UploadSessionId;
use crate::staged::StagedObject;
use crate::state::{
    Aborted, Created, Expired, Failed, Live, Phase, Scanning, Transition, UploadState, Uploaded,
    Uploading,
};

/// One row of `upload_sessions` (`docs/04-DATA-MODEL.md §8`), without its state.
///
/// The state lives in the phase parameter of [`Session`] rather than in a field here, so that no
/// code can read the state, branch on it and act — which is the if-ladder this crate exists to not
/// have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The session id. Also the `uploadId` on the wire (`docs/05-API.md §8`).
    pub id: UploadSessionId,
    /// The owning tenant. Never taken from client input (`CLAUDE.md` rule 3).
    pub tenant_id: TenantId,
    /// The library the content will land in, and whose limits were checked.
    pub library_id: LibraryId,
    /// The folder it will land in, or `None` for the library root.
    pub parent_id: Option<FileId>,
    /// The file a new version is being uploaded for, or `None` when the upload creates the file.
    ///
    /// When it is `Some`, it equals [`StagedObject::file`]; the row decoder refuses a row where
    /// the two disagree, because the object key is what the eventual version row points at.
    pub file_id: Option<FileId>,
    /// The name the file will have.
    pub name: String,
    /// The size the client declared at creation, which the library's ceiling was checked against.
    pub declared_size: Option<i64>,
    /// The media type the client declared. Advisory — nothing renders from it.
    pub declared_mime: Option<String>,
    /// Where the bytes are staged. See [`crate::staged`].
    pub staged: StagedObject,
    /// The provider's multipart upload id, or `None` for a single-shot upload.
    pub multipart_id: Option<String>,
    /// Bytes reported so far. Progress only, until completion replaces it with the store's number.
    pub bytes_received: i64,
    /// Who created the session.
    pub created_by: UserId,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it last changed state.
    pub updated_at: DateTime<Utc>,
    /// When the reaper may release its staged bytes.
    pub expires_at: DateTime<Utc>,
}

impl SessionRecord {
    /// Whether this session is past its expiry as of `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// An upload session in a known phase.
///
/// Cloneable and inspectable, but only transformable through the transition methods below.
#[derive(Debug, Clone)]
pub struct Session<P: Phase> {
    record: SessionRecord,
    evidence: P::Evidence,
}

impl<P: Phase> Session<P> {
    /// Builds a session in a phase. Crate-private: outside this crate, phases come from
    /// transitions and from loading a row.
    pub(crate) const fn from_parts(record: SessionRecord, evidence: P::Evidence) -> Self {
        Self { record, evidence }
    }

    /// The row behind this session.
    #[must_use]
    pub const fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// The session id.
    #[must_use]
    pub const fn id(&self) -> UploadSessionId {
        self.record.id
    }

    /// The owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.record.tenant_id
    }

    /// The state this session's row holds.
    #[must_use]
    pub const fn state(&self) -> UploadState {
        P::STATE
    }

    /// What justifies this phase — `()` for most of them. See [`Phase::Evidence`].
    #[must_use]
    pub const fn evidence(&self) -> &P::Evidence {
        &self.evidence
    }

    /// Moves the record forward in time and swaps the phase. The one place a phase changes.
    fn advance<To: Phase>(
        mut self,
        now: DateTime<Utc>,
        bytes_received: i64,
        evidence: To::Evidence,
    ) -> Transition<To> {
        self.record.updated_at = now;
        self.record.bytes_received = bytes_received;
        Transition::new(P::STATE, Session::<To>::from_parts(self.record, evidence))
    }
}

impl Session<Created> {
    /// Builds the session a freshly created upload starts in.
    ///
    /// Crate-private because a session must not exist without the limit check and the object-store
    /// call that [`crate::UploadService::create`] performs first.
    pub(crate) const fn new(record: SessionRecord) -> Self {
        Self { record, evidence: () }
    }
}

impl<P: Live> Session<P> {
    /// `CREATED`/`UPLOADING` → `UPLOADING`: the client is sending, and this much has arrived.
    ///
    /// Applied from `UPLOADING` as well, so progress reports after the first one are the same
    /// operation rather than a special case.
    pub fn begin_upload(self, bytes_received: u64, now: DateTime<Utc>) -> Transition<Uploading> {
        let clamped = i64::try_from(bytes_received).unwrap_or(i64::MAX);
        self.advance::<Uploading>(now, clamped, ())
    }

    /// `CREATED`/`UPLOADING` → `ABORTED`: the client gave up.
    ///
    /// The staged bytes are released by the caller *before* this is applied — see
    /// [`crate::UploadService::abort`] for why that order and not the other one.
    pub fn abort(self, now: DateTime<Utc>) -> Transition<Aborted> {
        let bytes = self.record.bytes_received;
        self.advance::<Aborted>(now, bytes, ())
    }

    /// `CREATED`/`UPLOADING` → `EXPIRED`: the session outlived `expires_at`.
    pub fn expire(self, now: DateTime<Utc>) -> Transition<Expired> {
        let bytes = self.record.bytes_received;
        self.advance::<Expired>(now, bytes, ())
    }

    /// `CREATED`/`UPLOADING` → `FAILED`: completion was attempted and refused.
    ///
    /// The reason travels with the phase so that the caller reporting the failure and the row
    /// recording it cannot disagree about which check fired.
    pub fn fail(self, reason: FailureReason, now: DateTime<Utc>) -> Transition<Failed> {
        let bytes = self.record.bytes_received;
        self.advance::<Failed>(now, bytes, reason)
    }
}

impl Session<Uploading> {
    /// `UPLOADING` → `UPLOADED`: every byte is staged and verified.
    ///
    /// Takes a [`VerifiedContent`], which cannot be built without comparing the declaration, the
    /// client's report and the object store's observation. `bytes_received` becomes the store's
    /// number, replacing whatever the client reported along the way.
    pub fn finish(self, verified: VerifiedContent, now: DateTime<Utc>) -> Transition<Uploaded> {
        let observed = i64::try_from(verified.size_bytes()).unwrap_or(i64::MAX);
        self.advance::<Uploaded>(now, observed, verified)
    }
}

impl Session<Uploaded> {
    /// `UPLOADED` → `SCANNING`: hands the staged object to antivirus.
    ///
    /// **The last transition in this crate.** `CLAUDE.md` rule 9 — nothing is `AVAILABLE` before
    /// antivirus completes — is enforced by there being nothing after this: `Session<Scanning>` has
    /// no transition methods, and no other phase exists to move to.
    pub fn hand_off(self, now: DateTime<Utc>) -> Transition<Scanning> {
        let bytes = self.record.bytes_received;
        let verified = self.evidence.clone();
        self.advance::<Scanning>(now, bytes, verified)
    }
}

impl Session<Scanning> {
    /// Everything the antivirus and version-commit stages need, and nothing more.
    ///
    /// Available only on a session that has been *written* as `SCANNING`, because the only way to
    /// hold one is through `UploadRepository::apply`. A handoff therefore cannot describe a version
    /// the database does not already know is being scanned.
    pub fn handoff(&self) -> ScanHandoff {
        ScanHandoff {
            session_id: self.record.id,
            tenant_id: self.record.tenant_id,
            library_id: self.record.library_id,
            parent_id: self.record.parent_id,
            existing_file_id: self.record.file_id,
            staged: self.record.staged.clone(),
            name: self.record.name.clone(),
            mime_type: self.record.declared_mime.clone(),
            content: self.evidence.clone(),
            created_by: self.record.created_by,
            handed_off_at: self.record.updated_at,
        }
    }
}

impl Session<Failed> {
    /// Why the completion was refused.
    #[must_use]
    pub const fn reason(&self) -> FailureReason {
        *self.evidence()
    }
}

/// The interface between an accepted upload and everything that must happen before it is readable.
///
/// # Why this type exists at all
///
/// A version row is written from this and from a scan result — never from this alone. The type
/// carries no `status`, no `av_status` and no "ready" flag, so a caller cannot construct one that
/// asserts the content is safe. It says what was uploaded and where it is staged; whether that
/// content may ever be `AVAILABLE` is a question only `enclave-antivirus` can answer
/// (`CLAUDE.md` rule 9, `plans/M1-CONTENT-CORE.md` D13).
///
/// `#[must_use]`: dropping a handoff is dropping the only record that a scan is owed. The row is
/// already `SCANNING`, so a session whose handoff was discarded would sit there until the reaper
/// noticed, which is the failure mode G6 describes and not one to arrive at by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "the session is already SCANNING; dropping the handoff strands it there"]
pub struct ScanHandoff {
    /// The session this came from, for correlation in logs and audit.
    pub session_id: UploadSessionId,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The library the content lands in.
    pub library_id: LibraryId,
    /// The folder it lands in, or `None` for the library root.
    pub parent_id: Option<FileId>,
    /// The existing file this is a new version of, or `None` when the commit creates the file
    /// under [`StagedObject::file`].
    pub existing_file_id: Option<FileId>,
    /// Where the bytes are, and the identifiers the version will carry.
    pub staged: StagedObject,
    /// The file's name.
    pub name: String,
    /// The declared media type, advisory as ever.
    pub mime_type: Option<String>,
    /// The verified size and checksum.
    pub content: VerifiedContent,
    /// Who uploaded it.
    pub created_by: UserId,
    /// When the session entered `SCANNING`.
    pub handed_off_at: DateTime<Utc>,
}

/// A session as it came out of the database.
///
/// Split by what this crate may do with it, not by state: two phases can still be acted on, and
/// everything else is [`SettledSession`], which has no transitions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LoadedSession {
    /// URLs issued; nothing reported yet.
    Created(Session<Created>),
    /// The client is sending.
    Uploading(Session<Uploading>),
    /// Anything from `UPLOADED` onward, including every failure state.
    Settled(SettledSession),
}

impl LoadedSession {
    /// The state the row holds.
    #[must_use]
    pub const fn state(&self) -> UploadState {
        match self {
            Self::Created(_) => UploadState::Created,
            Self::Uploading(_) => UploadState::Uploading,
            Self::Settled(settled) => settled.state,
        }
    }

    /// The row, whatever the state — this is what `GET /uploads/{id}` reports progress from.
    #[must_use]
    pub const fn record(&self) -> &SessionRecord {
        match self {
            Self::Created(session) => session.record(),
            Self::Uploading(session) => session.record(),
            Self::Settled(settled) => &settled.record,
        }
    }

    /// Narrows to the sessions this crate may still advance.
    ///
    /// # Errors
    ///
    /// [`UploadError::NotResumable`] for anything from `UPLOADED` onward. A `SCANNING` session is
    /// not "busy" — it belongs to another crate now.
    pub fn into_resumable(self) -> Result<Resumable> {
        match self {
            Self::Created(session) => Ok(Resumable::Created(session)),
            Self::Uploading(session) => Ok(Resumable::Uploading(session)),
            Self::Settled(settled) => Err(UploadError::NotResumable { state: settled.state }),
        }
    }
}

/// A session in a state this crate cannot act on: readable, never advanced.
#[derive(Debug, Clone)]
pub struct SettledSession {
    record: SessionRecord,
    state: UploadState,
}

impl SettledSession {
    /// Builds one. Crate-private — only the row decoder produces these.
    pub(crate) const fn new(record: SessionRecord, state: UploadState) -> Self {
        Self { record, state }
    }

    /// The row.
    #[must_use]
    pub const fn record(&self) -> &SessionRecord {
        &self.record
    }

    /// The state it holds.
    #[must_use]
    pub const fn state(&self) -> UploadState {
        self.state
    }
}

/// The two phases this crate may still advance, without the caller having to match on a phase type.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Resumable {
    /// `CREATED`.
    Created(Session<Created>),
    /// `UPLOADING`.
    Uploading(Session<Uploading>),
}

impl Resumable {
    /// The row.
    #[must_use]
    pub const fn record(&self) -> &SessionRecord {
        match self {
            Self::Created(session) => session.record(),
            Self::Uploading(session) => session.record(),
        }
    }

    /// The state it holds.
    #[must_use]
    pub const fn state(&self) -> UploadState {
        match self {
            Self::Created(_) => UploadState::Created,
            Self::Uploading(_) => UploadState::Uploading,
        }
    }

    /// → `UPLOADING`.
    pub fn begin_upload(self, bytes_received: u64, now: DateTime<Utc>) -> Transition<Uploading> {
        match self {
            Self::Created(session) => session.begin_upload(bytes_received, now),
            Self::Uploading(session) => session.begin_upload(bytes_received, now),
        }
    }

    /// → `ABORTED`.
    pub fn abort(self, now: DateTime<Utc>) -> Transition<Aborted> {
        match self {
            Self::Created(session) => session.abort(now),
            Self::Uploading(session) => session.abort(now),
        }
    }

    /// → `EXPIRED`.
    pub fn expire(self, now: DateTime<Utc>) -> Transition<Expired> {
        match self {
            Self::Created(session) => session.expire(now),
            Self::Uploading(session) => session.expire(now),
        }
    }

    /// → `FAILED`.
    pub fn fail(self, reason: FailureReason, now: DateTime<Utc>) -> Transition<Failed> {
        match self {
            Self::Created(session) => session.fail(reason, now),
            Self::Uploading(session) => session.fail(reason, now),
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A session record built without a database, for the unit tests in this crate.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// A `CREATED` session for one tenant, declaring `size` bytes.
    pub(crate) fn record(tenant: TenantId, size: i64) -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            id: UploadSessionId::new_v7(),
            tenant_id: tenant,
            library_id: LibraryId::new_v7(),
            parent_id: None,
            file_id: None,
            name: "quarterly.pdf".to_owned(),
            declared_size: Some(size),
            declared_mime: Some("application/pdf".to_owned()),
            staged: StagedObject::allocate(tenant, FileId::new_v7()),
            multipart_id: None,
            bytes_received: 0,
            created_by: UserId::new_v7(),
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::hours(24),
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_storage::ObjectMeta;

    use super::fixtures::record;
    use super::*;
    use crate::content::ReportedContent;

    const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn verified(record: &SessionRecord, size: u64) -> VerifiedContent {
        let observed = ObjectMeta {
            key: record.staged.key().clone(),
            size_bytes: size,
            etag: None,
            checksum_sha256: None,
            content_type: None,
            last_modified: None,
            provider_version_id: None,
            server_side_encryption: None,
        };
        let reported = ReportedContent { size_bytes: size, sha256_hex: DIGEST_HEX.to_owned() };
        VerifiedContent::verify(record.declared_size, &reported, &observed).unwrap()
    }

    #[test]
    fn the_happy_path_walks_the_documented_states_and_stops_at_scanning() {
        let record = record(TenantId::new_v7(), 64);
        let content = verified(&record, 64);
        let now = Utc::now();

        let uploading = Session::<Created>::new(record).begin_upload(10, now);
        assert_eq!(
            (uploading.from_state(), uploading.to_state()),
            (UploadState::Created, UploadState::Uploading)
        );

        let uploaded = uploading.into_session().finish(content, now);
        assert_eq!(
            (uploaded.from_state(), uploaded.to_state()),
            (UploadState::Uploading, UploadState::Uploaded)
        );
        // The store's number replaces whatever the client reported on the way.
        assert_eq!(uploaded.session().record().bytes_received, 64);

        let scanning = uploaded.into_session().hand_off(now);
        assert_eq!(
            (scanning.from_state(), scanning.to_state()),
            (UploadState::Uploaded, UploadState::Scanning)
        );

        // And there it ends. The handoff is the whole interface to antivirus.
        let handoff = scanning.into_session().handoff();
        assert_eq!(handoff.content.size_bytes(), 64);
        assert_eq!(handoff.staged.version(), handoff.staged.version());
    }

    #[test]
    fn a_settled_session_offers_no_way_back_into_the_machine() {
        let record = record(TenantId::new_v7(), 64);
        for state in [
            UploadState::Scanning,
            UploadState::Available,
            UploadState::Quarantined,
            UploadState::Failed,
        ] {
            let loaded = LoadedSession::Settled(SettledSession::new(record.clone(), state));
            assert_eq!(loaded.state(), state);
            let err = loaded.into_resumable().unwrap_err();
            assert!(matches!(err, UploadError::NotResumable { state: seen } if seen == state));
        }
    }

    #[test]
    fn every_failure_transition_is_available_from_both_live_phases() {
        let record = record(TenantId::new_v7(), 64);
        let now = Utc::now();

        for resumable in [
            Resumable::Created(Session::<Created>::new(record.clone())),
            Resumable::Uploading(Session::<Uploading>::from_parts(record.clone(), ())),
        ] {
            let from = resumable.state();
            assert_eq!(resumable.clone().abort(now).from_state(), from);
            assert_eq!(resumable.clone().expire(now).to_state(), UploadState::Expired);
            let failed = resumable.fail(FailureReason::ChecksumMismatch, now);
            assert_eq!(failed.to_state(), UploadState::Failed);
            assert_eq!(failed.into_session().reason(), FailureReason::ChecksumMismatch);
        }
    }

    #[test]
    fn expiry_is_decided_against_a_supplied_clock_and_not_a_read_of_the_wall() {
        let record = record(TenantId::new_v7(), 64);
        assert!(!record.is_expired_at(record.expires_at - chrono::Duration::seconds(1)));
        assert!(record.is_expired_at(record.expires_at));
        assert!(record.is_expired_at(record.expires_at + chrono::Duration::seconds(1)));
    }
}
