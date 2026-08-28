//! `docs/05-API.md §8` — the four upload endpoints.
//!
//! ```text
//! POST   /api/v1/uploads                → { uploadId, method, urls|uploadUrl, partSize }
//! PUT    <signed part URLs>             → direct to object storage, never through us
//! POST   /api/v1/uploads/{id}/complete  → 202 { fileId, versionId, state: "SCANNING" }
//! GET    /api/v1/uploads/{id}           → progress and state
//! DELETE /api/v1/uploads/{id}           → abort and release staged bytes
//! ```
//!
//! # What this module is, and what it deliberately is not
//!
//! `crates/uploads` was complete, tested and reachable by nothing (`ENC-682`). This is the
//! transport in front of it, so the rule for every handler below is the same: **decide, then
//! delegate.** The policy chain runs here (`plans/M1-CONTENT-CORE.md` D11) because
//! [`UploadService`] is unauthorized by construction — it reads no ACL and takes no
//! [`enclave_core::Actor`] — and it is safe only because the ENC-110 routing lint proves the caller
//! ran `PolicyEngine::enforce` first.
//!
//! Nothing in this module reads a quota, computes a version number, decides a version's status or
//! writes a row a domain crate could write for it. [`promote`] calls two crates and adds nothing:
//! `enclave_files` inserts the node, `enclave_versions` charges the quota, numbers the version and
//! writes it. That is not modesty; each of those has a single owner elsewhere and a second one here
//! would be a second answer.
//!
//! # Rule 9, and where it is actually kept
//!
//! `CLAUDE.md` rule 9 says nothing is `AVAILABLE` before antivirus completes. [`complete`] does not
//! enforce that with a comparison — it cannot express the violation.
//! [`UploadService::complete`] hands back a [`Session<Scanning>`](enclave_uploads::Session), the
//! phase machine has nothing after `Scanning`, and the `state` field on the wire is rendered from
//! [`Session::state`](enclave_uploads::Session::state) rather than from a literal. So there is no
//! edit to this file that publishes an upload; the change would have to be made in the state
//! machine, where it is a compile error.
//!
//! `the_completion_response_cannot_name_a_readable_state` asserts the second half — that no
//! spelling of a readable state appears in this module at all — because the first half only holds
//! while the wire value keeps coming from the type.
//!
//! **`ENC-826` did not weaken any of that.** [`progress`] now reports whether the upload became
//! servable, and it still names no readable state: the answer is `isReadable` on a
//! [`VersionState`] rendered from the committed row, which is
//! `enclave_versions::FileVersion::is_readable` — the same predicate the delivery routes' query
//! splices. This module reads a verdict; it does not reach one. Both source-scanning tests below
//! pass unchanged, and that is the point of running them against this change rather than adjusting
//! them for it.
//!
//! # Where an upload's progress actually lives (`ENC-826`)
//!
//! The session's machine ends at `SCANNING`, so `GET /uploads/{id}` used to report `SCANNING`
//! forever — including long after the version was published — and never named a `fileId` for a
//! new-file upload, because the session row has none until the commit writes one. A client polling
//! the documented progress endpoint could not learn that its own upload had finished, and had to
//! go to `GET /files/{id}/versions` with an id that appeared only in the `complete` response.
//!
//! [`ProgressView`] carries the version now, and its documentation records why the session's own
//! column is left alone rather than advanced by the antivirus pass.
//!
//! # Where a completed upload goes next
//!
//! `ENC-691`. [`enclave_uploads::ScanHandoff`] is described by its own crate as *the entire
//! interface between an accepted upload and everything that has to happen before anyone can read
//! it*, and until this row closed **no crate consumed one**. A completed session left a row in
//! `SCANNING`, no `files` row and no `file_versions` row — so `crates/worker`'s antivirus pass,
//! which queues on `file_versions.av_status`, had nothing to find, and the reaper's
//! `holds_staged_bytes` excludes `SCANNING`, so the staged bytes were never released either. The
//! response named a `fileId` and a `versionId` for rows that did not exist.
//!
//! [`promote`] is the consumer. It takes the handoff **by value**, so the `#[must_use]` that made
//! dropping one visible is now a move: the completion path has no branch that can hold a handoff
//! and not commit it. It creates the `files` row when the upload creates a file, and then calls
//! [`enclave_versions::VersionService::commit`], which owns the quota charge (`ENC-589`), the
//! index manifest (`ENC-643`), the outbox row and the audit row. Nothing of that is re-implemented
//! here; this module decides and delegates, as every other handler in it does.
//!
//! **One transaction, and the session's state is inside it.** [`UploadService::complete`]'s write
//! to `SCANNING`, the `files` insert and everything `VersionService::commit` does share the
//! transaction [`complete`] opened. A session that says `SCANNING` while no version exists is the
//! stranded state this row is about, and putting the two writes in one transaction is what makes
//! it unrepresentable rather than merely unlikely. A refused *commit* — no quota headroom, a name
//! already taken — therefore rolls the session back to the state it was in, which is retryable;
//! a refused *completion* is still persisted as `FAILED`, because wrong bytes are not retryable.
//!
//! The two blockers recorded on `ENC-691` were both answerable. A new-file upload has no `files`
//! row because nothing had ever created one — [`enclave_files::NewFile`] now carries the id, which
//! it must, since `enclave_uploads::StagedObject` spent that id staging the bytes. And
//! `storage_profile_id` has no source because `ENC-573` established there is no
//! `storage_profiles` table: the honest value is
//! [`enclave_versions::UNPROVISIONED_STORAGE_PROFILE`], which says so and stays findable by the
//! backfill that will end it.

use core::str::FromStr as _;
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use enclave_audit::ChainMode;
use enclave_core::{
    Action, Actor, ContainerAction, Error, FieldError, FileAction, FileId, LibraryId, ReasonCode,
    RequestContext, RequestId, ResourceKind, ResourceRef, TenantId, UserId, ValidationCode,
};
use enclave_db::TenantScoped;
use enclave_files::{FileRepository, NewFile, Parent};
use enclave_libraries::LibraryRepository;
use enclave_storage::{BlobStore, CompletedPart, UploadTarget};
use enclave_uploads::{
    Completion, IssuedUpload, LoadedSession, NewUpload, ReportedContent, ScanHandoff, UploadIntent,
    UploadLimits, UploadService, UploadSessionId,
};
use enclave_versions::{
    CommittedVersion, NewVersion, VersionBump, VersionRepository, VersionService,
    UNPROVISIONED_STORAGE_PROFILE,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::VersionState;
use crate::error::{ApiError, Envelope};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// How long a session lives before [`enclave_uploads::reap_expired`] may release its bytes.
///
/// `docs/03-LLD.md §15` gives this as `upload.session_ttl`, *default 24h*. It is a constant here
/// rather than a configuration read because `crates/config` models no such key — writing one is a
/// change to the configuration model and belongs with the rest of `upload.*`, not smuggled in
/// beside a route. The documented default is what a deployment gets today, which is at least the
/// value the document promises.
const SESSION_TTL: Duration = Duration::hours(24);

/// The per-file ceiling applied when a library sets none of its own.
///
/// [`UploadLimits::from_library`] takes the tenant default as an argument precisely because
/// `libraries.max_file_size_bytes` is nullable and means *"use the tenant default"*. The tenant's
/// own figure would come from the `MAX_FILE_BYTES` quota kind of `docs/04 §17`, and `crates/db`'s
/// quota reader answers only for `STORAGE_BYTES` — so there is nothing to read.
///
/// 5 GiB is not an arbitrary placeholder: it is the size M1's fifth exit criterion names, so a
/// deployment that has configured nothing still accepts exactly the upload the product claims to
/// support and refuses the one it does not.
const TENANT_DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// What a version records when the client declared no media type.
///
/// `files.mime_type` and `file_versions.mime_type` are both `NOT NULL`, and `mimeType` on
/// `POST /uploads` is optional and advisory — nothing renders from it and nothing trusts it. RFC
/// 2046 §4.5.1 makes this the value for *"unrecognised subtype of unrecognised type"*, which is
/// exactly the state of knowledge at commit: the bytes went from the client to the object store and
/// this process has never seen one of them. The content pipeline is what determines the real type
/// (`ENC-132`), and guessing from the file name here would produce a value a reader would trust.
const UNDECLARED_MIME_TYPE: &str = "application/octet-stream";

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The body of `POST /api/v1/uploads`.
///
/// `deny_unknown_fields` for `ENC-615`'s reason: a request that carries a field this release does
/// not know is a client asking for something it will not get, and accepting it silently is how a
/// caller comes to believe a setting applied. It matters more here than on a read — every field
/// below either restricts the upload or decides where its bytes land.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateUploadRequest {
    /// The library the content lands in, and whose extension rules and ceiling apply.
    library_id: LibraryId,
    /// The folder inside it, or absent for the library root.
    #[serde(default)]
    parent_id: Option<FileId>,
    /// The file this is a new version of. Absent means the upload creates a file.
    ///
    /// A distinct field rather than an inference from `name`, because the two intents are
    /// separately deniable: creating content in a container is `container.create`, and adding a
    /// version to an existing file is `file.edit`.
    #[serde(default)]
    file_id: Option<FileId>,
    /// The file's name. Its extension is what the library's rules are checked against.
    name: String,
    /// The size the client promises to send, checked against the ceiling before a URL exists.
    size_bytes: u64,
    /// The declared media type. Advisory — nothing renders from it.
    #[serde(default)]
    mime_type: Option<String>,
    /// A lowercase hex SHA-256 of the whole object, declared before a URL exists.
    ///
    /// **Required**, and not advisory. It is signed into the pre-signed `PUT` as
    /// `x-amz-checksum-sha256` — returned in [`IssuedUploadView::required_headers`] — so the
    /// provider hashes the body it receives and refuses it if the two disagree. A client that
    /// declares one digest and sends other bytes gets a failed `PUT`, and `complete` never sees the
    /// object at all.
    ///
    /// It was optional and, worse, dropped by the S3 store even when supplied: the provider
    /// computed nothing, `complete` had nothing to compare against, and a digest of all zeroes over
    /// a real object answered `202` (`ENC-820`).
    sha256: String,
}

/// One part of a multipart upload, as `docs/05-API.md §8`'s `urls` array.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartView {
    part_number: u32,
    offset: u64,
    length: u64,
    url: String,
}

/// The response to `POST /api/v1/uploads`.
///
/// `uploadUrl` and `urls` are mutually exclusive and `method` says which to read, so a client never
/// has to infer the shape from which field is absent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuedUploadView {
    upload_id: String,
    /// `SINGLE` or `MULTIPART`, as the store decided from the declared size.
    method: &'static str,
    /// The one `PUT` target, for `SINGLE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_url: Option<String>,
    /// Headers the `PUT` **must** carry, exactly as given.
    ///
    /// Not optional decoration and not a hint. The URL is signed over these headers, so a `PUT`
    /// that omits one or alters its value fails the signature check outright — which is what makes
    /// `x-amz-checksum-sha256` an integrity control rather than a courtesy: a client cannot decline
    /// to be checked without also failing to upload.
    ///
    /// On the wire because the process that signs the URL is not the process that sends the bytes.
    /// `ENC-821` is this fact learned the hard way for `content-type`, which was signed, documented
    /// nowhere, and cost the first client two attempts to diagnose as a `403`; `content-type`
    /// therefore appears here too rather than only in a paragraph of `docs/05-API.md`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    required_headers: BTreeMap<String, String>,
    /// Every part in order, for `MULTIPART`.
    #[serde(skip_serializing_if = "Option::is_none")]
    urls: Option<Vec<PartView>>,
    /// The nominal part size. The last part is shorter; each entry in `urls` carries its own
    /// `length`, which is the authoritative number.
    #[serde(skip_serializing_if = "Option::is_none")]
    part_size: Option<u64>,
    /// When the signed URLs stop working — shorter than the session, by design
    /// (`plans/M1-CONTENT-CORE.md` D14: a URL must not outlive the decision that produced it).
    urls_expire_at: DateTime<Utc>,
    /// When the session itself expires and its staged bytes may be released.
    expires_at: DateTime<Utc>,
}

/// The response to `GET /api/v1/uploads/{id}`.
///
/// # Why `state` alone could never finish the story (`ENC-826`)
///
/// `state` is the **upload session's** state, and the session's machine ends at `SCANNING`: that
/// is the last transition [`enclave_uploads`] can make, by construction — `Session<Scanning>` has
/// no transition methods and `Processing`, `Available` and `Quarantined` are not phases in that
/// crate at all. Everything after the handoff happens to the *version*. So a client polling
/// `state` watched `SCANNING` forever, on a file that had been published minutes earlier, and the
/// endpoint that looks like the upload-progress API could not report the end of an upload.
///
/// [`version`](Self::version) is the answer, and it is the same [`VersionState`] that
/// `GET /files/{id}` returns as `currentVersion` — so a client that can read one can read the
/// other, and "is my upload ready" is the same field on both endpoints (`ENC-825`).
///
/// # Derived at read time, not written by the antivirus pass
///
/// The alternative was to have `crates/worker` write `upload_sessions.state` as it advances the
/// version. Three reasons it is read here instead.
///
/// * **It would be a second mutable copy of a fact `file_versions` already owns.** Two writable
///   copies of one truth drift, and the one that drifts is always the copy nothing reads back.
/// * **The copy would outlive nothing.** A session is transient — `enclave_uploads::reap_expired`
///   releases it after `upload.session_ttl`, 24h — while the version is permanent. Deriving keeps
///   answering after the session row's own state has stopped being interesting.
/// * **It would cost the type-level guarantee in `enclave_uploads::state`.** For the worker to
///   write `PROCESSING` or `AVAILABLE` onto a session, those would have to *become* phases in a
///   sealed machine whose entire purpose is that they are not — the one thing standing between an
///   `UPDATE` and a session that claims content is readable before anything scanned it
///   (`CLAUDE.md` rule 9). That is a large hole to open for a status field.
///
/// What that costs: `state` keeps saying `SCANNING` after handoff. That is not a lie — it is a
/// true and final statement about the *session*, whose job ended there — and the wire says so by
/// naming its subject. Overloading one field to span two rows with two owners and two lifetimes is
/// how a client ends up unable to tell which of them it is looking at.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressView {
    upload_id: String,
    /// The state the **session** row holds, from [`LoadedSession::state`]. Terminal at `SCANNING`;
    /// see the type's documentation, and read [`version`](Self::version) for what happened next.
    state: &'static str,
    library_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    /// The file this upload is for.
    ///
    /// For a new-version upload this is the file named at creation. For a **new-file** upload the
    /// session row carries no file id — the row is created by the commit — so it is read off the
    /// committed version and is absent until that version exists. Absent rather than optimistic on
    /// purpose: the id is knowable from the staged key the moment the session is created, and
    /// putting it on the wire before the commit would be a response naming a row nothing has
    /// written, which is exactly what `ENC-691` was.
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    /// The version this upload became, once [`promote`] has committed one.
    ///
    /// Absent before the handoff. Carries `isReadable`, so a client learns that its upload is
    /// servable from the same predicate the delivery routes will apply to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<VersionState>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    declared_size: Option<i64>,
    bytes_received: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// One part the client reports at completion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportedPart {
    part_number: u32,
    etag: String,
}

/// The body of `POST /api/v1/uploads/{id}/complete`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompleteUploadRequest {
    /// The number of bytes the client says it sent. Verified against the declaration *and* against
    /// what the object store observed; a mismatch is a persisted refusal, not a warning.
    size_bytes: u64,
    /// Lowercase hex SHA-256 of the content, as the client computed it.
    sha256: String,
    /// The parts, for a multipart upload. Empty or absent for a single-shot one.
    #[serde(default)]
    parts: Vec<ReportedPart>,
}

/// The response to `POST /api/v1/uploads/{id}/complete`.
///
/// `docs/05-API.md §8`: *"the response after `complete` is `202` with `state: "SCANNING"`"*.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HandedOffView {
    upload_id: String,
    /// The file the content belongs to — the existing one for a new version, and the one this
    /// request created for a new file.
    file_id: String,
    /// The version this upload became.
    ///
    /// Both identifiers are read off the committed row rather than off the staged key. They are the
    /// same values — the key reserved them when the session was created
    /// (`enclave_uploads::StagedObject`) — but reading them from the row is what makes the response
    /// a statement about rows that exist. `ENC-691` was precisely a `202` naming two that did not.
    version_id: String,
    /// Always `SCANNING`, and rendered from the session's phase rather than written here.
    state: &'static str,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/uploads`.
///
/// The chain runs before the library is read and long before the object store is touched, so a
/// caller who may not write here learns nothing about the library and spends no bandwidth.
/// `docs/05-API.md §8`'s promise — *"a rejected upload never consumes bandwidth"* — is kept one
/// layer down as well: [`UploadService::create`] checks the name, the extension, the ceiling and
/// the quota above its single call to the store, and asserts that ordering against its own source.
///
/// # Errors
///
/// [`ApiError`]: `404` when the library is another tenant's, absent, or not granted to this caller;
/// the denial's own status for any other refusal; `400` for a name, extension or checksum the
/// library will not accept — including an absent or malformed `sha256`, which is required because
/// it is what the provider is made to verify; `403` `QUOTA_EXCEEDED` when the declared size already
/// cannot fit, or when it is above the largest upload this deployment's object store can have the
/// provider confirm a digest for.
pub async fn create(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let now = Utc::now();

    let request: CreateUploadRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };

    let intent = match request.file_id {
        Some(file) => UploadIntent::NewVersion(file),
        None => UploadIntent::NewFile,
    };
    let (action, resource) =
        target_of(ctx.tenant_id, request.library_id, request.parent_id, intent);

    // The chain, before anything at all has been read about the library.
    let decision = match state.policy.enforce(&ctx, action, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    // No obligation is dischargeable on this path and none is dropped (`CLAUDE.md` rule 8). A write
    // cannot honour `ReadOnly`; there is no rendition here to watermark and no artifact to
    // reclassify; and `docs/05-API.md §8` gives this request no field a justification could arrive
    // in, so demanding one would be a refusal in any case. Refusing every obligation is therefore
    // the honest reading rather than a shortcut, and `none_dischargeable` is the form that cannot
    // reach the caller without an audit row (`ENC-606`).
    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, action, &resource, refused).await);
    }

    let created_by = match author(&ctx) {
        Ok(author) => author,
        Err(refused) => return Err(state.audit.refuse(&ctx, action, &resource, refused).await),
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // The library's own acceptance rules. Read after the decision, because which extensions a
    // library refuses is a fact about the library, and a caller with no grant on it is not owed one.
    let library = LibraryRepository::find_by_id(&mut tx, ctx.tenant_id, request.library_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        // Authorized but absent: the same answer a fabricated id gets. The chain allowed because
        // the ACL walk found a grant it could reach; the row is gone.
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let limits = UploadLimits::from_library(&library.settings, TENANT_DEFAULT_MAX_FILE_BYTES);

    let new = NewUpload {
        library_id: request.library_id,
        parent_id: request.parent_id,
        intent,
        name: request.name,
        declared_size: request.size_bytes,
        declared_mime: request.mime_type,
        // Required by the wire type, so there is no arm here that can create a session with no
        // digest for the provider to verify against (`ENC-820`).
        declared_sha256: request.sha256,
        created_by,
    };

    let issued = UploadService::create(
        &mut tx,
        store.as_ref(),
        ctx.tenant_id,
        &new,
        &limits,
        SESSION_TTL,
        now,
    )
    .await
    .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok((StatusCode::CREATED, Json(view_of(issued))).into_response())
}

/// Handles `GET /api/v1/uploads/{id}` — progress and state.
///
/// # Errors
///
/// [`ApiError`]: `404` for a session that does not exist in this tenant, and for one whose target
/// this caller may not read.
pub async fn progress(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Json<ProgressView>, ApiError> {
    let request_id = ctx.request_id;
    let id = session_id(&id, request_id)?;

    let session = load(&state, &ctx, id).await?;
    let record = session.record();

    // Reading a session's progress is reading the container it will land in. `container.read`
    // rather than `container.create`: a caller who may browse the library may watch an upload into
    // it, and demanding the write permission to poll would make a shared upload unobservable to
    // everyone but its author.
    let resource = container_of(ctx.tenant_id, record.library_id, record.parent_id);
    authorize(&state, &ctx, Action::Container(ContainerAction::Read), &resource).await?;

    // The version this session's own bytes became, or `None` while it has not committed one
    // (`ENC-826`). Both identifiers come off the staged key, which allocated them when the session
    // was created and which the committed row is required to match — so this is a primary-key
    // lookup, not a search, and it names *this upload's* version rather than whatever the file
    // currently points at. That distinction is the reason it is not `VersionRepository::current`:
    // a later upload can move `files.current_version_id`, and this endpoint must keep answering
    // about the upload the caller asked about.
    //
    // `find` rather than `find_readable`: an unreadable version is precisely what a client polling
    // for progress needs to hear about, and it hears it as `isReadable: false` with the reason
    // beside it. No byte is served from here — this is metadata, and rule 9 lives on the delivery
    // routes, which apply the same predicate `VersionState` reports.
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let committed = VersionRepository::find(
        &mut tx,
        ctx.tenant_id,
        record.staged.file(),
        record.staged.version(),
    )
    .await
    .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(Json(ProgressView {
        upload_id: record.id.to_string(),
        state: session.state().as_str(),
        library_id: record.library_id.to_string(),
        parent_id: record.parent_id.map(|id| id.to_string()),
        // The committed row's own `file_id`, never the staged key's, for `ENC-691`'s reason: read
        // off the key it is a promise about a row that may not exist.
        file_id: record
            .file_id
            .or_else(|| committed.as_ref().map(|version| version.file_id))
            .map(|id| id.to_string()),
        version: committed.as_ref().map(VersionState::from),
        name: record.name.clone(),
        declared_size: record.declared_size,
        bytes_received: record.bytes_received,
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
    }))
}

/// Handles `POST /api/v1/uploads/{id}/complete`.
///
/// Verifies the size and SHA-256 against the declaration *and* against what the object store
/// observed, advances the session to `SCANNING`, commits the version behind it, and answers `202`.
/// See the module documentation for rule 9 and for what [`promote`] does inside this transaction.
///
/// # Errors
///
/// [`ApiError`]: `404` for an unknown session or an unauthorized target; `400` naming `sizeBytes`
/// or `sha256` when verification fails, which is a *persisted* refusal — the session is `FAILED`
/// and retrying it cannot succeed; `409` when the session has moved on, or another request
/// completed it first; `400` naming `name` when a live sibling already holds it; `403`
/// `QUOTA_EXCEEDED` when the tenant has no room for the bytes it has just staged. The last two
/// roll the whole transaction back, session state included, so the client may retry.
pub async fn complete(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let now = Utc::now();
    let id = session_id(&id, request_id)?;

    let request: CompleteUploadRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };

    let (action, resource) = writable_target(&state, &ctx, id).await?;
    authorize(&state, &ctx, action, &resource).await?;

    let reported = ReportedContent { size_bytes: request.size_bytes, sha256_hex: request.sha256 };
    let parts: Vec<CompletedPart> = request
        .parts
        .into_iter()
        .map(|part| CompletedPart { part_number: part.part_number, etag: part.etag })
        .collect();

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let completion =
        UploadService::complete(&mut tx, store.as_ref(), ctx.tenant_id, id, &reported, parts, now)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;

    match completion {
        Completion::Refused { session: _, reason } => {
            // Committed, not rolled back. A refusal is a *persisted* outcome — the staged bytes are
            // wrong and this session can never succeed — so rolling it back would invite the client
            // to retry a completion that cannot work (`enclave_uploads::Completion`).
            tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
            Err(ApiError::new(reason.to_error(), request_id))
        }
        Completion::HandedOff { session, handoff } => {
            // The handoff is moved in. `#[must_use]` made dropping one visible; a move makes it
            // impossible — there is no arm of this match that can hold a handoff and answer `202`
            // without a version behind it, which is what `ENC-691` was.
            let committed = match promote(&mut tx, &ctx, *handoff, now).await {
                Ok(committed) => committed,
                Err(error) => {
                    // Everything this request wrote goes, the session's `SCANNING` included. A row
                    // that says the bytes are being scanned while nothing exists to scan them is
                    // the stranded state; a rollback leaves the session exactly where the client
                    // can retry it from.
                    let _rolled_back = tx.rollback().await;
                    return Err(error);
                }
            };

            tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

            tracing::info!(
                tenant_id = %ctx.tenant_id,
                upload_session_id = %session.id(),
                file_id = %committed.version.file_id,
                version_id = %committed.version.id,
                version = %committed.version.number,
                "upload committed as a version, awaiting antivirus"
            );

            let body = HandedOffView {
                upload_id: session.id().to_string(),
                // From the committed row rather than from the staged key: these two identifiers
                // are a promise that the rows exist, and reading them off the key is how the
                // response came to name rows that did not.
                file_id: committed.version.file_id.to_string(),
                version_id: committed.version.id.to_string(),
                // From the session's phase, never a literal. See the module documentation.
                state: session.state().as_str(),
            };
            Ok((StatusCode::ACCEPTED, Json(body)).into_response())
        }
    }
}

/// Turns an accepted upload into a file version, in the caller's transaction.
///
/// # What it does, and what it refuses to do
///
/// Two calls, both to crates that own what they do:
///
/// 1. **The `files` row**, when the upload creates a file rather than versioning one. It carries
///    [`enclave_uploads::StagedObject::file`] — the id the session spent when it staged the bytes
///    under `tenant/{t}/files/{f}/versions/{v}` — because a node minted with any other id would
///    leave the object key naming a file that does not exist. `enclave_files` writes it
///    non-readable; nothing here chooses that status and nothing here could change it.
/// 2. **The version**, through [`VersionService::commit`], which is a single transaction covering
///    the quota charge, the version insert, the outbox row, the index manifest and the audit row.
///    None of those is repeated here. The version is written `SCANNING`/`PENDING` by constants
///    inside that function that take no argument, so rule 9 is not a comparison this function
///    could get wrong.
///
/// # The two values that are decisions
///
/// `bump` is [`VersionBump::Major`], so the first version of a new file is `1.0` and each upload
/// afterwards is the next published version. `libraries.versioning_mode` is the column that should
/// eventually decide this and is read by nothing in the workspace (`ENC-784`); until it is,
/// `Major` is the reading `docs/04 §7`'s default mode gives, and the alternative — minor bumps —
/// would file every upload as a draft of a version nobody published.
///
/// `mime_type` falls back to [`UNDECLARED_MIME_TYPE`] because the column is `NOT NULL` while the
/// client's declaration is optional and advisory. Sniffing belongs to the content pipeline, not to
/// a transaction that has never seen the bytes.
///
/// # Errors
///
/// [`ApiError`]: `400` naming `name` when a live sibling already holds it, or `parentId` when the
/// folder has gone; `403` `QUOTA_EXCEEDED` with the limit when the tenant has no room; `404` when
/// the file being versioned was trashed or removed between the session and now; `409` when a
/// concurrent commit took the version number. Every one of them leaves the caller's transaction
/// for the caller to roll back.
async fn promote(
    tx: &mut TenantScoped,
    ctx: &RequestContext,
    handoff: ScanHandoff,
    at: DateTime<Utc>,
) -> Result<CommittedVersion, ApiError> {
    let request_id = ctx.request_id;
    let file_id = handoff.staged.file();
    let mime_type = handoff.mime_type.clone().unwrap_or_else(|| UNDECLARED_MIME_TYPE.to_owned());

    if handoff.existing_file_id.is_none() {
        let parent = match handoff.parent_id {
            Some(folder) => Parent::Folder(folder),
            None => Parent::Library(handoff.library_id),
        };
        let node = NewFile {
            id: file_id,
            parent,
            name: handoff.name.clone(),
            mime_type: mime_type.clone(),
            created_by: handoff.created_by,
        };
        FileRepository::create_file(tx, ctx.tenant_id, &node, at)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;
    }

    // The store's observation, not the client's declaration — `VerifiedContent` cannot be built
    // without the two agreeing, and this is the number the quota is charged for.
    let size_bytes = i64::try_from(handoff.content.size_bytes()).map_err(|_error| {
        ApiError::new(
            Error::Validation(vec![FieldError::new("sizeBytes", ValidationCode::OutOfRange)]),
            request_id,
        )
    })?;

    let new = NewVersion {
        // Both ids come off the staged key rather than being minted here, because the bytes are
        // already at `tenant/{t}/files/{f}/versions/{v}` and that path is not rewritable without
        // copying them. A version whose row id differed from the one in its own object key would
        // leave an operator's `WHERE id = …` answering nothing for an object that plainly exists.
        id: handoff.staged.version(),
        file_id,
        // The staged key *is* the version key. Nothing is copied on commit; see
        // `enclave_uploads::staged` for why, and for the 5 GB limit that settled it.
        object_key: handoff.staged.as_str().to_owned(),
        storage_profile_id: UNPROVISIONED_STORAGE_PROFILE,
        size_bytes,
        checksum_sha256: handoff.content.sha256_hex().to_owned(),
        mime_type,
        bump: VersionBump::Major,
        created_by: handoff.created_by,
        // `docs/05-API.md §8`'s completion body carries no check-in comment field, so there is
        // nothing to record and a fabricated one would be words no user typed.
        comment: None,
    };

    VersionService::commit(tx, ctx, ChainMode::Enabled, &new, at)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))
}

/// Handles `DELETE /api/v1/uploads/{id}` — abort and release the staged bytes.
///
/// The bytes are deleted before the row is marked, which is [`UploadService::abort`]'s ordering and
/// not this handler's choice: the reverse order leaks, because the reaper's index excludes
/// `ABORTED`.
///
/// # Errors
///
/// [`ApiError`]: `404` for an unknown session or an unauthorized target; `409` for a session
/// antivirus already owns, or one already aborted.
pub async fn abort(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let request_id = ctx.request_id;
    let id = session_id(&id, request_id)?;

    let (action, resource) = writable_target(&state, &ctx, id).await?;
    authorize(&state, &ctx, action, &resource).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let _aborted = UploadService::abort(&mut tx, store.as_ref(), ctx.tenant_id, id, Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// The pieces the handlers share
// ---------------------------------------------------------------------------------------------

/// The action and resource an upload is decided against.
///
/// Two intents, two questions, and they must not be collapsed. Creating a file in a container is
/// `container.create` on that container — the folder when one is named, because a folder can carry
/// its own ACL and inheriting the library's answer would ignore it. Adding a version to an existing
/// file is `file.edit` on the file, which is a permission a caller can hold on one file in a
/// library they may not otherwise write to, and can equally lack on one file in a library they can.
const fn target_of(
    tenant: TenantId,
    library: LibraryId,
    parent: Option<FileId>,
    intent: UploadIntent,
) -> (Action, ResourceRef) {
    match intent {
        UploadIntent::NewVersion(file) => {
            (Action::File(FileAction::Edit), ResourceRef::file(tenant, file))
        }
        UploadIntent::NewFile => {
            (Action::Container(ContainerAction::Create), container_of(tenant, library, parent))
        }
    }
}

/// The container an upload lands in: the named folder, or the library root.
const fn container_of(tenant: TenantId, library: LibraryId, parent: Option<FileId>) -> ResourceRef {
    match parent {
        Some(folder) => ResourceRef::folder(tenant, folder),
        None => ResourceRef::library(tenant, library),
    }
}

/// Resolves the session named by the path to the resource whose ACL governs acting on it.
///
/// The row is read *before* the chain runs, which is the opposite of [`create`] and of
/// `crates/api/src/download.rs`, so it is worth saying why it is not a leak. The path names an
/// upload session, and a session carries no ACL of its own — the permission that governs completing
/// or aborting one is the permission on the thing it will become. There is nothing to enforce
/// against until the row has been read.
///
/// What the read can disclose is bounded to nothing a caller can use. It runs inside a
/// [`enclave_db::TenantScoped`] transaction, so row-level security has already restricted it to the
/// caller's own tenant; a miss and another tenant's id are the same [`Error::NotFound`]
/// (`enclave_uploads::UploadError::NotFound` documents that collapse); and a session whose target
/// this caller may not touch is refused by [`authorize`], which renders `ACCESS_DENIED` as `404` on
/// this path too. So the three cases — no such session, another tenant's session, a session whose
/// target is not yours — are one answer.
async fn writable_target(
    state: &ApiState,
    ctx: &RequestContext,
    id: UploadSessionId,
) -> Result<(Action, ResourceRef), ApiError> {
    let session = load(state, ctx, id).await?;
    let record = session.record();
    let intent = match record.file_id {
        Some(file) => UploadIntent::NewVersion(file),
        None => UploadIntent::NewFile,
    };
    Ok(target_of(ctx.tenant_id, record.library_id, record.parent_id, intent))
}

/// Loads a session in its own short transaction.
///
/// Separate from the transaction that acts on it, deliberately: the policy chain runs between the
/// two and takes connections of its own to resolve the ACL, so holding a transaction open across it
/// would have one request competing with itself for the pool. The service re-reads the row inside
/// the mutating transaction anyway, and its compare-and-swap — not this read — is what makes the
/// transition safe under concurrency.
async fn load(
    state: &ApiState,
    ctx: &RequestContext,
    id: UploadSessionId,
) -> Result<LoadedSession, ApiError> {
    let request_id = ctx.request_id;
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let session = UploadService::find(&mut tx, ctx.tenant_id, id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id));

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    session
}

/// Runs the chain and discharges the decision, for the handlers that have already resolved their
/// resource.
///
/// One function rather than three copies, so that the `404`-for-`ACCESS_DENIED` rendering and the
/// obligation refusal cannot be spelled three ways across one resource family.
async fn authorize(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<(), ApiError> {
    let decision = match state.policy.enforce(ctx, action, resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal(state, ctx, resource, error).await;
            return Err(ApiError::new(error, ctx.request_id));
        }
    };
    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(ctx, action, resource, refused).await);
    }
    Ok(())
}

/// Renders a bare `ACCESS_DENIED` on this family as an absence.
///
/// `CLAUDE.md` rule 7. The container analogue of [`crate::download::conceal_if_not_visible`], and it
/// asks the same question through the same chain: *may this caller see this resource at all?* If
/// they may, they already know it exists and deserve the actionable `403`; if they may not, they
/// learn nothing, which is what a cross-tenant probe must get.
///
/// It is not `download`'s function reused, because the visibility question differs by resource
/// kind: `file.metadata_read` against a library is not a question the authorization stage can
/// answer, and asking it would turn every container denial into whatever a mismatched action
/// happens to return. Every reason code other than `ACCESS_DENIED` passes through unchanged, for
/// the reason `crates/api/src/content.rs` gives — each is produced by a stage that runs either
/// before authorization or after it, and after it means the caller already holds a grant.
async fn conceal(
    state: &ApiState,
    ctx: &RequestContext,
    resource: &ResourceRef,
    denial: Error,
) -> Error {
    if !matches!(denial, Error::PolicyDenied { code: ReasonCode::AccessDenied, .. }) {
        return denial;
    }

    match state.policy.enforce(ctx, visibility_question(resource.kind), resource).await {
        Ok(decision) => {
            // Asked as a question, not as permission — but the obligations are still taken by value
            // rather than dropped, because `Obligations` is `#[must_use]` and the ability to ignore
            // one silently is what rule 8 removes.
            let _obligations = decision.into_obligations();
            denial
        }
        Err(Error::PolicyDenied { .. } | Error::NotFound) => Error::NotFound,
        // A chain that could not evaluate is not a chain that denied. Surfacing the real failure
        // keeps a database outage from being reported to every caller as a missing resource.
        Err(other) => other,
    }
}

/// The cheapest read a caller could hold on a resource of this kind.
///
/// Split out so the mapping is one table rather than a `match` buried inside [`conceal`]: asking
/// the wrong action here does not fail loudly — it silently turns an actionable `403` into a `404`,
/// or worse, a `404` into a `403`.
const fn visibility_question(kind: ResourceKind) -> Action {
    match kind {
        ResourceKind::File | ResourceKind::Folder | ResourceKind::Version => {
            Action::File(FileAction::MetadataRead)
        }
        _ => Action::Container(ContainerAction::Read),
    }
}

/// The user a session is attributed to.
///
/// `upload_sessions.created_by` is `NOT NULL` and references a `users` row, so a principal that is
/// not a directory member has nothing to write there. A guest carries a `GuestId` and a service
/// account a `ServiceAccountId`; both are `Uuid`s and neither names a `users` row, so accepting
/// `Actor::subject_id` here would write a foreign key that either fails or, worse, collides.
///
/// It is a [`Refused`] rather than an [`Error`] because the chain has already allowed by the time
/// this is asked, and a refusal after an `ALLOW` with no row of its own is `ENC-606` exactly. The
/// control is actor eligibility: nothing was attached to this request, the principal is simply not
/// one that can own an upload.
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`].
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        // A link bearer least of all (`ENC-879`): `Actor::subject_id` answers `Some` with a
        // `share_links.id`, which is exactly the collision this doc comment describes — a real
        // UUID naming a row in the wrong table. A `VIEW` or `EDIT` link is not an upload identity.
        Actor::Guest(_)
        | Actor::ServiceAccount(_)
        | Actor::McpClient(_)
        | Actor::LinkBearer(_)
        | Actor::System => Err(Refused::actor(ReasonCode::AccessDenied)),
    }
}

/// Parses the `{id}` path segment.
///
/// A malformed id is answered exactly as an absent one, on `crates/api/src/download.rs`'s
/// reasoning: reporting *"that is not a UUID"* is harmless in itself, but it makes the endpoint
/// answer two ways for two kinds of miss, and one answer is easier to keep than to re-derive.
fn session_id(raw: &str, request_id: RequestId) -> Result<UploadSessionId, ApiError> {
    UploadSessionId::from_str(raw).map_err(|_error| ApiError::new(Error::NotFound, request_id))
}

/// The `400` a body that will not decode produces.
///
/// The decoder's own message is not echoed. It quotes the input, and the input is a body this
/// endpoint has decided nothing about yet — `docs/05-API.md §5` keeps that out of an error
/// envelope, and `crates/api/src/admin/dlp.rs` bounds the one place that does echo a decoder.
fn unreadable_body() -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "The request body could not be read.",
        "Correct the field named in `details` and retry.",
    )
    .with_details(vec![serde_json::json!({
        "field": "body",
        "code": ValidationCode::InvalidFormat.as_str(),
    })])
}

/// The store's required headers, as the wire carries them.
///
/// A named function rather than an inline `collect` so that "this map is copied from the store and
/// nothing is added to it" is a single testable statement. Every value here was signed into the
/// URL; a value invented at this layer would not be, and the `PUT` would fail the signature check.
fn header_map(headers: Vec<enclave_storage::RequiredHeader>) -> BTreeMap<String, String> {
    headers.into_iter().map(|header| (header.name, header.value)).collect()
}

/// Renders an issued session onto the wire.
fn view_of(issued: IssuedUpload) -> IssuedUploadView {
    let expires_at = issued.session.record().expires_at;
    let upload_id = issued.session.id().to_string();

    match issued.target {
        UploadTarget::Single { url, required_headers } => IssuedUploadView {
            upload_id,
            method: "SINGLE",
            upload_url: Some(url.to_string()),
            required_headers: header_map(required_headers),
            urls: None,
            part_size: None,
            urls_expire_at: issued.urls_expire_at,
            expires_at,
        },
        UploadTarget::Multipart { upload_id: _, parts } => {
            // The provider's multipart id is deliberately not on the wire. The client completes
            // through `POST /uploads/{id}/complete`, which reads the id back out of the session
            // row; handing it over would let a caller complete or abort the object directly at the
            // provider, outside every decision this endpoint took.
            let part_size = parts.first().map(|part| part.length);
            let urls = parts
                .into_iter()
                .map(|part| PartView {
                    part_number: part.part_number,
                    offset: part.offset,
                    length: part.length,
                    url: part.url.to_string(),
                })
                .collect();
            IssuedUploadView {
                upload_id,
                method: "MULTIPART",
                upload_url: None,
                // Empty, and unreachable in practice: `UploadService::create` always declares a
                // digest, and a store that cannot confirm one for an upload this size refuses
                // before a URL exists. Left as an empty map rather than as an error arm because
                // this function renders whatever the store issued and decides nothing.
                required_headers: BTreeMap::new(),
                urls: Some(urls),
                part_size,
                urls_expire_at: issued.urls_expire_at,
                expires_at,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{GuestId, McpClientId, ServiceAccountId};

    use super::*;

    fn ctx_of(actor: Actor) -> RequestContext {
        let mut ctx = RequestContext::system(TenantId::new_v7());
        ctx.actor = actor;
        ctx
    }

    /// Rule 9's second half. The first half is structural — the wire `state` is rendered from
    /// `Session::state()`, and the phase machine has nothing after `Scanning` — but that only holds
    /// while the value keeps coming from the type. This is what catches somebody writing the
    /// literal instead.
    ///
    /// The needles are assembled at run time. `docs/12 §1.2`: a source-scanning test whose needle
    /// appears in its own source fails against itself, and two tests in this repository already
    /// have.
    #[test]
    fn the_completion_response_cannot_name_a_readable_state() {
        let source = include_str!("uploads.rs");
        // Everything after this module's opening is this test's own text.
        let handlers = source.split("mod tests {").next().expect("the module has a body");

        for needle in [
            format!("\"{}\"", "AVAILABLE"),
            format!("\"{}\"", "PROCESSING"),
            format!("UploadState::{}", "Available"),
            format!("UploadState::{}", "Processing"),
        ] {
            assert!(
                !handlers.contains(&needle),
                "`{needle}` appears in the upload routes. Nothing here may publish an upload: \
                 `UploadService::complete` returns a `Session<Scanning>`, the phase machine has no \
                 transition after it, and the wire `state` is rendered from `Session::state()` for \
                 exactly this reason (CLAUDE.md rule 9)."
            );
        }

        // The positive control. Without it this test passes against a file that names no state at
        // all — including one that has stopped reporting a state, which is a different defect the
        // same assertion would sail past (`docs/12 §1.2`).
        assert!(
            handlers.contains("session.state().as_str()"),
            "the completion response no longer renders its state from the session's phase, so the \
             absence asserted above proves nothing"
        );
    }

    /// Rule 9's *third* half, which `ENC-691` added: this module now writes a version row, and it
    /// must still be unable to say what state that row is in.
    ///
    /// `VersionService::commit` picks the status and the antivirus verdict from two constants that
    /// take no argument, so `SCANNING`/`PENDING` is a property of that statement. The way that could
    /// be undone from here is a second write beside the commit — an `UPDATE file_versions`, a
    /// `VersionStatus` this module chose, an `AvStatus` it converted. None of those names may
    /// appear, and none of them does.
    ///
    /// Needles assembled at run time, for `the_completion_response_cannot_name_a_readable_state`'s
    /// reason.
    #[test]
    fn nothing_here_can_choose_a_version_status_or_write_a_version_row_itself() {
        let source = include_str!("uploads.rs");
        let handlers = source.split("mod tests {").next().expect("the module has a body");

        for needle in [
            format!("{}Status::", "Version"),
            format!("{}Status::", "Av"),
            format!("UPDATE {}", "file_versions"),
            format!("INSERT INTO {}", "file_versions"),
            format!("{}::query", "sqlx"),
        ] {
            assert!(
                !handlers.contains(&needle),
                "`{needle}` appears in the upload routes. The version's status and its antivirus \
                 verdict are decided by constants inside `VersionService::commit`, which take no \
                 argument precisely so no caller can pass one (CLAUDE.md rule 9); and this module \
                 runs no statement of its own (rule 1)."
            );
        }

        // The positive control: the commit that owns those constants is still called from here.
        // Without it the absences above hold of a handler that has stopped committing anything,
        // which is the defect `ENC-691` was (`docs/12 §1.2`).
        assert!(
            handlers.contains("VersionService::commit("),
            "the completion path no longer commits a version, so asserting that it does not choose \
             a status proves nothing at all"
        );
    }

    /// `ENC-691` in one assertion: the handoff is **moved** into the commit, and the identifiers on
    /// the wire come out of the row that commit returned.
    ///
    /// The bug was not that the handoff was ignored — `#[must_use]` was satisfied, because the
    /// handler read `handoff.staged` for the two identifiers it put on the wire. That is exactly
    /// what a `202` naming rows that do not exist looks like from inside. So both halves are
    /// asserted: `promote` receives the handoff by value, and the response reads `committed`.
    #[test]
    fn the_handoff_is_moved_into_the_commit_and_the_response_names_the_row_it_produced() {
        let source = include_str!("uploads.rs");
        let handlers = source.split("mod tests {").next().expect("the module has a body");

        assert!(
            handlers.contains("promote(&mut tx, &ctx, *handoff, now)"),
            "the handoff is no longer moved into `promote`. A handoff that is borrowed, or read \
             field by field, can be satisfied without a version ever being committed — which is \
             what `#[must_use]` allowed and what ENC-691 was"
        );

        for field in ["file_id: committed.version.file_id", "version_id: committed.version.id"] {
            assert!(
                handlers.contains(field),
                "`{field}` is not what the completion response carries. Both identifiers must come \
                 from the committed row: read off the staged key they are a promise about rows \
                 nothing has written"
            );
        }

        // And nothing reads them back off the key for the response, which is the shape of the bug.
        assert!(
            !handlers.contains("handoff.staged.file().to_string()"),
            "the response is naming the file id from the staged key again"
        );
    }

    /// `ENC-826`: progress is reported about the version *this session* committed, and about
    /// nothing else.
    ///
    /// Two ways to get this wrong, and the test names both because they fail in opposite
    /// directions. Reading `VersionRepository::current` would answer about whatever the file
    /// points at *now* — so a second upload into the same file would silently change what this
    /// session reports, and a client would watch someone else's upload finish. Reading
    /// `find_readable` would collapse "still scanning" and "quarantined" into an absence, which is
    /// correct on a delivery route and is exactly the wrong answer on a progress endpoint: the
    /// caller polling it is the one person entitled to be told *why* their upload is not ready.
    ///
    /// Needles assembled at run time, for `the_completion_response_cannot_name_a_readable_state`'s
    /// reason (`docs/12-TESTING.md §1.2`).
    #[test]
    fn progress_reports_this_sessions_own_version_and_neither_hides_nor_guesses_its_state() {
        let source = include_str!("uploads.rs");
        let handlers = source.split("mod tests {").next().expect("the module has a body");

        // Both identifiers come off the staged key, which allocated them at session creation.
        for lookup in ["record.staged.file()", "record.staged.version()"] {
            assert!(
                handlers.contains(lookup),
                "`{lookup}` is gone. The version this session produced is found by the two ids its \
                 own staged key reserved; anything else answers about a different upload"
            );
        }

        for wrong in [
            format!("VersionRepository::{}(", "current"),
            format!("VersionRepository::{}(", "find_readable"),
        ] {
            assert!(
                !handlers.contains(&wrong),
                "`{wrong}` is used for the progress lookup. `current` reports whatever the file \
                 points at now rather than what this session committed, and `find_readable` turns \
                 a scanning or quarantined version into an absence — which is the one answer a \
                 client polling its own upload must not be given"
            );
        }

        // The positive control: without it every absence above holds of a handler that has stopped
        // reporting a version at all, which is the defect this row was.
        assert!(
            handlers.contains("version: committed.as_ref().map(VersionState::from)"),
            "the progress response no longer carries the committed version, so asserting how it is \
             looked up proves nothing. `state` is terminal at SCANNING and can never report the \
             end of an upload on its own (ENC-826)"
        );
    }

    /// The two intents are two separately deniable questions, and this is the table that says so.
    ///
    /// A regression that collapsed them would most likely do it in the permissive direction —
    /// asking `container.create` for a new version, so that anyone who may add a file to a library
    /// may overwrite any file in it.
    #[test]
    fn creating_a_file_and_versioning_one_ask_different_questions_of_different_resources() {
        let tenant = TenantId::new_v7();
        let library = LibraryId::new_v7();
        let folder = FileId::new_v7();
        let file = FileId::new_v7();

        let (action, resource) = target_of(tenant, library, None, UploadIntent::NewFile);
        assert_eq!(action, Action::Container(ContainerAction::Create));
        assert_eq!(resource, ResourceRef::library(tenant, library));

        // A named folder is the container, not the library: a folder can carry its own ACL, and
        // deciding against the library would ignore it.
        let (action, resource) = target_of(tenant, library, Some(folder), UploadIntent::NewFile);
        assert_eq!(action, Action::Container(ContainerAction::Create));
        assert_eq!(resource, ResourceRef::folder(tenant, folder));

        let (action, resource) = target_of(tenant, library, None, UploadIntent::NewVersion(file));
        assert_eq!(action, Action::File(FileAction::Edit));
        assert_eq!(resource, ResourceRef::file(tenant, file));

        // And a parent alongside a file id does not move the question back to the container.
        let (action, resource) =
            target_of(tenant, library, Some(folder), UploadIntent::NewVersion(file));
        assert_eq!(action, Action::File(FileAction::Edit));
        assert_eq!(resource, ResourceRef::file(tenant, file));
    }

    #[test]
    fn a_malformed_session_id_is_answered_as_an_absence() {
        let request_id = RequestId::new_v7();
        for junk in ["", "not-a-uuid", "0000", "../../etc/passwd"] {
            let refusal = session_id(junk, request_id).expect_err("a malformed id must be refused");
            assert!(
                matches!(refusal.error(), Error::NotFound),
                "`{junk}` was distinguishable from an id that does not exist"
            );
        }
        // The positive control: a well-formed id parses, so the assertion above is about the shape
        // of the input rather than about a function that refuses everything.
        let id = UploadSessionId::new_v7();
        let parsed = session_id(&id.to_string(), request_id).expect("a well-formed id");
        assert_eq!(parsed.as_uuid(), id.as_uuid());
    }

    /// `upload_sessions.created_by` names a `users` row, and only one actor kind has one.
    ///
    /// The permissive mistake here is `Actor::subject_id()`, which answers `Some` for a guest and
    /// for a service account too — both `Uuid`s that are not user ids.
    #[test]
    fn only_a_directory_member_can_own_an_upload() {
        let user = UserId::new_v7();
        assert_eq!(author(&ctx_of(Actor::User(user))).expect("a directory member"), user);

        for actor in [
            Actor::Guest(GuestId::new_v7()),
            Actor::ServiceAccount(ServiceAccountId::new_v7()),
            Actor::McpClient(McpClientId::new_v7()),
            Actor::System,
        ] {
            let refused = author(&ctx_of(actor)).expect_err("not a directory member");
            assert_eq!(refused.code(), ReasonCode::AccessDenied);
            assert_eq!(refused.control(), crate::refusal::Control::ActorEligibility);
        }
    }

    /// The visibility probe has to match the resource, or rule 7's answer inverts.
    #[test]
    fn the_visibility_question_matches_the_resource_kind() {
        assert_eq!(visibility_question(ResourceKind::File), Action::File(FileAction::MetadataRead));
        assert_eq!(
            visibility_question(ResourceKind::Folder),
            Action::File(FileAction::MetadataRead)
        );
        assert_eq!(
            visibility_question(ResourceKind::Library),
            Action::Container(ContainerAction::Read)
        );
        assert_eq!(
            visibility_question(ResourceKind::Workspace),
            Action::Container(ContainerAction::Read)
        );
    }

    #[test]
    fn a_body_is_decoded_strictly_and_in_camel_case() {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let body = format!(
            r#"{{"libraryId":"01937fa0-0000-7000-8000-000000000001",
                 "name":"Quarterly Plan.pdf","sizeBytes":64,"mimeType":"application/pdf",
                 "sha256":"{digest}"}}"#
        );
        let request: CreateUploadRequest = serde_json::from_str(&body).expect("a well-formed body");
        assert_eq!(request.name, "Quarterly Plan.pdf");
        assert_eq!(request.size_bytes, 64);
        assert_eq!(request.sha256, digest);
        assert!(request.file_id.is_none(), "no fileId means the upload creates a file");

        // `ENC-615`: a field this release does not know is refused rather than ignored, so a caller
        // cannot come to believe a setting applied.
        let unknown = format!(
            r#"{{"libraryId":"01937fa0-0000-7000-8000-000000000001","name":"a.pdf",
                 "sizeBytes":1,"sha256":"{digest}","overwrite":true}}"#
        );
        assert!(serde_json::from_str::<CreateUploadRequest>(&unknown).is_err());
    }

    /// `ENC-820`: a body with no `sha256` is refused at the decoder.
    ///
    /// The field carries no `#[serde(default)]`, so this is a property of the type rather than of a
    /// check somebody could delete — an upload started without a digest is one the object store has
    /// nothing to verify the body against, and `complete` would then be comparing the client's word
    /// with itself.
    #[test]
    fn an_upload_cannot_be_started_without_a_digest_for_the_store_to_verify() {
        let without = r#"{"libraryId":"01937fa0-0000-7000-8000-000000000001",
                          "name":"a.pdf","sizeBytes":1}"#;
        assert!(
            serde_json::from_str::<CreateUploadRequest>(without).is_err(),
            "an upload with no declared digest was accepted; nothing would verify what it stores"
        );

        // The positive control: the same body *with* a digest parses, so the refusal above is about
        // the missing field and not about a decoder that rejects everything.
        let with = r#"{"libraryId":"01937fa0-0000-7000-8000-000000000001","name":"a.pdf",
                       "sizeBytes":1,
                       "sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
        assert!(serde_json::from_str::<CreateUploadRequest>(with).is_ok());
    }

    /// The headers the client must send are copied from what the store said it signed, and nothing
    /// is invented beside them.
    ///
    /// A pre-signed URL commits to its `X-Amz-SignedHeaders`, so a response that omitted one leaves
    /// the client with a URL it cannot use — `ENC-821` for `content-type` — and one that *invented*
    /// a value would be worse: `x-amz-checksum-sha256` is what makes the provider verify the body,
    /// and a digest this layer made up is not the digest that was signed.
    ///
    /// That the map reaches the wire at all is asserted end to end in `tests/uploads.rs`, against
    /// the real router; this is only the mapping.
    #[test]
    fn the_required_headers_on_the_wire_are_the_ones_the_store_signed() {
        let headers = header_map(vec![
            enclave_storage::RequiredHeader {
                name: "content-type".to_owned(),
                value: "application/pdf".to_owned(),
            },
            enclave_storage::RequiredHeader {
                name: "x-amz-checksum-sha256".to_owned(),
                value: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_owned(),
            },
        ]);

        assert_eq!(
            headers.get("x-amz-checksum-sha256").map(String::as_str),
            Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            "the digest header the provider will verify against is not on the wire, so a client \
             cannot send it and every PUT fails the signature check"
        );
        assert_eq!(headers.get("content-type").map(String::as_str), Some("application/pdf"));
        assert_eq!(headers.len(), 2, "nothing was invented beside them");
        assert!(
            header_map(Vec::new()).is_empty(),
            "and none is fabricated when the store sent none"
        );
    }

    #[test]
    fn an_unreadable_body_names_the_field_and_quotes_nothing() {
        let envelope = unreadable_body();
        assert_eq!(envelope.status(), StatusCode::BAD_REQUEST);
        assert_eq!(envelope.code(), "VALIDATION_FAILED");
        let details = envelope.details();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["field"], "body");
        // Nothing the caller sent is echoed back — the entry is a field and a closed code.
        assert_eq!(details[0].as_object().map(serde_json::Map::len), Some(2));
    }

    #[test]
    fn the_documented_defaults_are_the_ones_a_deployment_gets() {
        // `docs/03-LLD.md §15`: `upload.session_ttl`, default 24h. A change here changes how long
        // an abandoned upload's bytes sit in the store before the reaper may release them.
        assert_eq!(SESSION_TTL.num_hours(), 24);
        // M1's fifth exit criterion is 5 GB, and a library that configures no ceiling must not
        // refuse the upload the product claims to support.
        assert_eq!(TENANT_DEFAULT_MAX_FILE_BYTES, 5 * 1024 * 1024 * 1024);
        // RFC 2046 §4.5.1. The one thing it must not be is a guess derived from the file name: a
        // version whose recorded type came from an extension is a value a reader would trust.
        assert_eq!(UNDECLARED_MIME_TYPE, "application/octet-stream");
    }
}
