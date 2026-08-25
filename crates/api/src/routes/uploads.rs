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
//! Nothing in this module reads a quota, writes a version row, or moves a state the service does
//! not move for it. That is not modesty; each of those has a single owner elsewhere and a second
//! one here would be a second answer.
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
//! # Where a completed upload goes next, which is nowhere yet
//!
//! `ENC-691`. [`enclave_uploads::ScanHandoff`] is described by its own crate as *the entire
//! interface between an accepted upload and everything that has to happen before anyone can read
//! it*, and **no crate consumes one**. `crates/worker`'s antivirus pass queues on
//! `file_versions.av_status`, and a completed session has no version row; the reaper's
//! `holds_staged_bytes` excludes `SCANNING`, so it will not collect the session either.
//!
//! [`complete`] therefore reports the identifiers the staged key already carries and stops. It does
//! **not** commit the version, and that is a decision rather than an omission:
//! `enclave_versions::VersionService::commit` needs a `files` row that does not exist for a
//! new-file upload, and a `storage_profile_id` for which `ENC-573` established there is no table
//! and therefore no honest source at the HTTP edge. Committing from here would also mean this
//! handler owning the quota charge (`ENC-589`) and the index enqueue (`ENC-643`) that live inside
//! that call — which is exactly the duplication that must not happen.

use core::str::FromStr as _;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use enclave_core::{
    Action, Actor, ContainerAction, Error, FileAction, FileId, LibraryId, ReasonCode,
    RequestContext, RequestId, ResourceKind, ResourceRef, TenantId, UserId, ValidationCode,
};
use enclave_libraries::LibraryRepository;
use enclave_storage::{BlobStore, CompletedPart, UploadTarget};
use enclave_uploads::{
    Completion, IssuedUpload, LoadedSession, NewUpload, ReportedContent, UploadIntent,
    UploadLimits, UploadService, UploadSessionId,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
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
    /// A lowercase hex SHA-256 the client declares up front, so the provider can refuse a
    /// corrupted transfer at the edge rather than storing it.
    #[serde(default)]
    sha256: Option<String>,
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressView {
    upload_id: String,
    /// The state the row holds, from [`LoadedSession::state`] — a client polling after `complete`
    /// is entitled to see `SCANNING`, and later `QUARANTINED`.
    state: &'static str,
    library_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
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
    /// The file the content belongs to — the existing one for a new version, and the id the staged
    /// key reserved for a new file.
    file_id: String,
    /// The version identifier the staged object carries.
    ///
    /// Reserved when the session was created (`enclave_uploads::StagedObject`), which is what lets
    /// the bytes be staged straight to the key the version will keep. **No `file_versions` row
    /// exists yet** — see the module documentation and `ENC-691`.
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
/// library will not accept; `403` `QUOTA_EXCEEDED` when the declared size already cannot fit.
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

    Ok(Json(ProgressView {
        upload_id: record.id.to_string(),
        state: session.state().as_str(),
        library_id: record.library_id.to_string(),
        parent_id: record.parent_id.map(|id| id.to_string()),
        file_id: record.file_id.map(|id| id.to_string()),
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
/// observed, then advances the session to `SCANNING` and answers `202`. See the module
/// documentation for rule 9, and for why no version row is written here.
///
/// # Errors
///
/// [`ApiError`]: `404` for an unknown session or an unauthorized target; `400` naming `sizeBytes`
/// or `sha256` when verification fails, which is a *persisted* refusal — the session is `FAILED`
/// and retrying it cannot succeed; `409` when the session has moved on, or another request
/// completed it first.
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

    // Committed on both arms. A refusal is a *persisted* outcome — the staged bytes are wrong and
    // this session can never succeed — so rolling it back would invite the client to retry a
    // completion that cannot work (`enclave_uploads::Completion`).
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    match completion {
        Completion::Refused { session: _, reason } => {
            Err(ApiError::new(reason.to_error(), request_id))
        }
        Completion::HandedOff { session, handoff } => {
            // The handoff is `#[must_use]` because dropping it drops the only record that a scan is
            // owed. It is consumed here for the identifiers the response carries; that nothing
            // downstream consumes one is `ENC-691` rather than something this handler can fix, and
            // the log line says so where an operator will meet it.
            tracing::info!(
                tenant_id = %ctx.tenant_id,
                upload_session_id = %handoff.session_id,
                file_id = %handoff.staged.file(),
                version_id = %handoff.staged.version(),
                "upload verified and handed off; no consumer commits the version yet (ENC-691)"
            );

            let body = HandedOffView {
                upload_id: session.id().to_string(),
                file_id: handoff.staged.file().to_string(),
                version_id: handoff.staged.version().to_string(),
                // From the session's phase, never a literal. See the module documentation.
                state: session.state().as_str(),
            };
            Ok((StatusCode::ACCEPTED, Json(body)).into_response())
        }
    }
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
        Actor::Guest(_) | Actor::ServiceAccount(_) | Actor::McpClient(_) | Actor::System => {
            Err(Refused::actor(ReasonCode::AccessDenied))
        }
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

/// Renders an issued session onto the wire.
fn view_of(issued: IssuedUpload) -> IssuedUploadView {
    let expires_at = issued.session.record().expires_at;
    let upload_id = issued.session.id().to_string();

    match issued.target {
        UploadTarget::Single { url } => IssuedUploadView {
            upload_id,
            method: "SINGLE",
            upload_url: Some(url.to_string()),
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
        let body = r#"{"libraryId":"01937fa0-0000-7000-8000-000000000001",
                       "name":"Quarterly Plan.pdf","sizeBytes":64,"mimeType":"application/pdf"}"#;
        let request: CreateUploadRequest = serde_json::from_str(body).expect("a well-formed body");
        assert_eq!(request.name, "Quarterly Plan.pdf");
        assert_eq!(request.size_bytes, 64);
        assert!(request.file_id.is_none(), "no fileId means the upload creates a file");

        // `ENC-615`: a field this release does not know is refused rather than ignored, so a caller
        // cannot come to believe a setting applied.
        let unknown = r#"{"libraryId":"01937fa0-0000-7000-8000-000000000001","name":"a.pdf",
                          "sizeBytes":1,"overwrite":true}"#;
        assert!(serde_json::from_str::<CreateUploadRequest>(unknown).is_err());
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
    }
}
