//! `docs/05-API.md §13` — the four endpoints a desktop or mobile sync client uses.
//!
//! ```text
//! POST /api/v1/sync/devices                register a device
//! GET  /api/v1/sync/devices                list; admin can list tenant-wide
//! POST /api/v1/sync/devices/{id}/wipe      request remote cache wipe
//! GET  /api/v1/sync/delta?scope=&cursor=   ordered change feed
//! POST /api/v1/sync/reserve                claim an upload slot for a changed local file
//! ```
//!
//! `docs/10-SYNC-AND-EDITING.md` is authoritative for what each one means.
//! `crates/sync` holds the model and the statements; this module is the HTTP shape and the policy
//! chain, and nothing else.
//!
//! # Rule 6, and where it is actually kept
//!
//! `CLAUDE.md` rule 6 and `docs/10 §1`: **sync is not download**. A caller who may download and may
//! not sync must be refused. That is kept in two places here and neither is optional:
//!
//! * [`delta`] asks the authorization stage for `file.download` **and** `file.sync` per file, and
//!   [`enclave_sync::Eligibility`] requires both. A caller with download and without sync gets an
//!   `ACCESS_REVOKED` tombstone — never a checksum, never a version id, never bytes.
//! * [`reserve`] runs the full chain for `file.sync` before it runs it for `file.edit`, so a caller
//!   who may edit through the web client cannot push a change from a device the tenant has not
//!   permitted to hold one.
//!
//! `crates/preview` proved the same split holds over HTTP for preview and download; this is the
//! third leg, and `crates/api/tests/sync.rs` asserts it with the positive control beside it.
//!
//! # Where the chain runs, and where it deliberately does not
//!
//! `docs/10 §5` requires eligibility to be evaluated **at delta time and again when the client
//! requests bytes**. That is what makes the split below safe rather than a shortcut:
//!
//! | Question | Where it is answered on the delta path |
//! |---|---|
//! | May this caller sync from this container at all? | `PolicyEngine::enforce`, once, on the scope — the full chain, so conditional access and DLP see the client, the device and the network |
//! | May this caller see / download / sync *this file*? | `AuthorizationService::authorize_many`, three batched questions over the page |
//! | Is the label, the library setting or the scan in the way? | one query each, in `crates/sync` |
//! | May these bytes leave? | `POST /files/{id}/download`, which runs the **whole** chain per file |
//!
//! The per-file batch is the same shape and the same justification `crates/api/src/content.rs`
//! gives for its listing trim: per-row trimming is not a separate audit event (`docs/07 §6.2`), and
//! a delta of five hundred entries cannot run five hundred chains. What the delta hands over is
//! *metadata* — a name, a size, a checksum. The bytes are a separate request against a separate
//! endpoint that does run the whole chain, and `docs/10 §5`'s re-evaluation is that endpoint.
//!
//! # Which device is asking
//!
//! `docs/10 §3` binds a sync token to a device with a `dev` claim, and `docs/03-LLD.md §5.2`
//! requires it on every sync token. Nothing issues one yet — `crates/api/src/auth.rs` builds a
//! `DeviceContext` with `device_id: None` and `DevicePosture::Unknown`, and `migrations/0001`'s
//! `devices` table has no writer. So [`asking_device`] prefers the verified claim and falls back to
//! a `deviceId` parameter, **which it then checks belongs to the caller**. A caller can therefore
//! only ever name one of their own devices; what the substitution costs is that one of a user's own
//! devices can impersonate another, which is a smaller thing than it sounds and is `ENC-736`. The
//! preference order is written so that the day the claim exists, the parameter stops being read.

use core::str::FromStr as _;
use core::time::Duration;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::Extension;
use axum::Json;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, DeviceId, Error, FileAction, FileId, Obligation,
    Obligations, ReasonCode, RequestContext, RequestId, ResourceRef, UserId, ValidationCode,
    VersionId,
};
use enclave_libraries::LibraryRepository;
use enclave_storage::BlobStore;
use enclave_sync::{
    DeltaCursor, Eligibility, FeedEntry, Registration, SyncDevice, SyncError, SyncRepository,
    SyncScope, TombstoneReason, Verdict, Visibility,
};
use enclave_uploads::{NewUpload, UploadIntent, UploadLimits, UploadService};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::download::conceal_if_not_visible;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::Refused;
use crate::state::ApiState;

/// Reading your own device list is a read of your own identity record, not of any content.
///
/// A device is bound to one user (`docs/10 §3`) and carries no `acl_entries` rows of its own, so
/// the resource whose permission governs it is the user. That makes listing reachable in the
/// shipped binary — `enclave_authorization::SelfServiceAuthorization` allows a principal to read
/// itself — while registration and wipe, which are `Create` and `Update`, are refused until an
/// identity-authorization model exists. That is the correct failure direction and it is `ENC-736`.
const DEVICE_READ: Action = Action::Container(ContainerAction::Read);

/// Enrolling a device creates a thing inside the caller's own identity.
const DEVICE_CREATE: Action = Action::Container(ContainerAction::Create);

/// A wipe changes an existing device. Not `Delete`: the row is never deleted (see
/// `migrations/0023_sync_devices.sql`), and an action that said otherwise would be the first step
/// towards a handler that made it true.
const DEVICE_UPDATE: Action = Action::Container(ContainerAction::Update);

/// Listing a scope's changes is a read of the container.
const SCOPE_READ: Action = Action::Container(ContainerAction::Read);

/// The action rule 6 is about, and the one every sync refusal is recorded against.
const SYNC: Action = Action::File(FileAction::Sync);

/// The second half of `docs/10 §5` condition 3.
const DOWNLOAD: Action = Action::File(FileAction::Download);

/// Whether the caller may know a file exists at all — the question that separates *omit* from
/// *tombstone* (`enclave_sync::eligibility`).
const METADATA_READ: Action = Action::File(FileAction::MetadataRead);

/// Writing a new version from a device is an edit.
const EDIT: Action = Action::File(FileAction::Edit);

/// The default and maximum page size for a delta.
///
/// `docs/10 §4`'s worked example uses `limit=500`. The maximum is the same number rather than a
/// larger one: a page is a policy evaluation over every entry in it, and an unbounded limit is a
/// caller choosing how much work one request does.
const DEFAULT_DELTA_LIMIT: i64 = 500;

/// How long a reservation's upload URLs live.
///
/// The same ceiling `crates/api/src/download.rs` applies to a signed download URL and for the same
/// reason (`plans/M1-CONTENT-CORE.md` D14): no S3-compatible backend can invalidate a pre-signed
/// URL before it expires, so the TTL *is* the revocation window.
const RESERVATION_TTL: Duration = Duration::from_secs(900);

/// The per-file ceiling applied when a library pins none.
///
/// `libraries.max_file_size_bytes` is nullable and means *"use the tenant default"*
/// (`docs/04-DATA-MODEL.md §7`), and there is no tenant-settings reader in this workspace yet. Five
/// gigabytes rather than "unlimited", because the only safe reading of an unconfigured ceiling is a
/// bounded one — and because `UploadLimits` treats a nonsensical limit as zero for the same reason.
/// Reading it from tenant settings is `ENC-738`.
const DEFAULT_TENANT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

// -------------------------------------------------------------------------------------------
// Wire types
// -------------------------------------------------------------------------------------------

/// `POST /sync/devices`'s body.
///
/// `publicKey` from `docs/10 §3` is deliberately absent rather than accepted and ignored: a key
/// stored and never verified reads like a control and is not one. See [`crate::sync`] and
/// `ENC-736`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// What the user will see in their device list.
    name: String,
    /// `windows`, `macos`, `ios`, …
    platform: String,
    /// The client build, which the minimum-version refusal of `docs/10 §10` reads.
    client_version: String,
}

/// A device, as its owner and an administrator see it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    id: String,
    user_id: String,
    name: String,
    platform: String,
    client_version: String,
    posture: &'static str,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wipe_requested_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wiped_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether a wipe has been asked for and the device has not confirmed it.
    ///
    /// On the wire as its own field rather than left for a client to derive from the two timestamps,
    /// because this is the fact `docs/10 §3.1` says the admin UI must show plainly: a cooperative
    /// wipe that has not been cooperated with has *not* happened, and a UI that renders
    /// "wipe requested" as "wiped" is the misreading the whole section exists to prevent.
    wipe_outstanding: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<&SyncDevice> for DeviceView {
    fn from(device: &SyncDevice) -> Self {
        Self {
            id: device.device_id.to_string(),
            user_id: device.user_id.to_string(),
            name: device.name.clone(),
            platform: device.platform.clone(),
            client_version: device.client_version.clone(),
            posture: posture_str(device.posture),
            state: device.state.as_str(),
            last_sync_at: device.last_sync_at,
            wipe_requested_at: device.wipe_requested_at,
            wiped_at: device.wiped_at,
            wipe_outstanding: device.wipe_outstanding(),
            created_at: device.created_at,
        }
    }
}

/// A list of devices.
#[derive(Debug, Serialize)]
pub struct DeviceList {
    items: Vec<DeviceView>,
}

/// `GET /sync/devices?userId=`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDevicesParams {
    /// Whose devices. Absent means the caller's own.
    ///
    /// Naming another user is a tenant-wide listing (`docs/05-API.md §13`) and is decided by the
    /// chain against *that* user's record, so a caller with no grant over them is refused exactly
    /// as they would be reading anything else of theirs.
    user_id: Option<String>,
}

/// `GET /sync/delta?scope=&cursor=&limit=&deviceId=`.
///
/// Every field is an owned `String` and nothing is parsed by `serde`, for the reason
/// `crates/api/src/content.rs` gives: a typed `Option<i64>` makes `?limit=abc` a deserialization
/// failure, which axum answers with its own plain-text `400` outside the one error envelope
/// `docs/05-API.md §5` requires.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaParams {
    scope: Option<String>,
    cursor: Option<String>,
    limit: Option<String>,
    device_id: Option<String>,
}

/// One entry of a delta, in the shape `docs/10 §4` puts on the wire.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeltaEntry {
    /// `UPSERT` or `TOMBSTONE`. The feed's own `op` is not this: a stored `UPSERT` becomes a
    /// `TOMBSTONE` for a caller who may not sync it (`enclave_sync::eligibility`).
    op: &'static str,
    file_id: String,
    /// The file's name. A tombstone carries it too — which is why a file the caller may not read is
    /// omitted rather than tombstoned.
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    /// Whether this entry is a folder rather than a file.
    is_folder: bool,
    /// Present only on an eligible entry: a tombstone must not hand over the means to fetch bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_sha256: Option<String>,
    modified_at: chrono::DateTime<chrono::Utc>,
    /// `docs/05-API.md §13`: *"Delta entries carry `syncEligible`"*.
    sync_eligible: bool,
    /// Why not, when not.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    seq: i64,
}

/// A page of the change feed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    entries: Vec<DeltaEntry>,
    /// The position to resume from — the highest `seq` **scanned**, not the highest emitted.
    cursor: String,
    has_more: bool,
}

/// `POST /sync/reserve`'s body (`docs/10 §6`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveRequest {
    file_id: String,
    /// The version the client edited from. `None` for a file the client believes has none.
    #[serde(default)]
    base_version_id: Option<VersionId>,
    /// The digest of what the client is about to send, so a corrupted transfer is refused at the
    /// edge rather than stored.
    #[serde(default)]
    checksum_sha256: Option<String>,
    /// What the client promises to send. Checked against the library's ceiling and the tenant's
    /// quota *here*, so a device does not upload gigabytes to be rejected at commit (`docs/10 §6`).
    size_bytes: u64,
    /// Which device is pushing.
    #[serde(default)]
    device_id: Option<DeviceId>,
}

/// A claimed upload slot.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reservation {
    /// The `uploadId` of `docs/05-API.md §8`. The client completes through the ordinary upload
    /// path; there is no sync-only commit endpoint, which is `docs/10 §2`'s *"it gets no privileged
    /// endpoint"* held structurally.
    upload_id: String,
    /// `SINGLE` or `MULTIPART`, so a client knows which shape of transfer to start.
    transfer: &'static str,
    /// When the URLs stop working.
    urls_expire_at: chrono::DateTime<chrono::Utc>,
    /// The version this reservation was taken against, echoed so a client can prove to itself that
    /// the server agreed with its base.
    #[serde(skip_serializing_if = "Option::is_none")]
    base_version_id: Option<String>,
}

// -------------------------------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/sync/devices` — enrol a device for the calling user.
///
/// The device is bound to the caller's own subject, taken from the verified token and never from
/// the body (`CLAUDE.md` rule 3): a body field naming a user would let one user enrol a device into
/// another's fan-out budget and, worse, receive that user's deltas.
///
/// # Errors
///
/// [`ApiError`]: the denial's own status for a policy refusal; `400` for an unusable field or a
/// user at `sync.max_devices_per_user`.
pub async fn register_device(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, DEVICE_CREATE, &resource, refused).await);
        }
    };
    let resource = ResourceRef::user(ctx.tenant_id, subject);

    let decision = state
        .policy
        .enforce(&ctx, DEVICE_CREATE, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, DEVICE_CREATE, &resource, refused).await);
    }

    let registration = Registration {
        user_id: subject,
        name: bounded(&request.name, "name", 200, request_id)?,
        platform: bounded(&request.platform, "platform", 100, request_id)?,
        client_version: bounded(&request.client_version, "clientVersion", 100, request_id)?,
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let device =
        SyncRepository::register(&mut tx, ctx.tenant_id, &registration, chrono::Utc::now())
            .await
            .map_err(|error| sync_failure(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, NO_STORE)],
        Json(DeviceView::from(&device)),
    )
        .into_response())
}

/// Handles `GET /api/v1/sync/devices` — the caller's devices, or another user's.
///
/// `docs/05-API.md §13`: *"list; admin can list tenant-wide"*. Which of the two happens is decided
/// by the chain rather than by a flag: the resource enforced is the user whose devices are being
/// asked for, so a caller who may not read that user is refused before the query runs, and a caller
/// who may is not distinguished from an "admin" by anything this handler knows.
///
/// # Errors
///
/// [`ApiError`]: the denial's own status for a policy refusal; `404` for an unparseable `userId`.
pub async fn list_devices(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<ListDevicesParams>,
) -> Result<Json<DeviceList>, ApiError> {
    let request_id = ctx.request_id;
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, DEVICE_READ, &resource, refused).await);
        }
    };

    // An unparseable `userId` names no user. `404` rather than a validation failure, so that
    // `?userId=<garbage>` and `?userId=<another tenant's id>` cannot be told apart.
    let owner: UserId = match params.user_id.as_deref() {
        Some(raw) => raw.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?,
        None => subject,
    };
    let resource = ResourceRef::user(ctx.tenant_id, owner);

    let decision = state.policy.enforce(&ctx, DEVICE_READ, &resource).await.map_err(|error| {
        // A user the caller may not read must be indistinguishable from one who does not exist.
        let error = if matches!(error, Error::PolicyDenied { code: ReasonCode::AccessDenied, .. }) {
            Error::NotFound
        } else {
            error
        };
        ApiError::new(error, request_id)
    })?;
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, DEVICE_READ, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let devices = SyncRepository::list(&mut tx, ctx.tenant_id, Some(owner), 200)
        .await
        .map_err(|error| sync_failure(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(Json(DeviceList { items: devices.iter().map(DeviceView::from).collect() }))
}

/// Handles `POST /api/v1/sync/devices/{id}/wipe` — ask a device to delete its local cache.
///
/// # What this guarantees, and what it cannot
///
/// It guarantees two things, both of them server-side and both effective immediately:
///
/// 1. `wipe_requested_at` is stamped and the device moves to `WIPING`, which is the instruction the
///    client reads on its next successful authentication.
/// 2. **The device stops being served.** [`enclave_sync::DeviceState::may_sync`] is true only for
///    `ACTIVE`, so from this commit onward every delta and every reservation naming this device is
///    refused. A wipe that only marked a row would be a wipe that never happened; this is the half
///    that stops more content reaching the machine whether or not the client ever cooperates.
///
/// It cannot delete what is already on the disk. `wiped_at` is stamped only by
/// [`enclave_sync::SyncRepository::acknowledge_wipe`], on the device's own confirmation, and a
/// device that never comes back online stays `WIPING` for ever — which the response says plainly
/// through `wipeOutstanding`. `docs/10 §3.1`: the control that matters for a stolen laptop is the
/// local cache being encrypted at rest with a key in the OS keystore, and that is the client's.
///
/// It also does not revoke the device's tokens, because nothing binds a token to a device yet
/// (`crates/api/src/auth.rs`, `ENC-736`). When the `dev` claim exists, killing the refresh family
/// belongs here, in the same transaction.
///
/// # Errors
///
/// [`ApiError`]: the denial's own status for a policy refusal; `404` when the id names no device in
/// this tenant.
pub async fn wipe_device(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(device): Path<String>,
) -> Result<Json<DeviceView>, ApiError> {
    let request_id = ctx.request_id;
    let device: DeviceId =
        device.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let held = SyncRepository::find(&mut tx, ctx.tenant_id, device)
        .await
        .map_err(|error| sync_failure(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // The device's *owner* is the resource whose permission governs the wipe, so the chain is asked
    // the same question it is asked for the listing. Read before the chain runs and used only to
    // build the reference: an absent device is answered `404` without a decision, which is the same
    // answer another tenant's device id gets, because row-level security made it absent.
    let Some(held) = held else {
        return Err(ApiError::new(Error::NotFound, request_id));
    };
    let resource = ResourceRef::user(ctx.tenant_id, held.user_id);

    let decision = state.policy.enforce(&ctx, DEVICE_UPDATE, &resource).await.map_err(|error| {
        let error = if matches!(error, Error::PolicyDenied { code: ReasonCode::AccessDenied, .. }) {
            Error::NotFound
        } else {
            error
        };
        ApiError::new(error, request_id)
    })?;
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, DEVICE_UPDATE, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let wiped = SyncRepository::request_wipe(&mut tx, ctx.tenant_id, device, chrono::Utc::now())
        .await
        .map_err(|error| sync_failure(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(Json(DeviceView::from(&wiped)))
}

/// Handles `GET /api/v1/sync/delta` — the ordered change feed for one scope.
///
/// # Errors
///
/// [`ApiError`]: `404` when the scope is another tenant's, absent or not granted; `400` for an
/// unusable `scope`, `cursor` or `limit`; the denial's own status for any other policy refusal.
/// `410 CURSOR_TOO_OLD` is returned as a rendered envelope rather than an `ApiError`, because
/// [`Error`] has no variant for it.
pub async fn delta(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<DeltaParams>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let scope = match params.scope.as_deref().map(SyncScope::from_str) {
        Some(Ok(scope)) => scope,
        Some(Err(_)) | None => {
            return Err(ApiError::new(
                Error::Validation(vec![enclave_core::FieldError::new(
                    "scope",
                    ValidationCode::InvalidFormat,
                )]),
                request_id,
            ))
        }
    };
    let cursor = match params.cursor.as_deref().map(DeltaCursor::from_str) {
        Some(Ok(cursor)) => cursor,
        None => DeltaCursor::START,
        Some(Err(_)) => {
            return Err(ApiError::new(
                Error::Validation(vec![enclave_core::FieldError::new(
                    "cursor",
                    ValidationCode::InvalidFormat,
                )]),
                request_id,
            ))
        }
    };
    let limit = delta_limit(params.limit.as_deref(), request_id)?;

    let resource = scope.resource(ctx.tenant_id);

    // The container gate. This is the enumeration boundary: a caller who may not read the library
    // learns nothing about it, and `conceal_if_not_visible` is what makes another tenant's library
    // id answer exactly as a fabricated one does (`CLAUDE.md` rule 7).
    let decision = match state.policy.enforce(&ctx, SCOPE_READ, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, SCOPE_READ, &resource, refused).await);
    }

    // The full chain for `file.sync` against the container, once. This is where conditional access
    // and DLP see the client, the device and the network — `docs/10 §3`'s
    // `IF client_type == SYNC AND device.posture != MANAGED THEN NO_SYNC` is a rule about the
    // *caller*, not about a file, so asking it per entry would be five hundred identical answers.
    //
    // A denial here is not concealed: the caller has already been told the container exists by the
    // decision above, so the honest `403` is the actionable one.
    let sync_decision = state
        .policy
        .enforce(&ctx, SYNC, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id));
    let scope_sync = match sync_decision {
        Ok(decision) => ScopeSync::from_obligations(&decision.into_obligations()),
        // A refusal at this level is not an error for the *delta* — it is every entry becoming a
        // tombstone, which is exactly `docs/10 §4`'s "a file the user lost access to appears as a
        // TOMBSTONE with a reason, not as an omission". The client is told, per file, that policy
        // does not permit sync, and can show "available on the web only" rather than emptying the
        // folder. The chain has already audited the denial.
        Err(_denied) => ScopeSync::Refused,
    };

    let device = asking_device(&state, &ctx, params.device_id.as_deref(), request_id).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let page = match SyncRepository::feed(&mut tx, ctx.tenant_id, scope, cursor, limit).await {
        Ok(page) => page,
        Err(SyncError::CursorTooOld) => return Ok(cursor_too_old().into_response(request_id)),
        Err(error) => return Err(sync_failure(error, request_id)),
    };

    let files: Vec<FileId> = page.entries.iter().map(|entry| entry.file_id).collect();
    let labels = SyncRepository::sync_blocked_by_label(&mut tx, ctx.tenant_id, &files)
        .await
        .map_err(|error| sync_failure(error, request_id))?;

    // Committed before the authorization batches below, for the reason `content.rs::browse` gives:
    // each batch opens its own tenant-scoped transaction, and holding this one open would need two
    // connections per request — a deadlock waiting for load on a small pool.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let entries = render(&state, &ctx, &page.entries, &labels, scope_sync)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // Best-effort, and after the page is assembled: a cursor recorded for a page that then failed
    // to render would move the device past changes it never received.
    if let Some(device) = device.as_ref() {
        if let Err(error) =
            record_cursor(&state, &ctx, device.device_id, scope, page.next_cursor).await
        {
            tracing::warn!(%error, "the server-side sync cursor could not be recorded");
        }
    }

    Ok((
        [(axum::http::header::CACHE_CONTROL, NO_STORE)],
        Json(Delta { entries, cursor: page.next_cursor.to_string(), has_more: page.has_more }),
    )
        .into_response())
}

/// Handles `POST /api/v1/sync/reserve` — claim an upload slot for a locally changed file.
///
/// # What it reserves, and why the endpoint exists at all
///
/// Three things, and each one is a refusal a device would otherwise discover after spending its
/// bandwidth (`docs/10 §6`):
///
/// 1. **The right to write this file from this device.** The full chain runs for `file.sync` and
///    then for `file.edit`. Sync first: a caller who may edit in the browser and may not sync is
///    refused here, which is `CLAUDE.md` rule 6 on the *write* side of the protocol.
/// 2. **Agreement about what the change is based on.** The client declares `baseVersionId`; if the
///    server has moved on, it gets `409` carrying `currentVersionId`, and `docs/10 §6`'s conflict
///    rule takes over — the client uploads its copy alongside rather than over.
/// 3. **A slot the storage layer knows about**, with the library's ceiling and the tenant's storage
///    quota already checked. `enclave_uploads::preflight` is advisory by construction and says so;
///    what it buys is that a device does not send gigabytes to be refused at commit.
///
/// # Errors
///
/// [`ApiError`]: the denial's own status for a policy refusal, `404` for an absent file. `409` and
/// `423` are rendered envelopes — [`Error::Conflict`] carries a revision rather than a version id,
/// and there is no variant for a locked resource.
#[allow(clippy::too_many_lines)]
pub async fn reserve(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    Json(request): Json<ReserveRequest>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let file: FileId =
        request.file_id.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => return Err(state.audit.refuse(&ctx, SYNC, &resource, refused).await),
    };

    // Rule 6, on the write side. Asked *before* `file.edit`, so the refusal a caller who may edit
    // but may not sync receives names the control that actually stopped them.
    for action in [SYNC, EDIT] {
        let decision = match state.policy.enforce(&ctx, action, &resource).await {
            Ok(decision) => decision,
            Err(error) => {
                let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
                return Err(ApiError::new(error, request_id));
            }
        };
        let obligations = decision.into_obligations();
        if let Err(refused) = satisfy_write(&obligations) {
            return Err(state.audit.refuse(&ctx, action, &resource, refused).await);
        }
    }

    let device = asking_device(&state, &ctx, None, request_id).await?;
    if let Some(device) = request.device_id {
        // A named device must be the caller's own and must still be allowed to sync — this is what
        // makes a wipe stop a push as well as a pull.
        let named = load_own_device(&state, &ctx, device, request_id).await?;
        if let Err(refused) = still_syncing(&named) {
            return Err(state.audit.refuse(&ctx, SYNC, &resource, refused).await);
        }
    }
    drop(device);

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let target = SyncRepository::reservation_target(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| sync_failure(error, request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    // A folder has no bytes and a trashed file has no future ones. Both `404`: whether an id names
    // a folder is information about the tenant's content, and this endpoint has one miss answer.
    if target.is_folder || target.deleted {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    // `docs/10 §6`: a file under `CHECKOUT` or an `EDITOR` lock is read-only to sync.
    if let Some(kind) = target.lock_kind.as_deref() {
        return Ok(locked(kind).into_response(request_id));
    }

    // The `409`. Compared against what the server holds *inside this transaction*, so a commit
    // landing between the read and the reservation cannot slip past.
    if target.current_version_id != request.base_version_id {
        return Ok(conflict(target.current_version_id).into_response(request_id));
    }

    let library = LibraryRepository::find_by_id(&mut tx, ctx.tenant_id, target.library_id)
        .await
        .map_err(|_error| ApiError::new(Error::NotFound, request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let limits = UploadLimits::from_library(&library.settings, DEFAULT_TENANT_MAX_FILE_BYTES);

    let issued = UploadService::create(
        &mut tx,
        store.as_ref(),
        ctx.tenant_id,
        &NewUpload {
            library_id: target.library_id,
            parent_id: target.parent_id,
            intent: UploadIntent::NewVersion(file),
            name: target.name.clone(),
            declared_size: request.size_bytes,
            declared_mime: None,
            declared_sha256: request.checksum_sha256.clone(),
            created_by: subject,
        },
        &limits,
        chrono::Duration::from_std(RESERVATION_TTL).unwrap_or_else(|_| chrono::Duration::hours(1)),
        chrono::Utc::now(),
    )
    .await
    .map_err(|error| ApiError::new(enclave_core::Error::from(error), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let transfer = match issued.target {
        enclave_storage::UploadTarget::Single { .. } => "SINGLE",
        enclave_storage::UploadTarget::Multipart { .. } => "MULTIPART",
    };

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, NO_STORE)],
        Json(Reservation {
            upload_id: issued.session.id().to_string(),
            transfer,
            urls_expire_at: issued.urls_expire_at,
            base_version_id: request.base_version_id.map(|id| id.to_string()),
        }),
    )
        .into_response())
}

// -------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------

/// Whether the chain permitted sync from this scope at all, and whether it attached an obligation
/// this path cannot discharge.
///
/// Three states rather than a `bool`, because "allowed" and "allowed with `NO_SYNC` attached" are
/// different facts that produce the same *outcome* and must not be confused when the reason is
/// written into a tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeSync {
    /// Allowed with nothing outstanding.
    Permitted,
    /// Allowed, with an obligation no sync path can satisfy — `NO_SYNC`, `NO_DOWNLOAD`, a
    /// watermark that placed bytes cannot carry.
    Obligated,
    /// Denied outright by a stage.
    Refused,
}

impl ScopeSync {
    /// Reads the chain's obligations for the sync action.
    ///
    /// Every obligation except [`Obligation::ReadOnly`] is undischargeable on this path, and the
    /// exception is argued rather than assumed: a delta hands over metadata and a checksum, and
    /// carries no mutation affordance for `ReadOnly` to suppress. A watermark cannot be burned into
    /// bytes copied verbatim to a disk; a justification has nowhere to be collected on a background
    /// poll; an approval is a workflow this endpoint cannot start. Each of those is a refusal
    /// rather than a shrug (`CLAUDE.md` rule 8) — here expressed as *every entry becomes a
    /// tombstone*, which is the refusal the protocol has a shape for.
    fn from_obligations(obligations: &Obligations) -> Self {
        let dischargeable =
            obligations.iter().all(|obligation| matches!(*obligation, Obligation::ReadOnly));
        if dischargeable {
            Self::Permitted
        } else {
            Self::Obligated
        }
    }

    /// Whether an entry may be eligible at all.
    const fn permits(self) -> bool {
        matches!(self, Self::Permitted)
    }
}

/// Turns feed entries into wire rows, evaluating eligibility per entry.
///
/// Three batched authorization questions over the whole page rather than three per entry:
/// *may you see it*, *may you download it*, *may you sync it*. The last two are separate questions
/// and that is the entire point (`CLAUDE.md` rule 6).
///
/// A failed resolution is not a denial (`crates/core/src/engine.rs`): a page that could not be
/// evaluated must not be served un-evaluated, so the error propagates rather than defaulting.
async fn render(
    state: &ApiState,
    ctx: &RequestContext,
    entries: &[FeedEntry],
    labels: &[(FileId, bool)],
    scope_sync: ScopeSync,
) -> Result<Vec<DeltaEntry>, Error> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let authorization: &dyn AuthorizationService = state.policy.authorization().as_ref();

    let refs: Vec<ResourceRef> = entries
        .iter()
        .map(|entry| {
            if entry.is_folder {
                ResourceRef::folder(ctx.tenant_id, entry.file_id)
            } else {
                ResourceRef::file(ctx.tenant_id, entry.file_id)
            }
        })
        .collect();

    let visible = authorization.authorize_many(ctx, METADATA_READ, &refs).await?;
    let downloadable = authorization.authorize_many(ctx, DOWNLOAD, &refs).await?;
    let syncable = authorization.authorize_many(ctx, SYNC, &refs).await?;

    let mut rendered = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        // Index-aligned by contract. A short vector trims *more* than necessary, which is a bug
        // rather than a disclosure — the same direction `content.rs::readable_children` chooses.
        let (Some(visible), Some(downloadable), Some(syncable)) =
            (visible.get(index), downloadable.get(index), syncable.get(index))
        else {
            continue;
        };

        let eligibility = Eligibility {
            visibility: if visible.is_allowed() { Visibility::Visible } else { Visibility::Hidden },
            deleted: entry.deleted,
            library_sync_enabled: entry.library_sync_enabled,
            classification_permits_sync: !labels
                .iter()
                .any(|(file, blocked)| *file == entry.file_id && *blocked),
            download_allowed: downloadable.is_allowed(),
            sync_allowed: syncable.is_allowed() && scope_sync != ScopeSync::Refused,
            obligations_dischargeable: scope_sync.permits(),
            // A folder has no bytes to scan, so rule 9 has nothing to say about it; a file with no
            // readable version is exactly what the predicate refused.
            version_readable: entry.is_folder || entry.readable_version.is_some(),
        };

        match eligibility.verdict() {
            Verdict::Omit => {}
            Verdict::Eligible => rendered.push(upsert_row(entry)),
            Verdict::Tombstone(reason) => rendered.push(tombstone_row(entry, reason)),
        }
    }
    Ok(rendered)
}

/// An eligible entry — the only shape that carries a version id and a checksum.
fn upsert_row(entry: &FeedEntry) -> DeltaEntry {
    DeltaEntry {
        op: "UPSERT",
        file_id: entry.file_id.to_string(),
        path: entry.name.clone(),
        parent_id: entry.parent_id.map(|id| id.to_string()),
        is_folder: entry.is_folder,
        version_id: entry.readable_version.as_ref().map(|version| version.id.to_string()),
        size_bytes: entry.readable_version.as_ref().map(|version| version.size_bytes),
        checksum_sha256: entry
            .readable_version
            .as_ref()
            .map(|version| version.checksum_sha256.clone()),
        modified_at: entry.modified_at,
        sync_eligible: true,
        reason: None,
        seq: entry.seq,
    }
}

/// An ineligible entry.
///
/// The version fields are `None` unconditionally, and that is the assertion rather than an
/// omission: a tombstone that carried a version id and a checksum would hand a caller who may not
/// sync the two values needed to ask for the bytes by another route.
fn tombstone_row(entry: &FeedEntry, reason: TombstoneReason) -> DeltaEntry {
    DeltaEntry {
        op: "TOMBSTONE",
        file_id: entry.file_id.to_string(),
        path: entry.name.clone(),
        parent_id: entry.parent_id.map(|id| id.to_string()),
        is_folder: entry.is_folder,
        version_id: None,
        size_bytes: None,
        checksum_sha256: None,
        modified_at: entry.modified_at,
        sync_eligible: false,
        reason: Some(reason.as_str()),
        seq: entry.seq,
    }
}

/// Which device is asking, when one can be established.
///
/// Prefers `ctx.device.device_id` — the verified `dev` claim — and falls back to a parameter that is
/// checked to belong to the caller. See [`crate::sync`] for why the fallback exists and what it
/// costs. `None` is a supported answer: a client that names no device gets its delta and no
/// server-side cursor is recorded for it.
async fn asking_device(
    state: &ApiState,
    ctx: &RequestContext,
    named: Option<&str>,
    request_id: RequestId,
) -> Result<Option<SyncDevice>, ApiError> {
    let candidate = match ctx.device.device_id {
        Some(claimed) => Some(claimed),
        None => match named {
            Some(raw) => Some(raw.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?),
            None => None,
        },
    };
    match candidate {
        None => Ok(None),
        Some(device) => load_own_device(state, ctx, device, request_id).await.map(Some),
    }
}

/// Loads a device and refuses one that is not the caller's.
///
/// A device belonging to another user in the same tenant answers `404`, not `403`: telling a caller
/// that a device id exists but is somebody else's is an enumeration of the tenant's device ids, and
/// `CLAUDE.md` rule 7's reasoning does not stop at files.
async fn load_own_device(
    state: &ApiState,
    ctx: &RequestContext,
    device: DeviceId,
    request_id: RequestId,
) -> Result<SyncDevice, ApiError> {
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let held = SyncRepository::find(&mut tx, ctx.tenant_id, device)
        .await
        .map_err(|error| sync_failure(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let subject = ctx.actor.subject_id();
    held.filter(|held| subject.is_some_and(|id| id == held.user_id.as_uuid()))
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))
}

/// Writes the server-side cursor, in its own transaction.
async fn record_cursor(
    state: &ApiState,
    ctx: &RequestContext,
    device: DeviceId,
    scope: SyncScope,
    cursor: DeltaCursor,
) -> Result<(), Error> {
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(Error::from)?;
    SyncRepository::record_cursor(
        &mut tx,
        ctx.tenant_id,
        device,
        scope,
        cursor,
        chrono::Utc::now(),
    )
    .await
    .map_err(Error::from)?;
    tx.commit().await.map_err(Error::from)
}

/// Honours every obligation a read-shaped sync endpoint can, or turns it into a refusal.
///
/// Exhaustive on purpose. [`Obligation`] is deliberately not `#[non_exhaustive]`, so a new
/// obligation breaks this and forces someone to decide what it means for a caller who is about to
/// be told what is on their disk.
///
/// # Errors
///
/// [`Refused`], which cannot become an error except through
/// [`crate::refusal::HandlerAudit::refuse`] — so the row is written by the type system rather than
/// by remembering to (`ENC-606`).
fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            // Satisfied by construction: these responses carry a device list or a change feed, and
            // neither offers a mutation affordance for `ReadOnly` to suppress.
            Obligation::ReadOnly => {}
            // Everything else. A device listing cannot be watermarked, a background poll has
            // nowhere to collect a justification, and an approval is a workflow this endpoint
            // cannot start. Rule 8: an obligation that cannot be discharged is a refusal.
            other => return Err(Refused::obligation(other)),
        }
    }
    Ok(())
}

/// The same, for the reservation path.
///
/// Separated from [`satisfy`] because the answer genuinely differs: a reservation *is* a mutation
/// affordance — it hands out URLs a client writes to — so [`Obligation::ReadOnly`] refuses here
/// where it is satisfied there. Collapsing the two would mean a read-only obligation silently
/// permitting a write.
///
/// # Errors
///
/// [`Refused`], as [`satisfy`].
fn satisfy_write(obligations: &Obligations) -> Result<(), Refused> {
    match obligations.iter().next() {
        None => Ok(()),
        Some(obligation) => Err(Refused::obligation(*obligation)),
    }
}

/// The refusal a device that may no longer sync earns.
///
/// This is the half of a remote wipe that actually stops content moving, on the write side: a
/// device in `WIPING`, `WIPED` or `REVOKED` is refused a reservation from the moment the wipe is
/// requested, whether or not the client ever acknowledges it. `SYNC_NOT_PERMITTED` rather than
/// `ACCESS_DENIED`, because the caller's *permissions* are unchanged — it is this machine that may
/// no longer hold a copy, and a client told "access denied" would prompt the user to ask for a
/// grant they already have.
///
/// A function returning [`Refused`] rather than an inline construction in the handler, and not only
/// to satisfy `cargo run -p xtask -- audit-coverage`: that gate's rule *is* the reason — a refusal
/// built where nothing can be proven to record it is a refusal that reaches a caller with no row.
///
/// # Errors
///
/// [`Refused`] when the device is in any state but `ACTIVE`.
fn still_syncing(device: &SyncDevice) -> Result<(), Refused> {
    if device.may_sync() {
        Ok(())
    } else {
        Err(Refused::actor(ReasonCode::SyncNotPermitted))
    }
}

/// The caller's own user id, or the refusal a subject-less principal earns.
///
/// A `System` actor has no user row and no device fan-out budget. It should never reach an HTTP
/// handler; saying so is cheaper than discovering it as a nil-UUID foreign-key violation.
fn subject(ctx: &RequestContext) -> Result<UserId, Refused> {
    ctx.actor
        .subject_id()
        .map(UserId::from_uuid)
        .ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))
}

/// `410 CURSOR_TOO_OLD` (`docs/10 §4`).
///
/// An [`Envelope`] rather than an [`ApiError`], because [`Error`]'s status comes from its variant
/// and none of them is `410`. The remediation is the client's actual next step: re-enumerate the
/// scope from the beginning.
fn cursor_too_old() -> Envelope {
    Envelope::new(
        StatusCode::GONE,
        "CURSOR_TOO_OLD",
        "The sync cursor is older than the change history this scope retains.",
        "Re-enumerate the scope from cursor 0.",
    )
}

/// `409 CONFLICT` carrying the version the server holds (`docs/10 §6`).
///
/// The current version is in `details` rather than in the prose, because `docs/05-API.md §5`
/// requires the three message fields to be literals and this one is data. Without it the client has
/// to make a second call to discover what it is conflicting with, which is a round trip on the one
/// path that is already carrying a user's unsaved work.
fn conflict(current: Option<VersionId>) -> Envelope {
    Envelope::new(
        StatusCode::CONFLICT,
        "CONFLICT",
        "The file has changed on the server since this device last synced it.",
        "Upload the local copy as a conflicted copy and let a person reconcile them.",
    )
    .with_details(vec![serde_json::json!({
        "field": "baseVersionId",
        "currentVersionId": current.map(|id| id.to_string()),
    })])
}

/// `423 LOCKED` for a file held under checkout or an editor session (`docs/10 §6`).
///
/// The holder's name is deliberately **not** in the payload. `docs/10 §6` says the client marks the
/// file locked with the holder's name, and that name is a directory fact about another user which
/// this endpoint has taken no decision about disclosing — the client already has it from the file's
/// metadata if it may see it.
fn locked(kind: &str) -> Envelope {
    let code = if kind == "EDITOR" { "EDITOR_LOCK" } else { "CHECKED_OUT" };
    Envelope::new(
        StatusCode::LOCKED,
        code,
        "The file is locked and cannot be written from a sync client.",
        "Wait for the lock to be released, or check the file in from the web client.",
    )
}

/// Parses and clamps `?limit=`.
///
/// Clamped rather than refused above the maximum, which is the choice `docs/05-API.md §6` makes for
/// pagination generally: a client asking for more than the server will give gets a smaller page and
/// `hasMore`, not an error it has to special-case. Zero and negative are refusals rather than
/// clamps, because they are a client that has computed a limit wrongly and would otherwise poll for
/// ever against a page that can never contain anything.
fn delta_limit(raw: Option<&str>, request_id: RequestId) -> Result<i64, ApiError> {
    let Some(raw) = raw else { return Ok(DEFAULT_DELTA_LIMIT) };
    let parsed = raw.trim().parse::<i64>().ok().filter(|value| *value > 0);
    match parsed {
        Some(value) => Ok(value.min(DEFAULT_DELTA_LIMIT)),
        None => Err(ApiError::new(
            Error::Validation(vec![enclave_core::FieldError::new(
                "limit",
                ValidationCode::OutOfRange,
            )]),
            request_id,
        )),
    }
}

/// Bounds a body string, matching the `CHECK` constraints in `migrations/0023_sync_devices.sql`.
///
/// Checked here as well as by the constraint so the caller gets a named field rather than a
/// database error, and checked in *characters* rather than bytes because the constraint uses
/// `length()`, which is PostgreSQL's character count.
fn bounded(
    raw: &str,
    field: &'static str,
    max_chars: usize,
    request_id: RequestId,
) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    let code = if trimmed.is_empty() {
        Some(ValidationCode::Required)
    } else if trimmed.chars().count() > max_chars {
        Some(ValidationCode::TooLong)
    } else {
        None
    };
    match code {
        None => Ok(trimmed.to_owned()),
        Some(code) => Err(ApiError::new(
            Error::Validation(vec![enclave_core::FieldError::new(field, code)]),
            request_id,
        )),
    }
}

/// Maps a `crates/sync` failure onto the one error type the API renders.
fn sync_failure(error: SyncError, request_id: RequestId) -> ApiError {
    ApiError::new(Error::from(error), request_id)
}

/// `DevicePosture`'s stored spelling, for the wire.
///
/// A match rather than a serde round trip: `DevicePosture` is a `serde` enumeration in
/// `enclave_core` with no `as_str`, and serialising it to a JSON string only to strip the quotes
/// would be a longer way to write the same four literals.
const fn posture_str(posture: enclave_core::DevicePosture) -> &'static str {
    match posture {
        enclave_core::DevicePosture::Unknown => "UNKNOWN",
        enclave_core::DevicePosture::Unmanaged => "UNMANAGED",
        enclave_core::DevicePosture::Managed => "MANAGED",
        enclave_core::DevicePosture::Compliant => "COMPLIANT",
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::ClassificationRank;

    use super::*;

    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }

    /// A tombstone hands over nothing that could be used to fetch the bytes.
    ///
    /// The point of the test is the *absence*: a future refactor that built one row type for both
    /// shapes and set `syncEligible` last would leak a version id and a checksum to precisely the
    /// caller who was just refused them.
    #[test]
    fn a_tombstone_carries_no_version_and_no_checksum() {
        let entry = FeedEntry {
            seq: 12,
            file_id: FileId::new_v7(),
            op: enclave_sync::ChangeOp::Upsert,
            library_id: enclave_core::LibraryId::new_v7(),
            name: "MSA.pdf".to_owned(),
            parent_id: None,
            is_folder: false,
            deleted: false,
            modified_at: chrono::Utc::now(),
            readable_version: Some(enclave_sync::ReadableVersion {
                id: VersionId::new_v7(),
                size_bytes: 812_311,
                checksum_sha256: "a".repeat(64),
            }),
            library_sync_enabled: true,
        };

        let refused = tombstone_row(&entry, TombstoneReason::AccessRevoked);
        assert!(!refused.sync_eligible);
        assert_eq!(refused.reason, Some("ACCESS_REVOKED"));
        assert_eq!(refused.version_id, None, "a tombstone named the version");
        assert_eq!(refused.checksum_sha256, None, "a tombstone carried a checksum");
        assert_eq!(refused.size_bytes, None);

        // The positive control: the same entry, eligible, does carry them — so the assertion above
        // is about the tombstone and not about an entry that never had a version.
        let allowed = upsert_row(&entry);
        assert!(allowed.sync_eligible);
        assert!(allowed.version_id.is_some());
        assert!(allowed.checksum_sha256.is_some());
    }

    /// A read-shaped sync response can discharge `ReadOnly` and nothing else.
    #[test]
    fn the_delta_refuses_every_obligation_it_cannot_discharge() {
        assert!(satisfy(&Obligations::none()).is_ok());
        assert!(satisfy(&obligations([Obligation::ReadOnly])).is_ok());
        for undischargeable in [
            Obligation::NoSync,
            Obligation::NoDownload,
            Obligation::Watermark,
            Obligation::RequireJustification,
            Obligation::RequireApproval,
            Obligation::Reclassify { to: ClassificationRank::new(40) },
        ] {
            let refused = satisfy(&obligations([undischargeable]))
                .expect_err("an undischargeable obligation must refuse");
            assert_eq!(refused.code(), undischargeable.unsatisfied_code());
        }
    }

    /// `ReadOnly` refuses a *reservation*, which is the one place the two paths must differ.
    #[test]
    fn read_only_permits_a_delta_and_refuses_a_reservation() {
        let read_only = obligations([Obligation::ReadOnly]);
        assert!(satisfy(&read_only).is_ok(), "a delta carries no mutation affordance");
        assert!(
            satisfy_write(&read_only).is_err(),
            "a reservation hands out URLs a client writes to; READ_ONLY must refuse it"
        );
    }

    /// The scope-level obligation reading is what turns a `NO_SYNC` into tombstones.
    #[test]
    fn a_no_sync_obligation_makes_the_scope_ineligible() {
        assert_eq!(ScopeSync::from_obligations(&Obligations::none()), ScopeSync::Permitted);
        assert_eq!(
            ScopeSync::from_obligations(&obligations([Obligation::ReadOnly])),
            ScopeSync::Permitted
        );
        assert_eq!(
            ScopeSync::from_obligations(&obligations([Obligation::NoSync])),
            ScopeSync::Obligated
        );
        assert!(!ScopeSync::Obligated.permits());
        assert!(!ScopeSync::Refused.permits());
        assert!(ScopeSync::Permitted.permits());
    }

    #[test]
    fn a_device_name_is_bounded_the_way_the_constraint_bounds_it() {
        let id = RequestId::new_v7();
        assert_eq!(bounded("  laptop  ", "name", 200, id).expect("trimmed"), "laptop");
        assert!(bounded("   ", "name", 200, id).is_err(), "a blank name is not a name");
        // Characters, not bytes: the constraint uses PostgreSQL's `length()`.
        let two_hundred_chars = "é".repeat(200);
        assert!(bounded(&two_hundred_chars, "name", 200, id).is_ok());
        assert!(bounded(&"é".repeat(201), "name", 200, id).is_err());
    }

    /// A wipe stops a push, not only a pull.
    #[test]
    fn a_device_told_to_wipe_may_not_reserve_an_upload() {
        let base = SyncDevice {
            tenant_id: enclave_core::TenantId::new_v7(),
            device_id: DeviceId::new_v7(),
            user_id: UserId::new_v7(),
            name: "laptop".to_owned(),
            platform: "macos".to_owned(),
            client_version: "1.0.0".to_owned(),
            posture: enclave_core::DevicePosture::Managed,
            state: enclave_sync::DeviceState::Active,
            last_sync_at: None,
            wipe_requested_at: None,
            wiped_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        // The positive control first, so the refusals below cannot be a function that refuses
        // everything.
        assert!(still_syncing(&base).is_ok(), "an active device may reserve");

        for state in [
            enclave_sync::DeviceState::Wiping,
            enclave_sync::DeviceState::Wiped,
            enclave_sync::DeviceState::Revoked,
            enclave_sync::DeviceState::Paused,
        ] {
            let stopped = SyncDevice { state, ..base.clone() };
            let refused = still_syncing(&stopped)
                .expect_err("a device that may not sync must not reserve an upload");
            assert_eq!(refused.code(), ReasonCode::SyncNotPermitted, "state = {state}");
        }
    }

    #[test]
    fn a_limit_is_clamped_upward_and_refused_downward() {
        let id = RequestId::new_v7();
        assert_eq!(delta_limit(None, id).expect("the default"), DEFAULT_DELTA_LIMIT);
        assert_eq!(delta_limit(Some("10"), id).expect("a small page"), 10);
        assert_eq!(
            delta_limit(Some("100000"), id).expect("clamped"),
            DEFAULT_DELTA_LIMIT,
            "an unbounded limit is a caller choosing how much work one request does"
        );
        for refused in ["0", "-1", "abc", ""] {
            assert!(delta_limit(Some(refused), id).is_err(), "`{refused}` was accepted");
        }
    }

    #[test]
    fn the_conflict_envelope_names_the_version_the_server_holds() {
        let current = VersionId::new_v7();
        let envelope = conflict(Some(current));
        assert_eq!(envelope.status(), StatusCode::CONFLICT);
        let rendered = serde_json::to_string(&envelope.details()[0]).expect("serialize");
        assert!(rendered.contains(&current.to_string()), "{rendered}");
    }

    #[test]
    fn a_stale_cursor_is_gone_rather_than_a_validation_failure() {
        // `410`, because the resource the cursor names is not malformed — it existed and has been
        // pruned. A `400` would tell the client to fix its request; the fix is to re-enumerate.
        assert_eq!(cursor_too_old().status(), StatusCode::GONE);
        assert_eq!(cursor_too_old().code(), "CURSOR_TOO_OLD");
    }

    #[test]
    fn an_editor_lock_and_a_checkout_are_distinguishable_to_the_client() {
        assert_eq!(locked("EDITOR").code(), "EDITOR_LOCK");
        assert_eq!(locked("CHECKOUT").code(), "CHECKED_OUT");
        assert_eq!(locked("EDITOR").status(), StatusCode::LOCKED);
    }
}
