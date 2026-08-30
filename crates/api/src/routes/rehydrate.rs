//! `POST /api/v1/files/{id}/rehydrate` — asking for archived bytes back (`ENC-946`).
//!
//! # Why this authorizes as `content_read`
//!
//! Rehydration is not a new power. It restores a file to the state it was already in, for a caller
//! who could already read it — so the question *"may this person summon these bytes"* has the same
//! answer as *"may this person read these bytes"*, and giving it an action of its own would create
//! a permission an administrator has to grant separately for something nobody would ever withhold.
//!
//! `ContentRead` and not `Download`: the point of a restore is to make the file usable again, and a
//! caller who may preview but not download still needs a preview that works. Choosing `Download`
//! would leave preview-only users looking at a file they are permitted to see and cannot summon.
//!
//! # Why it costs money and is still not rate-limited here
//!
//! Every restore is a billed retrieval, so this is a spend a caller can trigger. It is bounded by
//! two things that already exist: a second request against a version already `RESTORING` is a
//! no-op that touches no provider, so repeated clicks cost nothing after the first; and the chain
//! refuses a caller with no read grant before any of this runs. A per-tenant retrieval budget is a
//! real requirement and is `ENC-949`, not something to approximate here with a counter that would
//! be the only rate limit in the crate.

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use enclave_core::{Action, Error, FileAction, FileId, ResourceRef};
use enclave_storage::{BlobStore, StorageError};
use enclave_versions::StorageTier;
use serde::Serialize;
use std::sync::Arc;

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::state::ApiState;

/// The action a restore is decided as. See the module header.
const ACTION: Action = Action::File(FileAction::ContentRead);

/// How long a restored copy stays readable before falling back to cold.
///
/// Seven days. Long enough that a person who asked on Friday can still open it on Monday — the
/// realistic shape of a request that takes hours to satisfy — and short enough that a forgotten
/// restore stops being billed at hot rates within a week. Named here rather than inlined because
/// it is the one number in this file somebody will want to change.
const RESTORE_WINDOW_DAYS: i32 = 7;

/// What the caller is told.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Accepted {
    /// The tier the version is in now — `RESTORING`, or `HOT` if there was nothing to do.
    storage_tier: &'static str,
    /// Whether this request started a restore, as opposed to joining one already running.
    started: bool,
}

/// Handles `POST /api/v1/files/{id}/rehydrate`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unknown file, or a database failure. A store with no cold
/// tier and a version that is not archived are both rendered as `docs/05-API.md §5` envelopes in
/// the `Ok` arm.
pub async fn rehydrate(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    let decision = state
        .policy
        .enforce(&ctx, ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    // `PolicyDecision` is `#[must_use]`. This surface can discharge no obligation — there is no
    // rendition to watermark and no bytes to hand over, only a request queued at a provider — so an
    // obligation arriving here is a refusal (D29, `CLAUDE.md` rule 8).
    if let Err(refused) = crate::refusal::none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, ACTION, &resource, refused).await);
    }

    // Resolved through the same reader every content path uses, so rule 9 applies here too: a
    // version antivirus has not cleared is a `404` and is not summonable. Restoring quarantined
    // bytes would be paying to bring back something no read path will serve.
    let version =
        crate::download::readable_version_for(&state, &ctx, file, None, request_id).await?;

    match version.storage_tier {
        // Nothing to do, and reported as success rather than as an error: a caller who clicks twice
        // on a file that has already landed has got what they asked for, and a `409` here would
        // teach them that the working case looks like a failure.
        StorageTier::Hot => {
            return Ok(accepted(StorageTier::Hot, false));
        }
        // Already in flight. The provider is not asked again — S3 answers a duplicate
        // `RestoreObject` with `RestoreAlreadyInProgress`, and a caller cannot act on that, so it
        // is absorbed here where the state that makes it harmless is visible.
        StorageTier::Restoring => {
            return Ok(accepted(StorageTier::Restoring, false));
        }
        // A transition *to* cold that has not finished. Asking for it back mid-flight would race
        // the archive, and the two requests would arrive at the provider in an order neither
        // caller chose. `ENC-947`'s sweep resolves the row first.
        StorageTier::Archiving => {
            return Ok(Envelope::new(
                StatusCode::CONFLICT,
                "ARCHIVE_IN_PROGRESS",
                "This version is still being moved to long-term storage.",
                "Wait for the move to finish, then request it back.",
            )
            .into_response(request_id));
        }
        StorageTier::Archived => {}
    }

    if !store.capabilities().storage_tiers.is_confirmed() {
        // The row says `ARCHIVED` and this deployment's object store has no cold tier to bring it
        // back from. That is a real state — content archived under one storage profile and read
        // under another, or a bucket lifecycle rule this build cannot reverse — and it is reported
        // as what it is rather than as a failed restore, because no amount of retrying fixes it.
        return Ok(Envelope::new(
            StatusCode::CONFLICT,
            "RESTORE_UNSUPPORTED",
            "This deployment's object store cannot restore archived content.",
            "Contact an administrator: the bytes exist and need to be retrieved out of band.",
        )
        .into_response(request_id));
    }

    // The row is marked **before** the provider is called, and that order is the decision.
    //
    // Called-then-marked loses the request if the process dies between the two: the provider is
    // restoring, the row still says `ARCHIVED`, and the next caller pays for a second retrieval of
    // an object already on its way back. Marked-then-called can leave a row `RESTORING` for a
    // request that never landed, which is the cheaper failure and the one a sweep can see —
    // `restore_requested_at` exists so that "stuck since Tuesday" is answerable (`ENC-947`).
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let marked =
        enclave_versions::VersionRepository::mark_restoring(&mut tx, ctx.tenant_id, version.id)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if !marked {
        // Another request won the race and marked it first. Its provider call is the one that
        // counts; this one reports the shared outcome rather than issuing a second retrieval.
        return Ok(accepted(StorageTier::Restoring, false));
    }

    match store.request_restore(&version.object_key, RESTORE_WINDOW_DAYS).await {
        Ok(()) => {}
        Err(StorageError::Unsupported { .. }) => {
            return Ok(Envelope::new(
                StatusCode::CONFLICT,
                "RESTORE_UNSUPPORTED",
                "This deployment's object store cannot restore archived content.",
                "Contact an administrator: the bytes exist and need to be retrieved out of band.",
            )
            .into_response(request_id));
        }
        Err(error) => {
            // The row stays `RESTORING`. Rolling it back on a provider failure is tempting and
            // wrong: this cannot tell a request that was rejected from one that was accepted and
            // whose response was lost, and clearing the mark on the second case invites a duplicate
            // retrieval that is billed. The sweep reconciles against the store, which is the only
            // place the truth is.
            tracing::warn!(
                %ctx.request_id,
                %ctx.tenant_id,
                version_id = %version.id,
                error = %error,
                "a restore was requested and the object store refused; the row stays RESTORING for \
                 the sweep to reconcile"
            );
            return Err(ApiError::new(crate::download::storage_failure(&error), request_id));
        }
    }

    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        version_id = %version.id,
        days = RESTORE_WINDOW_DAYS,
        "a restore from cold storage was requested"
    );
    Ok(accepted(StorageTier::Restoring, true))
}

fn accepted(tier: StorageTier, started: bool) -> Response {
    (
        StatusCode::ACCEPTED,
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(Accepted { storage_tier: tier.as_str(), started }),
    )
        .into_response()
}
