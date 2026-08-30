//! Starring a file, and listing what this person starred (`ENC-959`).
//!
//! *Favorites* has carried a `Later` chip in the navigation since the shell was written, and there
//! was no table behind it until `migrations/0034`.
//!
//! # A favorite grants nothing, and is still put through the chain
//!
//! Starring is a private note about a file the person could already see: it confers no access,
//! reveals nothing to anybody else, and no other surface reads it. So the write is authorized as
//! **`file.metadata_read`** — the question is *may this person see that this file exists*, and a
//! caller who may not read it must not be able to learn that it exists by starring it either.
//!
//! Not `file.edit`: starring changes nothing about the document, and requiring an edit permission
//! would stop a reader bookmarking something they are allowed to read — which is most of what
//! favorites are for.
//!
//! # Idempotent on both sides, and both report what actually happened
//!
//! `PUT` on an already-starred file and `DELETE` on an unstarred one are both **success**. The
//! state the caller asked for is the state that holds, and a `409` would teach a client that the
//! ordinary double-click looks like a failure. `created` and `removed` say which of the two
//! happened, for a client that wants to count rather than guess.
//!
//! `PUT` rather than `POST`, for that reason: the request declares a desired state rather than
//! appending an event, and it may be repeated without changing the outcome.

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, ContainerAction, Error, FieldError, FileAction, FileId, Obligations, RequestContext,
    RequestId, ResourceRef, UserId, ValidationCode,
};
use enclave_db::favorites::FavoriteCandidate;
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Capabilities};
use crate::error::{ApiError, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// Starring names a file, so it is decided as a read of that file. See the module header.
const STAR: Action = Action::File(FileAction::MetadataRead);

/// Reading your own list is a read of yourself, as `GET /me/recent` and `GET /me/shared` are.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// Page sizes, matching the sibling listings so the three behave alike.
const DEFAULT_LIMIT: u32 = 50;
/// See [`DEFAULT_LIMIT`].
const MAX_LIMIT: u32 = 200;
/// See [`DEFAULT_LIMIT`].
const MIN_LIMIT: u32 = 1;

/// How far past the requested page the read looks, so a trimmed page is still full.
const OVER_FETCH: u32 = 3;

#[derive(Debug, Deserialize)]
pub struct FavoriteParams {
    limit: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Starred {
    /// Whether this request created the star, as opposed to finding it already there.
    created: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unstarred {
    /// Whether this request removed a star, as opposed to finding none.
    removed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FavoritePage {
    items: Vec<FavoriteItem>,
    /// How many candidates the chain refused. **A count, never which** — rule 7.
    filtered_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FavoriteItem {
    file_id: String,
    name: String,
    node_type: String,
    mime_type: String,
    library_id: String,
    parent_folder_id: Option<String>,
    classification: Option<ClassificationView>,
    favorited_at: DateTime<Utc>,
    capabilities: Capabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationView {
    key: String,
    label: String,
    rank: i32,
}

/// Handles `PUT /api/v1/files/{id}/favorite`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unknown file, an unusable caller, or a database failure.
pub async fn star(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let (user, file) = subject_and_file(&state, &ctx, &file).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    let created = enclave_db::favorites::add(&mut tx, user, file)
        .await
        // A foreign-key refusal here means the file is not this tenant's, which the chain has
        // already answered `404` for — so anything reaching this point is a real failure.
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), ctx.request_id))?;

    Ok((StatusCode::OK, [(header::CACHE_CONTROL, NO_STORE)], Json(Starred { created }))
        .into_response())
}

/// Handles `DELETE /api/v1/files/{id}/favorite`.
///
/// # Errors
///
/// As [`star`].
pub async fn unstar(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Response, ApiError> {
    let (user, file) = subject_and_file(&state, &ctx, &file).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    let removed = enclave_db::favorites::remove(&mut tx, user, file)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), ctx.request_id))?;

    Ok((StatusCode::OK, [(header::CACHE_CONTROL, NO_STORE)], Json(Unstarred { removed }))
        .into_response())
}

/// Handles `GET /api/v1/me/favorites`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure.
pub async fn list(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<FavoriteParams>,
) -> Result<Json<FavoritePage>, ApiError> {
    let request_id = ctx.request_id;
    let limit = limit(params.limit.as_deref(), request_id)?;

    let user = match subject(&ctx) {
        Ok(user) => user,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ_SELF, &resource, refused).await);
        }
    };

    let resource = ResourceRef::user(ctx.tenant_id, user);
    let decision = state
        .policy
        .enforce(&ctx, READ_SELF, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    // `PolicyDecision` is `#[must_use]`. This path can discharge no obligation, so one arriving
    // here is a refusal (D29, rule 8).
    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, READ_SELF, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let window = i64::from(limit.saturating_mul(OVER_FETCH).min(MAX_LIMIT * OVER_FETCH));
    let candidates = enclave_db::favorites::list(&mut tx, user, window)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // The trim. A star is the user's own note and is **not** permission: a file they favourited a
    // year ago may have been re-permissioned since, so every row goes through the chain before they
    // are told it is still there.
    let refs: Vec<ResourceRef> = candidates
        .iter()
        .map(|candidate| ResourceRef::file(ctx.tenant_id, candidate.file_id))
        .collect();
    let decisions = state
        .policy
        .authorization()
        .authorize_many(&ctx, STAR, &refs)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    if decisions.len() != refs.len() {
        // Every candidate treated as refused rather than some as undecided: an empty and honest
        // listing is the only answer available when the batch cannot be trusted to line up.
        return Ok(Json(FavoritePage { items: Vec::new(), filtered_count: candidates.len() }));
    }

    let mut items = Vec::new();
    let mut survived = 0_usize;
    for ((candidate, resource), decision) in candidates.iter().zip(&refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        let enforced =
            decision.ensure_allowed().map_err(|error| ApiError::new(error, request_id))?;
        survived += 1;
        if items.len() < limit as usize {
            items.push(
                item(&state, &ctx, candidate, resource, &enforced)
                    .await
                    .map_err(|error| ApiError::new(error, request_id))?,
            );
        }
    }

    Ok(Json(FavoritePage { items, filtered_count: candidates.len() - survived }))
}

/// The caller and the file, with the chain run against the file.
///
/// Shared by both writes because they ask the identical question and a second copy is a second
/// chance to weaken it.
async fn subject_and_file(
    state: &ApiState,
    ctx: &RequestContext,
    raw: &str,
) -> Result<(UserId, FileId), ApiError> {
    let request_id = ctx.request_id;
    let file: FileId = raw.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;

    let user = match subject(ctx) {
        Ok(user) => user,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(ctx, STAR, &resource, refused).await);
        }
    };

    let resource = ResourceRef::file(ctx.tenant_id, file);
    let decision = state
        .policy
        .enforce(ctx, STAR, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(ctx, STAR, &resource, refused).await);
    }

    Ok((user, file))
}

async fn item(
    state: &ApiState,
    ctx: &RequestContext,
    candidate: &FavoriteCandidate,
    resource: &ResourceRef,
    enforced: &Obligations,
) -> Result<FavoriteItem, Error> {
    let (capabilities, _reasons, _wire) =
        capabilities_for(state.policy.authorization().as_ref(), ctx, resource, enforced).await?;

    Ok(FavoriteItem {
        file_id: candidate.file_id.to_string(),
        name: candidate.name.clone(),
        node_type: candidate.node_type.clone(),
        mime_type: candidate.mime_type.clone(),
        library_id: candidate.library_id.to_string(),
        parent_folder_id: candidate.parent_folder_id.map(|id| id.to_string()),
        classification: candidate.classification.as_ref().map(|label| ClassificationView {
            key: label.key.clone(),
            label: label.label.clone(),
            rank: label.rank.get(),
        }),
        favorited_at: candidate.favorited_at,
        capabilities,
    })
}

/// The caller as a user, or a refusal.
///
/// `favorites.user_id` carries a composite foreign key onto `users`, so a service account or an MCP
/// client has no row to key against — and *"the system starred this"* is not a preference anybody
/// holds. Refused before the write rather than letting the key report it as an internal error.
fn subject(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        enclave_core::Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

/// Reads `?limit=`, clamping to the range, as the two sibling listings do.
fn limit(raw: Option<&str>, request_id: RequestId) -> Result<u32, ApiError> {
    match raw {
        None => Ok(DEFAULT_LIMIT),
        Some(text) => {
            text.trim().parse::<u32>().map(|asked| asked.clamp(MIN_LIMIT, MAX_LIMIT)).map_err(
                |_error| {
                    ApiError::new(
                        Error::Validation(vec![FieldError::new(
                            "limit",
                            ValidationCode::InvalidFormat,
                        )]),
                        request_id,
                    )
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// Starring is decided as a **read** of the file, never as an edit.
    ///
    /// Asserted because the alternative is superficially reasonable and would break the feature:
    /// `file.edit` would stop a reader bookmarking something they are allowed to read, which is
    /// most of what favorites are for. And it must not be weaker than `metadata_read` either — a
    /// caller who may not see a file must not learn it exists by starring it.
    #[test]
    fn starring_is_a_read_of_the_file_and_not_an_edit() {
        assert_eq!(STAR, Action::File(FileAction::MetadataRead));
        assert_ne!(STAR, Action::File(FileAction::Edit));
    }

    /// The page size behaves as the two sibling listings do.
    #[test]
    fn the_page_size_behaves_as_the_sibling_listings_do() {
        let id = RequestId::new_v7();
        assert_eq!(limit(None, id).expect("the default"), DEFAULT_LIMIT);
        assert_eq!(limit(Some("0"), id).expect("clamped up"), MIN_LIMIT);
        assert_eq!(limit(Some("9999"), id).expect("clamped down"), MAX_LIMIT);
        assert!(limit(Some("many"), id).is_err(), "a non-number is refused, never defaulted");
    }
}
