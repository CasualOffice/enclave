//! `GET /api/v1/me/shared` — what other people have given this person (`ENC-954`).
//!
//! # The hole
//!
//! `acl_entries` has had a production writer since `ENC-916`, and `grant()` since the ACL work. A
//! colleague can share a document with somebody outside any workspace that person belongs to, the
//! chain honours it on every request — and **there has never been a way to find it.** The grant
//! works and the recipient cannot discover it. *Shared with me* has carried an unbuilt chip in the
//! navigation because there was no query behind it; `enclave_db::shared` is that query.
//!
//! # The listing is a candidate generator and decides nothing
//!
//! Every row goes through `authorize_many` before the caller is told it exists — the same rule
//! `docs/07 §6` states for the vector index, and for the same reason: **an ACL row is not
//! permission.** Inheritance, information barriers, classification ceilings and DLP all sit above
//! it, so a row the read returns and the chain refuses is ordinary, and it must vanish without
//! trace. A count of what was withheld is reported; *which* rows never is (rule 7).
//!
//! # Why this authorizes on `metadata_read` and not on `share`
//!
//! The question is *"may this person see that this file exists"*, which is a metadata read. `share`
//! is the permission to *give* access, which is a different act by a different person — the sharer
//! — and requiring it here would hide a file from the very user it was shared with unless they
//! could also re-share it.
//!
//! # Groups, and why the closure is not resolved here
//!
//! A share reaches a person directly or through a team, and both must appear. The transitive
//! closure comes from `enclave_authorization::repo::group_closure`, which is the same expansion the
//! chain itself uses, bounded by the same configured depth. Re-deriving it here would be a second
//! definition of membership, free to disagree with the one that decides.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_core::FieldError;
use enclave_core::{
    Action, ContainerAction, Error, FileAction, Obligations, PolicyDecision, RequestContext,
    RequestId, ResourceRef, UserId, ValidationCode,
};
use enclave_db::shared::SharedCandidate;
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Capabilities};
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// Reading your own share list is a read of yourself, as `GET /me/recent` is.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// What each row is trimmed against. See the module header for why not `share`.
const METADATA_READ: Action = Action::File(FileAction::MetadataRead);

/// Default and maximum page sizes, matching `GET /me/recent` so the two listings behave alike.
const DEFAULT_LIMIT: u32 = 20;
/// See [`DEFAULT_LIMIT`].
const MAX_LIMIT: u32 = 100;
/// See [`DEFAULT_LIMIT`].
const MIN_LIMIT: u32 = 1;

/// How far past the requested page the read looks, so a trimmed page is still full.
///
/// The chain refuses some candidates, and a read that fetched exactly `limit` would return fewer
/// rows than asked for whenever it did — a page that looks short for a reason the user cannot see.
/// Three times, capped, for `crate::routes::recent`'s reason: a caller rendering twenty rows should
/// not pay for a hundred, and a tenant where two thirds of shares are refused is one where the
/// listing is the least of the problems.
const OVER_FETCH: u32 = 3;

#[derive(Debug, Deserialize)]
pub struct SharedParams {
    limit: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedPage {
    items: Vec<SharedItem>,
    /// How many candidates the chain refused. **A count, never which** — rule 7.
    filtered_count: usize,
    /// Whether the underlying read hit its limit, so the caller knows the set was cut.
    has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedItem {
    file_id: String,
    name: String,
    /// `FILE` or `FOLDER`. A shared folder is common and the client renders it differently.
    node_type: String,
    mime_type: String,
    library_id: String,
    parent_folder_id: Option<String>,
    classification: Option<ClassificationView>,
    shared_at: DateTime<Utc>,
    /// Who shared it, as an opaque id the client resolves against its own directory cache.
    shared_by: String,
    /// The group it came through, or `null` for a direct share.
    via_group: Option<String>,
    capabilities: Capabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationView {
    key: String,
    label: String,
    rank: i32,
}

/// Handles `GET /api/v1/me/shared`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure.
pub async fn shared(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<SharedParams>,
) -> Result<Json<SharedPage>, ApiError> {
    let request_id = ctx.request_id;
    let limit = limit(params.limit.as_deref(), request_id)?;

    // A principal with no `users` row has no shares and could not be named by one: `acl_entries`
    // stores a `USER` principal by id. Refused before the chain runs, as `routes::recent` does.
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

    // `PolicyDecision` is `#[must_use]`. This path can discharge no obligation — there is no
    // rendition to watermark, no bytes to withhold and nowhere to collect a justification — so an
    // obligation arriving here is a refusal (D29, rule 8).
    let obligations = consume(decision);
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, READ_SELF, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // The same expansion the chain uses, at the same configured depth (`ResolverLimits::DEFAULT`).
    // Called directly rather than through `AuthorizationService`: the trait's job is to *decide*,
    // and adding a membership-listing method to it would put a read with no verdict behind the
    // interface every policy stage is written against.
    let principal = enclave_authorization::resolve::Principal::new(
        enclave_authorization::resolve::PrincipalKind::User,
        user.as_uuid(),
    );
    let groups = enclave_authorization::repo::group_closure(
        &mut tx,
        ctx.tenant_id,
        principal,
        enclave_authorization::service::ResolverLimits::DEFAULT.max_group_depth,
    )
    .await
    .map_err(|error| ApiError::new(Error::from(error), request_id))?;
    let groups: Vec<enclave_core::GroupId> = groups.into_iter().collect();

    let window = i64::from(limit.saturating_mul(OVER_FETCH).min(MAX_LIMIT * OVER_FETCH));
    let candidates = enclave_db::shared::shared_with(&mut tx, user, &groups, Utc::now(), window)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let (admitted, filtered) = admit(&state, &ctx, &candidates.rows, limit)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    let mut items = Vec::with_capacity(admitted.len());
    for (candidate, resource, enforced) in admitted {
        items.push(
            item(&state, &ctx, candidate, &resource, &enforced)
                .await
                .map_err(|error| ApiError::new(error, request_id))?,
        );
    }

    Ok(Json(SharedPage { items, filtered_count: filtered, has_more: candidates.truncated }))
}

/// One admitted candidate: the row, the reference decided about, and the obligations carried.
type Admitted<'a> = (&'a SharedCandidate, ResourceRef, Obligations);

/// Trims the candidates to what this caller may see.
///
/// Index alignment is checked by length before `zip`, for `routes::recent`'s reason: a short answer
/// leaves the tail undecided and `zip` drops it silently. Here that direction is the safe one —
/// dropping counts a row as filtered and shows fewer — and it is still checked, because a listing
/// that quietly under-reports what it withheld is a listing nobody can reason about.
async fn admit<'a>(
    state: &ApiState,
    ctx: &RequestContext,
    candidates: &'a [SharedCandidate],
    limit: u32,
) -> Result<(Vec<Admitted<'a>>, usize), Error> {
    if candidates.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let refs: Vec<ResourceRef> = candidates
        .iter()
        .map(|candidate| ResourceRef::file(ctx.tenant_id, candidate.file_id))
        .collect();
    let decisions = state.policy.authorization().authorize_many(ctx, METADATA_READ, &refs).await?;

    if decisions.len() != refs.len() {
        // Every candidate is treated as refused rather than some as undecided. The listing is then
        // empty and honest, which is the only answer available when the batch cannot be trusted to
        // line up with what it decided about.
        return Ok((Vec::new(), candidates.len()));
    }

    let mut survivors: Vec<Admitted<'a>> = Vec::new();
    let mut survived = 0_usize;
    for ((candidate, resource), decision) in candidates.iter().zip(refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        // The stage allowed, so this cannot be an `Err`. Taking the obligations rather than
        // dropping the decision keeps a `READ_ONLY` attached to this row's metadata read from
        // evaporating between the trim and the capabilities built from it.
        let enforced = decision.ensure_allowed()?;
        survived += 1;
        if survivors.len() < limit as usize {
            survivors.push((candidate, resource, enforced));
        }
    }

    Ok((survivors, candidates.len() - survived))
}

/// Renders one surviving row, capabilities included.
async fn item(
    state: &ApiState,
    ctx: &RequestContext,
    candidate: &SharedCandidate,
    resource: &ResourceRef,
    enforced: &Obligations,
) -> Result<SharedItem, Error> {
    let (capabilities, _reasons, _wire) =
        capabilities_for(state.policy.authorization().as_ref(), ctx, resource, enforced).await?;

    Ok(SharedItem {
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
        shared_at: candidate.shared_at,
        shared_by: candidate.shared_by.to_string(),
        via_group: candidate.via_group.map(|id| id.to_string()),
        capabilities,
    })
}

/// The caller as a user, or a refusal.
fn subject(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        enclave_core::Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

/// Consumes the decision, which is what proves nothing was dropped.
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

/// Reads `?limit=`, clamping to the range and refusing what is not a number.
///
/// **Clamping rather than refusing, and it is copied from `routes::recent` deliberately.** Refusing
/// is arguably better — a caller that asked for 500 and silently received 100 has no way to know
/// the page was not the whole answer — but two paginated listings in one API that disagree about
/// what `?limit=500` means is worse than either choice made consistently. If clamping is wrong it
/// is wrong in both, and should change in both.
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

    /// `?limit=` behaves exactly as `GET /me/recent`'s does.
    ///
    /// Asserted rather than assumed, because the two are separate functions in separate modules and
    /// the cost of them drifting is paid by a client that pages one listing correctly and the other
    /// wrongly. The zero case is the one to watch: it clamps *up* to the minimum, so a caller asking
    /// for nothing gets one row rather than an empty page they might read as "no shares".
    #[test]
    fn the_page_size_behaves_as_the_sibling_listing_does() {
        let id = RequestId::new_v7();
        assert_eq!(limit(None, id).expect("the default"), DEFAULT_LIMIT);
        assert_eq!(limit(Some("1"), id).expect("the minimum"), MIN_LIMIT);
        assert_eq!(limit(Some("100"), id).expect("the maximum"), MAX_LIMIT);
        assert_eq!(limit(Some("0"), id).expect("clamped up"), MIN_LIMIT, "zero clamps to one");
        assert_eq!(limit(Some("500"), id).expect("clamped down"), MAX_LIMIT);
        assert_eq!(limit(Some(" 20 "), id).expect("trimmed"), 20, "whitespace is trimmed");
        assert!(limit(Some("many"), id).is_err(), "a non-number is refused, never defaulted");
        assert!(limit(Some("-1"), id).is_err(), "a negative page size is not a u32");
    }
}
