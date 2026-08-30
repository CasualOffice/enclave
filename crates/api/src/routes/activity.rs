//! `GET /api/v1/me/activity` — what changed, among the things this person can see (`ENC-960`).
//!
//! # The first reader `audit_events` has ever had
//!
//! The hash-chained audit log has been written since Phase 0 and nothing has ever selected from it.
//! `enclave_db::activity` is the query; this is the surface, and it is deliberately the narrowest
//! one. An administrative audit reader — `/admin/audit`, `AdminAction::ReadAudit`, both specified
//! in `docs/05 §14` and neither built — is a different surface answering a different question
//! (`ENC-961`).
//!
//! # Three exclusions, and the second is the one worth arguing
//!
//! **Denials are excluded.** A `DENY` row says somebody tried and was refused, which discloses that
//! they tried *and* that the resource exists — the second is exactly what rule 7 spends a `404` to
//! protect. Refusals are an administrator's to read.
//!
//! **Reads are excluded.** `metadata_read`, `preview` and `download` are the bulk of any real audit
//! log, and a feed carrying them would be a record of who looked at what, readable by everybody who
//! can open the file. That is a surveillance tool. The data being in the table is not an argument
//! for surfacing it, and an activity feed answers *what happened to this* — reading is not something
//! happening to it.
//!
//! **The actor's circumstances are excluded.** `ip`, `country`, `user_agent`, `session_id`,
//! `device_id` and `detail` exist so a security investigation can reconstruct a session. Putting a
//! colleague's IP address on a screen anybody with read access can open is a disclosure with no
//! upside.
//!
//! # Every row is still trimmed
//!
//! The read is not scoped to the caller — *what has been happening to the things I can see* is a
//! different question from *what have I done*, and the first is what an activity feed is for. The
//! scoping is the chain's: `authorize_many` on `file.metadata_read` decides every candidate before
//! the caller learns it exists, and `filteredCount` says how many were withheld and never which.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, ContainerAction, Error, FieldError, FileAction, RequestContext, RequestId, ResourceRef,
    UserId, ValidationCode,
};
use enclave_db::activity::ActivityCandidate;
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// Reading your own feed is a read of yourself, as the three sibling listings are.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// What each row is trimmed against.
///
/// `metadata_read` and not the action the row *records*: the question is whether this caller may
/// know the file exists now, not whether they could have performed the thing that happened to it.
/// Deciding on the recorded action would hide an edit from everybody who cannot edit — which is
/// most of the people an activity feed is for.
const TRIM: Action = Action::File(FileAction::MetadataRead);

/// Page sizes, matching the sibling listings.
const DEFAULT_LIMIT: u32 = 30;
/// See [`DEFAULT_LIMIT`].
const MAX_LIMIT: u32 = 100;
/// See [`DEFAULT_LIMIT`].
const MIN_LIMIT: u32 = 1;

/// How far past the requested page the read looks.
///
/// Larger than the sibling listings' three, and the reason is the shape of this data: a tenant's
/// audit log is dominated by activity on content most callers cannot see, so the proportion trimmed
/// here is far higher than on a list of things somebody was given or starred. Still bounded, and
/// `hasMore` is not offered — a feed that pages into an audit log is `ENC-961`'s surface, not this
/// one.
const OVER_FETCH: u32 = 8;

#[derive(Debug, Deserialize)]
pub struct ActivityParams {
    limit: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityPage {
    items: Vec<ActivityItem>,
    /// How many candidates the chain refused. **A count, never which** — rule 7.
    filtered_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityItem {
    file_id: String,
    name: String,
    node_type: String,
    library_id: String,
    /// The `family.verb` spelling, which the client maps to a sentence.
    action: String,
    /// Who did it, as an opaque id, or `null` for a principal with no user row.
    actor_id: Option<String>,
    /// Their display name, or `null` when the actor has no `users` row (`ENC-958`).
    ///
    /// A person's name is data rather than a message (`docs/14 §6`), and `null` is not *"Unknown"*.
    /// The client renders *"somebody"*, which is true of a service account and of `system` alike.
    actor_name: Option<String>,
    occurred_at: DateTime<Utc>,
}

/// Handles `GET /api/v1/me/activity`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure.
pub async fn activity(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<ActivityParams>,
) -> Result<Json<ActivityPage>, ApiError> {
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
    let candidates = enclave_db::activity::recent_changes(&mut tx, window)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if candidates.is_empty() {
        return Ok(Json(ActivityPage { items: Vec::new(), filtered_count: 0 }));
    }

    // One decision per *file*, not per event. A busy document produces many rows and they are all
    // the same question — batching the raw candidates would ask the chain about one file nine times
    // and put nine identical answers on the wire.
    let mut order: Vec<enclave_core::FileId> = Vec::new();
    for candidate in &candidates {
        if !order.contains(&candidate.file_id) {
            order.push(candidate.file_id);
        }
    }
    let refs: Vec<ResourceRef> =
        order.iter().map(|id| ResourceRef::file(ctx.tenant_id, *id)).collect();
    let decisions = state
        .policy
        .authorization()
        .authorize_many(&ctx, TRIM, &refs)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    if decisions.len() != refs.len() {
        // Every candidate treated as refused: an empty and honest feed is the only answer available
        // when the batch cannot be trusted to line up with what it decided about.
        return Ok(Json(ActivityPage { items: Vec::new(), filtered_count: candidates.len() }));
    }

    let visible: std::collections::HashSet<enclave_core::FileId> = order
        .iter()
        .zip(decisions)
        .filter_map(|(id, decision)| decision.is_allowed().then_some(*id))
        .collect();

    let mut items = Vec::new();
    let mut survived = 0_usize;
    for candidate in &candidates {
        if !visible.contains(&candidate.file_id) {
            continue;
        }
        survived += 1;
        if items.len() < limit as usize {
            items.push(item(candidate));
        }
    }

    Ok(Json(ActivityPage { items, filtered_count: candidates.len() - survived }))
}

fn item(candidate: &ActivityCandidate) -> ActivityItem {
    ActivityItem {
        file_id: candidate.file_id.to_string(),
        name: candidate.name.clone(),
        node_type: candidate.node_type.clone(),
        library_id: candidate.library_id.to_string(),
        action: candidate.action.clone(),
        actor_id: candidate.actor_id.map(|id| id.to_string()),
        actor_name: candidate.actor_display_name.clone(),
        occurred_at: candidate.occurred_at,
    }
}

/// The caller as a user, or a refusal.
fn subject(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        enclave_core::Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

/// Reads `?limit=`, clamping to the range, as the sibling listings do.
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

    /// The feed shows changes and never reads.
    ///
    /// **The assertion this surface most needs.** `enclave_db::activity::SHOWN_ACTIONS` is a list,
    /// and a list is one careless addition away from turning an activity feed into a record of who
    /// looked at what — readable by everybody who can open the file. That is a different product
    /// from the one this is, and it would arrive as a one-line diff that looked like completeness.
    ///
    /// Asserted as an exclusion of *read verbs* rather than an equality with today's list, so
    /// adding `file.move` is free and adding `file.download` is not.
    #[test]
    fn the_feed_shows_changes_and_never_reads() {
        for read in [
            "file.metadata_read",
            "file.preview",
            "file.download",
            "file.content_read",
            "file.print",
            "file.export",
            "file.version_read",
            "file.sync",
        ] {
            assert!(
                !enclave_db::activity::SHOWN_ACTIONS.contains(&read),
                "`{read}` is a read. A feed carrying it is a record of who looked at what, \
                 available to everybody who can open the file — a surveillance tool, and a \
                 different product from an activity feed"
            );
        }
        assert!(
            enclave_db::activity::SHOWN_ACTIONS.contains(&"file.edit"),
            "the control: the list must actually carry the changes it exists to show, or the \
             exclusions above are satisfied by an empty list"
        );
    }

    /// Rows are decided on `metadata_read`, not on the action they record.
    ///
    /// Deciding on the recorded action is the plausible mistake: it reads as "you may see the edit
    /// if you may edit", and it would hide every change from everybody who holds read access alone
    /// — which is most of the people a feed is for.
    #[test]
    fn a_row_is_decided_on_seeing_the_file_not_on_performing_the_action() {
        assert_eq!(TRIM, Action::File(FileAction::MetadataRead));
    }
}
