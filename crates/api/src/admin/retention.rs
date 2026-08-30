//! The retention administration surface (`docs/05-API.md §14`, `ENC-943`).
//!
//! `ENC-940` gave the chain a retention stage that decides whether a delete proceeds, and gave the
//! schema the two tables it reads. It gave a tenant administrator **no way to write one**: the only
//! path to a `retention_policies` row was `psql`, so a control the product enforces on every delete
//! could be configured by nobody using the product. This is that path.
//!
//! # Why this surface refuses more than it validates
//!
//! `migrations/0031` carries six named `CHECK` constraints — a `LEGAL_HOLD` may not permit user
//! deletion, a `DELETE_AFTER` must have a duration, a duration must be positive, an `EVENT` basis
//! must name its event and nothing else may, a `RECORD` must be flagged as one. **None of them is
//! restated here.** Two copies of a rule are two chances to relax it one at a time, and the copy
//! that drifts is the one nobody is reading. The handler writes, the database refuses, and the
//! refusal is translated — so the constraint that decides is the constraint an operator can read in
//! `psql`.
//!
//! What this module does own is the part the schema cannot express: which *shape* of request is
//! answerable at all, and what a refusal is allowed to tell the caller.
//!
//! # An assignment has no identifier, and that is a deliberate consequence
//!
//! `retention_assignments` is keyed by `(tenant_id, policy_id, scope_type, COALESCE(scope_id, …))`.
//! There is no `id` column to name, so withdrawal addresses the scope — which is also the form an
//! administrator can read straight off the listing in front of them, rather than an opaque handle
//! they must first look up.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use enclave_core::{Action, Actor, AdminAction, RequestContext, ResourceRef, UserId};
use enclave_db::retention::{
    AssignmentRow, NewPolicy, PgInterval, PolicyRow, RetentionAction, RetentionBasis,
    RetentionPolicyId, RetentionScopeType,
};
use enclave_db::DbError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action writing this surface is authorized as.
///
/// `AdminAction::ManagePolicy`'s doc comment has named retention since the vocabulary was written.
const WRITE_ACTION: Action = Action::Admin(AdminAction::ManagePolicy);

/// The action reading this surface is authorized as.
const READ_ACTION: Action = Action::Admin(AdminAction::ReadConfig);

/// The longest constraint detail that reaches a caller.
const MAX_DETAIL_CHARS: usize = 240;

/// The upper bound on a retention period, in days.
///
/// A hundred years. Not a compliance limit — no regulator asks for more — but a typo guard: an
/// administrator who means `P7Y` and writes `P7000Y` produces a policy indistinguishable from a
/// legal hold, and the difference only becomes visible on the day something should have been
/// destroyed and was not.
const MAX_DURATION_DAYS: i64 = 36_525;

// --- Wire types ---------------------------------------------------------------------------------

/// A policy as an administrator writes one.
///
/// `deny_unknown_fields` for the reason every admin body here carries it: a field silently dropped
/// is a control that governs differently from the way its author wrote it, and a retention control
/// that quietly ignored `allowUserDelete` would read as a hold and permit the delete.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyRequest {
    name: String,
    action: String,
    /// Whole days. An `INTERVAL` is what the column stores and what the arithmetic needs, but a
    /// JSON caller has no interval type, and accepting a count of *seconds* would invite the error
    /// `migrations/0031`'s column comment is about: `EXTRACT(EPOCH …)` assumes a 365.25-day year, so
    /// a seven-year retention expressed in seconds lands on a different day than `INTERVAL '7
    /// years'` does. Days are unambiguous, and the conversion below keeps them days.
    #[serde(default)]
    duration_days: Option<i64>,
    basis: String,
    #[serde(default)]
    event_key: Option<String>,
    #[serde(default)]
    is_record: bool,
    #[serde(default)]
    allow_user_delete: bool,
}

/// A scope as an administrator names one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AssignmentRequest {
    scope_type: String,
    #[serde(default)]
    scope_id: Option<Uuid>,
}

/// The scope named in a withdrawal's query string.
///
/// `pub` because it is an extractor on a `pub` handler, not because anything outside reads it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WithdrawQuery {
    scope_type: String,
    #[serde(default)]
    scope_id: Option<Uuid>,
}

/// A policy as this surface returns one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    id: Uuid,
    name: String,
    action: &'static str,
    duration_days: Option<i64>,
    basis: &'static str,
    event_key: Option<String>,
    is_record: bool,
    allow_user_delete: bool,
    created_at: String,
}

/// An assignment as this surface returns one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentView {
    policy_id: Uuid,
    scope_type: &'static str,
    scope_id: Option<Uuid>,
    applied_at: String,
    expires_at: Option<String>,
    /// Whether this assignment is in force now.
    ///
    /// Computed here rather than left to the client to derive from `expiresAt`: *"is this control
    /// on"* is the question the screen exists to answer, and three clients each comparing a
    /// timestamp against their own clock is three chances to answer it differently from the
    /// governing read, which compares against the database's.
    live: bool,
}

/// The listing both halves of the surface arrive at.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionView {
    policies: Vec<PolicyView>,
    assignments: Vec<AssignmentView>,
    /// The vocabularies, so the screen builds its pickers from the schema rather than from a copy.
    ///
    /// `ENC-937` is the argument: a client that hard-codes an enumeration drifts from the migration
    /// silently, and the drift shows up as an option that produces a 400 nobody can explain.
    vocabulary: Vocabulary,
}

/// The stored vocabularies, served rather than duplicated client-side.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vocabulary {
    actions: Vec<&'static str>,
    bases: Vec<&'static str>,
    scope_types: Vec<&'static str>,
}

// --- Handlers -----------------------------------------------------------------------------------

/// Handles `GET /api/v1/admin/retention/policies`.
///
/// Returns policies, assignments and the vocabularies in one response. One round trip rather than
/// three because they are one screen and are read together every time; splitting them would let a
/// client render a policy list against an assignment list fetched a second later, and show a
/// control as unapplied in the window between.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or a database failure.
pub async fn list(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, READ_ACTION).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let policies = enclave_db::retention::list_policies(&mut tx)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let assignments = enclave_db::retention::list_assignments(&mut tx)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let now = chrono::Utc::now();
    // `no-store`: a shared cache holding this would serve one tenant's retention posture out of a
    // proxy another caller's browser talked to.
    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(RetentionView {
            policies: policies.iter().map(policy_view).collect(),
            assignments: assignments.iter().map(|row| assignment_view(row, now)).collect(),
            vocabulary: Vocabulary {
                actions: RetentionAction::all().iter().map(|a| a.as_str()).collect(),
                bases: RetentionBasis::all().iter().map(|b| b.as_str()).collect(),
                scope_types: RetentionScopeType::all().iter().map(|s| s.as_str()).collect(),
            },
        }),
    )
        .into_response())
}

/// Handles `POST /api/v1/admin/retention/policies`.
///
/// # Ordering
///
/// The chain runs before the body is looked at, so a caller it refuses learns nothing about the
/// request schema or the tenant's vocabulary — not even that their JSON was malformed.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure. Rejected bodies are
/// rendered as `docs/05-API.md §5` envelopes in the `Ok` arm, because their statuses are ones
/// `Error` cannot express.
pub async fn create_policy(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) = super::require_step_up(&ctx, state.step_up, "retention.policy.write") {
        return Ok(envelope.into_response(request_id));
    }
    // The attribution check runs even though `retention_policies` records no author: it is what
    // keeps a service account or an MCP client from writing a control nobody can be asked about.
    // `ENC-943` deliberately did not add a `created_by` column in a migration of its own — that is
    // an expand-then-contract change to a table one release old, and the refusal below is the half
    // that matters today.
    if let Err(refused) = author(&ctx) {
        let resource = ResourceRef::tenant(ctx.tenant_id);
        return Err(state.audit.refuse(&ctx, WRITE_ACTION, &resource, refused).await);
    }

    let request: PolicyRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };

    let policy = match policy_from(&request) {
        Ok(policy) => policy,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    if let Err(error) = enclave_db::retention::insert_policy(&mut tx, &policy).await {
        return write_failure(error, request_id);
    }
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        policy_id = %policy.id,
        action = policy.action.as_str(),
        allow_user_delete = policy.allow_user_delete,
        "a retention policy was written"
    );

    let view = PolicyView {
        id: policy.id.as_uuid(),
        name: policy.name.clone(),
        action: policy.action.as_str(),
        duration_days: request.duration_days,
        basis: policy.basis.as_str(),
        event_key: policy.event_key.clone(),
        is_record: policy.is_record,
        allow_user_delete: policy.allow_user_delete,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let location = format!("/api/v1/admin/retention/policies/{}", policy.id);
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        [(header::LOCATION, location)],
        Json(view),
    )
        .into_response())
}

/// Handles `POST /api/v1/admin/retention/policies/{id}/assignments` — applying a policy.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure.
pub async fn assign(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(policy_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) = super::require_step_up(&ctx, state.step_up, "retention.assignment.write")
    {
        return Ok(envelope.into_response(request_id));
    }
    if let Err(refused) = author(&ctx) {
        let resource = ResourceRef::tenant(ctx.tenant_id);
        return Err(state.audit.refuse(&ctx, WRITE_ACTION, &resource, refused).await);
    }

    let request: AssignmentRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let (scope_type, scope_id) = match scope_from(&request.scope_type, request.scope_id) {
        Ok(scope) => scope,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let policy = RetentionPolicyId::from_uuid(policy_id);
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let applied =
        match enclave_db::retention::assign_policy(&mut tx, policy, scope_type, scope_id).await {
            Ok(applied) => applied,
            Err(error) => return write_failure(error, request_id),
        };
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if !applied {
        return Ok(Envelope::new(
            StatusCode::CONFLICT,
            "ASSIGNMENT_EXISTS",
            "That policy already applies to that scope.",
            "Withdraw the existing assignment first, or choose another scope.",
        )
        .into_response(request_id));
    }

    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        %policy_id,
        scope_type = scope_type.as_str(),
        "a retention policy was applied to a scope"
    );
    Ok((StatusCode::CREATED, [(header::CACHE_CONTROL, NO_STORE)]).into_response())
}

/// Handles `DELETE /api/v1/admin/retention/policies/{id}/assignments` — withdrawal.
///
/// # `DELETE` at the edge is an `UPDATE` underneath
///
/// `migrations/0031` grants `enclave_app` no `DELETE` on either table. A statement that removes the
/// evidence a retention control ever applied is precisely the statement these tables exist to make
/// impossible, so withdrawal stamps `expires_at` and leaves the row.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure.
pub async fn withdraw(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(policy_id): Path<Uuid>,
    Query(query): Query<WithdrawQuery>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) =
        super::require_step_up(&ctx, state.step_up, "retention.assignment.withdraw")
    {
        return Ok(envelope.into_response(request_id));
    }
    if let Err(refused) = author(&ctx) {
        let resource = ResourceRef::tenant(ctx.tenant_id);
        return Err(state.audit.refuse(&ctx, WRITE_ACTION, &resource, refused).await);
    }

    let (scope_type, scope_id) = match scope_from(&query.scope_type, query.scope_id) {
        Ok(scope) => scope,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let policy = RetentionPolicyId::from_uuid(policy_id);
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let withdrawn =
        enclave_db::retention::withdraw_assignment(&mut tx, policy, scope_type, scope_id)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if !withdrawn {
        // `404` and not `409`, and the two cases behind it — already withdrawn, never existed — are
        // one answer on purpose. See `withdraw_assignment`'s note: the caller administers this
        // tenant, so the distinction leaks nothing, and two messages that must keep agreeing about
        // a difference nobody can act on is how they stop agreeing.
        return Ok(Envelope::new(
            StatusCode::NOT_FOUND,
            "ASSIGNMENT_NOT_FOUND",
            "No live assignment of that policy to that scope.",
            "Refresh the list — it may already have been withdrawn.",
        )
        .into_response(request_id));
    }

    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        %policy_id,
        scope_type = scope_type.as_str(),
        "a retention assignment was withdrawn"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// --- Translation ----------------------------------------------------------------------------------

/// Runs the chain against the tenant, as every handler in this module's siblings does.
///
/// The resource is the tenant and not the policy being edited, for the reason `admin/mod.rs` gives:
/// a decision that varied with the object would be an oracle for the object's existence.
async fn enforce(state: &ApiState, ctx: &RequestContext, action: Action) -> Result<(), ApiError> {
    let decision = state
        .policy
        .enforce(ctx, action, &ResourceRef::tenant(ctx.tenant_id))
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it here is what proves nothing was dropped. This
    // surface can discharge no obligation — there is no rendition to watermark and nowhere to
    // collect a justification — so an obligation arriving here is a refusal (D29, rule 8).
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state
            .audit
            .refuse(ctx, action, &ResourceRef::tenant(ctx.tenant_id), refused)
            .await);
    }
    Ok(())
}

/// The caller, refused unless they are a user.
///
/// A retention policy is a commitment a tenant makes about what it will preserve, and *"the
/// system"* is not an answer to *"who decided these contracts could not be deleted for seven
/// years"*.
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

/// Reads a policy request into the row the writer takes.
///
/// Only the vocabulary and the duration's *representability* are checked here. Everything that is a
/// rule about a valid policy — which actions require a duration, which forbid `allowUserDelete` —
/// belongs to the migration's constraints, and the module header says why it is not repeated.
fn policy_from(request: &PolicyRequest) -> Result<NewPolicy, Envelope> {
    if request.name.trim().is_empty() {
        return Err(bad_field("name", "A policy needs a name an administrator will recognise."));
    }
    let action = decode(RetentionAction::all(), &request.action, "action")?;
    let basis = decode(RetentionBasis::all(), &request.basis, "basis")?;

    let duration =
        match request.duration_days {
            None => None,
            Some(days) if days <= 0 => return Err(bad_field(
                "durationDays",
                "A retention period must be at least one day. Zero or less computes a deadline \
                 that has already passed, which is a delete-immediately rule wearing a compliance \
                 control's name.",
            )),
            Some(days) if days > MAX_DURATION_DAYS => return Err(bad_field(
                "durationDays",
                "A retention period longer than a century is almost always a typo, and one that \
                 is indistinguishable from a legal hold until the day something should have been \
                 destroyed and was not.",
            )),
            // Days, kept as days. Not converted to microseconds: `timestamptz + INTERVAL '365 days'` is
            // calendar arithmetic that crosses daylight saving correctly, and a microsecond count is
            // not.
            Some(days) => Some(PgInterval {
                months: 0,
                days: i32::try_from(days).unwrap_or(i32::MAX),
                microseconds: 0,
            }),
        };

    Ok(NewPolicy {
        id: RetentionPolicyId::new_v7(),
        name: request.name.trim().to_owned(),
        action,
        duration,
        basis,
        event_key: request.event_key.clone(),
        is_record: request.is_record,
        allow_user_delete: request.allow_user_delete,
    })
}

/// Reads a scope, refusing the two shapes the table's `CHECK` would refuse less legibly.
fn scope_from(
    scope_type: &str,
    scope_id: Option<Uuid>,
) -> Result<(RetentionScopeType, Option<Uuid>), Envelope> {
    let scope = decode(RetentionScopeType::all(), scope_type, "scopeType")?;
    match (scope, scope_id) {
        (RetentionScopeType::Tenant, Some(_)) => Err(bad_field(
            "scopeId",
            "A TENANT-scoped assignment covers everything and names nothing.",
        )),
        (RetentionScopeType::Tenant, None) => Ok((scope, None)),
        (_, None) => {
            Err(bad_field("scopeId", "Every scope but TENANT names the thing it applies to."))
        }
        (_, Some(id)) => Ok((scope, Some(id))),
    }
}

/// Matches a wire value against a stored vocabulary, naming the alternatives on failure.
///
/// The alternatives come from `all()` rather than from a literal in the message, so a variant added
/// to the schema appears in the error without anybody remembering to add it.
fn decode<T: Copy + VocabularyItem>(
    vocabulary: &'static [T],
    raw: &str,
    field: &'static str,
) -> Result<T, Envelope> {
    vocabulary.iter().copied().find(|item| item.stored() == raw).ok_or_else(|| {
        let known = vocabulary.iter().map(|item| item.stored()).collect::<Vec<_>>().join(", ");
        bad_detail(field, format!("not one of: {known}"))
    })
}

/// The one thing [`decode`] needs of a vocabulary.
///
/// Named `stored` rather than `as_str` so it does not shadow the inherent `as_str` that
/// `stored_enum!` generates on each of these types: two methods with one name on one type is a call
/// site whose meaning depends on which trait happens to be in scope.
pub trait VocabularyItem {
    /// The stored spelling, identical to the migration's `CHECK` vocabulary.
    fn stored(&self) -> &'static str;
}

impl VocabularyItem for RetentionAction {
    fn stored(&self) -> &'static str {
        self.as_str()
    }
}

impl VocabularyItem for RetentionBasis {
    fn stored(&self) -> &'static str {
        self.as_str()
    }
}

impl VocabularyItem for RetentionScopeType {
    fn stored(&self) -> &'static str {
        self.as_str()
    }
}

/// Turns a constraint violation into the sentence the constraint was named for.
///
/// The mapping is by constraint name and not by parsing the driver's message, because the names are
/// stable and the message is not. A constraint this does not recognise falls through to a `500`,
/// which is the honest answer: a rule the schema enforces and the API cannot explain is a gap in
/// this function, not something to paper over with a generic `400`.
fn write_failure(
    error: DbError,
    request_id: enclave_core::RequestId,
) -> Result<Response, ApiError> {
    let DbError::Query(sqlx::Error::Database(ref db_error)) = error else {
        return Err(ApiError::new(error.into(), request_id));
    };
    let sentence = match db_error.constraint() {
        Some("retention_policies_duration_required") => {
            "KEEP_THEN_DELETE and DELETE_AFTER are a duration; without one there is no deadline to \
             compute and the policy would govern nothing."
        }
        Some("retention_policies_duration_positive") => {
            "A retention period must be longer than nothing."
        }
        Some("retention_policies_event_basis") => {
            "An EVENT basis names the event it waits for, and no other basis may carry one."
        }
        Some("retention_policies_record_flag") => {
            "A RECORD policy declares records. Set isRecord, or choose another action."
        }
        Some("retention_policies_hold_is_absolute") => {
            "A LEGAL_HOLD or RECORD policy may not permit user deletion. A hold a user can delete \
             under is not a hold, and it would read as a control in every administrative listing."
        }
        Some("retention_assignments_scope_target") => {
            "A TENANT-scoped assignment names nothing; every other scope names what it applies to."
        }
        Some("retention_assignments_policy_fkey") => {
            "No policy in this tenant has that identifier."
        }
        _ => return Err(ApiError::new(error.into(), request_id)),
    };
    Ok(Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "POLICY_REJECTED",
        "That retention policy is not one this schema allows.",
        "Correct the field the detail names and retry.",
    )
    .with_details(vec![serde_json::json!({ "reason": truncate(sentence) })])
    .into_response(request_id))
}

fn policy_view(row: &PolicyRow) -> PolicyView {
    PolicyView {
        id: row.id.as_uuid(),
        name: row.name.clone(),
        action: row.action.as_str(),
        // Months are reported as the days the column stores; a policy written through this surface
        // has `months = 0` by construction, and one written by hand in `psql` with `INTERVAL '7
        // years'` reports its months rather than silently reading as no duration at all.
        duration_days: row.duration.as_ref().map(|d| i64::from(d.days) + i64::from(d.months) * 30),
        basis: row.basis.as_str(),
        event_key: row.event_key.clone(),
        is_record: row.is_record,
        allow_user_delete: row.allow_user_delete,
        created_at: row.created_at.to_rfc3339(),
    }
}

fn assignment_view(row: &AssignmentRow, now: chrono::DateTime<chrono::Utc>) -> AssignmentView {
    AssignmentView {
        policy_id: row.policy_id.as_uuid(),
        scope_type: row.scope_type.as_str(),
        scope_id: row.scope_id,
        applied_at: row.applied_at.to_rfc3339(),
        expires_at: row.expires_at.map(|at| at.to_rfc3339()),
        live: row.applied_at <= now && row.expires_at.is_none_or(|at| at > now),
    }
}

fn unreadable_body(error: &serde_json::Error) -> Envelope {
    let detail = if error.to_string().starts_with("unknown field") {
        "the body carries a field this endpoint does not read; a retention field quietly dropped \
         is a control that preserves differently from the way its author wrote it"
    } else {
        "the body could not be read as a retention policy"
    };
    bad_detail("body", detail.to_owned())
}

fn bad_field(field: &'static str, detail: &'static str) -> Envelope {
    bad_detail(field, detail.to_owned())
}

fn bad_detail(field: &'static str, detail: String) -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "That retention policy could not be read.",
        "Correct the field the detail names and retry.",
    )
    .with_details(vec![serde_json::json!({ "field": field, "detail": truncate(&detail) })])
}

/// Bounds what reaches the caller.
///
/// serde quotes the offending name, and the offending name came from the request.
fn truncate(detail: &str) -> String {
    if detail.chars().count() <= MAX_DETAIL_CHARS {
        return detail.to_owned();
    }
    detail.chars().take(MAX_DETAIL_CHARS).collect::<String>() + "…"
}
