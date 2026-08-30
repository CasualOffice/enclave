//! `docs/05-API.md §16`'s eight workflow endpoints.
//!
//! `docs/15-WORKFLOWS-AND-SIGNING.md §§2–5` is authoritative for what these mean;
//! `crates/workflows` holds the model and the evaluator; this module is the HTTP edge and the one
//! place the policy chain is consulted. `ENC-739`.
//!
//! # Each handler enforces exactly once, and this table is the whole authorization design
//!
//! | Endpoint | Resource enforced | Action |
//! |---|---|---|
//! | `GET /workflows/tasks` | the caller's own `users` row | `container.read`, then a per-item `file.metadata_read` trim |
//! | `POST /files/{id}/workflows` | the file | `file.edit` |
//! | `POST /workflows/definitions/{id}/simulate` | the file named in the body | `file.edit` |
//! | `GET /workflows/instances/{id}` | the instance's file | `file.metadata_read` |
//! | `POST /workflows/instances/{id}/cancel` | the instance's file | `file.edit` |
//! | `POST /workflows/steps/{id}/approve` | the step's file | `file.content_read` |
//! | `POST /workflows/steps/{id}/reject` | the step's file | `file.content_read` |
//! | `POST /workflows/steps/{id}/delegate` | the step's file | `file.content_read` |
//!
//! Three of those choices are arguments rather than conventions.
//!
//! **`file.content_read` for a decision**, not `metadata_read`. `docs/15 §2.1`: *an approval
//! approves what was actually reviewed.* You cannot approve what you may not read, and authorizing
//! an approval as a metadata action would let somebody who can see a contract's *name* approve its
//! contents. It is `docs/15 §12` W1 — *a workflow cannot grant an actor access they do not
//! independently hold* — expressed as the action the chain is asked about.
//!
//! **`file.edit` for a start.** Starting a workflow does not change a byte, and it does put the
//! file under a process that gates its future and conscripts named colleagues into deciding about
//! it. Requiring the right to change the file is the conservative reading, and it is the one that
//! keeps `docs/15 §2`'s fourth property true in the *other* direction: a workflow can only require
//! action from people who hold access, and only somebody who holds real authority over the file
//! should be able to require it.
//!
//! **No new `Action` variant.** `enclave_core::Action` is deliberately not `#[non_exhaustive]` —
//! adding a family breaks every exhaustive match in every policy service, which is the point of its
//! design and the reason it is not done here for a surface that has an honest answer in the
//! existing vocabulary. A workflow action *is* an action on the file; modelling it as its own
//! family would invite a second permission model where a workflow grant could substitute for a file
//! grant, which is the exact escalation `§2` forbids.
//!
//! # `404`, and why the step endpoints are not `403`
//!
//! `CLAUDE.md` rule 7. The split is deliberate and it is not "everything is 404":
//!
//! * a step, instance or file in another tenant is invisible — the lookup runs under row-level
//!   security with the tenant from the verified token, so a foreign id arrives as *this* tenant's
//!   id for a row that does not exist, and the answer is the one a fabricated UUID gets;
//! * a caller the *chain* refuses with `ACCESS_DENIED` gets `404` through [`existence_gate`], for
//!   `crates/api/src/content.rs`'s reason: on a read path a `403` confirms existence;
//! * a caller who passes the chain and simply is not the assignee gets `403`. The step's existence
//!   is not a secret from somebody who can already read the file it is about, and answering `404`
//!   there would make "I am not the approver" indistinguishable from "the approval does not
//!   exist", which is an inbox nobody can debug.
//!
//! # Every refusal this module takes is a row before it is a response
//!
//! `CLAUDE.md` rule 10 and `ENC-606`. The chain audits its own decisions; a refusal taken *after*
//! it has allowed — not your step, already delegated, no reason given for a cancellation — reaches
//! the caller only through [`crate::refusal::HandlerAudit::refuse`], which writes the `DENY` row
//! first. [`refuse`] below is the one place that conversion happens, so there is exactly one
//! mapping from a `crates/workflows` [`Refusal`] to a wire code and an audit row, and a handler
//! cannot invent a second.

use core::str::FromStr;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use chrono::Utc;
use enclave_core::{
    Action, Actor, ContainerAction, Error, FileAction, FileId, PolicyDecision, ReasonCode,
    RequestContext, RequestId, ResourceKind, ResourceRef, StageDecision, UserId, ValidationCode,
};
use enclave_workflows::{
    plan_cancel, plan_decision, plan_delegate, plan_start, repo, Decision, InstanceFacts, Plan,
    Refusal, StepState, WorkflowDefinitionId, WorkflowError, WorkflowInstanceId, WorkflowStepId,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action a decision on a step is authorized as. See the module header.
const DECIDE_ACTION: Action = Action::File(FileAction::ContentRead);

/// The action starting, simulating or cancelling a workflow is authorized as.
const GOVERN_ACTION: Action = Action::File(FileAction::Edit);

/// The action reading an instance is authorized as.
const READ_ACTION: Action = Action::File(FileAction::MetadataRead);

/// The capability that answers *is this caller an owner of this thing* for `docs/15 §4`'s
/// cancellation rule.
///
/// `manage_permissions` is the closest the ACL model has to ownership: `enclave_core::FileAction`
/// documents it as *the action that can grant every other action, and therefore never implied by
/// any of them*. Asked as a **capability probe** rather than a second `enforce`, so it writes no
/// audit row of its own — the decision this request took is the one `GOVERN_ACTION` already
/// recorded, and a second `ALLOW` row for a question that only ever narrows the answer would make
/// the trail harder to read rather than more complete.
const OWNER_ACTION: Action = Action::File(FileAction::ManagePermissions);

// --- Wire types -------------------------------------------------------------------------------

/// `POST /api/v1/files/{id}/workflows`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartRequest {
    /// Which template to run.
    definition_id: String,
}

/// `POST /api/v1/workflows/definitions/{id}/simulate`.
///
/// The definition comes from the path and the file from the body, which is the mirror image of
/// [`StartRequest`] — and it is the reason both handlers can call one evaluator: between them they
/// name the same two things, so the *inputs* to the evaluation are identical and only the URL
/// differs. A simulate that took no file would be answering a different question from the one a
/// start asks, which is D28's failure mode in its quietest form.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SimulateRequest {
    /// The file the definition would be run against.
    file_id: String,
}

/// `POST /workflows/steps/{id}/approve` and `/reject`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionRequest {
    /// Optional for an approval, required for a rejection (`docs/05-API.md §16`).
    #[serde(default)]
    comment: Option<String>,
}

/// `POST /workflows/steps/{id}/delegate`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DelegateRequest {
    /// Who to hand the step to.
    to_user_id: String,
    /// Why. Required — `docs/15 §4` makes a delegation *explicit and recorded, never a silent
    /// substitution*, and a transfer with no stated reason is that substitution with a row.
    reason: String,
}

/// `POST /workflows/instances/{id}/cancel`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelRequest {
    /// Why. Required, here and in the database (`workflow_instances_cancellation_reason`).
    reason: String,
}

/// One instance, as a caller reads it back.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceView {
    /// The instance.
    id: String,
    /// The template it came from, and the version of it.
    definition_id: String,
    /// That version.
    definition_version: i32,
    /// Where it is.
    state: enclave_workflows::InstanceState,
    /// Which stage is open.
    current_stage: i32,
    /// The file.
    file_id: String,
    /// The version under review (`docs/15 §2.1`).
    version_id: String,
    /// Who started it.
    started_by: String,
    /// Its steps, in order. `docs/15 §11`: *progress is legible — who is next, who is late.*
    steps: Vec<StepView>,
}

/// One step row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepView {
    /// The step.
    id: String,
    /// Which stage, and what it is called.
    stage: i32,
    /// The stage's name, from the frozen config.
    stage_name: String,
    /// Which position within the stage. Rows sharing one are the same step's assignees.
    position: i32,
    /// What is asked.
    step_type: enclave_workflows::StepType,
    /// Who was asked.
    assignee_id: String,
    /// Who holds it now, if it was handed on. `docs/15 §4`: never a silent substitution.
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated_to: Option<String>,
    /// Where the row is.
    state: enclave_workflows::StepState,
}

/// The result of a simulation.
///
/// Deliberately the *same* description of the *same* plan a real start would apply — see
/// [`simulate`]. A shape with extra explanatory fields would be a second rendering that could drift
/// from the first, which is D28's failure in the response rather than in the evaluation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationView {
    /// Always `true`, and it is here rather than implied by the URL so a client that logs one
    /// response body cannot mistake it for a record of a workflow that ran.
    simulated: bool,
    /// The file it was simulated against.
    file_id: String,
    /// The version it would have bound to.
    version_id: String,
    /// Every step it would create, in order, with its assignee and its opening state.
    steps: Vec<SimulatedStep>,
}

/// One step a simulation would create.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedStep {
    /// Which stage.
    stage: i32,
    /// Its name.
    stage_name: String,
    /// Which position.
    position: i32,
    /// What would be asked.
    step_type: enclave_workflows::StepType,
    /// Of whom.
    assignee_id: String,
    /// `ASSIGNED` for the opening stage, `PENDING` for the rest.
    state: StepState,
}

/// A page of the caller's tasks.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskList {
    /// The tasks that survived the trim. See [`tasks`].
    items: Vec<TaskView>,
    /// Pagination, per `docs/05-API.md §6`.
    page: Page,
}

/// One task.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    /// The step to act on.
    step_id: String,
    /// Its instance.
    instance_id: String,
    /// The file it is about.
    file_id: String,
    /// The version under review.
    version_id: String,
    /// What is being asked.
    step_type: enclave_workflows::StepType,
    /// Which stage, and its name.
    stage: i32,
    /// The stage's name.
    stage_name: String,
    /// Whether the caller holds it as a delegate rather than as the original assignee.
    delegated: bool,
    /// When it is due.
    #[serde(skip_serializing_if = "Option::is_none")]
    due_at: Option<chrono::DateTime<Utc>>,
}

/// `docs/05-API.md §6`'s pagination object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    /// Always absent: the inbox is bounded at [`repo::MAX_TASKS`] and a cursor over an
    /// ACL-trimmed set is `crates/api/src/content.rs`'s problem, not solved here.
    next_cursor: Option<String>,
    /// Whether the database had more rows than the page took — **before** the trim. A page may
    /// therefore be short and still report `true`; see [`tasks`].
    has_more: bool,
}

// --- Handlers ---------------------------------------------------------------------------------

/// Handles `GET /api/v1/workflows/tasks` — `docs/05-API.md §16`, *steps assigned to me*.
///
/// # This is the leak surface, and the trim is the control
///
/// A task inbox is the cheapest enumeration oracle a workflow system has: it takes no argument and
/// returns a list. Two things keep it from becoming one.
///
/// **The query already names the caller.** [`repo::load_tasks`]'s predicate is *the caller is the
/// current holder* — the delegate where there is one, the assignee otherwise — so a step nobody
/// gave them never appears, whatever they can see.
///
/// **Every surviving row's file goes back through the chain.** Holding a step is not the same as
/// being allowed to know what it is *about*: an approver whose access to a file was revoked after
/// the workflow started still holds the row, and the file's name, id and version must not be
/// rendered to them. So each candidate's file is re-confirmed with
/// `AuthorizationService::authorize_many` for `file.metadata_read`, in one call for the page, and a
/// denied row is **dropped**. Not `403` — `CLAUDE.md` rule 7, and here it is not even a decision to
/// make: the row simply is not in the response, exactly as `browse` trims a folder listing.
///
/// The trim is silent and the page may be short while `has_more` is `true`, for
/// `crates/api/src/content.rs`'s reason: the cursor tracks what the *database* returned, and the
/// other way round skips every trimmed row's successors.
///
/// # The audited decision, and the honest gap
///
/// The chain runs once, for `container.read` on the caller's own `users` row — the resource a
/// personal inbox *is*, and `crates/api/src/me.rs`'s shape exactly. The per-item trim is
/// deliberately not a second audit event, for `docs/07 §6.2`'s reason.
///
/// `ENC-746` recorded that the deployed binary composed no ACL resolver, so every trim was denied
/// and the inbox always answered `200` with an empty list. **That is no longer true** (`ENC-965`):
/// `main.rs` composes `PgAclAuthorization` inside `SelfServiceOr` (`ENC-126`), the trim is real, and
/// this endpoint returns the steps a person actually holds — verified end to end against the
/// running binary the day the first workflow definition could be written.
///
/// What kept it empty until then was one layer further back: `workflow_definitions` had no writer
/// but a test fixture, so no instance could start and no step could exist to be held.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or a database failure.
pub async fn tasks(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<TaskParams>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let holder = match attributable_actor(&ctx) {
        Ok(holder) => holder,
        // A service account or MCP client has no `users` row, so it can hold no step — and the
        // resource this endpoint enforces on *is* the caller's own user record, so there is not
        // even a reference to name. Refused before the chain, and recorded before it is returned.
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ_ACTION, &resource, refused).await);
        }
    };

    let inbox = ResourceRef::new(ctx.tenant_id, ResourceKind::User, holder.as_uuid());
    let decision = state
        .policy
        .enforce(&ctx, Action::Container(ContainerAction::Read), &inbox)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, Action::Container(ContainerAction::Read), &inbox, decision).await?;

    let limit = params.limit.unwrap_or(repo::MAX_TASKS).clamp(1, repo::MAX_TASKS);
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    // One more than the page, so `has_more` is answered by the database rather than guessed.
    let candidates = repo::load_tasks(&mut tx, holder, limit.saturating_add(1))
        .await
        .map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;

    let has_more = i64::try_from(candidates.len()).unwrap_or(i64::MAX) > limit;
    let page: Vec<_> =
        candidates.into_iter().take(usize::try_from(limit).unwrap_or(usize::MAX)).collect();

    // The trim. One resolution for the whole page.
    let resources: Vec<ResourceRef> =
        page.iter().map(|task| ResourceRef::file(ctx.tenant_id, task.resource)).collect();
    let visible = state
        .policy
        .authorization()
        .authorize_many(&ctx, READ_ACTION, &resources)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    let items = page
        .iter()
        .zip(visible.iter())
        .filter(|(_, decision)| is_allowed(decision))
        .map(|(task, _)| TaskView {
            step_id: task.step.to_string(),
            instance_id: task.instance.to_string(),
            file_id: task.resource.to_string(),
            version_id: task.version.to_string(),
            step_type: task.step_type,
            stage: task.stage,
            stage_name: task.stage_name.clone(),
            delegated: task.delegated,
            due_at: task.due_at,
        })
        .collect();

    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(TaskList { items, page: Page { next_cursor: None, has_more } }),
    )
        .into_response())
}

/// `?limit=` for the task inbox.
#[derive(Debug, Default, Deserialize)]
pub struct TaskParams {
    /// How many tasks to return, clamped to [`repo::MAX_TASKS`].
    #[serde(default)]
    limit: Option<i64>,
}

/// Handles `POST /api/v1/files/{id}/workflows` — start an instance.
///
/// Calls [`plan_start`] and applies the plan. [`simulate`] calls the same function and does not.
/// See [`plan_start_for`], which is the code both share.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure. A duplicate start
/// is a `409` in the `Ok` arm, which is a status [`Error`] cannot express.
pub async fn start(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let file = parse_id::<FileId>(&file, request_id)?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    let decision = state
        .policy
        .enforce(&ctx, GOVERN_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, GOVERN_ACTION, &resource, decision).await?;

    let request: StartRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let definition = parse_id::<WorkflowDefinitionId>(&request.definition_id, request_id)?;
    let starter = actor_user(&state, &ctx, GOVERN_ACTION, &resource).await?;

    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let plan = match plan_start_for(&mut tx, definition, file, starter, request_id).await? {
        Ok(plan) => plan,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    // The one statement that differs from `simulate`.
    if let Err(error) = enclave_workflows::repo::apply(&mut tx, &plan).await {
        return workflow_write(error, request_id);
    }
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;

    let created = plan.created_instance().ok_or_else(|| {
        // Unreachable: `plan_start` always emits a `CreateInstance` first. Stated as an error rather
        // than an `expect` because `panic` is denied at the workspace level and a `500` here is
        // strictly better than a process that stops serving every other tenant.
        api(Error::Internal(anyhow::anyhow!("a start plan created no instance")), request_id)
    })?;
    started(&ctx, created.id, file);

    let location = format!("/api/v1/workflows/instances/{}", created.id);
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        [(header::LOCATION, location)],
        Json(serde_json::json!({ "id": created.id.to_string(), "state": "RUNNING" })),
    )
        .into_response())
}

/// Handles `POST /api/v1/workflows/definitions/{id}/simulate`.
///
/// # Why this handler is so short
///
/// Because it is [`start`] with one statement removed. `plans/M4-GOVERNANCE.md` D28 requires that
/// simulation be *indistinguishable from enforcement except in its effect*, and the way that is
/// held here is structural rather than asserted: both handlers enforce the **same action**
/// (`file.edit`) on the **same resource** (the file), both call [`plan_start_for`], and
/// `enclave_workflows::evaluate` cannot write — it takes no connection. There is no branch to get
/// wrong, because there is nothing to branch on.
///
/// The proof that it does not mutate is `simulate_writes_nothing_and_start_writes_everything` in
/// `crates/api/tests/workflows.rs`, which counts rows before and after **and** pairs the absence
/// with the positive control: the identical input, really executed, changes them.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or a database failure.
pub async fn simulate(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(definition): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let definition = parse_id::<WorkflowDefinitionId>(&definition, request_id)?;

    let request: SimulateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let file = parse_id::<FileId>(&request.file_id, request_id)?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    // The same action on the same resource a real start enforces. A cheaper one here — `read`, say,
    // on the grounds that nothing is written — is exactly the divergence D28 forbids: it would let
    // somebody rehearse a workflow they could not run, and the rehearsal would answer *yes* where
    // the real thing answers *no*.
    let decision = state
        .policy
        .enforce(&ctx, GOVERN_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, GOVERN_ACTION, &resource, decision).await?;

    let starter = actor_user(&state, &ctx, GOVERN_ACTION, &resource).await?;

    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let plan = match plan_start_for(&mut tx, definition, file, starter, request_id).await? {
        Ok(plan) => plan,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };
    // Rolled back rather than committed, and the transaction is read-only in fact: nothing between
    // `begin` and here writes. The rollback is belt-and-braces against a future reader assuming a
    // dropped `TenantScoped` commits.
    drop(tx);

    let Some(created) = plan.created_instance() else {
        return Err(api(
            Error::Internal(anyhow::anyhow!("a start plan created no instance")),
            request_id,
        ));
    };

    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(SimulationView {
            simulated: true,
            file_id: created.resource.to_string(),
            version_id: created.version.to_string(),
            steps: plan
                .created_steps()
                .map(|step| SimulatedStep {
                    stage: step.stage,
                    stage_name: step.stage_name.clone(),
                    position: step.position,
                    step_type: step.step_type,
                    assignee_id: step.assignee.to_string(),
                    state: step.state,
                })
                .collect(),
        }),
    )
        .into_response())
}

/// Handles `GET /api/v1/workflows/instances/{id}`.
///
/// # Errors
///
/// [`ApiError`]. A cross-tenant or invisible instance is [`Error::NotFound`], which is the same
/// answer a fabricated id gets.
pub async fn instance(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let id = parse_id::<WorkflowInstanceId>(&id, request_id)?;

    let (facts, steps) = load_instance(&state, &ctx, id).await?;
    let resource = ResourceRef::file(ctx.tenant_id, facts.resource);
    let decision = state
        .policy
        .enforce(&ctx, READ_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, READ_ACTION, &resource, decision).await?;

    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(InstanceView {
            id: facts.id.to_string(),
            definition_id: facts.definition_id.to_string(),
            definition_version: facts.definition_version,
            state: facts.state,
            current_stage: facts.current_stage,
            file_id: facts.resource.to_string(),
            version_id: facts.version.to_string(),
            started_by: facts.started_by.to_string(),
            steps: steps
                .iter()
                .map(|step| StepView {
                    id: step.id.to_string(),
                    stage: step.stage,
                    stage_name: step.stage_name.clone(),
                    position: step.position,
                    step_type: step.step_type,
                    assignee_id: step.assignee.to_string(),
                    delegated_to: step.delegated_to.map(|id| id.to_string()),
                    state: step.state,
                })
                .collect(),
        }),
    )
        .into_response())
}

/// Handles `POST /api/v1/workflows/instances/{id}/cancel`.
///
/// # Cancellation is destructive, so it is bounded twice
///
/// `docs/15 §4`: *cancellation requires the initiator or a workspace owner, a reason, and is
/// audited.* All three:
///
/// * **who** — the initiator, or a caller who holds `file.manage_permissions` on the file. The
///   owner half is a capability probe rather than a second `enforce`; see [`OWNER_ACTION`].
/// * **a reason** — required here as a `422`, and required in the database by
///   `workflow_instances_cancellation_reason`, so a second write path cannot lose it.
/// * **audited** — the chain records the `file.edit` decision, and a refusal here goes through
///   [`refuse`].
///
/// **What happens to steps already approved: nothing.** They keep their state, their decider and
/// their timestamp; only `PENDING` and `ASSIGNED` steps become `SKIPPED`. Cancellation ends what is
/// happening, it does not rewrite what happened — `enclave_workflows::repo`'s `SKIP_STEP` names
/// only the open states, and `workflow_steps_decision_complete` makes the alternative unwritable.
///
/// # Errors
///
/// [`ApiError`].
pub async fn cancel(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let id = parse_id::<WorkflowInstanceId>(&id, request_id)?;

    let (facts, steps) = load_instance(&state, &ctx, id).await?;
    let resource = ResourceRef::file(ctx.tenant_id, facts.resource);
    let decision = state
        .policy
        .enforce(&ctx, GOVERN_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, GOVERN_ACTION, &resource, decision).await?;

    let request: CancelRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let reason = request.reason.trim();
    if reason.is_empty() {
        return Ok(missing("reason", "A cancellation must say why.").into_response(request_id));
    }

    let actor = actor_user(&state, &ctx, GOVERN_ACTION, &resource).await?;
    let owns = capability(&state, &ctx, OWNER_ACTION, &resource).await?;

    let plan = match plan_cancel(&facts, &steps, actor, owns, reason.to_owned(), Utc::now()) {
        Ok(plan) => plan,
        Err(error) => return refuse(&state, &ctx, GOVERN_ACTION, &resource, error).await,
    };

    if let Err(error) = apply(&state, &ctx, &plan).await {
        return refuse(&state, &ctx, GOVERN_ACTION, &resource, error).await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Handles `POST /api/v1/workflows/steps/{id}/approve`.
///
/// # Errors
///
/// [`ApiError`].
pub async fn approve(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    decide(state, ctx, id, body, Decision::Approve).await
}

/// Handles `POST /api/v1/workflows/steps/{id}/reject`.
///
/// The comment is **required** (`docs/05-API.md §16`), and that is a governance requirement rather
/// than a schema one: a rejection terminates the instance for everybody, and *"rejected, no reason
/// given"* is the state a workflow exists to avoid.
///
/// # Errors
///
/// [`ApiError`].
pub async fn reject(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    decide(state, ctx, id, body, Decision::Reject).await
}

/// Handles `POST /api/v1/workflows/steps/{id}/delegate`.
///
/// # The delegate is checked, and checked again
///
/// `docs/15 §2`, fourth core property: a workflow cannot grant access. So the proposed delegate is
/// asked, here, whether they independently hold `file.content_read` on the file — the same action
/// the decision itself is authorized as. It is a **capability probe about another principal**,
/// asked over a context carrying that principal as the actor, and it can only *narrow* the outcome:
/// nothing about it lets the delegate do anything, and when they actually act the whole chain runs
/// under their own request, with their own network, device and conditional-access facts.
///
/// That is why both checks exist. This one refuses an ineligible delegate at the moment authority
/// is offered, which is when it can be corrected. The one at decision time is the authorization —
/// without it the step would be a stored capability that outlives the grant behind it.
///
/// # Errors
///
/// [`ApiError`].
pub async fn delegate(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let step = parse_id::<WorkflowStepId>(&id, request_id)?;

    let (facts, steps) = load_step_instance(&state, &ctx, step).await?;
    let resource = ResourceRef::file(ctx.tenant_id, facts.resource);
    let decision = state
        .policy
        .enforce(&ctx, DECIDE_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, DECIDE_ACTION, &resource, decision).await?;

    let request: DelegateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let reason = request.reason.trim();
    if reason.is_empty() {
        return Ok(missing("reason", "A delegation must say why.").into_response(request_id));
    }
    let to = parse_id::<UserId>(&request.to_user_id, request_id)?;
    let actor = actor_user(&state, &ctx, DECIDE_ACTION, &resource).await?;

    // Two questions about the delegate, and both must hold. The first is the composite foreign
    // key's condition, asked before the key so the answer is a refusal rather than a `500`.
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let exists = repo::is_active_user(&mut tx, to)
        .await
        .map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;

    let entitled = exists && delegate_entitled(&state, &ctx, to, &resource).await?;

    let plan = match plan_delegate(
        &facts,
        &steps,
        step,
        actor,
        to,
        entitled,
        reason.to_owned(),
        Utc::now(),
    ) {
        Ok(plan) => plan,
        Err(error) => return refuse(&state, &ctx, DECIDE_ACTION, &resource, error).await,
    };

    if let Err(error) = apply(&state, &ctx, &plan).await {
        return refuse(&state, &ctx, DECIDE_ACTION, &resource, error).await;
    }
    delegated(&ctx, step, actor, to);
    Ok(StatusCode::NO_CONTENT.into_response())
}

// --- The pieces the handlers share ------------------------------------------------------------

/// The evaluation both [`start`] and [`simulate`] run.
///
/// **One function, called from both, and it cannot write.** This is where D28 is held: whatever
/// either handler does afterwards, the definition decode, the scope check, the version binding and
/// every refusal came from the same code over the same rows. `ENC-741`.
///
/// The nested `Result` separates a fault (the outer arm) from a refusal a caller can act on (the
/// inner one, an envelope), because the two have different statuses and only one is worth a
/// caller's attention.
///
/// # Errors
///
/// [`ApiError`] for a database failure or an undecodable stored definition.
async fn plan_start_for(
    tx: &mut enclave_db::TenantScoped,
    definition: WorkflowDefinitionId,
    file: FileId,
    starter: UserId,
    request_id: RequestId,
) -> Result<Result<Plan, Envelope>, ApiError> {
    let Some(definition) = repo::load_definition(tx, definition)
        .await
        .map_err(|error| workflow_fault(error, request_id))?
    else {
        return Ok(Err(not_found("definition", "No such workflow definition.")));
    };
    let Some(resource) =
        repo::load_resource(tx, file).await.map_err(|error| workflow_fault(error, request_id))?
    else {
        // The chain has already allowed `file.edit` on this id, so an absent row here means a
        // folder or a trashed file rather than a permission question.
        return Ok(Err(not_found("file", "No such file.")));
    };

    match plan_start(&definition, &resource, starter, Utc::now()) {
        Ok(plan) => Ok(Ok(plan)),
        Err(WorkflowError::Refused(refusal)) => Ok(Err(refusal_envelope(refusal))),
        Err(WorkflowError::Definition(detail)) => Ok(Err(rejected("definition", &detail))),
        Err(other) => Err(workflow_fault(other, request_id)),
    }
}

/// The body of [`approve`] and [`reject`].
async fn decide(
    state: ApiState,
    ctx: RequestContext,
    id: String,
    body: Bytes,
    decision: Decision,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let step = parse_id::<WorkflowStepId>(&id, request_id)?;

    let (facts, steps) = load_step_instance(&state, &ctx, step).await?;
    let resource = ResourceRef::file(ctx.tenant_id, facts.resource);
    let allowed = state
        .policy
        .enforce(&ctx, DECIDE_ACTION, &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    discharge(&state, &ctx, DECIDE_ACTION, &resource, allowed).await?;

    let request: DecisionRequest = if body.is_empty() {
        DecisionRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
        }
    };
    let comment = request.comment.map(|text| text.trim().to_owned()).filter(|t| !t.is_empty());
    if decision == Decision::Reject && comment.is_none() {
        return Ok(missing("comment", "A rejection must say why.").into_response(request_id));
    }

    let actor = actor_user(&state, &ctx, DECIDE_ACTION, &resource).await?;

    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let current = repo::current_version(&mut tx, facts.resource)
        .await
        .map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;

    let plan =
        match plan_decision(&facts, &steps, step, actor, decision, comment, current, Utc::now()) {
            Ok(plan) => plan,
            // The one refusal that has to change something: the instance is expired by the same
            // request that was refused, so the row and the answer agree. See
            // `enclave_workflows::WorkflowError::Superseded`.
            Err(WorkflowError::Superseded(expiry)) => {
                if let Err(error) = apply(&state, &ctx, &expiry).await {
                    return refuse(&state, &ctx, DECIDE_ACTION, &resource, error).await;
                }
                superseded(&ctx, facts.id);
                return Ok(refusal_envelope(Refusal::VersionSuperseded).into_response(request_id));
            }
            Err(error) => return refuse(&state, &ctx, DECIDE_ACTION, &resource, error).await,
        };

    if let Err(error) = apply(&state, &ctx, &plan).await {
        return refuse(&state, &ctx, DECIDE_ACTION, &resource, error).await;
    }
    decided(&ctx, step, actor, decision);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Loads an instance and its steps, answering `404` for one this caller cannot see.
///
/// The read runs under `TenantScoped`, so another tenant's instance is simply absent — the
/// `404` is a consequence of never being able to detect it rather than a case to handle
/// (`crates/api/src/content.rs`'s note on `existence_gate`).
///
/// It runs **before** the chain because the chain needs a resource and the instance is what names
/// one. That ordering is safe and is worth stating: nothing is disclosed by it, the statement is
/// tenant-scoped and doubly held by row-level security, and the response is identical for an
/// instance that does not exist and one whose file the caller may not see.
async fn load_instance(
    state: &ApiState,
    ctx: &RequestContext,
    id: WorkflowInstanceId,
) -> Result<(InstanceFacts, Vec<enclave_workflows::StepFacts>), ApiError> {
    let request_id = ctx.request_id;
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let facts = repo::load_instance(&mut tx, id)
        .await
        .map_err(|error| workflow_fault(error, request_id))?
        .ok_or_else(|| api(Error::NotFound, request_id))?;
    let steps =
        repo::load_steps(&mut tx, id).await.map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;
    Ok((facts, steps))
}

/// The same, reached from a step id.
async fn load_step_instance(
    state: &ApiState,
    ctx: &RequestContext,
    step: WorkflowStepId,
) -> Result<(InstanceFacts, Vec<enclave_workflows::StepFacts>), ApiError> {
    let request_id = ctx.request_id;
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| api(e.into(), request_id))?;
    let facts = repo::load_instance_for_step(&mut tx, step)
        .await
        .map_err(|error| workflow_fault(error, request_id))?
        .ok_or_else(|| api(Error::NotFound, request_id))?;
    let steps = repo::load_steps(&mut tx, facts.id)
        .await
        .map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|e| api(e.into(), request_id))?;
    Ok((facts, steps))
}

/// Applies a plan in its own transaction.
///
/// # A refusal raised by a *statement* is still a refusal
///
/// `enclave_workflows::repo::apply` can refuse: its delegation statement carries
/// `WHERE delegated_to IS NULL`, so the loser of two concurrent transfers changes no rows and gets
/// [`Refusal::AlreadyDelegated`] — the same answer the snapshot check in
/// `enclave_workflows::authority` gives, from the layer that survives concurrency.
///
/// `ENC-739` shipped this returning [`WorkflowError`] and rendering **everything** it could not
/// recognise as a `500`, which turned that refusal into an internal error. Found by deliberately
/// removing the snapshot check and watching the integration test fail with `500` where it expected
/// `403` — the bound held, and the caller was told the server was broken. So the error travels back
/// out and every caller routes it through [`refuse`], which is the module's single conversion and
/// already knows the difference between a denial, a conflict and a fault.
///
/// # Errors
///
/// [`WorkflowError`], for the caller to hand to [`refuse`].
async fn apply(state: &ApiState, ctx: &RequestContext, plan: &Plan) -> Result<(), WorkflowError> {
    if plan.is_empty() {
        return Ok(());
    }
    let mut tx = state.db.begin(ctx.tenant_id).await?;
    enclave_workflows::repo::apply(&mut tx, plan).await?;
    tx.commit().await?;
    Ok(())
}

/// Consumes a [`PolicyDecision`], refusing anything this surface cannot discharge.
///
/// `none_dischargeable` rather than `Obligations::require_none`, for `ENC-606`'s reason: the latter
/// returns an `Error`, and an `Error` can reach a caller without an audit row. No stage attaches an
/// obligation to a workflow action today and this path could satisfy none if one did — there is no
/// rendition to watermark and nowhere to collect a justification — so an obligation arriving here is
/// a refusal (D29, `CLAUDE.md` rule 8).
async fn discharge(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
    decision: PolicyDecision,
) -> Result<(), ApiError> {
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(ctx, action, resource, refused).await);
    }
    Ok(())
}

/// The user this action will be attributed to.
///
/// `workflow_steps.decided_by` and `workflow_instances.started_by` both key onto `users`, because
/// *"the system"* is not an answer to *"who approved this contract"*. A service account, an MCP
/// client or `system` has no row there; the requirement is stated here rather than left to the
/// foreign key, so the refusal is a `403` with a reason rather than an integrity error rendered as
/// a `500` — `crates/api/src/admin/dlp.rs::author`'s argument.
async fn actor_user(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<UserId, ApiError> {
    match attributable_actor(ctx) {
        Ok(id) => Ok(id),
        Err(refused) => Err(state.audit.refuse(ctx, action, resource, refused).await),
    }
}

/// The principal an approval, a start or a cancellation can be attributed to.
///
/// Returns a [`Refused`] rather than an error, which is the shape `xtask audit-coverage` reads as
/// *audited by construction*: `Refused` has private fields and no conversion, so the only thing a
/// caller can do with one is hand it to [`crate::refusal::HandlerAudit::refuse`], which writes the
/// row first. `crates/api/src/admin/dlp.rs::author` is the same function one surface over, and this
/// is deliberately not shared with it — that refusal is about who may *own a rule* and this one is
/// about who can be held answerable for an approval, and one helper would make the two move
/// together the next time either changes.
///
/// # Errors
///
/// [`Refused`] carrying [`ReasonCode::AccessDenied`].
fn attributable_actor(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(ReasonCode::AccessDenied)),
    }
}

/// Whether the caller holds `action` on `resource`, as a hint rather than a decision.
///
/// `PolicyEngine::authorization` documents this as writing no audit row: it cannot allow anything,
/// and the enforcement happened when the action was attempted. Used for the *owner* half of
/// `docs/15 §4`'s cancellation rule, where the answer can only narrow what the caller may do.
///
/// `is_allowed()` and never `ensure_allowed()`, deliberately: the latter constructs a client-visible
/// denial outside the engine, which `xtask audit-coverage` enumerates and requires an
/// acknowledgement for. There is nothing to acknowledge here because nothing is refused here.
async fn capability(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<bool, ApiError> {
    let decision = state
        .policy
        .authorization()
        .authorize(ctx, action, resource)
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;
    Ok(is_allowed(&decision))
}

/// Whether the *proposed delegate* independently holds the right the step requires.
///
/// Asked over a context that carries the delegate as its actor and is otherwise this tenant's
/// system context. Two things about that are worth being explicit about, because a synthesized
/// context is the shape a bypass usually takes:
///
/// * it is asked of the **authorization service**, not of `enforce`, so it takes no decision, writes
///   no row, and grants nothing;
/// * it can only make the delegation *fail*. There is no path by which a `true` here permits
///   anything — the delegate's own request runs the whole chain under their own context, with their
///   own network and device facts, which this synthesized one deliberately does not carry.
async fn delegate_entitled(
    state: &ApiState,
    ctx: &RequestContext,
    delegate: UserId,
    resource: &ResourceRef,
) -> Result<bool, ApiError> {
    let mut probe = RequestContext::system(ctx.tenant_id);
    probe.actor = Actor::User(delegate);
    capability(state, &probe, DECIDE_ACTION, resource).await
}

/// Whether a stage decision allowed.
fn is_allowed(decision: &StageDecision) -> bool {
    decision.is_allowed()
}

/// Whether a refusal is an **authorization** answer or a **state conflict**.
///
/// The distinction decides two things that must not be decided separately: whether the refusal is
/// written to the audit trail as a `DENY`, and whether the caller is told `ACCESS_DENIED` or a
/// specific workflow code.
///
/// * **Authorization.** *This caller may not do this.* Five of them, and each is a control rather
///   than a state: not the holder, self-approval, delegation forbidden, a second delegation
///   (`ENC-740`'s bound firing), and cancelling somebody else's workflow. Each goes through
///   [`crate::refusal::HandlerAudit::refuse`] and so is a row before it is a response
///   (`CLAUDE.md` rule 10, `ENC-606`).
/// * **Conflict.** *This cannot be done to this thing right now.* The step is already decided, the
///   stage has not opened, the version moved on, the definition does not cover this file. Nobody
///   was denied anything — the chain allowed, and the request lost a race with reality or named
///   something inapplicable. Auditing these as `DENY` would fill the trail an investigator reads
///   with rows that are not refusals, which is noise `ENC-606` was careful not to add.
///
/// # The cost of the first branch, stated rather than worked around
///
/// An audited refusal is answered `ACCESS_DENIED`, not the specific code the conflict branch gets.
/// That is deliberate: `crates/api/src/refusal.rs` holds that the code the caller is given and the
/// code the row carries *are the same value by construction, which is what stops the auditor and
/// the refused user reading different words* — and [`ReasonCode`] is a closed vocabulary inside
/// `crates/audit`'s canonically hashed bytes, so widening it changes what tamper evidence covers
/// and is not this task's to do.
///
/// So a client cannot distinguish *not your step* from *you started this workflow*, and that is a
/// real usability cost on a surface where the second has an obvious next step. It is recorded in
/// `ENC-745` rather than paid for by minting a divergence the codebase explicitly warns against.
const fn is_authorization_refusal(refusal: Refusal) -> bool {
    match refusal {
        Refusal::NotTheHolder
        | Refusal::SelfApproval
        | Refusal::DelegationForbidden
        | Refusal::AlreadyDelegated
        | Refusal::NotCancellable => true,

        Refusal::StepNotOpen
        | Refusal::InstanceNotRunning
        | Refusal::StageNotOpen
        | Refusal::WrongStepType
        | Refusal::DelegateIsHolder
        | Refusal::DelegateNotEntitled
        | Refusal::VersionSuperseded
        | Refusal::OutOfScope
        | Refusal::DefinitionDisabled => false,
    }
}

/// How an authorization refusal is recorded.
///
/// [`Refused::actor`] for all five, because every one of them is a statement about *the principal*:
/// they are not the one being asked, or they are the one who asked. That is exactly what
/// [`crate::refusal::Control::ActorEligibility`] names — *the principal is not one this operation
/// can be performed by* — and it is what an investigator reading `policy_refs = handler:actor` will
/// be looking for.
///
/// A function returning [`Refused`] rather than an inline construction, and not only because
/// `xtask audit-coverage` reads the shape: the mapping from *which refusal* to *what the row says*
/// is one decision, and it belongs in one place where it can be changed once.
fn recorded_as(_refusal: Refusal) -> Refused {
    Refused::actor(ReasonCode::AccessDenied)
}

/// Turns a [`WorkflowError`] into the caller's response, auditing it first where it is a denial.
///
/// **The single conversion**, so the audit row and the caller's code cannot disagree and a handler
/// cannot invent a second mapping. `ENC-606`: `Refused` has private fields and no conversion into
/// an error, so `HandlerAudit::refuse` is the only way one becomes an `ApiError`, and it writes the
/// `DENY` row before it does.
///
/// A [`WorkflowError`] that is neither a refusal nor a conflict — a database failure, an
/// undecodable stored row — is not a policy answer and is rendered as the fault it is.
async fn refuse(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
    error: WorkflowError,
) -> Result<Response, ApiError> {
    match error {
        WorkflowError::Refused(refusal) if is_authorization_refusal(refusal) => {
            Err(state.audit.refuse(ctx, action, resource, recorded_as(refusal)).await)
        }
        WorkflowError::Refused(refusal) => {
            Ok(refusal_envelope(refusal).into_response(ctx.request_id))
        }
        other => Err(workflow_fault(other, ctx.request_id)),
    }
}

/// The `docs/05-API.md §5` envelope for one refusal.
///
/// One arm per variant, exhaustively, so a new refusal breaks this and forces somebody to decide
/// what the caller is told — `crates/api/src/error.rs::user_message`'s argument.
fn refusal_envelope(refusal: Refusal) -> Envelope {
    let (status, code, message, remediation) = match refusal {
        Refusal::NotTheHolder => (
            StatusCode::FORBIDDEN,
            "NOT_STEP_ASSIGNEE",
            "This step is not yours to act on.",
            "Only the person the step is assigned to, or their delegate, can decide it.",
        ),
        Refusal::StepNotOpen => (
            StatusCode::CONFLICT,
            "STEP_NOT_OPEN",
            "This step has already been decided.",
            "Re-read the workflow to see its current state.",
        ),
        Refusal::InstanceNotRunning => (
            StatusCode::CONFLICT,
            "WORKFLOW_NOT_RUNNING",
            "This workflow is no longer running.",
            "Re-read the workflow to see how it ended.",
        ),
        Refusal::StageNotOpen => (
            StatusCode::CONFLICT,
            "STAGE_NOT_OPEN",
            "This step's stage has not started yet.",
            "Wait for the earlier stages to finish.",
        ),
        Refusal::SelfApproval => (
            StatusCode::FORBIDDEN,
            "SELF_APPROVAL_NOT_PERMITTED",
            "You cannot approve a workflow you started.",
            "Ask another approver, or delegate the step to somebody else.",
        ),
        Refusal::WrongStepType => (
            StatusCode::CONFLICT,
            "WRONG_STEP_TYPE",
            "This step does not take that decision.",
            "A review cannot be rejected, and a signature is made through the signing flow.",
        ),
        Refusal::DelegationForbidden => (
            StatusCode::FORBIDDEN,
            "DELEGATION_NOT_PERMITTED",
            "This workflow does not allow steps to be handed on.",
            "Decide the step yourself, or ask an owner to cancel the workflow.",
        ),
        Refusal::AlreadyDelegated => (
            StatusCode::CONFLICT,
            "ALREADY_DELEGATED",
            "This step has already been handed on once, and cannot be handed on again.",
            "Ask the current holder to decide it.",
        ),
        Refusal::DelegateIsHolder => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DELEGATE_IS_HOLDER",
            "That person already holds this step.",
            "Choose somebody else.",
        ),
        Refusal::DelegateNotEntitled => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DELEGATE_NOT_ELIGIBLE",
            "That person cannot see the file this step is about.",
            "Choose somebody with access to the file, or grant them access first.",
        ),
        Refusal::VersionSuperseded => (
            StatusCode::CONFLICT,
            "VERSION_SUPERSEDED",
            "A newer version was published, so this approval no longer applies.",
            "Start the workflow again on the current version.",
        ),
        Refusal::NotCancellable => (
            StatusCode::FORBIDDEN,
            "NOT_WORKFLOW_OWNER",
            "Only the person who started this workflow, or an owner of the file, can cancel it.",
            "Ask one of them to cancel it.",
        ),
        Refusal::OutOfScope => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEFINITION_OUT_OF_SCOPE",
            "This workflow is not available for this file.",
            "Choose a workflow defined for this file's library or workspace.",
        ),
        Refusal::DefinitionDisabled => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEFINITION_DISABLED",
            "This workflow is switched off.",
            "Ask an administrator to enable it.",
        ),
    };
    Envelope::new(status, code, message, remediation)
}

/// Renders a `ACCESS_DENIED` denial on a read path as [`Error::NotFound`].
///
/// `crates/api/src/content.rs`'s function, repeated here rather than shared, because sharing it
/// would mean making it `pub(crate)` in a module that documents it as *the one place the 403/404
/// decision is made* for the read paths. Two copies of four lines are cheaper than one function
/// whose documentation is wrong about its own scope.
fn existence_gate(error: Error) -> Error {
    match error {
        Error::PolicyDenied { code: ReasonCode::AccessDenied, .. } => Error::NotFound,
        other => other,
    }
}

/// A fault, never a policy answer.
fn workflow_fault(error: WorkflowError, request_id: RequestId) -> ApiError {
    match error {
        WorkflowError::Db(db) => api(db.into(), request_id),
        other => {
            tracing::error!(%request_id, %other, "a workflow row or document is not usable");
            api(Error::Internal(anyhow::anyhow!("a workflow row is not usable")), request_id)
        }
    }
}

/// Renders a write failure, mapping the idempotency violation to the `409` it is.
///
/// `docs/15 §5`: *trigger evaluation is idempotent on `(definition_id, resource_id, version_id)`,
/// so a redelivered event cannot start a duplicate instance.* `uq_workflow_instances_trigger` is
/// what enforces that, and it is reported rather than swallowed: a caller who double-clicks learns
/// that the workflow already exists instead of getting a second one. `docs/15 §12` W4.
fn workflow_write(error: WorkflowError, request_id: RequestId) -> Result<Response, ApiError> {
    if let WorkflowError::Db(enclave_db::DbError::Query(ref source)) = error {
        if let Some(constraint) = source.as_database_error().and_then(|e| e.constraint()) {
            if constraint == "uq_workflow_instances_trigger" {
                return Ok(Envelope::new(
                    StatusCode::CONFLICT,
                    "WORKFLOW_ALREADY_RUNNING",
                    "This workflow is already running on this version of the file.",
                    "Open the existing workflow instead of starting a second one.",
                )
                .into_response(request_id));
            }
        }
    }
    Err(workflow_fault(error, request_id))
}

/// Parses a path or body identifier, answering `404` rather than `400` for a malformed one.
///
/// A malformed id and an id for a row that does not exist are the same thing to a caller who is not
/// entitled to know either way, and `crates/api/src/content.rs` answers both with `NotFound` for
/// that reason.
fn parse_id<T: FromStr>(raw: &str, request_id: RequestId) -> Result<T, ApiError> {
    raw.trim().parse::<T>().map_err(|_| api(Error::NotFound, request_id))
}

fn api(error: Error, request_id: RequestId) -> ApiError {
    ApiError::new(error, request_id)
}

fn missing(field: &'static str, message: &'static str) -> Envelope {
    Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VALIDATION_FAILED",
        message,
        "Supply it and retry.",
    )
    .with_details(vec![serde_json::json!({
        "field": field,
        "code": ValidationCode::Required.as_str(),
    })])
}

fn not_found(field: &'static str, message: &'static str) -> Envelope {
    Envelope::new(StatusCode::NOT_FOUND, "NOT_FOUND", message, "Check the identifier.")
        .with_details(vec![serde_json::json!({ "field": field })])
}

fn rejected(field: &'static str, detail: &str) -> Envelope {
    Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEFINITION_REJECTED",
        "The workflow definition could not be used.",
        "Correct the definition and retry.",
    )
    .with_details(vec![serde_json::json!({ "field": field, "detail": clip(detail) })])
}

fn unreadable_body(error: &serde_json::Error) -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "MALFORMED_BODY",
        "The request body could not be read.",
        "Send a JSON object matching the documented shape.",
    )
    .with_details(vec![serde_json::json!({ "detail": clip(&error.to_string()) })])
}

/// The longest decoder message that reaches a caller.
///
/// serde quotes the offending name, and the offending name came from the request
/// (`crates/api/src/admin/dlp.rs`).
const MAX_DETAIL_CHARS: usize = 240;

fn clip(text: &str) -> String {
    text.chars().take(MAX_DETAIL_CHARS).collect()
}

// --- Operator log lines -------------------------------------------------------------------------
//
// Not the audit trail. Audit happens inside the policy engine, for denials as well as allows
// (`CLAUDE.md` rule 10), and the engine has already written the row for each of these actions.
// These add what the audit row cannot carry: which workflow, which step, and who acted on whose
// behalf — `docs/15 §4`'s `acted_on_behalf_of`, which the row's closed vocabulary has no field for.

fn started(ctx: &RequestContext, instance: WorkflowInstanceId, file: FileId) {
    tracing::info!(
        %ctx.request_id, %ctx.tenant_id, actor = ?ctx.actor.kind(),
        %instance, %file, "workflow started"
    );
}

fn decided(ctx: &RequestContext, step: WorkflowStepId, actor: UserId, decision: Decision) {
    tracing::info!(
        %ctx.request_id, %ctx.tenant_id, %step, %actor, ?decision,
        "workflow step decided"
    );
}

fn delegated(ctx: &RequestContext, step: WorkflowStepId, from: UserId, to: UserId) {
    tracing::info!(
        %ctx.request_id, %ctx.tenant_id, %step, %from, %to,
        "workflow step delegated — acted_on_behalf_of is now recorded on the row"
    );
}

fn superseded(ctx: &RequestContext, instance: WorkflowInstanceId) {
    tracing::warn!(
        %ctx.request_id, %ctx.tenant_id, %instance,
        "a workflow was expired because the version under review was superseded (docs/15 §2.1)"
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_refusal_has_its_own_wire_code() {
        // A shared code would make two different refusals indistinguishable to a client that has to
        // offer a next step — `SELF_APPROVAL_NOT_PERMITTED` suggests delegating, `NOT_STEP_ASSIGNEE`
        // suggests nothing at all, and a client cannot tell them apart from one word.
        let refusals = [
            Refusal::NotTheHolder,
            Refusal::StepNotOpen,
            Refusal::InstanceNotRunning,
            Refusal::StageNotOpen,
            Refusal::SelfApproval,
            Refusal::WrongStepType,
            Refusal::DelegationForbidden,
            Refusal::AlreadyDelegated,
            Refusal::DelegateIsHolder,
            Refusal::DelegateNotEntitled,
            Refusal::VersionSuperseded,
            Refusal::NotCancellable,
            Refusal::OutOfScope,
            Refusal::DefinitionDisabled,
        ];
        let mut codes: Vec<&'static str> =
            refusals.iter().map(|r| refusal_envelope(*r).code()).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "two refusals share a wire code: {codes:?}");
    }

    #[test]
    fn a_refusal_about_holdership_is_403_and_never_404() {
        // `CLAUDE.md` rule 7 cuts the other way here, and the distinction is deliberate: a caller
        // who has already passed the chain for `file.content_read` can see the file, so the step's
        // existence is not a secret from them. Answering `404` would make "not your approval" and
        // "no such approval" indistinguishable, which is an inbox nobody can debug.
        assert_eq!(refusal_envelope(Refusal::NotTheHolder).status(), StatusCode::FORBIDDEN);
        assert_eq!(refusal_envelope(Refusal::SelfApproval).status(), StatusCode::FORBIDDEN);
        assert_eq!(refusal_envelope(Refusal::NotCancellable).status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_delegate_refusal_names_the_field_a_client_can_change() {
        let envelope = refusal_envelope(Refusal::DelegateNotEntitled);
        assert_eq!(envelope.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(envelope.code(), "DELEGATE_NOT_ELIGIBLE");
    }

    #[test]
    fn a_missing_reason_names_the_field_rather_than_the_rule() {
        let envelope = missing("reason", "A cancellation must say why.");
        assert_eq!(envelope.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            envelope.details().first().and_then(|d| d.get("field")).and_then(|f| f.as_str()),
            Some("reason")
        );
    }

    #[test]
    fn the_start_and_simulate_bodies_are_strict() {
        // `ENC-615`'s finding at a third boundary: a lenient body accepts a field and drops it, and
        // the field somebody added is the one they cared about.
        assert!(serde_json::from_str::<StartRequest>(
            r#"{"definitionId":"x","allowSelfApproval":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SimulateRequest>(r#"{"fileId":"x","apply":true}"#).is_err());
        assert!(serde_json::from_str::<DelegateRequest>(
            r#"{"toUserId":"x","reason":"y","onward":true}"#
        )
        .is_err());
    }

    #[test]
    fn a_delegation_body_without_a_reason_does_not_decode() {
        // `docs/15 §4`: never a silent substitution. A reason that could be omitted is a
        // substitution with a row and no explanation.
        assert!(serde_json::from_str::<DelegateRequest>(r#"{"toUserId":"x"}"#).is_err());
        assert!(serde_json::from_str::<CancelRequest>("{}").is_err());
    }

    #[test]
    fn an_approval_body_may_be_absent_entirely() {
        // The comment is optional on an approval and required on a rejection, and the requirement
        // is enforced in `decide` rather than by the type, because one type serves both.
        let decoded: DecisionRequest = serde_json::from_str("{}").expect("an empty body");
        assert!(decoded.comment.is_none());
    }

    #[test]
    fn the_three_actions_are_distinct_and_none_of_them_is_metadata_for_a_decision() {
        // The table in the module header, asserted. Authorizing a decision as a metadata action
        // would let somebody who can see a contract's *name* approve its contents.
        assert_eq!(DECIDE_ACTION, Action::File(FileAction::ContentRead));
        assert_eq!(GOVERN_ACTION, Action::File(FileAction::Edit));
        assert_ne!(DECIDE_ACTION, READ_ACTION);
        assert_ne!(GOVERN_ACTION, READ_ACTION);
    }

    #[test]
    fn simulate_and_start_are_authorized_identically() {
        // D28's requirement expressed as the only thing a unit test can reach: the two handlers
        // name one constant. A cheaper action for `simulate` would let somebody rehearse a workflow
        // they could not run, and the rehearsal would answer `yes` where the real thing answers
        // `no` — which is precisely "measuring something other than what enforcement will do".
        //
        // The behavioural half is `crates/api/tests/workflows.rs`.
        // `include_str!`, not `std::fs::read_to_string(file!())`: `file!()` is workspace-relative
        // and a test's working directory is the crate's, so the runtime read finds nothing.
        // `crates/versions/src/commit.rs` reads its own source the same way and for the same
        // reason — the property is about the *shape* of the code, which no behavioural test can
        // see, because a `simulate` that quietly enforced a weaker action would still return `200`
        // to every caller entitled to both.
        let start = include_str!("workflows.rs");
        let simulate_body = start
            .split_once("pub async fn simulate(")
            .and_then(|(_, rest)| rest.split_once("\npub async fn "))
            .map(|(body, _)| body)
            .expect("the simulate handler");
        assert!(
            simulate_body.contains("GOVERN_ACTION"),
            "simulate no longer enforces the action a real start enforces"
        );
        assert!(
            !simulate_body.contains("repo::apply"),
            "simulate now applies a plan, which is the mutation it exists not to perform"
        );
        assert!(
            simulate_body.contains("plan_start_for"),
            "simulate no longer calls the evaluator a real start calls, so the two can diverge"
        );
    }
}

// =================================================================================================
// Definitions — `ENC-965`
// =================================================================================================

/// Authoring a workflow is changing tenant policy, not editing a document.
///
/// `AdminAction::ManagePolicy`, the same action DLP rules, conditional-access rules and retention
/// policies are written under. A definition decides *whose approval a document needs before it is
/// published*, which is a rule about the tenant rather than a property of any file — and scoping it
/// to a file action would let anybody who can edit one document write a rule governing every
/// document in the library it names.
const AUTHOR_DEFINITION: Action = Action::Admin(enclave_core::AdminAction::ManagePolicy);

/// Reading the list is `ReadConfig`, as the sibling admin surfaces are.
const READ_DEFINITIONS: Action = Action::Admin(enclave_core::AdminAction::ReadConfig);

/// How many definitions one page returns.
const DEFINITION_PAGE: i64 = 200;

/// A definition as an author submits one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DefinitionRequest {
    name: String,
    /// `TENANT`, `WORKSPACE` or `LIBRARY`.
    scope_type: String,
    #[serde(default)]
    scope_id: Option<uuid::Uuid>,
    /// The stages document, decoded by `enclave_workflows::WorkflowDefinition` before it is stored.
    definition: serde_json::Value,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    allow_self_approval: bool,
    #[serde(default = "delegation_default")]
    delegation: String,
    #[serde(default = "on_new_version_default")]
    on_new_version: String,
}

const fn enabled_by_default() -> bool {
    true
}
fn delegation_default() -> String {
    "ONCE".to_owned()
}
fn on_new_version_default() -> String {
    "INVALIDATE".to_owned()
}

/// A definition as the listing returns it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionView {
    id: String,
    name: String,
    scope_type: String,
    scope_id: Option<String>,
    version: i32,
    enabled: bool,
    created_at: chrono::DateTime<Utc>,
}

/// The listing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefinitionList {
    items: Vec<DefinitionView>,
}

/// Handles `POST /api/v1/workflows/definitions`.
///
/// # The writer this table has never had
///
/// `workflow_definitions` has existed since `migrations/0024` and its only writer in the whole tree
/// was a test fixture. Everything downstream — the engine, `approve`, `reject`, `delegate` and the
/// inbox at `GET /workflows/tasks` — was reachable and permanently idle, because a start names a
/// definition and no definition could exist.
///
/// # The document is decoded before it is stored, and that is the point
///
/// `WorkflowDefinition::decode` runs the validation `crates/workflows/src/definition.rs` owns —
/// non-empty stages, a resolvable assignee on every step, a quorum no smaller than one and no
/// larger than the assignee set. A document that reached storage undecoded would be a definition
/// the *engine* rejects at start time, which turns an author's mistake into a runtime failure for
/// whoever tries to use it.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure. A rejected document
/// is a `422` envelope in the `Ok` arm, carrying the decoder's own sentence — *"unknown variant
/// `AUTOMATION`"* tells an author what to change.
pub async fn create_definition(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let resource = ResourceRef::tenant(ctx.tenant_id);

    let decision = state
        .policy
        .enforce(&ctx, AUTHOR_DEFINITION, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, AUTHOR_DEFINITION, &resource, refused).await);
    }
    if let Err(envelope) = crate::admin::require_step_up(&ctx, state.step_up, "workflow.definition")
    {
        return Ok(envelope.into_response(request_id));
    }
    let author = match attributable_actor(&ctx) {
        Ok(author) => author,
        Err(refused) => {
            return Err(state.audit.refuse(&ctx, AUTHOR_DEFINITION, &resource, refused).await)
        }
    };

    let request: DefinitionRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Envelope::new(
                StatusCode::BAD_REQUEST,
                "VALIDATION_FAILED",
                "That workflow definition could not be read.",
                "Correct the body and retry.",
            )
            .with_details(vec![serde_json::json!({ "detail": error.to_string() })])
            .into_response(request_id))
        }
    };

    let Some(scope) = scope_from(&request.scope_type, request.scope_id) else {
        return Ok(Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "That scope is not one this schema defines.",
            "Use TENANT with no scopeId, or WORKSPACE or LIBRARY with one.",
        )
        .into_response(request_id));
    };

    // Decoded here, before storage. See the doc comment.
    if let Err(error) = enclave_workflows::WorkflowDefinition::decode(&request.definition) {
        return Ok(Envelope::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEFINITION_REJECTED",
            "That workflow definition is not one this engine can run.",
            "Correct the stages the detail names and retry.",
        )
        .with_details(vec![serde_json::json!({ "detail": error.to_string() })])
        .into_response(request_id));
    }

    let new = enclave_workflows::repo::NewDefinition {
        id: enclave_workflows::WorkflowDefinitionId::new_v7(),
        scope,
        name: request.name.trim().to_owned(),
        definition: request.definition,
        enabled: request.enabled,
        allow_self_approval: request.allow_self_approval,
        delegation: request.delegation,
        on_new_version: request.on_new_version,
        created_by: author,
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    if let Err(error) = enclave_workflows::repo::insert_definition(&mut tx, &new).await {
        return Ok(Envelope::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEFINITION_REJECTED",
            "That workflow definition is not one this schema allows.",
            "Correct the field the detail names and retry.",
        )
        .with_details(vec![serde_json::json!({ "detail": error.to_string() })])
        .into_response(request_id));
    }
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        definition_id = %new.id,
        scope = new.scope.columns().0,
        "a workflow definition was written"
    );

    let location = format!("/api/v1/workflows/definitions/{}", new.id);
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        [(header::LOCATION, location)],
        Json(DefinitionView {
            id: new.id.to_string(),
            name: new.name,
            scope_type: new.scope.columns().0.to_owned(),
            scope_id: new.scope.columns().1.map(|id| id.to_string()),
            version: 1,
            enabled: new.enabled,
            created_at: Utc::now(),
        }),
    )
        .into_response())
}

/// Handles `GET /api/v1/workflows/definitions`.
///
/// The stages document is deliberately not returned — see
/// `enclave_workflows::repo::list_definitions`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or a database failure.
pub async fn list_definitions(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let resource = ResourceRef::tenant(ctx.tenant_id);

    let decision = state
        .policy
        .enforce(&ctx, READ_DEFINITIONS, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, READ_DEFINITIONS, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let rows = enclave_workflows::repo::list_definitions(&mut tx, DEFINITION_PAGE)
        .await
        .map_err(|error| workflow_fault(error, request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let items = rows
        .into_iter()
        .map(|row| DefinitionView {
            id: row.id.to_string(),
            name: row.name,
            scope_type: row.scope_type,
            scope_id: row.scope_id.map(|id| id.to_string()),
            version: row.version,
            enabled: row.enabled,
            created_at: row.created_at,
        })
        .collect();

    // `no-store`: a shared cache holding this would serve one tenant's approval rules out of a
    // proxy another caller's browser talked to.
    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(DefinitionList { items })).into_response())
}

/// Reads the stored `(scope_type, scope_id)` pair back into a [`Scope`].
///
/// `None` for a pair the schema's `workflow_definitions_scope_target` constraint would refuse
/// anyway — a `TENANT` naming something, or any other scope naming nothing. Checked here so the
/// caller meets a `400` that says which field, rather than a constraint violation.
fn scope_from(scope_type: &str, scope_id: Option<uuid::Uuid>) -> Option<enclave_workflows::Scope> {
    match (scope_type, scope_id) {
        ("TENANT", None) => Some(enclave_workflows::Scope::Tenant),
        ("WORKSPACE", Some(id)) => Some(enclave_workflows::Scope::Workspace(id)),
        ("LIBRARY", Some(id)) => Some(enclave_workflows::Scope::Library(id)),
        _ => None,
    }
}
