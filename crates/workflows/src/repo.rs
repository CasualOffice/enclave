//! The only code in this crate that touches a database.
//!
//! `enclave-db`'s own header asks for this arrangement — *no repositories; table-shaped access
//! belongs in the domain crate that owns the table* — so the statements live here, over that
//! crate's [`TenantScoped`] guard, in the runtime-checked form `CLAUDE.md`'s Rust conventions
//! require (no `sqlx::query!` in a domain crate).
//!
//! # Every statement writes its own `tenant_id` predicate
//!
//! Row-level security would enforce it anyway. `enclave-db`'s header says why both layers exist:
//! *application predicates cannot be proven complete across a codebase — one missing `WHERE` is a
//! leak, and no test can demonstrate the absence of a missing predicate. RLS is complete but
//! depends on a session variable being right.* A leak needs both to fail.
//!
//! The honest note that six prior sessions in this repository have had to write, and which belongs
//! here rather than in a report nobody reads: **deleting the `tenant_id` predicate from a statement
//! below will not fail a cross-tenant integration test**, because RLS holds that property alone.
//! What such a test proves is the isolation of the *path*. The predicates are held by
//! `the_statements_all_scope_by_tenant` at the bottom of this file, which reads the SQL, and the
//! authorization claims are held by same-tenant tests where a caller without the grant is refused.
//!
//! # The one statement whose shape is a control
//!
//! [`delegate`] is `UPDATE … SET delegated_to = $x WHERE … AND delegated_to IS NULL`. One
//! statement, so two delegations racing each other are resolved by PostgreSQL rather than by a
//! read-then-write in which both sides read `NULL` and both write. It reports how many rows it
//! changed, and zero is the loser of that race — surfaced as [`Refusal::AlreadyDelegated`], the
//! same answer the predicate in `crates/workflows/src/authority.rs` gives. `ENC-740`, and
//! `plans/M4-GOVERNANCE.md` D31's shape: the bound is enforced in the same statement as the write.

use chrono::{DateTime, Utc};
use enclave_core::id::{FileId, UserId, VersionId};
use enclave_db::ids::{sql, RowIdExt as _};
use enclave_db::{DbError, TenantScoped};
use sqlx::Row as _;
use uuid::Uuid;

use crate::definition::{Delegation, OnNewVersion, Quorum, Scope, StepType, WorkflowPolicy};
use crate::error::{Refusal, WorkflowError};
use crate::facts::{DefinitionFacts, InstanceFacts, ResourceFacts, StepFacts};
use crate::ids::{WorkflowDefinitionId, WorkflowInstanceId, WorkflowStepId};
use crate::plan::{Effect, NewInstance, NewStep, Plan};
use crate::state::{InstanceState, StepState};

/// The most steps one caller may have waiting on them in a single page.
///
/// `docs/05-API.md §6` fixes the ceiling at 500 for a listing; a task inbox is bounded far lower on
/// purpose, because every row returned costs an authorization decision in the trim
/// (`crates/api/src/workflows.rs`) and an inbox that needs a hundred rows to be useful is an inbox
/// nobody is reading anyway.
pub const MAX_TASKS: i64 = 100;

/// Applies a plan.
///
/// The counterpart to [`crate::evaluate`], and the division between them is the point: the
/// evaluator decides and cannot write, this writes and decides nothing. A statement here that
/// consulted a rule would be the second code path `plans/M4-GOVERNANCE.md` D28 forbids.
///
/// # Errors
///
/// [`WorkflowError::Db`] for any statement failure, and [`Refusal::AlreadyDelegated`] for the lost
/// half of a delegation race — see the module header.
pub async fn apply(tx: &mut TenantScoped, plan: &Plan) -> Result<(), WorkflowError> {
    for effect in plan.effects() {
        match effect {
            Effect::CreateInstance(instance) => insert_instance(tx, instance).await?,
            Effect::CreateStep(step) => insert_step(tx, step).await?,
            Effect::DecideStep { step, state, decided_by, comment, at } => {
                decide(tx, *step, *state, *decided_by, comment.as_deref(), *at).await?;
            }
            Effect::SkipStep { step } => skip(tx, *step).await?,
            Effect::OpenStage { instance, stage } => open_stage(tx, *instance, *stage).await?,
            Effect::FinishInstance { instance, state, reason, at } => {
                finish(tx, *instance, *state, reason.as_deref(), *at).await?;
            }
            Effect::Delegate { step, to, reason, at } => {
                delegate(tx, *step, *to, reason, *at).await?;
            }
        }
    }
    Ok(())
}

// --- Writes ---------------------------------------------------------------------------------------

const INSERT_INSTANCE: &str = "\
    INSERT INTO workflow_instances
      (tenant_id, id, definition_id, definition_version, resource_id, version_id, state,
       current_stage, started_by, started_at, allow_self_approval, delegation, on_new_version)
    VALUES ($1, $2, $3, $4, $5, $6, 'RUNNING', 0, $7, $8, $9, $10, $11)";

async fn insert_instance(tx: &mut TenantScoped, instance: &NewInstance) -> Result<(), DbError> {
    sqlx::query(INSERT_INSTANCE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(instance.id))
        .bind(sql(instance.definition_id))
        .bind(instance.definition_version)
        .bind(sql(instance.resource))
        .bind(sql(instance.version))
        .bind(sql(instance.started_by))
        .bind(instance.started_at)
        .bind(instance.policy.allow_self_approval)
        .bind(instance.policy.delegation.as_str())
        .bind(instance.policy.on_new_version.as_str())
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

const INSERT_STEP: &str = "\
    INSERT INTO workflow_steps
      (tenant_id, id, instance_id, stage, position, step_type, assignee_id, state, config)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";

async fn insert_step(tx: &mut TenantScoped, step: &NewStep) -> Result<(), DbError> {
    // The quorum and the stage name, frozen onto the row. See `facts.rs`: the evaluator reads these
    // and never re-reads `workflow_definitions`, which is what makes an in-flight instance immune
    // to a template edit.
    let config = serde_json::json!({
        "quorum": step.quorum,
        "stageName": step.stage_name,
    });

    sqlx::query(INSERT_STEP)
        .bind(sql(tx.tenant_id()))
        .bind(sql(step.id))
        .bind(sql(step.instance))
        .bind(step.stage)
        .bind(step.position)
        .bind(step.step_type.as_str())
        .bind(sql(step.assignee))
        .bind(step.state.as_str())
        .bind(config)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Records a decision.
///
/// `WHERE state IN ('PENDING','ASSIGNED')` is not belt-and-braces over the evaluator's check: it is
/// what makes the decision *atomic*. Two approvals of one step racing each other both pass
/// `may_decide` against the same snapshot; this predicate is what makes exactly one of them write.
const DECIDE_STEP: &str = "\
    UPDATE workflow_steps
       SET state = $3, decided_by = $4, decision_at = $5, comment = $6
     WHERE tenant_id = $1 AND id = $2 AND state IN ('PENDING','ASSIGNED')";

async fn decide(
    tx: &mut TenantScoped,
    step: WorkflowStepId,
    state: StepState,
    decided_by: UserId,
    comment: Option<&str>,
    at: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query(DECIDE_STEP)
        .bind(sql(tx.tenant_id()))
        .bind(sql(step))
        .bind(state.as_str())
        .bind(sql(decided_by))
        .bind(at)
        .bind(comment)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Releases a step nobody now needs to answer.
///
/// `WHERE state IN ('PENDING','ASSIGNED')` again, and here it carries the property the cancel path
/// is arranged around: **a step that has already been decided is not touched.** Cancelling a
/// workflow ends what is happening; it does not erase the record that a named person approved
/// something. `workflow_steps_decision_complete` would refuse the alternative anyway — a step
/// cannot leave `APPROVED` while keeping its decider — but the predicate is what means the question
/// never arises.
const SKIP_STEP: &str = "\
    UPDATE workflow_steps
       SET state = 'SKIPPED'
     WHERE tenant_id = $1 AND id = $2 AND state IN ('PENDING','ASSIGNED')";

async fn skip(tx: &mut TenantScoped, step: WorkflowStepId) -> Result<(), DbError> {
    sqlx::query(SKIP_STEP)
        .bind(sql(tx.tenant_id()))
        .bind(sql(step))
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

const OPEN_STAGE: &str = "\
    UPDATE workflow_steps
       SET state = 'ASSIGNED'
     WHERE tenant_id = $1 AND instance_id = $2 AND stage = $3 AND state = 'PENDING'";

const ADVANCE_INSTANCE: &str = "\
    UPDATE workflow_instances
       SET current_stage = $3, revision = revision + 1
     WHERE tenant_id = $1 AND id = $2 AND state = 'RUNNING'";

async fn open_stage(
    tx: &mut TenantScoped,
    instance: WorkflowInstanceId,
    stage: i32,
) -> Result<(), DbError> {
    sqlx::query(OPEN_STAGE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(instance))
        .bind(stage)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    sqlx::query(ADVANCE_INSTANCE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(instance))
        .bind(stage)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Moves the instance to a terminal state.
///
/// `WHERE state = 'RUNNING'` so a second terminal transition cannot overwrite the first: a
/// `COMPLETED` instance must not become `CANCELLED` because a cancel request arrived a moment late.
const FINISH_INSTANCE: &str = "\
    UPDATE workflow_instances
       SET state = $3, outcome_reason = $4, completed_at = $5, revision = revision + 1
     WHERE tenant_id = $1 AND id = $2 AND state = 'RUNNING'";

async fn finish(
    tx: &mut TenantScoped,
    instance: WorkflowInstanceId,
    state: InstanceState,
    reason: Option<&str>,
    at: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query(FINISH_INSTANCE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(instance))
        .bind(state.as_str())
        .bind(reason)
        .bind(at)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// Hands a step on, at most once.
///
/// **The `delegated_to IS NULL` predicate is the third layer of `ENC-740`'s bound**, and the only
/// one that survives concurrency: the vocabulary makes an onward chain unstorable, the predicate in
/// `authority.rs` refuses one against a snapshot, and this makes two simultaneous delegations
/// resolve to one. Zero rows changed is the loser, and it is reported as the same refusal the
/// snapshot check gives rather than as a success that wrote nothing.
const DELEGATE_STEP: &str = "\
    UPDATE workflow_steps
       SET delegated_to = $3, delegated_at = $4, delegation_reason = $5
     WHERE tenant_id = $1 AND id = $2
       AND delegated_to IS NULL
       AND state IN ('PENDING','ASSIGNED')";

async fn delegate(
    tx: &mut TenantScoped,
    step: WorkflowStepId,
    to: UserId,
    reason: &str,
    at: DateTime<Utc>,
) -> Result<(), WorkflowError> {
    let result = sqlx::query(DELEGATE_STEP)
        .bind(sql(tx.tenant_id()))
        .bind(sql(step))
        .bind(sql(to))
        .bind(at)
        .bind(reason)
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    if result.rows_affected() == 0 {
        return Err(Refusal::AlreadyDelegated.into());
    }
    Ok(())
}

// --- Reads ----------------------------------------------------------------------------------------

const LOAD_DEFINITION: &str = "\
    SELECT id, version, scope_type, scope_id, enabled, allow_self_approval, delegation,
           on_new_version, definition
      FROM workflow_definitions
     WHERE tenant_id = $1 AND id = $2";

/// Reads one definition.
///
/// # Errors
///
/// [`WorkflowError::Db`], or [`WorkflowError::Stored`] if the row does not decode.
/// A definition as an author submits one.
///
/// A separate type from [`DefinitionFacts`], which is what the engine reads: this one has been
/// validated against nothing but its own shape, and the four `CHECK` constraints in
/// `migrations/0024` are what it must survive. Keeping them apart means a handler cannot pass a
/// half-built row where a stored one is expected.
#[derive(Debug, Clone)]
pub struct NewDefinition {
    /// Identifier the caller minted, so the row it gets back is the row it named.
    pub id: WorkflowDefinitionId,
    /// Where it may be started.
    pub scope: Scope,
    /// What an author calls it.
    pub name: String,
    /// The document, already decoded once by the handler so a malformed one never reaches storage.
    pub definition: serde_json::Value,
    /// Whether a start may name it.
    pub enabled: bool,
    /// Whether the person who started an instance may approve their own step.
    pub allow_self_approval: bool,
    /// `FORBIDDEN` or `ONCE`.
    pub delegation: String,
    /// `INVALIDATE` or `CONTINUE`.
    pub on_new_version: String,
    /// Who wrote it. `NOT NULL` with a composite key onto `users`, because *"the system"* is not an
    /// answer to *"who decided this document needs two approvals"*.
    pub created_by: UserId,
}

/// Writes a definition at version 1 (`ENC-965`).
///
/// # Nothing could write one of these before
///
/// `workflow_definitions` has been in the schema since `migrations/0024` and its only writer in the
/// whole tree was a **test fixture**. `docs/05 §16` specifies `GET|POST /workflows/definitions`;
/// neither was registered. So the workflow engine, its evaluator, `approve`, `reject`, `delegate`
/// and the inbox at `GET /workflows/tasks` were all reachable and all permanently idle — a start
/// names a definition, and no definition could exist.
///
/// **Version 1, and versioning is deliberately not implemented here.** `docs/15 §2` says a
/// definition is versioned and an instance pins the version it started under, which means an edit
/// is a *new row at version n+1* and not an `UPDATE` — the instances already running must go on
/// reading the document they began with. That is `PATCH`'s design and it is `ENC-966`; writing a
/// first version is what unblocks everything else, and pretending to support edits by mutating the
/// row in place would silently rewrite the rules under every running approval.
///
/// # Errors
///
/// [`WorkflowError`] wrapping the query failure, including the four `CHECK` constraints and the
/// composite foreign key onto `users`.
pub async fn insert_definition(
    tx: &mut TenantScoped,
    new: &NewDefinition,
) -> Result<(), WorkflowError> {
    let (scope_type, scope_id) = new.scope.columns();
    sqlx::query(INSERT_DEFINITION)
        .bind(sql(tx.tenant_id()))
        .bind(sql(new.id))
        .bind(scope_type)
        .bind(scope_id)
        .bind(&new.name)
        .bind(&new.definition)
        .bind(new.enabled)
        .bind(new.allow_self_approval)
        .bind(&new.delegation)
        .bind(&new.on_new_version)
        .bind(sql(new.created_by))
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(())
}

/// One definition as a listing returns it.
#[derive(Debug, Clone)]
pub struct DefinitionSummary {
    /// Identifier.
    pub id: WorkflowDefinitionId,
    /// What it is called.
    pub name: String,
    /// Where it may be started.
    pub scope_type: String,
    /// The workspace or library named, or `None` for a tenant scope.
    pub scope_id: Option<Uuid>,
    /// Which version this row is.
    pub version: i32,
    /// Whether a start may name it.
    pub enabled: bool,
    /// When it was written.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Every definition in this tenant, newest first.
///
/// The **document is not returned**, and that is not an oversight: a listing exists to let somebody
/// choose one, and a stages array is neither summarisable nor useful at a glance. `GET
/// /workflows/definitions/{id}` is where the document belongs and is `ENC-966` along with `PATCH`.
///
/// # Errors
///
/// [`WorkflowError`] wrapping the query failure.
pub async fn list_definitions(
    tx: &mut TenantScoped,
    limit: i64,
) -> Result<Vec<DefinitionSummary>, WorkflowError> {
    let rows = sqlx::query(LIST_DEFINITIONS)
        .bind(sql(tx.tenant_id()))
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            Ok(DefinitionSummary {
                id: row.try_get_id("id")?,
                name: row.try_get("name")?,
                scope_type: row.try_get("scope_type")?,
                scope_id: row.try_get("scope_id")?,
                version: row.try_get("version")?,
                enabled: row.try_get("enabled")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(|error| WorkflowError::from(DbError::Query(error)))
}

// Version is literal `1`: this writes a first version and `ENC-966` owns the rest. A definition
// edited in place would rewrite the rules under every instance already running against it, which is
// what `docs/15 §2`'s pinning exists to prevent.
const INSERT_DEFINITION: &str = "
    INSERT INTO workflow_definitions
        (tenant_id, id, scope_type, scope_id, name, version, definition,
         enabled, allow_self_approval, delegation, on_new_version, created_by)
    VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, $9, $10, $11)";

const LIST_DEFINITIONS: &str = "
    SELECT id, name, scope_type, scope_id, version, enabled, created_at
      FROM workflow_definitions
     WHERE tenant_id = $1
     ORDER BY created_at DESC, id DESC
     LIMIT $2";

pub async fn load_definition(
    tx: &mut TenantScoped,
    id: WorkflowDefinitionId,
) -> Result<Option<DefinitionFacts>, WorkflowError> {
    let Some(row) = sqlx::query(LOAD_DEFINITION)
        .bind(sql(tx.tenant_id()))
        .bind(sql(id))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?
    else {
        return Ok(None);
    };

    let document: serde_json::Value = row.try_get("definition").map_err(DbError::Query)?;
    let decoded = crate::definition::WorkflowDefinition::decode(&document)
        // A *stored* document that does not decode is an operator's problem, not the caller's, so
        // it becomes a `500` rather than a `422`. The distinction is `error.rs`'s.
        .map_err(|error| WorkflowError::Stored(error.to_string()))?;

    Ok(Some(DefinitionFacts {
        id: row.try_get_id("id").map_err(DbError::Query)?,
        version: row.try_get("version").map_err(DbError::Query)?,
        scope: Scope::parse(
            row.try_get::<String, _>("scope_type").map_err(DbError::Query)?.as_str(),
            row.try_get::<Option<Uuid>, _>("scope_id").map_err(DbError::Query)?,
        )?,
        enabled: row.try_get("enabled").map_err(DbError::Query)?,
        policy: WorkflowPolicy {
            allow_self_approval: row.try_get("allow_self_approval").map_err(DbError::Query)?,
            delegation: Delegation::parse(
                row.try_get::<String, _>("delegation").map_err(DbError::Query)?.as_str(),
            )?,
            on_new_version: OnNewVersion::parse(
                row.try_get::<String, _>("on_new_version").map_err(DbError::Query)?.as_str(),
            )?,
        },
        stages: decoded.stages,
    }))
}

const LOAD_INSTANCE: &str = "\
    SELECT id, definition_id, definition_version, state, current_stage, started_by, resource_id,
           version_id, allow_self_approval, delegation, on_new_version
      FROM workflow_instances
     WHERE tenant_id = $1 AND id = $2";

/// Reads one instance.
///
/// # Errors
///
/// [`WorkflowError::Db`], or [`WorkflowError::Stored`] if the row does not decode.
pub async fn load_instance(
    tx: &mut TenantScoped,
    id: WorkflowInstanceId,
) -> Result<Option<InstanceFacts>, WorkflowError> {
    let row = sqlx::query(LOAD_INSTANCE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(id))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    row.map(|row| instance_from_row(&row)).transpose()
}

const LOAD_INSTANCE_FOR_STEP: &str = "\
    SELECT i.id, i.definition_id, i.definition_version, i.state, i.current_stage, i.started_by,
           i.resource_id, i.version_id, i.allow_self_approval, i.delegation, i.on_new_version
      FROM workflow_steps    s
      JOIN workflow_instances i ON i.tenant_id = s.tenant_id AND i.id = s.instance_id
     WHERE s.tenant_id = $1 AND s.id = $2";

/// Reads the instance one step belongs to.
///
/// The join carries `tenant_id` on both sides. It is redundant under row-level security — both
/// tables are policied — and it is written anyway for the module header's reason. Note what it
/// costs to omit: nothing observable, which is exactly why it has to be a written rule rather than
/// something a test would catch.
///
/// # Errors
///
/// [`WorkflowError::Db`], or [`WorkflowError::Stored`] if the row does not decode.
pub async fn load_instance_for_step(
    tx: &mut TenantScoped,
    step: WorkflowStepId,
) -> Result<Option<InstanceFacts>, WorkflowError> {
    let row = sqlx::query(LOAD_INSTANCE_FOR_STEP)
        .bind(sql(tx.tenant_id()))
        .bind(sql(step))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    row.map(|row| instance_from_row(&row)).transpose()
}

fn instance_from_row(row: &sqlx::postgres::PgRow) -> Result<InstanceFacts, WorkflowError> {
    Ok(InstanceFacts {
        id: row.try_get_id("id").map_err(DbError::Query)?,
        definition_id: row.try_get_id("definition_id").map_err(DbError::Query)?,
        definition_version: row.try_get("definition_version").map_err(DbError::Query)?,
        state: InstanceState::parse(
            row.try_get::<String, _>("state").map_err(DbError::Query)?.as_str(),
        )?,
        current_stage: row.try_get("current_stage").map_err(DbError::Query)?,
        started_by: row.try_get_id("started_by").map_err(DbError::Query)?,
        resource: row.try_get_id("resource_id").map_err(DbError::Query)?,
        version: row.try_get_id("version_id").map_err(DbError::Query)?,
        policy: WorkflowPolicy {
            allow_self_approval: row.try_get("allow_self_approval").map_err(DbError::Query)?,
            delegation: Delegation::parse(
                row.try_get::<String, _>("delegation").map_err(DbError::Query)?.as_str(),
            )?,
            on_new_version: OnNewVersion::parse(
                row.try_get::<String, _>("on_new_version").map_err(DbError::Query)?.as_str(),
            )?,
        },
    })
}

const LOAD_STEPS: &str = "\
    SELECT id, instance_id, stage, position, step_type, assignee_id, delegated_to, state, config
      FROM workflow_steps
     WHERE tenant_id = $1 AND instance_id = $2
     ORDER BY stage, position, id";

/// Reads every step of one instance, in evaluation order.
///
/// **All of them, decided ones included.** The evaluator counts quorums over the rows, so a loader
/// that returned only the open ones would make every quorum read as zero-of-n and no stage would
/// ever advance.
///
/// # Errors
///
/// [`WorkflowError::Db`], or [`WorkflowError::Stored`] if a row does not decode.
pub async fn load_steps(
    tx: &mut TenantScoped,
    instance: WorkflowInstanceId,
) -> Result<Vec<StepFacts>, WorkflowError> {
    let rows = sqlx::query(LOAD_STEPS)
        .bind(sql(tx.tenant_id()))
        .bind(sql(instance))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    rows.iter().map(step_from_row).collect()
}

fn step_from_row(row: &sqlx::postgres::PgRow) -> Result<StepFacts, WorkflowError> {
    let config: serde_json::Value = row.try_get("config").map_err(DbError::Query)?;
    // A row whose config lost its quorum falls back to `All`, which is the reading that cannot
    // complete a step somebody was still looking at. Erring the other way would let a repaired row
    // satisfy a three-person quorum with one approval.
    let quorum: Quorum = config
        .get("quorum")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or(Quorum::All);
    let stage_name =
        config.get("stageName").and_then(serde_json::Value::as_str).unwrap_or_default().to_owned();

    Ok(StepFacts {
        id: row.try_get_id("id").map_err(DbError::Query)?,
        instance: row.try_get_id("instance_id").map_err(DbError::Query)?,
        stage: row.try_get("stage").map_err(DbError::Query)?,
        position: row.try_get("position").map_err(DbError::Query)?,
        step_type: StepType::parse(
            row.try_get::<String, _>("step_type").map_err(DbError::Query)?.as_str(),
        )?,
        assignee: row.try_get_id("assignee_id").map_err(DbError::Query)?,
        delegated_to: row
            .try_get::<Option<Uuid>, _>("delegated_to")
            .map_err(DbError::Query)?
            .map(UserId::from_uuid),
        state: StepState::parse(
            row.try_get::<String, _>("state").map_err(DbError::Query)?.as_str(),
        )?,
        quorum,
        stage_name,
    })
}

/// One row of a caller's task inbox, before the trim.
///
/// It carries the file the step's instance is bound to, because that is what
/// `crates/api/src/workflows.rs` re-confirms against the policy chain before rendering the row. A
/// task list is the cheapest enumeration oracle in a workflow system — it takes no argument and
/// returns a list of things — so the file has to travel with the step for the trim to be possible
/// at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// The step.
    pub step: WorkflowStepId,
    /// Its instance.
    pub instance: WorkflowInstanceId,
    /// The file the instance governs. **The trim's subject.**
    pub resource: FileId,
    /// The version under review.
    pub version: VersionId,
    /// What is being asked.
    pub step_type: StepType,
    /// Which stage, and its name.
    pub stage: i32,
    /// The stage's name, from the frozen config.
    pub stage_name: String,
    /// Whether the caller holds it as the assignee or as a delegate.
    pub delegated: bool,
    /// When it is due, if it is.
    pub due_at: Option<DateTime<Utc>>,
    /// When the step was created, which is the inbox's sort key.
    pub created_at: DateTime<Utc>,
}

/// Every open step this caller holds, newest first.
///
/// The predicate is *"the caller is the current holder"*, which is the delegate where there is one
/// and the assignee otherwise — the same rule `crates/workflows/src/authority.rs::holder_of`
/// applies, written as SQL. A delegated step therefore leaves the assignee's inbox and appears in
/// the delegate's, which is what makes a delegation transfer the work as well as the obligation.
///
/// It also names `i.state = 'RUNNING'`: a step left `ASSIGNED` under a cancelled instance is
/// nobody's task, and showing it would be an inbox that cannot be emptied.
const LOAD_TASKS: &str = "\
    SELECT s.id, s.instance_id, s.stage, s.step_type, s.due_at, s.created_at, s.config,
           s.delegated_to, i.resource_id, i.version_id
      FROM workflow_steps     s
      JOIN workflow_instances i ON i.tenant_id = s.tenant_id AND i.id = s.instance_id
     WHERE s.tenant_id = $1
       AND s.state = 'ASSIGNED'
       AND i.state = 'RUNNING'
       AND ((s.delegated_to IS NULL AND s.assignee_id = $2) OR s.delegated_to = $2)
     ORDER BY s.created_at DESC, s.id DESC
     LIMIT $3";

/// Reads one page of a caller's open steps.
///
/// **This is not the authorization decision.** It answers *which steps name this person*; whether
/// they may know the files those steps are about is `crates/api/src/workflows.rs`'s trim, which
/// runs every candidate through the same chain that would refuse each one individually. A caller
/// who holds a step over a file they can no longer read sees nothing, not a `403` — `CLAUDE.md`
/// rule 7.
///
/// # Errors
///
/// [`WorkflowError::Db`], or [`WorkflowError::Stored`] if a row does not decode.
pub async fn load_tasks(
    tx: &mut TenantScoped,
    holder: UserId,
    limit: i64,
) -> Result<Vec<Task>, WorkflowError> {
    let rows = sqlx::query(LOAD_TASKS)
        .bind(sql(tx.tenant_id()))
        .bind(sql(holder))
        .bind(limit.clamp(1, MAX_TASKS))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            let config: serde_json::Value = row.try_get("config").map_err(DbError::Query)?;
            Ok(Task {
                step: row.try_get_id("id").map_err(DbError::Query)?,
                instance: row.try_get_id("instance_id").map_err(DbError::Query)?,
                resource: row.try_get_id("resource_id").map_err(DbError::Query)?,
                version: row.try_get_id("version_id").map_err(DbError::Query)?,
                step_type: StepType::parse(
                    row.try_get::<String, _>("step_type").map_err(DbError::Query)?.as_str(),
                )?,
                stage: row.try_get("stage").map_err(DbError::Query)?,
                stage_name: config
                    .get("stageName")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                delegated: row
                    .try_get::<Option<Uuid>, _>("delegated_to")
                    .map_err(DbError::Query)?
                    .is_some(),
                due_at: row.try_get("due_at").map_err(DbError::Query)?,
                created_at: row.try_get("created_at").map_err(DbError::Query)?,
            })
        })
        .collect()
}

const LOAD_RESOURCE: &str = "\
    SELECT id, workspace_id, library_id, current_version_id
      FROM files
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND node_type = 'FILE'";

/// Reads the three facts a start decides with.
///
/// `node_type = 'FILE'` because a workflow approves a *version*, and a folder has none. `ENC-739`'s
/// alternative — letting a folder through and failing on the absent version — would answer the same
/// caller two different ways depending on which check they tripped first.
///
/// # Errors
///
/// [`WorkflowError::Db`].
pub async fn load_resource(
    tx: &mut TenantScoped,
    file: FileId,
) -> Result<Option<ResourceFacts>, WorkflowError> {
    let Some(row) = sqlx::query(LOAD_RESOURCE)
        .bind(sql(tx.tenant_id()))
        .bind(sql(file))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?
    else {
        return Ok(None);
    };

    Ok(Some(ResourceFacts {
        file: row.try_get_id("id").map_err(DbError::Query)?,
        workspace: row.try_get("workspace_id").map_err(DbError::Query)?,
        library: row.try_get("library_id").map_err(DbError::Query)?,
        current_version: row
            .try_get::<Option<Uuid>, _>("current_version_id")
            .map_err(DbError::Query)?
            .map(VersionId::from_uuid),
    }))
}

const CURRENT_VERSION: &str = "\
    SELECT current_version_id FROM files WHERE tenant_id = $1 AND id = $2";

/// The file's current version, for the W3 check on a decision.
///
/// # Errors
///
/// [`WorkflowError::Db`].
pub async fn current_version(
    tx: &mut TenantScoped,
    file: FileId,
) -> Result<Option<VersionId>, WorkflowError> {
    let row = sqlx::query(CURRENT_VERSION)
        .bind(sql(tx.tenant_id()))
        .bind(sql(file))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(row
        .and_then(|row| row.try_get::<Option<Uuid>, _>("current_version_id").ok().flatten())
        .map(VersionId::from_uuid))
}

/// Whether `user` is a live, non-deleted member of this tenant.
///
/// The delegation guard's first half: the composite foreign key would reject a foreign or
/// non-existent delegate anyway, but as an integrity error rather than as the refusal it is. Asking
/// here means an administrator sees `DELEGATE_NOT_ELIGIBLE` rather than a `500`, and it is the same
/// argument `crates/api/src/admin/dlp.rs::author` makes one layer up.
///
/// # Errors
///
/// [`WorkflowError::Db`].
pub async fn is_active_user(tx: &mut TenantScoped, user: UserId) -> Result<bool, WorkflowError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL",
    )
    .bind(sql(tx.tenant_id()))
    .bind(sql(user))
    .fetch_optional(&mut **tx)
    .await
    .map_err(DbError::Query)?;
    Ok(found.is_some())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Every statement in this module, so the checks below cannot silently miss one somebody adds.
    const STATEMENTS: &[(&str, &str)] = &[
        ("INSERT_INSTANCE", INSERT_INSTANCE),
        ("INSERT_STEP", INSERT_STEP),
        ("DECIDE_STEP", DECIDE_STEP),
        ("SKIP_STEP", SKIP_STEP),
        ("OPEN_STAGE", OPEN_STAGE),
        ("ADVANCE_INSTANCE", ADVANCE_INSTANCE),
        ("FINISH_INSTANCE", FINISH_INSTANCE),
        ("DELEGATE_STEP", DELEGATE_STEP),
        ("LOAD_DEFINITION", LOAD_DEFINITION),
        ("LOAD_INSTANCE", LOAD_INSTANCE),
        ("LOAD_INSTANCE_FOR_STEP", LOAD_INSTANCE_FOR_STEP),
        ("LOAD_STEPS", LOAD_STEPS),
        ("LOAD_TASKS", LOAD_TASKS),
        ("LOAD_RESOURCE", LOAD_RESOURCE),
        ("CURRENT_VERSION", CURRENT_VERSION),
    ];

    #[test]
    fn the_statements_all_scope_by_tenant() {
        // The predicate-level assertion the module header explains: a cross-tenant *behavioural*
        // test cannot catch a dropped `tenant_id`, because row-level security holds that property
        // on its own. Six sessions in this repository have found that the hard way. This is what
        // holds layer 1, and it reads the SQL because nothing else can.
        //
        // An `INSERT` scopes by *writing* the column rather than by a predicate — RLS's `WITH
        // CHECK` is what refuses a foreign one — so the two forms are asserted separately. One
        // combined check would have to accept whichever spelling is looser, which is how a gate
        // starts proving less than its name says (`ENC-543`).
        for (name, sql) in STATEMENTS {
            if sql.trim_start().starts_with("INSERT") {
                assert!(
                    sql.contains("(tenant_id,") && sql.contains("VALUES ($1,"),
                    "{name} does not write tenant_id from the guard's own tenant as its first \
                     bound value"
                );
            } else {
                assert!(
                    sql.contains("tenant_id = $1"),
                    "{name} does not scope by tenant; RLS would still hold the row back, which is \
                     exactly why no behavioural test would notice (enclave-db's crate header)"
                );
            }
        }
    }

    #[test]
    fn the_joins_carry_tenant_id_on_both_sides() {
        for (name, sql) in STATEMENTS {
            if sql.contains(" JOIN ") {
                assert!(
                    sql.contains("i.tenant_id = s.tenant_id"),
                    "{name} joins two tenant-scoped tables without equating their tenants"
                );
            }
        }
    }

    #[test]
    fn the_delegation_statement_is_conditional_on_there_being_no_delegate_yet() {
        // `ENC-740`'s third layer, and the only one that survives two concurrent requests. Deleting
        // this predicate makes the statement succeed for both, so the last writer wins and the
        // step ends up with a holder the original assignee never chose.
        assert!(
            DELEGATE_STEP.contains("delegated_to IS NULL"),
            "the one-transfer bound has left the statement, so two simultaneous delegations both \
             succeed and the authority lands wherever the race did"
        );
    }

    #[test]
    fn the_decision_and_skip_statements_never_touch_a_decided_step() {
        // The cancel property: ending a workflow must not erase the record that a named person
        // approved something. Both statements name only the open states.
        for (name, sql) in [("DECIDE_STEP", DECIDE_STEP), ("SKIP_STEP", SKIP_STEP)] {
            assert!(
                sql.contains("state IN ('PENDING','ASSIGNED')"),
                "{name} can overwrite a decided step, so cancelling a workflow would rewrite the \
                 approvals made in it"
            );
        }
    }

    #[test]
    fn a_terminal_instance_cannot_be_moved_again() {
        assert!(
            FINISH_INSTANCE.contains("state = 'RUNNING'"),
            "a COMPLETED instance could be overwritten as CANCELLED by a request that arrived late"
        );
    }

    #[test]
    fn the_task_inbox_selects_the_current_holder_rather_than_the_original_assignee() {
        // Reading `assignee_id` alone would leave a delegated step in the assignee's inbox and out
        // of the delegate's — a delegation that moves the obligation and not the work.
        assert!(
            LOAD_TASKS
                .contains("(s.delegated_to IS NULL AND s.assignee_id = $2) OR s.delegated_to = $2"),
            "the inbox predicate no longer follows delegation"
        );
        assert!(
            LOAD_TASKS.contains("i.state = 'RUNNING'"),
            "a step under a cancelled instance would sit in an inbox that cannot be emptied"
        );
    }

    #[test]
    fn the_step_loader_reads_decided_steps_too() {
        // A loader filtered to open steps makes every quorum read as zero-of-n, so no stage ever
        // advances and every workflow strands one approval short.
        assert!(!LOAD_STEPS.contains("state ="), "{LOAD_STEPS}");
        assert!(!LOAD_STEPS.contains("state IN"), "{LOAD_STEPS}");
    }
}
