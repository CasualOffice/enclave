//! The evaluator: facts in, a [`Plan`] out, and no way to write anything.
//!
//! # Read the signatures first
//!
//! None of these functions takes a `TenantScoped`, a `DbPool`, or anything that could reach a
//! database. That is the whole of `plans/M4-GOVERNANCE.md` D28 as it applies to this surface:
//! `simulate` cannot take a cheaper path than a real start, because there is only one path and it
//! is the one that cannot act. `crates/api/src/workflows.rs` calls [`plan_start`] from both
//! handlers, behind one policy-chain call, for one action, on one resource; the two differ in a
//! single statement at the end — apply the plan, or describe it.
//!
//! `migrations/0021` makes the same argument for `RuleSet::evaluate` taking no mode argument: *the
//! code that reaches a conclusion has not been told which mode is running and cannot branch on
//! it.* Here it has not been told, and could not act on the answer if it had. `ENC-741`.
//!
//! # Determinism
//!
//! `docs/15 §2`, second core property: *given the same definition and the same event sequence, the
//! instance reaches the same state. No wall-clock reads inside evaluation; timers are events.*
//! Every function here takes `now` as an argument rather than calling `Utc::now()`, which is what
//! makes that literal. A test can therefore replay a sequence and assert the outcome without a
//! clock in the way, and an SLA sweep will be an event with a timestamp rather than a
//! `Utc::now()` buried three frames down.

use chrono::{DateTime, Utc};
use enclave_core::id::UserId;

use crate::authority::{may_cancel, may_decide, may_delegate};
use crate::error::{Refusal, WorkflowError};
use crate::facts::{DefinitionFacts, InstanceFacts, ResourceFacts, StepFacts};
use crate::ids::{WorkflowInstanceId, WorkflowStepId};
use crate::plan::{Effect, NewInstance, NewStep, Plan};
use crate::state::{InstanceState, StepState};

/// What a caller asked of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// `POST /workflows/steps/{id}/approve` — approve, acknowledge or complete, depending on the
    /// step type.
    Approve,
    /// `POST /workflows/steps/{id}/reject`. Only an `APPROVAL` step has a gate to reject.
    Reject,
}

impl Decision {
    /// The state the step takes.
    const fn resulting_state(self) -> StepState {
        match self {
            Self::Approve => StepState::Approved,
            Self::Reject => StepState::Rejected,
        }
    }
}

/// Plans the start of an instance.
///
/// **This is the function `simulate` calls.** It writes nothing and can write nothing; see the
/// module header.
///
/// Every step of every stage is planned, not only the opening one, with later stages `PENDING`.
/// Two reasons, and the second is the one that matters: a progress tracker and a task inbox both
/// need the whole shape from the start (`docs/15 §11`, *who is next, who is late*), and a
/// simulation whose answer stopped at stage one would be answering a different question from the
/// one an author asked — *what will this workflow ask of whom*.
///
/// # Errors
///
/// * [`Refusal::DefinitionDisabled`] — the template is switched off.
/// * [`Refusal::OutOfScope`] — a `LIBRARY`- or `WORKSPACE`-scoped definition started on a file
///   outside it. The column earns its keep here (`migrations/0024`).
/// * [`WorkflowError::Definition`] — the file has no current version, so there is nothing for an
///   approval to be *of* (`docs/15 §2.1`).
pub fn plan_start(
    definition: &DefinitionFacts,
    resource: &ResourceFacts,
    starter: UserId,
    now: DateTime<Utc>,
) -> Result<Plan, WorkflowError> {
    if !definition.enabled {
        return Err(Refusal::DefinitionDisabled.into());
    }
    if !definition.scope.covers(resource.workspace, resource.library) {
        return Err(Refusal::OutOfScope.into());
    }

    // `docs/15 §2.1`: bound to a version, not a file. A file with no committed version has nothing
    // for an approval to approve, and binding to the file instead is exactly the collapse the
    // property forbids.
    let Some(version) = resource.current_version else {
        return Err(WorkflowError::Definition(
            "the file has no current version, and an approval approves a version rather than a \
             file (docs/15 §2.1)"
                .to_owned(),
        ));
    };

    let instance = WorkflowInstanceId::new_v7();
    let mut plan = Plan::empty();
    plan.push(Effect::CreateInstance(Box::new(NewInstance {
        id: instance,
        definition_id: definition.id,
        definition_version: definition.version,
        resource: resource.file,
        version,
        started_by: starter,
        policy: definition.policy,
        started_at: now,
    })));

    for (stage_index, stage) in definition.stages.iter().enumerate() {
        let stage_number = i32::try_from(stage_index).unwrap_or(i32::MAX);
        for (position_index, step) in stage.steps.iter().enumerate() {
            let position = i32::try_from(position_index).unwrap_or(i32::MAX);
            for assignee in &step.assignees {
                plan.push(Effect::CreateStep(Box::new(NewStep {
                    id: WorkflowStepId::new_v7(),
                    instance,
                    stage: stage_number,
                    position,
                    step_type: step.step_type,
                    assignee: *assignee,
                    // The opening stage is live; every later one waits. Without this a two-stage
                    // approval could be completed by its second stage before its first ran.
                    state: if stage_number == 0 { StepState::Assigned } else { StepState::Pending },
                    quorum: step.quorum,
                    stage_name: stage.name.clone(),
                })));
            }
        }
    }

    Ok(plan)
}

/// Plans a decision on one step.
///
/// # The order of the checks
///
/// Authority first ([`may_decide`]), then the step type, then the version. A caller who does not
/// hold the step learns only that; the rest is information its holder is entitled to.
///
/// # The version check is the enforcement point for `docs/15 §12` W3
///
/// *A new version invalidates in-flight approvals by default.* Held here — at the moment somebody
/// tries to approve superseded content — rather than by a sweep at commit time, because this is
/// where the property actually bites and because a sweep can lag. The instance is expired in the
/// same plan, so the refusal and the state agree. `ENC-743` carries the proactive half, which
/// improves what a listing *shows* and adds nothing to what is *enforced*.
///
/// # Errors
///
/// [`WorkflowError::Refused`] carrying the [`Refusal`] that applies.
pub fn plan_decision(
    instance: &InstanceFacts,
    steps: &[StepFacts],
    step_id: WorkflowStepId,
    actor: UserId,
    decision: Decision,
    comment: Option<String>,
    current_version: Option<enclave_core::id::VersionId>,
    now: DateTime<Utc>,
) -> Result<Plan, WorkflowError> {
    let step = find(steps, step_id)?;
    let _claim = may_decide(instance, step, actor)?;

    let takes_it = match decision {
        Decision::Approve => step.step_type.takes_approval(),
        Decision::Reject => step.step_type.takes_rejection(),
    };
    if !takes_it {
        return Err(Refusal::WrongStepType.into());
    }

    // W3. `CONTINUE` is the documented opt-out and the instance pinned it at start, so a later
    // edit of the template cannot switch it on for work already in flight.
    if instance.policy.on_new_version == crate::definition::OnNewVersion::Invalidate
        && current_version.is_some_and(|current| current != instance.version)
    {
        let mut plan = Plan::empty();
        close_open_steps(&mut plan, steps, None);
        plan.push(Effect::FinishInstance {
            instance: instance.id,
            state: InstanceState::Expired,
            reason: Some(
                "the version under review was superseded (docs/15 §2.1, on_new_version = \
                 INVALIDATE)"
                    .to_owned(),
            ),
            at: now,
        });
        // The plan is returned *and* the caller is refused: `crates/api` applies it, so the
        // instance is expired by the same request that was told it could not approve. Returning
        // only the refusal would leave a `RUNNING` instance that every subsequent attempt also
        // refuses, with nothing recording why.
        return Err(WorkflowError::Superseded(Box::new(plan)));
    }

    let mut plan = Plan::empty();
    plan.push(Effect::DecideStep {
        step: step.id,
        state: decision.resulting_state(),
        decided_by: actor,
        comment,
        at: now,
    });

    match decision {
        // `docs/15 §4`: rejection at any step terminates the instance. A rework branch is the
        // section's documented alternative and is not built (`ENC-745`); terminating is the
        // default and the direction that cannot over-permit.
        Decision::Reject => {
            close_open_steps(&mut plan, steps, Some(step.id));
            plan.push(Effect::FinishInstance {
                instance: instance.id,
                state: InstanceState::Rejected,
                reason: None,
                at: now,
            });
        }
        Decision::Approve => advance(&mut plan, instance, steps, step, now),
    }

    Ok(plan)
}

/// Plans a cancellation.
///
/// # What happens to steps already approved
///
/// **Nothing.** A cancelled instance keeps every decision that was made in it: an `APPROVED` step
/// stays `APPROVED`, with its decider and its timestamp. Only steps that are still `PENDING` or
/// `ASSIGNED` become `SKIPPED`, because those are the ones nobody now needs to answer.
///
/// The alternative — resetting decided steps — would make cancellation a way to erase the record
/// that a named person approved something, which is the one thing the table exists to hold. The
/// `workflow_steps_decision_complete` constraint makes the wrong version unwritable anyway: a step
/// cannot leave `APPROVED` without also clearing `decided_by`, and the statement in
/// `crates/workflows/src/repo.rs` names only the open states.
///
/// # Errors
///
/// [`WorkflowError::Refused`] — see [`may_cancel`].
pub fn plan_cancel(
    instance: &InstanceFacts,
    steps: &[StepFacts],
    actor: UserId,
    owns_resource: bool,
    reason: String,
    now: DateTime<Utc>,
) -> Result<Plan, WorkflowError> {
    may_cancel(instance, actor, owns_resource)?;

    let mut plan = Plan::empty();
    close_open_steps(&mut plan, steps, None);
    plan.push(Effect::FinishInstance {
        instance: instance.id,
        state: InstanceState::Cancelled,
        reason: Some(reason),
        at: now,
    });
    Ok(plan)
}

/// Plans a delegation.
///
/// `entitled` is whether the proposed delegate independently holds the access the step requires;
/// `crates/api` answers it by asking the authorization service about the delegate, and asks the
/// whole chain again under the delegate's own context when they actually act. See
/// [`crate::authority`] for why both.
///
/// # Errors
///
/// [`WorkflowError::Refused`] — see [`may_delegate`].
pub fn plan_delegate(
    instance: &InstanceFacts,
    steps: &[StepFacts],
    step_id: WorkflowStepId,
    actor: UserId,
    to: UserId,
    entitled: bool,
    reason: String,
    now: DateTime<Utc>,
) -> Result<Plan, WorkflowError> {
    let step = find(steps, step_id)?;
    may_delegate(instance, step, actor, to, entitled)?;

    let mut plan = Plan::empty();
    plan.push(Effect::Delegate { step: step.id, to, reason, at: now });
    Ok(plan)
}

// --- The parts the four planners share -----------------------------------------------------------

/// Finds a step among the instance's steps.
///
/// A step id that names no step of *this* instance is [`Refusal::NotTheHolder`] rather than a
/// "not found": the caller reached this function through `crates/api`, which loaded the step by id
/// under row-level security and enforced the chain on the file it belongs to. By the time we are
/// here, "no such step in this instance" means the ids were mismatched, and answering it with a
/// distinguishable error would let a caller probe which step ids exist.
fn find(steps: &[StepFacts], id: WorkflowStepId) -> Result<&StepFacts, Refusal> {
    steps.iter().find(|step| step.id == id).ok_or(Refusal::NotTheHolder)
}

/// Skips every still-open step, optionally except one that is being decided in the same plan.
fn close_open_steps(plan: &mut Plan, steps: &[StepFacts], except: Option<WorkflowStepId>) {
    for step in steps {
        if step.state.is_open() && Some(step.id) != except {
            plan.push(Effect::SkipStep { step: step.id });
        }
    }
}

/// Works out what an approval does to the position, the stage and the instance.
///
/// Counted from the rows rather than from a running total kept on the instance. A counter is a
/// second source of truth that a hand-repaired row silently desynchronises; a count over
/// `(stage, position)` cannot disagree with the rows because it *is* the rows.
fn advance(
    plan: &mut Plan,
    instance: &InstanceFacts,
    steps: &[StepFacts],
    decided: &StepFacts,
    now: DateTime<Utc>,
) {
    let stage = decided.stage;

    // With this approval applied, is the decided step's own position satisfied?
    if !position_satisfied(steps, stage, decided.position, Some(decided.id)) {
        return;
    }

    // It is, so nobody else at that position needs to answer. `SKIPPED`, never deleted: the row is
    // the record that a named person was asked.
    for step in steps {
        if step.stage == stage
            && step.position == decided.position
            && step.id != decided.id
            && step.state.is_open()
        {
            plan.push(Effect::SkipStep { step: step.id });
        }
    }

    // Is every position of this stage now satisfied?
    let positions = stage_positions(steps, stage);
    let stage_done = positions.iter().all(|position| {
        position_satisfied(steps, stage, *position, Some(decided.id))
            || *position == decided.position
    });
    if !stage_done {
        return;
    }

    match next_stage(steps, stage) {
        Some(next) => {
            plan.push(Effect::OpenStage { instance: instance.id, stage: next });
        }
        None => {
            plan.push(Effect::FinishInstance {
                instance: instance.id,
                state: InstanceState::Completed,
                reason: None,
                at: now,
            });
        }
    }
}

/// Whether a position has met its quorum, counting `newly_approved` as approved.
///
/// The `newly_approved` argument is what lets this be asked about a decision that has not been
/// written yet — which is the whole reason this crate plans rather than mutates. Without it the
/// evaluator would have to write the row first and then ask, which is a mutation inside an
/// evaluation and therefore the thing `simulate` could not do.
fn position_satisfied(
    steps: &[StepFacts],
    stage: i32,
    position: i32,
    newly_approved: Option<WorkflowStepId>,
) -> bool {
    let rows: Vec<&StepFacts> =
        steps.iter().filter(|step| step.stage == stage && step.position == position).collect();
    if rows.is_empty() {
        return true;
    }

    let approvals = rows
        .iter()
        .filter(|step| step.state.is_affirmative() || Some(step.id) == newly_approved)
        .count();
    let total = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    let required = rows[0].quorum.required(total);

    u32::try_from(approvals).unwrap_or(u32::MAX) >= required
}

/// Every distinct position in one stage, ascending.
fn stage_positions(steps: &[StepFacts], stage: i32) -> Vec<i32> {
    let mut positions: Vec<i32> =
        steps.iter().filter(|step| step.stage == stage).map(|step| step.position).collect();
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// The stage after `stage`, if the instance has one.
fn next_stage(steps: &[StepFacts], stage: i32) -> Option<i32> {
    steps.iter().map(|step| step.stage).filter(|candidate| *candidate > stage).min()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::id::{FileId, VersionId};
    use uuid::Uuid;

    use super::*;
    use crate::definition::{
        Delegation, OnNewVersion, Quorum, Scope, Stage, StepSpec, StepType, WorkflowDefinition,
        WorkflowPolicy,
    };
    use crate::ids::WorkflowDefinitionId;

    fn user(byte: u8) -> UserId {
        UserId::from_uuid(Uuid::from_bytes([byte; 16]))
    }

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("a fixed instant")
    }

    fn policy() -> WorkflowPolicy {
        WorkflowPolicy {
            allow_self_approval: false,
            delegation: Delegation::Once,
            on_new_version: OnNewVersion::Invalidate,
        }
    }

    fn definition(stages: Vec<Stage>) -> DefinitionFacts {
        DefinitionFacts {
            id: WorkflowDefinitionId::new_v7(),
            version: 1,
            scope: Scope::Tenant,
            enabled: true,
            policy: policy(),
            stages,
        }
    }

    fn resource() -> ResourceFacts {
        ResourceFacts {
            file: FileId::new_v7(),
            workspace: Uuid::from_bytes([10; 16]),
            library: Uuid::from_bytes([11; 16]),
            current_version: Some(VersionId::new_v7()),
        }
    }

    fn approval(assignees: &[u8], quorum: Quorum) -> StepSpec {
        StepSpec {
            step_type: StepType::Approval,
            assignees: assignees.iter().copied().map(user).collect(),
            quorum,
        }
    }

    /// Turns a plan's `CreateStep` effects into the facts a later decision would read.
    ///
    /// The tests below therefore evaluate against exactly what `repo::apply` would have written,
    /// rather than against a hand-built parallel fixture that could drift from it.
    fn steps_from(plan: &Plan) -> Vec<StepFacts> {
        plan.created_steps()
            .map(|step| StepFacts {
                id: step.id,
                instance: step.instance,
                stage: step.stage,
                position: step.position,
                step_type: step.step_type,
                assignee: step.assignee,
                delegated_to: None,
                state: step.state,
                quorum: step.quorum,
                stage_name: step.stage_name.clone(),
            })
            .collect()
    }

    fn instance_from(plan: &Plan) -> InstanceFacts {
        let created = plan.created_instance().expect("the plan creates an instance");
        InstanceFacts {
            id: created.id,
            definition_id: created.definition_id,
            definition_version: created.definition_version,
            state: InstanceState::Running,
            current_stage: 0,
            started_by: created.started_by,
            resource: created.resource,
            version: created.version,
            policy: created.policy,
        }
    }

    /// Applies a plan to a fact set, the way `repo::apply` applies it to rows.
    fn replay(steps: &mut [StepFacts], instance: &mut InstanceFacts, plan: &Plan) {
        for effect in plan.effects() {
            match effect {
                Effect::DecideStep { step, state, .. } => {
                    for row in steps.iter_mut().filter(|row| row.id == *step) {
                        row.state = *state;
                    }
                }
                Effect::SkipStep { step } => {
                    for row in steps.iter_mut().filter(|row| row.id == *step) {
                        row.state = StepState::Skipped;
                    }
                }
                Effect::OpenStage { stage, .. } => {
                    instance.current_stage = *stage;
                    for row in steps
                        .iter_mut()
                        .filter(|row| row.stage == *stage && row.state == StepState::Pending)
                    {
                        row.state = StepState::Assigned;
                    }
                }
                Effect::FinishInstance { state, .. } => instance.state = *state,
                Effect::Delegate { step, to, .. } => {
                    for row in steps.iter_mut().filter(|row| row.id == *step) {
                        row.delegated_to = Some(*to);
                    }
                }
                Effect::CreateInstance(_) | Effect::CreateStep(_) => {}
            }
        }
    }

    #[test]
    fn a_start_plans_every_stage_with_only_the_first_one_open() {
        let definition = definition(vec![
            Stage { name: "legal".to_owned(), steps: vec![approval(&[2], Quorum::All)] },
            Stage { name: "finance".to_owned(), steps: vec![approval(&[3], Quorum::All)] },
        ]);
        let plan = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");

        let steps: Vec<&NewStep> = plan.created_steps().collect();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].state, StepState::Assigned);
        assert_eq!(steps[1].state, StepState::Pending, "a later stage must not open early");
        assert_eq!(steps[1].stage_name, "finance");
    }

    #[test]
    fn a_step_with_three_assignees_becomes_three_rows_sharing_a_position() {
        // What makes a quorum a count rather than a field somebody keeps in step with reality.
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2, 3, 4], Quorum::NOf { n: 2 })],
        }]);
        let plan = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");

        let steps: Vec<&NewStep> = plan.created_steps().collect();
        assert_eq!(steps.len(), 3);
        assert!(steps.iter().all(|step| step.stage == 0 && step.position == 0));
    }

    #[test]
    fn a_definition_outside_its_scope_is_refused() {
        let mut definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2], Quorum::All)],
        }]);
        definition.scope = Scope::Library(Uuid::from_bytes([99; 16]));

        let error = plan_start(&definition, &resource(), user(1), at())
            .expect_err("a library-scoped definition may not run on another library's file");
        assert!(matches!(error, WorkflowError::Refused(Refusal::OutOfScope)), "{error:?}");
    }

    #[test]
    fn a_file_with_no_current_version_cannot_start_a_workflow() {
        // `docs/15 §2.1`: an approval approves a version. Binding to the file would be the collapse
        // that property forbids.
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2], Quorum::All)],
        }]);
        let mut resource = resource();
        resource.current_version = None;

        let error =
            plan_start(&definition, &resource, user(1), at()).expect_err("nothing to approve");
        assert!(matches!(error, WorkflowError::Definition(_)), "{error:?}");
    }

    #[test]
    fn a_two_of_three_quorum_completes_on_the_second_approval_and_skips_the_third() {
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2, 3, 4], Quorum::NOf { n: 2 })],
        }]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let mut steps = steps_from(&start);
        let mut instance = instance_from(&start);
        let ids: Vec<WorkflowStepId> = steps.iter().map(|step| step.id).collect();

        let first = plan_decision(
            &instance,
            &steps,
            ids[0],
            user(2),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect("the first approval");
        assert!(
            !first.effects().iter().any(|e| matches!(e, Effect::FinishInstance { .. })),
            "one approval of two must not complete the instance"
        );
        replay(&mut steps, &mut instance, &first);

        let second = plan_decision(
            &instance,
            &steps,
            ids[1],
            user(3),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect("the second approval");
        replay(&mut steps, &mut instance, &second);

        assert_eq!(instance.state, InstanceState::Completed);
        assert_eq!(
            steps[2].state,
            StepState::Skipped,
            "the third approver must be released, not left waiting on a finished workflow"
        );
    }

    #[test]
    fn a_rejection_terminates_the_instance_and_releases_everyone_else() {
        let definition = definition(vec![
            Stage { name: "review".to_owned(), steps: vec![approval(&[2, 3], Quorum::All)] },
            Stage { name: "sign-off".to_owned(), steps: vec![approval(&[4], Quorum::All)] },
        ]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let mut steps = steps_from(&start);
        let mut instance = instance_from(&start);
        let rejected = steps[0].id;

        let plan = plan_decision(
            &instance,
            &steps,
            rejected,
            user(2),
            Decision::Reject,
            Some("the indemnity clause is unacceptable".to_owned()),
            Some(instance.version),
            at(),
        )
        .expect("a rejection");
        replay(&mut steps, &mut instance, &plan);

        assert_eq!(instance.state, InstanceState::Rejected);
        assert_eq!(steps[0].state, StepState::Rejected);
        assert_eq!(steps[1].state, StepState::Skipped);
        assert_eq!(steps[2].state, StepState::Skipped, "the second stage is released too");
    }

    #[test]
    fn a_stage_opens_only_when_every_position_in_the_one_before_is_satisfied() {
        let definition = definition(vec![
            Stage {
                name: "review".to_owned(),
                // Two positions in one stage: both must be satisfied before the stage advances.
                steps: vec![approval(&[2], Quorum::All), approval(&[3], Quorum::All)],
            },
            Stage { name: "sign-off".to_owned(), steps: vec![approval(&[4], Quorum::All)] },
        ]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let mut steps = steps_from(&start);
        let mut instance = instance_from(&start);
        let ids: Vec<WorkflowStepId> = steps.iter().map(|step| step.id).collect();

        let first = plan_decision(
            &instance,
            &steps,
            ids[0],
            user(2),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect("position 0");
        assert!(
            !first.effects().iter().any(|e| matches!(e, Effect::OpenStage { .. })),
            "one of two positions must not advance the stage"
        );
        replay(&mut steps, &mut instance, &first);

        let second = plan_decision(
            &instance,
            &steps,
            ids[1],
            user(3),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect("position 1");
        replay(&mut steps, &mut instance, &second);

        assert_eq!(instance.current_stage, 1);
        assert_eq!(instance.state, InstanceState::Running);
        assert_eq!(steps[2].state, StepState::Assigned, "the second stage is now live");
    }

    #[test]
    fn a_superseded_version_expires_the_instance_and_refuses_the_approval() {
        // `docs/15 §12` W3, held at the gate rather than by a sweep.
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2], Quorum::All)],
        }]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let steps = steps_from(&start);
        let instance = instance_from(&start);

        let error = plan_decision(
            &instance,
            &steps,
            steps[0].id,
            user(2),
            Decision::Approve,
            None,
            Some(VersionId::new_v7()),
            at(),
        )
        .expect_err("the version under review moved on");

        let WorkflowError::Superseded(plan) = error else {
            panic!("expected a superseded refusal carrying its plan, got {error:?}");
        };
        assert!(plan.effects().iter().any(|effect| matches!(
            effect,
            Effect::FinishInstance { state: InstanceState::Expired, .. }
        )));
    }

    #[test]
    fn continue_lets_an_approval_stand_on_a_superseded_version() {
        // The documented, rare opt-out of `docs/15 §2.1`, pinned on the instance so a template edit
        // cannot switch it on for work already in flight.
        let mut definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2], Quorum::All)],
        }]);
        definition.policy.on_new_version = OnNewVersion::Continue;

        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let steps = steps_from(&start);
        let instance = instance_from(&start);

        let plan = plan_decision(
            &instance,
            &steps,
            steps[0].id,
            user(2),
            Decision::Approve,
            None,
            Some(VersionId::new_v7()),
            at(),
        )
        .expect("CONTINUE permits it");
        assert!(plan.effects().iter().any(|effect| matches!(
            effect,
            Effect::FinishInstance { state: InstanceState::Completed, .. }
        )));
    }

    #[test]
    fn a_review_step_cannot_be_rejected_and_a_signature_step_cannot_be_approved() {
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![
                StepSpec {
                    step_type: StepType::Review,
                    assignees: vec![user(2)],
                    quorum: Quorum::All,
                },
                StepSpec {
                    step_type: StepType::Signature,
                    assignees: vec![user(3)],
                    quorum: Quorum::All,
                },
            ],
        }]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let steps = steps_from(&start);
        let instance = instance_from(&start);

        let error = plan_decision(
            &instance,
            &steps,
            steps[0].id,
            user(2),
            Decision::Reject,
            Some("no".to_owned()),
            Some(instance.version),
            at(),
        )
        .expect_err("a REVIEW step has no gate to reject");
        assert!(matches!(error, WorkflowError::Refused(Refusal::WrongStepType)), "{error:?}");

        let error = plan_decision(
            &instance,
            &steps,
            steps[1].id,
            user(3),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect_err("a signature is not obtained by clicking approve");
        assert!(matches!(error, WorkflowError::Refused(Refusal::WrongStepType)), "{error:?}");
    }

    #[test]
    fn cancelling_keeps_every_decision_already_made() {
        // The property the whole cancel path is arranged around: cancellation ends what is
        // happening, it does not rewrite what happened.
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2, 3], Quorum::All)],
        }]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let mut steps = steps_from(&start);
        let mut instance = instance_from(&start);

        let approved = plan_decision(
            &instance,
            &steps,
            steps[0].id,
            user(2),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect("the first approval");
        replay(&mut steps, &mut instance, &approved);
        assert_eq!(steps[0].state, StepState::Approved);

        let cancel = plan_cancel(
            &instance,
            &steps,
            user(1),
            false,
            "the counterparty withdrew".to_owned(),
            at(),
        )
        .expect("the initiator may cancel");
        replay(&mut steps, &mut instance, &cancel);

        assert_eq!(instance.state, InstanceState::Cancelled);
        assert_eq!(
            steps[0].state,
            StepState::Approved,
            "cancellation must not erase the record that a named person approved something"
        );
        assert_eq!(steps[1].state, StepState::Skipped, "the outstanding approver is released");
    }

    #[test]
    fn a_plan_for_a_step_of_another_instance_is_refused_as_holdership() {
        // Deliberately indistinguishable from "not your step": a distinguishable answer would let a
        // caller probe which step ids exist.
        let definition = definition(vec![Stage {
            name: "review".to_owned(),
            steps: vec![approval(&[2], Quorum::All)],
        }]);
        let start = plan_start(&definition, &resource(), user(1), at()).expect("a valid start");
        let steps = steps_from(&start);
        let instance = instance_from(&start);

        let error = plan_decision(
            &instance,
            &steps,
            WorkflowStepId::new_v7(),
            user(2),
            Decision::Approve,
            None,
            Some(instance.version),
            at(),
        )
        .expect_err("an unknown step id");
        assert!(matches!(error, WorkflowError::Refused(Refusal::NotTheHolder)), "{error:?}");
    }

    #[test]
    fn the_decoder_and_the_evaluator_agree_about_what_a_definition_instantiates_to() {
        // A definition decoded from JSON, not hand-built: this is the path an author's document
        // actually takes, and it is what stops the tests above from proving something about a
        // fixture that no request could produce.
        let document = serde_json::json!({
            "stages": [{
                "name": "review",
                "steps": [{
                    "type": "APPROVAL",
                    "assignees": [user(2).as_uuid(), user(3).as_uuid()],
                    "quorum": "any",
                }],
            }],
        });
        let decoded = WorkflowDefinition::decode(&document).expect("a valid definition");
        let facts = definition(decoded.stages);
        let plan = plan_start(&facts, &resource(), user(1), at()).expect("a valid start");

        let steps: Vec<&NewStep> = plan.created_steps().collect();
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|step| step.quorum == Quorum::Any));
    }
}
