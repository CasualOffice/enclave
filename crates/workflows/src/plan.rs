//! What an evaluation *would* do, described rather than done.
//!
//! # This type is why `simulate` cannot diverge from a real run
//!
//! `plans/M4-GOVERNANCE.md` D28: *`SIMULATION` must be indistinguishable from `ENFORCE` except in
//! its effect. Same detectors, same facts, same evaluation, same audit row shape. If simulation
//! takes a cheaper path, it measures something other than what enforcement will do.*
//!
//! `migrations/0021` records how `crates/dlp` makes that structural rather than tested: `RuleSet`
//! holds no mode field and `RuleSet::evaluate` takes no mode argument, so the code that reaches a
//! conclusion **has not been told which mode is running and cannot branch on it**.
//!
//! The same shape, one milestone over. [`crate::evaluate`]'s functions take no connection and
//! return a [`Plan`]. They therefore *cannot* write — not "must not", cannot: there is no
//! `TenantScoped` in scope and no way to obtain one — and there is no `simulate: bool` anywhere in
//! this crate for a second path to hang off. `POST /workflows/definitions/{id}/simulate` and
//! `POST /files/{id}/workflows` call one function, `plan_start`, behind one policy-chain call for
//! one action on one resource. They differ in exactly one statement: whether the returned `Plan` is
//! handed to [`crate::repo::apply`] or rendered.
//!
//! Writing the divergence would mean adding a second evaluator, which is a diff a reviewer sees,
//! rather than adding a branch, which is a diff a reviewer skims. `ENC-741`.
//!
//! # Ordering is part of the plan
//!
//! Effects apply in order, and the order is not incidental: a `CreateStep` cannot precede the
//! `CreateInstance` it references, and a `FinishInstance` after a `DecideStep` is what makes the
//! decided step visible in the terminal state. [`crate::repo::apply`] walks the slice; it does not
//! sort it.

use chrono::{DateTime, Utc};
use enclave_core::id::{FileId, UserId, VersionId};

use crate::definition::{Quorum, StepType, WorkflowPolicy};
use crate::ids::{WorkflowDefinitionId, WorkflowInstanceId, WorkflowStepId};
use crate::state::{InstanceState, StepState};

/// The instance an evaluation would create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInstance {
    /// The identifier the instance would take. Allocated by the evaluator so that the steps below
    /// can reference it, and so a simulation can show the shape it would have had.
    pub id: WorkflowInstanceId,
    /// The template.
    pub definition_id: WorkflowDefinitionId,
    /// The template's version, recorded for the audit trail.
    pub definition_version: i32,
    /// The file.
    pub resource: FileId,
    /// The version the approval will be *of* (`docs/15 §2.1`).
    pub version: VersionId,
    /// Who started it, and therefore who may cancel it.
    pub started_by: UserId,
    /// The policy the instance pins. See [`WorkflowPolicy`].
    pub policy: WorkflowPolicy,
    /// When.
    pub started_at: DateTime<Utc>,
}

/// One step row an evaluation would create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStep {
    /// The identifier the row would take.
    pub id: WorkflowStepId,
    /// The instance it belongs to.
    pub instance: WorkflowInstanceId,
    /// Which stage, zero-based.
    pub stage: i32,
    /// Which step of that stage, zero-based. Several rows share a `(stage, position)` — one per
    /// assignee — which is what makes the quorum a count.
    pub position: i32,
    /// What is asked.
    pub step_type: StepType,
    /// Who is asked.
    pub assignee: UserId,
    /// `ASSIGNED` for the opening stage, `PENDING` for every later one. Every step exists from the
    /// moment the instance starts, so a simulation and a progress tracker can both show the whole
    /// shape (`docs/15 §11`) — `PENDING` is what stops a later stage being decided early.
    pub state: StepState,
    /// The quorum this position was instantiated with, frozen onto the row.
    pub quorum: Quorum,
    /// The stage's name, frozen alongside it, so a progress tracker needs no definition lookup.
    pub stage_name: String,
}

/// One thing an evaluation would change.
///
/// Deliberately small and closed: every variant is a statement `crates/workflows/src/repo.rs` knows
/// how to write, and a variant nothing can apply would be a plan that describes more than it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Write the instance row.
    CreateInstance(Box<NewInstance>),
    /// Write one step row.
    CreateStep(Box<NewStep>),
    /// Record a decision on an open step.
    DecideStep {
        /// Which step.
        step: WorkflowStepId,
        /// What it becomes.
        state: StepState,
        /// Who decided — `docs/15 §4`'s `acted_on_behalf_of`, which is the assignee or the
        /// delegate and is recorded either way.
        decided_by: UserId,
        /// Their comment. Required for a rejection (`docs/05-API.md §16`).
        comment: Option<String>,
        /// When.
        at: DateTime<Utc>,
    },
    /// Close a step nobody now needs to answer: a quorum met around it, or a terminal instance.
    ///
    /// `SKIPPED`, never deleted. The row is the record that a named person *was* asked.
    SkipStep {
        /// Which step.
        step: WorkflowStepId,
    },
    /// Open a stage: every `PENDING` step in it becomes `ASSIGNED`.
    OpenStage {
        /// Which instance.
        instance: WorkflowInstanceId,
        /// Which stage.
        stage: i32,
    },
    /// Move the instance to a terminal state.
    FinishInstance {
        /// Which instance.
        instance: WorkflowInstanceId,
        /// What it becomes.
        state: InstanceState,
        /// Why, for the states that carry a reason. `CANCELLED` requires one, in the database as
        /// well as here (`workflow_instances_cancellation_reason`).
        reason: Option<String>,
        /// When.
        at: DateTime<Utc>,
    },
    /// Hand a step to another principal, once.
    Delegate {
        /// Which step.
        step: WorkflowStepId,
        /// To whom.
        to: UserId,
        /// Why. Required — a delegation with no reason is the *silent substitution* `docs/15 §4`
        /// forbids, minus the silence.
        reason: String,
        /// When.
        at: DateTime<Utc>,
    },
}

/// Everything an evaluation would do, in order.
///
/// `#[must_use]` for the reason `enclave_core::PolicyDecision` is: a plan that is neither applied
/// nor rendered is an evaluation whose result was dropped, and on the start path that is a workflow
/// the caller was told had begun and which has no rows.
#[must_use = "a plan that is neither applied nor described is an evaluation whose result was \
              silently discarded"]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    effects: Vec<Effect>,
}

impl Plan {
    /// An empty plan — a decision that changes nothing, which is a real outcome rather than an
    /// error: acknowledging a step whose quorum was already met changes no state.
    pub const fn empty() -> Self {
        Self { effects: Vec::new() }
    }

    /// Adds an effect. Order is preserved and is meaningful — see the module header.
    pub fn push(&mut self, effect: Effect) {
        self.effects.push(effect);
    }

    /// The effects, in order.
    #[must_use]
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// Whether the plan would change nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// The instance this plan would create, if it creates one.
    ///
    /// For the `Location` header and the simulation's summary. A method rather than a field on the
    /// plan so there is one plan type rather than one per evaluation kind.
    #[must_use]
    pub fn created_instance(&self) -> Option<&NewInstance> {
        self.effects.iter().find_map(|effect| match effect {
            Effect::CreateInstance(instance) => Some(instance.as_ref()),
            _ => None,
        })
    }

    /// The steps this plan would create, in order.
    pub fn created_steps(&self) -> impl Iterator<Item = &NewStep> {
        self.effects.iter().filter_map(|effect| match effect {
            Effect::CreateStep(step) => Some(step.as_ref()),
            _ => None,
        })
    }
}
