//! The rows an evaluation reads, decoded into values it can reason about.
//!
//! Deliberately plain data with no connection behind it. [`crate::evaluate`] takes these and
//! returns a [`crate::plan::Plan`]; it never reaches back for another row, which is what makes the
//! evaluation a pure function of what it was handed — `docs/15 §2`'s determinism property, and the
//! reason a simulation and a real run cannot answer differently.
//!
//! There is deliberately **no `WorkflowDefinition` among these facts**. A decision reads the
//! *steps*, which were frozen at instantiation with their quorum and their stage name
//! (`workflow_steps.config`), and the instance, which pinned its policy. It never re-reads
//! `workflow_definitions`. That is what makes an in-flight instance immune to a template edit:
//! `migrations/0024`'s header carries the argument, and it is a security property rather than a
//! convenience — one `UPDATE` on a template must not be able to make a hundred running approvals
//! self-approvable.

use enclave_core::id::{FileId, UserId, VersionId};

use crate::definition::{Quorum, StepType, WorkflowPolicy};
use crate::ids::{WorkflowDefinitionId, WorkflowInstanceId, WorkflowStepId};
use crate::state::{InstanceState, StepState};

/// One `workflow_instances` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceFacts {
    /// Its identifier.
    pub id: WorkflowInstanceId,
    /// The template it came from.
    pub definition_id: WorkflowDefinitionId,
    /// That template's version, for the audit trail.
    pub definition_version: i32,
    /// Where it is in its life.
    pub state: InstanceState,
    /// Which stage is open.
    pub current_stage: i32,
    /// Who started it — one half of `docs/15 §4`'s cancellation rule.
    pub started_by: UserId,
    /// The file it governs. The resource the policy chain is asked about.
    pub resource: FileId,
    /// The version it is bound to. `docs/15 §2.1`.
    pub version: VersionId,
    /// What it pinned at start.
    pub policy: WorkflowPolicy,
}

/// One `workflow_steps` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepFacts {
    /// Its identifier.
    pub id: WorkflowStepId,
    /// The instance it belongs to.
    pub instance: WorkflowInstanceId,
    /// Which stage.
    pub stage: i32,
    /// Which position within it. Several rows share one — see [`Self::quorum`].
    pub position: i32,
    /// What is asked.
    pub step_type: StepType,
    /// Who was asked.
    pub assignee: UserId,
    /// Who it was handed to, at most once.
    pub delegated_to: Option<UserId>,
    /// Where the row is in its life.
    pub state: StepState,
    /// The quorum this *position* was instantiated with, frozen onto every row of it. Counted over
    /// the rows sharing `(stage, position)` rather than tracked as a running total, so a row that
    /// somebody repaired by hand is counted rather than missed.
    pub quorum: Quorum,
    /// The stage's name, frozen alongside, so a progress tracker needs no definition lookup.
    pub stage_name: String,
}

/// One `workflow_definitions` row, as read for a start or a simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionFacts {
    /// Its identifier.
    pub id: WorkflowDefinitionId,
    /// Its version.
    pub version: i32,
    /// Where it may be started.
    pub scope: crate::definition::Scope,
    /// Whether it may be started at all.
    pub enabled: bool,
    /// The policy an instance will pin from it.
    pub policy: WorkflowPolicy,
    /// The decoded stages.
    pub stages: Vec<crate::definition::Stage>,
}

/// The file a workflow is being started on, reduced to what the start actually decides with.
///
/// Three fields and no more, on purpose: a start reads the file to answer *is this definition
/// allowed here* and *which version is the approval of*, and nothing else about the file is any of
/// this crate's business — the policy chain has already decided whether the caller may touch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceFacts {
    /// The file.
    pub file: FileId,
    /// Its workspace, for a `WORKSPACE`-scoped definition.
    pub workspace: uuid::Uuid,
    /// Its library, for a `LIBRARY`-scoped one.
    pub library: uuid::Uuid,
    /// Its current version, which is what the instance binds to and what a later approval is
    /// checked against (`docs/15 §2.1`).
    pub current_version: Option<VersionId>,
}
