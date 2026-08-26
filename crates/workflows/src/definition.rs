//! The template: stages, steps, assignees and quorums, and the policy an instance pins from it.
//!
//! `docs/15-WORKFLOWS-AND-SIGNING.md §2` is authoritative for the model and `§3` for the step
//! types. This module is only how one is written down, decoded and validated.
//!
//! # Decoding is strict and closed, and that is a control rather than tidiness
//!
//! `crates/dlp/src/store.rs` records the reason and `ENC-615` watched it fail: a decoder that
//! tolerates unknown fields accepts a document and *silently drops* the part it did not understand.
//! For a DLP rule that lost a pattern; here it would lose an assignee, a quorum, or the difference
//! between `APPROVAL` and `REVIEW` — and the author would see it stored, see it listed, and find
//! out at the moment the workflow behaved unlike the one they wrote.
//!
//! So every struct is `deny_unknown_fields`, every enum is a closed vocabulary, and
//! [`WorkflowDefinition::decode`] validates the shape rather than trusting it. `AUTOMATION` and
//! `CONDITION` are refused **by name**, which is what `migrations/0024`'s `step_type` `CHECK`
//! enforces one layer down: `docs/15 §3` defines both, neither has an evaluator, and a step nothing
//! can decide is an instance that stalls with no explanation.

use enclave_core::id::UserId;
use serde::{Deserialize, Serialize};

use crate::error::WorkflowError;

/// The largest definition this crate will decode.
///
/// Not arbitrary: every step in every stage becomes a `workflow_steps` row at instantiation, and
/// every one of those rows lands in somebody's inbox. A definition with a thousand stages is not a
/// workflow, it is a way to write a million rows with one request — so the bound is here, where it
/// is cheap, rather than discovered when the `INSERT` takes a minute.
const MAX_STAGES: usize = 32;

/// The most steps one stage may hold.
const MAX_STEPS_PER_STAGE: usize = 32;

/// The most assignees one step may name.
const MAX_ASSIGNEES: usize = 64;

/// What a step asks of the people named on it.
///
/// `docs/15 §3`. Two of the six types it defines are deliberately absent — see the module header
/// and `migrations/0024`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepType {
    /// Assignees approve or reject. The only type with a gate decision.
    Approval,
    /// Comment-and-acknowledge, without a gate decision. It can be acknowledged and it cannot be
    /// rejected: there is no decision for a rejection to gate.
    Review,
    /// A signing ceremony (`docs/15 §6`), decided by `crates/signing` and never by `/approve`.
    /// Storable here because `signature_requests.workflow_step_id` anchors on these rows.
    Signature,
    /// A human task with a due date. Completed, never rejected.
    Task,
}

impl StepType {
    /// The stored spelling, which is `migrations/0024`'s `CHECK` vocabulary exactly.
    ///
    /// A second spelling anywhere would guarantee a mismatch whose symptom is *"the step stopped
    /// being findable"*, which is `migrations/0021`'s note on `dlp_rules.action`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "APPROVAL",
            Self::Review => "REVIEW",
            Self::Signature => "SIGNATURE",
            Self::Task => "TASK",
        }
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for anything outside the vocabulary — including `AUTOMATION` and
    /// `CONDITION`, which the migration's `CHECK` cannot produce and which would otherwise arrive
    /// from a database restored across a schema change.
    pub fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "APPROVAL" => Ok(Self::Approval),
            "REVIEW" => Ok(Self::Review),
            "SIGNATURE" => Ok(Self::Signature),
            "TASK" => Ok(Self::Task),
            other => Err(WorkflowError::Stored(format!("unknown step type `{other}`"))),
        }
    }

    /// Whether `/approve` may decide this step.
    ///
    /// `SIGNATURE` is excluded because a signature is not an approval: `docs/15 §11` refuses even
    /// *bulk* approval for signatures, and `§6` makes the ceremony the thing that produces one.
    /// Letting a click on `/approve` mark a step `APPROVED` when a signature was required would be
    /// a workflow that reports it obtained something it did not.
    #[must_use]
    pub const fn takes_approval(self) -> bool {
        matches!(self, Self::Approval | Self::Review | Self::Task)
    }

    /// Whether `/reject` may decide this step.
    ///
    /// `APPROVAL` alone. `docs/15 §3` gives `REVIEW` no gate decision, a `TASK` is done or not
    /// done, and a declined signature is `crates/signing`'s to record with the evidence that
    /// belongs to it.
    #[must_use]
    pub const fn takes_rejection(self) -> bool {
        matches!(self, Self::Approval)
    }
}

/// How many of a step's assignees must approve before the step is satisfied.
///
/// `docs/15 §3`. On the *step*, over its assignees — which is why one step spec becomes several
/// `workflow_steps` rows sharing `(stage, position)`, and why a quorum is a count over that key
/// rather than a number somebody has to keep in step with the rows.
///
/// `SEQUENTIAL` from §3 is deliberately absent: it is an *ordering* rather than a count, it needs a
/// notion of whose turn it is that nothing here models, and a value stored under that name while
/// being evaluated as `ALL` would be a workflow that told three people at once that it was their
/// turn. `ENC-745`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Quorum {
    /// Every assignee.
    All,
    /// Any one of them.
    Any,
    /// A named number of them.
    NOf {
        /// How many approvals satisfy the step. Validated against the assignee count at decode.
        n: u32,
    },
}

impl Quorum {
    /// How many approvals satisfy a position holding `assignees` rows.
    ///
    /// Saturating rather than panicking on a stored row that disagrees with itself: a quorum of
    /// five over three assignees is unsatisfiable, which would strand the instance. The decoder
    /// refuses to *write* one; this is what a row written before the decoder existed gets, and it
    /// errs towards the stricter reading rather than towards completing something nobody approved.
    #[must_use]
    pub const fn required(self, assignees: u32) -> u32 {
        match self {
            Self::All => assignees,
            Self::Any => 1,
            Self::NOf { n } => {
                if n > assignees {
                    assignees
                } else {
                    n
                }
            }
        }
    }
}

/// One step of a stage: a type, the people it asks, and how many of them must answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepSpec {
    /// What is being asked.
    #[serde(rename = "type")]
    pub step_type: StepType,
    /// Who is being asked. Users only — `migrations/0024` and `ENC-744` carry why.
    pub assignees: Vec<UserId>,
    /// How many of them must answer. Absent means [`Quorum::All`], which is the reading that
    /// cannot accidentally complete a step somebody was still looking at.
    #[serde(default = "all_quorum")]
    pub quorum: Quorum,
}

const fn all_quorum() -> Quorum {
    Quorum::All
}

/// One stage: a name, and the steps that run in parallel inside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stage {
    /// What the stage is called, for the progress tracker `docs/15 §11` requires.
    pub name: String,
    /// Its steps. Parallel within the stage (`docs/15 §2`); the stage advances when every one of
    /// them has met its quorum.
    pub steps: Vec<StepSpec>,
}

/// The decoded `workflow_definitions.definition` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowDefinition {
    /// Ordered stages. Non-empty — see [`Self::validate`].
    pub stages: Vec<Stage>,
}

impl WorkflowDefinition {
    /// Decodes and validates a definition document.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Definition`], naming what was wrong. The message reaches the caller in the
    /// `details` array of the `docs/05-API.md §5` envelope, which is where a strict decoder earns
    /// its keep: *"unknown variant `AUTOMATION`"* tells an author what to change, and *"the
    /// definition was rejected"* sends them to `psql`.
    pub fn decode(document: &serde_json::Value) -> Result<Self, WorkflowError> {
        let decoded: Self = serde_json::from_value(document.clone())
            .map_err(|error| WorkflowError::Definition(error.to_string()))?;
        decoded.validate()?;
        Ok(decoded)
    }

    /// The shape claims serde cannot make.
    ///
    /// Each of these is a definition that would be *accepted* and then behave unlike a workflow:
    ///
    /// * **no stages** — the instance completes the moment it starts, so the workflow approves
    ///   everything it is pointed at without asking anybody. `migrations/0024` holds this one in
    ///   the database too, because it is the one whose failure mode is silent success.
    /// * **an empty stage** — the same, one stage in.
    /// * **a step with no assignees** — a position whose quorum is zero, satisfied on creation.
    /// * **a repeated assignee within one step** — the same person counted twice towards a
    ///   two-of-three quorum, which is a separation of duties that is not one. The database holds
    ///   it as well (`workflow_steps_one_row_per_assignee`); it is refused here so the author is
    ///   told what is wrong rather than shown a constraint name.
    /// * **`nOf` above the assignee count** — unsatisfiable, so the instance strands.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Definition`].
    fn validate(&self) -> Result<(), WorkflowError> {
        if self.stages.is_empty() {
            return Err(WorkflowError::Definition(
                "a definition needs at least one stage; one with none completes the instant it \
                 starts, approving whatever it was pointed at without asking anybody"
                    .to_owned(),
            ));
        }
        if self.stages.len() > MAX_STAGES {
            return Err(WorkflowError::Definition(format!(
                "a definition may hold at most {MAX_STAGES} stages"
            )));
        }

        for (index, stage) in self.stages.iter().enumerate() {
            if stage.name.trim().is_empty() {
                return Err(WorkflowError::Definition(format!("stage {index} has no name")));
            }
            if stage.steps.is_empty() {
                return Err(WorkflowError::Definition(format!(
                    "stage {index} (`{}`) has no steps",
                    stage.name
                )));
            }
            if stage.steps.len() > MAX_STEPS_PER_STAGE {
                return Err(WorkflowError::Definition(format!(
                    "stage {index} holds more than {MAX_STEPS_PER_STAGE} steps"
                )));
            }

            for (position, step) in stage.steps.iter().enumerate() {
                if step.assignees.is_empty() {
                    return Err(WorkflowError::Definition(format!(
                        "stage {index}, step {position} names no assignee, so its quorum is \
                         satisfied before anybody is asked"
                    )));
                }
                if step.assignees.len() > MAX_ASSIGNEES {
                    return Err(WorkflowError::Definition(format!(
                        "stage {index}, step {position} names more than {MAX_ASSIGNEES} assignees"
                    )));
                }

                let mut seen = step.assignees.clone();
                seen.sort_unstable_by_key(UserId::as_uuid);
                seen.dedup_by_key(|id| id.as_uuid());
                if seen.len() != step.assignees.len() {
                    return Err(WorkflowError::Definition(format!(
                        "stage {index}, step {position} names the same assignee twice, which lets \
                         one person satisfy a quorum meant to need several"
                    )));
                }

                if let Quorum::NOf { n } = step.quorum {
                    let assignees = u32::try_from(step.assignees.len()).unwrap_or(u32::MAX);
                    if n == 0 || n > assignees {
                        return Err(WorkflowError::Definition(format!(
                            "stage {index}, step {position} asks for {n} of {assignees} \
                             approvals, which cannot be satisfied"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Whether a step may be handed on, and how far.
///
/// **There is no variant meaning an onward chain**, and that is the point rather than an omission
/// (`ENC-740`, `migrations/0024`). Delegation transfers authority; a chain means the third holder's
/// entitlement to it was never examined by whoever originally held the step. The database carries
/// the same two-value vocabulary, so the bound holds on paths that never went through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Delegation {
    /// A step stays with the person it was given to.
    Forbidden,
    /// It may be handed on exactly once, to a named principal who independently holds the access
    /// the step requires.
    Once,
}

impl Delegation {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "FORBIDDEN",
            Self::Once => "ONCE",
        }
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for anything else.
    pub fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "FORBIDDEN" => Ok(Self::Forbidden),
            "ONCE" => Ok(Self::Once),
            other => Err(WorkflowError::Stored(format!("unknown delegation policy `{other}`"))),
        }
    }
}

/// What a new version does to an in-flight instance.
///
/// `docs/15 §2.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OnNewVersion {
    /// The default. An approval approves what was actually reviewed, so content moving on ends the
    /// instance rather than silently re-pointing it.
    Invalidate,
    /// The documented, rare opt-out. §2.1 says it is *audited loudly*, which here means the
    /// instance's own row records that it was started under it.
    Continue,
}

impl OnNewVersion {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalidate => "INVALIDATE",
            Self::Continue => "CONTINUE",
        }
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for anything else.
    pub fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "INVALIDATE" => Ok(Self::Invalidate),
            "CONTINUE" => Ok(Self::Continue),
            other => Err(WorkflowError::Stored(format!("unknown on-new-version policy `{other}`"))),
        }
    }
}

/// The three policies an instance pins from its definition at start.
///
/// Pinned rather than read live, and `migrations/0024`'s header carries the argument: a definition
/// is a template, and one `UPDATE` on a template must not be able to make a hundred in-flight
/// approvals self-approvable with nothing recording that the terms changed mid-flight. It is
/// `docs/15 §2`'s determinism property expressed as a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowPolicy {
    /// Whether the acting principal may be the person who started the instance.
    pub allow_self_approval: bool,
    /// Whether, and how far, a step may be handed on.
    pub delegation: Delegation,
    /// What a superseding version does.
    pub on_new_version: OnNewVersion,
}

/// Where a definition may be started.
///
/// Read at start rather than stored and ignored — see `migrations/0024`, which keeps this column
/// and drops `trigger` on exactly that test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Anywhere in the tenant.
    Tenant,
    /// Only files inside one workspace.
    Workspace(uuid::Uuid),
    /// Only files inside one library.
    Library(uuid::Uuid),
}

impl Scope {
    /// Whether a file in `workspace`/`library` is inside this scope.
    #[must_use]
    pub fn covers(self, workspace: uuid::Uuid, library: uuid::Uuid) -> bool {
        match self {
            Self::Tenant => true,
            Self::Workspace(id) => id == workspace,
            Self::Library(id) => id == library,
        }
    }

    /// The stored `(scope_type, scope_id)` pair.
    #[must_use]
    pub const fn columns(self) -> (&'static str, Option<uuid::Uuid>) {
        match self {
            Self::Tenant => ("TENANT", None),
            Self::Workspace(id) => ("WORKSPACE", Some(id)),
            Self::Library(id) => ("LIBRARY", Some(id)),
        }
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for an unknown type, or for the `NULL`/`NOT NULL` disagreement
    /// `workflow_definitions_scope_target` forbids — the check exists, and a row from before it did
    /// must not be read as tenant-wide by accident.
    pub fn parse(scope_type: &str, scope_id: Option<uuid::Uuid>) -> Result<Self, WorkflowError> {
        match (scope_type, scope_id) {
            ("TENANT", None) => Ok(Self::Tenant),
            ("WORKSPACE", Some(id)) => Ok(Self::Workspace(id)),
            ("LIBRARY", Some(id)) => Ok(Self::Library(id)),
            (other, _) => Err(WorkflowError::Stored(format!(
                "scope type `{other}` disagrees with its scope id"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn user(byte: u8) -> UserId {
        UserId::from_uuid(uuid::Uuid::from_bytes([byte; 16]))
    }

    fn one_stage(steps: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "stages": [{ "name": "review", "steps": steps }] })
    }

    #[test]
    fn a_well_formed_definition_decodes() {
        let document = one_stage(serde_json::json!([{
            "type": "APPROVAL",
            "assignees": [user(1).as_uuid(), user(2).as_uuid()],
            "quorum": { "n_of": { "n": 2 } },
        }]));
        let decoded = WorkflowDefinition::decode(&document).expect("a valid definition");
        assert_eq!(decoded.stages.len(), 1);
        assert_eq!(decoded.stages[0].steps[0].quorum, Quorum::NOf { n: 2 });
    }

    #[test]
    fn an_absent_quorum_means_all_rather_than_any() {
        // The direction matters: `Any` would let one of five approvers complete a step the other
        // four were still looking at, and an omitted field must not be the permissive reading.
        let document = one_stage(serde_json::json!([{
            "type": "APPROVAL",
            "assignees": [user(1).as_uuid()],
        }]));
        let decoded = WorkflowDefinition::decode(&document).expect("a valid definition");
        assert_eq!(decoded.stages[0].steps[0].quorum, Quorum::All);
    }

    #[test]
    fn an_automation_step_is_refused_by_name() {
        // `docs/15 §3` defines AUTOMATION; nothing here can evaluate one. The point of this
        // assertion is the *message*: an author who is told the variant is unknown can change it.
        let document = one_stage(serde_json::json!([{
            "type": "AUTOMATION",
            "assignees": [user(1).as_uuid()],
        }]));
        let error = WorkflowDefinition::decode(&document).expect_err("AUTOMATION has no evaluator");
        assert!(
            format!("{error}").contains("AUTOMATION"),
            "the refusal must name the variant it refused, not merely refuse: {error}"
        );
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_dropped() {
        // `ENC-615`'s finding at a new boundary. Without `deny_unknown_fields` this decodes and the
        // escalation policy is silently absent from the workflow that was written.
        let document = one_stage(serde_json::json!([{
            "type": "APPROVAL",
            "assignees": [user(1).as_uuid()],
            "escalateTo": user(2).as_uuid(),
        }]));
        let error = WorkflowDefinition::decode(&document).expect_err("unknown fields are refused");
        assert!(format!("{error}").contains("escalateTo"), "{error}");
    }

    #[test]
    fn a_definition_with_no_stages_is_refused() {
        let error = WorkflowDefinition::decode(&serde_json::json!({ "stages": [] }))
            .expect_err("an empty definition approves everything it is pointed at");
        assert!(format!("{error}").contains("at least one stage"), "{error}");
    }

    #[test]
    fn a_step_naming_the_same_assignee_twice_is_refused() {
        let document = one_stage(serde_json::json!([{
            "type": "APPROVAL",
            "assignees": [user(1).as_uuid(), user(1).as_uuid()],
            "quorum": { "n_of": { "n": 2 } },
        }]));
        let error = WorkflowDefinition::decode(&document)
            .expect_err("one person may not satisfy a two-person quorum alone");
        assert!(format!("{error}").contains("same assignee twice"), "{error}");
    }

    #[test]
    fn an_unsatisfiable_quorum_is_refused() {
        let document = one_stage(serde_json::json!([{
            "type": "APPROVAL",
            "assignees": [user(1).as_uuid()],
            "quorum": { "n_of": { "n": 3 } },
        }]));
        let error = WorkflowDefinition::decode(&document).expect_err("3 of 1 strands the instance");
        assert!(format!("{error}").contains("cannot be satisfied"), "{error}");
    }

    #[test]
    fn a_stored_quorum_above_the_assignee_count_clamps_rather_than_stranding() {
        assert_eq!(Quorum::NOf { n: 9 }.required(3), 3);
        assert_eq!(Quorum::All.required(3), 3);
        assert_eq!(Quorum::Any.required(3), 1);
    }

    #[test]
    fn only_approval_steps_take_a_rejection() {
        assert!(StepType::Approval.takes_rejection());
        assert!(!StepType::Review.takes_rejection());
        assert!(!StepType::Task.takes_rejection());
        assert!(!StepType::Signature.takes_rejection());
    }

    #[test]
    fn a_signature_step_is_never_decided_by_approve() {
        // A click on `/approve` marking a SIGNATURE step APPROVED would be the workflow reporting
        // it obtained a signature it never obtained (`docs/15 §6`, §11).
        assert!(!StepType::Signature.takes_approval());
        assert!(StepType::Approval.takes_approval());
        assert!(StepType::Review.takes_approval());
        assert!(StepType::Task.takes_approval());
    }

    #[test]
    fn the_step_type_vocabulary_round_trips_through_the_stored_spelling() {
        // A second spelling anywhere is a step that stops being findable (`migrations/0021`).
        for step_type in [StepType::Approval, StepType::Review, StepType::Signature, StepType::Task]
        {
            assert_eq!(StepType::parse(step_type.as_str()).expect("round trip"), step_type);
        }
        assert!(StepType::parse("AUTOMATION").is_err());
        assert!(StepType::parse("CONDITION").is_err());
    }

    #[test]
    fn the_delegation_vocabulary_has_no_onward_value() {
        // `ENC-740`. The enum is the bound; this asserts nothing has quietly grown a third arm.
        assert_eq!(Delegation::parse("ONCE").expect("once"), Delegation::Once);
        assert_eq!(Delegation::parse("FORBIDDEN").expect("forbidden"), Delegation::Forbidden);
        for attempt in ["CHAIN", "ALWAYS", "UNLIMITED", "ONWARD", "TWICE"] {
            assert!(
                Delegation::parse(attempt).is_err(),
                "`{attempt}` decoded, so an unbounded delegate chain has become storable"
            );
        }
    }

    #[test]
    fn a_library_scope_does_not_cover_another_library() {
        let library = uuid::Uuid::from_bytes([7; 16]);
        let workspace = uuid::Uuid::from_bytes([8; 16]);
        let elsewhere = uuid::Uuid::from_bytes([9; 16]);

        assert!(Scope::Library(library).covers(workspace, library));
        assert!(!Scope::Library(library).covers(workspace, elsewhere));
        assert!(Scope::Workspace(workspace).covers(workspace, elsewhere));
        assert!(!Scope::Workspace(workspace).covers(elsewhere, library));
        assert!(Scope::Tenant.covers(elsewhere, elsewhere));
    }

    #[test]
    fn a_scope_whose_type_and_id_disagree_is_refused() {
        // `workflow_definitions_scope_target` forbids the row; this is what a row from before the
        // constraint gets, and it must not be read as tenant-wide.
        assert!(Scope::parse("TENANT", Some(uuid::Uuid::nil())).is_err());
        assert!(Scope::parse("LIBRARY", None).is_err());
    }
}
