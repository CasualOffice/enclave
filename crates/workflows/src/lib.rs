//! `enclave-workflows` — the workflow engine: stages, steps, approvals and the authority to make
//! them.
//!
//! `docs/15-WORKFLOWS-AND-SIGNING.md §§2–5` is authoritative for what a workflow *is*;
//! `docs/05-API.md §16` for the wire; `migrations/0024_workflows.sql` for the tables and for the
//! four places this deliberately departs from `docs/15 §7`. `ENC-739`.
//!
//! # The shape, and the one thing to understand about it
//!
//! ```text
//!   facts (rows, decoded)  ──►  evaluate  ──►  Plan  ──►  repo::apply  ──►  rows
//!                                  │                 └──►  rendered as a simulation
//!                                  │
//!                              authority
//! ```
//!
//! **[`evaluate`] cannot write.** Its functions take no connection, no pool, nothing that could
//! reach a database; they take decoded facts and return a [`plan::Plan`]. That is not a style
//! choice, it is `plans/M4-GOVERNANCE.md` D28 made structural:
//!
//! > `SIMULATION` must be indistinguishable from `ENFORCE` except in its effect. If simulation
//! > takes a cheaper path, it measures something other than what enforcement will do.
//!
//! `POST /workflows/definitions/{id}/simulate` and `POST /files/{id}/workflows` call one function,
//! [`evaluate::plan_start`], behind one policy-chain call, for one action, on one resource. They
//! differ in a single statement: apply the plan, or describe it. There is no `simulate: bool`
//! anywhere in this crate for a second path to hang off — the same guarantee `migrations/0021`
//! records for `crates/dlp`, where `RuleSet::evaluate` takes no mode argument and so *the code that
//! reaches a conclusion has not been told which mode is running*. `ENC-741`.
//!
//! # A step is an authorization decision
//!
//! Two questions, and [`authority`] answers only the second:
//!
//! 1. **May this caller touch this file?** The policy chain, in `crates/api/src/workflows.rs`. This
//!    crate holds no `PolicyEngine` and takes no policy decision — `enclave-db`'s header states the
//!    rule (*no policy checks; a guard that also made access decisions would be a second, quieter
//!    policy chain*) and it applies to a domain crate just as much.
//! 2. **Was this caller the one being asked?** Holding the file confers no part of the answer. A
//!    workspace owner who can read every contract in the tenant is not thereby an approver of any
//!    of them.
//!
//! `docs/15 §2`'s fourth core property is the same statement from the other side: *a workflow
//! cannot grant an actor access they do not otherwise have — it can only require action from
//! someone who does.*
//!
//! # Delegation is bounded three times, in three different layers
//!
//! An unbounded delegate chain is a privilege-escalation path: the final holder's entitlement was
//! never examined by whoever originally held the step. `ENC-740`:
//!
//! * **the vocabulary** — [`definition::Delegation`] is `FORBIDDEN` or `ONCE` and has no value
//!   meaning *onward*, and `migrations/0024` carries the same two-value `CHECK`, so the bound holds
//!   for a `psql` session;
//! * **the predicate** — [`authority::may_delegate`] refuses a step that already has a delegate;
//! * **the statement** — [`repo`]'s `UPDATE … WHERE delegated_to IS NULL`, which is what resolves
//!   two simultaneous delegations to one.
//!
//! Plus the bound that is not about chains: a delegate must independently hold the access the step
//! requires, checked when authority is offered *and* again when it is used. One check would make
//! the step a stored capability that outlives the grant behind it.
//!
//! # What is not built
//!
//! Recorded here as well as in `TRACKER.md`, because an absence a reader has to infer is one they
//! will assume away:
//!
//! * **Triggers** (`docs/15 §5`). Every instance is started manually. `workflow_definitions` has no
//!   `trigger` column rather than an unread one — `ENC-745`.
//! * **`AUTOMATION` and `CONDITION` steps** (`§3`). No allowlist of platform actions exists, and a
//!   step nothing can decide is an instance that stalls silently — `ENC-745`.
//! * **Rework branches** (`§4`). A rejection terminates the instance, which is the section's own
//!   default — `ENC-745`.
//! * **Group and dynamic assignees** (`§2`) — `ENC-744`.
//! * **SLA breach and escalation** (`§4`). `due_at` is stored and nothing sweeps it.
//! * **The proactive half of W3** (`§2.1`). A superseding version expires an instance at the moment
//!   somebody tries to approve it, which is where the property bites; nothing notices at commit
//!   time — `ENC-743`.
//!
//! See `docs/02-HLD.md §4` for where this crate sits.

pub mod authority;
pub mod definition;
pub mod error;
pub mod evaluate;
pub mod facts;
pub mod ids;
pub mod plan;
pub mod repo;
pub mod state;

pub use authority::{holder_of, Claim};
pub use definition::{
    Delegation, OnNewVersion, Quorum, Scope, Stage, StepSpec, StepType, WorkflowDefinition,
    WorkflowPolicy,
};
pub use error::{Refusal, WorkflowError};
pub use evaluate::{plan_cancel, plan_decision, plan_delegate, plan_start, Decision};
pub use facts::{DefinitionFacts, InstanceFacts, ResourceFacts, StepFacts};
pub use ids::{WorkflowDefinitionId, WorkflowInstanceId, WorkflowStepId};
pub use plan::{Effect, NewInstance, NewStep, Plan};
pub use repo::Task;
pub use state::{InstanceState, StepState};
