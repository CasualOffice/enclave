//! What can go wrong, and the one distinction that matters at the edge.
//!
//! Two families, kept apart because they map to different HTTP statuses and — more importantly —
//! because only one of them is a *policy* refusal:
//!
//! * [`WorkflowError::Refused`] carries a [`Refusal`], which is this crate saying **no** about a
//!   step: not your step, already decided, self-approval, an onward delegation. Every one of these
//!   reaches a caller through `crates/api`'s handler audit port, so it is a row before it is a
//!   response (`ENC-606`, `CLAUDE.md` rule 10).
//! * everything else is a malformed definition, a malformed stored row, or a database failure.
//!
//! The split is not stylistic. A `Refused` that leaked out as a validation error would be a denial
//! with no audit row behind it, which is exactly the class of defect `ENC-606` closed one layer up.

use enclave_db::DbError;

/// Anything this crate can fail with.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// The caller may not do this to this step, or this step is not in a state to be done to.
    ///
    /// The only variant that is a policy answer rather than a fault. See [`Refusal`].
    #[error("refused: {0}")]
    Refused(#[from] Refusal),

    /// The instance's version has been superseded: the caller is refused **and** the instance is
    /// expired by the plan this carries.
    ///
    /// A variant of its own rather than a plain [`Refusal`], because this is the one refusal that
    /// has to *change something*. `docs/15 §2.1` invalidates in-flight approvals when a new version
    /// lands; refusing without expiring would leave the instance `RUNNING`, refusing every
    /// subsequent attempt in exactly the same way, with nothing in the row saying why — an
    /// approval queue that quietly never finishes. `crates/api` applies the plan and then answers
    /// with [`Refusal::VersionSuperseded`], so the refusal and the state agree in one request.
    ///
    /// Boxed because the plan is much larger than every other variant and clippy's
    /// `result_large_err` is right about what that costs on the happy path.
    #[error("the version under review has been superseded")]
    Superseded(Box<crate::plan::Plan>),

    /// A stored or submitted definition document does not decode.
    ///
    /// Strict and closed, for `crates/dlp`'s Q16 reason: a lenient decoder accepts a document and
    /// silently drops the half it did not understand, and the half it drops is the half somebody
    /// wrote deliberately. A definition naming an unbuilt step type is refused *by name* here
    /// rather than instantiated as something else.
    #[error("the workflow definition is not usable: {0}")]
    Definition(String),

    /// A row in the database does not decode into a value this crate can evaluate.
    ///
    /// Distinct from [`Self::Definition`] because the remedy is different: a bad *submitted*
    /// definition is the caller's to fix, and a bad *stored* row is an operator's. It becomes a
    /// `500` at the edge, deliberately, because a caller can do nothing about it.
    #[error("a stored workflow row is not usable: {0}")]
    Stored(String),

    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// A refusal about a step, an instance, or the authority to act on one.
///
/// A closed enumeration rather than a string, for the reason `enclave_core::ReasonCode` is one: it
/// is what the caller is told and what the audit row will carry, and those two have to be the same
/// word. `crates/api/src/workflows.rs` maps each variant to exactly one wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The caller holds neither the assignment nor the delegation for this step.
    ///
    /// The core authorization statement of the whole surface: approving a step means *this actor
    /// was entitled to approve this step*, which is a fact about the assignment and not about the
    /// caller's rights over the file. Holding `file.content_read` gets you past the policy chain;
    /// it does not make you the approver.
    #[error("the caller does not hold this step")]
    NotTheHolder,

    /// The step has already been decided, skipped or expired.
    #[error("the step is no longer open")]
    StepNotOpen,

    /// The instance is not running.
    #[error("the instance is not running")]
    InstanceNotRunning,

    /// The step's stage has not opened yet.
    ///
    /// Stages are ordered (`docs/15 §2`); a step in a later stage exists from the moment the
    /// instance starts, so that a simulation and an inbox can both show the whole shape — but it is
    /// `PENDING`, and deciding it early would let a workflow be completed out of order.
    #[error("the step's stage has not opened")]
    StageNotOpen,

    /// Self-approval, with the definition not permitting it.
    ///
    /// `docs/15 §4`: rejected by default, permitted only by `allow_self_approval`, which surfaces
    /// as a control weakness. The check is on the **acting** principal, whoever that is — the
    /// delegate as much as the assignee — because otherwise delegation is the escalation path: an
    /// initiator delegates a step to themselves and approves their own request.
    #[error("self-approval is not permitted by this workflow")]
    SelfApproval,

    /// This step type does not take the decision that was asked of it.
    ///
    /// A `SIGNATURE` step is decided by the signing ceremony (`docs/15 §6`), never by a click on
    /// `/approve`; a `REVIEW` step is comment-and-acknowledge and has no gate to reject
    /// (`docs/15 §3`).
    #[error("this step type does not take that decision")]
    WrongStepType,

    /// The definition forbids delegation.
    #[error("this workflow does not permit delegation")]
    DelegationForbidden,

    /// The step has already been delegated once, and there is no second transfer.
    ///
    /// The bound, and the reason it is a bound: an onward chain means the final holder's
    /// entitlement to the authority was never examined by whoever originally held it. `ENC-740`.
    #[error("this step has already been delegated")]
    AlreadyDelegated,

    /// The proposed delegate is the caller, or is already the assignee.
    #[error("a step cannot be delegated to its current holder")]
    DelegateIsHolder,

    /// The proposed delegate does not independently hold the right the step requires.
    ///
    /// `docs/15 §2`, fourth core property: *a workflow cannot grant an actor access they do not
    /// otherwise have — it can only require action from someone who does.* Checked when authority
    /// is offered as well as when it is used.
    #[error("the proposed delegate does not hold the required access")]
    DelegateNotEntitled,

    /// The instance is bound to a version that is no longer the file's current one.
    ///
    /// `docs/15 §2.1` and `§12` W3. The refusal is the enforcement point: an approval over content
    /// that has been superseded is exactly what "an approval approves what was actually reviewed"
    /// forbids. `on_new_version = CONTINUE` is the documented, audited opt-out.
    #[error("the version under review has been superseded")]
    VersionSuperseded,

    /// A cancellation from someone who is neither the initiator nor an owner of the resource.
    #[error("only the initiator or an owner may cancel this workflow")]
    NotCancellable,

    /// The definition's scope does not reach the file it was started on.
    ///
    /// A `LIBRARY`-scoped definition run against a file in another library. The column earns its
    /// place here (`migrations/0024`) rather than being stored and ignored.
    #[error("the definition's scope does not cover this file")]
    OutOfScope,

    /// The definition is disabled.
    #[error("the definition is not enabled")]
    DefinitionDisabled,
}
