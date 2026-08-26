//! Who may act on a step — the authorization half of every decision this crate takes.
//!
//! # A step is an authorization decision, not a state transition
//!
//! Approving a step is two questions, and collapsing them is the defect this module exists to
//! prevent:
//!
//! 1. **May this caller touch this file at all?** The policy chain answers it, in
//!    `crates/api/src/workflows.rs`, for `file.content_read` on the file the instance is bound to.
//!    That question is not asked here and cannot be — this crate holds no `PolicyEngine`.
//! 2. **Was this caller the one being asked?** That is *this* module, and holding the file confers
//!    no part of the answer. A workspace owner who can read every contract in the tenant is not
//!    thereby an approver of any of them.
//!
//! `docs/15 §2`'s fourth core property is the same statement from the other side: *a workflow
//! cannot grant an actor access they do not otherwise have — it can only require action from
//! someone who does.* Question 1 is what stops a workflow granting; question 2 is what makes the
//! requirement land on a named person rather than on anybody who can see the file.
//!
//! # Delegation, and why it is bounded in three places
//!
//! Delegation transfers authority, so an unbounded delegate chain is a privilege-escalation path:
//! the final holder's entitlement was never examined by whoever originally held the step.
//! `ENC-740` bounds it three times over, and the redundancy is deliberate because each layer fails
//! differently:
//!
//! * **The vocabulary.** [`crate::definition::Delegation`] is `FORBIDDEN` or `ONCE` and has no
//!   value meaning *onward*; `migrations/0024` carries the same two-value `CHECK`, so the bound
//!   holds for a `psql` session that never went through the enum.
//! * **The predicate.** [`may_delegate`] refuses a step that already carries a `delegated_to`.
//! * **The statement.** `crates/workflows/src/repo.rs` writes it as
//!   `UPDATE … WHERE delegated_to IS NULL`, one statement, so two delegations racing each other are
//!   resolved by the database rather than by a read-then-write that both sides win.
//!
//! And one bound that is not about chains at all: **the delegate must independently hold the access
//! the step requires**, checked when authority is offered and again when it is used. Checking only
//! at transfer time would make the step a stored capability that outlives the grant behind it — the
//! delegate's rights are revoked, and the step they were handed still works. `crates/api` performs
//! the second check by running the whole chain under the delegate's own request context when they
//! act; this module performs neither check, and takes the answer as an argument, because a crate
//! that could evaluate entitlement would be a second policy chain (`enclave-db`'s header,
//! *no policy checks*).

use enclave_core::id::UserId;

use crate::definition::Delegation;
use crate::error::Refusal;
use crate::facts::{InstanceFacts, StepFacts};

/// Which claim the caller is acting under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// They are the assignee, and the step has not been handed on.
    Assignee,
    /// The step was handed to them.
    Delegate,
}

/// Who currently holds a step: the delegate if there is one, the assignee otherwise.
///
/// One function rather than a `match` at each call site, because the two readings differ in exactly
/// the case that matters — a delegated step where the *original* assignee tries to act. Answering
/// that with `assignee_id` would let a delegation be undone by the person who made it, silently,
/// with the audit row naming them as the decider of a step they had already given away.
#[must_use]
pub fn holder_of(step: &StepFacts) -> UserId {
    step.delegated_to.unwrap_or(step.assignee)
}

/// Whether `actor` holds this step, and under which claim.
///
/// # Errors
///
/// [`Refusal::NotTheHolder`] when they hold neither claim.
pub fn claim_of(step: &StepFacts, actor: UserId) -> Result<Claim, Refusal> {
    match step.delegated_to {
        Some(delegate) if delegate == actor => Ok(Claim::Delegate),
        // Deliberately *not* `else if step.assignee == actor`: once a step is delegated the
        // assignee is no longer its holder. See `holder_of`.
        Some(_) => Err(Refusal::NotTheHolder),
        None if step.assignee == actor => Ok(Claim::Assignee),
        None => Err(Refusal::NotTheHolder),
    }
}

/// Whether `actor` may record a decision on this step.
///
/// The order of these checks is what a caller learns from, so it is chosen rather than incidental:
/// **holdership first**. Someone who does not hold the step is told only that, and learns nothing
/// about whether it was already decided, whose it is, or what the workflow's self-approval posture
/// is. Every later refusal is information only its holder is entitled to.
///
/// # Errors
///
/// * [`Refusal::InstanceNotRunning`] — the instance is over.
/// * [`Refusal::NotTheHolder`] — see [`claim_of`].
/// * [`Refusal::StepNotOpen`] — already decided, skipped or expired.
/// * [`Refusal::StageNotOpen`] — the step is real but its stage has not opened.
/// * [`Refusal::SelfApproval`] — see below.
pub fn may_decide(
    instance: &InstanceFacts,
    step: &StepFacts,
    actor: UserId,
) -> Result<Claim, Refusal> {
    let claim = claim_of(step, actor)?;

    if !matches!(instance.state, crate::state::InstanceState::Running) {
        return Err(Refusal::InstanceNotRunning);
    }
    if !step.state.is_open() {
        return Err(Refusal::StepNotOpen);
    }
    if step.state == crate::state::StepState::Pending || step.stage != instance.current_stage {
        return Err(Refusal::StageNotOpen);
    }

    // `docs/15 §4`: self-approval is rejected by default.
    //
    // **On the acting principal, whoever that is.** Testing `step.assignee` instead would leave
    // delegation as the escalation path in one move: an initiator assigns the step to a colleague,
    // the colleague delegates it back, and the initiator approves their own request with the
    // assignee check reading somebody else's name. `actor` is the person clicking, and it is the
    // only reading that closes it.
    if actor == instance.started_by && !instance.policy.allow_self_approval {
        return Err(Refusal::SelfApproval);
    }

    Ok(claim)
}

/// Whether `actor` may hand this step to `to`.
///
/// `entitled` is whether the *proposed delegate* independently holds the access the step requires.
/// It is an argument rather than something computed here: see the module header.
///
/// # Errors
///
/// * [`Refusal::DelegationForbidden`] — the instance pinned `FORBIDDEN`.
/// * [`Refusal::AlreadyDelegated`] — the one-transfer bound.
/// * [`Refusal::DelegateIsHolder`] — a transfer to the current holder is not a transfer.
/// * [`Refusal::DelegateNotEntitled`] — `entitled` was false.
/// * anything [`may_decide`] refuses, minus self-approval — see below.
pub fn may_delegate(
    instance: &InstanceFacts,
    step: &StepFacts,
    actor: UserId,
    to: UserId,
    entitled: bool,
) -> Result<(), Refusal> {
    // Holdership, openness and stage, in `may_decide`'s order and for its reason. Self-approval is
    // deliberately **not** among them: an initiator who holds a step they may not approve is
    // exactly the person who should be able to hand it to somebody who can, and refusing that would
    // strand the instance. The self-approval check runs when the *decision* is made, against the
    // person making it, which is where it belongs.
    let _claim = claim_of(step, actor)?;
    if !matches!(instance.state, crate::state::InstanceState::Running) {
        return Err(Refusal::InstanceNotRunning);
    }
    if !step.state.is_open() {
        return Err(Refusal::StepNotOpen);
    }
    if step.state == crate::state::StepState::Pending || step.stage != instance.current_stage {
        return Err(Refusal::StageNotOpen);
    }

    if instance.policy.delegation == Delegation::Forbidden {
        return Err(Refusal::DelegationForbidden);
    }
    // The one-transfer bound. `claim_of` has already established that `actor` is the current
    // holder, so reaching here with a delegate set means the actor *is* that delegate trying to
    // pass it on — which is precisely the chain this refuses.
    if step.delegated_to.is_some() {
        return Err(Refusal::AlreadyDelegated);
    }
    if to == actor || to == step.assignee {
        return Err(Refusal::DelegateIsHolder);
    }
    if !entitled {
        return Err(Refusal::DelegateNotEntitled);
    }

    Ok(())
}

/// Whether `actor` may cancel this instance.
///
/// `docs/15 §4`: *cancellation requires the initiator or a workspace owner, a reason, and is
/// audited.* `owns_resource` is the owner half, and it is an argument for the module header's
/// reason — the answer comes from the authorization service in `crates/api`, asked as a capability
/// question about `file.manage_permissions`, which is the closest thing the ACL model has to *owner
/// of this thing*.
///
/// Cancellation is destructive and its blast radius is worth stating: it ends the instance for
/// everybody, including assignees who have already approved. What it does **not** do is rewrite
/// their decisions — see [`crate::evaluate::plan_cancel`].
///
/// # Errors
///
/// * [`Refusal::InstanceNotRunning`] — already over. Cancelling a completed workflow would replace
///   a `COMPLETED` outcome with a `CANCELLED` one, which is a rewriting of what happened.
/// * [`Refusal::NotCancellable`] — neither initiator nor owner.
pub fn may_cancel(
    instance: &InstanceFacts,
    actor: UserId,
    owns_resource: bool,
) -> Result<(), Refusal> {
    if !matches!(instance.state, crate::state::InstanceState::Running) {
        return Err(Refusal::InstanceNotRunning);
    }
    if actor != instance.started_by && !owns_resource {
        return Err(Refusal::NotCancellable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::id::{FileId, VersionId};
    use uuid::Uuid;

    use super::*;
    use crate::definition::{OnNewVersion, Quorum, StepType, WorkflowPolicy};
    use crate::ids::{WorkflowDefinitionId, WorkflowInstanceId, WorkflowStepId};
    use crate::state::{InstanceState, StepState};

    fn user(byte: u8) -> UserId {
        UserId::from_uuid(Uuid::from_bytes([byte; 16]))
    }

    const INITIATOR: u8 = 1;
    const ASSIGNEE: u8 = 2;
    const DELEGATE: u8 = 3;
    const STRANGER: u8 = 4;
    const ONWARD: u8 = 5;

    fn instance() -> InstanceFacts {
        InstanceFacts {
            id: WorkflowInstanceId::new_v7(),
            definition_id: WorkflowDefinitionId::new_v7(),
            definition_version: 1,
            state: InstanceState::Running,
            current_stage: 0,
            started_by: user(INITIATOR),
            resource: FileId::new_v7(),
            version: VersionId::new_v7(),
            policy: WorkflowPolicy {
                allow_self_approval: false,
                delegation: Delegation::Once,
                on_new_version: OnNewVersion::Invalidate,
            },
        }
    }

    fn step(instance: &InstanceFacts) -> StepFacts {
        StepFacts {
            id: WorkflowStepId::new_v7(),
            instance: instance.id,
            stage: 0,
            position: 0,
            step_type: StepType::Approval,
            assignee: user(ASSIGNEE),
            delegated_to: None,
            state: StepState::Assigned,
            quorum: Quorum::All,
            stage_name: "review".to_owned(),
        }
    }

    #[test]
    fn the_assignee_may_decide_and_a_stranger_may_not() {
        let instance = instance();
        let step = step(&instance);
        assert_eq!(may_decide(&instance, &step, user(ASSIGNEE)), Ok(Claim::Assignee));
        assert_eq!(may_decide(&instance, &step, user(STRANGER)), Err(Refusal::NotTheHolder));
    }

    #[test]
    fn a_delegated_step_leaves_the_assignee_and_reaches_the_delegate() {
        // The property `holder_of` exists for: after a delegation the assignee is no longer the
        // holder. Reading `assignee_id` here would let a delegation be silently undone by the
        // person who made it.
        let instance = instance();
        let mut step = step(&instance);
        step.delegated_to = Some(user(DELEGATE));

        assert_eq!(holder_of(&step), user(DELEGATE));
        assert_eq!(may_decide(&instance, &step, user(DELEGATE)), Ok(Claim::Delegate));
        assert_eq!(may_decide(&instance, &step, user(ASSIGNEE)), Err(Refusal::NotTheHolder));
    }

    #[test]
    fn self_approval_is_refused_by_default_and_permitted_when_pinned() {
        let mut instance = instance();
        let mut step = step(&instance);
        step.assignee = user(INITIATOR);

        assert_eq!(may_decide(&instance, &step, user(INITIATOR)), Err(Refusal::SelfApproval));

        instance.policy.allow_self_approval = true;
        assert_eq!(may_decide(&instance, &step, user(INITIATOR)), Ok(Claim::Assignee));
    }

    #[test]
    fn delegating_a_step_back_to_the_initiator_does_not_let_them_self_approve() {
        // The escalation path the self-approval check is written against. If `may_decide` tested
        // `step.assignee` rather than the acting principal, this would be an approval: the assignee
        // column names a colleague, and the initiator is the one clicking.
        let instance = instance();
        let mut step = step(&instance);
        step.delegated_to = Some(user(INITIATOR));

        assert_eq!(holder_of(&step), user(INITIATOR));
        assert_eq!(may_decide(&instance, &step, user(INITIATOR)), Err(Refusal::SelfApproval));
    }

    #[test]
    fn a_step_may_be_delegated_once_and_never_onward() {
        // `ENC-740`, the predicate layer. The vocabulary layer is asserted in `definition.rs` and
        // the statement layer in `repo.rs`.
        let instance = instance();
        let mut step = step(&instance);

        assert_eq!(may_delegate(&instance, &step, user(ASSIGNEE), user(DELEGATE), true), Ok(()));

        step.delegated_to = Some(user(DELEGATE));
        assert_eq!(
            may_delegate(&instance, &step, user(DELEGATE), user(ONWARD), true),
            Err(Refusal::AlreadyDelegated),
            "the delegate handed the step on, so the authority now sits with somebody the \
             original holder never examined"
        );
    }

    #[test]
    fn the_original_assignee_cannot_reclaim_a_delegated_step_by_delegating_it_again() {
        // The other way round the chain: not the delegate passing it on, but the assignee reaching
        // past them. `claim_of` refuses before `AlreadyDelegated` is even reached.
        let instance = instance();
        let mut step = step(&instance);
        step.delegated_to = Some(user(DELEGATE));

        assert_eq!(
            may_delegate(&instance, &step, user(ASSIGNEE), user(ONWARD), true),
            Err(Refusal::NotTheHolder)
        );
    }

    #[test]
    fn a_delegate_who_does_not_hold_the_access_is_refused() {
        // `docs/15 §2`, fourth core property: a workflow cannot grant access. The check is here at
        // the moment authority is offered; `crates/api` runs the whole chain again when it is used.
        let instance = instance();
        let step = step(&instance);
        assert_eq!(
            may_delegate(&instance, &step, user(ASSIGNEE), user(DELEGATE), false),
            Err(Refusal::DelegateNotEntitled)
        );
    }

    #[test]
    fn a_forbidden_delegation_policy_refuses_every_transfer() {
        let mut instance = instance();
        instance.policy.delegation = Delegation::Forbidden;
        let step = step(&instance);
        assert_eq!(
            may_delegate(&instance, &step, user(ASSIGNEE), user(DELEGATE), true),
            Err(Refusal::DelegationForbidden)
        );
    }

    #[test]
    fn a_step_cannot_be_delegated_to_its_own_holder() {
        let instance = instance();
        let step = step(&instance);
        assert_eq!(
            may_delegate(&instance, &step, user(ASSIGNEE), user(ASSIGNEE), true),
            Err(Refusal::DelegateIsHolder)
        );
    }

    #[test]
    fn an_initiator_who_may_not_approve_may_still_delegate() {
        // Deliberate: refusing this would strand an instance whose only assignee is the person who
        // started it. The self-approval refusal belongs to the decision, not to the transfer.
        let instance = instance();
        let mut step = step(&instance);
        step.assignee = user(INITIATOR);

        assert_eq!(may_decide(&instance, &step, user(INITIATOR)), Err(Refusal::SelfApproval));
        assert_eq!(may_delegate(&instance, &step, user(INITIATOR), user(DELEGATE), true), Ok(()));
    }

    #[test]
    fn a_step_in_a_later_stage_cannot_be_decided_early() {
        let instance = instance();
        let mut step = step(&instance);
        step.stage = 1;
        step.state = StepState::Pending;
        assert_eq!(may_decide(&instance, &step, user(ASSIGNEE)), Err(Refusal::StageNotOpen));
    }

    #[test]
    fn a_decided_step_cannot_be_decided_again() {
        let instance = instance();
        let mut step = step(&instance);
        step.state = StepState::Approved;
        assert_eq!(may_decide(&instance, &step, user(ASSIGNEE)), Err(Refusal::StepNotOpen));
    }

    #[test]
    fn holdership_is_checked_before_anything_a_holder_would_learn() {
        // The ordering claim in `may_decide`'s documentation, asserted rather than described: a
        // stranger acting on a step that is *also* already decided is told only that it is not
        // theirs. The other order would let anyone enumerate which steps have been answered.
        let instance = instance();
        let mut step = step(&instance);
        step.state = StepState::Approved;
        assert_eq!(may_decide(&instance, &step, user(STRANGER)), Err(Refusal::NotTheHolder));
    }

    #[test]
    fn the_initiator_may_cancel_and_a_stranger_may_not() {
        let instance = instance();
        assert_eq!(may_cancel(&instance, user(INITIATOR), false), Ok(()));
        assert_eq!(may_cancel(&instance, user(STRANGER), false), Err(Refusal::NotCancellable));
        assert_eq!(may_cancel(&instance, user(STRANGER), true), Ok(()));
    }

    #[test]
    fn a_finished_instance_cannot_be_cancelled() {
        // Otherwise cancellation is a way to overwrite a COMPLETED outcome with a CANCELLED one,
        // which is a rewriting of what happened rather than an ending of what is happening.
        let mut instance = instance();
        instance.state = InstanceState::Completed;
        assert_eq!(may_cancel(&instance, user(INITIATOR), true), Err(Refusal::InstanceNotRunning));
    }
}
