//! The two lifecycles of `docs/15-WORKFLOWS-AND-SIGNING.md §4`.
//!
//! ```text
//! WorkflowInstance:  DRAFT -> RUNNING -> COMPLETED
//!                               |  \-> REJECTED
//!                               |  \-> CANCELLED
//!                               \----> EXPIRED
//!
//! StepInstance:      PENDING -> ASSIGNED -> {APPROVED | REJECTED | SIGNED | DECLINED | SKIPPED |
//!                                            EXPIRED}
//! ```
//!
//! Closed enumerations whose `as_str` is `migrations/0024`'s `CHECK` vocabulary exactly. A second
//! spelling anywhere would guarantee a mismatch whose symptom is *"the instance stopped being
//! found"*, which is `migrations/0021`'s note on `dlp_rules.action`.

use serde::Serialize;

use crate::error::WorkflowError;

/// Where an instance is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstanceState {
    /// Created but not started. Nothing produces one today — `POST /files/{id}/workflows` starts a
    /// running instance — and it is in the vocabulary because `docs/15 §4` defines it and a state a
    /// future draft surface writes must be readable by this one.
    Draft,
    /// In flight.
    Running,
    /// Every stage satisfied.
    Completed,
    /// A rejection terminated it.
    Rejected,
    /// The initiator or an owner ended it, with a reason.
    Cancelled,
    /// It timed out, or the version it was bound to was superseded (`docs/15 §2.1`).
    Expired,
}

impl InstanceState {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Rejected => "REJECTED",
            Self::Cancelled => "CANCELLED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Whether the instance is over.
    ///
    /// Defined once here rather than as a `matches!` at each call site, for the reason
    /// `Action::exposes_content` is: a caller that forgets a variant is a caller that treats a
    /// finished instance as running and lets somebody approve a step in it.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Rejected | Self::Cancelled | Self::Expired)
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for anything outside the vocabulary.
    pub fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "DRAFT" => Ok(Self::Draft),
            "RUNNING" => Ok(Self::Running),
            "COMPLETED" => Ok(Self::Completed),
            "REJECTED" => Ok(Self::Rejected),
            "CANCELLED" => Ok(Self::Cancelled),
            "EXPIRED" => Ok(Self::Expired),
            other => Err(WorkflowError::Stored(format!("unknown instance state `{other}`"))),
        }
    }
}

/// Where one step row is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepState {
    /// Its stage has not opened. It exists so the whole shape is visible from the start.
    Pending,
    /// Open, and waiting on its holder.
    Assigned,
    /// Approved, or acknowledged, or completed — see [`crate::definition::StepType`].
    Approved,
    /// Rejected, which terminates the instance.
    Rejected,
    /// Signed. Written by `crates/signing`, never by this crate.
    Signed,
    /// Declined. Likewise.
    Declined,
    /// Nobody needs to answer it: a quorum was met around it, or the instance ended.
    Skipped,
    /// It ran out of time, or its version was superseded.
    Expired,
}

impl StepState {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Assigned => "ASSIGNED",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Signed => "SIGNED",
            Self::Declined => "DECLINED",
            Self::Skipped => "SKIPPED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Whether the step is still waiting on somebody.
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Assigned)
    }

    /// Whether the step counts towards its position's quorum.
    ///
    /// `SIGNED` counts alongside `APPROVED` because a completed signing ceremony *is* that signer's
    /// answer (`docs/15 §1`: signing is a workflow step, not a separate universe). If it did not
    /// count, a stage holding a signature step could never advance.
    #[must_use]
    pub const fn is_affirmative(self) -> bool {
        matches!(self, Self::Approved | Self::Signed)
    }

    /// Reads one back.
    ///
    /// # Errors
    ///
    /// [`WorkflowError::Stored`] for anything outside the vocabulary.
    pub fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "ASSIGNED" => Ok(Self::Assigned),
            "APPROVED" => Ok(Self::Approved),
            "REJECTED" => Ok(Self::Rejected),
            "SIGNED" => Ok(Self::Signed),
            "DECLINED" => Ok(Self::Declined),
            "SKIPPED" => Ok(Self::Skipped),
            "EXPIRED" => Ok(Self::Expired),
            other => Err(WorkflowError::Stored(format!("unknown step state `{other}`"))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_instance_state_round_trips_through_its_stored_spelling() {
        for state in [
            InstanceState::Draft,
            InstanceState::Running,
            InstanceState::Completed,
            InstanceState::Rejected,
            InstanceState::Cancelled,
            InstanceState::Expired,
        ] {
            assert_eq!(InstanceState::parse(state.as_str()).expect("round trip"), state);
        }
    }

    #[test]
    fn every_step_state_round_trips_through_its_stored_spelling() {
        for state in [
            StepState::Pending,
            StepState::Assigned,
            StepState::Approved,
            StepState::Rejected,
            StepState::Signed,
            StepState::Declined,
            StepState::Skipped,
            StepState::Expired,
        ] {
            assert_eq!(StepState::parse(state.as_str()).expect("round trip"), state);
        }
    }

    #[test]
    fn only_running_and_draft_are_non_terminal() {
        assert!(!InstanceState::Running.is_terminal());
        assert!(!InstanceState::Draft.is_terminal());
        for state in [
            InstanceState::Completed,
            InstanceState::Rejected,
            InstanceState::Cancelled,
            InstanceState::Expired,
        ] {
            assert!(state.is_terminal(), "{state:?} must be terminal");
        }
    }

    #[test]
    fn a_signed_step_counts_towards_a_quorum_and_a_declined_one_does_not() {
        // Otherwise a stage holding a signature step could never advance (`docs/15 §1`).
        assert!(StepState::Signed.is_affirmative());
        assert!(StepState::Approved.is_affirmative());
        for state in [
            StepState::Pending,
            StepState::Assigned,
            StepState::Rejected,
            StepState::Declined,
            StepState::Skipped,
            StepState::Expired,
        ] {
            assert!(!state.is_affirmative(), "{state:?} must not count towards a quorum");
        }
    }
}
