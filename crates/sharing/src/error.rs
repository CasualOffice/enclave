//! Errors this crate can produce, and the deliberate indistinguishability at their heart.
//!
//! # One answer for every reason a link will not work
//!
//! [`SharingError::LinkUnusable`] covers a token that is malformed, unknown, expired, revoked or
//! exhausted. That is not laziness — it is `CLAUDE.md` rule 7 applied to an unauthenticated
//! endpoint, and the distinctions an attacker would extract from separate answers are exactly the
//! ones worth denying them:
//!
//! * *unknown* versus *expired* tells them whether a guessed token ever existed, which turns a
//!   256-bit search into an oracle;
//! * *revoked* tells them the document is interesting enough that somebody pulled the link;
//! * *exhausted* tells them the link works and they are merely late, which is an invitation to ask
//!   the recipient to forward it.
//!
//! The *creator* of a link sees the real state through the management API, where they are
//! authenticated and the resource is theirs. The redeemer sees one door that does not open.

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = SharingError> = core::result::Result<T, E>;

/// Something went wrong creating or redeeming a share link.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharingError {
    /// A statement failed.
    #[error("share link query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    #[error("share link database failure")]
    Database(#[from] enclave_db::DbError),

    /// A stored row could not be interpreted.
    #[error("share link column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// The link cannot be used, for one of several reasons the caller is not told apart.
    ///
    /// See the module documentation. This is the only outcome a redeemer ever observes.
    #[error("this link cannot be used")]
    LinkUnusable,

    /// The download budget is spent.
    ///
    /// Distinct from [`Self::LinkUnusable`] *inside* the crate so the caller can record the right
    /// `share_link_events` row and so the tests can tell a budget refusal from a bad token — but it
    /// maps to the same thing at the API edge, and [`From<SharingError> for CoreError`] is where
    /// that flattening happens rather than at each call site, where it would eventually be
    /// forgotten.
    #[error("this link cannot be used")]
    BudgetExhausted,

    /// The OS declined to provide randomness.
    ///
    /// A link minted from a degraded entropy source is worse than no link, so this propagates
    /// rather than falling back to anything.
    #[error("the operating system could not provide randomness")]
    EntropyUnavailable,
}

impl From<SharingError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Both refusals become `NotFound`, and this is the single place that collapse happens. A `403`
    /// would confirm the link exists; a `410 Gone` would confirm it once did; a `429` would confirm
    /// the budget is the only thing in the way. All three are answers to a question an
    /// unauthenticated caller should not be able to ask.
    fn from(value: SharingError) -> Self {
        match value {
            SharingError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            SharingError::Database(error) => error.into(),
            SharingError::LinkUnusable | SharingError::BudgetExhausted => Self::NotFound,
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_refusal_looks_the_same_from_outside() {
        // The property the module documentation argues for. If these ever diverged, a redeemer
        // could tell a guessed token that never existed from one that did — which is the whole
        // difference between a 256-bit search and an oracle.
        let unusable: CoreError = SharingError::LinkUnusable.into();
        let exhausted: CoreError = SharingError::BudgetExhausted.into();

        assert_eq!(unusable.code(), exhausted.code());
        assert!(matches!(unusable, CoreError::NotFound));
        assert!(matches!(exhausted, CoreError::NotFound));
    }

    #[test]
    fn a_database_outage_is_not_a_broken_link() {
        // Otherwise every link in the product silently "does not exist" during an incident, and
        // the support queue fills with people who were told their link was revoked.
        let error: CoreError = SharingError::Storage(sqlx::Error::PoolClosed).into();
        assert!(!matches!(error, CoreError::NotFound), "{error:?}");
        match error {
            CoreError::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::Postgres);
                assert!(retryable);
            }
            other => panic!("expected an upstream failure, got {other:?}"),
        }
    }

    #[test]
    fn a_degraded_entropy_source_is_our_defect_not_the_callers() {
        let error: CoreError = SharingError::EntropyUnavailable.into();
        assert_eq!(error.code(), "INTERNAL_ERROR");
    }
}
