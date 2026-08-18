//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! Two things shape it:
//!
//! 1. **No identity value ever appears in an error string.** An email address is personal data and
//!    a group name can carry organizational structure; both would land in logs and, through
//!    `Display`, potentially in a response body. Variants therefore name a *column* or a *field*
//!    and never the value that failed (`CLAUDE.md` rule 10, and the same reasoning as
//!    [`enclave_db::DbError`]).
//! 2. **A cursor that does not belong to this caller is a validation failure, not a hint.** It
//!    carries no indication of *why* — wrong tenant, wrong filter, wrong length, forged all
//!    collapse to one answer, so a cursor cannot be used to probe (`docs/03-LLD.md §17`).
//!
//! Every driver failure is funnelled through [`enclave_db::DbError`] rather than classified here.
//! Retryability and the `RowNotFound` → `404` mapping are decided in exactly one place in the
//! workspace; a second opinion in this crate is a second place for them to disagree.

use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_db::DbError;

/// Everything the identity repositories can fail with.
///
/// `thiserror` per `plans/M0-FOUNDATIONS.md` D2: the library defines its own error type and the
/// conversion into the canonical [`enclave_core::Error`] happens once, here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// A statement, transaction or connection failed.
    #[error("identity database failure")]
    Database(#[from] DbError),

    /// A stored row could not be reconstructed.
    ///
    /// Almost always a `CHECK` constraint and a Rust enumeration that have drifted apart — a
    /// migration added a status the code does not know. Names the column and a fixed reason, never
    /// the value.
    #[error("identity row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// The pagination cursor was malformed, or bound to a different tenant or filter set.
    ///
    /// Deliberately one variant for all of those. A cursor is opaque; telling a caller *which*
    /// check failed turns it into an oracle (`CLAUDE.md` rule 7).
    #[error("the pagination cursor is not valid for this request")]
    InvalidCursor,
}

impl IdentityError {
    /// Whether an identical retry has a realistic chance of succeeding.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            Self::MalformedRow { .. } | Self::InvalidCursor => false,
        }
    }
}

impl From<sqlx::Error> for IdentityError {
    /// Routes every driver failure through [`DbError::Query`].
    ///
    /// Written by hand rather than as a second `#[from]` because the classification — is this
    /// transient, is this a missing row — must not be re-derived here. `DbError` already answers
    /// both, and `?` on a `sqlx` result inside a repository still just works.
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<IdentityError> for CoreError {
    /// Maps an identity failure onto the one error type the API layer renders.
    ///
    /// A missing row becomes [`CoreError::NotFound`] — which is also what a cross-tenant read
    /// produces once row-level security has filtered the row away. The two are indistinguishable to
    /// the client by design (`CLAUDE.md` rule 7).
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::Database(source) => Self::from(source),
            IdentityError::InvalidCursor => {
                Self::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)])
            }
            // The column name stays in the source chain for the logs and never reaches the caller:
            // `Internal`'s `Display` is the bare phrase "internal error".
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The crate's result alias.
pub type Result<T, E = IdentityError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_row_is_a_404_and_never_a_403() {
        // A cross-tenant read that RLS filtered away arrives here. It must not become a 403: a 403
        // confirms the row exists somewhere (`CLAUDE.md` rule 7).
        let core: CoreError = IdentityError::from(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
        assert_eq!(core.status_code(), 404);
    }

    #[test]
    fn an_invalid_cursor_is_a_field_validation_failure() {
        let core: CoreError = IdentityError::InvalidCursor.into();
        match core {
            CoreError::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "cursor");
                assert_eq!(fields[0].code, ValidationCode::InvalidFormat);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_row_never_renders_its_detail_to_the_caller() {
        let core: CoreError =
            IdentityError::MalformedRow { column: "status", reason: "not a known user status" }
                .into();
        assert_eq!(core.to_string(), "internal error");
    }

    #[test]
    fn a_pool_timeout_is_retryable_and_a_bad_cursor_is_not() {
        assert!(IdentityError::from(sqlx::Error::PoolTimedOut).is_retryable());
        assert!(!IdentityError::InvalidCursor.is_retryable());
        assert!(!IdentityError::MalformedRow { column: "source", reason: "unknown" }.is_retryable());
    }
}
