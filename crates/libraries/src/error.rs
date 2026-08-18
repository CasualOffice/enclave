//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! The shape follows `enclave_workspaces::error`, and for the same reasons: an `If-Match` failure
//! carries the revision the caller needs in order to retry (`docs/05-API.md §9`), a write naming a
//! workspace that is not in this tenant is a `404` rather than a `403` (`CLAUDE.md` rule 7), and no
//! library name, slug or extension list ever appears in an error string — variants name a *column*
//! or a *field* and never its content (`CLAUDE.md` rule 10).
//!
//! Driver failures are funnelled through [`enclave_db::DbError`] rather than classified here, so
//! retryability and the `RowNotFound` → `404` mapping are decided in exactly one place in the
//! workspace.

use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_db::DbError;

/// Everything the library repository can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LibraryError {
    /// A statement, transaction or connection failed.
    #[error("library database failure")]
    Database(#[from] DbError),

    /// A stored row could not be reconstructed.
    ///
    /// Usually a `CHECK` constraint and a Rust enumeration that have drifted apart, or a JSONB
    /// column holding something that is not the array of strings it is supposed to be. Names the
    /// column and a fixed reason, never the value.
    #[error("library row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// The pagination cursor was malformed, or bound to a different tenant or listing.
    #[error("the pagination cursor is not valid for this request")]
    InvalidCursor,

    /// The caller's `If-Match` revision did not match the stored one.
    ///
    /// Carries the current revision so a client can re-read and retry. The write did **not**
    /// happen. A library's settings include `inherit_permissions`, `external_sharing` and the
    /// extension lists — a silent overwrite here is a silent change to who can take content out of
    /// the tenant, which is why the comparison is part of the `UPDATE` and never a prior read.
    #[error("the library has been modified since revision was read")]
    RevisionConflict {
        /// The revision the library actually holds now.
        current_revision: i64,
    },

    /// The workspace a library was to be created in does not exist in this tenant.
    ///
    /// Raised by the composite foreign key `(tenant_id, workspace_id)`, which is what makes a
    /// library under another tenant's workspace structurally impossible
    /// (`docs/04-DATA-MODEL.md §3.3`). Referential-integrity checks run beneath row-level security,
    /// so a workspace in another tenant fails identically to one that never existed — the
    /// indistinguishability `CLAUDE.md` rule 7 requires, obtained by construction.
    #[error("no such workspace in this tenant")]
    NoSuchWorkspace,
}

impl LibraryError {
    /// Whether an identical retry has a realistic chance of succeeding.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            Self::MalformedRow { .. }
            | Self::InvalidCursor
            | Self::RevisionConflict { .. }
            | Self::NoSuchWorkspace => false,
        }
    }
}

impl From<sqlx::Error> for LibraryError {
    /// Routes every unclassified driver failure through [`DbError::Query`].
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<LibraryError> for CoreError {
    /// Maps a library failure onto the one error type the API layer renders.
    fn from(error: LibraryError) -> Self {
        match error {
            LibraryError::Database(source) => Self::from(source),
            LibraryError::InvalidCursor => {
                Self::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)])
            }
            LibraryError::RevisionConflict { current_revision } => {
                Self::Conflict { current_revision }
            }
            LibraryError::NoSuchWorkspace => Self::NotFound,
            // The column name stays in the source chain for the logs and never reaches the caller.
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The crate's result alias.
pub type Result<T, E = LibraryError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_row_is_a_404_and_never_a_403() {
        let core: CoreError = LibraryError::from(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
        assert_eq!(core.status_code(), 404);
    }

    #[test]
    fn a_workspace_in_another_tenant_is_indistinguishable_from_one_that_never_existed() {
        assert_eq!(CoreError::from(LibraryError::NoSuchWorkspace).status_code(), 404);
    }

    #[test]
    fn a_revision_conflict_is_a_409_that_carries_the_current_revision() {
        let core: CoreError = LibraryError::RevisionConflict { current_revision: 12 }.into();
        match core {
            CoreError::Conflict { current_revision } => assert_eq!(current_revision, 12),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_row_never_renders_its_detail_to_the_caller() {
        let core: CoreError = LibraryError::MalformedRow {
            column: "allowed_extensions",
            reason: "not an array of strings",
        }
        .into();
        assert_eq!(core.to_string(), "internal error");
    }

    #[test]
    fn only_transport_failures_are_retryable() {
        assert!(LibraryError::from(sqlx::Error::PoolTimedOut).is_retryable());
        assert!(!LibraryError::InvalidCursor.is_retryable());
        assert!(!LibraryError::RevisionConflict { current_revision: 1 }.is_retryable());
        assert!(!LibraryError::NoSuchWorkspace.is_retryable());
    }
}
