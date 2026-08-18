//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! Three things shape it:
//!
//! 1. **A lost race is a domain answer, not a database failure.** `uq_workspace_slug` is the
//!    authority on whether a slug is free (see [`crate::workspace_repo`] for why a read-then-write
//!    check is wrong), so the constraint violation it raises has to arrive at the caller as
//!    [`WorkspaceError::SlugTaken`] — a `400` naming the field — rather than as an opaque `500`.
//! 2. **An `If-Match` failure carries the current revision.** `docs/05-API.md §9` returns `409`
//!    with the revision the resource actually holds, so the client can re-read, merge and retry
//!    without a round trip to discover it. That is why
//!    [`WorkspaceError::RevisionConflict`] carries a value rather than being a marker.
//! 3. **No name, slug or principal identifier appears in an error string.** A workspace name can
//!    carry organizational structure (`Project Ravenwood — acquisition`), and an error string is
//!    the shortest path from a value to a log line. Variants name a *field* and never its content
//!    (`CLAUDE.md` rule 10).
//!
//! Every driver failure is funnelled through [`enclave_db::DbError`] rather than classified here,
//! for the reason `enclave_identity::error` gives: retryability and the `RowNotFound` → `404`
//! mapping are decided in exactly one place in the workspace.

use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_db::DbError;

/// Everything the workspace repositories can fail with.
///
/// `thiserror` per `plans/M0-FOUNDATIONS.md` D2: the library defines its own error type and the
/// conversion into the canonical [`enclave_core::Error`] happens once, here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// A statement, transaction or connection failed.
    #[error("workspace database failure")]
    Database(#[from] DbError),

    /// A stored row could not be reconstructed.
    ///
    /// Almost always a `CHECK` constraint and a Rust enumeration that have drifted apart — a
    /// migration added a visibility the code does not know. Names the column and a fixed reason,
    /// never the value.
    #[error("workspace row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// The pagination cursor was malformed, or bound to a different tenant or listing.
    ///
    /// One variant for every rejection, so a cursor cannot be used to probe (`CLAUDE.md` rule 7).
    #[error("the pagination cursor is not valid for this request")]
    InvalidCursor,

    /// Another live workspace in this tenant already holds the slug.
    ///
    /// Raised by `uq_workspace_slug`, which ignores soft-deleted rows — so a slug becomes free
    /// again once the workspace holding it is trashed.
    #[error("the slug is already taken in this tenant")]
    SlugTaken,

    /// The caller's `If-Match` revision did not match the stored one.
    ///
    /// Carries the current revision so a client can re-read and retry. The write did **not**
    /// happen: a silent overwrite is the failure mode this variant exists to make impossible.
    #[error("the workspace has been modified since revision was read")]
    RevisionConflict {
        /// The revision the workspace actually holds now.
        current_revision: i64,
    },

    /// The principal is already a member of the workspace.
    ///
    /// Raised by the `workspace_members` primary key. A membership is not silently upgraded to a
    /// different role by an `add` — changing a role is a distinct, separately audited act.
    #[error("the principal is already a member of this workspace")]
    AlreadyMember,

    /// The workspace named by a write does not exist in this tenant.
    ///
    /// Comes from the composite foreign key on `workspace_members`, which is what makes a
    /// membership row pointing at another tenant's workspace structurally impossible
    /// (`docs/04-DATA-MODEL.md §3.3`). It reaches the caller as a `404` rather than a `403`,
    /// because a workspace in another tenant and a workspace that never existed must be
    /// indistinguishable (`CLAUDE.md` rule 7).
    #[error("no such workspace in this tenant")]
    NoSuchWorkspace,
}

impl WorkspaceError {
    /// Whether an identical retry has a realistic chance of succeeding.
    ///
    /// Everything except a transport failure is deterministic: a taken slug stays taken, a stale
    /// revision stays stale, and retrying either just burns a round trip.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            Self::MalformedRow { .. }
            | Self::InvalidCursor
            | Self::SlugTaken
            | Self::RevisionConflict { .. }
            | Self::AlreadyMember
            | Self::NoSuchWorkspace => false,
        }
    }
}

impl From<sqlx::Error> for WorkspaceError {
    /// Routes every unclassified driver failure through [`DbError::Query`].
    ///
    /// Written by hand rather than as a second `#[from]` so that the transient/permanent judgement
    /// is not re-derived here. Writes that can lose a race classify the error first — see
    /// [`crate::workspace_repo`] — and only what is left arrives through this path.
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<WorkspaceError> for CoreError {
    /// Maps a workspace failure onto the one error type the API layer renders.
    fn from(error: WorkspaceError) -> Self {
        match error {
            WorkspaceError::Database(source) => Self::from(source),
            WorkspaceError::InvalidCursor => {
                Self::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)])
            }
            WorkspaceError::SlugTaken => {
                Self::Validation(vec![FieldError::new("slug", ValidationCode::NotUnique)])
            }
            WorkspaceError::AlreadyMember => {
                Self::Validation(vec![FieldError::new("principalId", ValidationCode::NotUnique)])
            }
            WorkspaceError::RevisionConflict { current_revision } => {
                Self::Conflict { current_revision }
            }
            WorkspaceError::NoSuchWorkspace => Self::NotFound,
            // The column name stays in the source chain for the logs and never reaches the caller:
            // `Internal`'s `Display` is the bare phrase "internal error".
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The crate's result alias.
pub type Result<T, E = WorkspaceError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_row_is_a_404_and_never_a_403() {
        // A cross-tenant read that RLS filtered away arrives here. It must not become a 403: a 403
        // confirms the row exists somewhere (`CLAUDE.md` rule 7).
        let core: CoreError = WorkspaceError::from(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
        assert_eq!(core.status_code(), 404);
    }

    #[test]
    fn a_workspace_in_another_tenant_is_indistinguishable_from_one_that_never_existed() {
        let core: CoreError = WorkspaceError::NoSuchWorkspace.into();
        assert_eq!(core.status_code(), 404);
    }

    #[test]
    fn a_revision_conflict_is_a_409_that_carries_the_current_revision() {
        // Without the revision the client has to re-read to discover it, and a client that guesses
        // instead is a client that overwrites (`docs/05-API.md §9`).
        let core: CoreError = WorkspaceError::RevisionConflict { current_revision: 7 }.into();
        match core {
            CoreError::Conflict { current_revision } => assert_eq!(current_revision, 7),
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(
            CoreError::from(WorkspaceError::RevisionConflict { current_revision: 7 }).status_code(),
            409
        );
    }

    #[test]
    fn a_taken_slug_names_the_field_and_not_the_value() {
        let core: CoreError = WorkspaceError::SlugTaken.into();
        match core {
            CoreError::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "slug");
                assert_eq!(fields[0].code, ValidationCode::NotUnique);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
        // The rendered message carries no slug. A workspace slug is organizational information.
        assert!(!WorkspaceError::SlugTaken.to_string().contains('='));
    }

    #[test]
    fn a_duplicate_membership_is_a_field_validation_failure_not_a_conflict() {
        let core: CoreError = WorkspaceError::AlreadyMember.into();
        match core {
            CoreError::Validation(fields) => assert_eq!(fields[0].field, "principalId"),
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_row_never_renders_its_detail_to_the_caller() {
        let core: CoreError =
            WorkspaceError::MalformedRow { column: "visibility", reason: "not a known visibility" }
                .into();
        assert_eq!(core.to_string(), "internal error");
    }

    #[test]
    fn only_transport_failures_are_retryable() {
        assert!(WorkspaceError::from(sqlx::Error::PoolTimedOut).is_retryable());
        assert!(!WorkspaceError::SlugTaken.is_retryable());
        assert!(!WorkspaceError::RevisionConflict { current_revision: 1 }.is_retryable());
        assert!(!WorkspaceError::InvalidCursor.is_retryable());
    }
}
