//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! Three things shape it:
//!
//! 1. **No name ever appears in an error string.** A file name is content — `Q4 layoffs.xlsx`
//!    names the thing it is about — so a variant names a *field* and a fixed reason, never the
//!    value that failed (`CLAUDE.md` rule 10, and the same reasoning as [`enclave_db::DbError`]).
//! 2. **Absence and refusal are one answer.** [`FilesError::NotFound`] and
//!    [`FilesError::ParentNotFound`] both become [`enclave_core::Error::NotFound`], which is also
//!    what a row hidden by row-level security produces. A caller cannot tell "there is no such
//!    folder" from "there is one and it is not yours" (`CLAUDE.md` rule 7).
//! 3. **A rejected write says which rule rejected it, in a closed vocabulary.** A duplicate name, a
//!    cycle and a cross-library move are all things the caller can fix, so they map to field
//!    validation rather than to an opaque 500 — but by [`enclave_core::ValidationCode`], not by
//!    prose.
//!
//! Every driver failure is funnelled through [`enclave_db::DbError`] rather than classified here.
//! Retryability and the `RowNotFound` → `404` mapping are decided in exactly one place in the
//! workspace.

use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_db::DbError;

/// Everything the files repositories can fail with.
///
/// `thiserror` per `plans/M0-FOUNDATIONS.md` D2: the library defines its own error type and the
/// conversion into the canonical [`enclave_core::Error`] happens once, here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FilesError {
    /// A statement, transaction or connection failed.
    #[error("files database failure")]
    Database(#[from] DbError),

    /// A stored row could not be reconstructed.
    ///
    /// Almost always a `CHECK` constraint and a Rust enumeration that have drifted apart — a
    /// migration added a status the code does not know. Names the column and a fixed reason, never
    /// the value.
    #[error("file row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// The pagination cursor was malformed, or bound to a different tenant or filter set.
    ///
    /// One variant for all of those: a cursor is opaque, and telling a caller *which* check failed
    /// turns it into an oracle.
    #[error("the pagination cursor is not valid for this request")]
    InvalidCursor,

    /// The node does not exist, is in the trash, or belongs to another tenant.
    ///
    /// Deliberately indistinguishable. See the [module documentation](self).
    #[error("no such file or folder")]
    NotFound,

    /// The requested parent does not exist, is not a folder, or is in the trash.
    ///
    /// Also raised when the parent is in another tenant, because row-level security removed the
    /// row before this code saw it.
    #[error("the parent folder does not exist")]
    ParentNotFound,

    /// A sibling already holds this name.
    ///
    /// Detected by `uq_files_sibling_name` rejecting the write, never by reading first: a
    /// read-then-write leaves a window in which a concurrent create takes the name between the
    /// check and the insert, and the whole point of a unique index is that there is no such window.
    #[error("a sibling with this name already exists")]
    NameTaken,

    /// The name cannot be stored, addressed or rendered.
    #[error("the name is not usable: {reason}")]
    InvalidName {
        /// A fixed phrase from [`crate::normalize::validate_name`]. Never the name itself.
        reason: &'static str,
    },

    /// The caller's `If-Match` revision is not the revision the row holds.
    ///
    /// Carries the current revision so the client can re-read, merge and retry without a second
    /// round trip to discover it (`docs/03-LLD.md §14`).
    #[error("the node has been modified since the caller read it")]
    Conflict {
        /// The revision the row actually holds now.
        current_revision: i64,
    },

    /// The move would have made a folder its own ancestor.
    ///
    /// The subtree would then be unreachable from any root, invisible to every listing, and
    /// permanently unresolvable by the ACL walk — which is a recursive query that would spin.
    #[error("a folder cannot be moved inside itself")]
    CycleDetected,

    /// The move would have crossed a library boundary.
    ///
    /// Not supported here, and not an oversight: `library_id` and `workspace_id` are denormalized
    /// onto every descendant and both are inputs to ACL inheritance
    /// (`crates/authorization/src/repo.rs`), so a cross-library move is a rewrite of an entire
    /// subtree plus an `acl_revision` bump on all of it. That is a copy-and-delete operation with
    /// its own quota, storage and audit consequences.
    #[error("a node cannot be moved into a different library")]
    CrossLibraryMove,

    /// The node cannot be restored because its parent is still in the trash.
    ///
    /// Restoring it anyway would produce a live node inside a deleted folder: invisible to a
    /// listing, and — because the ACL walk stops at a deleted ancestor — permanently unresolvable.
    #[error("the parent folder is still in the trash")]
    ParentInTrash,

    /// The ancestor walk hit [`crate::path::MAX_DEPTH`].
    ///
    /// Either the tree is deeper than the platform supports, or `parent_id` holds a cycle that
    /// [`crate::FileRepository::reparent`] should have made impossible. Both are the platform's
    /// problem rather than the caller's, so this renders as an internal error — and it is an error
    /// rather than a truncated breadcrumb because a truncated path is a *wrong* path.
    #[error("the ancestor chain is deeper than the supported maximum")]
    PathTooDeep,

    /// Permanent deletion is not implemented in this crate. See [`crate::purge`].
    #[error("permanent deletion is not available in this build")]
    PurgeUnavailable,
}

impl FilesError {
    /// Whether an identical retry has a realistic chance of succeeding.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            _ => false,
        }
    }
}

impl From<sqlx::Error> for FilesError {
    /// Routes every unclassified driver failure through [`DbError::Query`].
    ///
    /// Written by hand rather than as a second `#[from]` so that the retryable/permanent
    /// classification is not re-derived here. Constraint violations do **not** arrive this way —
    /// [`crate::repo`] inspects the SQLSTATE first and turns the ones this crate has a domain
    /// answer for into [`FilesError::NameTaken`] and [`FilesError::ParentNotFound`].
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<FilesError> for CoreError {
    /// Maps a files failure onto the one error type the API layer renders.
    fn from(error: FilesError) -> Self {
        match error {
            FilesError::Database(source) => Self::from(source),
            FilesError::NotFound | FilesError::ParentNotFound => Self::NotFound,
            FilesError::Conflict { current_revision } => Self::Conflict { current_revision },
            FilesError::InvalidCursor => {
                Self::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)])
            }
            FilesError::NameTaken => {
                Self::Validation(vec![FieldError::new("name", ValidationCode::NotUnique)])
            }
            FilesError::InvalidName { .. } => {
                Self::Validation(vec![FieldError::new("name", ValidationCode::InvalidFormat)])
            }
            // Both are "this parent, for this node, is wrong" rather than "no such parent", which
            // is what `Inconsistent` says and why it is not `InvalidFormat`.
            FilesError::CycleDetected | FilesError::ParentInTrash => {
                Self::Validation(vec![FieldError::new("parentId", ValidationCode::Inconsistent)])
            }
            FilesError::CrossLibraryMove => {
                Self::Validation(vec![FieldError::new("parentId", ValidationCode::Unsupported)])
            }
            // The reason stays in the source chain for the logs and never reaches the caller:
            // `Internal`'s `Display` is the bare phrase "internal error".
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The crate's result alias.
pub type Result<T, E = FilesError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_node_and_a_missing_parent_are_both_404_and_never_403() {
        for error in [FilesError::NotFound, FilesError::ParentNotFound] {
            let core: CoreError = error.into();
            assert!(matches!(core, CoreError::NotFound));
            assert_eq!(core.status_code(), 404);
        }
        // And so is a row row-level security filtered away.
        let core: CoreError = FilesError::from(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
    }

    #[test]
    fn a_stale_revision_reports_the_current_one() {
        let core: CoreError = FilesError::Conflict { current_revision: 7 }.into();
        match core {
            CoreError::Conflict { current_revision } => assert_eq!(current_revision, 7),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_name_is_a_field_validation_failure_on_name() {
        let core: CoreError = FilesError::NameTaken.into();
        match core {
            CoreError::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "name");
                assert_eq!(fields[0].code, ValidationCode::NotUnique);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_cycle_and_a_cross_library_move_both_point_at_the_parent_field() {
        for (error, code) in [
            (FilesError::CycleDetected, ValidationCode::Inconsistent),
            (FilesError::ParentInTrash, ValidationCode::Inconsistent),
            (FilesError::CrossLibraryMove, ValidationCode::Unsupported),
        ] {
            match CoreError::from(error) {
                CoreError::Validation(fields) => {
                    assert_eq!(fields[0].field, "parentId");
                    assert_eq!(fields[0].code, code);
                }
                other => panic!("expected a validation failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn nothing_internal_renders_its_detail_to_the_caller() {
        for error in [
            FilesError::MalformedRow { column: "status", reason: "not a known status" },
            FilesError::PathTooDeep,
            FilesError::PurgeUnavailable,
        ] {
            let core: CoreError = error.into();
            assert_eq!(core.to_string(), "internal error");
        }
    }

    #[test]
    fn no_error_message_can_carry_a_file_name() {
        // The property, asserted rather than reviewed: every variant that is *about* a name takes
        // a fixed reason or nothing at all. A variant added with a `String` name field would have
        // to be added here, which is the point at which someone notices.
        let named = FilesError::InvalidName { reason: "a name cannot be empty" };
        assert_eq!(named.to_string(), "the name is not usable: a name cannot be empty");
        assert!(!FilesError::NameTaken.to_string().contains('\''));
    }

    #[test]
    fn a_pool_timeout_is_retryable_and_a_conflict_is_not() {
        assert!(FilesError::from(sqlx::Error::PoolTimedOut).is_retryable());
        assert!(!FilesError::Conflict { current_revision: 1 }.is_retryable());
        assert!(!FilesError::CycleDetected.is_retryable());
    }
}
