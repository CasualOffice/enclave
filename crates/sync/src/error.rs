//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! `plans/M0-FOUNDATIONS.md` D2: a library defines its own error type with `thiserror`, and the
//! conversion into the canonical [`enclave_core::Error`] happens once rather than being re-invented
//! at each call site with slightly different judgement about what a client may learn.
//!
//! # What is deliberately not a variant
//!
//! **Anything that would be a policy denial.** This crate takes no authorization decision — that is
//! `PolicyEngine::enforce`'s job and the handler's, and a second refusal vocabulary down here would
//! be a second, quieter policy chain (`CLAUDE.md` rule 1). The two refusals that *are* here,
//! [`SyncError::CursorTooOld`] and [`SyncError::VersionConflict`], are protocol facts rather than
//! access decisions: the first says the feed no longer reaches back that far, the second says the
//! server has moved on. Neither depends on who is asking.

use enclave_core::{Error as CoreError, FieldError, ValidationCode, VersionId};

/// Everything this crate can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The database failed.
    #[error("sync storage failed")]
    Db(#[from] enclave_db::DbError),

    /// A stored row could not be decoded into this crate's vocabulary.
    ///
    /// A `CHECK` constraint and a Rust enumeration that have drifted apart. It is an internal
    /// failure rather than a validation one: no client input reached it.
    #[error("a stored sync row holds `{value}`, which is not a known {vocabulary}")]
    UnknownVariant {
        /// Which vocabulary the value failed to parse as.
        vocabulary: &'static str,
        /// The value as stored. A column value from a closed vocabulary, never user prose.
        value: String,
    },

    /// The `scope` parameter was not `library:<uuid>`.
    #[error("the sync scope is not a recognised `type:id` pair")]
    InvalidScope,

    /// The `cursor` parameter was not a non-negative integer.
    #[error("the sync cursor is not a position in this feed")]
    InvalidCursor,

    /// The cursor points below the oldest entry the feed still holds.
    ///
    /// `docs/10-SYNC-AND-EDITING.md §4`: the client performs a scoped re-enumeration. Rendered as
    /// `410` by the handler, which is a status [`enclave_core::Error`] has no variant for — see
    /// `crates/api/src/sync.rs`.
    #[error("the sync cursor is older than the change-log retention window")]
    CursorTooOld,

    /// The client declared a base version the server has moved past.
    ///
    /// `docs/10 §6`: the client uploads its copy as a conflicted copy alongside the server's, and a
    /// human decides. The current version is carried so the client can do that without a second
    /// round trip to discover it.
    #[error("the file has a newer version than the one this change was made from")]
    VersionConflict {
        /// What `files.current_version_id` actually holds now.
        current_version_id: Option<VersionId>,
    },

    /// The device named is not one this tenant has registered, or is no longer usable.
    ///
    /// Deliberately one variant for "absent" and "revoked". A caller who could tell them apart
    /// could enumerate the tenant's device ids (`CLAUDE.md` rule 7 applied one level down from a
    /// file).
    #[error("no usable device")]
    NoSuchDevice,

    /// A field of a registration or reservation body was unusable.
    #[error("the request body is not valid")]
    Validation(Vec<FieldError>),
}

/// This crate's result alias.
pub type Result<T> = core::result::Result<T, SyncError>;

impl SyncError {
    /// A validation failure naming one field.
    #[must_use]
    pub fn field(field: &'static str, code: ValidationCode) -> Self {
        Self::Validation(vec![FieldError::new(field, code)])
    }
}

impl From<sqlx::Error> for SyncError {
    fn from(error: sqlx::Error) -> Self {
        // `Query`, always: this crate runs statements and never opens a pool or a transaction, so
        // the three transport variants are not reachable from here and picking one would misreport
        // a constraint violation as a connection failure. `DbError` is what decides retryability
        // (`crates/db/src/error.rs`), and it decides it from the driver error either way.
        Self::Db(enclave_db::DbError::Query(error))
    }
}

impl From<SyncError> for CoreError {
    /// The single mapping onto the type the API renders.
    ///
    /// [`SyncError::CursorTooOld`] and [`SyncError::VersionConflict`] are the two that do not fit:
    /// `Error` has no `410`, and its `Conflict` carries a revision rather than a version id. Both
    /// are therefore rendered by the handler through `docs/05-API.md §5`'s envelope directly, and
    /// mapping them here would be a second, worse answer — so they collapse to the honest
    /// remainder rather than pretending. The handler never lets one reach this conversion; the arms
    /// exist so that a future caller which does gets something defensible rather than a panic.
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::Db(inner) => inner.into(),
            SyncError::Validation(fields) => Self::Validation(fields),
            SyncError::InvalidScope => {
                Self::Validation(vec![FieldError::new("scope", ValidationCode::InvalidFormat)])
            }
            SyncError::InvalidCursor | SyncError::CursorTooOld => {
                Self::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)])
            }
            // A device the caller may not use is a device the caller must not learn exists.
            SyncError::NoSuchDevice => Self::NotFound,
            SyncError::VersionConflict { .. } => Self::Conflict { current_revision: 0 },
            SyncError::UnknownVariant { vocabulary, value } => {
                // The value is a closed-vocabulary column, so logging it carries no user content;
                // it is exactly what an operator needs to find the drifted `CHECK`.
                tracing::error!(vocabulary, value, "a stored sync row did not decode");
                Self::Internal(anyhow_message(vocabulary))
            }
        }
    }
}

/// Builds the opaque internal error, without letting the stored value into it.
fn anyhow_message(vocabulary: &'static str) -> anyhow::Error {
    anyhow::anyhow!("a stored sync row holds an unknown {vocabulary}")
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn an_unusable_device_is_an_absent_one_on_the_wire() {
        // `CLAUDE.md` rule 7, one level down from a file: a caller who could distinguish "revoked"
        // from "never existed" could enumerate the tenant's device ids.
        let rendered = CoreError::from(SyncError::NoSuchDevice);
        assert_eq!(rendered.status_code(), 404);
    }

    #[test]
    fn a_bad_scope_and_a_bad_cursor_name_the_field_they_came_from() {
        for (error, field) in [
            (SyncError::InvalidScope, "scope"),
            (SyncError::InvalidCursor, "cursor"),
            (SyncError::CursorTooOld, "cursor"),
        ] {
            match CoreError::from(error) {
                CoreError::Validation(fields) => {
                    assert_eq!(fields.len(), 1);
                    assert_eq!(fields[0].field, field);
                }
                other => panic!("expected a validation failure, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_drifted_vocabulary_does_not_carry_its_value_to_the_client() {
        let error = CoreError::from(SyncError::UnknownVariant {
            vocabulary: "device state",
            value: "TELEPORTED".to_owned(),
        });
        assert_eq!(error.status_code(), 500);
        assert!(
            !error.to_string().contains("TELEPORTED"),
            "the stored value reached the client-visible text: {error}"
        );
    }
}
