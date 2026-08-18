//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! Three things shape it:
//!
//! 1. **A refusal that happens before any URL is issued is a validation failure, and says which
//!    field.** `docs/05-API.md §8` requires the file-type and size checks to run before the client
//!    spends bandwidth, so those refusals are the ones a user actually sees, and a bare `400` with
//!    no field would leave the UI unable to point at the input.
//! 2. **A verification mismatch is not in here.** It is a [`crate::FailureReason`], because it has
//!    to be *persisted* on the session before it is reported — see [`crate::content`].
//! 3. **A lost race is its own variant.** Every state write is a compare-and-swap, and losing it
//!    means another request completed, aborted or expired the session concurrently. Reporting that
//!    as "not found" would send a client back to a session that no longer accepts writes.
//!
//! Driver failures funnel through [`enclave_db::DbError`] rather than being classified here, so
//! retryability and the `RowNotFound` → `404` mapping are decided in one place in the workspace.

use enclave_core::{Error as CoreError, FieldError, QuotaKind, UnknownVariant, ValidationCode};
use enclave_db::DbError;
use enclave_storage::StorageError;

use crate::state::UploadState;

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, UploadError>;

/// Everything the upload service and repository can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UploadError {
    /// A statement, transaction or connection failed.
    #[error("upload database failure")]
    Database(#[from] DbError),

    /// The object store failed.
    #[error("upload object-storage failure")]
    Storage(#[from] StorageError),

    /// A stored row could not be reconstructed.
    ///
    /// Names the column and a fixed reason, never the value — the same rule
    /// [`enclave_db::DbError`] follows.
    #[error("upload session column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// The stored `state` is not a value this release knows.
    #[error("upload session state is not a known value")]
    UnknownState(#[from] UnknownVariant),

    /// No such session in this tenant.
    ///
    /// A session belonging to another tenant is indistinguishable from one that does not exist
    /// (`CLAUDE.md` rule 7).
    #[error("no such upload session")]
    NotFound,

    /// The session is past the phase this crate can act on.
    ///
    /// The state is carried because a client polling `GET /uploads/{id}` is entitled to know
    /// whether its upload is scanning or was quarantined — that is the whole point of the poll
    /// (`docs/05-API.md §8`).
    #[error("this upload session is {state} and can no longer be modified here")]
    NotResumable {
        /// Where the session actually is.
        state: UploadState,
    },

    /// The session outlived `expires_at`.
    ///
    /// Distinct from [`UploadError::NotResumable`] because the remediation differs: the client
    /// starts a new session rather than polling this one.
    #[error("this upload session has expired; start a new one")]
    Expired,

    /// Another request moved the session while this one was working on it.
    #[error("this upload session moved from {expected} to another state concurrently")]
    ConcurrentTransition {
        /// The state the compare-and-swap required.
        expected: UploadState,
        /// The state it was asked to move to.
        attempted: UploadState,
    },

    /// The library refuses this file's extension.
    ///
    /// Carries the extension: it is the client's own input echoed back, exactly like any other
    /// field-level validation failure, and a user told only "not allowed" cannot act on it.
    #[error("this library does not accept `.{extension}` files")]
    ExtensionNotAllowed {
        /// The normalized extension that was refused.
        extension: String,
    },

    /// The declared size is above the library's ceiling.
    #[error("the declared size exceeds the {limit} byte maximum for this library")]
    FileTooLarge {
        /// The ceiling in force.
        limit: u64,
    },

    /// The SHA-256 declared when the session was created is not lowercase hex.
    ///
    /// Checked before the object store is asked for anything: the value is handed to the provider
    /// so it can reject a corrupted transfer, and a malformed one would either be ignored or
    /// rejected several gigabytes later.
    #[error("the declared checksum is not a lowercase hex SHA-256")]
    InvalidDeclaredChecksum,

    /// The upload declares a name that cannot be stored.
    #[error("the file name is not valid: {reason}")]
    InvalidName {
        /// A fixed phrase, never the name itself.
        reason: &'static str,
    },
}

impl UploadError {
    /// Whether an identical retry has a realistic chance of succeeding.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            // `StorageError` classifies itself only on the way into `enclave_core::Error`, and
            // that conversion consumes the value. `Upstream` is the variant it maps to a
            // retryable dependency failure; everything else is configuration or a caller bug.
            Self::Storage(source) => matches!(source, StorageError::Upstream { .. }),
            // A lost compare-and-swap is not retryable *as-is*: the caller must re-read the
            // session, because the state it planned against is gone.
            Self::MalformedRow { .. }
            | Self::UnknownState(_)
            | Self::NotFound
            | Self::NotResumable { .. }
            | Self::Expired
            | Self::ConcurrentTransition { .. }
            | Self::ExtensionNotAllowed { .. }
            | Self::FileTooLarge { .. }
            | Self::InvalidDeclaredChecksum
            | Self::InvalidName { .. } => false,
        }
    }
}

impl From<sqlx::Error> for UploadError {
    /// Routes every driver failure through [`DbError::Query`], so the transient/permanent
    /// classification is not re-derived here.
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<UploadError> for CoreError {
    /// Maps an upload failure onto the one error type the API layer renders
    /// (`docs/03-LLD.md §22`).
    ///
    /// Two mappings are deliberate rather than obvious:
    ///
    /// * **A file over the library's ceiling is `QuotaExceeded`, not a validation failure.** It is
    ///   the `MAX_FILE_BYTES` quota of `docs/05-API.md §5`, and it answers `403` with the limit, so
    ///   a client can show headroom instead of guessing.
    /// * **A lost compare-and-swap is `Conflict`.** The client re-reads the session and decides
    ///   what to do, which is exactly what a `409` means everywhere else in the API. There is no
    ///   revision column on `upload_sessions`, so the state machine is the concurrency token and
    ///   `current_revision` is reported as zero.
    fn from(err: UploadError) -> Self {
        match err {
            UploadError::NotFound => Self::NotFound,

            UploadError::ExtensionNotAllowed { .. } => {
                Self::Validation(vec![FieldError::new("name", ValidationCode::Unsupported)])
            }
            UploadError::InvalidName { .. } => {
                Self::Validation(vec![FieldError::new("name", ValidationCode::InvalidFormat)])
            }
            UploadError::InvalidDeclaredChecksum => {
                Self::Validation(vec![FieldError::new("sha256", ValidationCode::InvalidFormat)])
            }
            UploadError::FileTooLarge { limit } => Self::QuotaExceeded {
                quota: QuotaKind::MaxFileBytes,
                limit: i64::try_from(limit).unwrap_or(i64::MAX),
            },

            UploadError::Expired => {
                Self::Validation(vec![FieldError::new("uploadId", ValidationCode::OutOfRange)])
            }
            UploadError::NotResumable { .. } | UploadError::ConcurrentTransition { .. } => {
                Self::Conflict { current_revision: 0 }
            }

            UploadError::Storage(source) => source.into(),
            UploadError::Database(source) => source.into(),

            // A row this release cannot decode is a schema/code drift, not something a client did.
            // `Internal` keeps the detail in the log and out of the response body.
            other @ (UploadError::MalformedRow { .. } | UploadError::UnknownState(_)) => {
                Self::Internal(anyhow::Error::new(other))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_refusal_before_any_url_is_issued_names_the_field_or_the_quota() {
        let extension = UploadError::ExtensionNotAllowed { extension: "exe".to_owned() };
        let error: CoreError = extension.into();
        assert_eq!(error.status_code(), 400);
        assert_eq!(error.code(), "VALIDATION_FAILED");

        let error: CoreError = UploadError::FileTooLarge { limit: 1024 }.into();
        assert_eq!(error.code(), "QUOTA_EXCEEDED");
        // A capacity quota is a refusal, not a "try again later".
        assert_eq!(error.status_code(), 403);
    }

    #[test]
    fn a_missing_session_and_another_tenants_session_are_the_same_answer() {
        let error: CoreError = UploadError::NotFound.into();
        assert_eq!(error.status_code(), 404);
    }

    #[test]
    fn a_lost_race_is_a_conflict_rather_than_a_not_found() {
        let error: CoreError = UploadError::ConcurrentTransition {
            expected: UploadState::Uploading,
            attempted: UploadState::Uploaded,
        }
        .into();
        assert_eq!(error.status_code(), 409);

        let error: CoreError = UploadError::NotResumable { state: UploadState::Quarantined }.into();
        assert_eq!(error.status_code(), 409);
    }

    #[test]
    fn a_row_this_release_cannot_decode_never_reaches_the_client_as_detail() {
        let error: CoreError =
            UploadError::MalformedRow { column: "staged_key", reason: "not canonical" }.into();
        assert_eq!(error.status_code(), 500);
        assert_eq!(error.to_string(), "internal error");
    }

    #[test]
    fn nothing_but_a_transient_dependency_failure_is_retryable() {
        assert!(!UploadError::NotFound.is_retryable());
        assert!(!UploadError::Expired.is_retryable());
        assert!(!UploadError::FileTooLarge { limit: 1 }.is_retryable());
        assert!(!UploadError::ConcurrentTransition {
            expected: UploadState::Created,
            attempted: UploadState::Aborted,
        }
        .is_retryable());
    }
}
