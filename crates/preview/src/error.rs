//! Errors this crate can produce, and the line between an error and a refusal.
//!
//! The distinction is the one `enclave-authorization` draws between a denial and a failure, for the
//! same reason. A [`Refusal`](crate::budget::Refusal) is an *answer* about a document: it will not
//! render, re-running changes nothing, and the caller is told "no preview available". A
//! [`PreviewError`] means the pipeline could not reach an answer.
//!
//! Collapsing them would be wrong in both directions. A rendering worker that is down would read as
//! "this document has no preview" — cached as such, and silently wrong for every file until someone
//! noticed previews had stopped appearing. And a document engineered to hang would read as a
//! transient failure, which invites a retry, which is what it was engineered for.

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = PreviewError> = core::result::Result<T, E>;

/// Something went wrong producing or fetching a rendition.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PreviewError {
    /// A statement failed.
    #[error("rendition query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    #[error("rendition database failure")]
    Database(#[from] enclave_db::DbError),

    /// A stored row could not be interpreted.
    ///
    /// Carries the column and a fixed phrase, never the value.
    #[error("rendition row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// The rendering worker failed — died, timed out at the transport, or returned nonsense.
    ///
    /// Explicitly *not* a refusal. See the module documentation.
    #[error("the rendering worker failed")]
    Worker(#[source] anyhow::Error),

    /// The version cannot be rendered because nothing may read it yet.
    ///
    /// `CLAUDE.md` rule 9 and `plans/M1-CONTENT-CORE.md` D13: nothing is `AVAILABLE` before
    /// antivirus completes, and no read path serves `SCANNING` content. Rendering is a read path —
    /// arguably the most dangerous one, since it hands the bytes to a parser — so it is closed to
    /// the same states as every other. A quarantined version is never rendered at all.
    #[error("no readable version")]
    NotReadable,

    /// The object holding the source could not be fetched.
    #[error("the rendition source could not be read")]
    Source(#[source] anyhow::Error),

    /// The operating system declined to provide randomness for a print capability.
    ///
    /// Carries nothing, because there is nothing to carry that is not already in the variant name,
    /// and a capability is the one place where "we made do" is not an option: a token minted from a
    /// degraded entropy source is worse than no token, and the caller can retry (`ENC-724`).
    #[error("the operating system declined to provide entropy")]
    Entropy,
}

impl From<PreviewError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// [`PreviewError::NotReadable`] becomes `NotFound` rather than a policy denial or a `409`. A
    /// caller who may preview a file but whose version is still scanning, quarantined or absent
    /// gets one answer for all three — the same indistinguishability `CLAUDE.md` rule 7 requires,
    /// because "this file is quarantined" tells an uploader their malware arrived.
    fn from(value: PreviewError) -> Self {
        match value {
            PreviewError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            PreviewError::Database(error) => error.into(),
            PreviewError::NotReadable => Self::NotFound,
            PreviewError::Source(_) => {
                Self::Upstream { dependency: Dependency::ObjectStorage, retryable: true }
            }
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_worker_failure_never_renders_as_a_missing_preview() {
        // The property the cache depends on. If a dead worker mapped to `NotFound`, the pipeline
        // would record "this document has no preview" for every file it touched during an outage,
        // and the cache would keep saying so long after the worker came back.
        let error: CoreError = PreviewError::Worker(anyhow::anyhow!("pipe closed")).into();
        assert!(!matches!(error, CoreError::NotFound), "{error:?}");
        assert_eq!(error.code(), "INTERNAL_ERROR");
    }

    #[test]
    fn an_unreadable_version_is_indistinguishable_from_an_absent_one() {
        // Rule 7. A distinct status for "quarantined" would tell an uploader their malware landed.
        let error: CoreError = PreviewError::NotReadable.into();
        assert!(matches!(error, CoreError::NotFound), "{error:?}");
    }

    #[test]
    fn a_source_fetch_failure_names_object_storage_so_health_can_report_it() {
        let error: CoreError = PreviewError::Source(anyhow::anyhow!("connection reset")).into();
        match error {
            CoreError::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::ObjectStorage);
                assert!(retryable);
            }
            other => panic!("expected an upstream failure, got {other:?}"),
        }
    }
}
