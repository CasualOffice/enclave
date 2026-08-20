//! Errors this crate can produce, and the line between an error and a refusal.
//!
//! The same line `crates/preview/src/error.rs` draws, drawn again here because extraction reaches
//! it from the other side. A [`Refusal`](enclave_preview::Refusal) is an *answer* about a source:
//! it will not extract, re-running changes nothing, and the manifest records why. An
//! [`IndexingError`] means the pipeline could not reach an answer at all.
//!
//! Collapsing them is wrong in both directions, and extraction makes the second direction worse
//! than rendering does. A missing preview is visible — a user sees a placeholder and complains. A
//! document that failed to extract is *invisible*: it is filed, listed, and simply never appears in
//! a result. `plans/M3-DISCOVERY.md` D24 makes that the milestone's stated failure mode, so an
//! extraction worker that is down must never be recorded as "this document has no text".

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = IndexingError> = core::result::Result<T, E>;

/// Something went wrong running extraction, on our side of the line.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IndexingError {
    /// The extraction worker failed — died, the pipe broke, the task was cancelled.
    ///
    /// Explicitly *not* a refusal. See the module documentation.
    #[error("the extraction worker failed")]
    Worker(#[source] anyhow::Error),

    /// A statement against PostgreSQL failed while storing what extraction produced.
    ///
    /// Also explicitly not a refusal, and for the sharper version of the same reason: a document
    /// whose chunks could not be *written* has no text in the index and no record saying why. If
    /// this mapped to anything a caller or a manifest reads as "this document has no text", a
    /// database outage would mark every file it touched textless and they would stay invisible to
    /// search long after the outage ended.
    #[error("chunk storage failed")]
    Storage(#[from] sqlx::Error),
}

impl From<IndexingError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Nothing in this enum is a statement about a *document*, so nothing in it may become a `404`
    /// and tell a caller their file has no content.
    ///
    /// [`IndexingError::Worker`] is ours and stays `Internal`. [`IndexingError::Storage`] is the
    /// database's, and maps the way `PreviewError`'s and `SearchError`'s do — to `Upstream`, so
    /// health names PostgreSQL rather than reporting our own defect inside our own error budget
    /// (`ENC-171`). Retryability is read from the failure rather than assumed: a pool timeout or a
    /// dropped connection can succeed on a second attempt, and a constraint violation fails
    /// identically forever, so marking it retryable turns one bad write into several.
    fn from(value: IndexingError) -> Self {
        match value {
            IndexingError::Worker(_) => Self::Internal(anyhow::Error::new(value)),
            IndexingError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_worker_failure_never_renders_as_a_document_without_text() {
        // The property D24 turns on. If a dead worker mapped to `NotFound` — or to anything a
        // caller reads as "there is nothing here" — an outage would record every file it touched as
        // textless, and those files would stay invisible to search long after the worker came back,
        // with nothing on any surface saying so.
        let error: CoreError = IndexingError::Worker(anyhow::anyhow!("pipe closed")).into();
        assert!(!matches!(error, CoreError::NotFound), "{error:?}");
        assert_eq!(error.code(), "INTERNAL_ERROR");
    }

    #[test]
    fn a_failed_chunk_write_names_postgres_and_is_never_a_document_without_text() {
        // The same property from the storage side, and the reason `Storage` is not folded into
        // `Worker`: an operator seeing `INTERNAL_ERROR` looks at the indexing worker, and the
        // database is what is unwell. `ENC-171` is this mistake in the API renderer.
        let error: CoreError = IndexingError::Storage(sqlx::Error::PoolClosed).into();
        assert!(!matches!(error, CoreError::NotFound), "{error:?}");
        assert!(
            matches!(error, CoreError::Upstream { dependency: Dependency::Postgres, .. }),
            "a chunk write failure must name PostgreSQL: {error:?}"
        );
        assert_eq!(error.status_code(), 503, "a storage outage must not read as our own defect");
    }
}
