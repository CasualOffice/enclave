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

use enclave_core::Error as CoreError;

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
}

impl From<IndexingError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Everything here is `Internal` today, and that is the point rather than a gap: nothing in
    /// this enum is a statement about a *document*, so nothing in it may become a `404` and tell a
    /// caller their file has no content. When extraction grows a database or object-storage
    /// dependency, those arms map the way `PreviewError`'s do — to `Upstream`, so health can name
    /// what is broken.
    fn from(value: IndexingError) -> Self {
        match value {
            IndexingError::Worker(_) => Self::Internal(anyhow::Error::new(value)),
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
}
