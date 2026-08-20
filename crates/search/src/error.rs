//! Errors this crate can produce.
//!
//! # An outage is never an empty result
//!
//! The distinction that matters here is the one the post-filter turns on. A search that cannot
//! reach PostgreSQL must **fail**, not return nothing. "No matches" is an answer a caller acts on —
//! they conclude the document is not there, or was deleted, or that they misremembered its name.
//! Returning it during an incident is a search that lies confidently, which is the failure mode
//! `docs/07 §7`'s degraded mode exists to avoid and which an over-eager `unwrap_or_default` would
//! reintroduce in one line.

use enclave_core::{Dependency, Error as CoreError};

/// Something went wrong answering a search.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SearchError {
    /// A statement failed.
    #[error("search query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    #[error("search database failure")]
    Database(#[from] enclave_db::DbError),

    /// A stored row could not be interpreted.
    #[error("search column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// The vector index could not answer.
    ///
    /// A query failure, and **not** a degradation. `crate::degraded` sets out why the two must stay
    /// apart: degraded mode engages on states that persist across requests, so that the same query
    /// does not answer completely at 10:00:01 and degraded at 10:00:02. A single timed-out search
    /// is exactly the per-request signal that doctrine excludes, and turning it into a fallback
    /// here would put the trigger back one layer down where nobody is looking for it.
    ///
    /// Carries `operation` — fixed vocabulary, never the SDK's message. A Milvus error's display
    /// can echo the expression that provoked it, and this crate's expressions hold tenant and
    /// library identifiers (`CLAUDE.md` rule 10).
    #[error("the vector index could not answer `{operation}`")]
    VectorIndex {
        /// Which RPC failed, from a fixed set.
        operation: &'static str,
        /// Whether trying again could plausibly work. A server rejection fails identically the
        /// second time, and marking it retryable turns one bad request into several.
        retryable: bool,
    },

    /// The collection is not the one this code was written against.
    ///
    /// Separate from [`SearchError::VectorIndex`] because it is not an outage and a retry will not
    /// fix it — somebody has to reprovision. It reads as an internal failure rather than an
    /// upstream one for that reason.
    #[error("the vector collection is not usable: {reason}")]
    VectorCollection {
        /// What is wrong, in fixed vocabulary.
        reason: &'static str,
    },

    /// Authorization could not be resolved.
    ///
    /// Propagated, never converted into "this candidate is not visible". A resolver that failed on
    /// every row would otherwise look like a strict-but-working post-filter returning nothing —
    /// which is exactly the shape of a leak-free search and of a broken one.
    #[error("the post-filter could not resolve permissions")]
    Resolution(#[source] CoreError),
}

impl From<SearchError> for CoreError {
    fn from(value: SearchError) -> Self {
        match value {
            SearchError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            SearchError::Database(error) => error.into(),
            SearchError::VectorIndex { retryable, .. } => {
                Self::Upstream { dependency: Dependency::Milvus, retryable }
            }
            SearchError::Resolution(error) => error,
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_resolution_failure_is_never_an_empty_result() {
        // Asserted as a type property, because the dangerous version of this bug is not a wrong
        // mapping — it is a `unwrap_or_default()` at a call site. `SearchError::Resolution` exists
        // so that failure has somewhere to go that is not `Vec::new()`.
        let underlying = CoreError::Upstream { dependency: Dependency::Postgres, retryable: true };
        let error: CoreError = SearchError::Resolution(underlying).into();
        assert_eq!(error.status_code(), 503, "a resolution outage must not read as success");
    }

    #[test]
    fn a_storage_failure_names_postgres_so_health_can_report_it() {
        let error: CoreError = SearchError::Storage(sqlx::Error::PoolClosed).into();
        assert!(matches!(error, CoreError::Upstream { dependency: Dependency::Postgres, .. }));
    }

    #[test]
    fn a_failed_vector_query_names_milvus_and_is_never_an_empty_page() {
        // The distinction `crate::degraded` turns on: the vector store being *unreachable* is a
        // state that degrades, and one failed query is an error. If this mapped to anything with a
        // 2xx status the fallback would have been implemented here by accident.
        let error: CoreError =
            SearchError::VectorIndex { operation: "search", retryable: true }.into();
        assert!(matches!(error, CoreError::Upstream { dependency: Dependency::Milvus, .. }));
        assert_eq!(error.status_code(), 503);
    }

    #[test]
    fn a_misprovisioned_collection_is_not_reported_as_an_outage() {
        // A retry cannot fix a missing partition key, and reporting it as an upstream failure sends
        // an operator to look at Milvus's health instead of at who created the collection.
        let error: CoreError = SearchError::VectorCollection { reason: "no partition key" }.into();
        assert!(matches!(error, CoreError::Internal(_)));
    }
}
