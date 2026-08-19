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
}
