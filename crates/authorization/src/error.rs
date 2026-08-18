//! Errors this crate can produce, and how they reach the API edge.
//!
//! The distinction that matters here is the one `PolicyEngine::enforce` relies on: an **error** is
//! not a **denial**. A denial is an answer — the ACL was read and it said no. An error means the
//! ACL could not be read, and the engine propagates it rather than converting it into a refusal
//! (`crates/core/src/engine.rs`, `an_evaluation_failure_is_not_silently_converted_into_a_denial`).
//! Collapsing the two would let a database outage read as "access denied" and hide an incident
//! behind a plausible message — and, in the other direction, would let a resolver bug that throws
//! on every row look like a strict-but-working policy.

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = AuthzError> = core::result::Result<T, E>;

/// Something went wrong resolving effective permissions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// A statement failed.
    #[error("authorization query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    ///
    /// Resolution reads `acl_entries`, `files`, `libraries` and `group_members`, every one of them
    /// tenant-scoped and under forced row-level security. Without a tenant context the queries do
    /// not return "everything" — they return nothing, which would read as a clean deny-all. That is
    /// the failure mode PR #22 found, so it is an error and never a verdict.
    #[error("authorization database failure")]
    Database(#[from] enclave_db::DbError),

    /// A stored row could not be interpreted.
    ///
    /// Carries the column and a fixed phrase, never the value: an unreadable ACL row may well be a
    /// tampered one, and echoing its content into a log is how an injection payload travels.
    #[error("acl row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// The inheritance walk hit its depth limit before reaching a root.
    ///
    /// Deliberately an error rather than "resolve with what we have". A truncated chain is a chain
    /// missing its topmost ancestors, and those are exactly where an organisation-wide `DENY` is
    /// written — so a partial resolution can only ever be wrong in the permissive direction.
    #[error("inheritance chain exceeded the configured depth of {limit}")]
    ChainTooDeep {
        /// The configured limit that was reached.
        limit: i32,
    },
}

impl From<AuthzError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Transport-level database failures become [`CoreError::Upstream`] so a degraded response can
    /// name PostgreSQL; everything else becomes `Internal`, which keeps the source chain for the
    /// logs while rendering to the caller as the bare phrase "internal error". A malformed ACL row
    /// and a chain that is too deep are both our defects, not the caller's, and their shape stays
    /// out of the response body.
    fn from(value: AuthzError) -> Self {
        match value {
            AuthzError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            AuthzError::Database(error) => error.into(),
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_resolution_failure_never_renders_as_a_denial() {
        // The property the engine depends on: if this ever produced `PolicyDenied`, a database
        // outage would be indistinguishable from a policy that says no.
        let error: CoreError = AuthzError::ChainTooDeep { limit: 64 }.into();
        assert!(!matches!(error, CoreError::PolicyDenied { .. }), "{error:?}");
        assert_eq!(error.code(), "INTERNAL_ERROR");

        let error: CoreError =
            AuthzError::MalformedRow { column: "effect", reason: "not a known effect" }.into();
        assert!(!matches!(error, CoreError::PolicyDenied { .. }), "{error:?}");
    }

    #[test]
    fn a_transport_failure_names_postgres_so_health_can_report_it() {
        let error: CoreError = AuthzError::Storage(sqlx::Error::PoolClosed).into();
        assert!(
            matches!(
                error,
                CoreError::Upstream { dependency: Dependency::Postgres, retryable: true }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn an_internal_error_says_nothing_about_the_acl() {
        // `to_string()` on an error is exactly how internal detail reaches a response body.
        let error: CoreError =
            AuthzError::MalformedRow { column: "principal_type", reason: "unknown" }.into();
        assert_eq!(error.to_string(), "internal error");
    }
}
