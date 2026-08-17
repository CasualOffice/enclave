//! Errors this crate can produce.
//!
//! Audit failures are deliberately loud. `CLAUDE.md` rule 10 puts audit inside the policy engine,
//! which means a failure to record is a failure of the operation being recorded — never something
//! to swallow and continue past. The one exception is SIEM forwarding (`docs/06 §20`): a SIEM
//! outage must not block user operations, so that path buffers and retries rather than failing the
//! request, and its error type is the same only so callers do not need two.

use std::fmt;

use enclave_core::{Dependency, Error as CoreError};

/// The result type used throughout this crate.
pub type Result<T, E = AuditError> = std::result::Result<T, E>;

/// Something went wrong recording, reading back or verifying an audit event.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The database refused the write or the read.
    ///
    /// Never mapped to a success: an insert that did not happen is an action that must not be
    /// treated as having happened.
    #[error("audit storage failure")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened. Audit reads and standalone audit writes go
    /// through `TenantScoped` so row-level security sees a tenant; without one, PostgreSQL would
    /// either reject the write or silently return no rows.
    #[error("audit database failure")]
    Database(#[from] enclave_db::DbError),

    /// A detail payload contained field names that this crate refuses to persist.
    ///
    /// See [`crate::redact`] — this is the structural half of `U4` (audit never contains
    /// credentials).
    #[error(transparent)]
    Redaction(#[from] crate::redact::RedactionError),

    /// A stored row could not be read back into an [`crate::AuditEvent`].
    ///
    /// Carries the column and why, never the value: an unparsable row is frequently an *attacked*
    /// row, and echoing its content into logs is how a log-injection payload travels.
    #[error("audit row column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why it failed, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// A stored hash was not 32 bytes, so it cannot be a SHA-256 digest.
    #[error("stored hash is {len} bytes, expected 32")]
    HashLength {
        /// The length actually found.
        len: usize,
    },

    /// An invariant inside the sink broke — a poisoned lock, for instance.
    #[error("audit sink internal failure: {0}")]
    Internal(&'static str),
}

impl AuditError {
    /// Whether retrying the same write could plausibly succeed.
    ///
    /// Only transport-level database failures are retryable. A redaction rejection or a malformed
    /// row is deterministic: retrying produces the same answer and hides the defect.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Storage(e) => matches!(
                e,
                sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
            ),
            _ => false,
        }
    }
}

impl From<AuditError> for CoreError {
    /// Maps to the vocabulary the API edge speaks.
    ///
    /// Everything that is not a database transport problem becomes `Internal`, because no audit
    /// failure is a *client's* problem to fix and none of them should leak their shape into a
    /// response body.
    fn from(value: AuditError) -> Self {
        match value {
            AuditError::Storage(ref e) => {
                let retryable = matches!(
                    e,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// A hash that was not the right length to be a SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashLengthError {
    /// How many bytes were supplied.
    pub len: usize,
}

impl fmt::Display for HashLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected a 32-byte SHA-256 digest, got {} bytes", self.len)
    }
}

impl std::error::Error for HashLengthError {}

impl From<HashLengthError> for AuditError {
    fn from(value: HashLengthError) -> Self {
        Self::HashLength { len: value.len }
    }
}
