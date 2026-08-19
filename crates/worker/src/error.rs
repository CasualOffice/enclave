//! Errors the housekeeping loops can produce.
//!
//! # A failed sweep is not a failed search
//!
//! Everything here is reported to whatever drives the loop — the scheduler, a test, an operator
//! command — and to nobody else. There is no request to fail: a sweep that cannot reach PostgreSQL
//! leaves the denylist exactly as it was, which is the state every search already answers correctly
//! from. That is the whole point of `plans/M3-DISCOVERY.md` D22, and it is why these variants carry
//! no remediation and no HTTP mapping.
//!
//! What they must do is *name the dependency*, because an unavailable database and a statement that
//! is wrong are the same red line in a log otherwise, and only one of them fixes itself.

/// Something went wrong during a housekeeping pass.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkerError {
    /// A statement failed.
    #[error("worker statement failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    #[error("worker database failure")]
    Database(#[from] enclave_db::DbError),

    /// The denylist sweep failed inside `enclave-search`.
    #[error("the denylist sweep failed")]
    Search(#[from] enclave_search::SearchError),

    /// A stored row could not be interpreted.
    ///
    /// Fixed vocabulary rather than the offending value: these loops read rows written by the
    /// indexer, and echoing what an extractor produced into a log line is how a payload travels
    /// (`CLAUDE.md` rule 10).
    #[error("worker column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, without the value.
        reason: &'static str,
    },
}

/// The result type every entry point in this crate returns.
pub type Result<T> = core::result::Result<T, WorkerError>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn no_variant_can_carry_a_row_value_into_a_log() {
        // The one variant with interpolated fields is `MalformedRow`, and both of its fields are
        // `&'static str` — so there is no way to reach `Display` with something an extractor
        // produced. Asserted rather than trusted because the tempting fix for a debugging session
        // is to add the value "just while I look at this".
        let error = WorkerError::MalformedRow { column: "acl_epoch", reason: "not an integer" };
        let shown = error.to_string();
        assert!(shown.contains("acl_epoch"), "{shown}");
        assert!(shown.contains("not an integer"), "{shown}");
    }
}
