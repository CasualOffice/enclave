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

    /// A call into `enclave-search` failed — the sweep's `DELETE`, or a coverage probe's two
    /// counts.
    ///
    /// Named for the crate rather than for the caller, because both loops that reach it report
    /// through this one variant and a message naming the sweep appears in a coverage probe's log
    /// line otherwise.
    #[error("a call into enclave-search failed")]
    Search(#[from] enclave_search::SearchError),

    /// Indexing a version failed for a reason that is not the document's fault.
    ///
    /// A document that will not parse is **not** this: that is an `Outcome`, recorded on the
    /// manifest and counted. This is the storage or database underneath failing, which stops the
    /// queue rather than marking one file.
    #[error("indexing failed")]
    Indexing(#[from] enclave_indexing::IndexingError),

    /// Reading a version's readability failed.
    #[error("the readable-version lookup failed")]
    Preview(#[from] enclave_preview::PreviewError),

    /// Object storage failed while reading a version's bytes.
    #[error("reading object storage failed")]
    Blob(#[from] enclave_storage::StorageError),

    /// A deployment configured one half of the OCR mount pair and not the other (`ENC-546`).
    ///
    /// Refused rather than half-built. OCR over a scanned PDF needs both volumes — weights to
    /// recognise text and PDFium to render a page for them to read — and building the stage with one
    /// of them would index every scanned document as empty while the configuration file said OCR was
    /// on, which is `plans/M3-DISCOVERY.md` D24 reached through configuration.
    ///
    /// `enclave_config::validate::check_mounts` refuses the same state at startup. This variant is
    /// the second guard, for a `Config` that never went through the loader.
    ///
    /// Both fields are `&'static str`, so this message can only ever name a configuration *key* —
    /// never the path an operator wrote (`CLAUDE.md` rule 10).
    #[error(
        "`{present}` is configured but `{missing}` is not; OCR over a scanned PDF needs both \
         volumes, so set both or neither"
    )]
    IncompleteMount {
        /// The mount key that was set.
        present: &'static str,
        /// The mount key that was not.
        missing: &'static str,
    },

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
        // Two variants interpolate fields — `MalformedRow` and `IncompleteMount` — and every one of
        // those four fields is `&'static str`, so there is no way to reach `Display` with something
        // an extractor produced or something an operator wrote. Asserted rather than trusted because
        // the tempting fix for a debugging session is to add the value "just while I look at this".
        let error = WorkerError::MalformedRow { column: "acl_epoch", reason: "not an integer" };
        let shown = error.to_string();
        assert!(shown.contains("acl_epoch"), "{shown}");
        assert!(shown.contains("not an integer"), "{shown}");

        // A mount refusal names the two keys and cannot name the path behind either of them: a
        // deployment's filesystem layout is not something a log pipeline needs.
        let error = WorkerError::IncompleteMount { present: "pdfium", missing: "ocr_models" };
        let shown = error.to_string();
        assert!(shown.contains("pdfium"), "{shown}");
        assert!(shown.contains("ocr_models"), "{shown}");
    }
}
