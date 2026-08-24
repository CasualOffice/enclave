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

    /// The antivirus scanner could not be *used* — never that it reached an unwelcome verdict.
    ///
    /// The distinction is `crates/antivirus/src/error.rs`'s and it is the reason this variant is
    /// almost unreachable: a refused connection, a timeout and an engine answering `ERROR` are all
    /// `ScanVerdict::Error`, values, because `av.unavailable_policy` is written policy that has to
    /// be applied to them. Routed through here they would meet the caller that logs an error and
    /// moves on, and the `HOLD` would be lost.
    ///
    /// What is left is the caller's own inputs breaking, and `crate::antivirus` converts even those
    /// into a verdict at its one call site so that one unreadable object cannot stop a tenant's
    /// queue. The variant exists so that a future caller which does not make that choice cannot
    /// reach for `MalformedRow` instead.
    #[error("the antivirus scanner could not be used")]
    Antivirus(#[from] enclave_antivirus::AntivirusError),

    /// Object storage failed while reading a version's bytes.
    #[error("reading object storage failed")]
    Blob(#[from] enclave_storage::StorageError),

    /// A deployment configured one half of a mount pair and not the other.
    ///
    /// Refused rather than half-built, for two stages now:
    ///
    /// * **OCR** (`ENC-546`). A scanned PDF needs both volumes — weights to recognise text and
    ///   PDFium to render a page for them to read — and building the stage with one of them would
    ///   index every scanned document as empty while the configuration file said OCR was on, which
    ///   is `plans/M3-DISCOVERY.md` D24 reached through configuration.
    /// * **Embedding** (`ENC-661`). A mounted model with no `search.milvus` has nowhere to put its
    ///   vectors, so no stage can be built: the deployment loads 2.2 GB of weights and indexes
    ///   exactly as it did before, with nothing failing and dense search returning nothing.
    ///
    /// `enclave_config::validate`'s `check_mounts` and `check_embedding` refuse the same two states
    /// at startup. This variant is the second guard, for a `Config` that never went through the
    /// loader.
    ///
    /// Both fields are `&'static str`, so this message can only ever name a configuration *key* —
    /// never the path an operator wrote (`CLAUDE.md` rule 10).
    #[error(
        "`{present}` is configured but `{missing}` is not; the stage they belong to needs both, \
         so set both or neither"
    )]
    IncompleteMount {
        /// The mount key that was set.
        present: &'static str,
        /// The mount key that was not.
        missing: &'static str,
    },

    /// Producing a chunk's vectors failed or was refused (`ENC-557`).
    ///
    /// Always transient, by construction: `crates/embeddings/src/error.rs` has no variant meaning
    /// "this text will not embed", because there is no such text and a final error here is a
    /// document whose manifest completes with no vectors. So this stops the pass and the file stays
    /// claimed, exactly as an object-storage outage does — it never becomes a `FAILED` manifest,
    /// which is a verdict about somebody's document.
    #[error("embedding a version's chunks failed")]
    Embedding(#[from] enclave_embeddings::EmbeddingError),

    /// A file's effective classification could not be resolved, so its text was not embedded.
    ///
    /// **The deny-by-default answer to a gap, not a failure.** `ClassifiedText::new` requires the
    /// resource's effective classification — the label after the classification stage has run — and
    /// this deployment has no classification service and no `classifications` table for a rank to
    /// come from. Everything downstream of the rank is a faithful consequence of it and nothing
    /// downstream can detect that it is wrong: a fabricated `PUBLIC` would route a restricted
    /// document to a hosted endpoint under a ceiling that was working correctly, and a fabricated
    /// ceiling-height rank would write a `classification_rank` no caller's ceiling admits, which is
    /// a document that is filed, visible and absent from every search.
    ///
    /// So the file is not embedded and not recorded. Carries nothing: which file it was belongs in
    /// the pass's own span, and the reason is the same for every file in the deployment.
    #[error(
        "no classification service is configured, so a file's effective classification cannot be \
         resolved and its text cannot be routed to an embedding provider"
    )]
    Unclassified,

    /// The vector collection's dense width and the active embedding model's disagree (`ENC-533`).
    ///
    /// Refused at the point a stage is built rather than at the first write, because the width is
    /// fixed when the collection is *created*: a mismatch discovered later costs a new collection
    /// and every chunk of every tenant re-embedded (`docs/07 §9`). It is also refused per batch, for
    /// a provider whose vectors are not the width its deployment claimed.
    ///
    /// Both fields are widths — a configured integer and a compiled-in constant — so this message
    /// cannot name a path, a row or a document (`CLAUDE.md` rule 10).
    #[error(
        "the vector collection is {collection} dimensions wide and the embedding model emits \
         {model}; a collection's width is fixed at creation, so this is a reindex and not a \
         configuration edit"
    )]
    CollectionWidth {
        /// What the collection was created with.
        collection: u32,
        /// What the model produces.
        model: u32,
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
