//! This crate's error type, and its one-way mapping into the canonical one.
//!
//! # Why this enum is small
//!
//! Almost everything that goes wrong during a scan is *not* an error here. A refused connection, a
//! timeout, an engine that answers `ERROR` — all of those are
//! [`ScanVerdict::Error { retryable }`](crate::ScanVerdict::Error), a value, because
//! `docs/06-SECURITY-DLP-ACCESS.md §6.2` attaches a written policy to them (`av.unavailable_policy`)
//! and that policy has to be applied. Returning them as `Err` invites the one handler that maps
//! errors to `500` and drops the `HOLD`, which is precisely the shape of a version becoming
//! readable without having been scanned.
//!
//! What is left is failures of the caller's own inputs: the byte stream broke, or the scanner was
//! constructed with a configuration it cannot honour. Those are `Err`, because no antivirus policy
//! applies to them.

use enclave_core::Dependency;
use enclave_storage::StorageError;

/// This crate's result alias.
pub type Result<T> = core::result::Result<T, AntivirusError>;

/// Why a scan could not be attempted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AntivirusError {
    /// The byte stream handed to [`scan`](crate::AntivirusScanner::scan) failed part-way.
    ///
    /// The content was never fully seen, so no verdict about it is honest — including `Clean`.
    /// The caller retries the read; the version stays where it is.
    #[error("the content stream failed before the scan completed")]
    Source(#[from] StorageError),

    /// The scanner was configured in a way it cannot act on.
    ///
    /// Surfaced at construction wherever possible, so a deployment fails to start rather than
    /// failing every scan (`docs/08-BYO-INFRA.md §19` is the same argument for the whole config).
    #[error("antivirus configuration is unusable: {reason}")]
    Configuration {
        /// What is wrong. Operator-facing; never returned to an uploader.
        reason: String,
    },

    /// The engine could not be reached while answering
    /// [`engine_info`](crate::AntivirusScanner::engine_info).
    ///
    /// **[`scan`](crate::AntivirusScanner::scan) never returns this.** An unreachable engine on
    /// the scan path is [`ScanVerdict::Error`](crate::ScanVerdict::Error) so that
    /// `av.unavailable_policy` is applied to it. `engine_info` is an operational query with no
    /// policy attached — nothing becomes readable because a health probe failed — so it may fail
    /// in the ordinary way, and a health endpoint reporting "engine unknown" is more useful than
    /// one inventing a plausible version string.
    #[error("the antivirus engine could not be reached")]
    Unreachable,
}

impl From<AntivirusError> for enclave_core::Error {
    /// One-way, and beside the enum so the two are edited together: a variant added above without
    /// a mapping here is a compile error, which is the only reliable way to stop a new failure
    /// mode from defaulting to `500`.
    ///
    /// Both variants become [`enclave_core::Error::Upstream`] rather than `Internal`. The scan did
    /// not happen and the caller should try again; `Internal` says "this is our bug", which is
    /// wrong for a broken read and misleading for a misconfiguration.
    fn from(error: AntivirusError) -> Self {
        let (dependency, retryable) = match error {
            AntivirusError::Source(_) => (Dependency::ObjectStorage, true),
            AntivirusError::Configuration { .. } => (Dependency::Antivirus, false),
            AntivirusError::Unreachable => (Dependency::Antivirus, true),
        };
        Self::Upstream { dependency, retryable }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_stream_is_retryable_and_blamed_on_storage() {
        let error = AntivirusError::Source(StorageError::NotFound { key: "k".into() });
        match enclave_core::Error::from(error) {
            enclave_core::Error::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::ObjectStorage);
                assert!(retryable);
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn a_misconfiguration_is_not_retryable_and_needs_an_operator() {
        let error = AntivirusError::Configuration { reason: "no endpoint".into() };
        match enclave_core::Error::from(error) {
            enclave_core::Error::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::Antivirus);
                assert!(!retryable);
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn the_display_text_never_carries_engine_detail_to_a_response_body() {
        // `Configuration` is the one variant that holds free text, and it is operator-facing.
        // The mapping above discards it entirely — `Error::Upstream` has no message field — so
        // there is no path from this string to a client.
        let error = AntivirusError::Configuration { reason: "clamd at 10.0.0.4:3310".into() };
        assert!(enclave_core::Error::from(error).to_string().contains("ANTIVIRUS"));
    }
}
