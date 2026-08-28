//! The provider for `antivirus.provider: none`.
//!
//! # The name
//!
//! [`NoScanningPerformed`], not `NoopScanner`, `NullScanner` or `DisabledScanner`. In a wiring
//! block those three read as "the simple one" — a plausible default for a test, a local run, a
//! deployment somebody is in a hurry with. This one reads as a statement of fact about the
//! deployment, and there is no sentence containing it that sounds like scanning:
//!
//! ```text
//! let scanner: Arc<dyn AntivirusScanner> = Arc::new(NoScanningPerformed::new());
//! ```
//!
//! It is the same technique as [`UnconfiguredClassification`] in `enclave-classification`: name
//! the type for the state it represents, so the reader of a diff has to notice.
//!
//! [`UnconfiguredClassification`]: https://docs.rs/enclave-classification
//!
//! # Why it does not answer `Clean`
//!
//! Because it did not look. `Clean` is a claim about content, and this type has no basis for one;
//! answering it would put `av_status = 'CLEAN'` on the version and make unscanned content
//! indistinguishable from scanned content forever after — including to the signature-update rescan
//! sweep, which would then have no way to find it.
//!
//! It answers [`ScanVerdict::Unsupported`], which is honest — nothing here supports scanning — and
//! which routes into the policy `docs/06-SECURITY-DLP-ACCESS.md §6.2` already defines for content
//! that could not be scanned. The consequences fall out for free rather than needing a fourth rule:
//!
//! * `av_status` becomes `SKIPPED`, so unscanned content is queryable and the rescan sweep can
//!   find it if an engine is configured later.
//! * A tenant on the default `BLOCK` policy publishes nothing at all, which is the correct
//!   behaviour for "you turned off antivirus and did not say what should happen instead".
//! * A tenant on `ALLOW_WITH_FLAG` publishes, flagged unscanned — and *still* blocks at
//!   `CONFIDENTIAL` and above, because that ceiling is not a default one can switch off.
//!
//! That third bullet described an intention rather than the product until `ENC-828`:
//! `enclave_versions::READABLE_PREDICATE` accepted `CLEAN` and nothing else, so a version this
//! provider's policy deliberately *published* was refused by preview, download, export and sync
//! alike. `ALLOW_WITH_FLAG` was a no-op with a misleading name, and a deployment on
//! `antivirus.provider: none` was a write-only store — uploads succeeded and nothing could ever be
//! read back. The predicate now admits `AVAILABLE`/`SKIPPED`, which nothing but the publish path
//! can write; the `CLEAN` claim below is exactly as forbidden as it was.
//!
//! # Where it is refused
//!
//! `docs/08-BYO-INFRA.md §19`, enforced in `enclave-config`'s validation: the `enterprise` profile
//! will not start with `antivirus.provider: none`. That check is in the configuration layer on
//! purpose — by the time this crate could notice, the process is up and accepting uploads.

use async_trait::async_trait;
use enclave_storage::ByteStream;
use futures::StreamExt as _;
use tracing::warn;

use crate::error::Result;
use crate::model::{EngineInfo, ScanHint, ScanVerdict};
use crate::scanner::AntivirusScanner;

/// The engine name recorded on versions handled by this provider.
///
/// Written to `file_versions.av_engine`, so a later audit of "what scanned this" gets a sentence
/// rather than an empty column or the word `none`, which reads as missing data.
pub const ENGINE_NAME: &str = "none — no scanning was performed";

/// What is wired in when `antivirus.provider` is `none`.
///
/// See the module documentation for why this is not called `NoopScanner` and why it does not
/// answer [`ScanVerdict::Clean`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScanningPerformed;

impl NoScanningPerformed {
    /// Constructs the provider, warning once per construction that this deployment does not scan.
    ///
    /// The warning is here rather than at the call site because the call site is exactly what a
    /// reader skims. It costs one line in the log of a deployment that meant it, and is the only
    /// signal in a deployment that did not.
    #[must_use]
    pub fn new() -> Self {
        warn!(
            "antivirus.provider is `none`: uploaded content is NOT scanned for malware. \
             The enterprise deployment profile refuses this (docs/08-BYO-INFRA.md §19)."
        );
        Self
    }
}

#[async_trait]
impl AntivirusScanner for NoScanningPerformed {
    /// # Errors
    ///
    /// [`crate::AntivirusError::Source`] if the stream broke. The stream is still drained: a
    /// caller must not be able to tell from timing or from backpressure whether a real engine is
    /// behind this, or the disabled path would become a different code path with different bugs.
    async fn scan(&self, mut stream: ByteStream, _hint: ScanHint) -> Result<ScanVerdict> {
        while let Some(chunk) = stream.next().await {
            let _ = chunk?;
        }
        Ok(ScanVerdict::Unsupported)
    }

    /// # Errors
    ///
    /// Never. The signature is fallible because the trait is.
    async fn engine_info(&self) -> Result<EngineInfo> {
        Ok(EngineInfo {
            engine: ENGINE_NAME.to_owned(),
            signature_version: None,
            scans_content: false,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use bytes::Bytes;
    use enclave_core::ClassificationRank;
    use enclave_storage::StorageError;

    use super::*;
    use crate::eicar::eicar_test_file;
    use crate::outcome::{
        decide, AvStatus, ScanPolicy, UnsupportedPolicy, VersionDisposition, CONFIDENTIAL_RANK,
    };

    fn stream_of(bytes: Vec<u8>) -> ByteStream {
        let length = bytes.len() as u64;
        ByteStream::new(
            futures::stream::once(async move { Ok::<_, StorageError>(Bytes::from(bytes)) }),
            Some(length),
        )
    }

    #[tokio::test]
    async fn it_never_answers_clean_even_for_content_that_is_clean() {
        let verdict = NoScanningPerformed
            .scan(stream_of(b"an ordinary document".to_vec()), ScanHint::empty())
            .await
            .unwrap();
        assert_eq!(verdict, ScanVerdict::Unsupported);
        assert_ne!(verdict, ScanVerdict::Clean);
    }

    #[tokio::test]
    async fn it_does_not_detect_eicar_which_is_the_point_of_the_name() {
        // Stated as a test so that nobody reads `Unsupported` as a weak form of scanning: this
        // provider cannot tell EICAR from a shopping list, and the test says so out loud.
        let verdict = NoScanningPerformed
            .scan(stream_of(eicar_test_file()), ScanHint::empty())
            .await
            .unwrap();
        assert_eq!(verdict, ScanVerdict::Unsupported);
    }

    #[tokio::test]
    async fn its_engine_info_says_plainly_that_it_does_not_scan() {
        let info = NoScanningPerformed.engine_info().await.unwrap();
        assert!(!info.scans_content);
        assert!(info.engine.contains("no scanning"));
        assert_eq!(info.signature_version, None);
    }

    #[tokio::test]
    async fn under_the_default_policy_a_deployment_without_an_engine_publishes_nothing() {
        let verdict = NoScanningPerformed
            .scan(stream_of(b"anything".to_vec()), ScanHint::empty())
            .await
            .unwrap();
        let outcome = decide(&verdict, ScanPolicy::default(), None);
        assert_eq!(outcome.disposition, VersionDisposition::Quarantine);
        assert!(!outcome.readable());
        assert_eq!(outcome.av_status, AvStatus::Skipped);
    }

    #[tokio::test]
    async fn a_tenant_that_opts_into_allow_with_flag_still_blocks_confidential_content() {
        let verdict = NoScanningPerformed
            .scan(stream_of(b"anything".to_vec()), ScanHint::empty())
            .await
            .unwrap();
        let policy =
            ScanPolicy { unsupported: UnsupportedPolicy::AllowWithFlag, ..ScanPolicy::default() };

        let ordinary = decide(&verdict, policy, Some(ClassificationRank::new(20)));
        assert_eq!(ordinary.disposition, VersionDisposition::Publish);
        assert!(ordinary.flagged_unscanned, "published content must be marked as never scanned");

        let confidential = decide(&verdict, policy, Some(CONFIDENTIAL_RANK));
        assert_eq!(confidential.disposition, VersionDisposition::Quarantine);
    }
}
