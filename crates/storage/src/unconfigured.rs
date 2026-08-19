//! The store a deployment has when it has no store.
//!
//! # Why this exists rather than an `Option<Arc<dyn BlobStore>>`
//!
//! `ENC-170`: `crates/api`'s router registered two routes — download and preview — whose axum
//! `Extension` the binary never provided. Both answered `500`, and both passed every integration
//! test, because the tests build their own router with the extension attached. Nothing in the
//! workspace ran the binary against a real request, so the gap was invisible for four milestones.
//!
//! An `Option` would leave the same shape: a `None` somebody has to remember to check, at each of
//! the call sites, forever. This is the shape `crates/core`'s policy stages already use —
//! `UnconfiguredConditionalAccess`, `DisabledDlp` — where "not configured" is a *value* with
//! defined behaviour rather than an absence. The binary warns about it at start-up beside those,
//! for the reason `main.rs` gives: a deployment running with stages that permit everything looks
//! identical from the outside to one carefully allowing each request.
//!
//! # Every method refuses, and the self-check refuses hardest
//!
//! [`StorageError::NotConfigured`] renders as a `503` naming object storage: an operator's problem,
//! and retryable once somebody configures a store. A `404` would tell a caller their file is gone.
//!
//! [`PublicAccessCheck::verify_not_public`] returns `Inconclusive`, not a pass. There is no bucket,
//! so nothing was proven — and the whole point of that check (`docs/08-BYO-INFRA.md §5`) is that a
//! deployment refuses to start against a bucket it could not prove private. A stub that reported
//! "not public" would turn the absence of a bucket into evidence about one.

use core::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::blob_store::BlobStore;
use crate::error::{Result, StorageError};
use crate::model::{
    ByteRange, ByteStream, ObjectMeta, StoreCapabilities, Support, UploadRequest, UploadSession,
};
use crate::public_access::{PublicAccessCheck, PublicAccessError, PublicAccessReport};

/// A [`BlobStore`] that refuses everything, because there is nothing behind it.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredBlobStore;

/// The name used in start-up warnings and in the `Inconclusive` report.
const NO_BUCKET: &str = "<unconfigured>";

#[async_trait]
impl BlobStore for UnconfiguredBlobStore {
    async fn create_upload(&self, _request: UploadRequest) -> Result<UploadSession> {
        Err(StorageError::NotConfigured)
    }

    async fn complete_upload(&self, _session: &UploadSession) -> Result<ObjectMeta> {
        Err(StorageError::NotConfigured)
    }

    async fn signed_download(&self, _key: &str, _ttl: Duration) -> Result<Url> {
        Err(StorageError::NotConfigured)
    }

    async fn read_range(&self, _key: &str, _range: ByteRange) -> Result<ByteStream> {
        Err(StorageError::NotConfigured)
    }

    async fn copy(&self, _from: &str, _to: &str) -> Result<()> {
        Err(StorageError::NotConfigured)
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        Err(StorageError::NotConfigured)
    }

    /// Everything unsupported.
    ///
    /// Not the defaults of some notional provider: a caller that branches on a capability would
    /// otherwise take the multipart path against a store that has no multipart, and get a refusal
    /// several steps further from the cause than this one.
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities {
            backend: "unconfigured",
            multipart: None,
            signed_urls: false,
            single_use_signed_urls: false,
            max_signed_url_ttl: Duration::ZERO,
            versioning: Support::Unknown,
            object_lock: Support::Unknown,
            server_side_encryption: Support::Unknown,
            range_reads: false,
            server_side_copy: false,
        }
    }
}

#[async_trait]
impl PublicAccessCheck for UnconfiguredBlobStore {
    /// Inconclusive, never a pass. See the module documentation.
    async fn verify_not_public(
        &self,
    ) -> core::result::Result<PublicAccessReport, PublicAccessError> {
        Err(PublicAccessError::Inconclusive {
            bucket: NO_BUCKET.to_owned(),
            endpoint: None,
            probes: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn the_self_check_never_reports_a_bucket_it_did_not_probe_as_private() {
        // The assertion that matters. A stub returning `Ok` here would let a deployment with no
        // storage satisfy the one check that exists to stop it starting against a public bucket —
        // turning the absence of a bucket into evidence about one.
        let outcome = UnconfiguredBlobStore.verify_not_public().await;
        assert!(matches!(outcome, Err(PublicAccessError::Inconclusive { .. })), "{outcome:?}");
    }

    #[tokio::test]
    async fn every_operation_refuses_as_unconfigured_rather_than_as_missing() {
        // `NotFound` would tell a caller their file is gone; this is an operator's problem.
        let store = UnconfiguredBlobStore;
        assert!(matches!(
            store.signed_download("k", Duration::from_secs(60)).await,
            Err(StorageError::NotConfigured)
        ));
        assert!(matches!(store.copy("a", "b").await, Err(StorageError::NotConfigured)));
    }
}
