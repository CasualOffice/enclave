//! The object store, as the pipeline's source port.
//!
//! # Why the store stops here
//!
//! This is the only file in the delivery path that holds a
//! [`BlobStore`](enclave_storage::BlobStore). `crates/api/src/preview.rs` holds none by
//! construction, [`RenditionService`](crate::RenditionService) holds a
//! [`SourceReader`](crate::SourceReader) rather than a store, and a
//! [`Renderer`](crate::Renderer) is handed bytes rather than anything it could fetch with. Each of
//! those is one narrowing of the same capability, and this is where the last of it lives: a type
//! with one method, which reads one key it was given by a
//! [`ReadableVersion`](crate::ReadableVersion) and hands the bytes back.
//!
//! It cannot mint a URL — [`BlobStore::signed_download`](enclave_storage::BlobStore::signed_download)
//! is on the store it holds, and calling it is a diff a reviewer notices in the one file where such
//! a call would be visible. `CLAUDE.md` rule 6 asks that no original object-storage URL is issued on
//! a rendition path; what makes that true is that the whole path has one storage call site and it
//! is a `read_range`.
//!
//! # The bound is not the store's to choose
//!
//! [`ByteStream::collect_bounded`](enclave_storage::ByteStream::collect_bounded) takes a limit
//! because the exit criterion behind `crates/uploads` is a 5 GB transfer with flat API memory, and
//! an unbounded `collect` would be reached for eventually. The limit here is
//! [`RenderBudget::max_input_bytes`] — the same number the service checks the *row's* declared size
//! against before it fetches anything. Both checks exist for the reason
//! [`crate::service`] gives: the first stops the read from being attempted, and this one is what
//! holds when the row's `size_bytes` and the object disagree.

use std::sync::Arc;

use async_trait::async_trait;
use enclave_storage::{BlobStore, ByteRange, StorageError};

use crate::budget::RenderBudget;
use crate::error::{PreviewError, Result};
use crate::service::SourceReader;

/// Reads a version's bytes out of object storage, bounded by the render budget.
#[derive(Clone)]
pub struct BlobSource {
    store: Arc<dyn BlobStore>,
    max_bytes: usize,
}

impl BlobSource {
    /// Binds a store to a budget.
    ///
    /// The budget is taken whole rather than as a `usize` cap so that the call site cannot pass a
    /// number that disagrees with the one the service enforces — they come from one value.
    #[must_use]
    pub fn new(store: Arc<dyn BlobStore>, budget: RenderBudget) -> Self {
        Self {
            store,
            // On a 32-bit target the budget may exceed `usize`, and saturating is the safe
            // direction: the smaller of the two bounds wins, and a machine that cannot address the
            // buffer refuses before allocating rather than wrapping to something tiny.
            max_bytes: usize::try_from(budget.max_input_bytes).unwrap_or(usize::MAX),
        }
    }
}

impl core::fmt::Debug for BlobSource {
    /// Hand-written because `dyn BlobStore` has none, and because a store's own `Debug` could carry
    /// an endpoint or a bucket name into a log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobSource").field("max_bytes", &self.max_bytes).finish_non_exhaustive()
    }
}

#[async_trait]
impl SourceReader for BlobSource {
    async fn read(&self, object_key: &str) -> Result<Vec<u8>> {
        // From byte zero to the end. A rendition of the first page still needs the container's
        // trailer in most formats, so there is no prefix a general source reader could take.
        let stream = self
            .store
            .read_range(object_key, ByteRange::from(0))
            .await
            .map_err(|error| PreviewError::Source(anyhow::Error::new(error)))?;

        stream.collect_bounded(self.max_bytes).await.map_err(|error| {
            if matches!(error, StorageError::TooLarge { .. }) {
                // Worth a line of its own: the object is bigger than the row said it was, which is
                // either a `size_bytes` written from a client's claim or an object replaced under
                // its version. Both are worth knowing about and neither is the caller's fault.
                tracing::warn!(
                    limit = self.max_bytes,
                    "a version's object exceeded the input budget after its row passed the check"
                );
            }
            PreviewError::Source(anyhow::Error::new(error))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::time::Duration;

    use enclave_storage::{
        ByteStream, ObjectMeta, PublicAccessCheck, PublicAccessError, PublicAccessReport,
        Result as StorageResult, StoreCapabilities, Support, UploadRequest, UploadSession,
    };
    use url::Url;

    use super::*;

    /// A store holding one object, which is all a source reader can ask for.
    ///
    /// The five methods that move original bytes or mint URLs **panic**. An error would be
    /// something the caller could plausibly handle and move past; the claim under test is that this
    /// type never asks, so asking has to end the test (`crates/uploads`'s 5 GB fixture makes the
    /// same choice for the same reason).
    struct OneObject(Vec<u8>);

    #[async_trait]
    impl BlobStore for OneObject {
        async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
            panic!("the source reader created an upload")
        }
        async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
            panic!("the source reader completed an upload")
        }
        async fn signed_download(&self, _key: &str, _ttl: Duration) -> StorageResult<Url> {
            panic!("the rendition path minted a URL to an original — CLAUDE.md rule 6")
        }
        async fn read_range(&self, _key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
            let body = self.0.clone();
            let len = body.len() as u64;
            Ok(ByteStream::new(
                futures::stream::once(async move { Ok(axum_core_bytes(body)) }),
                Some(len),
            ))
        }
        async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
            panic!("the source reader copied an object")
        }
        async fn delete(&self, _key: &str) -> StorageResult<()> {
            panic!("the source reader deleted an object")
        }
        fn capabilities(&self) -> StoreCapabilities {
            StoreCapabilities {
                backend: "test",
                multipart: None,
                signed_urls: false,
                single_use_signed_urls: false,
                max_signed_url_ttl: Duration::ZERO,
                versioning: Support::Unknown,
                object_lock: Support::Unknown,
                server_side_encryption: Support::Unknown,
                range_reads: true,
                server_side_copy: false,
            }
        }
    }

    #[async_trait]
    impl PublicAccessCheck for OneObject {
        async fn verify_not_public(
            &self,
        ) -> core::result::Result<PublicAccessReport, PublicAccessError> {
            panic!("the source reader ran the bucket self-check")
        }
    }

    fn axum_core_bytes(body: Vec<u8>) -> bytes::Bytes {
        bytes::Bytes::from(body)
    }

    fn source(body: Vec<u8>, max_input_bytes: u64) -> BlobSource {
        BlobSource::new(
            Arc::new(OneObject(body)),
            RenderBudget { max_input_bytes, ..RenderBudget::DEFAULT },
        )
    }

    /// The budget bounds what this process will hold, whatever the object turns out to be.
    ///
    /// The control is the second half: an object inside the bound is read whole, so the refusal
    /// above is not the refusal of a reader that reads nothing.
    #[tokio::test]
    async fn an_object_larger_than_the_input_budget_is_never_held_in_memory() {
        let body = vec![7_u8; 4_096];

        // Matched rather than `expect_err`, which would print four thousand decimal bytes above
        // the sentence that matters. Watched to fail with `max_bytes` set to `usize::MAX`.
        match source(body.clone(), 1_024).read("tenant/x/y").await {
            Err(PreviewError::Source(_)) => {}
            Err(other) => panic!(
                "an oversized object is an object-storage answer, not a verdict about the \
                 document: {other:?}"
            ),
            Ok(read) => panic!("{} bytes were read under a 1 KiB budget", read.len()),
        }

        let read = source(body.clone(), 4_096).read("tenant/x/y").await.expect("within the budget");
        assert_eq!(read, body, "the reader must return the object it was asked for, whole");
    }
}
