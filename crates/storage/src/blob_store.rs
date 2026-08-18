//! The `BlobStore` trait.
//!
//! Seven members, exactly as `docs/08-BYO-INFRA.md §2` states them. The only departure from the
//! listing there is the supertrait bound: `PublicAccessCheck` instead of nothing, so that the
//! startup self-check `§3` requires cannot be omitted by a provider and stays reachable through
//! `&dyn BlobStore`. See [`crate::public_access`] for the argument.

use core::time::Duration;

use async_trait::async_trait;
use url::Url;

use crate::error::Result;
use crate::model::{
    ByteRange, ByteStream, ObjectMeta, StoreCapabilities, UploadRequest, UploadSession,
};
use crate::public_access::PublicAccessCheck;

/// Object storage for versions and renditions.
///
/// Implementations are held behind `Arc` and shared across the whole process; they must be cheap
/// to clone internally and safe to call concurrently.
///
/// # What this trait deliberately does not have
///
/// There is no `list`, no `exists` and no `read` returning `Vec<u8>`. PostgreSQL is authoritative
/// for what exists (`docs/04-DATA-MODEL.md`); a listing API on the store would be a second,
/// unpoliced answer to "what files are there", and the first caller that used it would be
/// enumerating objects without a tenant predicate. Byte access is a stream for the reason in
/// [`ByteStream`]'s documentation.
#[async_trait]
pub trait BlobStore: PublicAccessCheck + Send + Sync {
    /// Begins an upload, returning the URL or URLs the client sends bytes to.
    ///
    /// Whether the session is single-shot or multipart is the store's decision, from
    /// [`UploadRequest::content_length`] and the backend's limits — not the caller's. A caller
    /// choosing would have to know each backend's minimum part size, and would get it wrong for
    /// the one backend nobody tested against.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError`] — most usefully `TooManyParts` when the object is larger than the
    /// configured part size can address, and `AccessDenied` when the credential cannot create a
    /// multipart upload.
    async fn create_upload(&self, request: UploadRequest) -> Result<UploadSession>;

    /// Finalizes an upload and returns what the provider says it stored.
    ///
    /// The returned [`ObjectMeta`] is the authority for the size and checksum recorded on a version
    /// row — never the values the client declared. `plans/M1-CONTENT-CORE.md` D12 makes those
    /// columns immutable once written, so writing a client-supplied number there would make a
    /// client's claim permanent.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::IncompleteUpload`] if parts are missing, and any provider failure.
    async fn complete_upload(&self, session: &UploadSession) -> Result<ObjectMeta>;

    /// Mints a pre-signed download URL, valid for `ttl`.
    ///
    /// Called at the last moment, once per authorized request, and never cached
    /// (`plans/M1-CONTENT-CORE.md` D14) — a URL that outlives the decision that produced it is a
    /// standing grant. Implementations must refuse a `ttl` above their configured ceiling rather
    /// than silently clamping, so a caller asking for a day cannot believe it received one.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::TtlTooLong`], [`crate::StorageError::TtlZero`], or a provider
    /// failure.
    async fn signed_download(&self, key: &str, ttl: Duration) -> Result<Url>;

    /// Streams part of an object through this process.
    ///
    /// The path preview and antivirus use, where bytes must not become reachable to the client
    /// directly. `CLAUDE.md` rule 6: never issue an original object-storage URL on a preview path.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::NotFound`], [`crate::StorageError::InvalidRange`], or a provider
    /// failure.
    async fn read_range(&self, key: &str, range: ByteRange) -> Result<ByteStream>;

    /// Copies an object server-side.
    ///
    /// Both keys are validated against the canonical layout, so a copy cannot be used to write
    /// outside it — including into another tenant's prefix, which this makes visible in the
    /// arguments rather than implicit.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Key`] if either key is not canonical, or a provider failure.
    async fn copy(&self, from: &str, to: &str) -> Result<()>;

    /// Deletes an object.
    ///
    /// Deleting an object that is not there succeeds, because S3 makes deletion idempotent and a
    /// retry after a network failure must not fail the second time.
    ///
    /// # Errors
    ///
    /// [`crate::StorageError::Key`] if the key is not canonical, or a provider failure.
    async fn delete(&self, key: &str) -> Result<()>;

    /// What this store supports — multipart, single-use URLs, object lock.
    ///
    /// Reports what was *observed* at connect time, not what the provider family is assumed to
    /// do. See [`StoreCapabilities`] and [`crate::Support`].
    fn capabilities(&self) -> StoreCapabilities;
}
