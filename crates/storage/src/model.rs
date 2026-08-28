//! The vocabulary the [`BlobStore`](crate::BlobStore) trait speaks.
//!
//! Nothing here mentions a cloud SDK. That is the point of `docs/08-BYO-INFRA.md §1`: domain
//! crates depend on these types, so a second provider is a new module in this crate rather than a
//! change to every caller.

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::Stream;
use url::Url;

use crate::error::StorageError;
use crate::key::ObjectKey;

/// A half-open request for part of an object, expressed the way HTTP expresses it.
///
/// Inclusive end, because `Range: bytes=0-1023` is inclusive and translating between conventions
/// at the boundary is how off-by-one bugs get into a byte-range download that nobody notices until
/// a PDF viewer fails on the last page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    start: u64,
    end_inclusive: Option<u64>,
}

impl ByteRange {
    /// Everything from `start` to the end of the object.
    #[must_use]
    pub const fn from(start: u64) -> Self {
        Self { start, end_inclusive: None }
    }

    /// `len` bytes beginning at `start`.
    ///
    /// # Errors
    ///
    /// [`StorageError::InvalidRange`] if `len` is zero. A zero-length range is never what the
    /// caller meant, and S3 answers it with the whole object, which is precisely the failure mode
    /// a preview path must not have.
    pub const fn sized(start: u64, len: u64) -> Result<Self, StorageError> {
        if len == 0 {
            return Err(StorageError::InvalidRange { start, end_inclusive: Some(start) });
        }
        Ok(Self { start, end_inclusive: Some(start + len - 1) })
    }

    /// An explicit inclusive range.
    ///
    /// # Errors
    ///
    /// [`StorageError::InvalidRange`] if `end_inclusive < start`.
    pub const fn inclusive(start: u64, end_inclusive: u64) -> Result<Self, StorageError> {
        if end_inclusive < start {
            return Err(StorageError::InvalidRange { start, end_inclusive: Some(end_inclusive) });
        }
        Ok(Self { start, end_inclusive: Some(end_inclusive) })
    }

    /// First byte requested.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Last byte requested, or `None` for "to the end".
    #[must_use]
    pub const fn end_inclusive(&self) -> Option<u64> {
        self.end_inclusive
    }

    /// The value of the HTTP `Range` header this describes.
    #[must_use]
    pub fn header_value(&self) -> String {
        match self.end_inclusive {
            Some(end) => format!("bytes={}-{end}", self.start),
            None => format!("bytes={}-", self.start),
        }
    }
}

/// A stream of object bytes.
///
/// A stream and not a `Vec<u8>`, throughout, because the exit criterion in
/// `plans/M1-CONTENT-CORE.md §1` is a 5 GB transfer with flat API memory. A convenience method
/// that collected the whole object would be used, and the memory profile would regress in a code
/// path nobody thought of as a download — so [`ByteStream::collect_bounded`] takes a limit and
/// refuses to exceed it rather than offering an unbounded `collect`.
pub struct ByteStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send>>,
    content_length: Option<u64>,
}

impl ByteStream {
    /// Wraps any stream of chunks.
    #[must_use]
    pub fn new(
        stream: impl Stream<Item = Result<Bytes, StorageError>> + Send + 'static,
        content_length: Option<u64>,
    ) -> Self {
        Self { inner: Box::pin(stream), content_length }
    }

    /// The number of bytes the provider said it would send, when it said.
    #[must_use]
    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// Reads the whole stream into memory, refusing to exceed `limit` bytes.
    ///
    /// For the genuinely small reads — a policy document, a checksum sidecar, an antivirus probe of
    /// a header. `limit` is mandatory so that "small" is a decision made at the call site rather
    /// than an assumption about the object.
    ///
    /// # Errors
    ///
    /// [`StorageError::TooLarge`] as soon as the accumulated length would exceed `limit`; the
    /// remaining bytes are never fetched.
    pub async fn collect_bounded(mut self, limit: usize) -> Result<Vec<u8>, StorageError> {
        use futures::StreamExt as _;

        let mut out = Vec::new();
        while let Some(chunk) = self.inner.next().await {
            let chunk = chunk?;
            if out.len() + chunk.len() > limit {
                return Err(StorageError::TooLarge { limit });
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

impl fmt::Debug for ByteStream {
    /// Hand-written because a boxed stream has no `Debug`. Prints the length only — a `Debug` that
    /// buffered the body to show it would turn a log line into a copy of the file.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteStream").field("content_length", &self.content_length).finish()
    }
}

impl Stream for ByteStream {
    type Item = Result<Bytes, StorageError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Whether the backend was observed to support something, or could not be asked.
///
/// Three states rather than `bool`, because the honest answer to "does this bucket have object
/// lock?" on a least-privileged credential is "I am not allowed to find out". Reporting that as
/// `false` would let a records-management feature conclude the backend is unsuitable when it is
/// merely unreadable, and reporting it as `true` would be a fabrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Support {
    /// Observed to be present.
    Yes,
    /// Observed to be absent.
    No,
    /// Could not be determined — the probe was denied, or the backend does not implement the API.
    Unknown,
}

impl Support {
    /// True only for [`Support::Yes`].
    ///
    /// Named so that a caller reads as "require it", and so that `Unknown` can never be mistaken
    /// for a permissive default at a call site that only wanted a `bool`.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// What a backend's multipart upload allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartLimits {
    /// Smallest permitted part, except for the final one. 5 MiB on S3 and MinIO.
    pub min_part_bytes: u64,
    /// Largest permitted part. 5 GiB on S3.
    pub max_part_bytes: u64,
    /// Largest number of parts in one upload. 10 000 on S3.
    pub max_parts: u32,
}

/// What a store actually supports, as reported by the store rather than assumed by the caller.
///
/// `docs/08-BYO-INFRA.md §2` annotates `capabilities()` with "multipart, single-use URLs, object
/// lock". The fields that can be probed are probed once at connect time and cached; the fields
/// that are properties of the protocol are constants with a comment saying why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreCapabilities {
    /// Provider family, for logs and the admin "test connection" surface.
    pub backend: &'static str,
    /// Multipart limits, or `None` if the backend cannot do multipart at all.
    pub multipart: Option<MultipartLimits>,
    /// Whether the backend can mint pre-signed URLs.
    pub signed_urls: bool,
    /// Whether a signed URL can be invalidated after its first use.
    ///
    /// **False on every S3-compatible backend**, and that is not a gap in this implementation: the
    /// SigV4 pre-signed URL scheme has no server-side use counter, so a URL is replayable until it
    /// expires. `plans/M1-CONTENT-CORE.md` D14 is the compensating control — one URL per
    /// authorized request, minted at the last moment, never cached, short TTL — and reporting
    /// `false` here is what stops a caller from relying on a property the backend does not have.
    pub single_use_signed_urls: bool,
    /// The longest TTL this store will sign for, after the configured ceiling and the provider's
    /// own limit are both applied.
    pub max_signed_url_ttl: Duration,
    /// Whether bucket versioning is on. Relevant to records and legal hold
    /// (`docs/08-BYO-INFRA.md §3`).
    pub versioning: Support,
    /// Whether object lock is configured. Also a records/legal-hold input.
    pub object_lock: Support,
    /// Whether default server-side encryption is configured.
    pub server_side_encryption: Support,
    /// Whether byte-range reads are supported. Required by preview and by resumable download.
    pub range_reads: bool,
    /// Whether the backend can copy server-side, without the bytes passing through this process.
    pub server_side_copy: bool,
}

/// A request to store one object's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRequest {
    /// Where the bytes will live. An [`ObjectKey`], not a `String`, so the canonical layout cannot
    /// be bypassed by the one caller that builds its key by hand.
    pub key: ObjectKey,
    /// Total size in bytes. Known in advance because `docs/05-API.md` has the client declare it,
    /// and because it is what decides single-shot versus multipart.
    pub content_length: u64,
    /// MIME type to store alongside the object. Advisory: the platform's own type detection is
    /// authoritative, and this value is never used to decide how to render anything.
    pub content_type: Option<String>,
    /// Lowercase hex SHA-256 of the whole object, when the caller declared one.
    ///
    /// Not advisory, and not a hint. Setting this obliges the implementation to make the provider
    /// **compute the digest of the bytes it receives and refuse them if they disagree** — see
    /// [`BlobStore::create_upload`](crate::BlobStore::create_upload). An implementation that cannot
    /// arrange that for this request must return
    /// [`StorageError::ChecksumUnverifiable`](crate::StorageError::ChecksumUnverifiable) rather
    /// than issue a session whose digest nothing will check. `ENC-820` is what the permissive
    /// reading cost: the field was already here, already populated, and quietly dropped on the
    /// floor by the S3 implementation.
    pub checksum_sha256: Option<String>,
}

impl UploadRequest {
    /// A request with no optional fields set.
    #[must_use]
    pub const fn new(key: ObjectKey, content_length: u64) -> Self {
        Self { key, content_length, content_type: None, checksum_sha256: None }
    }

    /// Sets the advisory content type.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Sets the expected whole-object SHA-256, lowercase hex.
    #[must_use]
    pub fn with_checksum_sha256(mut self, checksum: impl Into<String>) -> Self {
        self.checksum_sha256 = Some(checksum.into());
        self
    }
}

/// One part of a multipart upload, and the URL the client sends it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartTarget {
    /// 1-based part number, as S3 numbers them.
    pub part_number: u32,
    /// Offset of this part within the object.
    pub offset: u64,
    /// Size of this part.
    pub length: u64,
    /// Where to `PUT` it.
    pub url: Url,
}

/// A part the client has finished uploading.
///
/// Filled in by the upload service (`ENC-129`) from what the client reported, and read by
/// [`BlobStore::complete_upload`](crate::BlobStore::complete_upload). It lives on the session
/// because the trait signature in `docs/08-BYO-INFRA.md §2` takes only `&UploadSession`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedPart {
    /// Which part.
    pub part_number: u32,
    /// The entity tag the provider returned for it.
    pub etag: String,
}

/// A header the client **must** send with a pre-signed request, or the provider will refuse it.
///
/// Not a suggestion the client may drop. A pre-signed SigV4 URL commits to the exact set of headers
/// that were present when it was signed — they appear in `X-Amz-SignedHeaders` — so a request
/// missing one, or carrying a different value for one, fails the signature check. That property is
/// what makes `x-amz-checksum-sha256` an *integrity control* rather than a courtesy: the client
/// cannot decline to be checked without also failing to upload.
///
/// It has to travel to the API's caller, because the process that signs the URL is not the process
/// that sends the bytes (`docs/05-API.md §8`: the API never proxies them). `ENC-821` is the same
/// lesson learned the hard way with `content-type`, which was signed and documented nowhere, and
/// cost the first client two attempts to diagnose as a `403`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredHeader {
    /// The header name, lowercase.
    pub name: String,
    /// The exact value that was signed.
    pub value: String,
}

/// How the client should send the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadTarget {
    /// Small enough for one `PUT`.
    Single {
        /// Where to `PUT` the whole object.
        url: Url,
        /// Headers the `PUT` must carry. See [`RequiredHeader`].
        required_headers: Vec<RequiredHeader>,
    },
    /// Large enough to need multipart.
    Multipart {
        /// The provider's upload id, required to complete or abort.
        upload_id: String,
        /// Every part, in order.
        parts: Vec<PartTarget>,
    },
}

/// An upload in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadSession {
    /// The key being written.
    pub key: ObjectKey,
    /// Total size declared at creation.
    pub content_length: u64,
    /// How to send the bytes.
    pub target: UploadTarget,
    /// When every URL in this session stops working.
    ///
    /// Short by construction (`plans/M1-CONTENT-CORE.md` D14). An upload that outlives it is
    /// restarted, not extended: extending would mean a URL surviving the authorization decision
    /// that produced it.
    pub expires_at: DateTime<Utc>,
    /// Parts the client has reported as uploaded. Empty for a single-shot upload.
    pub completed_parts: Vec<CompletedPart>,
}

impl UploadSession {
    /// Records a part the client finished, keeping the list ordered and free of duplicates.
    ///
    /// Re-reporting a part replaces the earlier entry rather than appending: a client retrying one
    /// part is normal, and S3 rejects a completion list containing the same part twice.
    pub fn record_part(&mut self, part: CompletedPart) {
        match self.completed_parts.binary_search_by_key(&part.part_number, |p| p.part_number) {
            Ok(existing) => self.completed_parts[existing] = part,
            Err(insert_at) => self.completed_parts.insert(insert_at, part),
        }
    }

    /// How many parts this session expects.
    #[must_use]
    pub fn expected_parts(&self) -> usize {
        match &self.target {
            UploadTarget::Single { .. } => 1,
            UploadTarget::Multipart { parts, .. } => parts.len(),
        }
    }
}

/// What the store knows about a stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// The key it is stored under.
    pub key: ObjectKey,
    /// Size in bytes as the provider reports it — the value a version row records, rather than the
    /// value the client claimed.
    pub size_bytes: u64,
    /// The provider's entity tag, with quotes stripped.
    pub etag: Option<String>,
    /// Base64 SHA-256 as the provider computed it, when the provider computes one.
    pub checksum_sha256: Option<String>,
    /// Stored content type.
    pub content_type: Option<String>,
    /// Provider's last-modified timestamp.
    pub last_modified: Option<DateTime<Utc>>,
    /// The provider's own object version id, when bucket versioning is on. Distinct from Enclave's
    /// `VersionId`: this one identifies a generation of bytes at the provider, not a version row.
    pub provider_version_id: Option<String>,
    /// The server-side encryption algorithm the provider reports for this object.
    pub server_side_encryption: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileId, TenantId, VersionId};

    use super::*;

    fn key() -> ObjectKey {
        ObjectKey::version(TenantId::new_v7(), FileId::new_v7(), VersionId::new_v7())
    }

    #[test]
    fn range_headers_match_the_http_form() {
        assert_eq!(ByteRange::from(0).header_value(), "bytes=0-");
        assert_eq!(ByteRange::sized(0, 1024).unwrap().header_value(), "bytes=0-1023");
        assert_eq!(ByteRange::inclusive(10, 19).unwrap().header_value(), "bytes=10-19");
    }

    #[test]
    fn a_zero_length_or_inverted_range_is_refused() {
        assert!(ByteRange::sized(5, 0).is_err());
        assert!(ByteRange::inclusive(10, 9).is_err());
        assert!(ByteRange::inclusive(10, 10).is_ok());
    }

    #[test]
    fn parts_are_recorded_in_order_and_retries_replace_rather_than_duplicate() {
        let mut session = UploadSession {
            key: key(),
            content_length: 3,
            target: UploadTarget::Multipart { upload_id: "u".to_owned(), parts: Vec::new() },
            expires_at: Utc::now(),
            completed_parts: Vec::new(),
        };

        session.record_part(CompletedPart { part_number: 3, etag: "c".to_owned() });
        session.record_part(CompletedPart { part_number: 1, etag: "a".to_owned() });
        session.record_part(CompletedPart { part_number: 2, etag: "b".to_owned() });
        session.record_part(CompletedPart { part_number: 2, etag: "b-retry".to_owned() });

        let seen: Vec<_> =
            session.completed_parts.iter().map(|p| (p.part_number, p.etag.as_str())).collect();
        assert_eq!(seen, vec![(1, "a"), (2, "b-retry"), (3, "c")]);
    }

    #[test]
    fn unknown_support_is_not_confirmed() {
        assert!(Support::Yes.is_confirmed());
        assert!(!Support::No.is_confirmed());
        assert!(!Support::Unknown.is_confirmed());
    }

    #[tokio::test]
    async fn collect_bounded_refuses_to_exceed_its_limit() {
        let chunks = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"0123456789")),
            Ok(Bytes::from_static(b"0123456789")),
        ]);
        let err = ByteStream::new(chunks, Some(20)).collect_bounded(15).await.unwrap_err();
        assert!(matches!(err, StorageError::TooLarge { limit: 15 }), "got: {err:?}");
    }

    #[tokio::test]
    async fn collect_bounded_returns_the_bytes_when_they_fit() {
        let chunks = futures::stream::iter(vec![Ok(Bytes::from_static(b"hello"))]);
        let out = ByteStream::new(chunks, Some(5)).collect_bounded(16).await.unwrap();
        assert_eq!(out, b"hello");
    }
}
