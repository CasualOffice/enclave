//! This crate's error type, and its one-way mapping into the canonical one.
//!
//! `thiserror` here and `anyhow` only at the boundary, per `CLAUDE.md`. The mapping into
//! [`enclave_core::Error`] lives beside the enum so the two are edited together: a variant added
//! here without a mapping is a compile error, which is the only reliable way to stop a new failure
//! mode from defaulting to `500`.

use core::time::Duration;

use crate::key::KeyError;
use crate::public_access::PublicAccessError;

/// This crate's result alias.
pub type Result<T> = core::result::Result<T, StorageError>;

/// Why an object-storage operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// No object storage is configured in this deployment.
    ///
    /// Not a failure of a configured store — the absence of one. It exists so that a binary started
    /// without storage **refuses** the paths that need it, loudly and with a reason, instead of
    /// registering routes whose dependency is missing and answering `500`. That is what
    /// `ENC-170` found: two routes did exactly that, and passed every integration test, because the
    /// tests build their own router with the dependency attached.
    ///
    /// Renders as a `503` naming object storage, because it is an operator's problem and a
    /// retryable one — once somebody configures a store.
    #[error(
        "no object storage is configured — set `storage` in enclave.yaml \
         (docs/08-BYO-INFRA.md §5)"
    )]
    NotConfigured,

    /// The object is not there.
    #[error("object `{key}` does not exist")]
    NotFound {
        /// The key that was requested. Safe to log — a key is UUIDs, and carries no file name.
        key: String,
    },

    /// The provider refused the operation.
    ///
    /// Distinct from [`StorageError::NotFound`] because the remediation is completely different:
    /// this one is an IAM policy that is missing an action, and it is never retryable.
    #[error(
        "object storage refused `{operation}` — the credential's policy is missing that action \
         (docs/08-BYO-INFRA.md §5)"
    )]
    AccessDenied {
        /// The provider API that was refused.
        operation: &'static str,
    },

    /// The bucket does not exist, or is not reachable at the configured endpoint.
    #[error(
        "bucket `{bucket}` was not found — check `bucket`, `endpoint` and `region`, and whether \
         path-style addressing is required"
    )]
    BucketNotFound {
        /// The configured bucket.
        bucket: String,
    },

    /// The startup self-check refused the bucket.
    #[error(transparent)]
    PublicBucket(#[from] PublicAccessError),

    /// A key did not conform to the canonical layout.
    #[error(transparent)]
    Key(#[from] KeyError),

    /// A signed URL was requested for longer than policy permits.
    #[error(
        "a signed URL was requested for {}s; the configured maximum is {}s \
         (plans/M1-CONTENT-CORE.md D14)",
        requested.as_secs(),
        maximum.as_secs()
    )]
    TtlTooLong {
        /// What the caller asked for.
        requested: Duration,
        /// The ceiling in force.
        maximum: Duration,
    },

    /// A signed URL was requested with a zero TTL.
    #[error("a signed URL was requested with a zero TTL")]
    TtlZero,

    /// The requested byte range is empty or inverted.
    #[error("byte range {start}-{end_inclusive:?} is empty or inverted")]
    InvalidRange {
        /// First byte requested.
        start: u64,
        /// Last byte requested.
        end_inclusive: Option<u64>,
    },

    /// A bounded read hit its limit.
    #[error("object exceeds the {limit} byte limit this read was given")]
    TooLarge {
        /// The limit the caller supplied.
        limit: usize,
    },

    /// The object is larger than the backend's multipart limits allow.
    #[error(
        "an upload of {content_length} bytes needs {needed} parts of {part_bytes} bytes; \
         the backend allows at most {max_parts}"
    )]
    TooManyParts {
        /// Declared object size.
        content_length: u64,
        /// Parts the configured part size would require.
        needed: u64,
        /// The configured part size.
        part_bytes: u64,
        /// The backend's ceiling.
        max_parts: u32,
    },

    /// Completion was attempted before every part had been reported.
    #[error("cannot complete the upload of `{key}`: {reported} of {expected} parts were reported")]
    IncompleteUpload {
        /// The key being written.
        key: String,
        /// How many parts the client reported.
        reported: usize,
        /// How many the session expects.
        expected: usize,
    },

    /// The backend does not support something the caller asked for.
    #[error("this store does not support {capability}")]
    Unsupported {
        /// What was asked for.
        capability: &'static str,
    },

    /// The caller asked for a provider-verified digest on an upload this backend cannot verify.
    ///
    /// Raised by [`BlobStore::create_upload`](crate::BlobStore::create_upload) *before* anything is
    /// signed, so the refusal costs no bandwidth — `docs/05-API.md §8`.
    ///
    /// The case that reaches it is multipart. A single `PUT` carrying `x-amz-checksum-sha256` is
    /// verified by S3 and by MinIO against the body they receive; a multipart upload is not, because
    /// what those backends compute for one is a *checksum of the part checksums* with a `-N` suffix,
    /// which is not the whole-object SHA-256 a version row records. AWS's `FULL_OBJECT` checksum
    /// type would close it and MinIO `RELEASE.2025-04-22` answers `InvalidArgument` to it, so on the
    /// backend this product ships with there is nothing to fall back to.
    ///
    /// Refusing here rather than accepting the upload and recording the client's unverified word is
    /// the whole of `ENC-820`: a stored digest nobody checked reads as evidence, and is worse than
    /// an absent one, which at least reads as unknown.
    #[error(
        "this store cannot have the provider verify a whole-object SHA-256 for an upload of \
         {content_length} bytes: above {threshold} bytes it is sent as a multipart upload, for \
         which this backend computes only a checksum of the part checksums"
    )]
    ChecksumUnverifiable {
        /// The declared size that pushed the upload past the threshold.
        content_length: u64,
        /// The largest upload this store can have the provider verify, in bytes.
        threshold: u64,
    },

    /// A digest handed to the store is not a lowercase hex SHA-256.
    ///
    /// A caller bug rather than client input — [`crate::UploadRequest::checksum_sha256`] documents
    /// the format, and every path into it validates first. Refused rather than passed through,
    /// because a value the provider cannot parse would be dropped by it and the upload would go
    /// back to being unverified without anybody being told.
    #[error("the declared checksum is not a lowercase hex SHA-256")]
    MalformedChecksum,

    /// The store's configuration is not usable.
    #[error("object storage configuration is invalid: {problem}")]
    Config {
        /// What is wrong, phrased for whoever wrote the configuration file.
        problem: String,
    },

    /// A credential reference could not be resolved.
    ///
    /// Carries the *reference* (`vault://workspace/s3#access_key_id`), never the value — the
    /// reference is already in the configuration file and is what makes the error actionable
    /// (`CLAUDE.md` rule 11).
    #[error("object storage credential `{reference}` could not be resolved")]
    Credential {
        /// The unresolvable reference.
        reference: String,
        /// The secret provider's own failure.
        #[source]
        source: enclave_config::SecretError,
    },

    /// The provider failed for a reason that is not one of the above.
    ///
    /// `detail` is the flattened SDK error chain. It is operator-facing and must never reach a
    /// client response body; the mapping to [`enclave_core::Error`] below is what guarantees that,
    /// because `Error::Upstream` renders as a bare "dependency unavailable".
    #[error("object storage `{operation}` failed: {detail}")]
    Upstream {
        /// The provider API that failed.
        operation: &'static str,
        /// The provider's error code, when it gave one.
        code: Option<String>,
        /// The flattened error chain, for logs.
        detail: String,
    },
}

impl StorageError {
    /// Whether an identical retry is likely to succeed.
    ///
    /// Deliberately conservative: only a genuine upstream failure is retryable. A permission error
    /// retried in a loop is how a deployment turns one misconfiguration into a rate-limit incident.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(self, Self::Upstream { .. })
    }
}

impl From<StorageError> for enclave_core::Error {
    /// Maps to the canonical error at the crate boundary (`docs/03-LLD.md §22`).
    ///
    /// Three groups, and the grouping is the security-relevant part:
    ///
    /// * `NotFound` becomes `Error::NotFound`, which is `404`.
    /// * Anything describing *our* configuration or credentials becomes a non-retryable
    ///   `Upstream`. It is `503` with no detail, so a client learns that storage is unavailable
    ///   and nothing about the bucket, the endpoint or the IAM policy.
    /// * Anything describing a caller mistake — a malformed key, an over-long TTL, an incomplete
    ///   upload — becomes `Internal`. These are bugs in a caller inside this process, not client
    ///   input, and `Error::Internal` keeps the detail in the log and out of the response.
    fn from(err: StorageError) -> Self {
        use enclave_core::Dependency;

        match err {
            StorageError::NotFound { .. } => Self::NotFound,

            StorageError::AccessDenied { .. }
            | StorageError::BucketNotFound { .. }
            | StorageError::PublicBucket(_)
            | StorageError::Config { .. }
            | StorageError::Credential { .. } => {
                Self::Upstream { dependency: Dependency::ObjectStorage, retryable: false }
            }

            StorageError::Upstream { .. } => {
                Self::Upstream { dependency: Dependency::ObjectStorage, retryable: true }
            }

            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::Error;

    use super::*;

    #[test]
    fn a_missing_object_is_a_404_and_not_a_dependency_failure() {
        let mapped: Error = StorageError::NotFound { key: "k".to_owned() }.into();
        assert_eq!(mapped.status_code(), 404);
    }

    /// A misconfigured bucket must not tell a client which bucket, which endpoint, or which IAM
    /// action is missing. `Error::Upstream` renders as a bare phrase; this test is what keeps it
    /// that way if a variant is ever re-grouped.
    #[test]
    fn configuration_failures_never_reach_the_client_as_detail() {
        let cases: Vec<StorageError> = vec![
            StorageError::AccessDenied { operation: "GetObject" },
            StorageError::BucketNotFound { bucket: "enclave-content".to_owned() },
            StorageError::Config { problem: "endpoint http://internal:9000".to_owned() },
        ];
        for case in cases {
            let rendered = case.to_string();
            let mapped: Error = case.into();
            assert_eq!(mapped.status_code(), 503);
            assert_eq!(mapped.to_string(), "dependency OBJECT_STORAGE unavailable");
            assert!(!mapped.to_string().contains(&rendered));
        }
    }

    #[test]
    fn only_upstream_failures_are_retryable() {
        assert!(StorageError::Upstream {
            operation: "PutObject",
            code: None,
            detail: "timeout".to_owned(),
        }
        .retryable());
        assert!(!StorageError::AccessDenied { operation: "PutObject" }.retryable());
        assert!(!StorageError::NotFound { key: "k".to_owned() }.retryable());
    }

    #[test]
    fn caller_mistakes_are_internal_rather_than_upstream() {
        let mapped: Error = StorageError::TtlTooLong {
            requested: Duration::from_secs(86_400),
            maximum: Duration::from_secs(300),
        }
        .into();
        assert_eq!(mapped.status_code(), 500);
        assert_eq!(mapped.to_string(), "internal error");
    }
}
