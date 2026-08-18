//! Configuration for the S3-compatible store.
//!
//! Mirrors the `storage_profiles` shape in `docs/08-BYO-INFRA.md §4`, minus the columns that
//! belong to the database row rather than to the client (`id`, `tenant_id`, `name`, `enabled`,
//! `residency_region`). Credentials are [`SecretRef`]s and nothing else: there is no field on this
//! struct that can hold a key, so `CLAUDE.md` rule 11 is enforced by the type rather than by
//! review.

use core::time::Duration;

use enclave_config::{HumanDuration, SecretRef};
use serde::Deserialize;
use url::Url;

use crate::error::StorageError;

/// AWS's ceiling on a SigV4 pre-signed URL. Requesting more is an error at the provider, so it is
/// an error here first, with a message that says why.
pub(crate) const PROVIDER_MAX_PRESIGN_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// S3's minimum size for any part but the last.
pub(crate) const S3_MIN_PART_BYTES: u64 = 5 * 1024 * 1024;
/// S3's maximum part size.
pub(crate) const S3_MAX_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// S3's maximum number of parts in one multipart upload.
pub(crate) const S3_MAX_PARTS: u32 = 10_000;

/// Which S3-compatible backend this is.
///
/// Not cosmetic: it selects which self-check probes are even attempted. MinIO does not implement
/// `GetPublicAccessBlock` or `GetBucketPolicyStatus`, and running them there produces a page of
/// "not implemented" noise in the startup log that trains an operator to ignore the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum S3Flavor {
    /// Amazon S3 itself. Every probe is available.
    #[default]
    Aws,
    /// MinIO. Bucket policy and ACL probes work; the AWS-only ones do not.
    Minio,
    /// Anything else speaking the S3 API — Ceph, R2, Wasabi, B2. Only the probes that are part of
    /// the core API are attempted.
    Generic,
}

impl S3Flavor {
    /// Whether `GetPublicAccessBlock` and `GetBucketPolicyStatus` exist on this backend.
    pub(crate) const fn has_aws_public_access_apis(self) -> bool {
        matches!(self, Self::Aws)
    }
}

/// Everything needed to talk to one bucket.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    /// The bucket holding versions and renditions.
    pub bucket: String,

    /// The region to sign for. Required even against MinIO, which ignores it but still expects the
    /// signature to be computed over one.
    pub region: String,

    /// Endpoint override. `None` uses the provider's AWS endpoint; set for MinIO, Ceph, R2 and
    /// anything else self-hosted.
    #[serde(default)]
    pub endpoint: Option<Url>,

    /// Path-style addressing (`{endpoint}/{bucket}/{key}`) rather than virtual-host
    /// (`{bucket}.{endpoint}/{key}`).
    ///
    /// Defaults to `true` and does so deliberately. Virtual-host addressing needs per-bucket DNS,
    /// which a self-hosted MinIO or Ceph does not have, so the default that works everywhere is
    /// path style; AWS deployments turn it off. Getting this wrong produces a DNS failure that
    /// looks like a network problem, which is why `docs/08-BYO-INFRA.md §4` gives it its own
    /// column.
    #[serde(default = "default_true")]
    pub path_style: bool,

    /// Reference to the access key id — `vault://…`, `env://…`. Never a literal.
    pub access_key_id: SecretRef,

    /// Reference to the secret access key. Never a literal.
    pub secret_access_key: SecretRef,

    /// Reference to a session token, for deployments using temporary credentials.
    #[serde(default)]
    pub session_token: Option<SecretRef>,

    /// Default life of a signed URL, used when a caller does not specify one.
    #[serde(default = "default_signed_url_ttl")]
    pub signed_url_ttl: HumanDuration,

    /// Ceiling on any signed URL, whatever a caller asks for.
    ///
    /// Separate from the default so that a caller with a legitimate reason for longer (a large
    /// multipart upload) has somewhere to go, and so that the ceiling is a single reviewable number
    /// rather than whatever the longest call site happens to pass.
    #[serde(default = "default_max_signed_url_ttl")]
    pub max_signed_url_ttl: HumanDuration,

    /// Objects at or below this size are uploaded in one `PUT`.
    #[serde(default = "default_multipart_threshold")]
    pub multipart_threshold_bytes: u64,

    /// Part size for multipart uploads.
    ///
    /// 16 MiB by default: large enough that a 5 GB object fits in 320 parts (well under the 10 000
    /// ceiling) and small enough that a failed part is a cheap retry.
    #[serde(default = "default_part_size")]
    pub part_size_bytes: u64,

    /// Which backend this is; selects the self-check probes.
    #[serde(default)]
    pub flavor: S3Flavor,
}

const fn default_true() -> bool {
    true
}

/// Five minutes. Long enough for a browser to start a download on a slow connection, short enough
/// that a URL captured from a log or a referrer header is worthless by the time it is read.
fn default_signed_url_ttl() -> HumanDuration {
    HumanDuration::from_secs(5 * 60)
}

/// One hour. The ceiling exists for multipart uploads, whose parts are signed once and used over
/// the life of the transfer.
fn default_max_signed_url_ttl() -> HumanDuration {
    HumanDuration::from_secs(60 * 60)
}

const fn default_multipart_threshold() -> u64 {
    16 * 1024 * 1024
}

const fn default_part_size() -> u64 {
    16 * 1024 * 1024
}

impl S3Config {
    /// A configuration with the documented defaults, for construction in code.
    #[must_use]
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        access_key_id: SecretRef,
        secret_access_key: SecretRef,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            path_style: true,
            access_key_id,
            secret_access_key,
            session_token: None,
            signed_url_ttl: default_signed_url_ttl(),
            max_signed_url_ttl: default_max_signed_url_ttl(),
            multipart_threshold_bytes: default_multipart_threshold(),
            part_size_bytes: default_part_size(),
            flavor: S3Flavor::Aws,
        }
    }

    /// Points the store at a self-hosted endpoint, in MinIO's usual shape.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: Url, flavor: S3Flavor) -> Self {
        self.endpoint = Some(endpoint);
        self.flavor = flavor;
        self
    }

    /// Rejects a configuration that cannot work, before anything tries to use it.
    ///
    /// Called by [`S3BlobStore::connect`](super::S3BlobStore::connect). Every check here is one
    /// that would otherwise surface as a confusing provider error at the first upload, hours after
    /// the deployment was declared healthy.
    ///
    /// # Errors
    ///
    /// [`StorageError::Config`] naming the field and the constraint it violates.
    pub fn validate(&self) -> Result<(), StorageError> {
        let problem = |problem: String| Err(StorageError::Config { problem });

        if self.bucket.trim().is_empty() {
            return problem("`bucket` is empty".to_owned());
        }
        if self.region.trim().is_empty() {
            return problem(
                "`region` is empty; SigV4 signs over a region even when the backend ignores it \
                 (use `us-east-1` for MinIO)"
                    .to_owned(),
            );
        }
        if self.signed_url_ttl.is_zero() {
            return problem(
                "`signed_url_ttl` is zero, so every URL would expire on issue".to_owned(),
            );
        }
        if self.signed_url_ttl.as_duration() > self.max_signed_url_ttl.as_duration() {
            return problem(format!(
                "`signed_url_ttl` ({}s) is above `max_signed_url_ttl` ({}s)",
                self.signed_url_ttl.as_secs(),
                self.max_signed_url_ttl.as_secs()
            ));
        }
        if self.max_signed_url_ttl.as_duration() > PROVIDER_MAX_PRESIGN_TTL {
            return problem(format!(
                "`max_signed_url_ttl` ({}s) is above the SigV4 pre-signing limit of {}s",
                self.max_signed_url_ttl.as_secs(),
                PROVIDER_MAX_PRESIGN_TTL.as_secs()
            ));
        }
        if self.part_size_bytes < S3_MIN_PART_BYTES {
            return problem(format!(
                "`part_size_bytes` ({}) is below the {S3_MIN_PART_BYTES} byte minimum for any \
                 part but the last",
                self.part_size_bytes
            ));
        }
        if self.part_size_bytes > S3_MAX_PART_BYTES {
            return problem(format!(
                "`part_size_bytes` ({}) is above the {S3_MAX_PART_BYTES} byte maximum",
                self.part_size_bytes
            ));
        }
        if self.multipart_threshold_bytes == 0 {
            return problem("`multipart_threshold_bytes` is zero".to_owned());
        }
        if let Some(endpoint) = &self.endpoint {
            if !matches!(endpoint.scheme(), "http" | "https") {
                return problem(format!(
                    "`endpoint` scheme `{}` is not http or https",
                    endpoint.scheme()
                ));
            }
            if endpoint.host_str().is_none() {
                return problem(format!("`endpoint` {endpoint} has no host"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn config() -> S3Config {
        S3Config::new(
            "enclave-content",
            "us-east-1",
            "env://S3_ACCESS_KEY_ID".parse().unwrap(),
            "env://S3_SECRET_ACCESS_KEY".parse().unwrap(),
        )
    }

    #[test]
    fn the_documented_defaults_validate() {
        config().validate().unwrap();
    }

    #[test]
    fn path_style_defaults_on_so_a_self_hosted_endpoint_works_without_dns() {
        assert!(config().path_style);
    }

    #[test]
    fn a_ttl_above_the_ceiling_is_refused() {
        let mut cfg = config();
        cfg.signed_url_ttl = HumanDuration::from_secs(7200);
        cfg.max_signed_url_ttl = HumanDuration::from_secs(3600);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_ceiling_above_the_sigv4_limit_is_refused() {
        let mut cfg = config();
        cfg.max_signed_url_ttl = HumanDuration::from_secs(8 * 24 * 60 * 60);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_part_size_below_the_s3_minimum_is_refused() {
        let mut cfg = config();
        cfg.part_size_bytes = 1024;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("part_size_bytes"), "{err}");
    }

    #[test]
    fn an_endpoint_that_is_not_http_is_refused() {
        let mut cfg = config();
        cfg.endpoint = Some("s3://enclave".parse().unwrap());
        assert!(cfg.validate().is_err());
    }

    /// The credential fields are `SecretRef`, so a YAML file holding a literal key cannot even
    /// deserialize. This is the type-level half of `CLAUDE.md` rule 11.
    #[test]
    fn a_literal_credential_does_not_deserialize() {
        let with_literal = r#"{
            "bucket": "enclave-content",
            "region": "us-east-1",
            "access_key_id": "a-literal-key-not-a-reference",
            "secret_access_key": "env://S3_SECRET_ACCESS_KEY"
        }"#;
        assert!(serde_json::from_str::<S3Config>(with_literal).is_err());

        let with_refs = r#"{
            "bucket": "enclave-content",
            "region": "us-east-1",
            "endpoint": "http://localhost:9000",
            "flavor": "minio",
            "access_key_id": "env://S3_ACCESS_KEY_ID",
            "secret_access_key": "vault://workspace/s3#secret_access_key",
            "signed_url_ttl": "5m"
        }"#;
        let parsed: S3Config = serde_json::from_str(with_refs).unwrap();
        assert_eq!(parsed.flavor, S3Flavor::Minio);
        assert_eq!(parsed.signed_url_ttl.as_secs(), 300);
        assert!(parsed.path_style, "path style should default on");
        parsed.validate().unwrap();
    }
}
