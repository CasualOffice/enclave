//! Configuration for the S3-compatible store.
//!
//! Mirrors the `storage_profiles` shape in `docs/08-BYO-INFRA.md §4`, minus the columns that
//! belong to the database row rather than to the client (`id`, `tenant_id`, `name`, `enabled`,
//! `residency_region`). Credentials are [`SecretRef`]s and nothing else: there is no field on this
//! struct that can hold a key, so `CLAUDE.md` rule 11 is enforced by the type rather than by
//! review.

use core::time::Duration;

use enclave_config::{HumanDuration, S3StorageConfig, SecretRef};
use serde::Deserialize;
use url::Url;

use crate::error::StorageError;

/// Re-exported from `enclave-config`, where it is defined.
///
/// It is a word an operator types (`flavor: minio`), so it belongs in the crate that models what an
/// operator writes; a vocabulary spelled in two crates is two spellings waiting to disagree. This
/// name stays because every caller already imports `enclave_storage::S3Flavor`.
pub use enclave_config::S3Flavor;

/// AWS's ceiling on a SigV4 pre-signed URL. Requesting more is an error at the provider, so it is
/// an error here first, with a message that says why.
pub(crate) const PROVIDER_MAX_PRESIGN_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// S3's minimum size for any part but the last.
pub(crate) const S3_MIN_PART_BYTES: u64 = 5 * 1024 * 1024;
/// S3's maximum part size.
pub(crate) const S3_MAX_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// S3's maximum number of parts in one multipart upload.
pub(crate) const S3_MAX_PARTS: u32 = 10_000;

/// Whether `GetPublicAccessBlock` and `GetBucketPolicyStatus` exist on this backend.
///
/// A free function rather than an inherent method because [`S3Flavor`] is defined in
/// `enclave-config`. That is the right place for the *word*; which administrative APIs a backend
/// implements is knowledge this crate owns, and it stays here.
pub(crate) const fn has_aws_public_access_apis(flavor: S3Flavor) -> bool {
    matches!(flavor, S3Flavor::Aws)
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

    /// Builds a client configuration from the `storage.s3` section an operator wrote.
    ///
    /// **This is the one place the two shapes meet**, and it is here rather than in each binary's
    /// `main` because both `enclave-api` and `enclave-worker` need it and a conversion written
    /// twice is a conversion that drifts once.
    ///
    /// [`enclave_config::S3StorageConfig`] is deliberately smaller than this struct — its doc
    /// comment argues why, and why the alternative of modelling `S3Config` itself in
    /// `enclave-config` would drag `aws-sdk-s3` into every crate in the workspace. What it does not
    /// carry is [`multipart_threshold_bytes`](Self::multipart_threshold_bytes) and
    /// [`part_size_bytes`](Self::part_size_bytes): S3 protocol pacing with no correctness content,
    /// which take the documented defaults here.
    ///
    /// Nothing is resolved by this call. The credential fields stay [`SecretRef`]s and are
    /// dereferenced inside [`S3BlobStore::connect`](super::S3BlobStore::connect), at the last
    /// moment (`docs/08-BYO-INFRA.md §6`).
    #[must_use]
    pub fn from_operator_config(section: &S3StorageConfig) -> Self {
        Self {
            bucket: section.bucket.clone(),
            region: section.region.clone(),
            endpoint: section.endpoint.clone(),
            path_style: section.path_style,
            access_key_id: section.access_key_id.clone(),
            secret_access_key: section.secret_access_key.clone(),
            session_token: section.session_token.clone(),
            signed_url_ttl: section.signed_url_ttl,
            max_signed_url_ttl: section.max_signed_url_ttl,
            multipart_threshold_bytes: default_multipart_threshold(),
            part_size_bytes: default_part_size(),
            flavor: section.flavor,
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

    /// The `storage.s3` section an operator writes becomes a client configuration that validates.
    ///
    /// The whole of `ENC-562` in one assertion: `deploy/config/enclave.example.yaml` used to carry
    /// a `storage:` block that nothing parsed, so the indexing pass could not be scheduled and
    /// `chunk_text` stayed empty in every real deployment. This runs the documented text through
    /// `enclave-config`'s loader — the same three layers a binary uses — and converts it here.
    ///
    /// Deliberate violation: changing any of the four transcribed fields in
    /// [`S3Config::from_operator_config`] to a default fails this by name. Dropping the
    /// `validate()` call at the end would let a conversion that produced an unusable configuration
    /// pass, which is why the assertion is not merely "the fields copied across".
    #[test]
    fn the_operator_section_becomes_a_client_configuration_that_validates() {
        let loaded = enclave_config::ConfigLoader::new()
            .without_env()
            .with_yaml(
                "enclave.yaml",
                "
storage:
  provider: s3
  s3:
    bucket: enclave-content
    region: us-east-1
    endpoint: http://localhost:9000
    flavor: minio
    path_style: true
    access_key_id: env://S3_ACCESS_KEY_ID
    secret_access_key: vault://workspace/s3#secret_access_key
    signed_url_ttl: 5m
    max_signed_url_ttl: 1h
",
            )
            .load()
            .expect("the documented section loads");

        let section = loaded.config().storage.s3.as_ref().expect("a bucket");
        let config = S3Config::from_operator_config(section);

        assert_eq!(config.bucket, "enclave-content");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.endpoint.as_ref().map(url::Url::as_str), Some("http://localhost:9000/"));
        assert_eq!(config.flavor, S3Flavor::Minio);
        assert!(config.path_style);
        assert_eq!(config.signed_url_ttl.as_secs(), 300);
        assert_eq!(config.max_signed_url_ttl.as_secs(), 3600);
        assert_eq!(config.access_key_id.to_string(), "env://S3_ACCESS_KEY_ID");
        assert_eq!(
            config.secret_access_key.to_string(),
            "vault://workspace/s3#secret_access_key",
            "the reference is carried across unresolved; resolution happens in `connect`"
        );

        // The two knobs the operator surface deliberately omits take this crate's defaults, and
        // those defaults are inside S3's limits — which is the point of asserting `validate()`
        // rather than the field values.
        assert_eq!(config.part_size_bytes, default_part_size());
        assert_eq!(config.multipart_threshold_bytes, default_multipart_threshold());
        config.validate().expect("a converted configuration must be usable");
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
