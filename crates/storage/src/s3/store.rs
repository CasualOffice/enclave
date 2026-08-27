//! The S3-compatible [`BlobStore`].
//!
//! One implementation covers AWS S3, MinIO, Ceph, R2, Wasabi and Backblaze B2, because they speak
//! the same API; what differs is the endpoint, the addressing style, and which administrative APIs
//! exist. Those three are configuration ([`S3Config`]) and a flavor
//! ([`S3Flavor`](super::S3Flavor)) rather than six implementations.

use core::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::types::{
    BucketVersioningStatus, ChecksumMode, CompletedMultipartUpload,
    CompletedPart as S3CompletedPart,
};
use aws_smithy_types::error::display::DisplayErrorContext;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_config::SecretRegistry;
use url::Url;

use crate::blob_store::BlobStore;
use crate::error::{Result, StorageError};
use crate::key::ObjectKey;
use crate::model::{
    ByteRange, ByteStream, CompletedPart, MultipartLimits, ObjectMeta, PartTarget, RequiredHeader,
    StoreCapabilities, Support, UploadRequest, UploadSession, UploadTarget,
};
use crate::public_access::PublicAccessCheck as _;
use crate::s3::anonymous::AnonymousProbe;
use crate::s3::config::{S3Config, S3_MAX_PARTS, S3_MAX_PART_BYTES, S3_MIN_PART_BYTES};

/// The header a pre-signed `PUT` must carry for the provider to verify what it stores.
///
/// Lowercase, because that is how it appears in `X-Amz-SignedHeaders` and how the client has to
/// send it.
const CHECKSUM_HEADER: &str = "x-amz-checksum-sha256";

/// The other header a pre-signed `PUT` from this store commits the client to.
///
/// It has always been signed — the SDK puts it on the request when `content_type` is set — and was
/// reported nowhere, which is `ENC-821`.
const CONTENT_TYPE_HEADER: &str = "content-type";

/// The number of hex characters in a SHA-256.
const SHA256_HEX_LEN: usize = 64;

/// An S3-compatible object store bound to one bucket.
///
/// Construct with [`S3BlobStore::connect_and_verify`] unless there is a stated reason not to; see
/// its documentation for the difference.
#[derive(Debug)]
pub struct S3BlobStore {
    client: aws_sdk_s3::Client,
    config: S3Config,
    capabilities: StoreCapabilities,
    anonymous: AnonymousProbe,
    anonymous_bucket_url: Option<String>,
}

impl S3BlobStore {
    /// Connects, validates the configuration, confirms the bucket exists, and probes what the
    /// backend supports — but does **not** run the public-access self-check.
    ///
    /// Exists for the two callers that legitimately need a store without the check: an admin "test
    /// connection" surface, which must report the check's findings rather than fail to construct,
    /// and the tests that create a deliberately public bucket in order to assert that the check
    /// refuses it. Application startup uses [`S3BlobStore::connect_and_verify`].
    ///
    /// # Errors
    ///
    /// [`StorageError::Config`] for an unusable configuration, [`StorageError::Credential`] if a
    /// credential reference does not resolve, [`StorageError::BucketNotFound`] if the bucket is not
    /// reachable, and [`StorageError::AccessDenied`] if the credential cannot even see it.
    pub async fn connect(config: S3Config, secrets: &SecretRegistry) -> Result<Self> {
        config.validate()?;

        let client = build_client(&config, secrets).await?;
        let anonymous_bucket_url = AnonymousProbe::bucket_url(
            config.endpoint.as_ref(),
            &config.region,
            &config.bucket,
            config.path_style,
        )
        .ok();

        let mut store = Self {
            client,
            capabilities: StoreCapabilities {
                backend: "s3",
                multipart: None,
                signed_urls: true,
                single_use_signed_urls: false,
                max_signed_url_ttl: config.max_signed_url_ttl.as_duration(),
                versioning: Support::Unknown,
                object_lock: Support::Unknown,
                server_side_encryption: Support::Unknown,
                range_reads: true,
                server_side_copy: true,
            },
            config,
            anonymous: AnonymousProbe::new(),
            anonymous_bucket_url,
        };

        // Ordered deliberately. The bucket has to be confirmed to exist *before* the self-check
        // runs, because the unsigned read probe reads a 404 as "anonymous access is allowed, the
        // object merely is not there" — sound only when the bucket is known to be there.
        store.confirm_bucket_exists().await?;
        store.probe_capabilities().await;
        Ok(store)
    }

    /// [`S3BlobStore::connect`], then the public-access self-check, refusing to return a store
    /// whose bucket is publicly readable.
    ///
    /// This is what a composition root calls. The failure is loud and names the bucket — see
    /// [`crate::public_access`].
    ///
    /// # Errors
    ///
    /// Everything [`S3BlobStore::connect`] returns, plus [`StorageError::PublicBucket`].
    pub async fn connect_and_verify(config: S3Config, secrets: &SecretRegistry) -> Result<Self> {
        let store = Self::connect(config, secrets).await?;
        let report = store.verify_not_public().await?;
        tracing::info!(
            bucket = %report.bucket,
            probes = report.conclusive().len(),
            "object storage public-access self-check passed: {report}"
        );
        Ok(store)
    }

    /// The configuration this store was built from. Contains only secret *references*.
    pub(crate) const fn config(&self) -> &S3Config {
        &self.config
    }

    pub(crate) const fn client(&self) -> &aws_sdk_s3::Client {
        &self.client
    }

    pub(crate) const fn anonymous(&self) -> &AnonymousProbe {
        &self.anonymous
    }

    pub(crate) fn anonymous_bucket_url(&self) -> Option<String> {
        self.anonymous_bucket_url.clone()
    }

    /// Abandons a multipart upload, releasing the parts the provider is holding.
    ///
    /// Not part of the `docs/08-BYO-INFRA.md §2` trait, and needed anyway: an abandoned multipart
    /// upload keeps its parts, and they are billed and counted against quota until something
    /// aborts them or a lifecycle rule does. The upload service (`ENC-129`) calls this when a
    /// session expires or is cancelled.
    ///
    /// # Errors
    ///
    /// [`StorageError::Unsupported`] for a single-shot session — there is nothing to abort — and
    /// any provider failure.
    pub async fn abort_upload(&self, session: &UploadSession) -> Result<()> {
        let UploadTarget::Multipart { upload_id, .. } = &session.target else {
            return Err(StorageError::Unsupported { capability: "aborting a single-shot upload" });
        };
        self.client
            .abort_multipart_upload()
            .bucket(&self.config.bucket)
            .key(session.key.as_str())
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|err| {
                self.map_err("AbortMultipartUpload", Some(session.key.as_str()), &err)
            })?;
        Ok(())
    }

    /// `HeadBucket`, so a wrong bucket, endpoint or addressing style fails at startup with a
    /// message naming the field rather than at the first upload with a signature error.
    async fn confirm_bucket_exists(&self) -> Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.config.bucket)
            .send()
            .await
            .map_err(|err| self.map_err("HeadBucket", None, &err))?;
        Ok(())
    }

    /// Asks the backend what it supports, once, and caches the answer.
    ///
    /// Never fails: a denied probe yields [`Support::Unknown`], which is the honest answer and is
    /// distinct from `No`. `capabilities()` is a report, not a health check, so a least-privileged
    /// credential must not stop the process from starting.
    async fn probe_capabilities(&mut self) {
        let bucket = &self.config.bucket;

        self.capabilities.versioning =
            match self.client.get_bucket_versioning().bucket(bucket).send().await {
                Ok(response) => match response.status() {
                    Some(&BucketVersioningStatus::Enabled) => Support::Yes,
                    Some(_) | None => Support::No,
                },
                Err(err) => {
                    tracing::debug!(error = %DisplayErrorContext(&err), "GetBucketVersioning");
                    Support::Unknown
                }
            };

        self.capabilities.object_lock =
            match self.client.get_object_lock_configuration().bucket(bucket).send().await {
                Ok(response) => {
                    if response.object_lock_configuration().is_some() {
                        Support::Yes
                    } else {
                        Support::No
                    }
                }
                Err(err) => absent_or_unknown(err.code()),
            };

        self.capabilities.server_side_encryption =
            match self.client.get_bucket_encryption().bucket(bucket).send().await {
                Ok(response) => {
                    if response.server_side_encryption_configuration().is_some() {
                        Support::Yes
                    } else {
                        Support::No
                    }
                }
                Err(err) => absent_or_unknown(err.code()),
            };

        // Multipart is not probeable without starting one, so it is reported from the protocol's
        // own limits, narrowed by the configured part size. Every S3-compatible backend in
        // `docs/08-BYO-INFRA.md §3` implements it.
        self.capabilities.multipart = Some(MultipartLimits {
            min_part_bytes: S3_MIN_PART_BYTES,
            max_part_bytes: S3_MAX_PART_BYTES,
            max_parts: S3_MAX_PARTS,
        });

        tracing::info!(
            bucket = %bucket,
            versioning = ?self.capabilities.versioning,
            object_lock = ?self.capabilities.object_lock,
            encryption = ?self.capabilities.server_side_encryption,
            "object storage capabilities probed"
        );
    }

    /// The TTL to sign with, refusing anything above the configured ceiling.
    ///
    /// Refuses rather than clamps. A caller that asked for a day and silently received five
    /// minutes writes an expiry into a response body that is wrong, and the client discovers it as
    /// a broken download instead of as an error.
    fn presign_config(&self, ttl: Duration) -> Result<PresigningConfig> {
        if ttl.is_zero() {
            return Err(StorageError::TtlZero);
        }
        let maximum = self.config.max_signed_url_ttl.as_duration();
        if ttl > maximum {
            return Err(StorageError::TtlTooLong { requested: ttl, maximum });
        }
        PresigningConfig::expires_in(ttl).map_err(|err| StorageError::Config {
            problem: format!("pre-signing configuration rejected a {}s TTL: {err}", ttl.as_secs()),
        })
    }

    /// Turns an SDK failure into this crate's error.
    ///
    /// The mapping is centralized so that "AccessDenied" cannot be reported as "not found" by one
    /// call site and as an internal error by another — the difference decides whether a caller
    /// sees `404` or `503`, and `CLAUDE.md` rule 7 depends on `404` meaning what it says.
    fn map_err<E>(&self, operation: &'static str, key: Option<&str>, err: &E) -> StorageError
    where
        E: ProvideErrorMetadata + std::error::Error,
    {
        let code = err.code().map(ToOwned::to_owned);
        match code.as_deref() {
            Some("NoSuchKey" | "NotFound") => {
                StorageError::NotFound { key: key.unwrap_or("<unknown>").to_owned() }
            }
            Some(
                "AccessDenied"
                | "AccessDeniedException"
                | "Forbidden"
                | "InvalidAccessKeyId"
                | "SignatureDoesNotMatch",
            ) => StorageError::AccessDenied { operation },
            Some("NoSuchBucket") => {
                StorageError::BucketNotFound { bucket: self.config.bucket.clone() }
            }
            _ => StorageError::Upstream {
                operation,
                code,
                detail: DisplayErrorContext(err).to_string(),
            },
        }
    }

    /// `HeadObject`, mapped into [`ObjectMeta`].
    ///
    /// `ChecksumMode::Enabled` is not optional decoration. S3 and MinIO omit `x-amz-checksum-*`
    /// from a `HeadObject` response unless it is asked for, so without it `checksum_sha256` comes
    /// back `None` for every object — including the ones the provider computed a digest for and
    /// verified. That was the silent second half of `ENC-820`: the request on the way out lacked
    /// the header, and the read on the way back would not have seen the answer either.
    async fn head(&self, key: ObjectKey) -> Result<ObjectMeta> {
        let head = self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key.as_str())
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
            .map_err(|err| self.map_err("HeadObject", Some(key.as_str()), &err))?;

        Ok(ObjectMeta {
            size_bytes: head.content_length().unwrap_or_default().max(0).unsigned_abs(),
            etag: head.e_tag().map(strip_quotes),
            checksum_sha256: head.checksum_sha256().map(ToOwned::to_owned),
            content_type: head.content_type().map(ToOwned::to_owned),
            last_modified: head.last_modified().and_then(to_chrono),
            provider_version_id: head.version_id().map(ToOwned::to_owned),
            server_side_encryption: head.server_side_encryption().map(|s| s.as_str().to_owned()),
            key,
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn create_upload(&self, request: UploadRequest) -> Result<UploadSession> {
        let key = request.key;
        let bucket = &self.config.bucket;

        // The digest, converted once, before anything is signed. `None` here means the caller asked
        // for no provider verification — the internal-write paths, where this process is itself the
        // client and there is no untrusted party to check.
        let expected = request.checksum_sha256.as_deref().map(base64_sha256_of_hex).transpose()?;

        if request.content_length <= self.config.multipart_threshold_bytes {
            let ttl = self.config.signed_url_ttl.as_duration();
            let mut put = self.client.put_object().bucket(bucket).key(key.as_str());
            let mut required_headers = Vec::new();

            if let Some(content_type) = &request.content_type {
                put = put.content_type(content_type);
                // Signed, therefore mandatory, therefore reported. `ENC-821`: this header was
                // already being signed and was named nowhere, so a client that sent a different
                // media type — or none — got a `403` that reads as an authorization failure.
                required_headers.push(RequiredHeader {
                    name: CONTENT_TYPE_HEADER.to_owned(),
                    value: content_type.clone(),
                });
            }

            // The header goes on the request *before* it is signed, which is the whole mechanism:
            // SigV4 covers every header present at signing time and names them in
            // `X-Amz-SignedHeaders`, so the client cannot omit `x-amz-checksum-sha256` (the
            // signature fails) and cannot alter it (likewise). Having received it, S3 and MinIO
            // hash the body and refuse it if the two disagree — so a client that lies about its
            // content gets a failed `PUT` rather than a stored object with a false digest beside
            // it. `ENC-820`.
            if let Some(digest) = &expected {
                put = put.checksum_sha256(digest);
                required_headers.push(RequiredHeader {
                    name: CHECKSUM_HEADER.to_owned(),
                    value: digest.clone(),
                });
            }

            let presigned = put
                .presigned(self.presign_config(ttl)?)
                .await
                .map_err(|err| self.map_err("PutObject", Some(key.as_str()), &err))?;

            return Ok(UploadSession {
                content_length: request.content_length,
                target: UploadTarget::Single {
                    url: parse_presigned(presigned.uri())?,
                    required_headers,
                },
                expires_at: Utc::now() + ttl,
                completed_parts: Vec::new(),
                key,
            });
        }

        // Multipart, and this backend cannot be made to verify a whole-object digest for one. See
        // `StorageError::ChecksumUnverifiable`. Refused here, above every `presigned()` call below,
        // so the client is told before it spends a byte.
        if expected.is_some() {
            return Err(StorageError::ChecksumUnverifiable {
                content_length: request.content_length,
                threshold: self.config.multipart_threshold_bytes,
            });
        }

        let part_size = self.config.part_size_bytes;
        let needed = request.content_length.div_ceil(part_size);
        if needed > u64::from(S3_MAX_PARTS) {
            return Err(StorageError::TooManyParts {
                content_length: request.content_length,
                needed,
                part_bytes: part_size,
                max_parts: S3_MAX_PARTS,
            });
        }

        let mut create = self.client.create_multipart_upload().bucket(bucket).key(key.as_str());
        if let Some(content_type) = &request.content_type {
            create = create.content_type(content_type);
        }
        let created = create
            .send()
            .await
            .map_err(|err| self.map_err("CreateMultipartUpload", Some(key.as_str()), &err))?;
        let upload_id = created
            .upload_id()
            .ok_or_else(|| StorageError::Upstream {
                operation: "CreateMultipartUpload",
                code: None,
                detail: "the provider returned no upload id".to_owned(),
            })?
            .to_owned();

        // Multipart uploads legitimately outlive a download URL, so they are signed against the
        // ceiling rather than the default. The ceiling is still a single configured number.
        let ttl = self.config.max_signed_url_ttl.as_duration();
        let presign = self.presign_config(ttl)?;

        let mut parts = Vec::with_capacity(usize::try_from(needed).unwrap_or(0));
        for index in 0..needed {
            let offset = index * part_size;
            let length = part_size.min(request.content_length - offset);
            let part_number = i32::try_from(index + 1).map_err(|_| StorageError::TooManyParts {
                content_length: request.content_length,
                needed,
                part_bytes: part_size,
                max_parts: S3_MAX_PARTS,
            })?;

            let presigned = self
                .client
                .upload_part()
                .bucket(bucket)
                .key(key.as_str())
                .upload_id(&upload_id)
                .part_number(part_number)
                .presigned(presign.clone())
                .await
                .map_err(|err| self.map_err("UploadPart", Some(key.as_str()), &err))?;

            parts.push(PartTarget {
                part_number: part_number.unsigned_abs(),
                offset,
                length,
                url: parse_presigned(presigned.uri())?,
            });
        }

        Ok(UploadSession {
            content_length: request.content_length,
            target: UploadTarget::Multipart { upload_id, parts },
            expires_at: Utc::now() + ttl,
            completed_parts: Vec::new(),
            key,
        })
    }

    async fn complete_upload(&self, session: &UploadSession) -> Result<ObjectMeta> {
        if let UploadTarget::Multipart { upload_id, parts } = &session.target {
            if session.completed_parts.len() != parts.len() {
                return Err(StorageError::IncompleteUpload {
                    key: session.key.as_str().to_owned(),
                    reported: session.completed_parts.len(),
                    expected: parts.len(),
                });
            }

            let mut completed = Vec::with_capacity(session.completed_parts.len());
            for CompletedPart { part_number, etag } in &session.completed_parts {
                let number = i32::try_from(*part_number).map_err(|_| StorageError::Config {
                    problem: format!("part number {part_number} is out of range"),
                })?;
                completed.push(S3CompletedPart::builder().part_number(number).e_tag(etag).build());
            }

            self.client
                .complete_multipart_upload()
                .bucket(&self.config.bucket)
                .key(session.key.as_str())
                .upload_id(upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder().set_parts(Some(completed)).build(),
                )
                .send()
                .await
                .map_err(|err| {
                    self.map_err("CompleteMultipartUpload", Some(session.key.as_str()), &err)
                })?;
        }

        // `HeadObject` in both branches on purpose. The size and checksum recorded on a version
        // row must be the provider's, never the client's declaration — those columns are immutable
        // once written (`plans/M1-CONTENT-CORE.md` D12), so a client's claim would become
        // permanent.
        self.head(session.key.clone()).await
    }

    async fn signed_download(&self, key: &str, ttl: Duration) -> Result<Url> {
        let key = ObjectKey::parse(key)?;
        let presigned = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key.as_str())
            .presigned(self.presign_config(ttl)?)
            .await
            .map_err(|err| self.map_err("GetObject", Some(key.as_str()), &err))?;
        parse_presigned(presigned.uri())
    }

    async fn read_range(&self, key: &str, range: ByteRange) -> Result<ByteStream> {
        let key = ObjectKey::parse(key)?;
        let response = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key.as_str())
            .range(range.header_value())
            .send()
            .await
            .map_err(|err| self.map_err("GetObject", Some(key.as_str()), &err))?;

        let content_length = response.content_length().map(|len| len.max(0).unsigned_abs());

        // `unfold` rather than a `map` over a `Stream`: the SDK's `ByteStream` exposes chunks
        // through an inherent `next()` and does not implement `Stream` without an adapter. Driving
        // it by hand keeps the transfer chunk-by-chunk, which is what the flat-memory exit
        // criterion in `plans/M1-CONTENT-CORE.md §1` needs.
        let chunks = futures::stream::unfold(
            (response.body, key.as_str().to_owned()),
            |(mut body, key)| async move {
                let chunk = body.next().await?;
                let mapped = chunk.map_err(|err| StorageError::Upstream {
                    operation: "GetObject",
                    code: None,
                    detail: format!("{key}: {}", DisplayErrorContext(&err)),
                });
                Some((mapped, (body, key)))
            },
        );

        Ok(ByteStream::new(chunks, content_length))
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let from = ObjectKey::parse(from)?;
        let to = ObjectKey::parse(to)?;
        self.client
            .copy_object()
            .bucket(&self.config.bucket)
            .copy_source(format!("{}/{from}", self.config.bucket))
            .key(to.as_str())
            .send()
            .await
            .map_err(|err| self.map_err("CopyObject", Some(from.as_str()), &err))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let key = ObjectKey::parse(key)?;
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(key.as_str())
            .send()
            .await
            .map_err(|err| self.map_err("DeleteObject", Some(key.as_str()), &err))?;
        Ok(())
    }

    fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }
}

/// Builds the SDK client from resolved credentials.
///
/// `aws-config` is deliberately not a dependency, so there is no provider chain to fall back on:
/// if the references do not resolve, the store does not exist. A process that could quietly pick
/// up an instance-profile credential would make the configured `credential_reference` advisory.
async fn build_client(config: &S3Config, secrets: &SecretRegistry) -> Result<aws_sdk_s3::Client> {
    async fn resolve(
        secrets: &SecretRegistry,
        reference: &enclave_config::SecretRef,
    ) -> Result<String> {
        let value = secrets.read(reference).await.map_err(|source| StorageError::Credential {
            reference: reference.to_string(),
            source,
        })?;
        value
            .expose_str()
            .map(ToOwned::to_owned)
            .map_err(|source| StorageError::Credential { reference: reference.to_string(), source })
    }

    let access_key_id = resolve(secrets, &config.access_key_id).await?;
    let secret_access_key = resolve(secrets, &config.secret_access_key).await?;
    let session_token = match &config.session_token {
        Some(reference) => Some(resolve(secrets, reference).await?),
        None => None,
    };

    let mut builder = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(config.region.clone()))
        .force_path_style(config.path_style)
        .credentials_provider(Credentials::new(
            access_key_id,
            secret_access_key,
            session_token,
            None,
            "enclave-config",
        ));

    if let Some(endpoint) = &config.endpoint {
        builder = builder.endpoint_url(endpoint.as_str().trim_end_matches('/'));
    }

    Ok(aws_sdk_s3::Client::from_conf(builder.build()))
}

/// A "does not exist" error code means the feature is off; anything else means we could not tell.
fn absent_or_unknown(code: Option<&str>) -> Support {
    match code {
        Some(
            "ObjectLockConfigurationNotFoundError"
            | "NoSuchObjectLockConfiguration"
            | "ServerSideEncryptionConfigurationNotFoundError",
        ) => Support::No,
        _ => Support::Unknown,
    }
}

/// The SDK hands back a `&str`; a caller gets a [`Url`], because a URL that does not parse is a
/// bug worth finding here rather than at the client.
fn parse_presigned(uri: &str) -> Result<Url> {
    Url::parse(uri).map_err(|err| StorageError::Upstream {
        operation: "presign",
        code: None,
        detail: format!("the provider returned an unparseable URL: {err}"),
    })
}

/// Turns the lowercase hex SHA-256 the platform speaks into the base64 S3 expects.
///
/// Two spellings of one digest, and the boundary between them is here rather than at every caller:
/// hex is what `file_versions.checksum_sha256` holds and what `docs/05-API.md §8` puts on the wire,
/// base64 is what `x-amz-checksum-sha256` carries. `enclave_uploads::content` performs the inverse
/// on the way back, and the two are asserted against the same vector.
///
/// # Errors
///
/// [`StorageError::MalformedChecksum`] for anything that is not 64 lowercase hex characters. It
/// refuses rather than passing the value through, because a digest the provider cannot parse is
/// one it will ignore — leaving the upload unverified with nobody told.
fn base64_sha256_of_hex(hex: &str) -> Result<String> {
    if hex.len() != SHA256_HEX_LEN {
        return Err(StorageError::MalformedChecksum);
    }
    let mut raw = [0_u8; SHA256_HEX_LEN / 2];
    for (index, byte) in raw.iter_mut().enumerate() {
        let nibble = |offset: usize| -> Option<u8> {
            match hex.as_bytes().get(index * 2 + offset)? {
                digit @ b'0'..=b'9' => Some(digit - b'0'),
                letter @ b'a'..=b'f' => Some(letter - b'a' + 10),
                _ => None,
            }
        };
        let (high, low) = nibble(0).zip(nibble(1)).ok_or(StorageError::MalformedChecksum)?;
        *byte = (high << 4) | low;
    }
    Ok(STANDARD.encode(raw))
}

/// S3 quotes its ETags. Stored unquoted so a comparison against a computed digest works without
/// every call site remembering to trim.
fn strip_quotes(etag: &str) -> String {
    etag.trim_matches('"').to_owned()
}

fn to_chrono(value: &aws_smithy_types::DateTime) -> Option<DateTime<Utc>> {
    Utc.timestamp_opt(value.secs(), value.subsec_nanos()).single()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn etags_are_stored_without_the_providers_quotes() {
        assert_eq!(strip_quotes("\"d41d8cd9\""), "d41d8cd9");
        assert_eq!(strip_quotes("d41d8cd9"), "d41d8cd9");
    }

    #[test]
    fn an_absent_configuration_is_no_and_a_denied_one_is_unknown() {
        assert_eq!(absent_or_unknown(Some("ObjectLockConfigurationNotFoundError")), Support::No);
        assert_eq!(
            absent_or_unknown(Some("ServerSideEncryptionConfigurationNotFoundError")),
            Support::No
        );
        assert_eq!(absent_or_unknown(Some("AccessDenied")), Support::Unknown);
        assert_eq!(absent_or_unknown(None), Support::Unknown);
    }

    #[test]
    fn a_presigned_url_that_does_not_parse_is_an_upstream_failure_not_a_panic() {
        assert!(parse_presigned("not a url").is_err());
        assert!(parse_presigned("https://example.com/a?b=c").is_ok());
    }

    /// The hex/base64 boundary, both directions.
    ///
    /// The reverse conversion lives in `enclave_uploads::content::decode_provider_sha256` and is
    /// what completion compares against, so the two spellings have to be inverses or a digest the
    /// provider confirmed would be reported as a mismatch. The empty-string digest is the vector
    /// both sides use.
    #[test]
    fn the_platforms_hex_digest_becomes_the_base64_the_header_carries() {
        const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        assert_eq!(base64_sha256_of_hex(HEX).unwrap(), B64);

        // Every byte value, so a nibble table that is wrong in one place cannot hide.
        let all_bytes: String = (0..=255_u8).map(|b| format!("{b:02x}")).collect();
        for chunk in all_bytes.as_bytes().chunks(64) {
            let hex = core::str::from_utf8(chunk).unwrap();
            let encoded = base64_sha256_of_hex(hex).unwrap();
            let decoded = STANDARD.decode(&encoded).unwrap();
            let round_tripped: String = decoded.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(round_tripped, hex);
        }
    }

    /// Anything that is not 64 lowercase hex characters is refused rather than forwarded.
    ///
    /// Forwarding is the dangerous option: the provider ignores a digest it cannot parse, the
    /// `PUT` succeeds, and the upload is unverified with nobody told — which is `ENC-820` again by
    /// a different route.
    #[test]
    fn a_digest_the_provider_could_not_parse_is_refused_rather_than_forwarded() {
        const HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        for bad in [
            String::new(),
            "deadbeef".to_owned(),
            HEX.to_uppercase(),
            format!("{HEX}0"),
            "g".repeat(64),
            " ".repeat(64),
            format!("{}=", &HEX[..63]),
        ] {
            assert!(
                matches!(base64_sha256_of_hex(&bad), Err(StorageError::MalformedChecksum)),
                "`{bad}` was accepted as a SHA-256"
            );
        }
    }
}
