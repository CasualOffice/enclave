//! `S3BlobStore` against a real S3-compatible backend.
//!
//! Every test here is `#[ignore]`d and runs against the MinIO in the dev stack
//! (`deploy/compose/dev.yml`, service `minio`) — `docker compose -f deploy/compose/dev.yml up -d
//! minio`, then export the three variables below and run with `--include-ignored`, which is how
//! `.github/workflows/ci.yml` invokes the suite. `plans/M1-CONTENT-CORE.md §6` Q5 asked MinIO or
//! LocalStack; MinIO, because it is already in the dev stack, and because it is the backend the
//! self-check has to work on where the AWS-only APIs do not exist.
//!
//! ```text
//! export ENCLAVE_TEST_S3_ENDPOINT=http://localhost:9000
//! export ENCLAVE_TEST_S3_ACCESS_KEY_ID=enclave
//! export ENCLAVE_TEST_S3_SECRET_ACCESS_KEY=…      # matches ENCLAVE_DEV_MINIO_PASSWORD
//! cargo test -p enclave-storage --test minio -- --include-ignored
//! ```
//!
//! The credentials are read as `env://` [`SecretRef`]s, not as literals — the same path production
//! uses, so the test exercises the credential resolution rather than routing around it
//! (`CLAUDE.md` rule 11).
//!
//! # The test that matters
//!
//! [`a_public_bucket_is_refused`] creates a bucket, opens it to the world with exactly the policy
//! `mc anonymous set download` writes, and asserts that the store refuses to be constructed
//! against it. That assertion is the reason this file exists: a self-check that has never been run
//! against an actually-public bucket is a self-check nobody has tested.

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::{tls, Connector};
use aws_smithy_runtime_api::client::http::HttpConnector as _;
use aws_smithy_runtime_api::http::Request;
use aws_smithy_types::body::SdkBody;
use enclave_config::SecretRegistry;
use enclave_core::{FileId, TenantId, VersionId};
use enclave_storage::{
    BlobStore, ByteRange, ObjectKey, Probe, PublicAccessCheck, PublicAccessError, S3BlobStore,
    S3Config, S3Flavor, StorageError, UploadRequest, UploadTarget, Verdict,
};

/// Attached to every `#[ignore]` so the harness is named at the test rather than in a comment
/// somebody has to go looking for.
const NEEDS_MINIO: &str =
    "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored";

const ENDPOINT: &str = "ENCLAVE_TEST_S3_ENDPOINT";
const ACCESS_KEY: &str = "ENCLAVE_TEST_S3_ACCESS_KEY_ID";
const SECRET_KEY: &str = "ENCLAVE_TEST_S3_SECRET_ACCESS_KEY";

/// A configuration pointing at a fresh, empty bucket that this test owns.
async fn fixture() -> (S3Config, aws_sdk_s3::Client, SecretRegistry) {
    let endpoint: url::Url = std::env::var(ENDPOINT)
        .unwrap_or_else(|_| panic!("{ENDPOINT} must be set: {NEEDS_MINIO}"))
        .parse()
        .expect("a valid endpoint URL");

    // Unique per run so tests never share a bucket policy, which is global to the bucket and would
    // make `a_public_bucket_is_refused` corrupt every other test in the file.
    let bucket = format!("enclave-test-{}", TenantId::new_v7());

    let mut config = S3Config::new(
        bucket.clone(),
        "us-east-1",
        format!("env://{ACCESS_KEY}").parse().unwrap(),
        format!("env://{SECRET_KEY}").parse().unwrap(),
    )
    .with_endpoint(endpoint, S3Flavor::Minio);
    // 5 MiB is S3's floor, and it keeps the multipart test's payload small enough to be quick.
    config.part_size_bytes = 5 * 1024 * 1024;
    config.multipart_threshold_bytes = 5 * 1024 * 1024;

    let admin = admin_client(&config);
    admin.create_bucket().bucket(&bucket).send().await.expect("create the test bucket");

    (config, admin, SecretRegistry::local())
}

/// A raw client for the setup a `BlobStore` deliberately cannot do — creating buckets and writing
/// bucket policies. Kept out of the trait for the reason in `blob_store.rs`: administrative
/// operations on the bucket are not something a domain crate should be able to reach.
fn admin_client(config: &S3Config) -> aws_sdk_s3::Client {
    let mut builder = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(config.region.clone()))
        .force_path_style(config.path_style)
        .credentials_provider(Credentials::new(
            std::env::var(ACCESS_KEY).unwrap_or_else(|_| panic!("{ACCESS_KEY}: {NEEDS_MINIO}")),
            std::env::var(SECRET_KEY).unwrap_or_else(|_| panic!("{SECRET_KEY}: {NEEDS_MINIO}")),
            None,
            None,
            "enclave-test",
        ));
    if let Some(endpoint) = &config.endpoint {
        builder = builder.endpoint_url(endpoint.as_str().trim_end_matches('/'));
    }
    aws_sdk_s3::Client::from_conf(builder.build())
}

/// Exactly what `mc anonymous set download <alias>/<bucket>` writes.
fn public_read_policy(bucket: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",
           "Principal":{{"AWS":["*"]}},"Action":["s3:GetObject"],
           "Resource":["arn:aws:s3:::{bucket}/*"]}}]}}"#
    )
}

fn http() -> Connector {
    Connector::builder()
        .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::AwsLc))
        .build()
}

/// `PUT`s to a pre-signed URL exactly as a browser would, and returns the status and ETag.
///
/// The point of going over real HTTP rather than calling `PutObject` through the SDK: the thing
/// under test is the *URL*, and a URL that the SDK would have signed differently is not evidence
/// that a client can upload with it.
async fn put(url: &url::Url, body: Vec<u8>) -> (u16, Option<String>) {
    let mut request = Request::new(SdkBody::from(body));
    request.set_method("PUT").unwrap();
    request.set_uri(url.as_str()).unwrap();
    let response = http().call(request).await.expect("the pre-signed PUT reached the endpoint");
    let etag = response.headers().get("etag").map(ToOwned::to_owned);
    (response.status().as_u16(), etag)
}

async fn get_status(url: &url::Url) -> u16 {
    let mut request = Request::new(SdkBody::empty());
    request.set_uri(url.as_str()).unwrap();
    http().call(request).await.expect("the pre-signed GET reached the endpoint").status().as_u16()
}

fn new_key() -> ObjectKey {
    ObjectKey::version(TenantId::new_v7(), FileId::new_v7(), VersionId::new_v7())
}

// ---------------------------------------------------------------------------
// The self-check.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_private_bucket_passes_the_self_check() {
    let (config, _admin, secrets) = fixture().await;
    let bucket = config.bucket.clone();

    let store = S3BlobStore::connect_and_verify(config, &secrets)
        .await
        .expect("a freshly created MinIO bucket is private and must pass");

    let report = store.verify_not_public().await.expect("and must keep passing");
    assert_eq!(report.bucket, bucket);

    // The unsigned probe specifically must have concluded, in the negative direction too. It is
    // the only probe that survives a least-privilege credential, so a pass resting solely on the
    // bucket-policy probe would evaporate the moment the deployment tightened its IAM policy —
    // which is exactly when the check needs to still work.
    let anonymous = report
        .probes
        .iter()
        .find(|p| p.probe == Probe::AnonymousRead)
        .expect("the unsigned read probe must run");
    assert_eq!(
        anonymous.verdict,
        Verdict::Private,
        "an unsigned read of a private bucket must be refused: {anonymous}"
    );
}

/// The test this whole module exists for.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_public_bucket_is_refused() {
    let (config, admin, secrets) = fixture().await;
    let bucket = config.bucket.clone();

    admin
        .put_bucket_policy()
        .bucket(&bucket)
        .policy(public_read_policy(&bucket))
        .send()
        .await
        .expect("open the bucket to the world");

    // Constructed without the check, so the check's own findings can be inspected.
    let store = S3BlobStore::connect(config.clone(), &secrets).await.expect("connect");
    let err = store.verify_not_public().await.expect_err("a public bucket must not pass");

    assert!(matches!(err, PublicAccessError::Exposed { .. }), "got: {err:?}");
    let rendered = err.to_string();
    assert!(rendered.contains(&bucket), "the refusal must name the bucket: {rendered}");
    assert!(rendered.contains("PUBLICLY READABLE"), "{rendered}");
    assert!(rendered.contains("mc anonymous set none"), "{rendered}");
    // Both the policy parser and the unsigned request must have caught it; either alone would be a
    // single point of failure on a backend that lacks the other.
    assert!(rendered.contains("s3:GetObject"), "the bucket policy probe missed it: {rendered}");
    assert!(rendered.contains("unsigned request"), "the anonymous probe missed it: {rendered}");

    // And the constructor a composition root uses must refuse outright.
    let err = S3BlobStore::connect_and_verify(config, &secrets)
        .await
        .expect_err("connect_and_verify must not return a store for a public bucket");
    assert!(matches!(err, StorageError::PublicBucket(_)), "got: {err:?}");
}

// ---------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_single_shot_upload_round_trips_through_a_pre_signed_url() {
    let (config, _admin, secrets) = fixture().await;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let key = new_key();
    let body = b"the quick brown fox".to_vec();
    let session = store
        .create_upload(UploadRequest::new(key.clone(), body.len() as u64))
        .await
        .expect("create_upload");

    let UploadTarget::Single { url } = &session.target else {
        panic!("a small object must not be multipart: {:?}", session.target);
    };
    let (status, _) = put(url, body.clone()).await;
    assert_eq!(status, 200, "the pre-signed PUT was rejected");

    let meta = store.complete_upload(&session).await.expect("complete_upload");
    assert_eq!(meta.size_bytes, body.len() as u64);
    assert_eq!(meta.key, key);

    // Read back through the store.
    let read = store
        .read_range(key.as_str(), ByteRange::from(0))
        .await
        .expect("read_range")
        .collect_bounded(1024)
        .await
        .expect("collect");
    assert_eq!(read, body);

    // And through a signed URL, which is what a client actually gets.
    let url = store
        .signed_download(key.as_str(), Duration::from_secs(60))
        .await
        .expect("signed_download");
    assert_eq!(get_status(&url).await, 200);

    // A partial read must be partial.
    let partial = store
        .read_range(key.as_str(), ByteRange::sized(4, 5).unwrap())
        .await
        .expect("read_range")
        .collect_bounded(1024)
        .await
        .expect("collect");
    assert_eq!(partial, b"quick");

    // Copy, then delete the original, and the copy must survive.
    let copy = new_key();
    store.copy(key.as_str(), copy.as_str()).await.expect("copy");
    store.delete(key.as_str()).await.expect("delete");

    let err = store.read_range(key.as_str(), ByteRange::from(0)).await.expect_err("gone");
    assert!(matches!(err, StorageError::NotFound { .. }), "got: {err:?}");
    assert!(store.read_range(copy.as_str(), ByteRange::from(0)).await.is_ok());

    // Deleting twice must succeed — a retry after a network failure is normal.
    store.delete(key.as_str()).await.expect("delete is idempotent");
}

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_multipart_upload_round_trips() {
    let (config, _admin, secrets) = fixture().await;
    let part_size = config.part_size_bytes as usize;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    // Two full parts and a short final one, which is the shape that catches an off-by-one in the
    // part-length arithmetic.
    let body: Vec<u8> = (0..part_size * 2 + 1024).map(|i| (i % 251) as u8).collect();
    let key = new_key();

    let mut session = store
        .create_upload(UploadRequest::new(key.clone(), body.len() as u64))
        .await
        .expect("create_upload");

    let UploadTarget::Multipart { parts, .. } = session.target.clone() else {
        panic!("an object above the threshold must be multipart");
    };
    assert_eq!(parts.len(), 3, "expected three parts");
    assert_eq!(parts[2].length, 1024, "the final part must be the remainder");

    for part in &parts {
        let offset = part.offset as usize;
        let slice = body[offset..offset + part.length as usize].to_vec();
        let (status, etag) = put(&part.url, slice).await;
        assert_eq!(status, 200, "part {} was rejected", part.part_number);
        session.record_part(enclave_storage::CompletedPart {
            part_number: part.part_number,
            etag: etag.expect("the provider must return an ETag for each part"),
        });
    }

    let meta = store.complete_upload(&session).await.expect("complete_upload");
    assert_eq!(meta.size_bytes, body.len() as u64);

    let tail = store
        .read_range(key.as_str(), ByteRange::sized((body.len() - 4) as u64, 4).unwrap())
        .await
        .expect("read_range")
        .collect_bounded(64)
        .await
        .expect("collect");
    assert_eq!(tail, body[body.len() - 4..]);
}

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn completing_before_every_part_is_reported_is_refused() {
    let (config, _admin, secrets) = fixture().await;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let session = store
        .create_upload(UploadRequest::new(new_key(), 12 * 1024 * 1024))
        .await
        .expect("create_upload");

    let err = store.complete_upload(&session).await.expect_err("no parts were reported");
    assert!(matches!(err, StorageError::IncompleteUpload { reported: 0, .. }), "got: {err:?}");

    // And the abandoned upload must be abortable, so its parts are not left billing.
    store.abort_upload(&session).await.expect("abort_upload");
}

// ---------------------------------------------------------------------------
// Reported capabilities, and the refusals that do not need a round trip.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn capabilities_report_what_minio_actually_does() {
    let (config, _admin, secrets) = fixture().await;
    let max_ttl = config.max_signed_url_ttl.as_duration();
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let caps = store.capabilities();
    assert_eq!(caps.backend, "s3");
    assert!(caps.signed_urls);
    assert!(caps.range_reads);
    assert!(caps.server_side_copy);
    assert_eq!(caps.max_signed_url_ttl, max_ttl);

    let multipart = caps.multipart.expect("MinIO supports multipart");
    assert_eq!(multipart.min_part_bytes, 5 * 1024 * 1024);
    assert_eq!(multipart.max_parts, 10_000);

    // The honest report: no S3-compatible backend can invalidate a pre-signed URL before it
    // expires, so this must stay `false` and the TTL must stay short
    // (`plans/M1-CONTENT-CORE.md` D14).
    assert!(
        !caps.single_use_signed_urls,
        "SigV4 pre-signed URLs are replayable until they expire; reporting otherwise would let a \
         caller rely on a property the backend does not have"
    );
}

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_ttl_above_the_configured_ceiling_is_refused_rather_than_clamped() {
    let (config, _admin, secrets) = fixture().await;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let err = store
        .signed_download(new_key().as_str(), Duration::from_secs(24 * 60 * 60))
        .await
        .expect_err("a day-long download URL must be refused");
    assert!(matches!(err, StorageError::TtlTooLong { .. }), "got: {err:?}");

    let err = store
        .signed_download(new_key().as_str(), Duration::ZERO)
        .await
        .expect_err("a zero TTL must be refused");
    assert!(matches!(err, StorageError::TtlZero), "got: {err:?}");
}

/// Object storage has no row-level security, so the canonical-key check is the equivalent control:
/// a caller cannot ask the store to sign, read, copy or delete a path of its own choosing.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_key_outside_the_canonical_layout_never_reaches_the_provider() {
    let (config, _admin, secrets) = fixture().await;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let good = new_key();
    for hostile in ["", "/", "../../etc/passwd", "tenant/../elsewhere/x"] {
        assert!(matches!(
            store.signed_download(hostile, Duration::from_secs(60)).await,
            Err(StorageError::Key(_))
        ));
        assert!(matches!(store.delete(hostile).await, Err(StorageError::Key(_))));
        assert!(matches!(
            store.read_range(hostile, ByteRange::from(0)).await,
            Err(StorageError::Key(_))
        ));
        assert!(matches!(store.copy(good.as_str(), hostile).await, Err(StorageError::Key(_))));
        assert!(matches!(store.copy(hostile, good.as_str()).await, Err(StorageError::Key(_))));
    }
}

/// A bucket that does not exist must fail at construction with a message naming the field to
/// change, not at the first upload with a signature error hours later.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn a_missing_bucket_fails_at_connect() {
    let (mut config, _admin, secrets) = fixture().await;
    config.bucket = format!("enclave-absent-{}", TenantId::new_v7());

    let err = S3BlobStore::connect(config, &secrets).await.expect_err("the bucket does not exist");
    assert!(
        matches!(err, StorageError::BucketNotFound { .. } | StorageError::NotFound { .. }),
        "got: {err:?}"
    );
}

/// The credential path is the production one: `env://` references resolved through
/// `SecretRegistry`. An unset reference must fail closed, naming the reference and not the value.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and ENCLAVE_TEST_S3_*; CI runs it with --include-ignored"]
async fn an_unresolvable_credential_reference_fails_closed() {
    let (mut config, _admin, secrets) = fixture().await;
    config.access_key_id = "env://ENCLAVE_TEST_S3_DEFINITELY_NOT_SET".parse().unwrap();

    let err = S3BlobStore::connect(config, &secrets).await.expect_err("the reference is unset");
    match err {
        StorageError::Credential { reference, .. } => {
            assert_eq!(reference, "env://ENCLAVE_TEST_S3_DEFINITELY_NOT_SET");
        }
        other => panic!("expected a credential failure, got: {other:?}"),
    }
}
