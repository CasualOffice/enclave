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
//! export TEST_S3_ENDPOINT=http://localhost:9000
//! export TEST_S3_ACCESS_KEY_ID=enclave
//! export TEST_S3_SECRET_ACCESS_KEY=…      # whatever the MinIO you point at was started with:
//!                                         # ENCLAVE_DEV_MINIO_PASSWORD for the compose stack,
//!                                         # `enclave-dev-secret` for CI's standalone container
//! cargo test -p enclave-storage --test minio -- --include-ignored
//! ```
//!
//! The credentials are read as `env://` [`SecretRef`]s, not as literals — the same path production
//! uses, so the test exercises the credential resolution rather than routing around it
//! (`CLAUDE.md` rule 11).
//!
//! # Why the names have no `ENCLAVE_` prefix
//!
//! They did until `ENC-544`, and it was a live tripwire. `ENCLAVE_` is `ConfigLoader`'s namespace:
//! it reads the whole process environment, so `ENCLAVE_TEST_S3_SECRET_ACCESS_KEY` became a
//! configuration field called `test_s3_secret_access_key`, the inline-credential scanner classed it
//! as a credential and refused it on entropy, and **any process started from a shell with these
//! exported would not start**. A test variable is not configuration and must not be named as
//! though it were. `deploy/README.md` states the rule and
//! `crates/config/tests/ambient_environment.rs` enforces it.
//!
//! # The test that matters
//!
//! [`a_public_bucket_is_refused`] creates a bucket, opens it to the world with exactly the policy
//! `mc anonymous set download` writes, and asserts that the store refuses to be constructed
//! against it. That assertion is the reason this file exists: a self-check that has never been run
//! against an actually-public bucket is a self-check nobody has tested.
//!
//! # The leakage-matrix rows that live here
//!
//! A5 and A6 of `docs/12-TESTING.md §4.2` are properties of the provider rather than of any
//! Enclave code path — "an unsigned request is refused", "a signature stops being honoured at its
//! expiry" — and `crates/testing/tests/leakage.rs` routes them here for that reason. Asserting
//! them against a mock would assert that the mock was written to agree with them. The half of A6
//! that this backend cannot support is stated in that test's own documentation rather than
//! quietly omitted.

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
    "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored";

const ENDPOINT: &str = "TEST_S3_ENDPOINT";
const ACCESS_KEY: &str = "TEST_S3_ACCESS_KEY_ID";
const SECRET_KEY: &str = "TEST_S3_SECRET_ACCESS_KEY";

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

/// Stores an object and returns the key it landed on.
///
/// The A5 and A6 tests both need an object that is genuinely *there*. A refusal on a key that was
/// never written proves nothing about whether the provider checks signatures — an empty bucket
/// refuses every read for the wrong reason, and the test would stay green after the control it
/// covers was removed.
async fn store_an_object(store: &S3BlobStore, body: &[u8]) -> ObjectKey {
    let key = new_key();
    let session = store
        .create_upload(UploadRequest::new(key.clone(), body.len() as u64))
        .await
        .expect("create_upload");

    let UploadTarget::Single { url } = &session.target else {
        panic!("these bodies are far below the multipart threshold: {:?}", session.target);
    };
    let (status, _) = put(url, body.to_vec()).await;
    assert_eq!(status, 200, "the pre-signed PUT was rejected");

    store.complete_upload(&session).await.expect("complete_upload");
    key
}

/// The URL somebody types when they have the key and nothing else.
///
/// Assembled from the endpoint and the key rather than derived from a signed URL with its query
/// removed: what A5 is about is a request that was never signed at all, and a stripped URL carries
/// the shape of one this process minted. Path style, which is what `S3Config::new` defaults to and
/// what the fixture keeps.
fn direct_url(endpoint: &url::Url, bucket: &str, key: &ObjectKey) -> url::Url {
    format!("{}/{bucket}/{}", endpoint.as_str().trim_end_matches('/'), key.as_str())
        .parse()
        .expect("a valid object URL")
}

// ---------------------------------------------------------------------------
// The self-check.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
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
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
async fn an_unresolvable_credential_reference_fails_closed() {
    let (mut config, _admin, secrets) = fixture().await;
    config.access_key_id = "env://TEST_S3_DEFINITELY_NOT_SET".parse().unwrap();

    let err = S3BlobStore::connect(config, &secrets).await.expect_err("the reference is unset");
    match err {
        StorageError::Credential { reference, .. } => {
            assert_eq!(reference, "env://TEST_S3_DEFINITELY_NOT_SET");
        }
        other => panic!("expected a credential failure, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The leakage matrix: A5 and A6 of `docs/12-TESTING.md §4.2`.
// ---------------------------------------------------------------------------

/// A5 — direct object-key access without a signed URL fails at the storage layer.
///
/// Not the same question the self-check asks. The anonymous probe in `src/public_access.rs`
/// fetches a key chosen so that it *cannot* exist, because that is the only way a `404` reads
/// unambiguously as "the request was authorized"; it runs once, at startup, against the bucket as
/// a whole. This asks whether a specific stored object's bytes are reachable by anyone who learns
/// its key — leaked from a log, a referrer header, a screenshot — which is the exposure the row
/// names. The object is confirmed readable *with* a signature first, so the refusal cannot be a
/// missing object wearing a `403`.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
async fn a5_a_stored_object_is_unreachable_without_a_signature() {
    let (config, _admin, secrets) = fixture().await;
    let bucket = config.bucket.clone();
    let endpoint = config.endpoint.clone().expect("the fixture points at the dev-stack MinIO");
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");

    let key =
        store_an_object(&store, b"A5: reachable only through a URL this process minted").await;

    let signed = store
        .signed_download(key.as_str(), Duration::from_secs(60))
        .await
        .expect("signed_download");
    assert_eq!(get_status(&signed).await, 200, "the object must be readable with a signature");

    // The same object, addressed by its key, with no signature and no credential.
    let direct = direct_url(&endpoint, &bucket, &key);

    // A mistyped bucket or the wrong addressing style would earn a `403` of its own, and the
    // assertion below would then pass without ever having named the object. The signed URL is
    // known to reach it, so requiring the two paths to agree is what makes the refusal about the
    // missing signature rather than about a URL that pointed nowhere.
    assert_eq!(
        direct.path(),
        signed.path(),
        "the unsigned URL must address exactly the object the signed one reaches"
    );

    let status = get_status(&direct).await;
    assert!(
        matches!(status, 401 | 403),
        "an unsigned GET of a known key returned {status}: the provider answered a request \
         carrying no credential, so every read control above it is advisory"
    );

    // And the signature is bound to the key it was minted for. Without that, one authorized
    // download would be a key to the whole bucket: swap the path, keep the query, read anything.
    let other = store_an_object(&store, b"A5: addressed by a signature that is not its own").await;
    let mut repointed = signed.clone();
    repointed.set_path(&format!("/{bucket}/{}", other.as_str()));
    let status = get_status(&repointed).await;
    assert!(
        matches!(status, 401 | 403),
        "a signed URL repointed at a different key returned {status}: the signature does not \
         cover the object it names"
    );
}

/// A6 — a signed URL cannot be replayed after expiry.
///
/// The row's second clause, "or after single use where supported", is not supported here and is
/// not faked. SigV4 pre-signed URLs have no server-side use counter, so no S3-compatible backend
/// can burn one; `StoreCapabilities::single_use_signed_urls` documents that at the field. What
/// this asserts instead is the honest pair: the store reports the capability as absent, and a
/// second fetch inside the TTL demonstrably succeeds. Pinning the replay as an observed fact is
/// the point — it keeps `plans/M1-CONTENT-CORE.md` D14 (one URL per authorized request, minted at
/// the last moment, never cached, short TTL) visibly the *only* thing between a captured URL and
/// the bytes, so a future caller cannot quietly start treating a URL as spent.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
async fn a6_a_signed_url_stops_working_at_expiry_and_replays_until_then() {
    // SigV4 caps a pre-signed URL at seven days but imposes no floor, so seconds is a legitimate
    // TTL and this test costs single digits. It is not shorter because the provider judges expiry
    // against its own clock: a one-second URL would be racing container clock skew, and the last
    // assertion would then pass for a reason that has nothing to do with expiry.
    const TTL: Duration = Duration::from_secs(5);

    let (config, _admin, secrets) = fixture().await;
    let store = S3BlobStore::connect_and_verify(config, &secrets).await.expect("connect");
    let key = store_an_object(&store, b"A6: valid until X-Amz-Date plus X-Amz-Expires").await;

    let url = store.signed_download(key.as_str(), TTL).await.expect("signed_download");
    assert_eq!(get_status(&url).await, 200, "a freshly signed URL must work");

    assert_eq!(
        get_status(&url).await,
        200,
        "a second fetch inside the TTL must succeed; a backend that refused it would mean the \
         reported capabilities are wrong"
    );
    assert!(
        !store.capabilities().single_use_signed_urls,
        "the replay above is what the backend does, so the store must not advertise single use"
    );

    tokio::time::sleep(TTL + Duration::from_secs(2)).await;

    let status = get_status(&url).await;
    assert!(
        matches!(status, 401 | 403),
        "a signed URL served {status} after its expiry: the short TTL is the whole compensating \
         control for a URL that cannot be revoked, and it is not being enforced"
    );
}

// ---------------------------------------------------------------------------
// From what an operator writes to bytes in a bucket (`ENC-562`).
// ---------------------------------------------------------------------------

/// The whole chain, end to end: `enclave.yaml` → `ConfigLoader` → `S3Config` → a live store.
///
/// This is the assertion that closes `ENC-562`. Everything else in this file starts from an
/// `S3Config` built in Rust, which proves the *client* works and says nothing about whether a
/// deployment can reach one — and for three milestones it could not: `enclave-config` modelled no
/// `storage:` section, so `crates/worker/src/main.rs::object_store` returned `None`, the indexing
/// pass was never scheduled, and `chunk_text` stayed empty in every real deployment.
///
/// So the configuration here is *text*, loaded through the same three layers a binary loads, and
/// the credentials are `env://` references resolved by the same `SecretRegistry` production uses —
/// no literal, and no shortcut past the part that was broken.
///
/// # Deliberate violation
///
/// Reverting `S3Config::from_operator_config` to `S3Config::new(bucket, region, …)` — dropping the
/// endpoint and the flavor, which is the shape of a conversion that forgets a field — fails here
/// against MinIO with a DNS or signature error rather than passing quietly, because the round trip
/// at the end needs every one of them.
#[tokio::test]
#[ignore = "requires the dev-stack MinIO and TEST_S3_*; CI runs it with --include-ignored"]
async fn an_operator_configuration_file_produces_a_working_store() {
    // A bucket to point the configuration at, created the only way a `BlobStore` cannot.
    let (fixture_config, _admin, _) = fixture().await;
    let bucket = fixture_config.bucket.clone();
    let endpoint = fixture_config.endpoint.clone().expect("the fixture sets an endpoint");

    let yaml = format!(
        "
storage:
  provider: s3
  s3:
    bucket: {bucket}
    region: us-east-1
    endpoint: {endpoint}
    flavor: minio
    path_style: true
    access_key_id: env://{ACCESS_KEY}
    secret_access_key: env://{SECRET_KEY}
    signed_url_ttl: 5m
    max_signed_url_ttl: 1h
"
    );

    let loaded = enclave_config::ConfigLoader::new()
        .without_env()
        .with_yaml("enclave.yaml", yaml)
        .load()
        .expect("an operator's storage section must load and validate");

    // Resolution reports by field path, at startup, exactly as a binary does — so a wrong Vault
    // path fails while somebody is watching the deploy rather than at the first upload.
    let secrets = SecretRegistry::local();
    let resolved = loaded
        .resolve_secrets(&secrets)
        .await
        .expect("the credential references must resolve through the registry");
    assert!(
        resolved.paths().any(|path| path == "storage.s3.secret_access_key"),
        "the S3 secret must be enrolled by field path: {:?}",
        resolved.paths().collect::<Vec<_>>()
    );

    let section = loaded.config().storage.s3.as_ref().expect("provider s3 carries a block");
    let store = S3BlobStore::connect_and_verify(S3Config::from_operator_config(section), &secrets)
        .await
        .expect("the store described by the configuration must connect and be private");

    // Bytes, not a handshake. A `connect` that succeeded against a misconfigured endpoint would
    // still fail the first real read, which is the failure this test exists to make impossible.
    let key = store_an_object(&store, b"hello world").await;

    let bytes = store
        .read_range(key.as_str(), ByteRange::from(0))
        .await
        .expect("read the object back")
        .collect_bounded(1024)
        .await
        .expect("the object is small");
    assert_eq!(&bytes[..], b"hello world");

    store.delete(key.as_str()).await.expect("clean up");
}
