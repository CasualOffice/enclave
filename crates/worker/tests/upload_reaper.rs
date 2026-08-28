//! The scheduled upload reaper, against a real PostgreSQL **and a real object store**.
//!
//! `ENC-806`. `crates/uploads/tests/sessions.rs` already proves what `reap_expired` and
//! `reclaim_stranded` do, against a recording stub. What it cannot prove — and what this file is
//! for — is what happens when the pass the worker actually schedules is pointed at a bucket that
//! really deletes things.
//!
//! # Why MinIO and not the stub
//!
//! Because the risk is the store, not the SQL. Since `ENC-691` a staged key **is** the committed
//! version's `object_key` — nothing is copied on commit — so a sweep that claimed a session which
//! did commit issues a real `DeleteObject` against a live file's only copy and leaves
//! `file_versions` pointing at nothing. A stub that records the key it was asked to delete proves
//! the pass *asked*; only a real bucket proves the bytes are still there afterwards, which is the
//! claim anyone would actually want made before this loop ran unattended in a deployment.
//!
//! # The absence trap
//!
//! "No live session is collected" passes for free against a sweep that collects nothing — which is
//! precisely the behaviour this row exists to end, so it is the one assertion that must never stand
//! alone. Every negative below is asserted in the **same run** as a positive control: a genuinely
//! stranded session's object is gone and its row is `EXPIRED` in the same `reap_pass` that leaves
//! the committed one untouched.
//!
//! # Running them
//!
//! ```text
//! export DATABASE_URL=postgres://enclave:enclave@127.0.0.1:55432/enclave
//! export TEST_S3_ENDPOINT=http://127.0.0.1:9000
//! export TEST_S3_ACCESS_KEY_ID=enclave
//! export TEST_S3_SECRET_ACCESS_KEY=…      # the dev stack's MinIO password
//! cargo test -p enclave-worker --test upload_reaper -- --include-ignored
//! ```
//!
//! The credentials are read as `env://` `SecretRef`s, never as literals — the same path the worker
//! binary takes (`CLAUDE.md` rule 11), and the variable names carry no `ENCLAVE_` prefix for the
//! reason `crates/storage/tests/minio.rs` gives at length.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use aws_smithy_http_client::{tls, Connector};
use aws_smithy_runtime_api::client::http::HttpConnector as _;
use aws_smithy_runtime_api::http::Request;
use aws_smithy_types::body::SdkBody;
use chrono::{DateTime, Duration, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId, VersionId};
use enclave_db::{DbPool, TenantScoped};
use enclave_storage::{
    BlobStore, ByteRange, ObjectKey, S3BlobStore, S3Config, S3Flavor, UploadRequest, UploadTarget,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// Attached to every `#[ignore]`, so the harness is named at the test rather than in a comment.
const NEEDS_MINIO: &str =
    "requires a live PostgreSQL and the dev-stack MinIO (TEST_S3_*); CI runs \
                           it with --include-ignored";

const ENDPOINT: &str = "TEST_S3_ENDPOINT";
const ACCESS_KEY: &str = "TEST_S3_ACCESS_KEY_ID";
const SECRET_KEY: &str = "TEST_S3_SECRET_ACCESS_KEY";
/// The dev stack's content bucket. Overridable, because CI's standalone MinIO names its own.
const BUCKET: &str = "TEST_S3_BUCKET";

/// The SHA-256 of the empty string, wherever a well-formed digest is needed.
const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Sixty-four bytes that are recognisably this test's, so a stray object in a shared dev bucket is
/// attributable.
const BODY: &[u8] = b"enclave ENC-806 upload reaper fixture ---------------------------";

// ---------------------------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------------------------

/// The store the worker binary would compose, pointed at the dev bucket.
///
/// `connect_and_verify` rather than `connect`, exactly as `crates/worker/src/main.rs::object_store`
/// does: a bucket that is readable by the world is refused here as well, so this test cannot pass
/// against a configuration the binary would not start on.
async fn store() -> S3BlobStore {
    let endpoint: url::Url = std::env::var(ENDPOINT)
        .unwrap_or_else(|_| panic!("{ENDPOINT} must be set: {NEEDS_MINIO}"))
        .parse()
        .expect("a valid endpoint URL");
    let bucket = std::env::var(BUCKET).unwrap_or_else(|_| "enclave-content".to_owned());

    let config = S3Config::new(
        bucket,
        "us-east-1",
        format!("env://{ACCESS_KEY}").parse().expect("an access-key reference"),
        format!("env://{SECRET_KEY}").parse().expect("a secret-key reference"),
    )
    .with_endpoint(endpoint, S3Flavor::Minio);

    S3BlobStore::connect_and_verify(config, &enclave_config::SecretRegistry::local())
        .await
        .expect("connect to the dev-stack MinIO")
}

/// Starts a database, applies migrations and seeds `tenant-alpha` / `tenant-beta`.
async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("build an application-role pool");
    (db, fixtures, pool)
}

/// Puts [`BODY`] at a fresh version key and returns it.
///
/// Written through the store's own pre-signed single-shot upload — the path a browser takes — so
/// the object under test is one this deployment's credentials and layout actually produced, rather
/// than one an SDK call planted beside them.
async fn stage(store: &S3BlobStore, tenant: TenantId, file: FileId) -> String {
    let key = ObjectKey::version(tenant, file, VersionId::new_v7());
    let session = store
        // No `with_content_type`: the header would be signed into the URL, and the bare `PUT`
        // below would then have to reproduce it exactly or the store answers 400.
        .create_upload(UploadRequest::new(key.clone(), BODY.len() as u64))
        .await
        .expect("open a staged upload");

    // `required_headers` is bound rather than ignored with `..`. `ENC-820` added it to this
    // variant, and every header named there was signed into the URL: a `PUT` that omits one fails
    // the provider's signature check with `403 SignatureDoesNotMatch`. Ignoring the field would
    // compile and would leave this test staging bytes the moment a header becomes mandatory —
    // which is exactly what happened when `content-type` was signed and documented nowhere
    // (`ENC-821`, two attempts to diagnose as a 403).
    let (url, required_headers) = match &session.target {
        UploadTarget::Single { url, required_headers } => (url.clone(), required_headers.clone()),
        other => panic!("a 64-byte object should be single-shot, not {other:?}"),
    };

    // A bare `PUT` to the pre-signed URL, which is what a browser does — `crates/storage/tests/
    // minio.rs`'s `put`, for its reason: the object under test should be one this deployment's own
    // signature produced. `aws-smithy-http-client` rather than a new HTTP dependency, because it is
    // already in the tree underneath `aws-sdk-s3` and shares the store's TLS stack.
    let mut request = Request::new(SdkBody::from(BODY));
    request.set_method("PUT").expect("a valid method");
    request.set_uri(url.as_str()).expect("a valid URI");
    for header in &required_headers {
        request.headers_mut().insert(header.name.clone(), header.value.clone());
    }
    let connector = Connector::builder()
        .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::AwsLc))
        .build();
    let response = connector.call(request).await.expect("the pre-signed PUT reached the endpoint");
    assert!(response.status().is_success(), "staging the object failed: {:?}", response.status());

    key.as_str().to_owned()
}

/// Whether the bucket still holds an object at `key`.
///
/// A one-byte ranged read rather than a `HEAD`, because it goes through [`BlobStore`] — the same
/// interface the reaper deletes through — so "present" and "deleted" are two answers from one
/// client rather than from two.
async fn present(store: &S3BlobStore, key: &str) -> bool {
    store.read_range(key, ByteRange::sized(0, 1).expect("a one-byte range")).await.is_ok()
}

/// Inserts an `upload_sessions` row in whatever state the test needs.
///
/// Written as SQL rather than driven through `UploadService`, and the reason is worth stating: this
/// crate does not depend on `enclave-libraries`, and the states under test — a session abandoned
/// mid-upload, a session stranded before `ENC-691` — are ones the *current* service can no longer
/// produce. `crates/uploads/tests/sessions.rs` covers what the live path writes; what this file
/// needs is the backlog a deployment already has.
#[allow(clippy::too_many_arguments)]
async fn session(
    conn: &mut PgConnection,
    tenant: TenantId,
    library: LibraryId,
    owner: UserId,
    name: &str,
    staged_key: &str,
    state: &str,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO upload_sessions
           (tenant_id, id, library_id, parent_id, file_id, name, declared_size, declared_mime,
            staged_key, multipart_id, state, bytes_received, created_by, created_at, updated_at,
            expires_at)
         VALUES ($1, $2, $3, NULL, NULL, $4, 64, 'text/plain', $5, NULL, $6, 0, $7, $8, $8, $9)",
    )
    .bind(tenant.as_uuid())
    .bind(id)
    .bind(library.as_uuid())
    .bind(name)
    .bind(staged_key)
    .bind(state)
    .bind(owner.as_uuid())
    .bind(updated_at)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .expect("insert the upload session");
    id
}

/// Writes the `file_versions` row a *correctly completed* upload leaves behind.
///
/// This row is the whole control. `ENC-691` makes the staged key the version's `object_key`
/// verbatim, so it is what stands between the reclaim and a live file's only copy of its bytes.
async fn commit_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    object_key: &str,
    owner: UserId,
) {
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 64, $6, 'text/plain', 1, 0, 'SCANNING', 'PENDING', $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(object_key)
    .bind(Uuid::nil())
    .bind(DIGEST_HEX)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert the version row");
}

/// The `state` column, read straight out, so an assertion is about the row and not this crate's
/// opinion of it.
async fn state_of(conn: &mut PgConnection, id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT state FROM upload_sessions WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .expect("read the state column")
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

/// One sweep, five sessions, real bytes in a real bucket: what goes, and what must not.
///
/// | session | state | why | expected |
/// |---|---|---|---|
/// | abandoned | `CREATED`, past its TTL | a client that vanished mid-upload | object deleted, row `EXPIRED` |
/// | stranded | `SCANNING`, idle, no version | the pre-`ENC-691` backlog | object deleted, row `EXPIRED` |
/// | committed | `SCANNING`, idle, **with** a version naming its key | a real file | **object survives**, row `SCANNING` |
/// | live | `CREATED`, TTL in the future | an upload in progress right now | object survives, row `CREATED` |
/// | fresh | `SCANNING`, handed off just now | a completion in flight | object survives, row `SCANNING` |
///
/// The first two are the positive controls and they are what stops the other three passing for
/// free: "nothing live was collected" is exactly what a reaper nobody calls achieves, which was the
/// state of every deployment before this row (`ENC-806`).
///
/// The committed row is the assertion that would cost a customer a file. It differs from the
/// stranded one in exactly one fact — a `file_versions` row naming its staged key — and both keys
/// hold real objects in MinIO, so the difference between the two outcomes is the store's behaviour
/// and not a stub's bookkeeping.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and the dev-stack MinIO (TEST_S3_*); CI runs it with --include-ignored"]
async fn a_stranded_sessions_object_is_deleted_and_a_committed_ones_survives() {
    let store = store().await;
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let now = Utc::now();

    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, owner, now).await.expect("insert the spine");

    let abandoned_key = stage(&store, tenant, spine.file).await;
    let stranded_key = stage(&store, tenant, spine.file).await;
    let committed_key = stage(&store, tenant, spine.file).await;
    let live_key = stage(&store, tenant, spine.file).await;
    let fresh_key = stage(&store, tenant, spine.file).await;

    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    let long_ago = now - Duration::hours(48);
    let abandoned = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "abandoned.txt",
        &abandoned_key,
        "CREATED",
        long_ago,
        now - Duration::hours(24),
    )
    .await;
    let stranded = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "stranded.txt",
        &stranded_key,
        "SCANNING",
        long_ago,
        now + Duration::hours(24),
    )
    .await;
    let committed = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "committed.txt",
        &committed_key,
        "SCANNING",
        long_ago,
        now + Duration::hours(24),
    )
    .await;
    let live = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "live.txt",
        &live_key,
        "CREATED",
        now,
        now + Duration::hours(24),
    )
    .await;
    let fresh = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "fresh.txt",
        &fresh_key,
        "SCANNING",
        now,
        now + Duration::hours(24),
    )
    .await;
    commit_version(&mut tx, tenant, spine.file, &committed_key, owner).await;
    tx.commit().await.expect("commit the fixtures");

    // Every object is really there before the sweep. Without this the "survives" assertions below
    // would be satisfied by a staging step that silently wrote nothing.
    for key in [&abandoned_key, &stranded_key, &committed_key, &live_key, &fresh_key] {
        assert!(present(&store, key).await, "the fixture object {key} was never staged");
    }

    let pass =
        enclave_worker::uploads::reap_pass(&pool, tenant, &store, now, Duration::hours(1), 100)
            .await
            .expect("the reaping pass");

    // **The bucket first, and the report afterwards.** The order is deliberate: a report is this
    // code's account of what it did, and the assertion worth failing on is what the store actually
    // holds. Breaking the version guard in `UploadRepository::claim_stranded` makes both fail, and
    // the message that should reach whoever broke it is the one about a customer's file, not the one
    // about a count being 2 instead of 1.
    //
    // The two positives lead, so a store that deleted nothing fails here rather than passing every
    // negative below for free.
    assert!(!present(&store, &abandoned_key).await, "an abandoned upload's bytes must be released");
    assert!(!present(&store, &stranded_key).await, "a stranded session's bytes must be released");

    assert!(
        present(&store, &committed_key).await,
        "the staged key IS the version's object_key: deleting it destroys a live file's only copy"
    );
    assert!(present(&store, &live_key).await, "an upload still inside its TTL keeps its bytes");
    assert!(present(&store, &fresh_key).await, "a completion in flight keeps its bytes");

    assert_eq!(
        (pass.expired.claimed, pass.expired.released, pass.expired.deferred),
        (1, 1, 0),
        "exactly the abandoned session, and it was actually released"
    );
    assert_eq!(
        (pass.stranded.found, pass.stranded.reclaimed, pass.stranded.deferred),
        (1, 1, 0),
        "exactly the stranded session, and it was actually reclaimed"
    );

    // And the rows.
    let mut conn = db.connect().await.expect("connect");
    assert_eq!(state_of(&mut conn, abandoned).await, "EXPIRED");
    assert_eq!(state_of(&mut conn, stranded).await, "EXPIRED");
    assert_eq!(
        state_of(&mut conn, committed).await,
        "SCANNING",
        "a session with a version behind it belongs to antivirus, not to the reaper"
    );
    assert_eq!(state_of(&mut conn, live).await, "CREATED");
    assert_eq!(state_of(&mut conn, fresh).await, "SCANNING");

    // Clean up what the sweep deliberately left, so a shared dev bucket does not accumulate this
    // test's fixtures. Not an assertion — a failure here would mask the ones above.
    for key in [&committed_key, &live_key, &fresh_key] {
        let _ignored = store.delete(key).await;
    }

    pool.close().await;
    drop(db);
}

/// A second sweep finds nothing and deletes nothing.
///
/// Idempotence is not a nicety here: the loop re-ticks immediately whenever a batch comes back
/// full, so a pass that could claim its own output would delete, mark, and claim the same rows
/// again. Both predicates are self-consuming — an `EXPIRED` row matches neither — and this is that
/// property against the real store, with the first run as its positive control.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and the dev-stack MinIO (TEST_S3_*); CI runs it with --include-ignored"]
async fn a_second_sweep_over_the_same_tenant_finds_nothing_left() {
    let store = store().await;
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let now = Utc::now();

    let spine = Spine::new(tenant);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, owner, now).await.expect("insert the spine");

    let key = stage(&store, tenant, spine.file).await;
    let mut tx = TenantScoped::begin(&pool, tenant).await.expect("begin");
    let id = session(
        &mut tx,
        tenant,
        spine.library,
        owner,
        "abandoned.txt",
        &key,
        "UPLOADING",
        now - Duration::hours(48),
        now - Duration::hours(24),
    )
    .await;
    tx.commit().await.expect("commit");

    let first =
        enclave_worker::uploads::reap_pass(&pool, tenant, &store, now, Duration::hours(1), 100)
            .await
            .expect("the first pass");
    assert_eq!(first.released(), 1, "the positive control: the first pass released it");
    assert!(!present(&store, &key).await);

    let second =
        enclave_worker::uploads::reap_pass(&pool, tenant, &store, now, Duration::hours(1), 100)
            .await
            .expect("the second pass");
    assert_eq!(
        (second.expired.claimed, second.stranded.found, second.released(), second.deferred()),
        (0, 0, 0, 0),
        "an EXPIRED row must match neither predicate again"
    );

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(state_of(&mut conn, id).await, "EXPIRED");

    pool.close().await;
    drop(db);
}

/// Another tenant's expired session is invisible, and this tenant's is released in the same run.
///
/// **Isolation layer**, and stated as such: row-level security, the `tenant_id = $1` predicate and
/// the `TenantScoped` context each refuse this independently, so it would still pass with any one of
/// them removed — `ENC-787`'s ninth finding was exactly that. It is asserted because a pass that
/// deletes object bytes is the worst possible place for a tenant predicate to be missing, and
/// because here the consequence is not a leak but a *destruction*: alpha's sweep reaching beta's key
/// would delete beta's bytes. The same-run positive control is what stops it passing against a sweep
/// that collects nothing.
///
/// **Confirmed by breaking it, and it did not break.** Replacing `tenant_id = $1` in `SELECT_EXPIRED`
/// with a tautology leaves this test green — row-level security refuses beta's row on its own. That
/// is the tenth time in this repository (`ENC-787` recorded the ninth), and it is why the assertion
/// that actually guards the predicate is
/// `enclave_uploads::repo::tests::every_statement_carries_the_application_tenant_predicate`, which
/// does fail on that edit. This test proves isolation; that one proves the layer.
#[tokio::test]
#[ignore = "requires a live PostgreSQL and the dev-stack MinIO (TEST_S3_*); CI runs it with --include-ignored"]
async fn one_tenants_sweep_cannot_reach_anothers_staged_bytes() {
    let store = store().await;
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let now = Utc::now();
    let expired_at = now - Duration::hours(24);
    let long_ago = now - Duration::hours(48);

    let alpha_spine = Spine::new(alpha);
    let beta_spine = Spine::new(beta);
    let mut admin = db.connect().await.expect("admin connection");
    alpha_spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("alpha spine");
    beta_spine.insert(&mut admin, fixtures.beta.owner, now).await.expect("beta spine");

    let alpha_key = stage(&store, alpha, alpha_spine.file).await;
    let beta_key = stage(&store, beta, beta_spine.file).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let alpha_id = session(
        &mut tx,
        alpha,
        alpha_spine.library,
        fixtures.alpha.owner,
        "alpha.txt",
        &alpha_key,
        "CREATED",
        long_ago,
        expired_at,
    )
    .await;
    tx.commit().await.expect("commit alpha");

    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let beta_id = session(
        &mut tx,
        beta,
        beta_spine.library,
        fixtures.beta.owner,
        "beta.txt",
        &beta_key,
        "CREATED",
        long_ago,
        expired_at,
    )
    .await;
    tx.commit().await.expect("commit beta");

    // Alpha's sweep. Beta's session differs in no way that matters — it is another tenant's.
    let pass =
        enclave_worker::uploads::reap_pass(&pool, alpha, &store, now, Duration::hours(1), 100)
            .await
            .expect("alpha's pass");

    assert_eq!(pass.expired.released, 1, "alpha's own, and only alpha's");
    assert!(!present(&store, &alpha_key).await);
    assert!(present(&store, &beta_key).await, "beta's staged bytes must not be touched");

    let mut conn = db.connect().await.expect("connect");
    assert_eq!(state_of(&mut conn, alpha_id).await, "EXPIRED");
    assert_eq!(state_of(&mut conn, beta_id).await, "CREATED");

    let _ignored = store.delete(&beta_key).await;
    pool.close().await;
    drop(db);
}
