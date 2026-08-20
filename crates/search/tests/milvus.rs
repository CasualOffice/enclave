//! The Milvus candidate generator, against the real thing.
//!
//! # Why these exist when `tests/postfilter.rs` already proves S5
//!
//! They are not the same test and neither replaces the other.
//!
//! `tests/postfilter.rs` proves the *guarantee*: given candidates nothing would ever generate — a
//! deleted file, another tenant's file, a file that does not exist — none of them survive. A fake
//! generator is the only way to state that contract in full, and that file says so.
//!
//! This one proves the *generator we shipped is behind that guarantee*. The interesting question
//! here is not whether the post-filter drops things; it is whether a real Milvus client, with a
//! real filter expression, a real collection and real `acl_tokens`, hands its output to the same
//! [`PostFilter::confirm`] and adds no path around it. The index below is deliberately loaded with
//! `acl_tokens` that name the caller on **every** chunk, including the ones they may not see — the
//! over-permissive index `docs/07-SEARCH-INDEXING.md §6` says correctness may never depend on.
//!
//! # Why most of them are `#[ignore]`
//!
//! Milvus publishes only to Docker Hub, anonymous pulls of it currently return `401`, and
//! `deploy/compose/dev.yml` documents both facts and puts it behind `--profile search` because of
//! them. So these carry the same marker the other infrastructure tests carry and CI runs them with
//! `--include-ignored`.
//!
//! [`a_connection_failure_is_a_state_and_not_an_error`] is deliberately **not** ignored. It needs a
//! closed port and nothing else, and it is the assertion most likely to be broken by a refactor —
//! somebody making the constructor fallible, or mapping a failed connect to `Err`. Leaving that one
//! runnable everywhere is the difference between catching the regression on the machine that
//! introduced it and catching it in CI a day later.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use enclave_authorization::PgAclAuthorization;
use enclave_core::{Actor, FileId, RequestContext, TenantId, UserId};
use enclave_db::{DbPool, TenantScoped};
use enclave_search::vector::{field, VectorIndex, VectorQuery};
use enclave_search::{
    denylist, MilvusConfig, MilvusIndex, PostFilter, Prefilter, Retrieval, VectorStore,
    DEFAULT_DENYLIST_LIMIT,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use milvus::v2 as sdk;
use milvus::v2::prelude::{ConsistencyLevel, FieldData, SparseVector};
use uuid::Uuid;

/// Small enough that the test's vectors are readable, large enough to be a real HNSW index.
const DIMENSION: u32 = 8;

/// A candidate budget far above anything these tests insert, so that a missing result is a
/// retrieval failure and never a truncation (`plans/M3-DISCOVERY.md` D21).
const BUDGET: u32 = 100;

/// Where a developer's Milvus is. The compose stack publishes it on the host.
fn endpoint() -> String {
    std::env::var("MILVUS_URI").unwrap_or_else(|_| "http://127.0.0.1:19530".to_owned())
}

/// A configuration pointing at a collection no other test binary will touch.
///
/// A shared collection name would make two test binaries running concurrently delete each other's
/// documents, and the failure would look like a post-filter that dropped too much — which is the
/// one failure in this crate that must never be dismissed as flakiness.
fn config() -> MilvusConfig {
    let mut config = MilvusConfig::new(endpoint(), DIMENSION);
    config.collection = format!("enclave_test_{}", Uuid::now_v7().simple());
    // Strong, not the production `Bounded`: these tests insert and then immediately search, and
    // under a bounded read that race resolves differently on a loaded machine. See
    // `MilvusConfig::consistency` for why the knob exists rather than the test sleeping.
    config.consistency = ConsistencyLevel::Strong;
    // A tenant per test at most, so the production partition count is memory spent on nothing.
    config.partitions = 2;
    config
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

fn ctx(tenant: TenantId, actor: UserId) -> RequestContext {
    RequestContext { actor: Actor::User(actor), ..RequestContext::system(tenant) }
}

/// A deterministic unit-ish vector whose only job is to be distinct from the others.
fn dense(seed: usize) -> Vec<f32> {
    (0..DIMENSION as usize)
        .map(|axis| if axis == seed % DIMENSION as usize { 1.0 } else { 0.1 })
        .collect()
}

fn sparse(seed: u32) -> SparseVector {
    BTreeMap::from([(seed, 1.0_f32), (seed + 1, 0.5_f32)])
}

/// Writes one chunk per spine, with `acl_tokens` naming `caller` on **every** one of them.
///
/// The tokens are the point. A real index drifts permissive between an ACL write and an index
/// write; this writes the end state of that drift directly, so the candidates that come back are
/// exactly the ones an index at its most wrong would propose. If the post-filter ever started
/// believing them, this is where it would show.
async fn index_chunks(
    client: &sdk::ClientV2,
    collection: &str,
    tenant: TenantId,
    caller: UserId,
    spines: &[Spine],
) {
    let count = spines.len();
    let token = format!("user:{caller}");
    let now = Utc::now().timestamp();

    let columns = vec![
        FieldData::varchar(
            field::CHUNK_ID,
            spines.iter().map(|spine| format!("{}:simple:0", spine.file)).collect(),
        ),
        FieldData::varchar(field::TENANT_ID, vec![tenant.to_string(); count]),
        FieldData::varchar(
            field::WORKSPACE_ID,
            spines.iter().map(|spine| spine.workspace.to_string()).collect(),
        ),
        FieldData::varchar(
            field::LIBRARY_ID,
            spines.iter().map(|spine| spine.library.to_string()).collect(),
        ),
        FieldData::varchar(
            field::FILE_ID,
            spines.iter().map(|spine| spine.file.to_string()).collect(),
        ),
        FieldData::varchar(
            field::VERSION_ID,
            spines.iter().map(|_| Uuid::now_v7().to_string()).collect(),
        ),
        FieldData::varchar(field::CHUNK_TYPE, vec!["BODY".to_owned(); count]),
        // The four nullable fields carry a validity mask; Milvus refuses an insert that supplies a
        // nullable field without one. Note the SDK's contract, which is easy to get backwards: the
        // values vector holds only the *present* rows, so its length must equal the number of
        // `true`s in the mask — not the row count.
        FieldData::varchar(
            field::TITLE,
            spines.iter().map(|spine| format!("document {}", spine.file)).collect(),
        )
        .with_validity(vec![true; count])
        .expect("a title for every row"),
        FieldData::varchar(
            field::TEXT,
            spines.iter().map(|spine| format!("the body of {}", spine.file)).collect(),
        ),
        FieldData::float_vector(field::DENSE_VECTOR, (0..count).map(dense).collect()),
        FieldData::sparse_float_vector(
            field::SPARSE_VECTOR,
            (0..count).map(|seed| sparse(seed as u32)).collect(),
        ),
        FieldData::int32(field::CLASSIFICATION_RANK, vec![0; count]),
        // Wrong on purpose, in the permissive direction, on every row.
        FieldData::array_varchar(field::ACL_TOKENS, vec![vec![token.clone()]; count]),
        FieldData::array_varchar(field::BARRIER_TOKENS, vec![Vec::new(); count]),
        FieldData::int64(field::ACL_EPOCH, vec![1; count]),
        FieldData::varchar(field::MIME_TYPE, vec!["application/pdf".to_owned(); count]),
        FieldData::varchar(field::LANGUAGE, vec!["en".to_owned(); count])
            .with_validity(vec![true; count])
            .expect("a language for every row"),
        FieldData::int32(field::PAGE_NUMBER, vec![1; count]),
        // Genuinely absent rather than an empty string: these rows are PDFs, and a PDF has no
        // sheet name. Writing `""` here would be the sentinel the schema's `varchar` helper exists
        // to avoid, and it would make this test pass without ever exercising a NULL.
        FieldData::varchar(field::SHEET_NAME, Vec::new())
            .with_validity(vec![false; count])
            .expect("no sheet name on any row"),
        FieldData::varchar(field::SECTION_PATH, vec!["/".to_owned(); count])
            .with_validity(vec![true; count])
            .expect("a section path for every row"),
        FieldData::int64(field::MODIFIED_TIMESTAMP, vec![now; count]),
    ];

    client
        .insert(
            sdk::request::dml::InsertRequest::builder()
                .collection_name(collection)
                .columns(columns)
                .build()
                .expect("a valid insert"),
        )
        .await
        .expect("index the chunks");
}

/// Grants one action on a spine's file.
async fn grant_action(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    file: FileId,
    caller: UserId,
    action: &str,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at)
         VALUES ($1, $2, 'FILE', $3, 'USER', $4, $5, 'ALLOW', $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(caller.as_uuid())
    .bind(action)
    .bind(Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("grant");
}

/// **S5, against a real index** — the index proposes three files it believes the caller may see,
/// and exactly one of them reaches them.
///
/// Every chunk carries the caller's `acl_tokens`, so the index's own opinion is that all three are
/// visible. PostgreSQL disagrees about two of them, for the two different reasons that matter: one
/// has no grant at all, and one is on the retrieval denylist with its grant left intact. The
/// surviving file is asserted by identity, not by count, and it is the *middle*-ranked of the three
/// so that a generator returning only its first hit — or a post-filter dropping everything, which
/// looks identical from outside — fails here.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search) and a live PostgreSQL \
            with migrations 0001–0011; CI runs it with --include-ignored"]
async fn s5_an_over_permissive_index_decides_nothing() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let ungranted = Spine::new(alpha);
    let visible = Spine::new(alpha);
    let revoked = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    for spine in [&ungranted, &visible, &revoked] {
        spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    }
    for spine in [&visible, &revoked] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, spine.file, caller, action).await;
        }
    }

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    let client = raw_client().await;
    index_chunks(
        &client,
        &index.config().collection,
        alpha,
        caller,
        &[ungranted, visible, revoked],
    )
    .await;

    // `revoked` keeps its ACL entries: this is the staleness an ACL does not capture — a purge, a
    // re-classification — which is the case `tests/postfilter.rs` isolates and which the denylist
    // is the only thing that catches.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    denylist::suppress(&mut tx, alpha, revoked.file, "content_purged", now, None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");

    let all = Prefilter::unnarrowed();
    let embedding = dense(1);
    let proposed = index
        .candidates(VectorQuery {
            tenant: alpha,
            embedding: &embedding,
            budget: BUDGET,
            prefilter: &all,
        })
        .await
        .expect("the index answers");

    let ids: Vec<FileId> = proposed.iter().map(|candidate| candidate.file_id).collect();
    for expected in [ungranted.file, visible.file, revoked.file] {
        assert!(
            ids.contains(&expected),
            "the index did not propose {expected}, so nothing below is about the post-filter: \
             {ids:?}"
        );
    }

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (confirmed, counts) =
        PostFilter::confirm(&mut tx, &authorization, &ctx(alpha, caller), proposed)
            .await
            .expect("post-filter");
    tx.commit().await.expect("commit");

    let survivors: Vec<FileId> = confirmed.iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        survivors,
        vec![visible.file],
        "the index's acl_tokens were believed by something downstream"
    );
    assert_eq!(counts.proposed, 3);
    assert_eq!(counts.unauthorized, 1, "the ungranted file was dropped by something else");
    assert_eq!(counts.denylisted, 1, "the denylist did not suppress the purged file");

    drop_collection(&client, &index.config().collection).await;
    drop(db);
}

/// `docs/07-SEARCH-INDEXING.md §4`: one Milvus partition key per tenant, read back from the server.
///
/// The schema builder is asserted separately in `src/milvus.rs`, where it runs on every machine.
/// This one asserts the thing that unit test cannot: that Milvus *accepted* the field as a
/// partition key and reports it as one. A schema built correctly and rejected silently would leave
/// every tenant's query scanning every tenant's vectors.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn a_created_collection_carries_the_tenant_partition_key() {
    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");

    assert_eq!(
        index.partition_key().await.expect("describe"),
        Some(field::TENANT_ID.to_owned()),
        "the collection was created without the partition key docs/07 §4 requires"
    );

    // Idempotent: the second call takes the already-exists path, which is the one that runs on
    // every start-up and therefore the one that has to be free of surprises.
    index.ensure_collection().await.expect("provisioning twice changes nothing");
    assert_eq!(index.partition_key().await.expect("describe"), Some(field::TENANT_ID.to_owned()));

    let client = raw_client().await;
    drop_collection(&client, &index.config().collection).await;
}

/// A store that cannot be reached is a **state**, and a query that fails is an **error**.
///
/// Both halves in one test, because the bug is always in the boundary between them rather than in
/// either side. `crate::degraded` forbids a per-request signal from changing the retrieval path, so
/// [`MilvusIndex::candidates`] failing must not quietly become a fallback; and D25 requires an
/// unreachable store to degrade rather than fail, so [`MilvusIndex::reachability`] must not raise.
///
/// Not `#[ignore]`: a closed loopback port is available on every machine, and this is the assertion
/// a well-meaning refactor breaks first.
#[tokio::test]
async fn a_connection_failure_is_a_state_and_not_an_error() {
    // Port 1 is reserved and nothing listens on it, so the connection is refused rather than
    // hanging — which keeps this test fast without relying on the timeout below.
    let mut config = MilvusConfig::new("http://127.0.0.1:1", DIMENSION);
    config.connect_timeout = Duration::from_millis(250);
    let index = MilvusIndex::new(config);

    let health = index.reachability().await;
    assert_eq!(
        health,
        VectorStore::Unreachable,
        "a refused connection was reported as a healthy store"
    );
    assert!(
        matches!(Retrieval::decide(health, 0, DEFAULT_DENYLIST_LIMIT), Retrieval::Degraded(_)),
        "an unreachable store did not engage degraded mode, so the search would have failed \
         instead of falling back"
    );

    // And the other half. A query against the same dead store is an error — never `Ok(vec![])`,
    // which a caller reads as "the tenant has no such document".
    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let outcome = index
        .candidates(VectorQuery {
            tenant: TenantId::new_v7(),
            embedding: &embedding,
            budget: BUDGET,
            prefilter: &all,
        })
        .await;
    assert!(outcome.is_err(), "an unreachable store answered a query with results: {outcome:?}");
}

/// A client for the test's own writes.
///
/// The tests write to the index with the raw SDK rather than through anything in `enclave-search`,
/// and that is deliberate rather than a gap: it lets them write `acl_tokens` no writer of ours
/// would ever produce, which is the same reason `tests/postfilter.rs` uses a fake generator.
async fn raw_client() -> sdk::ClientV2 {
    sdk::ClientV2::new(&sdk::prelude::ConnectConfig::new().uri(endpoint()))
        .await
        .expect("connect to Milvus")
}

/// Removes the test's collection, and does not fail the test if it cannot.
///
/// Cleanup runs after the assertions, so a drop that fails has nothing left to invalidate — and a
/// teardown that panics replaces the real failure with its own, which is how a one-line assertion
/// error becomes an afternoon.
async fn drop_collection(client: &sdk::ClientV2, collection: &str) {
    let request = sdk::request::collection::DropCollectionRequest::builder()
        .collection_name(collection)
        .build()
        .expect("a valid drop");
    if client.drop_collection(request).await.is_err() {
        eprintln!("could not drop {collection}; it is left behind for a human to remove");
    }
}
