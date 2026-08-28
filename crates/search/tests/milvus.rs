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
use enclave_search::health::{self, Expected, IndexCensus, IndexHealth};
use enclave_search::vector::{field, VectorIndex, VectorQuery};
use enclave_search::{
    denylist, Cause, Excerpt, Highlights, MilvusConfig, MilvusIndex, PostFilter, Prefilter,
    Retrieval, VectorStore, DEFAULT_COVERAGE_FLOOR, DEFAULT_DENYLIST_LIMIT,
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
    let bodies: Vec<String> =
        spines.iter().map(|spine| format!("the body of {}", spine.file)).collect();
    index_chunks_with_text(client, collection, tenant, caller, spines, bodies).await;
}

/// As [`index_chunks`], with the chunk bodies supplied.
///
/// Split out for `ENC-538`, whose question is entirely about how much of a chunk's `text` reaches a
/// candidate — so that test needs a chunk the size the chunker really produces, and every other test
/// here needs a body short enough to read in a failure message.
async fn index_chunks_with_text(
    client: &sdk::ClientV2,
    collection: &str,
    tenant: TenantId,
    caller: UserId,
    spines: &[Spine],
    bodies: Vec<String>,
) {
    let count = spines.len();
    assert_eq!(bodies.len(), count, "one body per spine");
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
        FieldData::varchar(field::TEXT, bodies),
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

/// **S6, against a real index** (`docs/12 §4.3`) — a `MetadataRead`-only caller gets the dense hit
/// and no excerpt, and cannot tell that from a chunk that had nothing to quote.
///
/// `ENC-541`. The gate is literally the same [`PostFilter::confirm`] the lexical S6 test exercises,
/// so this is coverage rather than a second mechanism — but `ENC-538` made this path produce
/// excerpts that are **new objects**, cut here from the chunk's `text` by `excerpt::preview` rather
/// than passed through, and the assertion that they are withheld is worth running against candidates
/// a real Milvus produced rather than inferring it from the lexical case.
///
/// Three files, and the third is the reason the test is worth running:
///
/// - `withheld` has a chunk of body text and the caller holds `file.metadata_read` alone. There is a
///   quotation and they do not get it.
/// - `unquotable` is indexed with an **empty** `text`. That is a legitimate state rather than a
///   contrivance — `milvus::decode` says so, because a metadata-only update writes scalars and
///   vectors and leaves the body alone — and it is the dense path's version of the lexical path's
///   name-only match: a hit with nothing to quote. The caller holds both actions and still receives
///   no excerpt.
/// - `readable` is the **positive control**. Without it every assertion here passes against a
///   decoder returning `None` for everything, which is `docs/12 §1.2`'s recurring shape and which
///   `ENC-538` already caught once on this exact path.
///
/// As everywhere in this file the index's `acl_tokens` name the caller on all three, so the index's
/// own opinion is that everything is fully visible and PostgreSQL is the only thing saying otherwise.
///
/// The difference between the first two exists in exactly one place and it is operator-facing:
/// `DropCounts::excerpt_withheld`. Nothing the caller receives distinguishes them.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search) and a live PostgreSQL \
            with migrations 0001–0011; CI runs it with --include-ignored"]
async fn s6_a_metadata_only_caller_gets_no_excerpt_from_a_dense_candidate() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let (withheld, unquotable, readable) =
        (Spine::new(alpha), Spine::new(alpha), Spine::new(alpha));
    let body = "Clause 7.2(b) sets out the perihelion review procedure.".to_owned();

    let mut admin = db.connect().await.expect("admin connection");
    for spine in [&withheld, &unquotable, &readable] {
        spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    }
    grant_action(&mut admin, alpha, withheld.file, caller, "file.metadata_read").await;
    for spine in [&unquotable, &readable] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, spine.file, caller, action).await;
        }
    }

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    let client = raw_client().await;
    index_chunks_with_text(
        &client,
        &index.config().collection,
        alpha,
        caller,
        &[withheld, unquotable, readable],
        vec![body.clone(), String::new(), body.clone()],
    )
    .await;

    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let proposed = index
        .candidates(VectorQuery {
            tenant: alpha,
            embedding: &embedding,
            budget: BUDGET,
            prefilter: &all,
        })
        .await
        .expect("the index answers");

    // The generator's half, asserted before the post-filter's: the excerpt this test is about must
    // exist in the candidate, or "withheld" below is indistinguishable from "never produced".
    let candidate = proposed
        .iter()
        .find(|candidate| candidate.file_id == withheld.file)
        .unwrap_or_else(|| panic!("the index did not propose {}: {proposed:?}", withheld.file));
    assert!(
        candidate.excerpt.is_some(),
        "the candidate carries no excerpt, so the post-filter has nothing to withhold and this \
         test proves nothing"
    );

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (confirmed, counts) =
        PostFilter::confirm(&mut tx, &authorization, &ctx(alpha, caller), proposed)
            .await
            .expect("post-filter");
    tx.commit().await.expect("commit");

    let hit = |file: FileId| -> &enclave_search::Confirmed {
        confirmed
            .iter()
            .find(|hit| hit.file_id == file)
            .unwrap_or_else(|| panic!("{file} is not among the hits: {confirmed:?}"))
    };

    // The control, first. A caller holding `ContentRead` over a chunk with text receives the
    // quotation, and it is that chunk's text.
    let quotation =
        hit(readable.file).excerpt.clone().expect("the control must receive its excerpt");
    assert!(
        body.starts_with(quotation.text().trim_end_matches('…')),
        "the control's excerpt is not text from its chunk: {shown:?}",
        shown = quotation.text()
    );

    assert_eq!(
        hit(withheld.file).excerpt,
        None,
        "the excerpt reached a caller who may know the document exists and may not read it"
    );
    assert_eq!(
        hit(unquotable.file).excerpt,
        None,
        "a chunk indexed with no text has nothing to quote"
    );
    assert_eq!(
        hit(withheld.file).excerpt,
        hit(unquotable.file).excerpt,
        "a withheld excerpt is distinguishable from an absent one, which tells the caller there is \
         content here they may not see"
    );

    assert_eq!(confirmed.len(), 3, "all three are visible hits: {confirmed:?}");
    assert_eq!(counts.unauthorized, 0, "nobody was dropped; only an excerpt was");
    assert_eq!(
        counts.excerpt_withheld, 1,
        "the withheld quotation was not reported; an operator cannot see the ContentRead gate firing"
    );

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

/// **`ENC-516`, against the real thing.** A live, healthy, *empty* collection degrades a tenant
/// PostgreSQL says is indexed.
///
/// This is the state the reachability trigger cannot see and the one the milestone is arranged
/// against: Milvus is up, `has_collection` succeeds, the circuit is closed, and the tenant's
/// partition holds nothing because somebody recreated the collection. Every existing signal reports
/// health. The response would say `degraded: false` and return almost nothing.
///
/// Both directions are asserted from the same live collection, because the assertion that carries
/// the weight is the difference: chunks are then inserted for the same tenant and the same probe has
/// to come back `Complete`. A probe that degraded unconditionally would pass the first half.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search) and a live PostgreSQL \
            with migrations 0001–0014; CI runs it with --include-ignored"]
async fn a_live_but_empty_collection_degrades_a_tenant_that_postgres_says_is_indexed() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let now = Utc::now();

    let indexed = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    indexed.insert(&mut admin, owner, now).await.expect("spine");
    // PostgreSQL's record of a successful indexing run: one READY manifest, one chunk.
    manifest(&mut admin, alpha, &indexed, owner, 1).await;

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");

    // The collection exists and is loaded, so reachability is honest and unhelpful.
    assert_eq!(
        index.reachability().await,
        VectorStore::Available,
        "the store is up; if this said otherwise the rest of the test proves nothing"
    );

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let empty = health::probe(&mut tx, alpha, &index, DEFAULT_COVERAGE_FLOOR)
        .await
        .expect("probe the empty collection");
    tx.commit().await.expect("commit");

    let decision = Retrieval::decide(empty.store_state(), 0, DEFAULT_DENYLIST_LIMIT);
    let Retrieval::Degraded(reason) = decision else {
        panic!("a live, empty collection answered `degraded: false`: {decision:?}");
    };
    assert_eq!(
        reason.cause(),
        Cause::IndexDepleted { expected_chunks: 1, observed_chunks: 0 },
        "the cause must name the hole rather than the connection"
    );

    // Now index the chunk PostgreSQL said was there, and the same probe has to stop degrading.
    let client = raw_client().await;
    index_chunks(&client, &index.config().collection, alpha, fixtures.alpha.member, &[indexed])
        .await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let stocked = health::probe(&mut tx, alpha, &index, DEFAULT_COVERAGE_FLOOR)
        .await
        .expect("probe the populated collection");
    tx.commit().await.expect("commit");

    assert_eq!(
        Retrieval::decide(stocked.store_state(), 0, DEFAULT_DENYLIST_LIMIT),
        Retrieval::Complete,
        "a store holding what PostgreSQL expects degraded anyway, which would make every search \
         degraded and the flag meaningless"
    );

    drop_collection(&client, &index.config().collection).await;
    drop(db);
}

/// The census counts one tenant's chunks, not the collection's.
///
/// The failure this catches is a single missing clause: without the partition-key predicate, a
/// tenant whose own chunks are entirely gone reads as fully stocked on the strength of everybody
/// else's data — the health signal reporting green *because* another tenant is healthy. `beta` is
/// loaded and `alpha` is empty, so a census that ignored the tenant returns a non-zero count here.
/// Deliberately needs **no PostgreSQL**. The question is entirely about what the store counts, and
/// the fewer moving parts stand between the assertion and the answer, the harder it is to explain a
/// failure away. `Spine` is used here only as a bundle of identifiers to write into the index; no
/// row is inserted anywhere.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn a_census_counts_only_the_tenant_it_was_asked_about() {
    let (alpha, beta) = (TenantId::new_v7(), TenantId::new_v7());
    let theirs = Spine::new(beta);

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    let client = raw_client().await;
    index_chunks(&client, &index.config().collection, beta, UserId::new_v7(), &[theirs]).await;

    assert_eq!(
        index.chunks(beta).await.expect("census beta"),
        1,
        "the collection does not hold beta's chunk, so the zero below would mean nothing"
    );
    assert_eq!(
        index.chunks(alpha).await.expect("census alpha"),
        0,
        "alpha's census counted another tenant's chunks, so an emptied alpha partition would read \
         as healthy on the strength of beta's data"
    );

    // And the consequence, spelled out against the comparison that uses it: alpha has manifests
    // claiming forty chunks and none of its own in the store, so it degrades even though the
    // collection is not empty.
    let alpha_is_missing = IndexHealth::assess(
        Expected::Chunks(40),
        index.chunks(alpha).await.expect("census alpha"),
        DEFAULT_COVERAGE_FLOOR,
    );
    assert!(
        matches!(
            Retrieval::decide(alpha_is_missing.store_state(), 0, DEFAULT_DENYLIST_LIMIT),
            Retrieval::Degraded(_)
        ),
        "a tenant whose chunks are gone stayed complete because the collection holds someone \
         else's"
    );

    drop_collection(&client, &index.config().collection).await;
}

/// A chunk of about the size `ChunkBudget::max_chars` produces, so that a budget assertion over one
/// is a real cut rather than a formality.
fn full_chunk() -> String {
    let mut chunk = String::from(
        "Section 4.1 Allowances. Employees may claim the standard allowance each quarter, subject \
         to approval by their line manager. ",
    );
    while chunk.chars().count() < 3_000 {
        chunk.push_str(
            "Nothing in this section affects the statutory minimum, and the appendix governs \
             where the two disagree. ",
        );
    }
    chunk
}

/// **`ENC-538`, against the real thing.** A dense hit carries a *quotation* of its chunk, not the
/// chunk.
///
/// The defect this closes was in the decoder and nowhere else: `text` was passed through untouched,
/// so a caller received up to 3 200 characters of document body from a healthy store and 240 from a
/// degraded one, for the same document. `src/excerpt.rs` proves the cutter; only a live search
/// proves that the decoder calls it, which is where the bug actually was.
///
/// Two documents, and the short one is the point as much as the long one. Every assertion about the
/// long chunk's excerpt being *smaller* than the chunk passes for free against a decoder that
/// returns `None` for everything — `docs/12 §1.2` — so the short document is the positive control:
/// it must arrive with its body intact and unmarked.
///
/// Deliberately needs no PostgreSQL. The question is what the generator produces, and `Spine` is
/// used here only as a bundle of identifiers to write into the index.
#[tokio::test]
#[ignore = "requires a live Milvus (deploy/compose/dev.yml --profile search); CI runs it with \
            --include-ignored"]
async fn a_dense_hit_quotes_its_chunk_rather_than_carrying_all_of_it() {
    let tenant = TenantId::new_v7();
    let caller = UserId::new_v7();
    let (long, short) = (Spine::new(tenant), Spine::new(tenant));

    let body = full_chunk();
    let note = "A short note about tantalum.".to_owned();
    assert!(
        body.chars().count() > enclave_search::excerpt::MAX_CHARS * 4,
        "the fixture is not large enough for the assertions below to mean anything: {} characters",
        body.chars().count()
    );

    let index = MilvusIndex::new(config());
    index.ensure_collection().await.expect("provision the collection");
    let client = raw_client().await;
    index_chunks_with_text(
        &client,
        &index.config().collection,
        tenant,
        caller,
        &[long, short],
        vec![body.clone(), note.clone()],
    )
    .await;

    let all = Prefilter::unnarrowed();
    let embedding = dense(0);
    let proposed = index
        .candidates(VectorQuery { tenant, embedding: &embedding, budget: BUDGET, prefilter: &all })
        .await
        .expect("the index answers");

    let excerpt = |file: FileId| -> Option<Excerpt> {
        proposed
            .iter()
            .find(|candidate| candidate.file_id == file)
            .unwrap_or_else(|| {
                panic!(
                    "the index did not propose {file}, so nothing here is about \
                                       the excerpt: {proposed:?}"
                )
            })
            .excerpt
            .clone()
    };

    // The control. An ordinary chunk arrives whole, unmarked, and character for character.
    assert_eq!(
        excerpt(short.file).as_ref().map(Excerpt::text),
        Some(note.as_str()),
        "a chunk that fits the budget did not survive the decoder intact, so every assertion \
         below could be satisfied by dropping excerpts altogether"
    );

    let quoted = excerpt(long.file).expect("a chunk of document body carries an excerpt");
    assert!(
        quoted.text().chars().count() <= enclave_search::excerpt::MAX_CHARS + 2,
        "the decoder passed the chunk through: {} characters against a budget of {}",
        quoted.text().chars().count(),
        enclave_search::excerpt::MAX_CHARS
    );
    assert!(
        quoted.text().ends_with('…'),
        "text was dropped from the end and not marked as elided: {:?}",
        quoted.text()
    );
    let trimmed = quoted.text().trim_end_matches('…');
    assert!(
        body.starts_with(trimmed),
        "the excerpt is not verbatim text from the head of the chunk: {trimmed:?}"
    );

    // **`ENC-542`.** A dense hit has no matched span, so it carries no offsets — and says which
    // kind of nothing that is. `Terms(vec![])` would mean the locator ran and found nothing; the
    // truth is that there was never a narrower span to find, because the matched unit is the chunk.
    // A renderer reading `Unlocated` marks nothing, rather than marking the whole passage.
    for hit in [&quoted, &excerpt(short.file).expect("the control carries an excerpt")] {
        assert_eq!(
            hit.highlights(),
            &Highlights::Unlocated,
            "a dense candidate claims located matches: {shown:?}",
            shown = hit.text()
        );
    }

    drop_collection(&client, &index.config().collection).await;
}

/// Writes the `file_versions` row and the `READY` manifest that says the file was indexed.
///
/// The manifest is PostgreSQL's half of the coverage signal: `chunk_count` is what the store is
/// then measured against.
async fn manifest(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    spine: &Spine,
    owner: UserId,
    chunk_count: i32,
) {
    let version = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 1024, 'deadbeef', 'application/pdf', 1, 0, 'AVAILABLE',
                 'CLEAN', $6, $7)",
    )
    .bind(version)
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("tenants/{}/blobs/{version}", tenant.as_uuid()))
    .bind(Uuid::now_v7())
    .bind(owner.as_uuid())
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("a version for the manifest to name");

    sqlx::query(
        "INSERT INTO index_manifests
           (tenant_id, file_id, version_id, index_version, extractor_version, chunker_version,
            embedding_model, status, chunk_count, updated_at)
         VALUES ($1, $2, $3, 1, 'v1', 'v1', 'local-test', 'READY', $4, $5)",
    )
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(version)
    .bind(chunk_count)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("the manifest");
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
