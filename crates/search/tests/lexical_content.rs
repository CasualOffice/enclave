//! `ENC-515` — degraded search finds a document by what it *says*, and still only for people
//! allowed to know it exists.
//!
//! # Why this is a separate file from `tests/degraded.rs`
//!
//! That file is about the fallback: when it engages, what the flag means, what it refuses to
//! propose. This one is about the half of it that did not exist — content — and it is the half that
//! changes the security question, because chunk text is document content rather than a filename.
//!
//! The two things it has to establish are therefore not symmetrical:
//!
//! 1. **Recall.** A word that appears only in the body finds the file. Before migration 0013 the
//!    lexical path searched names and scalar metadata only, so a contract whose body said
//!    *indemnity* was invisible unless that word was in its filename — invisible in exactly the
//!    circumstance degraded mode exists for.
//! 2. **That nothing about authorization moved.** `CLAUDE.md` rule 5 and `plans/M3-DISCOVERY.md`
//!    D25: a degraded path is a worse *recall* guarantee, never a worse *authorization* one. Content
//!    matching widens what the generator proposes, and every candidate it proposes still goes
//!    through `PostFilter::confirm`.
//!
//! # The text is written by the writer that ships
//!
//! `enclave_indexing::write_chunks` puts the rows here, not an `INSERT` spelled out in this file.
//! `ENC-515` is one table written by one crate and read by another, and the failure worth catching
//! is the two disagreeing about it — a column named differently, an expression that does not match
//! the index, a tenant column the writer fills and the reader ignores. A test that writes its own
//! rows cannot see any of that; it proves the reader agrees with the test author.
//!
//! Ignored by default: they need a live PostgreSQL with migrations `0001`–`0013`. CI runs them with
//! `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_authorization::PgAclAuthorization;
use enclave_core::{Actor, FileId, RequestContext, TenantId, UserId, VersionId};
use enclave_db::{DbPool, TenantScoped};
use enclave_indexing::{
    write_chunks, Chunk, ChunkBudget, Chunker, ChunkerVersion, Coordinates, Segment, SegmentKind,
};
use enclave_search::{
    lexical, DegradedReason, Retrieval, SearchResults, VectorStore, DEFAULT_DENYLIST_LIMIT,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// A generous candidate budget, for the reason `tests/degraded.rs` gives: the post-filter drops, so
/// a short page must never be a truncation in these tests.
const BUDGET: u32 = 100;

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test-1");

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

fn ctx(tenant: TenantId, actor: UserId) -> RequestContext {
    RequestContext { actor: Actor::User(actor), ..RequestContext::system(tenant) }
}

/// The reason a test is in degraded mode, obtained the only way it can be.
fn store_is_down() -> DegradedReason {
    match Retrieval::decide(VectorStore::Unreachable, 0, DEFAULT_DENYLIST_LIMIT) {
        Retrieval::Degraded(reason) => reason,
        Retrieval::Complete => panic!("an unreachable vector store must degrade"),
    }
}

/// A file whose *name says nothing*, with `body` as its extracted text.
///
/// The name is deliberately anodyne and identical in shape across every fixture here, so a hit can
/// only have come from the chunk store. If these tests named files after their contents they would
/// pass just as well against the pre-`ENC-515` implementation.
async fn file_with_body(
    admin: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    name: &str,
    body: &str,
) -> FileId {
    let now = Utc::now();
    let spine = Spine::new(tenant);
    spine.insert(&mut *admin, owner, now).await.expect("spine");

    sqlx::query("UPDATE files SET name = $2, normalized_name = lower($2) WHERE id = $1")
        .bind(spine.file.as_uuid())
        .bind(name)
        .execute(&mut *admin)
        .await
        .expect("rename");

    let version = insert_version(&mut *admin, tenant, spine.file, owner, 1).await;
    let chunker = Chunker::new(CHUNKER, ChunkBudget { target_chars: 1, ..ChunkBudget::DEFAULT });
    let chunks: Vec<Chunk> = chunker.chunk(
        version,
        &[Segment {
            kind: SegmentKind::Paragraph,
            text: body.to_owned(),
            coordinates: Coordinates::none(),
        }],
    );
    assert!(!chunks.is_empty(), "the fixture produced no chunks to store");
    write_chunks(&mut *admin, tenant, spine.file, version, CHUNKER, &chunks)
        .await
        .expect("store chunk text");

    spine.file
}

async fn insert_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    owner: UserId,
    major: i32,
) -> VersionId {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 12, 'deadbeef', 'text/plain', $6, 0, 'AVAILABLE', $7, $8)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(format!("objects/{id}"))
    .bind(Uuid::nil())
    .bind(major)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("version");
    VersionId::from(id)
}

/// Grants one action on one file, as the other suites here do.
async fn grant_action(
    conn: &mut PgConnection,
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

/// Runs the degraded search a caller would get with the vector store down.
async fn search(pool: &DbPool, tenant: TenantId, caller: UserId, query: &str) -> SearchResults {
    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, tenant, query, BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(tenant, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");
    results
}

/// **The gap `ENC-515` names** — a word that appears only in the body finds the document.
///
/// Two files, indistinguishable by name and by metadata. One's text contains `indemnity`; the
/// other's does not. Both are fully granted, so nothing here is about permissions: this is the
/// recall assertion, and the neighbour is what stops a generator that proposes everything from
/// passing it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_word_that_appears_only_in_the_body_finds_the_document() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let contract = file_with_body(
        &mut admin,
        alpha,
        fixtures.alpha.owner,
        "agreement-one.txt",
        "The supplier shall provide an indemnity against third-party claims.",
    )
    .await;
    let other = file_with_body(
        &mut admin,
        alpha,
        fixtures.alpha.owner,
        "agreement-two.txt",
        "The supplier shall deliver the goods on the agreed date.",
    )
    .await;

    for file in [contract, other] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }

    let results = search(&pool, alpha, caller, "indemnity").await;

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![contract],
        "the word is in one document's text and in neither filename; got {found:?}"
    );
    assert!(results.is_degraded(), "a content hit on the lexical path is still a degraded result");

    drop(db);
}

/// **S5, through the content half** — a caller who may not see a file does not get it by its text.
///
/// Three files whose bodies all contain the word, one of them in `tenant-beta`. The caller is
/// granted on exactly one of alpha's two.
///
/// Both numbers are asserted, and they check different things. `proposed == 2` says beta's file
/// never became a candidate even though its text matched as well as any other, so the post-filter is
/// not carrying tenant isolation on its own. `unauthorized == 1` says the post-filter did drop the
/// ungranted one, rather than the generator having quietly returned a single row for an unrelated
/// reason.
///
/// **What `proposed == 2` does not isolate**, stated because it was checked rather than assumed:
/// removing the `c.tenant_id = $1` predicate from the content CTE leaves this assertion green.
/// Three mechanisms exclude beta's file here — row-level security on `chunk_text` under the
/// caller's tenant-scoped transaction, the outer `f.tenant_id = $1`, and that CTE predicate — and
/// RLS alone is sufficient in this configuration. The predicate stays because it is what keeps the
/// scan from reading every tenant's chunks before discarding them, and because a query that reads
/// as tenant-scoped without knowing the session's settings is the one a reviewer can check.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn content_candidates_are_post_filtered_exactly_as_every_other_candidate_is() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let body = "Clause 7.2 sets out the perihelion review procedure.";
    let ungranted =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "record-one.txt", body).await;
    let visible =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "record-two.txt", body).await;
    let theirs =
        file_with_body(&mut admin, beta, fixtures.beta.owner, "record-three.txt", body).await;

    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, visible, caller, action).await;
    }

    let results = search(&pool, alpha, caller, "perihelion").await;

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![visible],
        "the content path returned files the caller may not see; wanted only {visible:?}"
    );
    assert_eq!(
        results.counts().proposed,
        2,
        "the other tenant's file ({theirs:?}) became a candidate: tenant isolation over chunk_text \
         is not holding and the post-filter is carrying it alone"
    );
    assert_eq!(
        results.counts().unauthorized,
        1,
        "the ungranted file ({ungranted:?}) was not dropped by resolution"
    );
    assert!(results.is_degraded());

    drop(db);
}

/// **`CLAUDE.md` rule 9, through the content half** — text belonging to a file that is not
/// `AVAILABLE` is never proposed.
///
/// Chunk rows outlive a file's status: text extracted from version 1 is still stored while version 2
/// is being scanned, and that is the window in which a read path that forgot rule 9 serves the
/// contents of a file no other surface will show. The available sibling shares the word, so this
/// fails loudly whether the predicate is widened to everything or narrowed to nothing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn text_of_a_file_that_is_not_available_is_never_proposed() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let body = "A note about the wolfram supply agreement.";
    let scanning =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "note-one.txt", body).await;
    let trashed =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "note-two.txt", body).await;
    let available =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "note-three.txt", body).await;

    for file in [scanning, trashed, available] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }
    sqlx::query("UPDATE files SET status = 'PROCESSING' WHERE id = $1")
        .bind(scanning.as_uuid())
        .execute(&mut admin)
        .await
        .expect("mark processing");
    sqlx::query("UPDATE files SET deleted_at = now() WHERE id = $1")
        .bind(trashed.as_uuid())
        .execute(&mut admin)
        .await
        .expect("trash");

    let results = search(&pool, alpha, caller, "wolfram").await;

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![available],
        "a processing or trashed file reached a caller through its stored text: {found:?}"
    );
    assert_eq!(
        results.counts().proposed,
        1,
        "the generator proposed the text of a file no read path may serve; the post-filter would \
         not have caught it, because the ACL grants it"
    );

    drop(db);
}

/// Text the current version no longer contains is not findable through the document.
///
/// The end-to-end half of `crates/indexing/tests/chunk_store.rs`'s prune assertion, and the reason
/// that prune is part of the same statement as the write. A phrase struck out of a contract stays
/// matchable if a re-index only ever inserts — with every permission check passing, because the
/// caller may genuinely read the file. It is not a leak the post-filter can see, so it has to be
/// impossible at the store.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn wording_removed_by_a_new_version_stops_being_findable() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let file = file_with_body(
        &mut admin,
        alpha,
        fixtures.alpha.owner,
        "policy.txt",
        "Employees may claim the tantalum allowance each quarter.",
    )
    .await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, file, caller, action).await;
    }

    // It is findable by the word that is about to be removed.
    assert_eq!(
        search(&pool, alpha, caller, "tantalum").await.hits().len(),
        1,
        "the fixture is not findable before the amendment, so the assertion below proves nothing"
    );

    // A new version, with the clause struck out.
    let second = insert_version(&mut admin, alpha, file, fixtures.alpha.owner, 2).await;
    let chunker = Chunker::new(CHUNKER, ChunkBudget { target_chars: 1, ..ChunkBudget::DEFAULT });
    let amended = chunker.chunk(
        second,
        &[Segment {
            kind: SegmentKind::Paragraph,
            text: "Employees may claim the standard allowance each quarter.".to_owned(),
            coordinates: Coordinates::none(),
        }],
    );
    write_chunks(&mut admin, alpha, file, second, CHUNKER, &amended).await.expect("amend");

    let results = search(&pool, alpha, caller, "tantalum").await;
    assert!(
        results.hits().is_empty(),
        "wording removed by a new version is still findable through the document: {:?}",
        results.hits()
    );
    assert_eq!(
        results.counts().proposed,
        0,
        "the removed wording was still proposed as a candidate"
    );

    // And the amendment is findable, so the assertion above is not passing because the store is
    // empty.
    assert_eq!(
        search(&pool, alpha, caller, "standard").await.hits().len(),
        1,
        "the new version's text is not searchable; the prune removed more than it should have"
    );

    drop(db);
}
