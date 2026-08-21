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
//! `ENC-529` added a third, and it belongs here because it is the same asymmetry one step further
//! on: the path now cuts an **excerpt** from that text, and an excerpt is a quotation of a document.
//! Two things follow. What is quoted must be text the document contains — `crates/search/src/
//! excerpt.rs` records why both `ts_headline` forms fail that, one visibly and one invisibly. And
//! the quotation is released only where every other disclosure decision is made, so a caller holding
//! `MetadataRead` alone gets the hit and nothing else — indistinguishable from a document that had
//! no quotable passage, which is `docs/12 §4.3` S6 and is the assertion this file exists to make now
//! that there is something real to withhold.
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
    lexical, Confirmed, DegradedReason, Excerpt, Highlights, Retrieval, SearchResults, VectorStore,
    DEFAULT_DENYLIST_LIMIT,
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
    file_with_paragraphs(admin, tenant, owner, name, &[body]).await
}

/// As [`file_with_body`], with each paragraph landing in a chunk of its own.
///
/// `target_chars: 1` makes the chunker flush after every segment, so the paragraph at index *n* is
/// the chunk at ordinal *n*. That is what lets a test say *the excerpt came from the third chunk*
/// rather than inferring it from the text.
async fn file_with_paragraphs(
    admin: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    name: &str,
    paragraphs: &[&str],
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
    let segments: Vec<Segment> = paragraphs
        .iter()
        .map(|text| Segment {
            kind: SegmentKind::Paragraph,
            text: (*text).to_owned(),
            coordinates: Coordinates::none(),
        })
        .collect();
    let chunks: Vec<Chunk> = chunker.chunk(version, &segments);
    assert_eq!(chunks.len(), paragraphs.len(), "the fixture did not chunk one paragraph per chunk");
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

/// The hit for one file, or a failure naming the file that is missing.
fn hit_for(results: &SearchResults, file: FileId) -> &Confirmed {
    results
        .hits()
        .iter()
        .find(|hit| hit.file_id == file)
        .unwrap_or_else(|| panic!("{file:?} is not among the hits: {:?}", results.hits()))
}

/// An excerpt with its elision marks removed — the part that claims to be text from the document.
fn quoted(excerpt: &Excerpt) -> &str {
    excerpt.text().trim_matches('…')
}

/// The substrings an excerpt's offsets select, sliced out of the excerpt itself (`ENC-542`).
///
/// Asserted on the substrings rather than on the numbers because the numbers are only ever used to
/// slice, and a span shifted by a forgotten elision mark is a plausible pair of integers and the
/// wrong word.
fn marked(excerpt: &Excerpt) -> Vec<&str> {
    match excerpt.highlights() {
        Highlights::Terms(spans) => spans
            .iter()
            .map(|span| {
                excerpt.text().get(span.start..span.end).expect("a span that slices its own text")
            })
            .collect(),
        Highlights::Unlocated => Vec::new(),
    }
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

/// **`ENC-529`** — a content hit carries a quotation of the passage that matched, and the quotation
/// is text the document actually contains.
///
/// The punctuation is the assertion. `Clause 7.2(b)` is *made of* its punctuation, and the obvious
/// implementation — `ts_headline` over the expression migrations 0012 and 0013 index — returns
/// `Clause 7 2 b`, which no document contains and which a caller cannot find in the file they are
/// then shown. `crates/search/src/excerpt.rs` records why both `ts_headline` forms were rejected;
/// this is that decision asserted end to end, through the real query, against text written by the
/// real writer.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_content_hit_quotes_the_document_including_the_punctuation_the_index_strips() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let body = "Clause 7.2(b) sets out the perihelion review procedure, and Schedule 4 names the \
                reviewers who must sign it off before the end of the accounting period.";
    let file =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "record-one.txt", body).await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, file, caller, action).await;
    }

    let results = search(&pool, alpha, caller, "perihelion").await;

    let excerpt =
        hit_for(&results, file).excerpt.clone().expect("a content hit carries a quotation");
    assert!(
        body.contains(quoted(&excerpt)),
        "the excerpt is not text from the document.\n  document: {body:?}\n  excerpt:  {shown:?}",
        shown = excerpt.text()
    );
    assert!(
        excerpt.text().to_lowercase().contains("perihelion"),
        "the excerpt does not contain the word that caused the hit: {shown:?}",
        shown = excerpt.text()
    );
    assert!(
        excerpt.text().contains("7.2(b)"),
        "the excerpt was cut from the punctuation-stripped form the index matches on: {shown:?}",
        shown = excerpt.text()
    );

    drop(db);
}

/// **`ENC-542`** — a content hit carries the offsets of the word that caused it, and they index the
/// string the caller receives.
///
/// `docs/05 §11` shows `<em>` on an excerpt and this crate returns plain text. Closing that means
/// carrying where the match is, so the API layer can mark up **without tokenizing document content**
/// a second time — which is the thing `crates/search/src/excerpt.rs` spends its length arguing
/// against. The unit tests prove the arithmetic; this proves it survives the round trip that
/// actually runs: PostgreSQL writes the chunk, the query locates the term, the decoder cuts, the
/// post-filter releases.
///
/// The body is deliberately long enough that the window opens with `…`. That mark is three bytes,
/// and an offset measured against the body instead of against the returned string lands three bytes
/// early — still on a character boundary, still slicing without error, and selecting the wrong word.
/// Asserting the *substring* rather than the numbers is what catches it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_content_hit_carries_offsets_that_select_the_word_that_caused_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let body = "This agreement is made between the parties named in Schedule 1, and the recitals \
                below record what each of them is bringing to it. Clause 7.2(b) sets out the \
                perihelion review procedure, and Schedule 4 names the reviewers who must sign it \
                off before the end of the accounting period in which the review falls due.";
    let file =
        file_with_body(&mut admin, alpha, fixtures.alpha.owner, "record-one.txt", body).await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, file, caller, action).await;
    }

    let results = search(&pool, alpha, caller, "perihelion").await;
    let excerpt =
        hit_for(&results, file).excerpt.clone().expect("a content hit carries a quotation");

    assert!(
        excerpt.text().starts_with('…'),
        "the fixture produced no leading elision mark, so it cannot catch the offset shift it \
         exists to catch: {shown:?}",
        shown = excerpt.text()
    );
    assert_eq!(
        marked(&excerpt),
        vec!["perihelion"],
        "the offsets do not select the term the caller typed: {shown:?}",
        shown = excerpt.text()
    );

    drop(db);
}

/// **S6, on the degraded path** (`docs/12 §4.3`) — a `MetadataRead`-only caller gets the hit and no
/// excerpt, and cannot tell that from a document that simply had none.
///
/// `plans/M3-THREAT-WALKTHROUGH.md §2.5` states the property this defends: distinguishing a withheld
/// excerpt from an absent one would say *there is content here you may not see*, which is a fact
/// about a document the caller cannot read. `Confirmed::excerpt` is `Option<String>` and `None`
/// deliberately means both things; before `ENC-529` that was cheap to honour on this path, because
/// the lexical generator never produced an excerpt at all.
///
/// Three files, so the assertion is about disclosure rather than about absence:
///
/// - `withheld` matched on its **body** and the caller holds `MetadataRead` only. There is a
///   quotation and they do not get it.
/// - `unquotable` matched on its **name**. The caller holds both actions and there is still no
///   excerpt, because nothing in the body matched and a snippet cut from a filename would say
///   nothing the hit does not already carry.
/// - `readable` matched on its body with both actions granted. **This one is the reason the test is
///   worth running**: without it every assertion below passes against the pre-`ENC-529` code, which
///   returned `None` for everything.
///
/// The difference between the first two exists in exactly one place, and it is operator-facing:
/// `DropCounts::excerpt_withheld`. Nothing in what the caller receives distinguishes them.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_metadata_only_caller_gets_no_excerpt_and_cannot_tell_it_from_a_document_with_none() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let owner = fixtures.alpha.owner;
    let mut admin = db.connect().await.expect("admin connection");

    let body = "The supplier shall provide an indemnity against third-party claims.";

    let withheld = file_with_body(&mut admin, alpha, owner, "record-one.txt", body).await;
    grant_action(&mut admin, alpha, withheld, caller, "file.metadata_read").await;

    let unquotable = file_with_body(
        &mut admin,
        alpha,
        owner,
        "indemnity-summary.txt",
        "A short administrative note with nothing relevant in it.",
    )
    .await;
    let readable = file_with_body(&mut admin, alpha, owner, "record-three.txt", body).await;
    for file in [unquotable, readable] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }

    let results = search(&pool, alpha, caller, "indemnity").await;

    assert_eq!(results.hits().len(), 3, "all three files are hits: {:?}", results.hits());

    // The control, first: if this is `None` the test below proves nothing, because it would pass
    // against an implementation that never produces an excerpt at all.
    let quotation = hit_for(&results, readable)
        .excerpt
        .clone()
        .expect("a caller holding ContentRead over a body match must receive the quotation");
    assert!(body.contains(quoted(&quotation)), "the control's excerpt is not from the document");

    assert_eq!(
        hit_for(&results, withheld).excerpt,
        None,
        "the excerpt reached a caller who may know the document exists and may not read it"
    );
    assert_eq!(
        hit_for(&results, unquotable).excerpt,
        None,
        "a file matched by its name alone has no matched passage, so it has nothing to quote"
    );
    assert_eq!(
        hit_for(&results, withheld).excerpt,
        hit_for(&results, unquotable).excerpt,
        "a withheld excerpt is distinguishable from an absent one, which tells the caller there is \
         content here they may not see"
    );

    // The distinction exists exactly once, and it is for the operator watching disclosure narrow.
    assert_eq!(
        results.counts().excerpt_withheld,
        1,
        "the withheld quotation was not reported; an operator cannot see the ContentRead gate firing"
    );
    assert_eq!(results.counts().unauthorized, 0, "nobody was dropped: all three are visible hits");

    drop(db);
}

/// The quotation comes from the chunk that matched, not from the beginning of the document.
///
/// This is the failure `ts_headline` over the raw text produces silently: its tokenization disagrees
/// with the indexed one, it finds nothing to highlight, and rather than saying so it returns the
/// **opening words of the document** — handed to a caller as the passage that answered their query.
/// Three paragraphs, three chunks, and the query word only in the last one; the first paragraph
/// carries a word that must not appear.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn the_quotation_is_cut_from_the_chunk_that_matched_and_not_from_the_first_one() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let opening = "This agreement is made between the parties named in Schedule 1.";
    let closing = "Employees may claim the tantalum allowance each quarter, in arrears.";
    let file = file_with_paragraphs(
        &mut admin,
        alpha,
        fixtures.alpha.owner,
        "record-one.txt",
        &[opening, "The parties agree to the terms set out below.", closing],
    )
    .await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, file, caller, action).await;
    }

    let results = search(&pool, alpha, caller, "tantalum").await;

    let excerpt =
        hit_for(&results, file).excerpt.clone().expect("a content hit carries a quotation");
    assert!(
        closing.contains(quoted(&excerpt)),
        "the excerpt did not come from the chunk that matched.\n  matched: {closing:?}\n  \
         excerpt: {shown:?}",
        shown = excerpt.text()
    );
    assert!(
        !excerpt.text().contains("Schedule 1"),
        "the excerpt is the opening of the document dressed as the passage that matched: {shown:?}",
        shown = excerpt.text()
    );

    drop(db);
}

/// Two identical searches return the identical quotation.
///
/// Rank ties between chunks are ordinary — two paragraphs of one document each containing the query
/// word once score the same — and without a total order in the `DISTINCT ON`'s `ORDER BY`,
/// PostgreSQL may return either. That is a document whose quotation changes between two identical
/// searches, which is reported as "search changed its mind" and reproduced by nobody. The fixture is
/// built to be exactly that tie.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0013; CI runs it with --include-ignored"]
async fn a_tie_between_two_matching_chunks_is_broken_the_same_way_every_time() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let mut admin = db.connect().await.expect("admin connection");

    let first = "The tantalum allowance is paid each quarter.";
    let second = "The tantalum entitlement is reviewed each year.";
    let file = file_with_paragraphs(
        &mut admin,
        alpha,
        fixtures.alpha.owner,
        "record-one.txt",
        &[first, second],
    )
    .await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, file, caller, action).await;
    }

    let expected = search(&pool, alpha, caller, "tantalum").await;
    let expected = hit_for(&expected, file).excerpt.clone().expect("a quotation");
    assert!(
        first.contains(quoted(&expected)),
        "the lowest ordinal must win a rank tie, so the quotation is the earlier passage: {expected:?}"
    );

    for _ in 0..5 {
        let again = search(&pool, alpha, caller, "tantalum").await;
        assert_eq!(
            hit_for(&again, file).excerpt.as_ref(),
            Some(&expected),
            "the same query quoted a different passage on a repeat run"
        );
    }

    drop(db);
}
