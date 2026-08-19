//! Degraded search: `plans/M3-DISCOVERY.md` D25, against a real PostgreSQL and real ACLs.
//!
//! # Why these run against real rows and not a fake generator
//!
//! `tests/postfilter.rs` uses a fake candidate generator, and explains why that is the honest choice
//! there: S5 needs candidates a real index would only propose by accident. The lexical generator is
//! the opposite case. It *is* the thing under test — what it can find, what it refuses to propose,
//! and whether its output reaches a caller without passing the post-filter — and every one of those
//! questions is a question about a SQL statement running against real files, real metadata and real
//! `acl_entries`.
//!
//! So the two files are complementary, not redundant: one proves the guarantee holds against
//! candidates nothing would generate, the other proves the generator we actually shipped is behind
//! that same guarantee.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_authorization::PgAclAuthorization;
use enclave_core::{Actor, FileId, RequestContext, TenantId, UserId};
use enclave_db::{DbPool, TenantScoped};
use enclave_search::{
    lexical, Candidate, DegradedReason, Retrieval, SearchResults, VectorStore,
    DEFAULT_DENYLIST_LIMIT,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use uuid::Uuid;

/// A generous candidate budget. D21: the post-filter drops, so a caller that passes its page size
/// here gets short pages. Nothing in these tests produces anything like this many rows; the number
/// is large so that a missing result is a retrieval failure and never a truncation.
const BUDGET: u32 = 100;

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
        Retrieval::Complete => panic!("an unreachable store must degrade"),
    }
}

/// **S5, on the degraded path** — a caller who may not see a file does not get it lexically either.
///
/// Two files in `tenant-alpha` share a distinctive word, and a third in `tenant-beta` shares it too.
/// The caller is granted on exactly one. The lexical generator has no idea about any of that: it
/// matches on text, which is the point — it is a candidate generator, and being wrong in the
/// permissive direction is what candidate generators are allowed to be.
///
/// The one the caller may see is the *second* of the two alpha files by name, so a fallback that
/// dropped everything — which looks identical from the outside to one that filters correctly —
/// fails on the surviving hit.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn degraded_results_are_post_filtered_exactly_as_vector_results_are() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let ungranted = Spine::new(alpha);
    let visible = Spine::new(alpha);
    let theirs = Spine::new(beta);

    let mut admin = db.connect().await.expect("admin connection");
    ungranted.insert(&mut admin, fixtures.alpha.owner, now).await.expect("ungranted spine");
    visible.insert(&mut admin, fixtures.alpha.owner, now).await.expect("visible spine");
    theirs.insert(&mut admin, fixtures.beta.owner, now).await.expect("beta spine");

    rename(&mut admin, ungranted.file, "Perihelion board pack.pptx").await;
    rename(&mut admin, visible.file, "Perihelion budget.xlsx").await;
    rename(&mut admin, theirs.file, "Perihelion, theirs.docx").await;

    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, visible.file, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "perihelion", BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");

    assert_eq!(
        results.hits().len(),
        1,
        "the degraded path returned files the caller may not see: {:?}",
        results.hits()
    );
    assert_eq!(results.hits()[0].file_id, visible.file);
    assert_eq!(
        results.counts().proposed,
        2,
        "the other tenant's file became a candidate; tenant scoping is not doing its job and the \
         post-filter is carrying it alone"
    );
    assert_eq!(
        results.counts().unauthorized,
        1,
        "the ungranted file was not dropped by resolution"
    );
    assert!(results.is_degraded());

    drop(db);
}

/// The flag distinguishes the two paths, and the two paths are otherwise the same search.
///
/// Both halves resolve the same caller against the same file and return the same hit, so the flag
/// is the *only* thing that differs. A test asserting `degraded == true` alone proves nothing: a
/// field hard-coded to `true` passes it, and a caller reading that field learns nothing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn the_flag_is_true_on_the_degraded_path_and_false_on_the_complete_one() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    rename(&mut admin, spine.file, "Chalcedony onboarding.pdf").await;
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, spine.file, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());

    // The complete path: candidates as the vector store would hand them over.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let complete = SearchResults::confirm(
        &mut tx,
        &authorization,
        &ctx(alpha, caller),
        vec![Candidate { file_id: spine.file, score: 0.9, excerpt: None }],
    )
    .await
    .expect("complete");
    tx.commit().await.expect("commit");

    // The degraded path: the same file, found lexically.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "chalcedony", BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let degraded =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("degraded");
    tx.commit().await.expect("commit");

    assert_eq!(complete.hits().len(), 1, "the complete path lost the file");
    assert_eq!(degraded.hits().len(), 1, "the degraded path lost the file");
    assert_eq!(complete.hits()[0].file_id, degraded.hits()[0].file_id);

    assert!(!complete.is_degraded(), "a complete result claimed degraded recall");
    assert_eq!(complete.degraded_reason(), None);
    assert!(degraded.is_degraded(), "a degraded result claimed complete recall — D25's failure");
    assert_eq!(degraded.degraded_reason(), Some(store_is_down()));

    drop(db);
}

/// Lexical search finds the document it was asked for, and not the one beside it.
///
/// Both files are granted to the caller, so nothing here is about permissions: this is the
/// assertion that the generator *retrieves*, and that a passing S5 is not just a filter that
/// refuses everything. The tokenization is the substance — `budget` matching `Q3-budget.xlsx`
/// requires the normalization in `lexical`'s module documentation, and without it the default
/// parser reads that filename as one indivisible token.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn lexical_search_finds_the_named_document_and_leaves_its_neighbour() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let wanted = Spine::new(alpha);
    let other = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    wanted.insert(&mut admin, fixtures.alpha.owner, now).await.expect("wanted spine");
    other.insert(&mut admin, fixtures.alpha.owner, now).await.expect("other spine");
    rename(&mut admin, wanted.file, "Q3-tantalum.xlsx").await;
    rename(&mut admin, other.file, "Q3 minutes.docx").await;
    for file in [wanted.file, other.file] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "tantalum", BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![wanted.file],
        "lexical search returned {found:?}; wanted exactly {:?}",
        wanted.file
    );
    // No extracted text exists to excerpt from, and a snippet cut from the filename would say
    // nothing the hit does not already carry. `lexical` explains why the honest answer is nothing.
    assert_eq!(results.hits()[0].excerpt, None);

    drop(db);
}

/// A scalar metadata value is searchable; a container-valued one is not, and the test says so.
///
/// `metadata_values.value_text` is NULL for arrays and objects by construction (migration 0009), so
/// the tag list is invisible to this path. Asserting the gap rather than only the capability is
/// what stops somebody discovering it during an incident.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn lexical_search_finds_a_document_by_a_scalar_metadata_value() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let tagged = Spine::new(alpha);
    let listed = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    tagged.insert(&mut admin, fixtures.alpha.owner, now).await.expect("tagged spine");
    listed.insert(&mut admin, fixtures.alpha.owner, now).await.expect("listed spine");
    // Neither filename contains the search term, so a hit can only have come from the metadata.
    rename(&mut admin, tagged.file, "unremarkable-one.docx").await;
    rename(&mut admin, listed.file, "unremarkable-two.docx").await;
    for file in [tagged.file, listed.file] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }

    let field = metadata_field(&mut admin, alpha, "matter").await;
    set_metadata(&mut admin, alpha, tagged.file, field, "\"Bellwether arbitration\"").await;
    set_metadata(&mut admin, alpha, listed.file, field, "[\"Bellwether\", \"arbitration\"]").await;

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "bellwether", BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![tagged.file],
        "expected only the file whose scalar metadata matched; got {found:?}"
    );

    drop(db);
}

/// **`CLAUDE.md` rule 9** — nothing that is not `AVAILABLE` is proposed, however well it matches.
///
/// A file mid-scan is not served by any read path, and a fallback written during an outage is
/// exactly where that gets forgotten. The available sibling matches the same word, so this fails
/// loudly if the predicate were widened to "everything" as well as if it were narrowed to nothing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn a_file_that_has_not_finished_processing_is_never_a_candidate() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let scanning = Spine::new(alpha);
    let available = Spine::new(alpha);
    let trashed = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    for spine in [&scanning, &available, &trashed] {
        spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    }
    rename(&mut admin, scanning.file, "Wolfram scanning.pdf").await;
    rename(&mut admin, available.file, "Wolfram available.pdf").await;
    rename(&mut admin, trashed.file, "Wolfram trashed.pdf").await;
    for file in [scanning.file, available.file, trashed.file] {
        for action in ["file.metadata_read", "file.content_read"] {
            grant_action(&mut admin, alpha, file, caller, action).await;
        }
    }
    sqlx::query("UPDATE files SET status = 'PROCESSING' WHERE id = $1")
        .bind(scanning.file.as_uuid())
        .execute(&mut admin)
        .await
        .expect("mark processing");
    sqlx::query("UPDATE files SET deleted_at = now() WHERE id = $1")
        .bind(trashed.file.as_uuid())
        .execute(&mut admin)
        .await
        .expect("trash");

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "wolfram", BUDGET, store_is_down())
        .await
        .expect("lexical candidates");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");

    let found: Vec<FileId> = results.hits().iter().map(|hit| hit.file_id).collect();
    assert_eq!(
        found,
        vec![available.file],
        "a file that is processing or trashed reached a caller through the degraded path: {found:?}"
    );
    assert_eq!(
        results.counts().proposed,
        1,
        "the generator proposed a file no read path may serve; the post-filter would not have \
         caught it, because the ACL grants it"
    );

    drop(db);
}

/// A query with nothing to match on returns nothing, and does not go looking.
///
/// The interesting half is that this is still a *degraded* result. Zero hits and `degraded: true`
/// is the honest answer to "I searched during an outage and found nothing"; zero hits alone is the
/// sentence D25 exists to stop the caller from writing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn a_query_with_no_words_is_empty_and_still_says_it_is_degraded() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let candidates = lexical::candidates(&mut tx, alpha, "   —  ", BUDGET, store_is_down())
        .await
        .expect("empty");
    let results =
        SearchResults::confirm_degraded(&mut tx, &authorization, &ctx(alpha, caller), candidates)
            .await
            .expect("confirm");
    tx.commit().await.expect("commit");

    assert!(results.hits().is_empty());
    assert_eq!(results.counts().proposed, 0);
    assert!(results.is_degraded(), "an empty degraded result must still be marked degraded");

    drop(db);
}

/// Gives a file a searchable name. `Spine` names its rows after their ids, which is right for
/// permission tests and useless for a text one.
async fn rename(conn: &mut sqlx::PgConnection, file: FileId, name: &str) {
    sqlx::query("UPDATE files SET name = $2, normalized_name = lower($2) WHERE id = $1")
        .bind(file.as_uuid())
        .bind(name)
        .execute(&mut *conn)
        .await
        .expect("rename");
}

/// A tenant-scoped `TEXT` field to hang values on.
async fn metadata_field(conn: &mut sqlx::PgConnection, tenant: TenantId, key: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_fields
           (id, tenant_id, scope, scope_id, key, label, field_type, created_at)
         VALUES ($1, $2, 'TENANT', NULL, $3, $3, 'TEXT', $4)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(key)
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("metadata field");
    id
}

/// Writes one metadata value. `value_text` is generated from `value`, never written.
async fn set_metadata(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    file: FileId,
    field: Uuid,
    json: &str,
) {
    sqlx::query(
        "INSERT INTO metadata_values
           (tenant_id, resource_type, resource_id, field_id, value, updated_by, updated_at)
         VALUES ($1, 'FILE', $2, $3, $4::jsonb, $5, $6)",
    )
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(field)
    .bind(json)
    .bind(Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("metadata value");
}

/// Grants one action on one file, as `tests/postfilter.rs` does — the harness helper does not
/// express two actions on one resource.
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
