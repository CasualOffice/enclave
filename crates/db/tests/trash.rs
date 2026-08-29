//! The recycle-bin read model against a real PostgreSQL — the query behind `GET /api/v1/trash`.
//!
//! `docs/12-TESTING.md §1.2` is the shape every test here is written to, and three of its rules do
//! most of the work:
//!
//! * **An assertion about an absence passes for free.** "The live file was not in the bin", "the
//!   other tenant's deletion was not in the bin", "the folder's children were not listed
//!   separately" are all true of a query that returns nothing, of a fixture that trashed nothing,
//!   and of a module that does not compile into anything anybody calls. So every test below that
//!   asserts something is *missing* proves, **under the identical fixture and in the same run**,
//!   that something comparable is *present*.
//! * **Watch it fail first.** Each test names, in its own doc comment, the edit to
//!   `crates/db/src/trash.rs` that turns it red. The names are not guesses: each was run.
//! * **The mutation has to be the interesting one.** The root-detection predicate has a weaker
//!   sibling that reads almost identically — `p.deleted_at IS NOT NULL` instead of
//!   `p.deleted_at = f.deleted_at` — and every test here except
//!   [`a_file_deleted_before_the_folder_above_it_is_still_its_own_row`] stays green under it. That
//!   one test is the whole reason the discriminator is an equality.
//!
//! # Row-level security is deliberately switched off in the isolation test
//!
//! `TestDb::pool` connects as `enclave_app` and therefore runs with RLS in force, which is right for
//! the ordinary paths — a test of the read model should run the way production runs. It is exactly
//! wrong for a cross-tenant assertion: with RLS in force, deleting the `tenant_id` predicate from
//! the SQL changes nothing observable, and the test would report a property the application query
//! does not hold. That is `ENC-124` in miniature, and this repository has had nine crates where a
//! deleted `tenant_id` predicate failed to fail because row security was holding the property alone.
//!
//! So [`another_tenants_recycle_bin_stays_out_of_this_tenants_list`] runs over [`TestDb::connect`] —
//! the harness's cluster superuser, which bypasses row security entirely — and proves that the
//! connection can see both tenants' trashed rows *before* asking [`roots_on`] the question. What it
//! demonstrates is the predicate, alone, unassisted.
//!
//! # The cascade is written as SQL rather than through `enclave-files`
//!
//! [`trash_subtree`] is setup, not subject. `enclave-files` depends on *this* crate, so it cannot be
//! a dev-dependency here without a cycle Cargo would have to close through a dev edge that does not
//! exist; and a test that drove the real repository would be asserting the repository's behaviour
//! rather than this query's. The helper is spelled to match `FileRepository::trash`'s
//! `TRASH_SUBTREE` exactly where it matters — **one `deleted_at` across every live descendant** —
//! because that shared instant is the entire premise of the predicate under test.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use enclave_core::{FileId, TenantId, UserId};
use enclave_db::trash::{
    roots, roots_on, TrashCandidate, TrashCandidates, TrashedKind, OVER_FETCH,
};
use enclave_db::{DbPool, TenantScoped};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

/// The seeded database, the fixture identities, and an **application-role** pool over it.
///
/// The pool is `enclave_app`, never the harness's superuser: a superuser bypasses row-level
/// security, and every ordinary test here should run the way the product runs. The one test that
/// wants RLS out of the way takes its own connection and says why.
async fn harness(connections: u32) -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(connections).await.expect("application pool");
    (db, fixtures, pool)
}

/// A workspace → library → folder → file spine, written over the administrative connection.
///
/// Setup, not subject (`crates/testing/src/content.rs`): these rows exist so the read model has
/// something to find, and writing them through the application role would be testing the fixtures
/// rather than the query.
async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    spine
}

/// One more node in an existing spine.
///
/// `parent` is `None` for a node directly at the library root, which is the case the contract's
/// `parentFolderId: null` describes. Every column is spelled as `migrations/0005_files.sql` defines
/// it, so a schema that drifts from it fails here rather than somewhere subtler.
async fn add_node(
    conn: &mut PgConnection,
    spine: &Spine,
    owner: UserId,
    name: &str,
    node_type: &str,
    parent: Option<FileId>,
) -> FileId {
    let id = FileId::new_v7();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, inherit_permissions, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, TRUE, $9, $9, now(), now())",
    )
    .bind(id.as_uuid())
    .bind(spine.tenant.as_uuid())
    .bind(spine.workspace.as_uuid())
    .bind(spine.library.as_uuid())
    .bind(parent.map(|p| p.as_uuid()))
    .bind(node_type)
    .bind(name)
    .bind(if node_type == "FOLDER" { "inode/directory" } else { "text/plain" })
    .bind(owner.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("insert a node");
    id
}

/// Moves a node and every **live** descendant to the trash, stamping one instant across all of them.
///
/// The shape of `enclave_files::repo::TRASH_SUBTREE`, written out here because `enclave-files`
/// cannot be a dependency of this crate's tests (see the module header). The two properties that
/// matter to the query under test are both present: the recursion stops at an already-trashed node,
/// and every row it does reach receives the *same* `deleted_at`.
///
/// `by` is written to `modified_by`, which is where the contract's `deletedBy` comes from. Returns
/// the instant, so a test can build the "deleted separately, before its parent" case deliberately
/// rather than by racing the clock.
async fn trash_subtree(
    conn: &mut PgConnection,
    tenant: TenantId,
    root: FileId,
    at: DateTime<Utc>,
    by: UserId,
    purge_after: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    let affected = sqlx::query(
        "WITH RECURSIVE subtree AS (
             SELECT f.id FROM files f
              WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NULL
             UNION
             SELECT c.id FROM subtree s
               JOIN files c ON c.tenant_id = $1 AND c.parent_id = s.id AND c.deleted_at IS NULL
         )
         UPDATE files
            SET deleted_at = $3, purge_after = $4, revision = revision + 1, modified_by = $5,
                modified_at = $3
          WHERE tenant_id = $1 AND id IN (SELECT id FROM subtree)",
    )
    .bind(tenant.as_uuid())
    .bind(root.as_uuid())
    .bind(at)
    .bind(purge_after)
    .bind(by.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("trash a subtree")
    .rows_affected();
    assert!(affected > 0, "the fixture must have trashed something, or the test proves nothing");
    at
}

/// Brings a node back, so an ordering test can re-delete it.
async fn untrash(conn: &mut PgConnection, tenant: TenantId, node: FileId) {
    let affected = sqlx::query(
        "UPDATE files SET deleted_at = NULL, purge_after = NULL
          WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(node.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("restore a node")
    .rows_affected();
    assert_eq!(affected, 1, "the fixture must have restored exactly one node");
}

/// The ids in one tenant's recycle bin, most recently deleted first.
async fn listed(pool: &DbPool, tenant: TenantId, limit: u32) -> Vec<FileId> {
    page(pool, tenant, limit).await.candidates.into_iter().map(|c| c.file_id).collect()
}

/// The whole window, for the tests that assert on a row's contents.
async fn page(pool: &DbPool, tenant: TenantId, limit: u32) -> TrashCandidates {
    let mut tx: TenantScoped = pool.begin(tenant).await.expect("begin");
    let window = roots(&mut tx, limit).await.expect("read the recycle bin");
    tx.commit().await.expect("commit");
    window
}

/// How many rows in this tenant are in the trash at all, read over the administrative connection.
///
/// Deliberately **not** through [`roots`]: a test that counted trashed rows with the statement under
/// test could not tell "the cascade wrote nothing" from "the read hid them", which is the whole
/// claim of the folder test.
async fn trashed_rows(conn: &mut PgConnection, tenant: TenantId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM files WHERE tenant_id = $1 AND deleted_at IS NOT NULL")
        .bind(tenant.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("count trashed rows")
}

fn find(window: &TrashCandidates, id: FileId) -> &TrashCandidate {
    window
        .candidates
        .iter()
        .find(|c| c.file_id == id)
        .unwrap_or_else(|| panic!("{id} must be in the recycle bin: {window:?}"))
}

// -------------------------------------------------------------------------------------------------
// One row per restore
// -------------------------------------------------------------------------------------------------

/// A trashed folder is one row, not one row per document inside it.
///
/// The defect this predicate exists to prevent: a folder with two documents produces **three**
/// trashed rows, and a listing of all three offers a restore on each child that would be a partial
/// restore of somebody's folder — `FileRepository::restore` brings back the whole subtree that
/// shares the instant, so restoring a child restores its siblings too and the caller was never told.
///
/// The separately-deleted file at the library root is the positive control, in the same run: without
/// it, "the bin holds one row" is equally true of a query that returns the first row it finds. The
/// count read over the administrative connection is the second control — it proves the two children
/// really are in the trash and really are being *hidden by the query* rather than never written.
///
/// Fails when the `NOT EXISTS` clause is deleted from `TRASH_ROOTS_SQL`: the bin then holds four
/// rows instead of two, and the assertion names both numbers.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_folder_is_listed_once_and_not_once_per_descendant() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    // `s.folder` already holds `s.file`; a second document makes the cascade three rows deep enough
    // that "one row" cannot be a coincidence of the fixture.
    let s = spine(&mut admin, alpha, user).await;
    let sibling = add_node(&mut admin, &s, user, "notes.txt", "FILE", Some(s.folder)).await;
    let alone = add_node(&mut admin, &s, user, "alone.txt", "FILE", None).await;

    let now = Utc::now();
    let _folder_at = trash_subtree(&mut admin, alpha, s.folder, now, user, None).await;
    let _alone_at =
        trash_subtree(&mut admin, alpha, alone, now + Duration::seconds(1), user, None).await;

    assert_eq!(
        trashed_rows(&mut admin, alpha).await,
        4,
        "the fixture must have trashed the folder, its two documents and the lone file — if it did \
         not, the assertion below is about a bin that was always this size"
    );

    let ids = listed(&pool, alpha, 50).await;
    assert_eq!(
        ids,
        vec![alone, s.folder],
        "the recycle bin must hold the two nodes somebody actually deleted, not the four rows the \
         cascade wrote; and the separately deleted file must still be one of them"
    );

    let window = page(&pool, alpha, 50).await;
    assert_eq!(
        find(&window, s.folder).kind,
        TrashedKind::Folder,
        "the folder must be reported as a folder: its restore cascades and the client's \
         confirmation has to say so"
    );
    assert_eq!(find(&window, alone).kind, TrashedKind::File);
    assert!(
        !window.candidates.iter().any(|c| c.file_id == s.file || c.file_id == sibling),
        "neither document inside the folder is its own restore: {window:?}"
    );
}

/// A file deleted before the folder above it stays its own row.
///
/// **The test the discriminator exists for, and the only one in this file that
/// `p.deleted_at IS NOT NULL` does not survive.** A document deleted on Monday inside a folder
/// deleted on Tuesday is not part of Tuesday's cascade: `RESTORE_SUBTREE` matches
/// `c.deleted_at = s.deleted_at`, so restoring the folder leaves that document behind. If this
/// listing hid it — as the weaker predicate would, on the grounds that its parent is trashed — the
/// document would be restorable by no request in the product, which is exactly the defect this whole
/// item exists to remove, reintroduced one level down.
///
/// The folder is the positive control in the same run: both are roots and both must be listed.
///
/// Fails when `p.deleted_at = f.deleted_at` is weakened to `p.deleted_at IS NOT NULL` (the
/// early-deleted document vanishes), and when the `NOT EXISTS` is deleted altogether (the folder's
/// other child appears as a third row).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_deleted_before_the_folder_above_it_is_still_its_own_row() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let later = add_node(&mut admin, &s, user, "later.txt", "FILE", Some(s.folder)).await;

    // Monday: the document alone. Tuesday: the folder, which cascades over `later` but cannot reach
    // `s.file`, because the recursion stops at an already-trashed node.
    let monday = Utc::now() - Duration::days(1);
    let _early = trash_subtree(&mut admin, alpha, s.file, monday, user, None).await;
    let tuesday = Utc::now();
    let _cascade = trash_subtree(&mut admin, alpha, s.folder, tuesday, user, None).await;

    let stored: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT deleted_at FROM files WHERE id = $1")
            .bind(s.file.as_uuid())
            .fetch_one(&mut admin)
            .await
            .expect("read the early deletion back");
    assert_eq!(
        stored,
        Some(monday),
        "the fixture's premise: the second cascade must not have restamped the first deletion, or \
         the two instants are equal and this test cannot distinguish the two predicates"
    );

    let ids = listed(&pool, alpha, 50).await;
    assert_eq!(
        ids,
        vec![s.folder, s.file],
        "the folder is Tuesday's deletion and the document is Monday's; restoring the folder will \
         not bring the document back, so a listing that hid the document would make it \
         unrestorable by any request in the product"
    );
    assert!(
        !ids.contains(&later),
        "the document that *was* part of Tuesday's cascade is not its own row: {ids:?}"
    );
}

// -------------------------------------------------------------------------------------------------
// What must not appear
// -------------------------------------------------------------------------------------------------

/// A live file never appears in the recycle bin; the trashed one beside it does.
///
/// The trashed file is the positive control and it is asserted in the same read, so "the live one is
/// absent" cannot be satisfied by a query that returns nothing at all. The failure this guards is
/// not cosmetic: this endpoint authorizes on `file.restore` rather than on `file.metadata_read`, so
/// a bin that leaked live rows would be a listing of a tenant's documents decided by the wrong
/// question.
///
/// Fails when `AND f.deleted_at IS NOT NULL` is deleted from `TRASH_ROOTS_SQL`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_live_file_never_appears_in_the_recycle_bin() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let survivor = add_node(&mut admin, &s, user, "survivor.txt", "FILE", None).await;

    assert!(
        listed(&pool, alpha, 50).await.is_empty(),
        "nothing has been deleted yet, so the bin must be empty; if it is not, the assertion below \
         is about a query that returns rows regardless"
    );

    let _at = trash_subtree(&mut admin, alpha, s.file, Utc::now(), user, None).await;

    assert_eq!(
        listed(&pool, alpha, 50).await,
        vec![s.file],
        "exactly the deleted document, and none of the live rows beside it — the folder above it, \
         the survivor at the root, or any other file in the tenant"
    );
    assert!(
        !listed(&pool, alpha, 50).await.contains(&survivor),
        "a live file is not a deletion anybody can undo"
    );
}

/// One tenant's recycle bin never appears in another's, with row-level security switched off.
///
/// The whole test runs over the harness's cluster superuser connection, where RLS is inert. That is
/// asserted first, not assumed: the connection counts trashed rows across both tenants with no
/// `app.tenant_id` set at all. Under RLS that statement errors — `current_setting` is used in its
/// strict form (`migrations/0002_rls_policies.sql`) — so what follows is a demonstration of the SQL,
/// alone, unassisted.
///
/// Beta's own bin is read back as the positive control: the row is present, reachable and
/// well-formed on this very connection, and the only reason it is absent from an alpha-scoped read
/// is the query.
///
/// Both tenants delete a file with the **same name**, so this cannot pass because the other tenant's
/// row was called something different.
///
/// Fails when `f.tenant_id = $1` is deleted from `TRASH_ROOTS_SQL`'s `WHERE`: an alpha-scoped read
/// then returns beta's deletion, and the assertion names it. Unlike `crates/db/tests/recent.rs`,
/// there is no second redundant clause to hold the property — the `users` join is `LEFT` and the
/// parent subquery is a `NOT EXISTS`, so neither can exclude an anchor row. This one predicate is
/// the whole of layer 1 here.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_recycle_bin_stays_out_of_this_tenants_list() {
    let (db, fx, _pool) = harness(2).await;
    let mut conn = db.connect().await.expect("administrative connection");

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    let alpha_file =
        add_node(&mut conn, &alpha, fx.alpha.owner, "Q3 Notes.pdf", "FILE", None).await;
    let beta_file = add_node(&mut conn, &beta, fx.beta.owner, "Q3 Notes.pdf", "FILE", None).await;

    let now = Utc::now();
    let _a = trash_subtree(&mut conn, fx.alpha.id, alpha_file, now, fx.alpha.owner, None).await;
    let _b = trash_subtree(&mut conn, fx.beta.id, beta_file, now, fx.beta.owner, None).await;

    // Row-level security is inert on this connection, and here is the proof. With RLS in force this
    // statement raises `unrecognized configuration parameter "app.tenant_id"`; a superuser bypasses
    // the policy and reads both tenants' rows. Everything below therefore tests the SQL alone.
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT tenant_id) FROM files WHERE deleted_at IS NOT NULL",
    )
    .fetch_one(&mut conn)
    .await
    .expect(
        "the superuser connection must be able to read files with no app.tenant_id set; if this \
         errors, row-level security is in force and the assertions below would be proving RLS \
         rather than the predicate",
    );
    assert_eq!(
        visible, 2,
        "this connection must be able to see both tenants' deletions, or the cross-tenant \
         assertion below is held by row security and not by the query"
    );

    let ids = |window: TrashCandidates| {
        window.candidates.into_iter().map(|c| c.file_id).collect::<Vec<_>>()
    };

    // The positive control, asserted before the negative: beta's deletion exists and is readable.
    assert_eq!(
        ids(roots_on(&mut conn, fx.beta.id, 50).await.expect("beta's recycle bin")),
        vec![beta_file],
        "beta's own bin must resolve, or the absence below is an absence of everything"
    );

    assert_eq!(
        ids(roots_on(&mut conn, fx.alpha.id, 50).await.expect("alpha's recycle bin")),
        vec![alpha_file],
        "alpha's bin must hold alpha's deletion and nothing of beta's, with row security switched \
         off — both files are called `Q3 Notes.pdf`, so this cannot pass on a name"
    );
}

// -------------------------------------------------------------------------------------------------
// Ordering
// -------------------------------------------------------------------------------------------------

/// The bin is ordered by the deletion instant, most recent first — and re-deleting an old item moves
/// it to the top.
///
/// The second half is the positive control for the first. Three files deleted in order come back
/// reversed, which is also what an implementation returning rows in *id* order would produce if the
/// fixture happened to create them backwards; restoring the oldest, deleting it again and watching
/// it lead the list is what separates "ordered by time" from "ordered by anything correlated with
/// it".
///
/// Fails when `ORDER BY f.deleted_at DESC` in `TRASH_ROOTS_SQL` becomes `ASC`, and when the
/// `ORDER BY` is deleted altogether (the re-deletion stops moving anything).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_bin_is_ordered_most_recently_deleted_first() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let b = add_node(&mut admin, &s, user, "b.txt", "FILE", None).await;
    let c = add_node(&mut admin, &s, user, "c.txt", "FILE", None).await;

    let start = Utc::now() - Duration::hours(1);
    /* Three deletions a minute apart, so the ordering assertion below is about `deleted_at` and
     * not about insertion order — which would pass against a statement with no `ORDER BY` at all. */
    let _oldest = trash_subtree(&mut admin, alpha, s.file, start, user, None).await;
    let _middle =
        trash_subtree(&mut admin, alpha, b, start + Duration::minutes(1), user, None).await;
    let _newest =
        trash_subtree(&mut admin, alpha, c, start + Duration::minutes(2), user, None).await;

    assert_eq!(
        listed(&pool, alpha, 50).await,
        vec![c, b, s.file],
        "the most recently deleted item must lead the bin"
    );

    untrash(&mut admin, alpha, s.file).await;
    let _again = trash_subtree(&mut admin, alpha, s.file, Utc::now(), user, None).await;

    assert_eq!(
        listed(&pool, alpha, 50).await,
        vec![s.file, c, b],
        "re-deleting the oldest item must move it to the top; if it does not, the order above was \
         creation order wearing a timestamp"
    );
}

// -------------------------------------------------------------------------------------------------
// What the contract needs from the row
// -------------------------------------------------------------------------------------------------

/// A row carries the revision the restore demands, and who deleted it.
///
/// `revision` is the field this whole endpoint exists to deliver: `POST /files/{id}/restore`
/// requires `If-Match`, and a trashed file answers `404` to the `GET` a client would otherwise read
/// its `ETag` from — so a listing without it shows a caller a document they cannot restore. It is
/// asserted against the value read independently over the administrative connection, not against a
/// constant, so a query that returned a plausible-looking number for the wrong row would fail.
///
/// `deletedBy` is `files.modified_by`, which the trash write stamps; the display name comes from the
/// `LEFT JOIN`. The member deletes and the owner does not, so a join that resolved the wrong user
/// would be visible rather than merely unasserted.
///
/// The library-root row and the nested row are each other's control for `parentFolderId`: a query
/// that returned `NULL` for every row would satisfy the first assertion alone. `purge_after` is
/// asserted in both its states for the same reason.
///
/// Fails when `f.revision` is dropped from the select list (the decode errors), when
/// `f.modified_by` is replaced by `f.created_by` (the deleter comes back as the owner), when
/// `f.parent_id` becomes a literal `NULL`, and when the `LEFT JOIN users` becomes a plain `JOIN` —
/// which does not fail here but fails in the shape this comment warns about, as a missing row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_row_carries_the_revision_the_restore_requires_and_who_deleted_it() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let (owner, deleter) = (fx.alpha.owner, fx.alpha.member);

    let s = spine(&mut admin, alpha, owner).await;
    let at_root = add_node(&mut admin, &s, owner, "Q3 Notes.pdf", "FILE", None).await;

    let purge = Utc::now() + Duration::days(30);
    let deleted_at = Utc::now();
    let _nested = trash_subtree(&mut admin, alpha, s.file, deleted_at, deleter, Some(purge)).await;
    // Deleted by a path that set no retention — the case `purgeAfter: null` describes.
    let _rooted =
        trash_subtree(&mut admin, alpha, at_root, deleted_at + Duration::seconds(1), deleter, None)
            .await;

    let expected_revision: i64 = sqlx::query_scalar("SELECT revision FROM files WHERE id = $1")
        .bind(s.file.as_uuid())
        .fetch_one(&mut admin)
        .await
        .expect("read the stored revision");

    let window = page(&pool, alpha, 50).await;

    let nested = find(&window, s.file);
    assert_eq!(
        nested.revision, expected_revision,
        "the row must carry the revision the next `If-Match` needs; without it this listing shows a \
         document nobody can restore"
    );
    assert_eq!(nested.deleted_at, deleted_at, "the instant the cascade stamped");
    assert_eq!(nested.purge_after, Some(purge), "how long is left is on the wire");
    assert_eq!(
        nested.deleted_by, deleter,
        "`deletedBy` is files.modified_by, which the trash write stamps — not the creator"
    );
    assert_eq!(
        nested.deleted_by_display_name.as_deref(),
        Some("member"),
        "the display name rides along on the users join, or the client shows a UUID to a person"
    );
    assert_eq!(
        nested.parent_folder_id,
        Some(s.folder),
        "a nested item names the folder it will return into"
    );
    assert_eq!(nested.library_id, s.library);
    assert_eq!(
        nested.mime_type, "application/octet-stream",
        "the media type rides along as stored, whatever the spine wrote"
    );
    assert_eq!(nested.kind, TrashedKind::File);

    let rooted = find(&window, at_root);
    assert_eq!(
        rooted.parent_folder_id, None,
        "an item at the library root has no parent folder, and this is only meaningful beside the \
         nested row above"
    );
    assert_eq!(
        rooted.purge_after, None,
        "a row deleted with no retention reports none rather than an invented date"
    );
    assert_eq!(rooted.name, "Q3 Notes.pdf");
}

// -------------------------------------------------------------------------------------------------
// The window
// -------------------------------------------------------------------------------------------------

/// The read asks for more than the caller wants, and says whether it stopped short.
///
/// Two reads over one bin of six deletions, and each is the other's control:
///
///   * `limit = 1` reads `OVER_FETCH` candidates — proving the over-fetch is arithmetic and not a
///     comment — and reports `more_beyond_window`, because two of the six were never looked at.
///   * `limit = 2` reaches the end of the bin, returns all six, and reports `false`.
///
/// Without the second, `more_beyond_window` could be a constant `true`; without the first, a
/// constant `false`. The flag is what separates "your recycle bin holds nothing" from "everything in
/// it belongs to somebody else" once the chain has filtered above.
///
/// Fails when `OVER_FETCH` is set to `1`, and when the probe row is dropped — `LIMIT $2` bound to
/// `window` instead of `window + 1` makes `more_beyond_window` permanently `false`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_window_over_fetches_and_reports_whether_it_stopped_short() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let mut deleted = vec![s.file];
    for n in 0..5 {
        deleted.push(add_node(&mut admin, &s, user, &format!("file-{n}.txt"), "FILE", None).await);
    }
    let start = Utc::now() - Duration::hours(1);
    for (n, node) in deleted.iter().enumerate() {
        let at = start + Duration::minutes(n as i64);
        let _at = trash_subtree(&mut admin, alpha, *node, at, user, None).await;
    }

    let mut tx = pool.begin(alpha).await.expect("begin");
    let narrow = roots(&mut tx, 1).await.expect("a one-row page");
    let wide = roots(&mut tx, 2).await.expect("a two-row page");
    tx.commit().await.expect("commit");

    assert_eq!(
        narrow.candidates.len(),
        OVER_FETCH as usize,
        "asking for one row must read OVER_FETCH candidates, so the policy chain has rows to spare \
         when it refuses some — and in a tenant-wide bin it refuses many"
    );
    assert!(
        narrow.more_beyond_window,
        "six rows exist and four were read, so the caller must be told the window stopped short — \
         otherwise a short page after filtering is indistinguishable from an exhausted bin"
    );

    assert_eq!(wide.candidates.len(), deleted.len(), "a window of eight reaches all six rows");
    assert!(
        !wide.more_beyond_window,
        "the window reached the end of the bin, so a short page after filtering is the whole truth \
         and `filteredCount` is exact; a constant `true` would make that state unreachable"
    );
}
