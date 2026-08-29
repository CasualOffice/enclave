//! `recent_files` against a real PostgreSQL — the read model behind `GET /api/v1/me/recent`.
//!
//! `docs/12-TESTING.md §1.2` is the shape every test here is written to, and two of its rules do
//! most of the work:
//!
//! * **An assertion about an absence passes for free.** "The other tenant's file was not in the
//!   list", "the other user's file was not in the list", "the trashed file was not in the list" are
//!   all true of a `recent` that returns nothing at all, of a table that was never written, and of a
//!   `record` that silently no-ops. So every test below that asserts something is *missing* proves,
//!   **under the identical fixture and in the same run**, that something comparable is *present*.
//!   The positive control is not decoration; without it the negative is a statement about the
//!   harness.
//! * **Watch it fail first.** Each test names, in its own doc comment, the edit to
//!   `crates/db/src/recent.rs` or to `migrations/0029_recent_files.sql` that turns it red. Where a
//!   predicate is *not* independently load-bearing, that is said too — see
//!   [`another_tenants_recency_stays_out_of_this_tenants_list`], whose comment was **wrong in its
//!   first draft** and was corrected by running the mutation rather than by reasoning about it: the
//!   statement carries tenant scoping twice, either clause alone is enough for that query, and the
//!   honest claim is about the pair.
//!
//! # Row-level security is deliberately switched off in the isolation test
//!
//! `TestDb::pool` connects as `enclave_app` and therefore runs with RLS in force, which is right for
//! the ordinary paths — a test of the read model should run the way production runs. But it is
//! exactly wrong for a cross-tenant assertion: with RLS in force, deleting the `tenant_id` predicate
//! from the SQL changes nothing observable, and the test would report a property the application
//! query does not hold. That is `ENC-124` in miniature, and this repository has had nine crates
//! where a deleted `tenant_id` predicate failed to fail because row security was holding the
//! property alone.
//!
//! So [`another_tenants_recency_stays_out_of_this_tenants_list`] runs over
//! [`TestDb::connect`] — the harness's cluster superuser, which bypasses row security entirely —
//! and proves that the connection can see both tenants' rows *before* asking [`recent_on`] the
//! question. What it demonstrates is the predicate, alone, unassisted.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use chrono::{DateTime, Utc};
use enclave_core::{ClassificationId, FileId, TenantId, UserId};
use enclave_db::recent::{recent, recent_on, record, record_on, OVER_FETCH};
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
/// something to join to, and writing them through the application role would be testing the
/// fixtures rather than the query.
async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    spine
}

/// One more `FILE` node in an existing spine, so a test can have several to order.
///
/// `parent` is `None` for a file directly at the library root, which is the case the contract's
/// `parentFolderId: null` describes. Every column is spelled as `migrations/0005_files.sql` defines
/// it, so a schema that drifts from it fails here rather than somewhere subtler.
async fn add_file(
    conn: &mut PgConnection,
    spine: &Spine,
    owner: UserId,
    name: &str,
    parent: Option<FileId>,
    mime: &str,
    classification: Option<ClassificationId>,
) -> FileId {
    let id = FileId::new_v7();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, classification_id, classification_source, inherit_permissions, created_by,
            modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, $5, 'FILE', $6, $6, $7, $8,
                 CASE WHEN $8::uuid IS NULL THEN NULL ELSE 'MANUAL' END,
                 TRUE, $9, $9, now(), now())",
    )
    .bind(id.as_uuid())
    .bind(spine.tenant.as_uuid())
    .bind(spine.workspace.as_uuid())
    .bind(spine.library.as_uuid())
    .bind(parent.map(|p| p.as_uuid()))
    .bind(name)
    .bind(mime)
    .bind(classification.map(|c| c.as_uuid()))
    .bind(owner.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("insert a file node");
    id
}

/// A label in a tenant's vocabulary, written as setup.
async fn add_classification(
    conn: &mut PgConnection,
    tenant: TenantId,
    key: &str,
    label: &str,
    rank: i32,
) -> ClassificationId {
    let id = ClassificationId::new_v7();
    sqlx::query(
        "INSERT INTO classifications (tenant_id, id, key, label, rank) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .bind(key)
    .bind(label)
    .bind(rank)
    .execute(&mut *conn)
    .await
    .expect("define a classification");
    id
}

/// Records one touch in its own transaction and commits, which is the shape every writer uses.
///
/// Separate transactions matter here and are not incidental: `now()` is `transaction_timestamp()`,
/// so two touches inside one transaction would share an instant and every ordering assertion below
/// would be asserting the tiebreak instead of the recency.
async fn touch(pool: &DbPool, tenant: TenantId, user: UserId, file: FileId) -> DateTime<Utc> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let at = record(&mut tx, user, file).await.expect("record a touch");
    tx.commit().await.expect("commit");
    at
}

/// The file ids in one user's window, most recent first.
async fn listed(pool: &DbPool, tenant: TenantId, user: UserId, limit: u32) -> Vec<FileId> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let page = recent(&mut tx, user, limit).await.expect("read recency");
    tx.commit().await.expect("commit");
    page.candidates.into_iter().map(|c| c.file_id).collect()
}

/// How many rows the table holds for one user, read over the administrative connection.
///
/// Deliberately **not** through [`recent`]: a test that counted rows with the statement under test
/// could not tell "the upsert added no row" from "the read dropped one", which is the whole claim.
async fn stored_rows(conn: &mut PgConnection, tenant: TenantId, user: UserId) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM recent_files WHERE tenant_id = $1 AND user_id = $2")
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .fetch_one(&mut *conn)
        .await
        .expect("count recency rows")
}

// -------------------------------------------------------------------------------------------------
// The upsert
// -------------------------------------------------------------------------------------------------

/// A second touch of the same file moves the instant and leaves the row count where it was.
///
/// Both halves are load-bearing and neither proves the other. "The count is still one" is true of a
/// `record` that failed silently, so the positive control is a touch of a *different* file in the
/// same run, which must take the count to two — that is what makes the first count a statement
/// about the conflict target rather than about whether anything was written at all.
///
/// Fails when the `ON CONFLICT (tenant_id, user_id, file_id) DO UPDATE` arm of `RECORD_SQL` is
/// changed to `DO NOTHING` (the instant stops moving), and when the conflict target is narrowed to
/// `(tenant_id, user_id)` (the second file overwrites the first and the count stays at one).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_second_touch_of_one_file_moves_the_instant_and_adds_no_row() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let second =
        add_file(&mut admin, &s, user, "second.txt", Some(s.folder), "text/plain", None).await;

    let first_touch = touch(&pool, alpha, user, s.file).await;
    assert_eq!(stored_rows(&mut admin, alpha, user).await, 1, "one touch, one row");

    let second_touch = touch(&pool, alpha, user, s.file).await;
    assert!(
        second_touch > first_touch,
        "a second touch must move the instant forwards: {first_touch} then {second_touch}"
    );
    assert_eq!(
        stored_rows(&mut admin, alpha, user).await,
        1,
        "a second touch of the same file must upsert, not append; a recency table that grows per \
         open is the log this read model exists so as not to be"
    );

    // The positive control for the count above. Without it, "still one row" is equally true of a
    // record that wrote nothing at all.
    touch(&pool, alpha, user, second).await;
    assert_eq!(
        stored_rows(&mut admin, alpha, user).await,
        2,
        "a touch of a different file must add a row; if it does not, the count assertion above is \
         measuring a write that never happens"
    );
}

/// An earlier transaction committing later cannot move a user's recency backwards.
///
/// `now()` is `transaction_timestamp()`, so a transaction that *began* first carries an older
/// instant however late it commits. The interleave below is that arrangement made deterministic: a
/// transaction is opened, held open while a second one opens, touches and commits, and only then
/// touches and commits itself.
///
/// The harness precondition — that the two transactions really do carry different instants — is
/// asserted rather than assumed, because if they shared one the test would pass against either
/// implementation and prove nothing.
///
/// Fails when `GREATEST(recent_files.last_accessed_at, EXCLUDED.last_accessed_at)` in `RECORD_SQL`
/// is replaced by the reading-identical `EXCLUDED.last_accessed_at`: the stored instant becomes the
/// earlier transaction's, and the assertion below names both values.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_earlier_transaction_committing_later_cannot_move_recency_backwards() {
    let (db, fx, pool) = harness(4).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;
    let s = spine(&mut admin, alpha, user).await;

    async fn transaction_instant(tx: &mut TenantScoped) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT now()").fetch_one(&mut **tx).await.expect("transaction now()")
    }

    let mut early = pool.begin(alpha).await.expect("begin the earlier transaction");
    let early_now = transaction_instant(&mut early).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut late = pool.begin(alpha).await.expect("begin the later transaction");
    let late_now = transaction_instant(&mut late).await;

    assert!(
        early_now < late_now,
        "the harness must produce two transactions with different instants, or this test cannot \
         distinguish the two implementations: {early_now} vs {late_now}"
    );

    let recorded_late = record(&mut late, user, s.file).await.expect("the later touch");
    late.commit().await.expect("commit the later transaction");
    assert_eq!(recorded_late, late_now, "the later touch stamps its own transaction's instant");

    let recorded_early = record(&mut early, user, s.file).await.expect("the earlier touch");
    early.commit().await.expect("commit the earlier transaction");

    assert_eq!(
        recorded_early, late_now,
        "the earlier transaction committed last and must not have won: recency would go backwards \
         for a user who did nothing but open one document twice"
    );

    // Read it back through the statement the endpoint uses, so the claim is about the stored row
    // and not only about what `record` chose to return.
    let mut tx = pool.begin(alpha).await.expect("begin");
    let page = recent(&mut tx, user, 8).await.expect("read recency");
    tx.commit().await.expect("commit");
    assert_eq!(
        page.candidates.first().expect("one candidate").last_accessed_at,
        late_now,
        "the stored instant must be the later of the two"
    );
}

// -------------------------------------------------------------------------------------------------
// Ordering
// -------------------------------------------------------------------------------------------------

/// The list is ordered by the stored instant, most recent first — and re-touching an old file moves
/// it to the top.
///
/// The second half is the positive control for the first. Three files touched in order come back
/// reversed, which is also what an implementation returning rows in *insertion* order would produce
/// if the fixture happened to insert them backwards; re-touching the oldest and watching it lead the
/// list is what separates "ordered by time" from "ordered by anything correlated with time".
///
/// Fails when `ORDER BY r.last_accessed_at DESC` in `RECENT_SQL` becomes `ASC`, and when the
/// `ORDER BY` is deleted altogether (the re-touch stops moving anything).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_list_is_ordered_by_recency_and_a_re_touch_moves_a_file_to_the_top() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let b = add_file(&mut admin, &s, user, "b.txt", Some(s.folder), "text/plain", None).await;
    let c = add_file(&mut admin, &s, user, "c.txt", Some(s.folder), "text/plain", None).await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, b).await;
    touch(&pool, alpha, user, c).await;

    assert_eq!(
        listed(&pool, alpha, user, 8).await,
        vec![c, b, s.file],
        "the most recently touched file must lead the list"
    );

    touch(&pool, alpha, user, s.file).await;

    assert_eq!(
        listed(&pool, alpha, user, 8).await,
        vec![s.file, c, b],
        "re-touching the oldest file must move it to the top; if it does not, the order above was \
         insertion order wearing a timestamp"
    );
}

// -------------------------------------------------------------------------------------------------
// What must not appear
// -------------------------------------------------------------------------------------------------

/// A trashed file drops out of the list; the live one beside it does not.
///
/// The live file is the positive control and it is asserted in the same read, so "the trashed one
/// is gone" cannot be satisfied by a query that returns nothing. A trashed node also has an empty
/// inheritance chain — `crates/authorization/src/repo.rs` joins `files` with `deleted_at IS NULL` on
/// the walk's own root — so a candidate the chain could not decide either way is dropped before the
/// chain is ever asked.
///
/// Fails when `AND f.deleted_at IS NULL` is deleted from the `files` join in `RECENT_SQL`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_file_leaves_the_list_and_its_live_sibling_stays() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let survivor =
        add_file(&mut admin, &s, user, "survivor.txt", Some(s.folder), "text/plain", None).await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, survivor).await;
    assert_eq!(
        listed(&pool, alpha, user, 8).await.len(),
        2,
        "both files must be listed before one is trashed, or the assertion below is free"
    );

    sqlx::query("UPDATE files SET deleted_at = now() WHERE id = $1")
        .bind(s.file.as_uuid())
        .execute(&mut admin)
        .await
        .expect("trash one file");

    assert_eq!(
        listed(&pool, alpha, user, 8).await,
        vec![survivor],
        "a trashed file must not appear in a recency list, and its live sibling must still be there"
    );
}

/// A purged file takes its recency row with it, and leaves its neighbour's alone.
///
/// This is the composite key's `ON DELETE CASCADE` rather than a predicate, and it is the reason
/// `enclave_app` needs no `DELETE` on `recent_files`: the database reclaims the row, not a job that
/// could be switched off. The surviving row is the positive control — a cascade that deleted
/// everything would satisfy the first assertion on its own.
///
/// Fails when `ON DELETE CASCADE` is dropped from `recent_files`' file key in
/// `migrations/0029_recent_files.sql`: the `DELETE` below then raises a foreign-key violation
/// instead, which the `expect` reports.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_purged_file_takes_its_recency_row_with_it() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let survivor =
        add_file(&mut admin, &s, user, "survivor.txt", Some(s.folder), "text/plain", None).await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, survivor).await;
    assert_eq!(stored_rows(&mut admin, alpha, user).await, 2, "two touches, two rows");

    sqlx::query("DELETE FROM files WHERE id = $1")
        .bind(s.file.as_uuid())
        .execute(&mut admin)
        .await
        .expect("purge one file; the recency row must cascade rather than block the delete");

    assert_eq!(
        stored_rows(&mut admin, alpha, user).await,
        1,
        "the purged file's recency row must be gone, and the other file's must remain"
    );
    assert_eq!(listed(&pool, alpha, user, 8).await, vec![survivor]);
}

/// One tenant's recency never appears in another's, with row-level security switched off.
///
/// The whole test runs over the harness's cluster superuser connection, where RLS is inert. That is
/// asserted first, not assumed: the connection reads `recent_files` with no `app.tenant_id` set at
/// all and must see both tenants' rows. Under RLS that statement errors — `current_setting` is used
/// in its strict form (`migrations/0002_rls_policies.sql`) — so what follows is a demonstration of
/// the SQL, alone, unassisted.
///
/// Beta's own list is read back as the positive control: the row is present, reachable and
/// well-formed on this very connection, and the only reason it is absent from an alpha-scoped read
/// is the query.
///
/// **Which predicate, precisely, because the first draft of this comment got it backwards and the
/// mutation run is what corrected it.** `RECENT_SQL` carries tenant scoping twice — `r.tenant_id =
/// $1` on the anchor and `f.tenant_id = $1` on the `files` join — and for this query the two are
/// redundant with each other. Deleting *either one alone* leaves this test green, because the
/// survivor still excludes the row; the honest claim is therefore about the **pair**, and deleting
/// both together is what turns it red, leaking beta's document name into an alpha-scoped read. Both
/// stay: the anchor's clause is also what makes `idx_recent_files_by_recency` usable rather than
/// scanning every tenant's recency, and the join's is what keeps a `file_id` that arrived by some
/// route the composite key did not cover from resolving to another tenant's row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_recency_stays_out_of_this_tenants_list() {
    let (db, fx, _pool) = harness(2).await;
    let mut conn = db.connect().await.expect("administrative connection");

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    record_on(&mut conn, fx.alpha.id, fx.alpha.owner, alpha.file).await.expect("alpha touch");
    record_on(&mut conn, fx.beta.id, fx.beta.owner, beta.file).await.expect("beta touch");

    // Row-level security is inert on this connection, and here is the proof. With RLS in force this
    // statement raises `unrecognized configuration parameter "app.tenant_id"`; a superuser bypasses
    // the policy and reads both tenants' rows. Everything below therefore tests the SQL alone.
    let visible: i64 = sqlx::query_scalar("SELECT count(DISTINCT tenant_id) FROM recent_files")
        .fetch_one(&mut conn)
        .await
        .expect(
            "the superuser connection must be able to read recent_files with no app.tenant_id \
             set; if this errors, row-level security is in force and the assertions below would be \
             proving RLS rather than the predicate",
        );
    assert_eq!(
        visible, 2,
        "this connection must be able to see both tenants' recency rows, or the cross-tenant \
         assertions below are held by row security and not by the query"
    );

    let ids = |page: enclave_db::recent::RecentCandidates| {
        page.candidates.into_iter().map(|c| c.file_id).collect::<Vec<_>>()
    };

    // The positive control, asserted before either negative: beta's row exists and is readable.
    assert_eq!(
        ids(recent_on(&mut conn, fx.beta.id, fx.beta.owner, 8).await.expect("beta recency")),
        vec![beta.file],
        "beta's own recency must resolve, or the absences below are an absence of everything"
    );

    // The cross-tenant question as an attacker would put it: alpha's context, beta's principal.
    assert!(
        ids(recent_on(&mut conn, fx.alpha.id, fx.beta.owner, 8).await.expect("cross-tenant read"))
            .is_empty(),
        "a read scoped to alpha must find nothing for a principal who belongs to beta, even on a \
         connection that can see every row in the table"
    );

    assert_eq!(
        ids(recent_on(&mut conn, fx.alpha.id, fx.alpha.owner, 8).await.expect("alpha recency")),
        vec![alpha.file],
        "alpha's list must hold alpha's file and nothing of beta's, with row security switched off"
    );
}

/// A touch naming another tenant's file, or another tenant's user, is refused by the composite key.
///
/// This is the control that actually stops a cross-tenant recency row from *existing*, and it is
/// the database's rather than the query's: `PostgreSQL runs referential-integrity checks with row
/// security deliberately not enforced` (`docs/04 §3.3`), so a single-column `REFERENCES files (id)`
/// would accept another tenant's file id and the read model would then be filtering rows that
/// should never have been storable. The test runs on the superuser connection for the same reason as
/// the one above: with RLS in force the `WITH CHECK` clause would refuse the write first and the key
/// would never be reached, so the assertion would be about the policy rather than about the key.
///
/// The successful touch is the positive control — without it, "the write was refused" is equally
/// true of a statement that is broken for everyone.
///
/// Fails when either composite key in `migrations/0029_recent_files.sql` is narrowed to its
/// single-column form: the offending insert then succeeds and the `expect_err` panics.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_touch_naming_another_tenants_file_or_user_is_refused_by_the_composite_key() {
    let (db, fx, _pool) = harness(2).await;
    let mut conn = db.connect().await.expect("administrative connection");

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    record_on(&mut conn, fx.alpha.id, fx.alpha.owner, alpha.file).await.expect(
        "the same statement must succeed within one tenant, or the refusals below are free",
    );

    // Each failed statement aborts the enclosing implicit transaction only, so a fresh connection
    // per attempt is not needed — but the error has to be observed rather than swallowed.
    record_on(&mut conn, fx.alpha.id, fx.alpha.owner, beta.file).await.expect_err(
        "a recency row in alpha naming beta's file must be refused by recent_files' composite file \
         key; a single-column REFERENCES files (id) would store it, because referential integrity \
         runs with row security not enforced",
    );

    record_on(&mut conn, fx.alpha.id, fx.beta.owner, alpha.file).await.expect_err(
        "a recency row in alpha naming beta's user must be refused by the composite user key",
    );
}

/// A colleague's recency stays out of your list, in the same tenant.
///
/// Row-level security cannot hold this at all — it is blind to which member of a tenant a row
/// belongs to — so `r.user_id = $2` is the entire boundary between two people's reading histories,
/// and this test is the only thing that watches it. The two lists are asserted in both directions in
/// one run, so neither assertion can be satisfied by a query that returns nothing.
///
/// Fails when `AND r.user_id = $2` is deleted from `RECENT_SQL`: both lists then hold both files,
/// and every tenant-isolation test in the workspace still passes.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_colleagues_recency_stays_out_of_this_users_list() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let (mine, theirs) = (fx.alpha.owner, fx.alpha.member);

    let s = spine(&mut admin, alpha, mine).await;
    let their_file =
        add_file(&mut admin, &s, mine, "theirs.txt", Some(s.folder), "text/plain", None).await;

    touch(&pool, alpha, mine, s.file).await;
    touch(&pool, alpha, theirs, their_file).await;

    assert_eq!(
        listed(&pool, alpha, theirs, 8).await,
        vec![their_file],
        "the colleague's own list must resolve, or the assertion below is free"
    );
    assert_eq!(
        listed(&pool, alpha, mine, 8).await,
        vec![s.file],
        "a file another user opened must not appear in this user's list; tenancy does not separate \
         two people, only this predicate does"
    );
}

// -------------------------------------------------------------------------------------------------
// What the contract needs from the join
// -------------------------------------------------------------------------------------------------

/// The file's own label rides along as key, label and rank; an unlabelled file reports `None`.
///
/// Both cases in one read. The unlabelled row is the half that a plain `JOIN` instead of a
/// `LEFT JOIN` would silently drop, which would show up as a *shorter list* rather than as a missing
/// chip — the kind of defect that looks like a filtering bug from the client.
///
/// Fails when the `LEFT JOIN classifications` becomes a `JOIN` (the unlabelled file vanishes), and
/// when `c.rank` is dropped from the select list (the decode errors rather than returning a chip
/// with no rank).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_files_own_label_rides_along_and_an_unlabelled_file_reports_none() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let internal = add_classification(&mut admin, alpha, "INTERNAL", "Internal", 20).await;
    let s = spine(&mut admin, alpha, user).await;
    let labelled = add_file(
        &mut admin,
        &s,
        user,
        "labelled.txt",
        Some(s.folder),
        "text/plain",
        Some(internal),
    )
    .await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, labelled).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    let page = recent(&mut tx, user, 8).await.expect("read recency");
    tx.commit().await.expect("commit");

    let top = page.candidates.first().expect("the labelled file leads the list");
    assert_eq!(top.file_id, labelled);
    let chip = top.classification.as_ref().expect("the labelled file must carry its label");
    assert_eq!(chip.key, "INTERNAL");
    assert_eq!(chip.label, "Internal");
    assert_eq!(chip.rank.get(), 20);

    let unlabelled = page.candidates.get(1).expect(
        "the unlabelled file must still be listed; a plain JOIN would drop it and the list would \
         look filtered rather than unlabelled",
    );
    assert_eq!(unlabelled.file_id, s.file);
    assert!(
        unlabelled.classification.is_none(),
        "a file carrying no label must report none, not a borrowed one"
    );
}

/// A file at the library root reports no parent folder; one inside a folder names it.
///
/// The contract's `parentFolderId: null` is the root case, and it is only meaningful beside the
/// nested case — a query that returned `NULL` for every row would satisfy the first assertion alone.
/// The name and MIME type are checked in the same read because they are the other two columns the
/// wire row cannot be built without, and a join that silently returned the wrong file's name would
/// otherwise pass every ordering test above.
///
/// Fails when `f.parent_id` is replaced by a literal `NULL` in `RECENT_SQL`, and when the `files`
/// join loses `AND f.id = r.file_id` (every row then reports whichever file the planner reached
/// first).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_at_the_library_root_reports_no_parent_folder() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let at_root = add_file(&mut admin, &s, user, "root.md", None, "text/markdown", None).await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, at_root).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    let page = recent(&mut tx, user, 8).await.expect("read recency");
    tx.commit().await.expect("commit");

    let root_row = page.candidates.first().expect("the root file leads the list");
    assert_eq!(root_row.file_id, at_root);
    assert_eq!(root_row.parent_folder_id, None, "a file at the library root has no parent folder");
    assert_eq!(root_row.name, "root.md");
    assert_eq!(root_row.mime_type, "text/markdown");
    assert_eq!(root_row.library_id, s.library);

    let nested = page.candidates.get(1).expect("the nested file is listed too");
    assert_eq!(
        nested.parent_folder_id,
        Some(s.folder),
        "a file inside a folder must name it, or the assertion above is true of every row"
    );
}

/// A folder that was touched never appears; the file beside it does.
///
/// Recording is deliberately cheap and asks no questions, so a caller that touches a folder writes a
/// row — the read is where the contract's shape is enforced. The file is the positive control in the
/// same read.
///
/// Fails when `AND f.node_type = 'FILE'` is deleted from the `files` join in `RECENT_SQL`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_folder_never_appears_in_a_recency_list() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;

    touch(&pool, alpha, user, s.file).await;
    touch(&pool, alpha, user, s.folder).await;

    assert_eq!(stored_rows(&mut admin, alpha, user).await, 2, "both touches were recorded");
    assert_eq!(
        listed(&pool, alpha, user, 8).await,
        vec![s.file],
        "a folder has no extension, no mime chip and no peek target, so it is not a recency row — \
         but the file beside it must still be one"
    );
}

// -------------------------------------------------------------------------------------------------
// The window
// -------------------------------------------------------------------------------------------------

/// The read asks for more than the caller wants, and says whether it stopped short.
///
/// Two reads over one fixture of six files, and each is the other's control:
///
///   * `limit = 1` reads `OVER_FETCH` candidates — proving the over-fetch is arithmetic and not a
///     comment — and reports `more_beyond_window`, because two of the six were never looked at.
///   * `limit = 2` reaches the end of the user's recency, returns all six, and reports `false`.
///
/// Without the second, `more_beyond_window` could be a constant `true`; without the first, a
/// constant `false`. `home.md` renders different empty states for "you have no recent files" and
/// "some were withheld", so a caller that cannot tell a short page from an exhausted one cannot pick
/// between them.
///
/// Fails when `OVER_FETCH` is set to `1`, and when the probe row is dropped — `LIMIT $3` bound to
/// `window` instead of `window + 1` makes `more_beyond_window` permanently `false`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_window_over_fetches_and_reports_whether_it_stopped_short() {
    let (db, fx, pool) = harness(2).await;
    let mut admin = db.connect().await.expect("administrative connection");
    let alpha = fx.alpha.id;
    let user = fx.alpha.owner;

    let s = spine(&mut admin, alpha, user).await;
    let mut files = vec![s.file];
    for n in 0..5 {
        files.push(
            add_file(
                &mut admin,
                &s,
                user,
                &format!("file-{n}.txt"),
                Some(s.folder),
                "text/plain",
                None,
            )
            .await,
        );
    }
    for file in &files {
        touch(&pool, alpha, user, *file).await;
    }

    let mut tx = pool.begin(alpha).await.expect("begin");
    let narrow = recent(&mut tx, user, 1).await.expect("a one-row page");
    let wide = recent(&mut tx, user, 2).await.expect("a two-row page");
    tx.commit().await.expect("commit");

    assert_eq!(
        narrow.candidates.len(),
        OVER_FETCH as usize,
        "asking for one row must read OVER_FETCH candidates, so the policy chain has rows to spare \
         when it refuses some"
    );
    assert!(
        narrow.more_beyond_window,
        "six rows exist and four were read, so the caller must be told the window stopped short — \
         otherwise a short page after filtering is indistinguishable from an exhausted list"
    );

    assert_eq!(wide.candidates.len(), files.len(), "a window of eight reaches all six rows");
    assert!(
        !wide.more_beyond_window,
        "the window reached the end of this user's recency, so a short page after filtering is the \
         whole truth; a constant `true` would make the client's filtered-empty state permanent"
    );
}
