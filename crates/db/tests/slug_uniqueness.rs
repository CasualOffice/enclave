//! `ENC-544` — a slug addresses exactly one live row in its container.
//!
//! The rule is `docs/04-DATA-MODEL.md §10.1`; `migrations/0017_slug_uniqueness.sql` is what puts it
//! in the schema. This file is the proof that the indexes do what §10.1 says, rather than that they
//! exist — a structural assertion ("an index named `uq_library_slug` is present") would pass against
//! an index over the wrong columns, or a non-unique one, or one whose predicate is missing.
//!
//! # Every refusal here has a permission beside it
//!
//! `docs/12 §1.2`: an assertion about an absence passes for free. "The second insert failed" holds
//! trivially against a schema where *no* insert succeeds — a typo in a column name, a `NOT NULL` on
//! something these tests do not set. So each refusal is paired with a case that must be **accepted**
//! by the same statement shape:
//!
//! | Refusal | Its positive control |
//! |---|---|
//! | a duplicate slug in one workspace | [`a_trashed_library_releases_its_slug`] — same slug, same workspace, accepted once the holder is trashed |
//! | (as above) | [`one_slug_in_two_workspaces_is_two_addresses`] — the key is scoped to the workspace, not the tenant |
//! | (as above) | [`one_slug_in_two_tenants_is_two_addresses`] — and `tenant_id` leads it (`CLAUDE.md` rule 4) |
//! | a duplicate list slug | [`a_trashed_list_releases_its_slug`] |
//! | (as above) | [`a_library_and_a_list_may_share_a_slug`] — the two indexes are separate namespaces, which §10.1 decides and constrains any future route by |
//!
//! And the refusals assert the **constraint name**, not merely that an error occurred: a `23505`
//! from some other unique index would otherwise read as this one holding.
//!
//! # Why these are raw statements rather than a repository call
//!
//! There is no repository for `lists` at all, and `LibraryRepository` deliberately does not
//! read-then-write to check slugs (`crates/libraries/src/library_repo.rs`). The property under test
//! belongs to the database, so it is asserted against the database, with the exact `INSERT` a writer
//! issues.
//!
//! Ignored by default because it needs a live PostgreSQL. CI runs it with `--include-ignored`; the
//! database is a throwaway the harness creates, never the one `DATABASE_URL` names (`ENC-504`).

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_testing::TestDb;
use sqlx::{Error as SqlxError, PgConnection};
use uuid::Uuid;

/// A freshly created, freshly migrated database, and a connection to it.
///
/// The handle is returned rather than dropped: dropping it drops the database.
async fn migrated() -> (TestDb, PgConnection) {
    let db = TestDb::start().await.expect(
        "the slug tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let conn = db.connect().await.expect("connect to the throwaway database");
    (db, conn)
}

/// Writes a workspace. Its own slug is unique per row, so `uq_workspace_slug` is never what refuses
/// anything below.
async fn workspace(conn: &mut PgConnection, tenant: Uuid, id: Uuid) {
    sqlx::query(
        "INSERT INTO workspaces
           (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
         VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, now(), now())",
    )
    .bind(id)
    .bind(tenant)
    .bind(format!("ws-{id}"))
    .bind(Uuid::now_v7())
    .execute(&mut *conn)
    .await
    .expect("insert workspace");
}

/// Attempts a library. Every column is spelled as `docs/04 §7` defines it.
async fn library(
    conn: &mut PgConnection,
    tenant: Uuid,
    ws: Uuid,
    id: Uuid,
    slug: &str,
) -> Result<(), SqlxError> {
    sqlx::query(
        "INSERT INTO libraries
           (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
            external_sharing, created_at, updated_at)
         VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', now(), now())",
    )
    .bind(id)
    .bind(tenant)
    .bind(ws)
    .bind(slug)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// Attempts a list. `docs/04 §10`.
async fn list(
    conn: &mut PgConnection,
    tenant: Uuid,
    ws: Uuid,
    id: Uuid,
    slug: &str,
) -> Result<(), SqlxError> {
    sqlx::query(
        "INSERT INTO lists
           (id, tenant_id, workspace_id, name, slug, created_at, updated_at)
         VALUES ($1, $2, $3, 'list', $4, now(), now())",
    )
    .bind(id)
    .bind(tenant)
    .bind(ws)
    .bind(slug)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// Soft-deletes one row. Two literal statements rather than an interpolated table name: sqlx's
/// `SqlSafeStr` bound refuses a built string outright, and the refusal is right.
async fn trash(conn: &mut PgConnection, table: Table, id: Uuid) {
    let statement = match table {
        Table::Libraries => "UPDATE libraries SET deleted_at = now() WHERE id = $1",
        Table::Lists => "UPDATE lists SET deleted_at = now() WHERE id = $1",
    };
    sqlx::query(statement).bind(id).execute(&mut *conn).await.expect("soft-delete");
}

/// Which container [`trash`] is acting on.
#[derive(Debug, Clone, Copy)]
enum Table {
    Libraries,
    Lists,
}

/// Asserts the failure is a unique violation raised by `index`, and not merely *a* failure.
fn refused_by(result: Result<(), SqlxError>, index: &str) {
    let err = match result {
        Ok(()) => panic!("the insert was accepted; `{index}` did not refuse the duplicate"),
        Err(err) => err,
    };
    let db = err
        .as_database_error()
        .unwrap_or_else(|| panic!("expected a database error from `{index}`, got: {err}"));
    assert_eq!(
        db.code().as_deref(),
        Some("23505"),
        "expected a unique violation from `{index}`, got SQLSTATE {:?}: {db}",
        db.code()
    );
    assert_eq!(
        db.constraint(),
        Some(index),
        "a unique violation was raised, but by `{:?}` rather than by `{index}` — the test would \
         otherwise report a different index holding this property (docs/12 §1.2)",
        db.constraint()
    );
}

// -------------------------------------------------------------------------------------------
// libraries — uq_library_slug
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_second_live_library_cannot_take_a_slug_in_the_same_workspace() {
    let (_db, mut conn) = migrated().await;
    let (tenant, ws) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, ws).await;

    library(&mut conn, tenant, ws, Uuid::now_v7(), "reports")
        .await
        .expect("the first library takes the slug");

    // Two live libraries called `reports` in one workspace make `…/{workspace}/reports` resolve to
    // whichever row the plan returns first — with two different ACLs behind it. §10.1.
    refused_by(library(&mut conn, tenant, ws, Uuid::now_v7(), "reports").await, "uq_library_slug");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_library_releases_its_slug() {
    let (_db, mut conn) = migrated().await;
    let (tenant, ws) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, ws).await;

    let first = Uuid::now_v7();
    library(&mut conn, tenant, ws, first, "reports").await.expect("the first library");
    trash(&mut conn, Table::Libraries, first).await;

    // The `WHERE deleted_at IS NULL` predicate, and the reason it is there: without it, "delete it
    // and start again" fails with an error naming a row the user can no longer see.
    library(&mut conn, tenant, ws, Uuid::now_v7(), "reports")
        .await
        .expect("a trashed library must not hold its slug against a replacement");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_slug_in_two_workspaces_is_two_addresses() {
    let (_db, mut conn) = migrated().await;
    let tenant = Uuid::now_v7();
    let (finance, legal) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, finance).await;
    workspace(&mut conn, tenant, legal).await;

    // `finance/reports` and `legal/reports` are two different reachable paths. A tenant-wide key
    // would refuse the second, which is why the index is scoped to the workspace.
    library(&mut conn, tenant, finance, Uuid::now_v7(), "reports").await.expect("finance/reports");
    library(&mut conn, tenant, legal, Uuid::now_v7(), "reports")
        .await
        .expect("legal/reports is a different path and must be permitted");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_slug_in_two_tenants_is_two_addresses() {
    let (_db, mut conn) = migrated().await;
    let (alpha, beta) = (Uuid::now_v7(), Uuid::now_v7());
    let (ws_a, ws_b) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, alpha, ws_a).await;
    workspace(&mut conn, beta, ws_b).await;

    // `tenant_id` leads the key (`CLAUDE.md` rule 4). A slug index that forgot it would make one
    // tenant's naming choices refuse another's — a cross-tenant coupling through a unique index.
    library(&mut conn, alpha, ws_a, Uuid::now_v7(), "reports").await.expect("alpha's reports");
    library(&mut conn, beta, ws_b, Uuid::now_v7(), "reports")
        .await
        .expect("a slug in one tenant must say nothing about another tenant's");
}

// -------------------------------------------------------------------------------------------
// lists — uq_list_slug
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_second_live_list_cannot_take_a_slug_in_the_same_workspace() {
    let (_db, mut conn) = migrated().await;
    let (tenant, ws) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, ws).await;

    list(&mut conn, tenant, ws, Uuid::now_v7(), "requests").await.expect("the first list");
    refused_by(list(&mut conn, tenant, ws, Uuid::now_v7(), "requests").await, "uq_list_slug");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_list_releases_its_slug() {
    let (_db, mut conn) = migrated().await;
    let (tenant, ws) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, ws).await;

    let first = Uuid::now_v7();
    list(&mut conn, tenant, ws, first, "requests").await.expect("the first list");
    trash(&mut conn, Table::Lists, first).await;

    list(&mut conn, tenant, ws, Uuid::now_v7(), "requests")
        .await
        .expect("a trashed list must not hold its slug against a replacement");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_and_a_list_may_share_a_slug() {
    let (_db, mut conn) = migrated().await;
    let (tenant, ws) = (Uuid::now_v7(), Uuid::now_v7());
    workspace(&mut conn, tenant, ws).await;

    // Two indexes, two namespaces — §10.1 decides this, and the consequence it names is a
    // constraint on any slug route designed later: the container kind has to appear in the path.
    // Asserted here so that a future migration collapsing the two namespaces fails a test rather
    // than passing silently.
    library(&mut conn, tenant, ws, Uuid::now_v7(), "reports").await.expect("the library");
    list(&mut conn, tenant, ws, Uuid::now_v7(), "reports")
        .await
        .expect("a list and a library are separate namespaces (docs/04 §10.1)");
}
