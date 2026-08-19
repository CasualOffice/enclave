//! Saved views against a real database.
//!
//! The properties worth a live PostgreSQL are the ones migration 0010 enforces rather than this
//! crate: a view belonging to exactly one container, an owner exactly when the scope is personal,
//! and only one default per library. Each is an invariant the read path assumes, and an assumption
//! a database does not enforce is one that holds until the first bulk import.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{LibraryId, TenantId, UserId, Uuid};
use enclave_db::{DbPool, TenantScoped};
use enclave_libraries::views::{NewLibraryView, ViewRepository, ViewScope, ViewType};
use enclave_libraries::{ExternalSharing, LibraryRepository, LibrarySettings, VersioningMode};
use enclave_testing::{Fixtures, TestDb};
use serde_json::json;
use sqlx::PgConnection;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

async fn insert_workspace(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workspaces (id, tenant_id, name, slug, visibility, created_by, created_at,
                                 updated_at)
         VALUES ($1, $2, 'Engineering', 'engineering', 'PRIVATE', $3, $4, $4)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert workspace");
    id
}

fn settings(name: &str) -> LibrarySettings {
    LibrarySettings {
        name: name.to_owned(),
        slug: name.to_lowercase(),
        inherit_permissions: true,
        default_classification_id: None,
        versioning_mode: VersioningMode::MajorMinor,
        version_limit: Some(25),
        require_checkout: false,
        require_approval: false,
        allowed_extensions: None,
        blocked_extensions: None,
        max_file_size_bytes: None,
        external_sharing: ExternalSharing::Disabled,
        ai_indexing_enabled: false,
        mcp_visible: true,
        sync_enabled: false,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

fn new_view(
    library: LibraryId,
    name: &str,
    scope: ViewScope,
    owner: Option<UserId>,
) -> NewLibraryView {
    NewLibraryView {
        library_id: library,
        name: name.to_owned(),
        view_type: ViewType::List,
        filter_definition: json!({ "status": "AVAILABLE" }),
        sort_definition: json!([{ "field": "name", "direction": "asc" }]),
        group_definition: None,
        visible_columns: json!(["name", "modified", "size"]),
        column_widths: None,
        scope,
        owner_id: owner,
        is_default: false,
        created_by: owner.unwrap_or_else(|| UserId::from(Uuid::nil())),
    }
}

async fn library(pool: &DbPool, tenant: TenantId, owner: UserId) -> LibraryId {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let workspace = insert_workspace(&mut tx, tenant, owner).await;
    let created = LibraryRepository::create(
        &mut tx,
        tenant,
        enclave_core::WorkspaceId::from(workspace),
        &settings("Specs"),
        Utc::now(),
    )
    .await
    .expect("create library");
    tx.commit().await.expect("commit");
    created.id
}

/// One person's arrangement is not visible to another person.
///
/// Small on its own, and exactly the kind of thing an information barrier exists to stop leaking
/// between two people who must not know what the other is working on: a saved filter says what
/// somebody is looking for.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0010; CI runs it with --include-ignored"]
async fn a_personal_view_belongs_to_one_person_and_a_shared_one_to_everybody() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let (owner, other) = (fixtures.alpha.owner, fixtures.alpha.member);
    let library = library(&pool, alpha, owner).await;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "Team view", ViewScope::Library, None),
        now,
    )
    .await
    .expect("shared view");
    ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "My view", ViewScope::Personal, Some(owner)),
        now,
    )
    .await
    .expect("owner's personal view");
    ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "Their view", ViewScope::Personal, Some(other)),
        now,
    )
    .await
    .expect("other's personal view");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let seen =
        ViewRepository::list_for_library(&mut tx, alpha, library, owner).await.expect("list");
    tx.commit().await.expect("commit");

    let names: Vec<&str> = seen.iter().map(|view| view.name.as_str()).collect();
    assert!(names.contains(&"Team view"), "the shared view is missing: {names:?}");
    assert!(names.contains(&"My view"), "the caller's own view is missing: {names:?}");
    assert!(
        !names.contains(&"Their view"),
        "another person's saved filter was returned, which says what they are looking for: {names:?}"
    );

    drop(db);
}

/// The database refuses a personal view with no owner, and a shared one with an owner.
///
/// Both are enforced by `CHECK`s rather than by this crate, so this asserts what actually protects
/// the invariant. A personal view with no owner is visible to everyone; a shared view with one
/// belongs to somebody who can be deactivated.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0010; CI runs it with --include-ignored"]
async fn the_database_refuses_a_view_whose_owner_disagrees_with_its_scope() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let library = library(&pool, alpha, owner).await;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let ownerless_personal = ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "A", ViewScope::Personal, None),
        now,
    )
    .await;
    assert!(ownerless_personal.is_err(), "a personal view with no owner is visible to everyone");
    tx.rollback().await.expect("rollback");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let owned_shared = ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "B", ViewScope::Library, Some(owner)),
        now,
    )
    .await;
    assert!(owned_shared.is_err(), "a shared view was allowed to belong to one person");
    tx.rollback().await.expect("rollback");

    drop(db);
}

/// A library has one default, and promoting a view demotes the previous one atomically.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0010; CI runs it with --include-ignored"]
async fn a_library_has_exactly_one_default_and_a_personal_view_can_never_be_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;
    let library = library(&pool, alpha, owner).await;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let first = ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "First", ViewScope::Library, None),
        now,
    )
    .await
    .expect("first");
    let second = ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "Second", ViewScope::Library, None),
        now,
    )
    .await
    .expect("second");
    let personal = ViewRepository::create(
        &mut tx,
        alpha,
        &new_view(library, "Mine", ViewScope::Personal, Some(owner)),
        now,
    )
    .await
    .expect("personal");

    assert!(ViewRepository::set_default(&mut tx, alpha, library, first.id, now)
        .await
        .expect("promote"));
    // Promoting the second must demote the first in the same statement pair, or the unique index
    // refuses — which is what makes "exactly one" true rather than "usually one".
    assert!(ViewRepository::set_default(&mut tx, alpha, library, second.id, now)
        .await
        .expect("promote"));

    // A personal view cannot be a library's default: promoting one imposes somebody's own
    // arrangement on everybody, which is a different act.
    assert!(
        !ViewRepository::set_default(&mut tx, alpha, library, personal.id, now)
            .await
            .expect("refuse"),
        "a personal view was promoted to the library's default"
    );

    let defaults: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM library_views WHERE tenant_id = $1 AND library_id = $2 AND is_default",
    )
    .bind(alpha.as_uuid())
    .bind(library.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(defaults, 1);
    tx.commit().await.expect("commit");

    drop(db);
}

/// A view belongs to exactly one container.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0010; CI runs it with --include-ignored"]
async fn a_view_cannot_belong_to_both_a_library_and_a_list_or_to_neither() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let library = library(&pool, alpha, fixtures.alpha.owner).await;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    for (label, library_id, list_id) in
        [("both", Some(library.as_uuid()), Some(Uuid::now_v7())), ("neither", None, None)]
    {
        let attempt = sqlx::query(
            "INSERT INTO library_views
               (id, tenant_id, library_id, list_id, name, view_type, filter_definition,
                sort_definition, visible_columns, scope, is_default, created_by, created_at,
                updated_at)
             VALUES ($1, $2, $3, $4, 'V', 'LIST', '{}'::jsonb, '[]'::jsonb, '[]'::jsonb,
                     'LIBRARY', FALSE, $5, $6, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(alpha.as_uuid())
        .bind(library_id)
        .bind(list_id)
        .bind(Uuid::nil())
        .bind(now)
        .execute(&mut *tx)
        .await;
        assert!(attempt.is_err(), "a view belonging to {label} container(s) was accepted");
    }
    tx.rollback().await.expect("rollback");

    drop(db);
}
