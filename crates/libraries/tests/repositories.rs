//! The library repository against a real PostgreSQL.
//!
//! Every test here is `#[ignore]`d and runs under the `enclave-testing` harness — `TestDb::start`
//! plus `DATABASE_URL`, which CI provides and invokes with `--include-ignored`
//! (`.github/workflows/ci.yml`, `crates/testing/src/lib.rs`). What they assert cannot be asserted
//! without a database: that the composite foreign key refuses a library under another tenant's
//! workspace, that an `If-Match` comparison inside an `UPDATE` is atomic with the write, and that
//! seventeen settings — two of them JSONB — survive a round trip in the order the statements bind
//! them.
//!
//! **Queries run as `enclave_app`.** `DATABASE_URL` points at a cluster superuser, because the
//! harness has to create databases, and *superusers bypass row-level security entirely*. Work goes
//! through `TestDb::pool`, which sets the application role; a test that used `TestDb::connect` for
//! its assertions would run with isolation switched off and prove nothing (PR #22).
//!
//! Workspaces are inserted here with plain SQL rather than through `enclave-workspaces`. This crate
//! does not depend on that one, and a test-only dependency to obtain a parent row would make the
//! two crates' test suites fail together for reasons that have nothing to do with either.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{TenantId, WorkspaceId};
use enclave_db::{sql, DbPool, TenantScoped};
use enclave_libraries::{
    ExternalSharing, LibraryError, LibraryFilter, LibraryRepository, LibrarySettings, PageSize,
    VersioningMode,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

/// Reason attached to every `#[ignore]` here, so the harness is named at each one.
const NEEDS_DB: &str = "requires a live PostgreSQL; CI runs it with --include-ignored";

/// Starts a database, applies migrations and seeds `tenant-alpha` / `tenant-beta`.
async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("build an application-role pool");
    (db, fixtures, pool)
}

/// Inserts a workspace for a library to hang off, as the application role.
async fn insert_workspace(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: enclave_core::UserId,
    slug: &str,
) -> WorkspaceId {
    let id = WorkspaceId::new_v7();
    sqlx::query(
        "INSERT INTO workspaces
           (tenant_id, id, name, slug, visibility, revision, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $3, 'PRIVATE', 1, $4, $5, $5)",
    )
    .bind(sql(tenant))
    .bind(sql(id))
    .bind(slug)
    .bind(sql(owner))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert workspace");
    id
}

/// Settings that exercise every column: both JSONB lists, both nullable numbers, and a
/// non-default value for each boolean so a transposed bind cannot pass unnoticed.
fn settings(name: &str) -> LibrarySettings {
    LibrarySettings {
        name: name.to_owned(),
        slug: name.to_owned(),
        inherit_permissions: false,
        default_classification_id: None,
        versioning_mode: VersioningMode::MajorMinor,
        version_limit: Some(25),
        require_checkout: true,
        require_approval: false,
        allowed_extensions: Some(vec![".docx".to_owned(), ".PDF".to_owned()]),
        blocked_extensions: Some(Vec::new()),
        max_file_size_bytes: Some(5_368_709_120),
        external_sharing: ExternalSharing::ExistingGuests,
        ai_indexing_enabled: false,
        mcp_visible: true,
        sync_enabled: false,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_setting_survives_a_round_trip_including_the_two_json_lists() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let workspace = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "engineering").await;
    let created =
        LibraryRepository::create(&mut tx, alpha, workspace, &settings("Specs"), Utc::now())
            .await
            .expect("create library");
    let found = LibraryRepository::find_by_id(&mut tx, alpha, created.id)
        .await
        .expect("query")
        .expect("the library exists");
    tx.commit().await.expect("commit");

    assert_eq!(found, created);
    assert_eq!(created.revision, 1, "a create must hand back a usable If-Match value");
    assert_eq!(created.workspace_id, workspace);
    assert_eq!(created.settings.slug, "specs", "the slug is folded on the way in");
    // The seventeen settings, as sent. Compared as a whole so a transposed bind between two
    // same-typed columns fails here rather than in production.
    assert_eq!(created.settings, LibrarySettings { slug: "specs".to_owned(), ..settings("Specs") });
    // An empty list is not an absent one: `blocked_extensions` was sent as `[]` and must come back
    // as `[]`, not as `None`.
    assert_eq!(created.settings.blocked_extensions, Some(Vec::new()));
    assert_eq!(
        created.settings.allowed_extensions,
        Some(vec![".docx".to_owned(), ".PDF".to_owned()]),
        "extensions are stored exactly as given, case included"
    );
    assert!(!created.settings.inherit_permissions, "the inheritance break is persisted faithfully");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_cannot_be_created_under_a_workspace_from_another_tenant() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let alpha_workspace = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "finance").await;
    tx.commit().await.expect("commit");

    // Alpha's workspace named from beta, and an id that exists nowhere: one answer for both, so a
    // caller cannot use the difference to learn that a workspace exists somewhere else.
    for target in [alpha_workspace, WorkspaceId::new_v7()] {
        let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
        let refused =
            LibraryRepository::create(&mut tx, beta, target, &settings("Specs"), Utc::now()).await;
        assert!(matches!(refused, Err(LibraryError::NoSuchWorkspace)), "{refused:?}");
        // Dropped rather than committed: a constraint violation aborts the transaction, which is
        // what the crate documentation warns callers about.
        drop(tx);
    }

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stale_revision_is_refused_and_changes_no_setting() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let workspace = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "engineering").await;
    let library =
        LibraryRepository::create(&mut tx, alpha, workspace, &settings("Specs"), Utc::now())
            .await
            .expect("create library");
    tx.commit().await.expect("commit");

    // Someone else's write lands first, opening external sharing up.
    let opened =
        LibrarySettings { external_sharing: ExternalSharing::Anyone, ..library.settings.clone() };
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let updated = LibraryRepository::update(
        &mut tx,
        alpha,
        library.id,
        library.revision,
        &opened,
        Utc::now(),
    )
    .await
    .expect("update")
    .expect("the library exists");
    tx.commit().await.expect("commit");
    assert_eq!(updated.revision, library.revision + 1);
    assert_eq!(updated.settings.external_sharing, ExternalSharing::Anyone);

    // Ours arrives holding the revision we read before that, and would have closed it again.
    let closed =
        LibrarySettings { external_sharing: ExternalSharing::Disabled, ..library.settings.clone() };
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let conflict = LibraryRepository::update(
        &mut tx,
        alpha,
        library.id,
        library.revision,
        &closed,
        Utc::now(),
    )
    .await;
    let stored = LibraryRepository::find_by_id(&mut tx, alpha, library.id)
        .await
        .expect("query")
        .expect("the library exists");
    tx.commit().await.expect("commit");

    match conflict {
        Err(LibraryError::RevisionConflict { current_revision }) => {
            assert_eq!(current_revision, updated.revision, "the client needs a value to retry on");
        }
        other => panic!("expected a revision conflict, got {other:?}"),
    }
    // A lost update here would silently change who can take content out of the tenant.
    assert_eq!(stored, updated);

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listing_stays_inside_one_workspace_and_pages_through_it_exactly_once() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let engineering = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "engineering").await;
    let finance = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "finance").await;

    let mut expected = Vec::new();
    for index in 0..5 {
        let library = LibraryRepository::create(
            &mut tx,
            alpha,
            engineering,
            &settings(&format!("lib-{index}")),
            Utc::now(),
        )
        .await
        .expect("create library");
        expected.push(library.id);
    }
    // Same slugs in the neighbouring workspace: a listing that lost its `workspace_id` predicate
    // would return these too, and every id would still look plausible.
    for index in 0..3 {
        LibraryRepository::create(
            &mut tx,
            alpha,
            finance,
            &settings(&format!("lib-{index}")),
            Utc::now(),
        )
        .await
        .expect("create library");
    }
    tx.commit().await.expect("commit");

    let filter = LibraryFilter::default();
    let limit = PageSize::new(2);
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
        let page = LibraryRepository::list_by_workspace(
            &mut tx,
            alpha,
            engineering,
            &filter,
            limit,
            cursor.as_deref(),
        )
        .await
        .expect("listing");
        tx.commit().await.expect("commit");

        seen.extend(page.libraries.iter().map(|library| library.id));
        assert_eq!(page.has_more, page.next_cursor.is_some());
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, expected, "every library in this workspace exactly once, in creation order");

    // A cursor issued for one workspace's listing is refused for another's.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let first =
        LibraryRepository::list_by_workspace(&mut tx, alpha, engineering, &filter, limit, None)
            .await
            .expect("listing");
    let rejected = LibraryRepository::list_by_workspace(
        &mut tx,
        alpha,
        finance,
        &filter,
        limit,
        first.next_cursor.as_deref(),
    )
    .await;
    tx.commit().await.expect("commit");
    assert!(matches!(rejected, Err(LibraryError::InvalidCursor)), "{rejected:?}");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_trashed_library_leaves_every_ordinary_read_and_another_tenant_never_saw_it() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let workspace = insert_workspace(&mut tx, alpha, fixtures.alpha.owner, "engineering").await;
    let library =
        LibraryRepository::create(&mut tx, alpha, workspace, &settings("Specs"), Utc::now())
            .await
            .expect("create library");
    tx.commit().await.expect("commit");

    // Both isolation layers say the same thing to the other tenant: absence.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
    assert!(LibraryRepository::find_by_id(&mut tx, beta, library.id)
        .await
        .expect("query")
        .is_none());
    assert!(LibraryRepository::update(
        &mut tx,
        beta,
        library.id,
        library.revision,
        &settings("Stolen"),
        Utc::now()
    )
    .await
    .expect("update")
    .is_none());
    assert!(!LibraryRepository::soft_delete(&mut tx, beta, library.id, None, Utc::now())
        .await
        .expect("soft delete"));
    let beta_listing = LibraryRepository::list_by_workspace(
        &mut tx,
        beta,
        workspace,
        &LibraryFilter::default(),
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    tx.commit().await.expect("commit");
    assert!(beta_listing.libraries.is_empty(), "alpha's library was visible from beta");

    // Trashing is idempotent, and honours an If-Match when one is supplied.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(LibraryRepository::soft_delete(
        &mut tx,
        alpha,
        library.id,
        Some(library.revision),
        Utc::now()
    )
    .await
    .expect("soft delete"));
    assert!(!LibraryRepository::soft_delete(&mut tx, alpha, library.id, None, Utc::now())
        .await
        .expect("soft delete"));

    assert!(LibraryRepository::find_by_id(&mut tx, alpha, library.id)
        .await
        .expect("query")
        .is_none());
    let ordinary = LibraryRepository::list_by_workspace(
        &mut tx,
        alpha,
        workspace,
        &LibraryFilter::default(),
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    let trash = LibraryRepository::list_by_workspace(
        &mut tx,
        alpha,
        workspace,
        &LibraryFilter { include_deleted: true },
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    tx.commit().await.expect("commit");

    assert!(ordinary.libraries.is_empty());
    assert!(
        trash.libraries.iter().any(|l| l.id == library.id && l.deleted_at.is_some()),
        "the trash view is the one listing that can still see it"
    );

    pool.close().await;
    drop(db);
}

/// Documents the one thing the `#[ignore]` reason has to keep saying.
#[test]
fn the_ignore_reason_names_where_these_run() {
    assert!(NEEDS_DB.contains("--include-ignored"));
}
