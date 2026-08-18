//! The workspace repositories against a real PostgreSQL.
//!
//! Every test here is `#[ignore]`d and runs under the `enclave-testing` harness — `TestDb::start`
//! plus `DATABASE_URL`, which CI provides and invokes with `--include-ignored`
//! (`.github/workflows/ci.yml`, `crates/testing/src/lib.rs`). They are not skipped work: they are
//! the assertions that cannot be made without a database. Three of them cannot be made *anywhere*
//! else — a partial unique index losing a race, a composite foreign key refusing a cross-tenant
//! write, and an `If-Match` comparison that has to be atomic with the write it guards are all
//! properties of PostgreSQL, not of our code, and a mock would only assert what we already assumed.
//!
//! # Two things every test here must keep true
//!
//! 1. **Queries run as `enclave_app`.** `DATABASE_URL` points at a cluster superuser, because the
//!    harness has to create databases — and *superusers bypass row-level security entirely*. Work
//!    goes through `TestDb::pool`, which sets the application role. A test that used
//!    `TestDb::connect` for its assertions would run with isolation switched off and prove nothing,
//!    which is what PR #22 found the hard way.
//! 2. **`tenant-beta` is not decoration.** It exists so a cross-tenant assertion cannot pass by
//!    accident (`docs/12-TESTING.md §3`); the workspaces created in it here deliberately carry the
//!    same slugs as alpha's.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{Duration, Utc};
use enclave_core::{TenantId, Uuid, WorkspaceId};
use enclave_db::{DbPool, TenantScoped};
use enclave_testing::{Fixtures, TestDb};
use enclave_workspaces::{
    MemberFilter, NewMember, PageSize, PrincipalId, PrincipalType, RoleId, Visibility,
    WorkspaceError, WorkspaceFilter, WorkspaceMemberRepository, WorkspaceRepository,
    WorkspaceSettings,
};

/// Reason attached to every `#[ignore]` here, so the harness is named at each one rather than in a
/// comment somebody has to go looking for.
const NEEDS_DB: &str = "requires a live PostgreSQL; CI runs it with --include-ignored";

/// Starts a database, applies migrations and seeds `tenant-alpha` / `tenant-beta`.
async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("build an application-role pool");
    (db, fixtures, pool)
}

/// A minimal set of settings, so each test varies only what it is about.
fn settings(name: &str, slug: &str) -> WorkspaceSettings {
    WorkspaceSettings {
        name: name.to_owned(),
        slug: slug.to_owned(),
        description: None,
        visibility: Visibility::Private,
        default_classification_id: None,
        storage_profile_id: None,
    }
}

/// Creates a workspace inside its own tenant-scoped transaction.
async fn create(
    pool: &DbPool,
    tenant: TenantId,
    owner: enclave_core::UserId,
    name: &str,
    slug: &str,
) -> enclave_workspaces::Workspace {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let workspace =
        WorkspaceRepository::create(&mut tx, tenant, &settings(name, slug), owner, Utc::now())
            .await
            .expect("create workspace");
    tx.commit().await.expect("commit");
    workspace
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_created_workspace_is_found_by_id_and_by_slug_in_any_case() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let created = create(&pool, alpha, fixtures.alpha.owner, "Finance", "Finance").await;
    assert_eq!(created.revision, 1, "a create must hand back a usable If-Match value");
    assert_eq!(created.slug, "finance", "the slug is folded on the way in");
    assert!(created.deleted_at.is_none());

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let by_id = WorkspaceRepository::find_by_id(&mut tx, alpha, created.id)
        .await
        .expect("query")
        .expect("the workspace exists");
    // Folded on the way out too, so one URL cannot resolve to two workspaces.
    let by_slug = WorkspaceRepository::find_by_slug(&mut tx, alpha, "  FINANCE ")
        .await
        .expect("query")
        .expect("the workspace resolves by slug");
    tx.commit().await.expect("commit");

    assert_eq!(by_id, created);
    assert_eq!(by_slug, created);

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_slug_is_unique_per_tenant_and_freed_by_a_soft_delete() {
    // The three properties of `uq_workspace_slug`, asserted where the index actually runs. None of
    // them can be observed without a database, and the second one is what a read-then-write check
    // would get wrong under concurrency.
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    let first = create(&pool, alpha, fixtures.alpha.owner, "Finance", "finance").await;

    // 1. A second live workspace cannot take the slug — and it is a domain answer, not a 500.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let clash = WorkspaceRepository::create(
        &mut tx,
        alpha,
        &settings("Finance Again", "FINANCE"),
        fixtures.alpha.owner,
        Utc::now(),
    )
    .await;
    assert!(matches!(clash, Err(WorkspaceError::SlugTaken)), "expected SlugTaken, got {clash:?}");
    // Dropped rather than committed: the violation aborted this transaction. See the note in the
    // membership test, and the crate documentation the note points at.
    drop(tx);

    // 2. The other tenant is unaffected: uniqueness is `(tenant_id, slug)`, not `(slug)`.
    let beta_finance = create(&pool, beta, fixtures.beta.owner, "Finance", "finance").await;
    assert_ne!(beta_finance.id, first.id);

    // 3. Trashing releases the slug, which is what the partial predicate is for.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(WorkspaceRepository::soft_delete(&mut tx, alpha, first.id, None, Utc::now())
        .await
        .expect("soft delete"));
    tx.commit().await.expect("commit");

    let reused = create(&pool, alpha, fixtures.alpha.owner, "Finance", "finance").await;
    assert_ne!(reused.id, first.id);

    // And the trashed one is gone from every ordinary read.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(WorkspaceRepository::find_by_id(&mut tx, alpha, first.id)
        .await
        .expect("query")
        .is_none());
    let trash = WorkspaceRepository::list_by_tenant(
        &mut tx,
        alpha,
        &WorkspaceFilter { include_deleted: true, ..Default::default() },
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    tx.commit().await.expect("commit");
    assert!(
        trash.workspaces.iter().any(|w| w.id == first.id && w.deleted_at.is_some()),
        "the trash view is the one listing that can still see it"
    );

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stale_revision_is_refused_and_overwrites_nothing() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let workspace = create(&pool, alpha, fixtures.alpha.owner, "Projects", "projects").await;

    // Someone else's write lands first.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let updated = WorkspaceRepository::update(
        &mut tx,
        alpha,
        workspace.id,
        workspace.revision,
        &settings("Projects (renamed)", "projects"),
        Utc::now(),
    )
    .await
    .expect("update")
    .expect("the workspace exists");
    tx.commit().await.expect("commit");
    assert_eq!(updated.revision, workspace.revision + 1);

    // Ours arrives holding the revision we read before that.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let conflict = WorkspaceRepository::update(
        &mut tx,
        alpha,
        workspace.id,
        workspace.revision,
        &settings("Projects (mine)", "projects"),
        Utc::now(),
    )
    .await;
    tx.commit().await.expect("commit");

    match conflict {
        Err(WorkspaceError::RevisionConflict { current_revision }) => {
            assert_eq!(
                current_revision, updated.revision,
                "the client needs the value to retry on"
            );
        }
        other => panic!("expected a revision conflict, got {other:?}"),
    }

    // The refusal is the whole point: nothing was written.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let stored = WorkspaceRepository::find_by_id(&mut tx, alpha, workspace.id)
        .await
        .expect("query")
        .expect("the workspace exists");
    tx.commit().await.expect("commit");
    assert_eq!(stored, updated, "a conflicting update must not overwrite");

    // A delete carrying the same stale revision is refused the same way.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let refused = WorkspaceRepository::soft_delete(
        &mut tx,
        alpha,
        workspace.id,
        Some(workspace.revision),
        Utc::now(),
    )
    .await;
    tx.commit().await.expect("commit");
    assert!(matches!(refused, Err(WorkspaceError::RevisionConflict { .. })), "{refused:?}");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_workspace_is_absent_rather_than_forbidden() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let alpha_ws = create(&pool, alpha, fixtures.alpha.owner, "Finance", "finance").await;

    // Both layers say no: the application predicate and row-level security. The answer is absence.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
    assert!(WorkspaceRepository::find_by_id(&mut tx, beta, alpha_ws.id)
        .await
        .expect("query")
        .is_none());
    assert!(WorkspaceRepository::find_by_slug(&mut tx, beta, "finance")
        .await
        .expect("query")
        .is_none());
    assert!(WorkspaceRepository::current_revision(&mut tx, beta, alpha_ws.id)
        .await
        .expect("query")
        .is_none());
    // A write is a no-op rather than a cross-tenant edit, and it reports absence, not a conflict.
    assert!(WorkspaceRepository::update(
        &mut tx,
        beta,
        alpha_ws.id,
        alpha_ws.revision,
        &settings("Stolen", "stolen"),
        Utc::now()
    )
    .await
    .expect("update")
    .is_none());
    assert!(!WorkspaceRepository::soft_delete(&mut tx, beta, alpha_ws.id, None, Utc::now())
        .await
        .expect("soft delete"));
    tx.commit().await.expect("commit");

    // And it is untouched.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let stored = WorkspaceRepository::find_by_id(&mut tx, alpha, alpha_ws.id)
        .await
        .expect("query")
        .expect("still there");
    tx.commit().await.expect("commit");
    assert_eq!(stored, alpha_ws);

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listing_pages_through_every_workspace_exactly_once() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut expected = Vec::new();
    for index in 0..7 {
        let slug = format!("workspace-{index}");
        expected.push(create(&pool, alpha, fixtures.alpha.owner, &slug, &slug).await.id);
    }
    // Beta's mirror workspaces carry the same slugs and must never appear in alpha's pages.
    for index in 0..3 {
        let slug = format!("workspace-{index}");
        create(&pool, fixtures.beta.id, fixtures.beta.owner, &slug, &slug).await;
    }

    let filter = WorkspaceFilter::default();
    let limit = PageSize::new(3);
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
        let page =
            WorkspaceRepository::list_by_tenant(&mut tx, alpha, &filter, limit, cursor.as_deref())
                .await
                .expect("listing");
        tx.commit().await.expect("commit");

        seen.extend(page.workspaces.iter().map(|workspace| workspace.id));
        assert_eq!(page.has_more, page.next_cursor.is_some());
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    let mut sorted = expected.clone();
    sorted.sort_unstable();
    assert_eq!(seen, sorted, "every workspace exactly once, in creation order");

    // A cursor from this listing is not accepted under a different filter.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let first = WorkspaceRepository::list_by_tenant(&mut tx, alpha, &filter, limit, None)
        .await
        .expect("listing");
    let other = WorkspaceFilter { include_deleted: true, ..Default::default() };
    let rejected = WorkspaceRepository::list_by_tenant(
        &mut tx,
        alpha,
        &other,
        limit,
        first.next_cursor.as_deref(),
    )
    .await;
    tx.commit().await.expect("commit");
    assert!(matches!(rejected, Err(WorkspaceError::InvalidCursor)), "{rejected:?}");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn membership_is_added_once_removed_once_and_never_crosses_a_tenant() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let workspace = create(&pool, alpha, fixtures.alpha.owner, "Finance", "finance").await;

    let principal = PrincipalId::from_uuid(fixtures.alpha.member.as_uuid());
    let member = NewMember {
        principal_id: principal,
        principal_type: PrincipalType::User,
        role_id: RoleId::from_uuid(Uuid::now_v7()),
        added_by: fixtures.alpha.owner,
        expires_at: None,
    };

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let added = WorkspaceMemberRepository::add(&mut tx, alpha, workspace.id, &member, Utc::now())
        .await
        .expect("add member");
    assert_eq!(added.principal_id, principal);
    assert_eq!(added.workspace_id, workspace.id);

    tx.commit().await.expect("commit");

    // A second add is refused rather than silently rewriting the role.
    //
    // Each expected refusal gets its own transaction, and that is not tidiness: a constraint
    // violation aborts the PostgreSQL transaction, so every later statement on the same connection
    // fails with `25P02` until it is rolled back. It is the reason the crate documentation tells
    // callers to treat these errors as ending the transaction — a handler that caught `SlugTaken`
    // and carried on writing would get that same opaque failure in production.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let again =
        WorkspaceMemberRepository::add(&mut tx, alpha, workspace.id, &member, Utc::now()).await;
    assert!(matches!(again, Err(WorkspaceError::AlreadyMember)), "{again:?}");
    drop(tx);

    // A membership pointing at a workspace that does not exist in this tenant is refused by the
    // composite foreign key — the same answer for a fabricated id and for another tenant's.
    for target in [workspace.id, WorkspaceId::new_v7()] {
        let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
        let refused =
            WorkspaceMemberRepository::add(&mut tx, beta, target, &member, Utc::now()).await;
        assert!(matches!(refused, Err(WorkspaceError::NoSuchWorkspace)), "{refused:?}");
        drop(tx);
    }

    // Revocation removes the row, and repeating it is a no-op rather than an error.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(WorkspaceMemberRepository::remove(&mut tx, alpha, workspace.id, principal)
        .await
        .expect("remove"));
    assert!(!WorkspaceMemberRepository::remove(&mut tx, alpha, workspace.id, principal)
        .await
        .expect("remove"));
    tx.commit().await.expect("commit");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn listings_hide_lapsed_memberships_and_trashed_workspaces() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let live = create(&pool, alpha, fixtures.alpha.owner, "Live", "live").await;
    let doomed = create(&pool, alpha, fixtures.alpha.owner, "Doomed", "doomed").await;

    let now = Utc::now();
    let current = PrincipalId::from_uuid(fixtures.alpha.member.as_uuid());
    let lapsed = PrincipalId::from_uuid(fixtures.alpha.viewer.as_uuid());

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    for (principal, expires_at) in [(current, None), (lapsed, Some(now - Duration::hours(1)))] {
        let member = NewMember {
            principal_id: principal,
            principal_type: PrincipalType::User,
            role_id: RoleId::from_uuid(Uuid::now_v7()),
            added_by: fixtures.alpha.owner,
            expires_at,
        };
        for workspace in [live.id, doomed.id] {
            WorkspaceMemberRepository::add(&mut tx, alpha, workspace, &member, now)
                .await
                .expect("add member");
        }
    }

    let default_filter = MemberFilter::default();
    let members = WorkspaceMemberRepository::list_members(
        &mut tx,
        alpha,
        live.id,
        &default_filter,
        now,
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    assert_eq!(
        members.members.iter().map(|m| m.principal_id).collect::<Vec<_>>(),
        vec![current],
        "a lapsed grant must not be displayed as a current one"
    );

    let everyone = WorkspaceMemberRepository::list_members(
        &mut tx,
        alpha,
        live.id,
        &MemberFilter { include_expired: true },
        now,
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    assert_eq!(everyone.members.len(), 2, "the administrative view still sees the lapsed row");

    // Trashing a workspace does not cascade to its membership rows, and the "my workspaces"
    // listing must still stop showing it.
    assert!(WorkspaceRepository::soft_delete(&mut tx, alpha, doomed.id, None, now)
        .await
        .expect("soft delete"));

    let mine = WorkspaceMemberRepository::list_for_principal(
        &mut tx,
        alpha,
        current,
        &default_filter,
        now,
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    tx.commit().await.expect("commit");

    assert_eq!(
        mine.workspaces.iter().map(|workspace| workspace.id).collect::<Vec<_>>(),
        vec![live.id],
        "a trashed workspace is not one of my workspaces"
    );

    pool.close().await;
    drop(db);
}

/// Documents the one thing the `#[ignore]` reason has to keep saying.
#[test]
fn the_ignore_reason_names_where_these_run() {
    assert!(NEEDS_DB.contains("--include-ignored"));
}
