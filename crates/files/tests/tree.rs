//! The file tree against a real PostgreSQL — the rules of `docs/04-DATA-MODEL.md §8` as the
//! database actually applies them.
//!
//! # Why these exist beside the unit tests
//!
//! `crates/files/src/repo.rs` proves the *statements* — that every one carries a tenant predicate,
//! that the listing never uses `OFFSET`, that the move guard is recursive. What it cannot prove is
//! that PostgreSQL agrees: that `uq_files_sibling_name` really does reject the second `Report.pdf`
//! and really does ignore the trashed one, that a recursive `WITH` inside an `UPDATE` refuses the
//! cycle it is written to refuse, and that a cascaded trash comes back as the same subtree.
//! Those are properties of the schema, and only the schema can answer them.
//!
//! # Everything runs as `enclave_app`
//!
//! Every read and write below goes through [`enclave_testing::TestDb::pool`], which
//! `SET ROLE enclave_app`s, inside a `TenantScoped` transaction. The harness's own connection is a
//! superuser, and **superusers bypass row-level security entirely** — a test suite that used it
//! would pass no matter what the policies said, which is exactly what happened before `ENC-124`.
//! The fixtures (workspaces and libraries) are written over the administrative connection because
//! they are setup, not subject.
//!
//! # Why they are ignored by default
//!
//! They need a live database with migrations `0004` and `0005` applied. CI runs them with
//! `--include-ignored` against the Compose PostgreSQL (`.github/workflows/ci.yml`), the same way
//! `crates/db/tests/rls_coverage.rs` and `crates/authorization/tests/acl_resolution.rs` do.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId, WorkspaceId};
use enclave_db::{
    charge_storage, configure_storage_quota, release_storage, storage_quota, DbPool, Enforcement,
    Released, TenantScoped,
};
use enclave_files::{
    ChildFilter, FileNode, FileRepository, FilesError, Mutation, NewFile, NewFolder, NodeStatus,
    NodeType, PageSize, Parent,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

/// A workspace and two libraries per tenant. Two, because a cross-library move has to have
/// somewhere to try to go.
#[derive(Debug, Clone, Copy)]
struct Fixture {
    tenant: TenantId,
    owner: UserId,
    workspace: WorkspaceId,
    library: LibraryId,
    other_library: LibraryId,
}

impl Fixture {
    fn new(tenant: TenantId, owner: UserId) -> Self {
        Self {
            tenant,
            owner,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            other_library: LibraryId::new_v7(),
        }
    }

    /// Writes the containers. Every column is spelled as `docs/04-DATA-MODEL.md §7` defines it.
    async fn insert(&self, conn: &mut PgConnection) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(self.owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        for library in [self.library, self.other_library] {
            sqlx::query(
                "INSERT INTO libraries
                   (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                    external_sharing, created_at, updated_at)
                 VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
            )
            .bind(library.as_uuid())
            .bind(self.tenant.as_uuid())
            .bind(self.workspace.as_uuid())
            .bind(format!("lib-{}", library.as_uuid()))
            .bind(fixed_time())
            .execute(&mut *conn)
            .await
            .expect("insert library");
        }
    }

    fn root(&self) -> Parent {
        Parent::Library(self.library)
    }

    /// A mutation stamped with its own instant.
    ///
    /// [`tick`] rather than [`fixed_time`], because `deleted_at` is the discriminator
    /// [`FileRepository::restore`] uses to decide which nodes were trashed *together*. A fixture
    /// clock that handed every operation the same instant would make two unrelated deletes
    /// indistinguishable — which is a property of the fixture, not of the repository, and would
    /// have the tests assert something no deployment experiences. The one case where it *is* the
    /// repository's property has its own test below.
    fn edit(&self, expected_revision: Option<i64>) -> Mutation {
        Mutation { actor: self.owner, expected_revision, at: tick() }
    }

    /// A mutation stamped with an instant the caller chose.
    fn edit_at(&self, at: DateTime<Utc>, expected_revision: Option<i64>) -> Mutation {
        Mutation { actor: self.owner, expected_revision, at }
    }
}

/// The instant every fixture row is created at. Fixed, so nothing in a fixture varies between runs.
fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// A distinct, increasing instant for each mutation — a deterministic stand-in for a real clock.
fn tick() -> DateTime<Utc> {
    static CLOCK: AtomicI64 = AtomicI64::new(1);
    fixed_time() + Duration::milliseconds(CLOCK.fetch_add(1, Ordering::Relaxed))
}

/// Starts a database, seeds the two tenants, writes a workspace and libraries into each, and
/// returns the application-role pool every assertion runs through.
async fn setup() -> (TestDb, DbPool, Fixture, Fixture) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures: Fixtures = db.seed().await.expect("seed the tenant fixtures");

    let alpha = Fixture::new(fixtures.alpha.id, fixtures.alpha.owner);
    let beta = Fixture::new(fixtures.beta.id, fixtures.beta.owner);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin).await;
    beta.insert(&mut admin).await;

    let pool = db.pool().await.expect("application-role pool");
    (db, pool, alpha, beta)
}

/// Creates a folder through the application role, in its own transaction.
async fn folder(pool: &DbPool, at: &Fixture, parent: Parent, name: &str) -> FileNode {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let node = FileRepository::create_folder(
        &mut tx,
        at.tenant,
        &NewFolder { parent, name: name.to_owned(), created_by: at.owner },
        fixed_time(),
    )
    .await
    .expect("create folder");
    tx.commit().await.expect("commit");
    node
}

/// Creates a file node through the application role, in its own transaction.
async fn file(pool: &DbPool, at: &Fixture, parent: Parent, name: &str) -> FileNode {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let node = FileRepository::create_file(
        &mut tx,
        at.tenant,
        &NewFile {
            id: FileId::new_v7(),
            parent,
            name: name.to_owned(),
            mime_type: "application/pdf".to_owned(),
            created_by: at.owner,
        },
        fixed_time(),
    )
    .await
    .expect("create file");
    tx.commit().await.expect("commit");
    node
}

/// Attempts a file creation and returns whatever came back.
async fn try_file(
    pool: &DbPool,
    at: &Fixture,
    parent: Parent,
    name: &str,
) -> Result<FileNode, FilesError> {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let result = FileRepository::create_file(
        &mut tx,
        at.tenant,
        &NewFile {
            id: FileId::new_v7(),
            parent,
            name: name.to_owned(),
            mime_type: "application/pdf".to_owned(),
            created_by: at.owner,
        },
        fixed_time(),
    )
    .await;
    // A failed statement poisons the transaction; roll back rather than commit.
    let _ignored = tx.rollback().await;
    result
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_child_takes_its_library_and_workspace_from_its_parent() {
    // The property the `INSERT … SELECT` exists for: the caller names a parent and nothing else,
    // so a node in one library with another library's `workspace_id` is unrepresentable rather
    // than merely rejected.
    let (_db, pool, alpha, _beta) = setup().await;

    let root = folder(&pool, &alpha, alpha.root(), "Finance").await;
    assert_eq!(root.library_id, alpha.library);
    assert_eq!(root.workspace_id, alpha.workspace);
    assert!(root.is_root_level());
    assert_eq!(root.status, NodeStatus::Available, "a folder has no content to scan");

    let child = file(&pool, &alpha, Parent::Folder(root.id), "Q1 Report.pdf").await;
    assert_eq!(child.parent_id, Some(root.id));
    assert_eq!(child.library_id, alpha.library);
    assert_eq!(child.workspace_id, alpha.workspace);
    // `CLAUDE.md` rule 9: a node with no version behind it is not available.
    assert_eq!(child.status, NodeStatus::Processing);
    assert_eq!(child.current_version_id, None);
    assert_eq!(child.size_bytes, 0);
    assert_eq!(child.revision, 1);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_second_sibling_with_the_same_folded_name_is_refused_by_the_index() {
    // Not by a preceding SELECT — see `crates/files/src/repo.rs`. The case and whitespace variants
    // prove the fold reaching the database is the same fold `normalized_name` is indexed on.
    let (_db, pool, alpha, beta) = setup().await;
    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;

    file(&pool, &alpha, Parent::Folder(here.id), "Report.pdf").await;

    for duplicate in ["Report.pdf", "report.pdf", "  REPORT.pdf  "] {
        assert!(
            matches!(
                try_file(&pool, &alpha, Parent::Folder(here.id), duplicate).await,
                Err(FilesError::NameTaken)
            ),
            "accepted a duplicate: {duplicate:?}"
        );
    }

    // The same name in a different folder is a different name.
    let elsewhere = folder(&pool, &alpha, alpha.root(), "Legal").await;
    file(&pool, &alpha, Parent::Folder(elsewhere.id), "Report.pdf").await;

    // And the same name in the other tenant, in a folder with the same name, is also fine. The
    // index is `(tenant_id, library_id, parent, normalized_name)`; a test that only used one tenant
    // would pass even if `tenant_id` were dropped from it.
    let beta_folder = folder(&pool, &beta, beta.root(), "Finance").await;
    file(&pool, &beta, Parent::Folder(beta_folder.id), "Report.pdf").await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_parent_that_is_a_file_or_trashed_or_another_tenants_is_all_one_answer() {
    let (_db, pool, alpha, beta) = setup().await;

    let leaf = file(&pool, &alpha, alpha.root(), "notes.txt").await;
    assert!(matches!(
        try_file(&pool, &alpha, Parent::Folder(leaf.id), "child.txt").await,
        Err(FilesError::ParentNotFound)
    ));

    let trashed = folder(&pool, &alpha, alpha.root(), "Archive").await;
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    FileRepository::trash(&mut tx, alpha.tenant, trashed.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash");
    tx.commit().await.expect("commit");
    assert!(matches!(
        try_file(&pool, &alpha, Parent::Folder(trashed.id), "child.txt").await,
        Err(FilesError::ParentNotFound)
    ));

    // `CLAUDE.md` rule 7: another tenant's folder is absent, not forbidden. Beta's own folder is
    // real, and alpha still cannot put anything in it.
    let beta_folder = folder(&pool, &beta, beta.root(), "Finance").await;
    assert!(matches!(
        try_file(&pool, &alpha, Parent::Folder(beta_folder.id), "child.txt").await,
        Err(FilesError::ParentNotFound)
    ));
    // And alpha cannot even see it.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let seen = FileRepository::find_including_trashed(&mut tx, alpha.tenant, beta_folder.id)
        .await
        .expect("read");
    tx.commit().await.expect("commit");
    assert!(seen.is_none(), "a cross-tenant read returned a row");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_listing_pages_through_children_and_refuses_another_folders_cursor() {
    let (_db, pool, alpha, _beta) = setup().await;
    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let there = folder(&pool, &alpha, alpha.root(), "Legal").await;

    let mut created = Vec::new();
    for index in 0..5 {
        created
            .push(file(&pool, &alpha, Parent::Folder(here.id), &format!("file-{index}.pdf")).await);
    }

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let first = FileRepository::list_children(
        &mut tx,
        alpha.tenant,
        Parent::Folder(here.id),
        &ChildFilter::default(),
        PageSize::new(2),
        None,
    )
    .await
    .expect("first page");
    assert_eq!(first.nodes.len(), 2);
    assert!(first.has_more);
    let cursor = first.next_cursor.clone().expect("a cursor");

    let second = FileRepository::list_children(
        &mut tx,
        alpha.tenant,
        Parent::Folder(here.id),
        &ChildFilter::default(),
        PageSize::new(2),
        Some(&cursor),
    )
    .await
    .expect("second page");
    assert_eq!(second.nodes.len(), 2);
    assert!(second.nodes.iter().all(|node| !first.nodes.contains(node)), "pages overlap");

    // A cursor is a position in *a* listing. Presented against another folder, or with another
    // filter, it is refused rather than silently skipping rows.
    for wrong in [
        FileRepository::list_children(
            &mut tx,
            alpha.tenant,
            Parent::Folder(there.id),
            &ChildFilter::default(),
            PageSize::new(2),
            Some(&cursor),
        )
        .await,
        FileRepository::list_children(
            &mut tx,
            alpha.tenant,
            Parent::Folder(here.id),
            &ChildFilter { node_type: Some(NodeType::File), include_trashed: false },
            PageSize::new(2),
            Some(&cursor),
        )
        .await,
    ] {
        assert!(matches!(wrong, Err(FilesError::InvalidCursor)));
    }

    // The library root holds the two folders and nothing else.
    let roots = FileRepository::list_children(
        &mut tx,
        alpha.tenant,
        alpha.root(),
        &ChildFilter { node_type: Some(NodeType::Folder), include_trashed: false },
        PageSize::default(),
        None,
    )
    .await
    .expect("root listing");
    tx.commit().await.expect("commit");
    assert_eq!(roots.nodes.len(), 2);
    assert!(roots.nodes.iter().all(FileNode::is_root_level));
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_rename_bumps_the_revision_and_a_stale_if_match_is_a_conflict() {
    let (_db, pool, alpha, _beta) = setup().await;
    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let node = file(&pool, &alpha, Parent::Folder(here.id), "draft.pdf").await;
    file(&pool, &alpha, Parent::Folder(here.id), "final.pdf").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let renamed = FileRepository::rename(
        &mut tx,
        alpha.tenant,
        node.id,
        "  Q1  Draft.pdf ",
        &alpha.edit(Some(node.revision)),
    )
    .await
    .expect("rename");
    assert_eq!(renamed.name, "Q1  Draft.pdf", "the display name keeps the user's spacing");
    assert_eq!(renamed.normalized_name, "q1 draft.pdf", "the fold collapses it");
    assert_eq!(renamed.revision, node.revision + 1);

    // The caller's `If-Match` is now stale.
    let stale = FileRepository::rename(
        &mut tx,
        alpha.tenant,
        node.id,
        "again.pdf",
        &alpha.edit(Some(node.revision)),
    )
    .await;
    assert!(
        matches!(stale, Err(FilesError::Conflict { current_revision }) if current_revision == renamed.revision)
    );

    // And a rename onto a live sibling's name is refused by the index.
    let taken = FileRepository::rename(
        &mut tx,
        alpha.tenant,
        node.id,
        "FINAL.pdf",
        &alpha.edit(Some(renamed.revision)),
    )
    .await;
    assert!(matches!(taken, Err(FilesError::NameTaken)));
    let _ignored = tx.rollback().await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_move_under_a_descendant_or_itself_is_refused_by_the_statement() {
    // The test the recursive guard exists for. Walking the ancestry in Rust and then issuing the
    // move would pass this test and still be wrong under concurrency; that this passes with the
    // guard inside the `UPDATE` is what makes the check real.
    let (_db, pool, alpha, _beta) = setup().await;

    let top = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let middle = folder(&pool, &alpha, Parent::Folder(top.id), "2026").await;
    let bottom = folder(&pool, &alpha, Parent::Folder(middle.id), "Q1").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");

    // Into its own grandchild.
    let cycle = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        top.id,
        Parent::Folder(bottom.id),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(cycle, Err(FilesError::CycleDetected)), "got {cycle:?}");

    // Into its own child.
    let cycle = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        top.id,
        Parent::Folder(middle.id),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(cycle, Err(FilesError::CycleDetected)), "got {cycle:?}");

    // Into itself.
    let cycle = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        top.id,
        Parent::Folder(top.id),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(cycle, Err(FilesError::CycleDetected)), "got {cycle:?}");

    // Downward is fine: the guard must not refuse a legitimate move.
    let moved = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        bottom.id,
        Parent::Folder(top.id),
        &alpha.edit(None),
    )
    .await
    .expect("a downward move is legitimate");
    assert_eq!(moved.parent_id, Some(top.id));
    assert_eq!(moved.revision, bottom.revision + 1);

    // And so is a move back to the library root.
    let to_root =
        FileRepository::reparent(&mut tx, alpha.tenant, moved.id, alpha.root(), &alpha.edit(None))
            .await
            .expect("move to the library root");
    assert!(to_root.is_root_level());
    tx.commit().await.expect("commit");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_move_across_libraries_or_tenants_is_refused() {
    let (_db, pool, alpha, beta) = setup().await;

    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let over_there = folder(&pool, &alpha, Parent::Library(alpha.other_library), "Elsewhere").await;
    let beta_folder = folder(&pool, &beta, beta.root(), "Finance").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");

    let crossed = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        here.id,
        Parent::Folder(over_there.id),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(crossed, Err(FilesError::CrossLibraryMove)), "got {crossed:?}");

    let crossed = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        here.id,
        Parent::Library(alpha.other_library),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(crossed, Err(FilesError::CrossLibraryMove)), "got {crossed:?}");

    // Another tenant's folder is absent, not forbidden.
    let crossed = FileRepository::reparent(
        &mut tx,
        alpha.tenant,
        here.id,
        Parent::Folder(beta_folder.id),
        &alpha.edit(None),
    )
    .await;
    assert!(matches!(crossed, Err(FilesError::ParentNotFound)), "got {crossed:?}");
    let _ignored = tx.rollback().await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn the_trash_takes_the_whole_subtree_and_the_restore_brings_back_exactly_it() {
    let (_db, pool, alpha, _beta) = setup().await;

    let top = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let middle = folder(&pool, &alpha, Parent::Folder(top.id), "2026").await;
    let leaf = file(&pool, &alpha, Parent::Folder(middle.id), "Q1.pdf").await;
    let sibling = file(&pool, &alpha, Parent::Folder(top.id), "cover.pdf").await;

    // Deleted first, on its own: it must not come back with the rest.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    FileRepository::trash(&mut tx, alpha.tenant, sibling.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash the sibling");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let trashed =
        FileRepository::trash(&mut tx, alpha.tenant, top.id, purge_at(), &alpha.edit(None))
            .await
            .expect("trash the tree");
    tx.commit().await.expect("commit");

    assert_eq!(trashed.len(), 3, "the subtree went, and the already-trashed sibling did not again");
    assert_eq!(trashed[0].id, top.id, "the addressed node comes back first");
    assert!(trashed.iter().all(FileNode::is_trashed));
    assert!(trashed.iter().all(|node| node.purge_after.is_some()));
    let ids: Vec<FileId> = trashed.iter().map(|node| node.id).collect();
    assert!(ids.contains(&middle.id) && ids.contains(&leaf.id));

    // Nothing trashed appears in an ordinary listing, and the whole subtree is gone from `find`.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let listing = FileRepository::list_children(
        &mut tx,
        alpha.tenant,
        alpha.root(),
        &ChildFilter::default(),
        PageSize::default(),
        None,
    )
    .await
    .expect("listing");
    assert!(listing.nodes.is_empty(), "a trashed folder is still listed");
    assert!(FileRepository::find_by_id(&mut tx, alpha.tenant, leaf.id)
        .await
        .expect("read")
        .is_none());
    assert!(FileRepository::find_including_trashed(&mut tx, alpha.tenant, leaf.id)
        .await
        .expect("read")
        .is_some());

    let restored = FileRepository::restore(&mut tx, alpha.tenant, top.id, &alpha.edit(None))
        .await
        .expect("restore");
    tx.commit().await.expect("commit");

    assert_eq!(restored.len(), 3, "the sibling deleted separately must stay deleted");
    assert_eq!(restored[0].id, top.id);
    assert!(restored.iter().all(|node| !node.is_trashed()));
    assert!(restored.iter().all(|node| node.purge_after.is_none()));
    assert!(!restored.iter().any(|node| node.id == sibling.id));

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let sibling_now = FileRepository::find_including_trashed(&mut tx, alpha.tenant, sibling.id)
        .await
        .expect("read")
        .expect("the sibling row is still there");
    tx.commit().await.expect("commit");
    assert!(sibling_now.is_trashed(), "an independently deleted node was restored by association");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_trashed_name_is_free_and_a_restore_that_collides_is_refused() {
    // The consequence of `uq_files_sibling_name` being partial. It is expected rather than
    // exceptional, and the caller has to be told which of the two it is.
    let (_db, pool, alpha, _beta) = setup().await;
    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let first = file(&pool, &alpha, Parent::Folder(here.id), "Report.pdf").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    FileRepository::trash(&mut tx, alpha.tenant, first.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash");
    tx.commit().await.expect("commit");

    // The name is free again.
    let second = file(&pool, &alpha, Parent::Folder(here.id), "Report.pdf").await;
    assert_ne!(second.id, first.id);

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let collided =
        FileRepository::restore(&mut tx, alpha.tenant, first.id, &alpha.edit(None)).await;
    assert!(matches!(collided, Err(FilesError::NameTaken)), "got {collided:?}");
    let _ignored = tx.rollback().await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_node_cannot_be_restored_into_a_folder_that_is_still_in_the_trash() {
    let (_db, pool, alpha, _beta) = setup().await;
    let here = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let leaf = file(&pool, &alpha, Parent::Folder(here.id), "Report.pdf").await;

    // The leaf goes first, on its own; then the folder above it.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    FileRepository::trash(&mut tx, alpha.tenant, leaf.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash the leaf");
    FileRepository::trash(&mut tx, alpha.tenant, here.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash the folder");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let orphaned = FileRepository::restore(&mut tx, alpha.tenant, leaf.id, &alpha.edit(None)).await;
    assert!(matches!(orphaned, Err(FilesError::ParentInTrash)), "got {orphaned:?}");

    // Restoring the folder is fine, and does not drag the separately-deleted leaf with it.
    let restored = FileRepository::restore(&mut tx, alpha.tenant, here.id, &alpha.edit(None))
        .await
        .expect("restore the folder");
    assert_eq!(restored.len(), 1);

    // Now the leaf can come back on its own.
    let leaf_again = FileRepository::restore(&mut tx, alpha.tenant, leaf.id, &alpha.edit(None))
        .await
        .expect("restore the leaf");
    tx.commit().await.expect("commit");
    assert_eq!(leaf_again.len(), 1);
    assert!(!leaf_again[0].is_trashed());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn a_breadcrumb_walks_to_the_library_root_and_stops_at_the_trash() {
    let (_db, pool, alpha, beta) = setup().await;

    let top = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let middle = folder(&pool, &alpha, Parent::Folder(top.id), "2026").await;
    let leaf = file(&pool, &alpha, Parent::Folder(middle.id), "Q1 Report.pdf").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let crumb =
        FileRepository::breadcrumb(&mut tx, alpha.tenant, leaf.id).await.expect("breadcrumb");
    assert_eq!(crumb.to_path(), "/Finance/2026/Q1 Report.pdf");
    assert_eq!(crumb.depth(), 2);
    assert_eq!(crumb.library_id, alpha.library);
    assert_eq!(crumb.workspace_id, alpha.workspace);
    assert_eq!(crumb.segments.first().map(|s| s.id), Some(top.id));
    assert_eq!(crumb.node().map(|s| s.id), Some(leaf.id));
    assert_eq!(crumb.node().map(|s| s.node_type), Some(NodeType::File));

    // A node at the root is its own only segment.
    let root_node = file(&pool, &alpha, alpha.root(), "readme.md").await;
    let crumb =
        FileRepository::breadcrumb(&mut tx, alpha.tenant, root_node.id).await.expect("crumb");
    assert_eq!(crumb.to_path(), "/readme.md");

    // Another tenant's node has no breadcrumb here, and neither does a trashed one.
    let beta_node = folder(&pool, &beta, beta.root(), "Finance").await;
    assert!(matches!(
        FileRepository::breadcrumb(&mut tx, alpha.tenant, beta_node.id).await,
        Err(FilesError::NotFound)
    ));
    FileRepository::trash(&mut tx, alpha.tenant, top.id, purge_at(), &alpha.edit(None))
        .await
        .expect("trash");
    assert!(matches!(
        FileRepository::breadcrumb(&mut tx, alpha.tenant, leaf.id).await,
        Err(FilesError::NotFound)
    ));
    tx.commit().await.expect("commit");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn every_write_refuses_a_node_from_another_tenant() {
    // The leakage row for this crate (`docs/12-TESTING.md §4`): every mutation, addressed at a real
    // node belonging to the other tenant, from a transaction scoped to this one. `tenant-beta`
    // mirrors `tenant-alpha` exactly, so none of these can pass by naming something that is
    // absent for an unrelated reason.
    let (_db, pool, alpha, beta) = setup().await;
    let victim = folder(&pool, &beta, beta.root(), "Finance").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");

    let renamed =
        FileRepository::rename(&mut tx, alpha.tenant, victim.id, "taken.pdf", &alpha.edit(None))
            .await;
    assert!(matches!(renamed, Err(FilesError::NotFound)), "got {renamed:?}");

    let moved =
        FileRepository::reparent(&mut tx, alpha.tenant, victim.id, alpha.root(), &alpha.edit(None))
            .await;
    assert!(matches!(moved, Err(FilesError::NotFound)), "got {moved:?}");

    let deleted =
        FileRepository::trash(&mut tx, alpha.tenant, victim.id, purge_at(), &alpha.edit(None))
            .await;
    assert!(matches!(deleted, Err(FilesError::NotFound)), "got {deleted:?}");

    let restored =
        FileRepository::restore(&mut tx, alpha.tenant, victim.id, &alpha.edit(None)).await;
    assert!(matches!(restored, Err(FilesError::NotFound)), "got {restored:?}");

    let listed = FileRepository::list_children(
        &mut tx,
        alpha.tenant,
        Parent::Folder(victim.id),
        &ChildFilter { node_type: None, include_trashed: true },
        PageSize::default(),
        None,
    )
    .await
    .expect("a listing of another tenant's folder is empty, not an error");
    assert!(listed.nodes.is_empty());
    tx.commit().await.expect("commit");

    // And the victim is untouched.
    let mut tx = TenantScoped::begin(&pool, beta.tenant).await.expect("begin");
    let after = FileRepository::find_by_id(&mut tx, beta.tenant, victim.id)
        .await
        .expect("read")
        .expect("beta's own folder");
    tx.commit().await.expect("commit");
    assert_eq!(after.name, victim.name);
    assert_eq!(after.revision, victim.revision);
    assert!(!after.is_trashed());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn two_deletes_stamped_with_the_same_instant_come_back_together() {
    // The documented imprecision of the `deleted_at` discriminator, asserted rather than left as a
    // sentence in a doc comment. `restore` decides which descendants belonged to the same delete by
    // comparing timestamps, so two deletes that share an instant are one delete as far as it can
    // tell. A request-scoped `Utc::now()` never collides at microsecond resolution; a batch job
    // reusing one instant across two operations would. If that ever needs to be exact, the fix is a
    // column recording which delete a row belonged to — not a cleverer query.
    let (_db, pool, alpha, _beta) = setup().await;
    let top = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let leaf = file(&pool, &alpha, Parent::Folder(top.id), "Q1.pdf").await;

    let instant = tick();
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    FileRepository::trash(
        &mut tx,
        alpha.tenant,
        leaf.id,
        purge_at(),
        &alpha.edit_at(instant, None),
    )
    .await
    .expect("trash the leaf on its own");
    let cascade = FileRepository::trash(
        &mut tx,
        alpha.tenant,
        top.id,
        purge_at(),
        &alpha.edit_at(instant, None),
    )
    .await
    .expect("trash the folder");
    assert_eq!(cascade.len(), 1, "the leaf was already in the trash and is not trashed twice");

    let restored = FileRepository::restore(&mut tx, alpha.tenant, top.id, &alpha.edit(None))
        .await
        .expect("restore");
    tx.commit().await.expect("commit");
    assert_eq!(restored.len(), 2, "with distinct instants this would be 1 — see the comment above");
    assert!(restored.iter().any(|node| node.id == leaf.id));
}

/// When the trash may next be *considered* for purging. Thirty days is a placeholder for a tenant
/// setting that does not exist yet (`plans/M1-CONTENT-CORE.md` Q7); the repository takes the
/// instant rather than inventing the window.
fn purge_at() -> DateTime<Utc> {
    fixed_time() + Duration::days(30)
}

// ---------------------------------------------------------------------------
// The stored-byte quota — `ENC-589`, `docs/12-TESTING.md §4.12` Q10 and Q11
// ---------------------------------------------------------------------------

/// An exhausted quota refuses a write and never a delete or a restore.
///
/// `plans/M4-GOVERNANCE.md` D31 and M4's third exit criterion: *a tenant over quota that cannot
/// delete anything cannot get back under it.* The refusal is asserted **first**, in the same
/// fixture and against the same tenant, because "the trash was not blocked" is true of a build
/// where the quota was never wired at all (`docs/12 §1.2`).
///
/// The charge here is `enclave_db::charge_storage` directly rather than a version commit: this
/// crate does not own that path, and what is under test is that *these* statements — trash and
/// restore — consult nothing. The commit's own refusal lives in `crates/versions/tests/versions.rs`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0018 applied; CI runs it with --include-ignored"]
async fn an_exhausted_quota_refuses_a_charge_and_never_the_trash_or_a_restore() {
    let (_db, pool, alpha, _beta) = setup().await;

    let top = folder(&pool, &alpha, alpha.root(), "Finance").await;
    let leaf = file(&pool, &alpha, Parent::Folder(top.id), "Q1.pdf").await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    configure_storage_quota(&mut tx, 4_096, 80, Enforcement::Block)
        .await
        .expect("configure the quota");
    let filled = charge_storage(&mut tx, 4_096).await.expect("charge");
    tx.commit().await.expect("commit");
    assert!(filled.is_admitted(), "the fixture has to reach the limit before it means anything");

    // Exhausted, and shown to be: one byte more is refused.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let refused = charge_storage(&mut tx, 1).await.expect("charge");
    tx.commit().await.expect("commit");
    assert!(refused.refused().is_some(), "got {refused:?}");

    // The delete, against that same exhausted tenant.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let trashed =
        FileRepository::trash(&mut tx, alpha.tenant, top.id, purge_at(), &alpha.edit(None))
            .await
            .expect("a delete is never quota-blocked");
    tx.commit().await.expect("commit");
    assert_eq!(trashed.len(), 2, "the folder and its child");
    assert!(trashed.iter().any(|node| node.id == leaf.id));

    // The trash is a *soft* delete: the bytes are still stored, so nothing may have been released.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let after = storage_quota(&mut tx).await.expect("read").expect("a quota row");
    tx.commit().await.expect("commit");
    assert_eq!(
        after.used_bytes, 4_096,
        "a release on soft delete would make the recycle bin an unmetered tier, and the nightly \
         reconciliation counts versions of trashed files for exactly that reason"
    );

    // And the way back out of the trash is not blocked either.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let restored = FileRepository::restore(&mut tx, alpha.tenant, top.id, &alpha.edit(None))
        .await
        .expect("a restore from the trash is never quota-blocked");
    tx.commit().await.expect("commit");
    assert_eq!(restored.len(), 2);

    // The loop closes: a release — which has no refusal variant — admits the charge that was
    // refused above.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let released = release_storage(&mut tx, 4_096).await.expect("release");
    let admitted = charge_storage(&mut tx, 1).await.expect("charge");
    tx.commit().await.expect("commit");
    assert!(matches!(released, Released::Recorded(_)));
    assert!(admitted.refused().is_none(), "freeing bytes admits what exhaustion refused");
}
