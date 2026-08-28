//! ACL resolution against a real PostgreSQL — the rules of `docs/04-DATA-MODEL.md §9` as the
//! database actually applies them.
//!
//! # Why these exist beside the unit tests
//!
//! `crates/authorization/src/resolve.rs` proves the *rules* in microseconds and without a server.
//! What it cannot prove is that the SQL feeds them the right rows: that the inheritance walk stops
//! where `inherit_permissions` says it does, that the group closure is transitive, that a row in
//! another tenant is invisible, and that all of this holds **as `enclave_app` under forced
//! row-level security** rather than as the superuser the harness connects with.
//!
//! That last clause is the lesson of PR #22, and it is why every read here goes through
//! [`enclave_testing::TestDb::pool`], which `SET ROLE enclave_app`s, while the fixtures are written
//! over the harness's own administrative connection. A test that resolved on the admin connection
//! would bypass RLS entirely and pass no matter what the policies said — which is exactly what
//! happened before ENC-124.
//!
//! # Why they are ignored by default
//!
//! They need a live database *and* migration `0004`, which creates `acl_entries`, `workspaces`,
//! `libraries` and `files`. CI runs them with `--include-ignored` against the Compose PostgreSQL
//! (`.github/workflows/ci.yml`), the same way `crates/db/tests/rls_coverage.rs` and
//! `crates/api/tests/me.rs` run.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use enclave_authorization::{Effective, PgAclAuthorization};
use enclave_authorization::{PrincipalKind, PrincipalSet};
use enclave_core::{
    Action, Actor, AuthorizationService as _, FileAction, FileId, GroupId, LibraryId,
    RequestContext, ResourceRef, ShareLinkId, StageDecision, TenantId, UserId, WorkspaceId,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

const ACTION: Action = Action::File(FileAction::Download);

/// A workspace → library → folder → file spine, which is the shape every content ACL question has.
#[derive(Debug, Clone, Copy)]
struct Tree {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    folder: FileId,
    file: FileId,
}

impl Tree {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            folder: FileId::new_v7(),
            file: FileId::new_v7(),
        }
    }

    fn file_ref(&self) -> ResourceRef {
        ResourceRef::file(self.tenant, self.file)
    }

    /// Writes the spine. Every column is spelled as `docs/04-DATA-MODEL.md §7`/`§8` defines it; a
    /// migration that diverges from the document should fail here rather than in production.
    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        let now = fixed_time();

        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(owner.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert library");

        self.insert_node(conn, self.folder, None, "FOLDER", owner).await;
        self.insert_node(conn, self.file, Some(self.folder), "FILE", owner).await;
    }

    async fn insert_node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        parent: Option<FileId>,
        node_type: &str,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 'application/octet-stream', TRUE, $8, $8,
                     $9, $9)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(parent.map(|id| id.as_uuid()))
        .bind(node_type)
        .bind(id.as_uuid().to_string())
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert file node");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Grants or refuses `ACTION` on one node.
async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource_id: Uuid,
    principal_type: &str,
    principal_id: Option<Uuid>,
    effect: &str,
    expires_at: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    .bind(principal_type)
    .bind(principal_id)
    // `file.download` — `Action`'s own `Display`, which is also what audit rows carry. The ACL and
    // the audit trail naming the same action the same way is what makes a denial explicable.
    .bind(ACTION.to_string())
    .bind(effect)
    .bind(Uuid::nil())
    .bind(fixed_time())
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Adds a membership the seeded fixtures do not have.
async fn join_group(conn: &mut PgConnection, tenant: TenantId, group: GroupId, member: UserId) {
    sqlx::query(
        "INSERT INTO group_members (tenant_id, group_id, member_id, member_type, added_at)
         VALUES ($1, $2, $3, 'USER', $4) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.as_uuid())
    .bind(group.as_uuid())
    .bind(member.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert group membership");
}

fn ctx(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx
}

fn allowed(decision: &StageDecision) -> bool {
    decision.is_allowed()
}

/// Starts a database, seeds the two tenants, and returns the pieces every test needs.
async fn setup() -> (TestDb, Fixtures) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    (db, fixtures)
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn an_allow_on_an_ancestor_is_inherited_and_a_deny_above_it_still_wins() {
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    // A grant on the library, two levels above the file.
    grant(
        &mut admin,
        alpha,
        "LIBRARY",
        tree.library.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(allowed(&decision), "an ALLOW on the library was not inherited by the file");

    // Now deny on the workspace, above the grant. Rule 3: the deny wins wherever it sits.
    grant(
        &mut admin,
        alpha,
        "WORKSPACE",
        tree.workspace.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        None,
    )
    .await;
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(!allowed(&decision), "a DENY on the workspace lost to an ALLOW on the library");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn a_deny_on_a_parent_beats_an_allow_on_the_child() {
    // The arrangement a "walk up until you find something" resolver gets wrong: the nearest entry
    // is the grant, and the correct answer is still refusal.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    grant(
        &mut admin,
        alpha,
        "FOLDER",
        tree.folder.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let decision = PgAclAuthorization::new(pool)
        .authorize(&ctx(alpha, user), ACTION, &tree.file_ref())
        .await
        .expect("resolve");
    assert!(!allowed(&decision), "an ALLOW on the file beat a DENY on its folder");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn a_deny_via_one_group_beats_an_allow_via_another() {
    // What real tenants produce: "all-staff" grants, "contractors" denies, one person is in both.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member; // already in `engineering`
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    join_group(&mut admin, alpha, fixtures.alpha.finance, user).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "GROUP",
        Some(fixtures.alpha.engineering.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    grant(
        &mut admin,
        alpha,
        "LIBRARY",
        tree.library.as_uuid(),
        "GROUP",
        Some(fixtures.alpha.finance.as_uuid()),
        "DENY",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let decision = PgAclAuthorization::new(pool)
        .authorize(&ctx(alpha, user), ACTION, &tree.file_ref())
        .await
        .expect("resolve");
    assert!(!allowed(&decision), "a DENY through one group lost to an ALLOW through another");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn a_grant_through_a_nested_group_is_found() {
    // `owner` is in `finance-leads`, which is a member of `finance`. Only the transitive closure
    // reaches the grant; a one-level membership query would refuse.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.owner;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, user).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "GROUP",
        Some(fixtures.alpha.finance.as_uuid()),
        "ALLOW",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let decision = PgAclAuthorization::new(pool)
        .authorize(&ctx(alpha, user), ACTION, &tree.file_ref())
        .await
        .expect("resolve");
    assert!(allowed(&decision), "the transitive group closure did not reach `finance`");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn an_expired_deny_does_not_deny() {
    // Rule 4, in the direction that locks people out rather than the one that lets them in: an
    // expiry that is not honoured outlives the reason it was written for.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    grant(
        &mut admin,
        alpha,
        "LIBRARY",
        tree.library.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        Some(Utc::now() - Duration::hours(1)),
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(allowed(&decision), "an expired DENY still denied");

    // The same entry, still in force, must deny — otherwise this test would also pass against a
    // resolver that ignored DENY entries altogether.
    grant(
        &mut admin,
        alpha,
        "FOLDER",
        tree.folder.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        Some(Utc::now() + Duration::hours(1)),
    )
    .await;
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(!allowed(&decision), "a live DENY did not deny");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn breaking_inheritance_stops_the_walk_at_the_break() {
    // Rule 1. The folder keeps its own entries; the library and workspace above it stop applying,
    // because breaking inheritance copies the effective entries down.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha,
        "FOLDER",
        tree.folder.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    grant(
        &mut admin,
        alpha,
        "WORKSPACE",
        tree.workspace.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);

    // While inheritance is intact the workspace DENY reaches the file.
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(!allowed(&decision), "the workspace DENY did not reach the file");

    // Break inheritance at the folder: the walk stops there, and the DENY above is out of the chain.
    sqlx::query("UPDATE files SET inherit_permissions = FALSE WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(tree.folder.as_uuid())
        .execute(&mut admin)
        .await
        .expect("break inheritance");

    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(allowed(&decision), "the walk did not stop at the broken inheritance");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn another_tenants_grant_never_applies() {
    // `docs/12-TESTING.md` T1. Two things are being checked at once: the resolver refuses a
    // reference carrying another tenant's id, and RLS makes beta's rows invisible to a transaction
    // scoped to alpha even if it did not.
    let (db, fixtures) = setup().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let tree = Tree::new(beta);
    let user = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.beta.owner).await;
    // Beta grants the action to *everyone*, which is the most permissive entry that can exist.
    grant(&mut admin, beta, "FILE", tree.file.as_uuid(), "EVERYONE", None, "ALLOW", None).await;

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);

    // Alpha's user asking about beta's file, exactly as a contaminated search candidate list would.
    let decision =
        authz.authorize(&ctx(alpha, user), ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(!allowed(&decision), "a grant in tenant-beta reached a caller in tenant-alpha");

    // And through the batch path, which does not pass through `PolicyEngine::enforce` and therefore
    // has no stage-1 tenant check in front of it.
    let decisions =
        authz.authorize_many(&ctx(alpha, user), ACTION, &[tree.file_ref()]).await.expect("resolve");
    assert_eq!(decisions.len(), 1);
    assert!(!allowed(&decisions[0]), "the batch path leaked across the tenant boundary");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn the_batch_agrees_with_the_singular_form_resource_by_resource() {
    // `authorize_many` is one query for N resources; `authorize` is that query with N = 1. This is
    // the test that keeps the two from drifting — the post-filter uses the batch, and a batch that
    // is more permissive than the singular form is a leak nobody would see in an endpoint test.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;

    let granted = Tree::new(alpha);
    let denied = Tree::new(alpha);
    let silent = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    for tree in [granted, denied, silent] {
        tree.insert(&mut admin, fixtures.alpha.owner).await;
    }
    grant(
        &mut admin,
        alpha,
        "FILE",
        granted.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    grant(&mut admin, alpha, "LIBRARY", denied.library.as_uuid(), "EVERYONE", None, "ALLOW", None)
        .await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        denied.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        None,
    )
    .await;

    let missing = ResourceRef::file(alpha, FileId::new_v7());
    let resources = vec![
        granted.file_ref(),
        denied.file_ref(),
        silent.file_ref(),
        missing,
        // A duplicate, because the post-filter does not promise a deduplicated candidate list and
        // the answers must stay index-aligned regardless.
        granted.file_ref(),
    ];

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let ctx = ctx(alpha, user);

    let batch = authz.authorize_many(&ctx, ACTION, &resources).await.expect("resolve batch");
    assert_eq!(batch.len(), resources.len(), "the batch lost or invented a verdict");

    for (index, resource) in resources.iter().enumerate() {
        let single = authz.authorize(&ctx, ACTION, resource).await.expect("resolve one");
        assert_eq!(
            allowed(&batch[index]),
            allowed(&single),
            "batch and singular disagreed about {resource}"
        );
    }

    assert!(allowed(&batch[0]), "the granted file was refused");
    assert!(!allowed(&batch[1]), "a DENY on the file lost to an EVERYONE grant on the library");
    assert!(!allowed(&batch[2]), "a file nobody granted was allowed");
    assert!(!allowed(&batch[3]), "a file that does not exist was allowed");
    assert!(allowed(&batch[4]), "the duplicate of the granted file was refused");

    let empty = authz.authorize_many(&ctx, ACTION, &[]).await.expect("resolve empty");
    assert!(empty.is_empty(), "an empty batch invented a verdict");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn a_grant_for_one_action_does_not_grant_another() {
    // There is no action implication in this resolver, deliberately. `docs/03-LLD.md §6` keeps
    // preview, download, print and export apart precisely so a policy can permit one and refuse the
    // next (`CLAUDE.md` rule 6), and an ACL that inferred them would collapse that distinction.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "ALLOW",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let ctx = ctx(alpha, user);

    let download = authz.authorize(&ctx, ACTION, &tree.file_ref()).await.expect("resolve");
    assert!(allowed(&download));

    let printed = authz
        .authorize(&ctx, Action::File(FileAction::Print), &tree.file_ref())
        .await
        .expect("resolve");
    assert!(!allowed(&printed), "a download grant leaked into print");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn resolution_returns_effective_states_a_caller_can_reason_about() {
    // The resolver distinguishes "denied by a rule" from "nobody granted it" for audit and support,
    // even though both become the same refusal at the API edge.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "USER",
        Some(user.as_uuid()),
        "DENY",
        None,
    )
    .await;

    let pool = db.pool().await.expect("application-role pool");
    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");
    let effective = enclave_authorization::AclResolver::new()
        .effective_in_tx(
            &mut tx,
            alpha,
            &Actor::User(user),
            ACTION,
            &[tree.file_ref(), ResourceRef::file(alpha, FileId::new_v7())],
            Utc::now(),
        )
        .await
        .expect("resolve");
    tx.commit().await.expect("commit");

    assert_eq!(effective[0], Effective::Denied, "an explicit DENY read as merely ungranted");
    assert_eq!(effective[1], Effective::NotGranted, "a missing file read as explicitly denied");
}

/// `ENC-879`. The share-link lookup's own `tenant_id` predicate, isolated from row-level security.
///
/// # Why this one test uses the connection every other test here must not
///
/// This module's header says every read goes through the harness pool, which `SET ROLE
/// enclave_app`s, because a read on the admin connection bypasses RLS and would pass whatever the
/// policies said. That is right for a test asking *does isolation hold*. This test asks a different
/// question — **does layer 1 hold on its own** — and the only way to ask it is to take layer 2 away.
///
/// It has to be asked, because deleting `s.tenant_id = $1` from `SHARE_TARGET_SQL` fails **nothing**
/// otherwise: `migrations/0008` puts a `FORCE`d policy on `share_links`, so on a scoped connection
/// beta's row is invisible whether or not the statement mentions a tenant. That shape has now been
/// found in ten crates in this repository, and the lesson each time was that the behavioural test
/// proved RLS and nothing else. So the mechanism is named rather than assumed: on the admin
/// connection the predicate is the only filter there is, and this test is what fails when it goes.
///
/// It asserts nothing about isolation in production, where both layers are present. It asserts that
/// there are two.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0027 applied; CI runs it with --include-ignored"]
async fn the_share_lookup_filters_by_tenant_without_help_from_row_level_security() {
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;

    let mut admin = db.connect().await.expect("admin connection");
    let alpha_tree = Tree::new(alpha);
    let beta_tree = Tree::new(beta);
    alpha_tree.insert(&mut admin, fixtures.alpha.owner).await;
    beta_tree.insert(&mut admin, fixtures.beta.owner).await;
    let alphas = insert_share_link(&mut admin, alpha, alpha_tree.file, fixtures.alpha.owner).await;
    let betas = insert_share_link(&mut admin, beta, beta_tree.file, fixtures.beta.owner).await;

    // Confirm the bypass is real before relying on it: as the superuser, both rows are visible.
    let both: i64 =
        sqlx::query_scalar("SELECT count(*) FROM share_links WHERE id = ANY($1::uuid[])")
            .bind(vec![alphas.as_uuid(), betas.as_uuid()])
            .fetch_one(&mut admin)
            .await
            .expect("count");
    assert_eq!(both, 2, "the admin connection is not bypassing RLS, so this test proves nothing");

    // The control: alpha's own link resolves under alpha.
    let found = enclave_authorization::repo::share_targets(
        &mut admin,
        alpha,
        &[alphas.as_uuid()],
        Utc::now(),
    )
    .await
    .expect("lookup");
    assert!(found.contains_key(&alphas.as_uuid()), "alpha's own link did not resolve");

    // The assertion: beta's link, asked under alpha, with nothing but the predicate in the way.
    let leaked = enclave_authorization::repo::share_targets(
        &mut admin,
        alpha,
        &[betas.as_uuid()],
        Utc::now(),
    )
    .await
    .expect("lookup");
    assert!(
        leaked.is_empty(),
        "another tenant's share link resolved with row-level security out of the way, so the \
         statement's own tenant_id predicate is not doing anything: {leaked:?}"
    );
}

/// Writes a `share_links` row directly. The crate under test has no minting API of its own, and
/// `enclave_sharing` would be a dependency cycle.
async fn insert_share_link(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    creator: UserId,
) -> ShareLinkId {
    let id = ShareLinkId::new_v7();
    sqlx::query(
        "INSERT INTO share_links
           (id, tenant_id, resource_type, resource_id, token_hash, permission, allow_download,
            audience, require_otp, require_mfa, download_count, created_by, created_at)
         VALUES ($1, $2, 'FILE', $3, $4, 'VIEW', TRUE, 'INTERNAL', FALSE, FALSE, 0, $5, $6)",
    )
    .bind(id.as_uuid())
    .bind(tenant.as_uuid())
    .bind(file.as_uuid())
    // A digest-shaped value, not a token: this crate never sees one, and a fixture that invented a
    // plausible token would be a credential literal in a tracked file (`CLAUDE.md` rule 11).
    .bind(format!("{:x}", id.as_uuid().as_u128()))
    .bind(creator.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert share link");
    id
}

/// `ENC-879`. The `EVERYONE` refusal is written in *two* places, and this is the one that pins the
/// SQL half.
///
/// `PrincipalSet::matches` refuses an `EVERYONE` entry for a link bearer, and so does the `WHERE`
/// clause of `repo::acl_entries_by_action`. That redundancy is deliberate — see the constant's doc
/// comment — but it has a cost worth naming: **no verdict-level test can tell which of the two is
/// holding**, because either alone produces the same refusal. Breaking one leaves every such test
/// green.
///
/// So this one does not look at a verdict. It asserts on the rows the query *returns*, which is the
/// only thing that changes when the `WHERE` clause changes. Deleting `AND $9` from `ACL_ENTRIES_SQL`
/// fails here and nowhere else.
///
/// It runs through the harness pool, which `SET ROLE enclave_app`s — a test of this query that ran
/// as the superuser would be testing PostgreSQL's RLS bypass, which is the trap
/// `crates/authorization/src/repo.rs`'s header records.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0027 applied; CI runs it with --include-ignored"]
async fn the_prefilter_does_not_even_fetch_an_everyone_row_for_a_link_bearer() {
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let tree = Tree::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    tree.insert(&mut admin, fixtures.alpha.owner).await;
    let link = ShareLinkId::new_v7();
    grant(&mut admin, alpha, "LIBRARY", tree.library.as_uuid(), "EVERYONE", None, "ALLOW", None)
        .await;
    grant(
        &mut admin,
        alpha,
        "FILE",
        tree.file.as_uuid(),
        "SHARE_LINK",
        Some(link.as_uuid()),
        "ALLOW",
        None,
    )
    .await;
    let _ignored = sqlx::Connection::close(admin).await;

    let nodes = [
        enclave_authorization::ChainNode::new(
            enclave_authorization::AclResourceType::File,
            tree.file.as_uuid(),
        ),
        enclave_authorization::ChainNode::new(
            enclave_authorization::AclResourceType::Library,
            tree.library.as_uuid(),
        ),
    ];

    let pool = db.pool().await.expect("application-role pool");
    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");

    // The control, first. An ordinary member's fetch *does* bring back the `EVERYONE` row, so the
    // row exists, the nodes are right, and the query works.
    let member = PrincipalSet::for_actor(&Actor::User(fixtures.alpha.member)).expect("a principal");
    let fetched = enclave_authorization::repo::acl_entries(
        &mut tx,
        alpha,
        &ACTION.to_string(),
        &nodes,
        &member,
        Utc::now(),
    )
    .await
    .expect("fetch");
    assert!(
        fetched.iter().any(|entry| entry.principal.kind == PrincipalKind::Everyone),
        "the EVERYONE row was not fetched for a member, so this fixture proves nothing: {fetched:?}"
    );

    // The finding: the same query, for a link bearer, does not bring the row back at all.
    let bearer = PrincipalSet::for_actor(&Actor::LinkBearer(link)).expect("a principal");
    let fetched = enclave_authorization::repo::acl_entries(
        &mut tx,
        alpha,
        &ACTION.to_string(),
        &nodes,
        &bearer,
        Utc::now(),
    )
    .await
    .expect("fetch");
    tx.commit().await.expect("commit");

    assert!(
        !fetched.iter().any(|entry| entry.principal.kind == PrincipalKind::Everyone),
        "an EVERYONE row crossed the wire for a share-link bearer: {fetched:?}"
    );
    // And its own row did, so the narrowing is about `EVERYONE` and not about the query having
    // stopped returning anything for this principal kind.
    assert!(
        fetched.iter().any(|entry| entry.principal.kind == PrincipalKind::ShareLink
            && entry.principal.id == Some(link.as_uuid())),
        "the link's own row was not fetched: {fetched:?}"
    );
}
