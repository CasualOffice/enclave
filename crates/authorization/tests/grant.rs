//! The ACL write path against a real PostgreSQL — `enclave_authorization::grant`.
//!
//! # Which connection these run on, and why it is the superuser
//!
//! Almost every integration suite in this workspace asserts over [`enclave_testing::TestDb::pool`],
//! which `SET ROLE enclave_app`s so that forced row-level security is genuinely in force. That is
//! the right default for a *read* path and it is the wrong one here, for a reason worth stating
//! precisely because getting it backwards is how eleven crates in this repository ended up with a
//! tenant-isolation test that could not fail.
//!
//! `acl_entries` has RLS enabled and forced with `USING` and `WITH CHECK` both on
//! `tenant_id = current_setting('app.tenant_id')`. Under `enclave_app` the database holds tenant
//! isolation on its own, so deleting `tenant_id = $1` from a statement in `grant.rs` changes
//! nothing an `enclave_app` test can observe: the test passes before the edit and after it, and
//! proves only that PostgreSQL works. To make the predicate load-bearing the policies have to be
//! inert, which means a role holding `BYPASSRLS`.
//!
//! The obvious candidate is `enclave_platform`, which `crates/db/tests/grant_coverage.rs` uses for
//! exactly this and which `pg_roles` confirms is `rolsuper = f, rolbypassrls = t`. It does not work
//! here: `enclave_platform` holds **no privilege at all on `acl_entries`** — `0003` granted the
//! table to `enclave_app` only — so `SET ROLE enclave_platform` turns every statement below into
//! `permission denied for table acl_entries` and the suite fails for a reason that has nothing to
//! do with what it is testing.
//!
//! So these run on [`enclave_testing::TestDb::connect`], the harness's own connection, which
//! `DATABASE_URL` points at the `enclave` role for: `rolsuper = t, rolbypassrls = t`. RLS is
//! bypassed entirely, which is the property this suite needs and the property that made PR #22's
//! defect invisible. **Every cross-tenant assertion below therefore tests the `tenant_id` predicate
//! in the SQL and nothing else.** Deleting any one of them turns exactly one test red, and the test
//! that goes red is named after the predicate that went missing.
//!
//! One test — [`a_written_grant_is_the_grant_the_resolver_reads`] — deliberately crosses back over
//! to the `enclave_app` pool, because the other half of the claim is that a row written this way is
//! visible to the resolver *with* the policies on. A grant that only the superuser can read is not
//! a grant.
//!
//! # Why they are ignored by default
//!
//! They need a live database with migrations `0004` (`acl_entries`), `0015` (`lists`) and `0027`
//! (`SHARE_LINK`). CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use enclave_authorization::grant::{entries_on, grant, revoke, Grant, GrantError, GrantedEntry};
use enclave_authorization::{
    AclResourceType, ChainNode, Effect, PgAclAuthorization, Principal, PrincipalKind,
};
use enclave_core::{
    Action, Actor, AuthorizationService as _, ContainerAction, FileAction, LibraryId,
    RequestContext, ShareLinkId, TenantId, UserId,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

/// The action almost every test below grants. `file.download` is the one `docs/12-TESTING.md §4`
/// leans on hardest, and it is what the resolution suite next door resolves.
const DOWNLOAD: Action = Action::File(FileAction::Download);

/// A second action, so a test can tell "the write touched one row" from "the write touched
/// everything".
const PREVIEW: Action = Action::File(FileAction::Preview);

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Starts a database, seeds `tenant-alpha` and `tenant-beta`, and writes alpha's content spine.
///
/// The spine is alpha's only. `tenant-beta` gets ACL rows without resources underneath them in the
/// cross-tenant tests, which is deliberate: the rows are what the predicates have to miss, and
/// building beta a whole tree to hold them would only obscure that.
async fn setup() -> (TestDb, Fixtures, Spine, PgConnection) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let mut conn = db.connect().await.expect("the harness's own connection");
    let spine = Spine::new(fixtures.alpha.id);
    spine.insert(&mut conn, fixtures.alpha.owner, fixed_time()).await.expect("insert the spine");
    (db, fixtures, spine, conn)
}

fn library_node(library: LibraryId) -> ChainNode {
    ChainNode::new(AclResourceType::Library, library.as_uuid())
}

/// A grant of `effect` to `user`, answered for by `granter`.
fn to_user(
    resource: ChainNode,
    user: UserId,
    effect: Effect,
    granter: UserId,
    expires_at: Option<DateTime<Utc>>,
) -> Grant {
    Grant {
        resource,
        principal: Principal::new(PrincipalKind::User, user.as_uuid()),
        effect,
        granted_by: granter,
        expires_at,
    }
}

/// Writes one `acl_entries` row directly, bypassing the module under test.
///
/// The cross-tenant tests need a row in `tenant-beta` that `grant` could not have written — beta's
/// resources do not exist — so this is the only way to stage them. It is also the shape the ground
/// truth is in: the same `INSERT` `enclave_testing::content::grant` uses.
async fn plant_entry(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
    principal: Principal,
    action: Action,
    effect: Effect,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(resource.kind.as_str())
    .bind(resource.id)
    .bind(principal.kind.as_str())
    .bind(principal.id)
    .bind(action.to_string())
    .bind(effect.as_str())
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("plant an acl entry");
}

/// Every stored row for one tenant and resource, read raw so an assertion is about the table rather
/// than about the module that reads it.
async fn stored_rows(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
) -> Vec<(String, String, Option<Uuid>, Uuid)> {
    sqlx::query(
        "SELECT action, effect, principal_id, granted_by
           FROM acl_entries
          WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
          ORDER BY action",
    )
    .bind(tenant.as_uuid())
    .bind(resource.kind.as_str())
    .bind(resource.id)
    .fetch_all(&mut *conn)
    .await
    .expect("read acl entries")
    .iter()
    .map(|row| {
        (
            row.get::<String, _>("action"),
            row.get::<String, _>("effect"),
            row.get::<Option<Uuid>, _>("principal_id"),
            row.get::<Uuid, _>("granted_by"),
        )
    })
    .collect()
}

fn ctx(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx
}

fn entry_for<'a>(entries: &'a [GrantedEntry], action: &str) -> &'a GrantedEntry {
    entries
        .iter()
        .find(|entry| entry.action == action)
        .unwrap_or_else(|| panic!("no entry for {action} in {entries:#?}"))
}

// ---------------------------------------------------------------------------------------------
// The grant exists at all
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_written_grant_is_the_grant_the_resolver_reads() {
    // The whole point of the module: before it, no code path in a running deployment could produce
    // a row this assertion could find. It is also the one test here that runs the *read* half as
    // `enclave_app`, with row-level security genuinely in force — a grant only a superuser can see
    // is not a grant.
    let (db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let user = fixtures.alpha.member;

    let written = grant(
        &mut conn,
        alpha,
        &to_user(library_node(spine.library), user, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the grant is written");
    assert_eq!(written, 1);

    let pool = db.pool().await.expect("application-role pool");
    let decision = PgAclAuthorization::new(pool)
        .authorize(&ctx(alpha, user), DOWNLOAD, &spine.file_ref())
        .await
        .expect("resolve");
    assert!(
        decision.is_allowed(),
        "a grant written on the library did not reach the file two levels below it"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn granted_by_is_recorded_and_must_be_a_user_of_this_tenant() {
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);

    grant(
        &mut conn,
        alpha,
        &to_user(library, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the grant is written");

    let rows = stored_rows(&mut conn, alpha, library).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3, fixtures.alpha.admin.as_uuid(), "granted_by was not recorded");

    // A granter nobody in this tenant can name makes the entry unexplainable in review, and there
    // is no foreign key to stop it — `acl_entries.granted_by` outlives the user row it points at.
    let stranger = UserId::from_uuid(Uuid::new_v4());
    let refused = grant(
        &mut conn,
        alpha,
        &to_user(library, fixtures.alpha.member, Effect::Allow, stranger, None),
        &[PREVIEW],
        fixed_time(),
    )
    .await;
    assert!(matches!(refused, Err(GrantError::UnknownGranter)), "{refused:?}");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_principal_that_does_not_exist_is_refused_rather_than_written() {
    // A pasted or mistyped UUID produces an entry that names nobody, grants nothing, occupies the
    // one row `uq_acl_entry` allows for its (principal, action), and can never be explained.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let ghost = UserId::from_uuid(Uuid::new_v4());

    let refused = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(library_node(spine.library), ghost, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await;
    assert!(matches!(refused, Err(GrantError::UnknownPrincipal)), "{refused:?}");
}

// ---------------------------------------------------------------------------------------------
// Upsert, not blind insert
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn re_granting_an_allow_updates_the_expiry_rather_than_colliding() {
    // `uq_acl_entry` permits one row per (resource, principal, action). A blind INSERT raises a
    // unique violation on the second call, which is what an administrator extending an expiry does.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let later = fixed_time() + Duration::days(30);

    let base = to_user(library, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None);
    grant(&mut conn, alpha, &base, &[DOWNLOAD], fixed_time()).await.expect("first grant");

    let extended = Grant { expires_at: Some(later), ..base };
    let written = grant(&mut conn, alpha, &extended, &[DOWNLOAD], fixed_time())
        .await
        .expect("re-granting an ALLOW over an ALLOW is ordinary");
    assert_eq!(written, 1);

    let entries = entries_on(&mut conn, alpha, library, fixed_time()).await.expect("read entries");
    assert_eq!(entries.len(), 1, "the second grant added a row instead of updating one");
    assert_eq!(entry_for(&entries, "file.download").entry.expires_at, Some(later));
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_repeated_action_in_one_call_does_not_abort_the_whole_write() {
    // PostgreSQL refuses an ON CONFLICT DO UPDATE that would touch one row twice, and it refuses
    // the *command*, not the duplicate — so an accidental repeat would drop the actions that were
    // fine, with an error naming none of them.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let library = library_node(spine.library);

    let written = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(library, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD, DOWNLOAD, PREVIEW],
        fixed_time(),
    )
    .await
    .expect("a repeated action is collapsed, not fatal");
    assert_eq!(written, 2, "the count must be the rows touched, not the actions offered");

    let rows = stored_rows(&mut conn, fixtures.alpha.id, library).await;
    assert_eq!(rows.len(), 2);
}

// ---------------------------------------------------------------------------------------------
// An ALLOW does not erase a DENY
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_allow_may_not_overwrite_a_deny_and_the_deny_survives_the_attempt() {
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let member = fixtures.alpha.member;

    grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Deny, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the DENY is written");

    let refused = grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD, PREVIEW],
        fixed_time(),
    )
    .await;
    match refused {
        Err(GrantError::DenyInPlace { actions }) => assert_eq!(actions, vec!["file.download"]),
        other => panic!("an ALLOW erased a DENY, or failed for the wrong reason: {other:?}"),
    }

    // Nothing was written, including the action that was not denied: a refusal must leave the ACL
    // exactly as it found it, or a caller cannot tell what part of their request took effect.
    let rows = stored_rows(&mut conn, alpha, library).await;
    assert_eq!(
        rows,
        vec![(
            "file.download".to_owned(),
            "DENY".to_owned(),
            Some(member.as_uuid()),
            fixtures.alpha.admin.as_uuid()
        )]
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_deny_may_overwrite_an_allow_because_that_only_narrows_access() {
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let member = fixtures.alpha.member;

    grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the ALLOW is written");
    grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Deny, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("a tightening must not be harder than a widening");

    let entries = entries_on(&mut conn, alpha, library, fixed_time()).await.expect("read entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entry_for(&entries, "file.download").entry.effect, Effect::Deny);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn lifting_a_deny_takes_a_revoke_and_then_a_grant() {
    // The documented two-act path. If this ever becomes one act, the test above stops meaning
    // anything.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let member = fixtures.alpha.member;
    let principal = Principal::new(PrincipalKind::User, member.as_uuid());

    grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Deny, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the DENY is written");

    let removed =
        revoke(&mut conn, alpha, library, principal, &[DOWNLOAD]).await.expect("revoke the DENY");
    assert_eq!(removed, 1);

    grant(
        &mut conn,
        alpha,
        &to_user(library, member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("with the DENY gone the ALLOW is ordinary");

    let entries = entries_on(&mut conn, alpha, library, fixed_time()).await.expect("read entries");
    assert_eq!(entry_for(&entries, "file.download").entry.effect, Effect::Allow);
}

// ---------------------------------------------------------------------------------------------
// A grant cannot cross a tenant
//
// Every test in this section runs on the superuser connection, where row-level security is
// bypassed, so the `tenant_id = $1` predicate in the statement is the only thing holding the
// property. Deleting it from the named statement turns exactly one of these red.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_deny_on_the_same_resource_id_does_not_block_this_tenants_grant() {
    // `DENIED_ACTIONS_SQL`. Remove `a.tenant_id = $1` from it and this goes red: beta's DENY is
    // found, alpha's ALLOW is refused, and one tenant has silently acquired a veto over another's
    // permissions — reachable by anyone who can guess or observe a UUID.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let library = library_node(spine.library);
    let member = fixtures.alpha.member;

    plant_entry(
        &mut conn,
        fixtures.beta.id,
        library,
        Principal::new(PrincipalKind::User, member.as_uuid()),
        DOWNLOAD,
        Effect::Deny,
    )
    .await;

    let written = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(library, member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("tenant-beta's DENY is not tenant-alpha's business");
    assert_eq!(written, 1);

    // And the two rows coexist: the upsert conflicted with neither, because `tenant_id` is the
    // first column of `uq_acl_entry`.
    let beta = stored_rows(&mut conn, fixtures.beta.id, library).await;
    assert_eq!(beta.len(), 1);
    assert_eq!(beta[0].1, "DENY", "the grant reached across and rewrote another tenant's row");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_revoke_does_not_remove_another_tenants_entry() {
    // `REVOKE_SQL`. Remove `a.tenant_id = $1` and this goes red — a `DELETE` is the one statement
    // here whose missing predicate destroys data rather than merely reading it.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let library = library_node(spine.library);
    let member = fixtures.alpha.member;
    let principal = Principal::new(PrincipalKind::User, member.as_uuid());

    plant_entry(&mut conn, fixtures.beta.id, library, principal, DOWNLOAD, Effect::Allow).await;
    grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(library, member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("alpha's own grant");

    let removed = revoke(&mut conn, fixtures.alpha.id, library, principal, &[DOWNLOAD])
        .await
        .expect("revoke");
    assert_eq!(removed, 1, "the revocation removed more than this tenant's row");
    assert_eq!(
        stored_rows(&mut conn, fixtures.beta.id, library).await.len(),
        1,
        "tenant-beta's entry was deleted by tenant-alpha's revocation"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn entries_on_does_not_return_another_tenants_entry() {
    // `ENTRIES_ON_SQL`. Remove `a.tenant_id = $1` and this goes red — a permissions screen showing
    // another tenant's principals is a directory leak with a UI in front of it.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let library = library_node(spine.library);

    plant_entry(
        &mut conn,
        fixtures.beta.id,
        library,
        Principal::new(PrincipalKind::User, fixtures.beta.owner.as_uuid()),
        PREVIEW,
        Effect::Allow,
    )
    .await;
    grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(library, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("alpha's own grant");

    let entries = entries_on(&mut conn, fixtures.alpha.id, library, fixed_time())
        .await
        .expect("read entries");
    assert_eq!(entries.len(), 1, "entries_on returned another tenant's rows: {entries:#?}");
    assert_eq!(entries[0].action, "file.download");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_granting_user_must_belong_to_this_tenant() {
    // `GRANTER_EXISTS_SQL`. Remove `tenant_id = $1` and this goes red: beta's owner is accepted as
    // the author of an entry in alpha, and the audit trail names somebody the tenant has never
    // heard of.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let refused = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(
            library_node(spine.library),
            fixtures.alpha.member,
            Effect::Allow,
            fixtures.beta.owner,
            None,
        ),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await;
    assert!(matches!(refused, Err(GrantError::UnknownGranter)), "{refused:?}");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_principal_from_another_tenant_cannot_be_granted_anything() {
    // The `USER` arm of `principal_exists_sql`. Remove `tenant_id = $1` and this goes red: a
    // cross-tenant grant becomes writable, and the row it writes is one the resolver in *this*
    // tenant will honour for a caller from another one.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let refused = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(
            library_node(spine.library),
            fixtures.beta.member,
            Effect::Allow,
            fixtures.alpha.admin,
            None,
        ),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await;
    assert!(matches!(refused, Err(GrantError::UnknownPrincipal)), "{refused:?}");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_grant_on_another_tenants_library_is_not_found() {
    // `LIBRARY_EXISTS_SQL`. Remove `tenant_id = $1` and this goes red. Note the answer: not found,
    // never forbidden — a `403` here would confirm that the library exists somewhere
    // (`CLAUDE.md` rule 7).
    let (_db, fixtures, _spine, mut conn) = setup().await;
    let beta_spine = Spine::new(fixtures.beta.id);
    beta_spine
        .insert(&mut conn, fixtures.beta.owner, fixed_time())
        .await
        .expect("insert beta's spine");

    let refused = grant(
        &mut conn,
        fixtures.alpha.id,
        &to_user(
            library_node(beta_spine.library),
            fixtures.alpha.member,
            Effect::Allow,
            fixtures.alpha.admin,
            None,
        ),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(GrantError::Authz(enclave_authorization::AuthzError::UnknownResource))
        ),
        "{refused:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// EVERYONE, expiry, content nodes and share links
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn everyone_stores_a_null_principal_id_and_still_folds_to_one_row_per_action() {
    // The `COALESCE` in `uq_acl_entry` is what makes this true: NULLs are distinct in a unique
    // index, so without the fold EVERYONE could hold the same action any number of times and the
    // duplicates would disagree the moment one was revoked.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let everyone = Grant {
        resource: library,
        principal: Principal::everyone(),
        effect: Effect::Allow,
        granted_by: fixtures.alpha.admin,
        expires_at: None,
    };

    grant(&mut conn, alpha, &everyone, &[DOWNLOAD], fixed_time()).await.expect("first grant");
    grant(&mut conn, alpha, &everyone, &[DOWNLOAD], fixed_time()).await.expect("second grant");

    let rows = stored_rows(&mut conn, alpha, library).await;
    assert_eq!(rows.len(), 1, "EVERYONE acquired a duplicate row: {rows:#?}");
    assert_eq!(rows[0].2, None, "EVERYONE must carry a NULL principal_id");

    // And the guard reaches it: a DENY to EVERYONE blocks an ALLOW to EVERYONE, which it can only
    // do if the predicate folds NULL the same way the index does.
    let denied = Grant { effect: Effect::Deny, ..everyone };
    grant(&mut conn, alpha, &denied, &[DOWNLOAD], fixed_time()).await.expect("tighten to DENY");
    let refused = grant(&mut conn, alpha, &everyone, &[DOWNLOAD], fixed_time()).await;
    assert!(matches!(refused, Err(GrantError::DenyInPlace { .. })), "{refused:?}");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_expired_entry_is_returned_flagged_and_ignored_by_the_resolver() {
    // Two different jobs, deliberately answered differently. The resolver drops the row (rule 4);
    // `entries_on` shows it, because the administrator asking why somebody lost access needs to see
    // the entry that lapsed — and because a lapsed DENY is what makes their next grant fail.
    let (db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let library = library_node(spine.library);
    let user = fixtures.alpha.member;
    let lapsed = fixed_time() - Duration::days(1);

    grant(
        &mut conn,
        alpha,
        &to_user(library, user, Effect::Allow, fixtures.alpha.admin, Some(lapsed)),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("the grant is written");

    let entries = entries_on(&mut conn, alpha, library, fixed_time()).await.expect("read entries");
    assert_eq!(entries.len(), 1, "an expired entry was hidden from administration");
    assert!(entries[0].expired, "the entry was returned without its expiry flag");

    let pool = db.pool().await.expect("application-role pool");
    let decision = PgAclAuthorization::new(pool)
        .authorize(&ctx(alpha, user), DOWNLOAD, &spine.file_ref())
        .await
        .expect("resolve");
    assert!(!decision.is_allowed(), "an expired entry granted access");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_grant_on_a_file_moves_the_acl_revision_the_search_index_compares() {
    // `files.acl_revision` is the index's `acl_epoch` (`docs/07 §6`). A permission change that did
    // not move it leaves the index believing its ACL tokens are current.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let file = ChainNode::new(AclResourceType::File, spine.file.as_uuid());

    let before = acl_revision(&mut conn, alpha, spine.file.as_uuid()).await;
    grant(
        &mut conn,
        alpha,
        &to_user(file, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await
    .expect("grant on the file");
    assert_eq!(acl_revision(&mut conn, alpha, spine.file.as_uuid()).await, before + 1);

    // And a resource type that does not match the node is not found rather than silently written:
    // ("FILE", folder_id) satisfies every CHECK and resolves against nothing.
    let mismatched = ChainNode::new(AclResourceType::File, spine.folder.as_uuid());
    let refused = grant(
        &mut conn,
        alpha,
        &to_user(mismatched, fixtures.alpha.member, Effect::Allow, fixtures.alpha.admin, None),
        &[DOWNLOAD],
        fixed_time(),
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(GrantError::Authz(enclave_authorization::AuthzError::UnknownResource))
        ),
        "{refused:?}"
    );
}

async fn acl_revision(conn: &mut PgConnection, tenant: TenantId, file: Uuid) -> i64 {
    sqlx::query_scalar("SELECT acl_revision FROM files WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.as_uuid())
        .bind(file)
        .fetch_one(&mut *conn)
        .await
        .expect("read acl_revision")
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn revoking_a_share_link_grant_does_not_end_the_link() {
    // `ENC-879`: a link bearer is a principal the chain can *name*, not one the chain owns. The
    // link's own lifecycle is what revokes it — `crate::service::link_principal_is_live` gates the
    // whole resolution on `share_links` before any chain is walked — so removing this row narrows a
    // grant and leaves a live link resolving to nothing.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let alpha = fixtures.alpha.id;
    let file = ChainNode::new(AclResourceType::File, spine.file.as_uuid());
    let link = ShareLinkId::new_v7();
    insert_share_link(&mut conn, alpha, link, spine.file.as_uuid(), fixtures.alpha.owner).await;

    let bearer = Principal::new(PrincipalKind::ShareLink, link.as_uuid());
    let written = grant(
        &mut conn,
        alpha,
        &Grant {
            resource: file,
            principal: bearer,
            effect: Effect::Allow,
            granted_by: fixtures.alpha.admin,
            expires_at: None,
        },
        &[PREVIEW],
        fixed_time(),
    )
    .await
    .expect("a SHARE_LINK grant is exactly what 0027 made writable");
    assert_eq!(written, 1);

    let removed =
        revoke(&mut conn, alpha, file, bearer, &[PREVIEW]).await.expect("revoke the grant");
    assert_eq!(removed, 1);

    let still_live: bool = sqlx::query_scalar(
        "SELECT revoked_at IS NULL FROM share_links WHERE tenant_id = $1 AND id = $2",
    )
    .bind(alpha.as_uuid())
    .bind(link.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("read the link");
    assert!(
        still_live,
        "revoking the ACL entry revoked the link: the two operations have been collapsed"
    );
}

async fn insert_share_link(
    conn: &mut PgConnection,
    tenant: TenantId,
    link: ShareLinkId,
    file: Uuid,
    created_by: UserId,
) {
    sqlx::query(
        "INSERT INTO share_links
           (id, tenant_id, resource_type, resource_id, token_hash, permission, allow_download,
            audience, created_by, created_at)
         VALUES ($1, $2, 'FILE', $3, $4, 'PREVIEW_ONLY', FALSE, 'ANYONE', $5, $6)",
    )
    .bind(link.as_uuid())
    .bind(tenant.as_uuid())
    .bind(file)
    // Not a token and not a hash of one: the column is only being made unique here. A real token
    // never enters a fixture (`CLAUDE.md` rule 11).
    .bind(format!("fixture-{}", link.as_uuid()))
    .bind(created_by.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert share link");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_resource_kind_with_no_table_is_refused_rather_than_written_and_forgotten() {
    // `acl_entries.resource_type` admits PAGE and LIST_ITEM; no migration creates either table. An
    // entry on one resolves against nothing, appears in no permissions UI, and is reachable by
    // nothing that walks the content tree.
    let (_db, fixtures, _spine, mut conn) = setup().await;
    for kind in [AclResourceType::Page, AclResourceType::ListItem] {
        let refused = grant(
            &mut conn,
            fixtures.alpha.id,
            &to_user(
                ChainNode::new(kind, Uuid::new_v4()),
                fixtures.alpha.member,
                Effect::Allow,
                fixtures.alpha.admin,
                None,
            ),
            &[DOWNLOAD],
            fixed_time(),
        )
        .await;
        assert!(
            matches!(refused, Err(GrantError::UnbackedResourceKind { .. })),
            "{kind}: {refused:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn revoking_something_that_was_never_granted_reports_nothing_removed() {
    // The distinction a permissions UI needs and `DELETE` will not volunteer. Reporting success
    // without a count would let a caller believe they had ended access they never had.
    let (_db, fixtures, spine, mut conn) = setup().await;
    let removed = revoke(
        &mut conn,
        fixtures.alpha.id,
        library_node(spine.library),
        Principal::new(PrincipalKind::User, fixtures.alpha.member.as_uuid()),
        &[Action::Container(ContainerAction::ManagePermissions)],
    )
    .await
    .expect("revoking nothing is not an error");
    assert_eq!(removed, 0);
}
