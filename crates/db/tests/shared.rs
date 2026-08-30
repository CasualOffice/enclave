//! *Shared with me* against a real PostgreSQL — **what did somebody deliberately give this person?**
//!
//! `ENC-954`. `acl_entries` has had a writer since `ENC-916` and nothing has ever listed what a
//! person was given, so a colleague could share a document outside any workspace this user belongs
//! to and they had no way to find it.
//!
//! Two shapes of mistake are possible here and they fail in opposite directions, so every test
//! below carries its opposite:
//!
//! * **Showing too much** — a `DENY`, an `EVERYONE` grant, a workspace membership, an expired
//!   entry. Each would put rows on the screen that are not shares, and the `DENY` case would offer
//!   a door the chain refuses when the user walks through it.
//! * **Showing too little** — a grant through a nested group, or one file whose several `acl_entries`
//!   rows collapse to nothing instead of to one row. Both hide something a person was given, which
//!   is the failure the feature exists to fix.
//!
//! An assertion that a row is absent passes against a query that returns nothing at all, so each
//! one runs **beside a positive on the same fixture and in the same test**.
//!
//! # Row-level security is off for the cross-tenant test, deliberately
//!
//! `TestDb::pool` connects as `enclave_app` and runs with RLS in force, which is right for the
//! ordinary paths and exactly wrong for a cross-tenant assertion: with RLS in force, deleting the
//! `tenant_id` predicate from the SQL changes nothing observable. That test takes the harness's
//! superuser connection and proves it can see both tenants' rows before asking the question.
//!
//! Ignored by default because they need a live PostgreSQL.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{Duration, Utc};
use enclave_core::{FileId, GroupId, TenantId, UserId};
use enclave_db::shared::{shared_with, shared_with_on, SharedCandidate};
use enclave_db::DbPool;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

async fn harness() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    spine
}

/// One `acl_entries` row, written as setup.
///
/// Every column spelled as `migrations/0004_content_and_acl.sql` defines it, so a schema that
/// drifts from it fails here rather than somewhere subtler.
#[allow(clippy::too_many_arguments)]
async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource: Uuid,
    principal_type: &str,
    principal: Option<Uuid>,
    action: &str,
    effect: &str,
    granted_by: UserId,
    expires_at: Option<chrono::DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id,
            action, effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource.to_string().parse::<Uuid>().expect("a uuid"))
    .bind(principal_type)
    .bind(principal)
    .bind(action)
    .bind(effect)
    .bind(granted_by.as_uuid())
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .expect("insert an acl entry");
}

fn ids(rows: &[SharedCandidate]) -> Vec<FileId> {
    rows.iter().map(|row| row.file_id).collect()
}

/// A file granted to a user appears; a workspace they are a member of does not.
///
/// The pair is the definition. Both are `acl_entries` rows naming this person, and only one of them
/// is a *share*: the other is how somebody joins a team, and including it would fill the screen
/// with every container the caller belongs to — a listing of "things I work on", which is what the
/// navigation already is.
///
/// Deleting `AND a.resource_type IN ('FILE','FOLDER')` from `SHARED_SQL` turns this red on the
/// second assertion while leaving the first green, which is why they are one test.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_file_grant_is_a_share_and_a_workspace_membership_is_not() {
    let (db, fx, pool) = harness().await;
    let mut admin = db.connect().await.expect("admin connection");
    let s = spine(&mut admin, fx.alpha.id, fx.alpha.owner).await;
    let member = fx.alpha.member;

    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        s.file.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut admin,
        fx.alpha.id,
        "WORKSPACE",
        s.workspace.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "container.read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;

    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let page = shared_with(&mut tx, member, &[], Utc::now(), 50).await.expect("read");

    assert_eq!(
        ids(&page.rows),
        vec![s.file],
        "a file granted to this person is a share, and the workspace they were added to is not: \
         one is somebody choosing to give them a document, the other is how they joined the team"
    );
}

/// A grant through a group appears, and says which group.
///
/// The control is the direct grant in the same listing: without it, *"the group grant appeared"* is
/// satisfied by a query that ignores `principal_type` altogether. `via_group` is asserted on both
/// rows because the two are different answers to *"why do I have this"* — somebody chose this
/// person, or somebody chose a team they happen to be in — and a user who cannot tell them apart
/// cannot reason about what they lose when they leave it.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_grant_through_a_group_appears_and_names_the_group() {
    let (db, fx, pool) = harness().await;
    let mut admin = db.connect().await.expect("admin connection");
    let s = spine(&mut admin, fx.alpha.id, fx.alpha.owner).await;
    let member = fx.alpha.member;
    let team = GroupId::new_v7();

    let direct = add_file(&mut admin, &s, fx.alpha.owner, "direct.txt").await;
    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        direct.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        s.file.as_uuid(),
        "GROUP",
        Some(team.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;

    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let page = shared_with(&mut tx, member, &[team], Utc::now(), 50).await.expect("read");

    let by_id = |id: FileId| page.rows.iter().find(|row| row.file_id == id).cloned();
    let via = by_id(s.file).expect("the group's file must appear");
    let straight = by_id(direct).expect("the control: the direct grant must appear");

    assert_eq!(via.via_group, Some(team), "a group share must name the group it came through");
    assert_eq!(straight.via_group, None, "a direct share came through no group and must say so");
}

/// A `DENY`, an `EVERYONE` grant and an expired entry are all absent; a live `ALLOW` is present.
///
/// Three exclusions in one test because they share a control and each is a different way to put a
/// row on the screen that is not a share:
///
/// * a `DENY` is access being **taken away**, and listing it offers a door the chain refuses;
/// * `EVERYONE` is a property of the tenant, and would put identical rows on every user's screen;
/// * an expired grant is one that has already ended.
///
/// Deleting any one of the three predicates turns this red on that row alone and leaves the control
/// green, which is what makes the four assertions worth having separately.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_denial_an_everyone_grant_and_an_expired_entry_are_not_shares() {
    let (db, fx, pool) = harness().await;
    let mut admin = db.connect().await.expect("admin connection");
    let s = spine(&mut admin, fx.alpha.id, fx.alpha.owner).await;
    let member = fx.alpha.member;

    let denied = add_file(&mut admin, &s, fx.alpha.owner, "denied.txt").await;
    let everyone = add_file(&mut admin, &s, fx.alpha.owner, "everyone.txt").await;
    let expired = add_file(&mut admin, &s, fx.alpha.owner, "expired.txt").await;

    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        s.file.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        denied.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "DENY",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        everyone.as_uuid(),
        "EVERYONE",
        None,
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut admin,
        fx.alpha.id,
        "FILE",
        expired.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        Some(Utc::now() - Duration::hours(1)),
    )
    .await;

    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let page = shared_with(&mut tx, member, &[], Utc::now(), 50).await.expect("read");
    let found = ids(&page.rows);

    assert!(found.contains(&s.file), "the control: a live ALLOW naming this user must appear");
    assert!(!found.contains(&denied), "a DENY is access taken away, never a share to offer");
    assert!(!found.contains(&everyone), "a grant to EVERYONE is a tenant property, not a share");
    assert!(!found.contains(&expired), "an expired grant has already ended");
}

/// One file with several grants is one row, carrying the earliest.
///
/// A share is written as several `acl_entries` rows — `ENC-916`'s founding grant writes fifteen —
/// and a listing showing each would repeat one file fifteen times. `DISTINCT ON` keeps the earliest,
/// because that is when the share *happened*; an aggregate would pair that instant with whichever
/// `granted_by` an arbitrary row carried, which is a listing that says the right time and the wrong
/// person.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn several_grants_on_one_file_are_one_row() {
    let (db, fx, pool) = harness().await;
    let mut admin = db.connect().await.expect("admin connection");
    let s = spine(&mut admin, fx.alpha.id, fx.alpha.owner).await;
    let member = fx.alpha.member;

    for action in ["file.metadata_read", "file.preview", "file.download", "file.version_read"] {
        grant(
            &mut admin,
            fx.alpha.id,
            "FILE",
            s.file.as_uuid(),
            "USER",
            Some(member.as_uuid()),
            action,
            "ALLOW",
            fx.alpha.owner,
            None,
        )
        .await;
    }

    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let page = shared_with(&mut tx, member, &[], Utc::now(), 50).await.expect("read");

    assert_eq!(
        page.rows.len(),
        1,
        "four grants on one file must be one row, not four: a share is a thing somebody gave you, \
         not a list of the verbs they enabled — got {:?}",
        ids(&page.rows)
    );
    assert_eq!(page.rows[0].file_id, s.file);
    assert_eq!(page.rows[0].shared_by, fx.alpha.owner, "the granter must be the one who granted");
}

/// A trashed file is not a share.
///
/// The control is a live file shared the same way in the same listing. Without the `deleted_at`
/// predicate the recipient sees a row that opens onto a `404`, which reads as the product losing
/// their document rather than as somebody having deleted it.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_trashed_file_leaves_the_share_list() {
    let (db, fx, pool) = harness().await;
    let mut admin = db.connect().await.expect("admin connection");
    let s = spine(&mut admin, fx.alpha.id, fx.alpha.owner).await;
    let member = fx.alpha.member;

    let trashed = add_file(&mut admin, &s, fx.alpha.owner, "gone.txt").await;
    for file in [s.file, trashed] {
        grant(
            &mut admin,
            fx.alpha.id,
            "FILE",
            file.as_uuid(),
            "USER",
            Some(member.as_uuid()),
            "file.metadata_read",
            "ALLOW",
            fx.alpha.owner,
            None,
        )
        .await;
    }
    sqlx::query("UPDATE files SET deleted_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(fx.alpha.id.as_uuid())
        .bind(trashed.as_uuid())
        .execute(&mut admin)
        .await
        .expect("trash it");

    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let page = shared_with(&mut tx, member, &[], Utc::now(), 50).await.expect("read");
    let found = ids(&page.rows);

    assert!(found.contains(&s.file), "the control: a live shared file must still appear");
    assert!(
        !found.contains(&trashed),
        "a trashed file must leave the list: a row that opens onto a 404 reads as the product \
         losing somebody's document"
    );
}

/// Another tenant's share never reaches this tenant's list.
///
/// Runs over the **superuser** connection, where row-level security is not enforced, because that
/// is the only condition in which this measures the statement's own predicates rather than RLS. The
/// connection is proved to see both tenants' rows before the question is asked.
///
/// # What this proves, and what it does not
///
/// `SHARED_SQL` carries **two** tenant predicates — one on `acl_entries` and one on the `files`
/// join — and the mutation run says they are genuinely redundant: deleting *either* leaves this
/// test green, and deleting *both* turns it red. So this asserts the property (no cross-tenant row)
/// and cannot attribute it to a particular clause.
///
/// The first draft of this comment claimed it proved the `acl_entries` predicate. It does not, and
/// the difference matters: a future edit that removed one clause as "redundant" would pass here
/// while halving the defence. That is what
/// [`the_shared_read_scopes_every_relation_it_touches`] is for — it counts them in the source,
/// which is the only place a lost predicate is visible while the behaviour still holds.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn another_tenants_share_never_reaches_this_tenants_list() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("superuser connection");

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    // The *same* user id named in both tenants' ACLs. Contrived, and that is the point: it removes
    // the principal from the set of things that could be doing the filtering, leaving only the
    // tenant predicate.
    let member = fx.alpha.member;
    grant(
        &mut conn,
        fx.alpha.id,
        "FILE",
        alpha.file.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.alpha.owner,
        None,
    )
    .await;
    grant(
        &mut conn,
        fx.beta.id,
        "FILE",
        beta.file.as_uuid(),
        "USER",
        Some(member.as_uuid()),
        "file.metadata_read",
        "ALLOW",
        fx.beta.owner,
        None,
    )
    .await;

    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM acl_entries WHERE principal_id = $1")
            .bind(member.as_uuid())
            .fetch_one(&mut conn)
            .await
            .expect("count");
    assert!(
        visible >= 2,
        "this connection must see both tenants' rows, or the assertion below is measuring row \
         security rather than the predicate"
    );

    let page = shared_with_on(&mut conn, fx.alpha.id, member, &[], Utc::now(), 50)
        .await
        .expect("read alpha's shares");
    let found = ids(&page.rows);

    assert!(found.contains(&alpha.file), "the control: alpha's own share must appear");
    assert!(
        !found.contains(&beta.file),
        "beta's share reached alpha's listing; the statement's own tenant_id predicate is what \
         must stop it, because row security is not enforced on this connection"
    );
}

/// One more `FILE` node in an existing spine.
///
/// Every column spelled as `migrations/0005_files.sql` defines it, matching `crates/db/tests/recent.rs`
/// — a schema that drifts fails here rather than somewhere subtler.
async fn add_file(conn: &mut PgConnection, spine: &Spine, owner: UserId, name: &str) -> FileId {
    let id = FileId::new_v7();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, inherit_permissions, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, $5, 'FILE', $6, $6, 'text/plain', TRUE, $7, $7, now(), now())",
    )
    .bind(id.as_uuid())
    .bind(spine.tenant.as_uuid())
    .bind(spine.workspace.as_uuid())
    .bind(spine.library.as_uuid())
    .bind(spine.folder.as_uuid())
    .bind(name)
    .bind(owner.as_uuid())
    .execute(&mut *conn)
    .await
    .expect("insert a file");
    id
}

/// Every relation the share read touches is scoped to one tenant (`ENC-954`).
///
/// **Layer one, asserted where it is written**, and the companion to
/// [`another_tenants_share_never_reaches_this_tenants_list`] rather than a duplicate of it. The
/// behavioural test proves no cross-tenant row comes back; it cannot prove *why*, because the two
/// predicates are redundant and losing one changes nothing observable. This one notices that.
///
/// The same shape as `crates/db/src/retention.rs`'s equivalent, and for the same reason: a `contains`
/// check would stay green with one of the two deleted, so the predicates are **counted**.
///
/// Two, exactly: `acl_entries` in the inner select and `files` in the join. `classifications` is a
/// `LEFT JOIN` and carries its own as well — three in the text — so the assertion is `>= 3` rather
/// than an equality that a fourth relation would break for no reason.
#[test]
fn the_shared_read_scopes_every_relation_it_touches() {
    // The statement as the crate compiles it, not a copy — a restated query proves the restatement.
    let sql = enclave_db::shared::SHARED_SQL_FOR_TESTS;
    let scoped = sql.matches("tenant_id = $1").count();
    assert!(
        scoped >= 3,
        "the share read has {scoped} tenant-scoped predicates; acl_entries, files and \
         classifications each need one. Losing a single one leaves every behavioural test in this \
         file green — the redundancy is deliberate, and this is what keeps it redundant rather \
         than absent: {sql}"
    );
}
