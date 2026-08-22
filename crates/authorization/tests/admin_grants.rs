//! `ENC-619` — the administrative grant, as PostgreSQL actually answers it.
//!
//! `crates/authorization/src/admin.rs`'s unit tests prove the *decision*: that a grant is a set,
//! that an administrative action never reaches the ACL resolver, that only a person holds one.
//! What they cannot prove is what this file is for — that the flag is read from the right row, in
//! the right tenant, **as `enclave_app` under forced row-level security**, and that the states a
//! revocation puts an account into are states in which the grant is gone.
//!
//! Every read here goes through [`enclave_testing::TestDb::pool`], which `SET ROLE enclave_app`s.
//! A test that read over the harness's own administrative connection would bypass RLS and pass
//! whatever the policies said, which is PR #22's lesson and `ENC-124`'s.
//!
//! Ignored by default: they need a live PostgreSQL. CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_authorization::{AdminGrants, AdminRoles as _, PgAdminRoles};
use enclave_core::{Actor, ServiceAccountId, UserId};
use enclave_testing::{Fixtures, TestDb};

/// The seeded administrator holds every administrative action; every other seeded user holds none.
///
/// Both halves in one run, because "the member was not an administrator" is true of a reader that
/// returns the empty set for everybody — `docs/12-TESTING.md §1.2`'s exact shape.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_seeded_administrator_holds_the_grants_and_the_other_users_hold_none() {
    let db = TestDb::start().await.expect("a live PostgreSQL");
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application-role pool");
    let roles = PgAdminRoles::new(pool);

    let granted = roles
        .grants_for(fixtures.alpha.id, &Actor::User(fixtures.alpha.admin))
        .await
        .expect("read grants");
    assert_eq!(granted, AdminGrants::global(), "users.is_admin is the global administrator");

    for (label, user) in [
        ("member", fixtures.alpha.member),
        ("owner", fixtures.alpha.owner),
        // `docs/01-PRD.md §4` has an Auditor who may read the audit log and change nothing. There
        // is no assignment table to say so, so today they hold nothing at all — asserted rather
        // than left to be discovered (`ENC-650`).
        ("auditor", fixtures.alpha.auditor),
    ] {
        let grants =
            roles.grants_for(fixtures.alpha.id, &Actor::User(user)).await.expect("read grants");
        assert!(grants.is_empty(), "{label} is not an administrator");
    }
}

/// One tenant's administrator is not another tenant's, and the reader cannot even see the row.
///
/// The seeded fixtures mirror each other, so beta's administrator is a *genuine* administrator —
/// the control is in the same run, and it is what makes the empty answer mean isolation rather than
/// a reader that finds nobody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_administrator_of_one_tenant_holds_nothing_in_another() {
    let db = TestDb::start().await.expect("a live PostgreSQL");
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application-role pool");
    let roles = PgAdminRoles::new(pool);

    // The control, both ways round: each administrator holds the grants in their own tenant.
    for (tenant, admin) in
        [(fixtures.alpha.id, fixtures.alpha.admin), (fixtures.beta.id, fixtures.beta.admin)]
    {
        let grants = roles.grants_for(tenant, &Actor::User(admin)).await.expect("read grants");
        assert_eq!(grants, AdminGrants::global());
    }

    // And neither holds anything in the other's, in both directions — a leak one way is a leak.
    for (tenant, foreign) in
        [(fixtures.alpha.id, fixtures.beta.admin), (fixtures.beta.id, fixtures.alpha.admin)]
    {
        let grants = roles.grants_for(tenant, &Actor::User(foreign)).await.expect("read grants");
        assert!(grants.is_empty(), "another tenant's administrator administers nothing here");
    }
}

/// A suspended or deprovisioned administrator holds nothing, and neither does a deleted one.
///
/// These are the states an incident response and a leaver process put an account into. The token
/// outlives the change by up to its lifetime, so the *grant* has to be gone at the moment the row
/// says so — which is why the states are in the statement's `WHERE` clause rather than checked
/// somewhere a later caller might skip.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_suspended_or_deleted_administrator_administers_nothing() {
    let db = TestDb::start().await.expect("a live PostgreSQL");
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application-role pool");
    let roles = PgAdminRoles::new(pool);
    let admin = fixtures.alpha.admin;

    // The control first: the same user, the same reader, before anything is changed.
    let before = roles.grants_for(fixtures.alpha.id, &Actor::User(admin)).await.expect("read");
    assert_eq!(before, AdminGrants::global());

    for state in ["SUSPENDED", "DEPROVISIONED"] {
        set_status(&db, &fixtures, admin, state, false).await;
        let grants =
            roles.grants_for(fixtures.alpha.id, &Actor::User(admin)).await.expect("read grants");
        assert!(grants.is_empty(), "a {state} administrator administers nothing");
    }

    // Restored, and the grant comes back — so the three assertions above are about the status
    // rather than about a reader that stopped working after the first `UPDATE`.
    set_status(&db, &fixtures, admin, "ACTIVE", false).await;
    let restored = roles.grants_for(fixtures.alpha.id, &Actor::User(admin)).await.expect("read");
    assert_eq!(restored, AdminGrants::global());

    set_status(&db, &fixtures, admin, "ACTIVE", true).await;
    let deleted = roles.grants_for(fixtures.alpha.id, &Actor::User(admin)).await.expect("read");
    assert!(deleted.is_empty(), "a deleted administrator administers nothing");
}

/// A principal that has no row in `users` is never an administrator, and no query is run for one.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_machine_principal_and_an_unknown_user_hold_nothing() {
    let db = TestDb::start().await.expect("a live PostgreSQL");
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application-role pool");
    let roles = PgAdminRoles::new(pool);

    // A service account whose id is *the administrator's*: the only difference between this and the
    // control below is the principal's kind, so the refusal cannot be about the id.
    let machine =
        Actor::ServiceAccount(ServiceAccountId::from_uuid(fixtures.alpha.admin.as_uuid()));
    let grants = roles.grants_for(fixtures.alpha.id, &machine).await.expect("read grants");
    assert!(grants.is_empty(), "is_admin is a column on users; a machine has no row there");

    let unknown =
        roles.grants_for(fixtures.alpha.id, &Actor::User(UserId::new_v7())).await.expect("read");
    assert!(unknown.is_empty());

    let system = roles.grants_for(fixtures.alpha.id, &Actor::System).await.expect("read");
    assert!(system.is_empty());

    // The control.
    let real = roles
        .grants_for(fixtures.alpha.id, &Actor::User(fixtures.alpha.admin))
        .await
        .expect("read");
    assert_eq!(real, AdminGrants::global());
}

/// Changes one seeded user's lifecycle state over the harness's own connection.
///
/// Written over the administrative connection deliberately: this is fixture manipulation, not the
/// claim. Every assertion above is made through `PgAdminRoles`, which runs as `enclave_app`.
async fn set_status(db: &TestDb, fixtures: &Fixtures, user: UserId, status: &str, deleted: bool) {
    let mut conn = db.connect().await.expect("admin connection");
    sqlx::query(
        "UPDATE users
            SET status = $3,
                deleted_at = CASE WHEN $4 THEN now() ELSE NULL END
          WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fixtures.alpha.id.as_uuid())
    .bind(user.as_uuid())
    .bind(status)
    .bind(deleted)
    .execute(&mut conn)
    .await
    .expect("update the fixture user");
}
