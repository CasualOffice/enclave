//! The identity repositories against a real PostgreSQL.
//!
//! Every test here is `#[ignore]`d and runs under the `enclave-testing` harness — `TestDb::start`
//! plus `DATABASE_URL`, which CI provides and invokes with `--include-ignored`
//! (`.github/workflows/ci.yml`, `crates/testing/src/lib.rs`). They are not skipped work: they are
//! the assertions that cannot be made without a database, and the ones that would have caught
//! `ENC-124`.
//!
//! # Two things every test here must keep true
//!
//! 1. **Queries run as `enclave_app`.** `DATABASE_URL` points at a cluster superuser, because the
//!    harness has to create databases — and *superusers bypass row-level security entirely*. Work
//!    goes through `TestDb::pool`, which sets the application role. A test that used
//!    `TestDb::connect` for its assertions would run with isolation switched off and prove nothing,
//!    which is exactly what happened until a real cross-tenant request returned `200` (`ENC-124`,
//!    migration `0003`).
//! 2. **Seeding is the only thing done as the superuser.** Inserting fixtures needs to write rows
//!    for two tenants at once, which is precisely what RLS forbids. So seeding uses the
//!    administrative connection and every *assertion* uses the application pool.
//!
//! `tenant-beta` is not decoration. It mirrors `tenant-alpha` with the same group and user names
//! (`docs/12-TESTING.md §3`), so a cross-tenant assertion that passes because the other tenant's
//! records happen to be called something else cannot pass by accident.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{GroupId, TenantId, UserId};
use enclave_db::{sql, DbPool, TenantScoped};
use enclave_identity::{
    GroupRepository, IdentityError, NestingLimit, PageSize, TenantRepository, UserFilter,
    UserRepository,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

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

/// Inserts a group directly, as the administrative user.
async fn insert_group(conn: &mut PgConnection, tenant: TenantId, id: GroupId, name: &str) {
    sqlx::query(
        "INSERT INTO groups (id, tenant_id, name, normalized_name, source, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'LOCAL', $5, $5)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(sql(id))
    .bind(sql(tenant))
    .bind(name)
    .bind(name.to_lowercase())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert group");
}

/// Inserts one membership edge.
async fn insert_edge(
    conn: &mut PgConnection,
    tenant: TenantId,
    group: GroupId,
    member: uuid::Uuid,
    kind: &str,
) {
    sqlx::query(
        "INSERT INTO group_members (tenant_id, group_id, member_id, member_type, added_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING",
    )
    .bind(sql(tenant))
    .bind(sql(group))
    .bind(member)
    .bind(kind)
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert group membership");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_tenant_resolves_by_id_and_by_slug_to_the_same_record() {
    let (db, fixtures, pool) = start().await;

    let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
    let by_id = TenantRepository::find_by_id(&mut tx, fixtures.alpha.id)
        .await
        .expect("query")
        .expect("the seeded tenant exists");
    // Case folding is the lookup's job: a custom-domain or path-based route may arrive in any case.
    let by_slug = TenantRepository::find_by_slug(&mut tx, "Tenant-Alpha")
        .await
        .expect("query")
        .expect("the seeded tenant resolves by slug");
    tx.commit().await.expect("commit");

    assert_eq!(by_id, by_slug);
    assert_eq!(by_id.slug, fixtures.alpha.slug);

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn only_a_verified_custom_domain_resolves_a_tenant() {
    // The attack: any tenant can insert a `tenant_domains` row claiming any hostname. Only the
    // verification token proves control, and this value becomes `app.tenant_id` — so resolving an
    // unverified claim is a tenancy takeover, not a routing bug.
    let (db, fixtures, pool) = start().await;

    let mut admin = db.connect().await.expect("administrative connection");
    for (domain, verified) in [("verified.example", true), ("claimed.example", false)] {
        sqlx::query(
            "INSERT INTO tenant_domains
               (tenant_id, domain, verified_at, verification_token, certificate_mode, created_at)
             VALUES ($1, $2, $3, 'token', 'AUTOMATIC', $4)",
        )
        .bind(sql(fixtures.alpha.id))
        .bind(domain)
        .bind(verified.then(Utc::now))
        .bind(Utc::now())
        .execute(&mut admin)
        .await
        .expect("insert domain");
    }

    // `tenant_domains` is under row-level security (migration 0002) and this path runs before any
    // tenant context exists, so it reads on the administrative connection here. In the product it
    // is `enclave_db::PlatformConnection` — see `enclave_identity::tenant_repo`.
    let resolved = TenantRepository::find_by_verified_domain(&mut admin, "Verified.Example.")
        .await
        .expect("query")
        .expect("a verified domain resolves");
    assert_eq!(resolved.id, fixtures.alpha.id);

    assert!(
        TenantRepository::find_by_verified_domain(&mut admin, "claimed.example")
            .await
            .expect("query")
            .is_none(),
        "an unverified domain claim must not resolve a tenant"
    );

    drop(admin);
    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_user_is_found_by_email_only_within_its_own_tenant() {
    let (db, fixtures, pool) = start().await;
    let alpha_email = format!("owner@{}.example", fixtures.alpha.slug);

    let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
    let found =
        UserRepository::find_by_email(&mut tx, fixtures.alpha.id, "  OWNER@Tenant-Alpha.Example ")
            .await
            .expect("query")
            .expect("the seeded owner is found through the normalized form");
    assert_eq!(found.id, fixtures.alpha.owner);
    assert_eq!(found.normalized_email, alpha_email);
    tx.commit().await.expect("commit");

    // The same address, asked for inside beta's tenant context. Two layers say no: the application
    // predicate and RLS. The answer is absence, never another tenant's row.
    let mut tx = TenantScoped::begin(&pool, fixtures.beta.id).await.expect("begin");
    assert!(
        UserRepository::find_by_email(&mut tx, fixtures.beta.id, &alpha_email)
            .await
            .expect("query")
            .is_none(),
        "alpha's user was visible from beta's transaction"
    );
    assert!(
        UserRepository::find_by_id(&mut tx, fixtures.beta.id, fixtures.alpha.owner)
            .await
            .expect("query")
            .is_none(),
        "alpha's user id resolved inside beta"
    );
    tx.commit().await.expect("commit");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_listing_pages_through_every_user_exactly_once() {
    let (db, fixtures, pool) = start().await;
    let filter = UserFilter::default();

    let mut seen: Vec<UserId> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;

    loop {
        let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
        let page = UserRepository::list_by_tenant(
            &mut tx,
            fixtures.alpha.id,
            &filter,
            PageSize::new(2),
            cursor.as_deref(),
        )
        .await
        .expect("query");
        tx.commit().await.expect("commit");

        pages += 1;
        assert!(pages < 10, "the paging loop did not terminate");
        seen.extend(page.users.iter().map(|user| user.id));
        assert_eq!(page.has_more, page.next_cursor.is_some());

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // Five seeded users, each exactly once, and none of beta's.
    assert_eq!(seen.len(), 5, "{seen:?}");
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 5, "a user was returned on two pages");
    assert!(!seen.contains(&fixtures.beta.owner));
    assert!(seen.contains(&fixtures.alpha.owner));
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]), "the listing is not id-ordered");

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_cursor_issued_by_one_tenant_is_refused_by_another() {
    let (db, fixtures, pool) = start().await;
    let filter = UserFilter::default();

    let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
    let page =
        UserRepository::list_by_tenant(&mut tx, fixtures.alpha.id, &filter, PageSize::new(1), None)
            .await
            .expect("query");
    tx.commit().await.expect("commit");
    let cursor = page.next_cursor.expect("five users do not fit on one page of one");

    let mut tx = TenantScoped::begin(&pool, fixtures.beta.id).await.expect("begin");
    let refused = UserRepository::list_by_tenant(
        &mut tx,
        fixtures.beta.id,
        &filter,
        PageSize::new(1),
        Some(&cursor),
    )
    .await;
    tx.commit().await.expect("commit");

    assert!(
        matches!(refused, Err(IdentityError::InvalidCursor)),
        "beta resumed alpha's listing: {refused:?}"
    );

    pool.close().await;
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_token_epoch_bump_increments_and_a_sign_in_leaves_updated_at_alone() {
    let (db, fixtures, pool) = start().await;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, fixtures.alpha.id).await.expect("begin");
    let before = UserRepository::find_by_id(&mut tx, fixtures.alpha.id, fixtures.alpha.owner)
        .await
        .expect("query")
        .expect("seeded owner");

    assert!(
        UserRepository::update_last_login_at(&mut tx, fixtures.alpha.id, fixtures.alpha.owner, now)
            .await
            .expect("update"),
        "a sign-in for an existing user must update exactly one row"
    );

    let after_login = UserRepository::find_by_id(&mut tx, fixtures.alpha.id, fixtures.alpha.owner)
        .await
        .expect("query")
        .expect("seeded owner");
    assert!(after_login.last_login_at.is_some());
    assert_eq!(
        after_login.updated_at, before.updated_at,
        "a sign-in bumped updated_at, invalidating every cached copy and breaking If-Match"
    );

    let epoch = UserRepository::bump_token_epoch(
        &mut tx,
        fixtures.alpha.id,
        fixtures.alpha.owner,
        Utc::now(),
    )
    .await
    .expect("bump")
    .expect("the user exists");
    assert_eq!(epoch, before.token_epoch + 1);

    let after_bump = UserRepository::find_by_id(&mut tx, fixtures.alpha.id, fixtures.alpha.owner)
        .await
        .expect("query")
        .expect("seeded owner");
    assert_eq!(after_bump.token_epoch, epoch);
    assert!(after_bump.updated_at > before.updated_at, "a security change must be visible");

    // Cross-tenant: beta cannot revoke alpha's tokens, and gets absence rather than an error.
    assert!(
        UserRepository::bump_token_epoch(
            &mut tx,
            fixtures.beta.id,
            fixtures.alpha.owner,
            Utc::now()
        )
        .await
        .expect("query")
        .is_none(),
        "a bump crossed a tenant boundary"
    );
    tx.commit().await.expect("commit");

    pool.close().await;
    drop(db);
}

/// The group-closure test: nesting, a cycle, and depth truncation, on real rows.
///
/// The unit tests in `group_repo` pin the walk's behaviour without a database; this pins the
/// *queries* that feed it — the `member_type` discriminator, the soft-delete filter and the tenant
/// predicate — which no in-memory test can reach.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_group_closure_follows_nesting_survives_a_cycle_and_truncates_at_the_limit() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("administrative connection");

    // --- a cycle: cycle-a ∈ cycle-b ∈ cycle-a, with `member` inside cycle-a ------------------
    let cycle_a = GroupId::new_v7();
    let cycle_b = GroupId::new_v7();
    insert_group(&mut admin, alpha, cycle_a, "cycle-a").await;
    insert_group(&mut admin, alpha, cycle_b, "cycle-b").await;
    insert_edge(&mut admin, alpha, cycle_b, cycle_a.as_uuid(), "GROUP").await;
    insert_edge(&mut admin, alpha, cycle_a, cycle_b.as_uuid(), "GROUP").await;
    insert_edge(&mut admin, alpha, cycle_a, fixtures.alpha.member.as_uuid(), "USER").await;

    // --- a chain twelve deep, with `viewer` at the bottom ------------------------------------
    let chain: Vec<GroupId> = (0..12).map(|_| GroupId::new_v7()).collect();
    for (index, group) in chain.iter().enumerate() {
        insert_group(&mut admin, alpha, *group, &format!("deep-{index:02}")).await;
    }
    for pair in chain.windows(2) {
        // pair[0] is a member of pair[1] — so the walk climbs from index 0 upward.
        insert_edge(&mut admin, alpha, pair[1], pair[0].as_uuid(), "GROUP").await;
    }
    insert_edge(&mut admin, alpha, chain[0], fixtures.alpha.viewer.as_uuid(), "USER").await;

    // --- a group the same user is in, but which has been soft-deleted ------------------------
    let retired = GroupId::new_v7();
    insert_group(&mut admin, alpha, retired, "retired").await;
    insert_edge(&mut admin, alpha, retired, fixtures.alpha.owner.as_uuid(), "USER").await;
    sqlx::query("UPDATE groups SET deleted_at = $2 WHERE id = $1")
        .bind(sql(retired))
        .bind(Utc::now())
        .execute(&mut admin)
        .await
        .expect("soft-delete the group");

    // --- a membership row of the wrong kind, pointing at the same id -------------------------
    // A `GUEST` edge with the user's id in it. If a query forgot `member_type`, this row would put
    // an extra group in the closure — a grant nobody made.
    let guest_only = GroupId::new_v7();
    insert_group(&mut admin, alpha, guest_only, "guests-only").await;
    insert_edge(&mut admin, alpha, guest_only, fixtures.alpha.member.as_uuid(), "GUEST").await;

    drop(admin);

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");

    // Nesting, from the seeded fixtures: owner ∈ finance-leads ∈ finance.
    let owner = GroupRepository::transitive_groups(
        &mut tx,
        alpha,
        fixtures.alpha.owner,
        NestingLimit::DEFAULT,
    )
    .await
    .expect("resolve");
    assert!(owner.contains(fixtures.alpha.finance_leads), "the direct group is missing");
    assert!(owner.contains(fixtures.alpha.finance), "nesting was not followed");
    assert!(!owner.contains(retired), "a soft-deleted group still confers membership");
    assert!(!owner.is_truncated());
    assert_eq!(owner.len(), 2);

    // The direct listing sees one edge only, and also excludes the deleted group.
    let direct =
        GroupRepository::direct_groups(&mut tx, alpha, fixtures.alpha.owner).await.expect("query");
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].id, fixtures.alpha.finance_leads);

    // A cycle terminates and yields both groups exactly once — and nothing reached through the
    // `GUEST` edge.
    let cyclic = GroupRepository::transitive_groups(
        &mut tx,
        alpha,
        fixtures.alpha.member,
        NestingLimit::DEFAULT,
    )
    .await
    .expect("resolve");
    assert!(cyclic.contains(cycle_a) && cyclic.contains(cycle_b));
    assert!(cyclic.contains(fixtures.alpha.engineering), "the seeded direct group is missing");
    assert!(!cyclic.contains(guest_only), "a GUEST membership row was followed for a USER");
    assert!(!cyclic.is_truncated(), "a cycle is a complete closure, not a truncated one");
    assert_eq!(cyclic.len(), 3);

    // Twelve levels, limit eight: eight groups, and the walk says it stopped short.
    let deep = GroupRepository::transitive_groups(
        &mut tx,
        alpha,
        fixtures.alpha.viewer,
        NestingLimit::DEFAULT,
    )
    .await
    .expect("resolve");
    assert!(deep.is_truncated(), "the depth limit was not reported");
    assert_eq!(deep.len(), 8);
    assert_eq!(deep.depth_reached(), 8);
    for group in &chain[..8] {
        assert!(deep.contains(*group));
    }
    for group in &chain[8..] {
        assert!(!deep.contains(*group), "a group past the limit is in the closure");
    }

    tx.commit().await.expect("commit");

    // The same user id, resolved inside beta's context: no groups, not beta's mirror of them.
    let mut tx = TenantScoped::begin(&pool, fixtures.beta.id).await.expect("begin");
    let crossed = GroupRepository::transitive_groups(
        &mut tx,
        fixtures.beta.id,
        fixtures.alpha.owner,
        NestingLimit::DEFAULT,
    )
    .await
    .expect("resolve");
    assert!(crossed.is_empty(), "alpha's membership was visible from beta: {crossed:?}");

    // Beta's own owner resolves beta's groups — proving the emptiness above is isolation and not a
    // broken query.
    let mirrored = GroupRepository::transitive_groups(
        &mut tx,
        fixtures.beta.id,
        fixtures.beta.owner,
        NestingLimit::DEFAULT,
    )
    .await
    .expect("resolve");
    assert!(mirrored.contains(fixtures.beta.finance_leads));
    assert!(!mirrored.contains(fixtures.alpha.finance_leads));
    tx.commit().await.expect("commit");

    pool.close().await;
    drop(db);
}

/// Runs without a database on purpose — it is about the other tests, not about the repositories.
#[test]
fn the_ignore_reason_names_the_harness() {
    // Trivial, and deliberately here: `plans/M1-CONTENT-CORE.md §5` forbids an `#[ignore]` without
    // a written reason naming where the test does run. This asserts the string every test in this
    // file carries is the one the harness answers to.
    assert!(NEEDS_DB.contains("--include-ignored"));
    assert!(NEEDS_DB.contains("PostgreSQL"));
}
