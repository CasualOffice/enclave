//! `ENC-584` — the per-tenant stored-byte quota, against a real PostgreSQL.
//!
//! `plans/M4-GOVERNANCE.md`'s exit criterion is *"quota exhaustion blocks writes while reads,
//! deletes and exports keep working"*, and `docs/12-TESTING.md §1.2` says exactly why the second
//! half of that sentence is dangerous to assert: **an assertion about an absence passes for free.**
//! "The delete was not blocked", "the read was not blocked", "the export was not blocked" are all
//! true of a quota that never engages at all, of a quota row that was never written, and of a
//! `charge_storage` that returns `Admitted` unconditionally.
//!
//! So every test here that asserts something was *not* refused proves, **under the identical
//! fixture and in the same test**, that something else *was* — and the refusal is asserted first.
//! A test that cannot show the quota engaging is not evidence about the quota.
//!
//! The same rule applies to the two structural properties:
//!
//! * the race D31 exists to prevent has a **positive control** — the check-then-write shape,
//!   written out in this file and run under the identical contention, which must over-issue. A
//!   concurrency test whose harness cannot produce contention passes against a naive
//!   implementation, which is exactly what happened to `docs/12 §4.4` H3 (`crates/testing`'s
//!   `pool_with_connections` carries that history);
//! * the reconciliation window has a positive control too — the same charge, run against a
//!   reconciler that *does* take a row lock, must time out. Without it, "the charge completed
//!   quickly" is a statement about an unloaded test machine.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::sync::Arc;

use enclave_core::TenantId;
use enclave_db::quota::{
    charge_storage, configure_storage_quota, correct_storage, observe_storage, reconcile_storage,
    release_storage, storage_quota, Charged, Enforcement, Released,
};
use enclave_db::{ConnectionUrl, DbConfig, DbPool};
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

/// A migrated, seeded database and an application-role pool over it.
///
/// The pool is the *application* role, never the harness's superuser: a superuser bypasses
/// row-level security entirely, and a cross-tenant assertion run over one proves nothing
/// (`crates/testing/src/lib.rs`, PR #22).
async fn harness(connections: u32) -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(connections).await.expect("application pool");
    (db, fixtures, pool)
}

/// A pool that also holds the cross-tenant credential, for [`reconcile_storage`].
///
/// The harness gives one superuser, which bypasses row-level security exactly as
/// `enclave_platform` does — the same stand-in `crates/db/src/tenants.rs` uses, and faithful for
/// the same reason.
async fn platform_pool(db: &TestDb) -> DbPool {
    let url = ConnectionUrl::new(db.url().to_owned());
    let config = DbConfig::new(url.clone())
        .with_application_role("enclave_app")
        .with_platform_url(url)
        .with_max_connections(4);
    DbPool::connect(&config).await.expect("platform pool")
}

/// Writes a quota row for `tenant` and returns nothing but the fact that it exists.
async fn set_quota(pool: &DbPool, tenant: TenantId, limit: u64, mode: Enforcement) {
    let mut tx = pool.begin(tenant).await.expect("begin");
    configure_storage_quota(&mut tx, limit, 80, mode).await.expect("configure the quota");
    tx.commit().await.expect("commit");
}

/// `used_bytes` as the row currently holds it, read over the application role.
async fn used(pool: &DbPool, tenant: TenantId) -> i64 {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let quota = storage_quota(&mut tx).await.expect("read").expect("a quota row");
    tx.commit().await.expect("commit");
    quota.used_bytes
}

/// Charges in its own transaction and commits. The shape every writer uses.
async fn charge(pool: &DbPool, tenant: TenantId, bytes: u64) -> Charged {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let outcome = charge_storage(&mut tx, bytes).await.expect("charge");
    tx.commit().await.expect("commit");
    outcome
}

/// A workspace → library → file spine plus `count` versions of `size` bytes each.
///
/// Written over the harness's administrative connection because it is *setup*, not subject
/// (`crates/testing/src/content.rs`), and spelled out here rather than through
/// `enclave_testing::content::Spine` for one reason: that helper takes a `chrono` timestamp, and
/// `chrono` is not a dependency of this crate. Adding one so a fixture could name an instant would
/// put a dependency edge in `Cargo.lock` to serve a test.
///
/// Every column is spelled as `migrations/0005` and `0006` define it, so a schema that drifts from
/// them fails here.
async fn seed_versions(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: Uuid,
    count: usize,
    size: i64,
    status: &str,
) -> Uuid {
    let (workspace, library, file) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

    sqlx::query(
        "INSERT INTO workspaces
           (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
         VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, now(), now())",
    )
    .bind(workspace)
    .bind(tenant.as_uuid())
    .bind(format!("ws-{workspace}"))
    .bind(owner)
    .execute(&mut *conn)
    .await
    .expect("insert a workspace");

    sqlx::query(
        "INSERT INTO libraries
           (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
            external_sharing, created_at, updated_at)
         VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', now(), now())",
    )
    .bind(library)
    .bind(tenant.as_uuid())
    .bind(workspace)
    .bind(format!("lib-{library}"))
    .execute(&mut *conn)
    .await
    .expect("insert a library");

    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, inherit_permissions, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, NULL, 'FILE', $5, $5, 'application/octet-stream', TRUE,
                 $6, $6, now(), now())",
    )
    .bind(file)
    .bind(tenant.as_uuid())
    .bind(workspace)
    .bind(library)
    .bind(file.to_string())
    .bind(owner)
    .execute(&mut *conn)
    .await
    .expect("insert a file");

    for index in 0..count {
        sqlx::query(
            "INSERT INTO file_versions
               (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes,
                checksum_sha256, mime_type, major, minor, status, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'sha256:test', 'application/octet-stream',
                     $7, 0, $8, $9, now())",
        )
        .bind(Uuid::new_v4())
        .bind(tenant.as_uuid())
        .bind(file)
        .bind(format!("obj/{}", Uuid::new_v4()))
        .bind(Uuid::new_v4())
        .bind(size)
        .bind(i32::try_from(index).expect("a small fixture") + 1)
        .bind(status)
        .bind(owner)
        .execute(&mut *conn)
        .await
        .expect("insert a file version");
    }

    file
}

// ---------------------------------------------------------------------------
// The exit criterion
// ---------------------------------------------------------------------------

/// `plans/M4-GOVERNANCE.md`'s third exit criterion, whole, in one fixture.
///
/// The order is the point. The refusal is asserted **first**, so that everything after it is a
/// statement about a quota that is demonstrably exhausted rather than about one that was never
/// configured. `docs/12 §1.2`: without that, "the delete was not blocked" holds trivially against
/// code that does nothing.
///
/// The last leg closes the loop the other way: after the release, a charge that was refused two
/// statements ago is **admitted**. That is what distinguishes "the release worked" from "the quota
/// stopped engaging".
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn quota_exhaustion_blocks_writes_while_reads_deletes_and_exports_keep_working() {
    let (db, fixtures, pool) = harness(4).await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");

    // Real content under the quota, so the "reads and exports still work" legs read something.
    let file =
        seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 2, 512, "AVAILABLE").await;

    set_quota(&pool, alpha, 1024, Enforcement::Block).await;
    assert!(
        matches!(charge(&pool, alpha, 1024).await, Charged::Admitted(_)),
        "a charge that exactly fills the quota must be admitted"
    );

    // 1. Exhausted. This is the positive control for every assertion below it.
    let refusal = charge(&pool, alpha, 1).await;
    let refused = refusal.refused().expect("one more byte must be refused");
    assert_eq!(refused.quota.used_bytes, 1024);
    assert_eq!(refused.quota.headroom_bytes(), 0);
    assert_eq!(used(&pool, alpha).await, 1024, "a refused charge must move nothing");

    // 2. Reads keep working — the quota itself is readable…
    let mut tx = pool.begin(alpha).await.expect("begin");
    let quota = storage_quota(&mut tx).await.expect("read the quota").expect("a quota row");
    assert_eq!(quota.used_bytes, quota.limit_bytes);

    // …and so is the content it is exhausted by. Read in the same transaction, under the same
    // exhausted row, so this cannot be a different fixture.
    let name: String = sqlx::query("SELECT name FROM files WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(file)
        .fetch_one(&mut *tx)
        .await
        .expect("a read path must not consult the quota")
        .get("name");
    assert_eq!(name, file.to_string());

    // 3. Exports keep working. An export is a read of the version rows and their bytes; the rows
    //    are what this layer can speak for, and nothing here may refuse them.
    let exportable: i64 = sqlx::query(
        "SELECT count(*) AS n FROM file_versions WHERE tenant_id = $1 AND file_id = $2",
    )
    .bind(alpha.as_uuid())
    .bind(file)
    .fetch_one(&mut *tx)
    .await
    .expect("an export path must not consult the quota")
    .get("n");
    assert_eq!(exportable, 2, "an exhausted tenant must still be able to enumerate what it holds");
    tx.commit().await.expect("commit");

    // 4. Deletes keep working, and are what gets the tenant back under.
    let mut tx = pool.begin(alpha).await.expect("begin");
    let released = release_storage(&mut tx, 512).await.expect("a delete must never be refused");
    sqlx::query("DELETE FROM file_versions WHERE tenant_id = $1 AND file_id = $2 AND major = 1")
        .bind(alpha.as_uuid())
        .bind(file)
        .execute(&mut *tx)
        .await
        .expect("a delete must not be blocked by an exhausted quota");
    tx.commit().await.expect("commit");

    let Released::Recorded(after_release) = released else {
        panic!("the tenant has a quota row, so the release must be recorded against it")
    };
    assert_eq!(after_release.used_bytes, 512);

    // 5. And the loop closes: the charge that was refused in step 1 now succeeds. Without this,
    //    every assertion above is satisfied by a quota that quietly stopped engaging.
    assert!(
        matches!(charge(&pool, alpha, 1).await, Charged::Admitted(_)),
        "after a delete freed room, the previously-refused charge must be admitted"
    );

    pool.close().await;
    drop(db);
}

/// Exhausting one tenant must not touch another's, and neither may see the other's row.
///
/// `tenant-beta` mirrors `tenant-alpha` with the same fixture shape (`docs/12 §3`), so this cannot
/// pass because the other tenant's row was called something else.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn exhausting_one_tenant_leaves_the_other_untouched_and_invisible() {
    let (db, fixtures, pool) = harness(4).await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    set_quota(&pool, alpha, 1024, Enforcement::Block).await;
    set_quota(&pool, beta, 1024, Enforcement::Block).await;

    assert!(matches!(charge(&pool, alpha, 1024).await, Charged::Admitted(_)));
    assert!(charge(&pool, alpha, 1).await.refused().is_some(), "alpha must be exhausted");

    // Beta is untouched by alpha's exhaustion — the positive control that makes the RLS leg below
    // mean something, because a quota that refused everyone would also pass "alpha is exhausted".
    assert!(
        matches!(charge(&pool, beta, 1024).await, Charged::Admitted(_)),
        "beta's quota is its own; alpha's exhaustion must not refuse it"
    );

    // Neither tenant's transaction can see the other's row at all.
    let mut tx = pool.begin(beta).await.expect("begin");
    let visible: i64 = sqlx::query("SELECT count(*) AS n FROM storage_quotas WHERE tenant_id = $1")
        .bind(alpha.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("query")
        .get("n");
    assert_eq!(visible, 0, "row-level security must hide alpha's quota from beta");

    // The positive control for that zero: the identical query, for beta's own row, returns it.
    let own: i64 = sqlx::query("SELECT count(*) AS n FROM storage_quotas WHERE tenant_id = $1")
        .bind(beta.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("query")
        .get("n");
    assert_eq!(own, 1, "the same query must find beta's own row, or the zero above proves nothing");
    tx.commit().await.expect("commit");

    // And alpha's counter never moved while beta filled its own.
    assert_eq!(used(&pool, alpha).await, 1024);

    pool.close().await;
    drop(db);
}

// ---------------------------------------------------------------------------
// D31 — the race the single statement exists to prevent
// ---------------------------------------------------------------------------

/// Sixteen concurrent charges against a quota with room for exactly one.
///
/// A pool of sixteen, deliberately: `TestDb::pool` caps at two, and on two connections this test is
/// a sequential test wearing `tokio::spawn` — which is how `docs/12 §4.4` H3 passed against a
/// deliberately naive implementation for a milestone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn sixteen_concurrent_charges_against_room_for_one_admit_exactly_one() {
    const CONTENDERS: u32 = 16;
    const CHARGE: u64 = 1000;

    let (db, fixtures, pool) = harness(CONTENDERS).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, CHARGE, Enforcement::Block).await;

    // Every contender reads its figure before any of them writes, which is the arrangement a
    // check-then-write cannot survive and this one must.
    let gate = Arc::new(tokio::sync::Barrier::new(CONTENDERS as usize));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..CONTENDERS {
        let (pool, gate) = (pool.clone(), Arc::clone(&gate));
        tasks.spawn(async move {
            let mut tx = pool.begin(alpha).await.expect("begin");
            gate.wait().await;
            let outcome = charge_storage(&mut tx, CHARGE).await.expect("charge");
            tx.commit().await.expect("commit");
            outcome
        });
    }

    let mut admitted = 0_usize;
    let mut refused = 0_usize;
    while let Some(result) = tasks.join_next().await {
        match result.expect("no task may panic") {
            Charged::Admitted(_) => admitted += 1,
            Charged::Refused(_) => refused += 1,
            Charged::Unmetered => panic!("the tenant has a quota row"),
        }
    }

    assert_eq!(admitted, 1, "exactly one charge fits; {admitted} were admitted");
    assert_eq!(refused, CONTENDERS as usize - 1);
    assert_eq!(
        used(&pool, alpha).await,
        i64::try_from(CHARGE).expect("fits"),
        "the counter must end at the limit, never above it"
    );

    pool.close().await;
    drop(db);
}

/// The positive control for the test above: the check-then-write shape, under identical contention.
///
/// `docs/12 §1.2` — a concurrency test that has never been shown to *catch* anything is a claim
/// about the implementation and about the harness at once, and it is the harness that has failed
/// before. This runs the wrong shape (`plans/M4-GOVERNANCE.md` D31's "a check-then-write is a race
/// whose losing side is an over-issued resource") on the same pool, the same barrier and the same
/// row, and requires it to over-issue.
///
/// If this test ever starts *passing the quota* — one admission — the harness has stopped producing
/// contention and the test above is proving nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_check_then_write_shape_over_issues_under_the_identical_contention() {
    const CONTENDERS: u32 = 16;
    const CHARGE: i64 = 1000;

    let (db, fixtures, pool) = harness(CONTENDERS).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, CHARGE as u64, Enforcement::Block).await;

    let gate = Arc::new(tokio::sync::Barrier::new(CONTENDERS as usize));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..CONTENDERS {
        let (pool, gate) = (pool.clone(), Arc::clone(&gate));
        tasks.spawn(async move {
            let mut tx = pool.begin(alpha).await.expect("begin");

            // Read…
            let row = sqlx::query(
                "SELECT used_bytes, limit_bytes FROM storage_quotas WHERE tenant_id = $1",
            )
            .bind(alpha.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("read the counter");
            let used: i64 = row.get("used_bytes");
            let limit: i64 = row.get("limit_bytes");

            // …hold every contender here until all of them have read…
            gate.wait().await;

            // …decide in Rust…
            if used + CHARGE > limit {
                tx.commit().await.expect("commit");
                return false;
            }

            // …and write what this task believed. The absolute assignment is the defect: it is what
            // "increment the counter after checking it" looks like once the check has gone stale.
            sqlx::query("UPDATE storage_quotas SET used_bytes = $2 WHERE tenant_id = $1")
                .bind(alpha.as_uuid())
                .bind(used + CHARGE)
                .execute(&mut *tx)
                .await
                .expect("write the counter");
            tx.commit().await.expect("commit");
            true
        });
    }

    let mut admitted = 0_usize;
    while let Some(result) = tasks.join_next().await {
        if result.expect("no task may panic") {
            admitted += 1;
        }
    }

    assert!(
        admitted > 1,
        "the check-then-write shape admitted {admitted} of {CONTENDERS} charges against room for \
         one. Exactly one means the harness is not producing contention — a pool too small, a \
         barrier that is not holding — and the test above is therefore proving nothing."
    );

    pool.close().await;
    drop(db);
}

/// The `CHECK` backstop: a charging statement that lost its bound aborts the transaction.
///
/// `plans/M4-GOVERNANCE.md` D31 asks the constraint to turn *a mistake in the statement* into a
/// failed transaction rather than an exceeded quota, so the mistake is what is run here — the
/// charging `UPDATE` with its `WHERE` clause stripped down to the tenant, which is what a dropped
/// predicate looks like.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_charge_that_escaped_its_where_clause_is_refused_by_the_check_constraint() {
    let (db, fixtures, pool) = harness(2).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, 1024, Enforcement::Block).await;

    // The control: the same statement, within the limit, succeeds. Without it a constraint that
    // rejected every update would satisfy the assertion below.
    let mut tx = pool.begin(alpha).await.expect("begin");
    sqlx::query("UPDATE storage_quotas SET used_bytes = used_bytes + $2 WHERE tenant_id = $1")
        .bind(alpha.as_uuid())
        .bind(1024_i64)
        .execute(&mut *tx)
        .await
        .expect("a charge inside the limit is an ordinary update");
    tx.commit().await.expect("commit");

    let mut tx = pool.begin(alpha).await.expect("begin");
    let error =
        sqlx::query("UPDATE storage_quotas SET used_bytes = used_bytes + $2 WHERE tenant_id = $1")
            .bind(alpha.as_uuid())
            .bind(1_i64)
            .execute(&mut *tx)
            .await
            .expect_err("a charge past the limit with no bound must be refused by the constraint");

    let db_error = error.as_database_error().expect("a server-side refusal");
    assert_eq!(db_error.code().as_deref(), Some("23514"), "expected a check-constraint violation");
    assert_eq!(db_error.constraint(), Some("storage_quotas_within_budget"));
    tx.rollback().await.expect("rollback");

    assert_eq!(used(&pool, alpha).await, 1024, "the failed transaction must have moved nothing");

    pool.close().await;
    drop(db);
}

// ---------------------------------------------------------------------------
// Notify before refusing
// ---------------------------------------------------------------------------

/// `plans/M4-GOVERNANCE.md §2`: quotas notify before they refuse.
///
/// Three properties in one fixture, and the third is the one that needs the first two to mean
/// anything: the crossing is announced **before** anything is refused, it is announced **once**,
/// and a release back under the soft limit re-arms it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_soft_limit_is_announced_once_and_before_the_first_refusal() {
    let (db, fixtures, pool) = harness(2).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, 1000, Enforcement::Block).await;

    // 79% — under the default soft limit of 80.
    let Charged::Admitted(first) = charge(&pool, alpha, 790).await else {
        panic!("790 of 1000 must be admitted")
    };
    assert!(!first.crossed_soft_limit, "79% must not announce anything");

    // 80% — the crossing, and still an admission. This is "notify **before** refuse": nothing has
    // been refused at this point and the announcement has already happened.
    let Charged::Admitted(second) = charge(&pool, alpha, 10).await else {
        panic!("800 of 1000 must be admitted")
    };
    assert!(second.crossed_soft_limit, "the charge that reaches 80% must announce the soft limit");

    // 90% — over the soft limit, but the crossing already happened; announcing again would mean one
    // notification per write for the rest of the tenant's life.
    let Charged::Admitted(third) = charge(&pool, alpha, 100).await else {
        panic!("900 of 1000 must be admitted")
    };
    assert!(!third.crossed_soft_limit, "the soft limit must be announced once, not once per write");
    assert!(third.quota.is_over_soft_limit());

    // Only now is anything refused, which is what makes the ordering above a fact rather than a
    // coincidence of the numbers chosen.
    assert!(charge(&pool, alpha, 101).await.refused().is_some(), "101 of a remaining 100");

    // Back under the soft limit, and the announcement re-arms — otherwise a tenant that freed space
    // and filled it again would cross in silence.
    let mut tx = pool.begin(alpha).await.expect("begin");
    release_storage(&mut tx, 500).await.expect("release");
    tx.commit().await.expect("commit");

    let Charged::Admitted(rearmed) = charge(&pool, alpha, 400).await else {
        panic!("800 of 1000 must be admitted")
    };
    assert!(rearmed.crossed_soft_limit, "crossing 80% a second time must announce again");

    pool.close().await;
    drop(db);
}

/// `MONITOR` and `WARN` count without refusing — the gradual rollout `§2` is built on.
///
/// The positive control is the third leg: the identical fixture under `BLOCK` refuses, so "nothing
/// was refused" above is a property of the mode rather than of a quota that never engages.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn monitor_and_warn_count_past_the_limit_and_block_does_not() {
    let (db, fixtures, pool) = harness(2).await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    set_quota(&pool, alpha, 1000, Enforcement::Monitor).await;
    let Charged::Admitted(monitored) = charge(&pool, alpha, 5000).await else {
        panic!("MONITOR must not refuse")
    };
    assert_eq!(monitored.quota.used_bytes, 5000, "MONITOR still counts");
    assert!(!monitored.crossed_soft_limit, "MONITOR announces nothing");

    // Moving to WARN acknowledges the overshoot in the same statement, which is the only way the
    // row can be written at all once it is over — see migrations/0018.
    set_quota(&pool, alpha, 1000, Enforcement::Warn).await;
    let Charged::Admitted(warned) = charge(&pool, alpha, 1).await else {
        panic!("WARN must not refuse")
    };
    assert_eq!(warned.quota.used_bytes, 5001);
    assert_eq!(warned.quota.overshoot_bytes, 4000, "the overshoot was acknowledged at 5000");

    // The control: the same numbers under BLOCK, in the mirror tenant.
    set_quota(&pool, beta, 1000, Enforcement::Block).await;
    assert!(
        charge(&pool, beta, 5000).await.refused().is_some(),
        "BLOCK must refuse what MONITOR and WARN admitted"
    );

    pool.close().await;
    drop(db);
}

/// A release for more than was ever charged saturates rather than aborting the delete.
///
/// The `CHECK (used_bytes >= 0)` would otherwise turn a quota-accounting bug into a failed
/// **delete**, which is D31's hostage situation reached by a different road.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_over_release_saturates_at_zero_rather_than_failing_the_delete() {
    let (db, fixtures, pool) = harness(2).await;
    let alpha = fixtures.alpha.id;
    set_quota(&pool, alpha, 1000, Enforcement::Block).await;
    assert!(matches!(charge(&pool, alpha, 100).await, Charged::Admitted(_)));

    let mut tx = pool.begin(alpha).await.expect("begin");
    let released = release_storage(&mut tx, 10_000).await.expect("a delete must never fail");
    tx.commit().await.expect("commit");

    let Released::Recorded(quota) = released else { panic!("the tenant has a quota row") };
    assert_eq!(quota.used_bytes, 0, "the counter saturates at zero");

    // And the tenant is not left in a broken state: the next charge behaves normally.
    assert!(matches!(charge(&pool, alpha, 1000).await, Charged::Admitted(_)));
    assert!(charge(&pool, alpha, 1).await.refused().is_some());

    pool.close().await;
    drop(db);
}

// ---------------------------------------------------------------------------
// Reconciliation, and the window it must not have
// ---------------------------------------------------------------------------

/// The relative correction preserves charges that commit while the job is running.
///
/// This is the assertion `plans/M4-GOVERNANCE.md §5`'s risk row asks for. The drift is measured,
/// **then** a charge commits, **then** the correction is applied — and the final figure must
/// include both. An absolute assignment would produce 6000 here rather than 6050, silently
/// discarding a real upload; the test names that number so a regression says which shape came back.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_charge_committed_during_reconciliation_survives_the_correction() {
    let (db, fixtures, pool) = harness(4).await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");

    // Six versions of 1000 bytes: the truth is 6000.
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 6, 1000, "AVAILABLE").await;
    set_quota(&pool, alpha, 100_000, Enforcement::Block).await;

    // The counter says 1000 — a write path that under-counted five uploads, which is exactly the
    // defect reconciliation exists to repair.
    assert!(matches!(charge(&pool, alpha, 1000).await, Charged::Admitted(_)));

    // 1. Observe. One statement, one snapshot.
    let mut read = pool.begin(alpha).await.expect("begin");
    let observation = observe_storage(&mut read).await.expect("observe").expect("a quota row");
    read.commit().await.expect("commit");
    assert_eq!(observation.recorded_bytes, 1000);
    assert_eq!(observation.measured_bytes, 6000);
    assert_eq!(observation.drift_bytes(), 5000, "the drift must be the whole under-count");

    // 2. A perfectly ordinary upload lands *after* the observation and *before* the correction.
    assert!(matches!(charge(&pool, alpha, 50).await, Charged::Admitted(_)));
    assert_eq!(used(&pool, alpha).await, 1050);

    // 3. Correct, with the observation taken before that upload existed.
    let mut write = pool.begin(alpha).await.expect("begin");
    let corrected =
        correct_storage(&mut write, observation).await.expect("correct").expect("a quota row");
    write.commit().await.expect("commit");

    assert_eq!(corrected.drift_bytes, 5000);
    assert_eq!(
        corrected.quota.used_bytes, 6050,
        "the correction must be relative: 6000 would mean the concurrent upload was erased, which \
         is the failure plans/M4-GOVERNANCE.md §5 names"
    );

    // A second pass finds nothing left to correct — the repair converged rather than oscillating.
    let mut read = pool.begin(alpha).await.expect("begin");
    let again = observe_storage(&mut read).await.expect("observe").expect("a quota row");
    read.commit().await.expect("commit");
    assert_eq!(
        again.drift_bytes(),
        -50,
        "the 50 charged after the snapshot is the remaining drift"
    );

    pool.close().await;
    drop(db);
}

/// The observation must not make a concurrent charge wait — the window itself.
///
/// The control is the second half, and it is what gives the first half teeth: the *same* charge,
/// against a reconciler that took `SELECT … FOR UPDATE` instead, must time out. Without it, "the
/// charge finished within five seconds" is a statement about the test machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_observation_holds_no_lock_a_charge_would_wait_on() {
    let (db, fixtures, pool) = harness(4).await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 4, 1000, "AVAILABLE").await;
    set_quota(&pool, alpha, 1_000_000, Enforcement::Block).await;

    // The shipped observation, held open for the whole of the charge below.
    let mut reconciler = pool.begin(alpha).await.expect("begin");
    let observation =
        observe_storage(&mut reconciler).await.expect("observe").expect("a quota row");
    assert_eq!(observation.measured_bytes, 4000);

    let charged = tokio::time::timeout(Duration::from_secs(5), charge(&pool, alpha, 100))
        .await
        .expect("a charge must not wait on the reconciliation's observation");
    assert!(matches!(charged, Charged::Admitted(_)));
    reconciler.commit().await.expect("commit");

    // The control: a reconciler that locked the row instead. The identical charge must now block,
    // which is the window this design exists to avoid — and the proof that the timeout above was
    // measuring something.
    let mut locker = pool.begin(alpha).await.expect("begin");
    sqlx::query("SELECT used_bytes FROM storage_quotas WHERE tenant_id = $1 FOR UPDATE")
        .bind(alpha.as_uuid())
        .fetch_one(&mut *locker)
        .await
        .expect("take the row lock");

    let blocked = tokio::time::timeout(Duration::from_secs(2), charge(&pool, alpha, 100)).await;
    assert!(
        blocked.is_err(),
        "a locking reconciler must block the charge; if it does not, the assertion above proves \
         nothing about the shipped one"
    );
    locker.rollback().await.expect("rollback");

    pool.close().await;
    drop(db);
}

/// What counts, and what does not.
///
/// `FAILED` versions assert that the bytes are *not* held, so they are the one status excluded.
/// Versions of a soft-deleted file still occupy storage and still count — otherwise the recycle bin
/// is an unmetered tier. Both directions are asserted, because a measurement that counted
/// everything and one that counted only `AVAILABLE` would each satisfy half of this.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_measurement_counts_stored_bytes_and_not_bytes_the_deployment_does_not_hold() {
    let (db, fixtures, pool) = harness(2).await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");

    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 1, 1000, "AVAILABLE").await;
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 1, 200, "QUARANTINED").await;
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 1, 30, "SCANNING").await;
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 1, 4, "FAILED").await;

    // A soft-deleted file, whose version still occupies bytes.
    let trashed =
        seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 1, 10_000, "AVAILABLE")
            .await;
    sqlx::query("UPDATE files SET deleted_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(trashed)
        .execute(&mut admin)
        .await
        .expect("soft-delete a file");

    set_quota(&pool, alpha, 1_000_000, Enforcement::Block).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    let observation = observe_storage(&mut tx).await.expect("observe").expect("a quota row");
    tx.commit().await.expect("commit");

    assert_eq!(
        observation.measured_bytes,
        1000 + 200 + 30 + 10_000,
        "QUARANTINED, SCANNING and trashed bytes are held and must count; FAILED asserts they are \
         not held and must not"
    );

    pool.close().await;
    drop(db);
}

/// The nightly pass, end to end, over both seeded tenants.
///
/// Asserts the two halves that make the report worth alerting on: a drifted tenant is counted and
/// corrected, and a tenant with **no quota row** is counted as unmetered rather than skipped in
/// silence — a deleted row is the shortest way to switch enforcement off, and this number is the
/// only thing that would notice.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_nightly_pass_corrects_drift_and_counts_the_tenants_it_cannot_meter() {
    let (db, fixtures, pool) = harness(4).await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let mut admin = db.connect().await.expect("admin connection");

    // Alpha: 3000 bytes stored, counter never incremented. Beta: no quota row at all.
    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 3, 1000, "AVAILABLE").await;
    set_quota(&pool, alpha, 1_000_000, Enforcement::Block).await;
    seed_versions(&mut admin, beta, fixtures.beta.owner.as_uuid(), 1, 7, "AVAILABLE").await;

    let platform = platform_pool(&db).await;
    let report = reconcile_storage(&platform).await.expect("reconcile");

    assert_eq!(report.examined, 2, "both seeded tenants are ACTIVE");
    assert_eq!(report.drifted, 1);
    assert_eq!(report.total_drift_bytes, 3000);
    assert_eq!(report.unmetered, 1, "beta has no quota row and must be counted, not skipped");
    assert_eq!(used(&pool, alpha).await, 3000, "alpha's counter now matches what it stores");

    // Idempotent: a second pass on an already-correct deployment finds nothing. Asserted because a
    // pass that re-applied its own correction would double every tenant every night.
    let second = reconcile_storage(&platform).await.expect("reconcile again");
    assert_eq!(second.drifted, 0);
    assert_eq!(second.total_drift_bytes, 0);
    assert_eq!(used(&pool, alpha).await, 3000);

    platform.close().await;
    pool.close().await;
    drop(db);
}

/// Reconciliation must be able to record a figure above the limit rather than failing on it.
///
/// The `CHECK` forbids `used > limit` under `BLOCK`, so without the acknowledgement in
/// `CORRECT_SQL` the nightly job would fail on exactly the tenants whose figure matters most — and
/// would fail on them again every night, leaving the number nobody can see as the true one.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn reconciliation_can_record_a_tenant_that_is_genuinely_over_its_limit() {
    let (db, fixtures, pool) = harness(2).await;
    let alpha = fixtures.alpha.id;
    let mut admin = db.connect().await.expect("admin connection");

    seed_versions(&mut admin, alpha, fixtures.alpha.owner.as_uuid(), 5, 1000, "AVAILABLE").await;
    set_quota(&pool, alpha, 1000, Enforcement::Block).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    let observation = observe_storage(&mut tx).await.expect("observe").expect("a quota row");
    tx.commit().await.expect("commit");
    assert_eq!(observation.drift_bytes(), 5000);

    let mut tx = pool.begin(alpha).await.expect("begin");
    let corrected =
        correct_storage(&mut tx, observation).await.expect("correct").expect("a quota row");
    tx.commit().await.expect("commit");

    assert_eq!(corrected.quota.used_bytes, 5000, "the truth must be recorded, limit or not");
    assert_eq!(corrected.quota.overshoot_bytes, 4000, "and the excess acknowledged");

    // The acknowledgement is not headroom: the tenant is still refused.
    assert!(
        charge(&pool, alpha, 1).await.refused().is_some(),
        "an acknowledged overshoot must not become room to write in"
    );

    // …and this is the one state in which a tenant is *strictly* over its limit, which is where the
    // "deletes are never quota-blocked" rule earns its keep — a tenant that cannot delete here can
    // never get back under. The exit-criterion test above cannot reach this state: under `BLOCK` no
    // charge can take a tenant past its limit, so it only ever sits exactly *at* it, and a release
    // guarded by `used_bytes <= limit_bytes` would pass there while failing every tenant that
    // reconciliation found genuinely over. Confirmed by breaking it both ways (`ENC-584`).
    let mut tx = pool.begin(alpha).await.expect("begin");
    let released = release_storage(&mut tx, 4500).await.expect("a delete must never be refused");
    tx.commit().await.expect("commit");
    let Released::Recorded(after) = released else {
        panic!("a tenant over its limit must still be able to delete its way back under")
    };
    assert_eq!(after.used_bytes, 500);
    assert_eq!(after.overshoot_bytes, 0, "coming back under must retire the acknowledgement");
    assert!(
        matches!(charge(&pool, alpha, 500).await, Charged::Admitted(_)),
        "and the room the delete freed must be usable"
    );

    pool.close().await;
    drop(db);
}
