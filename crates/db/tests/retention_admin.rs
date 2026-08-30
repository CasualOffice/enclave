//! The retention **write** path — the half `ENC-940` left to `psql` (`ENC-943`).
//!
//! `crates/db/tests/retention.rs` proves which policy governs a file. This proves an administrator
//! can put one there, apply it, and take it away again, and that the three ways that could go
//! quietly wrong do not.
//!
//! # What "quietly wrong" means for a write path, and why each test has a control
//!
//! `docs/12-TESTING.md §1.2`: an assertion about an absence passes for free. Every negative below
//! therefore runs beside a positive **in the same test and against the same fixture**:
//!
//! * *"the duplicate assignment was refused"* is true of an `assign_policy` that refuses
//!   everything, so the first call must be shown to succeed.
//! * *"the withdrawn assignment no longer governs"* is true of a `governing_policy` that finds
//!   nothing ever, so the same file must be shown to be governed before the withdrawal.
//! * *"another tenant's policy could not be applied"* is true of an `assign_policy` that is simply
//!   broken, so the identical call must succeed for this tenant's own policy.
//!
//! # Row-level security is off for the cross-tenant test, deliberately
//!
//! The same reasoning as `retention.rs`, and it matters more here. The composite foreign key
//! `(tenant_id, policy_id)` is what stops one tenant's policy being applied to another's content,
//! and **PostgreSQL runs referential-integrity checks with row security deliberately not enforced**
//! (`docs/04 §3.3`). So a test of that key under RLS would be measuring RLS. It runs over the
//! harness's superuser connection, where the key is the only thing left holding.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{TenantId, UserId};
use enclave_db::retention::{
    assign_policy, governing_policy, insert_policy, list_assignments, list_policies,
    withdraw_assignment, NewPolicy, PgInterval, RetentionAction, RetentionBasis, RetentionPolicyId,
    RetentionScopeType,
};
use enclave_db::DbPool;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

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
    let s = Spine::new(tenant);
    s.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    s
}

/// A seven-year `KEEP`, the shape an administrator writes most often.
fn seven_years(name: &str) -> NewPolicy {
    NewPolicy {
        id: RetentionPolicyId::new_v7(),
        name: name.to_owned(),
        action: RetentionAction::Keep,
        // Days, never a microsecond count. `migrations/0031`'s column comment is the argument:
        // `timestamptz + INTERVAL '2555 days'` is calendar arithmetic and a microsecond total is
        // not, and the direction of that error is *earlier* — a document destroyed a day before it
        // was permitted to be.
        duration: Some(PgInterval { months: 0, days: 2555, microseconds: 0 }),
        basis: RetentionBasis::Created,
        event_key: None,
        is_record: false,
        allow_user_delete: false,
    }
}

/// A policy written through the crate's own writer is the policy the reader returns.
///
/// The trivial-looking half is the one that would break silently: `insert_policy` binds nine
/// columns positionally, and two adjacent booleans — `is_record` and `allow_user_delete` — are
/// exactly the pair a transposition swaps with no type error to stop it.
///
/// **The two must therefore differ in the fixture, and the first draft of this test got that
/// wrong.** It wrote both as `false`, asserted both were `false`, and passed against a writer with
/// the binds transposed — because swapping two identical values changes nothing. It was a test
/// whose doc comment claimed a guarantee its assertions could not give, which is `docs/12 §1.2`'s
/// warning arriving from the other direction: not an absence that passes for free, but a *presence*
/// that is indistinguishable from its own negation. Caught by running the mutation rather than by
/// reasoning about it.
///
/// So the policy below is a `KEEP` that declares records and forbids user deletion —
/// `retention_policies_record_flag` is one-directional and permits exactly that — and transposing
/// the two binds in `INSERT_POLICY_SQL` now turns this red on both assertions.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_written_policy_reads_back_with_every_field_it_was_given() {
    let (_db, fx, pool) = harness().await;
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");

    let policy = NewPolicy { is_record: true, ..seven_years("Contracts") };
    insert_policy(&mut tx, &policy).await.expect("write the policy");
    let listed = list_policies(&mut tx).await.expect("read it back");

    let found = listed.iter().find(|p| p.id == policy.id).expect("the policy just written");
    assert_eq!(found.name, "Contracts");
    assert_eq!(found.action, RetentionAction::Keep);
    assert_eq!(found.basis, RetentionBasis::Created);
    assert_eq!(found.duration.as_ref().map(|d| d.days), Some(2555), "the duration is in days");
    assert!(
        found.is_record,
        "is_record was written true and read back false; the two boolean binds are transposed"
    );
    assert!(
        !found.allow_user_delete,
        "allow_user_delete was written false and read back true; the two boolean binds are \
         transposed, and every policy written through this surface now permits the deletion its \
         author created it to prevent"
    );
}

/// Applying the same policy to the same scope twice reports the second as a no-op.
///
/// The control is the first call: `assign_policy` returning `false` for everything would satisfy
/// the negative alone. The failure this guards is a double-submitted form reading as two changes —
/// an administrator believing they applied a control twice when the second attempt did nothing, and
/// (worse) an implementation that raised a constraint violation the handler rendered as a `500`.
///
/// Deleting `ON CONFLICT … DO NOTHING` from `INSERT_ASSIGNMENT_SQL` turns this red with a unique
/// violation rather than a `false`.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn applying_a_policy_to_the_same_scope_twice_changes_nothing_the_second_time() {
    let (_db, fx, pool) = harness().await;
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let spine = spine(&mut tx, fx.alpha.id, fx.alpha.owner).await;

    let policy = seven_years("Contracts");
    insert_policy(&mut tx, &policy).await.expect("write the policy");

    let first = assign_policy(
        &mut tx,
        policy.id,
        RetentionScopeType::Workspace,
        Some(spine.workspace.as_uuid()),
    )
    .await
    .expect("first assignment");
    let second = assign_policy(
        &mut tx,
        policy.id,
        RetentionScopeType::Workspace,
        Some(spine.workspace.as_uuid()),
    )
    .await
    .expect("second assignment");

    assert!(first, "the first assignment must apply, or the negative below proves nothing");
    assert!(!second, "the second must report that it changed nothing");
    let live = list_assignments(&mut tx).await.expect("list");
    assert_eq!(live.len(), 1, "one row, not two: {live:?}");
}

/// A `TENANT`-scoped assignment is the one duplicate the unique index would have missed.
///
/// `scope_id` is NULL for these rows, and NULLs are distinct in a unique constraint — so a
/// conflict target written as the plain column tuple rather than as the index's `COALESCE`
/// expression compiles, runs, and silently permits two identical tenant-wide assignments. That is
/// the broadest scope in the vocabulary and the one whose duplication is least visible.
///
/// Rewriting `ON CONFLICT (…, COALESCE(scope_id, …))` as `ON CONFLICT (…, scope_id)` turns this
/// red — and turns nothing else in this file red, which is why it is its own test.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_tenant_wide_assignment_cannot_be_made_twice_even_though_its_scope_id_is_null() {
    let (_db, fx, pool) = harness().await;
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");

    let policy = seven_years("Everything");
    insert_policy(&mut tx, &policy).await.expect("write the policy");

    let first = assign_policy(&mut tx, policy.id, RetentionScopeType::Tenant, None)
        .await
        .expect("first tenant-wide assignment");
    let second = assign_policy(&mut tx, policy.id, RetentionScopeType::Tenant, None)
        .await
        .expect("second tenant-wide assignment");

    assert!(first, "the first must apply");
    assert!(
        !second,
        "a second tenant-wide assignment of the same policy was accepted; the unique index folds \
         a NULL scope_id with COALESCE and the ON CONFLICT target must fold it the same way"
    );
}

/// Withdrawal stops a policy governing, and the file was governed before it.
///
/// This is the round trip the admin surface exists to make possible, asserted where it is decided
/// rather than at the HTTP edge. The control is the first `governing_policy` call: without it,
/// *"the withdrawn policy does not govern"* is satisfied by a join that never matched.
///
/// Deleting `AND (a.expires_at IS NULL OR a.expires_at > now())` from `GOVERNING_SQL` turns this
/// red — and that predicate is the only thing that makes withdrawal possible at all, because
/// `migrations/0031` grants no `DELETE`.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn withdrawing_an_assignment_stops_it_governing_a_file_it_governed_a_moment_ago() {
    let (_db, fx, pool) = harness().await;
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");
    let spine = spine(&mut tx, fx.alpha.id, fx.alpha.owner).await;

    let policy = seven_years("Contracts");
    insert_policy(&mut tx, &policy).await.expect("write the policy");
    assert!(
        assign_policy(
            &mut tx,
            policy.id,
            RetentionScopeType::Library,
            Some(spine.library.as_uuid())
        )
        .await
        .expect("assign"),
        "setup: the assignment must apply"
    );

    let before = governing_policy(&mut tx, spine.file).await.expect("read before");
    assert!(
        before.is_some(),
        "the file must be governed before the withdrawal, or the assertion after it is vacuous"
    );

    // Withdrawal is committed in its own transaction: `retention_assignments_expiry_after_
    // application` refuses `expires_at = applied_at`, and inside one transaction `now()` is frozen
    // at the statement's start. That constraint is not an obstacle to work around — an assignment
    // created and withdrawn with no time in between never applied to anything, and a retention
    // control that can be made to leave no trace of having existed is what the table forbids.
    tx.commit().await.expect("commit the assignment");
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin the withdrawal");

    let withdrawn = withdraw_assignment(
        &mut tx,
        policy.id,
        RetentionScopeType::Library,
        Some(spine.library.as_uuid()),
    )
    .await
    .expect("withdraw");
    assert!(withdrawn, "a live assignment must report that it was withdrawn");

    let again = withdraw_assignment(
        &mut tx,
        policy.id,
        RetentionScopeType::Library,
        Some(spine.library.as_uuid()),
    )
    .await
    .expect("withdraw again");
    assert!(!again, "withdrawing an already-withdrawn assignment must report that it did nothing");

    let after = governing_policy(&mut tx, spine.file).await.expect("read after");
    assert!(after.is_none(), "the withdrawn policy still governs the file: {after:?}");

    // The row survives. This is the property `migrations/0031` withholds `DELETE` for: the record
    // that a control once applied is itself part of the control.
    let rows = list_assignments(&mut tx).await.expect("list");
    assert_eq!(rows.len(), 1, "withdrawal must leave the row in place: {rows:?}");
    assert!(rows[0].expires_at.is_some(), "the withdrawn row must carry an expiry");
}

/// One tenant cannot apply another tenant's policy to its own content.
///
/// Runs over the **superuser** connection, where row-level security is not enforced — because that
/// is the condition PostgreSQL evaluates the foreign key under anyway (`docs/04 §3.3`), so it is
/// the only condition in which this test measures the key rather than RLS.
///
/// The control is in the same test: the identical call with alpha's *own* policy must succeed.
/// Without it, this passes against an `assign_policy` that has simply stopped working.
///
/// Rewriting `retention_assignments_policy_fkey` as a single-column `REFERENCES retention_policies
/// (id)` in `migrations/0031` turns this red — and a cross-tenant retention assignment is one
/// tenant governing another tenant's deletion path.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn another_tenants_policy_cannot_be_applied_to_this_tenants_content() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("superuser connection");
    let spine = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    // Beta's policy, written directly: this is setup for a question about alpha.
    let beta_policy = RetentionPolicyId::new_v7();
    sqlx::query(
        "INSERT INTO retention_policies
           (tenant_id, id, name, action, basis, allow_user_delete)
         VALUES ($1, $2, 'Beta keeps everything', 'KEEP', 'CREATED', FALSE)",
    )
    .bind(fx.beta.id.as_uuid())
    .bind(beta_policy.as_uuid())
    .execute(&mut conn)
    .await
    .expect("insert beta's policy");

    // Both rows are visible on this connection, so a refusal below is the key and not row security.
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM retention_policies")
        .fetch_one(&mut conn)
        .await
        .expect("count policies");
    assert!(
        visible >= 1,
        "the superuser connection must see beta's row for this test to mean anything"
    );

    let stolen = sqlx::query(
        "INSERT INTO retention_assignments (tenant_id, policy_id, scope_type, scope_id)
         VALUES ($1, $2, 'WORKSPACE', $3)",
    )
    .bind(fx.alpha.id.as_uuid())
    .bind(beta_policy.as_uuid())
    .bind(spine.workspace.as_uuid())
    .execute(&mut conn)
    .await;
    assert!(
        stolen.is_err(),
        "alpha applied beta's retention policy to an alpha workspace; the composite foreign key \
         is what refuses this, and PostgreSQL checks it with row security not enforced"
    );

    // The control: the same statement with alpha's own policy must succeed, or the refusal above
    // proves only that assignments cannot be written at all.
    let own = RetentionPolicyId::new_v7();
    sqlx::query(
        "INSERT INTO retention_policies (tenant_id, id, name, action, basis, allow_user_delete)
         VALUES ($1, $2, 'Alpha keeps everything', 'KEEP', 'CREATED', FALSE)",
    )
    .bind(fx.alpha.id.as_uuid())
    .bind(own.as_uuid())
    .execute(&mut conn)
    .await
    .expect("insert alpha's policy");
    sqlx::query(
        "INSERT INTO retention_assignments (tenant_id, policy_id, scope_type, scope_id)
         VALUES ($1, $2, 'WORKSPACE', $3)",
    )
    .bind(fx.alpha.id.as_uuid())
    .bind(own.as_uuid())
    .bind(spine.workspace.as_uuid())
    .execute(&mut conn)
    .await
    .expect("alpha's own policy must be applicable to alpha's workspace");
}

/// A policy the schema forbids is refused by the schema, and the writer reports it.
///
/// `insert_policy` restates none of `migrations/0031`'s six `CHECK` constraints, which is a
/// decision that is only safe if the constraints actually fire through this path. This is that
/// assertion, taken on the most dangerous of the six: a `LEGAL_HOLD` that permits user deletion
/// would read as an absolute control in every administrative listing and permit precisely the act
/// it exists to prevent.
///
/// The control is a policy identical but for `allow_user_delete`, which must be accepted.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_legal_hold_that_permits_user_deletion_is_refused_by_the_schema() {
    let (_db, fx, pool) = harness().await;
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin");

    let unsafe_hold = NewPolicy {
        id: RetentionPolicyId::new_v7(),
        name: "Litigation hold".to_owned(),
        action: RetentionAction::LegalHold,
        duration: None,
        basis: RetentionBasis::Created,
        event_key: None,
        is_record: false,
        allow_user_delete: true,
    };
    let refused = insert_policy(&mut tx, &unsafe_hold).await;
    assert!(
        refused.is_err(),
        "a LEGAL_HOLD permitting user deletion was stored; retention_policies_hold_is_absolute is \
         what refuses it, and without it the listing shows a hold that holds nothing"
    );

    // The control, in its own transaction because the failure above poisoned this one.
    drop(tx);
    let mut tx = pool.begin(fx.alpha.id).await.expect("begin again");
    let real_hold = NewPolicy { allow_user_delete: false, ..unsafe_hold };
    insert_policy(&mut tx, &real_hold)
        .await
        .expect("a LEGAL_HOLD that does not permit user deletion must be storable");
}
