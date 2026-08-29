//! `retention_policies` and `retention_assignments` against a real PostgreSQL — *which policy
//! governs this file?*
//!
//! `docs/12-TESTING.md §1.2` is the shape every test here is written to, and three of its rules do
//! the work:
//!
//! * **An assertion about an absence passes for free.** "The other tenant's policy did not apply",
//!   "the expired assignment did not apply", "no policy was found" are all true of a
//!   [`governing_policy_on`] that returns `None` for everything, of tables that were never written,
//!   and of a join that matches nothing. So every test below that asserts something is *missing*
//!   proves, **under the identical fixture and in the same run**, that something comparable is
//!   *present*.
//! * **Watch it fail first.** Each test names, in its own doc comment, the edit to
//!   `crates/db/src/retention.rs` or `migrations/0031_retention_policies.sql` that turns it red.
//!   Where the claim had to be narrowed after running the mutation, that is said — see
//!   [`another_tenants_retention_policy_never_governs_this_tenants_file`], whose comment reports
//!   which predicate is actually load-bearing rather than which one looks like it.
//! * **A negative that fails closed is not automatically safe.** It is here, and that inverts the
//!   usual reasoning. Every other read model in this crate fails towards *showing nothing*, which is
//!   safe; a retention read that fails towards finding nothing means **no policy**, which means the
//!   delete proceeds. So the positive cases carry as much weight as the negatives, and there is one
//!   for every scope: a `LIBRARY` arm silently deleted from the disjunction would leave every
//!   negative test in this file green and every library-scoped retention policy unenforced.
//!
//! # Row-level security is deliberately switched off in the isolation test
//!
//! `TestDb::pool` connects as `enclave_app` and therefore runs with RLS in force, which is right for
//! the ordinary paths. It is exactly wrong for a cross-tenant assertion: with RLS in force, deleting
//! the `tenant_id` predicate from the SQL changes nothing observable, and the test would report a
//! property the application query does not hold. That is `ENC-124` in miniature.
//!
//! So [`another_tenants_retention_policy_never_governs_this_tenants_file`] runs over
//! [`TestDb::connect`] — the harness's cluster superuser, which bypasses row security entirely — and
//! proves the connection can see both tenants' rows *before* asking the question. What it
//! demonstrates is the predicate, alone, unassisted.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use enclave_core::{FileId, TenantId, UserId};
use enclave_db::retention::{
    governing_policy, governing_policy_on, GoverningPolicy, RetentionAction, RetentionPolicyId,
    RetentionScopeType,
};
use enclave_db::DbPool;
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// The seeded database, the fixture identities, and an **application-role** pool over it.
///
/// The pool is `enclave_app`, never the harness's superuser: a superuser bypasses row-level
/// security, and the tests that should run the way production runs use this. The tests that want
/// RLS out of the way take their own connection and say why.
async fn harness() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

/// A workspace → library → folder → file spine, written over the administrative connection.
///
/// Setup, not subject (`crates/testing/src/content.rs`): these rows exist so the read has something
/// to resolve a scope against, and writing them through the application role would be testing the
/// fixtures rather than the query.
async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let s = Spine::new(tenant);
    s.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    s
}

/// A retention policy, written as setup.
///
/// `duration` is a PostgreSQL interval literal (`"7 years"`), cast in the statement rather than
/// converted in Rust — which is the same refusal `crates/db/src/retention.rs` makes at the read
/// boundary. A test that built the interval out of seconds would be quietly asserting the arithmetic
/// the module exists to avoid.
#[allow(clippy::too_many_arguments)]
async fn add_policy(
    conn: &mut PgConnection,
    tenant: TenantId,
    name: &str,
    action: RetentionAction,
    duration: Option<&str>,
    basis: &str,
    event_key: Option<&str>,
    allow_user_delete: bool,
) -> RetentionPolicyId {
    let id = RetentionPolicyId::new_v7();
    sqlx::query(
        "INSERT INTO retention_policies
           (tenant_id, id, name, action, duration, basis, event_key, is_record,
            allow_user_delete, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5::interval, $6, $7, $4 = 'RECORD', $8, now(), now())",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .bind(name)
    .bind(action.as_str())
    .bind(duration)
    .bind(basis)
    .bind(event_key)
    .bind(allow_user_delete)
    .execute(&mut *conn)
    .await
    .expect("insert a retention policy");
    id
}

/// The simple case of [`add_policy`]: a `CREATED` basis, no event key, no user deletion.
async fn policy(
    conn: &mut PgConnection,
    tenant: TenantId,
    name: &str,
    action: RetentionAction,
    duration: Option<&str>,
) -> RetentionPolicyId {
    add_policy(conn, tenant, name, action, duration, "CREATED", None, false).await
}

/// Applies a policy at a scope, with explicit timestamps.
///
/// `applied_at` is explicit in every call rather than defaulted, because it is the fourth term in
/// the precedence ordering: a test that let two assignments share `now()` would be asserting a
/// tiebreak it had not controlled.
async fn assign(
    conn: &mut PgConnection,
    tenant: TenantId,
    policy_id: RetentionPolicyId,
    scope_type: RetentionScopeType,
    scope_id: Option<Uuid>,
    applied_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO retention_assignments
           (tenant_id, policy_id, scope_type, scope_id, applied_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant.as_uuid())
    .bind(policy_id.as_uuid())
    .bind(scope_type.as_str())
    .bind(scope_id)
    .bind(applied_at)
    .bind(expires_at)
    .execute(&mut *conn)
    .await
    .expect("apply a retention policy at a scope");
}

/// A content type in a tenant's vocabulary, and the file put under it.
///
/// `files.content_type_id` carries no foreign key in `migrations/0005_files.sql`, so the row is not
/// strictly required — it is written anyway so the `CONTENT_TYPE` case is the arrangement the
/// product would actually be in rather than a loose UUID that happens to match.
async fn declare_content_type(conn: &mut PgConnection, tenant: TenantId, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_types (id, tenant_id, scope, scope_id, name, field_schema,
                                    created_at, updated_at)
         VALUES ($1, $2, 'TENANT', NULL, $3, '{}'::jsonb, now(), now())",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(name)
    .execute(&mut *conn)
    .await
    .expect("declare a content type");
    id
}

/// Puts an existing file under a content type.
async fn set_content_type(conn: &mut PgConnection, tenant: TenantId, file: FileId, ct: Uuid) {
    let affected =
        sqlx::query("UPDATE files SET content_type_id = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.as_uuid())
            .bind(file.as_uuid())
            .bind(ct)
            .execute(&mut *conn)
            .await
            .expect("set a file's content type")
            .rows_affected();
    assert_eq!(affected, 1, "the content type must have landed on exactly the file under test");
}

/// The policy that governs a file, or a panic naming the file — used where a test's whole point is
/// that *something* was found.
async fn governing(conn: &mut PgConnection, tenant: TenantId, file: FileId) -> GoverningPolicy {
    governing_policy_on(conn, tenant, file)
        .await
        .expect("the governing read must succeed")
        .unwrap_or_else(|| {
            panic!("no policy governs {file}, and this test exists because one must")
        })
}

// =================================================================================================

/// A policy assigned at each of the five scopes is found for a file beneath it.
///
/// The most important test in the file, and the one whose absence would be least visible. Every
/// other test here asserts that something is *not* found, and a scope arm silently deleted from
/// `GOVERNING_SQL`'s disjunction leaves all of them green while leaving every policy assigned at
/// that scope unenforced — retention failing closed means failing towards **not preserving**.
///
/// Four scopes are exercised in alpha on four independent spines, so none of them can be satisfied
/// by another's assignment, and `TENANT` is exercised in beta because a tenant-wide assignment
/// would by definition cover the other four. The returned `scope_type` is asserted as well as the
/// policy id: without it, a disjunction that had collapsed to a single always-true arm would still
/// find *a* policy, and this test would report success for the wrong reason.
///
/// Fails when any arm of the scope disjunction in `crates/db/src/retention.rs` is deleted.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_policy_assigned_at_each_scope_governs_a_file_beneath_it() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let now = Utc::now();

    // --- WORKSPACE, LIBRARY, CONTENT_TYPE and FILE, each on its own spine in alpha. -------------
    let ws_spine = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let lib_spine = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let ct_spine = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let file_spine = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let ct = declare_content_type(&mut conn, fx.alpha.id, "Contract").await;
    set_content_type(&mut conn, fx.alpha.id, ct_spine.file, ct).await;

    let ws_policy =
        policy(&mut conn, fx.alpha.id, "workspace rule", RetentionAction::Keep, None).await;
    let lib_policy =
        policy(&mut conn, fx.alpha.id, "library rule", RetentionAction::Keep, None).await;
    let ct_policy =
        policy(&mut conn, fx.alpha.id, "contract rule", RetentionAction::Keep, None).await;
    let file_policy =
        policy(&mut conn, fx.alpha.id, "this document", RetentionAction::Keep, None).await;

    let scopes = [
        (
            RetentionScopeType::Workspace,
            ws_policy,
            Some(ws_spine.workspace.as_uuid()),
            ws_spine.file,
        ),
        (
            RetentionScopeType::Library,
            lib_policy,
            Some(lib_spine.library.as_uuid()),
            lib_spine.file,
        ),
        (RetentionScopeType::ContentType, ct_policy, Some(ct), ct_spine.file),
        (RetentionScopeType::File, file_policy, Some(file_spine.file.as_uuid()), file_spine.file),
    ];

    for (scope, policy_id, scope_id, _) in scopes {
        assign(&mut conn, fx.alpha.id, policy_id, scope, scope_id, now, None).await;
    }

    for (scope, policy_id, _, file) in scopes {
        let found = governing(&mut conn, fx.alpha.id, file).await;
        assert_eq!(
            (found.policy_id, found.scope_type, found.covering),
            (policy_id, scope, 1),
            "a policy assigned at {scope} scope must govern a file beneath it, at that scope, and \
             be the only thing covering it"
        );
    }

    // --- TENANT, in beta, because a tenant-wide assignment covers everything above. -------------
    let beta_spine = spine(&mut conn, fx.beta.id, fx.beta.owner).await;
    let tenant_policy =
        policy(&mut conn, fx.beta.id, "tenant rule", RetentionAction::Keep, None).await;
    assign(&mut conn, fx.beta.id, tenant_policy, RetentionScopeType::Tenant, None, now, None).await;

    let found = governing(&mut conn, fx.beta.id, beta_spine.file).await;
    assert_eq!(
        (found.policy_id, found.scope_type),
        (tenant_policy, RetentionScopeType::Tenant),
        "a tenant-scoped assignment must govern a file in that tenant. Its scope_id is NULL, so \
         this is also the arm most easily broken by a change to the scope_target constraint"
    );
}

/// The stricter policy wins even when a narrower scope disagrees — and specificity still decides
/// between equals.
///
/// This is the whole argument of `crates/db/src/retention.rs` as an executable statement. Alpha
/// holds the case that disqualifies most-specific-wins: a tenant-wide `KEEP` and a library-scoped
/// `DELETE_AFTER 30 days` over the same file. Under most-specific-wins the library's rule decides
/// and the tenant's seven-year hold has been switched off by whoever administers that library.
///
/// Beta is the positive control **and** is arranged so that it fails if the scope ranking is
/// removed rather than merely reordered: two equally strict `KEEP` policies, the library one applied
/// *earlier* than the tenant one. With the scope ranking in place the library policy wins on
/// specificity; delete the `CASE a.scope_type` clause and the ordering falls through to
/// `applied_at DESC`, which picks the tenant policy and turns this red. So the pair proves that
/// strictness outranks specificity **and** that specificity is doing something.
///
/// Fails when `CASE p.action … END DESC` is moved after `CASE a.scope_type … END DESC` (alpha), or
/// when the scope ranking is deleted (beta).
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_stricter_policy_wins_even_when_a_narrower_scope_disagrees() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let now = Utc::now();

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let hold = policy(&mut conn, fx.alpha.id, "keep everything", RetentionAction::Keep, None).await;
    let hygiene = policy(
        &mut conn,
        fx.alpha.id,
        "clear the working library monthly",
        RetentionAction::DeleteAfter,
        Some("30 days"),
    )
    .await;
    assign(&mut conn, fx.alpha.id, hold, RetentionScopeType::Tenant, None, now, None).await;
    assign(
        &mut conn,
        fx.alpha.id,
        hygiene,
        RetentionScopeType::Library,
        Some(alpha.library.as_uuid()),
        now,
        None,
    )
    .await;

    let found = governing(&mut conn, fx.alpha.id, alpha.file).await;
    assert_eq!(
        (found.policy_id, found.action, found.scope_type, found.covering),
        (hold, RetentionAction::Keep, RetentionScopeType::Tenant, 2),
        "the tenant-wide KEEP must beat the library's DELETE_AFTER. If the library rule wins, a \
         compliance control has an off switch held by whoever administers the smallest container — \
         which is the reason this module does not use most-specific-wins"
    );

    // Beta: equal strictness, so specificity decides — and the library assignment is the *older*
    // one, so removing the scope ranking makes applied_at pick the tenant policy instead.
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;
    let beta_tenant =
        policy(&mut conn, fx.beta.id, "tenant keep", RetentionAction::Keep, None).await;
    let beta_library =
        policy(&mut conn, fx.beta.id, "library keep", RetentionAction::Keep, None).await;
    assign(
        &mut conn,
        fx.beta.id,
        beta_library,
        RetentionScopeType::Library,
        Some(beta.library.as_uuid()),
        now - Duration::days(2),
        None,
    )
    .await;
    assign(
        &mut conn,
        fx.beta.id,
        beta_tenant,
        RetentionScopeType::Tenant,
        None,
        now - Duration::days(1),
        None,
    )
    .await;

    let found = governing(&mut conn, fx.beta.id, beta.file).await;
    assert_eq!(
        (found.policy_id, found.scope_type, found.covering),
        (beta_library, RetentionScopeType::Library, 2),
        "between two policies that preserve identically the more specific one must win, even \
         though it was applied earlier. If the tenant policy wins here the scope ranking has been \
         removed and specificity has stopped meaning anything"
    );
}

/// A longer retention beats a shorter one, whichever scope each sits at.
///
/// Two arrangements in one run, mirrored, so that neither result can be produced by the scope
/// ranking alone:
///
/// * alpha — tenant-wide `KEEP_THEN_DELETE 7 years` against a **file-scoped** `KEEP_THEN_DELETE
///   30 days`. The seven-year rule wins from the *widest* scope, against the narrowest.
/// * beta — the same two durations with the scopes swapped. The seven-year rule wins again, now
///   from the narrowest scope.
///
/// Together they say the comparison is the duration and not the scope: no scope ordering, in either
/// direction, produces both answers. Either one alone would be satisfied by a rule this module does
/// not implement.
///
/// Fails when `p.duration DESC NULLS FIRST` is deleted from the ordering — the tiebreak then falls
/// to the scope rank, and alpha and beta return opposite answers, one of which is wrong.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_longer_retention_beats_a_shorter_one_at_any_scope() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let now = Utc::now();

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let long = policy(
        &mut conn,
        fx.alpha.id,
        "seven years",
        RetentionAction::KeepThenDelete,
        Some("7 years"),
    )
    .await;
    let short = policy(
        &mut conn,
        fx.alpha.id,
        "thirty days",
        RetentionAction::KeepThenDelete,
        Some("30 days"),
    )
    .await;
    assign(&mut conn, fx.alpha.id, long, RetentionScopeType::Tenant, None, now, None).await;
    assign(
        &mut conn,
        fx.alpha.id,
        short,
        RetentionScopeType::File,
        Some(alpha.file.as_uuid()),
        now,
        None,
    )
    .await;

    assert_eq!(
        governing(&mut conn, fx.alpha.id, alpha.file).await.policy_id,
        long,
        "seven years at tenant scope must beat thirty days at file scope"
    );

    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;
    let beta_long = policy(
        &mut conn,
        fx.beta.id,
        "seven years",
        RetentionAction::KeepThenDelete,
        Some("7 years"),
    )
    .await;
    let beta_short = policy(
        &mut conn,
        fx.beta.id,
        "thirty days",
        RetentionAction::KeepThenDelete,
        Some("30 days"),
    )
    .await;
    assign(&mut conn, fx.beta.id, beta_short, RetentionScopeType::Tenant, None, now, None).await;
    assign(
        &mut conn,
        fx.beta.id,
        beta_long,
        RetentionScopeType::File,
        Some(beta.file.as_uuid()),
        now,
        None,
    )
    .await;

    assert_eq!(
        governing(&mut conn, fx.beta.id, beta.file).await.policy_id,
        beta_long,
        "seven years at file scope must beat thirty days at tenant scope. With the scopes swapped \
         from the alpha case, no scope ordering can produce both answers — only the duration can"
    );
}

/// An expired assignment does not apply, and does not shadow one that still does.
///
/// Two claims, and the second is the one that matters. `enclave_app` holds no `DELETE` on
/// `retention_assignments`, so `expires_at` is the *only* way to withdraw a policy — and an expired
/// row that still won the precedence ordering would make retention permanent and unremovable by any
/// request the application can issue.
///
/// The positive controls are in the same run and under the same fixture: a second file covered by
/// an unexpired assignment of the same policy resolves, and the first file falls through to the
/// still-live tenant-wide policy rather than to nothing. Without them, "the expired one did not
/// apply" is equally true of a read that finds nothing at all.
///
/// Fails when `a.expires_at IS NULL OR a.expires_at > now()` is deleted from `GOVERNING_SQL`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_expired_assignment_does_not_apply_and_does_not_shadow_a_live_one() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let now = Utc::now();

    let withdrawn = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let still_held = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    // A LEGAL_HOLD, so the expired row would win the precedence ordering outright if it were
    // considered at all — an expiry filter tested against the weakest policy in the vocabulary
    // would be indistinguishable from the ordering doing the work.
    let matter =
        policy(&mut conn, fx.alpha.id, "matter 2024-11", RetentionAction::LegalHold, None).await;
    let baseline = policy(
        &mut conn,
        fx.alpha.id,
        "tenant baseline",
        RetentionAction::KeepThenDelete,
        Some("30 days"),
    )
    .await;

    assign(&mut conn, fx.alpha.id, baseline, RetentionScopeType::Tenant, None, now, None).await;
    assign(
        &mut conn,
        fx.alpha.id,
        matter,
        RetentionScopeType::File,
        Some(withdrawn.file.as_uuid()),
        now - Duration::days(30),
        Some(now - Duration::days(1)),
    )
    .await;
    assign(
        &mut conn,
        fx.alpha.id,
        matter,
        RetentionScopeType::File,
        Some(still_held.file.as_uuid()),
        now - Duration::days(30),
        Some(now + Duration::days(30)),
    )
    .await;

    // Positive control first: the same policy, the same shape of row, an expiry in the future.
    let held = governing(&mut conn, fx.alpha.id, still_held.file).await;
    assert_eq!(
        (held.policy_id, held.scope_type),
        (matter, RetentionScopeType::File),
        "an unexpired hold must still govern, or the negative below is a statement about the \
         fixture rather than about expires_at"
    );

    let released = governing(&mut conn, fx.alpha.id, withdrawn.file).await;
    assert_eq!(
        (released.policy_id, released.covering),
        (baseline, 1),
        "a released file must fall through to the tenant baseline, and must be covered by exactly \
         one live assignment. If the hold still wins here, expires_at withdraws nothing and — with \
         no DELETE granted on the table — retention has become permanent"
    );
}

/// A file no assignment covers reports no policy, rather than a default one.
///
/// The temptation this guards against is a fallback: some `KEEP`, some tenant-wide minimum, some
/// "safe" answer for a tenant that has configured nothing. Every one of those is a rule nobody
/// wrote, applied to every file in every unconfigured tenant, and indistinguishable in an audit row
/// from one an administrator chose.
///
/// The positive control is a second file in the same tenant, on the same connection, under the same
/// fixture, which *is* covered — so `None` here is the absence of a policy and not the absence of a
/// working query.
///
/// Fails when a default is introduced. It also fails when **both** joins are loosened to
/// `LEFT JOIN` — the shape a well-meaning refactor reaches for — and the way it fails is worth
/// recording, because it was measured rather than predicted: loosening the assignments join alone
/// changes nothing, since the inner join to `retention_policies` still drops the NULL row. With
/// both loosened the read returns a row of NULLs and `RetentionAction::from_column` refuses it with
/// `ColumnDecode(UnexpectedNullError)` rather than inventing a policy. That is the fail-closed path
/// the module's decode refusal exists for, arriving from a direction nobody designed it for.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_no_assignment_covers_has_no_policy_rather_than_a_default() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let uncovered = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let covered = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let rule = policy(&mut conn, fx.alpha.id, "library rule", RetentionAction::Keep, None).await;
    assign(
        &mut conn,
        fx.alpha.id,
        rule,
        RetentionScopeType::Library,
        Some(covered.library.as_uuid()),
        Utc::now(),
        None,
    )
    .await;

    assert_eq!(
        governing(&mut conn, fx.alpha.id, covered.file).await.policy_id,
        rule,
        "the covered file must resolve, or the absence below proves only that nothing works"
    );

    assert!(
        governing_policy_on(&mut conn, fx.alpha.id, uncovered.file)
            .await
            .expect("the governing read must succeed for an uncovered file")
            .is_none(),
        "a file no assignment covers must report no policy. A default here would be a retention \
         rule nobody wrote, applied to every file in every tenant that has configured none"
    );
}

/// One tenant's retention policy never governs another's file, with row-level security switched off.
///
/// The whole test runs over the harness's cluster superuser connection, where RLS is inert. That is
/// asserted first, not assumed: the connection reads `retention_assignments` with no `app.tenant_id`
/// set at all and must see both tenants' rows. Under RLS that statement errors — `current_setting`
/// is used in its strict form (`migrations/0002_rls_policies.sql`) — so what follows is a
/// demonstration of the SQL, alone, unassisted.
///
/// **Which predicate, precisely. The first draft of this comment was wrong and the mutation run is
/// what corrected it** — the same correction `crates/db/tests/recent.rs` records for its own
/// isolation test, arrived at the same way. `GOVERNING_SQL` carries tenant scoping three times:
/// `f.tenant_id = $1` on the `files` anchor, `a.tenant_id = $1` on the assignments join and
/// `p.tenant_id = $1` on the policies join. Deleting each in turn:
///
/// * **`f.tenant_id = $1` alone → red**, on the last assertion. Without it a file id belonging to
///   beta resolves inside an alpha-scoped read and is answered about.
/// * **`a.tenant_id = $1` alone → green.** **`p.tenant_id = $1` alone → green.** They are redundant
///   with *each other* for this statement: whichever survives still excludes beta's row.
/// * **Both together → red**, on the `covering` assertion, and this is the leak the test exists
///   for: a `TENANT`-scoped assignment matches on `scope_id IS NULL`, which is the same NULL in
///   every tenant, so beta's tenant-wide `LEGAL_HOLD` reaches alpha's file and outranks alpha's own
///   `KEEP`. The composite foreign key cannot prevent it — both rows are individually well-formed —
///   and neither can RLS on this connection.
///
/// So the honest claim is: one predicate load-bearing alone, and a **pair** whose members are
/// interchangeable but not disposable. All three stay; `crates/db/src/retention.rs` records what
/// each buys beyond isolation.
///
/// Beta's own answer is read back as the positive control: the hold is present, reachable and
/// well-formed on this very connection, and the only reason it is absent from an alpha-scoped read
/// is the query.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_retention_policy_never_governs_this_tenants_file() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let now = Utc::now();

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    // Tenant-wide in *both* tenants, so neither answer can come from a scope_id comparison — the
    // TENANT arm matches on `scope_id IS NULL`, which is the same NULL in every tenant.
    let alpha_rule =
        policy(&mut conn, fx.alpha.id, "alpha keep", RetentionAction::Keep, None).await;
    let beta_hold =
        policy(&mut conn, fx.beta.id, "beta matter", RetentionAction::LegalHold, None).await;
    assign(&mut conn, fx.alpha.id, alpha_rule, RetentionScopeType::Tenant, None, now, None).await;
    assign(&mut conn, fx.beta.id, beta_hold, RetentionScopeType::Tenant, None, now, None).await;

    // Row-level security is inert on this connection, and here is the proof. With RLS in force this
    // statement raises `unrecognized configuration parameter "app.tenant_id"`; a superuser bypasses
    // the policy and reads both tenants' rows. Everything below therefore tests the SQL alone.
    let visible: i64 =
        sqlx::query_scalar("SELECT count(DISTINCT tenant_id) FROM retention_assignments")
            .fetch_one(&mut conn)
            .await
            .expect(
                "the superuser connection must be able to read retention_assignments with no \
                 app.tenant_id set; if this errors, row-level security is in force and the \
                 assertions below would be proving RLS rather than the predicate",
            );
    assert_eq!(
        visible, 2,
        "this connection must be able to see both tenants' assignments, or the cross-tenant \
         assertions below are held by row security and not by the query"
    );

    // The positive control, asserted before either negative: beta's hold resolves.
    let beta_answer = governing(&mut conn, fx.beta.id, beta.file).await;
    assert_eq!(
        (beta_answer.policy_id, beta_answer.action),
        (beta_hold, RetentionAction::LegalHold),
        "beta's own hold must resolve, or the absences below are an absence of everything"
    );

    // Alpha's file, in alpha's context: alpha's own rule and nothing of beta's. `covering` is the
    // sharper half — a leaked assignment would show up here as 2 even if the ordering happened to
    // pick alpha's policy anyway.
    let alpha_answer = governing(&mut conn, fx.alpha.id, alpha.file).await;
    assert_eq!(
        (alpha_answer.policy_id, alpha_answer.action, alpha_answer.covering),
        (alpha_rule, RetentionAction::Keep, 1),
        "alpha's file must be governed by alpha's rule and covered by exactly one assignment, with \
         row security switched off. A LEGAL_HOLD outranks a KEEP, so if beta's assignment were \
         reachable it would win outright"
    );

    // The question as an attacker would put it: alpha's context, beta's file.
    assert!(
        governing_policy_on(&mut conn, fx.alpha.id, beta.file)
            .await
            .expect("cross-tenant read")
            .is_none(),
        "a read scoped to alpha must find nothing for a file that belongs to beta, even on a \
         connection that can see every row in both tables"
    );
}

/// An assignment naming another tenant's policy is refused by the composite key.
///
/// This is the control that stops a cross-tenant assignment from *existing*, and it is the
/// database's rather than the query's: PostgreSQL runs referential-integrity checks with row
/// security deliberately not enforced (`docs/04 §3.3`), so a single-column
/// `REFERENCES retention_policies (id)` would accept another tenant's policy id — and one tenant
/// would be governing another tenant's deletion path. The test runs on the superuser connection for
/// the same reason as the one above: with RLS in force the `WITH CHECK` clause refuses the write
/// first and the key is never reached, so the assertion would be about the policy rather than the
/// key.
///
/// The successful assignment is the positive control — without it, "the write was refused" is
/// equally true of a statement that is broken for everyone.
///
/// Fails when `retention_assignments_policy_fkey` in `migrations/0031_retention_policies.sql` is
/// narrowed to its single-column form: the offending insert then succeeds.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_assignment_naming_another_tenants_policy_is_refused_by_the_composite_key() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let beta_policy = policy(&mut conn, fx.beta.id, "beta rule", RetentionAction::Keep, None).await;

    // Positive control: the same policy, applied within its own tenant, lands.
    assign(&mut conn, fx.beta.id, beta_policy, RetentionScopeType::Tenant, None, Utc::now(), None)
        .await;

    let refused = sqlx::query(
        "INSERT INTO retention_assignments (tenant_id, policy_id, scope_type, applied_at)
         VALUES ($1, $2, 'TENANT', now())",
    )
    .bind(fx.alpha.id.as_uuid())
    .bind(beta_policy.as_uuid())
    .execute(&mut conn)
    .await
    .expect_err(
        "applying beta's retention policy inside alpha must be refused by the composite key: it is \
         two individually well-formed rows, and row security does not look at referential \
         integrity",
    );

    assert!(
        matches!(&refused, sqlx::Error::Database(e) if e.code().as_deref() == Some("23503")),
        "the refusal must be a foreign-key violation, not something else failing first: {refused:?}"
    );
}

/// The read works through the application role, under row-level security, as production runs it.
///
/// Every test above runs on the superuser connection, which is right for what they prove and wrong
/// as the only thing proved: a suite that never touched `enclave_app` would be green against a
/// table the application cannot select from at all — `ENC-124` exactly, and the reason
/// `migrations/0031` asserts its own grants at apply time.
///
/// So this one goes through [`DbPool::begin`] and [`governing_policy`], which take the tenant from
/// the transaction rather than from an argument. The negative half asks alpha's transaction about
/// beta's file: here RLS and the predicate agree, which is the two-layer arrangement working, and
/// the honest claim is only that the application path returns nothing — the *predicate*'s
/// contribution is what the superuser test above measures.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_can_read_a_governing_policy_through_a_scoped_transaction() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let alpha = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let beta = spine(&mut conn, fx.beta.id, fx.beta.owner).await;
    let rule = policy(&mut conn, fx.alpha.id, "alpha keep", RetentionAction::Keep, None).await;
    assign(&mut conn, fx.alpha.id, rule, RetentionScopeType::Tenant, None, Utc::now(), None).await;

    let mut tx = pool.begin(fx.alpha.id).await.expect("an alpha-scoped transaction");
    let found = governing_policy(&mut tx, alpha.file)
        .await
        .expect("the application role must be able to read the retention tables")
        .expect("alpha's tenant-wide rule must govern alpha's file");
    assert_eq!(
        (found.policy_id, found.scope_type),
        (rule, RetentionScopeType::Tenant),
        "the scoped form must resolve the same policy as the explicit one; if this fails with a \
         permission error, migrations/0031's GRANT did not reach enclave_app"
    );

    let cross = governing_policy(&mut tx, beta.file)
        .await
        .expect("a cross-tenant read must return no rows rather than erroring");
    assert!(
        cross.is_none(),
        "an alpha-scoped transaction must find no policy for a file that belongs to beta"
    );
    tx.commit().await.expect("commit");
}
