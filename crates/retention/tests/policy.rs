//! The retention stage against a real PostgreSQL — *may this caller destroy this content?*
//!
//! `crates/retention/src/lib.rs` was thirty-two lines and answered `allow` to everything, while
//! `docs/06-SECURITY-DLP-ACCESS.md §15` said *"retention and record policies override user
//! deletion"*. `ReasonCode::RetentionBlocksDelete` had existed since the error vocabulary was
//! written and **nothing in the workspace had ever returned it**. These tests are the proof that
//! something does now.
//!
//! # Three rules from `docs/12-TESTING.md §1.2` shape every test below
//!
//! * **An assertion about an absence passes for free.** "The other tenant's policy did not refuse",
//!   "restore was not blocked", "the uncovered file was deletable" are all true of a stage that
//!   allows everything — which is precisely the stage this crate shipped with. So every test here
//!   that asserts something was *permitted* proves, **under the identical fixture and in the same
//!   run**, that something comparable was *refused*. There is no test in this file whose whole
//!   result set is allows.
//! * **Watch it fail first.** Each test names, in its own doc comment, the edit to
//!   `crates/retention/src/policy.rs` that turns it red, and the edit was made and the failure
//!   watched. Where the obvious mutation turned out *not* to flip a test, that is reported rather
//!   than quietly replaced — see
//!   [`the_cascade_walk_does_not_cross_a_tenant_boundary`].
//! * **A negative that fails closed is not automatically safe.** This stage inverts the usual
//!   direction: its failure mode is *finding no policy*, which means the delete proceeds. So the
//!   refusals carry the weight and the allows are the controls, not the other way round.
//!
//! # Row-level security is switched off in one test, deliberately
//!
//! `TestDb::pool` connects as `enclave_app`, so the stage-level tests run with row security in
//! force, which is how production runs. That is exactly wrong for asserting what the SQL's
//! `tenant_id` predicates hold on their own: with RLS in force, deleting one changes nothing
//! observable and the test would report a property the query does not have (`ENC-124`). So
//! [`the_cascade_walk_does_not_cross_a_tenant_boundary`] runs [`cascade_probes_on`] over
//! `TestDb::connect` — the harness's cluster superuser, which bypasses row security entirely — and
//! proves the connection can see both tenants' rows before asking the question.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use enclave_core::{
    Action, FileAction, FileId, ReasonCode, RequestContext, ResourceRef, RetentionService as _,
    StageDecision, StageOutcome, TenantId, UserId,
};
use enclave_db::{
    governing_policy_on, DbPool, RetentionAction, RetentionPolicyId, RetentionScopeType,
    TenantScoped,
};
use enclave_retention::{
    cascade_probes_on, purge_deadline, CascadeLimits, PgRetention, PurgeDeadline,
    UnconfiguredRetention,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

// -------------------------------------------------------------------------------------------
// Fixtures. Setup, never subject: every row below is written over the administrative connection,
// because writing them through the stage under test would make the test a test of itself.
// -------------------------------------------------------------------------------------------

/// The seeded database, the fixture identities, and an **application-role** pool over it.
///
/// The pool is `enclave_app`, never the harness's superuser: a superuser bypasses row-level
/// security, and the stage tests should run the way production runs. The one test that wants RLS
/// out of the way takes its own connection and says why.
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
/// The folder holds the file, which is the arrangement the cascading-delete case needs: one node
/// addressed and one node beneath it.
async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let s = Spine::new(tenant);
    s.insert(conn, owner, Utc::now()).await.expect("insert a content spine");
    s
}

/// A retention policy, written as setup.
///
/// `duration` is a PostgreSQL interval literal (`"7 years"`), cast in the statement rather than
/// converted in Rust — the same refusal `migrations/0031_retention_policies.sql` makes. A test that
/// built the interval out of seconds would be quietly asserting the arithmetic the column exists to
/// avoid.
async fn policy(
    conn: &mut PgConnection,
    tenant: TenantId,
    name: &str,
    action: RetentionAction,
    duration: Option<&str>,
    allow_user_delete: bool,
) -> RetentionPolicyId {
    let id = RetentionPolicyId::new_v7();
    sqlx::query(
        "INSERT INTO retention_policies
           (tenant_id, id, name, action, duration, basis, event_key, is_record,
            allow_user_delete, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5::interval, 'CREATED', NULL, $4 = 'RECORD', $6, now(), now())",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .bind(name)
    .bind(action.as_str())
    .bind(duration)
    .bind(allow_user_delete)
    .execute(&mut *conn)
    .await
    .expect("insert a retention policy");
    id
}

/// Applies a policy at a scope.
async fn assign(
    conn: &mut PgConnection,
    tenant: TenantId,
    policy_id: RetentionPolicyId,
    scope_type: RetentionScopeType,
    scope_id: Option<Uuid>,
) {
    sqlx::query(
        "INSERT INTO retention_assignments
           (tenant_id, policy_id, scope_type, scope_id, applied_at, expires_at)
         VALUES ($1, $2, $3, $4, now(), NULL)",
    )
    .bind(tenant.as_uuid())
    .bind(policy_id.as_uuid())
    .bind(scope_type.as_str())
    .bind(scope_id)
    .execute(&mut *conn)
    .await
    .expect("apply a retention policy at a scope");
}

/// Puts a file under a policy that forbids the user deleting it, and returns the spine.
///
/// `KEEP` with `allow_user_delete = false` is the ordinary shape of the control — a retention
/// schedule an administrator wrote — rather than `LEGAL_HOLD`, which the schema forbids
/// `allow_user_delete` on anyway and which would therefore prove the `CHECK` rather than the stage.
async fn governed_spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let s = spine(conn, tenant, owner).await;
    let held =
        policy(conn, tenant, "seven-year hold", RetentionAction::Keep, Some("7 years"), false)
            .await;
    assign(conn, tenant, held, RetentionScopeType::File, Some(s.file.as_uuid())).await;
    s
}

// -------------------------------------------------------------------------------------------
// Assertions.
// -------------------------------------------------------------------------------------------

/// The stage's answer for one action on one resource, in `tenant`.
async fn decide(
    stage: &PgRetention,
    tenant: TenantId,
    action: FileAction,
    resource: ResourceRef,
) -> StageDecision {
    stage
        .evaluate(&RequestContext::system(tenant), Action::File(action), &resource)
        .await
        .expect("the retention stage must answer rather than fail")
}

/// Asserts a decision is a refusal naming `RETENTION_BLOCKS_DELETE`.
///
/// The wire string is asserted, not only the variant: `docs/05-API.md`'s error model puts this code
/// in the response body, and a rename that left the variant intact would change the contract
/// without changing any `match`.
#[track_caller]
fn assert_blocks_delete(decision: &StageDecision, what: &str) {
    match decision.outcome() {
        StageOutcome::Deny(code) => {
            assert_eq!(*code, ReasonCode::RetentionBlocksDelete, "{what}");
            assert_eq!(code.as_str(), "RETENTION_BLOCKS_DELETE", "{what}");
        }
        StageOutcome::Allow => panic!("{what}: retention allowed a delete it was meant to refuse"),
    }
}

#[track_caller]
fn assert_allows(decision: &StageDecision, what: &str) {
    assert!(decision.is_allowed(), "{what}: retention refused, and it had no business doing so");
}

// -------------------------------------------------------------------------------------------
// Tests.
// -------------------------------------------------------------------------------------------

/// A policy with `allow_user_delete = false` refuses the delete, and names the reason.
///
/// The whole point of the item: an administrator decides whether a user may destroy content, and
/// until this stage existed the answer was always yes. The positive control is in the same run and
/// on the same fixture shape — an identically-built file that no assignment covers — because
/// without it every assertion here would pass against a stage that refuses everything.
///
/// Fails when `PgRetention::first_refusal`'s `if !policy.allow_user_delete` is inverted or dropped;
/// the mutation used was deleting the `!`, which turned the refusal into an allow and the control
/// into a refusal, so both halves moved.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_policy_that_forbids_user_deletion_refuses_the_delete_and_names_the_reason() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let free = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let stage = PgRetention::new(pool);

    let refused = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, governed.file),
    )
    .await;
    assert_blocks_delete(&refused, "a file under a KEEP policy that forbids user deletion");

    // The positive control. Same tenant, same library shape, same action — the only difference is
    // that no assignment covers it.
    let allowed =
        decide(&stage, fx.alpha.id, FileAction::Delete, ResourceRef::file(fx.alpha.id, free.file))
            .await;
    assert_allows(&allowed, "a file no retention assignment covers");
}

/// **A folder whose descendant is governed cannot be deleted.**
///
/// The case this item exists for, and the one a naive implementation misses.
/// `FileRepository::trash` cascades — it stamps one `deleted_at` across the subtree — and
/// `crates/api/src/routes/lifecycle.rs` authorizes the descendants through
/// `AuthorizationService::authorize_many`, which is the *authorization stage alone* and never
/// reaches retention. A stage that asked only about the addressed node would let a seven-year hold
/// on a contract be defeated by deleting the folder the contract sits in.
///
/// Three assertions, and the middle one is what makes the first mean anything:
///
///   1. deleting the folder is refused;
///   2. **no policy governs the folder itself** — so the refusal came from beneath it and not from
///      an assignment that happened to cover both;
///   3. an identically-shaped folder whose descendant is *not* governed is deletable.
///
/// Fails when the walk is reduced to the addressed node — the mutation used was replacing
/// `cascade_probes(tx, root, …)` in `first_refusal` with `vec![root]`, which left assertions 2 and
/// 3 green and turned 1 into an allow.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_folder_whose_descendant_is_governed_cannot_be_deleted() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let free = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    // Assertion 2, first, because it is the premise of assertion 1. The assignment is `FILE`-scoped
    // on the leaf, so the folder is covered by nothing at all.
    let on_the_folder = governing_policy_on(&mut conn, fx.alpha.id, governed.folder)
        .await
        .expect("the governing read must succeed");
    assert!(
        on_the_folder.is_none(),
        "the folder must be ungoverned, or this test proves nothing about descendants: \
         {on_the_folder:?}"
    );

    let stage = PgRetention::new(pool);

    let refused = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::folder(fx.alpha.id, governed.folder),
    )
    .await;
    assert_blocks_delete(&refused, "a folder holding a file under a KEEP policy");

    let allowed = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::folder(fx.alpha.id, free.folder),
    )
    .await;
    assert_allows(&allowed, "a folder whose descendants no assignment covers");
}

/// The same file can still be restored, previewed and read.
///
/// `docs/06 §15` gives retention authority over *deletion*. A stage that also refused reads would
/// be a second authorization stage with none of the first one's model, and restore in particular
/// must stay open — refusing it would strand every document trashed before its policy was assigned,
/// inside a recycle bin its owner is told they may empty.
///
/// The delete refusal is asserted in the same run over the same file, so "restore was allowed"
/// cannot be the answer of a stage that allows everything.
///
/// Fails when `FileAction::Restore` (or any read action) is moved into the destructive arm of
/// `PgRetention::evaluate`'s match; the mutation used was moving `Restore` next to `Delete`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_governed_file_can_still_be_restored_previewed_and_read() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let stage = PgRetention::new(pool);
    let file = ResourceRef::file(fx.alpha.id, governed.file);

    for action in [
        FileAction::Restore,
        FileAction::Preview,
        FileAction::ContentRead,
        FileAction::MetadataRead,
        FileAction::Download,
        FileAction::Edit,
        FileAction::VersionRead,
    ] {
        let decision = decide(&stage, fx.alpha.id, action, file).await;
        assert_allows(&decision, &format!("{action} on a file under a retention policy"));
    }

    // The control: this file really is governed, and this stage really can refuse.
    let refused = decide(&stage, fx.alpha.id, FileAction::Delete, file).await;
    assert_blocks_delete(&refused, "the same file, deleted");
}

/// A policy with `allow_user_delete = true` allows the delete — the positive control the whole
/// suite rests on.
///
/// Without it, every assertion in this file passes against a stage that refuses every delete it is
/// asked about, which is a control that has replaced the product's delete path rather than
/// governing it. Both spines are covered by a policy; the only difference is the column.
///
/// Fails when `first_refusal` refuses on the presence of a policy rather than on its
/// `allow_user_delete` column — the mutation used was replacing the condition with `true`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_policy_that_permits_user_deletion_allows_the_delete() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let permissive = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let open = policy(
        &mut conn,
        fx.alpha.id,
        "three-year schedule, user may still delete",
        RetentionAction::Keep,
        Some("3 years"),
        true,
    )
    .await;
    assign(&mut conn, fx.alpha.id, open, RetentionScopeType::File, Some(permissive.file.as_uuid()))
        .await;

    let forbidding = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let stage = PgRetention::new(pool);

    // Both are governed. The premise, asserted rather than assumed.
    for (file, what) in
        [(permissive.file, "the permissive file"), (forbidding.file, "the forbidding file")]
    {
        let found = governing_policy_on(&mut conn, fx.alpha.id, file)
            .await
            .expect("the governing read must succeed");
        assert!(found.is_some(), "{what} must be covered by a policy");
    }

    let allowed = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, permissive.file),
    )
    .await;
    assert_allows(&allowed, "a file under a policy that permits user deletion");

    let refused = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, forbidding.file),
    )
    .await;
    assert_blocks_delete(&refused, "a file under a policy that forbids it");
}

/// A file no policy covers is deletable, and [`UnconfiguredRetention`] still allows everything.
///
/// Two claims that would each pass for free on their own, and do not here: the refusal of the
/// *governed* file by [`PgRetention`] in the same run is what proves the fixture is real, and the
/// allow of that same governed file by [`UnconfiguredRetention`] is what proves the empty-case
/// implementation is still the empty case. A deployment with no policies must keep working, and the
/// start-up warning that names that type is how an operator learns nothing blocks deletion in it.
///
/// Fails when `UnconfiguredRetention` is made to consult anything, and when `PgRetention` refuses
/// on the absence of a policy — the mutation used was inverting `first_refusal`'s `if let Some`
/// into a refusal on `None`, which flipped the uncovered file to a denial.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_uncovered_file_is_deletable_and_the_unconfigured_stage_allows_everything() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let free = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let stage = PgRetention::new(pool);
    let ctx = RequestContext::system(fx.alpha.id);
    let delete = Action::File(FileAction::Delete);

    let allowed =
        decide(&stage, fx.alpha.id, FileAction::Delete, ResourceRef::file(fx.alpha.id, free.file))
            .await;
    assert_allows(&allowed, "a file no assignment covers");

    let refused = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, governed.file),
    )
    .await;
    assert_blocks_delete(&refused, "a governed file, so the fixture is real");

    // The same governed file, through the empty-case stage.
    let unconfigured = UnconfiguredRetention;
    for file in [free.file, governed.file] {
        let decision = unconfigured
            .evaluate(&ctx, delete, &ResourceRef::file(fx.alpha.id, file))
            .await
            .expect("the unconfigured stage never fails");
        assert_allows(&decision, "UnconfiguredRetention, which has no policies to consult");
    }
}

/// A governed file in `tenant-beta` does not cause a refusal in `tenant-alpha`.
///
/// The tenant this stage reads under comes from [`RequestContext::tenant_id`] and from nowhere else
/// (`CLAUDE.md` rule 3). `ResourceRef::tenant_id` is not consulted — `PolicyEngine::enforce` has
/// already compared the two and answered `404` on a mismatch, so a reference like the one below
/// cannot arrive in production; what it demonstrates here is that the stage would not act on it if
/// one did.
///
/// The positive control is the identical file asked about under beta's own context, in the same
/// run: without it, "alpha was not refused" is true of every stage that never found a policy for any
/// reason, including a broken query.
///
/// Fails when `PgRetention::evaluate` opens its transaction on `resource.tenant_id` rather than
/// `ctx.tenant_id` — the mutation used, and it flips the first assertion to a refusal while leaving
/// the control green.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_retention_policy_does_not_refuse_this_tenants_delete() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let in_beta = governed_spine(&mut conn, fx.beta.id, fx.beta.owner).await;
    let stage = PgRetention::new(pool);

    // Beta's own file, addressed as beta's, carrying beta's tenant id — and asked under *alpha*.
    let alpha_view = stage
        .evaluate(
            &RequestContext::system(fx.alpha.id),
            Action::File(FileAction::Delete),
            &ResourceRef::file(fx.beta.id, in_beta.file),
        )
        .await
        .expect("the retention stage must answer rather than fail");
    assert_allows(&alpha_view, "another tenant's retention policy, seen from alpha");

    let beta_view =
        decide(&stage, fx.beta.id, FileAction::Delete, ResourceRef::file(fx.beta.id, in_beta.file))
            .await;
    assert_blocks_delete(&beta_view, "the same file under its own tenant's context");
}

/// The cascade walk's `tenant_id` predicate holds isolation on its own, with row security inert.
///
/// This runs over the harness's **cluster superuser**, which bypasses row-level security entirely,
/// so what is demonstrated is the predicate and nothing else. The connection is proved able to see
/// both tenants' rows before the question is asked, which is what makes the negative meaningful
/// rather than vacuous (`ENC-124`).
///
/// Fails when `f.tenant_id = $1` is deleted from `CASCADE_SQL`'s anchor term — the mutation used;
/// the beta subtree then resolves under alpha and the first assertion finds two nodes.
///
/// **What this test could not be made to prove, reported rather than dropped.** Deleting
/// `c.tenant_id = $1` from the *recursive* term leaves it green, and no fixture can change that:
/// `migrations/0005_files.sql` declares
/// `FOREIGN KEY (tenant_id, parent_id) REFERENCES files (tenant_id, id)`, so a row whose parent is
/// in another tenant cannot be written to construct the leak. The predicate stays — it is what
/// keeps the recursive join on `idx_files_parent` rather than scanning, and it is the layer that
/// would still hold if that key were ever relaxed — but it is defence in depth here and not the
/// thing this test measures.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_cascade_walk_does_not_cross_a_tenant_boundary() {
    let (db, fx, _pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    let in_beta = governed_spine(&mut conn, fx.beta.id, fx.beta.owner).await;

    // The premise: this connection is not subject to row security, so an empty answer below is the
    // predicate's doing and not the database's.
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM files WHERE tenant_id = $1 AND id IN ($2, $3)")
            .bind(fx.beta.id.as_uuid())
            .bind(in_beta.folder.as_uuid())
            .bind(in_beta.file.as_uuid())
            .fetch_one(&mut conn)
            .await
            .expect("count beta's spine");
    assert_eq!(visible, 2, "the superuser connection must be able to see beta's rows unaided");

    let from_alpha =
        cascade_probes_on(&mut conn, fx.alpha.id, in_beta.folder, CascadeLimits::DEFAULT)
            .await
            .expect("the walk must answer rather than fail");
    assert!(from_alpha.is_empty(), "alpha's walk reached another tenant's subtree: {from_alpha:?}");

    // The positive control, same connection, same statement, same fixture.
    let from_beta =
        cascade_probes_on(&mut conn, fx.beta.id, in_beta.folder, CascadeLimits::DEFAULT)
            .await
            .expect("the walk must answer rather than fail");
    assert!(
        from_beta.contains(&in_beta.file) || from_beta.contains(&in_beta.folder),
        "beta's own walk found nothing, so the empty answer above proves nothing: {from_beta:?}"
    );
}

/// The walk reaches the descendant, and a file-scoped assignment is never grouped away.
///
/// `CASCADE_SQL` reduces the subtree to one representative per
/// `(workspace_id, library_id, content_type_id)` plus every node carrying a `FILE`-scoped
/// assignment — see the module note on why that reduction is exact. This asserts the half of it
/// that a grouping bug would silently break: the pinned leaf is probed *individually*, so it is
/// present even though a sibling in the same class is the representative.
///
/// Fails when the `pinned` branch is dropped from `CASCADE_SQL`'s `probes` union — the mutation
/// used; the leaf then falls into the representative set and, with the folder sorting first by id
/// in the `DISTINCT ON`, disappears from the answer.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_scoped_assignment_is_probed_individually_rather_than_grouped_away() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let mut tx =
        TenantScoped::begin(&pool, fx.alpha.id).await.expect("a tenant-scoped transaction");
    let probes =
        enclave_retention::cascade_probes(&mut tx, governed.folder, CascadeLimits::DEFAULT)
            .await
            .expect("the walk must answer rather than fail");
    tx.commit().await.expect("commit the read");

    assert!(
        probes.contains(&governed.file),
        "the pinned leaf must be probed in its own right: {probes:?}"
    );
    // The control: the reduction is doing something, not merely returning every node. The folder
    // and the file share a workspace, library and content type, so the folder is the class
    // representative and both are present — two nodes, from a two-node subtree, is not yet a
    // reduction, so the claim asserted is the one this fixture can support.
    assert_eq!(probes.len(), 2, "folder and file, each for its own reason: {probes:?}");
}

/// A cascade wider than the limit is an **error**, not a truncated allow.
///
/// The direction matters more than the limit does. A `LIMIT` that silently trimmed the probe set
/// would make a delete of a large folder succeed by virtue of being large — the permissive failure
/// this whole module is arranged against — and it would do so with no signal anywhere.
///
/// The control is the same fixture under the default limits, which refuses: so "it errored" is not
/// the answer of a stage that cannot read the tables at all.
///
/// Fails when `cascade_probes_on` drops the `rows.len() > limits.max_probes` check. That mutation
/// was made and watched: the narrowed stage then *answered*, from a probe set the `LIMIT` had
/// trimmed. In this two-node fixture the answer it happened to give was still a refusal, and that is
/// the point rather than a weakness in the test — the answer had stopped being a function of the
/// whole cascade, and `LIMIT` without `ORDER BY` chooses which node survives. Trim the leaf instead
/// of the folder and the same code allows the delete.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_cascade_wider_than_the_limit_is_refused_rather_than_truncated() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let narrow =
        PgRetention::with_limits(pool.clone(), CascadeLimits { max_depth: 256, max_probes: 1 });
    let error = narrow
        .evaluate(
            &RequestContext::system(fx.alpha.id),
            Action::File(FileAction::Delete),
            &ResourceRef::folder(fx.alpha.id, governed.folder),
        )
        .await
        .expect_err("a cascade the stage cannot finish checking must not be answered");
    assert!(
        !matches!(error, enclave_core::Error::PolicyDenied { .. }),
        "an evaluation failure must never render as a denial: {error:?}"
    );

    // The control: under the default limits the same fixture produces an answer, and the answer is
    // a refusal.
    let wide = PgRetention::new(pool);
    let refused = decide(
        &wide,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::folder(fx.alpha.id, governed.folder),
    )
    .await;
    assert_blocks_delete(&refused, "the same folder under the default limits");
}

/// A purge deadline is the policy's duration added to the file's basis instant, in PostgreSQL.
///
/// `crates/api/src/routes/lifecycle.rs` hard-codes a thirty-day bin dwell and computes
/// `purge_after` from it alone, so a `KEEP_THEN_DELETE '7 years'` policy governs nothing on the
/// purge path today. This is the function that answers it, and the assertion is calendar
/// arithmetic: seven years after the file's `created_at`, not `created_at` plus 220 898 664
/// seconds.
///
/// Three answers in one run, because [`PurgeDeadline`] exists to keep them apart: a computable
/// deadline, an indefinite hold, and no retention at all. Collapsing the last two into `None` is the
/// bug that purges a file under a legal hold.
///
/// Fails when `+ $4` is removed from `DEADLINE_SQL` — the mutation used, which turns the deadline
/// into the basis instant itself. The differential assertion below closes the other half: it
/// asserts the answer is **not** `created_at + Duration::days(365 * 7)`, so a duration flattened
/// into days in Rust — the arithmetic `migrations/0031` says the `INTERVAL` column exists to avoid —
/// fails here rather than in seven years' time.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_purge_deadline_is_the_policys_duration_from_the_files_own_basis_instant() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");

    // A file on a schedule with an end.
    let scheduled = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let seven = policy(
        &mut conn,
        fx.alpha.id,
        "keep seven years then delete",
        RetentionAction::KeepThenDelete,
        Some("7 years"),
        false,
    )
    .await;
    assign(&mut conn, fx.alpha.id, seven, RetentionScopeType::File, Some(scheduled.file.as_uuid()))
        .await;

    // A file kept with no end.
    let forever = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;
    let indefinite =
        policy(&mut conn, fx.alpha.id, "keep, full stop", RetentionAction::Keep, None, false).await;
    assign(
        &mut conn,
        fx.alpha.id,
        indefinite,
        RetentionScopeType::File,
        Some(forever.file.as_uuid()),
    )
    .await;

    // A file nothing retains.
    let free = spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let expected: DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at + interval '7 years' FROM files WHERE tenant_id = $1 AND id = $2",
    )
    .bind(fx.alpha.id.as_uuid())
    .bind(scheduled.file.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("PostgreSQL's own calendar arithmetic");

    let mut tx =
        TenantScoped::begin(&pool, fx.alpha.id).await.expect("a tenant-scoped transaction");
    let scheduled_deadline =
        purge_deadline(&mut tx, scheduled.file).await.expect("a purge deadline");
    let forever_deadline = purge_deadline(&mut tx, forever.file).await.expect("a purge deadline");
    let free_deadline = purge_deadline(&mut tx, free.file).await.expect("a purge deadline");
    tx.commit().await.expect("commit the reads");

    assert_eq!(scheduled_deadline, PurgeDeadline::Until(expected));

    // The calendar, not a count of days. Seven years spans two leap days, so a duration flattened
    // into `365 * 7` days lands two days early — and two days early is a document destroyed two days
    // before it was permitted to be.
    let created_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT created_at FROM files WHERE tenant_id = $1 AND id = $2")
            .bind(fx.alpha.id.as_uuid())
            .bind(scheduled.file.as_uuid())
            .fetch_one(&mut conn)
            .await
            .expect("the file's own basis instant");
    let naive = created_at + Duration::days(365 * 7);
    assert_ne!(
        scheduled_deadline,
        PurgeDeadline::Until(naive),
        "the interval must be added by PostgreSQL; 365-day years land on the wrong date"
    );
    assert_eq!(
        forever_deadline,
        PurgeDeadline::Indefinite,
        "a KEEP with no duration is not a date"
    );
    assert_eq!(free_deadline, PurgeDeadline::Unretained, "no assignment covers this file at all");

    // What `lifecycle.rs` will do with them. The bin's dwell is a floor and never a ceiling.
    let dwell = Utc::now() + Duration::days(30);
    assert_eq!(scheduled_deadline.purge_after(dwell), Some(expected));
    assert_eq!(
        forever_deadline.purge_after(dwell),
        None,
        "an indefinite hold has no purge instant"
    );
    assert_eq!(free_deadline.purge_after(dwell), Some(dwell));
}

/// A `FileId` that names nothing is not an error and not a refusal.
///
/// Unknown, purged and another tenant's are one answer (`CLAUDE.md` rule 7). Retention has nothing
/// to say about a file it cannot resolve, and saying `RETENTION_BLOCKS_DELETE` about one would be a
/// statement that a policy exists — which is the fact `docs/06 §15` treats as sensitive in itself.
///
/// The control is a governed file in the same run, so "the unknown id was allowed" is not the
/// answer of a stage that allows everything.
///
/// Fails when `cascade_probes_on` treats an empty walk as an error, or when `first_refusal` refuses
/// on an empty probe set — the mutation used was returning `Some(..)` from `first_refusal` when the
/// probe list is empty.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_that_does_not_exist_is_neither_an_error_nor_a_refusal() {
    let (db, fx, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let governed = governed_spine(&mut conn, fx.alpha.id, fx.alpha.owner).await;

    let stage = PgRetention::new(pool);

    let nowhere = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, FileId::new_v7()),
    )
    .await;
    assert_allows(&nowhere, "an id that names no row");

    let refused = decide(
        &stage,
        fx.alpha.id,
        FileAction::Delete,
        ResourceRef::file(fx.alpha.id, governed.file),
    )
    .await;
    assert_blocks_delete(&refused, "a governed file in the same run");
}
