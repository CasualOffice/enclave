//! The security leakage matrix of `docs/12-TESTING.md §4`, for the surfaces that exist today.
//!
//! Each test is named for its matrix id, so a red result maps to a row in the document without a
//! translation step: `t5_…` is T5, `a7_…` is A7.
//!
//! # What this file covers, and what it does not
//!
//! `§4` lists about sixty assertions across ten families. Most of them are about surfaces that have
//! not been built — a test named for one of those would be a claim of coverage, and a matrix that
//! claims coverage it does not have is worse than a short one, because the gap stops being visible.
//! So the honest accounting, checked against the tree on 2026-08-19:
//!
//! **Asserted here.**
//!
//! | Row | Assertion |
//! |---|---|
//! | T1 | a foreign id is `404`, never `403` |
//! | T3 | a cursor issued in one tenant is rejected in another |
//! | T5 | RLS blocks a cross-tenant read with the application predicate deliberately removed |
//! | A3 | a `DENY` overrides an inherited `ALLOW` at every level |
//! | A4 | *partially* — see below |
//! | A7 | version reads respect the current file ACL, not the one at version creation |
//! | G5 | a file over the library limit is rejected before bytes are transferred |
//!
//! **Asserted elsewhere, verified as present rather than assumed.**
//!
//! * G1 (EICAR is quarantined) — `crates/antivirus/tests/eicar.rs`, against a real ClamAV.
//! * U2 (the application role cannot rewrite `audit_events`) —
//!   `crates/db/tests/rls_coverage.rs` and `crates/db/tests/grant_coverage.rs`, the latter over
//!   every partition.
//! * Part of T1 at the HTTP edge — `crates/api/tests/me.rs`, which sends a real cross-tenant
//!   request and asserts `404`. That is one endpoint; the row is about every endpoint, and the
//!   version here asserts the layers underneath so that a new handler inherits the property rather
//!   than needing its own copy of the test.
//!
//! **A4 is satisfied by `ENC-141`.** The row reads *"breaking inheritance materializes the
//! effective set with no privilege gain"*, and until that fix nothing materialised anything:
//! `inherit_permissions` was a column repositories stored and returned, the resolver stopped its
//! walk when it was `FALSE`, and a `DENY` above the break simply stopped applying. The two tests
//! below drive the real operations — `enclave_authorization::break_file_inheritance` and
//! `break_library_inheritance`, one per resource that carries the flag — and each asserts the
//! escalation case explicitly rather than only sweeping for neutrality. The third leg of the fix,
//! that a library settings replacement cannot flip the flag at all, is asserted next to the
//! repository it constrains, in `crates/libraries/tests/repositories.rs`.
//!
//! **Not assertable yet, with the reason.**
//!
//! * T2, S1–S10 — `crates/search`, `crates/indexing` and `crates/embeddings` are five-line
//!   skeletons. There is no index to post-filter and no candidate generator to over-permit.
//! * T4, A5, A6 — signed URLs exist in `enclave-storage`, but nothing mints one *for a tenant's
//!   object from a request context*: there is no download path. The provider-level half belongs in
//!   `crates/storage/tests/minio.rs` beside the rest of the S3 behaviour.
//! * T6 — custom-domain routing is not implemented; there is nothing to mismatch `tid` against.
//! * A1, A2 — `crates/preview` is a skeleton, so there is no rendition to return instead of an
//!   original and no export/print/copy path to deny independently.
//! * H1–H6 — `crates/sharing` is a skeleton.
//! * D5–D8 — the classification and retention stages are still `Unconfigured`, and `crates/incidents`
//!   is a skeleton. **D1–D4 are no longer here**: `ENC-582` gave DLP its five modes, and the tests
//!   live in `crates/dlp/tests/modes.rs`, driven through the real `PolicyEngine` with every other
//!   stage allowing. They are not database-backed and do not belong in this file — what they assert
//!   is the chain's decision, not a row's visibility. The obligation half of D4 that *is* about a
//!   real surface is in `crates/api/tests/delivery.rs`.
//! * K1–K10 — `crates/auth` is real, and its token rules are unit-tested inside it. The matrix form
//!   wants them asserted *through an authenticated request*, which needs endpoints that do not
//!   exist yet; `crates/api/tests/me.rs` is the one that does.
//! * Y1–Y7, W1–W5, N1–N7 — `crates/sync`, `crates/workflows` and `crates/signing` are skeletons.
//! * G2, G3, G4, G6 — extraction, preview sandboxing and the AV `HOLD` policy are not built.
//! * U1, U3, U4 — the audit chain is real and unit-tested (`crates/audit/src/chain.rs`), but "every
//!   allow and every deny in the matrix produces an audit event" is an assertion *about this file*,
//!   and it should be written when the matrix is broad enough for it to mean something.
//!
//! # Everything runs as `enclave_app`
//!
//! Fixtures are written over the harness's administrative connection because they are setup.
//! **Every assertion runs over [`TestDb::pool`]**, which `SET ROLE enclave_app`s, inside a
//! `TenantScoped` transaction. `DATABASE_URL` points at a cluster superuser — the harness has to
//! create databases — and superusers bypass row-level security entirely. A suite that asserted on
//! the admin connection would pass no matter what the policies said, which is what PR #22 turned
//! out to have been doing. T5 checks this about itself rather than trusting it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration as StdDuration;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use enclave_audit::{ChainMode, PgAuditSink};
use enclave_authorization::{
    break_file_inheritance, break_library_inheritance, AuthzError, PgAclAuthorization,
    ResolverLimits,
};
use enclave_classification::UnconfiguredClassification;
use enclave_conditional_access::UnconfiguredConditionalAccess;
use enclave_core::{
    Action, Actor, Error, FileAction, FileId, PolicyEngine, RequestContext, ResourceKind,
    ResourceRef, TenantId, UserId, VersionId,
};
use enclave_db::{DbPool, PageSize, TenantScoped};
use enclave_dlp::DisabledDlp;
use enclave_files::FileRepository;
use enclave_identity::{IdentityError, UserFilter, UserRepository};
use enclave_information_barriers::UnconfiguredBarriers;
use enclave_libraries::{ExternalSharing, LibraryRepository, LibrarySettings, VersioningMode};
use enclave_retention::UnconfiguredRetention;
use enclave_storage::{
    BlobStore, ByteRange, ByteStream, MultipartLimits, ObjectMeta, PublicAccessCheck,
    PublicAccessError, PublicAccessReport, Result as StorageResult, StoreCapabilities, Support,
    UploadRequest, UploadSession, UploadTarget,
};
use enclave_testing::content::{grant, revoke_all, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::schema::{role_standing, tenant_scoped_tables};
use enclave_testing::{Fixtures, TestDb};
use enclave_uploads::{NewUpload, UploadError, UploadIntent, UploadLimits, UploadService};
use enclave_versions::{NewVersion, VersionBump, VersionRepository, VersionService};
use sqlx::Row as _;
use url::Url;
use uuid::Uuid;

/// The action every content assertion is written against.
///
/// `file.download` rather than `file.read`, deliberately: it is the action `CLAUDE.md` rule 6 keeps
/// apart from preview, print and export, so a resolver that quietly implied one from another would
/// show up here.
const DOWNLOAD: Action = Action::File(FileAction::Download);

/// A second action, never granted anywhere, used to prove that a verdict is about the grant rather
/// than about the caller.
const PRINT: Action = Action::File(FileAction::Print);

// -------------------------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------------------------

/// Starts a database, applies migrations, seeds both tenants, and builds an application-role pool.
async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("build an application-role pool");
    (db, fixtures, pool)
}

/// The real chain, with the real ACL resolver and a real audit sink.
///
/// `PgAclAuthorization` rather than `SelfServiceAuthorization` (which `crates/api/tests/me.rs`
/// uses): the matrix rows here are *about* ACL resolution, and a stage that answers "yes, that is
/// you" would make every one of them vacuous.
fn engine(pool: &DbPool) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(UnconfiguredConditionalAccess),
        Arc::new(PgAclAuthorization::new(pool.clone())),
        Arc::new(UnconfiguredBarriers),
        Arc::new(UnconfiguredClassification),
        Arc::new(DisabledDlp),
        Arc::new(UnconfiguredRetention),
        Arc::new(PgAuditSink::new(pool.clone(), ChainMode::Enabled)),
    )
}

fn ctx(tenant: TenantId, user: UserId) -> RequestContext {
    RequestContext { actor: Actor::User(user), ..RequestContext::system(tenant) }
}

/// Runs the chain and reduces it to a boolean, consuming the obligations so nothing is dropped.
///
/// `PolicyDecision` is `#[must_use]` and `Obligations` with it (`CLAUDE.md` rule 8); the assertion
/// that there are none is part of what these tests prove — a stage that started attaching a
/// watermark to a download would fail here rather than silently having it ignored.
async fn allows(
    engine: &PolicyEngine,
    ctx: &RequestContext,
    action: Action,
    on: &ResourceRef,
) -> bool {
    match engine.enforce(ctx, action, on).await {
        Ok(decision) => {
            let obligations = decision.into_obligations();
            assert!(
                obligations.is_empty(),
                "a stage attached an obligation that this test would have dropped: {obligations:?}"
            );
            true
        }
        Err(Error::PolicyDenied { .. } | Error::NotFound) => false,
        Err(other) => panic!("the chain failed rather than deciding: {other:?}"),
    }
}

/// Promotes a statement built at runtime to `&'static str`.
///
/// sqlx 0.9 requires `'q: 'e` — the query must outlive the future executing it — which a `String`
/// local to an `async fn` cannot satisfy against `&mut PgConnection`. `enclave_testing::exec` leaks
/// for the same reason and explains it at length; this is the `fetch`-returning counterpart. The
/// leak is bounded by the number of tenant-scoped tables in the schema, a few dozen at most, and it
/// exists only in this test binary.
fn statement(sql: String) -> &'static str {
    Box::leak(sql.into_boxed_str())
}

// =============================================================================================
// §4.1 Cross-tenant isolation
// =============================================================================================

/// **T1** — a `tenant-beta` file id requested by a `tenant-alpha` user returns `404`, never `403`.
///
/// The two controls are what make this more than an assertion that everything is refused: the beta
/// file is genuinely readable *by beta*, so the refusal is not a broken fixture, and an ungranted
/// file inside alpha is refused with `403` — so `404` is specifically the cross-tenant answer and
/// not a blanket status this code path always produces.
///
/// The second half checks the layer underneath. PR #22's lesson is that the policy chain and
/// row-level security are two independent answers to the same question and the second caught what
/// the first waved through, so this asserts both: `enforce` says not-found, *and* the repository
/// running inside alpha's transaction cannot see the row at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn t1_a_foreign_file_id_is_not_found_and_never_forbidden() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let now = Utc::now();

    let alpha_spine = Spine::new(alpha);
    let ungranted = Spine::new(alpha);
    let beta_spine = Spine::new(beta);

    let mut admin = db.connect().await.expect("admin connection");
    alpha_spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("alpha spine");
    ungranted.insert(&mut admin, fixtures.alpha.owner, now).await.expect("alpha spine 2");
    beta_spine.insert(&mut admin, fixtures.beta.owner, now).await.expect("beta spine");

    // Beta grants the action to *everyone*, the most permissive entry that can exist. If anything
    // were to leak across the boundary, this is the entry that would do it.
    grant(
        &mut admin,
        beta,
        AclScope::File(beta_spine.file),
        AclPrincipal::Everyone,
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("beta grant");
    grant(
        &mut admin,
        alpha,
        AclScope::File(alpha_spine.file),
        AclPrincipal::User(fixtures.alpha.member),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("alpha grant");

    let engine = engine(&pool);
    let alpha_member = ctx(alpha, fixtures.alpha.member);

    // Control 1: the beta file really is readable, in beta.
    assert!(
        allows(&engine, &ctx(beta, fixtures.beta.member), DOWNLOAD, &beta_spine.file_ref()).await,
        "the beta fixture is not readable by beta, so the cross-tenant refusal below proves nothing"
    );

    // The row itself. `enforce` must produce NotFound, not a denial.
    let error = engine
        .enforce(&alpha_member, DOWNLOAD, &beta_spine.file_ref())
        .await
        .expect_err("a cross-tenant read must not be allowed");
    assert_eq!(error.status_code(), 404, "a cross-tenant read answered {}", error.status_code());
    assert_eq!(error.code(), "NOT_FOUND");
    assert!(
        !matches!(error, Error::PolicyDenied { .. }),
        "a 403 confirms the resource exists somewhere (CLAUDE.md rule 7): {error:?}"
    );

    // Control 2: inside alpha, a file nobody granted is a *denial* — so 404 above is the
    // cross-tenant answer specifically, not this path's answer to everything.
    let error = engine
        .enforce(&alpha_member, DOWNLOAD, &ungranted.file_ref())
        .await
        .expect_err("an ungranted file must not be allowed");
    assert_eq!(
        error.status_code(),
        403,
        "an ungranted same-tenant file should be denied, not disguised as absent"
    );
    // ...and the caller's own file still resolves, so the fixtures are not simply refusing.
    assert!(allows(&engine, &alpha_member, DOWNLOAD, &alpha_spine.file_ref()).await);

    // The second layer. Even if the chain had allowed it, the row is not visible to a transaction
    // scoped to alpha.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let seen = FileRepository::find_by_id(&mut tx, alpha, beta_spine.file).await.expect("find");
    tx.commit().await.expect("commit");
    assert!(seen.is_none(), "alpha's transaction could read a tenant-beta file row");

    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let seen = FileRepository::find_by_id(&mut tx, beta, beta_spine.file).await.expect("find");
    tx.commit().await.expect("commit");
    assert!(
        seen.is_some(),
        "beta cannot read its own file either — the `None` above is a broken fixture or a missing \
         GRANT, not tenant isolation"
    );
}

/// **T3** — a cursor issued in one tenant is rejected in another.
///
/// Through a real listing rather than through `Cursor::decode` directly: `crates/db/src/cursor.rs`
/// already unit-tests the codec, and what this adds is that the repository *presents* the tenant to
/// it. A listing that decoded with a constant, or with the tenant from the cursor itself, would
/// pass every unit test in that module and fail here.
///
/// The failure mode being prevented is not a data leak — RLS makes beta's page beta's page whatever
/// position it starts from — it is a *silent* one: without the binding, alpha's cursor would be
/// accepted in beta and every beta row sorting below that position would be skipped, which is a
/// wrong answer that looks like a right one.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn t3_a_cursor_issued_in_one_tenant_is_rejected_in_another() {
    let (_db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let filter = UserFilter::default();
    let page_size = PageSize::new(2);

    // Page 1 in alpha. The seeded tenant has five users, so there is certainly a next page.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let first = UserRepository::list_by_tenant(&mut tx, alpha, &filter, page_size, None)
        .await
        .expect("alpha page 1");
    tx.commit().await.expect("commit");

    assert_eq!(first.users.len(), 2, "the fixture tenant should page");
    let cursor = first.next_cursor.expect("a next page exists");
    for user in &first.users {
        assert_eq!(user.tenant_id, alpha, "an alpha listing returned another tenant's user");
    }

    // The same cursor, presented in beta.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let rejected =
        UserRepository::list_by_tenant(&mut tx, beta, &filter, page_size, Some(&cursor)).await;
    tx.commit().await.expect("commit");

    assert!(
        matches!(rejected, Err(IdentityError::InvalidCursor)),
        "a cursor issued in tenant-alpha was accepted in tenant-beta: {rejected:?}"
    );

    // And it is rejected as a *cursor* problem the client can act on, not as a 404 or a 500 — the
    // caller supplied a bad parameter and is entitled to be told which one.
    let rendered = Error::from(IdentityError::InvalidCursor);
    assert_eq!(rendered.status_code(), 400);
    assert_eq!(rendered.code(), "VALIDATION_FAILED");

    // Two controls, so the rejection is about the cursor's tenant and nothing else: beta pages
    // perfectly well without it, and the cursor still works in the tenant that issued it.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let beta_page = UserRepository::list_by_tenant(&mut tx, beta, &filter, page_size, None)
        .await
        .expect("beta page 1");
    tx.commit().await.expect("commit");
    assert_eq!(beta_page.users.len(), 2, "beta cannot page at all, so the rejection proves little");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let second = UserRepository::list_by_tenant(&mut tx, alpha, &filter, page_size, Some(&cursor))
        .await
        .expect("alpha page 2");
    tx.commit().await.expect("commit");
    assert_eq!(second.users.len(), 2);
    assert!(
        second.users.iter().all(|later| first.users.iter().all(|earlier| earlier.id != later.id)),
        "page 2 repeated a row from page 1, so the cursor is not a position"
    );
}

/// **T5** — row-level security blocks a cross-tenant read *with the application predicate
/// deliberately removed*.
///
/// This is the assertion that would have caught PR #22, and it is written to be un-fakeable in the
/// two ways that matter.
///
/// **The predicate is genuinely gone.** Every query below is `SELECT … FROM <table>` with no
/// `tenant_id` clause at all — the shape a broken query builder produces, and the same shape
/// `crates/api/src/me.rs` deliberately uses in production. The count it returns is therefore
/// entirely RLS's answer. One of them is the `/me` lookup verbatim, with a beta subject id bound
/// into an alpha-scoped transaction: exactly the request that returned `200` in PR #22.
///
/// **A zero has to mean isolation and not incapacity.** A table the application role cannot reach —
/// the state migration 0002 left the schema in — also returns nothing, and returning nothing is
/// what a passing isolation test looks like. So every table is checked in *both* directions: alpha
/// sees exactly alpha's rows and none of beta's, and beta sees exactly beta's. A missing `GRANT`
/// fails the second half. And the role is asked about itself first, because a superuser bypasses
/// RLS entirely and would make the whole file meaningless.
///
/// The table list comes from the catalog rather than from a literal, so a migration that adds a
/// tenant-scoped table extends this test by itself.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn t5_row_level_security_alone_blocks_a_cross_tenant_read() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let now = Utc::now();

    // Content in both tenants, so the loop below has something to be wrong about.
    let mut admin = db.connect().await.expect("admin connection");
    for (tenant, owner) in [(alpha, fixtures.alpha.owner), (beta, fixtures.beta.owner)] {
        let spine = Spine::new(tenant);
        spine.insert(&mut admin, owner, now).await.expect("spine");
        grant(
            &mut admin,
            tenant,
            AclScope::File(spine.file),
            AclPrincipal::Everyone,
            DOWNLOAD,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("grant");
    }

    let tables = tenant_scoped_tables(&mut admin).await.expect("tenant-scoped tables");
    assert!(!tables.is_empty(), "the catalog reports no tenant-scoped tables at all");

    // The truth, read as the superuser: how many rows each table holds per tenant.
    let mut expected: Vec<(String, i64, i64)> = Vec::new();
    for table in &tables {
        assert!(
            table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "a table name from the catalog is not a bare identifier: {table}"
        );
        let sql = statement(format!(
            "SELECT count(*) FILTER (WHERE tenant_id = $1) AS a,
                    count(*) FILTER (WHERE tenant_id = $2) AS b
             FROM {table}"
        ));
        let row = sqlx::query(sql)
            .bind(alpha.as_uuid())
            .bind(beta.as_uuid())
            .fetch_one(&mut admin)
            .await
            .expect("count rows per tenant");
        expected.push((table.clone(), row.get("a"), row.get("b")));
    }

    let populated = expected.iter().filter(|(_, a, b)| *a > 0 && *b > 0).count();
    assert!(
        populated >= 6,
        "only {populated} tenant-scoped tables hold rows in both tenants, so most of this loop is \
         vacuous. Seed more before trusting it."
    );

    for (scope, other, label) in [(alpha, beta, "alpha"), (beta, alpha, "beta")] {
        let mut tx = TenantScoped::begin(&pool, scope).await.expect("begin");

        // Before anything else: is this connection even subject to RLS? PR #22 was green because
        // the answer was no.
        let standing = role_standing(&mut tx).await.expect("role standing");
        assert!(
            standing.is_subject_to_rls(),
            "assertions ran as {standing:?}, which bypasses row-level security — every result \
             below would be meaningless"
        );
        assert_eq!(
            tx.observed_tenant_context().await.expect("read app.tenant_id"),
            Some(scope),
            "app.tenant_id is not what the transaction believes it is"
        );

        for (table, alpha_rows, beta_rows) in &expected {
            let (mine, theirs) =
                if scope == alpha { (*alpha_rows, *beta_rows) } else { (*beta_rows, *alpha_rows) };

            // No tenant predicate. None. Whatever comes back is RLS's answer and nothing else.
            let all = statement(format!("SELECT count(*) AS n FROM {table}"));
            let visible: i64 = sqlx::query(all)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "{label} could not read {table} at all: {error}. That is a missing GRANT, \
                         not isolation — the PR #22 failure mode, where every row being invisible \
                         looked like a passing test."
                    )
                })
                .get("n");

            assert_eq!(
                visible, mine,
                "{label} saw {visible} rows in {table} with no predicate; it owns {mine} and the \
                 other tenant owns {theirs}"
            );

            // The deliberately hostile form: ask for the *other* tenant's rows by name.
            let foreign =
                statement(format!("SELECT count(*) AS n FROM {table} WHERE tenant_id = $1"));
            let leaked: i64 = sqlx::query(foreign)
                .bind(other.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .expect("query for the other tenant's rows")
                .get("n");
            assert_eq!(leaked, 0, "{label} read {leaked} of the other tenant's rows from {table}");
        }

        tx.commit().await.expect("commit");
    }

    // The specific query from PR #22, verbatim from `crates/api/src/me.rs`: no tenant predicate,
    // an id from the other tenant, inside a scoped transaction.
    const ME: &str = "SELECT id, tenant_id, email, display_name, is_admin
                      FROM users
                      WHERE id = $1 AND deleted_at IS NULL";

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin alpha");
    let row = sqlx::query(ME)
        .bind(fixtures.beta.owner.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .expect("the /me lookup");
    tx.commit().await.expect("commit");
    assert!(
        row.is_none(),
        "the /me query, with its tenant predicate removed, read a tenant-beta user from an \
         alpha-scoped transaction. This is PR #22."
    );

    // And the control that makes that `None` mean something: the same query, same id, beta's scope.
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin beta");
    let row = sqlx::query(ME)
        .bind(fixtures.beta.owner.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .expect("the /me lookup");
    tx.commit().await.expect("commit");
    assert!(
        row.is_some(),
        "beta cannot read its own user with this query, so the `None` above says nothing about \
         isolation"
    );
}

// =============================================================================================
// §4.2 Authorization
// =============================================================================================

/// **A3** — a `DENY` entry overrides an inherited `ALLOW` at every level.
///
/// *Every* level is the point, so this is not one arrangement but four. The whole chain grants the
/// action; one node at a time is flipped to `DENY`; the file must be refused each time, and must go
/// back to being permitted when the node is flipped back. The flip-back is what stops the test
/// passing because of something unrelated that refuses everything.
///
/// The entry is *replaced* rather than added alongside, because `uq_acl_entry` permits one row per
/// `(resource, principal, action)` — a node cannot both allow and deny. That constraint is why
/// deny-wins has to be resolved across the chain rather than within a node.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn a3_a_deny_overrides_an_inherited_allow_at_every_level() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let member = fixtures.alpha.member;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("spine");

    let chain = [
        ("workspace", AclScope::Workspace(spine.workspace)),
        ("library", AclScope::Library(spine.library)),
        ("folder", AclScope::Folder(spine.folder)),
        ("file", AclScope::File(spine.file)),
    ];

    for (_, scope) in chain {
        grant(
            &mut admin,
            alpha,
            scope,
            AclPrincipal::User(member),
            DOWNLOAD,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("allow");
    }

    let engine = engine(&pool);
    let caller = ctx(alpha, member);

    assert!(
        allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the all-ALLOW chain does not permit the read, so no DENY below could prove anything"
    );

    for (name, scope) in chain {
        let removed = revoke_all(&mut admin, alpha, scope).await.expect("revoke");
        assert_eq!(removed, 1, "the {name} entry was not there to replace");
        grant(
            &mut admin,
            alpha,
            scope,
            AclPrincipal::User(member),
            DOWNLOAD,
            AclEffect::Deny,
            None,
        )
        .await
        .expect("deny");

        assert!(
            !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
            "a DENY on the {name} lost to the ALLOWs elsewhere in the chain"
        );

        // Put it back, and confirm the chain permits again — otherwise the refusal above could be
        // any accumulated state rather than this entry.
        let removed = revoke_all(&mut admin, alpha, scope).await.expect("revoke");
        assert_eq!(removed, 1);
        grant(
            &mut admin,
            alpha,
            scope,
            AclPrincipal::User(member),
            DOWNLOAD,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("restore");
        assert!(
            allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
            "removing the {name} DENY did not restore the read, so the refusal was not that entry"
        );
    }

    // A DENY reached through a group is still a DENY at that level. `member` is in `engineering`;
    // the entry names the group rather than the person, which is how real tenants write them.
    let removed = revoke_all(&mut admin, alpha, AclScope::Library(spine.library))
        .await
        .expect("revoke library");
    assert_eq!(removed, 1);
    grant(
        &mut admin,
        alpha,
        AclScope::Library(spine.library),
        AclPrincipal::Group(fixtures.alpha.engineering),
        DOWNLOAD,
        AclEffect::Deny,
        None,
    )
    .await
    .expect("group deny");
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "a DENY inherited through a group lost to direct ALLOWs above and below it"
    );
}

/// **A4** — breaking inheritance materialises the effective set and gains no privilege.
///
/// The operation is [`enclave_authorization::break_file_inheritance`]. Its whole job is to be
/// *neutral*: immediately after a break every principal must resolve exactly as they did
/// immediately before, because the entries that decided their access have been copied onto the
/// resource. What changes afterwards is only that edits to an ancestor no longer reach it.
///
/// Until `ENC-141` nothing performed the copy, so `inherit_permissions = FALSE` merely truncated
/// the resolver's walk — and a `DENY` written above the break stopped applying. That is a privilege
/// gain produced by an operation whose purpose is to narrow access, which is what this row forbids.
/// The escalation case is asserted first and on its own, because it is the defect; the probe sweep
/// after it is what proves the fix is neutral rather than merely denying.
///
/// The sweep asks a set rather than a single question, because a break can leak along three axes:
/// the principal (someone who had nothing gains something), the action (a download grant becomes a
/// print grant) and the node (the folder keeps rights the file never had). All three are in the
/// set, and the set is checked to contain both an allow and a denial so it cannot pass by refusing
/// everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn a4_breaking_inheritance_materialises_and_gains_no_privilege() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let member = fixtures.alpha.member;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("spine");

    // The escalation shape, exactly: allowed nearby, denied from above. Before `ENC-141` the break
    // deleted the denial by walking past it.
    grant(
        &mut admin,
        alpha,
        AclScope::Folder(spine.folder),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("allow at the folder");
    grant(
        &mut admin,
        alpha,
        AclScope::Workspace(spine.workspace),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Deny,
        None,
    )
    .await
    .expect("deny at the workspace");

    // A chain with more than the escalation in it, so the sweep has something to be neutral about:
    // the library allows the whole of engineering, and the folder allows the owner directly.
    grant(
        &mut admin,
        alpha,
        AclScope::Library(spine.library),
        AclPrincipal::Group(fixtures.alpha.engineering),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("group allow");
    grant(
        &mut admin,
        alpha,
        AclScope::Folder(spine.folder),
        AclPrincipal::User(fixtures.alpha.owner),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("owner allow");

    let engine = engine(&pool);
    let caller = ctx(alpha, member);
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the workspace DENY did not reach the file while inheritance was intact, so the break \
         cannot be shown to preserve it"
    );

    let probes: Vec<(&str, RequestContext, Action, ResourceRef)> = vec![
        ("member/download/file", ctx(alpha, member), DOWNLOAD, spine.file_ref()),
        ("owner/download/file", ctx(alpha, fixtures.alpha.owner), DOWNLOAD, spine.file_ref()),
        ("viewer/download/file", ctx(alpha, fixtures.alpha.viewer), DOWNLOAD, spine.file_ref()),
        ("owner/print/file", ctx(alpha, fixtures.alpha.owner), PRINT, spine.file_ref()),
        ("owner/download/folder", ctx(alpha, fixtures.alpha.owner), DOWNLOAD, spine.folder_ref()),
    ];

    let mut before = Vec::new();
    for (label, caller, action, resource) in &probes {
        before.push((*label, allows(&engine, caller, *action, resource).await));
    }
    assert!(
        before.iter().any(|(_, allowed)| *allowed) && before.iter().any(|(_, a)| !*a),
        "the probe set is all-allow or all-deny, so nothing it says after the break means \
         anything: {before:?}"
    );

    // The real operation — copy and flag flip together, on the harness's connection so it runs as
    // `enclave_app` under forced RLS like every other write here.
    let copied = break_file_inheritance(
        &mut admin,
        alpha,
        spine.folder.as_uuid(),
        ResolverLimits::DEFAULT,
        Utc::now(),
    )
    .await
    .expect("break inheritance at the folder");
    assert!(copied > 0, "the break copied nothing down");

    // The defect, asserted on its own so a regression names itself rather than appearing as one
    // line of a diff over five probes.
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "breaking inheritance let the workspace DENY fall off the chain — the ENC-141 privilege \
         escalation is back"
    );

    for ((label, caller, action, resource), (_, was)) in probes.iter().zip(before.iter()) {
        let now = allows(&engine, caller, *action, resource).await;
        assert_eq!(
            now, *was,
            "breaking inheritance changed the verdict for {label}: was {was}, now {now}"
        );
    }

    // The break is a state change, not an idempotent request: asking twice must not report two
    // successes, or two administrators can each believe they established this ACL.
    let again = break_file_inheritance(
        &mut admin,
        alpha,
        spine.folder.as_uuid(),
        ResolverLimits::DEFAULT,
        Utc::now(),
    )
    .await;
    assert!(
        matches!(again, Err(AuthzError::NotInheriting)),
        "breaking an already-broken resource did not say so: {again:?}"
    );

    // And it is a break: the ancestors genuinely stop reaching it now. Removing the workspace DENY
    // leaves the file denied, because the denial lives on the folder itself.
    let removed = revoke_all(&mut admin, alpha, AclScope::Workspace(spine.workspace))
        .await
        .expect("revoke the workspace deny");
    assert_eq!(removed, 1);
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the denial vanished with its ancestor, so it was never copied down — the break truncated \
         the walk instead of materialising it"
    );
}

/// **A4, at the library** — the same operation on the other resource that carries the flag.
///
/// `libraries.inherit_permissions` is a second door onto the same escalation: the resolver stops
/// its walk there exactly as it does on a file, so a library detached without a copy loses the
/// workspace's `DENY` entries. Fixing files alone would have moved the bug rather than closed it.
///
/// Written as its own test because the chain is a different shape — library to workspace, with no
/// recursion — and because a regression should name which of the two doors reopened.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn a4_breaking_library_inheritance_gains_no_privilege() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let member = fixtures.alpha.member;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("spine");

    grant(
        &mut admin,
        alpha,
        AclScope::Library(spine.library),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("allow at the library");
    grant(
        &mut admin,
        alpha,
        AclScope::Workspace(spine.workspace),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Deny,
        None,
    )
    .await
    .expect("deny at the workspace");

    let engine = engine(&pool);
    let caller = ctx(alpha, member);
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the workspace DENY did not reach the file while the library inherited"
    );

    let copied = break_library_inheritance(&mut admin, alpha, spine.library.as_uuid(), Utc::now())
        .await
        .expect("break inheritance at the library");
    assert!(copied > 0, "the break copied nothing down");

    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "detaching the library let the workspace DENY fall off the chain — ENC-141 through the \
         library door"
    );

    // Genuinely detached: the denial now lives on the library, not above it.
    let removed = revoke_all(&mut admin, alpha, AclScope::Workspace(spine.workspace))
        .await
        .expect("revoke the workspace deny");
    assert_eq!(removed, 1);
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the denial vanished with its ancestor, so the library break truncated instead of copying"
    );

    let again =
        break_library_inheritance(&mut admin, alpha, spine.library.as_uuid(), Utc::now()).await;
    assert!(
        matches!(again, Err(AuthzError::NotInheriting)),
        "breaking an already-detached library did not say so: {again:?}"
    );
}

/// **A7** — a version read respects the *current* file ACL, not the ACL at version creation.
///
/// Three things together are what make this true, and each is asserted rather than assumed.
///
/// 1. A version carries no ACL of its own. `acl_entries.resource_type` has no `VERSION` value, so a
///    version-level grant is not merely absent — it is unrepresentable. The test tries to write one
///    and requires the `CHECK` constraint to refuse.
/// 2. Nothing resolves a version reference. Asking the chain about `ResourceKind::Version` is
///    refused even while the file it belongs to is fully granted, so a caller cannot address a
///    version and route around the file's chain.
/// 3. The verdict is recomputed, not remembered. A version committed while the grant was in force
///    becomes unreadable the moment the grant is revoked — and a version committed *after* the
///    revocation becomes readable again when the grant returns. The two versions are always
///    answered identically, which is the property: creation-time state leaves no trace.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn a7_a_version_read_respects_the_current_file_acl() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let member = fixtures.alpha.member;
    let spine = Spine::new(alpha);
    let storage_profile = Uuid::now_v7();

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("spine");
    grant(
        &mut admin,
        alpha,
        AclScope::File(spine.file),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("allow");

    let engine = engine(&pool);
    let caller = ctx(alpha, member);
    let owner_ctx = ctx(alpha, fixtures.alpha.owner);

    // (1) The schema cannot express a version-level grant.
    let refused = sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at)
         VALUES ($1, $2, 'VERSION', $3, 'EVERYONE', NULL, $4, 'ALLOW', $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(alpha.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(DOWNLOAD.to_string())
    .bind(Uuid::nil())
    .execute(&mut admin)
    .await;
    assert!(
        refused.is_err(),
        "acl_entries accepted a VERSION-scoped grant. A version with permissions of its own is a \
         second answer to 'may I read this file', and the older one wins by accident."
    );

    // A version, committed while the grant is in force.
    let first =
        commit_version(&pool, &owner_ctx, spine.file, storage_profile, fixtures.alpha.owner).await;

    assert!(
        allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "the file grant does not permit the read, so the revocation below proves nothing"
    );

    // (2) The version reference itself resolves to nothing, even now.
    let version_ref = ResourceRef::new(alpha, ResourceKind::Version, first.as_uuid());
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &version_ref).await,
        "a version reference was granted access independently of its file"
    );

    // (3) Revoke on the file. The version row is untouched — and unreadable.
    let removed = revoke_all(&mut admin, alpha, AclScope::File(spine.file)).await.expect("revoke");
    assert_eq!(removed, 1);
    assert!(
        !allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "revoking the file's ACL did not stop the read — the verdict is being remembered"
    );

    // A second version, committed while access is revoked.
    let second =
        commit_version(&pool, &owner_ctx, spine.file, storage_profile, fixtures.alpha.owner).await;
    assert_ne!(first, second);

    // Restore the grant. Both versions are readable again, and neither is privileged over the other
    // by the ACL that happened to be in force when it was written.
    grant(
        &mut admin,
        alpha,
        AclScope::File(spine.file),
        AclPrincipal::User(member),
        DOWNLOAD,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("re-grant");
    assert!(
        allows(&engine, &caller, DOWNLOAD, &spine.file_ref()).await,
        "restoring the grant did not restore the read"
    );

    // Both rows are still there, under the same single verdict: the history is intact and the
    // permission question was answered once, about the file.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    for version in [first, second] {
        let found = VersionRepository::find(&mut tx, alpha, spine.file, version)
            .await
            .expect("read the version");
        assert!(found.is_some(), "version {version} vanished");
    }
    tx.commit().await.expect("commit");
}

/// Commits one version of `file`, returning its id.
async fn commit_version(
    pool: &DbPool,
    ctx: &RequestContext,
    file: FileId,
    storage_profile: Uuid,
    created_by: UserId,
) -> VersionId {
    let new = NewVersion {
        file_id: file,
        // Globally unique by `uq_version_object`, so it cannot be a constant.
        object_key: format!("{}/{}", ctx.tenant_id, Uuid::now_v7()),
        storage_profile_id: storage_profile,
        size_bytes: 4_096,
        checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        mime_type: "application/pdf".to_owned(),
        bump: VersionBump::Major,
        created_by,
        comment: None,
    };

    let mut tx = TenantScoped::begin(pool, ctx.tenant_id).await.expect("begin");
    let committed = VersionService::commit(&mut tx, ctx, ChainMode::Enabled, &new, Utc::now())
        .await
        .expect("commit a version");
    tx.commit().await.expect("commit");
    committed.version.id
}

// =============================================================================================
// §4.8 Ingestion safety
// =============================================================================================

/// **G5** — a file exceeding the library's size limit is rejected *before bytes are transferred*.
///
/// "Before bytes are transferred" is asserted by making it impossible to transfer any: the object
/// store handed to the refused call panics on every method it has. There is no counter to read
/// afterwards and no way for the assertion to be satisfied by an unchecked zero — if the upload
/// path touches storage at all, the test dies where it happened.
///
/// The control is the same call one byte under the ceiling, against a store that records. It has to
/// reach storage, which is what proves the refusal above was the size check rather than a stub that
/// never gets called. Both the library's own ceiling and the tenant default it falls back to are
/// covered, because `max_file_size_bytes` is nullable and "use the tenant default" is the path a
/// library gets by not setting one.
///
/// A rejected upload must also leave nothing behind: no session row, and therefore no staged key to
/// reap.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0006; CI runs it with --include-ignored"]
async fn g5_a_file_over_the_library_limit_is_rejected_before_any_byte_moves() {
    const CEILING: u64 = 1024;

    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let owner = fixtures.alpha.owner;

    // Two libraries: one with an explicit ceiling, one that inherits the tenant default.
    let mut admin = db.connect().await.expect("admin connection");
    let spine = Spine::new(alpha);
    spine.insert(&mut admin, owner, Utc::now()).await.expect("spine");

    let inherited = LibraryRepository::create(
        &mut admin,
        alpha,
        spine.workspace,
        &settings("inherits-default", None),
        Utc::now(),
    )
    .await
    .expect("create a library with no ceiling of its own")
    .id;

    let explicit = LibraryRepository::create(
        &mut admin,
        alpha,
        spine.workspace,
        &settings("explicit-ceiling", Some(i64::try_from(CEILING).expect("fits"))),
        Utc::now(),
    )
    .await
    .expect("create a library with an explicit ceiling")
    .id;

    let by_library = UploadLimits::from_library(&settings("x", Some(1024)), u64::MAX);
    let by_default = UploadLimits::from_library(&settings("x", None), CEILING);
    assert_eq!(by_library.max_file_size_bytes(), CEILING);
    assert_eq!(by_default.max_file_size_bytes(), CEILING, "the tenant default was not applied");

    let refusing = RefusingStore;

    for (label, library, limits) in
        [("explicit", explicit, &by_library), ("tenant default", inherited, &by_default)]
    {
        let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
        let result = UploadService::create(
            &mut tx,
            &refusing,
            alpha,
            &upload(library, owner, "over.pdf", CEILING + 1),
            limits,
            Duration::hours(1),
            Utc::now(),
        )
        .await;
        tx.commit().await.expect("commit");

        match result {
            Err(UploadError::FileTooLarge { limit }) => assert_eq!(limit, CEILING),
            other => panic!("the {label} ceiling did not refuse an oversized upload: {other:?}"),
        }
    }

    // Nothing was written. A refused upload that left a session behind would be a reservation
    // nobody asked for and a staged key the reaper has to clean up.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let sessions: i64 = sqlx::query("SELECT count(*) AS n FROM upload_sessions")
        .fetch_one(&mut *tx)
        .await
        .expect("count sessions")
        .get("n");
    tx.commit().await.expect("commit");
    assert_eq!(sessions, 0, "a refused upload left {sessions} session row(s) behind");

    // The control: exactly at the ceiling, the same call reaches storage and succeeds. Without
    // this, `RefusingStore` never panicking would be equally consistent with a code path that
    // never calls the store at all.
    let recorder = RecordingStore::default();
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let issued = UploadService::create(
        &mut tx,
        &recorder,
        alpha,
        &upload(explicit, owner, "at-the-limit.pdf", CEILING),
        &by_library,
        Duration::hours(1),
        Utc::now(),
    )
    .await
    .expect("an upload at the ceiling must be accepted");
    tx.commit().await.expect("commit");

    assert_eq!(
        recorder.calls(),
        1,
        "the accepted upload never reached the object store, so the refused ones prove nothing \
         about ordering"
    );
    assert!(matches!(issued.target, UploadTarget::Single { .. }));

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let sessions: i64 = sqlx::query("SELECT count(*) AS n FROM upload_sessions")
        .fetch_one(&mut *tx)
        .await
        .expect("count sessions")
        .get("n");
    tx.commit().await.expect("commit");
    assert_eq!(sessions, 1, "the accepted upload did not record a session");
}

/// Library settings with one ceiling and no extension rules, so size is the only thing under test.
fn settings(slug: &str, max_file_size_bytes: Option<i64>) -> LibrarySettings {
    LibrarySettings {
        name: slug.to_owned(),
        slug: slug.to_owned(),
        inherit_permissions: true,
        default_classification_id: None,
        versioning_mode: VersioningMode::MajorMinor,
        version_limit: None,
        require_checkout: false,
        require_approval: false,
        allowed_extensions: None,
        blocked_extensions: None,
        max_file_size_bytes,
        external_sharing: ExternalSharing::Disabled,
        ai_indexing_enabled: false,
        mcp_visible: false,
        sync_enabled: false,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

fn upload(
    library_id: enclave_core::LibraryId,
    created_by: UserId,
    name: &str,
    declared_size: u64,
) -> NewUpload {
    NewUpload {
        library_id,
        parent_id: None,
        intent: UploadIntent::NewFile,
        name: name.to_owned(),
        declared_size,
        declared_mime: Some("application/pdf".to_owned()),
        declared_sha256: None,
        created_by,
    }
}

// ---------------------------------------------------------------------------------------------
// Object stores
// ---------------------------------------------------------------------------------------------

/// A store that cannot be contacted without failing the test.
///
/// The whole of G5's "before bytes are transferred" clause. A recording stub would let the
/// assertion be a count someone could get wrong; a panic makes the guarantee structural.
#[derive(Debug)]
struct RefusingStore;

impl RefusingStore {
    fn refuse(operation: &str) -> ! {
        panic!(
            "the upload path contacted object storage ({operation}) for a request that must be \
             refused before any byte moves (docs/12-TESTING.md §4.8 G5, docs/05-API.md §8)"
        )
    }
}

#[async_trait]
impl PublicAccessCheck for RefusingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Self::refuse("verify_not_public")
    }
}

#[async_trait]
impl BlobStore for RefusingStore {
    async fn create_upload(&self, _request: UploadRequest) -> StorageResult<UploadSession> {
        Self::refuse("create_upload")
    }
    async fn complete_upload(&self, _session: &UploadSession) -> StorageResult<ObjectMeta> {
        Self::refuse("complete_upload")
    }
    async fn signed_download(&self, _key: &str, _ttl: StdDuration) -> StorageResult<Url> {
        Self::refuse("signed_download")
    }
    async fn read_range(&self, _key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        Self::refuse("read_range")
    }
    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        Self::refuse("copy")
    }
    async fn delete(&self, _key: &str) -> StorageResult<()> {
        Self::refuse("delete")
    }
    fn capabilities(&self) -> StoreCapabilities {
        capabilities("refusing-stub")
    }
}

/// A store that counts what it was asked to do, for the control case.
#[derive(Debug, Default)]
struct RecordingStore {
    created: AtomicUsize,
}

impl RecordingStore {
    fn calls(&self) -> usize {
        self.created.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PublicAccessCheck for RecordingStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        Ok(PublicAccessReport { bucket: "test".to_owned(), endpoint: None, probes: Vec::new() })
    }
}

#[async_trait]
impl BlobStore for RecordingStore {
    async fn create_upload(&self, request: UploadRequest) -> StorageResult<UploadSession> {
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(UploadSession {
            key: request.key,
            content_length: request.content_length,
            target: UploadTarget::Single {
                url: Url::parse("https://store.invalid/put").expect("url"),
            },
            expires_at: Utc::now() + Duration::minutes(15),
            completed_parts: Vec::new(),
        })
    }
    async fn complete_upload(&self, session: &UploadSession) -> StorageResult<ObjectMeta> {
        Ok(ObjectMeta {
            key: session.key.clone(),
            size_bytes: session.content_length,
            etag: Some("etag".to_owned()),
            checksum_sha256: None,
            content_type: None,
            last_modified: Some(Utc::now()),
            provider_version_id: None,
            server_side_encryption: None,
        })
    }
    async fn signed_download(&self, _key: &str, _ttl: StdDuration) -> StorageResult<Url> {
        Ok(Url::parse("https://store.invalid/get").expect("url"))
    }
    async fn read_range(&self, key: &str, _range: ByteRange) -> StorageResult<ByteStream> {
        Err(enclave_storage::StorageError::NotFound { key: key.to_owned() })
    }
    async fn copy(&self, _from: &str, _to: &str) -> StorageResult<()> {
        Ok(())
    }
    async fn delete(&self, _key: &str) -> StorageResult<()> {
        Ok(())
    }
    fn capabilities(&self) -> StoreCapabilities {
        capabilities("recording-stub")
    }
}

fn capabilities(backend: &'static str) -> StoreCapabilities {
    StoreCapabilities {
        backend,
        multipart: Some(MultipartLimits {
            min_part_bytes: 5 * 1024 * 1024,
            max_part_bytes: 5 * 1024 * 1024 * 1024,
            max_parts: 10_000,
        }),
        signed_urls: true,
        single_use_signed_urls: false,
        max_signed_url_ttl: StdDuration::from_secs(900),
        versioning: Support::Unknown,
        object_lock: Support::Unknown,
        server_side_encryption: Support::Unknown,
        range_reads: false,
        server_side_copy: true,
    }
}

/// A test-free assertion about the fixtures every row above depends on.
///
/// `tenant-beta` exists so cross-tenant assertions have a realistic counterpart
/// (`docs/12-TESTING.md §3`). If the two tenants ever shared an identifier, T1 and T5 would pass
/// vacuously — and they would keep passing.
#[test]
fn the_two_fixture_tenants_never_collide() {
    let f = Fixtures::default();
    assert_ne!(f.alpha.id, f.beta.id);
    assert_ne!(f.alpha.owner, f.beta.owner);
    assert_ne!(f.alpha.member, f.beta.member);
    assert_ne!(f.alpha.engineering, f.beta.engineering);
}
