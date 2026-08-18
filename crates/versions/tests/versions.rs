//! Versions against a real PostgreSQL — the rules of `docs/04-DATA-MODEL.md §8` and
//! `docs/03-LLD.md §15` as the database actually applies them.
//!
//! # Why these exist beside the unit tests
//!
//! `crates/versions/src/commit.rs` proves the *statements* — that every one carries a tenant
//! predicate, that no literal `'AVAILABLE'` appears in the insert, that the numbering expression
//! has the shape it should. What it cannot prove is that PostgreSQL agrees: that the numbering
//! actually lands on `1.0`, `2.0`, `2.1`; that `uq_version_object` really is global rather than per
//! tenant; and above all that the `file_versions_immutable` trigger **refuses**.
//!
//! That last one is the reason this file is not optional. `plans/M1-CONTENT-CORE.md` D12 says
//! immutability is a database guarantee rather than an application convention, and the difference
//! between the two is exactly whether anyone has watched it say no. So these tests try to violate
//! it: they promote a version to `AVAILABLE` and then attempt to rewrite each of the five frozen
//! columns, one at a time, and assert the refusal — and then attempt the governance columns and
//! assert they still go through, because a trigger that froze everything would pass a naive test
//! and break the antivirus rescan path.
//!
//! # Everything runs as `enclave_app`
//!
//! Every read and write below goes through [`enclave_testing::TestDb::pool`], which
//! `SET ROLE enclave_app`s, inside a `TenantScoped` transaction. The harness's own connection is a
//! superuser, and **superusers bypass row-level security entirely** — a suite that used it would
//! pass no matter what the policies said (`ENC-124`). The fixtures — workspaces, libraries and file
//! nodes — are written over the administrative connection because they are setup, not subject.
//!
//! # Why they are ignored by default
//!
//! They need a live database with migrations `0004`, `0005` and `0006` applied. CI runs them with
//! `--include-ignored` against the service container in `.github/workflows/ci.yml`, the same way
//! `crates/files/tests/tree.rs` and `crates/db/tests/rls_coverage.rs` do. No service beyond
//! PostgreSQL is needed: nothing here touches object storage.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicI64, Ordering};

use chrono::{DateTime, Duration, Utc};
use enclave_audit::ChainMode;
use enclave_core::{
    Actor, FileId, LibraryId, RequestContext, TenantId, UserId, Uuid, VersionId, WorkspaceId,
};
use enclave_db::{DbPool, TenantScoped};
use enclave_testing::{Fixtures, TestDb};
use enclave_versions::{
    classify_write, CommittedVersion, FileVersion, NewVersion, PageLimit, RestoreVersion,
    VersionBump, VersionRepository, VersionService, VersionStatus, VersionsError,
};
use sqlx::{PgConnection, Row as _};

/// A workspace, a library and one file per tenant.
#[derive(Debug, Clone, Copy)]
struct Fixture {
    tenant: TenantId,
    owner: UserId,
    workspace: WorkspaceId,
    library: LibraryId,
    file: FileId,
    storage_profile: Uuid,
}

impl Fixture {
    fn new(tenant: TenantId, owner: UserId) -> Self {
        Self {
            tenant,
            owner,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            file: FileId::new_v7(),
            storage_profile: Uuid::now_v7(),
        }
    }

    /// Writes the containers and the file node. Every column is spelled as
    /// `docs/04-DATA-MODEL.md §7` and `§8` define it.
    async fn insert(&self, conn: &mut PgConnection) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(self.owner.as_uuid())
        .bind(tick())
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR_MINOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(tick())
        .execute(&mut *conn)
        .await
        .expect("insert library");

        // `PROCESSING` with no current version: exactly what `crates/files` creates, because a
        // file node has no content until a version is committed into it (`CLAUDE.md` rule 9).
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, node_type, name, normalized_name,
                mime_type, status, created_by, modified_by, created_at, modified_at)
             VALUES ($1, $2, $3, $4, 'FILE', 'report.pdf', 'report.pdf', 'application/pdf',
                     'PROCESSING', $5, $5, $6, $6)",
        )
        .bind(self.file.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(self.owner.as_uuid())
        .bind(tick())
        .execute(&mut *conn)
        .await
        .expect("insert file");
    }

    /// A request context attributed to this tenant's owner.
    ///
    /// Built from [`RequestContext::system`] with the actor replaced, because the audit row has to
    /// name a principal and `Actor::System` would make every assertion about attribution vacuous.
    fn ctx(&self) -> RequestContext {
        RequestContext { actor: Actor::User(self.owner), ..RequestContext::system(self.tenant) }
    }

    /// The description of a new version, with a key nobody else will use.
    fn new_version(&self, bump: VersionBump) -> NewVersion {
        NewVersion {
            file_id: self.file,
            object_key: format!("{}/{}", self.tenant, Uuid::now_v7()),
            storage_profile_id: self.storage_profile,
            size_bytes: 4_096,
            checksum_sha256: "e3b0c44298fc1c149afbf4c8996fb924".to_owned(),
            mime_type: "application/pdf".to_owned(),
            bump,
            created_by: self.owner,
            comment: Some("first draft".to_owned()),
        }
    }
}

/// A distinct, increasing instant for each write.
///
/// Anchored on `now()` rather than on a fixed date, and that is load-bearing rather than
/// stylistic: `audit_events` is range-partitioned by `occurred_at` and migration 0001 pre-creates
/// three months from the current one. A fixture clock pinned to a fixed calendar date would insert
/// audit rows into a partition that does not exist, and every test that audits would fail for a
/// reason that has nothing to do with what it tests.
fn tick() -> DateTime<Utc> {
    static CLOCK: AtomicI64 = AtomicI64::new(1);
    Utc::now() + Duration::milliseconds(CLOCK.fetch_add(1, Ordering::Relaxed))
}

/// Starts a database, seeds the two tenants, writes their containers, and returns the
/// application-role pool every assertion runs through.
async fn setup() -> (TestDb, DbPool, Fixture, Fixture) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures: Fixtures = db.seed().await.expect("seed the tenant fixtures");

    let alpha = Fixture::new(fixtures.alpha.id, fixtures.alpha.owner);
    let beta = Fixture::new(fixtures.beta.id, fixtures.beta.owner);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin).await;
    beta.insert(&mut admin).await;

    let pool = db.pool().await.expect("application-role pool");
    (db, pool, alpha, beta)
}

/// Commits a version through the application role, in its own transaction.
async fn commit(pool: &DbPool, at: &Fixture, new: &NewVersion) -> CommittedVersion {
    try_commit(pool, at, new).await.expect("commit a version")
}

/// The same, returning whatever came back.
async fn try_commit(
    pool: &DbPool,
    at: &Fixture,
    new: &NewVersion,
) -> Result<CommittedVersion, VersionsError> {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let result = VersionService::commit(&mut tx, &at.ctx(), ChainMode::Enabled, new, tick()).await;
    if result.is_ok() {
        tx.commit().await.expect("commit");
    }
    result
}

/// Attempts a restore and returns whatever came back.
async fn try_restore(
    pool: &DbPool,
    at: &Fixture,
    request: &RestoreVersion,
) -> Result<CommittedVersion, VersionsError> {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let result =
        VersionService::restore(&mut tx, &at.ctx(), ChainMode::Enabled, request, tick()).await;
    if result.is_ok() {
        tx.commit().await.expect("commit");
    }
    result
}

/// Moves a version to `AVAILABLE`/`CLEAN`, the way the antivirus path will.
///
/// Written here as raw SQL rather than through a repository function because there is no such
/// function yet — the transition belongs to `ENC-132`. What matters for these tests is that the
/// trigger permits it: a version is mutable until it is available, and only then frozen.
async fn make_available(pool: &DbPool, at: &Fixture, version: VersionId) {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    sqlx::query(
        "UPDATE file_versions SET status = 'AVAILABLE', av_status = 'CLEAN', av_engine = 'test',
                av_signature_version = '1', av_scanned_at = $3
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(at.tenant.as_uuid())
    .bind(version.as_uuid())
    .bind(tick())
    .execute(&mut *tx)
    .await
    .expect("promote the version");
    tx.commit().await.expect("commit");
}

/// Runs one `UPDATE file_versions … SET <assignment>` and returns the classified outcome.
///
/// The assignment is a literal from the test, never from input; this helper exists so that the
/// twelve attempts below read as twelve one-line statements of intent instead of twelve copies of
/// the same eight lines.
async fn try_update(
    pool: &DbPool,
    at: &Fixture,
    version: VersionId,
    assignment: &str,
) -> Result<(), VersionsError> {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let statement =
        format!("UPDATE file_versions SET {assignment} WHERE tenant_id = $1 AND id = $2");
    let outcome = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(at.tenant.as_uuid())
        .bind(version.as_uuid())
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|error| classify_write(error, 0));
    if outcome.is_ok() {
        tx.commit().await.expect("commit");
    }
    outcome
}

/// Reads one version back through the repository.
async fn read(pool: &DbPool, at: &Fixture, version: VersionId) -> Option<FileVersion> {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let found = VersionRepository::find(&mut tx, at.tenant, at.file, version)
        .await
        .expect("read the version");
    tx.commit().await.expect("commit");
    found
}

/// Counts rows in a table for one tenant, through the application role.
async fn count(pool: &DbPool, tenant: TenantId, table: &'static str) -> i64 {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let statement = format!("SELECT count(*) FROM {table} WHERE tenant_id = $1");
    let row = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(tenant.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("count rows");
    let total: i64 = row.try_get(0).expect("a count");
    tx.commit().await.expect("commit");
    total
}

// ---------------------------------------------------------------------------
// The commit
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn the_first_version_of_a_file_is_one_zero_whichever_bump_was_asked_for() {
    let (_db, pool, alpha, beta) = setup().await;

    let first = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    assert_eq!(first.version.number.to_string(), "1.0");

    // And a file whose first commit is a *minor* one still starts at 1.0 rather than 0.1 or 1.1:
    // there is no version 0 to draft against.
    let other = commit(&pool, &beta, &beta.new_version(VersionBump::Minor)).await;
    assert_eq!(other.version.number.to_string(), "1.0");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn the_database_numbers_majors_and_minors_in_sequence() {
    let (_db, pool, alpha, _beta) = setup().await;

    let numbers = [
        (VersionBump::Major, "1.0"),
        (VersionBump::Minor, "1.1"),
        (VersionBump::Minor, "1.2"),
        (VersionBump::Major, "2.0"),
        (VersionBump::Minor, "2.1"),
        (VersionBump::Major, "3.0"),
    ];
    for (bump, expected) in numbers {
        let committed = commit(&pool, &alpha, &alpha.new_version(bump)).await;
        assert_eq!(committed.version.number.to_string(), expected, "after a {bump:?} bump");
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn a_committed_version_is_never_available_and_no_content_path_can_read_it() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;

    // `CLAUDE.md` rule 9, asserted against the row the database actually holds.
    assert_eq!(committed.version.status, VersionStatus::Scanning);
    assert!(!committed.version.is_readable());

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    assert!(
        VersionRepository::find(&mut tx, alpha.tenant, alpha.file, committed.version.id)
            .await
            .expect("history read")
            .is_some(),
        "history must show it — its owner needs to see that it is scanning"
    );
    assert!(
        VersionRepository::find_readable(&mut tx, alpha.tenant, alpha.file, committed.version.id)
            .await
            .expect("content read")
            .is_none(),
        "no content path may resolve a version that has not been scanned"
    );
    tx.commit().await.expect("commit");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn the_commit_points_the_file_at_the_new_version_and_bumps_its_revision() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let row = sqlx::query(
        "SELECT current_version_id, revision, size_bytes, status FROM files
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind(alpha.tenant.as_uuid())
    .bind(alpha.file.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("read the file");
    tx.commit().await.expect("commit");

    let current: Uuid = row.try_get("current_version_id").expect("current version");
    assert_eq!(current, committed.version.id.as_uuid());
    assert_eq!(row.try_get::<i64, _>("revision").expect("revision"), committed.file_revision);
    assert_eq!(row.try_get::<i64, _>("size_bytes").expect("size"), 4_096);
    // The file must not advertise itself as available while pointing at unscanned bytes.
    assert_eq!(row.try_get::<String, _>("status").expect("status"), "PROCESSING");

    // And `current` resolves to the same row through the repository.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let resolved = VersionRepository::current(&mut tx, alpha.tenant, alpha.file)
        .await
        .expect("current version")
        .expect("there is one");
    tx.commit().await.expect("commit");
    assert_eq!(resolved.id, committed.version.id);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn the_version_its_event_and_its_audit_row_commit_together() {
    let (_db, pool, alpha, _beta) = setup().await;
    commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;

    assert_eq!(count(&pool, alpha.tenant, "file_versions").await, 1);
    assert_eq!(count(&pool, alpha.tenant, "events_outbox").await, 1);
    assert_eq!(count(&pool, alpha.tenant, "audit_events").await, 1);

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let event = sqlx::query("SELECT event_type FROM events_outbox WHERE tenant_id = $1")
        .bind(alpha.tenant.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("the outbox row");
    assert_eq!(event.try_get::<String, _>("event_type").expect("type"), "file.version.created");

    let audit =
        sqlx::query("SELECT action, outcome, resource_type FROM audit_events WHERE tenant_id = $1")
            .bind(alpha.tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("the audit row");
    assert_eq!(audit.try_get::<String, _>("action").expect("action"), "file.edit");
    assert_eq!(audit.try_get::<String, _>("outcome").expect("outcome"), "ALLOW");
    assert_eq!(audit.try_get::<String, _>("resource_type").expect("resource"), "version");
    tx.commit().await.expect("commit");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn a_rolled_back_commit_leaves_no_version_no_event_and_no_audit_row() {
    let (_db, pool, alpha, _beta) = setup().await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let committed = VersionService::commit(
        &mut tx,
        &alpha.ctx(),
        ChainMode::Enabled,
        &alpha.new_version(VersionBump::Major),
        tick(),
    )
    .await
    .expect("the write itself succeeds");
    // Visible inside its own transaction…
    assert_eq!(committed.version.number.to_string(), "1.0");
    tx.rollback().await.expect("rollback");

    // …and gone once that transaction did not happen. This is the property that makes the
    // signature `&mut PgConnection` rather than a pool: an event announcing a version that was
    // rolled back is a silent, permanent disagreement between the index and the database.
    assert_eq!(count(&pool, alpha.tenant, "file_versions").await, 0);
    assert_eq!(count(&pool, alpha.tenant, "events_outbox").await, 0);
    assert_eq!(count(&pool, alpha.tenant, "audit_events").await, 0);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn a_version_cannot_be_committed_into_a_trashed_file() {
    let (_db, pool, alpha, _beta) = setup().await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    sqlx::query("UPDATE files SET deleted_at = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.tenant.as_uuid())
        .bind(alpha.file.as_uuid())
        .bind(tick())
        .execute(&mut *tx)
        .await
        .expect("trash the file");
    tx.commit().await.expect("commit");

    // The foreign key would happily accept this — the trash is a soft delete — so the predicate in
    // the statement is what refuses it. Adding content to something the user believes they deleted
    // is a resurrection nobody asked for.
    let refused = try_commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    assert!(matches!(refused, Err(VersionsError::FileNotFound)), "{refused:?}");
}

// ---------------------------------------------------------------------------
// Immutability — the guarantee, watched refusing
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn an_available_version_refuses_every_change_to_its_content_identity() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    let version = committed.version.id;

    // Before it is available the row is still being assembled, and the upload path legitimately
    // rewrites size and checksum as parts land. The trigger must not stand in the way of that.
    try_update(&pool, &alpha, version, "size_bytes = 8192")
        .await
        .expect("a SCANNING version is still mutable");

    make_available(&pool, &alpha, version).await;

    // The five columns `docs/04-DATA-MODEL.md §8` freezes, one at a time, each with the column the
    // trigger reports. A trigger that fired for the wrong column would still fail a naive test;
    // this one says which.
    let frozen = [
        ("object_key = 'somewhere/else'", "object_key"),
        ("checksum_sha256 = 'ffff'", "checksum_sha256"),
        ("size_bytes = 1", "size_bytes"),
        ("major = 9", "major"),
        ("minor = 9", "minor"),
    ];
    for (assignment, column) in frozen {
        match try_update(&pool, &alpha, version, assignment).await {
            Err(VersionsError::Immutable { column: reported }) => {
                assert_eq!(reported, column, "the trigger named the wrong column");
            }
            other => panic!("`{assignment}` was not refused: {other:?}"),
        }
    }

    // And nothing changed. A trigger that raised *after* letting the write land would produce the
    // same errors and a different table.
    let stored = read(&pool, &alpha, version).await.expect("the version is still there");
    assert_eq!(stored.size_bytes, 8_192);
    assert_eq!(stored.checksum_sha256, committed.version.checksum_sha256);
    assert_eq!(stored.object_key, committed.version.object_key);
    assert_eq!(stored.number, committed.version.number);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn an_available_version_still_accepts_its_governance_columns() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    let version = committed.version.id;
    make_available(&pool, &alpha, version).await;

    // The other half of D12, and the half a naive "freeze the row" trigger would break. A rescan
    // that finds a new signature has to be able to quarantine an available version; an approval
    // decision has to be recordable. Freezing those would make the trigger a bug.
    for assignment in [
        "approval_state = 'APPROVED'",
        "av_engine = 'clamav'",
        "av_signature_version = '27000'",
        "av_status = 'INFECTED'",
        "status = 'QUARANTINED'",
        "comment = 'checked in from the desktop client'",
    ] {
        try_update(&pool, &alpha, version, assignment)
            .await
            .unwrap_or_else(|error| panic!("`{assignment}` should be allowed: {error:?}"));
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn writing_a_frozen_column_its_current_value_is_not_a_change() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    make_available(&pool, &alpha, committed.version.id).await;

    // The trigger tests for a *change*, not for a mention. This matters for any writer that
    // updates a row by re-sending every column it read — an ORM, a generated statement, a
    // hand-written `UPDATE … SET everything` — which would otherwise be refused for touching
    // nothing.
    try_update(&pool, &alpha, committed.version.id, "size_bytes = 4096, comment = 'unchanged'")
        .await
        .expect("re-writing the same value is not a mutation");
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn a_restore_adds_a_version_and_changes_nothing_that_already_existed() {
    let (_db, pool, alpha, _beta) = setup().await;

    let original = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    make_available(&pool, &alpha, original.version.id).await;
    let second = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    make_available(&pool, &alpha, second.version.id).await;

    let restored = try_restore(
        &pool,
        &alpha,
        &RestoreVersion {
            file_id: alpha.file,
            source: original.version.id,
            // A *new* key: the caller has already copied the bytes. `uq_version_object` is global,
            // so re-pointing at the source's key is not an option that exists.
            object_key: format!("{}/restored-{}", alpha.tenant, Uuid::now_v7()),
            bump: VersionBump::Major,
            restored_by: alpha.owner,
            comment: Some("back to 1.0".to_owned()),
        },
    )
    .await
    .expect("restore");

    // A new version, numbered after the newest — not a renumbering of the old one.
    assert_eq!(restored.version.number.to_string(), "3.0");
    assert_eq!(restored.version.checksum_sha256, original.version.checksum_sha256);
    assert_eq!(restored.version.size_bytes, original.version.size_bytes);
    assert_eq!(restored.version.mime_type, original.version.mime_type);
    assert_ne!(restored.version.object_key, original.version.object_key);
    // And scanned again from scratch: the bytes are a new object and the signature database has
    // moved on since the original was cleared.
    assert_eq!(restored.version.status, VersionStatus::Scanning);
    assert!(!restored.version.is_readable());

    // The source is untouched, which is the whole point of restoring by adding.
    let source_now = read(&pool, &alpha, original.version.id).await.expect("still there");
    assert_eq!(source_now.number, original.version.number);
    assert_eq!(source_now.object_key, original.version.object_key);
    assert_eq!(source_now.status, VersionStatus::Available);

    assert_eq!(count(&pool, alpha.tenant, "file_versions").await, 3);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn a_version_that_may_not_be_served_may_not_be_restored_from() {
    let (_db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;

    let request = RestoreVersion {
        file_id: alpha.file,
        source: committed.version.id,
        object_key: format!("{}/restored-{}", alpha.tenant, Uuid::now_v7()),
        bump: VersionBump::Major,
        restored_by: alpha.owner,
        comment: None,
    };

    // Still scanning: there are no settled bytes to copy.
    let refused = try_restore(&pool, &alpha, &request).await;
    assert!(matches!(refused, Err(VersionsError::SourceNotRestorable)), "{refused:?}");

    // Quarantined: the bytes are ones the system has already refused to serve, and re-publishing
    // them under a new number would launder them past the check that stopped them.
    make_available(&pool, &alpha, committed.version.id).await;
    try_update(
        &pool,
        &alpha,
        committed.version.id,
        "av_status = 'INFECTED', status = 'QUARANTINED'",
    )
    .await
    .expect("quarantine");
    let refused = try_restore(&pool, &alpha, &request).await;
    assert!(matches!(refused, Err(VersionsError::SourceNotRestorable)), "{refused:?}");

    // A version of another file is simply not found, rather than reported as unrestorable — the
    // caller learns nothing about what exists elsewhere.
    let elsewhere = RestoreVersion { source: VersionId::new_v7(), ..request };
    let refused = try_restore(&pool, &alpha, &elsewhere).await;
    assert!(matches!(refused, Err(VersionsError::NotFound)), "{refused:?}");
}

// ---------------------------------------------------------------------------
// Isolation and uniqueness
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn one_tenant_cannot_read_or_page_through_another_tenants_versions() {
    let (_db, pool, alpha, beta) = setup().await;
    let mine = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    let theirs = commit(&pool, &beta, &beta.new_version(VersionBump::Major)).await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    // Asking for beta's version with beta's file id, from alpha's transaction. Both layers refuse:
    // the `tenant_id = $1` predicate and the row-level security policy.
    assert!(VersionRepository::find(&mut tx, alpha.tenant, beta.file, theirs.version.id)
        .await
        .expect("read")
        .is_none());
    // And with alpha's own file id, in case a version id alone were enough.
    assert!(VersionRepository::find(&mut tx, alpha.tenant, alpha.file, theirs.version.id)
        .await
        .expect("read")
        .is_none());
    let page = VersionRepository::list(&mut tx, alpha.tenant, beta.file, None, PageLimit::DEFAULT)
        .await
        .expect("list");
    assert!(page.versions.is_empty(), "another tenant's history must not page");
    tx.commit().await.expect("commit");

    // Alpha's own version is readable from alpha, so the assertions above are about isolation
    // rather than about everything being invisible.
    assert!(read(&pool, &alpha, mine.version.id).await.is_some());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn an_object_key_belongs_to_exactly_one_version_across_the_whole_deployment() {
    let (_db, pool, alpha, beta) = setup().await;

    let key = format!("shared/{}", Uuid::now_v7());
    let mut mine = alpha.new_version(VersionBump::Major);
    mine.object_key.clone_from(&key);
    commit(&pool, &alpha, &mine).await;

    // The same key, from the other tenant. `uq_version_object` is deliberately *not* tenant-scoped:
    // two rows naming one object is how a purge for one tenant deletes another tenant's bytes.
    let mut theirs = beta.new_version(VersionBump::Major);
    theirs.object_key = key;
    let refused = try_commit(&pool, &beta, &theirs).await;
    assert!(matches!(refused, Err(VersionsError::ObjectKeyInUse)), "{refused:?}");
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn history_pages_newest_first_without_repeating_or_skipping_a_version() {
    let (_db, pool, alpha, _beta) = setup().await;

    for _ in 0..5 {
        commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    }

    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
        let page =
            VersionRepository::list(&mut tx, alpha.tenant, alpha.file, before, PageLimit::new(2))
                .await
                .expect("list");
        tx.commit().await.expect("commit");

        seen.extend(page.versions.iter().map(|version| version.number.to_string()));
        assert_eq!(page.has_more, page.next_before.is_some());
        match page.next_before {
            Some(next) => before = Some(next),
            None => break,
        }
    }

    assert_eq!(seen, vec!["5.0", "4.0", "3.0", "2.0", "1.0"]);
}
