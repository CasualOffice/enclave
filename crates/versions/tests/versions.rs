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
use enclave_db::{
    configure_storage_quota, release_storage, storage_quota, DbPool, Enforcement, Released,
    TenantScoped,
};
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
            id: VersionId::new_v7(),
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

// ---------------------------------------------------------------------------
// The stored-byte quota — `ENC-589`, `docs/12-TESTING.md §4.12` Q7–Q11
// ---------------------------------------------------------------------------
//
// `ENC-584` proved the *statement* against a live database (`crates/db/tests/storage_quota.rs`).
// What it could not prove is that anything calls it, which is the whole of `ENC-589` and the whole
// of `plans/M4-GOVERNANCE.md §2`: a control that is switched off is indistinguishable from an
// absent one except in the compliance answer.
//
// So these test the *integration* (`docs/12 §1.1`) — that the charge happens on the real commit
// path, in the real transaction, before the row it pays for — and every assertion about an absence
// here carries its positive control in the same fixture (`docs/12 §1.2`). "The refused commit
// stored nothing" is true of a commit path that stores nothing ever.

/// Writes a quota row for `tenant` over the application role.
async fn set_quota(pool: &DbPool, tenant: TenantId, limit: u64, mode: Enforcement) {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    configure_storage_quota(&mut tx, limit, 80, mode).await.expect("configure the quota");
    tx.commit().await.expect("commit");
}

/// `used_bytes` as the row currently holds it, or `None` for an unmetered tenant.
async fn used(pool: &DbPool, tenant: TenantId) -> Option<i64> {
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    let quota = storage_quota(&mut tx).await.expect("read the quota");
    tx.commit().await.expect("commit");
    quota.map(|quota| quota.used_bytes)
}

/// The file's `revision`, which every successful commit bumps and no refused one may.
async fn revision(pool: &DbPool, at: &Fixture) -> i64 {
    let mut tx = TenantScoped::begin(pool, at.tenant).await.expect("begin");
    let row = sqlx::query("SELECT revision FROM files WHERE tenant_id = $1 AND id = $2")
        .bind(at.tenant.as_uuid())
        .bind(at.file.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .expect("read the revision");
    let revision: i64 = row.try_get("revision").expect("a revision");
    tx.commit().await.expect("commit");
    revision
}

/// A new version of a given size, with a key nobody else will use.
fn sized(at: &Fixture, bytes: i64) -> NewVersion {
    NewVersion { size_bytes: bytes, ..at.new_version(VersionBump::Major) }
}

/// Everything a committed version leaves behind, counted in one place.
///
/// The refusal test asserts that **none** of it moves, and the control asserts that **all** of it
/// does. Counting them together is what stops the refusal leg from passing against a commit path
/// that never wrote an outbox row in the first place.
#[derive(Debug, PartialEq, Eq)]
struct Footprint {
    versions: i64,
    outbox: i64,
    audit: i64,
    revision: i64,
    used_bytes: Option<i64>,
}

async fn footprint(pool: &DbPool, at: &Fixture) -> Footprint {
    Footprint {
        versions: count(pool, at.tenant, "file_versions").await,
        outbox: count(pool, at.tenant, "events_outbox").await,
        audit: count(pool, at.tenant, "audit_events").await,
        revision: revision(pool, at).await,
        used_bytes: used(pool, at.tenant).await,
    }
}

/// **The test that matters most.** A commit over the quota is refused and stores nothing — and the
/// identical commit under a quota with room stores everything.
///
/// The control runs *first* and is asserted in full, because "no version row, no outbox row, no
/// audit row, no counter movement" is an assertion about an absence and passes for free against a
/// path that writes none of them (`docs/12 §1.2`). Once the control has shown all five moving, the
/// refusal leg is evidence.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn a_commit_over_the_quota_is_refused_and_stores_nothing_while_one_with_room_stores_all_of_it(
) {
    let (_db, pool, alpha, _beta) = setup().await;
    set_quota(&pool, alpha.tenant, 8_192, Enforcement::Block).await;

    let before = footprint(&pool, &alpha).await;
    assert_eq!(before.used_bytes, Some(0), "a fresh quota row starts at zero");

    // The positive control: 4 KiB into 8 KiB of room.
    let admitted = commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    let stored = footprint(&pool, &alpha).await;
    assert_eq!(stored.versions, before.versions + 1, "the version row");
    assert_eq!(stored.outbox, before.outbox + 1, "the file.version.created event");
    assert_eq!(stored.audit, before.audit + 1, "the audit row");
    assert_eq!(stored.revision, before.revision + 1, "the file's revision");
    assert_eq!(stored.used_bytes, Some(4_096), "the counter");
    assert_eq!(
        admitted.charged.expect("a metered tenant is charged").quota.used_bytes,
        4_096,
        "the commit reports the figure its own charge reached"
    );

    // The refusal: 8 KiB into the 4 KiB that is left.
    let refused = try_commit(&pool, &alpha, &sized(&alpha, 8_192)).await;
    match refused {
        Err(VersionsError::StorageQuotaExceeded(refusal)) => {
            assert_eq!(refusal.requested_bytes, 8_192);
            assert_eq!(refusal.quota.limit_bytes, 8_192);
            // Unchanged: the refusal moved nothing, which is the `WHERE` clause doing its job
            // rather than a rollback tidying up after it.
            assert_eq!(refusal.quota.used_bytes, 4_096);
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }

    assert_eq!(
        footprint(&pool, &alpha).await,
        stored,
        "a refused commit must leave no version row, no event, no audit row, no revision bump and \
         no counter movement — the whole transaction rolls back with the charge inside it"
    );

    // And the refusal renders as a quota refusal rather than a server error.
    let error: enclave_core::Error =
        try_commit(&pool, &alpha, &sized(&alpha, 8_192)).await.expect_err("still refused").into();
    assert_eq!(error.status_code(), 403, "quota exhaustion is not a 500");
}

/// The transaction property, proved directly: the charge is visible **inside** the transaction and
/// gone once it rolls back.
///
/// The in-transaction read is the positive control. Without it, "the counter did not move after a
/// rollback" is satisfied by a commit path that never charges at all — which is precisely the state
/// `ENC-589` exists to leave behind.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn a_charge_is_visible_inside_the_commits_transaction_and_gone_when_it_rolls_back() {
    let (_db, pool, alpha, _beta) = setup().await;
    set_quota(&pool, alpha.tenant, 1_048_576, Enforcement::Block).await;

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    VersionService::commit(
        &mut tx,
        &alpha.ctx(),
        ChainMode::Enabled,
        &sized(&alpha, 4_096),
        tick(),
    )
    .await
    .expect("commit the version");
    let inside = storage_quota(&mut tx).await.expect("read").expect("a quota row");
    assert_eq!(inside.used_bytes, 4_096, "the charge ran in this transaction");

    // Rolled back rather than committed — the failure mode this is arranged around is a write that
    // dies after the charge.
    tx.rollback().await.expect("roll back");

    assert_eq!(
        used(&pool, alpha.tenant).await,
        Some(0),
        "a charge that could commit apart from the version it pays for would leak quota on every \
         failed upload"
    );
    assert_eq!(count(&pool, alpha.tenant, "file_versions").await, 0, "and no version survived");

    // The other half: the same commit, committed, does move it.
    commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    assert_eq!(used(&pool, alpha.tenant).await, Some(4_096));
}

/// A failure *after* the charge and before the commit leaves the counter untouched.
///
/// Forced with a real post-charge failure rather than an injected one: a duplicate `object_key` is
/// refused by `uq_version_object`, which is the statement immediately after the charge. The
/// successful commit above it is the control — it shows the counter moving under the identical
/// fixture, so "unchanged" is a statement about a charge that ran and rolled back.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn a_commit_that_fails_after_the_charge_leaves_the_counter_untouched() {
    let (_db, pool, alpha, _beta) = setup().await;
    set_quota(&pool, alpha.tenant, 1_048_576, Enforcement::Block).await;

    let first = sized(&alpha, 4_096);
    commit(&pool, &alpha, &first).await;
    assert_eq!(used(&pool, alpha.tenant).await, Some(4_096), "the control: a charge that landed");

    let clash = NewVersion { object_key: first.object_key.clone(), ..sized(&alpha, 65_536) };
    let refused = try_commit(&pool, &alpha, &clash).await;
    assert!(matches!(refused, Err(VersionsError::ObjectKeyInUse)), "{refused:?}");

    assert_eq!(
        used(&pool, alpha.tenant).await,
        Some(4_096),
        "the 64 KiB charge was made and then rolled back with the insert that failed after it; a \
         counter that kept it is the drift ENC-584's reconciliation would spend the night undoing"
    );
}

/// Exhaustion blocks the write and nothing else — the exit criterion, with the refusal first.
///
/// The "not blocked" legs are statements about a demonstrably exhausted quota rather than about one
/// that never engaged. The loop closes at the end: a release brings the tenant back under its limit
/// and the commit that was refused is admitted.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn an_exhausted_quota_refuses_a_commit_while_every_read_of_the_history_keeps_working() {
    let (_db, pool, alpha, _beta) = setup().await;
    set_quota(&pool, alpha.tenant, 4_096, Enforcement::Block).await;

    let committed = commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    let version = committed.version.id;

    // Exhausted, and shown to be.
    let refused = try_commit(&pool, &alpha, &sized(&alpha, 1)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");

    // Reads, against the tenant that has just been refused a write.
    assert!(read(&pool, &alpha, version).await.is_some(), "find must not consult the quota");

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let current = VersionRepository::current(&mut tx, alpha.tenant, alpha.file)
        .await
        .expect("read the current version");
    let page = VersionRepository::list(&mut tx, alpha.tenant, alpha.file, None, PageLimit::new(10))
        .await
        .expect("page the history");
    tx.commit().await.expect("commit");
    assert_eq!(current.map(|version| version.id), Some(version));
    assert_eq!(page.versions.len(), 1, "history is readable at the limit");

    // And the loop closes: freeing bytes admits the commit that was refused.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let released = release_storage(&mut tx, 4_096).await.expect("release");
    tx.commit().await.expect("commit");
    assert!(matches!(released, Released::Recorded(_)), "a release can never be refused");

    commit(&pool, &alpha, &sized(&alpha, 1)).await;
}

/// One tenant's exhaustion never refuses another's commit.
///
/// `tenant-beta` exists so this is realistic rather than notional: identical fixtures, identical
/// limits, identical sizes, and the only difference is which tenant has spent its allowance.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn tenant_betas_exhaustion_does_not_refuse_tenant_alphas_commit() {
    let (_db, pool, alpha, beta) = setup().await;
    set_quota(&pool, alpha.tenant, 4_096, Enforcement::Block).await;
    set_quota(&pool, beta.tenant, 4_096, Enforcement::Block).await;

    commit(&pool, &beta, &sized(&beta, 4_096)).await;
    let refused = try_commit(&pool, &beta, &sized(&beta, 1)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");

    // Alpha has spent nothing, and beta's row is not visible to it.
    commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    assert_eq!(used(&pool, alpha.tenant).await, Some(4_096));
    assert_eq!(used(&pool, beta.tenant).await, Some(4_096), "and beta's counter did not move");
}

/// A tenant with no quota row is unmetered, never refused.
///
/// Provisioning order must not be the difference between a working deployment and a read-only one.
/// The control is `tenant-beta`, configured and refused under the identical fixture — without it
/// this passes against a build where the charge was never wired at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn a_tenant_with_no_quota_row_commits_unmetered_while_a_configured_one_is_refused() {
    let (_db, pool, alpha, beta) = setup().await;
    set_quota(&pool, beta.tenant, 4_096, Enforcement::Block).await;

    let refused = try_commit(&pool, &beta, &sized(&beta, 8_192)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");

    let committed = commit(&pool, &alpha, &sized(&alpha, 8_192)).await;
    assert!(committed.charged.is_none(), "an unmetered tenant is charged nothing");
    assert_eq!(used(&pool, alpha.tenant).await, None, "and has no row to charge");
}

/// `MONITOR` counts without refusing; `BLOCK` refuses the identical charge.
///
/// `plans/M4-GOVERNANCE.md §2` — a control that cannot be turned on gradually will be turned on
/// carelessly, or not at all. Both halves in one test, because "MONITOR did not refuse" is worth
/// nothing without the demonstration that the same commit under `BLOCK` does.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn monitor_counts_a_commit_it_will_not_refuse_and_block_refuses_the_same_one() {
    let (_db, pool, alpha, beta) = setup().await;
    set_quota(&pool, alpha.tenant, 4_096, Enforcement::Monitor).await;
    set_quota(&pool, beta.tenant, 4_096, Enforcement::Block).await;

    let over = commit(&pool, &alpha, &sized(&alpha, 65_536)).await;
    assert_eq!(
        over.charged.expect("monitored tenants are still counted").quota.used_bytes,
        65_536,
        "MONITOR counts; it is the refusal it promises not to make"
    );

    let refused = try_commit(&pool, &beta, &sized(&beta, 65_536)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");
    assert_eq!(used(&pool, beta.tenant).await, Some(0), "and BLOCK moved nothing");
}

/// The soft limit is announced by exactly one commit, and before anything is refused.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn one_commit_reports_the_soft_limit_crossing_and_the_next_ones_do_not() {
    let (_db, pool, alpha, _beta) = setup().await;
    // 80% of 10 000 is 8 000.
    set_quota(&pool, alpha.tenant, 10_000, Enforcement::Block).await;

    let under = commit(&pool, &alpha, &sized(&alpha, 7_900)).await;
    assert!(
        !under.charged.expect("metered").crossed_soft_limit,
        "79% is under the threshold and must not announce"
    );

    let crossing = commit(&pool, &alpha, &sized(&alpha, 100)).await;
    assert!(
        crossing.charged.expect("metered").crossed_soft_limit,
        "8 000 of 10 000 is the crossing"
    );

    let after = commit(&pool, &alpha, &sized(&alpha, 100)).await;
    assert!(
        !after.charged.expect("metered").crossed_soft_limit,
        "announced once per crossing, not once per write"
    );

    // Notified well before refused, which is the ordering §2 asks for.
    let refused = try_commit(&pool, &alpha, &sized(&alpha, 10_000)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");
}

/// A restore pays for its copy of the bytes, and is refused when they do not fit.
///
/// The restored version is a *new* object holding the same content — `uq_version_object` makes
/// sharing the source's key unrepresentable — so the deployment is storing both. A restore exempt
/// from the charge would be a way to grow a tenant's footprint without moving its counter.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005, 0006 and 0018 applied; CI runs it with --include-ignored"]
async fn a_restore_is_charged_for_its_copy_and_refused_when_it_does_not_fit() {
    let (_db, pool, alpha, _beta) = setup().await;
    set_quota(&pool, alpha.tenant, 12_288, Enforcement::Block).await;

    let source = commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    make_available(&pool, &alpha, source.version.id).await;
    assert_eq!(used(&pool, alpha.tenant).await, Some(4_096));

    let restored = try_restore(&pool, &alpha, &restore_of(&alpha, source.version.id))
        .await
        .expect("the restore fits");
    assert_eq!(restored.charged.expect("metered").quota.used_bytes, 8_192, "charged a second time");

    // Fill the remainder, then a further restore has nowhere to go.
    commit(&pool, &alpha, &sized(&alpha, 4_096)).await;
    let refused = try_restore(&pool, &alpha, &restore_of(&alpha, source.version.id)).await;
    assert!(matches!(refused, Err(VersionsError::StorageQuotaExceeded(_))), "{refused:?}");
    assert_eq!(used(&pool, alpha.tenant).await, Some(12_288), "and nothing was charged for it");
}

/// A restore request pointing at a fresh key, which is the only kind the schema allows.
fn restore_of(at: &Fixture, source: VersionId) -> RestoreVersion {
    RestoreVersion {
        file_id: at.file,
        source,
        object_key: format!("{}/{}", at.tenant, Uuid::now_v7()),
        bump: VersionBump::Major,
        restored_by: at.owner,
        comment: None,
    }
}

/// A committed version is queued for indexing, in the same transaction that created it.
///
/// # Why this is asserted here rather than in `crates/indexing`
///
/// `ENC-643`. `enclave_indexing::enqueue` had 27 test references and no caller in any binary, so
/// every test of the queue passed against a queue nothing ever wrote to. A file could pass
/// antivirus, become readable, and never be indexed — stored, visible, permanently unsearchable,
/// with nothing reporting it. The gap was between two crates, so only a test that commits a real
/// version and then looks in the manifest table can see it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004, 0005 and 0006 applied; CI runs it with --include-ignored"]
async fn committing_a_version_queues_it_for_indexing() {
    let (db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;

    let mut conn = db.connect().await.expect("connection");
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM index_manifests
          WHERE tenant_id = $1 AND file_id = $2 AND version_id = $3",
    )
    .bind(alpha.tenant.as_uuid())
    .bind(alpha.file.as_uuid())
    .bind(committed.version.id.as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("count the manifests");

    assert_eq!(
        queued, 1,
        "the committed version has no index manifest, so the indexing pass will never see it — \
         which is ENC-643, the state in which a file is stored, readable and unsearchable"
    );

    // The control: a version that was never committed has no manifest, so the assertion above is
    // the enqueue rather than a table that answers 1 to everything.
    let absent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM index_manifests WHERE tenant_id = $1 AND version_id = $2",
    )
    .bind(alpha.tenant.as_uuid())
    .bind(VersionId::new_v7().as_uuid())
    .fetch_one(&mut conn)
    .await
    .expect("count the manifests");
    assert_eq!(absent, 0, "a version that was never committed has a manifest");
}

/// **`READABLE_PREDICATE` and `is_readable` accept exactly the same rows — asked of PostgreSQL.**
///
/// The two spellings of `CLAUDE.md` rule 9 are deliberately two: one is a `WHERE` fragment the
/// delivery queries splice, the other a `const fn` that `GET /files/{id}` renders `isReadable`
/// from. Two spellings of one rule is one too many, and the only thing that makes it safe is a test
/// that runs *both* over the same rows and compares them.
///
/// # Why the whole cross-product, and why this test was rewritten rather than kept
///
/// It used to check the SQL half by looking for two substrings and the Rust half against a table
/// built from the same `matches!` the function uses. That is precisely how `ENC-828` survived:
/// `AVAILABLE`/`SKIPPED` — what every upload to a deployment with no antivirus engine becomes —
/// was refused by both halves, so they agreed, wrongly, for four milestones while a substring check
/// reported them in step.
///
/// So this sweeps all thirty `VersionStatus` x `AvStatus` combinations, writes each one to a real
/// row, and asks the real predicate through the real query planner. A cross-product is what catches
/// a pair drifting; two interesting cases catch only the cases that were interesting when they were
/// written.
///
/// # The control
///
/// An agreement test is satisfiable by both halves saying *no* to everything — which is not
/// hypothetical here: `readable_version` answered `None` for every version in every deployment for
/// four milestones and every rule-9 assertion in the workspace passed (`ENC-641`). So the servable
/// combinations are asserted by name and by count.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_two_spellings_of_readable_agree_against_a_real_database() {
    const STATUSES: [&str; 6] =
        ["PENDING", "SCANNING", "PROCESSING", "AVAILABLE", "QUARANTINED", "FAILED"];
    const AV_STATUSES: [&str; 5] = ["PENDING", "CLEAN", "INFECTED", "SKIPPED", "ERROR"];

    let (db, pool, alpha, _beta) = setup().await;
    let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
    let version = committed.version.id;

    // The query is built here, from the exported predicate, exactly as a caller writing its own
    // read path would. A hand-retyped copy would make this test agree with itself.
    let query = format!(
        "SELECT 1 FROM file_versions WHERE tenant_id = $1 AND id = $2 AND {}",
        enclave_versions::READABLE_PREDICATE
    );

    let mut admin = db.connect().await.expect("admin connection");
    let mut servable: Vec<(&str, &str)> = Vec::new();

    for status in STATUSES {
        for av in AV_STATUSES {
            // Written over the administrative connection because the immutability trigger freezes
            // a version once it is `AVAILABLE`, and this sweep has to move it back out again.
            sqlx::query(
                "UPDATE file_versions SET status = $1, av_status = $2 \
                  WHERE tenant_id = $3 AND id = $4",
            )
            .bind(status)
            .bind(av)
            .bind(alpha.tenant.as_uuid())
            .bind(version.as_uuid())
            .execute(&mut admin)
            .await
            .unwrap_or_else(|error| panic!("move the version to {status}/{av}: {error}"));

            // The SQL half: the exported predicate, spliced, run by PostgreSQL.
            let sql_says: bool = sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(query.clone()))
                .bind(alpha.tenant.as_uuid())
                .bind(version.as_uuid())
                .fetch_optional(&mut admin)
                .await
                .expect("run the readable predicate")
                .is_some();

            // The Rust half: the record as the repository decodes it, through `is_readable`.
            let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
            let row: FileVersion =
                VersionRepository::find(&mut tx, alpha.tenant, alpha.file, version)
                    .await
                    .expect("read the version")
                    .expect("the version exists");
            tx.commit().await.expect("commit");

            assert_eq!(
                row.status.as_str(),
                status,
                "the row did not take the status this iteration wrote"
            );
            assert_eq!(row.av.status.as_str(), av, "the row did not take the av_status");

            assert_eq!(
                row.is_readable(),
                sql_says,
                "{status}/{av}: FileVersion::is_readable says {} and READABLE_PREDICATE says {}. \
                 The two spellings of CLAUDE.md rule 9 have drifted — GET /files/{{id}} will \
                 report a readiness the delivery routes do not honour, which is ENC-825's defect \
                 and how ENC-828 stayed invisible",
                row.is_readable(),
                sql_says
            );

            // And the free function both are defined in terms of, so a caller holding only the
            // pair (`crates/worker`'s antivirus pass) cannot get a third answer.
            assert_eq!(
                enclave_versions::is_readable_pair(row.status, row.av.status),
                sql_says,
                "{status}/{av}: is_readable_pair disagrees with the SQL predicate"
            );

            if sql_says {
                servable.push((status, av));
            }
        }
    }

    drop(admin);

    // The control. Agreement is free if nothing is ever servable.
    assert_eq!(
        servable,
        vec![("AVAILABLE", "CLEAN"), ("AVAILABLE", "SKIPPED")],
        "exactly two of the thirty combinations are servable: a completed clean scan, and \
         ALLOW_WITH_FLAG's published-but-uninspected version (ENC-828). AVAILABLE/PENDING is not \
         among them — that is a scan which has not completed, which is the clause of rule 9 no \
         configuration reaches (ENC-646)"
    );
}

/// Stamping a verification advances the drift scan's queue (`ENC-951`).
///
/// **The property a comment claimed and no test held.** The scan orders warm versions by
/// `tier_verified_at`, oldest first with `NULL` before everything, and takes a bounded batch. If a
/// row that is checked and found genuinely warm is *not* stamped, the ordering returns it
/// immediately — and the scan re-checks one batch for ever while the rest of the corpus goes
/// unverified, at one `HeadObject` per row per tick, indefinitely.
///
/// It is invisible from outside: the pass runs, logs a verified count, and reports success. Only
/// the queue not moving gives it away, which is what this asserts.
///
/// Deleting `mark_tier_verified` from `crates/worker/src/tiering.rs`'s confirmed-warm arm compiles
/// cleanly and passes every other test in this workspace; it turns this one red.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004-0006 and 0033"]
async fn verifying_a_tier_moves_that_version_to_the_back_of_the_drift_queue() {
    let (_db, pool, alpha, _beta) = setup().await;

    // Three warm versions of the one fixture file, none ever verified. Successive majors rather
    // than three files: the drift queue is over `file_versions` and does not care which file a row
    // belongs to, and superseded versions are still warm objects a lifecycle rule can move.
    let mut ids = Vec::new();
    for _ in 0..3_u32 {
        let committed = commit(&pool, &alpha, &alpha.new_version(VersionBump::Major)).await;
        ids.push(committed.version.id);
    }

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");

    let first = VersionRepository::least_recently_verified(&mut tx, alpha.tenant, 1)
        .await
        .expect("read the drift queue");
    let head = first.first().expect("three warm versions exist, so the queue is not empty").id;
    assert!(ids.contains(&head), "the queue must return one of the versions just committed");

    // The control: asking again without stamping returns the *same* row. Without this, the
    // assertion below is satisfied by a query that returns rows at random.
    let again = VersionRepository::least_recently_verified(&mut tx, alpha.tenant, 1)
        .await
        .expect("read the drift queue again");
    assert_eq!(
        again.first().map(|v| v.id),
        Some(head),
        "an unstamped queue must be stable, or the ordering is not doing the work this test \
         attributes to the stamp"
    );

    VersionRepository::mark_tier_verified(&mut tx, alpha.tenant, head)
        .await
        .expect("stamp the verification");

    let after = VersionRepository::least_recently_verified(&mut tx, alpha.tenant, 1)
        .await
        .expect("read the drift queue after stamping");
    assert_ne!(
        after.first().map(|v| v.id),
        Some(head),
        "a verified version must move to the back of the queue; if it does not, the drift scan \
         re-checks one batch for ever and the rest of the corpus is never verified"
    );

    // And it is still *in* the queue — moved, not dropped. A stamp that removed rows would leave
    // the deployment with a queue that empties and a corpus that stops being re-checked.
    let all = VersionRepository::least_recently_verified(&mut tx, alpha.tenant, 10)
        .await
        .expect("read the whole queue");
    assert!(
        all.iter().any(|v| v.id == head),
        "verification moves a version to the back of the queue, never out of it: tiers drift \
         again, so a row checked once still has to be checked later"
    );
    tx.commit().await.expect("commit");
}
