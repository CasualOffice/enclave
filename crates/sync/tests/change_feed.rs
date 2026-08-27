//! The change feed's ordering guarantee, the device registry, and the wipe.
//!
//! `ENC-734`. These are the properties `migrations/0023_sync_devices.sql` argues for in prose; this
//! file is where they are demonstrated against a real PostgreSQL, because every one of them is a
//! property *of PostgreSQL* — a row lock's duration, a rollback's effect on a counter, a `CHECK`
//! constraint — and a mock would assert that our mock behaves the way we assumed
//! (`plans/M0-FOUNDATIONS.md` D7).
//!
//! # The one that matters most
//!
//! [`allocation_order_is_commit_order_not_clock_order`] is the reason the cursor is what it is. It
//! holds one writer's transaction open and shows that a second writer in the same scope **cannot
//! take a sequence number** until the first commits. That is what makes `seq > cursor` complete: a
//! reader can never observe `n+1` while `n` is still in flight, so it can never store a cursor that
//! skips `n`. A timestamp cursor fails this by construction and a PostgreSQL `SEQUENCE` fails it
//! too — `nextval` neither locks nor rolls back.
//!
//! Ignored by default: they need a live PostgreSQL. CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use chrono::Utc;
use enclave_core::{DeviceId, FileId, LibraryId, TenantId, UserId, WorkspaceId};
use enclave_sync::{DeltaCursor, DeviceState, Registration, SyncError, SyncRepository, SyncScope};
use enclave_testing::TestDb;
use sqlx::{PgConnection, Row};

/// A tenant with a user, a workspace and a library — the smallest thing a feed can exist in.
#[derive(Debug, Clone, Copy)]
struct Fixture {
    tenant: TenantId,
    user: UserId,
    workspace: WorkspaceId,
    library: LibraryId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            tenant: TenantId::new_v7(),
            user: UserId::new_v7(),
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
        }
    }

    fn scope(self) -> SyncScope {
        SyncScope::library(self.library)
    }

    async fn insert(self, conn: &mut PgConnection) {
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at)
             VALUES ($1, $2, 'fixture', 'ACTIVE', $3, $3)",
        )
        .bind(self.tenant.as_uuid())
        .bind(format!("t-{}", self.tenant.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert tenant");

        sqlx::query(
            "INSERT INTO users
               (id, tenant_id, email, normalized_email, display_name, status, source,
                created_at, updated_at)
             VALUES ($1, $2, $3, $3, 'Fixture', 'ACTIVE', 'LOCAL', $4, $4)",
        )
        .bind(self.user.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("{}@example.test", self.user.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert user");

        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(self.user.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, sync_enabled, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', TRUE, $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert library");
    }
}

/// Writes one file. The trigger is what appends the feed entry; nothing here mentions the feed.
async fn insert_file(conn: &mut PgConnection, fixture: Fixture, file: FileId) {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, node_type, name, normalized_name, mime_type,
            inherit_permissions, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, 'FILE', $5, $5, 'application/pdf', TRUE, $6, $6, $7, $7)",
    )
    .bind(file.as_uuid())
    .bind(fixture.tenant.as_uuid())
    .bind(fixture.workspace.as_uuid())
    .bind(fixture.library.as_uuid())
    .bind(file.as_uuid().to_string())
    .bind(fixture.user.as_uuid())
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("insert file");
}

/// The sequence numbers the feed holds for one scope, in order.
async fn sequences(conn: &mut PgConnection, fixture: Fixture) -> Vec<i64> {
    sqlx::query(
        "SELECT seq FROM sync_change_log
          WHERE tenant_id = $1 AND scope_type = 'LIBRARY' AND scope_id = $2
          ORDER BY seq",
    )
    .bind(fixture.tenant.as_uuid())
    .bind(fixture.library.as_uuid())
    .fetch_all(&mut *conn)
    .await
    .expect("read the feed")
    .iter()
    .map(|row| row.get::<i64, _>("seq"))
    .collect()
}

// ---------------------------------------------------------------------------------------------
// The ordering guarantee
// ---------------------------------------------------------------------------------------------

/// **The property the whole cursor design rests on.**
///
/// A second writer in the same scope cannot take a sequence number while the first writer's
/// transaction is open. Demonstrated by holding one open and showing the other does not finish.
///
/// # Why the timeout is the assertion and not a flake
///
/// The claim is *"B blocks until A commits"*. A blocked statement is an absence of progress, and
/// the only way to observe an absence is to wait and find it still absent. Two seconds is far
/// longer than the insert takes when it is not blocked — the unblocked half of this test runs in
/// single-digit milliseconds — so a timeout here is the row lock, not a slow machine. The positive
/// control immediately below is what stops this passing because of some *other* stall: after A
/// commits, B completes, and its sequence number is higher than A's.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn allocation_order_is_commit_order_not_clock_order() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;

    // Four connections: two for the racing writers, headroom for the reads.
    let pool = db.pool_with_connections(4).await.expect("pool");

    let first = FileId::new_v7();
    let second = FileId::new_v7();

    let mut a = pool.begin(fixture.tenant).await.expect("begin A");
    insert_file(&mut a, fixture, first).await;

    // B, in its own task, so the main task can observe that it does not finish.
    let pool_for_b = pool.clone();
    let handle = tokio::spawn(async move {
        let mut b = pool_for_b.begin(fixture.tenant).await.expect("begin B");
        insert_file(&mut b, fixture, second).await;
        b.commit().await.expect("commit B");
    });

    // The assertion: with A holding the counter row, B cannot get a number.
    let blocked = tokio::time::timeout(Duration::from_secs(2), async {
        // Poll rather than await the handle directly, so the handle survives for the join below.
        loop {
            if handle.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        blocked.is_err(),
        "a second writer allocated a sequence number while the first was still in flight. That is \
         precisely the window in which a reader stores a cursor above a change that has not landed \
         — and never sees it again. The counter row's lock is what is supposed to prevent it."
    );

    a.commit().await.expect("commit A");

    // The positive control: once A commits, B proceeds and lands above it.
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("B must complete once A commits")
        .expect("B's task");

    let seqs = sequences(&mut admin, fixture).await;
    assert_eq!(seqs, vec![1, 2], "the feed is not a contiguous prefix: {seqs:?}");

    let mut read = pool.begin(fixture.tenant).await.expect("begin read");
    let page =
        SyncRepository::feed(&mut read, fixture.tenant, fixture.scope(), DeltaCursor::START, 10)
            .await
            .expect("read the feed");
    read.commit().await.expect("commit read");

    let order: Vec<FileId> = page.entries.iter().map(|entry| entry.file_id).collect();
    assert_eq!(
        order,
        vec![first, second],
        "the feed's order is not the order the transactions committed in"
    );
}

/// An aborted writer leaves no hole, because the counter rolls back with it.
///
/// This is the half a PostgreSQL `SEQUENCE` cannot give: `nextval` is non-transactional, so a
/// rolled-back writer burns its number permanently and a client cannot tell "5 was abandoned" from
/// "5 has not landed yet".
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_aborted_write_leaves_no_gap_in_the_sequence() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let mut doomed = pool.begin(fixture.tenant).await.expect("begin");
    insert_file(&mut doomed, fixture, FileId::new_v7()).await;
    drop(doomed); // rolls back

    let survivor = FileId::new_v7();
    let mut kept = pool.begin(fixture.tenant).await.expect("begin");
    insert_file(&mut kept, fixture, survivor).await;
    kept.commit().await.expect("commit");

    let seqs = sequences(&mut admin, fixture).await;
    assert_eq!(
        seqs,
        vec![1],
        "the abandoned transaction burned a sequence number: {seqs:?}. A client resuming from 1 \
         would wait for a change that will never arrive."
    );
}

/// A client replaying from an old cursor converges, and sees nothing twice.
///
/// `docs/10 §4`: *"A client that replays from an old cursor converges; it never needs a full
/// re-scan."*
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn replaying_from_an_old_cursor_converges_without_duplicates() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let files: Vec<FileId> = (0..5).map(|_| FileId::new_v7()).collect();
    for file in &files {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        insert_file(&mut tx, fixture, *file).await;
        tx.commit().await.expect("commit");
    }

    // Page through two at a time from the beginning, exactly as a client would.
    let mut cursor = DeltaCursor::START;
    let mut seen: Vec<FileId> = Vec::new();
    loop {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        let page = SyncRepository::feed(&mut tx, fixture.tenant, fixture.scope(), cursor, 2)
            .await
            .expect("read");
        tx.commit().await.expect("commit");
        seen.extend(page.entries.iter().map(|entry| entry.file_id));
        cursor = page.next_cursor;
        if !page.has_more {
            break;
        }
    }
    assert_eq!(seen, files, "paging did not return every change exactly once");

    // Replay from the middle. Everything above the cursor, nothing below it, nothing twice.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let replay = SyncRepository::feed(
        &mut tx,
        fixture.tenant,
        fixture.scope(),
        DeltaCursor::new(2).expect("a valid position"),
        100,
    )
    .await
    .expect("read");
    tx.commit().await.expect("commit");
    let replayed: Vec<FileId> = replay.entries.iter().map(|entry| entry.file_id).collect();
    assert_eq!(replayed, files[2..], "a replay did not converge on the tail");
}

/// Several changes to one file inside one window collapse to the newest, and the cursor still
/// advances past all of them.
///
/// # Why the changes are interleaved
///
/// The feed is `X, Y, X` rather than `X, X, X`, and that is the whole test. Collapsing keeps each
/// file at the position of its *first* appearance, so after the collapse the last **emitted** entry
/// is `Y` at sequence 2 while the last **scanned** row was `X` at sequence 3. A cursor taken from
/// the emitted rows would therefore be 2, and the next call would re-deliver sequence 3 for ever.
/// With three changes to one file the two numbers coincide and the bug is invisible — which is how
/// the first version of this test passed against an implementation that had it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn repeated_changes_to_one_file_collapse_but_do_not_shorten_the_cursor() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let first = FileId::new_v7();
    let second = FileId::new_v7();
    for file in [first, second] {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        insert_file(&mut tx, fixture, file).await;
        tx.commit().await.expect("commit");
    }

    // A third change, to the *first* file — so the newest row in the window belongs to the entry
    // that sits first after the collapse.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    sqlx::query("UPDATE files SET modified_at = now() WHERE tenant_id = $1 AND id = $2")
        .bind(fixture.tenant.as_uuid())
        .bind(first.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("touch the file");
    tx.commit().await.expect("commit");

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let page =
        SyncRepository::feed(&mut tx, fixture.tenant, fixture.scope(), DeltaCursor::START, 100)
            .await
            .expect("read");
    tx.commit().await.expect("commit");

    assert_eq!(page.entries.len(), 2, "three changes to two files produced three entries");
    assert_eq!(
        page.entries.last().map(|entry| entry.seq),
        Some(2),
        "the collapse did not keep each file at its first position"
    );
    assert_eq!(
        page.next_cursor.get(),
        3,
        "the cursor tracked the last *emitted* row rather than the last *scanned* one, so the next \
         call would re-deliver sequence 3 — for ever, on every poll"
    );

    // And the resumption is empty, which is the property the number is for.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let next =
        SyncRepository::feed(&mut tx, fixture.tenant, fixture.scope(), page.next_cursor, 100)
            .await
            .expect("read");
    tx.commit().await.expect("commit");
    assert!(next.entries.is_empty(), "resuming from the cursor re-delivered a change");
}

/// A cursor the feed no longer reaches is `CURSOR_TOO_OLD`, not an empty page.
///
/// An empty page is the dangerous answer: the client would conclude it is up to date and stop.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_pruned_or_impossible_cursor_is_refused_rather_than_answered_empty() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    for _ in 0..3 {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        insert_file(&mut tx, fixture, FileId::new_v7()).await;
        tx.commit().await.expect("commit");
    }

    // A cursor above the high-water mark cannot have come from this feed.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let refused = SyncRepository::feed(
        &mut tx,
        fixture.tenant,
        fixture.scope(),
        DeltaCursor::new(99).expect("a position"),
        10,
    )
    .await;
    tx.commit().await.expect("commit");
    assert!(
        matches!(refused, Err(SyncError::CursorTooOld)),
        "a cursor past the end of the feed was answered with a page: {refused:?}"
    );

    // Prune the first two entries, as the 30-day window will.
    sqlx::query("DELETE FROM sync_change_log WHERE tenant_id = $1 AND seq <= 2")
        .bind(fixture.tenant.as_uuid())
        .execute(&mut admin)
        .await
        .expect("prune");

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let pruned =
        SyncRepository::feed(&mut tx, fixture.tenant, fixture.scope(), DeltaCursor::START, 10)
            .await;
    tx.commit().await.expect("commit");
    assert!(
        matches!(pruned, Err(SyncError::CursorTooOld)),
        "a cursor below the retained window was answered with a partial page, which the client \
         would apply and then believe itself up to date: {pruned:?}"
    );

    // The positive control: a client that is exactly up to date with what is retained is served.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let served = SyncRepository::feed(
        &mut tx,
        fixture.tenant,
        fixture.scope(),
        DeltaCursor::new(2).expect("a position"),
        10,
    )
    .await
    .expect("a cursor at the edge of the window is still valid");
    tx.commit().await.expect("commit");
    assert_eq!(served.entries.len(), 1);
}

/// The feed is a tenant's own, and this test says which layer proves it.
///
/// **This proves row-level security, not the application predicate**, and the distinction is the
/// point: deleting `cl.tenant_id = $1` from `FEED_WINDOW_SQL` leaves this test passing, because RLS
/// holds the property on its own. Six crates in this repository have learned that the hard way. The
/// authorization layer's own cross-tenant behaviour is asserted in `crates/api/tests/sync.rs`,
/// where a *same-tenant* caller without the grant is refused — the case RLS has nothing to say
/// about.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_feed_is_invisible_to_another() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let alpha = Fixture::new();
    let beta = Fixture::new();
    alpha.insert(&mut admin).await;
    beta.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let mut tx = pool.begin(beta.tenant).await.expect("begin");
    insert_file(&mut tx, beta, FileId::new_v7()).await;
    tx.commit().await.expect("commit");

    // Alpha asks for beta's library by id. The scope is well-formed and the rows exist.
    let mut tx = pool.begin(alpha.tenant).await.expect("begin");
    let page =
        SyncRepository::feed(&mut tx, alpha.tenant, beta.scope(), DeltaCursor::START, 10).await;
    tx.commit().await.expect("commit");
    match page {
        Ok(page) => assert!(
            page.entries.is_empty(),
            "another tenant's changes were served: {} entries",
            page.entries.len()
        ),
        // `CursorTooOld` is also an acceptable answer here and is the honest one: from alpha's side
        // the scope has no high-water mark at all, so cursor 0 > high 0 is false and the read is
        // simply empty. Asserting either outcome is fine; asserting *entries* is what matters.
        Err(error) => panic!("a cross-tenant read failed for the wrong reason: {error:?}"),
    }

    // The positive control: beta sees its own change. Without this, an implementation that returned
    // nothing to everybody would pass the assertion above.
    let mut tx = pool.begin(beta.tenant).await.expect("begin");
    let own = SyncRepository::feed(&mut tx, beta.tenant, beta.scope(), DeltaCursor::START, 10)
        .await
        .expect("beta reads its own feed");
    tx.commit().await.expect("commit");
    assert_eq!(own.entries.len(), 1, "the fixture wrote nothing readable");
}

// ---------------------------------------------------------------------------------------------
// The device registry and the wipe
// ---------------------------------------------------------------------------------------------

/// A wipe stamps the request, moves the device to `WIPING`, and **stops it being served**.
///
/// The last clause is the one that is easy to leave out and is the only one that acts without the
/// device's cooperation.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_wipe_is_requested_and_only_acknowledged_by_the_device() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let registration = Registration {
        user_id: fixture.user,
        name: "laptop".to_owned(),
        platform: "macos".to_owned(),
        client_version: "1.0.0".to_owned(),
    };

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let device = SyncRepository::register(&mut tx, fixture.tenant, &registration, Utc::now())
        .await
        .expect("register");
    tx.commit().await.expect("commit");
    assert_eq!(device.state, DeviceState::Active);
    assert!(device.may_sync(), "a freshly registered device must be able to sync");
    assert!(!device.wipe_outstanding());

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let wiping =
        SyncRepository::request_wipe(&mut tx, fixture.tenant, device.device_id, Utc::now())
            .await
            .expect("request the wipe");
    tx.commit().await.expect("commit");

    assert_eq!(wiping.state, DeviceState::Wiping);
    assert!(wiping.wipe_requested_at.is_some());
    assert!(
        wiping.wiped_at.is_none(),
        "the server stamped `wiped_at` on its own behalf. Nothing has run on the device; recording \
         a completed wipe is the one thing a wipe record must not do (docs/10 §3.1)."
    );
    assert!(wiping.wipe_outstanding(), "an unacknowledged wipe must read as outstanding");
    assert!(
        !wiping.may_sync(),
        "a device told to wipe is still being served changes; the wipe would be undone by the next \
         poll"
    );

    // Only the device's own acknowledgement completes it.
    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let wiped =
        SyncRepository::acknowledge_wipe(&mut tx, fixture.tenant, device.device_id, Utc::now())
            .await
            .expect("acknowledge");
    tx.commit().await.expect("commit");
    assert_eq!(wiped.state, DeviceState::Wiped);
    assert!(wiped.wiped_at.is_some());
    assert!(!wiped.wipe_outstanding());
    assert!(!wiped.may_sync());
}

/// The fan-out bound is enforced, and the row is written in the transaction that checked it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_user_cannot_exceed_the_device_bound() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let registration = Registration {
        user_id: fixture.user,
        name: "laptop".to_owned(),
        platform: "macos".to_owned(),
        client_version: "1.0.0".to_owned(),
    };

    let mut held = Vec::new();
    for _ in 0..enclave_sync::MAX_DEVICES_PER_USER {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        held.push(
            SyncRepository::register(&mut tx, fixture.tenant, &registration, Utc::now())
                .await
                .expect("register"),
        );
        tx.commit().await.expect("commit");
    }

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let refused =
        SyncRepository::register(&mut tx, fixture.tenant, &registration, Utc::now()).await;
    tx.commit().await.expect("commit");
    assert!(
        matches!(refused, Err(SyncError::Validation(_))),
        "the sixth device was accepted: {refused:?}"
    );

    // The positive control for the bound's *shape*: a revoked device frees a slot, because the
    // bound is on how many machines hold copies rather than on how many were ever enrolled.
    sqlx::query(
        "UPDATE sync_devices SET state = 'REVOKED' WHERE tenant_id = $1 AND device_id = $2",
    )
    .bind(fixture.tenant.as_uuid())
    .bind(held[0].device_id.as_uuid())
    .execute(&mut admin)
    .await
    .expect("revoke");

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let accepted =
        SyncRepository::register(&mut tx, fixture.tenant, &registration, Utc::now()).await;
    tx.commit().await.expect("commit");
    assert!(accepted.is_ok(), "revoking a device did not free a slot: {accepted:?}");
}

/// A device id that belongs to another tenant is simply absent.
///
/// As with the feed, **this proves row-level security**: the statement's own `tenant_id` predicate
/// and RLS both hold it, and removing the predicate leaves the test passing. It is here because the
/// device registry is the one place a caller could otherwise enumerate machine names across a
/// deployment, and a structural assertion that the boundary is in place is worth having even when
/// it cannot say which layer held.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_device_is_invisible_outside_its_tenant() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let alpha = Fixture::new();
    let beta = Fixture::new();
    alpha.insert(&mut admin).await;
    beta.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let mut tx = pool.begin(beta.tenant).await.expect("begin");
    let device = SyncRepository::register(
        &mut tx,
        beta.tenant,
        &Registration {
            user_id: beta.user,
            name: "beta laptop".to_owned(),
            platform: "windows".to_owned(),
            client_version: "1.0.0".to_owned(),
        },
        Utc::now(),
    )
    .await
    .expect("register");
    tx.commit().await.expect("commit");

    let mut tx = pool.begin(alpha.tenant).await.expect("begin");
    let found = SyncRepository::find(&mut tx, alpha.tenant, device.device_id).await.expect("find");
    tx.commit().await.expect("commit");
    assert!(found.is_none(), "another tenant's device was visible");

    // The positive control: beta finds its own.
    let mut tx = pool.begin(beta.tenant).await.expect("begin");
    let own = SyncRepository::find(&mut tx, beta.tenant, device.device_id).await.expect("find");
    tx.commit().await.expect("commit");
    assert!(own.is_some(), "the device was not readable by the tenant that owns it");
}

/// A wipe against a device this tenant does not have is an absence, not a `403`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn wiping_a_device_that_is_not_this_tenants_is_an_absence() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let fixture = Fixture::new();
    fixture.insert(&mut admin).await;
    let pool = db.pool_with_connections(2).await.expect("pool");

    let mut tx = pool.begin(fixture.tenant).await.expect("begin");
    let refused =
        SyncRepository::request_wipe(&mut tx, fixture.tenant, DeviceId::new_v7(), Utc::now()).await;
    tx.commit().await.expect("commit");
    assert!(matches!(refused, Err(SyncError::NoSuchDevice)), "{refused:?}");
}

/// The counter is per scope, so two libraries do not share a sequence.
///
/// A shared counter would still be monotonic and would still never lose a change — it would simply
/// make every client re-read every other library's changes to find its own, which is the kind of
/// defect that shows up as a bandwidth bill rather than as a bug.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn each_scope_carries_its_own_sequence() {
    let db = TestDb::start().await.expect("a test database");
    let mut admin = db.connect().await.expect("connect");
    let first = Fixture::new();
    first.insert(&mut admin).await;

    // A second library in the same tenant and workspace.
    let second = Fixture { library: LibraryId::new_v7(), ..first };
    sqlx::query(
        "INSERT INTO libraries
           (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
            external_sharing, sync_enabled, created_at, updated_at)
         VALUES ($1, $2, $3, 'lib2', $4, TRUE, 'MAJOR', 'DISABLED', TRUE, now(), now())",
    )
    .bind(second.library.as_uuid())
    .bind(second.tenant.as_uuid())
    .bind(second.workspace.as_uuid())
    .bind(format!("lib-{}", second.library.as_uuid()))
    .execute(&mut admin)
    .await
    .expect("insert the second library");

    let pool = db.pool_with_connections(2).await.expect("pool");
    for fixture in [first, second, first] {
        let mut tx = pool.begin(fixture.tenant).await.expect("begin");
        insert_file(&mut tx, fixture, FileId::new_v7()).await;
        tx.commit().await.expect("commit");
    }

    assert_eq!(sequences(&mut admin, first).await, vec![1, 2]);
    assert_eq!(sequences(&mut admin, second).await, vec![1]);
}

/// The counter row is not deletable by the application role, and the reason is in the migration.
///
/// A `DELETE` here restarts a scope at 1, and every device holding a higher cursor stops receiving
/// changes silently and permanently. Asserted as a grant rather than as behaviour, because the
/// behaviour is a wrong answer nobody would notice.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_cannot_delete_a_scope_counter_or_a_device() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");

    for (table, deletable) in [
        ("sync_scope_sequences", false),
        ("sync_devices", false),
        ("sync_cursors", false),
        // The one exception, argued in the migration: a retention-bounded derived feed whose
        // pruning has a specified consequence.
        ("sync_change_log", true),
    ] {
        let granted: bool =
            sqlx::query_scalar("SELECT has_table_privilege('enclave_app', $1, 'DELETE')")
                .bind(table)
                .fetch_one(&mut conn)
                .await
                .expect("read the grant");
        assert_eq!(
            granted, deletable,
            "enclave_app's DELETE on {table} is {granted}, expected {deletable} \
             (migrations/0023_sync_devices.sql)"
        );
    }
}

/// Every table 0023 creates is tenant-scoped in the way `CLAUDE.md` rule 4 requires.
///
/// The workspace-wide gates in `crates/db/tests` already assert this over the whole schema. It is
/// restated here for one reason: those gates enumerate the catalog, so a migration that failed to
/// *create* a table would leave them green with one fewer table to check.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_table_this_migration_creates_exists_and_is_forced() {
    let db = TestDb::start().await.expect("a test database");
    let mut conn = db.connect().await.expect("connect");

    for table in ["sync_devices", "sync_cursors", "sync_scope_sequences", "sync_change_log"] {
        let row = sqlx::query(
            "SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'public' AND c.relname = $1",
        )
        .bind(table)
        .fetch_optional(&mut conn)
        .await
        .expect("read the catalog")
        .unwrap_or_else(|| panic!("{table} was not created by migration 0023"));

        assert!(row.get::<bool, _>("enabled"), "{table} has row security disabled");
        assert!(row.get::<bool, _>("forced"), "{table} does not force row security");
    }

    // And the trigger, which is what makes the feed complete rather than a table nobody writes.
    let trigger: Option<String> = sqlx::query_scalar(
        "SELECT tgname FROM pg_catalog.pg_trigger
          WHERE tgrelid = 'public.files'::regclass AND tgname = 'sync_files_change_feed'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("read pg_trigger");
    assert!(
        trigger.is_some(),
        "the change-feed trigger is not attached to `files`; the delta would be permanently empty \
         and every device would believe itself up to date"
    );
}
