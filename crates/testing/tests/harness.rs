//! Proves the harness itself works. If these fail, every test that relies on it is suspect.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use enclave_testing::TestDb;
use sqlx::Row;

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_test_database_is_created_migrated_and_seeded() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let mut conn = db.connect().await.expect("connect");

    let tenants: i64 = sqlx::query("SELECT count(*) AS n FROM tenants")
        .fetch_one(&mut conn)
        .await
        .expect("count tenants")
        .get("n");
    assert_eq!(tenants, 2, "both fixture tenants should exist");

    let users: i64 = sqlx::query("SELECT count(*) AS n FROM users WHERE tenant_id = $1")
        .bind(fixtures.alpha.id.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("count users")
        .get("n");
    assert_eq!(users, 5, "tenant-alpha should have its five principals");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn seeding_is_idempotent() {
    // The seed command (ENC-115) and the harness both call this. Running it twice must not
    // duplicate rows or fail, or "re-seed the dev database" becomes a destructive operation.
    let db = TestDb::start().await.expect("start");
    db.seed().await.expect("first seed");
    db.seed().await.expect("second seed");

    let mut conn = db.connect().await.expect("connect");
    let users: i64 = sqlx::query("SELECT count(*) AS n FROM users")
        .fetch_one(&mut conn)
        .await
        .expect("count")
        .get("n");
    assert_eq!(users, 10, "two tenants of five users, not duplicated");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn each_handle_gets_its_own_database() {
    // Test binaries run concurrently. If two handles shared a database, one binary's fixtures would
    // appear in another's assertions and the failures would be maddening to reproduce.
    let a = TestDb::start().await.expect("a");
    let b = TestDb::start().await.expect("b");
    assert_ne!(a.name(), b.name());

    a.seed().await.expect("seed a");
    let mut conn_b = b.connect().await.expect("connect b");
    let users: i64 = sqlx::query("SELECT count(*) AS n FROM users")
        .fetch_one(&mut conn_b)
        .await
        .expect("count")
        .get("n");
    assert_eq!(users, 0, "seeding one database must not touch another");
}
