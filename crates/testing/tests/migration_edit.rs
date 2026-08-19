//! `ENC-172` — proves that editing an already-applied migration fails *legibly*.
//!
//! The refusal itself is not in question and must not be softened: migrations are forward-only and
//! checksummed (`CLAUDE.md`, SQL conventions), and the comparison that fires here is that gate.
//! What was wrong is that it fired as `Migrate(VersionMismatch(9))` — a variant name and an
//! integer, with no migration named, no cause given and no remedy, in the one situation where
//! editing a migration is legitimate: one that is not merged yet, being iterated on against a
//! database that has already applied an earlier draft. It cost three attempts to verify an
//! unrelated change before that was worked out.
//!
//! # Why the checksum is edited rather than the file
//!
//! The gate compares the checksum recorded in `_sqlx_migrations` against the checksum embedded in
//! the binary, so overwriting the recorded one reproduces "this migration changed under you"
//! exactly — and does it from a test, which cannot edit a `.sql` and rebuild itself. `enclave-db`'s
//! `an_edited_migration_names_itself_and_the_way_out` covers the classifier in isolation; this
//! covers the part that unit test cannot, that sqlx really does raise `VersionMismatch` here and
//! that it really does arrive at the classifier.
//!
//! This runs against `TestDb`'s throwaway database and never against the one `DATABASE_URL` names.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_db::{run_migrations_on, DbError, MIGRATIONS};
use enclave_testing::TestDb;

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_edited_migration_is_refused_by_name_and_with_a_remedy() {
    let db = TestDb::start().await.expect("start a test database");
    let mut conn = db.connect().await.expect("connect");

    // The last migration, because that is the one a person iterating on an unmerged change is
    // editing. Read from the embedded set rather than hardcoded, so this keeps testing the newest
    // migration as the tree grows instead of quietly pinning itself to 0009.
    let edited = MIGRATIONS.iter().last().expect("at least one migration").version;

    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(vec![0_u8; 4])
        .bind(edited)
        .execute(&mut conn)
        .await
        .expect("rewrite the recorded checksum");

    let error = run_migrations_on(&mut conn).await.expect_err(
        "a migration whose recorded checksum no longer matches must not be re-applied, and must \
         not be skipped either",
    );

    let DbError::MigrationModified { version, .. } = &error else {
        panic!("the forward-only gate fired but said nothing actionable: {error:?}");
    };
    assert_eq!(*version, edited, "the error must name the migration that actually changed");

    let message = error.to_string();
    assert!(
        message.contains(&edited.to_string()),
        "someone reading the log gets the version or gets nothing: {message}"
    );
    assert!(
        message.contains("_sqlx_migrations"),
        "the remedy has to be the command, not a description of one: {message}"
    );
    assert!(
        message.contains("forward-only") && message.contains("add a new migration"),
        "a merged migration must be sent forward rather than reset, or this message becomes the \
         documented way round the gate: {message}"
    );

    drop(conn);
    drop(db);
}
