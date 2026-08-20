//! `ENC-504` option (b) — the harness leaves the database it was pointed at alone.
//!
//! # The failure this removes
//!
//! A migration applied to the database `DATABASE_URL` names records that migration's **checksum**
//! there. Locally that database is a developer's dev stack, not a throwaway. So: edit an unmerged
//! migration, run the tests, switch branches — and every subsequent run fails the forward-only
//! checksum gate on a migration you are no longer editing. The gate is correct; the state it is
//! comparing against was written by the test run itself. It cost three interruptions in one
//! afternoon, and `ENC-172` had already improved the *message* twice by then, which is what
//! finally made the point that the class had to go rather than be labelled better.
//!
//! # Why this asserts rather than reads
//!
//! The obvious test — "assert `DATABASE_URL`'s database has no `_sqlx_migrations`" — is wrong in
//! the environment that matters most. A developer's dev-stack database is *supposed* to be
//! migrated; the application runs against it. Such a test would fail for everyone with a working
//! stack and, worse, would pass vacuously against a broken harness on any database that was
//! already migrated with the same checksums, which is exactly the case where a broken harness does
//! no harm.
//!
//! So the shared database is stood in for. An empty, unmigrated throwaway plays the part of
//! `DATABASE_URL`; a complete harness lifecycle — create, migrate, seed, pool, drop — is pointed at
//! it; and then the stand-in is examined. It is empty at the start whatever the developer's real
//! database contains, so "still empty afterwards" is a claim with only one way to be true.
//!
//! What remains, deliberately, is that the stand-in is itself created from the real `DATABASE_URL`
//! by `CREATE DATABASE`. That is unavoidable: a cluster-level statement has to be issued from
//! inside some database. It adds a `pg_database` row and removes it again, and writes nothing
//! inside the administrative database.
//!
//! The last test in this file is the odd one out: it reads the source tree instead of a database,
//! and it is not `#[ignore]`d. It is here because the two above cannot run without PostgreSQL, and
//! the regression they guard against — some new file reaching for `DATABASE_URL` and migrating it —
//! is one a compiler-only check can catch. It is a guard against a habit returning, not a proof
//! that the harness behaves; the two tests above are the proof.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use enclave_testing::TestDb;
use sqlx::{PgConnection, Row};

/// Whether `public._sqlx_migrations` exists in the database this connection is attached to.
///
/// `to_regclass` rather than a query against the table: a missing table is the expected answer, and
/// `SELECT ... FROM _sqlx_migrations` would raise `42P01` instead of returning `false`, which is a
/// harder thing to assert on and an easier thing to get accidentally right.
async fn has_migration_table(conn: &mut PgConnection) -> bool {
    sqlx::query("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL AS present")
        .fetch_one(conn)
        .await
        .expect("probe for _sqlx_migrations")
        .get("present")
}

/// Every ordinary or partitioned table in `public`.
async fn public_tables(conn: &mut PgConnection) -> Vec<String> {
    sqlx::query(
        r"
        SELECT c.relname AS table_name
        FROM pg_catalog.pg_class     c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
        ORDER BY c.relname
        ",
    )
    .fetch_all(conn)
    .await
    .expect("enumerate public tables")
    .iter()
    .map(|r| r.get::<String, _>("table_name"))
    .collect()
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_full_harness_lifecycle_writes_nothing_to_the_database_it_was_pointed_at() {
    // The stand-in for `DATABASE_URL`. Unmigrated, so the assertions at the bottom start from a
    // state that cannot already satisfy them.
    let shared = TestDb::start_unmigrated().await.expect("create the stand-in shared database");

    {
        let mut conn = shared.connect().await.expect("connect to the stand-in");
        assert!(
            !has_migration_table(&mut conn).await,
            "the stand-in must start unmigrated, or nothing below distinguishes a harness that \
             leaves it alone from one that does not"
        );
        assert!(
            public_tables(&mut conn).await.is_empty(),
            "the stand-in must start empty for the same reason"
        );
    }

    // A whole lifecycle, not just `start`: seeding and a pool are where a harness would most
    // plausibly reach for "the" database rather than its own.
    {
        let db = TestDb::start_on(shared.url()).await.expect("start a test database");
        assert_ne!(
            db.name(),
            shared.name(),
            "the harness must not hand back the database it was given"
        );

        let fixtures = db.seed().await.expect("seed");
        let pool = db.pool().await.expect("pool");

        // Prove the throwaway really was migrated and seeded — otherwise this test would pass just
        // as well against a harness that does nothing at all, which is the other way to leave the
        // shared database untouched and is not the property being claimed.
        let mut own = db.connect().await.expect("connect to the throwaway");
        assert!(has_migration_table(&mut own).await, "the throwaway database must be migrated");
        let tenants: i64 = sqlx::query("SELECT count(*) AS n FROM tenants WHERE id = $1")
            .bind(fixtures.alpha.id.as_uuid())
            .fetch_one(&mut own)
            .await
            .expect("count")
            .get("n");
        assert_eq!(tenants, 1, "the throwaway database must be seeded");

        drop(own);
        pool.close().await;
    }

    // Now the claim itself.
    let mut conn = shared.connect().await.expect("reconnect to the stand-in");
    assert!(
        !has_migration_table(&mut conn).await,
        "the harness recorded migration state in the database it was pointed at. That is ENC-504: \
         on a developer's machine this database is their dev stack, and the checksum written here \
         fails the forward-only gate on every later run against a different branch."
    );
    let leftovers = public_tables(&mut conn).await;
    assert!(
        leftovers.is_empty(),
        "the harness created tables in the database it was pointed at: {leftovers:?}"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_throwaway_database_is_gone_once_its_handle_is() {
    // The other half of "does not accumulate state": the harness's own databases have to go away
    // too, or a week of local runs leaves a cluster full of `enclave_test_*` orphans and the next
    // person to look assumes the cleanup was never written.
    let shared = TestDb::start_unmigrated().await.expect("create the stand-in shared database");

    let name = {
        let db = TestDb::start_on(shared.url()).await.expect("start");
        // An open session against the throwaway is the case that used to block DROP DATABASE and
        // leak one database per run; `pg_terminate_backend` in the cleanup path is what handles it.
        let _pool = db.pool().await.expect("pool");
        let _held = db.connect().await.expect("hold a connection open");
        db.name().to_owned()
    };

    let mut conn = shared.connect().await.expect("connect to the stand-in");
    let survivors: i64 = sqlx::query("SELECT count(*) AS n FROM pg_database WHERE datname = $1")
        .bind(&name)
        .fetch_one(&mut conn)
        .await
        .expect("look for the dropped database")
        .get("n");
    assert_eq!(survivors, 0, "{name} outlived its handle; test databases must not accumulate");
}

/// Every file permitted to read `DATABASE_URL` from the environment, and why.
///
/// The shape of an exemption is defined here rather than invented under pressure, the same way
/// `EXEMPT` is defined in the coverage gates. Adding an entry is a reviewable act, and the question
/// a reviewer should ask is the one this whole change is about: does this file go on to *write* to
/// the database it just resolved?
const MAY_READ_DATABASE_URL: &[(&str, &str)] = &[
    (
        "crates/testing/src/lib.rs",
        "the harness itself — it resolves the administrative connection that CREATE DATABASE is \
         issued on, and migrates only the databases it creates",
    ),
    (
        "crates/testing/tests/role_race.rs",
        "ENC-117, deliberately destructive and documented as such: it drops cluster-wide roles to \
         reproduce the ENC-116 race, runs in its own CI job against its own server, and migrates \
         only the enc_race_* databases it creates and drops",
    ),
    (
        "crates/cli/src/connect.rs",
        "not a test: this is how the operator CLI resolves its target, and `enclave-cli migrate` \
         applying migrations to the database an operator named is the entire point of it",
    ),
];

/// Collects `.rs` files under `dir`.
fn rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("read a directory entry").path();
        if path.is_dir() {
            rust_files(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

#[test]
fn nothing_new_reaches_for_the_shared_database() {
    // `crates/`, from this crate's manifest directory. Walking the tree rather than grepping so the
    // gate runs wherever `cargo test` does, with no shell involved.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/testing sits two levels below the workspace root")
        .join("crates");

    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(
        files.len() > 100,
        "only {} files found; the walk is not reaching the tree",
        files.len()
    );

    // Assembled at runtime rather than written as a literal, for the same reason the secrets gate
    // makes tests assemble PEM banners: a gate whose needle appears verbatim in its own source
    // matches itself. This one did, on its first run.
    let quoted = format!("env::va{}\"DATABASE_URL\")", "r(");
    let unquoted = format!("env::va{}DATABASE_URL", "r(");

    let mut readers = BTreeSet::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        // The read, not the mention: `DATABASE_URL` appears in comments and documentation all over
        // the workspace, and a gate that fired on those would be turned off within a week.
        if source.contains(&quoted) || source.contains(&unquoted) {
            let relative = file.strip_prefix(crates.parent().expect("workspace root")).map_or_else(
                |_| file.display().to_string(),
                |p| p.display().to_string().replace('\\', "/"),
            );
            readers.insert(relative);
        }
    }

    let permitted: BTreeSet<String> =
        MAY_READ_DATABASE_URL.iter().map(|(path, _)| (*path).to_owned()).collect();

    let unexpected: Vec<&String> = readers.difference(&permitted).collect();
    assert!(
        unexpected.is_empty(),
        "these files read DATABASE_URL and are not on the list in this test: {unexpected:?}\n\n\
         `DATABASE_URL` is a developer's own dev-stack database. A test that migrates it records \
         that migration's checksum there, and every later run from a branch without it then fails \
         the forward-only gate on a migration nobody touched — ENC-504, three interruptions in one \
         afternoon. Use `enclave_testing::TestDb`, which creates and migrates its own throwaway \
         database. If this file genuinely must resolve the shared connection, add it above with \
         the reason it does not write to what it resolves."
    );

    let gone: Vec<&String> = permitted.difference(&readers).collect();
    assert!(
        gone.is_empty(),
        "these files are on the list but no longer read DATABASE_URL: {gone:?}. A stale exemption \
         is an exemption nobody is reading — delete the entry."
    );
}
