//! The migration runner.
//!
//! # Why the migrations are embedded rather than read from disk
//!
//! `sqlx::migrate!` reads `migrations/` at **compile** time and bakes the statements and their
//! checksums into the binary. That gives three properties worth having:
//!
//! * a release artifact carries the exact schema it was built against, so a container cannot be
//!   deployed next to the wrong copy of the SQL;
//! * the checksums are computed from what shipped, so an edit to an already-applied migration is
//!   detected as a mismatch rather than silently reapplied — which is what makes "forward-only,
//!   numbered, checksummed" (`CLAUDE.md`, SQL conventions) enforceable rather than aspirational;
//! * a missing or malformed migration file is a build failure, not a startup failure in production.
//!
//! # Why this does not use the application pool
//!
//! Migrations are DDL. They must run as `enclave_migrator`, the role that *owns* every object —
//! the application role owns nothing, which is exactly what makes `FORCE ROW LEVEL SECURITY` apply
//! to it (`docs/04-DATA-MODEL.md §3.2`). Running migrations from the application pool would either
//! fail on the first `ALTER`, or, worse, succeed on a deployment where someone had "temporarily"
//! granted ownership to the application role and thereby disabled layer 2 of tenant isolation for
//! every table.
//!
//! It also opens a single connection rather than a pool: migrations run once, hold an advisory lock
//! for their duration, and a pool of idle connections holding owner privileges is a standing
//! liability for no benefit.
//!
//! This is the first of the three legitimate cross-tenant paths named in
//! `plans/M0-FOUNDATIONS.md` D3 and is on the ENC-110 lint's deny-list.

use sqlx::migrate::Migrator;
use sqlx::{Connection, PgConnection};

use crate::config::DbConfig;
use crate::DbError;

/// Every migration in the workspace's `migrations/` directory, embedded at compile time.
///
/// Exposed so that ENC-112's testcontainers harness can migrate a throwaway database without
/// constructing a [`DbConfig`], and so that an operator-facing command can list what a binary
/// believes the schema to be.
pub static MIGRATIONS: Migrator = sqlx::migrate!("../../migrations");

/// Applies every outstanding migration, connecting as the schema owner.
///
/// Uses `migration_url`, falling back to `platform_url`; with neither set this fails rather than
/// borrowing the application's credentials, for the reason in the module documentation.
///
/// Idempotent: `sqlx` records applied versions in `_sqlx_migrations` and takes an advisory lock for
/// the duration, so several replicas starting at once produce one migration run and several waits,
/// not several concurrent attempts at the same `CREATE TABLE`.
pub async fn run_migrations(config: &DbConfig) -> Result<(), DbError> {
    let (url, field) = config.migration_target().ok_or(DbError::InvalidConfig {
        field: "migration_url",
        problem: "is not set, and no platform_url is available to fall back to",
    })?;

    let options = url.connect_options(field)?.application_name("enclave-migrate");
    let mut conn = PgConnection::connect_with(&options).await.map_err(DbError::Connect)?;

    let result = run_migrations_on(&mut conn).await;

    // Closed explicitly rather than dropped: an owner-privileged connection should not outlive the
    // one job it was opened for, and a close failure here is not worth masking the migration
    // result, which is what an early `?` would do.
    if let Err(error) = conn.close().await {
        tracing::warn!(%error, "failed to close the migration connection cleanly");
    }

    result
}

/// Applies every outstanding migration on a connection the caller already holds.
///
/// The seam for ENC-112: the test harness starts a container, gets a superuser connection, and
/// needs migration 001 applied to it — including the `CREATE ROLE` statements, which the ordinary
/// migration role cannot execute. Production goes through [`run_migrations`] instead, so that the
/// role a migration runs as is a configuration decision rather than a call-site decision.
pub async fn run_migrations_on(conn: &mut PgConnection) -> Result<(), DbError> {
    tracing::info!(count = MIGRATIONS.iter().len(), "applying migrations");
    if let Err(error) = MIGRATIONS.run(&mut *conn).await {
        return Err(classify_migration_failure(error));
    }
    tracing::info!("migrations applied");
    Ok(())
}

/// Turns an unreadable migration failure into one an operator can act on.
///
/// Two cases are special-cased, and both earn it by having been met: the cluster-wide role race
/// (`ENC-116`), and an already-applied migration that has since been edited (`ENC-172`). Every
/// other failure passes through unchanged, because inventing friendly text for errors we have not
/// actually seen produces confident, wrong advice — `VersionMissing` and `Dirty` are deliberately
/// left alone for exactly that reason.
///
/// Neither case changes what happens: both still fail, and the checksum comparison behind the
/// second *is* the forward-only gate. What changes is that the message names the migration and the
/// way out, rather than being a variant name and an integer.
fn classify_migration_failure(error: sqlx::migrate::MigrateError) -> DbError {
    if is_role_creation_race(&error) {
        return DbError::RolesNotProvisioned { source: error };
    }
    if let sqlx::migrate::MigrateError::VersionMismatch(version) = &error {
        return DbError::MigrationModified { version: *version, source: error };
    }
    DbError::Migrate(error)
}

/// Whether a migration failure is the losing side of a concurrent `CREATE ROLE`.
///
/// Matched on the structured fields rather than the message string: SQLSTATE 23505
/// (`unique_violation`) against `pg_authid`, PostgreSQL's role catalogue. Message text is
/// localised and changes between releases; the SQLSTATE and the relation name do not.
///
/// Note that 42710 (`duplicate_object`, "role already exists") is deliberately **not** matched.
/// That is the sequential collision, it already reads clearly, and 0001's guard swallows it.
fn is_role_creation_race(error: &sqlx::migrate::MigrateError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(db) =
            current.downcast_ref::<sqlx::Error>().and_then(sqlx::Error::as_database_error)
        {
            let unique_violation = db.code().as_deref() == Some("23505");
            let against_roles = db.table() == Some("pg_authid")
                || db.constraint().is_some_and(|c| c.contains("pg_authid"));
            if unique_violation && against_roles {
                return true;
            }
        }
        source = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_binary_carries_at_least_the_foundation_migration() {
        // A compile-time embed that silently resolved to an empty directory would leave every
        // deployment with no schema and no error, so assert that something is actually in there.
        assert!(MIGRATIONS.iter().len() >= 1, "no migrations were embedded");
        let first = MIGRATIONS.iter().next().expect("at least one migration");
        assert_eq!(first.version, 1, "migration numbering must start at 0001");
    }

    #[test]
    fn migrations_are_forward_only() {
        // `docs/11-OPERATIONS.md §8`: there are no down-migrations by design. A reversible
        // migration appearing here means someone added a `.down.sql`, which changes the operational
        // model and must be a conscious decision rather than a file that slipped in.
        for migration in MIGRATIONS.iter() {
            assert!(
                !migration.migration_type.is_down_migration(),
                "migration {} is a down migration",
                migration.version
            );
        }
    }

    #[test]
    fn migration_versions_are_unique_and_ascending() {
        // Two files claiming the same version apply in an order that depends on the filesystem;
        // catching it here is cheaper than catching it in a production apply.
        let mut previous: Option<i64> = None;
        for migration in MIGRATIONS.iter() {
            if let Some(previous) = previous {
                assert!(
                    migration.version > previous,
                    "migration {} does not follow {previous}",
                    migration.version
                );
            }
            previous = Some(migration.version);
        }
    }

    #[test]
    fn an_edited_migration_names_itself_and_the_way_out() {
        // `ENC-172`. The raw failure is `Migrate(VersionMismatch(9))`, which is a variant name and
        // an integer: it says neither what was edited nor what to do, and the remedy is destructive
        // enough that guessing is expensive. Assert the message carries both.
        let classified =
            classify_migration_failure(sqlx::migrate::MigrateError::VersionMismatch(9));

        let DbError::MigrationModified { version, .. } = &classified else {
            panic!("an edited migration must not stay an opaque Migrate: {classified:?}");
        };
        assert_eq!(*version, 9);

        let message = classified.to_string();
        assert!(message.contains('9'), "the message must name the migration: {message}");
        assert!(
            message.contains("_sqlx_migrations"),
            "the message must give the remedy verbatim, not describe it: {message}"
        );
        assert!(
            message.contains("forward-only") && message.contains("add a new migration"),
            "the message must send someone with a *merged* migration forward, not backward, or it \
             becomes a documented way round the gate: {message}"
        );
        assert!(
            !classified.is_retryable(),
            "the checksums will not agree on the next attempt, and a retry loop buries the message"
        );
    }

    #[test]
    fn other_migration_failures_are_left_alone() {
        // The classifier's value is that it is narrow. A dirty migration and a missing one have
        // different causes and different remedies; folding them in here would attach confident,
        // wrong advice to failures nobody has actually diagnosed.
        for error in
            [sqlx::migrate::MigrateError::Dirty(3), sqlx::migrate::MigrateError::VersionMissing(3)]
        {
            assert!(
                matches!(classify_migration_failure(error), DbError::Migrate(_)),
                "only the two diagnosed failures are re-worded"
            );
        }
    }

    #[tokio::test]
    async fn migrating_without_an_owner_credential_is_refused_rather_than_improvised() {
        // The failure that matters: falling back to the application role would either fail on the
        // first `ALTER` or, on a misconfigured deployment, succeed and make the application an
        // owner — which switches off `FORCE ROW LEVEL SECURITY` for it.
        let config = crate::DbConfig::new("postgres://enclave_app@localhost/enclave");
        let err = run_migrations(&config).await.expect_err("must refuse");
        assert!(matches!(err, DbError::InvalidConfig { field: "migration_url", .. }));
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn migrations_apply_to_an_empty_database_and_are_idempotent() {
        // `TestDb::start` **is** the first apply: it creates an empty database and runs every
        // migration on it, so the `expect` below is the first half of this test's name. That half
        // is asserted there rather than here on purpose — the harness holds the setup lock across
        // the run, and migration 0001's `CREATE ROLE` guard is check-then-act, so a first apply
        // issued from here would race every other test binary in the cluster (`ENC-116`).
        //
        // A throwaway database rather than the one `DATABASE_URL` names: applying migrations to a
        // developer's dev stack records their checksums in it, and that is `ENC-504`.
        let db = enclave_testing::TestDb::start()
            .await
            .expect("migrations must apply to a fresh, empty database");
        let mut conn = db.connect().await.expect("connect");

        // Re-applying is not a hypothetical: every replica does it on every rollout. Safe outside
        // the setup lock, because every migration is already recorded as applied — sqlx runs no
        // statement at all, so there is no second `CREATE ROLE` to race with.
        run_migrations_on(&mut conn).await.expect("second apply must be a no-op");
        run_migrations_on(&mut conn).await.expect("third apply must be a no-op");
    }
}

#[cfg(test)]
mod rebuild_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    /// The build script still tells Cargo to watch `migrations/`.
    ///
    /// `ENC-155`: without that directive, editing a `.sql` rebuilds nothing, because the macro's
    /// input is a directory no `.rs` file mentions. Every schema gate in the workspace applies
    /// migrations through this crate and then inspects the result — so a stale build means those
    /// gates report **green against a schema nobody is running**, which is how the defect was
    /// found: a deliberate violation failed to fail.
    ///
    /// Asserted by reading the build script rather than by observing a rebuild, because a test
    /// cannot watch Cargo decide. It is a guard against deletion, not a proof of the mechanism —
    /// the mechanism was proven by removing `FORCE ROW LEVEL SECURITY` from a migration and
    /// watching the RLS gate fail by name without anything being touched.
    #[test]
    fn the_build_script_watches_the_migrations_directory() {
        let script = include_str!("../build.rs");
        assert!(
            script.contains("cargo:rerun-if-changed=../../migrations"),
            "the migrations rerun-if-changed directive is gone; editing a .sql will silently not \
             reach the binary, and every schema gate will pass against a stale schema (ENC-155)"
        );
    }
}
