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
/// Only one case is special-cased, and it earns it: the cluster-wide role race (`ENC-116`). Every
/// other failure passes through unchanged, because inventing friendly text for errors we have not
/// actually seen produces confident, wrong advice.
fn classify_migration_failure(error: sqlx::migrate::MigrateError) -> DbError {
    if is_role_creation_race(&error) {
        return DbError::RolesNotProvisioned { source: error };
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
    #[ignore = "needs PostgreSQL; runs under ENC-112's testcontainers harness"]
    async fn migrations_apply_to_an_empty_database_and_are_idempotent() {
        let config = crate::test_support::test_config();
        let (url, field) = config.migration_target().expect("the harness configures an owner url");
        let options = url.connect_options(field).expect("valid url");
        let mut conn = PgConnection::connect_with(&options).await.expect("connect");

        run_migrations_on(&mut conn).await.expect("first apply");
        // Running twice is not a hypothetical: every replica does it on every rollout.
        run_migrations_on(&mut conn).await.expect("second apply must be a no-op");
    }
}
