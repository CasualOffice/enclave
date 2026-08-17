//! The crate's error type and its translation into [`enclave_core::Error`].
//!
//! Two properties drive the shape of [`DbError`]:
//!
//! 1. **Nothing here may carry a connection URL.** A PostgreSQL URL contains a password, and an
//!    error string is the shortest path from a secret to a log line (`CLAUDE.md` rule 11). The
//!    configuration variants therefore name a *field*, never a value, and the URL parse failure is
//!    deliberately not kept as a `source`.
//! 2. **The database layer decides what is retryable, not the caller.** The same dependency fails
//!    both ways — an acquire timeout is worth retrying, a check-constraint violation never is — so
//!    the distinction is made where the driver error is still in hand, and travels outward as
//!    [`enclave_core::Error::Upstream { retryable, .. }`](enclave_core::Error::Upstream).

use enclave_core::{Dependency, Error as CoreError};

/// Everything that can go wrong between this crate and PostgreSQL.
///
/// `thiserror` per `plans/M0-FOUNDATIONS.md` D2: libraries define their own error type, and the
/// conversion into the canonical [`enclave_core::Error`] happens once, here, rather than being
/// re-invented at every call site with slightly different judgement about what the client is
/// allowed to learn.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DbError {
    /// A configuration value was rejected before any connection was attempted.
    ///
    /// Carries the field name and a fixed description of the problem — never the value, because
    /// the most likely field to be wrong is also the one holding the password.
    #[error("invalid database configuration: `{field}` {problem}")]
    InvalidConfig {
        /// Which configuration field was rejected, in the spelling used by `docs/08-BYO-INFRA.md`.
        field: &'static str,
        /// What is wrong with it, as a fixed phrase.
        problem: &'static str,
    },

    /// The pool could not be established at startup.
    #[error("could not connect to postgres")]
    Connect(#[source] sqlx::Error),

    /// No connection became available within the configured acquire timeout.
    ///
    /// Separate from [`DbError::Connect`] because this is the signal that the pool is too small or
    /// that transactions are being held open too long — an operational fault with a different fix
    /// from an unreachable database.
    #[error("no pooled connection became available")]
    Acquire(#[source] sqlx::Error),

    /// Establishing the tenant context for a transaction failed.
    ///
    /// This is the one failure that must never be swallowed and retried without the `SET`: a
    /// transaction whose `app.tenant_id` was not established is a transaction that RLS will treat
    /// as having no tenant at all. See [`crate::TenantScoped`].
    #[error("could not establish the tenant context for this transaction")]
    TenantContext(#[source] sqlx::Error),

    /// Beginning, committing or rolling back a transaction failed.
    #[error("transaction control failed")]
    Transaction(#[source] sqlx::Error),

    /// A statement failed.
    #[error("database query failed")]
    Query(#[source] sqlx::Error),

    /// The migration runner failed to resolve or apply migrations.
    #[error("migration failed")]
    Migrate(#[source] sqlx::migrate::MigrateError),

    /// Two migrations raced to create the cluster-wide roles, and this one lost.
    ///
    /// Roles are cluster-wide; sqlx's migration advisory lock is keyed on the *database* name
    /// (`generate_lock_id(&database_name)`), so two processes migrating **different** databases in
    /// one cluster do not serialise. Migration 0001's `IF NOT EXISTS` guard is then check-then-act:
    /// both pass it, both issue `CREATE ROLE`, and one fails on `pg_authid_rolname_index`.
    ///
    /// This variant exists because the raw failure is unreadable. PostgreSQL reports
    /// `duplicate key value violates unique constraint "pg_authid_rolname_index"` — SQLSTATE 23505
    /// against a system catalog, with nothing connecting it to roles, to provisioning, or to what
    /// the operator should do. Sequential collisions raise 42710 with a plain "role already exists";
    /// only the racing path produces the opaque one, which is exactly the path someone meets at
    /// three in the morning on a first deploy.
    ///
    /// The race itself is an accepted risk (`ENC-116`): provisioning the roles before migrations
    /// run makes the guard a no-op, which is what `deploy/compose/init/01-roles.sql` and the
    /// production provisioning step in `docs/11-OPERATIONS.md §12` do. What is not acceptable is
    /// the failure being unintelligible when someone skips that step.
    #[error(
        "the database roles were not provisioned before migrations ran, and two migrations raced \
         to create them. Provision enclave_app, enclave_migrator and enclave_platform before \
         starting the application — deploy/compose/init/01-roles.sql locally, or the credential \
         provisioning step in docs/11-OPERATIONS.md §12 — then retry. Retrying without \
         provisioning may also succeed, because the roles now exist."
    )]
    RolesNotProvisioned {
        /// The underlying failure, kept for diagnosis.
        #[source]
        source: sqlx::migrate::MigrateError,
    },

    /// A cross-tenant path was requested on a deployment that has not configured one.
    ///
    /// Deliberately an error rather than a silent fall back to the application pool: the
    /// application role is subject to RLS, so a "helpful" fallback would turn a missing
    /// configuration into a query that quietly returns no rows for every tenant but its own.
    #[error("no platform (cross-tenant) connection is configured")]
    PlatformNotConfigured,
}

impl DbError {
    /// Whether an identical retry has a realistic chance of succeeding.
    ///
    /// Retryability is a property of the *failure*, not of the operation: a pool acquire timeout or
    /// a dropped socket is transient, while a constraint violation or a configuration error will
    /// fail identically forever. Callers use this to decide between a retry and a job failure; the
    /// API edge uses it to choose between `503` and `500`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::InvalidConfig { .. } | Self::PlatformNotConfigured | Self::Migrate(_) => false,
            // Retryable: the losing racer's next attempt finds the roles already there.
            Self::RolesNotProvisioned { .. } => true,
            Self::Acquire(_) => true,
            Self::Connect(source)
            | Self::TenantContext(source)
            | Self::Transaction(source)
            | Self::Query(source) => sqlx_error_is_transient(source),
        }
    }

    /// Whether this error is PostgreSQL saying "no rows".
    ///
    /// Exposed because the distinction is invisible once the error has been converted to
    /// [`enclave_core::Error`], and repository code frequently wants to turn a missing row into a
    /// domain-specific absence rather than a `404`.
    #[must_use]
    pub fn is_row_not_found(&self) -> bool {
        matches!(self, Self::Query(sqlx::Error::RowNotFound))
    }
}

/// Classifies a driver error as transient or permanent.
///
/// The database *responding* with an error means the statement was understood and rejected —
/// retrying sends the same statement to the same rejection. Only failures of the transport, the
/// pool, or the server's availability are worth another attempt.
fn sqlx_error_is_transient(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
        // A `Database` error is the server's considered answer: a unique violation, a check
        // constraint, an RLS policy refusal. None of those change on retry.
        sqlx::Error::Database(_) => false,
        _ => false,
    }
}

impl From<DbError> for CoreError {
    /// Maps a database failure onto the one error type the API layer knows how to render.
    ///
    /// Three deliberate choices:
    ///
    /// * `RowNotFound` becomes [`CoreError::NotFound`], which is also what a cross-tenant read
    ///   produces once RLS has filtered the row away — the two are indistinguishable to the client
    ///   by design (`CLAUDE.md` rule 7).
    /// * Connectivity failures become [`CoreError::Upstream`] naming [`Dependency::Postgres`], so
    ///   a health-degraded response can say *which* dependency is down without a string match.
    /// * Everything else becomes [`CoreError::Internal`], which carries the full source chain for
    ///   the logs while rendering as the bare phrase "internal error" to the caller. Constraint
    ///   names and RLS policy names are internal control detail and stay out of responses.
    fn from(error: DbError) -> Self {
        if error.is_row_not_found() {
            return Self::NotFound;
        }
        match error {
            DbError::Connect(_) | DbError::Acquire(_) => {
                Self::Upstream { dependency: Dependency::Postgres, retryable: true }
            }
            other if other.is_retryable() => {
                Self::Upstream { dependency: Dependency::Postgres, retryable: true }
            }
            // `anyhow::Error::new` preserves the whole source chain, so the constraint name or
            // policy name a developer needs is still in the logs even though the caller only ever
            // sees the phrase "internal error".
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn row_not_found_becomes_not_found_not_an_internal_error() {
        // A cross-tenant read that RLS filtered away arrives here as `RowNotFound`. It must not
        // become a 500, and it must not become a 403 either (`CLAUDE.md` rule 7).
        let core: CoreError = DbError::Query(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
        assert_eq!(core.status_code(), 404);
    }

    #[test]
    fn acquire_timeout_is_retryable_and_names_postgres() {
        let err = DbError::Acquire(sqlx::Error::PoolTimedOut);
        assert!(err.is_retryable());
        let core: CoreError = err.into();
        assert!(matches!(
            core,
            CoreError::Upstream { dependency: Dependency::Postgres, retryable: true }
        ));
    }

    #[test]
    fn configuration_errors_are_never_retried() {
        let err = DbError::InvalidConfig {
            field: "application_role",
            problem: "is not a plain identifier",
        };
        assert!(!err.is_retryable());
        let core: CoreError = err.into();
        assert!(matches!(core, CoreError::Internal(_)));
    }

    #[test]
    fn missing_platform_configuration_is_loud_and_permanent() {
        let err = DbError::PlatformNotConfigured;
        assert!(!err.is_retryable());
        assert!(!err.is_row_not_found());
    }

    #[test]
    fn internal_errors_do_not_render_driver_detail_to_the_caller() {
        // `Internal`'s Display is the bare phrase; the detail lives in the source chain, which is
        // logged but never serialized into a response body.
        let core: CoreError = DbError::Migrate(sqlx::migrate::MigrateError::Dirty(1)).into();
        assert_eq!(core.to_string(), "internal error");
    }
}
