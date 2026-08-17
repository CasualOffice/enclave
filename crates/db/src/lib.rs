//! `enclave-db` — the PostgreSQL pool, the migration runner, and the tenant-scoped query guard.
//!
//! This crate exists to make one class of bug unrepresentable: a query that reaches tenant data
//! without a tenant context. Enclave defends that boundary in two independent layers
//! (`docs/04-DATA-MODEL.md §3`), and both of them pass through here.
//!
//! * **Layer 1 — the query guard.** [`TenantScoped`] is the only public route to a connection that
//!   can see tenant data, and it cannot be constructed without establishing the tenant context.
//!   The raw pool is `pub(crate)`.
//! * **Layer 2 — row-level security.** Every tenant-scoped table has RLS enabled *and forced*, with
//!   a policy comparing `tenant_id` to `current_setting('app.tenant_id')`. The application connects
//!   as a role that owns nothing, so `FORCE` applies to it and it cannot opt out.
//!
//! Neither layer is a backstop for the other. Application predicates cannot be proven complete
//! across a codebase — one missing `WHERE` is a leak, and no test can demonstrate the absence of a
//! missing predicate. RLS is complete but depends on a session variable being right, which is a
//! runtime property. Together, a leak requires both a missing predicate *and* a wrong session
//! variable, and each has its own test.
//!
//! # Using it
//!
//! ```text
//! let pool = DbPool::connect(&config).await?;
//!
//! let mut tx = pool.begin(ctx.tenant_id).await?;          // SET LOCAL app.tenant_id happens here
//! let row = sqlx::query("SELECT name FROM files WHERE tenant_id = $1 AND id = $2")
//!     .bind(sql(tx.tenant_id()))                          // layer 1: the predicate is still written
//!     .bind(sql(file_id))
//!     .fetch_one(&mut *tx)
//!     .await?;
//! tx.commit().await?;
//! ```
//!
//! The `tenant_id` predicate is written even though RLS would enforce it anyway. That is the point
//! of having two layers; it is also what makes the T5 test meaningful — removing the predicate must
//! still fail to return another tenant's row.
//!
//! # What is deliberately not here
//!
//! * **No `sqlx::query!`.** The compile-time-checked macros need a live database at build time and
//!   tie the build to a schema snapshot. Domain crates use this crate's guard with runtime-checked
//!   queries; see `CLAUDE.md`, Rust conventions.
//! * **No repositories.** Table-shaped access belongs in the domain crate that owns the table.
//!   This crate owns *how* a connection is obtained, never *what* is asked of it.
//! * **No policy checks.** Authorization is `PolicyEngine::enforce`'s job (`docs/03-LLD.md §12`).
//!   A guard that also made access decisions would be a second, quieter policy chain.
//!
//! See `plans/M0-FOUNDATIONS.md` D3 for the decision record behind [`TenantScoped`], and
//! `docs/02-HLD.md §4` for where this crate sits.

pub mod config;
pub mod error;
pub mod ids;
pub mod migrate;
pub mod pool;
pub mod tenant;

pub use config::{ConnectionUrl, DbConfig};
pub use error::DbError;
pub use ids::{sql, RowIdExt, Sql, SqlId};
pub use migrate::{run_migrations, run_migrations_on, MIGRATIONS};
pub use pool::{DbPool, PlatformConnection};
pub use tenant::TenantScoped;

/// Result alias for this crate's fallible operations.
///
/// The error converts into [`enclave_core::Error`] at the API edge; see [`error`] for what each
/// variant becomes and why.
pub type Result<T, E = DbError> = core::result::Result<T, E>;

#[cfg(test)]
mod test_support {
    //! Shared setup for the tests that need a real database.
    //!
    //! Every test using this is `#[ignore]`d until ENC-112 lands the testcontainers harness. The
    //! URL is read from the environment rather than hard-coded so that the harness can point the
    //! same tests at a throwaway container, and so that nothing resembling a credential is ever
    //! committed (`CLAUDE.md` rule 11) — the fallback below is a local development default with no
    //! password in it.

    use crate::DbConfig;

    /// Configuration for a database the harness has already started and migrated.
    pub(crate) fn test_config() -> DbConfig {
        // `DATABASE_URL` first, because that is what every other consumer already uses — the
        // enclave-testing harness, the RLS coverage gate, sqlx's own tooling and psql.
        //
        // Two names for one thing is why these tests ran nowhere. CI set `DATABASE_URL`; these
        // tests read `ENCLAVE_TEST_DATABASE_URL`, found nothing, fell back to a default pointing at
        // a database that did not exist, and were `#[ignore]`d so nobody saw them fail. The
        // fallback is kept for anyone with the old variable exported, but it is no longer the
        // only name that works.
        let url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| std::env::var("ENCLAVE_TEST_DATABASE_URL").ok())
            .unwrap_or_else(|| "postgres://postgres@localhost:5432/enclave_test".to_owned());
        // The harness's container gives one superuser credential, so it is both the application
        // and the migration URL there. A real deployment separates them, which is why the two
        // fields exist rather than one.
        DbConfig::new(url.clone()).with_migration_url(url).with_application_name("enclave-tests")
    }
}
