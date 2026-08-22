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
//!
//!   [`quota`] is the one exception, and it is argued rather than assumed (`ENC-584`). A storage
//!   quota has no domain crate to belong to: it bounds `crates/uploads`, `crates/versions` and
//!   `crates/sync` alike, and `docs/02-HLD.md` — authoritative for the crate list — has no crate
//!   for it. The alternatives were worse in the specific way `plans/M0-FOUNDATIONS.md` D1 forbids:
//!   putting it in `crates/uploads` makes every other writer depend sideways on a peer domain
//!   crate, and copying the statement into each makes `plans/M4-GOVERNANCE.md` D31 a convention
//!   rather than a control — three copies of a `WHERE` clause are three chances for one of them to
//!   drop the limit. It sits here for the same reason [`tenants::active_tenants`] does: the
//!   crate below every domain crate is the only place a shared invariant can be written once.
//!
//!   [`conditional_access`] is the second exception, and its argument is the reverse one
//!   (`ENC-590`): the rules *do* have a domain crate, and `crates/conditional_access` would have to
//!   reach past this one to read them. `CLAUDE.md` forbids that in the sentence that matters — all
//!   database access through [`TenantScoped`], no `sqlx::query!` in a domain crate — so the
//!   statements live here and hold no opinion about what a rule means: the module handles strings
//!   and JSON text, and the crate that owns the rule types owns their vocabulary.
//! * **No policy checks.** Authorization is `PolicyEngine::enforce`'s job (`docs/03-LLD.md §12`).
//!   A guard that also made access decisions would be a second, quieter policy chain.
//! * **No cursor signature.** [`cursor`] binds a listing position to a tenant and a filter set and
//!   checks both on the way back in, but it does not sign. `docs/03-LLD.md §17` says cursors are
//!   signed; signing needs a key, and the key belongs to the deployment's key provider at the API
//!   edge, not to a crate that has no key material of its own. **The note for the API layer:** what
//!   signing adds here is integrity against a *tampered* cursor, and a tampered cursor can only
//!   move the position within the same tenant and the same filter — a page the caller was already
//!   entitled to request. Close the remaining gap where the key lives.
//!
//! # Primitives that sit here because everything above needs them
//!
//! [`Cursor`], [`PageSize`], [`FilterFingerprint`] and [`normalize_slug`] are pagination and
//! lookup-key primitives, not domain types. They were in `enclave-identity` until `ENC-137`, which
//! made every crate with a listing depend sideways on a peer domain crate — the edge
//! `plans/M0-FOUNDATIONS.md` D1 forbids. A cursor is a *security* primitive besides: it is bound to
//! a tenant and a filter set, so a second copy is a second place for that binding to weaken.
//!
//! See `plans/M0-FOUNDATIONS.md` D3 for the decision record behind [`TenantScoped`], and
//! `docs/02-HLD.md §4` for where this crate sits.

pub mod conditional_access;
pub mod config;
pub mod cursor;
pub mod error;
pub mod ids;
pub mod migrate;
pub mod normalize;
pub mod pool;
pub mod quota;
pub mod security_facts;
pub mod tenant;
pub mod tenants;

pub use conditional_access::{
    insert_rule, load_rules, set_rule_mode, withdraw_rule, RuleId, RuleRow,
};
pub use config::{ConnectionUrl, DbConfig};
pub use cursor::{Cursor, FilterFingerprint, InvalidCursor, PageSize};
pub use error::DbError;
pub use ids::{sql, RowIdExt, Sql, SqlId};
pub use migrate::{run_migrations, run_migrations_on, MIGRATIONS};
pub use normalize::normalize_slug;
pub use pool::{DbPool, PlatformConnection};
pub use quota::{
    charge_storage, configure_storage_quota, correct_storage, observe_storage, reconcile_storage,
    release_storage, storage_quota, Admitted, Charged, Corrected, Enforcement, Observation,
    Refused, Released, StorageQuota, StorageReconciliation,
};
pub use security_facts::{external_exposure, load_facts, record_facts, resolve_content};
pub use tenant::TenantScoped;
pub use tenants::active_tenants;

/// Result alias for this crate's fallible operations.
///
/// The error converts into [`enclave_core::Error`] at the API edge; see [`error`] for what each
/// variant becomes and why.
pub type Result<T, E = DbError> = core::result::Result<T, E>;

#[cfg(test)]
mod test_support {
    //! Shared setup for the tests that need a real database.
    //!
    //! Every test using this is `#[ignore]`d and gets a **throwaway** database from
    //! `enclave_testing::TestDb`, never the one `DATABASE_URL` names. That is `ENC-504`: the
    //! database a developer exports as `DATABASE_URL` is their dev stack, and a test run that
    //! writes migration state into it makes the next run on a different branch fail the
    //! forward-only checksum gate on a migration nobody touched.
    //!
    //! `enclave-testing` is a dev-dependency of this crate and depends on it normally; Cargo allows
    //! that cycle because it closes through a dev edge. See `Cargo.toml`.

    // A harness that could not start is a test that cannot run; the workspace warns on this in
    // non-test code, and every test module in this crate carries the same allow.
    #![allow(clippy::expect_used)]

    use crate::DbConfig;
    use enclave_testing::TestDb;

    /// A throwaway database, migrated, plus the configuration to reach it.
    ///
    /// The handle comes back with the configuration because dropping it drops the database. A test
    /// that binds it to `_` gets a pool pointing at a database that is already being deleted.
    pub(crate) async fn test_database() -> (TestDb, DbConfig) {
        let db = TestDb::start().await.expect(
            "these tests need a PostgreSQL they may create databases on; CI provides a service \
             container, locally use deploy/compose/dev.yml and set DATABASE_URL",
        );
        let config = config_for(&db);
        (db, config)
    }

    /// Configuration addressing an already-created, already-migrated test database.
    pub(crate) fn config_for(db: &TestDb) -> DbConfig {
        // The harness's cluster gives one superuser credential, so it is both the application and
        // the migration URL here. A real deployment separates them, which is why the two fields
        // exist rather than one.
        let url = db.url().to_owned();
        DbConfig::new(url.clone()).with_migration_url(url).with_application_name("enclave-tests")
    }
}
