//! The tenant-scoped query guard — layer 1 of tenant isolation, and the home of decision D3.
//!
//! # The property being defended
//!
//! Row-level security answers `tenant_id = current_setting('app.tenant_id')::uuid`
//! (`docs/04-DATA-MODEL.md §3.2`). That is only a boundary if `app.tenant_id` is (a) always set
//! before a tenant-scoped statement runs and (b) never still set when the connection is handed to
//! the next caller. Connection pooling makes (b) the hard half: a connection is reused by whoever
//! checks it out next, and "whoever" is a different tenant several times a second.
//!
//! # The decision
//!
//! `SET LOCAL app.tenant_id`, issued **inside an explicit transaction**, by this type, never by a
//! caller. `SET LOCAL` is scoped to the transaction: at `COMMIT` or `ROLLBACK` PostgreSQL restores
//! the previous value, so a connection returning to the pool cannot carry a tenant forward. There is
//! no code path in this crate that sets the value any other way, and no public API that hands out a
//! connection on which a caller could set it themselves.
//!
//! Alternatives were considered and rejected in `plans/M0-FOUNDATIONS.md` D3; the short forms:
//! session-level `SET` survives the checkout and one misuse is a cross-tenant leak; a pool per
//! tenant does not survive contact with thousands of tenants; application `WHERE` clauses alone
//! cannot be proven complete, which is why there are two layers rather than one.
//!
//! # Why `set_config` rather than the literal `SET LOCAL`
//!
//! `SET` is a utility statement and cannot take bind parameters, so writing it means formatting a
//! tenant id into SQL. `SELECT set_config('app.tenant_id', $1, true)` is the same operation —
//! `true` is `is_local` — reached through the parameterised protocol. A `TenantId` is a validated
//! UUID and could not carry SQL anyway; the reason to prefer the bind is that it stays safe if this
//! ever takes a value that is *not* a parsed UUID, which is the shape most injection defects have.
//!
//! # Failure behaviour
//!
//! If the `set_config` fails, [`TenantScoped::begin`] returns an error and the transaction is
//! dropped, which rolls it back. There is deliberately no path that continues with the context
//! unset: an unset `app.tenant_id` makes `current_setting` raise, so RLS fails closed rather than
//! matching everything — but relying on that is a second line of defence, not a plan.

use enclave_core::id::TenantId;
use sqlx::postgres::PgConnection;
use sqlx::{Postgres, Row, Transaction};

use crate::pool::DbPool;
use crate::DbError;

/// The GUC that RLS policies read. Defined once here so a typo cannot exist in two places: a
/// mismatch between this name and the one in the policies would make every scoped query fail closed
/// (best case) or, if the policy name were the misspelled one, match nothing at all.
const TENANT_GUC: &str = "app.tenant_id";

/// An open transaction that has this tenant's context established.
///
/// Obtained only from [`DbPool::begin`]. Dereferences to a [`PgConnection`], so it is used exactly
/// like a `sqlx` transaction:
///
/// ```text
/// let mut tx = pool.begin(ctx.tenant_id).await?;
/// let row = sqlx::query("SELECT id FROM files WHERE id = $1")
///     .bind(sql(file_id))
///     .fetch_one(&mut *tx)
///     .await?;
/// tx.commit().await?;
/// ```
///
/// Dropping without [`commit`](Self::commit) rolls back — `sqlx`'s transaction does that, and it is
/// the right default here: a handle abandoned because of an early `?` must not leave a partial
/// write behind.
#[derive(Debug)]
pub struct TenantScoped {
    tenant_id: TenantId,
    tx: Transaction<'static, Postgres>,
}

impl TenantScoped {
    /// Opens a transaction and establishes the tenant context on it.
    ///
    /// The two steps are inseparable by construction: there is no constructor that produces a
    /// `TenantScoped` without the `set_config`, and no accessor that yields the transaction before
    /// it has run. That is what makes "a tenant-scoped query outside a tenant-scoped transaction"
    /// unrepresentable rather than merely discouraged.
    ///
    /// The tenant id comes from the verified request context and never from client input
    /// (`CLAUDE.md` rule 3) — this function cannot enforce that, but it is the last place the value
    /// is visible before it becomes the isolation boundary, so it is worth restating here.
    pub async fn begin(pool: &DbPool, tenant_id: TenantId) -> Result<Self, DbError> {
        let mut tx = pool.app_pool().begin().await.map_err(DbError::Transaction)?;

        // `is_local = true` — the third argument — is the entire decision. Flipping it to `false`
        // would make this a session-level setting that outlives the transaction and travels to the
        // next checkout, which is exactly the leak D3 exists to prevent.
        // Bound as text, not as a uuid: `set_config(text, text, bool)` is the only signature, and
        // sending a uuid-typed parameter makes PostgreSQL fail to resolve the function.
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(TENANT_GUC)
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(DbError::TenantContext)?;

        Ok(Self { tenant_id, tx })
    }

    /// The tenant this transaction is bound to.
    ///
    /// Useful for building the `tenant_id` column of an `INSERT`: the application predicate is not
    /// made redundant by RLS, it is the other layer of it (`docs/04-DATA-MODEL.md §3`), and taking
    /// the value from here rather than from a parameter makes the two layers agree by construction.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Reads `app.tenant_id` back from PostgreSQL as the server currently sees it.
    ///
    /// This is not how normal code learns the tenant — [`tenant_id`](Self::tenant_id) is, and it
    /// costs no round trip. It exists so the D3 proof can assert the server's view rather than the
    /// client's belief about it; a test that checks its own local field would pass even if the
    /// `set_config` had never been sent.
    pub async fn observed_tenant_context(&mut self) -> Result<Option<TenantId>, DbError> {
        read_tenant_context(&mut self.tx).await
    }

    /// Commits, ending the transaction and with it the tenant context.
    pub async fn commit(self) -> Result<(), DbError> {
        self.tx.commit().await.map_err(DbError::Transaction)
    }

    /// Rolls back explicitly.
    ///
    /// Dropping does the same thing; this exists for the case where the rollback is the intended
    /// outcome and the failure to perform it should be reported rather than swallowed by `Drop`.
    pub async fn rollback(self) -> Result<(), DbError> {
        self.tx.rollback().await.map_err(DbError::Transaction)
    }
}

impl core::ops::Deref for TenantScoped {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl core::ops::DerefMut for TenantScoped {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

/// Asks PostgreSQL what `app.tenant_id` currently is on this connection.
///
/// The `true` second argument to `current_setting` is `missing_ok`: without it, reading an unset
/// custom GUC raises, and "unset" is precisely the answer this function needs to be able to return
/// — a connection that carries no tenant is the successful outcome of the leak test, not an error.
/// An empty string is treated as unset too, because that is what a GUC reset to its default looks
/// like once it has been set within the session.
pub(crate) async fn read_tenant_context(
    conn: &mut PgConnection,
) -> Result<Option<TenantId>, DbError> {
    let row = sqlx::query("SELECT current_setting($1, true)")
        .bind(TENANT_GUC)
        .fetch_one(conn)
        .await
        .map_err(DbError::Query)?;

    let raw: Option<String> = row.try_get(0).map_err(DbError::Query)?;
    match raw.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(value) => value.parse::<TenantId>().map(Some).map_err(|_| {
            // The GUC holding something that is not a UUID means either a hand-issued `SET` from
            // outside this crate or a corrupted session. Both are isolation faults, so this is an
            // error rather than a `None` that would read as "no tenant, carry on".
            DbError::InvalidConfig {
                field: "app.tenant_id",
                problem: "was set to something that is not a uuid",
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::test_support::test_database;

    /// D3's proof, and the reason this crate exists in the shape it does.
    ///
    /// Twenty-four concurrent transactions across six tenants, on a pool of **two** connections, so
    /// that every connection is reused many times and reuse happens under contention rather than in
    /// a quiescent test. Each task asserts the server's view of `app.tenant_id` twice — once
    /// immediately, once after yielding long enough for other tasks to be interleaved — and then
    /// again after work has been done on the connection.
    ///
    /// The assertion that would fail if `SET LOCAL` were session-level is the middle one: with a
    /// session `SET`, a task would frequently observe the tenant of whoever last used that
    /// connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn no_transaction_ever_observes_another_tenants_context() {
        const TENANTS: usize = 6;
        const TASKS: usize = 24;

        let (_db, config) = test_database().await;
        let pool = crate::DbPool::connect(&config.with_max_connections(2))
            .await
            .expect("connect to the test database");

        let tenants: Vec<TenantId> = (0..TENANTS).map(|_| TenantId::new_v7()).collect();
        let mut tasks = tokio::task::JoinSet::new();

        for index in 0..TASKS {
            let pool = pool.clone();
            let expected = tenants[index % TENANTS];
            tasks.spawn(async move {
                let mut scoped = pool.begin(expected).await.expect("begin scoped transaction");

                assert_eq!(
                    scoped.observed_tenant_context().await.expect("read context"),
                    Some(expected),
                    "the tenant context was not established on entry"
                );

                // Yield with the transaction open, so that other tasks are certain to be mid-flight
                // on the other pooled connection while this one is holding its context.
                tokio::time::sleep(Duration::from_millis(20)).await;

                assert_eq!(
                    scoped.observed_tenant_context().await.expect("read context"),
                    Some(expected),
                    "the tenant context changed while the transaction was open"
                );

                // Do some actual work, then look again: a statement must not disturb the setting.
                sqlx::query("SELECT 1").execute(&mut *scoped).await.expect("query");
                let observed =
                    scoped.observed_tenant_context().await.expect("read context").expect("set");
                scoped.commit().await.expect("commit");
                (expected, observed)
            });
        }

        let mut seen: HashMap<TenantId, usize> = HashMap::new();
        while let Some(result) = tasks.join_next().await {
            let (expected, observed) = result.expect("no task may panic");
            assert_eq!(expected, observed, "a transaction observed another tenant's context");
            *seen.entry(expected).or_default() += 1;
        }
        assert_eq!(seen.len(), TENANTS, "every tenant must have been exercised");

        pool.close().await;
    }

    /// The second half of the property: a connection *returning* to the pool carries nothing.
    ///
    /// Checked outside a transaction, on a raw checkout from the application pool, because that is
    /// the state the next caller inherits. If `SET LOCAL` were ever changed to a session `SET`,
    /// this is the test that would fail first and most clearly.
    #[tokio::test]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn a_returned_connection_carries_no_tenant_context() {
        // A pool of one guarantees the connection examined afterwards is the same physical
        // connection the transaction used — otherwise the test could pass by luck.
        let (_db, config) = test_database().await;
        let pool = crate::DbPool::connect(&config.with_max_connections(1))
            .await
            .expect("connect to the test database");

        let tenant = TenantId::new_v7();
        let mut scoped = pool.begin(tenant).await.expect("begin");
        assert_eq!(scoped.observed_tenant_context().await.expect("read"), Some(tenant));
        scoped.commit().await.expect("commit");

        let mut conn = pool.app_pool().acquire().await.expect("reacquire the same connection");
        let leaked = read_tenant_context(&mut conn).await;
        assert_eq!(
            leaked.expect("read"),
            None,
            "tenant context survived the transaction and reached the next checkout"
        );

        // `PgPool::close` waits for every connection to be returned, and `conn` holds one until the
        // end of this function — so closing first is a self-deadlock that hangs rather than
        // fails. Hidden until now because the test was `#[ignore]`d and had never run (ENC-118).
        drop(conn);
        pool.close().await;
    }

    /// A rollback must clear the context just as a commit does — the abort path is the one people
    /// forget, and it is reached by every `?` in every handler.
    #[tokio::test]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn a_rolled_back_transaction_also_clears_the_context() {
        let (_db, config) = test_database().await;
        let pool = crate::DbPool::connect(&config.with_max_connections(1))
            .await
            .expect("connect to the test database");

        let tenant = TenantId::new_v7();
        let scoped = pool.begin(tenant).await.expect("begin");
        scoped.rollback().await.expect("rollback");

        let mut conn = pool.app_pool().acquire().await.expect("reacquire");
        assert_eq!(
            read_tenant_context(&mut conn).await.expect("read"),
            None,
            "tenant context survived a rollback"
        );

        // `PgPool::close` waits for every connection to be returned, and `conn` holds one until the
        // end of this function — so closing first is a self-deadlock that hangs rather than
        // fails. Hidden until now because the test was `#[ignore]`d and had never run (ENC-118).
        drop(conn);
        pool.close().await;
    }

    /// Dropping the handle without committing must behave like the rollback above: no leaked
    /// context, and no half-written transaction.
    #[tokio::test]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn dropping_the_handle_clears_the_context_too() {
        let (_db, config) = test_database().await;
        let pool = crate::DbPool::connect(&config.with_max_connections(1))
            .await
            .expect("connect to the test database");

        {
            let mut scoped = pool.begin(TenantId::new_v7()).await.expect("begin");
            sqlx::query("SELECT 1").execute(&mut *scoped).await.expect("query");
            // No commit: the handle goes out of scope here.
        }

        let mut conn = pool.app_pool().acquire().await.expect("reacquire");
        assert_eq!(
            read_tenant_context(&mut conn).await.expect("read"),
            None,
            "tenant context survived a dropped handle"
        );

        // `PgPool::close` waits for every connection to be returned, and `conn` holds one until the
        // end of this function — so closing first is a self-deadlock that hangs rather than
        // fails. Hidden until now because the test was `#[ignore]`d and had never run (ENC-118).
        drop(conn);
        pool.close().await;
    }

    /// The handle's own idea of its tenant must match the server's, always. A divergence here would
    /// mean application predicates and RLS disagree, which is the failure mode where one layer
    /// silently stops contributing.
    #[tokio::test]
    #[ignore = "needs PostgreSQL; CI runs it with --include-ignored"]
    async fn the_handles_tenant_matches_the_servers() {
        let (_db, config) = test_database().await;
        let pool = crate::DbPool::connect(&config).await.expect("connect");
        let tenant = TenantId::new_v7();
        let mut scoped = pool.begin(tenant).await.expect("begin");
        assert_eq!(scoped.tenant_id(), tenant);
        assert_eq!(scoped.observed_tenant_context().await.expect("read"), Some(tenant));
        // `PgPool::close` waits for every connection to be returned, and `scoped` holds one until the
        // end of this function — so closing first is a self-deadlock that hangs rather than
        // fails. Hidden until now because the test was `#[ignore]`d and had never run (ENC-118).
        drop(scoped);
        pool.close().await;
    }

    #[test]
    fn the_guc_name_matches_the_one_the_policies_read() {
        // `docs/04-DATA-MODEL.md §3.2` fixes this string in both the policy definitions and here.
        // A rename in one place only would make every scoped query fail closed, which is safe but
        // total; asserting the literal keeps the two halves visibly coupled.
        assert_eq!(TENANT_GUC, "app.tenant_id");
    }
}
