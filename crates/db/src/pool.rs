//! Pool construction and the two ways out of it.
//!
//! There are exactly two: [`DbPool::begin`], which yields a [`TenantScoped`] transaction, and
//! [`DbPool::platform_connection`], which does not. The raw `sqlx` pool is `pub(crate)` so that
//! "just this once" is not available as a spelling — a domain crate that wants a connection has to
//! name a tenant or name itself as one of the three cross-tenant callers, and both of those are
//! reviewable.

use std::sync::Arc;

use enclave_core::id::TenantId;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use sqlx::{Executor, Postgres};

use crate::config::DbConfig;
use crate::tenant::TenantScoped;
use crate::DbError;

/// A handle to the database: the application pool, and optionally the platform pool.
///
/// Cloning is cheap — `sqlx`'s pool is already an `Arc` internally — so this is passed by value
/// into every task and stored in application state without a second layer of `Arc`.
#[derive(Clone, Debug)]
pub struct DbPool {
    /// Connections held by a role that RLS applies to. Everything tenant-scoped goes through here.
    app: PgPool,
    /// Connections held by the `BYPASSRLS` role, when one is configured. See
    /// [`DbPool::platform_connection`].
    platform: Option<PgPool>,
}

impl DbPool {
    /// Builds the pools and proves the credentials work before returning.
    ///
    /// Connections are established eagerly (`min_connections` is honoured at construction) rather
    /// than lazily on first query. The difference matters operationally: a wrong password should
    /// fail a deployment's readiness check, not the first user request after the rollout is
    /// declared successful.
    pub async fn connect(config: &DbConfig) -> Result<Self, DbError> {
        config.validate()?;

        let app = build_pool(
            config,
            config.url.connect_options("url")?,
            config.max_connections,
            Some(config.session_setup_sql()),
        )
        .await?;

        let platform = match &config.platform_url {
            Some(url) => Some(
                build_pool(
                    config,
                    url.connect_options("platform_url")?,
                    config.platform_max_connections,
                    // Deliberately no `SET ROLE` and no `statement_timeout`: the platform pool
                    // exists for the outbox drain and the tenant enumerator, whose statements are
                    // legitimately long, and reducing its role would defeat the reason it exists.
                    None,
                )
                .await?,
            ),
            None => None,
        };

        tracing::info!(
            max_connections = config.max_connections,
            platform_configured = platform.is_some(),
            "database pools established"
        );

        Ok(Self { app, platform })
    }

    /// Opens a transaction with this tenant's context established.
    ///
    /// The only way to reach tenant data. See [`TenantScoped`] for why the context is set here and
    /// never by a caller.
    pub async fn begin(&self, tenant_id: TenantId) -> Result<TenantScoped, DbError> {
        TenantScoped::begin(self, tenant_id).await
    }

    /// The application pool, for this crate only.
    ///
    /// `pub(crate)` is load-bearing: the pool has no tenant context, so anything that could reach
    /// it could read every tenant's rows if RLS were ever misconfigured. Layer 1 of the isolation
    /// model (`docs/04-DATA-MODEL.md §3.1`) is precisely the absence of a public accessor here.
    pub(crate) fn app_pool(&self) -> &PgPool {
        &self.app
    }

    /// Checks out a connection that **bypasses row-level security**.
    ///
    /// # This is the tenant isolation escape hatch
    ///
    /// The connection is held by `enclave_platform`, a `BYPASSRLS` role. Nothing filters what it
    /// can see. There are exactly three legitimate callers, from `docs/04-DATA-MODEL.md §3.2` and
    /// `plans/M0-FOUNDATIONS.md` D3:
    ///
    /// 1. **the migration runner** — DDL is not tenant-scoped;
    /// 2. **the outbox publisher** — it drains `events_outbox` across all tenants in one pass, and
    ///    a per-tenant drain would need a tenant list to drain, which is the next item;
    /// 3. **the scheduler's tenant enumerator** — the query that produces the tenant list cannot
    ///    itself be scoped to a tenant.
    ///
    /// This method is on the deny-list of the ENC-110 routing lint. A call from anywhere other than
    /// those three fails the build, and adding a fourth caller is a design decision that changes the
    /// deny-list in the same commit — the deny-list is the review surface, exactly as the handler
    /// allowlist is for policy enforcement.
    ///
    /// Anything a request handler does belongs in [`DbPool::begin`] instead. If a handler appears
    /// to need this, the actual requirement is almost always "resolve a tenant from a host header",
    /// which is a separate, deliberately narrow lookup rather than general cross-tenant access.
    ///
    /// Fails with [`DbError::PlatformNotConfigured`] when no platform URL is set, rather than
    /// silently falling back to the application pool: the fallback would be subject to RLS with no
    /// tenant context, which reads as "zero rows everywhere" — a data-loss-shaped bug that looks
    /// like an empty queue.
    pub async fn platform_connection(&self) -> Result<PlatformConnection, DbError> {
        let pool = self.platform.as_ref().ok_or(DbError::PlatformNotConfigured)?;
        let conn = pool.acquire().await.map_err(DbError::Acquire)?;
        Ok(PlatformConnection { conn })
    }

    /// Whether a cross-tenant path is available at all.
    ///
    /// Lets a binary refuse to start a worker whose only job needs the platform role, instead of
    /// discovering it at the first tick.
    pub fn has_platform_access(&self) -> bool {
        self.platform.is_some()
    }

    /// Round-trips a trivial statement, for the readiness probe.
    ///
    /// Runs on the application pool on purpose: a probe that checks a connection the request path
    /// does not use answers the wrong question.
    pub async fn health_check(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.app).await.map_err(DbError::Query)?;
        Ok(())
    }

    /// Connections currently held by the application pool, idle or busy. For metrics.
    pub fn size(&self) -> u32 {
        self.app.size()
    }

    /// Connections currently idle in the application pool. For metrics: a persistent zero here with
    /// non-zero acquire timeouts is the signature the pool-exhaustion path is being hit.
    pub fn num_idle(&self) -> usize {
        self.app.num_idle()
    }

    /// Closes both pools and waits for checked-out connections to be returned.
    ///
    /// Called on shutdown so that in-flight transactions get the chance to commit rather than being
    /// severed mid-write.
    pub async fn close(&self) {
        self.app.close().await;
        if let Some(platform) = &self.platform {
            platform.close().await;
        }
    }
}

/// Builds one pool, optionally applying per-connection session setup.
///
/// The setup runs in `after_connect` rather than before each query: it is per-*connection* state,
/// so paying for it once per connection instead of once per checkout is both correct and cheaper.
/// Nothing tenant-scoped may be set here — that is the whole distinction `SET LOCAL` draws in
/// [`crate::TenantScoped`], and a tenant id set in this hook would survive the checkout.
async fn build_pool(
    config: &DbConfig,
    options: sqlx::postgres::PgConnectOptions,
    max_connections: u32,
    session_setup: Option<String>,
) -> Result<PgPool, DbError> {
    let options = options.application_name(&config.application_name);
    let setup: Option<Arc<str>> = session_setup.map(Arc::from);

    let mut builder = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(config.min_connections.min(max_connections))
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime);

    if let Some(setup) = setup {
        builder = builder.after_connect(move |conn, _meta| {
            let setup = Arc::clone(&setup);
            Box::pin(async move {
                conn.execute(&*setup).await?;
                Ok(())
            })
        });
    }

    builder.connect_with(options).await.map_err(DbError::Connect)
}

/// A checked-out connection that is **not** subject to row-level security.
///
/// Deliberately verbose to hold and to name. It dereferences to a plain [`PgConnection`], so it can
/// be passed to `sqlx` queries as `&mut *conn`, but it never dereferences to something that looks
/// tenant-scoped — a reader of a call site can always tell which of the two paths is in use.
///
/// See [`DbPool::platform_connection`] for who may hold one.
#[derive(Debug)]
pub struct PlatformConnection {
    conn: PoolConnection<Postgres>,
}

impl PlatformConnection {
    /// Reads back `app.tenant_id` on this connection, which must be unset.
    ///
    /// Exposed for the D3 proof (`plans/M0-FOUNDATIONS.md`): the property being demonstrated is not
    /// only that a scoped transaction sees its own tenant, but that a connection returned to the
    /// pool and handed out again carries nothing. That second half needs a way to look, and a
    /// deliberate one is better than a test reaching into private state.
    pub async fn observed_tenant_context(&mut self) -> Result<Option<TenantId>, DbError> {
        crate::tenant::read_tenant_context(&mut self.conn).await
    }
}

impl core::ops::Deref for PlatformConnection {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl core::ops::DerefMut for PlatformConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::test_support::test_config;

    #[tokio::test]
    async fn an_invalid_configuration_fails_before_a_socket_is_opened() {
        // No database is running in a unit-test environment, so reaching the connect attempt would
        // produce `Connect`, not `InvalidConfig`. Getting `InvalidConfig` back is the proof that
        // validation happened first.
        let config = test_config().with_max_connections(0);
        let err = DbPool::connect(&config).await.expect_err("must be refused");
        assert!(matches!(err, DbError::InvalidConfig { field: "max_connections", .. }));
    }

    #[tokio::test]
    async fn a_malformed_url_is_reported_without_quoting_it() {
        let config = crate::DbConfig::new("not-a-url-with-a-password-in-it");
        let err = DbPool::connect(&config).await.expect_err("must be refused");
        assert!(matches!(err, DbError::InvalidConfig { field: "url", .. }));
        assert!(
            !err.to_string().contains("not-a-url-with-a-password-in-it"),
            "the connection string leaked into the error message"
        );
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; runs under ENC-112's testcontainers harness"]
    async fn the_platform_path_is_refused_when_it_is_not_configured() {
        let pool = DbPool::connect(&test_config()).await.expect("connect");
        assert!(!pool.has_platform_access());
        let err = pool.platform_connection().await.expect_err("must not fall back to the app pool");
        assert!(matches!(err, DbError::PlatformNotConfigured));
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; runs under ENC-112's testcontainers harness"]
    async fn health_check_uses_the_application_pool() {
        let pool = DbPool::connect(&test_config()).await.expect("connect");
        pool.health_check().await.expect("a healthy database answers SELECT 1");
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; runs under ENC-112's testcontainers harness"]
    async fn the_configured_statement_timeout_is_actually_in_force() {
        // The setup hook is easy to get wrong in a way that is invisible: a typo in the batch means
        // no timeout at all, and nothing fails until a runaway query takes a pool down.
        use std::time::Duration;
        let config = test_config().with_statement_timeout(Duration::from_millis(200));
        let pool = DbPool::connect(&config).await.expect("connect");
        let mut scoped = pool.begin(TenantId::new_v7()).await.expect("begin");
        let result = sqlx::query("SELECT pg_sleep(5)").execute(&mut *scoped).await;
        assert!(result.is_err(), "the statement timeout did not fire");
        pool.close().await;
    }
}
