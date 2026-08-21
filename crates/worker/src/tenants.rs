//! The production [`TenantSource`]: the scheduler's tenant enumerator, in three lines.
//!
//! The three lines are the point. The query — and with it the only use of the row-level-security
//! escape hatch — lives in [`enclave_db::active_tenants`], inside the crate that owns
//! `DbPool::platform_connection`, so that accessor still has no caller anywhere else in the
//! workspace and `grep -rn platform_connection crates/` is still a complete list of the places RLS
//! is bypassed. What is left here is the adapter, and an adapter with no logic in it is one nobody
//! has to review for a second time.
//!
//! `crates/worker/src/lib.rs` refuses to let *housekeeping* enumerate tenants and that refusal
//! stands: nothing in [`invalidation`](crate::invalidation), [`epoch`](crate::epoch),
//! [`coverage`](crate::coverage) or [`indexing`](crate::indexing) calls this. The scheduler does,
//! once per tick, and hands each pass the list.

use async_trait::async_trait;
use enclave_core::TenantId;
use enclave_db::DbPool;

use crate::schedule::TenantSource;
use crate::Result;

/// Reads the tenant list from PostgreSQL through the platform role.
///
/// Holds the pool by value because [`DbPool`] is already an `Arc` internally; a second layer would
/// buy nothing.
#[derive(Debug, Clone)]
pub struct DbTenants {
    pool: DbPool,
}

impl DbTenants {
    /// Wraps a pool. The pool must have a platform URL configured, or every call fails with
    /// `DbError::PlatformNotConfigured` — which the binary checks for at start-up rather than
    /// discovering on the first tick, using `DbPool::has_platform_access`.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TenantSource for DbTenants {
    async fn tenants(&self) -> Result<Vec<TenantId>> {
        Ok(enclave_db::active_tenants(&self.pool).await?)
    }
}
