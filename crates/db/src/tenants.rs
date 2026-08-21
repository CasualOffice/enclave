//! The tenant enumerator — D3's third cross-tenant caller, made real.
//!
//! # Why this lives here and not in the process that needs it
//!
//! [`DbPool::platform_connection`] names three legitimate callers, and the third —
//! "the scheduler's tenant enumerator" — had never been written. `migrations/0002_rls_policies.sql`
//! has been granting `SELECT ON tenants TO enclave_platform` for it since M0, with the reason
//! spelled out beside the grant, and nothing claimed the grant.
//!
//! `crates/worker/src/main.rs` is what finally needs it: every housekeeping pass takes the tenants
//! to work on as a parameter, deliberately (`crates/worker/src/lib.rs` explains at length why
//! housekeeping must not go and find them), so the process that schedules those passes has to
//! produce the list.
//!
//! It is written **here**, in the crate that owns the escape hatch, rather than in that binary. The
//! property being protected is not "few callers" but "few callers *outside this crate*": with the
//! enumerator here, [`DbPool::platform_connection`] still has zero callers anywhere else in the
//! workspace, and `grep -rn platform_connection crates/` is still a complete list of the places
//! row-level security is bypassed. Had the worker written its own, that list would have grown a
//! caller, and the next job that wants a tenant list would have a precedent to copy rather than a
//! function to call.
//!
//! # It answers one question and cannot be asked a second
//!
//! [`active_tenants`] returns ids. Not names, not slugs, not settings, not statuses. That is the
//! whole surface, and it is narrow on purpose: a `tenants()` returning rows would be a
//! BYPASSRLS-backed reader of tenant metadata sitting in the crate every domain crate depends on,
//! and the first caller wanting a display name would find it perfectly reasonable. Anything that
//! needs more than an id about a tenant is answering a request, and a request has a tenant already.

use enclave_core::id::TenantId;
use sqlx::Row as _;
use uuid::Uuid;

use crate::pool::DbPool;
use crate::DbError;

/// Every tenant a background job should currently work on, oldest id first.
///
/// # Which tenants are in the list, and which are not
///
/// `ACTIVE` and `READ_ONLY`, and nothing else. The list is a *product* decision, not this function's
/// judgement: `docs/11-OPERATIONS.md §12` defines the tenant lifecycle, and it says a `SUSPENDED`
/// tenant has "background processing paused" — so a housekeeping enumerator that included one would
/// be spending the deployment's CPU on exactly the tenant an operator suspended to stop spending it.
/// `READ_ONLY` is the opposite case and is included: its content is still served, so its index still
/// has to be right.
///
/// `DELETING` and soft-deleted rows are excluded for a different reason — their content is on its
/// way out, so extraction, embedding and index budget spent on them is spent on rows that will not
/// exist. That is the same reasoning `crates/worker/src/epoch.rs` gives for skipping trashed files,
/// and the only direction a pure-efficiency mechanism may err in.
///
/// **The known cost is a suspended tenant's gauges.** `crates/worker/src/coverage.rs` publishes a
/// level, and a level nobody refreshes freezes at its last value rather than disappearing — which is
/// the reading that looks healthiest. `docs/11-OPERATIONS.md §12` is where that is recorded; the
/// alternative, enumerating suspended tenants so their gauges keep moving, trades a stale metric for
/// ignoring the lifecycle rule, and the lifecycle rule is the one an operator relies on.
///
/// # Errors
///
/// [`DbError::PlatformNotConfigured`] when no platform URL is configured, which is the case for a
/// deployment that has not set `database.platform_url`. That is a refusal, never an empty list: a
/// worker that read "no tenants" from a missing credential would idle forever while reporting
/// healthy, which is the failure `platform_connection` documents as data-loss-shaped.
pub async fn active_tenants(pool: &DbPool) -> Result<Vec<TenantId>, DbError> {
    let mut conn = pool.platform_connection().await?;

    let rows =
        sqlx::query(ACTIVE_TENANTS_SQL).fetch_all(&mut *conn).await.map_err(DbError::Query)?;

    rows.iter()
        .map(|row| row.try_get::<Uuid, _>("id").map(TenantId::from_uuid).map_err(DbError::Query))
        .collect()
}

/// The tenants a background job works on.
///
/// An **allow-list** of statuses rather than `<> 'DELETING'`, and that is the deny-by-default shape:
/// a status added to `migrations/0001`'s `CHECK` in a later milestone is excluded until somebody
/// decides it should not be, instead of joining the work list because nobody thought about it.
///
/// `deleted_at IS NULL` is a second, different exclusion rather than the same one twice: a tenant is
/// moved to `DELETING` while its content is purged and only then stamped `deleted_at`, so a row can
/// be soft-deleted while carrying a status the allow-list would otherwise admit.
///
/// `ORDER BY id` so two replicas walk the list the same way. That is not what keeps them apart —
/// the sweep's advisory lock and the reconciler's `SKIP LOCKED` do that — but an unordered list makes
/// a contended run's logs unreadable, and `ORDER BY` on a primary key is free.
const ACTIVE_TENANTS_SQL: &str = "
SELECT id
  FROM tenants
 WHERE deleted_at IS NULL
   AND status IN ('ACTIVE', 'READ_ONLY')
 ORDER BY id
";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Both exclusions, read out of the statement.
    ///
    /// This one is nearly free and says so: it compiles nothing and asserts about a string. It is
    /// here because the behavioural half below needs a database and this does not, so a developer
    /// who deletes a clause finds out from `cargo test` rather than from CI.
    #[test]
    fn the_statement_names_the_statuses_it_admits_rather_than_the_ones_it_refuses() {
        assert!(ACTIVE_TENANTS_SQL.contains("deleted_at IS NULL"));
        assert!(ACTIVE_TENANTS_SQL.contains("status IN ('ACTIVE', 'READ_ONLY')"));
        assert!(
            !ACTIVE_TENANTS_SQL.contains("<>"),
            "a deny-list admits every status a later migration adds"
        );
    }

    /// The enumerator lists what a background job should work on, and nothing else.
    ///
    /// Every state `migrations/0001`'s `CHECK` allows, plus the soft-deleted one, because a test with
    /// a single live tenant passes against a `SELECT id FROM tenants` carrying no predicate at all —
    /// which is what somebody writes the day a clause looks redundant.
    ///
    /// `READ_ONLY` is the half a blunter predicate gets wrong in the other direction: its content is
    /// still being served, so its index still has to be right.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
    async fn it_lists_working_tenants_and_omits_paused_and_departing_ones() {
        let (db, config) = crate::test_support::test_database().await;
        let fixtures = db.seed().await.expect("seed the fixtures");
        let mut admin = db.connect().await.expect("admin connection");

        // `beta` is read-only and must still be listed. The other three are each excluded for a
        // different reason, and no two of them are excluded by the same clause.
        set_status(&mut admin, fixtures.beta.id, "READ_ONLY", false).await;
        let suspended = insert_tenant(&mut admin, "tenant-suspended", "SUSPENDED", false).await;
        let deleting = insert_tenant(&mut admin, "tenant-deleting", "DELETING", false).await;
        let deleted = insert_tenant(&mut admin, "tenant-deleted", "ACTIVE", true).await;

        let pool = platform_pool(&config).await;
        let listed = active_tenants(&pool).await.expect("enumerate tenants");

        assert!(listed.contains(&fixtures.alpha.id), "an active tenant was not listed");
        assert!(listed.contains(&fixtures.beta.id), "a read-only tenant was dropped from the list");
        assert!(
            !listed.contains(&suspended),
            "a suspended tenant was handed to the passes; docs/11 §12 pauses its background \
             processing"
        );
        assert!(!listed.contains(&deleting), "a DELETING tenant was handed to the passes");
        assert!(!listed.contains(&deleted), "a soft-deleted tenant was handed to the passes");
        assert_eq!(listed.len(), 2, "listed {listed:?}");

        drop(db);
    }

    /// No platform credential is a refusal, never an empty list.
    ///
    /// The distinction is the whole reason this is worth a test: an empty list is a scheduler that
    /// idles at full health while a backlog builds, and it is what a fallback to the application
    /// pool would produce — row-level security with no tenant context set matches nothing.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
    async fn without_the_platform_role_it_refuses_rather_than_reporting_no_tenants() {
        let (db, config) = crate::test_support::test_database().await;
        let _seeded = db.seed().await.expect("seed the fixtures");

        // The same database, reached without a platform URL. There *are* tenants; the credential to
        // enumerate them is what is missing.
        let pool = DbPool::connect(&config).await.expect("application pool");
        let error =
            active_tenants(&pool).await.expect_err("an unconfigured platform role must fail");
        assert!(matches!(error, DbError::PlatformNotConfigured), "{error:?}");

        drop(db);
    }

    /// A pool whose platform URL is the test cluster's own credential.
    ///
    /// The harness gives one superuser, and a superuser bypasses row-level security exactly as
    /// `enclave_platform` does — which is what makes it a faithful stand-in here and a hazard
    /// everywhere else (`TestDb::pool` says so at length).
    async fn platform_pool(config: &crate::DbConfig) -> DbPool {
        let config = config.clone().with_platform_url(config.url.clone());
        DbPool::connect(&config).await.expect("platform pool")
    }

    async fn insert_tenant(
        conn: &mut sqlx::PgConnection,
        slug: &str,
        status: &str,
        deleted: bool,
    ) -> TenantId {
        let id = TenantId::new_v7();
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at, deleted_at)
             VALUES ($1, $2, $2, $3, now(), now(), CASE WHEN $4 THEN now() END)",
        )
        .bind(id.as_uuid())
        .bind(slug)
        .bind(status)
        .bind(deleted)
        .execute(&mut *conn)
        .await
        .expect("insert a tenant");
        id
    }

    async fn set_status(
        conn: &mut sqlx::PgConnection,
        tenant: TenantId,
        status: &str,
        deleted: bool,
    ) {
        sqlx::query(
            "UPDATE tenants SET status = $2, deleted_at = CASE WHEN $3 THEN now() END WHERE id = $1",
        )
        .bind(tenant.as_uuid())
        .bind(status)
        .bind(deleted)
        .execute(&mut *conn)
        .await
        .expect("update a tenant");
    }
}
