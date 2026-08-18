//! `enclave-testing` — the integration-test harness.
//!
//! Every integration and security test in the workspace runs against a **real PostgreSQL**, never a
//! mock. The properties under test — row-level security, the transactional outbox, constraint
//! enforcement, `SET LOCAL` semantics under connection pooling — are properties of PostgreSQL. A
//! mock would assert that our mock behaves the way we assumed PostgreSQL does, which is the belief
//! being tested (`plans/M0-FOUNDATIONS.md` D7).
//!
//! # How a test gets a database
//!
//! [`TestDb::start`] reads `DATABASE_URL`, connects to it as an administrative user, and creates a
//! **fresh, uniquely-named database** for the caller. Migrations are applied to that database, and
//! it is dropped when the handle goes out of scope.
//!
//! One database per test binary rather than per test: container or database creation costs about a
//! second, and a suite that takes twenty minutes is a suite people stop running locally, which is a
//! slower way of having no tests at all.
//!
//! Because each binary gets its own database, test binaries can run in parallel without seeing each
//! other's rows — which matters, since `cargo test` runs them concurrently by default.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = enclave_testing::TestDb::start().await?;
//! let fixtures = db.seed().await?;
//! let pool = db.pool().await?;
//! // ... assert against fixtures.alpha / fixtures.beta ...
//! # Ok(())
//! # }
//! ```
//!
//! # Why not testcontainers
//!
//! `plans/M0-FOUNDATIONS.md` D7 named testcontainers. This harness takes a `DATABASE_URL` instead,
//! and the plan records why: the essential property of D7 is *a real database rather than a mock*,
//! and that is preserved exactly. What changes is who starts the server — the Compose stack
//! (`ENC-113`) or CI's service container, both of which have to exist anyway. Adding a container
//! runtime as a library dependency would duplicate them and put an image pull on the critical path
//! of every local test run.

//! # What else is here
//!
//! [`content`] builds the workspace → library → folder → file spine and the ACL entries over it, so
//! the four suites that need one stop writing the same `INSERT` four times. [`schema`] asks
//! PostgreSQL what is tenant-scoped and whether the current role is actually subject to row-level
//! security — the question PR #22 turned out to hinge on.

#![allow(clippy::expect_used, clippy::unwrap_used)]

pub mod content;
pub mod schema;

use std::fmt;

use chrono::{DateTime, TimeZone, Utc};
use enclave_core::{GroupId, TenantId, UserId};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// Anything that can go wrong setting a test database up.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// `DATABASE_URL` is absent or empty.
    #[error(
        "DATABASE_URL is not set. Integration tests need a real PostgreSQL: start one with \
         `docker compose -f deploy/compose/dev.yml up -d postgres`, or point DATABASE_URL at any \
         database you can create databases on."
    )]
    NoDatabaseUrl,

    /// The administrative connection failed.
    #[error("could not connect to {url_summary}: {source}")]
    Connect {
        /// The host and database, with any credentials removed.
        url_summary: String,
        /// The underlying failure.
        source: sqlx::Error,
    },

    /// A statement failed.
    #[error("harness statement failed")]
    Sql(#[from] sqlx::Error),

    /// Migrations did not apply.
    #[error("migrations failed to apply to the test database")]
    Migrate(#[from] enclave_db::DbError),
}

/// Advisory-lock key serialising test-database setup across the cluster.
///
/// Arbitrary but fixed, and namespaced high enough not to collide with the application's own
/// advisory locks (the audit chain uses per-tenant keys derived from tenant ids).
const SETUP_LOCK: i64 = 0x0e11_c1a1_7e57_0001_u64 as i64;

/// Runs one ad-hoc DDL statement.
///
/// Public because the integration tests need the same escape hatch the harness does.
///
/// # Errors
///
/// Whatever the statement fails with.
///
/// sqlx 0.9 requires `'q: 'e` — the query must outlive the future executing it — and for
/// `impl<'c> Executor<'c> for &'c mut PgConnection` that cannot be satisfied by a `String` local
/// to an `async fn`: the local is dropped at the end of the body the future spans. A reborrow does
/// not help, and neither does binding earlier.
///
/// So the statement is promoted to `&'static str`. That is a leak, and worth being explicit about
/// rather than hiding: it is bounded by the number of DDL statements the *test harness* issues in a
/// process — creating and dropping test databases, a few dozen at most, tens of bytes each. It is
/// not on any request path and never runs in the product.
///
/// The alternative shapes were worse: owning the connection would restructure every caller, and
/// `Box::leak` at each call site would spread the same cost without the explanation.
pub async fn exec(conn: &mut PgConnection, sql: String) -> Result<(), sqlx::Error> {
    let sql: &'static str = Box::leak(sql.into_boxed_str());
    sqlx::raw_sql(sql).execute(&mut *conn).await.map(|_| ())
}

/// A disposable database, dropped when this handle is.
pub struct TestDb {
    admin_url: String,
    name: String,
    url: String,
}

impl fmt::Debug for TestDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the URL: it carries a password, and a panicking test prints its fixtures.
        f.debug_struct("TestDb").field("database", &self.name).finish()
    }
}

impl TestDb {
    /// Creates a fresh database, applies every migration, and returns a handle to it.
    ///
    /// # Errors
    ///
    /// [`HarnessError::NoDatabaseUrl`] when `DATABASE_URL` is unset, and connection or migration
    /// failures otherwise.
    pub async fn start() -> Result<Self, HarnessError> {
        let admin_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .ok_or(HarnessError::NoDatabaseUrl)?;

        // Unique per handle, so parallel test binaries cannot collide. Truncated because
        // PostgreSQL identifiers stop at 63 bytes.
        let suffix = Uuid::new_v4().simple().to_string();
        let name = format!("enclave_test_{}", &suffix[..16]);

        let mut admin = connect(&admin_url).await?;

        // Serialise setup across every TestDb in this cluster.
        //
        // Migration 0001 creates three cluster-wide roles, guarded by
        // `IF NOT EXISTS (SELECT 1 FROM pg_roles ...)`. That guard is check-then-act: two databases
        // migrating at once both pass the check, both issue CREATE ROLE, and one fails with
        // `unique_violation` on pg_authid_rolname_index. Reproduced 10 times out of 10 before this
        // lock existed.
        //
        // The lock is taken here rather than fixing the migration because migrations are
        // forward-only (`CLAUDE.md`) and 0001 is already merged. The underlying migration defect is
        // tracked as ENC-116; this makes the harness deterministic without editing history or
        // weakening the gate that forbids it.
        //
        // Session-level, on a connection this function owns for its whole duration, so it is
        // released when `admin` closes even if we return early.
        sqlx::query("SELECT pg_advisory_lock($1)").bind(SETUP_LOCK).execute(&mut admin).await?;

        let result = Self::create_and_migrate(&admin_url, &name, &mut admin).await;

        let _ignored =
            sqlx::query("SELECT pg_advisory_unlock($1)").bind(SETUP_LOCK).execute(&mut admin).await;
        let _ignored = admin.close().await;

        let url = result?;
        Ok(Self { admin_url, name, url })
    }

    /// Creates the database and applies migrations, with the setup lock already held.
    async fn create_and_migrate(
        admin_url: &str,
        name: &str,
        admin: &mut PgConnection,
    ) -> Result<String, HarnessError> {
        // The name is generated from a UUID, never from caller input, so interpolating it is safe —
        // and CREATE DATABASE cannot take a bind parameter anyway.
        exec(admin, format!(r#"CREATE DATABASE "{name}""#)).await?;

        let url = swap_database(admin_url, name);
        let mut conn = connect(&url).await?;
        let migrated = enclave_db::run_migrations_on(&mut conn).await;
        let _ignored = conn.close().await;
        migrated?;

        Ok(url)
    }

    /// The connection URL for this database.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The database's name, for diagnostics.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Builds a [`enclave_db::DbPool`] against this database.
    ///
    /// The pool is small on purpose: the tests that matter here — the pool-exhaustion proof of
    /// plan decision D3 — are about what happens when connections are *contended*, and a pool
    /// large enough to give every task its own connection would quietly stop testing that.
    ///
    /// # Errors
    ///
    /// Connection failures.
    pub async fn pool(&self) -> Result<enclave_db::DbPool, HarnessError> {
        // `with_max_connections(2)` exists in the db crate for exactly this: the D3 proof runs on a
        // contended pool, and a pool large enough to hand every task its own connection would stop
        // testing the thing it is there to test.
        // `SET ROLE enclave_app` matters more than it looks. `DATABASE_URL` points at the cluster
        // superuser — that is what lets the harness create databases — and **superusers bypass
        // row-level security entirely**. A pool that stayed superuser would run every test with the
        // isolation switched off while appearing to prove it, which is exactly what happened until
        // ENC-124 sent a real cross-tenant request and got 200.
        let config = enclave_db::DbConfig::new(enclave_db::ConnectionUrl::new(self.url.clone()))
            .with_max_connections(2)
            .with_application_role("enclave_app");
        Ok(enclave_db::DbPool::connect(&config).await?)
    }

    /// Opens a connection to this database.
    ///
    /// # Errors
    ///
    /// Connection failures.
    pub async fn connect(&self) -> Result<PgConnection, HarnessError> {
        connect(&self.url).await
    }

    /// Seeds the deterministic tenant fixtures.
    ///
    /// # Errors
    ///
    /// Any statement failure.
    pub async fn seed(&self) -> Result<Fixtures, HarnessError> {
        let mut conn = self.connect().await?;
        let fixtures = Fixtures::default();
        for tenant in [&fixtures.alpha, &fixtures.beta] {
            tenant.insert(&mut conn).await?;
        }
        let _ignored = conn.close().await;
        Ok(fixtures)
    }

    /// Drops the database. Called automatically on drop; exposed for tests that want to assert it.
    ///
    /// # Errors
    ///
    /// Connection or statement failures.
    pub async fn cleanup(&self) -> Result<(), HarnessError> {
        let mut admin = connect(&self.admin_url).await?;
        // Terminate stragglers first: a pool that has not finished dropping will otherwise hold the
        // database open and DROP will fail, leaking a database per test run.
        let terminate = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
            self.name
        );
        let _ignored = exec(&mut admin, terminate).await;
        exec(&mut admin, format!(r#"DROP DATABASE IF EXISTS "{}""#, self.name)).await?;
        let _ignored = admin.close().await;
        Ok(())
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Drop is synchronous and the cleanup is async. Rather than block a runtime thread — which
        // deadlocks on a current-thread runtime — hand it to a detached thread with its own
        // runtime. A leaked test database is a nuisance; a hung test suite is a broken one.
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let handle = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            runtime.block_on(async {
                if let Ok(mut admin) = connect(&admin_url).await {
                    let terminate = format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
                    );
                    let _ignored = exec(&mut admin, terminate).await;
                    let _ignored =
                        exec(&mut admin, format!(r#"DROP DATABASE IF EXISTS "{name}""#)).await;
                    let _ignored = admin.close().await;
                }
            });
        });
        let _ignored = handle.join();
    }
}

async fn connect(url: &str) -> Result<PgConnection, HarnessError> {
    PgConnection::connect(url)
        .await
        .map_err(|source| HarnessError::Connect { url_summary: redact(url), source })
}

/// Replaces the database component of a connection URL.
fn swap_database(url: &str, database: &str) -> String {
    match url.rfind('/') {
        Some(slash) => {
            let (head, tail) = url.split_at(slash + 1);
            // Preserve any query string; sslmode and friends matter.
            match tail.find('?') {
                Some(q) => format!("{head}{database}{}", &tail[q..]),
                None => format!("{head}{database}"),
            }
        }
        None => url.to_owned(),
    }
}

/// Strips credentials from a URL so it can appear in an error message.
fn redact(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        }
        _ => url.to_owned(),
    }
}

/// A deterministic UUID, so a failure is reproducible from the log alone.
///
/// Random fixture IDs make a failing assertion unrepeatable and force the reader to re-run the suite
/// to learn what `9f3c…` was. These are derived from a fixed namespace and a name.
fn fixture_id(name: &str) -> Uuid {
    const NAMESPACE: Uuid = Uuid::from_bytes([
        0x0e, 0x11, 0xc1, 0xa1, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    Uuid::new_v5(&NAMESPACE, name.as_bytes())
}

/// A fixed instant, so timestamps in fixtures never vary between runs.
fn fixture_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed timestamp")
}

/// The two seeded tenants.
///
/// `beta` exists so that every cross-tenant assertion has a realistic counterpart: it mirrors
/// `alpha`'s structure with the **same names**, so a test that passes only because the other
/// tenant's records were called something else cannot pass by accident (`docs/12-TESTING.md §3`).
#[derive(Debug, Clone)]
pub struct Fixtures {
    /// The primary tenant.
    pub alpha: TenantFixture,
    /// The mirror tenant, for cross-tenant assertions.
    pub beta: TenantFixture,
}

impl Default for Fixtures {
    fn default() -> Self {
        Self { alpha: TenantFixture::new("tenant-alpha"), beta: TenantFixture::new("tenant-beta") }
    }
}

/// One seeded tenant and its principals.
#[derive(Debug, Clone)]
pub struct TenantFixture {
    /// The tenant's slug, and the prefix of every derived fixture id.
    pub slug: String,
    /// The tenant id.
    pub id: TenantId,
    /// Workspace owner.
    pub owner: UserId,
    /// Ordinary member.
    pub member: UserId,
    /// Read-only user.
    pub viewer: UserId,
    /// Tenant administrator.
    pub admin: UserId,
    /// Read-only auditor.
    pub auditor: UserId,
    /// `engineering` group.
    pub engineering: GroupId,
    /// `finance` group.
    pub finance: GroupId,
    /// `finance-leads`, nested inside `finance`, so group-closure resolution has something to
    /// resolve.
    pub finance_leads: GroupId,
}

impl TenantFixture {
    fn new(slug: &str) -> Self {
        let id = |name: &str| fixture_id(&format!("{slug}/{name}"));
        Self {
            slug: slug.to_owned(),
            id: TenantId::from_uuid(id("tenant")),
            owner: UserId::from_uuid(id("user/owner")),
            member: UserId::from_uuid(id("user/member")),
            viewer: UserId::from_uuid(id("user/viewer")),
            admin: UserId::from_uuid(id("user/admin")),
            auditor: UserId::from_uuid(id("user/auditor")),
            engineering: GroupId::from_uuid(id("group/engineering")),
            finance: GroupId::from_uuid(id("group/finance")),
            finance_leads: GroupId::from_uuid(id("group/finance-leads")),
        }
    }

    /// Every user in this tenant, with the local part of its email.
    fn users(&self) -> [(UserId, &'static str, bool); 5] {
        [
            (self.owner, "owner", false),
            (self.member, "member", false),
            (self.viewer, "viewer", false),
            (self.admin, "admin", true),
            (self.auditor, "auditor", false),
        ]
    }

    async fn insert(&self, conn: &mut PgConnection) -> Result<(), HarnessError> {
        let now = fixture_time();

        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at)
             VALUES ($1, $2, $3, 'ACTIVE', $4, $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(self.id.as_uuid())
        .bind(&self.slug)
        .bind(&self.slug)
        .bind(now)
        .execute(&mut *conn)
        .await?;

        for (user, local, is_admin) in self.users() {
            let email = format!("{local}@{}.example", self.slug);
            sqlx::query(
                "INSERT INTO users
                   (id, tenant_id, email, normalized_email, display_name, status, is_admin,
                    source, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, 'LOCAL', $7, $7)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(user.as_uuid())
            .bind(self.id.as_uuid())
            .bind(&email)
            .bind(email.to_lowercase())
            .bind(local)
            .bind(is_admin)
            .bind(now)
            .execute(&mut *conn)
            .await?;
        }

        for (group, name) in [
            (self.engineering, "engineering"),
            (self.finance, "finance"),
            (self.finance_leads, "finance-leads"),
        ] {
            sqlx::query(
                "INSERT INTO groups
                   (id, tenant_id, name, normalized_name, source, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'LOCAL', $5, $5)
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(group.as_uuid())
            .bind(self.id.as_uuid())
            .bind(name)
            .bind(name.to_lowercase())
            .bind(now)
            .execute(&mut *conn)
            .await?;
        }

        // finance-leads nests inside finance, and member belongs to engineering. Without a nested
        // group the closure-resolution path is never exercised by any test that uses these
        // fixtures, and that path is where deny-wins inheritance gets subtle.
        for (group, member, kind) in [
            (self.finance, self.finance_leads.as_uuid(), "GROUP"),
            (self.engineering, self.member.as_uuid(), "USER"),
            (self.finance_leads, self.owner.as_uuid(), "USER"),
        ] {
            sqlx::query(
                "INSERT INTO group_members (tenant_id, group_id, member_id, member_type, added_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
            )
            .bind(self.id.as_uuid())
            .bind(group.as_uuid())
            .bind(member)
            .bind(kind)
            .bind(now)
            .execute(&mut *conn)
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_ids_are_stable_across_runs() {
        // The whole point: a failing assertion must name the same id tomorrow.
        let a = Fixtures::default();
        let b = Fixtures::default();
        assert_eq!(a.alpha.id, b.alpha.id);
        assert_eq!(a.alpha.owner, b.alpha.owner);
    }

    #[test]
    fn the_two_tenants_share_no_identifiers() {
        // If alpha and beta ever collided, every cross-tenant test would pass vacuously.
        let f = Fixtures::default();
        assert_ne!(f.alpha.id, f.beta.id);
        assert_ne!(f.alpha.owner, f.beta.owner);
        assert_ne!(f.alpha.engineering, f.beta.engineering);
    }

    #[test]
    fn urls_are_rewritten_without_losing_query_parameters() {
        assert_eq!(
            swap_database("postgres://u:p@host:5432/enclave", "t1"),
            "postgres://u:p@host:5432/t1"
        );
        assert_eq!(
            swap_database("postgres://u:p@host:5432/enclave?sslmode=require", "t1"),
            "postgres://u:p@host:5432/t1?sslmode=require"
        );
    }

    #[test]
    fn credentials_never_survive_into_an_error_message() {
        let redacted = redact("postgres://user:hunter2@db.internal:5432/enclave");
        assert!(!redacted.contains("hunter2"), "{redacted}");
        assert!(!redacted.contains("user"), "{redacted}");
        assert!(redacted.contains("db.internal"), "{redacted}");
    }
}
