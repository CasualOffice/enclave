//! Catalog introspection, so a test can assert something about *every* tenant-scoped table rather
//! than about the handful whose names the author remembered.
//!
//! The difference matters more than it sounds. A leakage assertion written against a fixed list of
//! tables silently stops covering the table added next week, which is the table nobody has thought
//! about yet. Asking PostgreSQL what exists means a new migration extends the assertion by itself —
//! and, if the new table is not isolated, fails the run that introduced it.

use sqlx::{PgConnection, Row as _};

use crate::HarnessError;

/// Every table in `public` that carries a `tenant_id` column, alphabetically.
///
/// This is the same definition migrations `0002` and `0003` use to decide what to enable row-level
/// security on and what to grant, and the same one `crates/db/tests/rls_coverage.rs` checks — so
/// "tenant-scoped" means one thing across the schema, the gates and the tests.
///
/// Partitions are excluded: `audit_events` is partitioned, and a partition inherits its parent's
/// policies and grants. Counting them would report the same table many times and, worse, would let
/// a test pass by asserting the same property repeatedly about one table.
///
/// # Errors
///
/// Any statement failure.
pub async fn tenant_scoped_tables(conn: &mut PgConnection) -> Result<Vec<String>, HarnessError> {
    let rows = sqlx::query(
        "SELECT c.relname AS table_name
         FROM pg_catalog.pg_class     c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
         WHERE n.nspname  = 'public'
           AND c.relkind  IN ('r', 'p')
           AND a.attname  = 'tenant_id'
           AND a.attnum   > 0
           AND NOT a.attisdropped
           AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid = c.oid
           )
         ORDER BY c.relname",
    )
    .fetch_all(&mut *conn)
    .await?;

    rows.iter().map(|row| row.try_get("table_name").map_err(HarnessError::from)).collect()
}

/// How the current session's role stands with respect to row-level security.
///
/// Exists because of PR #22: the harness connected as the cluster superuser, superusers bypass RLS
/// entirely, and every isolation test passed while proving nothing. A test that asserts "the other
/// tenant's rows were not visible" is only worth reading if it can also say *the role it ran as was
/// subject to the policies* — otherwise a green result is equally consistent with the policies
/// having been skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStanding {
    /// The effective role name.
    pub role: String,
    /// Whether it is a superuser, which bypasses row-level security.
    pub superuser: bool,
    /// Whether it holds `BYPASSRLS`.
    pub bypass_rls: bool,
}

impl RoleStanding {
    /// Whether row-level security actually applies to this role.
    #[must_use]
    pub const fn is_subject_to_rls(&self) -> bool {
        !self.superuser && !self.bypass_rls
    }
}

/// Reads the current session's standing, as PostgreSQL sees it.
///
/// # Errors
///
/// Any statement failure.
pub async fn role_standing(conn: &mut PgConnection) -> Result<RoleStanding, HarnessError> {
    let row = sqlx::query(
        "SELECT current_user::text AS role, r.rolsuper AS superuser, r.rolbypassrls AS bypass_rls
         FROM pg_catalog.pg_roles r
         WHERE r.rolname = current_user",
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(RoleStanding {
        role: row.try_get("role")?,
        superuser: row.try_get("superuser")?,
        bypass_rls: row.try_get("bypass_rls")?,
    })
}
