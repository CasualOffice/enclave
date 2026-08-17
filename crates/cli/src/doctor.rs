//! `enclave-cli doctor` — what to run when the stack "doesn't work".
//!
//! Strictly read-only. Someone runs this on a database they are already unsure about, sometimes in
//! production; a diagnostic that repaired anything would be a diagnostic nobody dares run, and the
//! first thing it would repair is the evidence.
//!
//! It checks the four things that are wrong in almost every case, in the order that makes the
//! answer useful:
//!
//! 1. **connectivity** — can this binary reach the server at all, and as whom;
//! 2. **migrations** — is the schema there, and is it the one this binary was built against;
//! 3. **row-level security** — is layer 2 of tenant isolation actually enabled and forced
//!    (`docs/04-DATA-MODEL.md §3.2`);
//! 4. **grants** — does `enclave_app` hold what it needs, and *not* hold `UPDATE`/`DELETE` on
//!    `audit_events`, which is the U2 assertion in `docs/12-TESTING.md §4`.
//!
//! Checks 3 and 4 are security properties, not conveniences. A database where they are wrong will
//! serve requests perfectly happily, which is exactly why a command has to ask.

use anyhow::Context as _;
use sqlx::{PgConnection, Row as _};

use crate::connect::Target;
use crate::schema::{ahead_of_binary, applied_migrations, pending, table_exists, AppliedMigration};

/// The application role whose grants are checked. Created by `migrations/0001_foundations.sql`.
const APP_ROLE: &str = "enclave_app";

/// How a single check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// As expected.
    Pass,
    /// Not broken, but not what a healthy deployment looks like.
    Warn,
    /// Broken. The command exits non-zero.
    Fail,
}

impl Status {
    const fn marker(self) -> &'static str {
        match self {
            Self::Pass => "[ ok ]",
            Self::Warn => "[warn]",
            Self::Fail => "[fail]",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone)]
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
    /// What to do about it. Present on every non-passing check, because a diagnostic that names a
    /// problem without naming the fix has moved the work rather than done it.
    remedy: Option<String>,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: Status::Pass, detail: detail.into(), remedy: None }
    }

    fn warn(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self { name, status: Status::Warn, detail: detail.into(), remedy: Some(remedy.into()) }
    }

    fn fail(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self { name, status: Status::Fail, detail: detail.into(), remedy: Some(remedy.into()) }
    }

    fn print(&self) {
        println!("  {} {:<18} {}", self.status.marker(), self.name, self.detail);
        if let Some(remedy) = &self.remedy {
            for line in remedy.lines() {
                println!("         {:<18} → {line}", "");
            }
        }
    }
}

/// Runs every check and prints the report.
///
/// # Errors
///
/// When the database cannot be reached at all, or when any check fails — the exit code is what a
/// script or a CI job reads.
pub(crate) async fn run(target: &Target) -> anyhow::Result<()> {
    println!("enclave-cli doctor");
    println!("  target: {}", target.summary());
    println!("  from:   {}", target.origin());
    println!();

    // Connectivity is not a `Check`: without it there is nothing to check, and the connection
    // error is already the actionable message.
    let mut conn = target.connect().await?;
    let identity = identity(&mut conn).await?;

    let applied = applied_migrations(&mut conn).await?;
    let checks = vec![
        Check::pass("connectivity", identity.describe()),
        migration_check(&applied),
        rls_check(&tenant_tables(&mut conn).await?),
        grants_check(&app_grants(&mut conn).await?),
    ];

    for check in &checks {
        check.print();
    }
    println!();

    let failures = checks.iter().filter(|check| check.status == Status::Fail).count();
    let warnings = checks.iter().filter(|check| check.status == Status::Warn).count();
    println!("  {failures} failing, {warnings} warning(s)");

    if failures > 0 {
        anyhow::bail!("{failures} check(s) failed against {}", target.summary());
    }
    Ok(())
}

/// Who this connection is, and what that implies for the checks below it.
#[derive(Debug, Clone)]
struct Identity {
    server_version: String,
    database: String,
    role: String,
    superuser: bool,
    bypass_rls: bool,
}

impl Identity {
    fn describe(&self) -> String {
        let mut detail = format!(
            "PostgreSQL {} · database {} · role {}",
            self.server_version, self.database, self.role
        );
        if self.superuser || self.bypass_rls {
            // Worth saying out loud: on such a connection every tenant-scoped query silently sees
            // every tenant, so "it works when I run it by hand" proves nothing about the
            // application role.
            detail.push_str(" (bypasses row-level security)");
        }
        detail
    }
}

async fn identity(conn: &mut PgConnection) -> anyhow::Result<Identity> {
    let row = sqlx::query(
        "SELECT current_setting('server_version')       AS server_version,
                current_database()::text                AS database,
                current_user::text                      AS role,
                (SELECT rolsuper     FROM pg_catalog.pg_roles WHERE rolname = current_user) AS superuser,
                (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user) AS bypass_rls",
    )
    .fetch_one(&mut *conn)
    .await
    .context("connected, but could not read the server's identity")?;

    Ok(Identity {
        server_version: row.try_get("server_version")?,
        database: row.try_get("database")?,
        role: row.try_get("role")?,
        superuser: row.try_get::<Option<bool>, _>("superuser")?.unwrap_or(false),
        bypass_rls: row.try_get::<Option<bool>, _>("bypass_rls")?.unwrap_or(false),
    })
}

/// A table carrying `tenant_id`, and the state of its isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TenantTable {
    name: String,
    enabled: bool,
    forced: bool,
    policy: bool,
}

/// The same predicate the ENC-106 CI gate applies, asked of a live database.
///
/// Derived from the catalog rather than from a list of table names, for the reason
/// `migrations/0002_rls_policies.sql` gives: the rule is "a `tenant_id` column implies a policy",
/// and a hardcoded list is a copy of the rule that can fall behind it.
async fn tenant_tables(conn: &mut PgConnection) -> anyhow::Result<Vec<TenantTable>> {
    let rows = sqlx::query(
        "SELECT c.relname::text        AS name,
                c.relrowsecurity       AS enabled,
                c.relforcerowsecurity  AS forced,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_policy p
                    WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation'
                )                      AS policy
         FROM pg_catalog.pg_class      c
         JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
         JOIN pg_catalog.pg_attribute  a ON a.attrelid = c.oid
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p')
           AND a.attname = 'tenant_id'
           AND a.attnum  > 0
           AND NOT a.attisdropped
         ORDER BY c.relname",
    )
    .fetch_all(&mut *conn)
    .await
    .context("could not read row-level security state from the catalog")?;

    rows.into_iter()
        .map(|row| {
            Ok(TenantTable {
                name: row.try_get("name")?,
                enabled: row.try_get("enabled")?,
                forced: row.try_get("forced")?,
                policy: row.try_get("policy")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .context("unexpected catalog shape reading row-level security state")
}

/// What `enclave_app` may do. Booleans rather than a privilege list because the question is a fixed
/// set of yes/no expectations, and two of them are expected to be **no**.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AppGrants {
    role_exists: bool,
    schema_present: bool,
    schema_usage: bool,
    tenants_select: bool,
    users_select: bool,
    users_insert: bool,
    audit_select: bool,
    audit_insert: bool,
    /// Must be `false`. See `docs/04-DATA-MODEL.md §14`.
    audit_update: bool,
    /// Must be `false`.
    audit_delete: bool,
}

async fn app_grants(conn: &mut PgConnection) -> anyhow::Result<AppGrants> {
    let role_exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)")
            .bind(APP_ROLE)
            .fetch_one(&mut *conn)
            .await
            .context("could not check whether the application role exists")?
            .try_get(0)?;

    // `has_table_privilege` raises on a table that does not exist, so an unmigrated database has to
    // be detected before asking rather than by catching the error.
    let schema_present = table_exists(&mut *conn, "users").await?
        && table_exists(&mut *conn, "tenants").await?
        && table_exists(&mut *conn, "audit_events").await?;

    if !role_exists || !schema_present {
        return Ok(AppGrants { role_exists, schema_present, ..AppGrants::default() });
    }

    let row = sqlx::query(
        "SELECT has_schema_privilege($1, 'public', 'USAGE')            AS schema_usage,
                has_table_privilege($1, 'public.tenants', 'SELECT')     AS tenants_select,
                has_table_privilege($1, 'public.users', 'SELECT')       AS users_select,
                has_table_privilege($1, 'public.users', 'INSERT')       AS users_insert,
                has_table_privilege($1, 'public.audit_events', 'SELECT') AS audit_select,
                has_table_privilege($1, 'public.audit_events', 'INSERT') AS audit_insert,
                has_table_privilege($1, 'public.audit_events', 'UPDATE') AS audit_update,
                has_table_privilege($1, 'public.audit_events', 'DELETE') AS audit_delete",
    )
    .bind(APP_ROLE)
    .fetch_one(&mut *conn)
    .await
    .context("could not read the application role's grants")?;

    Ok(AppGrants {
        role_exists,
        schema_present,
        schema_usage: row.try_get("schema_usage")?,
        tenants_select: row.try_get("tenants_select")?,
        users_select: row.try_get("users_select")?,
        users_insert: row.try_get("users_insert")?,
        audit_select: row.try_get("audit_select")?,
        audit_insert: row.try_get("audit_insert")?,
        audit_update: row.try_get("audit_update")?,
        audit_delete: row.try_get("audit_delete")?,
    })
}

/// Turns the applied-migration list into a verdict.
fn migration_check(applied: &[AppliedMigration]) -> Check {
    let failed: Vec<_> = applied.iter().filter(|row| !row.success).map(|row| row.label()).collect();
    if !failed.is_empty() {
        return Check::fail(
            "migrations",
            format!("{} migration(s) did not complete: {}", failed.len(), failed.join(", ")),
            "resolve the partially-applied migration by hand; migrations are forward-only",
        );
    }

    let Some(latest) = applied.last() else {
        return Check::fail(
            "migrations",
            "no migrations have been applied — this database has no Enclave schema",
            "run `enclave-cli migrate`",
        );
    };

    let outstanding = pending(applied);
    if !outstanding.is_empty() {
        return Check::warn(
            "migrations",
            format!("at {}, with {} pending", latest.label(), outstanding.len()),
            "run `enclave-cli migrate`",
        );
    }

    let ahead = ahead_of_binary(applied);
    if !ahead.is_empty() {
        return Check::warn(
            "migrations",
            format!("the database is ahead of this binary by {} migration(s)", ahead.len()),
            "this binary is older than the schema — deploy the matching build before writing",
        );
    }

    Check::pass("migrations", format!("at {} · {} applied", latest.label(), applied.len()))
}

/// Turns the catalog's view of RLS into a verdict.
fn rls_check(tables: &[TenantTable]) -> Check {
    if tables.is_empty() {
        return Check::warn(
            "row-level security",
            "no tenant-scoped tables exist",
            "expected after migration 0001; run `enclave-cli migrate`",
        );
    }

    let offenders: Vec<String> = tables
        .iter()
        .filter(|table| !(table.enabled && table.forced && table.policy))
        .map(|table| {
            let mut missing = Vec::new();
            if !table.enabled {
                missing.push("not enabled");
            }
            if !table.forced {
                // The one people forget. Without FORCE the owner is exempt from its own policy,
                // and every check above this line still passes.
                missing.push("not forced");
            }
            if !table.policy {
                missing.push("no tenant_isolation policy");
            }
            format!("{} ({})", table.name, missing.join(", "))
        })
        .collect();

    if offenders.is_empty() {
        return Check::pass(
            "row-level security",
            format!("{} tenant-scoped table(s), all enabled, forced and policied", tables.len()),
        );
    }

    Check::fail(
        "row-level security",
        format!("tenant isolation is not enforced on: {}", offenders.join("; ")),
        "re-apply migrations/0002_rls_policies.sql as the schema owner; until then every tenant-scoped query can read every tenant",
    )
}

/// Turns the grant matrix into a verdict.
fn grants_check(grants: &AppGrants) -> Check {
    if !grants.role_exists {
        return Check::fail(
            "grants",
            format!("the {APP_ROLE} role does not exist"),
            "apply migrations/0001_foundations.sql, which creates the three roles",
        );
    }
    if !grants.schema_present {
        return Check::fail(
            "grants",
            "the schema is not present, so the role's grants cannot be checked",
            "run `enclave-cli migrate`",
        );
    }

    // The append-only property first: this is the one where a *held* privilege is the defect, and
    // it outranks anything missing. An application role that can rewrite audit_events makes the
    // hash chain worthless (`docs/12-TESTING.md §4`, U2).
    let mut forbidden = Vec::new();
    if grants.audit_update {
        forbidden.push("UPDATE on audit_events");
    }
    if grants.audit_delete {
        forbidden.push("DELETE on audit_events");
    }
    if !forbidden.is_empty() {
        return Check::fail(
            "grants",
            format!("{APP_ROLE} holds {} — the audit log is not append-only", forbidden.join(" and ")),
            "REVOKE UPDATE, DELETE ON audit_events FROM enclave_app (migrations/0002_rls_policies.sql §4)",
        );
    }

    let expected = [
        (grants.schema_usage, "USAGE on schema public"),
        (grants.tenants_select, "SELECT on tenants"),
        (grants.users_select, "SELECT on users"),
        (grants.users_insert, "INSERT on users"),
        (grants.audit_select, "SELECT on audit_events"),
        (grants.audit_insert, "INSERT on audit_events"),
    ];
    let missing: Vec<&str> =
        expected.iter().filter(|(held, _)| !held).map(|(_, label)| *label).collect();

    if missing.is_empty() {
        return Check::pass(
            "grants",
            format!("{APP_ROLE} has its grants, and cannot UPDATE or DELETE audit_events"),
        );
    }

    Check::fail(
        "grants",
        format!("{APP_ROLE} is missing: {}", missing.join(", ")),
        "re-apply migrations/0002_rls_policies.sql as the schema owner",
    )
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn migration(version: i64, success: bool) -> AppliedMigration {
        AppliedMigration { version, description: "foundations".to_owned(), success }
    }

    fn healthy_grants() -> AppGrants {
        AppGrants {
            role_exists: true,
            schema_present: true,
            schema_usage: true,
            tenants_select: true,
            users_select: true,
            users_insert: true,
            audit_select: true,
            audit_insert: true,
            audit_update: false,
            audit_delete: false,
        }
    }

    fn table(name: &str) -> TenantTable {
        TenantTable { name: name.to_owned(), enabled: true, forced: true, policy: true }
    }

    #[test]
    fn an_unmigrated_database_is_a_failure_with_the_command_that_fixes_it() {
        let check = migration_check(&[]);
        assert_eq!(check.status, Status::Fail);
        assert!(check.remedy.unwrap().contains("enclave-cli migrate"));
    }

    #[test]
    fn a_pending_migration_warns_rather_than_fails() {
        // A schema one release behind still serves requests; calling it a failure would train
        // people to ignore the exit code.
        let check = migration_check(&[migration(1, true)]);
        assert_eq!(check.status, Status::Warn);
    }

    #[test]
    fn a_half_applied_migration_outranks_everything_else() {
        let applied: Vec<_> = crate::schema::embedded_versions()
            .into_iter()
            .map(|version| migration(version, false))
            .collect();
        let check = migration_check(&applied);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("did not complete"), "{}", check.detail);
    }

    #[test]
    fn a_fully_migrated_database_passes() {
        let applied: Vec<_> = crate::schema::embedded_versions()
            .into_iter()
            .map(|version| migration(version, true))
            .collect();
        assert_eq!(migration_check(&applied).status, Status::Pass);
    }

    #[test]
    fn rls_enabled_but_not_forced_is_a_failure_that_says_so() {
        // The subtle one: `ENABLE` without `FORCE` exempts the owner, and every other symptom of a
        // healthy database remains. Naming "not forced" is the entire value of this check.
        let mut tables = vec![table("users"), table("groups")];
        tables[0].forced = false;
        let check = rls_check(&tables);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("users (not forced)"), "{}", check.detail);
        assert!(!check.detail.contains("groups"), "{}", check.detail);
    }

    #[test]
    fn a_missing_policy_is_reported_per_table() {
        let mut tables = vec![table("files")];
        tables[0].policy = false;
        let check = rls_check(&tables);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("no tenant_isolation policy"), "{}", check.detail);
    }

    #[test]
    fn fully_isolated_tables_pass() {
        assert_eq!(rls_check(&[table("users"), table("groups")]).status, Status::Pass);
    }

    #[test]
    fn no_tenant_scoped_tables_is_a_warning_not_a_pass() {
        // Vacuous truth is the failure mode of every "all of them are fine" check: with no tables
        // the offender list is empty, and reporting that as healthy would be wrong.
        assert_eq!(rls_check(&[]).status, Status::Warn);
    }

    #[test]
    fn healthy_grants_pass() {
        assert_eq!(grants_check(&healthy_grants()).status, Status::Pass);
    }

    #[test]
    fn a_writable_audit_log_is_reported_before_any_missing_grant() {
        // U2. Both problems are present here; the append-only violation is the one that must be on
        // the screen, because a missing SELECT is an outage and this is a cover-up capability.
        let grants = AppGrants { audit_delete: true, users_select: false, ..healthy_grants() };
        let check = grants_check(&grants);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("append-only"), "{}", check.detail);
    }

    #[test]
    fn a_missing_grant_names_the_privilege_and_the_table() {
        let grants = AppGrants { users_insert: false, ..healthy_grants() };
        let check = grants_check(&grants);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("INSERT on users"), "{}", check.detail);
    }

    #[test]
    fn an_absent_role_is_distinguished_from_a_missing_grant() {
        // Different fix: one re-applies 0001, the other re-applies 0002.
        let check = grants_check(&AppGrants::default());
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains(APP_ROLE), "{}", check.detail);
        assert!(check.remedy.unwrap().contains("0001"));
    }

    #[test]
    fn every_non_passing_check_carries_a_remedy() {
        // The rule this module is built on: a diagnostic without a next step has moved the work.
        let checks = [
            migration_check(&[]),
            rls_check(&[]),
            grants_check(&AppGrants::default()),
            grants_check(&AppGrants { audit_update: true, ..healthy_grants() }),
        ];
        for check in checks {
            assert_ne!(check.status, Status::Pass, "{} should not pass", check.name);
            assert!(check.remedy.is_some(), "{} has no remedy", check.name);
        }
    }

    #[test]
    fn a_bypassrls_connection_is_called_out() {
        // "It works when I run it by hand" is usually this.
        let identity = Identity {
            server_version: "16.2".to_owned(),
            database: "enclave".to_owned(),
            role: "postgres".to_owned(),
            superuser: true,
            bypass_rls: false,
        };
        assert!(identity.describe().contains("bypasses row-level security"));
    }
}
