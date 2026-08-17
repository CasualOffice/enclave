//! ENC-106 — the RLS coverage gate.
//!
//! Asserts the invariant in `CLAUDE.md` rule 4 and `docs/04-DATA-MODEL.md §3`: **every table with a
//! `tenant_id` column has row-level security enabled, forced, and at least one policy.**
//!
//! This is a structural test, not a behavioural one. It does not check that any particular query is
//! filtered; it checks that the mechanism which does the filtering is switched on everywhere it
//! must be. That distinction matters because the failure mode it guards against is not a bad query
//! — it is a table added six months from now by someone who did not read `docs/04`, on a Friday.
//!
//! Three properties, each of which is separately load-bearing:
//!
//! * `rowsecurity` — policies exist and apply.
//! * `forcerowsecurity` — they apply *to the table owner too*. Without this, anything connecting as
//!   the owner silently sees every tenant, and the isolation is decorative.
//! * at least one policy — RLS with no policy denies everything, which fails closed but also fails
//!   the product. A table in that state is a misconfiguration, not a safe default.
//!
//! Ignored by default because it needs a live PostgreSQL. CI runs it with `--include-ignored`
//! against a service container; locally, start one and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_db::migrate::run_migrations_on;
use sqlx::{Connection, PgConnection, Row};

/// Tables that legitimately carry a `tenant_id` column while not being tenant-scoped rows.
///
/// Empty, deliberately. It exists so that the *shape* of an exemption is defined — a table name and
/// the reason — rather than being invented under pressure the first time someone needs one. Adding
/// an entry is a reviewable act, and a reviewer should ask why the column is there at all.
const EXEMPT: &[(&str, &str)] = &[];

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.trim().is_empty())
}

async fn connect_and_migrate() -> PgConnection {
    let url = database_url().expect(
        "DATABASE_URL must be set to run the RLS coverage gate; \
         CI provides a service container, locally use deploy/compose/dev.yml",
    );
    let mut conn = PgConnection::connect(&url).await.expect("connect to the test database");
    run_migrations_on(&mut conn).await.expect("apply migrations");
    conn
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_tenant_scoped_table_has_rls_enabled_forced_and_a_policy() {
    let mut conn = connect_and_migrate().await;

    // One query rather than three, so the report names every offending table at once. A gate that
    // surfaces one failure per run turns a ten-minute fix into a ten-round game.
    let rows = sqlx::query(
        r#"
        SELECT c.relname                        AS table_name,
               c.relrowsecurity                 AS enabled,
               c.relforcerowsecurity            AS forced,
               count(p.polname)                 AS policies
        FROM pg_catalog.pg_class      c
        JOIN pg_catalog.pg_namespace  n  ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute  a  ON a.attrelid = c.oid
        LEFT JOIN pg_catalog.pg_policy p ON p.polrelid = c.oid
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')          -- ordinary and partitioned tables
          AND a.attname = 'tenant_id'
          AND a.attnum > 0
          AND NOT a.attisdropped
        GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
        ORDER BY c.relname
        "#,
    )
    .fetch_all(&mut conn)
    .await
    .expect("enumerate tenant-scoped tables");

    assert!(
        !rows.is_empty(),
        "no table with a tenant_id column was found. Either the migrations did not run, or the \
         query above stopped matching the schema — both mean this gate is proving nothing, which \
         is worse than it failing."
    );

    let mut failures = Vec::new();
    let mut checked = 0usize;

    for row in &rows {
        let name: String = row.get("table_name");
        if let Some((_, reason)) = EXEMPT.iter().find(|(t, _)| *t == name) {
            println!("  exempt  {name} — {reason}");
            continue;
        }
        checked += 1;

        let enabled: bool = row.get("enabled");
        let forced: bool = row.get("forced");
        let policies: i64 = row.get("policies");

        let mut missing = Vec::new();
        if !enabled {
            missing.push("ENABLE ROW LEVEL SECURITY");
        }
        if !forced {
            missing.push("FORCE ROW LEVEL SECURITY");
        }
        if policies == 0 {
            missing.push("a policy");
        }

        if missing.is_empty() {
            println!("  ok      {name} ({policies} polic{})", if policies == 1 { "y" } else { "ies" });
        } else {
            failures.push(format!("{name}: missing {}", missing.join(", ")));
        }
    }

    assert!(
        failures.is_empty(),
        "RLS coverage gate failed for {} of {checked} tenant-scoped tables:\n  {}\n\n\
         Every tenant-scoped table needs ENABLE + FORCE row level security and a tenant_isolation \
         policy, in the same migration that creates it (docs/04-DATA-MODEL.md §3). Migration 0002 \
         applies these by looping over every table with a tenant_id column — if a table is missing \
         here, it was probably created after that loop ran.",
        failures.len(),
        failures.join("\n  "),
    );

    println!("\nRLS coverage: {checked} tenant-scoped tables, all enabled, forced and policied.");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_isolation_policy_reads_the_tenant_from_the_session_not_the_query() {
    let mut conn = connect_and_migrate().await;

    // A policy that hard-codes a tenant, or that compares tenant_id to itself, would satisfy the
    // structural test above while isolating nothing. Assert the predicate actually consults the
    // GUC that TenantScoped sets.
    let rows = sqlx::query(
        r#"
        SELECT c.relname                                  AS table_name,
               pg_catalog.pg_get_expr(p.polqual, p.polrelid)      AS using_expr,
               pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr
        FROM pg_catalog.pg_policy     p
        JOIN pg_catalog.pg_class      c ON c.oid = p.polrelid
        JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND p.polname = 'tenant_isolation'
        ORDER BY c.relname
        "#,
    )
    .fetch_all(&mut conn)
    .await
    .expect("read tenant_isolation policies");

    assert!(!rows.is_empty(), "no tenant_isolation policy exists on any table");

    let mut failures = Vec::new();
    for row in &rows {
        let name: String = row.get("table_name");
        let using: Option<String> = row.get("using_expr");
        let check: Option<String> = row.get("check_expr");

        for (label, expr) in [("USING", &using), ("WITH CHECK", &check)] {
            match expr {
                None => failures.push(format!("{name}: {label} clause is absent")),
                Some(e) if !e.contains("app.tenant_id") => {
                    failures.push(format!("{name}: {label} does not read app.tenant_id — `{e}`"));
                }
                Some(e) if !e.contains("tenant_id") => {
                    failures.push(format!("{name}: {label} does not constrain tenant_id — `{e}`"));
                }
                Some(_) => {}
            }
        }
    }

    assert!(
        failures.is_empty(),
        "tenant_isolation policies are not enforcing the session tenant:\n  {}",
        failures.join("\n  "),
    );

    println!("{} tenant_isolation policies all read app.tenant_id.", rows.len());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_audit_trail_cannot_be_rewritten_by_the_application_role() {
    let mut conn = connect_and_migrate().await;

    // Test U2 (docs/12-TESTING.md §4.9). An append-only audit trail that the application can UPDATE
    // is not append-only, and the difference only becomes visible when someone needs the log to be
    // trustworthy — which is exactly when it is too late to find out.
    let rows = sqlx::query(
        r#"
        SELECT privilege_type
        FROM information_schema.role_table_grants
        WHERE table_schema = 'public'
          AND table_name   = 'audit_events'
          AND grantee      = 'enclave_app'
        "#,
    )
    .fetch_all(&mut conn)
    .await
    .expect("read audit_events grants");

    let granted: Vec<String> = rows.iter().map(|r| r.get::<String, _>("privilege_type")).collect();

    for forbidden in ["UPDATE", "DELETE", "TRUNCATE"] {
        assert!(
            !granted.iter().any(|g| g == forbidden),
            "enclave_app holds {forbidden} on audit_events; the audit trail is not append-only. \
             Granted: {granted:?}"
        );
    }
    assert!(
        granted.iter().any(|g| g == "INSERT"),
        "enclave_app cannot INSERT into audit_events, so nothing can be audited. Granted: {granted:?}"
    );

    println!("audit_events grants for enclave_app: {granted:?}");
}
