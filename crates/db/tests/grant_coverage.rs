//! ENC-127a — the grant coverage gate.
//!
//! The sibling gate in `rls_coverage.rs` proves that every tenant-scoped table has row-level
//! security enabled, forced, and a policy that reads `app.tenant_id`. It cannot prove the one thing
//! that makes any of that matter: **that the role those policies constrain can actually reach the
//! table at all.**
//!
//! That gap is not hypothetical. Migration 0002 enabled and forced RLS everywhere and granted
//! `enclave_app` on `audit_events` and nothing else. Because the application role could not touch
//! any other table, nothing ever connected as it — the harness and the dev stack both used the
//! cluster superuser, and a superuser bypasses row-level security entirely. Every isolation test in
//! the workspace was passing with isolation switched off, until an end-to-end request finally tried
//! a cross-tenant read and got `200` (PR #22 / ENC-124). Migration 0003 added the missing grants;
//! this file is the gate that notices if they ever go missing again.
//!
//! The distinction between the two gates is worth stating precisely, because it is the whole point:
//!
//! * `rls_coverage` asks *"is this table protected?"* — a table nobody can query answers "yes".
//! * `grant_coverage` asks *"is this table usable by the protected role?"* — the question whose
//!   "no" made every "yes" above meaningless.
//!
//! Four properties, each separately load-bearing:
//!
//! 1. **Every tenant-scoped table grants `enclave_app` at least `SELECT`.** A protected, ungranted
//!    table is how the whole system quietly reverts to running as superuser.
//! 2. **`audit_events` and its partitions grant `SELECT` and `INSERT`, and not `UPDATE`, `DELETE`
//!    or `TRUNCATE`.** This deliberately restates test U2 (`docs/12-TESTING.md §4.9`) from the grant
//!    side rather than the revoke side: `rls_coverage` reads `role_table_grants` for the parent
//!    only, so a partition granted `UPDATE` by hand — or by a future partition-creation job that
//!    forgets the `REVOKE` — would satisfy it while leaving the audit trail rewritable.
//! 3. **`enclave_app` is neither `SUPERUSER` nor `BYPASSRLS`.** Either attribute makes every policy
//!    in the schema decorative, and no other check in CI would notice: RLS coverage would still be
//!    green, the policies would still be correct, and they would simply never be applied.
//! 4. **`enclave_app` can `SET app.tenant_id`.** The isolation policies use `current_setting()` in
//!    its strict form, so a role that cannot set the parameter does not get an empty result — every
//!    query errors, or, in the variants that tolerate a missing GUC, returns nothing at all. Both
//!    read as "the database is empty" rather than "the grant is broken", which is exactly the class
//!    of failure that took a full PR to diagnose last time.
//!
//! Ignored by default because it needs a live PostgreSQL. CI runs it with `--include-ignored` in
//! the `grant-coverage` job of `.github/workflows/structural-gates.yml`, against a service
//! container; locally, start one and set `DATABASE_URL`. It inspects a throwaway database created
//! by the harness, never the one `DATABASE_URL` names (`ENC-504`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_testing::TestDb;
use sqlx::{PgConnection, Row};

/// The role the application connects as, and the only role this gate has an opinion about.
const APP_ROLE: &str = "enclave_app";

/// The role the outbox drain, the tenant enumerator and the refresh-token lookups run as.
const PLATFORM_ROLE: &str = "enclave_platform";

/// Tables that carry a `tenant_id` column and are deliberately unreachable by `enclave_app`.
///
/// Empty, deliberately — the same shape as `rls_coverage::EXEMPT` and for the same reason. An
/// exemption here is stronger than an exemption there: it asserts that a tenant-scoped table exists
/// which the application must never read, which means some *other* role reaches it, which means a
/// reviewer needs to know which role and why. Making that a code change with a written reason is
/// the point.
const EXEMPT: &[(&str, &str)] = &[];

/// A freshly created, freshly migrated database, and a connection to it.
///
/// The handle is returned rather than dropped because dropping it drops the database — the caller
/// has to keep it alive for as long as the connection is used.
///
/// This gate used to migrate the database `DATABASE_URL` names directly, which is what `ENC-504`
/// removed: locally that is a developer's dev stack, and a migration applied to it records the
/// migration's checksum there, failing the forward-only gate on every later run from a branch that
/// no longer has it. The role attributes read below are cluster-wide either way — `enclave_app` and
/// `enclave_platform` are created by migration 0001 and belong to the cluster, not to a database —
/// so moving the connection one database over changes nothing about what is being asserted.
async fn migrated_database() -> (TestDb, PgConnection) {
    let db = TestDb::start().await.expect(
        "the grant coverage gate needs a PostgreSQL it may create databases on; CI provides a \
         service container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let conn = db.connect().await.expect("connect to the throwaway database");
    (db, conn)
}

/// Names of `audit_events` and every partition currently attached to it.
///
/// Read from `pg_inherits` rather than hardcoded: partitions are created by a scheduled job at
/// runtime, so the set is not knowable from the migrations, and a gate that checked only the ones
/// that existed when it was written would go quiet exactly as the table grew.
async fn audit_tables(conn: &mut PgConnection) -> Vec<String> {
    sqlx::query(
        r#"
        SELECT c.relname AS table_name
        FROM pg_catalog.pg_class      c
        JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND (
                c.relname = 'audit_events'
             OR c.oid IN (
                    SELECT i.inhrelid
                    FROM pg_catalog.pg_inherits i
                    WHERE i.inhparent = 'public.audit_events'::regclass
                )
          )
        ORDER BY c.relname
        "#,
    )
    .fetch_all(&mut *conn)
    .await
    .expect("enumerate audit_events and its partitions")
    .iter()
    .map(|r| r.get::<String, _>("table_name"))
    .collect()
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_tenant_scoped_table_is_reachable_by_the_application_role() {
    let (_db, mut conn) = migrated_database().await;

    // A table is only usable if the schema containing it is too. Checked first and separately,
    // because a missing schema USAGE makes every per-table result below a false negative and the
    // report would name twenty tables for one cause.
    let schema_usable: bool =
        sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'USAGE')")
            .bind(APP_ROLE)
            .fetch_one(&mut conn)
            .await
            .expect("check schema usage");
    assert!(
        schema_usable,
        "{APP_ROLE} lacks USAGE on schema public, so no grant below can be exercised. \
         GRANT USAGE ON SCHEMA public TO {APP_ROLE} (migrations/0002_rls_policies.sql §1)."
    );

    // `has_table_privilege` rather than `information_schema.role_table_grants`, because the question
    // is "can this role reach the table", not "is there a row saying so": the former accounts for
    // privileges held through role membership and for grants to PUBLIC, and a gate that missed
    // those would fail on a working database.
    let rows = sqlx::query(
        r#"
        SELECT c.relname                                          AS table_name,
               has_table_privilege($1, c.oid, 'SELECT')           AS may_select,
               has_table_privilege($1, c.oid, 'INSERT')           AS may_insert
        FROM pg_catalog.pg_class      c
        JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute  a ON a.attrelid = c.oid
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')          -- ordinary and partitioned tables
          AND a.attname = 'tenant_id'
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY c.relname
        "#,
    )
    .bind(APP_ROLE)
    .fetch_all(&mut conn)
    .await
    .expect("enumerate tenant-scoped tables and their grants");

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

        let may_select: bool = row.get("may_select");
        let may_insert: bool = row.get("may_insert");

        if may_select {
            println!("  ok      {name} (SELECT{})", if may_insert { ", INSERT" } else { "" });
        } else {
            failures.push(format!("{name}: {APP_ROLE} holds no SELECT"));
        }
    }

    assert!(
        failures.is_empty(),
        "grant coverage gate failed for {} of {checked} tenant-scoped tables:\n  {}\n\n\
         A tenant-scoped table that {APP_ROLE} cannot read is not a safe table — it is a table \
         nothing has ever queried under row-level security. That is precisely the state that let \
         the whole system run as superuser with RLS inert until an end-to-end cross-tenant read \
         returned 200 (ENC-124, migrations/0003_application_role_grants.sql). Grant the \
         application role its DML in the same migration that creates the table.",
        failures.len(),
        failures.join("\n  "),
    );

    println!("\nGrant coverage: {checked} tenant-scoped tables, all reachable by {APP_ROLE}.");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_audit_trail_is_append_only_on_every_partition() {
    let (_db, mut conn) = migrated_database().await;

    let tables = audit_tables(&mut conn).await;
    assert!(
        !tables.is_empty(),
        "audit_events was not found. Either the migrations did not run, or the table was renamed \
         — either way this gate is proving nothing about the audit trail."
    );
    assert!(
        tables.iter().any(|t| t == "audit_events"),
        "the partitions of audit_events were found but audit_events itself was not: {tables:?}"
    );

    let mut failures = Vec::new();

    for table in &tables {
        // Read per table rather than in one grouped query so the report can say "this partition",
        // which is the only actionable form: a partition-creation job that forgets the REVOKE
        // leaves the parent correct and one child wrong.
        let row = sqlx::query(
            r#"
            SELECT has_table_privilege($1, format('public.%I', $2::text)::regclass, 'SELECT')   AS may_select,
                   has_table_privilege($1, format('public.%I', $2::text)::regclass, 'INSERT')   AS may_insert,
                   has_table_privilege($1, format('public.%I', $2::text)::regclass, 'UPDATE')   AS may_update,
                   has_table_privilege($1, format('public.%I', $2::text)::regclass, 'DELETE')   AS may_delete,
                   has_table_privilege($1, format('public.%I', $2::text)::regclass, 'TRUNCATE') AS may_truncate
            "#,
        )
        .bind(APP_ROLE)
        .bind(table)
        .fetch_one(&mut conn)
        .await
        .expect("read audit table privileges");

        let may_select: bool = row.get("may_select");
        let may_insert: bool = row.get("may_insert");

        let mut problems = Vec::new();
        if !may_select {
            problems.push("missing SELECT — the chain verifier cannot read the trail");
        }
        if !may_insert {
            problems.push("missing INSERT — nothing can be audited");
        }
        for (label, held) in [
            ("UPDATE", row.get::<bool, _>("may_update")),
            ("DELETE", row.get::<bool, _>("may_delete")),
            ("TRUNCATE", row.get::<bool, _>("may_truncate")),
        ] {
            if held {
                problems.push(match label {
                    "UPDATE" => {
                        "holds UPDATE — history can be rewritten and the hash chain \
                                 recomputed to match"
                    }
                    "DELETE" => "holds DELETE — a tenant can erase its own audit trail",
                    _ => "holds TRUNCATE — the whole trail can be discarded in one statement",
                });
            }
        }

        if problems.is_empty() {
            println!("  ok      {table} (SELECT, INSERT; no UPDATE/DELETE/TRUNCATE)");
        } else {
            failures.push(format!("{table}: {}", problems.join("; ")));
        }
    }

    assert!(
        failures.is_empty(),
        "the audit trail is not append-only for {APP_ROLE} on {} of {} audit tables:\n  {}\n\n\
         Test U2 (docs/12-TESTING.md §4.9, docs/04-DATA-MODEL.md §14). The hash chain is only worth \
         computing if the rows behind it cannot be rewritten by whoever holds the application \
         credentials. Every audit_events partition — including ones created at runtime by the \
         partition job — needs GRANT SELECT, INSERT and REVOKE UPDATE, DELETE, TRUNCATE, as \
         migrations/0002_rls_policies.sql §4 does for the ones that existed then.",
        failures.len(),
        tables.len(),
        failures.join("\n  "),
    );

    println!("\nAudit grants: {} tables, all append-only for {APP_ROLE}.", tables.len());
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_cannot_opt_out_of_row_level_security() {
    let (_db, mut conn) = migrated_database().await;

    let row = sqlx::query(
        r#"
        SELECT rolsuper     AS is_superuser,
               rolbypassrls AS bypasses_rls
        FROM pg_catalog.pg_roles
        WHERE rolname = $1
        "#,
    )
    .bind(APP_ROLE)
    .fetch_optional(&mut conn)
    .await
    .expect("read the application role's attributes");

    let row = row.unwrap_or_else(|| {
        panic!(
            "the role {APP_ROLE} does not exist. Migration 0001 creates it; if it is absent, the \
             application is connecting as something else and nothing in this file is being tested."
        )
    });

    let is_superuser: bool = row.get("is_superuser");
    let bypasses_rls: bool = row.get("bypasses_rls");

    // Deliberately two assertions with two messages. The remedies differ (ALTER ROLE ... NOSUPERUSER
    // versus NOBYPASSRLS) and, more importantly, so do the blast radii: a superuser application role
    // is a far larger finding than one extra role attribute.
    assert!(
        !is_superuser,
        "{APP_ROLE} is a SUPERUSER. Superusers bypass row-level security entirely, so every \
         tenant_isolation policy in the schema is decorative and every isolation test in the \
         workspace is passing vacuously — which is exactly what happened in ENC-124. \
         ALTER ROLE {APP_ROLE} NOSUPERUSER."
    );
    assert!(
        !bypasses_rls,
        "{APP_ROLE} holds BYPASSRLS. Row-level security is not applied to it, so tenant isolation \
         is off for the application while every structural gate stays green. Only \
         enclave_platform may hold BYPASSRLS, and only for the three code paths named in \
         migrations/0002_rls_policies.sql §5. ALTER ROLE {APP_ROLE} NOBYPASSRLS."
    );

    // The counter-example, asserted rather than assumed: if enclave_platform had lost BYPASSRLS the
    // checks above would still pass while the outbox publisher silently stopped seeing rows, and it
    // would prove that this query is reading the attribute it thinks it is.
    let platform_bypasses: Option<bool> =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = $1")
            .bind("enclave_platform")
            .fetch_optional(&mut conn)
            .await
            .expect("read enclave_platform's attributes");
    assert_eq!(
        platform_bypasses,
        Some(true),
        "enclave_platform must exist and hold BYPASSRLS (migrations/0002_rls_policies.sql §5). \
         If this fails alongside the assertions above passing, read rolbypassrls as unreliable \
         rather than the roles as correct."
    );

    println!("{APP_ROLE}: NOSUPERUSER, NOBYPASSRLS. enclave_platform: BYPASSRLS, as intended.");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_can_set_the_tenant_parameter() {
    let (_db, mut conn) = migrated_database().await;

    // Half one: the catalog grant. `GRANT SET ON PARAMETER app.tenant_id TO enclave_app` is what
    // migration 0003 added; if a later migration revokes it, this is where that shows up.
    let may_set: bool =
        sqlx::query_scalar("SELECT has_parameter_privilege($1, 'app.tenant_id', 'SET')")
            .bind(APP_ROLE)
            .fetch_one(&mut conn)
            .await
            .expect("check the app.tenant_id parameter privilege");
    assert!(
        may_set,
        "{APP_ROLE} may not SET app.tenant_id. The tenant_isolation policies read that parameter \
         with current_setting() in its strict form, so without it every tenant-scoped query fails \
         — and the failure looks like an empty database rather than a missing grant, which is the \
         hardest possible shape to diagnose. \
         GRANT SET ON PARAMETER app.tenant_id TO {APP_ROLE} \
         (migrations/0003_application_role_grants.sql)."
    );

    // Half two: actually do it. The catalog says what is permitted; only the round trip proves the
    // parameter is settable *and readable back* by that role, which is the property TenantScoped
    // depends on. SET ROLE drops the connecting role's superuser status for permission checks, so
    // this is a real test even though DATABASE_URL points at the cluster owner.
    let tenant = "00000000-0000-0000-0000-0000000000aa";

    // `set_config('role', …)` rather than `SET ROLE …`: sqlx 0.9 only accepts `&'static str` SQL, and
    // interpolating a role name into a statement is the shape this repository does not write even
    // when the value is a constant.
    sqlx::query("SELECT set_config('role', $1, false)")
        .bind(APP_ROLE)
        .execute(&mut conn)
        .await
        .unwrap_or_else(|e| panic!("SET ROLE {APP_ROLE} failed: {e}"));

    let set_result = sqlx::query("SELECT set_config('app.tenant_id', $1, false)")
        .bind(tenant)
        .execute(&mut conn)
        .await;

    let read_back: Result<String, _> = if set_result.is_ok() {
        sqlx::query_scalar("SELECT current_setting('app.tenant_id', false)")
            .fetch_one(&mut conn)
            .await
    } else {
        Err(sqlx::Error::RowNotFound)
    };

    // Reset before asserting, so a failure does not leave the connection wedged for whatever the
    // test harness reuses it for.
    if let Err(e) = sqlx::query("SELECT set_config('role', 'none', false)").execute(&mut conn).await
    {
        println!("warning: could not reset the session role: {e}");
    }

    let set_err = set_result.err();
    assert!(
        set_err.is_none(),
        "as {APP_ROLE}, setting app.tenant_id failed: {}. TenantScoped issues this on every \
         transaction; if the role cannot, no tenant-scoped query can run at all.",
        set_err.map_or_else(String::new, |e| e.to_string()),
    );
    assert_eq!(
        read_back.as_deref().ok(),
        Some(tenant),
        "as {APP_ROLE}, app.tenant_id did not read back as the value just written. The policies \
         compare tenant_id against exactly this setting, so a value that does not survive the \
         round trip isolates nothing."
    );

    println!("{APP_ROLE} can SET and read back app.tenant_id.");
}

/// The two privileges a session refresh and a logout need, proved by *running the statements*.
///
/// `ENC-705`. `RefreshTokenStore::find_by_hash` and `revoke_returning` are the only callers of
/// `DbPool::platform_connection` in `crates/db/src/auth_tokens.rs`, and they take it because a
/// refresh token arrives as an opaque string with no tenant beside it: scoping the lookup would
/// mean accepting a tenant from the caller, one layer from a request body (`CLAUDE.md` rule 3).
///
/// `0002_rls_policies.sql` granted `enclave_platform` nothing on `refresh_tokens`, so in a
/// deployment that really separates the roles both statements failed with `permission denied` —
/// sign-in worked and **staying** signed in did not. `0025` grants the two privileges.
///
/// # Why this runs the statements instead of reading `information_schema`
///
/// A catalogue query asserts that a grant exists. It does not assert that the statement the code
/// actually issues is permitted by it, and those are different claims — a grant on the wrong
/// object, or the right object under a search path that resolves elsewhere, satisfies the first
/// and not the second. More to the point, the reason this defect survived is that **the harness
/// connects as the cluster superuser**, which bypasses grants entirely: any assertion made on this
/// connection without `SET ROLE` passes whether or not the migration ran. `SET ROLE` is what makes
/// the assertion mean anything here.
///
/// Ignored by default because it needs a live PostgreSQL. CI runs it with `--include-ignored`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_platform_role_can_read_and_revoke_refresh_tokens() {
    let (_db, mut conn) = migrated_database().await;

    // A literal rather than `format!`: the workspace refuses dynamic SQL strings, and it is right
    // to — the role name is a constant, so nothing is gained by building it at run time.
    sqlx::query("SET ROLE enclave_platform")
        .execute(&mut conn)
        .await
        .unwrap_or_else(|e| panic!("could not assume {PLATFORM_ROLE}: {e}"));

    // The shapes the two statements have, not the statements themselves: what is under test is the
    // privilege, and binding a real token hash would test the schema instead. `WHERE false` keeps
    // the UPDATE from touching a row while still requiring UPDATE to be permitted — PostgreSQL
    // checks privilege before it evaluates the predicate.
    let select = sqlx::query("SELECT id, tenant_id, token_hash FROM refresh_tokens WHERE false")
        .fetch_all(&mut conn)
        .await;
    let update = sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE false")
        .execute(&mut conn)
        .await;

    // Reset before asserting, so a failure does not leave the connection wedged for the harness.
    if let Err(e) = sqlx::query("RESET ROLE").execute(&mut conn).await {
        println!("warning: could not reset the session role: {e}");
    }

    assert!(
        select.is_ok(),
        "as {PLATFORM_ROLE}, SELECT on refresh_tokens failed: {}.          `RefreshTokenStore::find_by_hash` issues this on every refresh, so no session can be          renewed and every user is signed out when their access token expires (ENC-705).",
        select.err().map_or_else(String::new, |e| e.to_string()),
    );
    assert!(
        update.is_ok(),
        "as {PLATFORM_ROLE}, UPDATE on refresh_tokens failed: {}.          `revoke_returning` issues this for both `revoke_family` and `revoke_all_for_subject`, so          logout fails and a stolen token cannot be revoked (ENC-705).",
        update.err().map_or_else(String::new, |e| e.to_string()),
    );

    println!("{PLATFORM_ROLE} can SELECT and UPDATE refresh_tokens.");
}

/// The negative control: the privilege is granted, not inherited from being a superuser.
///
/// `docs/12-TESTING.md §1.2` — the assertion above is that two statements *succeed*, which succeeds
/// for free on a connection that bypasses grants, and this whole defect existed because that is
/// exactly the connection the harness uses. So this asserts that the same role is refused something
/// it was deliberately **not** granted. If this passes while the test above passes, `SET ROLE` is
/// doing real work and the grant is doing the rest.
///
/// `DELETE` is the probe because `0025` names its absence and gives the reason: `insert` and
/// `rotate` carry their own `tenant_id` and go through `DbPool::begin`, so the platform role — which
/// holds `BYPASSRLS` and therefore sees every tenant — has no business destroying these rows.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_platform_role_is_refused_what_it_was_not_granted() {
    let (_db, mut conn) = migrated_database().await;

    // A literal rather than `format!`: the workspace refuses dynamic SQL strings, and it is right
    // to — the role name is a constant, so nothing is gained by building it at run time.
    sqlx::query("SET ROLE enclave_platform")
        .execute(&mut conn)
        .await
        .unwrap_or_else(|e| panic!("could not assume {PLATFORM_ROLE}: {e}"));

    let deleted = sqlx::query("DELETE FROM refresh_tokens WHERE false").execute(&mut conn).await;

    if let Err(e) = sqlx::query("RESET ROLE").execute(&mut conn).await {
        println!("warning: could not reset the session role: {e}");
    }

    let error = deleted.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        error.contains("permission denied"),
        "as {PLATFORM_ROLE}, DELETE on refresh_tokens was permitted (or failed for another \
         reason: {error:?}). Either 0025 granted more than it says, or this connection is not \
         really running as that role — and if it is not, the test above proves nothing either, \
         because the harness connects as the cluster superuser."
    );

    println!("{PLATFORM_ROLE} is refused DELETE on refresh_tokens, so the grant above is real.");
}
