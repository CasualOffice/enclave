//! Every foreign key between two tenant-scoped tables carries `tenant_id` in the constraint.
//!
//! `CLAUDE.md` rule 4, `docs/04-DATA-MODEL.md §3.3`, `docs/12-TESTING.md §5`.
//!
//! # Why this gate existed as a name before it existed as a test
//!
//! `ENC-543`. `.github/workflows/structural-gates.yml` has guarded this rule since the gates were
//! written, but the assertion was conditional on *this file existing*: absent, the job printed
//! `GATE PENDING … NOT ENFORCED YET` and exited zero. The job is named
//! `RULE: every FK between tenant-scoped tables includes tenant_id`, so in a pull request's checks
//! list it read **pass**, in green, having never looked at a foreign key.
//!
//! It stayed that way for a milestone, and `ENC-502` is what it cost: `library_views.list_id` had
//! no foreign key at all, recorded honestly as a comment *in the migration* — the only place it
//! could be recorded, because nothing enumerated keys. The RLS and grant gates enumerate
//! tenant-scoped **tables**; until now nothing enumerated their **keys**.
//!
//! # What the rule protects, and why RLS does not
//!
//! A row referencing a parent in another tenant is two individually well-formed rows. Row-level
//! security does not catch it, and the reason is specific rather than incidental: **PostgreSQL runs
//! referential-integrity checks with row security deliberately not enforced**, so the key's own
//! lookup sees every tenant's rows. A single-column `REFERENCES files (id)` therefore happily
//! accepts another tenant's file.
//!
//! Putting `tenant_id` *in the key* is what closes it: `(tenant_id, file_id)` cannot match a parent
//! whose `tenant_id` differs, because the tuple does not match. The composite key is the control —
//! not a redundancy on top of one.
//!
//! # Scope, stated so the gate is not read as proving more than it does
//!
//! This asserts the key's **shape**, not any query's behaviour. It says nothing about whether a
//! given handler scopes its reads; that is the policy chain's job and `no_raw_pool.py`'s. What it
//! does guarantee is that the database cannot be *asked* to hold a cross-tenant reference through a
//! declared key.
//!
//! Ignored by default because it needs a live PostgreSQL. CI runs it with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_testing::TestDb;
use sqlx::{PgConnection, Row};

/// Foreign keys between two tenant-scoped tables that legitimately omit `tenant_id`.
///
/// Empty, deliberately — the same reasoning as `rls_coverage.rs`'s exemption list. It exists so the
/// *shape* of an exemption is defined in advance (a constraint name and a reason) rather than
/// invented under pressure, and so that adding one is a reviewable act.
///
/// Before adding an entry, note what an exemption means here: that the database will accept a row
/// pointing at another tenant's row, and that something else is expected to prevent it. That
/// "something else" has to be named.
const EXEMPT: &[(&str, &str)] = &[];

/// Every foreign key whose source *and* target both carry a `tenant_id` column.
///
/// The `EXISTS` pair is the whole selection rule: a key from a tenant-scoped table to a
/// platform-wide one (`storage_profiles`, say) is not in scope, because there is no tenant on the
/// far side to disagree with. `conkey`/`confkey` are resolved to column names with ordinality so
/// the report can print the key as written.
const KEYS_SQL: &str = r#"
SELECT con.conname                                       AS constraint_name,
       src.relname                                       AS source_table,
       tgt.relname                                       AS target_table,
       (SELECT array_agg(a.attname ORDER BY k.ord)
          FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_catalog.pg_attribute a
            ON a.attrelid = con.conrelid AND a.attnum = k.attnum)   AS source_columns,
       (SELECT array_agg(a.attname ORDER BY k.ord)
          FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_catalog.pg_attribute a
            ON a.attrelid = con.confrelid AND a.attnum = k.attnum)  AS target_columns
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class     src ON src.oid = con.conrelid
JOIN pg_catalog.pg_class     tgt ON tgt.oid = con.confrelid
JOIN pg_catalog.pg_namespace n   ON n.oid   = src.relnamespace
WHERE con.contype = 'f'
  AND n.nspname = 'public'
  AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
               WHERE a.attrelid = src.oid AND a.attname = 'tenant_id'
                 AND a.attnum > 0 AND NOT a.attisdropped)
  AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
               WHERE a.attrelid = tgt.oid AND a.attname = 'tenant_id'
                 AND a.attnum > 0 AND NOT a.attisdropped)
ORDER BY src.relname, con.conname
"#;

/// A freshly created, freshly migrated database, and a connection to it.
///
/// The handle is returned rather than dropped because dropping it drops the database. It creates
/// its own throwaway rather than migrating whatever `DATABASE_URL` names — `ENC-504`.
async fn migrated_database() -> (TestDb, PgConnection) {
    let db = TestDb::start().await.expect(
        "the composite-FK gate needs a PostgreSQL it may create databases on; CI provides a \
         service container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let conn = db.connect().await.expect("connect to the throwaway database");
    (db, conn)
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_foreign_key_between_tenant_scoped_tables_carries_tenant_id() {
    let (_db, mut conn) = migrated_database().await;

    let rows = sqlx::query(KEYS_SQL)
        .fetch_all(&mut conn)
        .await
        .expect("enumerate foreign keys between tenant-scoped tables");

    // The gate's own liveness check, and it is not ceremony: this file's whole history is a gate
    // that reported success while inspecting nothing. A query that stopped matching the catalog
    // would do exactly that again, silently, and the checks list would still say `pass`.
    assert!(
        !rows.is_empty(),
        "no foreign key between two tenant-scoped tables was found. Either the migrations did not \
         run, or the catalog query stopped matching the schema. Both mean this gate is proving \
         nothing — which is the state ENC-543 exists to end, not to repeat."
    );

    let mut failures = Vec::new();
    let mut checked = 0_usize;

    for row in &rows {
        let name: String = row.get("constraint_name");
        let source: String = row.get("source_table");
        let target: String = row.get("target_table");
        let source_columns: Vec<String> = row.get("source_columns");
        let target_columns: Vec<String> = row.get("target_columns");

        if let Some((_, reason)) = EXEMPT.iter().find(|(c, _)| *c == name) {
            println!("  exempt  {name} — {reason}");
            continue;
        }
        checked += 1;

        let carries_source = source_columns.iter().any(|c| c == "tenant_id");
        let carries_target = target_columns.iter().any(|c| c == "tenant_id");

        // Both sides, not either. A key listing `tenant_id` only on the referencing side still
        // matches a parent row by the remaining columns alone, so the tenant is never compared.
        if carries_source && carries_target {
            println!("  ok      {source}({}) -> {target}({})", source_columns.join(", "), target_columns.join(", "));
        } else {
            let side = match (carries_source, carries_target) {
                (false, false) => "both sides",
                (true, false) => "the referenced side",
                (false, true) => "the referencing side",
                (true, true) => unreachable!("handled above"),
            };
            failures.push(format!(
                "{name}: {source}({}) -> {target}({}) — tenant_id is missing from {side}",
                source_columns.join(", "),
                target_columns.join(", "),
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "composite-FK gate failed for {} of {checked} foreign keys between tenant-scoped \
         tables:\n  {}\n\n\
         A row referencing a parent in another tenant is two individually well-formed rows, and \
         row-level security does not catch it: PostgreSQL runs referential-integrity checks with \
         row security deliberately not enforced, so the key's lookup sees every tenant's rows. \
         Putting tenant_id in the key is the control — `FOREIGN KEY (tenant_id, x) REFERENCES \
         t (tenant_id, x)` — and it needs a matching UNIQUE (tenant_id, id) on the parent \
         (docs/04-DATA-MODEL.md §3.3, CLAUDE.md rule 4).",
        failures.len(),
        failures.join("\n  "),
    );

    println!(
        "\nComposite-FK coverage: {checked} foreign keys between tenant-scoped tables, all \
         carrying tenant_id on both sides."
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_single_column_key_between_tenant_scoped_tables_is_actually_rejected() {
    // The gate above asserts an absence — no key omits tenant_id — and `docs/12 §1.2` records that
    // an assertion about an absence passes for free. Against a schema that is already correct, it
    // would pass just as happily if the query returned nothing useful, if `carries_source` were
    // inverted, or if the loop never ran.
    //
    // So this builds the violation the gate exists to catch, in the throwaway database, and
    // requires the *same* query and comparison to name it. It is the positive control.
    let (_db, mut conn) = migrated_database().await;

    sqlx::query(
        "CREATE TABLE gate_probe_parent (
             tenant_id UUID NOT NULL,
             id        UUID NOT NULL,
             PRIMARY KEY (tenant_id, id),
             UNIQUE (id)
         )",
    )
    .execute(&mut conn)
    .await
    .expect("create the probe parent");

    // Single-column key: exactly the shape rule 4 forbids, and exactly the shape that accepts
    // another tenant's row.
    sqlx::query(
        "CREATE TABLE gate_probe_child (
             tenant_id UUID NOT NULL,
             id        UUID NOT NULL PRIMARY KEY,
             parent_id UUID NOT NULL REFERENCES gate_probe_parent (id)
         )",
    )
    .execute(&mut conn)
    .await
    .expect("create the probe child");

    let rows = sqlx::query(KEYS_SQL).fetch_all(&mut conn).await.expect("enumerate foreign keys");

    let probe = rows
        .iter()
        .find(|row| row.get::<String, _>("source_table") == "gate_probe_child")
        .expect("the probe key is between two tenant-scoped tables and must be enumerated");

    let source_columns: Vec<String> = probe.get("source_columns");
    let target_columns: Vec<String> = probe.get("target_columns");

    assert!(
        !source_columns.iter().any(|c| c == "tenant_id")
            || !target_columns.iter().any(|c| c == "tenant_id"),
        "the probe key was built without tenant_id and the check above did not notice: \
         source={source_columns:?} target={target_columns:?}. The gate's comparison is what is \
         broken, not the schema."
    );
}
