//! ENC-117 — proves the cluster-wide role race produces a *legible* failure.
//!
//! The race itself is an accepted risk (`ENC-116`): provisioning the roles before migrations run
//! makes migration 0001's guard a no-op. What was not acceptable is the failure being
//! unintelligible when someone skips that step — PostgreSQL reports SQLSTATE 23505 against
//! `pg_authid_rolname_index`, which says nothing about roles, provisioning, or what to do.
//!
//! This reproduces the race deliberately — many databases, migrated concurrently, roles dropped
//! first — and asserts that whatever comes back is `RolesNotProvisioned` and never a raw
//! `Migrate`. It lives here rather than in `enclave-db` because reproducing it needs the harness,
//! and `enclave-testing` depends on `enclave-db` rather than the other way around.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_db::{run_migrations_on, DbError};
use sqlx::{Connection, Executor, PgConnection};
use uuid::Uuid;

fn admin_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|u| !u.trim().is_empty())
}

fn swap_db(url: &str, name: &str) -> String {
    let slash = url.rfind('/').expect("a database component");
    let (head, tail) = url.split_at(slash + 1);
    match tail.find('?') {
        Some(q) => format!("{head}{name}{}", &tail[q..]),
        None => format!("{head}{name}"),
    }
}

/// Connects, migrates, closes. A named function so the `&mut conn` borrow stays inside one
/// concrete lifetime — inlined into `tokio::spawn` the compiler cannot prove sqlx's `Acquire`
/// impl is general enough.
async fn migrate_one(url: String) -> Result<(), DbError> {
    let mut conn = PgConnection::connect(&url).await.expect("connect");
    let result = run_migrations_on(&mut conn).await;
    let _ignored = conn.close().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_lost_role_creation_race_reports_what_to_do_about_it() {
    let Some(admin_url) = admin_url() else { panic!("DATABASE_URL must be set") };

    // Deliberately NOT using TestDb: its advisory lock exists precisely to prevent this race, and
    // the point here is to cause it.
    const RACERS: usize = 6;
    let mut observed_race = false;

    for attempt in 0..5 {
        let mut admin = PgConnection::connect(&admin_url).await.expect("admin");

        // Clear leftovers from an earlier run first. DROP ROLE fails while the role still owns
        // objects, so a database abandoned by a panicking attempt keeps the roles alive — and the
        // test would then report "the race never fired" when the truth is that its precondition
        // was never met. Assert the precondition instead of inferring it from the outcome.
        let leftovers: Vec<String> = sqlx::query_scalar(
            "SELECT datname FROM pg_database WHERE datname LIKE 'enc\\_race\\_%'",
        )
        .fetch_all(&mut admin)
        .await
        .expect("list leftovers");
        for name in leftovers {
            let _ignored = admin
                .execute(
                    format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
                    )
                    .as_str(),
                )
                .await;
            let _ignored =
                admin.execute(format!(r#"DROP DATABASE IF EXISTS "{name}""#).as_str()).await;
        }

        for role in ["enclave_app", "enclave_migrator", "enclave_platform"] {
            let _ignored = admin.execute(format!("DROP ROLE IF EXISTS {role}").as_str()).await;
        }

        let still_there: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_roles WHERE rolname IN              ('enclave_app','enclave_migrator','enclave_platform')",
        )
        .fetch_one(&mut admin)
        .await
        .expect("count roles");
        assert_eq!(
            still_there, 0,
            "could not drop the roles, so the race cannot be reproduced and this test would              otherwise report a false negative. Usually a database from an earlier run still              depends on them: \\l in psql, drop anything named enc_race_*, and retry."
        );

        let mut names = Vec::new();
        for i in 0..RACERS {
            let name = format!("enc_race_{}_{i}", &Uuid::new_v4().simple().to_string()[..8]);
            admin.execute(format!(r#"CREATE DATABASE "{name}""#).as_str()).await.expect("create");
            names.push(name);
        }
        let _ignored = admin.close().await;

        // OS threads with their own runtimes rather than tokio::spawn: sqlx's `Acquire` impl is
        // not general enough to cross a spawn boundary, and a barrier releases every migration at
        // once, which is what makes the race actually fire rather than theoretically exist.
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(RACERS));
        let handles: Vec<_> = names
            .iter()
            .map(|name| {
                let url = swap_db(&admin_url, name);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime");
                    barrier.wait();
                    runtime.block_on(migrate_one(url))
                })
            })
            .collect();

        for handle in handles {
            match handle.join().expect("join") {
                Ok(()) => {}
                Err(DbError::RolesNotProvisioned { .. }) => observed_race = true,
                Err(other) => panic!(
                    "attempt {attempt}: the race produced an unreadable error instead of \
                     RolesNotProvisioned: {other:?}"
                ),
            }
        }

        // Clean up whether or not the race fired.
        let mut admin = PgConnection::connect(&admin_url).await.expect("admin");
        for name in &names {
            let _ignored = admin
                .execute(
                    format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
                    )
                    .as_str(),
                )
                .await;
            let _ignored =
                admin.execute(format!(r#"DROP DATABASE IF EXISTS "{name}""#).as_str()).await;
        }
        let _ignored = admin.close().await;

        if observed_race {
            break;
        }
    }

    assert!(
        observed_race,
        "the race never fired in 5 attempts of {RACERS} concurrent migrations, so this test \
         proved nothing. Either PostgreSQL began serialising CREATE ROLE, or the setup stopped \
         reproducing it — investigate rather than deleting the test."
    );
}
