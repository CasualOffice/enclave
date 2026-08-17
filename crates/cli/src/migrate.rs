//! `enclave-cli migrate` — apply outstanding migrations and say which ones ran.
//!
//! The reporting is the reason this exists rather than `sqlx migrate run`: the interesting output
//! is the *difference* between what the database had applied before and after, and a runner that
//! prints "migrations applied" leaves an operator unable to tell a no-op deployment from one that
//! just rewrote the schema.
//!
//! Migrations are DDL and run as the schema owner (`crates/db/src/migrate.rs`). This command
//! therefore expects an owner credential, and says so when the server refuses.

use anyhow::Context as _;

use crate::connect::Target;
use crate::schema::{ahead_of_binary, applied_migrations, pending};

/// Applies every outstanding migration.
///
/// # Errors
///
/// Connection failures, and any failure inside the migration runner.
pub(crate) async fn run(target: &Target) -> anyhow::Result<()> {
    println!("enclave-cli migrate");
    println!("  target: {}", target.summary());
    println!("  from:   {}", target.origin());
    println!();

    let mut conn = target.connect().await?;

    let before = applied_migrations(&mut conn).await?;
    let outstanding = pending(&before);

    for version in ahead_of_binary(&before) {
        // Not an error: the operator may be mid-rollback and know exactly why. It is printed
        // loudly because the alternative is a silent "nothing to do" on a database that is not the
        // schema this binary was built against.
        println!(
            "  note: the database has migration {version:04}, which this binary does not carry"
        );
    }

    if outstanding.is_empty() {
        println!("  nothing to apply — {} migration(s) already applied", before.len());
        report_failures(&before)?;
        return Ok(());
    }

    println!("  will apply {} migration(s):", outstanding.len());
    for version in &outstanding {
        println!("    {version:04}");
    }
    println!();

    enclave_db::run_migrations_on(&mut conn).await.with_context(|| {
        format!(
            "migrations failed against {}.\n  migrations run as the schema owner \
             (enclave_migrator); a permission error here usually means {} holds application \
             credentials instead",
            target.summary(),
            target.origin()
        )
    })?;

    let after = applied_migrations(&mut conn).await?;
    let newly: Vec<_> =
        after.iter().filter(|row| !before.iter().any(|had| had.version == row.version)).collect();

    println!("  applied:");
    for row in &newly {
        println!("    {}", row.label());
    }
    println!();
    println!("  schema is at version {}", after.last().map_or(0, |row| row.version));

    report_failures(&after)
}

/// Turns a half-applied migration into a non-zero exit.
///
/// `sqlx` records a failed apply with `success = false` and refuses to continue past it on the next
/// run. Reporting it as success because this invocation did not itself fail would leave the
/// database in a state where the next deployment fails for reasons nobody connected to this one.
fn report_failures(applied: &[crate::schema::AppliedMigration]) -> anyhow::Result<()> {
    let failed: Vec<_> = applied.iter().filter(|row| !row.success).map(|row| row.label()).collect();
    if failed.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "the database records {} migration(s) that did not complete: {}.\n  \
         resolve the partially-applied migration by hand; a forward-only schema has no automatic \
         way back (docs/11-OPERATIONS.md §8)",
        failed.len(),
        failed.join(", ")
    )
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use crate::schema::AppliedMigration;

    use super::*;

    fn row(version: i64, success: bool) -> AppliedMigration {
        AppliedMigration { version, description: "foundations".to_owned(), success }
    }

    #[test]
    fn a_clean_migration_history_reports_nothing() {
        report_failures(&[row(1, true), row(2, true)]).expect("all successful");
    }

    #[test]
    fn a_half_applied_migration_fails_the_command() {
        // Exit code matters here: this runs in CI and in deployment scripts, where "printed a
        // warning" and "succeeded" are the same thing.
        let err = report_failures(&[row(1, true), row(2, false)]).expect_err("must fail");
        let message = format!("{err}");
        assert!(message.contains("0002 foundations"), "{message}");
    }
}
