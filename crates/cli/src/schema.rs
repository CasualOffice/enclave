//! Read-only questions about the state of a database.
//!
//! Shared by `migrate`, `doctor` and `seed`'s pre-flight. Everything here is a `SELECT`: the three
//! callers have very different rights to write, and a helper that occasionally wrote something
//! would make `doctor` — the command someone runs on a database they are worried about — a command
//! that changes it.

use anyhow::Context as _;
use sqlx::{PgConnection, Row as _};

/// One row of `_sqlx_migrations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedMigration {
    /// The numeric version, from the file name.
    pub(crate) version: i64,
    /// The description, from the file name.
    pub(crate) description: String,
    /// Whether the apply completed. A `false` row is a database left half-migrated.
    pub(crate) success: bool,
}

impl AppliedMigration {
    /// `0002 rls policies`, the form used in every command's output.
    pub(crate) fn label(&self) -> String {
        format!("{:04} {}", self.version, self.description)
    }
}

/// Whether a table exists in the `public` schema.
///
/// `to_regclass` returns `NULL` rather than raising for an unknown name, which is what makes it
/// usable on a database that has never been migrated — the case every one of these helpers has to
/// survive, since "nothing is set up" is the most likely reason someone is running `doctor`.
pub(crate) async fn table_exists(conn: &mut PgConnection, table: &str) -> anyhow::Result<bool> {
    let qualified = format!("public.{table}");
    let row = sqlx::query("SELECT to_regclass($1) IS NOT NULL")
        .bind(&qualified)
        .fetch_one(&mut *conn)
        .await
        .with_context(|| format!("could not check whether {qualified} exists"))?;
    row.try_get::<bool, _>(0).context("unexpected result checking for a table")
}

/// Every migration `sqlx` has recorded, oldest first.
///
/// An unmigrated database answers with an empty list rather than an error: there is a real
/// difference between "no migrations have been applied" and "the database is unreachable", and
/// collapsing them would make `doctor` report the wrong problem.
pub(crate) async fn applied_migrations(
    conn: &mut PgConnection,
) -> anyhow::Result<Vec<AppliedMigration>> {
    if !table_exists(&mut *conn, "_sqlx_migrations").await? {
        return Ok(Vec::new());
    }

    let rows =
        sqlx::query("SELECT version, description, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&mut *conn)
            .await
            .context("could not read the applied migrations from _sqlx_migrations")?;

    rows.into_iter()
        .map(|row| {
            Ok(AppliedMigration {
                version: row.try_get("version")?,
                description: row.try_get("description")?,
                success: row.try_get("success")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .context("_sqlx_migrations does not have the columns this version of sqlx writes")
}

/// The versions this binary carries, from the compile-time embed in `enclave-db`.
///
/// Compared against the applied set rather than trusted: the interesting failure is a binary that
/// is *older* than the database, and only the difference between the two lists shows it.
pub(crate) fn embedded_versions() -> Vec<i64> {
    enclave_db::MIGRATIONS.iter().map(|migration| migration.version).collect()
}

/// Versions this binary carries that the database has not applied.
pub(crate) fn pending(applied: &[AppliedMigration]) -> Vec<i64> {
    let embedded = embedded_versions();
    embedded
        .into_iter()
        .filter(|version| !applied.iter().any(|row| row.version == *version))
        .collect()
}

/// Versions the database has applied that this binary does not carry.
///
/// A non-empty answer means the binary is behind the schema — a rollback that went one release too
/// far, or a deploy of the wrong image. It is reported rather than treated as an error, because the
/// operator is the one who knows which of the two it is.
pub(crate) fn ahead_of_binary(applied: &[AppliedMigration]) -> Vec<i64> {
    let embedded = embedded_versions();
    applied.iter().map(|row| row.version).filter(|version| !embedded.contains(version)).collect()
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn applied(version: i64) -> AppliedMigration {
        AppliedMigration { version, description: "test".to_owned(), success: true }
    }

    #[test]
    fn an_empty_database_has_every_embedded_migration_pending() {
        let pending = pending(&[]);
        assert_eq!(pending, embedded_versions());
        assert!(!pending.is_empty(), "the binary should carry migrations at all");
    }

    #[test]
    fn a_fully_migrated_database_has_nothing_pending() {
        let rows: Vec<_> = embedded_versions().into_iter().map(applied).collect();
        assert!(pending(&rows).is_empty());
        assert!(ahead_of_binary(&rows).is_empty());
    }

    #[test]
    fn a_database_migrated_past_this_binary_is_reported_rather_than_ignored() {
        // The shape of a bad rollback: the schema has something the binary has never heard of.
        let mut rows: Vec<_> = embedded_versions().into_iter().map(applied).collect();
        rows.push(applied(9999));
        assert_eq!(ahead_of_binary(&rows), vec![9999]);
        assert!(pending(&rows).is_empty());
    }

    #[test]
    fn a_gap_in_the_middle_is_still_pending() {
        // sqlx applies by version, so an out-of-order apply leaves a hole rather than an error;
        // reporting only "the highest version" would hide it.
        let versions = embedded_versions();
        let Some((_, rest)) = versions.split_first() else { panic!("no migrations embedded") };
        let rows: Vec<_> = rest.iter().copied().map(applied).collect();
        assert_eq!(pending(&rows), vec![versions[0]]);
    }

    #[test]
    fn labels_are_zero_padded_so_they_sort_the_way_the_files_do() {
        let row =
            AppliedMigration { version: 2, description: "rls policies".to_owned(), success: true };
        assert_eq!(row.label(), "0002 rls policies");
    }
}
