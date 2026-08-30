//! Turning stored rows back into [`FileVersion`].
//!
//! Kept in one place rather than inline in each query, so that the column names a statement selects
//! and the column names a decoder reads sit next to each other. The failure mode this guards
//! against is quiet: a `SELECT` that stops listing a column and a decoder that still asks for it
//! produce a runtime `ColumnNotFound` on a path that may only run in production.
//!
//! Every failure is [`VersionsError::MalformedRow`] naming the column and a fixed reason — never
//! the value. An unparseable `status` is schema/code drift, and echoing the offending content into
//! a log is how content travels out of the database (`CLAUDE.md` rule 10).

use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{Result, VersionsError};
use crate::model::{
    ApprovalState, AvScan, AvStatus, FileVersion, StorageTier, VersionNumber, VersionStatus,
};

/// The `file_versions` columns every statement in this crate selects or returns.
///
/// A macro rather than a `const`, and that is not decoration: `concat!` accepts only literals, so a
/// `const` could not be spliced into a compile-time SQL string and every query would spell the list
/// out again. Four hand-written copies of twenty-one column names is four places for a `SELECT` and
/// this decoder to drift, and the drift shows up as a runtime `ColumnNotFound` on whichever path
/// runs least often. A macro expands to the literal, so there is one list and the queries are still
/// constants.
macro_rules! version_columns {
    () => {
        "id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256, \
         mime_type, major, minor, status, av_status, av_engine, av_signature_version, \
         av_scanned_at, approval_state, encryption_mode, encryption_key_ref, created_by, \
         created_at, comment, storage_tier, restore_requested_at"
    };
}

pub(crate) use version_columns;

/// The same list as a value, for the assertions that count and inspect it.
///
/// Test-only: the queries splice the macro, so a runtime copy would be a second definition with
/// nothing but a test reading it.
#[cfg(test)]
pub(crate) const VERSION_COLUMNS: &str = version_columns!();

/// Rebuilds a [`FileVersion`].
///
/// # Errors
///
/// [`VersionsError::MalformedRow`] when a column is absent or holds a value outside its `CHECK`
/// constraint's vocabulary.
pub(crate) fn version_from_row(row: &PgRow) -> Result<FileVersion> {
    Ok(FileVersion {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        file_id: row.try_get_id("file_id")?,
        object_key: row.try_get("object_key")?,
        storage_profile_id: row.try_get("storage_profile_id")?,
        size_bytes: row.try_get("size_bytes")?,
        checksum_sha256: row.try_get("checksum_sha256")?,
        mime_type: row.try_get("mime_type")?,
        number: VersionNumber::new(row.try_get("major")?, row.try_get("minor")?),
        status: parse_enum::<VersionStatus>(row, "status", "not a known version status")?,
        av: AvScan {
            status: parse_enum::<AvStatus>(row, "av_status", "not a known antivirus status")?,
            engine: row.try_get("av_engine")?,
            signature_version: row.try_get("av_signature_version")?,
            scanned_at: row.try_get("av_scanned_at")?,
        },
        approval_state: parse_optional_enum::<ApprovalState>(
            row,
            "approval_state",
            "not a known approval state",
        )?,
        encryption_mode: row.try_get("encryption_mode")?,
        // A stored tier this build cannot read is a refusal, never a default (`ENC-946`). `Hot`
        // would mint a signed URL for bytes that may be in Glacier; `Archived` would take readable
        // content offline. Neither is a guess worth making, and `parse_enum` refuses for the same
        // reason `status` above does.
        storage_tier: parse_enum::<StorageTier>(row, "storage_tier", "not a known storage tier")?,
        restore_requested_at: row.try_get("restore_requested_at")?,
        encryption_key_ref: row.try_get("encryption_key_ref")?,
        created_by: row.try_get_id("created_by")?,
        created_at: timestamp(row, "created_at")?,
        comment: row.try_get("comment")?,
    })
}

/// Reads a text column and parses it into a closed vocabulary.
///
/// The `reason` is a fixed phrase supplied by the caller, so the error can say which vocabulary
/// rejected the value without the value itself appearing anywhere.
fn parse_enum<T: FromStr>(row: &PgRow, column: &'static str, reason: &'static str) -> Result<T> {
    let raw: String = row.try_get(column)?;
    T::from_str(&raw).map_err(|_| VersionsError::MalformedRow { column, reason })
}

/// The same, for a nullable column where `NULL` is a value with a meaning.
///
/// `approval_state` is `NULL` in a library without content approval — an absence, not a missing
/// state — which is why this returns `Ok(None)` rather than treating the null as drift.
fn parse_optional_enum<T: FromStr>(
    row: &PgRow,
    column: &'static str,
    reason: &'static str,
) -> Result<Option<T>> {
    let raw: Option<String> = row.try_get(column)?;
    raw.map(|value| T::from_str(&value).map_err(|_| VersionsError::MalformedRow { column, reason }))
        .transpose()
}

/// Reads a `NOT NULL` `TIMESTAMPTZ`.
///
/// `av_scanned_at` is read through plain `try_get` instead, because there `NULL` means "not scanned
/// yet" rather than schema drift.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| VersionsError::MalformedRow { column, reason: "not a readable timestamp" })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_column_list_is_well_formed_and_complete() {
        for column in VERSION_COLUMNS.split(',') {
            let column = column.trim();
            assert!(!column.is_empty(), "empty column in the list");
            assert!(
                column.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "`{column}` is not a plain identifier"
            );
        }
        // Every column of `file_versions`. A column added to the table and not read here is a
        // field this crate cannot see; a column named here that the table does not have is a
        // runtime `ColumnNotFound`. The migrations are the reference for both.
        //
        // 21 from `0006`, plus `storage_tier` and `restore_requested_at` from `0032` (`ENC-946`).
        assert_eq!(VERSION_COLUMNS.split(',').count(), 23);
    }

    /// A column added by a later `ALTER TABLE` is read too.
    ///
    /// Split out from the test below rather than folded into it, because the two parse different
    /// shapes: `CREATE TABLE` has a body to walk, and an `ALTER TABLE ... ADD COLUMN` does not.
    /// Folding them would mean one loose parser covering both, and the loose half is the one that
    /// stops catching anything.
    ///
    /// **This is the gap `ENC-946` found.** `every_column_the_migration_defines_is_read` reads
    /// `0006` alone, so it has been blind to every column added by a migration since — the
    /// completeness check that looked complete. It is `0032`'s two columns today; the assertion is
    /// written against a list of migrations so the next `ALTER` is one line rather than a new test.
    #[test]
    fn every_column_a_later_migration_adds_is_read() {
        const ALTERS: &[(&str, &str)] =
            &[("0032_storage_tier", include_str!("../../../migrations/0032_storage_tier.sql"))];

        let mut found = 0_usize;
        for (name, sql) in ALTERS {
            for line in sql.lines() {
                let trimmed = line.trim();
                let Some(rest) = trimmed.strip_prefix("ADD COLUMN IF NOT EXISTS ") else {
                    continue;
                };
                let column = rest.split_whitespace().next().expect("a column name");
                found += 1;
                assert!(
                    VERSION_COLUMNS.contains(column),
                    "`{column}` is added to file_versions by {name} and nothing reads it"
                );
            }
        }
        // Without this the loop is vacuous: a parser that matches nothing passes every assertion
        // inside it, which is `docs/12 §1.2` in its purest form.
        assert!(found >= 2, "the ALTER parser found {found} columns; it has stopped matching");
    }

    #[test]
    fn every_column_the_migration_defines_is_read() {
        // Read the migration rather than restating it, for the reason `model` reads it too: a
        // restated list is a second copy that drifts.
        const MIGRATION: &str = include_str!("../../../migrations/0006_versions_and_uploads.sql");
        let body = MIGRATION
            .split("CREATE TABLE IF NOT EXISTS file_versions (")
            .nth(1)
            .expect("the file_versions definition")
            .split("\n);")
            .next()
            .expect("its closing paren");

        for line in body.lines() {
            let trimmed = line.trim();
            let Some(name) = trimmed.split_whitespace().next() else { continue };
            // Constraint clauses (`UNIQUE`, `FOREIGN KEY`) and comments, not columns.
            if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
                continue;
            }
            assert!(
                VERSION_COLUMNS.contains(name),
                "`{name}` is a column of file_versions and nothing reads it"
            );
        }
    }
}
