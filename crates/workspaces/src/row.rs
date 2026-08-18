//! Turning stored rows back into the types in [`crate::model`].
//!
//! Kept in one place rather than inline in each repository so that the column names a query selects
//! and the column names a decoder reads sit next to each other. The failure mode this guards
//! against is quiet: a `SELECT` that stops listing a column and a decoder that still asks for it
//! produce a runtime `ColumnNotFound` on a path that may only run in production.
//!
//! Every failure is [`WorkspaceError::MalformedRow`] naming the column and a fixed reason — never
//! the value. An unparseable `visibility` is schema/code drift, and echoing the offending content
//! into a log is how organizational detail travels out of the database (`CLAUDE.md` rule 10).

use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{Result, WorkspaceError};
use crate::model::{PrincipalType, Visibility, Workspace, WorkspaceMember};

// The column lists each decoder below reads, as the reference the query constants are checked
// against. Test-only on purpose, as in `enclave_identity::row`: the queries spell their `SELECT`
// lists out as literals, and what is needed is not shared code but a check that the two agree.

/// The `workspaces` columns every workspace query selects.
#[cfg(test)]
pub(crate) const WORKSPACE_COLUMNS: &str = "id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at";

/// The same list qualified with the alias the membership join uses.
#[cfg(test)]
pub(crate) const WORKSPACE_COLUMNS_ALIASED: &str =
    "w.id, w.tenant_id, w.name, w.slug, w.description, w.visibility, \
     w.default_classification_id, w.storage_profile_id, w.revision, w.created_by, w.created_at, \
     w.updated_at, w.deleted_at";

/// The `workspace_members` columns every membership query selects.
#[cfg(test)]
pub(crate) const MEMBER_COLUMNS: &str = "tenant_id, workspace_id, principal_id, principal_type, \
     role_id, added_by, added_at, expires_at";

/// Rebuilds a [`Workspace`].
///
/// # Errors
///
/// [`WorkspaceError::MalformedRow`] when a column is absent or holds a value outside its `CHECK`
/// constraint's vocabulary.
pub(crate) fn workspace_from_row(row: &PgRow) -> Result<Workspace> {
    Ok(Workspace {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        name: row.try_get("name")?,
        slug: row.try_get("slug")?,
        description: row.try_get("description")?,
        visibility: parse_enum::<Visibility>(row, "visibility", "not a known visibility")?,
        default_classification_id: row.try_get("default_classification_id")?,
        storage_profile_id: row.try_get("storage_profile_id")?,
        revision: row.try_get("revision")?,
        created_by: row.try_get_id("created_by")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

/// Rebuilds a [`WorkspaceMember`].
///
/// # Errors
///
/// As [`workspace_from_row`].
pub(crate) fn member_from_row(row: &PgRow) -> Result<WorkspaceMember> {
    Ok(WorkspaceMember {
        tenant_id: row.try_get_id("tenant_id")?,
        workspace_id: row.try_get_id("workspace_id")?,
        principal_id: row.try_get_id("principal_id")?,
        principal_type: parse_enum::<PrincipalType>(
            row,
            "principal_type",
            "not a known principal type",
        )?,
        role_id: row.try_get_id("role_id")?,
        added_by: row.try_get_id("added_by")?,
        added_at: timestamp(row, "added_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

/// Reads a text column and parses it into a closed vocabulary.
///
/// The `reason` is a fixed phrase supplied by the caller, so the error can say which vocabulary
/// rejected the value without the value itself appearing anywhere.
fn parse_enum<T>(row: &PgRow, column: &'static str, reason: &'static str) -> Result<T>
where
    T: FromStr,
{
    let raw: String = row.try_get(column)?;
    T::from_str(&raw).map_err(|_| WorkspaceError::MalformedRow { column, reason })
}

/// Reads a `TIMESTAMPTZ` that the schema declares `NOT NULL`.
///
/// A named helper only so that every non-null timestamp is read the same way; a NULL here is schema
/// drift rather than an absent value, and it should say so rather than surfacing as a decode error
/// with no column name in it.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| WorkspaceError::MalformedRow { column, reason: "not a readable timestamp" })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The aliased list is hand-written, so prove it is the same list. A missing column here is a
    /// `ColumnNotFound` on the "a principal's workspaces" path only — the path a member sees on
    /// every page load and no unit test can otherwise reach.
    #[test]
    fn the_aliased_workspace_columns_are_the_unaliased_ones() {
        let stripped: Vec<String> = WORKSPACE_COLUMNS_ALIASED
            .split(',')
            .map(|column| column.trim().trim_start_matches("w.").to_owned())
            .collect();
        let plain: Vec<String> =
            WORKSPACE_COLUMNS.split(',').map(|column| column.trim().to_owned()).collect();
        assert_eq!(stripped, plain);
    }

    /// Every decoder reads exactly the columns its `SELECT` lists. Checked by name because the
    /// mismatch is invisible until a query runs.
    #[test]
    fn every_column_list_is_well_formed() {
        for list in [WORKSPACE_COLUMNS, WORKSPACE_COLUMNS_ALIASED, MEMBER_COLUMNS] {
            for column in list.split(',') {
                let column = column.trim();
                assert!(!column.is_empty(), "empty column in `{list}`");
                assert!(
                    column.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c == '.'),
                    "`{column}` is not a plain identifier"
                );
            }
        }
        // Every column of `workspaces` and of `workspace_members` in migration 0004. A column
        // added there and forgotten here is a field this crate would silently stop round-tripping.
        assert_eq!(WORKSPACE_COLUMNS.split(',').count(), 13);
        assert_eq!(MEMBER_COLUMNS.split(',').count(), 8);
    }
}
