//! Turning stored rows back into [`FileNode`].
//!
//! Kept in one place rather than inline in each query so that the column names a statement selects
//! and the column names a decoder reads sit next to each other. The failure mode this guards
//! against is quiet: a `SELECT` that stops listing a column and a decoder that still asks for it
//! produce a runtime `ColumnNotFound` on a path that may only run in production.
//!
//! Every failure is [`FilesError::MalformedRow`] naming the column and a fixed reason — never the
//! value. An unparseable `status` is schema/code drift, and echoing the offending content into a
//! log is how content travels out of the database (`CLAUDE.md` rule 10).

use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{FilesError, Result};
use crate::model::{FileNode, NodeStatus, NodeType};

/// The `files` columns every statement in this crate selects or returns.
///
/// Test-only, as the reference the query constants are checked against: the queries spell their
/// lists out as literals — `concat!` takes only literals, and building SQL with `format!` on every
/// call to avoid one duplicated string is the wrong trade. What is needed is not shared code but a
/// check that the two agree, and that is what a constant plus an assertion gives.
#[cfg(test)]
pub(crate) const NODE_COLUMNS: &str = "id, tenant_id, workspace_id, library_id, parent_id, \
     node_type, name, normalized_name, mime_type, current_version_id, size_bytes, \
     inherit_permissions, revision, acl_revision, is_record, on_legal_hold, status, created_by, \
     modified_by, created_at, modified_at, deleted_at, purge_after";

/// The same list qualified with the table name.
///
/// Needed by the two `INSERT … SELECT … RETURNING` statements, whose source is `files` aliased as
/// the parent row. Unqualified names there would be resolvable to two different things by eye even
/// where PostgreSQL itself is not confused, and the reader of a data-modifying statement should
/// never have to work out which row is being returned.
#[cfg(test)]
pub(crate) const NODE_COLUMNS_QUALIFIED: &str = "files.id, files.tenant_id, files.workspace_id, \
     files.library_id, files.parent_id, files.node_type, files.name, files.normalized_name, \
     files.mime_type, files.current_version_id, files.size_bytes, files.inherit_permissions, \
     files.revision, files.acl_revision, files.is_record, files.on_legal_hold, files.status, \
     files.created_by, files.modified_by, files.created_at, files.modified_at, files.deleted_at, \
     files.purge_after";

/// Rebuilds a [`FileNode`].
///
/// # Errors
///
/// [`FilesError::MalformedRow`] when a column is absent or holds a value outside its `CHECK`
/// constraint's vocabulary.
pub(crate) fn node_from_row(row: &PgRow) -> Result<FileNode> {
    Ok(FileNode {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        workspace_id: row.try_get_id("workspace_id")?,
        library_id: row.try_get_id("library_id")?,
        parent_id: row.try_get_opt_id("parent_id")?,
        node_type: parse_enum::<NodeType>(row, "node_type", "not a known node type")?,
        name: row.try_get("name")?,
        normalized_name: row.try_get("normalized_name")?,
        mime_type: row.try_get("mime_type")?,
        current_version_id: row.try_get_opt_id("current_version_id")?,
        size_bytes: row.try_get("size_bytes")?,
        inherit_permissions: row.try_get("inherit_permissions")?,
        revision: row.try_get("revision")?,
        acl_revision: row.try_get("acl_revision")?,
        is_record: row.try_get("is_record")?,
        on_legal_hold: row.try_get("on_legal_hold")?,
        status: parse_enum::<NodeStatus>(row, "status", "not a known node status")?,
        created_by: row.try_get_id("created_by")?,
        modified_by: row.try_get_id("modified_by")?,
        created_at: timestamp(row, "created_at")?,
        modified_at: timestamp(row, "modified_at")?,
        deleted_at: row.try_get("deleted_at")?,
        purge_after: row.try_get("purge_after")?,
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
    T::from_str(&raw).map_err(|_| FilesError::MalformedRow { column, reason })
}

/// Reads a `NOT NULL` `TIMESTAMPTZ`.
///
/// `deleted_at` and `purge_after` are read through plain `try_get` instead, because there `NULL` is
/// a value with a meaning rather than a schema drift.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| FilesError::MalformedRow { column, reason: "not a readable timestamp" })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_qualified_column_list_is_the_unqualified_one() {
        // The qualified list is hand-written, so prove it is the same list. A missing column there
        // is a `ColumnNotFound` on the create path only.
        let stripped: Vec<String> = NODE_COLUMNS_QUALIFIED
            .split(',')
            .map(|column| column.trim().trim_start_matches("files.").to_owned())
            .collect();
        let plain: Vec<String> =
            NODE_COLUMNS.split(',').map(|column| column.trim().to_owned()).collect();
        assert_eq!(stripped, plain);
    }

    #[test]
    fn the_column_list_is_well_formed_and_complete() {
        for column in NODE_COLUMNS.split(',') {
            let column = column.trim();
            assert!(!column.is_empty(), "empty column in the list");
            assert!(
                column.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "`{column}` is not a plain identifier"
            );
        }
        // Every field of `FileNode`. A field added to the struct without a column here fails to
        // compile in `node_from_row`; a column added here without a field fails this count.
        assert_eq!(NODE_COLUMNS.split(',').count(), 23);
    }

    #[test]
    fn the_columns_this_crate_does_not_read_are_absent_on_purpose() {
        // `classification_id`, `classification_source` and `content_type_id` belong to crates that
        // do not exist yet, and `core` has no newtype for either identifier. See `crate::model`.
        for absent in ["classification_id", "classification_source", "content_type_id"] {
            assert!(
                !NODE_COLUMNS.contains(absent),
                "{absent} is read without a type to read it as"
            );
        }
    }
}
