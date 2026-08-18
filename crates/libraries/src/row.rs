//! Turning stored rows back into the types in [`crate::model`], and the extension lists back into
//! JSONB.
//!
//! Kept in one place so that the column names a query selects and the column names a decoder reads
//! sit next to each other: a `SELECT` that stops listing a column and a decoder that still asks for
//! it produce a runtime `ColumnNotFound` on a path that may only run in production.
//!
//! Every failure is [`LibraryError::MalformedRow`] naming the column and a fixed reason — never the
//! value.
//!
//! # The two JSONB columns
//!
//! `allowed_extensions` and `blocked_extensions` are `JSONB` with no shape enforced by the
//! database, so the shape is enforced here: an array of strings, or `NULL`. Anything else is
//! rejected rather than coerced. Silently reading `{"deny": [".exe"]}` as an empty list would turn
//! a deny-list into no deny-list, which is a control that stops working while looking like it works
//! — the failure mode worth being loud about.

use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{LibraryError, Result};
use crate::model::{ExternalSharing, Library, LibrarySettings, VersioningMode};

/// The `libraries` columns every query selects — every column migration 0004 creates.
#[cfg(test)]
pub(crate) const LIBRARY_COLUMNS: &str = "id, tenant_id, workspace_id, name, slug, \
     inherit_permissions, default_classification_id, versioning_mode, version_limit, \
     require_checkout, require_approval, allowed_extensions, blocked_extensions, \
     max_file_size_bytes, external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, \
     storage_profile_id, retention_policy_id, revision, created_at, updated_at, deleted_at";

/// Rebuilds a [`Library`].
///
/// # Errors
///
/// [`LibraryError::MalformedRow`] when a column is absent, holds a value outside its `CHECK`
/// constraint's vocabulary, or holds JSONB that is not an array of strings.
pub(crate) fn library_from_row(row: &PgRow) -> Result<Library> {
    Ok(Library {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        workspace_id: row.try_get_id("workspace_id")?,
        settings: LibrarySettings {
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            inherit_permissions: row.try_get("inherit_permissions")?,
            default_classification_id: row.try_get("default_classification_id")?,
            versioning_mode: parse_enum::<VersioningMode>(
                row,
                "versioning_mode",
                "not a known versioning mode",
            )?,
            version_limit: row.try_get("version_limit")?,
            require_checkout: row.try_get("require_checkout")?,
            require_approval: row.try_get("require_approval")?,
            allowed_extensions: extensions_from_row(row, "allowed_extensions")?,
            blocked_extensions: extensions_from_row(row, "blocked_extensions")?,
            max_file_size_bytes: row.try_get("max_file_size_bytes")?,
            external_sharing: parse_enum::<ExternalSharing>(
                row,
                "external_sharing",
                "not a known external-sharing setting",
            )?,
            ai_indexing_enabled: row.try_get("ai_indexing_enabled")?,
            mcp_visible: row.try_get("mcp_visible")?,
            sync_enabled: row.try_get("sync_enabled")?,
            storage_profile_id: row.try_get("storage_profile_id")?,
            retention_policy_id: row.try_get("retention_policy_id")?,
        },
        revision: row.try_get("revision")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

/// Renders an extension list for binding to a `JSONB` column.
///
/// `None` binds SQL `NULL` — "no list" — which is not the same as an empty array, which permits or
/// blocks nothing at all. Keeping the two distinct is the whole reason the field is an `Option`.
pub(crate) fn extensions_to_json(extensions: Option<&Vec<String>>) -> Option<Value> {
    extensions.map(|list| Value::Array(list.iter().cloned().map(Value::String).collect()))
}

/// Reads a `JSONB` array of strings.
fn extensions_from_row(row: &PgRow, column: &'static str) -> Result<Option<Vec<String>>> {
    let raw: Option<Value> = row
        .try_get(column)
        .map_err(|_| LibraryError::MalformedRow { column, reason: "not readable JSON" })?;

    let Some(value) = raw else {
        return Ok(None);
    };

    let Value::Array(items) = value else {
        return Err(LibraryError::MalformedRow { column, reason: "not a JSON array" });
    };

    items
        .into_iter()
        .map(|item| match item {
            Value::String(text) => Ok(text),
            // Not coerced with `to_string()`: a number or an object in this list means something
            // wrote a shape the application does not understand, and guessing at it would produce
            // an extension rule nobody authored.
            _ => Err(LibraryError::MalformedRow { column, reason: "not an array of strings" }),
        })
        .collect::<Result<Vec<String>>>()
        .map(Some)
}

/// Reads a text column and parses it into a closed vocabulary.
fn parse_enum<T>(row: &PgRow, column: &'static str, reason: &'static str) -> Result<T>
where
    T: FromStr,
{
    let raw: String = row.try_get(column)?;
    T::from_str(&raw).map_err(|_| LibraryError::MalformedRow { column, reason })
}

/// Reads a `TIMESTAMPTZ` that the schema declares `NOT NULL`.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| LibraryError::MalformedRow { column, reason: "not a readable timestamp" })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_column_list_is_well_formed_and_complete() {
        for column in LIBRARY_COLUMNS.split(',') {
            let column = column.trim();
            assert!(!column.is_empty(), "empty column in the list");
            assert!(
                column.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "`{column}` is not a plain identifier"
            );
        }
        // Every column of `libraries` in migration 0004. One added there and forgotten here is a
        // setting this crate would silently stop round-tripping.
        assert_eq!(LIBRARY_COLUMNS.split(',').count(), 24);
    }

    #[test]
    fn an_absent_extension_list_is_not_an_empty_one() {
        // `NULL` means "no allow-list, everything passes"; `[]` means "nothing passes". Collapsing
        // them either opens a library up or locks it shut, and both are silent.
        assert_eq!(extensions_to_json(None), None);
        assert_eq!(extensions_to_json(Some(&Vec::new())), Some(Value::Array(Vec::new())));
    }

    #[test]
    fn an_extension_list_round_trips_through_json() {
        let list = vec![".docx".to_owned(), ".PDF".to_owned()];
        let json = extensions_to_json(Some(&list)).unwrap();
        // Stored exactly as given — case included. Folding here would make this crate a second
        // opinion on how the upload path compares an extension.
        assert_eq!(
            json,
            Value::Array(vec![Value::String(".docx".into()), Value::String(".PDF".into())])
        );
    }
}
