//! Turning a stored row back into a [`LoadedSession`].
//!
//! Kept in one place so the column list a query selects and the column names a decoder reads sit
//! next to each other — the failure mode otherwise is a `SELECT` that stops listing a column and a
//! decoder that still asks for it, which is a runtime `ColumnNotFound` on a path that may only run
//! in production.
//!
//! Every failure is [`UploadError::MalformedRow`] naming a column and a fixed reason, never the
//! value: a row that will not decode is schema/code drift, and echoing its contents into a log is
//! how a file name travels somewhere it was not meant to go (`CLAUDE.md` rule 10).

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt as _;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{Result, UploadError};
use crate::session::{LoadedSession, Session, SessionRecord, SettledSession};
use crate::staged::StagedObject;
use crate::state::{Created, UploadState, Uploading};

// The column list every query selects, as the reference the query constants are checked against.
// Test-only on purpose, and for the reason `enclave_identity::row` gives: the queries spell their
// `SELECT` lists out as literals, because `concat!` takes only literals and building SQL with
// `format!` on every call to avoid one duplicated string is the wrong trade. What is needed is not
// shared code but a check that the two agree, and that is exactly what a constant plus an
// assertion gives.

/// The `upload_sessions` columns every query in this crate selects, in order.
#[cfg(test)]
pub(crate) const SESSION_COLUMNS: &str = "id, tenant_id, library_id, parent_id, file_id, name, \
     declared_size, declared_mime, staged_key, multipart_id, state, bytes_received, created_by, \
     created_at, updated_at, expires_at";

/// Rebuilds a session from a row, in whichever phase the `state` column names.
///
/// # Errors
///
/// [`UploadError::MalformedRow`] for a column that will not decode, and
/// [`UploadError::UnknownState`] for a `state` outside this release's vocabulary — which is a
/// migration that added a state the code does not know, not something a client did.
pub(crate) fn session_from_row(row: &PgRow) -> Result<LoadedSession> {
    let state: UploadState = row
        .try_get::<String, _>("state")
        .map_err(|_| UploadError::MalformedRow { column: "state", reason: "absent or not text" })?
        .parse()?;

    let staged = StagedObject::parse(&row.try_get::<String, _>("staged_key").map_err(|_| {
        UploadError::MalformedRow { column: "staged_key", reason: "absent or not text" }
    })?)?;

    let record = SessionRecord {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        library_id: row.try_get_id("library_id")?,
        parent_id: row.try_get_opt_id("parent_id")?,
        file_id: row.try_get_opt_id("file_id")?,
        name: row.try_get("name")?,
        declared_size: row.try_get("declared_size")?,
        declared_mime: row.try_get("declared_mime")?,
        staged,
        multipart_id: row.try_get("multipart_id")?,
        bytes_received: row.try_get("bytes_received")?,
        created_by: row.try_get_id("created_by")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
        expires_at: timestamp(row, "expires_at")?,
    };

    // The object key is what the eventual version row points at, and `file_id` is what the commit
    // will attach that version to. If a row ever holds two different files, the bytes and the
    // metadata would end up describing different things — refuse rather than pick one.
    if let Some(file_id) = record.file_id {
        if file_id != record.staged.file() {
            return Err(UploadError::MalformedRow {
                column: "staged_key",
                reason: "the staged key names a different file than file_id",
            });
        }
    }

    Ok(match state {
        UploadState::Created => LoadedSession::Created(Session::<Created>::from_parts(record, ())),
        UploadState::Uploading => {
            LoadedSession::Uploading(Session::<Uploading>::from_parts(record, ()))
        }
        // Everything else — including `UPLOADED`, which no committed row ever holds; see
        // `crate::reaper` — is readable and not advanceable here.
        settled => LoadedSession::Settled(SettledSession::new(record, settled)),
    })
}

/// Reads a `TIMESTAMPTZ`.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| UploadError::MalformedRow { column, reason: "absent, or not a timestamptz" })
}
