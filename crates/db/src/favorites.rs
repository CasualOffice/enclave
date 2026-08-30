//! What a person has starred (`ENC-959`).
//!
//! *Favorites* has carried a `Later` chip in the navigation since the shell was written and had
//! never existed in this schema. `migrations/0034` creates it; this is the read and write.
//!
//! # A favorite is the user's own data
//!
//! It grants nothing, reveals nothing and decides nothing — a private note somebody made about a
//! file they could already see. Two people starring one file are two rows that know nothing about
//! each other. That is why the key is `(tenant_id, user_id, file_id)` and why no other table
//! references this one.
//!
//! It is still put through the policy chain by the caller before it is written or listed, and the
//! reason is not the favourite: it is the *file*. Starring names a resource, and a person who may
//! not read a file may not learn that it exists by starring it either.

use chrono::{DateTime, Utc};
use enclave_core::{ClassificationRank, FileId, LibraryId, TenantId, UserId};
use sqlx::{PgConnection, Row as _};

use crate::ids::{sql, RowIdExt as _};
use crate::recent::RecentClassification;
use crate::tenant::TenantScoped;
use crate::DbError;

/// One starred resource, with the detail a listing needs.
#[derive(Debug, Clone)]
pub struct FavoriteCandidate {
    /// The file or folder.
    pub file_id: FileId,
    /// Its name, as stored.
    pub name: String,
    /// `FILE` or `FOLDER`. A person may star either.
    pub node_type: String,
    /// Its media type. A folder's is `inode/directory`.
    pub mime_type: String,
    /// The library it lives in — half of the route the client links to.
    pub library_id: LibraryId,
    /// The folder containing it, or `None` at the library root.
    pub parent_folder_id: Option<FileId>,
    /// The label on the file's own row, or `None`.
    pub classification: Option<RecentClassification>,
    /// When it was starred. The listing's order.
    pub favorited_at: DateTime<Utc>,
}

/// Stars a file for this user, or does nothing if it already is.
///
/// Returns whether this call created the row. `false` means it was already starred, which is
/// **success and not a conflict**: starring is a statement about a preference, and the preference
/// after two clicks is the same as after one. `ON CONFLICT DO NOTHING` against the natural key is
/// what makes that true without a read first — a `SELECT` then an `INSERT` would be the same race
/// `plans/M1-CONTENT-CORE.md` D18 describes, for an answer nobody needs.
///
/// # Errors
///
/// [`DbError::Query`], including the composite foreign key's refusal when the file is another
/// tenant's or the user has no `users` row.
pub async fn add(tx: &mut TenantScoped, user: UserId, file: FileId) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let created: Option<(DateTime<Utc>,)> = sqlx::query_as(ADD_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(sql(file))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(created.is_some())
}

/// Un-stars a file, or does nothing if it was not starred.
///
/// Returns whether a row was removed. `false` is success for the same reason `add` returning
/// `false` is: the state the caller asked for is the state that now holds.
///
/// A real `DELETE`, unlike every policy table in this schema. `migrations/0034`'s header argues it:
/// there is no compliance value in the record that somebody once starred a document, and
/// withholding the verb would mean carrying tombstones of a preference nobody audits.
///
/// # Errors
///
/// [`DbError::Query`].
pub async fn remove(tx: &mut TenantScoped, user: UserId, file: FileId) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let removed = sqlx::query(REMOVE_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(sql(file))
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(removed.rows_affected() > 0)
}

/// This user's stars, most recent first.
///
/// Trashed files are filtered by the join, exactly as `crate::recent` filters them: a row that
/// opens onto a `404` reads as the product losing somebody's document rather than as somebody
/// having deleted it. The `favorites` row survives, so restoring the file brings the star back.
///
/// # Errors
///
/// [`DbError::Query`].
pub async fn list(
    tx: &mut TenantScoped,
    user: UserId,
    limit: i64,
) -> Result<Vec<FavoriteCandidate>, DbError> {
    let tenant = tx.tenant_id();
    list_on(tx, tenant, user, limit).await
}

/// [`list`] for a caller holding a plain connection.
///
/// Exists for the isolation tests, which have to run the statement where row-level security is not
/// silently doing the work the `tenant_id` predicate is credited with (`docs/12 §4.1`).
///
/// # Errors
///
/// As [`list`].
pub async fn list_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
    limit: i64,
) -> Result<Vec<FavoriteCandidate>, DbError> {
    let rows = sqlx::query(LIST_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            Ok(FavoriteCandidate {
                file_id: row.try_get_id("file_id")?,
                name: row.try_get("name")?,
                node_type: row.try_get("node_type")?,
                mime_type: row.try_get("mime_type")?,
                library_id: row.try_get_id("library_id")?,
                parent_folder_id: row.try_get_opt_id("parent_id")?,
                classification: classification(row)?,
                favorited_at: row.try_get("favorited_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(DbError::Query)
}

fn classification(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<RecentClassification>, sqlx::Error> {
    // `LEFT JOIN`, so all three columns are absent together. Keyed off `key` rather than tested
    // three times: a row with a label and no key is not a state `classifications` can hold.
    let key: Option<String> = row.try_get("classification_key")?;
    let Some(key) = key else { return Ok(None) };
    Ok(Some(RecentClassification {
        key,
        label: row.try_get("classification_label")?,
        rank: ClassificationRank::new(row.try_get::<i32, _>("classification_rank")?),
    }))
}

// `RETURNING created_at` rather than a bare `INSERT`, so the caller can tell a new star from one
// that was already there. `DO NOTHING` returns no row on conflict, which is exactly the signal.
const ADD_SQL: &str = "
    INSERT INTO favorites (tenant_id, user_id, file_id)
    VALUES ($1, $2, $3)
    ON CONFLICT (tenant_id, user_id, file_id) DO NOTHING
    RETURNING created_at";

const REMOVE_SQL: &str = "
    DELETE FROM favorites
     WHERE tenant_id = $1 AND user_id = $2 AND file_id = $3";

// The `files` join carries its own `tenant_id`, as every correlated read in this crate does: a
// second table gets the same treatment as the first.
const LIST_SQL: &str = "
SELECT v.file_id                       AS file_id,
       v.created_at                    AS favorited_at,
       f.name                          AS name,
       f.node_type                     AS node_type,
       f.mime_type                     AS mime_type,
       f.library_id                    AS library_id,
       f.parent_id                     AS parent_id,
       c.key                           AS classification_key,
       c.label                         AS classification_label,
       c.rank                          AS classification_rank
  FROM favorites v
  JOIN files f
    ON f.tenant_id = $1
   AND f.id = v.file_id
   AND f.deleted_at IS NULL
  LEFT JOIN classifications c
    ON c.tenant_id = $1
   AND c.id = f.classification_id
 WHERE v.tenant_id = $1
   AND v.user_id = $2
 ORDER BY v.created_at DESC, v.file_id DESC
 LIMIT $3
";
