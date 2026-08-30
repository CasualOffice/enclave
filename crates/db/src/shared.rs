//! *Shared with me* — resources somebody explicitly granted this person (`ENC-954`).
//!
//! # The hole this closes
//!
//! `acl_entries` has had a writer since `ENC-916` and `grant()` since the ACL work: a person can be
//! given access to a file. **Nothing has ever listed what they were given.** The navigation carries
//! *Shared with me* as an unbuilt chip, and until this there was no query behind it — so a colleague
//! could share a document outside any workspace this person belongs to and they would have no way
//! to find it. The grant worked, the chain honoured it, and the recipient could not discover it.
//!
//! # What counts as a share, and what deliberately does not
//!
//! An `acl_entries` row naming this user, or a group they are in, on a `FILE` or `FOLDER`. That is
//! the shape of a deliberate act: somebody opened a thing and gave this person access to it.
//!
//! * **`WORKSPACE` and `LIBRARY` grants are not shares.** They are how a person joins a team, and
//!   including them would fill the screen with every container the caller is a member of — which is
//!   what the navigation already is.
//! * **`DENY` rows are excluded**, and not merely ignored. A `DENY` is access being *taken away*,
//!   and listing it would offer a door the chain refuses when the user walks through it.
//! * **`EVERYONE` is excluded.** A grant to everyone is a property of the tenant rather than a
//!   share with this person, and it would put identical rows on every user's screen.
//!
//! # This read decides nothing
//!
//! It is a candidate generator, exactly as the vector index is in `docs/07 §6`, and the same rule
//! applies: **every row is put through `PolicyEngine::enforce` before the caller is told it
//! exists.** An ACL row is not permission — inheritance, barriers, classification and DLP all sit
//! above it — so a row here that the chain refuses is ordinary and must vanish silently.
//!
//! Expiry is filtered here *and* re-checked by the chain. This predicate keeps a tenant's history
//! off the wire; it is not the authority.

use chrono::{DateTime, Utc};
use enclave_core::{ClassificationRank, FileId, GroupId, LibraryId, TenantId, UserId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::ids::{sql, RowIdExt as _};
use crate::recent::RecentClassification;
use crate::tenant::TenantScoped;
use crate::DbError;

/// One shared resource, with the file detail a listing needs and the grant that produced it.
#[derive(Debug, Clone)]
pub struct SharedCandidate {
    /// The file or folder that was shared.
    pub file_id: FileId,
    /// Its name, as stored.
    pub name: String,
    /// `FILE` or `FOLDER`. A folder can be shared and the client renders it differently.
    pub node_type: String,
    /// Its media type. Empty for a folder, which has none.
    pub mime_type: String,
    /// The library it lives in — half of the route the client links to.
    pub library_id: LibraryId,
    /// The folder containing it, or `None` at the library root.
    pub parent_folder_id: Option<FileId>,
    /// The label on the file's own row, or `None`. Not the chain maximum, for the reason
    /// `crate::recent` gives about the same column.
    pub classification: Option<RecentClassification>,
    /// When the share was made. The listing's order, and what a person reads as *"when"*.
    pub shared_at: DateTime<Utc>,
    /// Who made it. `acl_entries.granted_by` is `NOT NULL`, because *"the system shared this with
    /// you"* is not an answer to *"who gave me this"*.
    pub shared_by: UserId,
    /// Their display name, or `None` for a principal with no `users` row (`ENC-958`).
    ///
    /// Resolved by a `LEFT JOIN` here rather than by the API layer, for the reason
    /// [`crate::trash`] gives about `deletedBy`: the alternative is one query per row against
    /// `users`, which makes the screen's cost proportional to its length for a column that is one
    /// join. `None` is rendered as *"somebody"* and never as the id — a raw UUID in a sentence is
    /// worse than an honest absence.
    pub shared_by_display_name: Option<String>,
    /// The group the grant came through, or `None` when it named the user directly.
    ///
    /// Two different answers to *"why do I have this"*: a direct share is somebody choosing this
    /// person, a group share is somebody choosing a team they happen to be in. Someone who cannot
    /// tell them apart cannot reason about what they lose when they leave the team.
    pub via_group: Option<GroupId>,
}

/// What a page of shares looks like before the chain has trimmed it.
#[derive(Debug, Clone, Default)]
pub struct SharedCandidates {
    /// The rows, most recently shared first, ties broken by id descending so the order is stable.
    pub rows: Vec<SharedCandidate>,
    /// Whether the read hit its limit, so the caller knows the set was cut rather than exhausted.
    pub truncated: bool,
}

/// Resources explicitly shared with this user, most recent first.
///
/// `groups` is the caller's **transitive** closure, resolved by
/// `enclave_authorization::repo::group_closure`. Passed in rather than resolved here: this crate
/// holds no opinion about group nesting depth, and duplicating the recursion would be a second
/// definition of membership free to disagree with the one the chain uses.
///
/// # Errors
///
/// [`DbError::Query`] on failure, including a stored `node_type` this schema does not define.
pub async fn shared_with(
    tx: &mut TenantScoped,
    user: UserId,
    groups: &[GroupId],
    now: DateTime<Utc>,
    limit: i64,
) -> Result<SharedCandidates, DbError> {
    let tenant = tx.tenant_id();
    shared_with_on(tx, tenant, user, groups, now, limit).await
}

/// [`shared_with`] for a caller holding a plain connection.
///
/// Exists for the isolation tests, which have to run the statement where row-level security is not
/// silently doing the work the `tenant_id` predicate is credited with (`docs/12 §4.1`).
///
/// # Errors
///
/// As [`shared_with`].
pub async fn shared_with_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
    groups: &[GroupId],
    now: DateTime<Utc>,
    limit: i64,
) -> Result<SharedCandidates, DbError> {
    let group_ids: Vec<Uuid> = groups.iter().map(|group| group.as_uuid()).collect();
    let rows = sqlx::query(SHARED_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(&group_ids)
        .bind(now)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    let truncated = i64::try_from(rows.len()).unwrap_or(i64::MAX) >= limit;
    let rows = rows
        .iter()
        .map(|row| {
            Ok(SharedCandidate {
                file_id: row.try_get_id("file_id")?,
                name: row.try_get("name")?,
                node_type: row.try_get("node_type")?,
                mime_type: row.try_get("mime_type")?,
                library_id: row.try_get_id("library_id")?,
                parent_folder_id: row.try_get_opt_id("parent_id")?,
                classification: classification(row)?,
                shared_at: row.try_get("shared_at")?,
                shared_by: row.try_get_id("shared_by")?,
                shared_by_display_name: row.try_get("shared_by_display_name")?,
                via_group: row.try_get_opt_id("via_group")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(DbError::Query)?;

    Ok(SharedCandidates { rows, truncated })
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

// One row per resource, not per grant.
//
// A share is written as several `acl_entries` rows — `ENC-916`'s founding grant writes fifteen —
// and a listing showing each would repeat one file fifteen times.
//
// `DISTINCT ON` rather than `GROUP BY`, because the row that survives has to be a *specific* one:
// the earliest grant is when the share happened, and `MIN(granted_at)` with the other columns
// aggregated separately would pair that instant with whichever `granted_by` an arbitrary row
// carried — a listing that says the right time and the wrong person.
//
// The `files` join carries its own `tenant_id`, as every correlated read in this crate does: a
// second table gets the same treatment as the first, and `acl_entries.resource_id` is polymorphic
// over seven resource types with no foreign key to lean on (`migrations/0004`).
/// The statement, exposed for the source-level scoping assertion in `crates/db/tests/shared.rs`.
///
/// A `const` the test reads rather than a copy it restates: `docs/12 §1.2` — a test that restates
/// the thing it is testing proves the restatement.
pub const SHARED_SQL_FOR_TESTS: &str = SHARED_SQL;

const SHARED_SQL: &str = "
SELECT g.resource_id                   AS file_id,
       g.granted_at                    AS shared_at,
       g.granted_by                    AS shared_by,
       u.display_name                  AS shared_by_display_name,
       g.via_group                     AS via_group,
       f.name                          AS name,
       f.node_type                     AS node_type,
       f.mime_type                     AS mime_type,
       f.library_id                    AS library_id,
       f.parent_id                     AS parent_id,
       c.key                           AS classification_key,
       c.label                         AS classification_label,
       c.rank                          AS classification_rank
  FROM (
        SELECT DISTINCT ON (a.resource_id)
               a.resource_id,
               a.granted_at,
               a.granted_by,
               CASE WHEN a.principal_type = 'GROUP' THEN a.principal_id END AS via_group
          FROM acl_entries a
         WHERE a.tenant_id = $1
           AND a.resource_type IN ('FILE','FOLDER')
           AND a.effect = 'ALLOW'
           AND (a.expires_at IS NULL OR a.expires_at > $4)
           AND ( (a.principal_type = 'USER'  AND a.principal_id = $2)
              OR (a.principal_type = 'GROUP' AND a.principal_id = ANY($3::uuid[])) )
         ORDER BY a.resource_id, a.granted_at ASC
       ) g
  JOIN files f
    ON f.tenant_id = $1
   AND f.id = g.resource_id
   AND f.deleted_at IS NULL
  LEFT JOIN classifications c
    ON c.tenant_id = $1
   AND c.id = f.classification_id
  LEFT JOIN users u
    ON u.tenant_id = $1
   AND u.id = g.granted_by
 ORDER BY g.granted_at DESC, g.resource_id DESC
 LIMIT $5
";
