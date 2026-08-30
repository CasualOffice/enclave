//! What changed, for the people who can see the thing that changed (`ENC-960`).
//!
//! # Nothing has ever read `audit_events`
//!
//! The append-only, hash-chained audit log has been written since Phase 0 and **no query in this
//! workspace has ever selected from it** — not a user surface, and not the `/admin/audit` endpoint
//! `docs/05 §14`'s map has listed since it was drawn. This is the first reader, and it is
//! deliberately the narrowest one: an administrative audit reader is a different surface with a
//! different action (`AdminAction::ReadAudit`) and is still unbuilt (`ENC-961`).
//!
//! # The two decisions that make this safe to expose
//!
//! **Only `ALLOW`.** A `DENY` row says somebody tried and was refused, which discloses both that
//! they tried and that the resource exists — the second is what `CLAUDE.md` rule 7 spends a `404`
//! to protect. Reading refusals is an administrative power, not a member's.
//!
//! **Only changes, never reads.** `file.metadata_read`, `preview` and `download` are the majority
//! of every audit log and are excluded on purpose: a feed that showed them would be a record of who
//! looked at what, available to everybody who can open the file. That is a surveillance tool, and
//! the fact that the data is sitting in the table is not a reason to build one. An activity feed
//! answers *what happened to this*, and reading is not something happening to it.
//!
//! Everything about the *actor's* circumstances — `ip`, `country`, `user_agent`, `session_id`,
//! `device_id`, `detail` — is excluded for the same reason in a sharper form. Those columns exist so
//! a security investigation can reconstruct a session; putting a colleague's IP address on a screen
//! anybody with read access can open is a disclosure with no upside at all.
//!
//! # This read decides nothing
//!
//! It is a candidate generator, exactly as `crate::shared` is: every row is put through
//! `PolicyEngine::enforce` by the caller before anybody is told it exists. An audit row naming a
//! file is not permission to know about that file.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId, UserId};
use sqlx::{PgConnection, Row as _};

use crate::ids::{sql, RowIdExt as _};
use crate::tenant::TenantScoped;
use crate::DbError;

/// One thing that happened.
#[derive(Debug, Clone)]
pub struct ActivityCandidate {
    /// The file it happened to.
    pub file_id: FileId,
    /// The file's current name. Read from `files`, not from the audit row, and the difference
    /// matters: the audit log stores no name — `CLAUDE.md` rule 10 keeps content out of it — so a
    /// renamed file shows its name *now*, which is the one a reader can act on.
    pub name: String,
    /// `FILE` or `FOLDER`.
    pub node_type: String,
    /// The library it lives in.
    pub library_id: enclave_core::LibraryId,
    /// What happened, in the `family.verb` spelling `Action`'s `Display` produces.
    pub action: String,
    /// Who did it, or `None` for a principal with no user id — a service account or `system`.
    pub actor_id: Option<UserId>,
    /// When.
    pub occurred_at: DateTime<Utc>,
}

/// Recent changes in this tenant, newest first.
///
/// **Not scoped to the caller.** An activity feed answers *what has been happening to the things I
/// can see*, which is a different question from *what have I done* — a person wants to know their
/// colleague edited the contract, and `idx_audit_actor` exists for the other question if a surface
/// ever needs it. The scoping to *what I can see* is the caller's trim, not this predicate.
///
/// # Errors
///
/// [`DbError::Query`].
pub async fn recent_changes(
    tx: &mut TenantScoped,
    limit: i64,
) -> Result<Vec<ActivityCandidate>, DbError> {
    let tenant = tx.tenant_id();
    recent_changes_on(tx, tenant, limit).await
}

/// [`recent_changes`] for a caller holding a plain connection.
///
/// Exists for the isolation tests, which have to run the statement where row-level security is not
/// silently doing the work the `tenant_id` predicate is credited with (`docs/12 §4.1`).
///
/// # Errors
///
/// As [`recent_changes`].
pub async fn recent_changes_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    limit: i64,
) -> Result<Vec<ActivityCandidate>, DbError> {
    let rows = sqlx::query(RECENT_SQL)
        .bind(sql(tenant))
        .bind(limit)
        .bind(SHOWN_ACTIONS)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            Ok(ActivityCandidate {
                file_id: row.try_get_id("file_id")?,
                name: row.try_get("name")?,
                node_type: row.try_get("node_type")?,
                library_id: row.try_get_id("library_id")?,
                action: row.try_get("action")?,
                actor_id: row.try_get_opt_id("actor_id")?,
                occurred_at: row.try_get("occurred_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(DbError::Query)
}

/// The actions an activity feed shows.
///
/// **Changes only.** Reads are excluded and the module header argues it: a feed of who previewed
/// what is a surveillance tool, and `file.metadata_read` alone outnumbers every other file action
/// in a real log by an order of magnitude.
///
/// Exposed so `crates/api` can render each one and a test can assert the set is what it claims —
/// a list that silently grew a read action would turn this surface into the thing it refuses to be.
pub const SHOWN_ACTIONS: &[&str] = &[
    "file.edit",
    "file.delete",
    "file.restore",
    "file.move",
    "file.copy",
    "file.manage_permissions",
    "file.share",
    "file.share_external",
];

// `resource_type = 'file'` and a join to `files`, so a row whose resource has been purged or belongs
// to another tenant produces nothing. The join carries its own `tenant_id`, as every correlated read
// in this crate does.
//
// `DISTINCT ON` is deliberately *not* used: two edits to one file are two things that happened, and
// collapsing them would make a feed that says "changed" once for a document somebody revised nine
// times. That is the opposite of `crate::shared`, where several ACL rows are one share — the
// difference is that a share is a state and an edit is an event.
const RECENT_SQL: &str = "
SELECT a.resource_id                   AS file_id,
       a.action                        AS action,
       a.actor_id                      AS actor_id,
       a.occurred_at                   AS occurred_at,
       f.name                          AS name,
       f.node_type                     AS node_type,
       f.library_id                    AS library_id
  FROM audit_events a
  JOIN files f
    ON f.tenant_id = a.tenant_id
   AND f.id = a.resource_id
   AND f.deleted_at IS NULL
 WHERE a.tenant_id = $1
   AND a.outcome = 'ALLOW'
   AND a.resource_type = 'file'
   AND a.action = ANY($3::text[])
 ORDER BY a.occurred_at DESC, a.sequence DESC
 LIMIT $2
";
