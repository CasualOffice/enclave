//! Every statement this crate runs.
//!
//! Each function takes the `&mut PgConnection` a [`enclave_db::TenantScoped`] transaction derefs
//! to, never a pool — the same shape `crates/versions` and `crates/files` use
//! (`plans/M1-CONTENT-CORE.md` D10). The tenant predicate is written into every statement even
//! though row-level security applies its own: that is the point of having two layers, and it is
//! what makes the T5-style test meaningful (`crates/db/src/lib.rs`).
//!
//! **No authorization decision is taken here.** The feed read returns what the tenant's feed holds;
//! which of it a *caller* may see is decided by the policy chain at the edge and rendered by
//! [`crate::Eligibility`]. A repository that filtered by grant would be a second enforcement point,
//! and a second enforcement point is one the `ENC-110` policy-routing lint does not check.

use chrono::{DateTime, Utc};
use enclave_core::{DeviceId, DevicePosture, FileId, TenantId, UserId, VersionId};
use enclave_db::{sql, RowIdExt as _};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::delta::{ChangeOp, FeedEntry, FeedPage, ReadableVersion};
use crate::device::{DeviceState, Registration, SyncDevice, MAX_DEVICES_PER_USER};
use crate::error::{Result, SyncError};
use crate::scope::{DeltaCursor, SyncScope};

/// How deep the classification walk goes before it gives up.
///
/// The same bound `enclave_db::MAX_CHAIN_DEPTH` uses, taken from there rather than restated, so the
/// two walks cannot disagree about how deep a tree may be.
const MAX_CHAIN_DEPTH: i32 = enclave_db::MAX_CHAIN_DEPTH;

/// The columns a device row decodes from.
///
/// A macro rather than a `const`, for the reason `crates/versions`' `readable_predicate!` is one:
/// `concat!` takes only literals, and every statement below has to be a `&'static str` — sqlx 0.9's
/// `SqlSafeStr` bound refuses a `format!`ed query, which is the injection guard working as
/// intended. One list, spliced into four statements, so a column added to the table cannot be read
/// by one query and missed by its neighbour.
macro_rules! device_columns {
    () => {
        "tenant_id, device_id, user_id, name, platform, client_version, posture, state, \
         last_sync_at, wipe_requested_at, wiped_at, created_at, updated_at"
    };
}

/// The feed window: one scope, everything above a cursor, in order.
///
/// # The `file_versions` join is the rule-9 predicate and nothing else
///
/// The `AND` splices [`enclave_versions::READABLE_PREDICATE`] — the *same text* as
/// `FileVersion::is_readable`'s SQL twin — rather than a retyped `status = 'AVAILABLE' AND
/// av_status = 'CLEAN'`. `crates/versions/src/model.rs` exports it precisely so that a caller
/// writing its own read path splices one definition instead of inventing a second, and a sync is a
/// read path: a `LEFT JOIN` that missed the predicate would place scanning content on a laptop
/// (`CLAUDE.md` rule 9).
///
/// The join is `LEFT` so that a file whose version is *not* readable still produces a row. That is
/// deliberate: an omitted row is a file that silently vanishes from a device, and the whole point
/// of `docs/10 §4` is that it becomes a `QUARANTINED` tombstone instead.
const FEED_WINDOW_SQL: &str = concat!(
    "
SELECT cl.seq,
       cl.file_id,
       cl.op,
       f.library_id,
       f.name,
       f.parent_id,
       f.node_type,
       f.deleted_at,
       f.modified_at,
       l.sync_enabled,
       v.id              AS version_id,
       v.size_bytes      AS version_size_bytes,
       v.checksum_sha256 AS version_checksum
  FROM sync_change_log cl
  JOIN files     f ON f.tenant_id = cl.tenant_id AND f.id = cl.file_id
  JOIN libraries l ON l.tenant_id = cl.tenant_id AND l.id = f.library_id
  LEFT JOIN file_versions v
         ON v.tenant_id = f.tenant_id
        AND v.id        = f.current_version_id
        AND ",
    "status = 'AVAILABLE' AND av_status = 'CLEAN'",
    "
 WHERE cl.tenant_id  = $1
   AND cl.scope_type = $2
   AND cl.scope_id   = $3
   AND cl.seq        > $4
 ORDER BY cl.seq
 LIMIT $5
"
);

/// The two facts that decide whether a presented cursor still addresses this feed.
///
/// `next_seq` is the scope's high-water mark and `oldest` the lowest entry still retained. A cursor
/// above the first, or more than one below the second, is a cursor whose successors have been
/// pruned or never existed — `410 CURSOR_TOO_OLD` and a scoped re-enumeration (`docs/10 §4`).
const FEED_BOUNDS_SQL: &str = "
SELECT COALESCE((SELECT s.next_seq
                   FROM sync_scope_sequences s
                  WHERE s.tenant_id = $1 AND s.scope_type = $2 AND s.scope_id = $3), 0) AS high,
       (SELECT min(cl.seq)
          FROM sync_change_log cl
         WHERE cl.tenant_id = $1 AND cl.scope_type = $2 AND cl.scope_id = $3) AS oldest
";

/// Whether any label on a file's chain blocks sync — `docs/10 §5` condition 2.
///
/// # Why this walk exists beside `enclave_db::effective_classification`
///
/// That one answers *"what rank"*, as a maximum over the chain, one file at a time. This one
/// answers *"does anything on the chain set `sync_blocked`"* for a **page of files at once**, and
/// the two differences are both load-bearing.
///
/// **A page at a time**, because the per-file form is one recursive query per entry and a page is
/// five hundred entries — the delta would be five hundred round trips for one control.
///
/// **`bool_or` rather than the maximum-ranked label's flag.** `sync_blocked` is an obligation
/// attached to a label, not a comparison against a threshold, and every obligation in this codebase
/// is most-restrictive-wins. Reading the flag off the *highest-ranked* label alone would mean a
/// `CONFIDENTIAL` label that blocks sync stops blocking it the moment a higher `RESTRICTED` label
/// that does not appears above it in the tree — a control switched off by adding a *more*
/// sensitive label, which is the direction that leaks.
///
/// The ancestor filter mirrors `enclave_db::classifications`' walk exactly, including the two
/// things that look like omissions there and are deliberate: it does **not** stop at
/// `inherit_permissions = FALSE` (`ENC-141`: nothing materialises a label when that flag flips, so
/// honouring it would silently declassify), and it does **not** filter withdrawn labels
/// (`migrations/0022`: withdrawal governs assignment, not meaning).
const SYNC_BLOCKED_SQL: &str = "
WITH RECURSIVE ancestry AS (
    SELECT f.id AS root, f.id, f.parent_id, f.library_id, f.classification_id, 0 AS depth
      FROM files f
     WHERE f.tenant_id = $1 AND f.id = ANY($2)
    UNION ALL
    SELECT a.root, p.id, p.parent_id, p.library_id, p.classification_id, a.depth + 1
      FROM ancestry a
      JOIN files p
        ON p.tenant_id = $1 AND p.id = a.parent_id AND p.deleted_at IS NULL
     WHERE a.depth < $3
),
labels AS (
    SELECT a.root, c.sync_blocked
      FROM ancestry a
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = a.classification_id
    UNION ALL
    SELECT a.root, c.sync_blocked
      FROM ancestry a
      JOIN libraries l
        ON l.tenant_id = $1 AND l.id = a.library_id AND l.deleted_at IS NULL
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = l.default_classification_id
     WHERE a.parent_id IS NULL
    UNION ALL
    SELECT a.root, c.sync_blocked
      FROM ancestry a
      JOIN libraries l
        ON l.tenant_id = $1 AND l.id = a.library_id AND l.deleted_at IS NULL
      JOIN workspaces w
        ON w.tenant_id = $1 AND w.id = l.workspace_id AND w.deleted_at IS NULL
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = w.default_classification_id
     WHERE a.parent_id IS NULL
)
SELECT root AS file_id, bool_or(sync_blocked) AS blocked
  FROM labels
 GROUP BY root
";

/// The repository. A unit struct rather than a handle, because every function takes its connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncRepository;

impl SyncRepository {
    // ---------------------------------------------------------------------------------------
    // Devices
    // ---------------------------------------------------------------------------------------

    /// Registers a device, refusing once the user is at `sync.max_devices_per_user`.
    ///
    /// The bound is checked and the row written **in the caller's transaction**, so two
    /// simultaneous registrations cannot both read four and both write a fifth. It is a count
    /// rather than a constraint because the limit is configuration rather than schema
    /// (`docs/10 §3`); the transaction is what makes the check binding.
    ///
    /// Only `ACTIVE` and `PAUSED` devices count. A revoked or wiped device holds no copy of
    /// anything, and the bound is on how many machines hold copies.
    ///
    /// # Errors
    ///
    /// [`SyncError::Validation`] naming `deviceCount` when the user is at the limit; database
    /// failures otherwise.
    pub async fn register(
        conn: &mut PgConnection,
        tenant: TenantId,
        registration: &Registration,
        now: DateTime<Utc>,
    ) -> Result<SyncDevice> {
        let held: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sync_devices
              WHERE tenant_id = $1 AND user_id = $2 AND state IN ('ACTIVE','PAUSED')",
        )
        .bind(sql(tenant))
        .bind(sql(registration.user_id))
        .fetch_one(&mut *conn)
        .await?;

        if usize::try_from(held).unwrap_or(usize::MAX) >= MAX_DEVICES_PER_USER {
            return Err(SyncError::field("deviceCount", enclave_core::ValidationCode::OutOfRange));
        }

        let device = DeviceId::new_v7();
        let row = sqlx::query(concat!(
            "INSERT INTO sync_devices
               (tenant_id, device_id, user_id, name, platform, client_version, selected_scopes,
                posture, state, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, 'UNKNOWN', 'ACTIVE', $7, $7)
             RETURNING ",
            device_columns!()
        ))
        .bind(sql(tenant))
        .bind(sql(device))
        .bind(sql(registration.user_id))
        .bind(&registration.name)
        .bind(&registration.platform)
        .bind(&registration.client_version)
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

        device_from_row(&row)
    }

    /// One device, or `None`.
    ///
    /// Returns revoked and wiped devices too: the wipe endpoint has to be able to answer *"already
    /// wiped"* without the row being invisible, and the device list shows them so an administrator
    /// can see that an offboarding completed.
    ///
    /// # Errors
    ///
    /// Database and decoding failures.
    pub async fn find(
        conn: &mut PgConnection,
        tenant: TenantId,
        device: DeviceId,
    ) -> Result<Option<SyncDevice>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            device_columns!(),
            " FROM sync_devices WHERE tenant_id = $1 AND device_id = $2"
        ))
        .bind(sql(tenant))
        .bind(sql(device))
        .fetch_optional(&mut *conn)
        .await?;
        row.as_ref().map(device_from_row).transpose()
    }

    /// Every device in the tenant, or every device of one user.
    ///
    /// `docs/05-API.md §13`: *"list; admin can list tenant-wide"*. Which of the two a caller gets
    /// is the handler's decision, taken from the policy chain — passing `None` here is not a
    /// privilege, it is the shape of a query whose privilege was decided one layer up.
    ///
    /// # Errors
    ///
    /// Database and decoding failures.
    pub async fn list(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: Option<UserId>,
        limit: i64,
    ) -> Result<Vec<SyncDevice>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            device_columns!(),
            " FROM sync_devices
              WHERE tenant_id = $1 AND ($2::uuid IS NULL OR user_id = $2)
              ORDER BY device_id
              LIMIT $3"
        ))
        .bind(sql(tenant))
        .bind(user.map(sql))
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;
        rows.iter().map(device_from_row).collect()
    }

    /// Records a wipe request and moves the device to `WIPING`.
    ///
    /// **This is the whole of what the server can do**, and the row is written so that the
    /// limitation is visible rather than implied: `wipe_requested_at` is stamped, `wiped_at` is
    /// not. `docs/10 §3.1` — the client deletes its cache and its tokens on its next successful
    /// authentication and *acknowledges*, and only then is `wiped_at` stamped by
    /// [`SyncRepository::acknowledge_wipe`]. A device that never comes back stays in `WIPING` for
    /// ever, which is the honest rendering of a cooperative wipe.
    ///
    /// Idempotent: a second request against a device already in `WIPING` updates the timestamp and
    /// returns the row, because a client that missed the first instruction should be told again.
    /// A device that has already acknowledged is left alone — re-wiping a wiped device would clear
    /// the evidence that the wipe completed.
    ///
    /// # Errors
    ///
    /// [`SyncError::NoSuchDevice`] when the id names no row in this tenant; database failures
    /// otherwise.
    pub async fn request_wipe(
        conn: &mut PgConnection,
        tenant: TenantId,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<SyncDevice> {
        let row = sqlx::query(concat!(
            "UPDATE sync_devices
                SET wipe_requested_at = $3,
                    state             = 'WIPING',
                    updated_at        = $3
              WHERE tenant_id = $1 AND device_id = $2 AND wiped_at IS NULL
              RETURNING ",
            device_columns!()
        ))
        .bind(sql(tenant))
        .bind(sql(device))
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => device_from_row(&row),
            // Either the device is not this tenant's, or it has already acknowledged. The already
            // wiped case is re-read rather than reported as a miss, so an administrator asking
            // twice is told the wipe completed instead of being told the device does not exist.
            None => Self::find(conn, tenant, device)
                .await?
                .filter(|held| held.wiped_at.is_some())
                .ok_or(SyncError::NoSuchDevice),
        }
    }

    /// Stamps `wiped_at` on the device's own acknowledgement.
    ///
    /// Only ever called for a device that asked — the `wipe_requested_at IS NOT NULL` predicate is
    /// the same condition the table's `CHECK` enforces, written here so the statement fails to
    /// match rather than fails to commit.
    ///
    /// # Errors
    ///
    /// [`SyncError::NoSuchDevice`] when no outstanding wipe matches; database failures otherwise.
    pub async fn acknowledge_wipe(
        conn: &mut PgConnection,
        tenant: TenantId,
        device: DeviceId,
        now: DateTime<Utc>,
    ) -> Result<SyncDevice> {
        let row = sqlx::query(concat!(
            "UPDATE sync_devices
                SET wiped_at   = $3,
                    state      = 'WIPED',
                    updated_at = $3
              WHERE tenant_id = $1 AND device_id = $2
                AND wipe_requested_at IS NOT NULL AND wiped_at IS NULL
              RETURNING ",
            device_columns!()
        ))
        .bind(sql(tenant))
        .bind(sql(device))
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;
        row.as_ref().map(device_from_row).transpose()?.ok_or(SyncError::NoSuchDevice)
    }

    // ---------------------------------------------------------------------------------------
    // The feed
    // ---------------------------------------------------------------------------------------

    /// Reads one window of a scope's feed, refusing a cursor the feed no longer reaches.
    ///
    /// The window is `seq > cursor ORDER BY seq LIMIT n`, which is complete and duplicate-free
    /// because of how `seq` is allocated — see the header of `migrations/0023_sync_devices.sql`.
    /// Nothing here can restore that property if the allocation loses it, which is why the argument
    /// lives in the migration and not in this doc comment.
    ///
    /// Entries naming the same file more than once inside one window are collapsed to the newest,
    /// because each entry carries the file's *current* state and the older ones would be identical
    /// rows with lower sequence numbers. [`FeedPage::next_cursor`] is the highest `seq` **scanned**
    /// rather than emitted, so the collapse cannot skip a change.
    ///
    /// # Errors
    ///
    /// [`SyncError::CursorTooOld`] when the presented position is above the scope's high-water mark
    /// or below its oldest retained entry; database and decoding failures otherwise.
    pub async fn feed(
        conn: &mut PgConnection,
        tenant: TenantId,
        scope: SyncScope,
        cursor: DeltaCursor,
        limit: i64,
    ) -> Result<FeedPage> {
        let bounds = sqlx::query(FEED_BOUNDS_SQL)
            .bind(sql(tenant))
            .bind(scope.kind().as_str())
            .bind(scope.id())
            .fetch_one(&mut *conn)
            .await?;
        let high: i64 = bounds.try_get("high")?;
        let oldest: Option<i64> = bounds.try_get("oldest")?;

        // A cursor above the high-water mark cannot have come from this feed. It is reachable only
        // from a fabricated value or from a counter that was reset, and in both cases the client's
        // position is meaningless — a scoped re-enumeration is the recovery, which is exactly what
        // `410 CURSOR_TOO_OLD` asks for.
        if cursor.get() > high {
            return Err(SyncError::CursorTooOld);
        }
        // `cursor + 1 < oldest` means the entries between them were pruned. `cursor + 1 == oldest`
        // is the ordinary case of a client that is exactly up to date with what is retained.
        if let Some(oldest) = oldest {
            if cursor.get() + 1 < oldest {
                return Err(SyncError::CursorTooOld);
            }
        }

        let rows = sqlx::query(FEED_WINDOW_SQL)
            .bind(sql(tenant))
            .bind(scope.kind().as_str())
            .bind(scope.id())
            .bind(cursor.get())
            .bind(limit)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = i64::try_from(rows.len()).unwrap_or(i64::MAX) >= limit;
        let scanned = rows.last().map(|row| row.try_get::<i64, _>("seq")).transpose()?;

        // Collapse to the newest entry per file, preserving `seq` order. `rows` is already ordered
        // ascending, so keeping the last occurrence is keeping the highest sequence.
        let mut entries: Vec<FeedEntry> = Vec::with_capacity(rows.len());
        for row in &rows {
            let entry = feed_entry_from_row(row)?;
            if let Some(existing) = entries.iter_mut().find(|held| held.file_id == entry.file_id) {
                *existing = entry;
            } else {
                entries.push(entry);
            }
        }

        Ok(FeedPage {
            next_cursor: DeltaCursor::new(scanned.unwrap_or_else(|| cursor.get()))?,
            entries,
            has_more,
        })
    }

    /// Whether any label on each file's chain blocks sync (`docs/10 §5` condition 2).
    ///
    /// Returns one entry per file that has at least one label on its chain. A file absent from the
    /// result carries no label anywhere above it, which is *not* the same as "permitted" in
    /// general — what an absent label means is the tenant's `Unlabelled` policy to decide
    /// (`enclave_core::ClassificationResolution`) — but it is the same for *this* control, because
    /// `sync_blocked` is an obligation a label attaches and an absent label attaches none.
    ///
    /// # Errors
    ///
    /// Database and decoding failures.
    pub async fn sync_blocked_by_label(
        conn: &mut PgConnection,
        tenant: TenantId,
        files: &[FileId],
    ) -> Result<Vec<(FileId, bool)>> {
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = files.iter().map(|file| file.as_uuid()).collect();
        let rows = sqlx::query(SYNC_BLOCKED_SQL)
            .bind(sql(tenant))
            .bind(&ids)
            .bind(MAX_CHAIN_DEPTH)
            .fetch_all(&mut *conn)
            .await?;
        rows.iter()
            .map(|row| {
                let file: FileId = row.try_get_id("file_id")?;
                let blocked: Option<bool> = row.try_get("blocked")?;
                Ok((file, blocked.unwrap_or(false)))
            })
            .collect()
    }

    /// Records where a device has read to.
    ///
    /// Best-effort from the handler's point of view and deliberately so: the authoritative cursor
    /// on any one call is the one the client presents, and this row exists so a device that lost
    /// its local state can resume rather than re-enumerate. Written with `GREATEST` so a
    /// re-delivery of an older page cannot walk a device backwards.
    ///
    /// # Errors
    ///
    /// Database failures.
    pub async fn record_cursor(
        conn: &mut PgConnection,
        tenant: TenantId,
        device: DeviceId,
        scope: SyncScope,
        cursor: DeltaCursor,
        now: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_cursors (tenant_id, device_id, scope_type, scope_id, cursor, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, device_id, scope_type, scope_id)
             DO UPDATE SET cursor     = GREATEST(sync_cursors.cursor, EXCLUDED.cursor),
                           updated_at = EXCLUDED.updated_at",
        )
        .bind(sql(tenant))
        .bind(sql(device))
        .bind(scope.kind().as_str())
        .bind(scope.id())
        .bind(cursor.get())
        .bind(now)
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "UPDATE sync_devices SET last_sync_at = $3, updated_at = $3
              WHERE tenant_id = $1 AND device_id = $2",
        )
        .bind(sql(tenant))
        .bind(sql(device))
        .bind(now)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Reservation
    // ---------------------------------------------------------------------------------------

    /// The three facts `POST /sync/reserve` needs about a file before it may claim a slot.
    ///
    /// One query rather than three: the version the server holds, whether a lock stops sync
    /// writing, and which library's limits apply. Reading them separately would let the file be
    /// checked out between the version read and the lock read, which is the window a reservation
    /// exists to close.
    ///
    /// # Errors
    ///
    /// Database and decoding failures.
    pub async fn reservation_target(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<Option<ReservationTarget>> {
        let row = sqlx::query(
            "SELECT f.library_id,
                    f.parent_id,
                    f.name,
                    f.node_type,
                    f.current_version_id,
                    f.deleted_at,
                    lk.kind AS lock_kind
               FROM files f
               LEFT JOIN file_locks lk
                      ON lk.tenant_id = f.tenant_id
                     AND lk.file_id   = f.id
                     AND (lk.expires_at IS NULL OR lk.expires_at > now())
              WHERE f.tenant_id = $1 AND f.id = $2",
        )
        .bind(sql(tenant))
        .bind(sql(file))
        .fetch_optional(&mut *conn)
        .await?;

        let Some(row) = row else { return Ok(None) };
        let deleted: Option<DateTime<Utc>> = row.try_get("deleted_at")?;
        let node_type: String = row.try_get("node_type")?;
        Ok(Some(ReservationTarget {
            library_id: row.try_get_id("library_id")?,
            parent_id: row.try_get_opt_id("parent_id")?,
            name: row.try_get("name")?,
            is_folder: node_type == "FOLDER",
            current_version_id: row.try_get_opt_id("current_version_id")?,
            deleted: deleted.is_some(),
            lock_kind: row.try_get("lock_kind")?,
        }))
    }
}

/// What a reservation is being asked to write over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationTarget {
    /// The library whose limits and quota apply.
    pub library_id: enclave_core::LibraryId,
    /// The folder it sits in.
    pub parent_id: Option<FileId>,
    /// Its current name, which the new version keeps.
    pub name: String,
    /// Folders have no bytes and cannot be reserved against.
    pub is_folder: bool,
    /// What the server currently holds. The `409` is decided against this.
    pub current_version_id: Option<VersionId>,
    /// Whether the file has been trashed.
    pub deleted: bool,
    /// `CHECKOUT`, `EDITOR`, `SYSTEM`, or `None`. `docs/10 §6`: a locked file is read-only to sync.
    pub lock_kind: Option<String>,
}

/// Decodes `devices.posture`'s stored vocabulary.
///
/// A hand-written match rather than a serde round trip because [`DevicePosture`] carries no
/// `FromStr` — it is a `serde` enumeration in `enclave_core`, and asking `serde_json` to parse a
/// bare column value would mean quoting it into JSON first. The four spellings are the `CHECK`
/// constraint's, and the exhaustive match is what breaks if a fifth is ever added.
fn posture_from_str(raw: &str) -> Result<DevicePosture> {
    match raw {
        "UNKNOWN" => Ok(DevicePosture::Unknown),
        "UNMANAGED" => Ok(DevicePosture::Unmanaged),
        "MANAGED" => Ok(DevicePosture::Managed),
        "COMPLIANT" => Ok(DevicePosture::Compliant),
        other => {
            Err(SyncError::UnknownVariant { vocabulary: "DevicePosture", value: other.to_owned() })
        }
    }
}

/// Decodes a device row.
fn device_from_row(row: &sqlx::postgres::PgRow) -> Result<SyncDevice> {
    let posture: String = row.try_get("posture")?;
    let state: String = row.try_get("state")?;
    Ok(SyncDevice {
        tenant_id: row.try_get_id("tenant_id")?,
        device_id: row.try_get_id("device_id")?,
        user_id: row.try_get_id("user_id")?,
        name: row.try_get("name")?,
        platform: row.try_get("platform")?,
        client_version: row.try_get("client_version")?,
        posture: posture_from_str(&posture)?,
        state: state.parse::<DeviceState>()?,
        last_sync_at: row.try_get("last_sync_at")?,
        wipe_requested_at: row.try_get("wipe_requested_at")?,
        wiped_at: row.try_get("wiped_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// Decodes one feed row.
fn feed_entry_from_row(row: &sqlx::postgres::PgRow) -> Result<FeedEntry> {
    let op: String = row.try_get("op")?;
    let node_type: String = row.try_get("node_type")?;
    let deleted_at: Option<DateTime<Utc>> = row.try_get("deleted_at")?;
    let version_id: Option<VersionId> = row.try_get_opt_id("version_id")?;

    // Built together or not at all: a version id with no checksum is a row the client cannot use to
    // decide whether it already holds the bytes, and half a version is worse than none.
    let readable_version = match version_id {
        Some(id) => Some(ReadableVersion {
            id,
            size_bytes: row.try_get("version_size_bytes")?,
            checksum_sha256: row.try_get("version_checksum")?,
        }),
        None => None,
    };

    Ok(FeedEntry {
        seq: row.try_get("seq")?,
        file_id: row.try_get_id("file_id")?,
        op: op.parse::<ChangeOp>()?,
        library_id: row.try_get_id("library_id")?,
        name: row.try_get("name")?,
        parent_id: row.try_get_opt_id("parent_id")?,
        is_folder: node_type == "FOLDER",
        deleted: deleted_at.is_some(),
        modified_at: row.try_get("modified_at")?,
        readable_version,
        library_sync_enabled: row.try_get("sync_enabled")?,
    })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// `CLAUDE.md` rule 9, asserted on the *text* of the statement rather than on its behaviour.
    ///
    /// The behavioural assertion is in `crates/sync/tests/delta.rs`, which puts a `SCANNING`
    /// version in the feed and reads the tombstone back. This one catches the edit that would
    /// silently remove it: `READABLE_PREDICATE` is spliced from `crates/versions`, and a future
    /// hand-retyped copy that dropped `av_status` would still compile and still pass every test
    /// that does not have a quarantined fixture.
    #[test]
    fn the_feed_window_splices_the_one_readable_predicate() {
        assert!(
            FEED_WINDOW_SQL.contains(enclave_versions::READABLE_PREDICATE),
            "the feed's version join no longer carries the readable predicate; unscanned content \
             would be offered to a device.\n{FEED_WINDOW_SQL}"
        );
    }

    /// The window is ordered and bounded, which is what makes a cursor mean anything.
    #[test]
    fn the_feed_window_is_ordered_by_seq_and_bounded_by_the_cursor() {
        assert!(FEED_WINDOW_SQL.contains("ORDER BY cl.seq"), "an unordered window has no cursor");
        assert!(FEED_WINDOW_SQL.contains("cl.seq        > $4"), "the cursor is not applied");
        assert!(FEED_WINDOW_SQL.contains("cl.tenant_id  = $1"), "layer 1 is missing");
    }

    /// The classification walk does not stop at a permission break — `ENC-141`.
    #[test]
    fn the_label_walk_does_not_honour_inherit_permissions() {
        assert!(
            !SYNC_BLOCKED_SQL.contains("inherit_permissions"),
            "the sync_blocked walk stops at a permission break, which silently declassifies — the \
             escalation ENC-141 fixed, one control over"
        );
        assert!(
            SYNC_BLOCKED_SQL.contains("bool_or(sync_blocked)"),
            "a most-restrictive-wins obligation is being read off one label"
        );
    }
}
