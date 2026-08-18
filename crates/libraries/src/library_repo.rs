//! Creating, reading, updating and trashing libraries.
//!
//! # The workspace is established by the foreign key
//!
//! [`create`] does not `SELECT` the workspace first. The composite key
//! `(tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id)` decides, atomically with the
//! insert, that the parent exists *and* belongs to this tenant — and it keeps deciding that after
//! the row is written, which a prior read cannot. Referential-integrity checks run beneath
//! row-level security, so a workspace in another tenant is refused exactly as a fabricated id is:
//! one answer, [`LibraryError::NoSuchWorkspace`], which the API edge renders as `404`.
//!
//! [`create`]: LibraryRepository::create
//!
//! # There is no slug uniqueness here, and that is not an oversight
//!
//! `workspaces` has `uq_workspace_slug`; `libraries` has no equivalent index in
//! `docs/04-DATA-MODEL.md §7` or in migration 0004. Two live libraries in one workspace can
//! therefore hold the same slug today. This crate does **not** paper over that with a
//! read-then-write check: such a check is not a constraint — it loses the race it exists to
//! prevent, and it would advertise a guarantee the database is not making. Slugs are still folded
//! through [`normalize_slug`] on the way in and on the way out, so the day the index is added it
//! finds consistent data and can be built without a repair migration. The gap is reported for
//! amendment rather than hidden.
//!
//! # No authorization
//!
//! Nothing here reads an ACL, and `inherit_permissions` is stored and returned without being
//! interpreted (`crate::model`). The policy chain runs in the handler
//! (`plans/M1-CONTENT-CORE.md` D11).

use chrono::{DateTime, Utc};
use enclave_core::{LibraryId, TenantId, WorkspaceId};
use enclave_db::{sql, Cursor, FilterFingerprint, PageSize};
use sqlx::{PgConnection, Row as _};

use crate::error::{LibraryError, Result};
use crate::model::{Library, LibrarySettings};
use crate::normalize_slug;
use crate::row::{extensions_to_json, library_from_row};

/// Which libraries a listing should return.
///
/// The fingerprint of this value — together with the workspace it is scoped to — is bound into the
/// cursor, so a caller cannot page through one workspace's libraries and resume in another's, or
/// switch the filter halfway and silently skip rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LibraryFilter {
    /// Include trashed libraries.
    ///
    /// `false` by default: a trashed library appearing in an ordinary picker is how content that
    /// somebody removed gets written to again.
    pub include_deleted: bool,
}

impl LibraryFilter {
    /// The digest bound into this listing's cursors, for the listing scoped to `workspace`.
    ///
    /// Every field participates, and so does the workspace: two workspaces are two listings, and a
    /// cursor that crossed between them would resume at a position that means nothing in the
    /// second one.
    #[must_use]
    pub fn fingerprint(&self, workspace: WorkspaceId) -> FilterFingerprint {
        FilterFingerprint::of(&[
            "libraries.by_workspace",
            "workspace",
            &workspace.to_string(),
            "deleted",
            if self.include_deleted { "include" } else { "exclude" },
        ])
    }
}

/// One page of a library listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryPage {
    /// The libraries, in ascending id order — which, since every id is UUIDv7, is creation order.
    pub libraries: Vec<Library>,
    /// The opaque cursor for the next page, or `None` at the end of the listing.
    pub next_cursor: Option<String>,
    /// Whether another page exists (`docs/05-API.md §6` puts `hasMore` on the wire).
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageSize,
}

/// Reads and writes libraries.
///
/// Every function takes the `&mut PgConnection` a `TenantScoped` transaction derefs to, never a
/// pool (`plans/M1-CONTENT-CORE.md` D10), and every statement carries its own `tenant_id = $1`
/// predicate beside row-level security (`docs/04-DATA-MODEL.md §3`).
#[derive(Debug, Clone, Copy, Default)]
pub struct LibraryRepository;

impl LibraryRepository {
    /// Creates a library in a workspace and returns it as stored.
    ///
    /// The id is minted here — UUIDv7, so `ORDER BY id` is creation order and the cursor has a
    /// stable key. `revision` starts at 1, so the `ETag` from a create is immediately usable as an
    /// `If-Match`.
    ///
    /// # Errors
    ///
    /// [`LibraryError::NoSuchWorkspace`] if the workspace does not exist in this tenant; storage
    /// and decode failures otherwise.
    pub async fn create(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        settings: &LibrarySettings,
        now: DateTime<Utc>,
    ) -> Result<Library> {
        let id = LibraryId::new_v7();
        let row =
            bind_settings(sqlx::query(INSERT_LIBRARY).bind(sql(tenant)).bind(sql(id)), settings)
                .bind(sql(workspace))
                .bind(now)
                .fetch_one(&mut *conn)
                .await
                .map_err(parent_aware)?;
        library_from_row(&row)
    }

    /// Finds a library by id.
    ///
    /// Trashed libraries are not returned; see [`LibraryFilter::include_deleted`] for the listing
    /// that can see them.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`LibraryError::MalformedRow`] if a stored row holds a value outside
    /// the vocabulary in [`crate::model`].
    pub async fn find_by_id(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
    ) -> Result<Option<Library>> {
        let row = sqlx::query(SELECT_LIBRARY_BY_ID)
            .bind(sql(tenant))
            .bind(sql(library))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(library_from_row).transpose()
    }

    /// Lists a workspace's libraries, one page at a time.
    ///
    /// Ordered by `id`; `OFFSET` is not used, because `docs/03-LLD.md §17` prohibits it — a deep
    /// offset re-reads and discards every preceding row and shifts under concurrent inserts.
    ///
    /// This is every library in the workspace, not the ones the caller may see. Visibility is the
    /// policy chain's answer, decided before the handler reaches this crate.
    ///
    /// # Errors
    ///
    /// Storage failures, decode failures, and [`LibraryError::InvalidCursor`] if the cursor was
    /// issued for a different tenant, workspace or filter set.
    pub async fn list_by_workspace(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        filter: &LibraryFilter,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<LibraryPage> {
        let fingerprint = filter.fingerprint(workspace);
        let after = match cursor {
            Some(text) => Some(
                Cursor::<LibraryId>::decode(text, tenant, fingerprint)
                    .map_err(|_| LibraryError::InvalidCursor)?,
            ),
            None => None,
        };

        // One more row than asked for, so "is there a next page" is answered by the same query
        // rather than by a second `COUNT` — a round trip against a different snapshot.
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_LIBRARY_PAGE)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(after.map(sql))
            .bind(filter.include_deleted)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = rows.len() as i64 > limit.get();
        let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
        let libraries: Vec<Library> = kept.map(library_from_row).collect::<Result<_>>()?;

        let next_cursor = match libraries.last() {
            Some(last) if has_more => Some(Cursor::new(tenant, last.id, fingerprint).encode()),
            _ => None,
        };

        Ok(LibraryPage { libraries, next_cursor, has_more, limit })
    }

    /// Replaces a library's settings, if the caller's revision is still current.
    ///
    /// `expected_revision` is the `If-Match` value (`docs/05-API.md §9`) and the comparison is part
    /// of the `UPDATE`'s `WHERE` clause. That matters more here than almost anywhere else in the
    /// system: these settings include `inherit_permissions`, `external_sharing`, `mcp_visible` and
    /// the extension lists, so a lost update is a silent change to who can take content out of the
    /// tenant.
    ///
    /// `workspace_id` is not settable. Moving a library re-parents its ACL inheritance, which is a
    /// different operation with different audit and different consequences.
    ///
    /// `inherit_permissions` is not settable here either, and for the same kind of reason: breaking
    /// inheritance has to copy the effective entries down in the same transaction, or every
    /// ancestor `DENY` silently stops applying (`ENC-141`). Sending a value that differs from the
    /// stored one is [`LibraryError::InheritanceNotSettableHere`] rather than a quiet no-op —
    /// see `enclave_authorization::break_library_inheritance`.
    ///
    /// Returns `Ok(None)` when there is no such live library in this tenant.
    ///
    /// # Errors
    ///
    /// [`LibraryError::RevisionConflict`] when the revision has moved on — carrying the current
    /// value, with nothing written — [`LibraryError::InheritanceNotSettableHere`] when the settings
    /// would change `inherit_permissions`, and storage or decode failures.
    pub async fn update(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
        expected_revision: i64,
        settings: &LibrarySettings,
        now: DateTime<Utc>,
    ) -> Result<Option<Library>> {
        let query = sqlx::query(UPDATE_LIBRARY)
            .bind(sql(tenant))
            .bind(sql(library))
            .bind(expected_revision);
        let row = bind_settings_without_inheritance(query, settings)
            .bind(now)
            .fetch_optional(&mut *conn)
            .await?;

        match row {
            Some(row) => {
                let library = library_from_row(&row)?;
                // Refused, not ignored. A caller who sent `inherit_permissions: false` and got back
                // `200 OK` would believe the library no longer inherits — and would keep believing
                // it while the workspace's entries went on applying. Returning an error puts the
                // disagreement where the caller can see it, and rolls back the rest of their
                // settings change with it.
                if library.settings.inherit_permissions != settings.inherit_permissions {
                    return Err(LibraryError::InheritanceNotSettableHere);
                }
                Ok(Some(library))
            }
            None => match Self::current_revision(conn, tenant, library).await? {
                Some(current_revision) => Err(LibraryError::RevisionConflict { current_revision }),
                None => Ok(None),
            },
        }
    }

    /// Trashes a library.
    ///
    /// A soft delete: the row keeps its content and gains a `deleted_at`. Purging is the retention
    /// path's job.
    ///
    /// **This does not cascade**, and the omission is deliberate rather than pending. Files under
    /// the library are untouched, so a trashed library is not a read path that has been closed —
    /// which is exactly why `enclave-authorization`'s inheritance walk joins `libraries` with
    /// `deleted_at IS NULL`: content beneath a trashed library resolves to an empty chain and is
    /// refused. Cascading here would instead mean an unbounded write inside the caller's
    /// transaction.
    ///
    /// Returns `false` when there was no live library with that id in this tenant, which makes a
    /// repeated delete idempotent rather than an error.
    ///
    /// # Errors
    ///
    /// [`LibraryError::RevisionConflict`] if `expected_revision` is stale, and storage failures.
    pub async fn soft_delete(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
        expected_revision: Option<i64>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let deleted = sqlx::query(SOFT_DELETE_LIBRARY)
            .bind(sql(tenant))
            .bind(sql(library))
            .bind(expected_revision)
            .bind(now)
            .execute(&mut *conn)
            .await?
            .rows_affected()
            == 1;

        if deleted {
            // Ids only in the structured fields; no library name, which can carry organizational
            // detail (`CLAUDE.md` rule 10).
            tracing::info!(
                tenant_id = %tenant,
                library_id = %library,
                "library trashed; content beneath it stops resolving through inheritance"
            );
            return Ok(true);
        }

        match (expected_revision, Self::current_revision(conn, tenant, library).await?) {
            (Some(expected), Some(current)) if expected != current => {
                Err(LibraryError::RevisionConflict { current_revision: current })
            }
            _ => Ok(false),
        }
    }

    /// The revision of a live library, or `None` if there is not one.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn current_revision(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
    ) -> Result<Option<i64>> {
        let row = sqlx::query(SELECT_LIBRARY_REVISION)
            .bind(sql(tenant))
            .bind(sql(library))
            .fetch_optional(&mut *conn)
            .await?;
        row.map(|row| row.try_get::<i64, _>("revision")).transpose().map_err(Into::into)
    }
}

/// Binds the seventeen settings columns, in the order both statements list them.
///
/// Written once and shared by the insert and the update on purpose: with seventeen positional
/// parameters, two hand-written bind sequences would eventually differ by one, and a transposition
/// between two `BOOLEAN`s — `mcp_visible` and `sync_enabled`, say — is accepted by PostgreSQL
/// without complaint. The compiler cannot catch it; not writing it twice can.
/// The same, minus `inherit_permissions`, for the update path.
///
/// A separate function rather than a flag on [`bind_settings`] because the bind *positions* differ:
/// getting them silently out of step would write one column's value into another, and every column
/// here governs what leaves the tenant.
fn bind_settings_without_inheritance<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    settings: &'q LibrarySettings,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(&settings.name)
        .bind(normalize_slug(&settings.slug))
        .bind(settings.default_classification_id)
        .bind(settings.versioning_mode.as_str())
        .bind(settings.version_limit)
        .bind(settings.require_checkout)
        .bind(settings.require_approval)
        .bind(extensions_to_json(settings.allowed_extensions.as_ref()))
        .bind(extensions_to_json(settings.blocked_extensions.as_ref()))
        .bind(settings.max_file_size_bytes)
        .bind(settings.external_sharing.as_str())
        .bind(settings.ai_indexing_enabled)
        .bind(settings.mcp_visible)
        .bind(settings.sync_enabled)
        .bind(settings.storage_profile_id)
        .bind(settings.retention_policy_id)
}

fn bind_settings<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    settings: &'q LibrarySettings,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(&settings.name)
        .bind(normalize_slug(&settings.slug))
        .bind(settings.inherit_permissions)
        .bind(settings.default_classification_id)
        .bind(settings.versioning_mode.as_str())
        .bind(settings.version_limit)
        .bind(settings.require_checkout)
        .bind(settings.require_approval)
        .bind(extensions_to_json(settings.allowed_extensions.as_ref()))
        .bind(extensions_to_json(settings.blocked_extensions.as_ref()))
        .bind(settings.max_file_size_bytes)
        .bind(settings.external_sharing.as_str())
        .bind(settings.ai_indexing_enabled)
        .bind(settings.mcp_visible)
        .bind(settings.sync_enabled)
        .bind(settings.storage_profile_id)
        .bind(settings.retention_policy_id)
}

/// Turns the composite foreign key's refusal into the domain answer.
fn parent_aware(error: sqlx::Error) -> LibraryError {
    let is_missing_parent = error.as_database_error().is_some_and(|db| {
        db.code().as_deref() == Some("23503")
            && (db.constraint() == Some("libraries_tenant_id_workspace_id_fkey")
                || db.table() == Some("libraries"))
    });
    if is_missing_parent {
        return LibraryError::NoSuchWorkspace;
    }
    LibraryError::from(error)
}

/// The full column list, spelled once per statement because `concat!` takes only literals and
/// building SQL with `format!` on every call is the wrong trade. `crate::row`'s constant plus the
/// tests below are what keep them in agreement. Test-only, like `crate::row`'s copy: it is a
/// reference to check the literals against, not a value the queries are built from.
#[cfg(test)]
const COLUMNS: &str = "id, tenant_id, workspace_id, name, slug, inherit_permissions, \
     default_classification_id, versioning_mode, version_limit, require_checkout, \
     require_approval, allowed_extensions, blocked_extensions, max_file_size_bytes, \
     external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, storage_profile_id, \
     retention_policy_id, revision, created_at, updated_at, deleted_at";

/// Creates a library. `tenant_id` is `$1` in every statement in this crate, so a query missing the
/// isolation predicate is visible by eye.
const INSERT_LIBRARY: &str = "INSERT INTO libraries \
     (tenant_id, id, name, slug, inherit_permissions, default_classification_id, versioning_mode, \
      version_limit, require_checkout, require_approval, allowed_extensions, blocked_extensions, \
      max_file_size_bytes, external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, \
      storage_profile_id, retention_policy_id, workspace_id, revision, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
      $19, $20, 1, $21, $21) \
     RETURNING id, tenant_id, workspace_id, name, slug, inherit_permissions, \
     default_classification_id, versioning_mode, version_limit, require_checkout, \
     require_approval, allowed_extensions, blocked_extensions, max_file_size_bytes, \
     external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, storage_profile_id, \
     retention_policy_id, revision, created_at, updated_at, deleted_at";

/// One library by id.
const SELECT_LIBRARY_BY_ID: &str = "SELECT id, tenant_id, workspace_id, name, slug, \
     inherit_permissions, default_classification_id, versioning_mode, version_limit, \
     require_checkout, require_approval, allowed_extensions, blocked_extensions, \
     max_file_size_bytes, external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, \
     storage_profile_id, retention_policy_id, revision, created_at, updated_at, deleted_at \
     FROM libraries WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// One page of a workspace's libraries.
const SELECT_LIBRARY_PAGE: &str = "SELECT id, tenant_id, workspace_id, name, slug, \
     inherit_permissions, default_classification_id, versioning_mode, version_limit, \
     require_checkout, require_approval, allowed_extensions, blocked_extensions, \
     max_file_size_bytes, external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, \
     storage_profile_id, retention_policy_id, revision, created_at, updated_at, deleted_at \
     FROM libraries \
     WHERE tenant_id = $1 AND workspace_id = $2 \
       AND ($3::uuid IS NULL OR id > $3::uuid) \
       AND ($4::boolean OR deleted_at IS NULL) \
     ORDER BY id ASC \
     LIMIT $5";

/// The optimistic-concurrency update. The revision comparison is in the `WHERE` clause on purpose.
/// `inherit_permissions` is deliberately absent from the `SET` list. Flipping it to `FALSE` breaks
/// ACL inheritance, and a break that does not first materialise the effective set drops every
/// ancestor `DENY` — the `ENC-141` privilege escalation. It changes only through
/// `enclave_authorization::break_library_inheritance`, which does both halves in one transaction.
/// The column is still returned, so [`LibraryRepository::update`] can see that a caller tried.
const UPDATE_LIBRARY: &str = "UPDATE libraries \
     SET name = $4, slug = $5, default_classification_id = $6, \
         versioning_mode = $7, version_limit = $8, require_checkout = $9, require_approval = $10, \
         allowed_extensions = $11, blocked_extensions = $12, max_file_size_bytes = $13, \
         external_sharing = $14, ai_indexing_enabled = $15, mcp_visible = $16, sync_enabled = $17, \
         storage_profile_id = $18, retention_policy_id = $19, \
         revision = revision + 1, updated_at = $20 \
     WHERE tenant_id = $1 AND id = $2 AND revision = $3 AND deleted_at IS NULL \
     RETURNING id, tenant_id, workspace_id, name, slug, inherit_permissions, \
     default_classification_id, versioning_mode, version_limit, require_checkout, \
     require_approval, allowed_extensions, blocked_extensions, max_file_size_bytes, \
     external_sharing, ai_indexing_enabled, mcp_visible, sync_enabled, storage_profile_id, \
     retention_policy_id, revision, created_at, updated_at, deleted_at";

/// The soft delete. `$3` is the optional `If-Match` revision.
const SOFT_DELETE_LIBRARY: &str = "UPDATE libraries \
     SET deleted_at = $4, updated_at = $4, revision = revision + 1 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
       AND ($3::bigint IS NULL OR revision = $3::bigint)";

/// The one number an `If-Match` failure needs to report.
const SELECT_LIBRARY_REVISION: &str =
    "SELECT revision FROM libraries WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::LIBRARY_COLUMNS;

    #[test]
    fn the_select_lists_match_the_decoders_column_constant() {
        assert_eq!(COLUMNS, LIBRARY_COLUMNS, "the decoder and the queries must read one list");
        for query in [INSERT_LIBRARY, SELECT_LIBRARY_BY_ID, SELECT_LIBRARY_PAGE, UPDATE_LIBRARY] {
            assert!(query.contains(COLUMNS), "{query}");
        }
    }

    #[test]
    fn every_query_carries_the_application_tenant_predicate() {
        for query in [
            SELECT_LIBRARY_BY_ID,
            SELECT_LIBRARY_PAGE,
            UPDATE_LIBRARY,
            SOFT_DELETE_LIBRARY,
            SELECT_LIBRARY_REVISION,
        ] {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
        // The insert has no `WHERE`; its half of the rule is that it stamps `tenant_id` from `$1`.
        assert!(INSERT_LIBRARY.contains("(tenant_id, id,"), "{INSERT_LIBRARY}");
        assert!(INSERT_LIBRARY.contains("VALUES ($1,"), "{INSERT_LIBRARY}");
    }

    #[test]
    fn the_settings_binder_and_the_statements_agree_on_the_parameter_order() {
        // `bind_settings` binds seventeen values in one fixed order; both statements must list the
        // same seventeen columns in that order, or a transposition between two same-typed columns
        // is written silently. Extract the order from each statement and compare.
        let expected: Vec<&str> = vec![
            "name",
            "slug",
            "inherit_permissions",
            "default_classification_id",
            "versioning_mode",
            "version_limit",
            "require_checkout",
            "require_approval",
            "allowed_extensions",
            "blocked_extensions",
            "max_file_size_bytes",
            "external_sharing",
            "ai_indexing_enabled",
            "mcp_visible",
            "sync_enabled",
            "storage_profile_id",
            "retention_policy_id",
        ];

        // The insert lists them positionally, between `id,` and `, workspace_id`.
        let insert_columns = INSERT_LIBRARY
            .split_once("(tenant_id, id, ")
            .expect("the insert's column list")
            .1
            .split_once(", workspace_id")
            .expect("the insert's column list ends before workspace_id")
            .0;
        let listed: Vec<String> =
            insert_columns.split(',').map(|column| column.trim().to_owned()).collect();
        assert_eq!(listed, expected);

        // The update lists them as assignments, in the same order, from `$4` upward — minus
        // `inherit_permissions`, which it may not write (`ENC-141`). That one omission is the whole
        // difference between the two lists, and asserting it that way means adding a column to one
        // statement and not the other still fails here rather than at runtime with a value in the
        // wrong column.
        let expected_update: Vec<&str> =
            expected.iter().copied().filter(|column| *column != "inherit_permissions").collect();
        let assignments: Vec<String> = UPDATE_LIBRARY
            .split_once("SET ")
            .expect("the update's assignments")
            .1
            .split_once(", revision = revision + 1")
            .expect("the assignments end before the revision bump")
            .0
            .split(',')
            .map(|assignment| {
                assignment.trim().split_once(" =").expect("an assignment").0.to_owned()
            })
            .collect();
        assert_eq!(assignments, expected_update);
        assert_eq!(
            assignments.len() + 1,
            expected.len(),
            "the update writes a different number of settings than the insert, so one of them has \
             a column the other does not"
        );
    }

    #[test]
    fn the_update_cannot_write_inherit_permissions() {
        // The `ENC-141` control, asserted on the statement itself rather than only through a
        // database round trip: breaking inheritance must copy the effective ACL down in the same
        // transaction, and a settings replacement has no way to do that. If this column ever
        // returns to the `SET` list, a single `PATCH` silently drops every ancestor `DENY`.
        let assignments = UPDATE_LIBRARY
            .split_once("SET ")
            .expect("the update's assignments")
            .1
            .split_once(" WHERE ")
            .expect("the assignments end at the WHERE")
            .0;
        assert!(
            !assignments.contains("inherit_permissions"),
            "UPDATE_LIBRARY assigns inherit_permissions: {assignments}"
        );
        // Still returned, because `update` compares it to what the caller asked for and refuses
        // rather than silently ignoring them.
        assert!(UPDATE_LIBRARY.contains(
            "RETURNING id, tenant_id, workspace_id, name, slug, \
     inherit_permissions"
        ));
    }

    #[test]
    fn the_listing_never_uses_offset() {
        assert!(!SELECT_LIBRARY_PAGE.to_uppercase().contains("OFFSET"));
        assert!(SELECT_LIBRARY_PAGE.contains("ORDER BY id ASC"), "the cursor assumes this order");
        assert!(
            SELECT_LIBRARY_PAGE.contains("workspace_id = $2"),
            "a listing that lost this would return the tenant's every library"
        );
    }

    #[test]
    fn the_update_compares_the_revision_in_the_where_clause_and_increments_it() {
        assert!(UPDATE_LIBRARY.contains("revision = $3"), "the If-Match is part of the write");
        assert!(UPDATE_LIBRARY.contains("revision = revision + 1"));
        assert!(!UPDATE_LIBRARY.contains("workspace_id ="), "a library is not re-parented here");
    }

    #[test]
    fn no_write_or_read_can_reach_a_trashed_library() {
        for query in
            [SELECT_LIBRARY_BY_ID, SELECT_LIBRARY_REVISION, UPDATE_LIBRARY, SOFT_DELETE_LIBRARY]
        {
            assert!(query.contains("deleted_at IS NULL"), "{query}");
        }
        assert!(!SOFT_DELETE_LIBRARY.to_uppercase().contains("DELETE FROM"));
    }

    #[test]
    fn every_filter_field_and_the_workspace_change_the_fingerprint() {
        let workspace = WorkspaceId::new_v7();
        let other = WorkspaceId::new_v7();
        let base = LibraryFilter::default();
        let with_deleted = LibraryFilter { include_deleted: true };

        assert_ne!(base.fingerprint(workspace), with_deleted.fingerprint(workspace));
        assert_ne!(base.fingerprint(workspace), base.fingerprint(other));
        assert_eq!(base.fingerprint(workspace), LibraryFilter::default().fingerprint(workspace));
    }

    #[test]
    fn a_cursor_from_one_workspaces_listing_is_rejected_in_another() {
        let tenant = TenantId::new_v7();
        let filter = LibraryFilter::default();
        let mine = filter.fingerprint(WorkspaceId::new_v7());
        let yours = filter.fingerprint(WorkspaceId::new_v7());

        let cursor = Cursor::new(tenant, LibraryId::new_v7(), mine).encode();
        assert!(Cursor::<LibraryId>::decode(&cursor, tenant, mine).is_ok());
        assert!(Cursor::<LibraryId>::decode(&cursor, tenant, yours).is_err());
        // And not across tenants either.
        assert!(Cursor::<LibraryId>::decode(&cursor, TenantId::new_v7(), mine).is_err());
    }
}
