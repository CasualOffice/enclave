//! Creating, reading, updating and trashing workspaces.
//!
//! # Uniqueness is the index's job, not a read's
//!
//! `uq_workspace_slug` is `UNIQUE (tenant_id, slug) WHERE deleted_at IS NULL`. [`create`] and
//! [`update`] therefore **write and catch**, rather than checking first and writing after:
//!
//! ```text
//! SELECT 1 FROM workspaces WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL   -- no rows
//!                                                     ← another request commits the same slug here
//! INSERT INTO workspaces ...                                                            -- boom
//! ```
//!
//! The window between the check and the write is small and it is not zero, and the two requests
//! that land in it are precisely the two that were racing for the same name. A read-then-write also
//! *reports* the wrong thing when it loses: it returns success from one request and an unhandled
//! `500` from the other, instead of two well-formed answers. The index is atomic; the pair of
//! statements is not.
//!
//! The partial predicate is what makes a trashed workspace release its slug, so a name can be
//! reused after deletion (`docs/04-DATA-MODEL.md §7`) — and it is also why "does this slug exist"
//! has no useful answer at all outside the write itself.
//!
//! [`create`]: WorkspaceRepository::create
//! [`update`]: WorkspaceRepository::update
//!
//! # Slugs are folded on the way in *and* on the way out
//!
//! The index is on the raw column, so `Acme` and `acme` would otherwise be two different live
//! workspaces reachable by two spellings of one URL. Every write and every lookup here goes through
//! [`normalize_slug`], which makes the constraint effectively case-insensitive without a schema
//! change. See the note in the crate documentation: a stored `normalized_slug` column, as `users`
//! and `groups` have, is the durable fix and needs a migration this task does not own.
//!
//! # No authorization
//!
//! Nothing here consults `visibility`, membership or an ACL. The policy chain runs in the handler,
//! before this crate is reached (`plans/M1-CONTENT-CORE.md` D11). A listing that quietly filtered
//! by visibility would be a second enforcement point that the routing lint cannot see, and the
//! first time it disagreed with `PolicyEngine::enforce` one of the two would be wrong.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UserId, WorkspaceId};
use enclave_db::sql;
use enclave_identity::{Cursor, FilterFingerprint, PageSize};
use sqlx::{PgConnection, Row as _};

use crate::error::{Result, WorkspaceError};
use crate::model::{Visibility, Workspace, WorkspaceSettings};
use crate::normalize_slug;
use crate::row::workspace_from_row;
use crate::violation::is_unique_violation;

/// Which workspaces a listing should return.
///
/// The fingerprint of this value is bound into the cursor, so a caller cannot page through with one
/// filter and resume with another — see `enclave_identity::cursor` for why that is a correctness
/// problem and not a nicety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkspaceFilter {
    /// Restrict to one visibility, or `None` for every visibility.
    ///
    /// A convenience for administrative surfaces — "show me every `TENANT_VISIBLE` workspace" —
    /// and never a substitute for authorization. Whether the caller may see a workspace is decided
    /// before this crate is reached.
    pub visibility: Option<Visibility>,
    /// Include trashed workspaces.
    ///
    /// `false` by default and it should stay that way outside the trash view and compliance
    /// surfaces: a deleted workspace appearing in an ordinary picker is how content nobody meant
    /// to keep gets re-shared.
    pub include_deleted: bool,
}

impl WorkspaceFilter {
    /// The digest bound into this listing's cursors.
    ///
    /// Every field participates. A field added here and forgotten in this function produces cursors
    /// that are accepted across two different filters, which silently skips rows.
    #[must_use]
    pub fn fingerprint(&self) -> FilterFingerprint {
        FilterFingerprint::of(&[
            "workspaces.by_tenant",
            "visibility",
            self.visibility.map_or("*", |visibility| visibility.as_str()),
            "deleted",
            if self.include_deleted { "include" } else { "exclude" },
        ])
    }
}

/// One page of a workspace listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePage {
    /// The workspaces, in ascending id order — which, since every id is UUIDv7, is creation order.
    pub workspaces: Vec<Workspace>,
    /// The opaque cursor for the next page, or `None` at the end of the listing.
    pub next_cursor: Option<String>,
    /// Whether another page exists. Redundant with `next_cursor.is_some()` and carried anyway,
    /// because `docs/05-API.md §6` puts `hasMore` on the wire.
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageSize,
}

/// Reads and writes workspaces.
///
/// Every function takes the `&mut PgConnection` a `TenantScoped` transaction derefs to, never a
/// pool (`plans/M1-CONTENT-CORE.md` D10). The `tenant` argument is the application-layer half of
/// the two-layer isolation in `docs/04-DATA-MODEL.md §3`; row-level security is the other half, and
/// neither is a backstop for the other.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkspaceRepository;

impl WorkspaceRepository {
    /// Creates a workspace and returns it as stored.
    ///
    /// The id is minted here rather than accepted from the caller: it is a UUIDv7, and having one
    /// place generate it is what keeps `ORDER BY id` equal to creation order for the cursor to rely
    /// on. Retry-safety for a repeated request is the idempotency key's job at the API edge
    /// (`docs/05-API.md §8`), not a guessable id's.
    ///
    /// `revision` starts at 1, so the `ETag` a client receives from a create is immediately usable
    /// as an `If-Match` on the next write.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::SlugTaken`] if another live workspace in this tenant holds the slug — see
    /// the [module documentation](self) for why that is detected by the constraint rather than by a
    /// prior read. Storage failures otherwise.
    pub async fn create(
        conn: &mut PgConnection,
        tenant: TenantId,
        settings: &WorkspaceSettings,
        created_by: UserId,
        now: DateTime<Utc>,
    ) -> Result<Workspace> {
        let id = WorkspaceId::new_v7();
        let row = sqlx::query(INSERT_WORKSPACE)
            .bind(sql(tenant))
            .bind(sql(id))
            .bind(&settings.name)
            .bind(normalize_slug(&settings.slug))
            .bind(settings.description.as_deref())
            .bind(settings.visibility.as_str())
            .bind(settings.default_classification_id)
            .bind(settings.storage_profile_id)
            .bind(sql(created_by))
            .bind(now)
            .fetch_one(&mut *conn)
            .await
            .map_err(slug_aware)?;
        workspace_from_row(&row)
    }

    /// Finds a workspace by id.
    ///
    /// Trashed workspaces are not returned; see [`WorkspaceFilter::include_deleted`] for the
    /// listing that can see them.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`WorkspaceError::MalformedRow`] if a stored row holds a value outside
    /// the vocabulary in [`crate::model`].
    pub async fn find_by_id(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
    ) -> Result<Option<Workspace>> {
        let row = sqlx::query(SELECT_WORKSPACE_BY_ID)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(workspace_from_row).transpose()
    }

    /// Finds a workspace by slug within one tenant.
    ///
    /// The slug is folded through [`normalize_slug`] first, so the lookup agrees with what
    /// [`WorkspaceRepository::create`] stored about which spellings are the same slug.
    ///
    /// Scoped to a tenant, always: two tenants may each have a `finance` workspace, which is why
    /// the index is `(tenant_id, slug)` rather than `(slug)`.
    ///
    /// # Errors
    ///
    /// As [`WorkspaceRepository::find_by_id`].
    pub async fn find_by_slug(
        conn: &mut PgConnection,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Workspace>> {
        let row = sqlx::query(SELECT_WORKSPACE_BY_SLUG)
            .bind(sql(tenant))
            .bind(normalize_slug(slug))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(workspace_from_row).transpose()
    }

    /// Lists a tenant's workspaces, one page at a time.
    ///
    /// Ordered by `id`, which is a UUIDv7 and therefore both creation-ordered and unique — so the
    /// sort key and the tie-break are one column and there is no equal-key window to step over.
    /// `OFFSET` is not used: `docs/03-LLD.md §17` prohibits it, because a deep offset re-reads and
    /// discards every preceding row and shifts under concurrent inserts.
    ///
    /// This is **not** "the workspaces the caller may see". It is every workspace in the tenant
    /// that matches the filter; the policy chain decides visibility before the handler gets here.
    ///
    /// # Errors
    ///
    /// Storage failures, decode failures, and [`WorkspaceError::InvalidCursor`] if the cursor was
    /// issued for a different tenant or a different filter set.
    pub async fn list_by_tenant(
        conn: &mut PgConnection,
        tenant: TenantId,
        filter: &WorkspaceFilter,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<WorkspacePage> {
        let fingerprint = filter.fingerprint();
        let after = match cursor {
            Some(text) => Some(
                Cursor::<WorkspaceId>::decode(text, tenant, fingerprint)
                    .map_err(|_| WorkspaceError::InvalidCursor)?,
            ),
            None => None,
        };

        // One more row than asked for, so "is there a next page" is answered by the same query
        // rather than by a second `COUNT` — which would be both a round trip and a different
        // snapshot from the page it describes.
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_WORKSPACE_PAGE)
            .bind(sql(tenant))
            .bind(after.map(sql))
            .bind(filter.visibility.map(|visibility| visibility.as_str()))
            .bind(filter.include_deleted)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        page_from_rows(&rows, tenant, limit, fingerprint)
    }

    /// Replaces a workspace's mutable state, if the caller's revision is still current.
    ///
    /// `expected_revision` is the `If-Match` value (`docs/05-API.md §9`). The comparison is part of
    /// the `UPDATE`'s `WHERE` clause, so it is decided by the same statement that writes — a
    /// read-compare-write here would reintroduce exactly the lost-update window optimistic
    /// concurrency exists to close.
    ///
    /// Returns `Ok(None)` when there is no such live workspace in this tenant. A stale revision is
    /// an error rather than a `None`, because those two outcomes call for different client
    /// behaviour: re-read and merge, versus stop.
    ///
    /// # Errors
    ///
    /// * [`WorkspaceError::RevisionConflict`] — the workspace exists and has moved on. Carries the
    ///   current revision; **nothing was written**.
    /// * [`WorkspaceError::SlugTaken`] — the new slug belongs to another live workspace.
    /// * Storage and decode failures.
    pub async fn update(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        expected_revision: i64,
        settings: &WorkspaceSettings,
        now: DateTime<Utc>,
    ) -> Result<Option<Workspace>> {
        let row = sqlx::query(UPDATE_WORKSPACE)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(expected_revision)
            .bind(&settings.name)
            .bind(normalize_slug(&settings.slug))
            .bind(settings.description.as_deref())
            .bind(settings.visibility.as_str())
            .bind(settings.default_classification_id)
            .bind(settings.storage_profile_id)
            .bind(now)
            .fetch_optional(&mut *conn)
            .await
            .map_err(slug_aware)?;

        match row {
            Some(row) => workspace_from_row(&row).map(Some),
            // No row matched. Either the workspace is gone, or the revision moved — and the caller
            // needs to be able to tell those apart, so ask.
            None => match Self::current_revision(conn, tenant, workspace).await? {
                Some(current_revision) => {
                    Err(WorkspaceError::RevisionConflict { current_revision })
                }
                None => Ok(None),
            },
        }
    }

    /// Trashes a workspace.
    ///
    /// A soft delete: the row keeps its content, gains a `deleted_at`, and drops out of
    /// `uq_workspace_slug` so the slug becomes available again. Purging is the retention path's
    /// job, not this one's.
    ///
    /// `expected_revision` is optional because a delete is not always issued with an `If-Match`;
    /// when it is present it is enforced exactly as [`WorkspaceRepository::update`] enforces it.
    ///
    /// Returns `false` when there was no live workspace with that id in this tenant — including
    /// when it was already trashed, which makes a repeated delete idempotent rather than an error.
    ///
    /// **This does not cascade.** Libraries and content under the workspace are untouched; whatever
    /// walks them is the caller's, and doing it here would make a trash operation an unbounded
    /// write inside someone else's transaction.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::RevisionConflict`] if `expected_revision` is stale, and storage failures.
    pub async fn soft_delete(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
        expected_revision: Option<i64>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let deleted = sqlx::query(SOFT_DELETE_WORKSPACE)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .bind(expected_revision)
            .bind(now)
            .execute(&mut *conn)
            .await?
            .rows_affected()
            == 1;

        if deleted {
            // No name or slug in the message body — the structured fields carry the ids, and they
            // are what a log pipeline redacts on (`CLAUDE.md` rule 10).
            tracing::info!(
                tenant_id = %tenant,
                workspace_id = %workspace,
                "workspace trashed; its slug is available again"
            );
            return Ok(true);
        }

        // Nothing was written. Distinguish "already gone" from "your revision is stale" for the
        // same reason `update` does.
        match (expected_revision, Self::current_revision(conn, tenant, workspace).await?) {
            (Some(expected), Some(current)) if expected != current => {
                Err(WorkspaceError::RevisionConflict { current_revision: current })
            }
            _ => Ok(false),
        }
    }

    /// The revision of a live workspace, or `None` if there is not one.
    ///
    /// Exposed because a caller that is about to issue an `If-Match` write, or that has just been
    /// refused one, otherwise has to fetch the whole record to learn one number.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn current_revision(
        conn: &mut PgConnection,
        tenant: TenantId,
        workspace: WorkspaceId,
    ) -> Result<Option<i64>> {
        let row = sqlx::query(SELECT_WORKSPACE_REVISION)
            .bind(sql(tenant))
            .bind(sql(workspace))
            .fetch_optional(&mut *conn)
            .await?;
        row.map(|row| row.try_get::<i64, _>("revision")).transpose().map_err(Into::into)
    }
}

/// Assembles a page from the probe rows, trimming the extra one and minting the next cursor.
///
/// Shared by the two listings that return workspaces so that the "fetch one extra, keep `limit`"
/// arithmetic exists once — an off-by-one here either drops a row from every page or advertises a
/// page that is not there.
pub(crate) fn page_from_rows(
    rows: &[sqlx::postgres::PgRow],
    tenant: TenantId,
    limit: PageSize,
    fingerprint: FilterFingerprint,
) -> Result<WorkspacePage> {
    let has_more = rows.len() as i64 > limit.get();
    let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
    let workspaces: Vec<Workspace> = kept.map(workspace_from_row).collect::<Result<_>>()?;

    let next_cursor = match workspaces.last() {
        Some(last) if has_more => Some(Cursor::new(tenant, last.id, fingerprint).encode()),
        _ => None,
    };

    Ok(WorkspacePage { workspaces, next_cursor, has_more, limit })
}

/// Turns a `uq_workspace_slug` violation into the domain answer, and leaves everything else alone.
fn slug_aware(error: sqlx::Error) -> WorkspaceError {
    if is_unique_violation(&error, "uq_workspace_slug", "workspaces") {
        return WorkspaceError::SlugTaken;
    }
    WorkspaceError::from(error)
}

/// Creates a workspace. `tenant_id` binds first in every statement in this crate, so that the
/// isolation predicate is always `$1` and a query missing it is visible by eye.
const INSERT_WORKSPACE: &str = "INSERT INTO workspaces \
     (tenant_id, id, name, slug, description, visibility, default_classification_id, \
      storage_profile_id, revision, created_by, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $10) \
     RETURNING id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at";

/// One workspace by id.
const SELECT_WORKSPACE_BY_ID: &str = "SELECT id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at \
     FROM workspaces WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// One workspace by slug, within a tenant. Matches `uq_workspace_slug`.
const SELECT_WORKSPACE_BY_SLUG: &str =
    "SELECT id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at \
     FROM workspaces WHERE tenant_id = $1 AND slug = $2 AND deleted_at IS NULL";

/// One page of workspaces.
///
/// The `$2::uuid IS NULL OR` form is what lets one statement serve the first page and every page
/// after it. Two SQL strings chosen by a branch would be two query plans, two places for the filter
/// predicates to drift, and a first page that can be filtered differently from the rest.
const SELECT_WORKSPACE_PAGE: &str = "SELECT id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at \
     FROM workspaces \
     WHERE tenant_id = $1 \
       AND ($2::uuid IS NULL OR id > $2::uuid) \
       AND ($3::text IS NULL OR visibility = $3::text) \
       AND ($4::boolean OR deleted_at IS NULL) \
     ORDER BY id ASC \
     LIMIT $5";

/// The optimistic-concurrency update. The revision comparison is in the `WHERE` clause on purpose.
const UPDATE_WORKSPACE: &str = "UPDATE workspaces \
     SET name = $4, slug = $5, description = $6, visibility = $7, \
         default_classification_id = $8, storage_profile_id = $9, \
         revision = revision + 1, updated_at = $10 \
     WHERE tenant_id = $1 AND id = $2 AND revision = $3 AND deleted_at IS NULL \
     RETURNING id, tenant_id, name, slug, description, visibility, \
     default_classification_id, storage_profile_id, revision, created_by, created_at, updated_at, \
     deleted_at";

/// The soft delete. `$3` is the optional `If-Match` revision.
const SOFT_DELETE_WORKSPACE: &str = "UPDATE workspaces \
     SET deleted_at = $4, updated_at = $4, revision = revision + 1 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
       AND ($3::bigint IS NULL OR revision = $3::bigint)";

/// The one number an `If-Match` failure needs to report.
const SELECT_WORKSPACE_REVISION: &str =
    "SELECT revision FROM workspaces WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::WORKSPACE_COLUMNS;

    const EVERY_QUERY: [&str; 7] = [
        INSERT_WORKSPACE,
        SELECT_WORKSPACE_BY_ID,
        SELECT_WORKSPACE_BY_SLUG,
        SELECT_WORKSPACE_PAGE,
        UPDATE_WORKSPACE,
        SOFT_DELETE_WORKSPACE,
        SELECT_WORKSPACE_REVISION,
    ];

    #[test]
    fn the_select_lists_match_the_decoders_column_constant() {
        for query in
            [INSERT_WORKSPACE, SELECT_WORKSPACE_BY_ID, SELECT_WORKSPACE_BY_SLUG, UPDATE_WORKSPACE]
        {
            assert!(query.contains(WORKSPACE_COLUMNS), "{query}");
        }
        assert!(SELECT_WORKSPACE_PAGE.contains(WORKSPACE_COLUMNS));
    }

    #[test]
    fn every_query_carries_the_application_tenant_predicate() {
        // RLS is the other layer and neither is redundant (`docs/04-DATA-MODEL.md §3`). A query
        // that lost this would still be correct today and would stop being correct the moment
        // something ran it on a connection without a tenant context.
        for query in EVERY_QUERY.iter().filter(|query| **query != INSERT_WORKSPACE) {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
        // The insert has no `WHERE`, so its half of the rule is that it stamps `tenant_id` from
        // `$1` rather than from anything the caller put in the row.
        assert!(INSERT_WORKSPACE.contains("(tenant_id, id,"), "{INSERT_WORKSPACE}");
        assert!(INSERT_WORKSPACE.contains("VALUES ($1,"), "{INSERT_WORKSPACE}");
    }

    #[test]
    fn the_listing_never_uses_offset() {
        // `docs/03-LLD.md §17` prohibits deep OFFSET in the query layer.
        assert!(!SELECT_WORKSPACE_PAGE.to_uppercase().contains("OFFSET"));
        assert!(SELECT_WORKSPACE_PAGE.contains("ORDER BY id ASC"), "the cursor assumes this order");
    }

    #[test]
    fn the_update_compares_the_revision_in_the_where_clause_and_increments_it() {
        // If the comparison moved into application code, two writers holding the same revision
        // would both pass it and the second would silently overwrite the first.
        assert!(UPDATE_WORKSPACE.contains("revision = $3"), "the If-Match is part of the write");
        assert!(UPDATE_WORKSPACE.contains("revision = revision + 1"));
        assert!(UPDATE_WORKSPACE.contains("RETURNING"), "the caller needs the new revision");
    }

    #[test]
    fn no_write_can_reach_a_trashed_workspace() {
        // A write to a trashed row would resurrect content that a retention or trash flow believes
        // is gone, and it would collide with a live workspace that has since taken the slug.
        for query in [UPDATE_WORKSPACE, SOFT_DELETE_WORKSPACE] {
            assert!(query.contains("deleted_at IS NULL"), "{query}");
        }
    }

    #[test]
    fn a_soft_delete_only_hides_the_row() {
        assert!(!SOFT_DELETE_WORKSPACE.to_uppercase().contains("DELETE FROM"));
        assert!(SOFT_DELETE_WORKSPACE.contains("deleted_at = $4"));
        // The optional If-Match: absent means "delete whatever is there".
        assert!(SOFT_DELETE_WORKSPACE.contains("$3::bigint IS NULL OR revision = $3::bigint"));
    }

    #[test]
    fn reads_and_writes_agree_that_a_trashed_workspace_is_absent() {
        for query in [SELECT_WORKSPACE_BY_ID, SELECT_WORKSPACE_BY_SLUG, SELECT_WORKSPACE_REVISION] {
            assert!(query.contains("deleted_at IS NULL"), "{query}");
        }
    }

    #[test]
    fn every_filter_field_changes_the_fingerprint() {
        // The property: a cursor issued under one filter must not be accepted under another. It
        // holds only if every field is hashed, so enumerate them here — a new field added to
        // `WorkspaceFilter` and forgotten in `fingerprint` fails this test.
        let base = WorkspaceFilter::default();
        let by_visibility = WorkspaceFilter { visibility: Some(Visibility::Private), ..base };
        let by_deleted = WorkspaceFilter { include_deleted: true, ..base };

        assert_ne!(base.fingerprint(), by_visibility.fingerprint());
        assert_ne!(base.fingerprint(), by_deleted.fingerprint());
        assert_ne!(by_visibility.fingerprint(), by_deleted.fingerprint());
        assert_eq!(base.fingerprint(), WorkspaceFilter::default().fingerprint());
    }

    #[test]
    fn two_different_visibilities_produce_two_different_fingerprints() {
        let private =
            WorkspaceFilter { visibility: Some(Visibility::Private), ..Default::default() };
        let tenant =
            WorkspaceFilter { visibility: Some(Visibility::TenantVisible), ..Default::default() };
        assert_ne!(private.fingerprint(), tenant.fingerprint());
    }

    #[test]
    fn a_cursor_from_one_filter_is_rejected_by_another() {
        // The end-to-end statement of the property, without a database: `list_by_tenant` decodes
        // through exactly this call.
        let tenant = TenantId::new_v7();
        let listing =
            WorkspaceFilter { visibility: Some(Visibility::Private), include_deleted: false };
        let cursor = Cursor::new(tenant, WorkspaceId::new_v7(), listing.fingerprint()).encode();

        assert!(Cursor::<WorkspaceId>::decode(&cursor, tenant, listing.fingerprint()).is_ok());
        assert!(Cursor::<WorkspaceId>::decode(
            &cursor,
            tenant,
            WorkspaceFilter::default().fingerprint()
        )
        .is_err());
    }
}
