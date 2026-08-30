//! Reading version history.
//!
//! # The shape every function takes
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without `app.tenant_id`
//! established, and the `no-raw-pool` gate keeps it that way. Every statement *also* carries an
//! explicit `tenant_id = $1` predicate: that is layer 1 of `docs/04-DATA-MODEL.md §3`, and the pair
//! is what makes a leak require two independent failures rather than one.
//!
//! # Two lookups, not one
//!
//! [`VersionRepository::find`] returns a version whatever state it is in; it is what the history
//! panel and the uploader's own progress view read. [`VersionRepository::find_readable`] applies
//! [`READABLE_PREDICATE`] and is what every content path reads — preview, download, export, sync,
//! extraction. They are separate functions rather than one function with a boolean, because a
//! boolean is a thing that gets passed wrongly and `CLAUDE.md` rule 9 has no acceptable failure
//! mode (`plans/M1-CONTENT-CORE.md` D13).
//!
//! Nothing here decides *whether the caller may* read: the policy chain runs in the handler, before
//! a domain service is reached (`plans/M1-CONTENT-CORE.md` D11). What these functions decide is
//! whether the content is in a state that may be served *at all*, which is a property of the row.

use enclave_core::{FileId, TenantId, VersionId};
use enclave_db::sql;
use sqlx::PgConnection;

use enclave_db::RowIdExt as _;
use sqlx::Row as _;

use crate::error::Result;
use crate::model::{readable_predicate, FileVersion, StorageTier, VersionNumber};
use crate::row::{parse_enum, version_columns, version_from_row};

/// How many versions one page of history may hold.
///
/// A newtype rather than a bare `i64` for the usual reason — an unclamped limit is a table scan a
/// client can ask for — and *not* the opaque cursor machinery the tenant-wide listings use. Version
/// history is keyed by [`VersionNumber`], which is already unique per file, already ordered, and
/// already shown to the user; wrapping it in an encoded cursor would add a format to keep
/// compatible without adding a property the pair does not already have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageLimit(i64);

impl PageLimit {
    /// The page size used when a caller does not ask for one.
    pub const DEFAULT: Self = Self(50);
    /// The largest page this repository will serve, whatever was asked for.
    pub const MAX: i64 = 200;

    /// Clamps a requested size into range.
    ///
    /// Clamping rather than rejecting: a client asking for 10 000 versions has made a reasonable
    /// request badly, and a page of 200 with `has_more` set answers it truthfully.
    #[must_use]
    pub const fn new(requested: i64) -> Self {
        if requested < 1 {
            Self(1)
        } else if requested > Self::MAX {
            Self(Self::MAX)
        } else {
            Self(requested)
        }
    }

    /// The clamped value.
    #[must_use]
    pub const fn get(&self) -> i64 {
        self.0
    }
}

impl Default for PageLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One page of a file's version history, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionPage {
    /// The versions, newest first — the order `idx_versions_file` is built in.
    pub versions: Vec<FileVersion>,
    /// The number to pass as `before` for the next page, or `None` at the end of the history.
    pub next_before: Option<VersionNumber>,
    /// Whether another page exists. Redundant with `next_before.is_some()` and carried anyway,
    /// because `docs/05-API.md §6` puts `hasMore` on the wire and a caller should not have to infer
    /// a documented field from the absence of another one.
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageLimit,
}

/// Reads versions.
///
/// A unit-like namespace rather than a constructed service: it holds no state, and every function
/// takes the connection it must run on. Anything that could be held — a pool, a tenant — is exactly
/// what must not be captured.
#[derive(Debug, Clone, Copy, Default)]
pub struct VersionRepository;

impl VersionRepository {
    /// Finds one version of one file, in whatever state it is in.
    ///
    /// For history and for an uploader watching their own commit progress. **Not** for a content
    /// path — use [`VersionRepository::find_readable`] there.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`crate::VersionsError::MalformedRow`] if a stored row holds a value
    /// outside the vocabulary in [`crate::model`].
    pub async fn find(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        version: VersionId,
    ) -> Result<Option<FileVersion>> {
        let row = sqlx::query(SELECT_VERSION)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(sql(version))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(version_from_row).transpose()
    }

    /// Finds one version *and* asserts it may be served.
    ///
    /// Returns `None` for a version that exists but is still scanning, is quarantined, or failed —
    /// deliberately indistinguishable from one that does not exist, so a content endpoint cannot
    /// accidentally report "this exists but is infected" to someone who should only learn that
    /// nothing came back.
    ///
    /// This is the function every preview, download, export, print, sync and extraction path calls.
    /// `CLAUDE.md` rule 9 is then a property of the query rather than of remembering to check.
    ///
    /// # Errors
    ///
    /// As [`VersionRepository::find`].
    pub async fn find_readable(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        version: VersionId,
    ) -> Result<Option<FileVersion>> {
        let row = sqlx::query(SELECT_READABLE_VERSION)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(sql(version))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(version_from_row).transpose()
    }

    /// Finds the version `files.current_version_id` points at.
    ///
    /// Resolved through the `files` row rather than by taking the highest number, because those two
    /// answers differ exactly when it matters: immediately after a commit the newest version is
    /// still `SCANNING`, and `current_version_id` is the pointer the rest of the system agrees on.
    /// A trashed file has no current version as far as this is concerned.
    ///
    /// # Errors
    ///
    /// As [`VersionRepository::find`].
    pub async fn current(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<Option<FileVersion>> {
        let row = sqlx::query(SELECT_CURRENT_VERSION)
            .bind(sql(tenant))
            .bind(sql(file))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(version_from_row).transpose()
    }

    /// Lists a file's version history, newest first, one page at a time.
    ///
    /// Every version is listed, including the ones no read path will serve. That is deliberate:
    /// history is metadata, and a user who cannot see that version 3.0 exists and was quarantined
    /// is a user who reports the file as silently corrupted. What the listing must never do is hand
    /// over the content of such a version, and it does not — it returns rows, and every content
    /// path goes back through [`VersionRepository::find_readable`].
    ///
    /// Keyset paging on `(major, minor)`, never `OFFSET`: `docs/03-LLD.md §17` prohibits deep
    /// offsets, and the pair is unique per file by `uq_version_number`, so there is no equal-key
    /// window to step over.
    ///
    /// # Errors
    ///
    /// As [`VersionRepository::find`].
    pub async fn list(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        before: Option<VersionNumber>,
        limit: PageLimit,
    ) -> Result<VersionPage> {
        // One more row than asked for, so "is there a next page" is answered by the same query
        // rather than by a second `COUNT` — which would be both a round trip and a different
        // snapshot from the page it describes.
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_VERSION_PAGE)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(before.map(|number| number.major))
            .bind(before.map(|number| number.minor))
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = rows.len() as i64 > limit.get();
        let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
        let versions: Vec<FileVersion> = kept.map(version_from_row).collect::<Result<_>>()?;

        let next_before = match versions.last() {
            Some(last) if has_more => Some(last.number),
            _ => None,
        };

        Ok(VersionPage { versions, next_before, has_more, limit })
    }
    /// Marks a version as being restored from cold storage, if it is archived (`ENC-946`).
    ///
    /// Returns whether this call is the one that changed it. `false` means the version was not
    /// `ARCHIVED` when the statement ran — already restoring, already hot, or mid-archive — and the
    /// caller must **not** issue a provider retrieval on the strength of it: every restore is
    /// billed, and two callers clicking at once would otherwise pay twice for one object.
    ///
    /// The predicate names the tier it is leaving, so the check and the write are one statement.
    /// A `SELECT` then an `UPDATE` is the download-budget defect in `plans/M1-CONTENT-CORE.md` D18:
    /// under `READ COMMITTED` the loser of a race re-evaluates this `WHERE` against the updated row
    /// and matches nothing, which is what makes "exactly one caller starts the restore" a property
    /// of the database rather than of the handler's ordering.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn mark_restoring(
        conn: &mut PgConnection,
        tenant: TenantId,
        version: VersionId,
    ) -> Result<bool> {
        let changed = sqlx::query(MARK_RESTORING)
            .bind(tenant.as_uuid())
            .bind(version.as_uuid())
            .fetch_optional(&mut *conn)
            .await?;
        Ok(changed.is_some())
    }
    /// Versions mid-transition, oldest first, for the reconciler (`ENC-947`).
    ///
    /// `ARCHIVING` and `RESTORING` only — the two states that cannot resolve themselves. A
    /// `RESTORING` row whose bytes have landed stays `RESTORING` for ever without this, which makes
    /// `POST /files/{id}/rehydrate` a request that is accepted and never completes.
    ///
    /// Bounded by `limit` and ordered by `restore_requested_at NULLS FIRST` so an `ARCHIVING` row —
    /// which has no timestamp — is never starved behind a queue of restores, and so the longest
    /// wait is served first. Reads `idx_file_versions_in_transition`, the partial index
    /// `migrations/0032` added for exactly this query.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn in_transition(
        conn: &mut PgConnection,
        tenant: TenantId,
        limit: i64,
    ) -> Result<Vec<InTransition>> {
        let rows = sqlx::query(IN_TRANSITION)
            .bind(tenant.as_uuid())
            .bind(limit)
            .fetch_all(&mut *conn)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(InTransition {
                    id: row.try_get_id("id")?,
                    object_key: row.try_get("object_key")?,
                    tier: parse_enum::<StorageTier>(
                        row,
                        "storage_tier",
                        "not a known storage tier",
                    )?,
                })
            })
            .collect()
    }

    /// Records what the store actually reported, if the row still says what it said (`ENC-947`).
    ///
    /// Returns whether the row moved. `expected` is in the predicate, so a reconciler that read a
    /// row, spent a network round trip at the provider, and came back to find a user's rehydrate
    /// had changed it does **not** overwrite that: it loses, reports `false`, and picks the row up
    /// next pass with a fresh observation. A blind `UPDATE ... WHERE id = $2` would let a stale
    /// observation put an `ARCHIVED` row back over a restore somebody had just started.
    ///
    /// `restore_requested_at` is untouched. It is evidence of how long the last restore took, and
    /// the moment it becomes useful is the moment the restore completes (`migrations/0032`).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn reconcile_tier(
        conn: &mut PgConnection,
        tenant: TenantId,
        version: VersionId,
        expected: StorageTier,
        observed: StorageTier,
    ) -> Result<bool> {
        let changed = sqlx::query(RECONCILE_TIER)
            .bind(tenant.as_uuid())
            .bind(version.as_uuid())
            .bind(expected.as_str())
            .bind(observed.as_str())
            .fetch_optional(&mut *conn)
            .await?;
        Ok(changed.is_some())
    }
}

/// One version the reconciler has to resolve.
///
/// Three fields and no more: the reconciler needs an id to write back, a key to ask the store
/// about, and the tier it is leaving so the write can be conditional on it. Returning a whole
/// [`FileVersion`] would put every column of a table this pass walks in bulk onto the wire for
/// three values.
#[derive(Debug, Clone)]
pub struct InTransition {
    /// Which version.
    pub id: VersionId,
    /// The object to ask the store about.
    pub object_key: String,
    /// What the row says now, and what the reconciling write is conditional on.
    pub tier: StorageTier,
}

const IN_TRANSITION: &str = "
    SELECT id, object_key, storage_tier
      FROM file_versions
     WHERE tenant_id = $1
       AND storage_tier IN ('ARCHIVING','RESTORING')
     ORDER BY restore_requested_at ASC NULLS FIRST
     LIMIT $2";

const RECONCILE_TIER: &str = "
    UPDATE file_versions
       SET storage_tier = $4
     WHERE tenant_id = $1 AND id = $2 AND storage_tier = $3
    RETURNING id";

/// `now()` from the database's clock, not the caller's:/// `now()` from the database's clock, not the caller's: `restore_requested_at` is what a sweep
/// measures a stuck restore against, and a wall clock that disagrees with the sweep's would make
/// "waiting six hours" a number nobody can act on.
const MARK_RESTORING: &str = "
    UPDATE file_versions
       SET storage_tier = 'RESTORING', restore_requested_at = now()
     WHERE tenant_id = $1 AND id = $2 AND storage_tier = 'ARCHIVED'
    RETURNING id";

/// One version of one file. `file_id` is in the predicate as well as `id` so that a version id
/// belonging to a different file cannot be read through a URL naming this one.
const SELECT_VERSION: &str = concat!(
    "SELECT ",
    version_columns!(),
    " FROM file_versions WHERE tenant_id = $1 AND file_id = $2 AND id = $3"
);

/// The same, restricted to versions that may be served.
const SELECT_READABLE_VERSION: &str = concat!(
    "SELECT ",
    version_columns!(),
    " FROM file_versions WHERE tenant_id = $1 AND file_id = $2 AND id = $3 AND ",
    readable_predicate!()
);

/// The version the file points at. The subquery carries its own tenant predicate, because a
/// correlated read of `files` is a second table and gets the same treatment as the first.
const SELECT_CURRENT_VERSION: &str = concat!(
    "SELECT ",
    version_columns!(),
    " FROM file_versions",
    " WHERE tenant_id = $1 AND file_id = $2",
    " AND id = (SELECT current_version_id FROM files",
    " WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL)"
);

/// One page of history.
///
/// The `$3::int IS NULL OR` form is what lets one statement serve the first page and every page
/// after it. The alternative — two SQL strings chosen by a branch — is two query plans, two places
/// for the predicates to drift, and a first page that can be filtered differently from the rest
/// without anything failing.
///
/// `ROW(major, minor) < ROW($3, $4)` rather than a hand-expanded `major < $3 OR (major = $3 AND
/// minor < $4)`: the row comparison is one expression, matches `idx_versions_file`, and cannot be
/// got subtly wrong at the boundary between two major versions.
const SELECT_VERSION_PAGE: &str = concat!(
    "SELECT ",
    version_columns!(),
    " FROM file_versions",
    " WHERE tenant_id = $1 AND file_id = $2",
    " AND ($3::int IS NULL OR ROW(major, minor) < ROW($3::int, $4::int))",
    " ORDER BY major DESC, minor DESC",
    " LIMIT $5"
);

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::model::READABLE_PREDICATE;
    use crate::row::VERSION_COLUMNS;

    const ALL_QUERIES: &[&str] =
        &[SELECT_VERSION, SELECT_READABLE_VERSION, SELECT_CURRENT_VERSION, SELECT_VERSION_PAGE];

    #[test]
    fn every_query_selects_exactly_the_columns_the_decoder_reads() {
        for query in ALL_QUERIES {
            assert!(query.contains(VERSION_COLUMNS), "{query}");
        }
    }

    #[test]
    fn every_query_carries_the_application_tenant_predicate() {
        // RLS is the other layer and neither is redundant (`docs/04-DATA-MODEL.md §3`). A query
        // that lost this would still be correct today and would stop being correct the moment
        // something ran it on a connection without a tenant context.
        for query in ALL_QUERIES {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
        // Including the correlated subquery, which reads a second table.
        assert_eq!(
            SELECT_CURRENT_VERSION.matches("tenant_id = $1").count(),
            2,
            "the files subquery needs its own tenant predicate"
        );
    }

    #[test]
    fn every_lookup_is_scoped_to_its_file() {
        // A version id from another file must not resolve through a URL naming this one, even
        // within the same tenant.
        for query in ALL_QUERIES {
            assert!(query.contains("file_id = $2"), "{query}");
        }
    }

    #[test]
    fn only_the_content_lookup_filters_on_availability() {
        assert!(SELECT_READABLE_VERSION.contains(READABLE_PREDICATE));
        // And it is the *same* predicate as the Rust one, spliced from the same constant's text
        // rather than retyped — the assertion above is what proves that.
        assert!(!SELECT_VERSION.contains("av_status = 'CLEAN'"));
        assert!(!SELECT_VERSION_PAGE.contains("av_status = 'CLEAN'"));
    }

    #[test]
    fn the_listing_never_uses_offset_and_orders_the_way_the_index_does() {
        assert!(!SELECT_VERSION_PAGE.to_uppercase().contains("OFFSET"));
        assert!(SELECT_VERSION_PAGE.contains("ORDER BY major DESC, minor DESC"));
        assert!(SELECT_VERSION_PAGE.contains("ROW(major, minor) < ROW($3::int, $4::int)"));
    }

    #[test]
    fn the_page_limit_is_clamped_at_both_ends() {
        assert_eq!(PageLimit::new(0).get(), 1);
        assert_eq!(PageLimit::new(-9).get(), 1);
        assert_eq!(PageLimit::new(10).get(), 10);
        assert_eq!(PageLimit::new(10_000).get(), PageLimit::MAX);
        assert_eq!(PageLimit::default().get(), PageLimit::DEFAULT.get());
    }
}
