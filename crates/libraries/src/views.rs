//! Saved views: which columns a library shows, in what order, filtered and grouped how.
//!
//! # A view is an arrangement, never a permission
//!
//! This is the sentence the whole module is built around, and it is worth being precise about
//! because the shape of a view invites the opposite reading. A view carries a `filter_definition`;
//! filters select rows; selecting rows is what authorization does. It would be an easy and
//! catastrophic mistake to let one stand in for the other.
//!
//! So: a view decides **what is displayed**, and the policy chain decides **what exists** for a
//! caller. The two compose in one direction only — a view can hide a row a caller may see, and can
//! never reveal one they may not. A view whose filter names a file the caller has no grant on shows
//! them nothing, because the listing it decorates was already trimmed by
//! `PolicyEngine::enforce` before this crate is reached (`plans/M1-CONTENT-CORE.md` D11).
//!
//! Nothing here takes a `RequestContext`, resolves an ACL or reads a file row. That is not an
//! omission to be corrected later: it is what makes the direction above structural. A future
//! function here that took a caller and returned rows would be a second place that decides
//! visibility, and the ENC-110 routing lint would not see it.
//!
//! # Scope is about who may *use* a view, not what it may show
//!
//! `PERSONAL` is one person's arrangement of their own screen; the rest are shared. Migration 0010
//! makes the two structural distinctions that follow — an owner exactly when the scope is personal,
//! and a personal view never being a library's default — as `CHECK`s rather than as rules this
//! crate remembers, because imposing one person's arrangement on a whole library is a different act
//! with different permissions.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{LibraryId, TenantId, UnknownVariant, UserId, Uuid};
use serde_json::Value;
use sqlx::{PgConnection, Row as _};

use crate::error::{LibraryError, Result};

macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test can assert the Rust set against the constraint's set.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownVariant::new(stringify!($name), other)),
                }
            }
        }
    };
}

db_enum! {
    /// How the rows are laid out (`library_views.view_type`).
    ///
    /// Presentation only. None of these changes which rows are returned — a `GALLERY` of a folder
    /// and a `LIST` of it show the same files.
    pub enum ViewType {
        /// Rows, one line each.
        List => "LIST",
        /// Rows, denser.
        Compact => "COMPACT",
        /// Rows with a detail pane.
        Details => "DETAILS",
        /// A grid of tiles.
        Grid => "GRID",
        /// Cards carrying a preview.
        Cards => "CARDS",
        /// Image-first, for libraries that are mostly pictures.
        Gallery => "GALLERY",
        /// Large tiles.
        Tiles => "TILES",
        /// The folder hierarchy, expanded.
        Tree => "TREE",
        /// Ordered by time.
        Timeline => "TIMELINE",
    }
}

db_enum! {
    /// Who may use a view (`library_views.scope`).
    pub enum ViewScope {
        /// One person's own arrangement. Has an owner, and can never be a library's default.
        Personal => "PERSONAL",
        /// Everyone who can see the library.
        Library => "LIBRARY",
        /// Everyone in the workspace.
        Workspace => "WORKSPACE",
        /// Offered as a starting point across the tenant.
        TenantTemplate => "TENANT_TEMPLATE",
    }
}

/// A saved view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryView {
    /// The view's identifier.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The library it arranges. `None` when it belongs to a list instead.
    pub library_id: Option<LibraryId>,
    /// The list it arranges, for the milestone that brings lists.
    pub list_id: Option<Uuid>,
    /// What a person calls it.
    pub name: String,
    /// How the rows are laid out.
    pub view_type: ViewType,
    /// Which rows to show — of the rows the caller may already see. See the module documentation.
    pub filter_definition: Value,
    /// The order.
    pub sort_definition: Value,
    /// The grouping, if any.
    pub group_definition: Option<Value>,
    /// Which columns, in which order.
    pub visible_columns: Value,
    /// Column widths, if a person has adjusted them.
    pub column_widths: Option<Value>,
    /// Who may use it.
    pub scope: ViewScope,
    /// Whose it is — set exactly when the scope is personal.
    pub owner_id: Option<UserId>,
    /// Whether the library opens with it.
    pub is_default: bool,
    /// Who created it.
    pub created_by: UserId,
    /// When.
    pub created_at: DateTime<Utc>,
    /// When it last changed.
    pub updated_at: DateTime<Utc>,
}

/// What a caller supplies to create a view.
#[derive(Debug, Clone)]
pub struct NewLibraryView {
    /// The library it arranges.
    pub library_id: LibraryId,
    /// What a person calls it.
    pub name: String,
    /// How the rows are laid out.
    pub view_type: ViewType,
    /// Which rows to show.
    pub filter_definition: Value,
    /// The order.
    pub sort_definition: Value,
    /// The grouping, if any.
    pub group_definition: Option<Value>,
    /// Which columns.
    pub visible_columns: Value,
    /// Column widths.
    pub column_widths: Option<Value>,
    /// Who may use it.
    pub scope: ViewScope,
    /// Whose it is — must be `Some` exactly when `scope` is `Personal`, which the database enforces.
    pub owner_id: Option<UserId>,
    /// Whether the library opens with it.
    pub is_default: bool,
    /// Who is creating it.
    pub created_by: UserId,
}

/// Reads and writes saved views.
#[derive(Debug, Clone, Copy)]
pub struct ViewRepository;

impl ViewRepository {
    /// Stores a view.
    ///
    /// The three invariants migration 0010 carries as `CHECK`s — one container, an owner exactly
    /// when personal, a personal view never default — are not re-checked here. A constraint
    /// violation surfaces as a storage failure naming the constraint, which is a better error than
    /// a duplicate rule in Rust that can drift from the one the database actually applies.
    ///
    /// # Errors
    ///
    /// Storage failures, including the constraint violations above.
    pub async fn create(
        conn: &mut PgConnection,
        tenant: TenantId,
        new: &NewLibraryView,
        now: DateTime<Utc>,
    ) -> Result<LibraryView> {
        let row = sqlx::query(CREATE_SQL)
            .bind(Uuid::now_v7())
            .bind(tenant.as_uuid())
            .bind(new.library_id.as_uuid())
            .bind(&new.name)
            .bind(new.view_type.as_str())
            .bind(&new.filter_definition)
            .bind(&new.sort_definition)
            .bind(new.group_definition.as_ref())
            .bind(&new.visible_columns)
            .bind(new.column_widths.as_ref())
            .bind(new.scope.as_str())
            .bind(new.owner_id.map(|owner| owner.as_uuid()))
            .bind(new.is_default)
            .bind(new.created_by.as_uuid())
            .bind(now)
            .fetch_one(&mut *conn)
            .await?;
        view_from_row(&row)
    }

    /// Every view a caller may use in one library: the shared ones, plus their own.
    ///
    /// The `owner` filter is about *whose arrangement* this is, not about permission. A caller who
    /// may not see the library sees nothing here either — not because of this predicate, but
    /// because the handler ran the policy chain before reaching this crate.
    ///
    /// # Errors
    ///
    /// Storage failures and unreadable rows.
    pub async fn list_for_library(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
        owner: UserId,
    ) -> Result<Vec<LibraryView>> {
        let rows = sqlx::query(LIST_SQL)
            .bind(tenant.as_uuid())
            .bind(library.as_uuid())
            .bind(owner.as_uuid())
            .fetch_all(&mut *conn)
            .await?;
        rows.iter().map(view_from_row).collect()
    }

    /// Makes one view the library's default, and unmakes the previous one.
    ///
    /// Returns whether a view was promoted; `false` means there is no such promotable view in this
    /// library — it does not exist, belongs elsewhere, or is somebody's personal arrangement.
    ///
    /// # The order, and the check that has to come before it
    ///
    /// Promotability is confirmed **first**, and that is not defensive tidiness. The first version
    /// of this cleared the existing default and then attempted the promotion, so a refused
    /// promotion left the library with *no* default at all — it opened to nothing, and the caller
    /// was told `false` as though nothing had happened. A test asking for a personal view to be
    /// promoted found it.
    ///
    /// Given a promotable target, the demote-then-promote order is forced: `uq_view_default`
    /// permits one default per library, so promoting first violates it. Both writes are in the
    /// caller's transaction, so the window in which the library has no default does not exist
    /// outside it.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn set_default(
        conn: &mut PgConnection,
        tenant: TenantId,
        library: LibraryId,
        view: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let promotable: Option<i32> = sqlx::query_scalar(PROMOTABLE_SQL)
            .bind(tenant.as_uuid())
            .bind(library.as_uuid())
            .bind(view)
            .fetch_optional(&mut *conn)
            .await?;
        if promotable.is_none() {
            return Ok(false);
        }

        sqlx::query(CLEAR_DEFAULT_SQL)
            .bind(tenant.as_uuid())
            .bind(library.as_uuid())
            .bind(now)
            .execute(&mut *conn)
            .await?;

        let promoted = sqlx::query(SET_DEFAULT_SQL)
            .bind(tenant.as_uuid())
            .bind(library.as_uuid())
            .bind(view)
            .bind(now)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        Ok(promoted > 0)
    }

    /// Removes a view.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub async fn delete(conn: &mut PgConnection, tenant: TenantId, view: Uuid) -> Result<bool> {
        let removed = sqlx::query(DELETE_SQL)
            .bind(tenant.as_uuid())
            .bind(view)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        Ok(removed > 0)
    }
}

fn view_from_row(row: &sqlx::postgres::PgRow) -> Result<LibraryView> {
    fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
        row: &'r sqlx::postgres::PgRow,
        name: &'static str,
    ) -> Result<T> {
        row.try_get(name).map_err(|_| LibraryError::MalformedRow {
            column: name,
            reason: "missing or of an unexpected type",
        })
    }
    fn parse<T: core::str::FromStr>(raw: &str, column: &'static str) -> Result<T> {
        raw.parse().map_err(|_| LibraryError::MalformedRow {
            column,
            reason: "not a value this crate knows",
        })
    }

    let view_type: String = column(row, "view_type")?;
    let scope: String = column(row, "scope")?;

    Ok(LibraryView {
        id: column(row, "id")?,
        tenant_id: TenantId::from(column::<Uuid>(row, "tenant_id")?),
        library_id: column::<Option<Uuid>>(row, "library_id")?.map(LibraryId::from),
        list_id: column(row, "list_id")?,
        name: column(row, "name")?,
        view_type: parse(&view_type, "view_type")?,
        filter_definition: column(row, "filter_definition")?,
        sort_definition: column(row, "sort_definition")?,
        group_definition: column(row, "group_definition")?,
        visible_columns: column(row, "visible_columns")?,
        column_widths: column(row, "column_widths")?,
        scope: parse(&scope, "scope")?,
        owner_id: column::<Option<Uuid>>(row, "owner_id")?.map(UserId::from),
        is_default: column(row, "is_default")?,
        created_by: UserId::from(column::<Uuid>(row, "created_by")?),
        created_at: column(row, "created_at")?,
        updated_at: column(row, "updated_at")?,
    })
}

macro_rules! view_columns {
    () => {
        "id, tenant_id, library_id, list_id, name, view_type, filter_definition, \
         sort_definition, group_definition, visible_columns, column_widths, scope, owner_id, \
         is_default, created_by, created_at, updated_at"
    };
}

const CREATE_SQL: &str = concat!(
    "INSERT INTO library_views
        (id, tenant_id, library_id, name, view_type, filter_definition, sort_definition,
         group_definition, visible_columns, column_widths, scope, owner_id, is_default,
         created_by, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)
     RETURNING ",
    view_columns!()
);

/// Shared views, plus this caller's own personal ones — and nobody else's personal ones.
///
/// A personal view is somebody's arrangement of their own screen, and listing another person's
/// would leak what they choose to look at: which columns they watch, which filter they saved. Small
/// on its own, and exactly the sort of thing an information barrier exists to stop leaking between
/// two people who must not know what the other is working on (`docs/06 §14`).
const LIST_SQL: &str = concat!(
    "SELECT ",
    view_columns!(),
    " FROM library_views
      WHERE tenant_id = $1 AND library_id = $2
        AND (scope <> 'PERSONAL' OR owner_id = $3)
      ORDER BY is_default DESC, name ASC"
);

/// Whether this view can be a library's default at all.
///
/// `scope <> 'PERSONAL'` here rather than only in the `CHECK`: the constraint would refuse the
/// promotion anyway, but as a constraint violation — an error shaped like a bug, raised *after* the
/// existing default had already been cleared.
const PROMOTABLE_SQL: &str = "
SELECT 1 FROM library_views
 WHERE tenant_id = $1 AND library_id = $2 AND id = $3 AND scope <> 'PERSONAL'
";

const CLEAR_DEFAULT_SQL: &str = "
UPDATE library_views
   SET is_default = FALSE, updated_at = $3
 WHERE tenant_id = $1 AND library_id = $2 AND is_default
";

const SET_DEFAULT_SQL: &str = "
UPDATE library_views
   SET is_default = TRUE, updated_at = $4
 WHERE tenant_id = $1 AND library_id = $2 AND id = $3 AND scope <> 'PERSONAL'
";

const DELETE_SQL: &str = "DELETE FROM library_views WHERE tenant_id = $1 AND id = $2";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_vocabulary_matches_its_check_constraint() {
        let migration = include_str!("../../../migrations/0010_library_views.sql");

        for (needle, variants) in [
            // Keyed on the constraint's opening rather than on the whole declaration, so that
            // re-indenting the migration cannot silently stop this test finding anything — which
            // would leave it passing while checking nothing.
            (
                "CHECK (view_type IN (",
                ViewType::all().iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            ),
            ("CHECK (scope IN (", ViewScope::all().iter().map(|v| v.as_str()).collect::<Vec<_>>()),
        ] {
            let clause = migration
                .split_once(needle)
                .unwrap_or_else(|| panic!("constraint not found: {needle}"))
                .1
                .split_once(')')
                .expect("closing paren")
                .0;
            for variant in &variants {
                assert!(clause.contains(&format!("'{variant}'")), "`{variant}` is missing");
            }
            assert_eq!(
                clause.matches('\'').count() / 2,
                variants.len(),
                "the constraint permits a value this crate cannot name: {clause}"
            );
        }
    }

    #[test]
    fn the_listing_never_returns_another_persons_personal_view() {
        // Asserted on the statement, because the predicate *is* the control. A personal view is
        // somebody's arrangement of their own screen, and listing another person's leaks which
        // columns they watch and which filter they saved.
        assert!(
            LIST_SQL.contains("scope <> 'PERSONAL' OR owner_id = $3"),
            "the listing lost its owner predicate: {LIST_SQL}"
        );
    }

    #[test]
    fn nothing_here_can_widen_what_a_caller_sees() {
        // The module's central claim, asserted the only way a unit test can: no statement in this
        // module reads a content table. A view arranges rows the chain already admitted; a query
        // here that joined `files` would be a second place deciding visibility, and the ENC-110
        // routing lint does not look inside a domain crate.
        for statement in [CREATE_SQL, LIST_SQL, CLEAR_DEFAULT_SQL, SET_DEFAULT_SQL, DELETE_SQL] {
            for table in ["files", "file_versions", "acl_entries", "share_links"] {
                assert!(
                    !statement.contains(table),
                    "a view statement reads `{table}`, which makes this crate a second answer to \
                     what a caller may see: {statement}"
                );
            }
        }
    }
}
