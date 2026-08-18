//! Where a node is: the chain from its library's root down to the node itself.
//!
//! # One statement, not one per level
//!
//! The walk is a recursive `WITH`, so a breadcrumb costs one round trip whatever the depth. The
//! obvious alternative — fetch the node, fetch its parent, repeat — is one round trip per level on
//! a path that renders on every file page and in every search result, and it reads a different
//! snapshot at each step, so a concurrent move produces a breadcrumb that never existed.
//!
//! # What a breadcrumb is not
//!
//! It is **not** a permission statement. A caller can be entitled to a file and not to its parent
//! folder, and rendering the ancestry of something they may see is not the same as granting them
//! anything about the ancestors. The policy chain decides what of this the caller is shown
//! (`docs/03-LLD.md §12`); this module answers where the node sits.
//!
//! It also does not carry the library's *name*. That column belongs to `libraries` and to the crate
//! that owns it; joining to it here would make this crate a second authority on how a library is
//! named. [`Breadcrumb::library_id`] is what a caller resolves it with.

use enclave_core::{FileId, LibraryId, TenantId, WorkspaceId};
use enclave_db::{sql, RowIdExt};
use sqlx::{PgConnection, Row as _};

use crate::error::{FilesError, Result};
use crate::model::NodeType;
use crate::repo::FileRepository;

/// How many ancestors the walk will climb before giving up.
///
/// A bound rather than an unbounded walk, because `parent_id` is the one column in this schema that
/// can express a cycle, and a recursive query over one does not terminate on its own. 128 is far
/// beyond any tree a person navigates and far below anything that costs measurable time.
///
/// **Nothing enforces this limit at creation time.** A tree deeper than this can be built, and its
/// breadcrumb then fails with [`FilesError::PathTooDeep`] rather than returning a partial path — a
/// truncated breadcrumb is a *wrong* answer about where something lives, and this one renders next
/// to permission-bearing UI. Enforcing the limit on the write path belongs with the API-level
/// validation in `ENC-133`.
pub const MAX_DEPTH: i32 = 128;

/// One node on the way down to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSegment {
    /// The node's identifier.
    pub id: FileId,
    /// Its display name.
    pub name: String,
    /// Whether it is the file at the end or a folder on the way.
    pub node_type: NodeType,
}

/// The ancestry of a node, root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breadcrumb {
    /// The library the chain belongs to.
    pub library_id: LibraryId,
    /// The workspace that library belongs to.
    pub workspace_id: WorkspaceId,
    /// Every node from the library root down to and including the node asked about.
    ///
    /// Never empty: a node that exists is its own last segment.
    pub segments: Vec<PathSegment>,
}

impl Breadcrumb {
    /// The node the breadcrumb was built for.
    #[must_use]
    pub fn node(&self) -> Option<&PathSegment> {
        self.segments.last()
    }

    /// How many folders lie above the node. Zero at the library root.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.segments.len().saturating_sub(1)
    }

    /// Renders the chain as a `/`-separated path, library-relative.
    ///
    /// Unambiguous because [`crate::normalize::validate_name`] refuses a name containing `/` or
    /// `\`. It is a *display* form: it is not an identifier, nothing resolves a node by it, and it
    /// must not be used as an object-storage key — versions are addressed by id precisely so that a
    /// rename does not move an object.
    #[must_use]
    pub fn to_path(&self) -> String {
        let mut path = String::new();
        for segment in &self.segments {
            path.push('/');
            path.push_str(&segment.name);
        }
        path
    }
}

impl FileRepository {
    /// Walks a node to its library root and returns the chain.
    ///
    /// Trashed nodes have no breadcrumb: the walk only crosses live rows, so a node in the trash —
    /// or one whose ancestor is — is reported as [`FilesError::NotFound`]. That is deliberate. A
    /// trash view shows where something *was*, which is a property of the delete operation and not
    /// of the current tree, and inventing it from a walk that steps through deleted folders would
    /// give a path that no longer leads anywhere.
    ///
    /// # Errors
    ///
    /// [`FilesError::NotFound`] if the node is gone, in the trash, another tenant's, or — the
    /// inconsistent case — live underneath an ancestor that is not. [`FilesError::PathTooDeep`] if
    /// the chain is longer than [`MAX_DEPTH`].
    pub async fn breadcrumb(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<Breadcrumb> {
        let rows = sqlx::query(SELECT_ANCESTRY)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(MAX_DEPTH)
            .fetch_all(&mut *conn)
            .await?;

        // Root first: the statement orders by descending depth, so the topmost ancestor reached is
        // the first row.
        let Some(top) = rows.first() else {
            return Err(FilesError::NotFound);
        };

        if top.try_get_opt_id::<FileId>("parent_id")?.is_some() {
            let depth: i32 = top.try_get("depth")?;
            // Either the guard stopped the climb, or the parent is not walkable — deleted, or
            // absent. The second is a node no navigation can reach, which is the same answer as
            // not existing.
            return Err(if depth >= MAX_DEPTH {
                FilesError::PathTooDeep
            } else {
                FilesError::NotFound
            });
        }

        let mut segments = Vec::with_capacity(rows.len());
        for row in &rows {
            segments.push(PathSegment {
                id: row.try_get_id("id")?,
                name: row.try_get("name")?,
                node_type: row.try_get::<String, _>("node_type")?.parse().map_err(|_| {
                    FilesError::MalformedRow {
                        column: "node_type",
                        reason: "not a known node type",
                    }
                })?,
            });
        }

        Ok(Breadcrumb {
            library_id: top.try_get_id("library_id")?,
            workspace_id: top.try_get_id("workspace_id")?,
            segments,
        })
    }
}

/// The ancestor chain of one node, deepest first in the walk and root first in the result.
///
/// `UNION ALL` is safe here and `depth` is the terminator: unlike the move guard, this walk has an
/// explicit bound, and `UNION` would hide a cycle by silently deduplicating it into a plausible
/// path. With `UNION ALL` a cycle climbs to [`MAX_DEPTH`] and is reported.
///
/// Every step re-states the tenant, so the walk cannot climb out of the tenant even where row-level
/// security is not in force, and `deleted_at IS NULL` at every step is what makes a node under a
/// trashed folder unreachable rather than reachable through the trash.
const SELECT_ANCESTRY: &str = "\
WITH RECURSIVE up AS ( \
    SELECT f.id, f.parent_id, f.name, f.node_type, f.library_id, f.workspace_id, 0 AS depth \
      FROM files f \
     WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NULL \
    UNION ALL \
    SELECT p.id, p.parent_id, p.name, p.node_type, p.library_id, p.workspace_id, u.depth + 1 \
      FROM up u \
      JOIN files p ON p.tenant_id = $1 AND p.id = u.parent_id AND p.deleted_at IS NULL \
     WHERE u.depth < $3 \
) \
SELECT id, parent_id, name, node_type, library_id, workspace_id, depth \
  FROM up \
 ORDER BY depth DESC";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn segment(name: &str, node_type: NodeType) -> PathSegment {
        PathSegment { id: FileId::new_v7(), name: name.to_owned(), node_type }
    }

    fn breadcrumb(segments: Vec<PathSegment>) -> Breadcrumb {
        Breadcrumb {
            library_id: LibraryId::new_v7(),
            workspace_id: WorkspaceId::new_v7(),
            segments,
        }
    }

    #[test]
    fn a_path_is_rendered_library_relative_and_root_first() {
        let crumb = breadcrumb(vec![
            segment("Finance", NodeType::Folder),
            segment("2026", NodeType::Folder),
            segment("Q1 Report.pdf", NodeType::File),
        ]);
        assert_eq!(crumb.to_path(), "/Finance/2026/Q1 Report.pdf");
        assert_eq!(crumb.depth(), 2);
        assert_eq!(crumb.node().map(|node| node.name.as_str()), Some("Q1 Report.pdf"));
    }

    #[test]
    fn a_node_at_the_library_root_is_its_own_only_segment() {
        let crumb = breadcrumb(vec![segment("readme.md", NodeType::File)]);
        assert_eq!(crumb.to_path(), "/readme.md");
        assert_eq!(crumb.depth(), 0);
    }

    #[test]
    fn the_walk_is_bounded_tenant_scoped_and_blind_to_the_trash() {
        // Three properties of the statement, none of which fails visibly if it is lost: an
        // unbounded walk hangs on a cycle, a missing tenant predicate climbs out of the tenant, and
        // a missing `deleted_at` filter makes a path lead through a deleted folder.
        assert!(SELECT_ANCESTRY.contains("u.depth < $3"));
        assert_eq!(SELECT_ANCESTRY.matches("tenant_id = $1").count(), 2);
        assert_eq!(SELECT_ANCESTRY.matches("deleted_at IS NULL").count(), 2);
        assert!(SELECT_ANCESTRY.contains("ORDER BY depth DESC"), "the result is root first");
    }

    #[test]
    fn the_depth_bound_is_generous_enough_to_never_be_a_product_limit() {
        // A guard a real tree can reach is a product limit nobody documented. Held as a `const`
        // assertion so lowering `MAX_DEPTH` into that territory fails to build rather than fails a
        // test run.
        const { assert!(MAX_DEPTH >= 64, "a real tree must never reach the guard") };
    }
}
