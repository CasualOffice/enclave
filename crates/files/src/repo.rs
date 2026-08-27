//! The metadata tree: creating nodes, listing them, renaming, moving, and the trash.
//!
//! # The shape every function takes
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without `app.tenant_id`
//! established. Every statement *also* carries an explicit `tenant_id = $1` predicate: that is
//! layer 1 of `docs/04-DATA-MODEL.md §3`, and the pair is what makes a leak require two independent
//! failures rather than one.
//!
//! # Nothing here decides anything
//!
//! No permission is read and no policy is evaluated. The chain runs in the handler, before a domain
//! service is reached (`plans/M1-CONTENT-CORE.md` D11); a repository that started making decisions
//! would be a second, unlinted enforcement point. What this module *does* enforce is structural
//! integrity — a parent that is a folder, a library that a move cannot leave, a tree that cannot
//! contain a cycle — because those are properties of the data, and the database is the only place
//! they can be guaranteed under concurrency.
//!
//! # Constraints do the checking, not reads
//!
//! Three invariants are enforced by the statement itself rather than by a preceding `SELECT`:
//!
//! * **Sibling name uniqueness** — by `uq_files_sibling_name` (`docs/04-DATA-MODEL.md §8`). A
//!   read-then-write leaves a window in which a concurrent create takes the name, and the whole
//!   point of a unique index is that there is no such window. The violation is mapped to
//!   [`FilesError::NameTaken`] by this module's `classify`.
//! * **A parent that exists, is a folder, and is not in the trash** — by making the `INSERT` an
//!   `INSERT … SELECT` over the parent row. Zero rows selected means zero rows inserted, and
//!   `workspace_id` and `library_id` are copied from the parent rather than taken from the caller,
//!   so a child in a different library than its parent is not merely rejected but unrepresentable.
//! * **No cycles** — by a recursive `WITH` in the `UPDATE`'s own `WHERE` clause. Walking the
//!   ancestry in Rust and then issuing the move is the same read-then-write window: two concurrent
//!   moves can each observe an acyclic tree and together produce a cycle.
//!
//! # Optimistic concurrency
//!
//! Every mutation takes a [`Mutation`] carrying the caller's `If-Match` revision
//! (`docs/03-LLD.md §14`). The check is a predicate in the `UPDATE`, never a preceding read, for
//! the same reason. When a statement matches nothing, a *diagnosis* read then decides which of
//! "gone", "stale" or "structurally refused" to report — on the failure path only, and best-effort:
//! the tree can change again between the write and the diagnosis, and the answer is an error
//! message rather than a decision.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId};
use enclave_db::sql;
use enclave_db::{Cursor, FilterFingerprint, PageSize};
use sqlx::error::ErrorKind;
use sqlx::PgConnection;

use crate::error::{FilesError, Result};
use crate::model::{FileNode, NodeStatus, NodeType};
use crate::normalize::{display_name, normalize_name, validate_name};
use crate::row::node_from_row;

/// The media type stored for a folder.
///
/// `files.mime_type` is `NOT NULL` with no default, so a folder needs *something*, and inventing a
/// private spelling would mean every consumer learning it. `inode/directory` is what
/// freedesktop.org's shared MIME database uses for a directory, which makes it the value a
/// synchronization client, a preview service and a desktop file manager already recognise.
pub const FOLDER_MIME_TYPE: &str = "inode/directory";

/// The unique index that decides whether a name is free (`migrations/0005_files.sql`).
///
/// Named here so [`classify`] maps *that* violation, and not any other unique violation, onto
/// [`FilesError::NameTaken`]. A primary-key collision is a UUIDv7 accident and must not be reported
/// to a user as "pick another name".
const SIBLING_NAME_INDEX: &str = "uq_files_sibling_name";

/// Where a node sits: at a library's root, or inside a folder.
///
/// One type for both because every operation that takes a parent has to answer the same question,
/// and `Option<FileId>` cannot: a `None` parent still needs a library, and the library is not
/// derivable from the absent folder. Making the root case carry its [`LibraryId`] is what lets
/// `workspace_id` and `library_id` be read from the database in both cases rather than trusted from
/// the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parent {
    /// The library's root. The node's `parent_id` is `NULL`.
    Library(LibraryId),
    /// A folder within a library.
    Folder(FileId),
}

/// A new file node: metadata only, with no content yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFile {
    /// The id the node will carry.
    ///
    /// Supplied rather than minted here, because on the one path that creates a file with content
    /// the id is **already spent**. `enclave_uploads::StagedObject` allocates a [`FileId`] when the
    /// session is created and stages the bytes straight to
    /// `tenant/{t}/files/{f}/versions/{v}` (`docs/02-HLD.md §7`), so that a commit is an `INSERT`
    /// rather than a 5 GB server-side copy. A node minted with a fresh id here would leave that
    /// object key naming a file that does not exist — the key cannot be rewritten without copying
    /// the bytes, which is the whole thing the staging layout exists to avoid (`ENC-691`).
    ///
    /// A caller with no id to honour passes [`FileId::new_v7`]. It is a field rather than a
    /// defaulted argument so that every call site states which of the two it is: an id that is
    /// silently regenerated is the failure this exists to make visible.
    pub id: FileId,
    /// Where it goes.
    pub parent: Parent,
    /// The name as the user typed it.
    pub name: String,
    /// The declared media type. Not sniffed here and not trusted downstream — the antivirus and
    /// preview paths determine the real type (`ENC-132`).
    pub mime_type: String,
    /// Who is creating it.
    pub created_by: UserId,
}

/// A new folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFolder {
    /// Where it goes.
    pub parent: Parent,
    /// The name as the user typed it.
    pub name: String,
    /// Who is creating it.
    pub created_by: UserId,
}

/// The three things every mutation needs beyond its own arguments.
///
/// Grouped rather than passed loose so that adding a fourth — an idempotency key, say — is one
/// change instead of six, and so that a call site cannot silently transpose two arguments of the
/// same type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mutation {
    /// Who is making the change. Becomes `modified_by`.
    pub actor: UserId,
    /// The revision the caller believes it holds (`If-Match`), or `None` to write unconditionally.
    ///
    /// `None` is for server-initiated maintenance, not for handlers: a user-facing write that skips
    /// this silently overwrites whatever changed in between (`docs/03-LLD.md §14`).
    pub expected_revision: Option<i64>,
    /// The instant recorded as `modified_at`. Supplied rather than taken from the clock here, so
    /// that one logical operation timestamps every row it touches identically — which is what
    /// makes a cascaded trash restorable as a unit.
    pub at: DateTime<Utc>,
}

/// Which children a listing should return.
///
/// The fingerprint of this value *and of the parent* is bound into the cursor, so a caller cannot
/// page through one folder with one filter and resume in another folder or with another filter —
/// which would silently skip rows rather than fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChildFilter {
    /// Restrict to files or to folders, or `None` for both.
    pub node_type: Option<NodeType>,
    /// Include nodes in the trash.
    ///
    /// `false` by default and it should stay that way outside a trash view: a trashed file
    /// appearing in an ordinary listing is how a deleted document gets re-shared.
    pub include_trashed: bool,
}

impl ChildFilter {
    /// The digest bound into this listing's cursors.
    ///
    /// The parent participates as well as the filter fields. A cursor is a position in *a* listing,
    /// and "the children of folder A" and "the children of folder B" are two listings; without the
    /// parent in the digest, a cursor from one is accepted by the other and every child of B whose
    /// id sorts below the position is skipped.
    #[must_use]
    pub fn fingerprint(&self, parent: Parent) -> FilterFingerprint {
        let (scope, id) = match parent {
            Parent::Library(library) => ("library", library.to_string()),
            Parent::Folder(folder) => ("folder", folder.to_string()),
        };
        FilterFingerprint::of(&[
            "scope",
            scope,
            &id,
            "type",
            self.node_type.map_or("*", |node_type| node_type.as_str()),
            "trashed",
            if self.include_trashed { "include" } else { "exclude" },
        ])
    }
}

/// One page of a child listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePage {
    /// The nodes, in ascending id order — which, since every id is UUIDv7, is creation order.
    pub nodes: Vec<FileNode>,
    /// The opaque cursor for the next page, or `None` at the end of the listing.
    pub next_cursor: Option<String>,
    /// Whether another page exists. Redundant with `next_cursor.is_some()` and carried anyway,
    /// because `docs/05-API.md §6` puts `hasMore` on the wire.
    pub has_more: bool,
    /// The size actually used, after clamping.
    pub limit: PageSize,
}

/// Reads and writes the file tree.
///
/// Stateless: every function takes the connection it runs on. See the [module
/// documentation](self) for why that connection is never a pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileRepository;

impl FileRepository {
    /// Creates a folder.
    ///
    /// The folder is [`NodeStatus::Available`] immediately. A folder has no content, so there is
    /// nothing for antivirus to clear and nothing that rule 9 could be about; leaving it
    /// `PROCESSING` would hide it from every listing forever.
    ///
    /// # Errors
    ///
    /// [`FilesError::InvalidName`] before any statement runs; [`FilesError::ParentNotFound`] if the
    /// parent does not exist, is not a folder, is in the trash, or belongs to another tenant;
    /// [`FilesError::NameTaken`] if a live sibling already holds the folded name.
    pub async fn create_folder(
        conn: &mut PgConnection,
        tenant: TenantId,
        folder: &NewFolder,
        now: DateTime<Utc>,
    ) -> Result<FileNode> {
        Self::insert(
            conn,
            tenant,
            // A folder has no staged object and therefore no id to honour.
            FileId::new_v7(),
            folder.parent,
            &folder.name,
            FOLDER_MIME_TYPE,
            NodeType::Folder,
            NodeStatus::Available,
            folder.created_by,
            now,
        )
        .await
    }

    /// Creates a file node — the metadata row, with no version behind it.
    ///
    /// **The node is created [`NodeStatus::Processing`], not `AVAILABLE`.** It has no content yet:
    /// `current_version_id` is `NULL` and `size_bytes` is `0`. `CLAUDE.md` rule 9 says nothing is
    /// `AVAILABLE` before antivirus completes, and a node that announced availability while
    /// holding nothing would be a read path serving unscanned content the moment the first version
    /// landed. The transition to `AVAILABLE` belongs to the upload-commit and antivirus paths
    /// (`ENC-131`, `ENC-132`), which are also the only places that can honestly make it — so until
    /// they exist, no file node in this system reaches `AVAILABLE`, and that is the intended
    /// direction to be wrong in.
    ///
    /// The node carries [`NewFile::id`], which the caller chose — see that field for why the
    /// upload path has no freedom here.
    ///
    /// # Errors
    ///
    /// As [`FileRepository::create_folder`].
    pub async fn create_file(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: &NewFile,
        now: DateTime<Utc>,
    ) -> Result<FileNode> {
        Self::insert(
            conn,
            tenant,
            file.id,
            file.parent,
            &file.name,
            &file.mime_type,
            NodeType::File,
            NodeStatus::Processing,
            file.created_by,
            now,
        )
        .await
    }

    /// Finds a live node by id. Trashed nodes are not returned.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`FilesError::MalformedRow`] if a stored row holds a value outside the
    /// vocabulary in [`crate::model`].
    pub async fn find_by_id(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<Option<FileNode>> {
        let row = sqlx::query(SELECT_NODE_BY_ID)
            .bind(sql(tenant))
            .bind(sql(file))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(node_from_row).transpose()
    }

    /// Finds a node by id whether or not it is in the trash.
    ///
    /// Separate from [`FileRepository::find_by_id`] rather than a flag on it, because every read
    /// path should have to say out loud that it wants trashed rows. This one exists for the trash
    /// view, for restore, and for the diagnosis of a write that matched nothing.
    ///
    /// # Errors
    ///
    /// As [`FileRepository::find_by_id`].
    pub async fn find_including_trashed(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<Option<FileNode>> {
        let row = sqlx::query(SELECT_NODE_BY_ID_ANY_STATE)
            .bind(sql(tenant))
            .bind(sql(file))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(node_from_row).transpose()
    }

    /// Lists the children of a folder or of a library root, one page at a time.
    ///
    /// Ordered by `id`, which is a UUIDv7 and therefore both creation-ordered and unique — so the
    /// sort key and the tie-break are one column and there is no equal-key window to step over.
    /// `OFFSET` is not used: `docs/03-LLD.md §17` prohibits it.
    ///
    /// **Name ordering is not offered here.** A file explorer wants `ORDER BY normalized_name`, and
    /// a cursor over a non-unique sort key needs the key *and* a tie-break in the cursor;
    /// [`Cursor`] carries one identifier. Adding the second column is `ENC-133`'s to do, in the
    /// read-path task that also owns the API contract for sorting.
    ///
    /// # Errors
    ///
    /// Storage failures, decode failures, and [`FilesError::InvalidCursor`] if the cursor was
    /// issued for a different tenant, a different parent or a different filter set.
    pub async fn list_children(
        conn: &mut PgConnection,
        tenant: TenantId,
        parent: Parent,
        filter: &ChildFilter,
        limit: PageSize,
        cursor: Option<&str>,
    ) -> Result<FilePage> {
        let fingerprint = filter.fingerprint(parent);
        let after = match cursor {
            Some(text) => Some(
                Cursor::<FileId>::decode(text, tenant, fingerprint)
                    .map_err(|_| FilesError::InvalidCursor)?,
            ),
            None => None,
        };

        let (library, folder) = match parent {
            Parent::Library(library) => (Some(library), None),
            Parent::Folder(folder) => (None, Some(folder)),
        };

        // One more row than asked for, so "is there a next page" is answered by the same query
        // rather than by a second `COUNT` — which would be both a round trip and a different
        // snapshot from the page it describes.
        let probe = limit.get().saturating_add(1);

        let rows = sqlx::query(SELECT_CHILDREN_PAGE)
            .bind(sql(tenant))
            .bind(library.map(sql))
            .bind(folder.map(sql))
            .bind(after.map(sql))
            .bind(filter.node_type.map(|node_type| node_type.as_str()))
            .bind(filter.include_trashed)
            .bind(probe)
            .fetch_all(&mut *conn)
            .await?;

        let has_more = rows.len() as i64 > limit.get();
        let kept = rows.iter().take(usize::try_from(limit.get()).unwrap_or(usize::MAX));
        let nodes: Vec<FileNode> = kept.map(node_from_row).collect::<Result<_>>()?;

        let next_cursor = match nodes.last() {
            Some(last) if has_more => Some(Cursor::new(tenant, last.id, fingerprint).encode()),
            _ => None,
        };

        Ok(FilePage { nodes, next_cursor, has_more, limit })
    }

    /// Renames a node in place.
    ///
    /// # Errors
    ///
    /// [`FilesError::InvalidName`]; [`FilesError::NameTaken`] if a live sibling holds the folded
    /// name; [`FilesError::NotFound`] if the node is gone, in the trash, or another tenant's;
    /// [`FilesError::Conflict`] if `expected_revision` is stale.
    pub async fn rename(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        new_name: &str,
        change: &Mutation,
    ) -> Result<FileNode> {
        validate_name(new_name)?;

        let row = sqlx::query(RENAME_NODE)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(display_name(new_name))
            .bind(normalize_name(new_name))
            .bind(sql(change.actor))
            .bind(change.at)
            .bind(change.expected_revision)
            .fetch_optional(&mut *conn)
            .await
            .map_err(classify)?;

        match row {
            Some(row) => node_from_row(&row),
            None => Err(Self::diagnose_write(conn, tenant, file, change).await?),
        }
    }

    /// Moves a node to a new parent within the same library.
    ///
    /// A move to [`Parent::Library`] puts the node at the library root; the library must be the one
    /// it already belongs to. See [`FilesError::CrossLibraryMove`] for why crossing is refused
    /// rather than implemented.
    ///
    /// The cycle guard is part of the `UPDATE` (see the [module documentation](self)); it rejects
    /// moving a folder into itself or into any of its own descendants.
    ///
    /// # Errors
    ///
    /// [`FilesError::NotFound`], [`FilesError::Conflict`], [`FilesError::ParentNotFound`],
    /// [`FilesError::CrossLibraryMove`], [`FilesError::CycleDetected`], and
    /// [`FilesError::NameTaken`] if the destination already holds the node's name.
    pub async fn reparent(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        new_parent: Parent,
        change: &Mutation,
    ) -> Result<FileNode> {
        let query = match new_parent {
            Parent::Library(library) => sqlx::query(MOVE_TO_LIBRARY_ROOT)
                .bind(sql(tenant))
                .bind(sql(file))
                .bind(sql(library)),
            Parent::Folder(folder) => {
                sqlx::query(MOVE_INTO_FOLDER).bind(sql(tenant)).bind(sql(file)).bind(sql(folder))
            }
        };

        let row = query
            .bind(sql(change.actor))
            .bind(change.at)
            .bind(change.expected_revision)
            .fetch_optional(&mut *conn)
            .await
            .map_err(classify)?;

        match row {
            Some(row) => node_from_row(&row),
            None => Err(Self::diagnose_move(conn, tenant, file, new_parent, change).await?),
        }
    }

    /// Moves a node, and everything under it, to the trash.
    ///
    /// A soft delete: `deleted_at` and `purge_after` are set, the rows stay, and nothing is
    /// destroyed (`docs/03-LLD.md §18`). Permanent deletion is [`crate::purge`], which is not
    /// implemented and says why.
    ///
    /// **The whole subtree goes, with one identical `deleted_at`.** Trashing only the folder would
    /// leave its children live: still counted, still listed by any query that filters on
    /// `library_id` rather than walking, and — because the ACL walk stops at a deleted ancestor —
    /// no longer resolvable to a permission. The shared timestamp is also what makes the operation
    /// reversible: [`FileRepository::restore`] restores exactly the nodes that were trashed
    /// *together with* this one, and leaves alone anything that was already in the trash for its
    /// own reasons.
    ///
    /// `purge_after` is supplied by the caller rather than computed here. How long the trash keeps
    /// something is a tenant retention setting, and `plans/M1-CONTENT-CORE.md` Q7 has not been
    /// answered; a default invented in a repository would become the answer by accident.
    ///
    /// Returns every node moved to the trash, the addressed one first — the caller needs the whole
    /// set for audit and for search-index invalidation (`docs/07-SEARCH-INDEXING.md §6`).
    ///
    /// # The storage quota, on both sides
    ///
    /// **Nothing here reads the quota and nothing here releases it** (`ENC-589`,
    /// `plans/M4-GOVERNANCE.md` D31).
    ///
    /// Not read, because a tenant over its limit that cannot delete cannot get back under it —
    /// which turns a billing control into a hostage situation. A `UPDATE files SET deleted_at`
    /// bounded by a quota is the shortest way to build one.
    ///
    /// Not released, because this destroys nothing. The bytes behind every version of every node
    /// in the subtree are still in object storage and still being paid for, and
    /// `enclave_db`'s reconciliation counts versions of soft-deleted files for exactly that reason.
    /// Releasing here would under-count by the size of the recycle bin, and the nightly job would
    /// report the difference as drift in the write path. The release belongs to [`crate::purge`].
    ///
    /// # Errors
    ///
    /// [`FilesError::NotFound`] if the node is gone, already in the trash, or another tenant's;
    /// [`FilesError::Conflict`] if `expected_revision` is stale.
    pub async fn trash(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        purge_after: DateTime<Utc>,
        change: &Mutation,
    ) -> Result<Vec<FileNode>> {
        let rows = sqlx::query(TRASH_SUBTREE)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(change.at)
            .bind(purge_after)
            .bind(sql(change.actor))
            .bind(change.expected_revision)
            .fetch_all(&mut *conn)
            .await
            .map_err(classify)?;

        if rows.is_empty() {
            return Err(Self::diagnose_write(conn, tenant, file, change).await?);
        }

        let trashed = Self::collect_subtree(&rows, file)?;
        // Counts and ids only. Never the name — that is content (`CLAUDE.md` rule 10).
        tracing::info!(
            tenant_id = %tenant,
            file_id = %file,
            nodes = trashed.len(),
            "subtree moved to the trash"
        );
        Ok(trashed)
    }

    /// Restores a node, and the subtree that was trashed with it, from the trash.
    ///
    /// Only descendants whose `deleted_at` equals this node's are restored — that is, exactly the
    /// ones the same [`FileRepository::trash`] call put there. A child deleted separately, before
    /// its parent was, stays deleted, which is what its own delete meant. The discriminator is
    /// exact rather than heuristic because the trash write stamps one timestamp across the subtree;
    /// two independent deletes colliding on the same microsecond would merge, and that is the
    /// residual imprecision.
    ///
    /// The node's parent must be live. Restoring into a trashed folder would produce a live node
    /// inside a deleted one: absent from every listing, and unresolvable by the ACL walk, which
    /// stops at a deleted ancestor.
    ///
    /// Returns every node restored, the addressed one first.
    ///
    /// # Errors
    ///
    /// [`FilesError::NotFound`] if the node is gone, not in the trash, or another tenant's;
    /// [`FilesError::Conflict`] if `expected_revision` is stale; [`FilesError::ParentInTrash`];
    /// [`FilesError::NameTaken`] if the name was taken by a sibling while the node was in the
    /// trash — the unique index ignores trashed rows, so this is expected rather than exceptional
    /// and the caller should offer a rename.
    pub async fn restore(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        change: &Mutation,
    ) -> Result<Vec<FileNode>> {
        let rows = sqlx::query(RESTORE_SUBTREE)
            .bind(sql(tenant))
            .bind(sql(file))
            .bind(sql(change.actor))
            .bind(change.at)
            .bind(change.expected_revision)
            .fetch_all(&mut *conn)
            .await
            .map_err(classify)?;

        if rows.is_empty() {
            return Err(Self::diagnose_restore(conn, tenant, file, change).await?);
        }

        let restored = Self::collect_subtree(&rows, file)?;
        tracing::info!(
            tenant_id = %tenant,
            file_id = %file,
            nodes = restored.len(),
            "subtree restored from the trash"
        );
        Ok(restored)
    }

    /// The one `INSERT` behind both constructors.
    ///
    /// Two statements, not one, because the two parents are different relations: a root node's
    /// `workspace_id` comes from `libraries`, a child's from its parent row. Both derive those
    /// columns from the database, so neither trusts the caller for them.
    #[allow(clippy::too_many_arguments)]
    async fn insert(
        conn: &mut PgConnection,
        tenant: TenantId,
        id: FileId,
        parent: Parent,
        name: &str,
        mime_type: &str,
        node_type: NodeType,
        status: NodeStatus,
        created_by: UserId,
        now: DateTime<Utc>,
    ) -> Result<FileNode> {
        validate_name(name)?;

        let query = match parent {
            Parent::Library(library) => sqlx::query(CREATE_AT_LIBRARY_ROOT)
                .bind(sql(tenant))
                .bind(sql(id))
                .bind(sql(library)),
            Parent::Folder(folder) => {
                sqlx::query(CREATE_IN_FOLDER).bind(sql(tenant)).bind(sql(id)).bind(sql(folder))
            }
        };

        let row = query
            .bind(node_type.as_str())
            .bind(display_name(name))
            .bind(normalize_name(name))
            .bind(mime_type)
            .bind(status.as_str())
            .bind(sql(created_by))
            .bind(now)
            .fetch_optional(&mut *conn)
            .await
            .map_err(classify)?;

        // Zero rows means the `SELECT` feeding the `INSERT` found no parent: absent, in the trash,
        // not a folder, or another tenant's. All four are one answer (`CLAUDE.md` rule 7).
        row.as_ref().map(node_from_row).transpose()?.ok_or(FilesError::ParentNotFound)
    }

    /// Decodes the rows a subtree write returned, addressed node first.
    ///
    /// `UPDATE … RETURNING` has no `ORDER BY`, and the caller should not have to search a vector
    /// for the node it named.
    fn collect_subtree(rows: &[sqlx::postgres::PgRow], root: FileId) -> Result<Vec<FileNode>> {
        let mut nodes: Vec<FileNode> = rows.iter().map(node_from_row).collect::<Result<_>>()?;
        root_first(&mut nodes, root);
        Ok(nodes)
    }

    /// Decides what to report when a single-row write matched nothing.
    ///
    /// Failure path only. Best effort by construction: the row can change again between the write
    /// and this read, so the outcome is a message, never a decision.
    async fn diagnose_write(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        change: &Mutation,
    ) -> Result<FilesError> {
        let node = Self::find_including_trashed(conn, tenant, file).await?;
        Ok(Self::stale_or_gone(node.as_ref(), change, |node| !node.is_trashed()))
    }

    /// As [`FileRepository::diagnose_write`], for a restore, whose preconditions are the mirror
    /// image: the node must be *in* the trash, and its parent must not be.
    async fn diagnose_restore(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        change: &Mutation,
    ) -> Result<FilesError> {
        let Some(node) = Self::find_including_trashed(conn, tenant, file).await? else {
            return Ok(FilesError::NotFound);
        };
        // A node that is not in the trash has nothing to restore, and saying so as `NotFound`
        // keeps a restore from becoming a way to ask whether an id exists.
        let staleness = Self::stale_or_gone(Some(&node), change, FileNode::is_trashed);
        if !matches!(staleness, FilesError::NotFound) || !node.is_trashed() {
            return Ok(staleness);
        }

        match node.parent_id {
            Some(parent) if Self::find_by_id(conn, tenant, parent).await?.is_none() => {
                Ok(FilesError::ParentInTrash)
            }
            _ => Ok(FilesError::NotFound),
        }
    }

    /// Decides what to report when a move matched nothing.
    ///
    /// The order matters, and it is the order of the `UPDATE`'s own predicates: existence, then
    /// revision, then the destination, then the library, and a cycle by elimination. The last step
    /// is sound because the statement's `WHERE` enumerates exactly these conditions — if every
    /// other one holds, the guard that refused is the recursive one.
    async fn diagnose_move(
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
        new_parent: Parent,
        change: &Mutation,
    ) -> Result<FilesError> {
        let node = Self::find_including_trashed(conn, tenant, file).await?;
        let staleness = Self::stale_or_gone(node.as_ref(), change, |node| !node.is_trashed());
        let Some(node) = node.filter(|node| !node.is_trashed()) else {
            return Ok(staleness);
        };
        if !matches!(staleness, FilesError::NotFound) {
            return Ok(staleness);
        }

        match new_parent {
            Parent::Library(library) if library != node.library_id => {
                Ok(FilesError::CrossLibraryMove)
            }
            Parent::Library(_) => Ok(FilesError::NotFound),
            Parent::Folder(target) => match Self::find_by_id(conn, tenant, target).await? {
                None => Ok(FilesError::ParentNotFound),
                Some(target) if !target.is_folder() => Ok(FilesError::ParentNotFound),
                Some(target) if target.library_id != node.library_id => {
                    Ok(FilesError::CrossLibraryMove)
                }
                Some(_) => Ok(FilesError::CycleDetected),
            },
        }
    }

    /// "Gone", "stale", or neither, for a node a write did not match.
    ///
    /// `usable` is the state the write required — live for a rename, trashed for a restore. A node
    /// in the wrong state is reported as absent rather than as a distinct condition, so that a
    /// write cannot be used to probe for the existence of an id.
    fn stale_or_gone(
        node: Option<&FileNode>,
        change: &Mutation,
        usable: impl Fn(&FileNode) -> bool,
    ) -> FilesError {
        match node {
            None => FilesError::NotFound,
            Some(node) if !usable(node) => FilesError::NotFound,
            Some(node) => match change.expected_revision {
                Some(expected) if expected != node.revision => {
                    FilesError::Conflict { current_revision: node.revision }
                }
                _ => FilesError::NotFound,
            },
        }
    }
}

/// Moves the addressed node to the front of a subtree result.
///
/// Separate from the decoding so that the promise in the doc comments — "the addressed one first" —
/// is a property a test can hold, rather than three lines inside an async function that only runs
/// with a database.
fn root_first(nodes: &mut [FileNode], root: FileId) {
    if let Some(index) = nodes.iter().position(|node| node.id == root) {
        nodes.swap(0, index);
    }
}

/// Turns the constraint violations this crate has a domain answer for into domain errors.
///
/// Everything else keeps its [`enclave_db::DbError`] classification. Two are mapped:
///
/// * a unique violation on [`SIBLING_NAME_INDEX`] — the name is taken. Checked by *name*, because
///   the other unique constraints on `files` are the primary key and `(tenant_id, id)`, and a
///   collision on either is a UUIDv7 accident that must not be reported as "pick another name".
/// * a foreign-key violation — the only foreign keys on `files` are to `libraries` and to the
///   parent row, so this is a parent that vanished between the `SELECT` feeding the `INSERT` and
///   the write.
fn classify(error: sqlx::Error) -> FilesError {
    if let Some(db) = error.as_database_error() {
        match db.kind() {
            ErrorKind::UniqueViolation if db.constraint() == Some(SIBLING_NAME_INDEX) => {
                return FilesError::NameTaken;
            }
            ErrorKind::ForeignKeyViolation => return FilesError::ParentNotFound,
            _ => {}
        }
    }
    FilesError::from(error)
}

/// A new node at a library's root.
///
/// `workspace_id` and `library_id` come from the `libraries` row, never from the caller: a node
/// whose `workspace_id` disagreed with its library's would resolve its ACL against the wrong
/// workspace. Zero rows — no such library, or it is deleted, or it is another tenant's — inserts
/// nothing.
const CREATE_AT_LIBRARY_ROOT: &str = "\
INSERT INTO files (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, \
     normalized_name, mime_type, status, created_by, modified_by, created_at, modified_at) \
SELECT $2, $1, l.workspace_id, l.id, NULL, $4, $5, $6, $7, $8, $9, $9, $10, $10 \
  FROM libraries l \
 WHERE l.tenant_id = $1 AND l.id = $3 AND l.deleted_at IS NULL \
RETURNING files.id, files.tenant_id, files.workspace_id, files.library_id, files.parent_id, \
     files.node_type, files.name, files.normalized_name, files.mime_type, \
     files.current_version_id, files.size_bytes, files.inherit_permissions, files.revision, \
     files.acl_revision, files.is_record, files.on_legal_hold, files.status, files.created_by, \
     files.modified_by, files.created_at, files.modified_at, files.deleted_at, files.purge_after";

/// A new node inside a folder.
///
/// The `WHERE` is the parent check: exists, is a folder, is not in the trash, is this tenant's.
/// `workspace_id` and `library_id` are copied from it, which makes a child in a different library
/// than its parent unrepresentable rather than merely rejected.
const CREATE_IN_FOLDER: &str = "\
INSERT INTO files (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, \
     normalized_name, mime_type, status, created_by, modified_by, created_at, modified_at) \
SELECT $2, $1, p.workspace_id, p.library_id, p.id, $4, $5, $6, $7, $8, $9, $9, $10, $10 \
  FROM files p \
 WHERE p.tenant_id = $1 AND p.id = $3 AND p.node_type = 'FOLDER' AND p.deleted_at IS NULL \
RETURNING files.id, files.tenant_id, files.workspace_id, files.library_id, files.parent_id, \
     files.node_type, files.name, files.normalized_name, files.mime_type, \
     files.current_version_id, files.size_bytes, files.inherit_permissions, files.revision, \
     files.acl_revision, files.is_record, files.on_legal_hold, files.status, files.created_by, \
     files.modified_by, files.created_at, files.modified_at, files.deleted_at, files.purge_after";

/// One live node by id.
const SELECT_NODE_BY_ID: &str = "SELECT id, tenant_id, workspace_id, library_id, parent_id, \
     node_type, name, normalized_name, mime_type, current_version_id, size_bytes, \
     inherit_permissions, revision, acl_revision, is_record, on_legal_hold, status, created_by, \
     modified_by, created_at, modified_at, deleted_at, purge_after \
     FROM files WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// One node by id, trashed or not.
const SELECT_NODE_BY_ID_ANY_STATE: &str = "SELECT id, tenant_id, workspace_id, library_id, \
     parent_id, node_type, name, normalized_name, mime_type, current_version_id, size_bytes, \
     inherit_permissions, revision, acl_revision, is_record, on_legal_hold, status, created_by, \
     modified_by, created_at, modified_at, deleted_at, purge_after \
     FROM files WHERE tenant_id = $1 AND id = $2";

/// One page of children.
///
/// The `$n::type IS NULL OR` form is what lets one statement serve the first page and every page
/// after it, and a library root as well as a folder. The alternative — SQL strings chosen by a
/// branch — is several query plans and several places for the filter predicates to drift, with a
/// first page that can be filtered differently from the rest without anything failing.
///
/// The parent predicate is written as two branches rather than `IS NOT DISTINCT FROM` so that both
/// remain index-scannable on `idx_files_parent`: a NULL-valued parameter compared with
/// `IS NOT DISTINCT FROM` is not.
const SELECT_CHILDREN_PAGE: &str = "SELECT id, tenant_id, workspace_id, library_id, parent_id, \
     node_type, name, normalized_name, mime_type, current_version_id, size_bytes, \
     inherit_permissions, revision, acl_revision, is_record, on_legal_hold, status, created_by, \
     modified_by, created_at, modified_at, deleted_at, purge_after \
     FROM files \
     WHERE tenant_id = $1 \
       AND ($2::uuid IS NULL OR library_id = $2::uuid) \
       AND (($3::uuid IS NULL AND parent_id IS NULL) OR parent_id = $3::uuid) \
       AND ($4::uuid IS NULL OR id > $4::uuid) \
       AND ($5::text IS NULL OR node_type = $5::text) \
       AND ($6::boolean OR deleted_at IS NULL) \
     ORDER BY id ASC \
     LIMIT $7";

/// Renames in place. The unique index decides whether the new name is free.
const RENAME_NODE: &str = "UPDATE files \
     SET name = $3, normalized_name = $4, revision = revision + 1, modified_by = $5, \
         modified_at = $6 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
       AND ($7::bigint IS NULL OR revision = $7::bigint) \
     RETURNING id, tenant_id, workspace_id, library_id, parent_id, node_type, name, \
         normalized_name, mime_type, current_version_id, size_bytes, inherit_permissions, \
         revision, acl_revision, is_record, on_legal_hold, status, created_by, modified_by, \
         created_at, modified_at, deleted_at, purge_after";

/// Moves a node under a folder, refusing a cycle in the same statement.
///
/// `ancestry` walks *up* from the destination. If the node being moved appears anywhere in that
/// chain — including as the destination itself — the move would make it its own ancestor. Walking
/// up is bounded by the tree's depth; walking the moved node's descendants down would be bounded by
/// its size, which is the larger number in every realistic case.
///
/// `UNION`, not `UNION ALL`: a cycle already present in the data collapses instead of recurring
/// forever. The recursion reads the pre-statement snapshot of `files`, so it cannot see its own
/// update.
const MOVE_INTO_FOLDER: &str = "\
WITH RECURSIVE \
node AS ( \
    SELECT library_id FROM files \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
), \
target AS ( \
    SELECT id, parent_id, library_id FROM files \
     WHERE tenant_id = $1 AND id = $3 AND node_type = 'FOLDER' AND deleted_at IS NULL \
), \
ancestry AS ( \
    SELECT t.id, t.parent_id FROM target t \
    UNION \
    SELECT p.id, p.parent_id FROM ancestry a \
      JOIN files p ON p.tenant_id = $1 AND p.id = a.parent_id \
) \
UPDATE files \
   SET parent_id = $3, revision = revision + 1, modified_by = $4, modified_at = $5 \
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
   AND ($6::bigint IS NULL OR revision = $6::bigint) \
   AND EXISTS (SELECT 1 FROM target t JOIN node n ON n.library_id = t.library_id) \
   AND NOT EXISTS (SELECT 1 FROM ancestry WHERE ancestry.id = $2) \
RETURNING id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name, \
     mime_type, current_version_id, size_bytes, inherit_permissions, revision, acl_revision, \
     is_record, on_legal_hold, status, created_by, modified_by, created_at, modified_at, \
     deleted_at, purge_after";

/// Moves a node to its library's root. No cycle is possible; the library must be its own.
const MOVE_TO_LIBRARY_ROOT: &str = "UPDATE files \
     SET parent_id = NULL, revision = revision + 1, modified_by = $4, modified_at = $5 \
     WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND library_id = $3 \
       AND ($6::bigint IS NULL OR revision = $6::bigint) \
     RETURNING id, tenant_id, workspace_id, library_id, parent_id, node_type, name, \
         normalized_name, mime_type, current_version_id, size_bytes, inherit_permissions, \
         revision, acl_revision, is_record, on_legal_hold, status, created_by, modified_by, \
         created_at, modified_at, deleted_at, purge_after";

/// Soft-deletes a node and every live descendant, stamping one `deleted_at` across all of them.
///
/// The revision check applies to the addressed node only. A caller holds an `If-Match` for the
/// thing it asked to delete, not for every descendant, and requiring one for the subtree would make
/// deleting a folder impossible while anything inside it was being edited.
const TRASH_SUBTREE: &str = "\
WITH RECURSIVE subtree AS ( \
    SELECT f.id FROM files f \
     WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NULL \
       AND ($6::bigint IS NULL OR f.revision = $6::bigint) \
    UNION \
    SELECT c.id FROM subtree s \
      JOIN files c ON c.tenant_id = $1 AND c.parent_id = s.id AND c.deleted_at IS NULL \
) \
UPDATE files \
   SET deleted_at = $3, purge_after = $4, revision = revision + 1, modified_by = $5, \
       modified_at = $3 \
 WHERE tenant_id = $1 AND id IN (SELECT id FROM subtree) \
RETURNING id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name, \
     mime_type, current_version_id, size_bytes, inherit_permissions, revision, acl_revision, \
     is_record, on_legal_hold, status, created_by, modified_by, created_at, modified_at, \
     deleted_at, purge_after";

/// Restores a node and exactly the descendants that were trashed with it.
///
/// `c.deleted_at = s.deleted_at` is the discriminator: the trash write stamps one timestamp across
/// the subtree, so equality selects that operation's rows and nothing else. The seed row also
/// requires a live parent — a restore into a trashed folder produces a node no listing can reach.
const RESTORE_SUBTREE: &str = "\
WITH RECURSIVE subtree AS ( \
    SELECT f.id, f.deleted_at FROM files f \
     WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NOT NULL \
       AND ($5::bigint IS NULL OR f.revision = $5::bigint) \
       AND (f.parent_id IS NULL \
            OR EXISTS (SELECT 1 FROM files p \
                        WHERE p.tenant_id = $1 AND p.id = f.parent_id \
                          AND p.deleted_at IS NULL)) \
    UNION \
    SELECT c.id, c.deleted_at FROM subtree s \
      JOIN files c ON c.tenant_id = $1 AND c.parent_id = s.id AND c.deleted_at = s.deleted_at \
) \
UPDATE files \
   SET deleted_at = NULL, purge_after = NULL, revision = revision + 1, modified_by = $3, \
       modified_at = $4 \
 WHERE tenant_id = $1 AND id IN (SELECT id FROM subtree) \
RETURNING id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name, \
     mime_type, current_version_id, size_bytes, inherit_permissions, revision, acl_revision, \
     is_record, on_legal_hold, status, created_by, modified_by, created_at, modified_at, \
     deleted_at, purge_after";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::WorkspaceId;

    use super::*;
    use crate::row::{NODE_COLUMNS, NODE_COLUMNS_QUALIFIED};

    /// Every statement in this module.
    const EVERY_QUERY: [&str; 10] = [
        CREATE_AT_LIBRARY_ROOT,
        CREATE_IN_FOLDER,
        SELECT_NODE_BY_ID,
        SELECT_NODE_BY_ID_ANY_STATE,
        SELECT_CHILDREN_PAGE,
        RENAME_NODE,
        MOVE_INTO_FOLDER,
        MOVE_TO_LIBRARY_ROOT,
        TRASH_SUBTREE,
        RESTORE_SUBTREE,
    ];

    /// Collapses whitespace, so a comparison is about the columns rather than about where a Rust
    /// string literal happened to be wrapped.
    fn squash(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn every_statement_returns_the_columns_the_decoder_reads() {
        // The failure this catches is invisible until the statement runs: a `RETURNING` list one
        // column short is a `ColumnNotFound` from `node_from_row`, on whichever path was written
        // last.
        for query in EVERY_QUERY {
            let squashed = squash(query);
            assert!(
                squashed.contains(&squash(NODE_COLUMNS))
                    || squashed.contains(&squash(NODE_COLUMNS_QUALIFIED)),
                "{query}"
            );
        }
    }

    #[test]
    fn every_statement_carries_the_application_tenant_predicate() {
        // Row-level security is the other layer and neither is redundant
        // (`docs/04-DATA-MODEL.md §3`). A statement that lost this would still be correct today and
        // would stop being correct the moment something ran it without a tenant context.
        for query in EVERY_QUERY {
            assert!(query.contains("tenant_id = $1"), "{query}");
        }
    }

    #[test]
    fn no_write_can_reach_another_tenants_row_through_a_join() {
        // Every recursive step and every subquery re-states the tenant, so a walk cannot climb out
        // of the tenant even if row-level security were not in force.
        for query in [MOVE_INTO_FOLDER, TRASH_SUBTREE, RESTORE_SUBTREE] {
            let joins = query.matches("JOIN files").count();
            let predicates = query.matches("tenant_id = $1").count();
            assert!(
                predicates > joins,
                "a join in this statement has no tenant predicate:\n{query}"
            );
        }
    }

    #[test]
    fn the_listing_never_uses_offset_and_orders_by_the_cursor_key() {
        // `docs/03-LLD.md §17` prohibits deep OFFSET in the query layer.
        assert!(!SELECT_CHILDREN_PAGE.to_uppercase().contains("OFFSET"));
        assert!(SELECT_CHILDREN_PAGE.contains("ORDER BY id ASC"), "the cursor assumes this order");
    }

    #[test]
    fn the_trash_write_is_a_soft_delete_and_never_a_delete() {
        // The property `docs/03-LLD.md §18` turns on: user deletion never destroys a row. A
        // `DELETE` appearing in this crate at all is the thing to catch.
        for query in EVERY_QUERY {
            assert!(!query.contains("DELETE FROM"), "{query}");
            assert!(!query.contains("TRUNCATE"), "{query}");
        }
        assert!(TRASH_SUBTREE.contains("deleted_at = $3"));
        assert!(TRASH_SUBTREE.contains("purge_after = $4"));
        assert!(RESTORE_SUBTREE.contains("deleted_at = NULL"));
        assert!(RESTORE_SUBTREE.contains("purge_after = NULL"), "a restored node is not scheduled");
    }

    #[test]
    fn the_move_refuses_a_cycle_in_the_statement_rather_than_in_rust() {
        // Two concurrent moves can each observe an acyclic tree and together produce a cycle. Only
        // a guard inside the write can prevent that.
        assert!(MOVE_INTO_FOLDER.contains("WITH RECURSIVE"));
        assert!(
            MOVE_INTO_FOLDER.contains("NOT EXISTS (SELECT 1 FROM ancestry WHERE ancestry.id = $2)")
        );
        assert!(
            !MOVE_INTO_FOLDER.contains("UNION ALL"),
            "UNION ALL would recur forever on a cycle already in the data"
        );
    }

    #[test]
    fn every_mutation_bumps_the_revision_and_records_the_actor() {
        for query in [RENAME_NODE, MOVE_INTO_FOLDER, MOVE_TO_LIBRARY_ROOT, TRASH_SUBTREE] {
            assert!(query.contains("revision = revision + 1"), "{query}");
            assert!(query.contains("modified_by = $"), "{query}");
        }
        assert!(RESTORE_SUBTREE.contains("revision = revision + 1"));
    }

    #[test]
    fn every_single_row_mutation_honours_if_match() {
        // `docs/03-LLD.md §14`: a stale write is a 409, and the check is a predicate in the write
        // rather than a preceding read, or it is not a check at all.
        for query in [RENAME_NODE, MOVE_INTO_FOLDER, MOVE_TO_LIBRARY_ROOT] {
            assert!(query.contains("IS NULL OR revision = $"), "{query}");
        }
        assert!(TRASH_SUBTREE.contains("IS NULL OR f.revision = $6::bigint"));
        assert!(RESTORE_SUBTREE.contains("IS NULL OR f.revision = $5::bigint"));
    }

    #[test]
    fn a_created_node_takes_its_library_and_workspace_from_the_database() {
        // The caller supplies a parent; it does not supply `workspace_id`. A node whose workspace
        // disagreed with its library's would resolve its ACL against the wrong workspace.
        assert!(CREATE_AT_LIBRARY_ROOT.contains("l.workspace_id, l.id"));
        assert!(CREATE_IN_FOLDER.contains("p.workspace_id, p.library_id, p.id"));
        assert!(
            CREATE_IN_FOLDER.contains("p.node_type = 'FOLDER'"),
            "only a folder may be a parent"
        );
        assert!(CREATE_IN_FOLDER.contains("p.deleted_at IS NULL"), "no creating inside the trash");
    }

    #[test]
    fn nothing_folds_a_name_in_sql() {
        // `crates/files/src/normalize.rs` explains why: `lower()` is collation-dependent, and the
        // collation belongs to the database rather than to the code.
        for query in EVERY_QUERY {
            assert!(!query.to_lowercase().contains("lower("), "{query}");
            assert!(!query.to_lowercase().contains("normalize("), "{query}");
        }
    }

    #[test]
    fn a_folder_is_created_available_and_a_file_is_not() {
        // `CLAUDE.md` rule 9. Asserted on the constants the two constructors pass, because the
        // statement itself only sees a bound parameter.
        assert_eq!(NodeStatus::Available.as_str(), "AVAILABLE");
        assert_eq!(NodeStatus::Processing.as_str(), "PROCESSING");
        assert_eq!(FOLDER_MIME_TYPE, "inode/directory");
    }

    #[test]
    fn every_listing_dimension_changes_the_cursor_fingerprint() {
        // The property: a cursor issued for one listing must not be accepted by another. It holds
        // only if every dimension is hashed — including the parent, which is not a field of the
        // filter. A field added to `ChildFilter` and forgotten in `fingerprint` fails this test.
        let folder = Parent::Folder(FileId::new_v7());
        let other_folder = Parent::Folder(FileId::new_v7());
        let library = Parent::Library(LibraryId::new_v7());
        let base = ChildFilter::default();

        assert_eq!(base.fingerprint(folder), base.fingerprint(folder));
        assert_ne!(base.fingerprint(folder), base.fingerprint(other_folder));
        assert_ne!(base.fingerprint(folder), base.fingerprint(library));
        assert_ne!(
            base.fingerprint(folder),
            ChildFilter { node_type: Some(NodeType::File), ..base }.fingerprint(folder)
        );
        assert_ne!(
            base.fingerprint(folder),
            ChildFilter { include_trashed: true, ..base }.fingerprint(folder)
        );
        assert_ne!(
            ChildFilter { node_type: Some(NodeType::File), ..base }.fingerprint(folder),
            ChildFilter { node_type: Some(NodeType::Folder), ..base }.fingerprint(folder)
        );
    }

    #[test]
    fn a_library_and_a_folder_with_the_same_uuid_are_different_listings() {
        // `LibraryId` and `FileId` are different types but the same 16 bytes. Without the scope
        // label in the digest, a cursor from a library-root listing would be accepted by a folder
        // listing whose folder happened to share the id.
        let raw = FileId::new_v7();
        let folder = Parent::Folder(raw);
        let library = Parent::Library(LibraryId::from_uuid(raw.as_uuid()));
        assert_ne!(
            ChildFilter::default().fingerprint(folder),
            ChildFilter::default().fingerprint(library)
        );
    }

    #[test]
    fn a_cursor_from_one_folder_is_rejected_by_another() {
        // The end-to-end statement of the property, without a database: `list_children` decodes
        // through exactly this call.
        let tenant = TenantId::new_v7();
        let here = Parent::Folder(FileId::new_v7());
        let there = Parent::Folder(FileId::new_v7());
        let filter = ChildFilter::default();
        let cursor = Cursor::new(tenant, FileId::new_v7(), filter.fingerprint(here)).encode();

        assert!(Cursor::<FileId>::decode(&cursor, tenant, filter.fingerprint(here)).is_ok());
        assert!(Cursor::<FileId>::decode(&cursor, tenant, filter.fingerprint(there)).is_err());
        assert!(Cursor::<FileId>::decode(&cursor, TenantId::new_v7(), filter.fingerprint(here))
            .is_err());
    }

    #[test]
    fn a_stale_revision_is_reported_as_a_conflict_and_a_wrong_state_as_absence() {
        let node = node_fixture(7, false);
        let stale =
            Mutation { actor: node.modified_by, expected_revision: Some(6), at: node.modified_at };
        let current = Mutation { expected_revision: Some(7), ..stale };
        let unconditional = Mutation { expected_revision: None, ..stale };

        assert!(matches!(
            FileRepository::stale_or_gone(Some(&node), &stale, |n| !n.is_trashed()),
            FilesError::Conflict { current_revision: 7 }
        ));
        // Current revision, and the write still matched nothing: something else changed underneath.
        assert!(matches!(
            FileRepository::stale_or_gone(Some(&node), &current, |n| !n.is_trashed()),
            FilesError::NotFound
        ));
        assert!(matches!(
            FileRepository::stale_or_gone(None, &unconditional, |n| !n.is_trashed()),
            FilesError::NotFound
        ));
        // A trashed node, for a write that needed a live one: absent, not "in the trash". A write
        // must not become a way to probe for an id (`CLAUDE.md` rule 7).
        let trashed = node_fixture(7, true);
        assert!(matches!(
            FileRepository::stale_or_gone(Some(&trashed), &stale, |n| !n.is_trashed()),
            FilesError::NotFound
        ));
    }

    #[test]
    fn the_addressed_node_comes_back_first_from_a_subtree_write() {
        // Without this the caller has to search the vector for the node it named, and "root first"
        // in the doc comments would be a comment rather than a property. `RETURNING` has no
        // `ORDER BY`, so the database will not do it.
        let mut nodes =
            vec![node_fixture(1, false), node_fixture(1, false), node_fixture(1, false)];
        let root = nodes[2].id;
        root_first(&mut nodes, root);
        assert_eq!(nodes[0].id, root);
        assert_eq!(nodes.len(), 3, "nothing is dropped");

        // A root that is not in the set leaves the order alone rather than panicking: a subtree
        // write that returned rows always includes the addressed node, and if it ever did not, the
        // caller is better served by the rows than by a crash.
        let untouched = nodes.iter().map(|node| node.id).collect::<Vec<_>>();
        root_first(&mut nodes, FileId::new_v7());
        assert_eq!(nodes.iter().map(|node| node.id).collect::<Vec<_>>(), untouched);
    }

    fn node_fixture(revision: i64, trashed: bool) -> FileNode {
        let now = DateTime::from_timestamp(1_767_225_600, 0).expect("a valid fixed instant");
        FileNode {
            id: FileId::new_v7(),
            tenant_id: TenantId::new_v7(),
            workspace_id: WorkspaceId::new_v7(),
            library_id: LibraryId::new_v7(),
            parent_id: None,
            node_type: NodeType::File,
            name: "report.pdf".to_owned(),
            normalized_name: "report.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            current_version_id: None,
            size_bytes: 0,
            inherit_permissions: true,
            revision,
            acl_revision: 1,
            is_record: false,
            on_legal_hold: false,
            status: NodeStatus::Processing,
            created_by: UserId::new_v7(),
            modified_by: UserId::new_v7(),
            created_at: now,
            modified_at: now,
            deleted_at: trashed.then_some(now),
            purge_after: trashed.then_some(now),
        }
    }
}
