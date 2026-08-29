//! The recycle bin — the read model behind `GET /api/v1/trash`, and the query that answers *what
//! did I delete*.
//!
//! `DELETE /api/v1/files/{id}` and `POST /api/v1/files/{id}/restore` shipped with `ENC-807`, and
//! between them they left a hole nobody could climb out of: **nothing listed the trash.**
//! `GET /libraries/{id}/items` filters `deleted_at IS NOT NULL` out, and
//! `FileRepository::find_including_trashed` resolves an id the caller already
//! holds. So a document deleted through the product vanished from every listing in it, and the
//! restore endpoint was reachable only by somebody who had written the UUID down first. This module
//! is the missing half of that pair.
//!
//! # What this module returns, said before anything else
//!
//! [`roots`] returns **candidates**. Nothing here authorizes and nothing here has asked whether the
//! caller may restore a single one of the rows it names. It is every trashed node in one tenant
//! that is the root of its own deletion — which is a fact about `files.deleted_at`, not a
//! permission — and the trash is **tenant-wide**, so the rows it produces routinely belong to
//! libraries the caller has never been able to see.
//!
//! That makes this the most dangerous read model in the crate to serve directly, more so than
//! [`crate::recent`]: a recency row is at least something the caller once opened, whereas a row here
//! has no relationship to them at all. The API layer therefore puts every candidate to the
//! authorization stage before it reaches the wire, drops the refusals, and counts them into the
//! contract's `filteredCount` rather than answering `403` (`CLAUDE.md` rule 7 — a per-row status
//! confirms that a particular file exists). It is stated here, on [`TrashCandidates`], and on every
//! public item below, because **a read model that looks authorized is one somebody will serve
//! directly**.
//!
//! # Only the roots of a cascade, and the predicate that says so
//!
//! `FileRepository::trash` cascades: it stamps **one** `deleted_at` across the
//! whole subtree. `FileRepository::restore` undoes exactly that set, discriminating
//! on `c.deleted_at = s.deleted_at`. So a listing of every trashed row would show a folder and each
//! of its hundred children as a hundred and one separate entries, and restoring any child would be a
//! partial restore of somebody's folder.
//!
//! The statement therefore keeps a row only when **no parent shares its `deleted_at`**:
//!
//! ```text
//! AND NOT EXISTS (SELECT 1 FROM files p
//!                  WHERE p.tenant_id = $1 AND p.id = f.parent_id
//!                    AND p.deleted_at = f.deleted_at)
//! ```
//!
//! It is the exact negation of `RESTORE_SUBTREE`'s recursive term, which is what makes "one row per
//! restore" true by construction rather than by agreement between two queries. Three cases fall out
//! of it and all three are wanted:
//!
//! * A node at the library root has no parent, so the subquery matches nothing — a root.
//! * A node whose parent is **live** is a root: its parent was never deleted, so it was deleted on
//!   its own.
//! * A node whose parent is trashed at a **different** instant is also a root, and this is the case
//!   a naive `parent is not trashed` predicate gets wrong. A file deleted on Monday inside a folder
//!   deleted on Tuesday is not part of Tuesday's cascade — `RESTORE_SUBTREE` will not bring it back
//!   with the folder — so if this listing hid it, it would be unrestorable by any request. It is
//!   listed, and restoring it while the folder is still in the trash is refused by
//!   `FilesError::ParentInTrash`, which is a refusal the caller can act on
//!   (restore the folder first) rather than a row that does not exist.
//!
//! `p.deleted_at = f.deleted_at` is a plain equality and not `IS NOT DISTINCT FROM` on purpose:
//! `f.deleted_at` is `NOT NULL` under the outer predicate, so a live parent's `NULL` compares to
//! unknown, the subquery finds nothing, and the row is correctly a root. Writing it null-safe would
//! make a *live* parent match a hypothetical `NULL`-deleted child and hide the row.
//!
//! # The order, and the index it rides
//!
//! Most-recently-deleted first, with `f.id DESC` as the tiebreak so two rows sharing an instant —
//! which the cascade guarantees for anything trashed together — keep a stable order between two
//! reads of an unchanged table.
//!
//! `docs/04-DATA-MODEL.md` has promised `idx_files_trash` since the file surface was specified and
//! no migration created it until this listing needed one; `migrations/0030_files_trash_index.sql`
//! carries that account in full. Two properties of it are load-bearing here. It is **partial** on
//! `deleted_at IS NOT NULL`, which is what keeps it proportional to the recycle bin rather than to
//! the library — the trash is a small fraction of `files` and an unpartitioned index would not be.
//! And its key is `(tenant_id, deleted_at DESC)` rather than the document's original
//! `(tenant_id, purge_after)`, because this `ORDER BY` is the only statement in the product that
//! reads the trash as a set. Today the two columns sort identically, since `purge_after` is
//! `deleted_at` plus the one constant `routes::lifecycle::TRASH_RETENTION_DAYS`; they stop doing so
//! the day retention becomes a tenant setting, and indexing what the reader orders by is what makes
//! this ordering survive that day rather than silently becoming a sort.
//!
//! # Over-fetching, and why the factor is a constant with an argument attached
//!
//! The chain drops rows, and here it drops many: the read is tenant-wide, so a caller in a large
//! tenant may be shown fifty candidates of which two are theirs to restore. [`roots`] reads
//! [`OVER_FETCH`] times what the caller asked for, capped at [`MAX_CANDIDATES`].
//!
//! Four, and the number is a judgement rather than a measurement. At the endpoint's cap of fifty
//! rows it costs a two-hundred-row scan of the partial range plus one `users` join, which is cheap
//! and is not on any critical path — the trash is a screen people visit deliberately. A larger
//! factor buys progressively less, because the rows further down are older and a recycle bin padded
//! out of last month is not what the caller came for; a factor of one would make a single
//! unrestorable row a visibly short page.
//!
//! [`TrashCandidates::more_beyond_window`] is what an over-fetch factor alone cannot answer. One
//! extra row is read past the window purely to set it. `false` means the window reached the end of
//! this tenant's recycle bin, so a short page after filtering is the whole truth and
//! `filteredCount` is exact. `true` means rows were left unread, so a short page is short *because
//! this function stopped looking* and the count is a floor. Without the flag the two are
//! indistinguishable, and the endpoint would under-report in exactly the case a user notices.
//!
//! # Why this sits in `enclave-db`
//!
//! The crate header names four argued exceptions to "no repositories here" and [`crate::recent`] is
//! the fifth; this is the sixth, and it takes recency's argument with one addition.
//!
//! `crates/files` owns the `files` table, and on the face of it this belongs there. It cannot go
//! there as written: the contract's `deletedBy` is a display name, which lives in `users`, and
//! `enclave-files` has no dependency on identity and no business acquiring one to render a listing
//! — `FileNode` deliberately carries `modified_by` as an id and nothing more. The
//! alternative was a second query per row against `users` from the API layer, which makes the
//! screen's cost proportional to its length for a column that is one join.
//!
//! This is a placement judgement and not a security one, and it is worth saying which: nothing about
//! isolation depends on the module living here. If `crates/files` ever grows a listing surface that
//! can join identity without inverting the layering, this row is the one that should move.
//!
//! # What the join does and does not carry
//!
//! * **`node_type` is carried**, unlike [`crate::recent`], because a trashed *folder* is the most
//!   important row this endpoint returns — it is the one whose restore brings back a hundred
//!   documents — and the client draws a different icon and a different confirmation for it.
//! * **`revision` is carried**, and it is the field this whole listing exists to deliver alongside
//!   the name: `POST /files/{id}/restore` **requires** `If-Match`, so a client that can see a
//!   trashed file and not its revision cannot restore anything. A listing that made the caller
//!   fetch the revision separately would be asking them to `GET` a file that answers `404` while it
//!   is in the trash.
//! * **`classification` is not read.** The recency contract renders a chip; this one does not, and
//!   resolving a label the wire has no field for would be a join nobody reads.
//! * **`files.status` is not filtered**, on [`crate::recent`]'s reasoning: it is the processing
//!   state, not the antivirus verdict, and a name is not content (`CLAUDE.md` rule 9 is about
//!   serving bytes). A file that was still scanning when it was deleted must still be restorable.
//! * **The `users` join is `LEFT`.** An inner join would silently drop every row whose deleter's
//!   account has since been hard-deleted, and a dropped row in a listing looks exactly like a
//!   filtering bug from the client — the failure `crates/db/tests/recent.rs` records for the
//!   classifications join. The caller reports `None` and the wire renders `null`.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UserId};
use sqlx::{PgConnection, Row as _};

use crate::ids::{sql, RowIdExt as _};
use crate::tenant::TenantScoped;
use crate::DbError;

/// How many candidates [`roots`] reads for each row the caller intends to render.
///
/// Four. The module header argues the number; what belongs here is the consequence of changing it.
/// Raising it costs a proportionally longer scan of the partial trash range and buys resilience to
/// a caller whose tenant's recycle bin is mostly other people's deletions — which, since the read is
/// tenant-wide, is the ordinary case in a large tenant rather than an unusual one. Lowering it
/// towards one makes a page with a single unrestorable row visibly short. It is never a substitute
/// for [`TrashCandidates::more_beyond_window`], which is what says whether the window was wide
/// enough this time.
pub const OVER_FETCH: u32 = 4;

/// The ceiling on candidates read in one call, whatever the caller multiplies out to.
///
/// The endpoint's own cap is fifty, so the ordinary window is two hundred and this bound is never
/// reached in a well-formed request. It exists because a read model that trusted its caller's
/// arithmetic would turn a mistaken `limit` into a scan of every row a tenant has ever deleted. Five
/// hundred is far above anything the contract can ask for and far below anything that would matter
/// to the planner, which is the whole property wanted: it can only ever bound a bug.
pub const MAX_CANDIDATES: u32 = 500;

/// Whether a trashed node is a file or a folder.
///
/// A local enum rather than `enclave_files::NodeType` because `enclave-files` depends on *this*
/// crate; the dependency cannot run the other way without inverting the layering
/// (`plans/M0-FOUNDATIONS.md` D1). What the two share is the `CHECK (node_type IN ('FILE','FOLDER'))`
/// constraint in `migrations/0005_files.sql`, and [`TrashedKind::as_str`] spells it in the same
/// words, so the wire value and the stored value cannot drift apart silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashedKind {
    /// A document.
    File,
    /// A container. Restoring it brings back everything trashed with it.
    Folder,
}

impl TrashedKind {
    /// The stored spelling, which is also the contract's `type` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "FILE",
            Self::Folder => "FOLDER",
        }
    }

    /// Reads the column, refusing anything the `CHECK` constraint should have made impossible.
    ///
    /// A decode error rather than a default, because both defaults are wrong in a way a reader
    /// would not notice: calling an unknown row a file draws a document icon on something that may
    /// hold a hundred documents, and calling it a folder promises a restore that cascades when it
    /// does not.
    fn from_column(raw: &str) -> Result<Self, sqlx::Error> {
        match raw {
            "FILE" => Ok(Self::File),
            "FOLDER" => Ok(Self::Folder),
            other => Err(sqlx::Error::Decode(
                format!(
                    "a trashed row carries the node type `{other}`, which the files table's CHECK \
                     constraint does not permit and this crate cannot render"
                )
                .into(),
            )),
        }
    }
}

/// One node in the recycle bin, **before** the policy chain has been asked about it.
///
/// Every field is a fact from `files` and `users`. None of them is a permission, and the presence of
/// a value here is not evidence that the caller may see — let alone restore — the node: the read is
/// tenant-wide, so most rows in a large tenant belong to people the caller has never worked with.
/// See the module header.
///
/// There is deliberately nothing capability-shaped on this struct, so a handler cannot serve a row
/// without having run the chain over it first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashCandidate {
    /// The node that was deleted.
    pub file_id: FileId,
    /// Its name, as stored.
    pub name: String,
    /// File or folder. A folder's restore brings back everything trashed with it.
    pub kind: TrashedKind,
    /// The media type. `inode/directory` for a folder.
    pub mime_type: String,
    /// The library it will return into — half of the container the restore is decided against.
    pub library_id: LibraryId,
    /// The folder it will return into, or `None` for a node at the library root, which is the
    /// contract's `parentFolderId: null`.
    pub parent_folder_id: Option<FileId>,
    /// When the cascade that removed it ran, on the deleting transaction's clock.
    pub deleted_at: DateTime<Utc>,
    /// The earliest instant permanent deletion may be *considered*, or `None` when the row carries
    /// none.
    ///
    /// `files.purge_after` is nullable and the trash write always sets it, so `None` here means the
    /// row was deleted by something other than `DELETE /files/{id}`. Reported rather than
    /// substituted: a client that shows *"7 days left"* over an invented retention is worse than one
    /// that shows nothing.
    pub purge_after: Option<DateTime<Utc>>,
    /// The revision the next `If-Match` must carry. See the module header — without it the row is
    /// unrestorable.
    pub revision: i64,
    /// Who deleted it, from `files.modified_by`, which the trash write stamps.
    pub deleted_by: UserId,
    /// Their display name, or `None` when no `users` row answers to the id.
    pub deleted_by_display_name: Option<String>,
}

/// A window of candidates, and whether the window reached the end of the recycle bin.
///
/// The pair is the point. `candidates` alone cannot tell a caller whether a short answer means
/// "that is the whole bin" or "that is everything this call looked at", and after the chain has
/// dropped rows those two produce the same visible list from different truths — one of which makes
/// `filteredCount` exact and the other a floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashCandidates {
    /// The rows, most recently deleted first, ties broken by `file_id` descending.
    pub candidates: Vec<TrashCandidate>,
    /// `true` when at least one further row exists past the window this call read.
    ///
    /// Set from one extra row fetched and discarded, not from a `COUNT(*)`: the count would be a
    /// second scan of the same range to answer a question with two interesting values.
    pub more_beyond_window: bool,
}

/// Every node in one tenant's recycle bin that is the root of its own deletion.
///
/// The predicates, and what each is holding on its own:
///
///   * `f.tenant_id = $1`, `u.tenant_id = $1` and `p.tenant_id = $1` — tenant isolation as an
///     application predicate, written on the anchor, on the identity join *and* inside the
///     root-detection subquery. Row-level security says the same thing independently and neither
///     layer is a backstop for the other (`lib.rs`). The anchor's is the load-bearing one and
///     `crates/db/tests/trash.rs` measures that rather than assuming it: deleting it leaks another
///     tenant's document names on a connection where RLS is inert. The subquery's is subtler and
///     fails in the *other* direction — without it a parent row from another tenant could match on
///     `id` alone and suppress a row this tenant is entitled to see, which is a deletion nobody can
///     undo rather than a disclosure.
///   * `f.deleted_at IS NOT NULL` — the trash, as opposed to the library. Deleting it returns every
///     live file in the tenant from an endpoint that authorizes on `file.restore`.
///   * The `NOT EXISTS` — one row per restore. The module header argues it in full.
///
/// The `LEFT JOIN` to `users` is left rather than inner so that a deleter whose account has gone
/// cannot remove their deletions from the bin; see the module header.
const TRASH_ROOTS_SQL: &str = "
SELECT f.id           AS file_id,
       f.name         AS name,
       f.node_type    AS node_type,
       f.mime_type    AS mime_type,
       f.library_id   AS library_id,
       f.parent_id    AS parent_id,
       f.deleted_at   AS deleted_at,
       f.purge_after  AS purge_after,
       f.revision     AS revision,
       f.modified_by  AS deleted_by,
       u.display_name AS deleted_by_display_name
  FROM files f
  LEFT JOIN users u
    ON u.tenant_id = $1
   AND u.id = f.modified_by
 WHERE f.tenant_id = $1
   AND f.deleted_at IS NOT NULL
   AND NOT EXISTS (SELECT 1
                     FROM files p
                    WHERE p.tenant_id = $1
                      AND p.id = f.parent_id
                      AND p.deleted_at = f.deleted_at)
 ORDER BY f.deleted_at DESC, f.id DESC
 LIMIT $2
";

/// Candidates for one tenant's `GET /api/v1/trash` page — **unauthorized**, see the module header.
///
/// `limit` is how many rows the caller intends to *render*; this reads [`OVER_FETCH`] times that
/// many, capped at [`MAX_CANDIDATES`], so the chain has rows to spare when it refuses some. The
/// caller still has to enforce its own limit on what survives — this function's `limit` is an input
/// to a window size, not a promise about the answer's length.
///
/// This form takes the tenant explicitly and so can be pointed at any tenant the connection can
/// reach; prefer [`roots`], which cannot. It exists for the isolation tests, which have to run the
/// statement somewhere row-level security is not silently doing the work the predicate is credited
/// with (`crates/db/tests/trash.rs`).
///
/// # Errors
///
/// Query failures, and a `node_type` outside the two the `CHECK` constraint permits. A missing
/// `users` row is **not** an error — it is `None` — because the alternative is a recycle bin that
/// hides rows when an account is removed.
pub async fn roots_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    limit: u32,
) -> Result<TrashCandidates, DbError> {
    let window = limit.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES);

    // One row past the window, read only to answer "was there more?". `saturating_add` because
    // `window` is already capped well below `u32::MAX`, and a panic on an arithmetic edge would be
    // an expensive way to learn that a client sent a large `limit`.
    let probe = i64::from(window.saturating_add(1));

    let rows = sqlx::query(TRASH_ROOTS_SQL)
        .bind(sql(tenant))
        .bind(probe)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    let more_beyond_window = rows.len() as u64 > u64::from(window);

    let candidates = rows
        .iter()
        .take(window as usize)
        .map(|row| {
            let node_type: String = row.try_get("node_type").map_err(DbError::Query)?;

            Ok(TrashCandidate {
                file_id: row.try_get_id("file_id").map_err(DbError::Query)?,
                name: row.try_get("name").map_err(DbError::Query)?,
                kind: TrashedKind::from_column(&node_type).map_err(DbError::Query)?,
                mime_type: row.try_get("mime_type").map_err(DbError::Query)?,
                library_id: row.try_get_id("library_id").map_err(DbError::Query)?,
                parent_folder_id: row.try_get_opt_id("parent_id").map_err(DbError::Query)?,
                deleted_at: row.try_get("deleted_at").map_err(DbError::Query)?,
                purge_after: row.try_get("purge_after").map_err(DbError::Query)?,
                revision: row.try_get("revision").map_err(DbError::Query)?,
                deleted_by: row.try_get_id("deleted_by").map_err(DbError::Query)?,
                deleted_by_display_name: row
                    .try_get("deleted_by_display_name")
                    .map_err(DbError::Query)?,
            })
        })
        .collect::<Result<Vec<_>, DbError>>()?;

    Ok(TrashCandidates { candidates, more_beyond_window })
}

/// [`roots_on`], for a caller holding a [`TenantScoped`] transaction.
///
/// The tenant comes from the transaction rather than from an argument, so this form cannot be asked
/// about a tenant other than the one whose row-level-security context is established
/// (`CLAUDE.md` rule 3). Every production caller should be this one.
///
/// It is still **unauthorized**: a scoped transaction proves which tenant the rows belong to and
/// says nothing about whether the caller may restore any of them.
///
/// # Errors
///
/// As [`roots_on`].
pub async fn roots(tx: &mut TenantScoped, limit: u32) -> Result<TrashCandidates, DbError> {
    let tenant = tx.tenant_id();
    roots_on(&mut *tx, tenant, limit).await
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Layer 1, asserted where it is written.
    ///
    /// A deleted `tenant_id` predicate leaves row-level security holding tenant isolation alone —
    /// `docs/12 §4.1` `T5`'s designed property, and therefore something a behavioural test running
    /// under RLS cannot catch. The behavioural half is in `crates/db/tests/trash.rs` and runs where
    /// RLS is inert; this is the cheap, always-run half.
    ///
    /// Three occurrences, counted rather than merely found: the anchor, the `users` join and the
    /// root-detection subquery each need one, and a `contains` over the whole statement would be
    /// green with any two of the three deleted.
    #[test]
    fn every_relation_in_the_read_is_scoped_to_one_tenant() {
        assert!(
            TRASH_ROOTS_SQL.contains("f.tenant_id = $1"),
            "the trash read has no tenant predicate on its anchor; deleting it is the ENC-124 \
             shape, and the harness's superuser connection would not notice: {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("u.tenant_id = $1"),
            "the identity join must be tenant-scoped, or another tenant's display name can be read \
             through a join row security is not asked about: {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("p.tenant_id = $1"),
            "the root-detection subquery must be tenant-scoped: an unscoped parent lookup lets \
             another tenant's row suppress one of this tenant's, which is a deletion nobody can \
             undo: {TRASH_ROOTS_SQL}"
        );

        let scoped = TRASH_ROOTS_SQL.matches("tenant_id = $1").count();
        assert!(
            scoped >= 3,
            "the trash read has {scoped} tenant-scoped predicates; the anchor, the users join and \
             the parent subquery each need one"
        );
    }

    /// The trash is the trash, not the library.
    ///
    /// A one-line deletion that produces a query returning *more* rows — the direction a test
    /// asserting presence never notices — and the rows it adds are every live file in the tenant,
    /// on an endpoint whose one action is restore.
    #[test]
    fn the_read_returns_only_nodes_that_are_in_the_trash() {
        assert!(
            TRASH_ROOTS_SQL.contains("f.deleted_at IS NOT NULL"),
            "without this the recycle bin is the whole tenant: {TRASH_ROOTS_SQL}"
        );
    }

    /// One row per restore, as a property of the statement.
    ///
    /// Asserted over the three clauses of the subquery rather than over the words `NOT EXISTS`,
    /// because the failure that matters is a *weakened* predicate — dropping the `deleted_at`
    /// equality turns "the root of this cascade" into "anything whose parent is not trashed", which
    /// hides a file deleted before the folder above it was and makes it unrestorable by any request.
    #[test]
    fn the_read_lists_only_the_root_of_each_cascade() {
        assert!(
            TRASH_ROOTS_SQL.contains("NOT EXISTS"),
            "a trashed folder and its hundred children would otherwise be a hundred and one rows, \
             and restoring a child would be a partial restore of somebody's folder: \
             {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("p.id = f.parent_id"),
            "the subquery must look up the row's own parent: {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("p.deleted_at = f.deleted_at"),
            "the discriminator is the shared instant, matching RESTORE_SUBTREE's own \
             `c.deleted_at = s.deleted_at`; `p.deleted_at IS NOT NULL` reads almost the same and \
             hides a node deleted before its parent was: {TRASH_ROOTS_SQL}"
        );
    }

    /// The order the contract promises, including its tiebreak.
    ///
    /// The cascade stamps one instant across a subtree, so ties are guaranteed rather than
    /// theoretical here: without `f.id DESC` two nodes deleted together swap places between
    /// refreshes of the same unchanged bin.
    #[test]
    fn the_read_is_ordered_most_recently_deleted_first_with_a_stable_tiebreak() {
        assert!(
            TRASH_ROOTS_SQL.contains("ORDER BY f.deleted_at DESC, f.id DESC"),
            "most-recently-deleted first is what a person means by `what did I just delete`, and \
             the tiebreak is what makes two reads of an unchanged bin agree: {TRASH_ROOTS_SQL}"
        );
    }

    /// The row carries what `POST /files/{id}/restore` will demand.
    ///
    /// `revision` is the one field whose absence makes the whole listing useless: the restore
    /// requires `If-Match`, and a trashed file answers `404` to the `GET` a client would otherwise
    /// read it from. Asserted beside the identity join, which is the other column the contract
    /// cannot be built without.
    #[test]
    fn the_read_carries_the_revision_the_restore_requires() {
        assert!(
            TRASH_ROOTS_SQL.contains("f.revision"),
            "without the revision a client can see a deleted file and cannot restore it, which is \
             the defect this module exists to fix: {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("LEFT JOIN users"),
            "a plain JOIN would drop every row whose deleter's account is gone, and a dropped row \
             looks like a filtering bug from the client: {TRASH_ROOTS_SQL}"
        );
        assert!(
            TRASH_ROOTS_SQL.contains("f.modified_by"),
            "`deletedBy` is files.modified_by, which the trash write stamps: {TRASH_ROOTS_SQL}"
        );
    }

    /// The over-fetch is real arithmetic, not a comment.
    ///
    /// A factor of one is the defect the constant exists to prevent and it is a one-character edit
    /// away. Both assertions are written as the window calculation rather than as a comparison
    /// against the constant, so each states the property in the terms the caller sees.
    #[test]
    fn the_window_over_fetches_and_stays_bounded() {
        assert!(
            1_u32.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES) > 1,
            "an over-fetch factor of {OVER_FETCH} reads exactly what the caller renders, so one \
             unrestorable row is one missing row in the recycle bin"
        );
        assert_eq!(
            u32::MAX.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES),
            MAX_CANDIDATES,
            "the window must saturate rather than wrap or scan every row a tenant ever deleted"
        );
    }

    /// The two node types are the two the migration's `CHECK` permits, and nothing else decodes.
    ///
    /// The positive controls are the first two assertions: without them, "an unknown value is
    /// refused" is equally true of a function that refuses everything, which would make the recycle
    /// bin permanently empty.
    #[test]
    fn a_node_type_outside_the_check_constraint_is_a_decode_error() {
        assert_eq!(TrashedKind::from_column("FILE").expect("a file"), TrashedKind::File);
        assert_eq!(TrashedKind::from_column("FOLDER").expect("a folder"), TrashedKind::Folder);
        assert_eq!(TrashedKind::File.as_str(), "FILE", "the stored and wire spellings are one");
        assert_eq!(TrashedKind::Folder.as_str(), "FOLDER");

        let refused = TrashedKind::from_column("SHORTCUT").expect_err("not a node type");
        assert!(
            matches!(refused, sqlx::Error::Decode(_)),
            "an unknown node type must be a decode error rather than a default: defaulting to FILE \
             draws a document icon on something that may hold a hundred documents, and defaulting \
             to FOLDER promises a cascade the restore will not perform"
        );
    }
}
