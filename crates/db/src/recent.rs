//! Per-user recency — the read model behind `GET /api/v1/me/recent`, and **not** a query over the
//! audit trail.
//!
//! `migrations/0029_recent_files.sql` holds the argument for the table's shape; this module is the
//! two statements that write a last-seen fact and read a page of them back.
//!
//! # What this module returns, said before anything else
//!
//! [`recent`] returns **candidates**. Nothing here authorizes, and nothing here has asked whether
//! the caller may see a single one of the files it names. It is a list of rows the *recency* table
//! holds for one user, joined to whatever `files` carries that the wire contract needs; the entries
//! are exactly as trustworthy as "this user opened this file at some point", which is a fact about
//! the past and not a permission in the present.
//!
//! That matters because a grant is not permanent. Between the touch and the read a file can be
//! moved under a folder the caller has no access to, an ACL entry can be revoked, a barrier can be
//! declared, a classification can be raised past what the caller's device or network is allowed to
//! see. Every one of those makes a row in this list a row that must not be shown, and none of them
//! is visible from this table.
//!
//! So the API layer runs `PolicyEngine::enforce` over each candidate and drops the ones that are
//! refused, counting them into the contract's `filteredCount` rather than answering `403`
//! (`CLAUDE.md` rule 7 — a `403` on one row of a list confirms that row exists). This is stated at
//! the top of the module, in the doc comment of every public item below, and in
//! [`RecentCandidates`]' own name, because **a read model that looks authorized is one somebody
//! will serve directly** — and it would be the one screen in the product that loads first.
//!
//! # Why this sits in `enclave-db`
//!
//! The crate header names four argued exceptions to "no repositories here"; this is the fifth, and
//! its argument is the one [`crate::quota`] makes rather than the one [`crate::classifications`]
//! makes. There is no domain crate this belongs to: recency is written by whatever surface a person
//! opened something through — `crates/api`'s file, preview, download and search paths alike — and
//! read by one endpoint that belongs to none of them. `docs/02-HLD.md`, authoritative for the crate
//! list, has no crate for it, and inventing one for a two-statement table would be the sideways
//! dependency `plans/M0-FOUNDATIONS.md` D1 forbids, five times over.
//!
//! # Over-fetching, and why the factor is a named constant with an argument attached
//!
//! The chain drops rows. A caller asking for eight and being handed eight candidates gets a short
//! page whenever any of them is refused, and the screen `web/design-system/specs/home.md` describes
//! is eight rows tall — so the common case would be a list with holes in it for a user whose
//! recency happens to include one restricted document.
//!
//! [`recent`] therefore reads [`OVER_FETCH`] times what the caller asked for. Four, and the number
//! is a judgement rather than a measurement, so here is the judgement: at eight requested rows it
//! costs a 32-row index range scan on the screen's critical path — trivially cheap — and it absorbs
//! a user whose three-quarters most recent activity is in places they have since lost access to,
//! which is already an unusual account. A larger factor buys less and less: the rows further down
//! are older, and a "continue working" list padded out of last month's documents is not the feature.
//!
//! **What happens when the chain drops so many that the page is still short** is the part an
//! over-fetch factor alone does not answer, and it is why [`RecentCandidates`] carries
//! [`more_beyond_window`](RecentCandidates::more_beyond_window). One extra row is read past the
//! window purely to set it. `false` means the window reached the end of this user's recency, so a
//! short page after filtering is the whole truth and the client's filtered-empty state is exact.
//! `true` means rows were left unread, so a short page is short *because this function stopped
//! looking* — the API layer can widen and re-ask, or report the count as the floor it is. Without
//! the flag the two are indistinguishable, and the endpoint would silently under-report
//! `filteredCount` in exactly the case the user notices.
//!
//! # What the join does and does not carry
//!
//! * **`extension`** is not read. It is `name` after the last dot, which is presentation: deriving
//!   it in SQL would put the rule in two places the first time the client wanted `tar.gz` handled
//!   differently.
//! * **`classification`** is the label on the file's **own** row, resolved to key, label and rank —
//!   which is what the contract asks for (*"`classification` is null when the file carries none"*)
//!   and what the chip in `home.md` renders. It is deliberately **not**
//!   [`crate::classifications::effective_classification`]'s chain maximum, and the difference is
//!   real: a file with no label of its own inside a `RESTRICTED` folder shows no chip here. Two
//!   reasons, in order of weight. The walk returns a rank and a source and carries no key or label,
//!   so it cannot fill this contract without a second query per row; and `classifications.rs`'s own
//!   header is this repository's warning about a second walk drifting from the first (`ENC-141`) —
//!   duplicating `EFFECTIVE_SQL` inside this statement would be that drift, arriving pre-merged.
//!   The chip under-reporting sensitivity is a display gap, not an access one: the chain still runs
//!   over every candidate and still refuses what the inherited label forbids.
//! * **`files.status`** is not filtered. It is the processing state, not the antivirus verdict —
//!   that lives on `file_versions.av_status`, which `crates/preview/src/repo.rs`'s
//!   `READABLE_PREDICATE` tests on the paths that actually serve bytes. `CLAUDE.md` rule 9 is about
//!   serving content, and a name and a link are not content; filtering here would instead make a
//!   document vanish from the surface designed to bring you back to it for as long as a scan takes.
//! * **Folders** are excluded (`node_type = 'FILE'`). The contract's row has an extension, a mime
//!   type and a peek target; a folder has none of the three.
//! * **Trashed and purged files** are excluded (`deleted_at IS NULL`, and the composite key's
//!   `ON DELETE CASCADE` for the purge). A trashed file also has an empty inheritance chain —
//!   `crates/authorization/src/repo.rs` joins `files` with `deleted_at IS NULL` on the walk's root —
//!   so every candidate the chain could not decide is dropped before the chain is asked.

use chrono::{DateTime, Utc};
use enclave_core::{ClassificationRank, FileId, LibraryId, TenantId, UserId};
use sqlx::{PgConnection, Row as _};

use crate::ids::{sql, RowIdExt as _};
use crate::tenant::TenantScoped;
use crate::DbError;

/// How many candidates [`recent`] reads for each row the caller intends to render.
///
/// Four. The module header argues the number; what belongs on the constant is the consequence of
/// changing it. Raising it costs a proportionally longer index range scan on the home screen's
/// critical path and buys resilience to users whose recent activity is mostly no longer readable;
/// lowering it towards one makes a page with a single refused row visibly short. It is never a
/// substitute for [`RecentCandidates::more_beyond_window`], which is what tells the caller whether
/// the window was wide enough this time.
pub const OVER_FETCH: u32 = 4;

/// The ceiling on candidates read in one call, whatever the caller multiplies out to.
///
/// The endpoint's own cap is eight (`web/design-system/specs/home.md`), but a read model that
/// trusted its caller's arithmetic would turn a mistaken `limit` into a full scan of a user's
/// history on the first request of a session. 200 is far above anything the contract can ask for
/// and far below anything that would matter to the planner, which is the whole property wanted: it
/// can only ever bound a bug.
pub const MAX_CANDIDATES: u32 = 200;

/// One row of a user's recency, **before** the policy chain has been asked about it.
///
/// Every field is a fact from `recent_files` and `files`. None of them is a permission, and the
/// presence of a value here is not evidence that the caller may see the file — see the module
/// header. The `capabilities` object the wire contract carries is the API layer's to build from the
/// decision it takes; there is deliberately nothing capability-shaped on this struct, so a handler
/// cannot serve one without having run the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentCandidate {
    /// The file this row is about.
    pub file_id: FileId,
    /// Its name, as stored. The wire contract's `extension` is derived from this by the API layer.
    pub name: String,
    /// Its MIME type, which the client maps to an icon token.
    pub mime_type: String,
    /// The library it lives in — half of the route the client links to.
    pub library_id: LibraryId,
    /// The folder containing it, or `None` for a file at the library root, which is what the
    /// contract's `parentFolderId: null` means.
    pub parent_folder_id: Option<FileId>,
    /// The label on the file's own row, or `None` when it carries none. Not the chain maximum — the
    /// module header says why, and what that costs.
    pub classification: Option<RecentClassification>,
    /// When this user last opened it, on PostgreSQL's clock.
    pub last_accessed_at: DateTime<Utc>,
}

/// A classification as the recency contract spells it: key, label and rank together.
///
/// Three columns rather than a [`ClassificationId`](enclave_core::ClassificationId) the caller
/// resolves, because the client needs all three at once — the key selects the locked colour token,
/// the label is what a person reads, and the rank is what anything comparing sensitivity uses — and
/// a second query per row to fetch them would make the home screen's cost proportional to its
/// length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentClassification {
    /// The stable identifier policy and the client's `.cls--{key}` class name are written against.
    pub key: String,
    /// The display form, which is localised and renamed where the key is neither.
    pub label: String,
    /// The ordinal. Higher is more sensitive.
    pub rank: ClassificationRank,
}

/// A window of candidates, and whether the window reached the end of the user's recency.
///
/// The pair is the point. `candidates` alone cannot tell a caller whether a short answer means
/// "that is everything this user has" or "that is everything this call looked at" — and after the
/// chain has dropped some of them, those two produce the same visible list from different truths.
/// `home.md` renders different empty states for them (*"Never say 'you have no recent files' when
/// the truth is 'some were withheld'"*), so the distinction has to survive down here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentCandidates {
    /// The rows, most recent first. Ties broken by `file_id` descending so the order is stable
    /// between two reads of an unchanged table.
    pub candidates: Vec<RecentCandidate>,
    /// `true` when at least one further row exists past the window this call read.
    ///
    /// Set from one extra row fetched and discarded, not from a `COUNT(*)`: the count would be a
    /// second scan of the same range to answer a question with only two interesting values.
    pub more_beyond_window: bool,
}

/// Records that a user opened a file, or moves the instant if the pair is already recorded.
///
/// `now()` is PostgreSQL's, and `GREATEST` is what makes the column monotonic — the migration
/// header argues both, and the short form is that `now()` is `transaction_timestamp()`, so two
/// overlapping transactions carry instants in the opposite order to their commits and a plain
/// assignment would let recency go backwards under load.
///
/// `RETURNING` the stored value rather than nothing, so a caller learns the instant that actually
/// won without a second read.
const RECORD_SQL: &str = "
INSERT INTO recent_files (tenant_id, user_id, file_id, last_accessed_at)
VALUES ($1, $2, $3, now())
ON CONFLICT (tenant_id, user_id, file_id)
DO UPDATE SET last_accessed_at = GREATEST(recent_files.last_accessed_at, EXCLUDED.last_accessed_at)
RETURNING last_accessed_at
";

/// One user's most recent files in one tenant, joined to what the wire contract renders.
///
/// The predicates, and what each is holding on its own:
///
///   * `r.tenant_id = $1` and `f.tenant_id = $1` — tenant isolation as an application predicate,
///     written on the anchor *and* on the join. Row-level security says the same thing
///     independently, and neither layer is a backstop for the other (`lib.rs`). The two clauses are
///     redundant with **each other** for this statement, and that is measured rather than assumed:
///     `crates/db/tests/recent.rs` records that deleting either one alone leaves the cross-tenant
///     test green and deleting both together leaks. Both stay — the anchor's is what makes
///     `idx_recent_files_by_recency` a range scan instead of a scan of every tenant's recency, and
///     the join's is what stops a `file_id` that reached this table by some route the composite key
///     did not cover from resolving against another tenant's row.
///   * `r.user_id = $2` — the half **no** database control holds. RLS is blind to which colleague
///     in a tenant a row belongs to, so this predicate alone stands between one person's reading
///     history and another's. It is the only predicate here with no second layer behind it.
///   * `f.deleted_at IS NULL` and `f.node_type = 'FILE'` — see the module header.
///
/// The `LEFT JOIN` to `classifications` is left rather than inner because an unlabelled file must
/// still appear: an inner join would silently drop every row the contract wants `classification:
/// null` for, which is most of them.
const RECENT_SQL: &str = "
SELECT r.file_id                       AS file_id,
       r.last_accessed_at              AS last_accessed_at,
       f.name                          AS name,
       f.mime_type                     AS mime_type,
       f.library_id                    AS library_id,
       f.parent_id                     AS parent_id,
       c.key                           AS classification_key,
       c.label                         AS classification_label,
       c.rank                          AS classification_rank
  FROM recent_files r
  JOIN files f
    ON f.tenant_id = $1
   AND f.id = r.file_id
   AND f.deleted_at IS NULL
   AND f.node_type = 'FILE'
  LEFT JOIN classifications c
    ON c.tenant_id = $1
   AND c.id = f.classification_id
 WHERE r.tenant_id = $1
   AND r.user_id = $2
 ORDER BY r.last_accessed_at DESC, r.file_id DESC
 LIMIT $3
";

/// Records that `user` opened `file`, in the caller's transaction and on the database's clock.
///
/// Returns the instant the row now carries, which is not always the instant of this call: a touch
/// whose transaction began before one already recorded leaves the newer value in place, so a caller
/// comparing the two learns that its write was superseded rather than lost.
///
/// This form takes the tenant explicitly and so can be pointed at any tenant the connection can
/// reach; prefer [`record`], which cannot. It exists for callers holding a plain connection — and
/// for the isolation tests, which have to run the statement somewhere row-level security is not
/// silently doing the work the predicate is credited with.
///
/// # Errors
///
/// Query failures, including both composite foreign keys: a `file_id` or a `user_id` belonging to
/// another tenant is refused by the key rather than stored (`migrations/0029_recent_files.sql`).
pub async fn record_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
    file: FileId,
) -> Result<DateTime<Utc>, DbError> {
    sqlx::query(RECORD_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(sql(file))
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::Query)?
        .try_get("last_accessed_at")
        .map_err(DbError::Query)
}

/// [`record_on`], for a caller holding a [`TenantScoped`] transaction.
///
/// The tenant comes from the transaction rather than from an argument, so this form cannot be asked
/// to write into a tenant other than the one whose row-level-security context is established. Every
/// production caller should be this one.
///
/// # Errors
///
/// As [`record_on`].
pub async fn record(
    tx: &mut TenantScoped,
    user: UserId,
    file: FileId,
) -> Result<DateTime<Utc>, DbError> {
    let tenant = tx.tenant_id();
    record_on(&mut *tx, tenant, user, file).await
}

/// Candidates for one user's `GET /me/recent` page — **unauthorized**, see the module header.
///
/// `limit` is how many rows the caller intends to *render*; this reads [`OVER_FETCH`] times that
/// many, capped at [`MAX_CANDIDATES`], so the chain has rows to spare when it refuses some. The
/// caller still has to enforce its own limit on what survives — this function's `limit` is an
/// input to a window size, not a promise about the answer's length.
///
/// This form takes the tenant explicitly and so can be pointed at any tenant the connection can
/// reach; prefer [`recent`], which cannot. See [`record_on`] for why it is public.
///
/// # Errors
///
/// Query failures, and a `rank` that is not an `i32`. A classification row with a key but no label
/// cannot occur — both columns are `NOT NULL` in `migrations/0022_classifications.sql` — so the
/// three are read as one presence and a partial row would surface as a decode error rather than as
/// a chip with a missing name.
pub async fn recent_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
    limit: u32,
) -> Result<RecentCandidates, DbError> {
    let window = limit.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES);

    // One row past the window, read only to answer "was there more?". `saturating_add` because
    // `window` is already capped well below `u32::MAX`, and because a panic on the home screen's
    // first query would be an expensive way to learn about an arithmetic edge.
    let probe = i64::from(window.saturating_add(1));

    let rows = sqlx::query(RECENT_SQL)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(probe)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    let more_beyond_window = rows.len() as u64 > u64::from(window);

    let candidates = rows
        .iter()
        .take(window as usize)
        .map(|row| {
            let classification = match (
                row.try_get::<Option<String>, _>("classification_key").map_err(DbError::Query)?,
                row.try_get::<Option<String>, _>("classification_label").map_err(DbError::Query)?,
                row.try_get::<Option<i32>, _>("classification_rank").map_err(DbError::Query)?,
            ) {
                (Some(key), Some(label), Some(rank)) => {
                    Some(RecentClassification { key, label, rank: ClassificationRank::new(rank) })
                }
                _ => None,
            };

            Ok(RecentCandidate {
                file_id: row.try_get_id("file_id").map_err(DbError::Query)?,
                name: row.try_get("name").map_err(DbError::Query)?,
                mime_type: row.try_get("mime_type").map_err(DbError::Query)?,
                library_id: row.try_get_id("library_id").map_err(DbError::Query)?,
                parent_folder_id: row.try_get_opt_id("parent_id").map_err(DbError::Query)?,
                last_accessed_at: row.try_get("last_accessed_at").map_err(DbError::Query)?,
                classification,
            })
        })
        .collect::<Result<Vec<_>, DbError>>()?;

    Ok(RecentCandidates { candidates, more_beyond_window })
}

/// [`recent_on`], for a caller holding a [`TenantScoped`] transaction.
///
/// The tenant comes from the transaction, so this form cannot be asked about another one. It is
/// still **unauthorized**: a scoped transaction proves which tenant the rows belong to and says
/// nothing about whether the caller may see them.
///
/// # Errors
///
/// As [`recent_on`].
pub async fn recent(
    tx: &mut TenantScoped,
    user: UserId,
    limit: u32,
) -> Result<RecentCandidates, DbError> {
    let tenant = tx.tenant_id();
    recent_on(&mut *tx, tenant, user, limit).await
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
    /// under RLS cannot catch. The behavioural half lives in `crates/db/tests/recent.rs` and runs
    /// where RLS is inert; this is the cheap, always-run half.
    ///
    /// Two assertions rather than one, because an `INSERT` has no `WHERE`: a single
    /// `contains("tenant_id = $1")` over both statements would be green for the one that *writes*
    /// the tenant no matter which column it wrote it into.
    #[test]
    fn every_statement_is_scoped_to_one_tenant() {
        assert!(
            RECENT_SQL.contains("r.tenant_id = $1"),
            "the recency read has no tenant predicate; deleting it is the ENC-124 shape, and the \
             harness's superuser connection would not notice: {RECENT_SQL}"
        );

        assert!(
            RECORD_SQL.contains("(tenant_id, user_id, file_id, last_accessed_at)")
                && RECORD_SQL.contains("VALUES ($1, $2, $3,"),
            "the upsert must write tenant_id from $1 as its first column, or a touch can be \
             recorded into a tenant the caller's transaction is not scoped to: {RECORD_SQL}"
        );
    }

    /// The join carries the tenant too, not only the anchor.
    ///
    /// The test above is satisfied by the `WHERE` alone. A `files` or `classifications` join that
    /// dropped its own `tenant_id = $1` would still contain the string, so this counts them: the
    /// recency anchor, the `files` join and the `classifications` join, three in all.
    #[test]
    fn the_read_scopes_every_join_and_not_only_its_anchor() {
        let scoped = RECENT_SQL.matches("tenant_id = $1").count();
        assert!(
            scoped >= 3,
            "the recency read has {scoped} tenant-scoped predicates; the anchor, the files join \
             and the classifications join each need one, or another tenant's name and label can be \
             read through a join row security is not asked about"
        );
    }

    /// The predicate no database control is holding.
    ///
    /// Row-level security isolates tenants and knows nothing about users, so this one string is the
    /// entire boundary between two colleagues' reading histories. Deleting it produces a query that
    /// still passes every tenant-isolation test in the workspace.
    #[test]
    fn the_read_is_scoped_to_one_user_as_well_as_one_tenant() {
        assert!(
            RECENT_SQL.contains("r.user_id = $2"),
            "the recency read must be scoped to one user; RLS is blind to which member of a tenant \
             a row belongs to, so without this a colleague's history is served as your own: \
             {RECENT_SQL}"
        );
    }

    /// Recency must not go backwards, and the upsert is where that is decided.
    ///
    /// `DO UPDATE SET last_accessed_at = EXCLUDED.last_accessed_at` reads identically and is wrong
    /// under overlapping transactions — `now()` is `transaction_timestamp()`. The behavioural proof
    /// is in `crates/db/tests/recent.rs`; this asserts the shape so the two cannot drift.
    #[test]
    fn the_upsert_moves_the_instant_forwards_only() {
        assert!(
            RECORD_SQL
                .contains("GREATEST(recent_files.last_accessed_at, EXCLUDED.last_accessed_at)"),
            "the upsert must take the greater of the stored and incoming instants; a plain \
             assignment lets a transaction that began earlier and committed later move a user's \
             recency backwards: {RECORD_SQL}"
        );
    }

    /// The trash and the folder filter, as properties of the statement.
    ///
    /// Both are one-line deletions that produce a query returning *more* rows — the direction a
    /// test asserting presence never notices. The behavioural halves are in the integration suite;
    /// this is the always-run guard against the deletion.
    #[test]
    fn the_read_excludes_the_trash_and_excludes_folders() {
        assert!(
            RECENT_SQL.contains("f.deleted_at IS NULL"),
            "a trashed file must not appear in a recency list: its inheritance chain is empty, so \
             the policy chain cannot even decide it: {RECENT_SQL}"
        );
        assert!(
            RECENT_SQL.contains("f.node_type = 'FILE'"),
            "the recency contract's row has an extension, a mime type and a peek target; a folder \
             has none of the three: {RECENT_SQL}"
        );
    }

    /// The order the index exists to serve, including its tiebreak.
    ///
    /// `idx_recent_files_by_recency` is `(tenant_id, user_id, last_accessed_at DESC, file_id DESC)`
    /// precisely because this clause is. Changing one without the other turns the home screen's
    /// first query into a sort over everything a user has ever opened, silently and only under a
    /// data volume no test fixture has.
    #[test]
    fn the_read_is_ordered_by_recency_with_a_stable_tiebreak() {
        assert!(
            RECENT_SQL.contains("ORDER BY r.last_accessed_at DESC, r.file_id DESC"),
            "the recency read must order by time descending with file_id as a tiebreak, matching \
             idx_recent_files_by_recency; without the tiebreak two opens sharing a microsecond \
             swap places between refreshes: {RECENT_SQL}"
        );
    }

    /// The over-fetch is real arithmetic, not a comment.
    ///
    /// A factor of one is the defect this constant exists to prevent, and it is a one-character
    /// edit away. Both assertions are written as the window calculation rather than as a bare
    /// comparison against the constant, so each states the property in the terms the caller sees:
    /// asking for one row must read more than one, and a mistaken `limit` must not turn into an
    /// unbounded scan.
    #[test]
    fn the_window_over_fetches_and_stays_bounded() {
        assert!(
            1_u32.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES) > 1,
            "an over-fetch factor of {OVER_FETCH} reads exactly what the caller renders, so one \
             refused row is one missing row on the home screen"
        );
        assert!(
            u32::MAX.saturating_mul(OVER_FETCH).min(MAX_CANDIDATES) == MAX_CANDIDATES,
            "the window must saturate at MAX_CANDIDATES rather than wrapping or scanning a user's \
             whole history on a mistaken limit"
        );
    }
}
