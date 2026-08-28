//! The retrieval denylist: what makes a revocation take effect before the index hears about it.
//!
//! # Why this is not a job queue
//!
//! `docs/12-TESTING.md §4.3` S3 asks that a revoked file vanish from results **immediately**, before
//! any index update. S4 asks that S3 still hold with the invalidation worker stopped.
//!
//! Those two forbid the design everybody reaches for first — enqueue a job, let a worker remove the
//! document from the vector store. A stopped worker then means a revoked file stays findable *and
//! the search still answers*. Not an outage, which is visible: a wrong answer delivered
//! confidently, which is not.
//!
//! So a revocation writes a row here in the same transaction that changes the ACL
//! (`plans/M3-DISCOVERY.md` D22), and every search reads it. The worker's job is cleanup afterwards,
//! and its absence costs index size, never correctness. S4 is the test that a stopped worker changes
//! nothing a caller can observe.
//!
//! # This is not an access control
//!
//! Worth stating because the name invites the opposite reading. The denylist is an
//! *index-freshness* mechanism. What decides whether a caller may see a file is
//! [`crate::postfilter`], resolving against `acl_entries` — which runs whether or not this table has
//! a row, and which no amount of denylist tampering can widen.
//!
//! That is why migration 0011 grants `DELETE` here without the argument the content tables needed:
//! removing a suppression cannot reveal anything the post-filter would not have allowed anyway. It
//! can only cost freshness.
//!
//! # "Has the index caught up?" — what a row can now say, and what it still cannot
//!
//! Migration 0011 documented `clears_at` as "when the suppression may be lifted, once the index is
//! known to have caught up", and nothing in the schema could answer the second half. `ENC-520`
//! named that rather than proxying it; `migrations/0014_index_catch_up.sql` is the answer and its
//! header carries the full reasoning. In short, a row now holds a generation counter
//! ([`SuppressionSeq`]) that a vector-store write can name, so the three states are distinct:
//!
//! - **nobody has asserted anything** — [`CatchUp::unasserted`], which is *unknown* and not "no";
//! - **a write is confirmed but a later suppression is not** — [`CatchUp::behind`];
//! - **a confirmed write covers the current suppression** — [`CatchUp::caught_up`].
//!
//! Two refusals hold that in place, and both are asserted over the SQL text below rather than left
//! to review:
//!
//! 1. **Nothing lifts on it.** [`lift_expired`] and [`suppressed`] read `clears_at` and nothing
//!    else. A lift conditional on a confirmation would make S4 (`docs/12-TESTING.md §4.3`) pass
//!    because a writer ran rather than because the denylist write is inside the ACL transaction —
//!    the same mistake `crates/worker/src/epoch.rs` refuses in the other direction.
//! 2. **There is no per-file predicate.** [`catch_up`] counts a tenant's rows by state; nothing
//!    here answers "is *this* file's index current?". `crates/worker/src/lib.rs` explains why that
//!    function is the one a search path eventually calls to skip work, and this crate is where it
//!    would do the most damage.
//!
//! And the honest limit, stated because a counter looks more authoritative than it is:
//! [`confirm_indexed`] records a **claim** by whatever performed the vector-store write. PostgreSQL
//! cannot verify it against Milvus. Nothing depends on it, which is what makes an unverifiable
//! claim safe to store — it is an operator's signal and a rebuild's input, never a read path's.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::SearchError;

/// Which suppression of a file a vector-store write is about.
///
/// A generation counter, bumped by every [`suppress`] of the same file, and deliberately **not** a
/// timestamp. `added_at` comes from the caller's clock and a confirmation would come from another
/// process's; comparing those two is the latent bug this module already records in [`lift_expired`],
/// where a worker running seconds fast lifted a suppression the database still held in force. A
/// value read from a row and written back to it has no clock in it.
///
/// Not `#[must_use]`: [`suppress`] returns one, and the overwhelming majority of callers — every
/// ACL change that suppresses a file and does not itself index — correctly have nothing to do with
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuppressionSeq(i64);

impl SuppressionSeq {
    /// A generation a writer carried across a process boundary — a job payload, a batch record.
    ///
    /// Deliberately constructible, because the writer that reports back is rarely the process that
    /// suppressed. What stops a fabricated value from reading as "caught up" forever is not this
    /// constructor's absence but the row's own `CHECK`, which refuses an `indexed_seq` ahead of the
    /// `suppression_seq` it claims to cover
    /// (`migrations/0014_index_catch_up.sql`).
    #[must_use]
    pub const fn new(seq: i64) -> Self {
        Self(seq)
    }

    /// The stored value, for a writer that has to carry it across a vector-store call.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for SuppressionSeq {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// How much of a tenant's denylist a vector-store write is known to cover.
///
/// Per tenant, never per file — see this module's documentation for why the per-file form is
/// refused. The three counters sum to the tenant's denylist size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CatchUp {
    /// Rows nobody has asserted anything about. **Unknown, not "the index is behind"** — in a
    /// deployment whose index writer has never called [`confirm_indexed`], this is every row, and
    /// a signal that reported those as "behind" would be indistinguishable from a real backlog.
    pub unasserted: u64,
    /// Rows whose last confirmed write predates their current suppression.
    pub behind: u64,
    /// Rows whose last confirmed write covers their current suppression.
    pub caught_up: u64,
}

impl CatchUp {
    /// Rows in this tenant's denylist, whatever their state.
    #[must_use]
    pub const fn rows(&self) -> u64 {
        self.unasserted + self.behind + self.caught_up
    }
}

/// Which of these files are currently suppressed.
///
/// Takes the candidate set rather than returning the whole denylist: a tenant that has just
/// reorganised its permissions can have a very large one, and a search's latency budget is not the
/// place to discover that.
///
/// A row whose `clears_at` has passed is *not* suppressed — the sweep that removes it is
/// housekeeping, and waiting for housekeeping to make a correct answer correct is the S4 mistake in
/// the opposite direction.
///
/// # Errors
///
/// Storage failures.
pub async fn suppressed(
    conn: &mut PgConnection,
    tenant: TenantId,
    files: &[FileId],
) -> Result<HashSet<FileId>, SearchError> {
    if files.is_empty() {
        return Ok(HashSet::new());
    }

    let ids: Vec<Uuid> = files.iter().map(|file| file.as_uuid()).collect();
    let rows =
        sqlx::query(SUPPRESSED_SQL).bind(tenant.as_uuid()).bind(&ids).fetch_all(&mut *conn).await?;

    rows.iter()
        .map(|row| {
            row.try_get::<Uuid, _>("file_id").map(FileId::from).map_err(|_| {
                SearchError::MalformedRow { column: "file_id", reason: "missing or not a uuid" }
            })
        })
        .collect()
}

/// Suppresses a file from retrieval.
///
/// **Call this in the same transaction as the ACL change that caused it.** A separate transaction
/// leaves a window in which the permission has changed and the index has not been told, and that
/// window is precisely what S3 forbids. Taking a `&mut PgConnection` rather than a pool is what
/// makes it impossible to commit separately (`plans/M1-CONTENT-CORE.md` D10).
///
/// Idempotent: suppressing an already-suppressed file refreshes the reason and the timestamp rather
/// than failing, because the second revocation is as real as the first.
///
/// # What it returns, and why anyone would want it
///
/// The [`SuppressionSeq`] this suppression created — bumped on every call, including the repeat
/// ones. It is what a subsequent vector-store write names when it reports back through
/// [`confirm_indexed`], and returning it here is what removes the need for a per-file "is this
/// file's index current?" read: the writer is *handed* the generation it is working on rather than
/// having to go and ask. See this module's documentation for why the asking form is refused.
///
/// A repeat suppression deliberately leaves `indexed_seq` alone. The old confirmation then sorts
/// *behind* the new generation, which is exactly right — a write that covered the previous
/// revocation says nothing about this one — and it keeps "confirmed once, then re-suppressed"
/// distinguishable from "never confirmed".
///
/// # Errors
///
/// Storage failures.
pub async fn suppress(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    reason: &str,
    now: DateTime<Utc>,
    clears_at: Option<DateTime<Utc>>,
) -> Result<SuppressionSeq, SearchError> {
    let row = sqlx::query(SUPPRESS_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(reason)
        .bind(now)
        .bind(clears_at)
        .fetch_one(&mut *conn)
        .await?;

    row.try_get::<i64, _>("suppression_seq").map(SuppressionSeq).map_err(|_| {
        SearchError::MalformedRow { column: "suppression_seq", reason: "missing or not a bigint" }
    })
}

/// Records that a vector-store write covering `seq` has completed for `file`.
///
/// **Call it after the store write, with the [`SuppressionSeq`] read before it.** That ordering is
/// the whole content of the claim: a confirmation recorded first would name a write that had not
/// happened, and one that re-read the row afterwards would silently absorb a suppression that
/// arrived during the write.
///
/// Records the newest claim and never an older one, so two writers finishing out of order leave the
/// later generation recorded rather than the last one to commit.
///
/// # What this is not
///
/// Not a lift, and not a condition on one. `clears_at` still decides when a suppression stops
/// suppressing, and [`suppressed`] — the read on every search — does not look at this column. See
/// this module's documentation and `migrations/0014_index_catch_up.sql`.
///
/// A row that is not there is not an error: the suppression may have been lifted while the store
/// write was in flight, which is the ordinary case and not a failure. `false` says nothing was
/// recorded, so a caller that cares can tell it apart from a claim that landed.
///
/// # Errors
///
/// Storage failures, including the `CHECK` that refuses a confirmation ahead of the row's own
/// generation — a fabricated claim rather than an observed one.
pub async fn confirm_indexed(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    seq: SuppressionSeq,
) -> Result<bool, SearchError> {
    let updated = sqlx::query(CONFIRM_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(seq.get())
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(updated > 0)
}

/// How much of this tenant's denylist a confirmed vector-store write covers.
///
/// Per tenant, never per file. The counts are for an operator and for a rebuild's progress
/// reporting; nothing on the search path reads them, and no function here will answer the question
/// for a single file — `crates/worker/src/lib.rs` sets out why that predicate is the one a search
/// eventually calls to skip work.
///
/// Reads the whole of a tenant's denylist, so it belongs in a housekeeping pass and not in a
/// request. That is the same reason [`suppressed`] takes a candidate set instead of returning the
/// table.
///
/// # Errors
///
/// Storage failures.
pub async fn catch_up(conn: &mut PgConnection, tenant: TenantId) -> Result<CatchUp, SearchError> {
    let row = sqlx::query(CATCH_UP_SQL).bind(tenant.as_uuid()).fetch_one(&mut *conn).await?;

    let read = |column: &'static str| -> Result<u64, SearchError> {
        let count: i64 = row
            .try_get(column)
            .map_err(|_| SearchError::MalformedRow { column, reason: "missing or not a bigint" })?;
        u64::try_from(count)
            .map_err(|_| SearchError::MalformedRow { column, reason: "a count came back negative" })
    };

    Ok(CatchUp {
        unasserted: read("unasserted")?,
        behind: read("behind")?,
        caught_up: read("caught_up")?,
    })
}

/// How many of this tenant's files are suppressed **right now**.
///
/// `docs/07-SEARCH-INDEXING.md §6.4` step 3's input: past a configured size the denylist means
/// invalidation is so far behind that the index is known to be wrong at scale, and retrieval
/// degrades to lexical rather than burning over-fetch budget on candidates the post-filter is about
/// to drop. [`crate::Retrieval::decide`] takes the number; this is where it comes from
/// (`ENC-698` — until it, the search route passed a literal `0`, which was inert only because
/// unreachability outranks denylist pressure and became wrong the moment a store was reachable).
///
/// # It counts what [`suppressed`] would drop, and that is load-bearing
///
/// The same `clears_at` clause, against the same clock. A count that included expired rows would
/// degrade a tenant whose denylist is entirely stale — every file in it findable, none of them
/// suppressed — which is a tenant getting *worse recall* because housekeeping has not run. `§6.4`
/// puts the lift on `clears_at` alone and this reads the same rule; the assertion that they cannot
/// drift is in this module's tests, over the SQL, because there is nowhere else to make it.
///
/// # Why a request may ask this and [`catch_up`] may not
///
/// [`catch_up`] is three filtered aggregates for an operator and belongs in housekeeping. This is
/// one `count(*)` over one tenant's rows in a table that is small by construction — `§6.4` sizes it
/// in thousands and calls anything larger a backlog — and the search path has no other way to learn
/// the number the decision needs. It answers about the *tenant*, never about a file: there is
/// deliberately no `file_id` in it, for the reason this module's tests assert about `catch_up`.
///
/// # Errors
///
/// Storage failures. Never a zero standing in for one — a failed read that reported an empty
/// denylist would silently promote a tenant off the fallback during exactly the incident the
/// fallback exists for.
pub async fn in_force(conn: &mut PgConnection, tenant: TenantId) -> Result<usize, SearchError> {
    let row = sqlx::query(IN_FORCE_SQL).bind(tenant.as_uuid()).fetch_one(&mut *conn).await?;
    let count: i64 = row.try_get("in_force").map_err(|_| SearchError::MalformedRow {
        column: "in_force",
        reason: "missing or not a bigint",
    })?;
    usize::try_from(count).map_err(|_| SearchError::MalformedRow {
        column: "in_force",
        reason: "a count came back negative",
    })
}

/// Lifts suppressions whose `clears_at` has passed, judged by the database's clock.
///
/// The worker's housekeeping. Returns how many were lifted, so a sweep that finds nothing is
/// distinguishable in metrics from a sweep that did not run.
///
/// # Why this takes no `now`
///
/// It used to, and that was a latent bug rather than a stylistic choice — found by the session that
/// wrote the sweep on top of it. [`suppressed`] judges expiry against PostgreSQL's `now()`, because
/// it runs inside the search's own transaction. If this compared against a timestamp the *caller*
/// supplied, the two would be different clocks: a worker running a few seconds fast would delete
/// rows the database still considers in force, and the file it was suppressing becomes findable
/// early — briefly, on one node, for reasons nothing logs.
///
/// The parameter is therefore gone rather than documented, because the only thing a caller could
/// usefully do with it is move the deadline forward. Both functions now ask the same clock the same
/// question.
///
/// # Errors
///
/// Storage failures.
pub async fn lift_expired(conn: &mut PgConnection, tenant: TenantId) -> Result<u64, SearchError> {
    let lifted =
        sqlx::query(LIFT_SQL).bind(tenant.as_uuid()).execute(&mut *conn).await?.rows_affected();
    Ok(lifted)
}

/// Rows still in force. A passed `clears_at` is already lifted, whether or not the sweep has run.
const SUPPRESSED_SQL: &str = "
SELECT d.file_id
  FROM retrieval_denylist d
  JOIN unnest($2::uuid[]) AS c(file_id) ON c.file_id = d.file_id
 WHERE d.tenant_id = $1
   AND (d.clears_at IS NULL OR d.clears_at > now())
";

/// The upsert, and the generation bump that lets a later write name this suppression.
///
/// `indexed_seq` is not in the `DO UPDATE` list on purpose: a confirmation of the *previous*
/// revocation must survive as a value that now sorts behind the new generation, rather than being
/// erased into the "nobody has asserted anything" state it is not in.
const SUPPRESS_SQL: &str = "
INSERT INTO retrieval_denylist (tenant_id, file_id, reason, added_at, clears_at, suppression_seq)
VALUES ($1, $2, $3, $4, $5, 1)
    ON CONFLICT (tenant_id, file_id)
    DO UPDATE SET reason = EXCLUDED.reason,
                  added_at = EXCLUDED.added_at,
                  clears_at = EXCLUDED.clears_at,
                  suppression_seq = retrieval_denylist.suppression_seq + 1
RETURNING suppression_seq
";

/// Records a claim that the vector store no longer holds this file as of generation `$3`.
///
/// `GREATEST` so an out-of-order confirmation cannot walk the record backwards. The row's own
/// `CHECK` refuses a generation ahead of `suppression_seq`, so this can only ever move within
/// claims a writer actually observed.
const CONFIRM_SQL: &str = "
UPDATE retrieval_denylist
   SET indexed_seq = GREATEST(COALESCE(indexed_seq, 0), $3)
 WHERE tenant_id = $1 AND file_id = $2
";

/// The three states of `docs/04-DATA-MODEL.md §15`, counted.
///
/// One pass, so the three numbers describe one snapshot: three separate counts of a table under
/// concurrent suppression would sum to a total no row ever had.
const CATCH_UP_SQL: &str = "
SELECT count(*) FILTER (WHERE indexed_seq IS NULL)                AS unasserted,
       count(*) FILTER (WHERE indexed_seq < suppression_seq)      AS behind,
       count(*) FILTER (WHERE indexed_seq >= suppression_seq)     AS caught_up
  FROM retrieval_denylist
 WHERE tenant_id = $1
";

const LIFT_SQL: &str = "
DELETE FROM retrieval_denylist
 WHERE tenant_id = $1 AND clears_at IS NOT NULL AND clears_at <= now()
";

/// Suppressions in force for one tenant, by the same rule [`suppressed`] applies to a candidate.
///
/// The `WHERE` clause is [`SUPPRESSED_SQL`]'s minus the candidate join, and the test below is what
/// keeps it that way: a count that used a different notion of "in force" from the drop would report
/// pressure that no search is actually feeling, or miss pressure that every search is.
const IN_FORCE_SQL: &str = "
SELECT count(*) AS in_force
  FROM retrieval_denylist
 WHERE tenant_id = $1
   AND (clears_at IS NULL OR clears_at > now())
";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The assertion `ENC-520` exists to keep true, made over the SQL because there is nowhere else
    /// to make it.
    ///
    /// The tempting change is one clause: `AND (indexed_seq IS NULL OR indexed_seq <
    /// suppression_seq)` on the read, or `AND indexed_seq >= suppression_seq` on the lift. Either
    /// reads as an improvement — "stop suppressing a file the index has already dropped" — and
    /// either makes a caller's answer depend on a worker having run and reported back. S4 would
    /// keep passing, for the wrong reason, and the wrong reason is invisible in a green suite.
    #[test]
    fn neither_the_search_read_nor_the_lift_consults_the_catch_up_columns() {
        for (name, statement) in [("suppressed", SUPPRESSED_SQL), ("lift_expired", LIFT_SQL)] {
            assert!(
                !statement.contains("indexed_seq"),
                "{name} became conditional on an index write having been confirmed"
            );
            assert!(
                !statement.contains("suppression_seq"),
                "{name} became conditional on a suppression's generation"
            );
        }
    }

    /// **`ENC-698`.** The degradation trigger counts exactly what the post-filter would drop.
    ///
    /// The tempting divergence is one clause in either direction, and both are wrong in a way that
    /// is invisible from a call site. A count with no `clears_at` filter degrades a tenant whose
    /// denylist is entirely expired — every one of those files is findable, nothing is being
    /// suppressed, and the tenant loses dense retrieval because a sweep has not run. A count that
    /// also consulted `indexed_seq` would make the trigger depend on a worker having reported back,
    /// which is the conditional lift `docs/07 §6.4` refuses and which `ENC-520` guards for the read
    /// and the lift.
    #[test]
    fn the_degradation_count_and_the_search_drop_mean_the_same_thing_by_in_force() {
        let clause = "(clears_at IS NULL OR clears_at > now())";
        assert!(
            IN_FORCE_SQL.contains(clause),
            "the count must apply the expiry rule `suppressed` applies: {IN_FORCE_SQL}"
        );
        // `suppressed` qualifies its columns; the substring compared is the rule, not the alias.
        assert!(
            SUPPRESSED_SQL.contains("d.clears_at IS NULL OR d.clears_at > now()"),
            "the drop stopped judging expiry against the database clock: {SUPPRESSED_SQL}"
        );
        assert!(
            !IN_FORCE_SQL.contains("indexed_seq") && !IN_FORCE_SQL.contains("suppression_seq"),
            "the trigger became conditional on an index write having been confirmed"
        );
        assert!(
            !IN_FORCE_SQL.contains("file_id"),
            "the trigger grew a per-file projection, which is the oracle ENC-518 refuses"
        );
    }

    /// No per-file freshness answer, asserted where it would be written.
    ///
    /// `crates/worker/src/lib.rs` refusal 1: a `fn is_fresh(file) -> bool` is what a search
    /// eventually calls to skip work. The aggregate here cannot become one by accident — it would
    /// have to grow a `file_id` in its projection first, and that is what fails.
    #[test]
    fn the_catch_up_reader_cannot_answer_for_one_file() {
        assert!(
            !CATCH_UP_SQL.contains("file_id"),
            "the catch-up reader grew a per-file projection, which is the oracle ENC-518 refuses"
        );
        assert!(CATCH_UP_SQL.contains("count(*)"), "it is an aggregate or it is an oracle");
    }

    /// A re-suppression must move the generation, or a stale confirmation reads as covering it.
    #[test]
    fn a_repeat_suppression_bumps_the_generation_and_keeps_the_old_claim() {
        assert!(
            SUPPRESS_SQL.contains("suppression_seq = retrieval_denylist.suppression_seq + 1"),
            "a second revocation of the same file would inherit the first one's confirmation"
        );
        assert!(
            !SUPPRESS_SQL.contains("indexed_seq"),
            "clearing the claim would make 'confirmed, then re-suppressed' unknown rather than \
             behind"
        );
    }
}
