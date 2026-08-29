//! The retention stage over PostgreSQL — the one decision this stage exists to take.
//!
//! `crates/db/src/retention.rs` answers *which policy governs this file*. This module answers the
//! only question the policy chain asks of retention: **may this caller destroy this content?**
//!
//! # Why this is a stage and not a `WHERE` clause
//!
//! The tempting implementation is a predicate on the delete statement — `AND NOT EXISTS (SELECT 1
//! FROM retention_assignments …)` — and it is wrong in three separate ways, each of which is a rule
//! this repository has written down.
//!
//!   * **A statement that matches no rows is not a refusal, it is a silence.** `UPDATE … WHERE`
//!     with a retention predicate returns zero rows affected, and the handler has to invent a
//!     reason for it. The reason it would invent is indistinguishable from *the file was already
//!     deleted*, from *the revision did not match*, and from *the id was never real*. A user told
//!     "not found" when the true answer is "a legal hold covers this matter" has been told
//!     something false.
//!   * **Nothing would be audited.** `CLAUDE.md` rule 10: a refusal is recorded by
//!     `PolicyEngine::enforce`, which records exactly the [`StageDecision`]s the stages hand it. A
//!     denial expressed as a `WHERE` clause is a denial no row in `audit_events` explains, and
//!     "we refused to destroy this document and here is when and why" is the single statement a
//!     retention system exists to be able to make.
//!   * **The ordering would be lost, and the ordering is the control.**
//!     `docs/06-SECURITY-DLP-ACCESS.md §15` puts retention **last** in the chain *"so a user who
//!     lacks permission is told they lack permission rather than learning that a matter-specific
//!     legal hold exists"*. A predicate on the write runs after every stage, which sounds like the
//!     same thing and is not: the chain's ordering is about which refusal the caller is *shown*,
//!     and the write is reached only once the chain has allowed — so the predicate would fire for
//!     exactly the callers who got that far, and its message would be the first thing they learned.
//!     Being a stage is what makes the ordering property inherited rather than re-argued. **No
//!     stage before this one may short-circuit on retention state**, for the same reason.
//!
//! # A cascading delete is a delete of the subtree
//!
//! `FileRepository::trash` stamps one `deleted_at` across the whole subtree, and
//! `crates/api/src/routes/lifecycle.rs` authorizes the descendants through
//! `AuthorizationService::authorize_many` — the **authorization stage alone**, which never reaches
//! retention. So a delete addressed at a folder arrives here as one [`ResourceRef`] naming the
//! folder, and a stage that asked only about that node would let a seven-year hold on a contract be
//! defeated by deleting the folder the contract sits in.
//!
//! This stage therefore walks the same subtree the cascade will, and refuses if **any** node
//! beneath the addressed one is governed by a policy that forbids user deletion. The walk is
//! [`CASCADE_SQL`] and is [`crates/files`'s `LIVE_SUBTREE`] re-derived here for one reason: it does
//! not filter on `deleted_at`. `crates/db/src/retention.rs` omits the same predicate and says why —
//! *a policy that stopped applying the moment somebody pressed delete would be a retention control
//! that any user could step around by deleting first and waiting* — and the same argument applies
//! to the walk. Trash and purge both arrive as [`FileAction::Delete`]; one addresses a live subtree
//! and the other a trashed one, and walking both is the superset.
//!
//! [`crates/files`'s `LIVE_SUBTREE`]: https://example.invalid/
//!
//! # The subtree is walked once and probed a handful of times
//!
//! Asking [`enclave_db::governing_policy`] about every node of a ten-thousand-file folder would be
//! ten thousand round trips inside one transaction, on the delete path. It is also unnecessary, and
//! the reason is a property of the governing read rather than a guess about it.
//!
//! `GOVERNING_SQL` matches a file through exactly five columns of that file's own row — the
//! `TENANT` arm matches every file, and the other four equate `scope_id` against `workspace_id`,
//! `library_id`, `content_type_id` and `id`. So **two files with the same
//! `(workspace_id, library_id, content_type_id)`, neither of which carries a `FILE`-scoped
//! assignment, match an identical set of assignments and therefore resolve to an identical
//! governing policy** — the `ORDER BY` is total (it ends `a.applied_at DESC, p.id DESC`), so equal
//! inputs give an equal winner rather than merely a comparable one.
//!
//! [`CASCADE_SQL`] reduces the subtree to that equivalence: every node carrying a `FILE`-scoped
//! assignment, individually, plus one representative of each distinct
//! `(workspace_id, library_id, content_type_id)` among the nodes that do not. The reduction can
//! only ever probe *more* than necessary — the `FILE`-scope test deliberately omits the expiry
//! filter, so an expired file-scoped assignment moves a node out of the representative set and into
//! the probed set, which costs a round trip and changes no answer.
//!
//! **This is a claim about `GOVERNING_SQL`'s five scopes, and a sixth would break it silently.**
//! [`crate::policy::tests::the_grouping_key_covers_every_scope_the_governing_read_matches_on`] is
//! the guard: it fails the day [`RetentionScopeType`] grows a variant, and the fix is a new column
//! in the grouping key, not a new arm anywhere else.
//!
//! # What is deliberately not decided here
//!
//! Everything except destruction. `docs/06 §15` gives retention authority over *deletion*; a stage
//! that also refused reads would be a second authorization stage with none of the first one's
//! model, and `is_record` would quietly become a permission nobody granted. [`FileAction::Restore`]
//! in particular is always allowed — restoring is the opposite of destroying, and refusing it would
//! strand every document trashed before its policy was assigned.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, ContainerAction, Dependency, Error as CoreError, FileAction, FileId, ReasonCode,
    RequestContext, ResourceRef, Result as CoreResult, RetentionService, ShareAction,
    StageDecision, TenantId,
};
use enclave_db::{
    governing_policy, sql, DbPool, GoverningPolicy, RetentionAction, RetentionBasis, RowIdExt as _,
    TenantScoped,
};
use sqlx::{PgConnection, Row as _};

/// The result type used throughout this crate.
pub type Result<T, E = RetentionError> = core::result::Result<T, E>;

/// Something went wrong evaluating retention.
///
/// The distinction `PolicyEngine::enforce` depends on, restated here because it is easy to lose:
/// **an error is not a denial.** A denial is an answer — the policy was read and it forbids the
/// delete. An error means the policy could not be read, and the engine propagates it rather than
/// converting it into a refusal. Collapsing the two in *this* stage would be the more dangerous
/// direction of the two: a database outage that read as `RETENTION_BLOCKS_DELETE` would tell a user
/// a legal hold exists where none does, which is a false statement about a matter.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RetentionError {
    /// A statement failed.
    #[error("retention query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened, or a governing read failed.
    ///
    /// Never a verdict. `retention_policies` and `retention_assignments` are both under forced
    /// row-level security, so without a tenant context the reads return nothing — which here means
    /// *no policy*, which means the delete proceeds. That failure mode has to be an error or it is
    /// a control that switches itself off.
    #[error("retention database failure")]
    Database(#[from] enclave_db::DbError),

    /// The delete cascade is deeper than the walk will follow.
    ///
    /// An error rather than "decide on what we found". A truncated walk is a walk missing its
    /// deepest nodes, and a partial answer here can only ever be wrong in the permissive direction
    /// — the direction that destroys content.
    #[error("the delete cascade is deeper than the configured limit of {limit}")]
    CascadeTooDeep {
        /// The configured depth that was reached.
        limit: i32,
    },

    /// The delete cascade spans more distinct retention scopes than the stage will probe.
    ///
    /// The same argument as [`Self::CascadeTooDeep`], and the same direction. Note what the limit
    /// counts: not files, but *equivalence classes* plus file-scoped assignments, so a folder of a
    /// million documents in one library under one content type costs one probe.
    #[error("the delete cascade spans more retention scopes than the configured limit of {limit}")]
    CascadeTooWide {
        /// The configured probe count that was exceeded.
        limit: usize,
    },
}

impl From<RetentionError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks.
    ///
    /// Nothing here becomes [`CoreError::PolicyDenied`], and that is the property worth stating: a
    /// refusal from this stage is a [`StageDecision`], constructed in [`PgRetention::evaluate`],
    /// audited by the engine. An error is the other thing, and it renders as an internal or an
    /// upstream failure so that "we could not read your retention policy" never reaches a user
    /// wearing the words of a policy that read fine and said no.
    fn from(value: RetentionError) -> Self {
        match value {
            RetentionError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            RetentionError::Database(error) => error.into(),
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// Bounds on how far the cascade walk will go before it refuses to answer.
///
/// Both are bounds on work done inside a request, and both exist for the reason
/// [`enclave_authorization::ResolverLimits`] exists: an unbounded recursive query over data a user
/// controls is a denial-of-service primitive. Exceeding either is an error — see
/// [`RetentionError::CascadeTooDeep`] — because the alternative is a partial answer, and a partial
/// retention answer permits a delete it has not finished checking.
///
/// [`enclave_authorization::ResolverLimits`]: https://example.invalid/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CascadeLimits {
    /// How many levels below the addressed node the walk will follow.
    pub max_depth: i32,
    /// How many governing reads one evaluation will issue.
    ///
    /// Counts equivalence classes and file-scoped assignments, not files — see the module note on
    /// the reduction.
    pub max_probes: usize,
}

impl CascadeLimits {
    /// The limits in force unless a caller says otherwise.
    ///
    /// 256 levels is far past any tree a person navigates and far short of anything PostgreSQL
    /// notices. 512 probes is generous against what the reduction actually produces: a tenant would
    /// need five hundred distinct `(workspace, library, content type)` combinations, or five hundred
    /// individually-pinned files, inside a single delete.
    pub const DEFAULT: Self = Self { max_depth: 256, max_probes: 512 };
}

impl Default for CascadeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The nodes whose retention must be consulted before the addressed node is destroyed.
///
/// Returns the addressed node itself plus the reduced set of its descendants — see the module note
/// for what "reduced" means and why the reduction is exact. An empty answer means the addressed
/// node is not visible in this tenant at all, which is [`Ok`] and not an error: it is the same
/// answer for another tenant's id, a purged one and one that was never real (`CLAUDE.md` rule 7).
///
/// `$3` is the depth bound and `$4` is the probe bound **plus one**, so that hitting the bound is
/// distinguishable from sitting exactly on it. A `LIMIT` that silently truncated would be the
/// permissive failure this whole module is arranged against.
///
/// Every `tenant_id` predicate is written explicitly. Row-level security says the same thing
/// independently and neither layer is a backstop for the other; which of them is load-bearing is
/// measured in `crates/retention/tests/policy.rs`, on a connection where row security is inert.
const CASCADE_SQL: &str = "
WITH RECURSIVE subtree AS (
    SELECT f.id, f.workspace_id, f.library_id, f.content_type_id, 0 AS depth
      FROM files f
     WHERE f.tenant_id = $1
       AND f.id        = $2
    UNION ALL
    SELECT c.id, c.workspace_id, c.library_id, c.content_type_id, s.depth + 1
      FROM subtree s
      JOIN files c
        ON c.tenant_id = $1
       AND c.parent_id = s.id
     WHERE s.depth < $3
),
nodes AS (
    SELECT DISTINCT id, workspace_id, library_id, content_type_id FROM subtree
),
classified AS (
    SELECT n.id,
           n.workspace_id,
           n.library_id,
           n.content_type_id,
           EXISTS (SELECT 1
                     FROM retention_assignments a
                    WHERE a.tenant_id = $1
                      AND a.scope_type = 'FILE'
                      AND a.scope_id = n.id) AS pinned
      FROM nodes n
),
probes AS (
    SELECT id FROM classified WHERE pinned
    UNION
    SELECT id FROM (
        SELECT DISTINCT ON (workspace_id, library_id, content_type_id) id
          FROM classified
         WHERE NOT pinned
         ORDER BY workspace_id, library_id, content_type_id, id
    ) representatives
)
SELECT p.id                            AS id,
       (SELECT max(depth) FROM subtree) AS deepest
  FROM probes p
 LIMIT $4
";

/// The instant a file's own basis column is read at, for [`purge_deadline_on`].
///
/// The addition happens in PostgreSQL and the interval is never flattened into seconds. That is
/// `migrations/0031_retention_policies.sql`'s rule and it is not a style preference:
/// `timestamptz + interval '7 years'` is calendar arithmetic that lands on the same day seven years
/// later, whereas `EXTRACT(EPOCH FROM interval '7 years')` assumes a 365.25-day year and lands
/// somewhere else. A deadline a day early is a document destroyed a day before it was permitted to
/// be.
///
/// `$3::text` is cast explicitly because PostgreSQL cannot infer the type of a bare parameter used
/// as a `CASE` operand.
const DEADLINE_SQL: &str = "
SELECT CASE $3::text
         WHEN 'CREATED'  THEN f.created_at
         WHEN 'MODIFIED' THEN f.modified_at
       END + $4 AS deadline
  FROM files f
 WHERE f.tenant_id = $1
   AND f.id        = $2
";

/// When a trashed file may be destroyed, as far as retention is concerned.
///
/// Deliberately three answers rather than an `Option<DateTime<Utc>>`. *Nothing retains this* and
/// *this is retained forever* are opposite instructions that both come out of an `Option` as
/// `None`, and the caller that confuses them purges a file under a legal hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeDeadline {
    /// No unexpired assignment covers the file. Retention imposes no deadline of its own; the
    /// recycle bin's dwell is the only one.
    Unretained,
    /// Retained until this instant, and purgeable after it.
    Until(DateTime<Utc>),
    /// Retained with no computable end.
    ///
    /// A `KEEP` or `RECORD` policy with no duration, any `LEGAL_HOLD`, or a basis this build cannot
    /// resolve to an instant. All three are the same instruction to a purge sweep — *not by a
    /// clock* — and separating them would invite a caller to treat one of them as a deadline.
    Indefinite,
}

impl PurgeDeadline {
    /// The instant a purge sweep may destroy the file, given the recycle bin's own dwell.
    ///
    /// `bin_dwell_until` is what the deployment would have used with no retention configured —
    /// today `crates/api/src/routes/lifecycle.rs`'s `now + TRASH_RETENTION_DAYS`. The answer is the
    /// **later** of the two, never the retention deadline alone: the bin's dwell is a promise to the
    /// user that a mistaken delete is recoverable for thirty days, and a `DELETE_AFTER '1 day'`
    /// policy must not shorten it into a thirty-second undo window.
    ///
    /// [`None`] means *never*, and a caller storing this into `files.purge_after` should store SQL
    /// `NULL` — which is what the column already means for a file no sweep may touch.
    #[must_use]
    pub fn purge_after(self, bin_dwell_until: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Unretained => Some(bin_dwell_until),
            Self::Until(retained_until) => Some(retained_until.max(bin_dwell_until)),
            Self::Indefinite => None,
        }
    }
}

/// [`RetentionService`] backed by `retention_policies` and `retention_assignments` in PostgreSQL.
///
/// Holds a pool because the trait hands it no connection: the policy chain is composed once at
/// start-up and called from handlers that have no transaction of their own yet. Every query still
/// runs inside a [`TenantScoped`] transaction opened here — the pool is passed to
/// [`TenantScoped::begin`] and never queried directly, which is the distinction the no-raw-pool
/// gate draws.
///
/// The tenant comes from [`RequestContext::tenant_id`] and never from
/// [`ResourceRef::tenant_id`] (`CLAUDE.md` rule 3). `PolicyEngine::enforce` has already compared
/// the two and answered `404` on a mismatch, so a reference naming another tenant cannot reach here
/// in production; when one does in a test, the transaction is still this tenant's and the answer is
/// the same as for a file that does not exist.
#[derive(Debug, Clone)]
pub struct PgRetention {
    pool: DbPool,
    limits: CascadeLimits,
}

impl PgRetention {
    /// Builds the stage over an existing pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool, limits: CascadeLimits::DEFAULT }
    }

    /// Builds the stage with explicit cascade limits.
    #[must_use]
    pub const fn with_limits(pool: DbPool, limits: CascadeLimits) -> Self {
        Self { pool, limits }
    }

    /// The bounds this stage walks under.
    #[must_use]
    pub const fn limits(&self) -> CascadeLimits {
        self.limits
    }

    /// The first node of the cascade whose policy forbids the caller from deleting it.
    ///
    /// One transaction for the walk and every governing read, so the answer is a consistent
    /// snapshot: an assignment written between the walk and a probe cannot produce a decision that
    /// was never true of any single state of the database.
    async fn blocking_node(
        &self,
        tenant: TenantId,
        root: FileId,
    ) -> Result<Option<GoverningPolicy>> {
        let mut tx = TenantScoped::begin(&self.pool, tenant).await?;
        let found = self.first_refusal(&mut tx, root).await;
        // Read-only, so the rollback a dropped handle performs would be equivalent; committing
        // explicitly keeps the connection's return to the pool on the success path rather than in
        // `Drop`, where a failure would be invisible.
        let committed = tx.commit().await;
        let found = found?;
        committed?;
        Ok(found)
    }

    /// The walk and the probes, inside a transaction the caller owns.
    async fn first_refusal(
        &self,
        tx: &mut TenantScoped,
        root: FileId,
    ) -> Result<Option<GoverningPolicy>> {
        for node in cascade_probes(tx, root, self.limits).await? {
            if let Some(policy) = governing_policy(tx, node).await? {
                if !policy.allow_user_delete {
                    return Ok(Some(policy));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl RetentionService for PgRetention {
    /// Whether retention permits this action.
    ///
    /// Exhaustive over every action the workspace defines, deliberately and against the temptation
    /// to write `_ => allow`. `enclave_core::Action` is not `#[non_exhaustive]` for exactly this
    /// reason — *"adding an action should break every exhaustive match in every policy service,
    /// because each of them genuinely has to decide what the new action means"* — and a wildcard
    /// here is how a future `FileAction::Shred` becomes a destructive path retention never saw.
    ///
    /// # Errors
    ///
    /// Evaluation failures, which are never denials ([`RetentionError`]).
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        let destructive = match action {
            Action::File(file) => match file {
                // The one action this stage exists to be able to refuse. Covers both halves of
                // `docs/03-LLD.md §6`'s definition — "move to the recycle bin or purge" — because a
                // policy that governed only one of them would be evaded by using the other.
                FileAction::Delete => true,
                // `Restore` is the opposite of destroying. Refusing it would strand every document
                // trashed before its policy was assigned, in a bin its owner is told they may
                // empty.
                FileAction::Restore
                // Everything below reads, exposes, copies or edits. Retention has authority over
                // *deletion* (`docs/06 §15`); a stage that refused these would be a second
                // authorization stage with none of the first one's model, and `is_record` would
                // become a permission nobody granted.
                | FileAction::MetadataRead
                | FileAction::Preview
                | FileAction::ContentRead
                | FileAction::Download
                | FileAction::Print
                | FileAction::Export
                | FileAction::Edit
                | FileAction::Copy
                | FileAction::Move
                | FileAction::Share
                | FileAction::ShareExternal
                | FileAction::VersionRead
                | FileAction::VersionRestore
                | FileAction::ManagePermissions
                | FileAction::Sync => false,
            },
            // `ContainerAction::Delete` removes a workspace or library "and, transitively, what it
            // holds", so it is destructive — and it is deliberately **not** decided here. A
            // container reference carries no `FileId`, the cascade walk has nothing to seed from,
            // and answering `allow` on a walk that never ran would be a control reporting a result
            // it did not compute. It is allowed because the container delete endpoints do not exist
            // yet; the day one lands it needs a scope-rooted walk of its own, and this arm is where
            // a reader meets that. See the crate's `integration_needed` note and `ENC-940`.
            Action::Container(
                ContainerAction::Read
                | ContainerAction::Create
                | ContainerAction::Update
                | ContainerAction::Delete
                | ContainerAction::ManageMembers
                | ContainerAction::ManagePermissions,
            ) => false,
            // A share is a grant, not content. Revoking one destroys no bytes.
            Action::Share(
                ShareAction::Create
                | ShareAction::CreateExternal
                | ShareAction::Read
                | ShareAction::Update
                | ShareAction::Revoke,
            ) => false,
            // Tenant administration. A retention policy is itself administered through these, and a
            // stage that refused them would make a misconfigured policy unfixable.
            Action::Admin(_) => false,
        };

        if !destructive {
            return Ok(StageDecision::allow());
        }

        // A destructive action against something with no `FileId` — a version, a chunk, a user.
        // There is no subtree to walk and no file row to resolve a scope against, so there is no
        // retention state to consult.
        let Some(root) = resource.as_file_id() else {
            return Ok(StageDecision::allow());
        };

        match self.blocking_node(ctx.tenant_id, root).await.map_err(CoreError::from)? {
            // The refusal names the code and nothing else. `GoverningPolicy` carries the policy's
            // name, its matter and its duration, and none of that reaches the caller: `docs/06 §15`
            // is explicit that the existence of a matter-specific hold is itself sensitive, and
            // `ReasonCode::RetentionBlocksDelete` renders as `RETENTION_BLOCKS_DELETE` with a
            // `ContactAdministrator` remediation, which is the whole of what a user is owed here.
            // The engine writes the audit row that does name the policy.
            Some(_policy) => Ok(StageDecision::deny(ReasonCode::RetentionBlocksDelete)),
            None => Ok(StageDecision::allow()),
        }
    }
}

/// The nodes whose retention governs a delete addressed at `root`, for a caller holding a
/// transaction.
///
/// The tenant comes from the transaction rather than from an argument, so this form cannot be asked
/// about a tenant other than the one whose row-level-security context is established. Every
/// production caller should be this one.
///
/// # Errors
///
/// As [`cascade_probes_on`].
pub async fn cascade_probes(
    tx: &mut TenantScoped,
    root: FileId,
    limits: CascadeLimits,
) -> Result<Vec<FileId>> {
    let tenant = tx.tenant_id();
    cascade_probes_on(&mut *tx, tenant, root, limits).await
}

/// [`cascade_probes`] against an explicit tenant.
///
/// This form can be pointed at any tenant the connection can reach; prefer [`cascade_probes`],
/// which cannot. It exists for the isolation tests, which have to run the statement somewhere
/// row-level security is not silently doing the work the `tenant_id` predicates are credited with.
///
/// # Errors
///
/// Query failures; [`RetentionError::CascadeTooDeep`] when the walk hits `limits.max_depth`, and
/// [`RetentionError::CascadeTooWide`] when more than `limits.max_probes` nodes need consulting.
/// Both are errors rather than truncations because a truncated cascade check permits a delete it
/// has not finished checking.
pub async fn cascade_probes_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    root: FileId,
    limits: CascadeLimits,
) -> Result<Vec<FileId>> {
    // One more than the bound, so that "we hit the limit" is distinguishable from "we sit on it".
    let fetch = i64::try_from(limits.max_probes).unwrap_or(i64::MAX).saturating_add(1);

    let rows = sqlx::query(CASCADE_SQL)
        .bind(sql(tenant))
        .bind(sql(root))
        .bind(limits.max_depth)
        .bind(fetch)
        .fetch_all(&mut *conn)
        .await?;

    if rows.len() > limits.max_probes {
        return Err(RetentionError::CascadeTooWide { limit: limits.max_probes });
    }

    let mut probes = Vec::with_capacity(rows.len());
    for row in &rows {
        // Every row carries the same `deepest`; checking it on each is free and does not depend on
        // the result set being non-empty in some particular way.
        let deepest: Option<i32> = row.try_get("deepest")?;
        if deepest.is_some_and(|depth| depth >= limits.max_depth) {
            return Err(RetentionError::CascadeTooDeep { limit: limits.max_depth });
        }
        probes.push(row.try_get_id("id")?);
    }
    Ok(probes)
}

/// When a trashed file may be purged, for a caller holding a transaction.
///
/// The answer `crates/api/src/routes/lifecycle.rs` needs and does not have: it hard-codes a
/// thirty-day bin dwell and computes `purge_after` from it alone, so a `KEEP '7 years'` policy
/// governs nothing on the purge path today. Combine the result with that dwell through
/// [`PurgeDeadline::purge_after`].
///
/// # Errors
///
/// As [`purge_deadline_on`].
pub async fn purge_deadline(tx: &mut TenantScoped, file: FileId) -> Result<PurgeDeadline> {
    let policy = governing_policy(tx, file).await?;
    let Some(policy) = policy else { return Ok(PurgeDeadline::Unretained) };
    let tenant = tx.tenant_id();
    purge_deadline_on(&mut *tx, tenant, file, &policy).await
}

/// [`purge_deadline`] for a policy the caller has already resolved.
///
/// Split out because the purge sweep resolves the governing policy anyway — it has to, to know
/// whether the file may be destroyed at all — and resolving it twice would put the precedence read
/// on the sweep's critical path once per file for no answer it did not already hold.
///
/// # Errors
///
/// Query failures. A file that is not visible in `tenant` is [`PurgeDeadline::Indefinite`], not an
/// error and not a deadline: an id this transaction cannot resolve is one no sweep should act on.
pub async fn purge_deadline_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    policy: &GoverningPolicy,
) -> Result<PurgeDeadline> {
    // A hold ends when a matter is released, never on a clock. `retention_policies` permits a
    // duration on a `LEGAL_HOLD` row and no sweep may act on it: reading that duration as a
    // deadline would destroy evidence on a schedule nobody set.
    if policy.action == RetentionAction::LegalHold {
        return Ok(PurgeDeadline::Indefinite);
    }

    // No duration means indefinite — `migrations/0031` requires one for `KEEP_THEN_DELETE` and
    // `DELETE_AFTER`, so this is a `KEEP` or a `RECORD` that says "keep, full stop".
    let Some(duration) = policy.duration else { return Ok(PurgeDeadline::Indefinite) };

    // `CREATED` and `MODIFIED` are columns of `files`. The other three are not resolvable in this
    // build and are refused rather than approximated:
    //
    //   * `LAST_ACCESSED` would need a last-access instant for the file. `recent_files` records
    //     one *per user*, which is a different fact; taking the maximum over it would make a
    //     retention deadline depend on who happened to open the document.
    //   * `EVENT` waits for `event_key`, and nothing publishes retention events yet.
    //   * `DECLARED_RECORD` reads `records.declared_at`, and `migrations/0031` deliberately did not
    //     create that table.
    //
    // Answering `Indefinite` is the closed direction for a retention control — it preserves — and
    // it is visible: a policy whose files never leave the bin is a question an administrator asks,
    // whereas an approximated deadline is a document destroyed on a date nobody chose.
    let basis = match policy.basis {
        RetentionBasis::Created => "CREATED",
        RetentionBasis::Modified => "MODIFIED",
        RetentionBasis::LastAccessed | RetentionBasis::Event | RetentionBasis::DeclaredRecord => {
            return Ok(PurgeDeadline::Indefinite)
        }
    };

    let deadline: Option<DateTime<Utc>> = sqlx::query(DEADLINE_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .bind(basis)
        .bind(duration)
        .fetch_optional(&mut *conn)
        .await?
        .map(|row| row.try_get("deadline"))
        .transpose()?
        .flatten();

    Ok(deadline.map_or(PurgeDeadline::Indefinite, PurgeDeadline::Until))
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_db::RetentionScopeType;

    use super::*;

    /// The reduction in [`CASCADE_SQL`] is exact only while `GOVERNING_SQL` matches a file through
    /// the four columns this grouping key names, plus the tenant-wide arm that matches every file.
    ///
    /// A sixth scope — a `FOLDER` scope is the obvious one somebody will want — would make two
    /// files in the same workspace, library and content type resolve to *different* policies, and
    /// the representative chosen here would answer for a class it no longer represents. That is a
    /// silent permissive failure: a folder-scoped hold defeated by deleting a sibling's parent.
    ///
    /// Fails the day [`RetentionScopeType`] grows a variant. The fix is a new column in
    /// `CASCADE_SQL`'s `DISTINCT ON`, not a new arm anywhere else.
    #[test]
    fn the_grouping_key_covers_every_scope_the_governing_read_matches_on() {
        assert_eq!(
            RetentionScopeType::all(),
            &[
                RetentionScopeType::Tenant,
                RetentionScopeType::Workspace,
                RetentionScopeType::Library,
                RetentionScopeType::ContentType,
                RetentionScopeType::File,
            ],
            "CASCADE_SQL groups undistinguished nodes by (workspace_id, library_id, \
             content_type_id) and probes file-scoped ones individually. A scope this key does not \
             name would make the representative answer for files it does not represent"
        );

        assert!(
            CASCADE_SQL.contains("DISTINCT ON (workspace_id, library_id, content_type_id)"),
            "the grouping key is the four scopes minus the tenant-wide one, which matches every \
             file, and minus the file-scoped one, which is probed individually: {CASCADE_SQL}"
        );
        assert!(
            CASCADE_SQL.contains("a.scope_type = 'FILE'"),
            "a file-scoped assignment takes its node out of the grouping and into an individual \
             probe; without this arm a pinned file would be answered for by a sibling: {CASCADE_SQL}"
        );
    }

    /// The walk never filters on `deleted_at`, and that is deliberate.
    ///
    /// `crates/db/src/retention.rs` omits the same predicate for the same reason: a retention
    /// control that stopped applying the moment somebody pressed delete would be evaded by deleting
    /// first and waiting. `FileAction::Delete` is both trash and purge, so the walk has to reach a
    /// subtree that is already in the bin.
    ///
    /// Fails when `AND f.deleted_at IS NULL` is added to either term.
    #[test]
    fn the_cascade_walk_does_not_stop_at_the_recycle_bin() {
        assert!(
            !CASCADE_SQL.contains("deleted_at"),
            "a delete addressed at a trashed subtree is a purge, and it is exactly the operation \
             retention exists to refuse: {CASCADE_SQL}"
        );
    }

    /// Tenant isolation is written as an application predicate on every table the walk touches.
    ///
    /// Three of them: the anchor, the recursive join, and the file-scope probe. Row-level security
    /// says the same thing independently and neither layer is a backstop for the other. Which of
    /// the three is load-bearing *alone* is measured in `tests/policy.rs`, on a connection where
    /// row security is inert.
    #[test]
    fn every_table_the_walk_touches_carries_a_tenant_predicate() {
        assert_eq!(
            CASCADE_SQL.matches("tenant_id = $1").count(),
            3,
            "the anchor, the recursive join and the file-scope probe each need one; a missing \
             predicate on the recursive term would let a subtree cross a tenant boundary if a \
             `parent_id` ever named another tenant's row: {CASCADE_SQL}"
        );
    }

    /// The bin's dwell is a floor, never a ceiling.
    ///
    /// A `DELETE_AFTER '1 day'` policy must not turn a thirty-day recycle bin into a one-day one:
    /// the dwell is a promise that a mistaken delete is recoverable, and retention's job is to
    /// *extend* preservation, not to shorten it.
    ///
    /// Fails when `purge_after` returns the retention deadline rather than the later of the two.
    #[test]
    fn retention_never_shortens_the_recycle_bins_own_dwell() {
        let now = Utc::now();
        let dwell = now + chrono::Duration::days(30);

        let short = PurgeDeadline::Until(now + chrono::Duration::days(1));
        assert_eq!(
            short.purge_after(dwell),
            Some(dwell),
            "a short policy must not shorten the bin"
        );

        let long = PurgeDeadline::Until(now + chrono::Duration::days(2555));
        assert_eq!(
            long.purge_after(dwell),
            Some(now + chrono::Duration::days(2555)),
            "a long policy must extend past the bin"
        );

        assert_eq!(PurgeDeadline::Unretained.purge_after(dwell), Some(dwell));
    }

    /// *Nothing retains this* and *this is retained forever* must not collapse into one answer.
    ///
    /// The failure this guards is a purge sweep that treats a missing deadline as "no deadline, go
    /// ahead" and destroys a file under a legal hold. Fails if `Indefinite` is ever given a
    /// `purge_after` of `Some(_)`.
    #[test]
    fn an_indefinitely_retained_file_has_no_purge_instant_at_all() {
        let dwell = Utc::now() + chrono::Duration::days(30);
        assert_eq!(PurgeDeadline::Indefinite.purge_after(dwell), None);
        assert_ne!(
            PurgeDeadline::Indefinite.purge_after(dwell),
            PurgeDeadline::Unretained.purge_after(dwell),
            "an unretained file and one held forever are opposite instructions to a sweep"
        );
    }

    /// An evaluation failure never renders as a denial.
    ///
    /// The property the engine depends on: if this produced `PolicyDenied`, a database outage would
    /// be indistinguishable from a legal hold — and it would tell a user a matter exists.
    #[test]
    fn a_retention_failure_never_renders_as_a_refusal() {
        let error: CoreError = RetentionError::CascadeTooDeep { limit: 256 }.into();
        assert!(!matches!(error, CoreError::PolicyDenied { .. }), "{error:?}");
        assert_eq!(error.code(), "INTERNAL_ERROR");

        let error: CoreError = RetentionError::CascadeTooWide { limit: 512 }.into();
        assert!(!matches!(error, CoreError::PolicyDenied { .. }), "{error:?}");

        let error: CoreError = RetentionError::Storage(sqlx::Error::PoolClosed).into();
        assert!(
            matches!(
                error,
                CoreError::Upstream { dependency: Dependency::Postgres, retryable: true }
            ),
            "{error:?}"
        );
    }
}
