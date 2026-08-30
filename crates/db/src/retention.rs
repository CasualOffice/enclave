//! Retention — one question, asked once: **which policy governs this file?**
//!
//! `migrations/0031_retention_policies.sql` holds the argument for the two tables' shape; this
//! module is the single statement that reads them, and the precedence rule that statement encodes.
//!
//! # Why there is a decision to take at all
//!
//! `retention_assignments` scopes at `TENANT`, `WORKSPACE`, `LIBRARY`, `CONTENT_TYPE` and `FILE`, so
//! a single file is routinely covered several times over: a tenant-wide seven-year rule, a
//! library-wide three-year one, a content-type rule for contracts, and an explicit hold on the one
//! document somebody is arguing about. Only one of them can decide whether today's delete goes
//! through. Something has to choose, and the choice is not a detail — it is the whole of what a
//! retention control *is*.
//!
//! # The obvious rule, and why it is wrong here
//!
//! Most-specific-wins is how ACLs work, how classifications inherit, how nearly everything with a
//! scope in this product works, and it is the wrong rule for retention. It has one consequence and
//! that consequence disqualifies it:
//!
//! > A tenant-wide *"keep everything for seven years"* would be switched off by anybody who can
//! > create a library-scoped policy.
//!
//! That is a compliance control with an off switch, held by whoever administers the smallest
//! container. Retention exists precisely to bind people who would rather not be bound — the whole
//! point of a seven-year rule is that the person holding the inconvenient document cannot shorten
//! it — and a precedence rule that lets the narrower scope win hands them the shears. Specificity
//! is an expression of *local intent*, and local intent is the thing a compliance obligation is
//! designed to override.
//!
//! # The rule this module implements: the strictest policy wins
//!
//! Ordered, and every step is in `GOVERNING_SQL`'s `ORDER BY` in this order:
//!
//! 1. **How much the action preserves.** `LEGAL_HOLD` > `RECORD` > `KEEP` > `KEEP_THEN_DELETE` >
//!    `DELETE_AFTER`. A hold is absolute; a record is immutable for its term; `KEEP` never deletes;
//!    `KEEP_THEN_DELETE` guarantees a period first; `DELETE_AFTER` guarantees nothing and only
//!    schedules destruction.
//! 2. **How long it preserves.** Longer wins, and a `NULL` duration on a preserving action is
//!    indefinite and therefore longest. Only ever compared within one action rank, so `NULL` never
//!    has to mean two things at once.
//! 3. **Specificity — but only as a tiebreak between equals.** `FILE` > `CONTENT_TYPE` > `LIBRARY` >
//!    `WORKSPACE` > `TENANT`. Two policies that preserve identically are equally correct answers to
//!    the compliance question, so the local one is the better answer to *why*: it is the one an
//!    administrator wrote about this content. `CONTENT_TYPE` outranks `LIBRARY` deliberately — a
//!    content type says what a document *is* and a library says where it currently *sits*, an
//!    obligation attaches to the former, and moving a file between libraries must not silently
//!    change how long it is kept.
//! 4. **`applied_at` descending, then the policy id descending.** Not a rule — a tiebreak. If two
//!    policies are equally strict and equally specific they are equally right, and the only
//!    property actually needed is that two reads of an unchanged table agree. Without a total order
//!    the answer would be whatever the plan happened to produce, which makes a retention decision
//!    flicker and makes a test that asserts one flaky rather than wrong.
//!
//! ## What the rule costs, stated rather than hidden
//!
//! It can over-retain. A tenant that has a genuine *minimisation* obligation — delete after thirty
//! days, and keeping the data longer is itself the violation — cannot express it as a
//! `DELETE_AFTER` policy that a `KEEP` at any scope will not beat. That case is real and this rule
//! does not serve it.
//!
//! It is still the right default, because **the two failure modes are not symmetric.** Retaining
//! something that could have been deleted leaves a document in a system, discoverable, deletable
//! tomorrow when somebody notices. Deleting something that should have been retained destroys
//! evidence, is irreversible, and is the failure that ends in a spoliation finding. A rule that
//! must be wrong sometimes should be wrong in the recoverable direction. When minimisation gets a
//! real design it gets a real mechanism — an obligation the chain carries rather than a policy that
//! wins a comparison — not an inversion of this ordering.
//!
//! # What this module returns, and what it deliberately does not decide
//!
//! [`governing_policy`] returns the policy and *nothing about what to do with it*. It does not say
//! whether a delete is permitted, does not compute a deadline, and does not look at
//! `files.on_legal_hold`. Those are the retention **stage**'s, and the split is `CLAUDE.md` rule 10
//! in the place it bites: a refusal must be returned *from a stage*, because `PolicyEngine::enforce`
//! is what audits refusals — allows and denials alike — and a repository that refused on its own
//! would produce a denial no audit row exists for.
//!
//! Rule 2 is the other half. Retention is evaluated **last**, after authorization and barriers, and
//! that ordering is load-bearing rather than incidental: a caller who lacks permission must be told
//! they lack permission, not that a matter-specific legal hold exists on a document they were never
//! allowed to know about (`docs/06 §15`). Nothing here may be consulted early to shortcut the chain.
//!
//! # `duration` is an `INTERVAL`, and it stays one
//!
//! `PgInterval` — months, days and microseconds kept apart — crosses this boundary unflattened, and
//! that is a deliberate refusal to be convenient. `timestamptz + interval '7 years'` is calendar
//! arithmetic: the same day of the same month, seven years on, across every leap day between.
//! `EXTRACT(EPOCH FROM interval '7 years')` is a 365.25-day year and lands somewhere else. The
//! difference is a day or two, and a retention deadline computed a day early is a document destroyed
//! a day before it was permitted to be — an irreversible act, taken by a rounding error, in the one
//! subsystem whose entire purpose is not to do that.
//!
//! So the deadline arithmetic belongs in PostgreSQL, where `duration` can be added to a timestamp
//! directly, and this type exists to be carried to that statement rather than to be reasoned about
//! in Rust. There is deliberately no `as_seconds()`, and there should not be one.
//!
//! # Why this sits in `enclave-db`
//!
//! The crate header names four argued exceptions to *"no repositories here"*, [`crate::recent`] is
//! the fifth and [`crate::trash`] the sixth; this is the seventh, and it takes
//! [`crate::conditional_access`]' argument rather than [`crate::quota`]'s. The retention
//! *stage* will own what a policy means — `docs/02-HLD.md`, authoritative for the crate list, gives
//! it a crate — and that crate would otherwise have to reach past this one for a connection, which
//! `CLAUDE.md` forbids in the sentence that matters: all database access through [`TenantScoped`],
//! no `sqlx::query!` in a domain crate. So the statement lives here.
//!
//! What that crate cannot delegate here is the *decision*. This module holds a precedence ordering
//! and no policy: it will tell you which of five policies governs a file, and it has no opinion
//! about whether that means the delete proceeds.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::ids::{sql, RowIdExt as _, SqlId};
use crate::tenant::TenantScoped;
use crate::DbError;

/// A retention period as PostgreSQL stores it: months, days and microseconds, kept apart.
///
/// Re-exported rather than converted. See the module header — collapsing it to a count of seconds
/// silently changes what `+ duration` means, and the direction of the error is *earlier*.
pub use sqlx::postgres::types::PgInterval;

/// Generates a vocabulary that mirrors a `CHECK` constraint in
/// `migrations/0031_retention_policies.sql`.
///
/// The same shape `crates/files/src/model.rs` uses, and copied for the reason it copied it:
/// `enclave_core`'s equivalent macro is private to that crate. What the macro buys is that
/// [`as_str`](RetentionAction::as_str) and `from_column` are generated from one list, so the writer
/// and the reader cannot fall a variant apart.
///
/// **No `PartialOrd`/`Ord` is derived, and that is the point of writing the derive list out here.**
/// A derived ordering on [`RetentionAction`] would be a second precedence rule — silent, defined by
/// declaration order, and free to disagree with the one in `GOVERNING_SQL` that actually decides.
/// Ranking lives in the statement, in one place, where the tests can see it.
macro_rules! stored_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored spelling, identical to the migration's `CHECK` vocabulary.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, in declaration order — for admin surfaces that enumerate the
            /// vocabulary instead of hard-coding it, and for the tests that check this list against
            /// the migration's `CHECK` and against `GOVERNING_SQL`'s ranking.
            #[must_use]
            pub const fn all() -> &'static [Self] { &[ $( Self::$variant ),+ ] }

            /// Reads the column, refusing anything the `CHECK` constraint should have made
            /// impossible.
            ///
            /// A decode failure rather than a default, and here that is not merely tidy: every
            /// default is a *retention* answer, so a wrong one destroys or preserves a document for
            /// a reason nobody chose. An unrecognised value means the migration's vocabulary and
            /// this one have drifted, and the honest response is to refuse the read — which the
            /// stage propagates, which refuses the delete.
            fn from_column(raw: &str) -> Result<Self, sqlx::Error> {
                match raw {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(sqlx::Error::Decode(
                        format!(
                            "retention: `{other}` is not a {} this schema defines. \
                             migrations/0031_retention_policies.sql's CHECK constraint and this \
                             vocabulary have drifted apart; the read is refused rather than \
                             guessed, because every guess is a retention decision",
                            stringify!($name),
                        )
                        .into(),
                    )),
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

stored_enum! {
    /// What a retention policy does to the content it governs.
    ///
    /// `docs/04-DATA-MODEL.md §13`'s vocabulary, verbatim. Declaration order here is *not* the
    /// precedence order — see the macro's note on `Ord`; `GOVERNING_SQL` ranks them and is the only
    /// place that does.
    pub enum RetentionAction {
        /// Retain indefinitely. Never deleted by the lifecycle.
        Keep => "KEEP",
        /// Retain for `duration` measured from `basis`, then delete.
        KeepThenDelete => "KEEP_THEN_DELETE",
        /// Delete `duration` after `basis`, with no retention guarantee before that.
        DeleteAfter => "DELETE_AFTER",
        /// Declare governed content a record: immutable, out of the ordinary lifecycle.
        Record => "RECORD",
        /// Preserve absolutely, for a matter. The migration refuses `allow_user_delete` with this.
        LegalHold => "LEGAL_HOLD",
    }
}

stored_enum! {
    /// Which instant a policy's `duration` is measured from.
    ///
    /// This module reads the value and does not resolve it: `LAST_ACCESSED`, `EVENT` and
    /// `DECLARED_RECORD` all need tables or facts outside these two — `records` in particular does
    /// not exist yet — so turning a basis into a timestamp is the stage's job and not a read
    /// model's.
    pub enum RetentionBasis {
        /// The file's `created_at`.
        Created => "CREATED",
        /// The file's `modified_at`.
        Modified => "MODIFIED",
        /// The last access recorded for the file.
        LastAccessed => "LAST_ACCESSED",
        /// An external event named by `event_key`, which the migration requires with this basis.
        Event => "EVENT",
        /// The instant the file was declared a record.
        DeclaredRecord => "DECLARED_RECORD",
    }
}

stored_enum! {
    /// The scope an assignment attaches a policy at.
    ///
    /// Every one of these is a column of the covered file's own row, which is what makes the
    /// governing read five equality probes rather than a walk: retention, unlike an ACL, has no
    /// per-folder scope and therefore no chain to climb.
    pub enum RetentionScopeType {
        /// Everything in the tenant. `scope_id` is NULL for these rows.
        Tenant => "TENANT",
        /// Everything in one workspace.
        Workspace => "WORKSPACE",
        /// Everything in one library.
        Library => "LIBRARY",
        /// Everything of one content type, wherever it sits.
        ContentType => "CONTENT_TYPE",
        /// One named file.
        File => "FILE",
    }
}

/// A retention policy's identifier, unique within a tenant.
///
/// Defined here rather than in `enclave_core::id` for the reason [`crate::dlp::DlpRuleId`] and
/// [`crate::conditional_access::RuleId`] are: `core` carries the identifiers that cross crate
/// boundaries, and this one does not yet — nothing outside this module and the retention stage has
/// a use for it. It moves to `core` when a second crate needs to name one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetentionPolicyId(Uuid);

impl RetentionPolicyId {
    /// A new, time-ordered identifier.
    #[must_use]
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl core::fmt::Display for RetentionPolicyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl SqlId for RetentionPolicyId {
    const TYPE_NAME: &'static str = "RetentionPolicyId";

    fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    fn to_uuid(self) -> Uuid {
        self.0
    }
}

/// The policy that governs one file, and the assignment that carried it there.
///
/// The assignment half is not decoration. A retention refusal is the least explicable denial in the
/// product — it says *no* about a document the caller can see, for a reason held in a table they
/// cannot — so the stage needs to be able to audit **which** policy decided and **at what scope**,
/// and [`covering`](Self::covering) is what lets it record that the answer was a choice among
/// several rather than the only candidate. All three come out of the same statement; asking again
/// would put a second query on the deletion path of every file in the product.
///
/// There is deliberately nothing decision-shaped here: no `may_delete`, no computed deadline, no
/// obligation. Those belong to the retention stage, because a refusal has to be returned from a
/// stage for `PolicyEngine::enforce` to audit it (`CLAUDE.md` rule 10).
///
/// **`scope_id` is deliberately absent, and its absence loses nothing.** Given the file, every
/// scope's target is already determined: `TENANT` is the file's tenant, `WORKSPACE` its
/// `workspace_id`, `LIBRARY` its `library_id`, `CONTENT_TYPE` its `content_type_id`, `FILE` its own
/// id. Returning it would restate a column of `files` — and it would put an untyped `Uuid` on a
/// public boundary, which `CLAUDE.md` forbids and which here would be four different kinds of
/// identifier sharing one type with nothing to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoverningPolicy {
    /// The policy that won.
    pub policy_id: RetentionPolicyId,
    /// Its administrator-facing name, for the audit row and the admin surface.
    pub name: String,
    /// What it does. Ranked first in the precedence ordering.
    pub action: RetentionAction,
    /// How long, or `None` for indefinite. An `INTERVAL`, unflattened — see the module header.
    pub duration: Option<PgInterval>,
    /// Which instant `duration` is measured from. Resolving it is the stage's job.
    pub basis: RetentionBasis,
    /// The event `basis` waits for; `Some` exactly when the basis is
    /// [`RetentionBasis::Event`](RetentionBasis::Event), which the migration enforces both ways.
    pub event_key: Option<String>,
    /// Whether governed content is a record — immutable and outside the ordinary lifecycle.
    pub is_record: bool,
    /// Whether a user may still delete governed content themselves. The migration refuses this for
    /// `LEGAL_HOLD` and `RECORD`, so it is never `true` alongside either.
    pub allow_user_delete: bool,
    /// The scope the winning assignment attaches at. Third in the precedence ordering, and only
    /// ever a tiebreak between policies that preserve identically.
    pub scope_type: RetentionScopeType,
    /// When that assignment was applied.
    pub applied_at: DateTime<Utc>,
    /// When it stops applying, or `None` for indefinitely. Always in the future — an expired
    /// assignment is not returned at all.
    pub expires_at: Option<DateTime<Utc>>,
    /// How many unexpired assignments cover this file in total, this one included.
    ///
    /// Never zero: a `GoverningPolicy` exists only because at least one covered it. Greater than
    /// one means the precedence ordering actually chose, which is the fact worth having in an audit
    /// row — *"kept under the tenant hold, which beat the library's 30-day rule"* is a defensible
    /// sentence and *"kept"* is not.
    pub covering: u32,
}

/// Which policy governs one file — the whole precedence rule, as one statement.
///
/// One statement rather than five, and the reason is where this runs: the deletion path of every
/// file in the product, plus every purge sweep, plus every lifecycle job. Five round trips and a
/// comparison in Rust would put the precedence rule in a place no `EXPLAIN` can see and no database
/// constraint can bound, and it would make the answer depend on interleaving if an assignment
/// changed between the probes.
///
/// The predicates, and what each holds on its own:
///
///   * `f.tenant_id = $1`, `a.tenant_id = $1` and `p.tenant_id = $1` — tenant isolation as an
///     application predicate, written on the anchor and on both joins. Row-level security says the
///     same thing independently and neither layer is a backstop for the other (`lib.rs`).
///
///     **Which of the three is load-bearing was measured, not reasoned about**, by deleting each on
///     a connection where RLS is inert (`crates/db/tests/retention.rs`). `f.tenant_id = $1` is
///     load-bearing **alone**: without it a file id from another tenant resolves and is answered
///     about. `a.tenant_id = $1` and `p.tenant_id = $1` are redundant *with each other* — deleting
///     either one alone leaves the isolation test green, because the survivor still excludes the
///     row — and deleting **both together leaks**: a `TENANT`-scoped assignment matches on
///     `scope_id IS NULL`, which is the same NULL in every tenant, so another tenant's tenant-wide
///     legal hold reaches this tenant's file. All three stay. The pair is not decoration: the
///     assignments clause is also what keeps this an index probe on
///     `idx_retention_assignments_scope` instead of a scan of every tenant's assignments, and the
///     policies clause is what stops a `policy_id` that reached the assignment table by some route
///     the composite key did not cover from resolving to another tenant's policy row.
///   * The five-way scope disjunction — each arm equates `scope_type` *and* `scope_id`, so each is
///     an index probe on `idx_retention_assignments_scope` rather than a filter over the tenant's
///     whole assignment set. `TENANT` matches on `scope_id IS NULL`, which is the shape the
///     migration's `retention_assignments_scope_target` constraint guarantees.
///   * `a.expires_at IS NULL OR a.expires_at > now()` — the withdrawal mechanism. `enclave_app`
///     holds no `DELETE` on either table, so without this clause an assignment could never be
///     undone: it is not a nicety, it is the only way out.
///
/// **`f.deleted_at IS NULL` is deliberately absent**, unlike every other read model in this crate. A
/// trashed file is exactly the file whose retention matters most — the purge sweep asks this
/// question about rows that are already in the recycle bin, and a policy that stopped applying the
/// moment somebody pressed delete would be a retention control that any user could step around by
/// deleting first and waiting.
///
/// `count(*) OVER ()` runs before `LIMIT`, so it counts every covering assignment and not the one
/// that survived it.
///
/// The `ORDER BY` is the precedence rule and the module header argues every line of it. The action
/// ranking has no `ELSE`: an action the `CHECK` permits and this `CASE` does not know ranks `NULL`,
/// `NULL` sorts first under `DESC`, so it wins — and then `RetentionAction::from_column` refuses to
/// decode it and the read fails. Both halves point the same way, which is closed.
const GOVERNING_SQL: &str = "
SELECT p.id                AS policy_id,
       p.name              AS name,
       p.action            AS action,
       p.duration          AS duration,
       p.basis             AS basis,
       p.event_key         AS event_key,
       p.is_record         AS is_record,
       p.allow_user_delete AS allow_user_delete,
       a.scope_type        AS scope_type,
       a.applied_at        AS applied_at,
       a.expires_at        AS expires_at,
       count(*) OVER ()    AS covering
  FROM files f
  JOIN retention_assignments a
    ON a.tenant_id = $1
   AND (a.expires_at IS NULL OR a.expires_at > now())
   AND ( (a.scope_type = 'TENANT'       AND a.scope_id IS NULL)
      OR (a.scope_type = 'WORKSPACE'    AND a.scope_id = f.workspace_id)
      OR (a.scope_type = 'LIBRARY'      AND a.scope_id = f.library_id)
      OR (a.scope_type = 'CONTENT_TYPE' AND a.scope_id = f.content_type_id)
      OR (a.scope_type = 'FILE'         AND a.scope_id = f.id) )
  JOIN retention_policies p
    ON p.tenant_id = $1
   AND p.id = a.policy_id
 WHERE f.tenant_id = $1
   AND f.id = $2
 ORDER BY CASE p.action
            WHEN 'LEGAL_HOLD'       THEN 4
            WHEN 'RECORD'           THEN 3
            WHEN 'KEEP'             THEN 2
            WHEN 'KEEP_THEN_DELETE' THEN 1
            WHEN 'DELETE_AFTER'     THEN 0
          END DESC,
          p.duration DESC NULLS FIRST,
          CASE a.scope_type
            WHEN 'FILE'         THEN 4
            WHEN 'CONTENT_TYPE' THEN 3
            WHEN 'LIBRARY'      THEN 2
            WHEN 'WORKSPACE'    THEN 1
            WHEN 'TENANT'       THEN 0
          END DESC,
          a.applied_at DESC,
          p.id DESC
 LIMIT 1
";

/// The policy governing `file`, or `None` when no unexpired assignment covers it.
///
/// `None` means **no policy**, not a default one. There is deliberately no fallback: a retention
/// answer invented here would be a rule nobody wrote, applied to every file in every tenant that
/// has not configured retention, and it would be indistinguishable in an audit row from one an
/// administrator chose. What a tenant with no retention configuration has is no retention, and the
/// stage is where that turns into a decision.
///
/// This form takes the tenant explicitly and so can be pointed at any tenant the connection can
/// reach; prefer [`governing_policy`], which cannot. It exists for callers holding a plain
/// connection — and for the isolation tests, which have to run the statement somewhere row-level
/// security is not silently doing the work the predicate is credited with.
///
/// # Errors
///
/// Query failures, and a decode refusal when `action`, `basis` or `scope_type` holds a value this
/// vocabulary does not define — see `from_column`, and note that the refusal is the safe direction:
/// the stage propagates it and the delete does not proceed.
pub async fn governing_policy_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
) -> Result<Option<GoverningPolicy>, DbError> {
    let Some(row) = sqlx::query(GOVERNING_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .fetch_optional(&mut *conn)
        .await
        .map_err(DbError::Query)?
    else {
        return Ok(None);
    };

    let action: String = row.try_get("action").map_err(DbError::Query)?;
    let basis: String = row.try_get("basis").map_err(DbError::Query)?;
    let scope_type: String = row.try_get("scope_type").map_err(DbError::Query)?;
    let covering: i64 = row.try_get("covering").map_err(DbError::Query)?;

    Ok(Some(GoverningPolicy {
        policy_id: row.try_get_id("policy_id").map_err(DbError::Query)?,
        name: row.try_get("name").map_err(DbError::Query)?,
        action: RetentionAction::from_column(&action).map_err(DbError::Query)?,
        duration: row.try_get("duration").map_err(DbError::Query)?,
        basis: RetentionBasis::from_column(&basis).map_err(DbError::Query)?,
        event_key: row.try_get("event_key").map_err(DbError::Query)?,
        is_record: row.try_get("is_record").map_err(DbError::Query)?,
        allow_user_delete: row.try_get("allow_user_delete").map_err(DbError::Query)?,
        scope_type: RetentionScopeType::from_column(&scope_type).map_err(DbError::Query)?,
        applied_at: row.try_get("applied_at").map_err(DbError::Query)?,
        expires_at: row.try_get("expires_at").map_err(DbError::Query)?,
        // Saturating rather than fallible: the count is bounded by the tenant's own assignment
        // count and cannot realistically exceed five, and a retention read that failed because a
        // *diagnostic* field overflowed would refuse a delete for a reason unrelated to retention.
        covering: u32::try_from(covering).unwrap_or(u32::MAX),
    }))
}

/// [`governing_policy_on`], for a caller holding a [`TenantScoped`] transaction.
///
/// The tenant comes from the transaction rather than from an argument, so this form cannot be asked
/// about a tenant other than the one whose row-level-security context is established. Every
/// production caller should be this one — including, when it exists, the retention stage.
///
/// # Errors
///
/// As [`governing_policy_on`].
pub async fn governing_policy(
    tx: &mut TenantScoped,
    file: FileId,
) -> Result<Option<GoverningPolicy>, DbError> {
    let tenant = tx.tenant_id();
    governing_policy_on(&mut *tx, tenant, file).await
}

/// A policy as an administrative surface lists it.
///
/// Distinct from [`GoverningPolicy`] on purpose. That one answers *"what governs this file"* and
/// carries the assignment that reached it — `scope_type`, `applied_at`, `covering`. This one is the
/// policy's own row and nothing else, because a listing that folded in one assignment would show a
/// policy applied to four scopes four times, and a listing that folded in all of them would make
/// the shape of the response depend on data the caller has not asked for yet.
#[derive(Debug, Clone)]
pub struct PolicyRow {
    /// Identifier, unique within the tenant.
    pub id: RetentionPolicyId,
    /// What an administrator called it. Shown in listings and never parsed.
    pub name: String,
    /// What the policy does to content it governs.
    pub action: RetentionAction,
    /// How long, for the two actions that require one.
    pub duration: Option<PgInterval>,
    /// What the duration is measured from.
    pub basis: RetentionBasis,
    /// The event a `RetentionBasis::Event` policy waits for.
    pub event_key: Option<String>,
    /// Whether governed content is a record.
    pub is_record: bool,
    /// Whether a user may still delete governed content themselves.
    pub allow_user_delete: bool,
    /// When the policy was written.
    pub created_at: DateTime<Utc>,
}

/// One binding of a policy to a scope.
///
/// There is no identifier column: `migrations/0031` keys an assignment by
/// `(tenant_id, policy_id, scope_type, COALESCE(scope_id, …))`, so the tuple *is* the address. An
/// admin surface withdrawing one therefore names the scope rather than an opaque id, which is also
/// the form an administrator can read back from the listing they are looking at.
#[derive(Debug, Clone)]
pub struct AssignmentRow {
    /// The policy this applies.
    pub policy_id: RetentionPolicyId,
    /// Which kind of thing it is attached to.
    pub scope_type: RetentionScopeType,
    /// The thing itself, `None` exactly when the scope is the whole tenant.
    pub scope_id: Option<Uuid>,
    /// When it started applying.
    pub applied_at: DateTime<Utc>,
    /// When it stops, `None` for indefinitely.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A policy an administrator has asked to create.
///
/// A separate type from [`PolicyRow`] rather than one with an optional id, because the two differ
/// in what they promise: this one has been validated against nothing yet, and the database's six
/// `CHECK` constraints are what it must survive. Keeping them apart means a handler cannot pass a
/// half-built row where a stored one is expected.
#[derive(Debug, Clone)]
pub struct NewPolicy {
    /// Identifier the caller minted, so the row it gets back is the row it named.
    pub id: RetentionPolicyId,
    /// What to call it.
    pub name: String,
    /// What it does.
    pub action: RetentionAction,
    /// How long.
    pub duration: Option<PgInterval>,
    /// Measured from what.
    pub basis: RetentionBasis,
    /// The event key, for an `EVENT` basis.
    pub event_key: Option<String>,
    /// Whether governed content is a record.
    pub is_record: bool,
    /// Whether a user may still delete governed content.
    pub allow_user_delete: bool,
}

const LIST_POLICIES_SQL: &str = "
    SELECT id, name, action, duration, basis, event_key, is_record, allow_user_delete, created_at
      FROM retention_policies
     WHERE tenant_id = $1
     ORDER BY created_at DESC, id DESC";

const INSERT_POLICY_SQL: &str = "
    INSERT INTO retention_policies
        (tenant_id, id, name, action, duration, basis, event_key, is_record, allow_user_delete)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";

const LIST_ASSIGNMENTS_SQL: &str = "
    SELECT policy_id, scope_type, scope_id, applied_at, expires_at
      FROM retention_assignments
     WHERE tenant_id = $1
     ORDER BY applied_at DESC";

// `ON CONFLICT … DO NOTHING` against the unique index rather than a `SELECT` first: two
// administrators assigning the same policy to the same scope at the same moment is a race a
// read-then-write loses, and the loser's `INSERT` would raise a constraint violation the handler
// would have to translate back into the same answer this gives directly. `RETURNING` tells the
// caller which of the two happened, which is the difference between `201` and `409`.
//
// The conflict target is written as the index's expression, not `(tenant_id, policy_id, scope_type,
// scope_id)`: that tuple is not unique — NULLs are distinct — and naming it would compile, run, and
// silently permit duplicate TENANT-scoped assignments, which is the one scope where a duplicate is
// most likely and least visible.
const INSERT_ASSIGNMENT_SQL: &str = "
    INSERT INTO retention_assignments (tenant_id, policy_id, scope_type, scope_id)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (tenant_id, policy_id, scope_type,
                 COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))
    DO NOTHING
    RETURNING applied_at";

// Withdrawal is an `UPDATE`, because `migrations/0031` grants `enclave_app` no `DELETE` on this
// table. `now()` rather than a bound timestamp so the value comes from the database's clock, and
// `expires_at IS NULL` so withdrawing an already-withdrawn assignment reports that it changed
// nothing instead of moving the deadline a second time.
//
// `> applied_at` is not asserted here: `retention_assignments_expiry_after_application` is a table
// constraint, so an assignment applied in the same transaction — `applied_at = now()` — cannot be
// withdrawn in it. That is correct rather than awkward. An assignment created and withdrawn in one
// transaction never applied to anything, and a retention control that can be made to leave no trace
// of having existed is the one thing this table is for.
const WITHDRAW_ASSIGNMENT_SQL: &str = "
    UPDATE retention_assignments
       SET expires_at = now()
     WHERE tenant_id = $1
       AND policy_id = $2
       AND scope_type = $3
       AND scope_id IS NOT DISTINCT FROM $4
       AND expires_at IS NULL
    RETURNING policy_id";

fn policy_row(row: &sqlx::postgres::PgRow) -> Result<PolicyRow, sqlx::Error> {
    Ok(PolicyRow {
        id: row.try_get_id("id")?,
        name: row.try_get("name")?,
        action: RetentionAction::from_column(row.try_get("action")?)?,
        duration: row.try_get("duration")?,
        basis: RetentionBasis::from_column(row.try_get("basis")?)?,
        event_key: row.try_get("event_key")?,
        is_record: row.try_get("is_record")?,
        allow_user_delete: row.try_get("allow_user_delete")?,
        created_at: row.try_get("created_at")?,
    })
}

/// Every retention policy this tenant has written, newest first.
///
/// Withdrawn policies are **not** filtered out, because a policy cannot be withdrawn — only its
/// assignments can. A policy with no live assignment governs nothing and still belongs in the
/// listing: it is the thing an administrator re-applies, and hiding it would make re-application
/// look like authoring a new control.
///
/// # Errors
///
/// [`DbError::Query`] if the statement fails, or a decode error if the stored vocabulary and this
/// one have drifted — see [`RetentionAction`].
pub async fn list_policies(tx: &mut TenantScoped) -> Result<Vec<PolicyRow>, DbError> {
    let tenant = tx.tenant_id();
    let rows = sqlx::query(LIST_POLICIES_SQL)
        .bind(sql(tenant))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    rows.iter().map(policy_row).collect::<Result<_, _>>().map_err(DbError::Query)
}

/// Every assignment this tenant has made, live or withdrawn.
///
/// Expired rows are returned rather than filtered: this is the administrative view, and *"this
/// policy stopped applying to the Legal library last Tuesday"* is the question an administrator
/// most often has. The governing read in [`governing_policy_on`] filters them, which is the place
/// where the distinction decides something.
///
/// # Errors
///
/// [`DbError::Query`] if the statement fails or a stored `scope_type` is not one this schema
/// defines.
pub async fn list_assignments(tx: &mut TenantScoped) -> Result<Vec<AssignmentRow>, DbError> {
    let tenant = tx.tenant_id();
    let rows = sqlx::query(LIST_ASSIGNMENTS_SQL)
        .bind(sql(tenant))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    rows.iter()
        .map(|row| {
            Ok(AssignmentRow {
                policy_id: row.try_get_id("policy_id")?,
                scope_type: RetentionScopeType::from_column(row.try_get("scope_type")?)?,
                scope_id: row.try_get("scope_id")?,
                applied_at: row.try_get("applied_at")?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(DbError::Query)
}

/// Writes a policy.
///
/// The six `CHECK` constraints in `migrations/0031` are the validation, and they are deliberately
/// not restated in Rust. A duplicated rule is a rule with two chances to be relaxed one at a time,
/// and the copy that drifts is the one nobody is reading — so a policy that claims to be a
/// `LEGAL_HOLD` a user may delete under is refused by the database, and this returns that refusal
/// rather than pre-empting it.
///
/// # Errors
///
/// [`DbError::Query`], including a constraint violation whose name identifies which rule was
/// broken — the constraints are named for exactly that reason.
pub async fn insert_policy(tx: &mut TenantScoped, policy: &NewPolicy) -> Result<(), DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(INSERT_POLICY_SQL)
        .bind(sql(tenant))
        .bind(sql(policy.id))
        .bind(&policy.name)
        .bind(policy.action.as_str())
        .bind(policy.duration.as_ref())
        .bind(policy.basis.as_str())
        .bind(policy.event_key.as_ref())
        .bind(policy.is_record)
        .bind(policy.allow_user_delete)
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Applies a policy to a scope.
///
/// Returns `false` when an identical live assignment already existed, which the caller renders as
/// `409` rather than as a second `201` — applying a policy twice is almost always a double-submit,
/// and reporting it as success would leave an administrator believing they had made two changes.
///
/// The composite foreign key is what stops another tenant's policy being applied here, and it is
/// load-bearing rather than decorative: PostgreSQL runs referential integrity with row security
/// deliberately not enforced, so a single-column reference would accept one.
///
/// # Errors
///
/// [`DbError::Query`], including the foreign-key violation raised when `policy_id` names no policy
/// in this tenant, and the `retention_assignments_scope_target` violation when a non-`TENANT` scope
/// arrives with no `scope_id`.
pub async fn assign_policy(
    tx: &mut TenantScoped,
    policy: RetentionPolicyId,
    scope_type: RetentionScopeType,
    scope_id: Option<Uuid>,
) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let applied: Option<(DateTime<Utc>,)> = sqlx::query_as(INSERT_ASSIGNMENT_SQL)
        .bind(sql(tenant))
        .bind(sql(policy))
        .bind(scope_type.as_str())
        .bind(scope_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(applied.is_some())
}

/// Stops an assignment applying, from now.
///
/// Returns whether a live assignment was withdrawn. `false` means it was already withdrawn or never
/// existed — indistinguishable here on purpose, and for the same reason `crates/db/src/dlp.rs`
/// makes the same two indistinguishable: the caller is an administrator of *this* tenant, so the
/// distinction leaks nothing, but a handler that branched on it would grow two messages that must
/// keep agreeing about a difference nobody can act on.
///
/// The row is left in place. `migrations/0031` grants no `DELETE`, and the reason is on the grants:
/// a statement that removes the evidence a policy ever applied is the statement a retention table
/// exists to make impossible.
///
/// # Errors
///
/// [`DbError::Query`] if the statement fails.
pub async fn withdraw_assignment(
    tx: &mut TenantScoped,
    policy: RetentionPolicyId,
    scope_type: RetentionScopeType,
    scope_id: Option<Uuid>,
) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let withdrawn: Option<(Uuid,)> = sqlx::query_as(WITHDRAW_ASSIGNMENT_SQL)
        .bind(sql(tenant))
        .bind(sql(policy))
        .bind(scope_type.as_str())
        .bind(scope_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    Ok(withdrawn.is_some())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The migration this module reads, read back as text.
    ///
    /// The vocabularies below are checked against the `CHECK` constraints themselves rather than
    /// against a copy of them in a comment. `docs/12 §1.2`: a test that restates the thing it is
    /// testing proves the restatement.
    const MIGRATION: &str = include_str!("../../../migrations/0031_retention_policies.sql");

    /// Layer 1, asserted where it is written.
    ///
    /// A deleted `tenant_id` predicate leaves row-level security holding tenant isolation alone —
    /// `docs/12 §4.1` `T5`'s designed property, and therefore something a behavioural test running
    /// under RLS cannot catch. The behavioural half lives in `crates/db/tests/retention.rs` and runs
    /// where RLS is inert; this is the cheap, always-run half.
    ///
    /// Three, counted, not one: the anchor on `files`, the join to `retention_assignments` and the
    /// join to `retention_policies`. A single `contains` would stay green with two of the three
    /// deleted, and the one on `retention_policies` is the one that matters most — it is what stops
    /// another tenant's policy name reaching an audit row.
    #[test]
    fn every_relation_in_the_governing_read_is_scoped_to_one_tenant() {
        let scoped = GOVERNING_SQL.matches("tenant_id = $1").count();
        assert!(
            scoped >= 3,
            "the governing read has {scoped} tenant-scoped predicates; the files anchor, the \
             assignments join and the policies join each need one, or another tenant's retention \
             policy can decide this tenant's deletion: {GOVERNING_SQL}"
        );
    }

    /// The precedence rule, as the ordering that implements it.
    ///
    /// Every clause is a one-line deletion that leaves a query returning a plausible row — the
    /// direction no assertion about a returned value notices, because *some* policy still comes
    /// back. `crates/db/tests/retention.rs` proves each behaviourally; this is the always-run guard
    /// against the deletion.
    #[test]
    fn the_ordering_ranks_strictness_first_and_specificity_only_as_a_tiebreak() {
        let action_rank = GOVERNING_SQL
            .find("CASE p.action")
            .expect("the ordering must rank actions by how much they preserve");
        let scope_rank = GOVERNING_SQL
            .find("CASE a.scope_type")
            .expect("the ordering must rank scopes as a tiebreak");
        assert!(
            action_rank < scope_rank,
            "the action ranking must come before the scope ranking in the ORDER BY. With them the \
             other way round, most-specific wins — and a tenant-wide seven-year hold is switched \
             off by anybody who can create a library-scoped policy: {GOVERNING_SQL}"
        );

        let duration_rank = GOVERNING_SQL
            .find("p.duration DESC NULLS FIRST")
            .expect("longer preservation must beat shorter, with NULL meaning indefinite");
        assert!(
            action_rank < duration_rank && duration_rank < scope_rank,
            "duration must be compared after the action rank and before the scope rank: comparing \
             it first would let a 10-year DELETE_AFTER beat a 1-year KEEP_THEN_DELETE, and \
             comparing it after the scope would let a file-scoped 30 days beat a tenant-wide 7 \
             years: {GOVERNING_SQL}"
        );

        assert!(
            GOVERNING_SQL.contains("a.applied_at DESC") && GOVERNING_SQL.contains("p.id DESC"),
            "the ordering must end in a total tiebreak, or two equally strict, equally specific \
             policies resolve to whichever the plan happened to produce and the answer flickers \
             between two reads of an unchanged table: {GOVERNING_SQL}"
        );
    }

    /// Expiry is the only way to withdraw an assignment, so the read has to honour it.
    ///
    /// `enclave_app` holds no `DELETE` on `retention_assignments` (`migrations/0031`), which makes
    /// this predicate load-bearing in a way an expiry filter usually is not: deleting the clause
    /// does not merely show stale rows, it makes retention permanent and unremovable by any request
    /// the application can issue.
    #[test]
    fn an_expired_assignment_is_filtered_by_the_read_and_not_by_a_sweep() {
        assert!(
            GOVERNING_SQL.contains("a.expires_at IS NULL OR a.expires_at > now()"),
            "the governing read must exclude expired assignments; no DELETE is granted on the \
             table, so this clause is the only withdrawal mechanism there is: {GOVERNING_SQL}"
        );
    }

    /// The trash is not an exit from retention.
    ///
    /// Every other read model in this crate filters `deleted_at IS NULL`, so adding it here would
    /// look like consistency rather than like the defect it is: a policy that stopped applying when
    /// a file reached the recycle bin could be stepped around by deleting first and waiting for the
    /// purge, which is the one path retention exists to stand in.
    #[test]
    fn a_trashed_file_still_has_its_retention_policy() {
        assert!(
            !GOVERNING_SQL.contains("deleted_at"),
            "the governing read must not filter trashed files: the purge sweep asks this question \
             about rows already in the recycle bin, and a policy that lapsed on delete would be \
             evaded by deleting first: {GOVERNING_SQL}"
        );
    }

    /// Each scope arm equates both columns, so each is an index probe.
    ///
    /// Dropping `scope_type` from an arm is the interesting mutation and it is silent: the query
    /// still returns a row, it just also matches a `LIBRARY` assignment whose `scope_id` happens to
    /// equal a workspace id — and, far more likely, it stops using
    /// `idx_retention_assignments_scope` on the deletion path of every file.
    #[test]
    fn every_scope_arm_equates_both_the_scope_type_and_its_target() {
        for scope in RetentionScopeType::all() {
            let arm = format!("a.scope_type = '{}'", scope.as_str());
            assert!(
                GOVERNING_SQL.contains(&arm),
                "the governing read has no arm for {scope} scope, so a policy assigned there \
                 governs nothing and fails silently towards not preserving: {GOVERNING_SQL}"
            );
        }
        assert!(
            GOVERNING_SQL.contains("a.scope_type = 'TENANT'       AND a.scope_id IS NULL"),
            "the TENANT arm must match on scope_id IS NULL, which is the shape \
             retention_assignments_scope_target guarantees: {GOVERNING_SQL}"
        );
    }

    /// The vocabulary in the ranking is the vocabulary in the enum.
    ///
    /// The `CASE` has no `ELSE`, so an action the enum knows and the ranking does not sorts `NULL`
    /// and wins every comparison — which is the safe direction and is still not something to leave
    /// to a future edit. Checked against `RetentionAction::all()` rather than a hard-coded list, so
    /// adding a variant fails here.
    #[test]
    fn the_action_ranking_covers_every_action_the_vocabulary_defines() {
        for action in RetentionAction::all() {
            assert!(
                GOVERNING_SQL.contains(&format!("WHEN '{}'", action.as_str())),
                "{action} has no rank in the governing read's ORDER BY, so it sorts NULL and wins \
                 every comparison by accident rather than by argument: {GOVERNING_SQL}"
            );
        }
    }

    /// The Rust vocabularies and the migration's `CHECK` constraints are one list.
    ///
    /// Read out of the migration file itself. A variant added to one and not the other is the
    /// classic drift: the `CHECK` accepts a value `from_column` refuses, and the first time anybody
    /// notices is a retention read failing in production against a row an admin endpoint happily
    /// wrote.
    #[test]
    fn every_stored_vocabulary_matches_the_migrations_check_constraint() {
        for action in RetentionAction::all() {
            assert!(
                MIGRATION.contains(&format!("'{}'", action.as_str())),
                "{action} is in RetentionAction and not in \
                 migrations/0031_retention_policies.sql's CHECK vocabulary"
            );
        }
        for basis in RetentionBasis::all() {
            assert!(
                MIGRATION.contains(&format!("'{}'", basis.as_str())),
                "{basis} is in RetentionBasis and not in the migration's CHECK vocabulary"
            );
        }
        for scope in RetentionScopeType::all() {
            assert!(
                MIGRATION.contains(&format!("'{}'", scope.as_str())),
                "{scope} is in RetentionScopeType and not in the migration's CHECK vocabulary"
            );
        }
    }

    /// An unknown stored value is refused rather than defaulted.
    ///
    /// The positive control is in the same assertion pair: a value the vocabulary *does* define
    /// decodes, so "it refused" is not equally true of a function that refuses everything.
    #[test]
    fn an_action_outside_the_vocabulary_is_a_decode_failure_and_not_a_default() {
        assert_eq!(
            RetentionAction::from_column("LEGAL_HOLD").expect("a defined action must decode"),
            RetentionAction::LegalHold,
        );
        let refused = RetentionAction::from_column("KEEP_FOREVER_PROBABLY")
            .expect_err("an undefined action must not decode to anything");
        assert!(
            matches!(refused, sqlx::Error::Decode(_)),
            "an unrecognised action must surface as a decode failure, because every default here \
             is a retention decision nobody made: {refused:?}"
        );
    }

    /// The count is taken in the same statement as the winner.
    ///
    /// `count(*) OVER ()` is evaluated before `LIMIT`, so it counts the covering set rather than
    /// the survivor. Replacing it with a second query would put an extra round trip on the deletion
    /// path of every file, and the two reads could disagree.
    #[test]
    fn the_covering_count_is_taken_before_the_limit_and_in_one_statement() {
        assert!(
            GOVERNING_SQL.contains("count(*) OVER ()"),
            "the covering count must be a window function in this statement: it is what lets an \
             audit row say the answer was a choice among several rather than the only candidate: \
             {GOVERNING_SQL}"
        );
        assert_eq!(
            GOVERNING_SQL.matches("SELECT").count(),
            1,
            "the governing read must remain one statement with no subquery; the precedence rule \
             belongs somewhere EXPLAIN can see it: {GOVERNING_SQL}"
        );
    }
}
