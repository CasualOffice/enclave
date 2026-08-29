//! Writing `acl_entries` — the half of authorization that did not exist.
//!
//! Everything else in this crate reads. [`crate::resolve`] holds the rules, [`crate::repo`] fetches
//! the rows, [`crate::service`] answers the question, and [`crate::materialise`] copies entries that
//! were already written somewhere else. Until this module the only statement in the crate — in the
//! whole workspace outside `/tests/` — that could put a row *into* `acl_entries` was
//! [`crate::materialise::MATERIALISE_SQL`], and nothing called it with an entry that did not
//! already exist. A running deployment could therefore resolve permissions perfectly and could not
//! be given one: every grant in every test arrived through `enclave_testing::content::grant`, which
//! is a fixture and ships in no binary. The product was a lock with no key cut for it.
//!
//! # The shape of the gap, so it is not re-opened somewhere else
//!
//! The temptation, once a permissions route exists, is to write its `INSERT` in the handler. That
//! is the same mistake in a new place: the statement below carries five decisions that are not
//! obvious from the DDL — the conflict target is an *expression* list, an `ALLOW` may not land on a
//! `DENY`, `inherited_from` has to be cleared, duplicate actions abort the whole statement, and a
//! file's `acl_revision` has to move — and each of them is silent when it is wrong. They belong in
//! one function that the tests in `tests/grant.rs` can hold still.
//!
//! # This is an engine, not an entry point
//!
//! Nothing here authorizes anything. A caller must already have taken
//! [`enclave_core::ContainerAction::ManagePermissions`] on the resource through
//! `PolicyEngine::enforce` (`CLAUDE.md` rule 1, `docs/03-LLD.md §12`) — this module will happily
//! write a grant for a caller who holds nothing, because it is the thing the policy chain calls
//! *after* it has decided, not a second place where the decision is made. Two authorization checks
//! that can disagree are worse than one, and the one inside the chain is the one that audits
//! (`CLAUDE.md` rule 10).
//!
//! For the same reason there is no audit call here. The write is a step of `enforce`'s `execute`
//! stage, and the audit row for it is emitted by the engine with the decision that permitted it.
//! An audit row written here would be a second, differently-shaped record of the same event.
//!
//! # Transaction discipline
//!
//! Every function takes the caller's `&mut PgConnection` — a `TenantScoped` transaction (D10) —
//! exactly as [`crate::materialise`] does, and never opens one of its own. A grant that committed
//! independently of the operation that authorized it is a grant that survives the rollback of its
//! own justification. A caller who never commits gets no grant, which is the correct failure.
//!
//! # Why the tenant is a parameter as well as a session setting
//!
//! Row-level security on `acl_entries` is enabled and forced, with `USING` and `WITH CHECK` both on
//! `tenant_id = current_setting('app.tenant_id')`, so a correctly-configured connection cannot see
//! or write another tenant's rows. Every statement below *also* names `tenant_id = $1`. That is not
//! belt-and-braces for its own sake: `enclave_platform` holds `BYPASSRLS`, the migration and test
//! harnesses connect as a superuser, and a future maintenance job is one `SET ROLE` away from
//! running this code with the policies inert. `tests/grant.rs` runs the whole suite on exactly such
//! a connection, so deleting any one of those predicates turns a test red rather than turning a
//! guarantee into a comment.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Dependency, Error as CoreError, FieldError, TenantId, UserId, ValidationCode,
};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::AuthzError;
use crate::resolve::{AclEntry, AclResourceType, ChainNode, Effect, Principal, PrincipalKind};

/// The result type of this module.
pub type Result<T, E = GrantError> = core::result::Result<T, E>;

/// How many distinct actions one call may name.
///
/// A permissions UI writes a role's worth of actions at a time — the seeded owner fixture is eleven
/// — and the whole `Action` vocabulary is smaller than this. The limit exists so that a caller who
/// builds the array from untrusted input cannot turn one request into an unbounded write inside a
/// transaction that is holding row locks on `acl_entries`, which is on the read path of every
/// authorization decision in the product.
pub const MAX_GRANT_ACTIONS: usize = 64;

// -------------------------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------------------------

/// Something went wrong writing an ACL entry.
///
/// A separate enumeration from [`AuthzError`] rather than more variants on it, and the distinction
/// is real rather than administrative: [`AuthzError`] is the vocabulary of *resolution*, and
/// `PolicyEngine::enforce` relies on none of its variants being a denial (`crate::error`). The
/// failures below are all refusals of a **write** the caller asked for, and several of them are the
/// caller's fault in a way that no resolution failure ever is. Mixing the two would put
/// "you may not overwrite that `DENY`" in the same enumeration the engine is required never to read
/// as a verdict.
///
/// Resolution failures still arrive, through [`GrantError::Authz`], because the write path reads
/// before it writes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GrantError {
    /// A resolution or storage failure, in the vocabulary the rest of the crate speaks.
    #[error(transparent)]
    Authz(#[from] AuthzError),

    /// An `ALLOW` was asked to land on a `DENY`, and refused.
    ///
    /// The decision, argued in full on [`grant`]: `uq_acl_entry` permits exactly one row per
    /// `(resource, principal, action)`, so an unguarded upsert would make an ordinary grant the
    /// mechanism that erases a decisive `DENY` — and a `DENY` beats every `ALLOW` at every level of
    /// the chain (`docs/04-DATA-MODEL.md §9` resolution rule 3). Lifting one is [`revoke`] followed
    /// by [`grant`]: two deliberate acts, two audit rows.
    #[error("an ALLOW may not overwrite the DENY already in place on: {}", .actions.join(", "))]
    DenyInPlace {
        /// The actions that are denied, in the spelling `acl_entries.action` holds.
        actions: Vec<String>,
    },

    /// `granted_by` names nobody in this tenant.
    ///
    /// `acl_entries.granted_by` is `NOT NULL` and carries no foreign key — `docs/04 §9` could not
    /// give it one, because the column outlives the user row it points at. Checking it here is what
    /// keeps the column meaning something: an entry whose granter cannot be named is an entry no
    /// review can ever explain.
    #[error("the granting user does not exist in this tenant")]
    UnknownGranter,

    /// The principal the grant names does not exist in this tenant.
    ///
    /// One error for "in another tenant" and for "never existed", per `CLAUDE.md` rule 7 — a
    /// distinct answer would let anyone who may grant a permission enumerate another tenant's
    /// directory one UUID at a time.
    #[error("the principal named by this grant does not exist in this tenant")]
    UnknownPrincipal,

    /// The principal's identifier and its kind disagree.
    ///
    /// `EVERYONE` carries no identifier and every other kind must carry one. A `USER` with no id
    /// would be written as `NULL`, fold into the nil UUID under `uq_acl_entry`, and collide with
    /// the tenant's `EVERYONE` row for the same action — one grant silently becoming the most
    /// permissive entry the schema can express.
    #[error("a `{kind}` principal carries the wrong kind of identifier")]
    MalformedPrincipal {
        /// The kind that was wrong.
        kind: &'static str,
    },

    /// The resource kind has no table in this schema yet.
    ///
    /// `acl_entries.resource_type` admits `PAGE` and `LIST_ITEM`; `migrations/` creates neither
    /// table (`0015_lists.sql` says so for `list_items` in as many words). An entry on a resource
    /// that cannot exist resolves against nothing, is invisible to every permissions UI, and cannot
    /// be cleaned up by anything that walks the content tree — so it is refused rather than
    /// written and forgotten.
    #[error("`{kind}` has no table in this schema, so an entry on it could never resolve")]
    UnbackedResourceKind {
        /// The resource type, in its database spelling.
        kind: &'static str,
    },

    /// No action was named.
    ///
    /// A no-op rather than an error would be worse: a caller who built an empty array from a failed
    /// parse would be told their grant succeeded.
    #[error("a grant must name at least one action")]
    NoActions,

    /// More actions than [`MAX_GRANT_ACTIONS`].
    #[error("a single call may name at most {limit} actions")]
    TooManyActions {
        /// The limit that was exceeded.
        limit: usize,
    },

    /// An [`enclave_core::AdminAction`] was offered as an ACL grant.
    ///
    /// `acl_entries.action` is free text, and `crate::admin` decides administrative actions from
    /// `users.is_admin` without ever consulting this table. A row spelling `admin.manage_policy`
    /// would therefore grant nothing today and be honoured the day somebody wires the two together
    /// — which is the shape of privilege escalation that `crate::admin`'s first structural refusal
    /// exists to prevent. Refusing the write is the cheap end of that.
    #[error("an administrative action is not grantable through an acl entry")]
    AdminActionNotGrantable,

    /// The rows this call addressed changed underneath it.
    ///
    /// Only reachable when another transaction wrote a `DENY` between this one's guard read and its
    /// write. The write is guarded a second time in SQL so the outcome is a refusal rather than a
    /// silent overwrite; this is how that refusal reaches the caller.
    #[error("the acl entries this grant addresses were changed concurrently")]
    RaceLost,
}

impl From<sqlx::Error> for GrantError {
    /// Storage failures keep the crate's one representation.
    ///
    /// Written by hand rather than as a second `#[from]` so that a transport failure has exactly
    /// one shape in this crate — two variants that both mean "PostgreSQL said no" would need every
    /// downstream `match` to remember both, and the one that forgot would be the one deciding
    /// whether an incident is retryable.
    fn from(value: sqlx::Error) -> Self {
        Self::Authz(AuthzError::Storage(value))
    }
}

impl From<GrantError> for CoreError {
    /// Maps onto the vocabulary the API edge speaks (`docs/03-LLD.md §22`, `docs/05-API.md §5`).
    ///
    /// The mapping is deliberately blunt about what it does *not* say. A refused `ALLOW` renders as
    /// a conflict and never names the principal or the resource beyond what the caller already
    /// sent; an unknown principal and an unknown granter are both a validation failure on the field
    /// the caller typed, so neither becomes a way to ask "does this UUID exist in some tenant".
    fn from(value: GrantError) -> Self {
        match value {
            GrantError::Authz(error) => error.into(),
            // The resource is not in the state the caller assumed, and re-sending the same request
            // will not change that: the `DENY` has to be revoked first. `current_revision` is 0
            // because an ACL entry has no revision to re-read — the same reason
            // `AuthzError::NotInheriting` uses.
            GrantError::DenyInPlace { .. } | GrantError::RaceLost => {
                Self::Conflict { current_revision: 0 }
            }
            GrantError::UnknownGranter => {
                Self::Validation(vec![FieldError::new("granted_by", ValidationCode::InvalidFormat)])
            }
            GrantError::UnknownPrincipal | GrantError::MalformedPrincipal { .. } => {
                Self::Validation(vec![FieldError::new(
                    "principal_id",
                    ValidationCode::InvalidFormat,
                )])
            }
            GrantError::UnbackedResourceKind { .. } => Self::Validation(vec![FieldError::new(
                "resource_type",
                ValidationCode::Unsupported,
            )]),
            GrantError::NoActions => {
                Self::Validation(vec![FieldError::new("actions", ValidationCode::Required)])
            }
            GrantError::TooManyActions { .. } => {
                Self::Validation(vec![FieldError::new("actions", ValidationCode::TooLong)])
            }
            GrantError::AdminActionNotGrantable => {
                Self::Validation(vec![FieldError::new("actions", ValidationCode::Unsupported)])
            }
        }
    }
}

/// Kept so the mapping above cannot drift from the dependency the health endpoint reports.
const _: Dependency = Dependency::Postgres;

// -------------------------------------------------------------------------------------------
// The grant
// -------------------------------------------------------------------------------------------

/// Everything one call writes except the actions themselves.
///
/// A struct rather than five more parameters because the fields have to agree with each other —
/// `Principal { kind: Everyone, id: Some(..) }` and `ChainNode::new(File, folder_id)` are both
/// accepted by the `CHECK` constraints and both resolve against nothing — and because a
/// nine-argument function is one where a caller swaps two `Uuid`s and the compiler agrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// What the entry hangs on.
    pub resource: ChainNode,
    /// Who it names.
    pub principal: Principal,
    /// Grant or refusal.
    pub effect: Effect,
    /// The user answering for it. Recorded, and checked to be real.
    pub granted_by: UserId,
    /// When it stops applying, if ever.
    ///
    /// Compared with `> now` by both the query in [`crate::repo`] and [`AclEntry::is_live_at`], so
    /// an expiry exactly equal to the moment of resolution has already lapsed.
    pub expires_at: Option<DateTime<Utc>>,
}

/// One stored `acl_entries` row, as a permissions UI needs to see it.
///
/// [`AclEntry`] is what *resolution* needs: the resource, the principal, the effect and the expiry,
/// with the action left out because the resolver has already bucketed rows by it. Administration
/// needs the rest — which action, who granted it, when, whether it was copied down by a broken
/// inheritance, and whether it is still in force — so this wraps rather than replaces it. The
/// resolver and the UI reading the same [`AclEntry`] out of the same row is what stops the screen
/// that explains a permission from disagreeing with the code that enforces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedEntry {
    /// The row's primary key, so a UI can address one entry.
    pub id: Uuid,
    /// The resolver's view of the row.
    pub entry: AclEntry,
    /// The action, as free text.
    ///
    /// Deliberately not [`Action`]. `acl_entries.action` is a `TEXT` column with no `CHECK`
    /// (`docs/04 §9`), so a row may hold a spelling this build does not know — one written by an
    /// older release, or by a tenant's own tooling. Parsing here would make those rows invisible to
    /// the only screen that could ever remove them, which is the opposite of what a permissions UI
    /// is for. [`grant`] validates on the way in; this reports what is there.
    pub action: String,
    /// The ancestor this entry was copied from when inheritance was broken, if it was
    /// ([`crate::materialise`]).
    pub inherited_from: Option<Uuid>,
    /// Who granted it.
    pub granted_by: Uuid,
    /// When.
    pub granted_at: DateTime<Utc>,
    /// Whether `expires_at` has passed — `true` means the row is stored and inert.
    ///
    /// Flagged rather than filtered, and [`entries_on`] says why.
    pub expired: bool,
}

/// Writes or updates the entries granting `actions` to a principal on a resource.
///
/// Returns how many rows the statement touched, which equals the number of *distinct* actions
/// named. Duplicates in `actions` are collapsed before the write, because PostgreSQL aborts an
/// `INSERT … ON CONFLICT DO UPDATE` that would touch one row twice — `["file.read", "file.read"]`
/// would otherwise fail the whole call with a message about command ordering that says nothing
/// about the caller's array.
///
/// # An `ALLOW` will not overwrite a `DENY`
///
/// This is the one decision in the module worth arguing, so: `uq_acl_entry` permits exactly one row
/// per `(tenant, resource_type, resource_id, principal_type, principal_id, action)`, with a
/// `COALESCE` folding `EVERYONE`'s `NULL` identifier into the nil UUID. There is nowhere to put a
/// second row. A blind upsert would therefore make `grant` the mechanism that *erases* a `DENY` —
/// and a `DENY` wins over every `ALLOW` at every level of the inheritance chain
/// (`docs/04-DATA-MODEL.md §9` resolution rule 3), which makes it the strongest statement the ACL
/// model can make and the one a tenant reaches for when something must not happen.
///
/// The alternative was to let the upsert through and rely on the operator noticing. That costs an
/// undetectable privilege gain through an ordinary, permitted operation: an administrator grants
/// `file.read` to a group in a permissions dialog, and the legal hold somebody wrote last quarter
/// is gone, with the only trace an audit row that says a grant succeeded. Refusing costs one extra
/// call. Lifting a denial is [`revoke`] and then [`grant`] — two deliberate acts, two audit rows,
/// and a reviewer who can see both.
///
/// The refusal ignores `expires_at`: a lapsed `DENY` blocks the `ALLOW` too. It is inert for
/// resolution, but it is still the only record that a denial was ever written, and overwriting it
/// destroys that record for the benefit of a caller who is one [`revoke`] away from the same
/// outcome. The guard read and the `WHERE` on the write use the same rule, for the reason
/// [`crate::materialise`] gives about its own count and copy sharing one fragment.
///
/// Re-granting an `ALLOW` over an `ALLOW` is ordinary and updates the effect, the expiry, the
/// granter and the timestamp. So is a `DENY` over anything, including an existing `ALLOW`: that
/// direction only ever narrows access, and refusing it would make a tightening harder than a
/// widening.
///
/// # `inherited_from` is cleared
///
/// An entry written here was written *on* this resource by somebody who answered for it, so the
/// column that says "this was copied down from an ancestor" must not survive the overwrite. Leaving
/// it would tell a reviewer that a direct grant came from a parent, and would make the entry look
/// like something a re-materialisation may legitimately replace.
///
/// # `SHARE_LINK` principals
///
/// Granting to [`PrincipalKind::ShareLink`] is what `ENC-879` made possible and is the only row
/// that can ever authorize a redemption — a link bearer is deliberately outside `EVERYONE`, so
/// before that migration no row could match one. Note what [`revoke`] does **not** do with it, on
/// [`revoke`]'s own documentation.
///
/// # Errors
///
/// * [`GrantError::DenyInPlace`] — see above.
/// * [`GrantError::UnknownGranter`], [`GrantError::UnknownPrincipal`],
///   [`GrantError::MalformedPrincipal`] — the row would name somebody who is not there.
/// * [`GrantError::UnbackedResourceKind`] — `PAGE` or `LIST_ITEM`.
/// * [`GrantError::NoActions`], [`GrantError::TooManyActions`],
///   [`GrantError::AdminActionNotGrantable`] — the action list.
/// * [`AuthzError::UnknownResource`], through [`GrantError::Authz`] — the resource is another
///   tenant's, soft-deleted, or never existed. One answer for all three (`CLAUDE.md` rule 7).
/// * [`GrantError::RaceLost`] — a concurrent `DENY`.
/// * Storage failures.
pub async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    grant: &Grant,
    actions: &[Action],
    now: DateTime<Utc>,
) -> Result<usize> {
    let actions = grantable_actions(actions)?;
    let (principal_type, principal_id) = principal_columns(grant.principal)?;

    // Ordered so that nothing is written before everything the row asserts has been checked. A
    // caller who gets an error has an unchanged ACL, which is what lets a route surface the failure
    // without having to reason about whether its transaction is still clean.
    require_granter(conn, tenant, grant.granted_by).await?;
    require_principal(conn, tenant, grant.principal).await?;
    touch_resource(conn, tenant, grant.resource).await?;

    let blocked = denied_actions(conn, tenant, grant, &actions).await?;
    if grant.effect == Effect::Allow && !blocked.is_empty() {
        return Err(GrantError::DenyInPlace { actions: blocked });
    }

    let written = sqlx::query(GRANT_SQL)
        .bind(tenant.as_uuid())
        .bind(grant.resource.kind.as_str())
        .bind(grant.resource.id)
        .bind(principal_type)
        .bind(principal_id)
        .bind(grant.effect.as_str())
        .bind(grant.granted_by.as_uuid())
        .bind(now)
        .bind(grant.expires_at)
        .bind(&actions)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    let written = usize::try_from(written).unwrap_or(usize::MAX);
    if written < actions.len() {
        // The `WHERE` on the `DO UPDATE` declined a row, which it can only do for a `DENY` that
        // arrived after the guard read above. Re-read so the caller is told which action, and fall
        // back to the generic race if that transaction has since been rolled back.
        let blocked = denied_actions(conn, tenant, grant, &actions).await?;
        return if blocked.is_empty() {
            Err(GrantError::RaceLost)
        } else {
            Err(GrantError::DenyInPlace { actions: blocked })
        };
    }
    Ok(written)
}

/// Removes the entries naming `actions` for a principal on a resource.
///
/// Returns how many rows went, so a caller can tell "revoked" from "there was nothing there" — a
/// distinction a permissions UI needs and `DELETE` will not volunteer.
///
/// # What is deliberately not checked
///
/// Neither the resource nor the principal has to still exist. Revocation is the direction that only
/// ever narrows access, and the entries most worth removing are exactly the ones whose subject has
/// gone: a soft-deleted folder, a group that was disbanded, a user who left. Refusing to clean
/// those up — in order to protect them from being cleaned up — would leave a tenant with rows no
/// supported operation can reach. Administrative actions are removable here for the same reason,
/// although [`grant`] will not write one: a row that should not exist must have a way out.
///
/// # This is not how a share link is revoked
///
/// Deleting the `SHARE_LINK` entry removes the grant a redemption resolves against, and it does not
/// end the link. `crate::service`'s `link_principal_is_live` gates the whole resolution on
/// `share_links` still holding a live row for the bearer — checked *before* any chain is walked —
/// so the link's own lifecycle (`revoked_at`, `expires_at`, `max_downloads`) is what actually
/// revokes it, and it does so no matter what `acl_entries` says. The two are not interchangeable
/// and the difference is observable: revoke the link and the bearer is refused everywhere, at once,
/// including through any other entry that might name it; revoke only this row and a live link
/// remains live, visible in the sharing UI, and resolving to nothing. `ENC-879`'s reasoning is that
/// a link bearer is a principal the chain can name, not that it is a principal the chain owns —
/// ending a link stays `enclave_shares`' operation, and this function narrows a grant.
///
/// # Errors
///
/// [`GrantError::NoActions`], [`GrantError::TooManyActions`],
/// [`GrantError::MalformedPrincipal`], and storage failures.
pub async fn revoke(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
    principal: Principal,
    actions: &[Action],
) -> Result<usize> {
    let actions = revocable_actions(actions)?;
    let (principal_type, principal_id) = principal_columns(principal)?;

    let removed = sqlx::query(REVOKE_SQL)
        .bind(tenant.as_uuid())
        .bind(resource.kind.as_str())
        .bind(resource.id)
        .bind(principal_type)
        .bind(principal_id)
        .bind(&actions)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    // Best-effort, and after the delete rather than before it: a revocation on a resource that has
    // since been trashed must still remove the rows, so a missing file is not an error here the way
    // it is in `grant`. `bump_file_acl_revision` reporting zero simply means there was no live row
    // to signal about.
    if removed > 0 {
        let _bumped = bump_file_acl_revision(conn, tenant, resource).await?;
    }

    Ok(usize::try_from(removed).unwrap_or(usize::MAX))
}

/// Every entry stored directly on one resource, expired ones included and flagged.
///
/// Ordered by principal and then action, so a UI renders the same list twice in the same order.
///
/// # Why expired entries are returned rather than filtered
///
/// Resolution drops them — [`crate::repo`]'s `WHERE` clause and [`AclEntry::is_live_at`] both apply
/// `expires_at > now`, rule 4 of `docs/04-DATA-MODEL.md §9` — and that filtering is what governs
/// every decision the product makes. This function is not on that path. It backs the screen an
/// administrator opens to ask *why* somebody lost access, and hiding the lapsed entry is hiding the
/// answer: the row is still stored, it still occupies the one slot `uq_acl_entry` allows for its
/// `(principal, action)`, and — because [`grant`] refuses to overwrite a `DENY` at any expiry — a
/// lapsed `DENY` is the specific thing that makes a new `ALLOW` fail. An administrator who cannot
/// see it cannot act on it.
///
/// [`GrantedEntry::expired`] carries the verdict so no caller has to re-derive it and get the
/// boundary wrong in the other direction from the resolver.
///
/// This returns only the resource's **own** entries. The effective set is what the caller inherits
/// from its ancestors as well, and answering that question is [`crate::service::AclResolver`]'s —
/// a second implementation of the chain walk here would be one refactor away from disagreeing with
/// the one that enforces, which is the trap [`crate::materialise`] documents.
///
/// # Errors
///
/// Storage failures, and [`AuthzError::MalformedRow`] through [`GrantError::Authz`] for a stored
/// `resource_type`, `principal_type` or `effect` this build does not recognise — never guessed at,
/// in either direction.
pub async fn entries_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
    now: DateTime<Utc>,
) -> Result<Vec<GrantedEntry>> {
    let rows = sqlx::query(ENTRIES_ON_SQL)
        .bind(tenant.as_uuid())
        .bind(resource.kind.as_str())
        .bind(resource.id)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter().map(|row| granted_entry(row, now)).collect()
}

// -------------------------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------------------------

/// The action strings a grant may write, deduplicated and in the order they were given.
///
/// Deduplication is not tidiness. `INSERT … ON CONFLICT DO UPDATE` refuses to touch the same row
/// twice in one command, so a repeated action aborts the entire statement — including the actions
/// that were fine — with an error about command ordering. Collapsing here turns a caller's harmless
/// mistake into a no-op instead of a total failure, and keeps the returned count honest by making
/// it the number of rows the write is actually expected to touch.
fn grantable_actions(actions: &[Action]) -> Result<Vec<String>> {
    let mut deduplicated = normalise_actions(actions, |action| {
        if matches!(action, Action::Admin(_)) {
            Err(GrantError::AdminActionNotGrantable)
        } else {
            Ok(())
        }
    })?;
    deduplicated.shrink_to_fit();
    Ok(deduplicated)
}

/// The same, for [`revoke`], which accepts administrative actions.
///
/// A row spelling `admin.manage_policy` cannot be written by [`grant`], but one may already exist —
/// written by an earlier release, by a fixture, or by hand — and the only thing worse than an
/// ungrantable row is an ungrantable row that also cannot be removed.
fn revocable_actions(actions: &[Action]) -> Result<Vec<String>> {
    normalise_actions(actions, |_| Ok(()))
}

/// Bounds, deduplicates and renders an action list, applying `admissible` to each.
///
/// `Action`'s `Display` — `family.verb`, e.g. `file.download` — is what `acl_entries.action` holds
/// and what an audit row carries. Rendering here rather than accepting strings is the whole reason
/// a grant and the decision it is supposed to permit can be relied on to name the same thing: a
/// grant written as `"download"` matches nothing and looks correct in every UI.
fn normalise_actions(
    actions: &[Action],
    admissible: impl Fn(&Action) -> Result<()>,
) -> Result<Vec<String>> {
    if actions.is_empty() {
        return Err(GrantError::NoActions);
    }
    if actions.len() > MAX_GRANT_ACTIONS {
        return Err(GrantError::TooManyActions { limit: MAX_GRANT_ACTIONS });
    }

    let mut seen: HashSet<String> = HashSet::with_capacity(actions.len());
    let mut rendered = Vec::with_capacity(actions.len());
    for action in actions {
        admissible(action)?;
        let text = action.to_string();
        if seen.insert(text.clone()) {
            rendered.push(text);
        }
    }
    Ok(rendered)
}

/// The `(principal_type, principal_id)` pair, with the one consistency rule the schema cannot state.
///
/// `principal_id` is nullable so that `EVERYONE` can exist, which means the column cannot also
/// require an identifier for every other kind. The `CHECK` constraint has no way to express
/// "`NULL` if and only if `EVERYONE`", so it is expressed here — and it matters more than it looks:
/// `uq_acl_entry` folds a `NULL` identifier into the nil UUID, so a `USER` written without one does
/// not merely fail to match its user, it competes for the row `EVERYONE` occupies.
fn principal_columns(principal: Principal) -> Result<(&'static str, Option<Uuid>)> {
    match (principal.kind, principal.id) {
        (PrincipalKind::Everyone, None) => Ok((PrincipalKind::Everyone.as_str(), None)),
        (PrincipalKind::Everyone, Some(_)) => {
            Err(GrantError::MalformedPrincipal { kind: PrincipalKind::Everyone.as_str() })
        }
        (kind, Some(id)) => Ok((kind.as_str(), Some(id))),
        (kind, None) => Err(GrantError::MalformedPrincipal { kind: kind.as_str() }),
    }
}

/// Refuses a grant whose `granted_by` names nobody in this tenant.
async fn require_granter(
    conn: &mut PgConnection,
    tenant: TenantId,
    granted_by: UserId,
) -> Result<()> {
    let found: Option<i32> = sqlx::query_scalar(GRANTER_EXISTS_SQL)
        .bind(tenant.as_uuid())
        .bind(granted_by.as_uuid())
        .fetch_optional(&mut *conn)
        .await?;
    if found.is_none() {
        return Err(GrantError::UnknownGranter);
    }
    Ok(())
}

/// Refuses a grant to a principal that does not exist in this tenant.
///
/// **Existence, not liveness.** A guest whose invitation has lapsed, a service account that is
/// disabled and a share link that has been revoked all still exist, and a grant naming one of them
/// is written. That is deliberate: liveness is what the resolver checks at decision time
/// (`crate::service`'s `link_principal_is_live`, `expires_at`, `users.deleted_at`), and it changes
/// underneath a stored row constantly. Refusing the write for it would mean a grant that was legal
/// on Monday is illegal on Tuesday and legal again on Wednesday, and an administrator restoring a
/// suspended account could not restore its permissions first. What existence *does* catch is the
/// case liveness never will — a mistyped or pasted UUID, which produces an entry that names nobody,
/// grants nothing, and can never be explained by any screen that shows it.
///
/// `EVERYONE` has nothing to look up.
async fn require_principal(
    conn: &mut PgConnection,
    tenant: TenantId,
    principal: Principal,
) -> Result<()> {
    let Some(statement) = principal_exists_sql(principal.kind) else {
        return Ok(());
    };
    // Checked by `principal_columns` before this is reached; belt and braces, because a `None` here
    // would silently look up the nil UUID and refuse for the wrong reason.
    let Some(id) = principal.id else {
        return Err(GrantError::MalformedPrincipal { kind: principal.kind.as_str() });
    };

    let found: Option<i32> = sqlx::query_scalar(statement)
        .bind(tenant.as_uuid())
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    if found.is_none() {
        return Err(GrantError::UnknownPrincipal);
    }
    Ok(())
}

/// Confirms the resource exists in this tenant, and signals the search index when it is content.
///
/// Two jobs in one round trip on purpose, for `FILE` and `FOLDER`: the `UPDATE` that bumps
/// `acl_revision` reports how many rows it matched, and that count *is* the existence check. Doing
/// them separately would mean a window in which the resource passed the check and was trashed
/// before the bump.
///
/// # Why `acl_revision` and not `revision`
///
/// `acl_revision` is what the search index carries as `acl_epoch` and what the epoch reconciler
/// compares (`crates/search/src/writer.rs`, `docs/07-SEARCH-INDEXING.md §6`), so a permission change
/// that did not move it leaves the index believing its ACL tokens are current. `revision` is the
/// optimistic-concurrency token a client sends back as `If-Match`; bumping it here would make every
/// permission change invalidate every open editor's handle on a file whose *content* nobody
/// touched. [`crate::materialise`] moves both because breaking inheritance also flips a column on
/// the file itself.
///
/// The bump covers the resource the entry hangs on. A grant on a `WORKSPACE` or a `LIBRARY` changes
/// the effective permissions of every file beneath it and is **not** propagated: that is a write
/// across an unbounded subtree inside a request, which is the exact shape
/// [`crate::materialise::MAX_MATERIALISED_ENTRIES`] exists to refuse. The index is a candidate
/// generator and its tokens are an optimisation — every result is confirmed against PostgreSQL
/// before it is returned (`CLAUDE.md` rule 5) — so a stale epoch upstream of a grant costs recall,
/// never confidentiality. It is still a gap worth closing with a background reconciler rather than
/// here.
async fn touch_resource(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
) -> Result<()> {
    match resource.kind {
        AclResourceType::File | AclResourceType::Folder => {
            if bump_file_acl_revision(conn, tenant, resource).await? == 0 {
                return Err(AuthzError::UnknownResource.into());
            }
            Ok(())
        }
        AclResourceType::Workspace | AclResourceType::Library | AclResourceType::List => {
            let statement = match resource.kind {
                AclResourceType::Workspace => WORKSPACE_EXISTS_SQL,
                AclResourceType::Library => LIBRARY_EXISTS_SQL,
                _ => LIST_EXISTS_SQL,
            };
            let found: Option<i32> = sqlx::query_scalar(statement)
                .bind(tenant.as_uuid())
                .bind(resource.id)
                .fetch_optional(&mut *conn)
                .await?;
            if found.is_none() {
                return Err(AuthzError::UnknownResource.into());
            }
            Ok(())
        }
        AclResourceType::Page | AclResourceType::ListItem => {
            Err(GrantError::UnbackedResourceKind { kind: resource.kind.as_str() })
        }
    }
}

/// Moves `files.acl_revision` for a content node, and reports whether there was one to move.
///
/// `node_type = $3` is not redundant with the primary key. `("FILE", folder_id)` satisfies the
/// `resource_type` `CHECK`, is accepted by the index, and resolves against nothing — the exact
/// mismatch `enclave_testing::content::AclScope` exists to make unrepresentable in fixtures. Here
/// it turns into "that resource does not exist", which is the honest answer.
async fn bump_file_acl_revision(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: ChainNode,
) -> Result<u64> {
    if !matches!(resource.kind, AclResourceType::File | AclResourceType::Folder) {
        return Ok(0);
    }
    Ok(sqlx::query(BUMP_ACL_REVISION_SQL)
        .bind(tenant.as_uuid())
        .bind(resource.id)
        .bind(resource.kind.as_str())
        .execute(&mut *conn)
        .await?
        .rows_affected())
}

/// The actions among `actions` that already carry a stored `DENY` for this resource and principal.
///
/// Shared by the guard before the write and the diagnosis after it, so the two can never disagree
/// about what "denied" means — the same argument [`crate::materialise`] makes for sharing one SQL
/// fragment between its count and its copy.
async fn denied_actions(
    conn: &mut PgConnection,
    tenant: TenantId,
    grant: &Grant,
    actions: &[String],
) -> Result<Vec<String>> {
    let (principal_type, principal_id) = principal_columns(grant.principal)?;
    let rows = sqlx::query(DENIED_ACTIONS_SQL)
        .bind(tenant.as_uuid())
        .bind(grant.resource.kind.as_str())
        .bind(grant.resource.id)
        .bind(principal_type)
        .bind(principal_id)
        .bind(actions)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter().map(|row| column::<String>(row, "action")).collect()
}

// -------------------------------------------------------------------------------------------
// Row reading
// -------------------------------------------------------------------------------------------

/// Reads a column, turning a decode failure into a message that names the column and nothing else.
///
/// A local twin of [`crate::repo`]'s. Kept local rather than shared because that one is private to
/// the read path and making it `pub(crate)` would be a change to a file this task does not own; the
/// duplication is four lines and the behaviour it must match — never echo the value, because an
/// unreadable ACL row may be a tampered one (`CLAUDE.md` rule 10) — is stated in both places.
fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T> {
    row.try_get(name).map_err(|_| {
        AuthzError::MalformedRow { column: name, reason: "missing or of an unexpected type" }.into()
    })
}

/// Reads one `acl_entries` row into the shape administration works on.
fn granted_entry(row: &sqlx::postgres::PgRow, now: DateTime<Utc>) -> Result<GrantedEntry> {
    let raw_type: String = column(row, "resource_type")?;
    let kind = AclResourceType::parse(&raw_type).ok_or(AuthzError::MalformedRow {
        column: "resource_type",
        reason: "not a resource type this resolver knows",
    })?;
    let raw_principal: String = column(row, "principal_type")?;
    let principal_kind = PrincipalKind::parse(&raw_principal).ok_or(AuthzError::MalformedRow {
        column: "principal_type",
        reason: "not a principal kind this resolver knows",
    })?;
    let raw_effect: String = column(row, "effect")?;
    let effect = Effect::parse(&raw_effect)
        .ok_or(AuthzError::MalformedRow { column: "effect", reason: "neither ALLOW nor DENY" })?;

    let entry = AclEntry {
        resource: ChainNode::new(kind, column(row, "resource_id")?),
        principal: Principal {
            kind: principal_kind,
            id: column::<Option<Uuid>>(row, "principal_id")?,
        },
        effect,
        expires_at: column::<Option<DateTime<Utc>>>(row, "expires_at")?,
    };

    Ok(GrantedEntry {
        id: column(row, "id")?,
        // Asked of the entry rather than recomputed from the column, so the flag a UI renders and
        // the rule the resolver applies are the same line of code (`AclEntry::is_live_at`).
        expired: !entry.is_live_at(now),
        entry,
        action: column(row, "action")?,
        inherited_from: column::<Option<Uuid>>(row, "inherited_from")?,
        granted_by: column(row, "granted_by")?,
        granted_at: column(row, "granted_at")?,
    })
}

// -------------------------------------------------------------------------------------------
// Statements
// -------------------------------------------------------------------------------------------

/// The principal-match predicate, folded exactly as `uq_acl_entry` folds it.
///
/// The `COALESCE` on both sides is not decorative. `uq_acl_entry` is a unique index on an
/// **expression** list whose fifth element is `COALESCE(principal_id, '00000000-…'::uuid)`, so the
/// obvious predicate — `a.principal_id = $5` — never matches an `EVERYONE` row, because `NULL =
/// NULL` is `NULL` and not `TRUE`. Written that way the `DENY` guard would find nothing for
/// `EVERYONE`, the upsert would conflict with the row anyway, and the denial this module exists to
/// protect would be overwritten by the one principal that covers the whole tenant.
///
/// A macro rather than a `const` for the reason [`crate::materialise`]'s `scoped_sql!` gives:
/// `concat!` only concatenates literals, and writing this twice is the duplication it exists to
/// prevent. It is used by the `DENY` guard and by [`revoke`], and those two disagreeing would mean
/// a grant refused for a `DENY` that a revocation cannot reach.
macro_rules! principal_match {
    () => {
        " AND a.principal_type = $4
   AND COALESCE(a.principal_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE($5::uuid, '00000000-0000-0000-0000-000000000000'::uuid)"
    };
}

/// Writes the entries, and refuses to let an `ALLOW` land on a `DENY`.
///
/// Three things about this statement are load-bearing and none of them are visible in the DDL:
///
/// 1. **The conflict target is the index's full expression list, not a column list.** `uq_acl_entry`
///    is a unique index on `(tenant_id, resource_type, resource_id, principal_type,
///    COALESCE(principal_id, nil), action)`. PostgreSQL matches an `ON CONFLICT` target against the
///    index definition, so naming the columns instead — the obvious thing to write — does not fail
///    to compile, it fails at runtime with "there is no unique or exclusion constraint matching the
///    ON CONFLICT specification", on every call, in production.
/// 2. **The `WHERE` on the `DO UPDATE` is the race guard.** [`grant`] reads first so the caller gets
///    a precise error, but a `DENY` committed between that read and this write would be waited on by
///    the unique index and then cheerfully overwritten. With the clause, the row is declined,
///    `rows_affected` falls short, and the call refuses. `EXCLUDED.effect = 'DENY'` is what keeps a
///    tightening — a `DENY` over anything — legal.
/// 3. **`inherited_from` is set to `NULL` on both paths.** A grant written on a resource is a direct
///    grant, whatever the row it replaced claimed.
const GRANT_SQL: &str = "
INSERT INTO acl_entries
    (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
     effect, inherited_from, granted_by, granted_at, expires_at)
SELECT gen_random_uuid(), $1::uuid, $2::text, $3::uuid, $4::text, $5::uuid, a.action,
       $6::text, NULL, $7::uuid, $8::timestamptz, $9::timestamptz
  FROM unnest($10::text[]) AS a(action)
    ON CONFLICT (tenant_id, resource_type, resource_id, principal_type,
                 COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid), action)
    DO UPDATE SET effect         = EXCLUDED.effect,
                  inherited_from = EXCLUDED.inherited_from,
                  granted_by     = EXCLUDED.granted_by,
                  granted_at     = EXCLUDED.granted_at,
                  expires_at     = EXCLUDED.expires_at
              WHERE acl_entries.effect <> 'DENY' OR EXCLUDED.effect = 'DENY'
";

/// The stored `DENY`s among a set of actions.
///
/// No `expires_at` predicate, and [`grant`] argues why: a lapsed `DENY` is inert for resolution and
/// is still the only record that a denial was written, so it blocks the overwrite. This has to
/// agree with `GRANT_SQL`'s `WHERE`, which also ignores expiry.
const DENIED_ACTIONS_SQL: &str = concat!(
    "
SELECT a.action
  FROM acl_entries a
 WHERE a.tenant_id = $1
   AND a.resource_type = $2
   AND a.resource_id = $3",
    principal_match!(),
    "
   AND a.action = ANY($6::text[])
   AND a.effect = 'DENY'
 ORDER BY a.action
"
);

/// Removes the entries. Aliased `a` so it can share [`principal_match`].
const REVOKE_SQL: &str = concat!(
    "
DELETE FROM acl_entries a
 WHERE a.tenant_id = $1
   AND a.resource_type = $2
   AND a.resource_id = $3",
    principal_match!(),
    "
   AND a.action = ANY($6::text[])
"
);

/// Everything stored directly on one resource, in a stable order.
///
/// `NULLS FIRST` puts the tenant-wide `EVERYONE` entries — the most permissive rows that can
/// exist — at the top of the principal they belong to, which is where an administrator auditing a
/// resource should meet them.
const ENTRIES_ON_SQL: &str = "
SELECT a.id, a.resource_type, a.resource_id, a.principal_type, a.principal_id, a.action,
       a.effect, a.inherited_from, a.granted_by, a.granted_at, a.expires_at
  FROM acl_entries a
 WHERE a.tenant_id = $1 AND a.resource_type = $2 AND a.resource_id = $3
 ORDER BY a.principal_type, a.principal_id NULLS FIRST, a.action
";

/// Whether `granted_by` is a user of this tenant.
///
/// `deleted_at` is not consulted: `granted_by` is a historical fact about who answered for an
/// entry, and a granter who later leaves does not make the grant unwritable — see
/// [`require_principal`] for the same argument at greater length.
const GRANTER_EXISTS_SQL: &str = "
SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2
";

/// The existence lookup for one principal kind, or `None` when there is nothing to look up.
///
/// `EVERYONE` names nobody by construction. The tables are the ones `docs/04-DATA-MODEL.md §5`
/// and `§6` define and the ones `principal_type`'s `CHECK` was widened to match
/// (`migrations/0027_share_link_principal.sql`); a kind added to that constraint without a table
/// here will fail to compile, which is the point of matching exhaustively.
const fn principal_exists_sql(kind: PrincipalKind) -> Option<&'static str> {
    match kind {
        PrincipalKind::User => Some("SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2"),
        PrincipalKind::Group => Some("SELECT 1 FROM groups WHERE tenant_id = $1 AND id = $2"),
        PrincipalKind::Guest => Some("SELECT 1 FROM guests WHERE tenant_id = $1 AND id = $2"),
        PrincipalKind::ServiceAccount => {
            Some("SELECT 1 FROM service_accounts WHERE tenant_id = $1 AND id = $2")
        }
        PrincipalKind::ShareLink => {
            Some("SELECT 1 FROM share_links WHERE tenant_id = $1 AND id = $2")
        }
        PrincipalKind::Everyone => None,
    }
}

/// Whether the workspace is live in this tenant.
const WORKSPACE_EXISTS_SQL: &str = "
SELECT 1 FROM workspaces WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
";

/// Whether the library is live in this tenant.
const LIBRARY_EXISTS_SQL: &str = "
SELECT 1 FROM libraries WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
";

/// Whether the list is live in this tenant (`migrations/0015_lists.sql`).
const LIST_EXISTS_SQL: &str = "
SELECT 1 FROM lists WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
";

/// Signals the search index that a content node's effective ACL moved (`docs/07 §6`).
const BUMP_ACL_REVISION_SQL: &str = "
UPDATE files
   SET acl_revision = acl_revision + 1
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND node_type = $3
";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{AdminAction, ContainerAction, FileAction};

    use super::*;

    #[test]
    fn a_repeated_action_is_collapsed_rather_than_aborting_the_write() {
        // PostgreSQL refuses an ON CONFLICT DO UPDATE that would touch one row twice, and the error
        // it raises names neither the action nor the caller's array.
        let actions = grantable_actions(&[
            Action::File(FileAction::ContentRead),
            Action::File(FileAction::ContentRead),
            Action::File(FileAction::Download),
        ])
        .expect("a repeated action is not an error");
        assert_eq!(actions, vec!["file.content_read".to_owned(), "file.download".to_owned()]);
    }

    #[test]
    fn an_administrative_action_cannot_be_granted_but_can_be_revoked() {
        let admin = [Action::Admin(AdminAction::ManagePolicy)];
        assert!(matches!(grantable_actions(&admin), Err(GrantError::AdminActionNotGrantable)));
        assert_eq!(
            revocable_actions(&admin).expect("an existing admin row must be removable"),
            vec!["admin.manage_policy".to_owned()]
        );
    }

    #[test]
    fn an_empty_action_list_is_refused_rather_than_reported_as_a_grant() {
        assert!(matches!(grantable_actions(&[]), Err(GrantError::NoActions)));
    }

    #[test]
    fn an_action_is_written_in_the_spelling_the_resolver_reads() {
        // The grant, the audit row and `acl_entries.action` all say `container.manage_permissions`.
        // A grant that spelled it any other way would match nothing and look correct everywhere.
        let actions = grantable_actions(&[Action::Container(ContainerAction::ManagePermissions)])
            .expect("a container action is grantable");
        assert_eq!(actions, vec!["container.manage_permissions".to_owned()]);
    }

    #[test]
    fn only_everyone_may_omit_its_identifier() {
        assert_eq!(
            principal_columns(Principal::everyone()).expect("EVERYONE carries no id"),
            ("EVERYONE", None)
        );
        let id = Uuid::from_u128(7);
        assert_eq!(
            principal_columns(Principal::new(PrincipalKind::User, id)).expect("a user has an id"),
            ("USER", Some(id))
        );
        // The dangerous one: a USER with no id folds into the nil UUID under `uq_acl_entry` and
        // competes for the row EVERYONE occupies.
        assert!(matches!(
            principal_columns(Principal { kind: PrincipalKind::User, id: None }),
            Err(GrantError::MalformedPrincipal { kind: "USER" })
        ));
        assert!(matches!(
            principal_columns(Principal { kind: PrincipalKind::Everyone, id: Some(id) }),
            Err(GrantError::MalformedPrincipal { kind: "EVERYONE" })
        ));
    }

    #[test]
    fn every_principal_kind_the_check_constraint_admits_has_a_lookup_or_a_reason() {
        for kind in PrincipalKind::all() {
            let statement = principal_exists_sql(*kind);
            if *kind == PrincipalKind::Everyone {
                assert!(statement.is_none(), "EVERYONE names nobody to look up");
            } else {
                let statement = statement.unwrap_or_else(|| {
                    panic!(
                        "{} has no existence lookup, so a typo'd id would be written",
                        kind.as_str()
                    )
                });
                assert!(
                    statement.contains("tenant_id = $1"),
                    "{}'s lookup does not scope to the tenant",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn the_conflict_target_names_the_index_expression_and_not_its_columns() {
        // Naming the columns compiles, passes review, and fails at runtime on every call — see
        // GRANT_SQL. This is the cheapest possible guard against that edit.
        assert!(
            GRANT_SQL.contains(
                "COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid), action)"
            ),
            "the ON CONFLICT target no longer matches uq_acl_entry's expression list"
        );
    }

    #[test]
    fn every_reading_statement_names_the_tenant_in_its_predicate() {
        // Row-level security holds this property on a correctly configured connection and does not
        // hold it for `enclave_platform`, a superuser, or a maintenance job that has SET ROLE. The
        // predicate is the guarantee; RLS is the second one.
        //
        // `GRANT_SQL` is deliberately absent: it is the one statement here that writes rather than
        // reads, so it has no `WHERE` to carry the predicate and is asserted separately below. A
        // single loop over both shapes is what this test used to be, and it failed — the assertion
        // was a substring check that no `INSERT` can satisfy, which made the *test* wrong about a
        // statement that was right. Two tests, because they are two different properties.
        for statement in [
            DENIED_ACTIONS_SQL,
            REVOKE_SQL,
            ENTRIES_ON_SQL,
            GRANTER_EXISTS_SQL,
            WORKSPACE_EXISTS_SQL,
            LIBRARY_EXISTS_SQL,
            LIST_EXISTS_SQL,
            BUMP_ACL_REVISION_SQL,
        ] {
            assert!(
                statement.contains("tenant_id = $1"),
                "a statement in this module does not scope to the tenant:\n{statement}"
            );
        }
    }

    /// The write scopes to the tenant in the two places an `INSERT ... ON CONFLICT` can.
    ///
    /// A row this statement writes is stamped with `$1` and can only ever collide with a row of the
    /// same tenant, which is what makes a cross-tenant `DO UPDATE` unreachable rather than merely
    /// unlikely. Both halves are asserted because they fail differently: dropping the bind writes
    /// another tenant's row, and dropping `tenant_id` from the conflict target makes one tenant's
    /// grant overwrite another's for the same resource id.
    #[test]
    fn the_write_stamps_the_tenant_and_conflicts_only_within_it() {
        let sql = GRANT_SQL;

        // `tenant_id` is the second column written, and `$1` is the second value selected into it.
        let columns = sql.split("SELECT").next().expect("the column list precedes SELECT");
        assert!(
            columns.contains("(id, tenant_id,"),
            "tenant_id is not the second column of the insert:\n{sql}"
        );
        assert!(
            sql.contains("SELECT gen_random_uuid(), $1::uuid,"),
            "$1 is not bound into the tenant_id column:\n{sql}"
        );

        // `tenant_id` leads the conflict target, so `uq_acl_entry` cannot match a foreign row.
        assert!(
            sql.contains("ON CONFLICT (tenant_id,"),
            "the conflict target does not lead with tenant_id, so a DO UPDATE could reach another \
             tenant's row:\n{sql}"
        );
    }

    #[test]
    fn an_error_body_never_carries_the_acl() {
        let error: CoreError =
            GrantError::DenyInPlace { actions: vec!["file.read".to_owned()] }.into();
        assert!(matches!(error, CoreError::Conflict { .. }), "{error:?}");

        // Rule 7: an unknown principal must not be distinguishable from another tenant's, and
        // neither may render as anything that confirms existence.
        let error: CoreError = GrantError::UnknownPrincipal.into();
        assert_eq!(error.code(), "VALIDATION_FAILED");
    }

    #[test]
    fn a_write_failure_is_never_a_denial() {
        // The same property `crate::error` proves for resolution: the engine must not be able to
        // read a storage failure as a policy answer.
        let error: CoreError = GrantError::from(sqlx::Error::PoolClosed).into();
        assert!(!matches!(error, CoreError::PolicyDenied { .. }), "{error:?}");
    }
}
