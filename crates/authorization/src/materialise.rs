//! Breaking inheritance, done so that it grants nothing.
//!
//! `docs/04-DATA-MODEL.md §9` says what the operation must mean: *"Breaking inheritance copies the
//! effective entries down with `inherited_from` set, so the break is explicit and auditable rather
//! than implicit."*
//!
//! # The defect this closes (`ENC-141`)
//!
//! Until this module nothing implemented the copy, so setting `inherit_permissions = FALSE` only
//! truncated the resolver's walk. The ancestors stopped being consulted, and **a `DENY` written
//! above the break stopped applying** — a caller who was denied became allowed by an operation
//! whose entire purpose is to *narrow* access. Escalation through a supported feature, available to
//! anyone permitted to break inheritance on a resource.
//!
//! Copying the effective set down first makes the break neutral by construction: immediately after
//! it, every principal resolves exactly as they did immediately before, because the entries that
//! decided their access now sit on the resource itself. What changes afterwards is that edits to an
//! ancestor no longer reach it — which is what "break inheritance" means, and all it should mean.
//!
//! # Why the walk is borrowed rather than rewritten
//!
//! The ancestors are collected with [`crate::repo::file_chains`] — the very query
//! [`crate::service`] resolves with. A second, similar-looking walk written here would be one
//! refactor away from disagreeing with it, and a disagreement means materialisation copies a
//! different set from the one that was being enforced. At that point the break stops being neutral
//! and the escalation is back, in a form that reads as correct.
//!
//! # Atomicity
//!
//! Both statements run on the caller's `&mut PgConnection` (D10), which is a `TenantScoped`
//! transaction. The copy must commit with the flag flip: the reverse order, or two transactions,
//! leaves a window in which the resource inherits nothing and has been given nothing, and a crash
//! inside that window leaves the escalation permanently. A caller who never commits gets neither
//! half, which is the correct failure.

use chrono::{DateTime, Utc};
use enclave_core::TenantId;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::{AuthzError, Result};
use crate::repo;
use crate::resolve::AclResourceType;
use crate::service::ResolverLimits;

/// How many entries one break may copy before it is refused.
///
/// A file under a workspace carrying tens of thousands of grants would otherwise turn a single API
/// call into an unbounded write inside a request's latency budget. The limit sits far above any
/// hierarchy an organisation builds by hand and far below the point where the write becomes an
/// outage, so a runaway is a refusal rather than a stall.
pub const MAX_MATERIALISED_ENTRIES: usize = 10_000;

/// Copies the effective ACL onto a file or folder, then stops it inheriting.
///
/// Returns the number of entries the resource holds afterwards.
///
/// `limits` is the resolver's own — passing anything else lets the copy walk a different distance
/// from the enforcement it is supposed to preserve.
///
/// # Errors
///
/// * [`AuthzError::NotInheriting`] — the resource already had inheritance broken. An error rather
///   than a no-op: two callers who both believe they are establishing this resource's ACL must not
///   both be told they succeeded.
/// * [`AuthzError::UnknownResource`] — invisible to this transaction: another tenant's,
///   soft-deleted, or never real. All three are one answer on purpose (`CLAUDE.md` rule 7).
/// * [`AuthzError::TooManyEntries`] — the effective set exceeds [`MAX_MATERIALISED_ENTRIES`].
/// * [`AuthzError::ChainTooDeep`] — propagated from the walk. A truncated chain is missing exactly
///   the topmost ancestors, which is where an organisation-wide `DENY` lives, so materialising from
///   one would drop the denial and re-create the bug this module exists to fix.
/// * Storage failures.
pub async fn break_file_inheritance(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: Uuid,
    limits: ResolverLimits,
    now: DateTime<Utc>,
) -> Result<usize> {
    let chains = repo::file_chains(conn, tenant, &[file], limits.max_inheritance_depth).await?;
    let chain = chains.get(&file).ok_or(AuthzError::UnknownResource)?;

    // The walk includes the resource itself at depth 0 and stops at a node that does not inherit,
    // so a one-node chain means there was nothing above to bring down — the break has already
    // happened.
    if chain.nodes().len() < 2 {
        return Err(AuthzError::NotInheriting);
    }

    // The whole chain, self included. Not just the ancestors: the copy has to produce the
    // *effective* set, and the resource's own entries are part of that. Leaving them out would mean
    // an ancestor `DENY` landing beside a direct `ALLOW` for the same principal and action, which
    // `uq_acl_entry` cannot hold — one of the two would be dropped by the index rather than by the
    // rule.
    let kinds: Vec<String> = chain.nodes().iter().map(|n| n.kind.as_str().to_owned()).collect();
    let ids: Vec<Uuid> = chain.nodes().iter().map(|n| n.id).collect();

    let effective: i64 = sqlx::query_scalar(COUNT_EFFECTIVE_SQL)
        .bind(tenant.as_uuid())
        .bind(&kinds)
        .bind(&ids)
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

    // Counted before anything is written, so a refusal is a refusal and not a half-done break.
    let effective = usize::try_from(effective).unwrap_or(usize::MAX);
    if effective > MAX_MATERIALISED_ENTRIES {
        return Err(AuthzError::TooManyEntries { limit: MAX_MATERIALISED_ENTRIES });
    }

    // `node_type` is the resource's own ACL spelling. A folder's copied entries must say `FOLDER`
    // or the resolver will not join them back to it, and the break would silently strip every
    // permission instead of preserving them.
    let node_type: String = sqlx::query_scalar(NODE_TYPE_SQL)
        .bind(tenant.as_uuid())
        .bind(file)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(AuthzError::UnknownResource)?;
    let _known = AclResourceType::parse(&node_type).ok_or(AuthzError::MalformedRow {
        column: "node_type",
        reason: "not a resource type this resolver knows",
    })?;

    sqlx::query(MATERIALISE_SQL)
        .bind(tenant.as_uuid())
        .bind(&kinds)
        .bind(&ids)
        .bind(now)
        .bind(&node_type)
        .bind(file)
        .execute(&mut *conn)
        .await?;

    // Only now, and only for a resource whose effective set is already sitting on it.
    stop_inheriting(conn, STOP_FILE_INHERITING_SQL, tenant, file).await?;

    Ok(effective)
}

/// Copies the effective ACL onto a library, then stops it inheriting from its workspace.
///
/// The library half of the same operation, and it exists because the escalation does. `libraries`
/// carries its own `inherit_permissions`, the resolver's walk stops at it exactly as it does on a
/// file, and a library whose flag is flipped without a copy drops the workspace's `DENY` entries in
/// precisely the way [`break_file_inheritance`] exists to prevent. Fixing one door and not the
/// other would move the bug rather than close it — which is why `enclave_libraries` no longer lets
/// a settings update touch the column at all.
///
/// A library's chain is short: itself, then its workspace. There is nothing recursive to bound, so
/// no depth limit applies and [`AuthzError::ChainTooDeep`] cannot arise.
///
/// # Errors
///
/// As [`break_file_inheritance`], less the depth error.
pub async fn break_library_inheritance(
    conn: &mut PgConnection,
    tenant: TenantId,
    library: Uuid,
    now: DateTime<Utc>,
) -> Result<usize> {
    let chains = repo::library_chains(conn, tenant, &[library]).await?;
    let chain = chains.get(&library).ok_or(AuthzError::UnknownResource)?;

    if chain.nodes().len() < 2 {
        return Err(AuthzError::NotInheriting);
    }

    let kinds: Vec<String> = chain.nodes().iter().map(|n| n.kind.as_str().to_owned()).collect();
    let ids: Vec<Uuid> = chain.nodes().iter().map(|n| n.id).collect();

    let effective: i64 = sqlx::query_scalar(COUNT_EFFECTIVE_SQL)
        .bind(tenant.as_uuid())
        .bind(&kinds)
        .bind(&ids)
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

    let effective = usize::try_from(effective).unwrap_or(usize::MAX);
    if effective > MAX_MATERIALISED_ENTRIES {
        return Err(AuthzError::TooManyEntries { limit: MAX_MATERIALISED_ENTRIES });
    }

    sqlx::query(MATERIALISE_SQL)
        .bind(tenant.as_uuid())
        .bind(&kinds)
        .bind(&ids)
        .bind(now)
        .bind(AclResourceType::Library.as_str())
        .bind(library)
        .execute(&mut *conn)
        .await?;

    stop_inheriting(conn, STOP_LIBRARY_INHERITING_SQL, tenant, library).await?;

    Ok(effective)
}

/// Flips the flag, and refuses if there was nothing to flip.
///
/// The statements repeat `inherit_permissions` in their predicates so that two concurrent breaks
/// cannot both report success: whichever commits second updates no row and is told the truth,
/// rather than each administrator believing they established the resource's ACL.
async fn stop_inheriting(
    conn: &mut PgConnection,
    statement: &'static str,
    tenant: TenantId,
    resource: Uuid,
) -> Result<()> {
    let flipped = sqlx::query(statement)
        .bind(tenant.as_uuid())
        .bind(resource)
        .execute(&mut *conn)
        .await?
        .rows_affected();

    if flipped == 0 {
        return Err(AuthzError::NotInheriting);
    }
    Ok(())
}

/// The resource's own ACL spelling — `FILE` or `FOLDER`.
const NODE_TYPE_SQL: &str = "
SELECT f.node_type
  FROM files f
 WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NULL
";

/// Every entry that bears on the chain, expired ones excluded (rule 4).
///
/// Shared verbatim by the count and the copy so the two can never disagree about what "effective"
/// means — a count taken over a wider set than the copy writes would refuse breaks that are within
/// the limit, and a narrower one would let an unbounded write through the check.
///
/// A macro rather than a `const` because `concat!` only concatenates literals, and the alternative
/// — writing the fragment out twice — is exactly the duplication this exists to prevent.
macro_rules! scoped_sql {
    () => {
        "
SELECT a.principal_type, a.principal_id, a.action, a.effect,
       a.granted_by, a.granted_at, a.expires_at, a.resource_id
  FROM acl_entries a
  JOIN unnest($2::text[], $3::uuid[]) AS n(resource_type, resource_id)
    ON n.resource_type = a.resource_type AND n.resource_id = a.resource_id
 WHERE a.tenant_id = $1 AND (a.expires_at IS NULL OR a.expires_at > $4)
"
    };
}

/// What a break would leave on the resource, counted before it is written.
///
/// One row per `(principal, action)` rather than per stored entry, because that is the unit both
/// `uq_acl_entry` and the resolver work in — counting raw rows would refuse a chain that collapses
/// to a handful of entries.
const COUNT_EFFECTIVE_SQL: &str = concat!(
    "WITH scoped AS (",
    scoped_sql!(),
    ")
SELECT count(*) FROM (
    SELECT principal_type, principal_id, action FROM scoped GROUP BY 1, 2, 3
) AS effective"
);

/// Collapses the chain by the resolution rules and writes the result onto the resource.
///
/// The `ORDER BY` **is** the policy, which is why it is written as one rather than hidden in an
/// aggregate. `DISTINCT ON` keeps the first row per `(principal, action)`, and the four keys pick
/// it in the order `docs/04-DATA-MODEL.md §9` specifies:
///
/// 1. **`DENY` before `ALLOW`.** `uq_acl_entry` is on `(…, principal, action)` and does not include
///    `effect`, so when a workspace denies what a folder allows, only one row can survive. Letting
///    the index choose would keep whichever arrived first, and half the time that is the `ALLOW` —
///    precisely the privilege gain A4 forbids.
/// 2. **Never-expiring before dated**, then **the latest expiry.** An entry that grants until Friday
///    and one that grants forever together grant forever; taking the earliest would revoke on
///    Saturday access the break was supposed to preserve.
/// 3. **The resource's own entry before an ancestor's**, among rows that tie on everything above.
///    That is what makes `inherited_from` truthful: an entry that was already written directly on
///    the resource stays marked as direct, and only a genuine copy is marked with its source.
///
/// `granted_by` and `granted_at` are carried from the winning row rather than stamped with whoever
/// broke inheritance. The break did not grant anything — it moved where existing grants are stored,
/// and rewriting the granter would erase the provenance of every entry on the resource in a single
/// operation. Who performed the break is an audit event (`CLAUDE.md` rule 10), not an ACL column.
///
/// `DO UPDATE` is unconditional because `scoped` already contains the resource's own entries: the
/// row being overwritten is one of the inputs to the row overwriting it, so the update can only
/// ever write the effective value. Any key already on the resource is therefore present in the
/// insert, which is also why no `DELETE` is needed — there is nothing left behind to orphan.
const MATERIALISE_SQL: &str = concat!(
    "WITH scoped AS (",
    scoped_sql!(),
    "),
winner AS (
    SELECT DISTINCT ON (s.principal_type, s.principal_id, s.action)
           s.principal_type, s.principal_id, s.action, s.effect,
           s.granted_by, s.granted_at, s.expires_at, s.resource_id
      FROM scoped s
     ORDER BY s.principal_type, s.principal_id, s.action,
              (s.effect = 'DENY') DESC,
              (s.expires_at IS NULL) DESC,
              s.expires_at DESC,
              (s.resource_id = $6) DESC
)
INSERT INTO acl_entries
    (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
     effect, inherited_from, granted_by, granted_at, expires_at)
SELECT gen_random_uuid(), $1, $5, $6, w.principal_type, w.principal_id, w.action,
       w.effect,
       CASE WHEN w.resource_id = $6 THEN NULL ELSE w.resource_id END,
       w.granted_by, w.granted_at, w.expires_at
  FROM winner w
    ON CONFLICT (tenant_id, resource_type, resource_id, principal_type,
                 COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid), action)
    DO UPDATE SET effect         = EXCLUDED.effect,
                  inherited_from = EXCLUDED.inherited_from,
                  granted_by     = EXCLUDED.granted_by,
                  granted_at     = EXCLUDED.granted_at,
                  expires_at     = EXCLUDED.expires_at"
);

/// Flips a file's flag, and bumps `acl_revision` so the search index re-checks (`docs/07 §6`).
const STOP_FILE_INHERITING_SQL: &str = "
UPDATE files
   SET inherit_permissions = FALSE,
       revision            = revision + 1,
       acl_revision        = acl_revision + 1
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND inherit_permissions
";

/// The same for a library.
const STOP_LIBRARY_INHERITING_SQL: &str = "
UPDATE libraries
   SET inherit_permissions = FALSE,
       revision            = revision + 1
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND inherit_permissions
";
