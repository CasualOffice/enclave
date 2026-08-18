//! The SQL behind resolution: three round trips for a batch of any size.
//!
//! # Shape
//!
//! Per `plans/M1-CONTENT-CORE.md` D10 every function here takes a `&mut PgConnection` — never a
//! pool — so it physically cannot run outside the caller's `TenantScoped` transaction, and
//! therefore cannot run without `app.tenant_id` established. Every statement *also* carries an
//! explicit `tenant_id = $1` predicate. That is not belt and braces for its own sake: it is layer 1
//! of `docs/04-DATA-MODEL.md §3`, and the pair is what makes a leak require two independent
//! failures rather than one.
//!
//! # Why three queries and not N
//!
//! `authorize_many` is the search post-filter (`docs/07-SEARCH-INDEXING.md §6.2`), which runs over
//! ~200 candidates inside a single search request's latency budget. The work is therefore organised
//! as: one recursive walk for every candidate's inheritance chain, one recursive walk for the
//! caller's group closure, one fetch of the ACL rows for the union of every chain. Three round
//! trips, whether the batch holds one resource or two hundred. A per-resource loop would be 600.
//!
//! # Running as the application role
//!
//! These queries return rows only when row-level security lets them. PR #22 is the reason that
//! sentence is worth writing down: the policies were correct, but nothing had ever executed as
//! `enclave_app`, so nothing had ever *proved* they were. The integration tests in
//! `tests/acl_resolution.rs` go through the harness pool, which `SET ROLE enclave_app`s, and any
//! test added here must do the same or it is testing PostgreSQL's superuser bypass.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use enclave_core::{GroupId, TenantId};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::error::{AuthzError, Result};
use crate::resolve::{
    AclEntry, AclResourceType, ChainNode, Effect, InheritanceChain, Principal, PrincipalKind,
    PrincipalSet,
};

/// Walks a batch of files or folders to their roots, honouring `inherit_permissions` (rule 1).
///
/// The walk stops **at** the first node whose `inherit_permissions` is `FALSE` — that node's own
/// entries still apply, nothing above it does. That is what breaking inheritance means: the break
/// copies the effective entries down (`docs/04-DATA-MODEL.md §9`), so the ancestors above it are
/// redundant by construction rather than merely ignored.
///
/// Rows the caller may not see — another tenant's, or soft-deleted — simply do not join, so the
/// resource comes back with an empty chain and resolves to a refusal. A missing resource and a
/// forbidden one are deliberately the same outcome (`CLAUDE.md` rule 7).
const FILE_CHAIN_SQL: &str = "
WITH RECURSIVE roots AS (
    SELECT DISTINCT id FROM unnest($2::uuid[]) AS t(id)
),
walk AS (
    SELECT r.id AS root_id,
           f.id AS node_id,
           f.node_type,
           f.parent_id,
           f.library_id,
           f.inherit_permissions,
           0 AS depth
      FROM roots r
      JOIN files f
        ON f.tenant_id = $1 AND f.id = r.id AND f.deleted_at IS NULL
    UNION ALL
    SELECT w.root_id,
           p.id,
           p.node_type,
           p.parent_id,
           p.library_id,
           p.inherit_permissions,
           w.depth + 1
      FROM walk w
      JOIN files p
        ON p.tenant_id = $1 AND p.id = w.parent_id AND p.deleted_at IS NULL
     WHERE w.inherit_permissions AND w.depth < $3
)
SELECT w.root_id,
       w.node_type                 AS resource_type,
       w.node_id                   AS resource_id,
       w.depth                     AS depth,
       w.inherit_permissions       AS inherits,
       (w.parent_id IS NOT NULL)   AS has_parent
  FROM walk w
UNION ALL
SELECT w.root_id, 'LIBRARY', l.id, w.depth + 1, l.inherit_permissions, TRUE
  FROM walk w
  JOIN libraries l
    ON l.tenant_id = $1 AND l.id = w.library_id AND l.deleted_at IS NULL
 WHERE w.parent_id IS NULL AND w.inherit_permissions
UNION ALL
SELECT w.root_id, 'WORKSPACE', l.workspace_id, w.depth + 2, FALSE, FALSE
  FROM walk w
  JOIN libraries l
    ON l.tenant_id = $1 AND l.id = w.library_id AND l.deleted_at IS NULL
 WHERE w.parent_id IS NULL AND w.inherit_permissions AND l.inherit_permissions
 ORDER BY 1, 4
";

/// A library's own chain: itself, then its workspace if it inherits.
const LIBRARY_CHAIN_SQL: &str = "
SELECT l.id AS root_id, l.workspace_id, l.inherit_permissions AS inherits
  FROM libraries l
 WHERE l.tenant_id = $1 AND l.id = ANY($2::uuid[]) AND l.deleted_at IS NULL
";

/// A workspace's chain is the workspace, and this query exists to establish that it is real.
///
/// Without it an unknown UUID would produce a one-node chain against which an ACL entry could
/// never match anyway — the same verdict, reached by accident rather than on purpose.
const WORKSPACE_CHAIN_SQL: &str = "
SELECT w.id AS root_id
  FROM workspaces w
 WHERE w.tenant_id = $1 AND w.id = ANY($2::uuid[]) AND w.deleted_at IS NULL
";

/// The caller's transitive group closure (rule 2).
///
/// `UNION` rather than `UNION ALL` so a membership cycle collapses instead of recurring, and a
/// depth cap besides — `docs/04-DATA-MODEL.md §5` permits nesting "to a configured depth (default
/// 8)", which makes the cap the documented semantic rather than a safety valve.
const GROUP_CLOSURE_SQL: &str = "
WITH RECURSIVE closure AS (
    SELECT gm.group_id, 1 AS depth
      FROM group_members gm
     WHERE gm.tenant_id = $1 AND gm.member_id = $2 AND gm.member_type = $3
    UNION
    SELECT gm.group_id, c.depth + 1
      FROM closure c
      JOIN group_members gm
        ON gm.tenant_id = $1 AND gm.member_id = c.group_id AND gm.member_type = 'GROUP'
     WHERE c.depth < $4
)
SELECT DISTINCT group_id FROM closure
";

/// Every entry that could bear on this batch.
///
/// The `WHERE` clause narrows by node, action, expiry and principal so that a tenant's whole ACL
/// does not cross the wire. It is a prefilter and not the rule — [`crate::resolve`] re-applies the
/// principal and expiry tests on what comes back, so a mistake here costs bytes rather than
/// correctness.
const ACL_ENTRIES_SQL: &str = "
SELECT a.resource_type, a.resource_id, a.principal_type, a.principal_id, a.effect, a.expires_at
  FROM acl_entries a
  JOIN unnest($3::text[], $4::uuid[]) AS n(resource_type, resource_id)
    ON n.resource_type = a.resource_type AND n.resource_id = a.resource_id
 WHERE a.tenant_id = $1
   AND a.action = $2
   AND (a.expires_at IS NULL OR a.expires_at > $5)
   AND (
         a.principal_type = 'EVERYONE'
      OR (a.principal_type = $6 AND a.principal_id = $7)
      OR (a.principal_type = 'GROUP' AND a.principal_id = ANY($8::uuid[]))
   )
";

/// Reads a column, turning a decode failure into a message that names the column and nothing else.
fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T> {
    row.try_get(name).map_err(|_| AuthzError::MalformedRow {
        column: name,
        reason: "missing or of an unexpected type",
    })
}

/// Collects the inheritance chains of a batch of files and folders.
///
/// Returns one entry per resource that exists; resources absent from the map were not visible to
/// this transaction and must be refused by the caller.
///
/// # Errors
///
/// Storage failures, unreadable rows, and [`AuthzError::ChainTooDeep`] when the walk hit
/// `max_depth` with more tree above it — a truncated chain is missing exactly the ancestors that
/// carry organisation-wide denials, so it is refused rather than resolved.
pub async fn file_chains(
    conn: &mut PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
    max_depth: i32,
) -> Result<HashMap<Uuid, InheritanceChain>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(FILE_CHAIN_SQL)
        .bind(tenant.as_uuid())
        .bind(ids)
        .bind(max_depth)
        .fetch_all(&mut *conn)
        .await?;

    let mut chains: HashMap<Uuid, InheritanceChain> = HashMap::new();
    // The deepest row of each chain, kept to detect a walk that stopped because it ran out of
    // allowance rather than because it reached a root.
    let mut deepest: HashMap<Uuid, (i32, bool, bool)> = HashMap::new();

    for row in &rows {
        let root: Uuid = column(row, "root_id")?;
        let raw_type: String = column(row, "resource_type")?;
        let kind = AclResourceType::parse(&raw_type).ok_or(AuthzError::MalformedRow {
            column: "resource_type",
            reason: "not a resource type this resolver knows",
        })?;
        let id: Uuid = column(row, "resource_id")?;
        let depth: i32 = column(row, "depth")?;
        let inherits: bool = column(row, "inherits")?;
        let has_parent: bool = column(row, "has_parent")?;

        chains.entry(root).or_default().push(ChainNode::new(kind, id));
        let seen = deepest.entry(root).or_insert((depth, inherits, has_parent));
        if depth >= seen.0 {
            *seen = (depth, inherits, has_parent);
        }
    }

    for (depth, inherits, has_parent) in deepest.into_values() {
        if depth >= max_depth && inherits && has_parent {
            return Err(AuthzError::ChainTooDeep { limit: max_depth });
        }
    }

    Ok(chains)
}

/// Collects the chains of a batch of libraries.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn library_chains(
    conn: &mut PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, InheritanceChain>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(LIBRARY_CHAIN_SQL)
        .bind(tenant.as_uuid())
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;

    let mut chains = HashMap::new();
    for row in &rows {
        let root: Uuid = column(row, "root_id")?;
        let workspace: Uuid = column(row, "workspace_id")?;
        let inherits: bool = column(row, "inherits")?;

        let mut chain = InheritanceChain::new(vec![ChainNode::new(AclResourceType::Library, root)]);
        if inherits {
            chain.push(ChainNode::new(AclResourceType::Workspace, workspace));
        }
        let _replaced = chains.insert(root, chain);
    }
    Ok(chains)
}

/// Confirms which of a batch of workspaces exist, chaining each to itself.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn workspace_chains(
    conn: &mut PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, InheritanceChain>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(WORKSPACE_CHAIN_SQL)
        .bind(tenant.as_uuid())
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?;

    let mut chains = HashMap::new();
    for row in &rows {
        let root: Uuid = column(row, "root_id")?;
        let _replaced = chains.insert(
            root,
            InheritanceChain::new(vec![ChainNode::new(AclResourceType::Workspace, root)]),
        );
    }
    Ok(chains)
}

/// Resolves the caller's transitive group closure (rule 2).
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn group_closure(
    conn: &mut PgConnection,
    tenant: TenantId,
    principal: Principal,
    max_depth: i32,
) -> Result<HashSet<GroupId>> {
    let Some(id) = principal.id else {
        // `EVERYONE` has no membership to expand, and no `acl_entries` row can name it as one.
        return Ok(HashSet::new());
    };

    let rows = sqlx::query(GROUP_CLOSURE_SQL)
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(principal.kind.as_str())
        .bind(max_depth)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter().map(|row| column::<Uuid>(row, "group_id").map(GroupId::from_uuid)).collect()
}

/// Fetches the entries bearing on a set of chain nodes for one action.
///
/// # Errors
///
/// Storage failures and unreadable rows — including an unrecognised `effect`, `resource_type` or
/// `principal_type`, none of which are guessed at.
pub async fn acl_entries(
    conn: &mut PgConnection,
    tenant: TenantId,
    action: &str,
    nodes: &[ChainNode],
    principals: &PrincipalSet,
    now: DateTime<Utc>,
) -> Result<Vec<AclEntry>> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }

    let types: Vec<String> = nodes.iter().map(|n| n.kind.as_str().to_owned()).collect();
    let ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let groups: Vec<Uuid> = principals.groups().iter().map(|g| g.as_uuid()).collect();
    let direct = principals.direct();

    let rows = sqlx::query(ACL_ENTRIES_SQL)
        .bind(tenant.as_uuid())
        .bind(action)
        .bind(&types)
        .bind(&ids)
        .bind(now)
        .bind(direct.kind.as_str())
        .bind(direct.id)
        .bind(&groups)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter()
        .map(|row| {
            let raw_type: String = column(row, "resource_type")?;
            let kind = AclResourceType::parse(&raw_type).ok_or(AuthzError::MalformedRow {
                column: "resource_type",
                reason: "not a resource type this resolver knows",
            })?;
            let raw_principal: String = column(row, "principal_type")?;
            let principal_kind =
                PrincipalKind::parse(&raw_principal).ok_or(AuthzError::MalformedRow {
                    column: "principal_type",
                    reason: "not a principal kind this resolver knows",
                })?;
            let raw_effect: String = column(row, "effect")?;
            let effect = Effect::parse(&raw_effect).ok_or(AuthzError::MalformedRow {
                column: "effect",
                reason: "neither ALLOW nor DENY",
            })?;

            Ok(AclEntry {
                resource: ChainNode::new(kind, column(row, "resource_id")?),
                principal: Principal {
                    kind: principal_kind,
                    id: column::<Option<Uuid>>(row, "principal_id")?,
                },
                effect,
                expires_at: column::<Option<DateTime<Utc>>>(row, "expires_at")?,
            })
        })
        .collect()
}
