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
//! The same three trips answer several *actions* at once ([`acl_entries_by_action`]), because the
//! first two do not depend on the action at all and the third narrows by it with `= ANY` as cheaply
//! as with `=`. A listing page asking ten capability questions about a page of rows is therefore
//! three statements rather than thirty.
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

/// What each of a batch of share links points at (`ENC-879`).
///
/// A share link has no ACL of its own — `acl_entries.resource_type` has no `SHARE` value — because
/// the permission that governs a link is the permission on the thing it exposes. So resolving a
/// `ResourceKind::Share` reference means one extra hop: find the link's target, then walk *that*.
///
/// **Revoked and expired links resolve to nothing.** They are excluded here rather than compared
/// afterwards, so a caller asking about a dead link gets an empty chain and therefore a refusal, on
/// the same footing as a link that never existed (`CLAUDE.md` rule 7). This is *not* the redemption
/// path's liveness check — that one lives in the `WHERE` clause of the `UPDATE` that spends the
/// budget (`enclave_sharing::redeem`), because only a check inside the spending statement is safe
/// under concurrency. This one exists so that an authorization question about a revoked link cannot
/// come back `ALLOW`.
///
/// `expires_at` is compared against a bound instant rather than `now()` so that every stage of one
/// request judges the link against the same moment, which is the argument `effective_actions_in_tx`
/// makes for taking `now` as an argument at all.
const SHARE_TARGET_SQL: &str = "
SELECT s.id AS share_id, s.resource_type, s.resource_id
  FROM share_links s
 WHERE s.tenant_id = $1
   AND s.id = ANY($2::uuid[])
   AND s.revoked_at IS NULL
   AND (s.expires_at IS NULL OR s.expires_at > $3)
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

/// Every entry that could bear on this batch, for every action it asks about.
///
/// The `WHERE` clause narrows by node, action, expiry and principal so that a tenant's whole ACL
/// does not cross the wire. It is a prefilter and not the rule — [`crate::resolve`] re-applies the
/// principal and expiry tests on what comes back, so a mistake here costs bytes rather than
/// correctness.
///
/// `$9` is [`PrincipalSet::matched_by_everyone`], and it is the one clause here that is *not*
/// merely a prefilter. `ENC-879`: a share-link bearer is deliberately outside "everyone in this
/// tenant", so an `EVERYONE` row must not reach it. The rule is re-applied in
/// [`crate::resolve::PrincipalSet::matches`] as this module's header promises, and it is written
/// twice on purpose — deleting either one must leave the other refusing, because a tenant-wide grant
/// silently reaching a link bearer would extend every link into every internally-shared resource in
/// the tenant. It is a bound predicate rather than two SQL strings so that the two paths cannot
/// drift in anything but this one boolean.
///
/// `action = ANY($2)` rather than `action = $2` because the cost of resolution is ~80% fixed
/// (ENC-145, `tests/authorize_many_cost.rs`): a transaction and three round trips, plus about
/// 0.03 ms per extra candidate. Asking about ten actions in ten calls therefore costs ten times a
/// question that the same three statements can answer once. `a.action` is *selected* as well as
/// filtered, because a row that arrives without saying which action it belongs to can only be
/// attributed by guessing, and a misattributed `DENY` is a privilege change in whichever direction
/// the guess went.
const ACL_ENTRIES_SQL: &str = "
SELECT a.resource_type, a.resource_id, a.principal_type, a.principal_id, a.action, a.effect,
       a.expires_at
  FROM acl_entries a
  JOIN unnest($3::text[], $4::uuid[]) AS n(resource_type, resource_id)
    ON n.resource_type = a.resource_type AND n.resource_id = a.resource_id
 WHERE a.tenant_id = $1
   AND a.action = ANY($2::text[])
   AND (a.expires_at IS NULL OR a.expires_at > $5)
   AND (
         (a.principal_type = 'EVERYONE' AND $9)
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

/// What each of a batch of live share links points at, as an ACL chain node (`ENC-879`).
///
/// Links absent from the returned map are unknown, revoked, expired, or in another tenant — four
/// states this deliberately does not distinguish. See [`SHARE_TARGET_SQL`].
///
/// A row whose `resource_type` this release does not recognise is a **refusal**, not an error and
/// not a guess: the same argument [`crate::resolve::AclResourceType::parse`] makes. `SHARE` is not
/// one of the values, so a link pointing at another link resolves to nothing rather than recursing.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn share_targets(
    conn: &mut PgConnection,
    tenant: TenantId,
    ids: &[Uuid],
    now: DateTime<Utc>,
) -> Result<HashMap<Uuid, ChainNode>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(SHARE_TARGET_SQL)
        .bind(tenant.as_uuid())
        .bind(ids)
        .bind(now)
        .fetch_all(&mut *conn)
        .await?;

    let mut targets = HashMap::new();
    for row in &rows {
        let share: Uuid = column(row, "share_id")?;
        let kind: String = column(row, "resource_type")?;
        let resource: Uuid = column(row, "resource_id")?;
        // `share_links.resource_type` spells `LIBRARY`, `FOLDER` and `FILE`, which are three of
        // `AclResourceType`'s seven. An unrecognised value drops the link from the map and is
        // therefore a refusal.
        if let Some(kind) = AclResourceType::parse(&kind) {
            let _replaced = targets.insert(share, ChainNode::new(kind, resource));
        }
    }
    Ok(targets)
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

/// Which buckets each fetched row belongs in, keyed by the action as it is spelled in the column.
///
/// A `Vec<usize>` per action rather than a single index because a caller may repeat an action —
/// nine capability probes that happen to include `download` twice, say — and every occurrence has
/// to receive the same rows. Dropping the repeat would leave one column of the answer empty, which
/// reads as "not granted" and silently removes a permission the caller has.
fn destinations(actions: &[String]) -> HashMap<&str, Vec<usize>> {
    let mut destinations: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, action) in actions.iter().enumerate() {
        destinations.entry(action.as_str()).or_default().push(index);
    }
    destinations
}

/// Reads one `acl_entries` row into the shape resolution works on.
fn entry(row: &sqlx::postgres::PgRow) -> Result<AclEntry> {
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

    Ok(AclEntry {
        resource: ChainNode::new(kind, column(row, "resource_id")?),
        principal: Principal {
            kind: principal_kind,
            id: column::<Option<Uuid>>(row, "principal_id")?,
        },
        effect,
        expires_at: column::<Option<DateTime<Utc>>>(row, "expires_at")?,
    })
}

/// Fetches the entries bearing on a set of chain nodes, for several actions in one statement.
///
/// The result is one bucket per element of `actions`, index-aligned with it, holding only the rows
/// whose `action` column equals that element. Splitting here rather than downstream is deliberate:
/// it is the *only* point in the multi-action path where rows for different actions coexist, so it
/// is the only place a `DENY` on `download` could end up deciding `preview`. Everything after it
/// consumes one bucket at a time and cannot mix them even in principle.
///
/// # Errors
///
/// Storage failures and unreadable rows — including an unrecognised `effect`, `resource_type`,
/// `principal_type` or `action`, none of which are guessed at. An `action` that matches nothing the
/// caller asked for cannot be produced by the query above, so seeing one means the text the caller
/// bound and the text the row holds have stopped agreeing; filing it in an arbitrary bucket would
/// apply a real entry to the wrong question, so it is refused instead.
pub async fn acl_entries_by_action(
    conn: &mut PgConnection,
    tenant: TenantId,
    actions: &[String],
    nodes: &[ChainNode],
    principals: &PrincipalSet,
    now: DateTime<Utc>,
) -> Result<Vec<Vec<AclEntry>>> {
    let mut buckets: Vec<Vec<AclEntry>> = vec![Vec::new(); actions.len()];
    if nodes.is_empty() || actions.is_empty() {
        return Ok(buckets);
    }

    let types: Vec<String> = nodes.iter().map(|n| n.kind.as_str().to_owned()).collect();
    let ids: Vec<Uuid> = nodes.iter().map(|n| n.id).collect();
    let groups: Vec<Uuid> = principals.groups().iter().map(|g| g.as_uuid()).collect();
    let direct = principals.direct();

    let rows = sqlx::query(ACL_ENTRIES_SQL)
        .bind(tenant.as_uuid())
        .bind(actions)
        .bind(&types)
        .bind(&ids)
        .bind(now)
        .bind(direct.kind.as_str())
        .bind(direct.id)
        .bind(&groups)
        .bind(principals.matched_by_everyone())
        .fetch_all(&mut *conn)
        .await?;

    let destinations = destinations(actions);
    for row in &rows {
        let action: String = column(row, "action")?;
        let indices = destinations.get(action.as_str()).ok_or(AuthzError::MalformedRow {
            column: "action",
            reason: "not one of the actions this resolution asked about",
        })?;
        let entry = entry(row)?;
        for index in indices {
            buckets[*index].push(entry);
        }
    }
    Ok(buckets)
}

/// Fetches the entries bearing on a set of chain nodes for one action.
///
/// The whole body is a delegation to [`acl_entries_by_action`], for the reason
/// `PgAclAuthorization::authorize` gives for delegating to its own batch path: a second
/// implementation of one question is how the narrower form ends up applying a filter the wider one
/// does not, and it is the wider one that the listing and search paths run.
///
/// # Errors
///
/// As [`acl_entries_by_action`].
pub async fn acl_entries(
    conn: &mut PgConnection,
    tenant: TenantId,
    action: &str,
    nodes: &[ChainNode],
    principals: &PrincipalSet,
    now: DateTime<Utc>,
) -> Result<Vec<AclEntry>> {
    let actions = [action.to_owned()];
    let mut buckets = acl_entries_by_action(conn, tenant, &actions, nodes, principals, now).await?;
    // One action in, one bucket out. `pop` rather than indexing so that a shape this function did
    // not expect yields no entries — which grants nothing — instead of a panic inside a policy
    // stage.
    Ok(buckets.pop().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn actions(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn every_action_gets_its_own_bucket() {
        let names = actions(&["file.preview", "file.download", "file.print"]);
        let destinations = destinations(&names);
        assert_eq!(destinations.get("file.preview"), Some(&vec![0]));
        assert_eq!(destinations.get("file.download"), Some(&vec![1]));
        assert_eq!(destinations.get("file.print"), Some(&vec![2]));
        // The row that would carry one action's DENY into another's answer is one that lands in a
        // bucket it does not belong to. Nothing here is a home for an action nobody asked about.
        assert_eq!(destinations.get("file.export"), None);
    }

    #[test]
    fn a_repeated_action_is_answered_at_every_position_it_appears() {
        // Not a hypothetical: a capability table that lists an action twice would otherwise get a
        // populated answer at the first position and an empty one at the second, and an empty
        // bucket is indistinguishable from "nobody granted it".
        let names = actions(&["file.download", "file.preview", "file.download"]);
        let destinations = destinations(&names);
        assert_eq!(destinations.get("file.download"), Some(&vec![0, 2]));
        assert_eq!(destinations.get("file.preview"), Some(&vec![1]));
    }
}
