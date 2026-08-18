//! Groups, and the resolution of nested membership into a flat closure.
//!
//! # What the closure is for, and what it is not
//!
//! `docs/04-DATA-MODEL.md §9` describes authorization as: expand the principal into its transitive
//! group closure plus `EVERYONE`, gather the ACL entries for that set, apply deny-wins. This module
//! does the **first step only**. It answers "which groups is this user in, directly or through
//! nesting" and nothing else — no ACL is read here, no decision is made here, and `EVERYONE` is not
//! synthesized here because it belongs to the authorization vocabulary rather than to the
//! membership tables. `ENC-126` owns the resolver that consumes this.
//!
//! # Depth and cycles
//!
//! `docs/04-DATA-MODEL.md §5`: *nested groups are permitted to a configured depth (default 8)*. Two
//! failure modes follow from that sentence, and both are handled here rather than left to callers:
//!
//! * **A cycle** — group A contains B, B contains A. Directory synchronization produces these, and
//!   a naive walk recurses until the stack ends. [`Walk`] keeps a `seen` set, so a group is
//!   expanded at most once; a cycle terminates on its second visit with a complete closure.
//! * **Depth beyond the limit** — the walk stops and reports [`GroupClosure::is_truncated`].
//!   Truncation *removes* groups from the closure, so its effect on a later authorization decision
//!   is to grant less, never more. That is the only direction in which getting this wrong is
//!   survivable, and it is why truncation is a flag rather than an error: refusing outright would
//!   turn one badly-nested group into an outage for everyone in it. It is logged at `warn`, because
//!   a tenant hitting the limit is quietly getting less access than it configured.
//!
//! # Why a loop rather than a recursive CTE
//!
//! `WITH RECURSIVE` could do this in one statement, and `UNION` (rather than `UNION ALL`) even
//! terminates on cycles. It is not used because the depth limit is the point: expressing "stop at 8
//! and tell me you stopped" inside a CTE means threading a depth column and a truncation flag
//! through the recursion, for a walk that is at most nine round trips against an indexed table
//! (`idx_group_members_member`). If profiling later disagrees, the seam is [`ParentSource`] and the
//! behaviour is already pinned by unit tests that touch no database.

use core::num::NonZeroU8;
use std::collections::BTreeSet;

use async_trait::async_trait;
use enclave_core::{GroupId, TenantId, UserId};
use enclave_db::{sql, RowIdExt, Sql};
use sqlx::PgConnection;

use crate::error::Result;
use crate::model::{Group, MemberType};
use crate::row::group_from_row;

/// How deep nested membership may be resolved.
///
/// A newtype over [`NonZeroU8`] so that a limit of zero — which would resolve *no* groups and hand
/// authorization an empty closure for every user in the deployment — is not constructible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NestingLimit(NonZeroU8);

/// The depth `docs/04-DATA-MODEL.md §5` specifies.
const DEFAULT_DEPTH: u8 = 8;

impl NestingLimit {
    /// The default from `docs/04-DATA-MODEL.md §5`.
    pub const DEFAULT: Self = Self(match NonZeroU8::new(DEFAULT_DEPTH) {
        Some(levels) => levels,
        // Unreachable — `DEFAULT_DEPTH` is a non-zero literal. A `match` rather than `unwrap`
        // because the workspace forbids `unwrap` outside tests and this is a const context.
        None => NonZeroU8::MIN,
    });

    /// Builds a limit, or `None` for zero.
    #[must_use]
    pub const fn new(levels: u8) -> Option<Self> {
        match NonZeroU8::new(levels) {
            Some(levels) => Some(Self(levels)),
            None => None,
        }
    }

    /// The limit as a plain count of levels.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }
}

impl Default for NestingLimit {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The set of groups a principal belongs to, directly or through nesting.
///
/// A `BTreeSet` rather than a `Vec`: the closure is a *set* — a group reachable by two paths is one
/// grant, not two — and the ordering makes the value deterministic, which matters when it is hashed
/// into a cache key or printed by a failing assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupClosure {
    groups: BTreeSet<GroupId>,
    depth_reached: u8,
    truncated: bool,
}

impl GroupClosure {
    /// The groups, in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = GroupId> + '_ {
        self.groups.iter().copied()
    }

    /// The groups as a `Vec`, for binding into an `= ANY($1)` lookup.
    #[must_use]
    pub fn to_vec(&self) -> Vec<GroupId> {
        self.groups.iter().copied().collect()
    }

    /// Whether a specific group is in the closure.
    #[must_use]
    pub fn contains(&self, group: GroupId) -> bool {
        self.groups.contains(&group)
    }

    /// How many groups the closure holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the principal belongs to no groups at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// How many levels of nesting were walked. `0` when the principal has no groups.
    #[must_use]
    pub const fn depth_reached(&self) -> u8 {
        self.depth_reached
    }

    /// Whether the nesting limit cut the walk short.
    ///
    /// `true` means the closure is **incomplete**: further groups exist and are not in it. Callers
    /// that need completeness — a compliance report, an administrative "why can this user see
    /// that" view — must surface it rather than present a partial answer as a whole one. An
    /// authorization decision need not: a smaller closure only ever denies more.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Reads groups and membership.
///
/// Every function takes the `&mut PgConnection` a `TenantScoped` transaction derefs to, never a
/// pool (`plans/M1-CONTENT-CORE.md` D10). The `tenant` argument is the application-layer half of
/// the two-layer isolation in `docs/04-DATA-MODEL.md §3`; it must equal the transaction's tenant,
/// and if it does not, row-level security returns nothing rather than another tenant's rows.
#[derive(Debug, Clone, Copy, Default)]
pub struct GroupRepository;

impl GroupRepository {
    /// Finds one group by id.
    ///
    /// Soft-deleted groups are not returned. A deleted group must stop conferring access
    /// immediately, and the surest way to guarantee that is for it to stop being findable.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`crate::IdentityError::MalformedRow`] if a stored row holds a value
    /// outside the vocabulary in [`crate::model`].
    pub async fn find_by_id(
        conn: &mut PgConnection,
        tenant: TenantId,
        group: GroupId,
    ) -> Result<Option<Group>> {
        let row = sqlx::query(SELECT_GROUP_BY_ID)
            .bind(sql(tenant))
            .bind(sql(group))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(group_from_row).transpose()
    }

    /// The groups this user is a member of *directly* — one edge, no nesting.
    ///
    /// Ordered by normalized name so an administrative listing is stable between calls.
    ///
    /// # Errors
    ///
    /// As [`GroupRepository::find_by_id`].
    pub async fn direct_groups(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<Group>> {
        let rows = sqlx::query(SELECT_DIRECT_GROUPS)
            .bind(sql(tenant))
            .bind(sql(user))
            .bind(MemberType::User.as_str())
            .fetch_all(&mut *conn)
            .await?;
        rows.iter().map(group_from_row).collect()
    }

    /// Resolves the user's full group closure, following nesting to `limit` levels.
    ///
    /// An *input* to authorization, not authorization. See the [module documentation](self) for the
    /// cycle and truncation behaviour — both are properties of the walk rather than of a caller
    /// remembering to check for them.
    ///
    /// # Errors
    ///
    /// Storage failures. Depth truncation is **not** an error; see [`GroupClosure::is_truncated`].
    pub async fn transitive_groups(
        conn: &mut PgConnection,
        tenant: TenantId,
        user: UserId,
        limit: NestingLimit,
    ) -> Result<GroupClosure> {
        let direct = direct_group_ids(conn, tenant, user).await?;
        let mut source = PgParentSource { conn, tenant };
        let closure = resolve(&mut source, direct, limit).await?;

        if closure.truncated {
            // Warn, not debug: a tenant whose groups nest deeper than the limit is getting less
            // access than its administrators configured, and nobody would work that out from an
            // unexplained empty permission list.
            tracing::warn!(
                tenant_id = %tenant,
                user_id = %user,
                limit = limit.get(),
                resolved = closure.len(),
                "group nesting exceeded the configured depth; the closure is incomplete and \
                 authorization will grant less than is configured"
            );
        }

        Ok(closure)
    }
}

/// Where the walk gets the next level of parents.
///
/// A seam, so the depth and cycle behaviour can be tested exhaustively without a database — which
/// matters, because those are the parts that are easy to get wrong and impossible to observe in a
/// passing integration test. The database implementation and the in-memory test one drive the
/// *same* [`resolve`], so a test cannot pass against a driver the product does not use.
#[async_trait]
trait ParentSource {
    /// The groups holding any of `members` as a direct member, via a `GROUP` edge.
    async fn parents_of(&mut self, members: &[GroupId]) -> Result<Vec<GroupId>>;
}

/// The production source: one indexed query per level.
struct PgParentSource<'c> {
    conn: &'c mut PgConnection,
    tenant: TenantId,
}

#[async_trait]
impl ParentSource for PgParentSource<'_> {
    async fn parents_of(&mut self, members: &[GroupId]) -> Result<Vec<GroupId>> {
        let ids: Vec<Sql<GroupId>> = members.iter().copied().map(sql).collect();
        let rows = sqlx::query(SELECT_PARENT_GROUPS)
            .bind(sql(self.tenant))
            .bind(MemberType::Group.as_str())
            .bind(&ids)
            .fetch_all(&mut *self.conn)
            .await?;
        collect_group_ids(&rows)
    }
}

/// The walk itself. Breadth-first, one round trip per level.
///
/// Deliberately not recursive: recursion over directory data nobody in this process controls is how
/// a cycle becomes a stack overflow, and a stack overflow aborts the process rather than failing
/// the request.
async fn resolve<S: ParentSource + Send>(
    source: &mut S,
    direct: Vec<GroupId>,
    limit: NestingLimit,
) -> Result<GroupClosure> {
    let mut walk = Walk::new(limit);
    walk.absorb(direct);

    while let Some(frontier) = walk.take_frontier() {
        let parents = source.parents_of(&frontier).await?;
        walk.absorb(parents);
    }

    Ok(walk.finish())
}

/// The breadth-first state: what has been seen, what is left to expand, how deep we are.
#[derive(Debug)]
struct Walk {
    seen: BTreeSet<GroupId>,
    frontier: Vec<GroupId>,
    depth: u8,
    limit: u8,
    truncated: bool,
}

impl Walk {
    fn new(limit: NestingLimit) -> Self {
        Self {
            seen: BTreeSet::new(),
            frontier: Vec::new(),
            depth: 0,
            limit: limit.get(),
            truncated: false,
        }
    }

    /// Takes in one level's worth of groups.
    ///
    /// Three properties live here.
    ///
    /// **Cycles**: `seen` is the whole defence — a group already in the closure is never queued
    /// again, so a cycle contributes each of its members once and then the frontier empties.
    ///
    /// **Depth**: at the limit, newly discovered groups are discarded rather than added, and only
    /// *newly discovered* ones set `truncated` — so a deepest level whose parents are all already
    /// in the closure is a complete answer and is not reported as cut short.
    ///
    /// **What counts as a level**: the depth advances only when a level contributes a group the
    /// closure did not already hold. The final query of any walk returns nothing new — that is how
    /// the walk learns it is finished — and counting it would report every closure as one level
    /// deeper than it is, including an empty one.
    fn absorb(&mut self, groups: impl IntoIterator<Item = GroupId>) {
        if self.depth >= self.limit {
            if groups.into_iter().any(|group| !self.seen.contains(&group)) {
                self.truncated = true;
            }
            self.frontier.clear();
            return;
        }

        let mut discovered = false;
        for group in groups {
            if self.seen.insert(group) {
                self.frontier.push(group);
                discovered = true;
            }
        }
        if discovered {
            self.depth += 1;
        }
    }

    /// The groups to expand next, or `None` when the walk is finished.
    fn take_frontier(&mut self) -> Option<Vec<GroupId>> {
        if self.frontier.is_empty() {
            return None;
        }
        Some(core::mem::take(&mut self.frontier))
    }

    fn finish(self) -> GroupClosure {
        GroupClosure { depth_reached: self.depth, groups: self.seen, truncated: self.truncated }
    }
}

/// The direct group ids, without materializing whole `Group` rows.
///
/// A closure over a deeply nested directory reads many edges and needs none of the columns, so the
/// walk stays on ids from the first query onward.
async fn direct_group_ids(
    conn: &mut PgConnection,
    tenant: TenantId,
    user: UserId,
) -> Result<Vec<GroupId>> {
    let rows = sqlx::query(SELECT_DIRECT_GROUP_IDS)
        .bind(sql(tenant))
        .bind(sql(user))
        .bind(MemberType::User.as_str())
        .fetch_all(&mut *conn)
        .await?;
    collect_group_ids(&rows)
}

/// Reads the `group_id` column out of every row.
fn collect_group_ids(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<GroupId>> {
    let mut ids = Vec::with_capacity(rows.len());
    for row in rows {
        ids.push(row.try_get_id::<GroupId>("group_id")?);
    }
    Ok(ids)
}

/// One group by id. The `tenant_id` predicate is the application layer of the two-layer isolation;
/// RLS is the other, and neither is redundant (`docs/04-DATA-MODEL.md §3`).
///
/// The column list is spelled out rather than built from [`GROUP_COLUMNS`] at runtime — `concat!`
/// takes only literals, and assembling SQL with `format!` on every call to save one duplicated
/// string is the wrong trade. A unit test asserts the two agree.
const SELECT_GROUP_BY_ID: &str = "SELECT id, tenant_id, name, normalized_name, description, \
     source, external_id, created_at, updated_at \
     FROM groups WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";

/// Direct memberships, joined to `groups` so a soft-deleted group cannot appear.
const SELECT_DIRECT_GROUPS: &str = "SELECT g.id, g.tenant_id, g.name, g.normalized_name, \
     g.description, g.source, g.external_id, g.created_at, g.updated_at \
     FROM group_members m \
     JOIN groups g ON g.tenant_id = m.tenant_id AND g.id = m.group_id \
     WHERE m.tenant_id = $1 AND m.member_id = $2 AND m.member_type = $3 \
       AND g.deleted_at IS NULL \
     ORDER BY g.normalized_name ASC, g.id ASC";

/// The id-only form of the above, for the closure walk.
///
/// `member_type = $3` is not decoration: `member_id` is a discriminated reference, so without it a
/// user id would be matched against membership rows meant for guests or service accounts.
const SELECT_DIRECT_GROUP_IDS: &str = "SELECT m.group_id FROM group_members m \
     JOIN groups g ON g.tenant_id = m.tenant_id AND g.id = m.group_id \
     WHERE m.tenant_id = $1 AND m.member_id = $2 AND m.member_type = $3 \
       AND g.deleted_at IS NULL";

/// One level of nesting: the groups that contain any of the given groups.
const SELECT_PARENT_GROUPS: &str = "SELECT m.group_id FROM group_members m \
     JOIN groups g ON g.tenant_id = m.tenant_id AND g.id = m.group_id \
     WHERE m.tenant_id = $1 AND m.member_type = $2 AND m.member_id = ANY($3) \
       AND g.deleted_at IS NULL";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::collections::BTreeMap;

    use super::*;
    use crate::row::{GROUP_COLUMNS, GROUP_COLUMNS_ALIASED};

    /// An in-memory membership graph: group → the groups that contain it.
    ///
    /// Drives the *same* [`resolve`] the database path does, so these assertions are about the
    /// production walk and not about a parallel implementation written for the test.
    #[derive(Debug, Default)]
    struct MapSource {
        parents: BTreeMap<GroupId, Vec<GroupId>>,
        calls: usize,
    }

    #[async_trait]
    impl ParentSource for MapSource {
        async fn parents_of(&mut self, members: &[GroupId]) -> Result<Vec<GroupId>> {
            self.calls += 1;
            Ok(members
                .iter()
                .filter_map(|member| self.parents.get(member))
                .flatten()
                .copied()
                .collect())
        }
    }

    impl MapSource {
        /// A chain `groups[0] ∈ groups[1] ∈ … ∈ groups[n-1]`.
        fn chain(groups: &[GroupId]) -> Self {
            let mut source = Self::default();
            for window in groups.windows(2) {
                source.parents.entry(window[0]).or_default().push(window[1]);
            }
            source
        }
    }

    fn groups(count: usize) -> Vec<GroupId> {
        (0..count).map(|_| GroupId::new_v7()).collect()
    }

    #[tokio::test]
    async fn a_user_in_no_groups_resolves_to_an_empty_closure() {
        let mut source = MapSource::default();
        let closure = resolve(&mut source, Vec::new(), NestingLimit::DEFAULT).await.unwrap();
        assert!(closure.is_empty());
        assert_eq!(closure.depth_reached(), 0);
        assert!(!closure.is_truncated());
        assert_eq!(source.calls, 0, "an empty frontier must not cost a round trip");
    }

    #[tokio::test]
    async fn nesting_is_followed_to_the_top() {
        // finance-leads ∈ finance ∈ all-staff, and the user is only in finance-leads.
        let chain = groups(3);
        let mut source = MapSource::chain(&chain);
        let closure = resolve(&mut source, vec![chain[0]], NestingLimit::DEFAULT).await.unwrap();

        assert_eq!(closure.len(), 3);
        for group in &chain {
            assert!(closure.contains(*group), "{group} missing from the closure");
        }
        assert!(!closure.is_truncated());
        assert_eq!(closure.depth_reached(), 3);
    }

    #[tokio::test]
    async fn a_group_reachable_by_two_paths_appears_once() {
        let (leaf, left, right, top) =
            (GroupId::new_v7(), GroupId::new_v7(), GroupId::new_v7(), GroupId::new_v7());
        let mut source = MapSource::default();
        source.parents.insert(leaf, vec![left, right]);
        source.parents.insert(left, vec![top]);
        source.parents.insert(right, vec![top]);

        let closure = resolve(&mut source, vec![leaf], NestingLimit::DEFAULT).await.unwrap();
        assert_eq!(closure.len(), 4);
        assert_eq!(closure.to_vec().len(), 4, "the closure is a set, not a bag");
    }

    #[tokio::test]
    async fn a_cycle_terminates_rather_than_recursing() {
        // a ∈ b ∈ a — the shape a directory sync produces and a naive walk dies on.
        let (a, b) = (GroupId::new_v7(), GroupId::new_v7());
        let mut source = MapSource::default();
        source.parents.insert(a, vec![b]);
        source.parents.insert(b, vec![a]);

        let closure = resolve(&mut source, vec![a], NestingLimit::DEFAULT).await.unwrap();

        assert_eq!(closure.len(), 2, "both groups, each exactly once");
        assert!(closure.contains(a) && closure.contains(b));
        assert!(!closure.is_truncated(), "a cycle is complete, not truncated");
        assert!(source.calls <= 3, "the walk revisited a group: {} calls", source.calls);
    }

    #[tokio::test]
    async fn a_self_referential_group_terminates_too() {
        let a = GroupId::new_v7();
        let mut source = MapSource::default();
        source.parents.insert(a, vec![a]);

        let closure = resolve(&mut source, vec![a], NestingLimit::DEFAULT).await.unwrap();
        assert_eq!(closure.len(), 1);
        assert!(!closure.is_truncated());
    }

    #[tokio::test]
    async fn nesting_deeper_than_the_limit_is_truncated_and_says_so() {
        // Twelve levels, limit eight: eight groups resolved, four dropped, flag set.
        let chain = groups(12);
        let mut source = MapSource::chain(&chain);
        let closure = resolve(&mut source, vec![chain[0]], NestingLimit::DEFAULT).await.unwrap();

        assert!(closure.is_truncated(), "the walk must report that it stopped short");
        assert_eq!(closure.len(), 8, "exactly the configured number of levels is retained");
        assert_eq!(closure.depth_reached(), 8);
        for group in &chain[..8] {
            assert!(closure.contains(*group));
        }
        for group in &chain[8..] {
            assert!(!closure.contains(*group), "a group beyond the limit leaked into the closure");
        }
    }

    #[tokio::test]
    async fn truncation_only_ever_removes_groups() {
        // The safety argument for making truncation a flag rather than an error: a shorter limit
        // must produce a subset, never a different set.
        let chain = groups(6);

        let mut source = MapSource::chain(&chain);
        let deep = resolve(&mut source, vec![chain[0]], NestingLimit::DEFAULT).await.unwrap();

        let mut source = MapSource::chain(&chain);
        let shallow =
            resolve(&mut source, vec![chain[0]], NestingLimit::new(3).unwrap()).await.unwrap();

        assert!(shallow.is_truncated());
        assert!(shallow.len() < deep.len());
        for group in shallow.iter() {
            assert!(deep.contains(group), "a shallower walk produced a group the deeper one lacks");
        }
    }

    #[tokio::test]
    async fn a_closure_that_ends_exactly_at_the_limit_is_not_reported_as_truncated() {
        // Eight levels with a limit of eight: complete. Reporting truncation here would cry wolf on
        // every correctly-configured tenant that happens to use the full depth.
        let chain = groups(8);
        let mut source = MapSource::chain(&chain);
        let closure = resolve(&mut source, vec![chain[0]], NestingLimit::DEFAULT).await.unwrap();
        assert_eq!(closure.len(), 8);
        assert!(!closure.is_truncated());
    }

    #[test]
    fn a_nesting_limit_of_zero_is_not_constructible() {
        // Zero would hand authorization an empty closure for every user: every group grant in the
        // deployment silently stops applying.
        assert!(NestingLimit::new(0).is_none());
        assert_eq!(NestingLimit::default().get(), 8, "docs/04-DATA-MODEL.md §5");
    }

    /// Every membership query filters on `member_type`. `member_id` is a discriminated reference —
    /// without the filter a user id is matched against guest and service-account rows too.
    #[test]
    fn every_membership_query_filters_on_member_type() {
        for query in [SELECT_DIRECT_GROUPS, SELECT_DIRECT_GROUP_IDS, SELECT_PARENT_GROUPS] {
            assert!(query.contains("member_type"), "{query}");
            assert!(
                query.contains("g.deleted_at IS NULL"),
                "a deleted group must not grant access"
            );
            assert!(query.contains("m.tenant_id = $1"), "the application predicate is missing");
        }
    }

    /// The column lists in the queries are hand-written copies of the constants the decoder is
    /// documented against. A column dropped from one and not the other is a `ColumnNotFound` at
    /// runtime, on whichever path happens to run first in production.
    #[test]
    fn the_select_lists_match_the_decoders_column_constants() {
        assert!(SELECT_GROUP_BY_ID.contains(GROUP_COLUMNS), "{SELECT_GROUP_BY_ID}");
        assert!(SELECT_DIRECT_GROUPS.contains(GROUP_COLUMNS_ALIASED), "{SELECT_DIRECT_GROUPS}");
    }
}
