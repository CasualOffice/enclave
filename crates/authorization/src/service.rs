//! The resolver and the [`AuthorizationService`] implementation over it.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, AuthorizationService, ReasonCode, RequestContext, ResourceKind, ResourceRef,
    Result as CoreResult, StageDecision, TenantId,
};
use enclave_db::{DbPool, TenantScoped};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::Result;
use crate::repo;
use crate::resolve::{
    AclResourceType, ChainNode, Effective, EffectiveGrid, EffectiveIndex, InheritanceChain,
    PrincipalKind, PrincipalSet,
};

/// Bounds on how far resolution will walk before refusing to answer.
///
/// Both are caps on *recursion in the database*, and both exist because an unbounded recursive CTE
/// over data a user controls is a denial-of-service primitive: a cycle in `group_members`, or a
/// deep enough folder tree, would otherwise be a query that never returns while holding a
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverLimits {
    /// How many ancestors the inheritance walk will climb.
    ///
    /// Exceeding it is an error, not a partial answer — see [`crate::error::AuthzError::ChainTooDeep`].
    pub max_inheritance_depth: i32,
    /// How deeply nested groups are followed.
    ///
    /// Exceeding it is *not* an error: `docs/04-DATA-MODEL.md §5` permits nesting "to a configured
    /// depth (default 8)", so a membership beyond the limit is not a membership at all, and
    /// truncating is the documented behaviour rather than a shortfall of it.
    pub max_group_depth: i32,
}

impl ResolverLimits {
    /// The limits in force unless a caller says otherwise.
    ///
    /// 64 ancestors is far past anything a person navigates and far short of anything PostgreSQL
    /// notices; 8 is the group-nesting default of `docs/04-DATA-MODEL.md §5`. A `const` rather than
    /// only a [`Default`] impl so the constructors can stay `const` and so there is exactly one
    /// place these numbers are written.
    pub const DEFAULT: Self = Self { max_inheritance_depth: 64, max_group_depth: 8 };
}

impl Default for ResolverLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a resource reference turns out to be, once its tenant and kind have been checked.
///
/// The three refusals are separated because they refuse for genuinely different reasons and the
/// distinction is worth having in a test, but they produce the same answer: nothing is queried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// A file or folder: walk the tree.
    FileTree(Uuid),
    /// A library.
    Library(Uuid),
    /// A workspace.
    Workspace(Uuid),
    /// A share link, which has to be resolved to what it points at before it can be walked
    /// (`ENC-879`).
    ///
    /// The only target that is not final. [`resolve_share_targets`] rewrites it into a
    /// [`Target::FileTree`] or a [`Target::Library`] before any chain is looked up; one that is
    /// still a `ShareLink` afterwards is a link that could not be resolved — unknown, revoked,
    /// expired, or another tenant's — and [`chain_key`] refuses it like any other.
    ShareLink(Uuid),
    /// Belongs to another tenant. Refused without a query — see [`AclResolver::effective_in_tx`].
    ForeignTenant,
    /// A kind that carries no ACL rows.
    Unsupported,
}

/// Classifies a reference against the tenant the transaction is scoped to.
///
/// The tenant comparison is here, and not left to `PolicyEngine::enforce`, because
/// [`AuthorizationService::authorize_many`] is called *directly* by the search post-filter
/// (`docs/07-SEARCH-INDEXING.md §6.2`) — it does not pass through the engine, so the engine's
/// stage-1 tenant check does not run for it. Without this, a candidate list contaminated with
/// another tenant's ids would be resolved against this tenant's `SET LOCAL app.tenant_id`, where
/// the rows are invisible and every verdict happens to be a refusal — right answer, no check, and
/// one schema change away from being the wrong answer.
fn classify(tenant: TenantId, resource: &ResourceRef) -> Target {
    if resource.tenant_id != tenant {
        return Target::ForeignTenant;
    }
    match resource.kind {
        ResourceKind::File | ResourceKind::Folder => Target::FileTree(resource.id),
        ResourceKind::Library => Target::Library(resource.id),
        ResourceKind::Workspace => Target::Workspace(resource.id),
        // `ENC-879`. A share link resolves — but through one extra hop, because it carries no
        // `acl_entries` rows of its own: the permission that governs a link is the permission on
        // the thing it exposes. That is the rule `crates/api/src/routes/shares.rs` was already
        // applying by hand, and this is it inside the resolver, where a link that is revoked,
        // expired or another tenant's simply produces no chain.
        ResourceKind::Share => Target::ShareLink(resource.id),
        // Versions, chunks, users, devices, pages, lists and list items are all real resources;
        // none of them resolve through the file inheritance tree. Pages and lists do carry
        // `acl_entries` rows (`docs/04-DATA-MODEL.md §9`) but their containment is not modelled
        // yet, and a chain that guessed at it would be a permission model nobody specified.
        // Refused until each is designed.
        _ => Target::Unsupported,
    }
}

/// Replaces every [`Target::ShareLink`] with the target of the link it names (`ENC-879`).
///
/// Runs before any chain walk, and only when the batch actually contains a share reference — the
/// common case pays nothing. A link that resolves to nothing keeps its `ShareLink` target, which
/// [`chain_key`] refuses, so unknown, revoked, expired and cross-tenant links are one answer.
///
/// # Errors
///
/// Storage failures and unreadable rows.
async fn resolve_share_targets(
    conn: &mut PgConnection,
    tenant: TenantId,
    targets: &mut [Target],
    now: DateTime<Utc>,
) -> Result<()> {
    let shares: Vec<Uuid> = targets
        .iter()
        .filter_map(|target| match *target {
            Target::ShareLink(id) => Some(id),
            _ => None,
        })
        .collect();
    if shares.is_empty() {
        return Ok(());
    }

    let resolved = repo::share_targets(conn, tenant, &shares, now).await?;
    for target in targets.iter_mut() {
        let Target::ShareLink(id) = *target else { continue };
        // `AclResourceType::Folder` and `File` both walk the file tree, exactly as
        // `ResourceRef::file` and `ResourceRef::folder` do — `merge_chains` keys on the family, not
        // on the row's own kind, which is what makes that safe.
        *target = match resolved.get(&id).map(|node| (node.kind, node.id)) {
            Some((AclResourceType::File | AclResourceType::Folder, id)) => Target::FileTree(id),
            Some((AclResourceType::Library, id)) => Target::Library(id),
            // A link pointing at a workspace, page, list or list item: `share_links.resource_type`
            // cannot hold any of them today, so this is schema drift rather than a case to model.
            // Left unresolved, which refuses.
            Some(_) | None => Target::ShareLink(id),
        };
    }
    Ok(())
}

/// Whether the caller, *if* it is a share-link bearer, presents a link that is still usable
/// (`ENC-879`).
///
/// `true` for every other principal without asking anything: a user, a guest and a service account
/// are not credentials with expiry dates, and charging them a round trip would be paying for a
/// question that has no answer.
///
/// Unknown, revoked, expired and another tenant's link are one answer, which is `CLAUDE.md` rule 7
/// arriving on the *principal* rather than on the resource. The cross-tenant leg is held twice
/// here: `share_targets` carries an explicit `tenant_id = $1` predicate (layer 1) and runs on a
/// `TenantScoped` connection where row-level security excludes the row anyway (layer 2).
///
/// # Errors
///
/// Storage failures. A failure is *not* "the link is dead": a database blip must not be able to
/// masquerade as a policy answer in either direction (`crates/core/src/engine.rs`).
async fn link_principal_is_live(
    conn: &mut PgConnection,
    tenant: TenantId,
    principals: &PrincipalSet,
    now: DateTime<Utc>,
) -> Result<bool> {
    let direct = principals.direct();
    if direct.kind != PrincipalKind::ShareLink {
        return Ok(true);
    }
    // `Principal::id` is `None` only for `EVERYONE`, which is not this kind — but a `SHARE_LINK`
    // principal with no id names no link, so it holds nothing.
    let Some(id) = direct.id else { return Ok(false) };
    Ok(!repo::share_targets(conn, tenant, &[id], now).await?.is_empty())
}

/// ACL resolution per `docs/04-DATA-MODEL.md §9`.
///
/// Holds no connection and no pool: it is the rules plus their limits, so a caller that already has
/// a `TenantScoped` transaction open can resolve inside it and have the decision and the work it
/// authorises commit or roll back together.
#[derive(Debug, Clone, Copy, Default)]
pub struct AclResolver {
    limits: ResolverLimits,
}

impl AclResolver {
    /// A resolver with the default limits.
    #[must_use]
    pub const fn new() -> Self {
        Self { limits: ResolverLimits::DEFAULT }
    }

    /// A resolver with explicit limits.
    #[must_use]
    pub const fn with_limits(limits: ResolverLimits) -> Self {
        Self { limits }
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> ResolverLimits {
        self.limits
    }

    /// Resolves one action over a batch of resources inside a caller-supplied transaction.
    ///
    /// The returned vector is index-aligned with `resources`, including duplicates and including
    /// the entries that were refused without a query.
    ///
    /// The body is a one-action call to [`AclResolver::effective_actions_in_tx`], for the reason
    /// [`PgAclAuthorization::authorize`] gives for delegating to its own batch path: two
    /// implementations of one question are how the narrower form ends up answering something the
    /// wider one does not, and here the two would differ over the rule that matters most — which
    /// action a fetched `DENY` belongs to.
    ///
    /// # Errors
    ///
    /// As [`AclResolver::effective_actions_in_tx`].
    pub async fn effective_in_tx(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        actor: &Actor,
        action: Action,
        resources: &[ResourceRef],
        now: DateTime<Utc>,
    ) -> Result<Vec<Effective>> {
        let grid = self
            .effective_actions_in_tx(
                conn,
                tenant,
                actor,
                core::slice::from_ref(&action),
                resources,
                now,
            )
            .await?;
        // One action in, one row out. Unreachable by construction; if it ever stopped holding, the
        // refusing answer is the safe one, and it is still the right length.
        Ok(grid
            .for_action(0)
            .map_or_else(|| vec![Effective::NotGranted; resources.len()], <[Effective]>::to_vec))
    }

    /// Resolves a set of actions over a batch of resources in one pass.
    ///
    /// The answer is keyed by `(action, resource)`: [`EffectiveGrid::for_action`] takes an index
    /// into `actions` and yields a row index-aligned with `resources`, duplicates and
    /// refused-without-a-query entries included.
    ///
    /// # Why the actions travel together
    ///
    /// The first two of the three round trips — the inheritance walk and the group closure — do not
    /// mention the action at all, and ENC-145 measured the cost of a resolution as ~80% fixed
    /// (`tests/authorize_many_cost.rs`). Ten actions asked one at a time therefore pay that fixed
    /// cost ten times to re-derive identical chains. A listing page is exactly this shape: nine
    /// capability probes plus the trim's `metadata_read`, over one page of rows.
    ///
    /// # Why it cannot mix one action's verdict into another's
    ///
    /// Rows are separated once, in [`repo::acl_entries_by_action`], by the `action` column the
    /// query now selects; each action's [`EffectiveIndex`] is then built from its own bucket and
    /// from nothing else. Deny-wins runs inside one index, so a `DENY` has no representation that
    /// could reach another action's answer. What the two do share is each resource's inheritance
    /// chain, which is action-independent by definition — and is looked up once here, so every
    /// action necessarily decides against the same chain rather than against a re-derived one.
    ///
    /// `now` is taken as an argument rather than read from the clock so that every resource *and
    /// every action* in one pass is judged against a single instant: with a `download` grant
    /// expiring mid-flight, a per-call `Utc::now()` would let one page's capabilities disagree with
    /// each other about whether the same entry had expired.
    ///
    /// # Errors
    ///
    /// Storage failures, unreadable rows, and a chain deeper than the configured limit. None of
    /// these is converted into a denial: an evaluation that could not happen is not an evaluation
    /// that said no (`crates/core/src/engine.rs`).
    pub async fn effective_actions_in_tx(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        actor: &Actor,
        actions: &[Action],
        resources: &[ResourceRef],
        now: DateTime<Utc>,
    ) -> Result<EffectiveGrid> {
        let mut targets: Vec<Target> = resources.iter().map(|r| classify(tenant, r)).collect();

        // An actor with no ACL principal cannot be named by any entry, so there is nothing to ask
        // the database. Returning before the queries is not just an optimisation: it is what stops
        // `EVERYONE` from being matched by a principal the ACL model has no way to talk about.
        let Some(principals) = PrincipalSet::for_actor(actor) else {
            return Ok(refusing(actions.len(), resources.len()));
        };

        // `ENC-879`. **A share link is a principal only while it is live.**
        //
        // Found by `the_chain_authorizes_the_link_bearer_a_redemption_presents`' sibling: an
        // `acl_entries` row naming a link outlives the link, so without this a revoked or expired
        // link kept every grant it had been given — `docs/12 §4.4` H4 requires revocation to close
        // a link *including for an already-open session*, and an authorization stage that answers
        // `ALLOW` for a revoked credential is that requirement failing at the one layer that
        // decides.
        //
        // Deleting the `acl_entries` row at revocation time was the alternative and it is worse:
        // revocation would then be two writes that can half-succeed, and the grant would survive
        // whichever half failed. Liveness is read here, in the same transaction as the decision, so
        // there is no window.
        //
        // The check is `repo::share_targets` rather than a second liveness predicate, deliberately:
        // one function owns "is this link usable", so the resource side and the principal side
        // cannot drift into disagreeing about a revoked link.
        if !link_principal_is_live(conn, tenant, &principals, now).await? {
            return Ok(refusing(actions.len(), resources.len()));
        }

        // `ENC-879`. Query 0, and only when a share reference is in the batch: a share link has no
        // chain of its own, so it is rewritten into the target it exposes before anything is walked.
        resolve_share_targets(conn, tenant, &mut targets, now).await?;

        let mut files = Vec::new();
        let mut libraries = Vec::new();
        let mut workspaces = Vec::new();
        for target in &targets {
            match *target {
                Target::FileTree(id) => files.push(id),
                Target::Library(id) => libraries.push(id),
                Target::Workspace(id) => workspaces.push(id),
                // A `ShareLink` still standing after `resolve_share_targets` is a link that
                // resolved to nothing, so it belongs with the other refusals.
                Target::ShareLink(_) | Target::ForeignTenant | Target::Unsupported => {}
            }
        }
        if actions.is_empty() || (files.is_empty() && libraries.is_empty() && workspaces.is_empty())
        {
            return Ok(refusing(actions.len(), resources.len()));
        }

        // Query 1 — every candidate's chain, in one walk per family.
        let mut chains: HashMap<ChainNode, InheritanceChain> = HashMap::new();
        merge_chains(
            &mut chains,
            AclResourceType::File,
            repo::file_chains(conn, tenant, &files, self.limits.max_inheritance_depth).await?,
        );
        merge_chains(
            &mut chains,
            AclResourceType::Library,
            repo::library_chains(conn, tenant, &libraries).await?,
        );
        merge_chains(
            &mut chains,
            AclResourceType::Workspace,
            repo::workspace_chains(conn, tenant, &workspaces).await?,
        );

        // Query 2 — the caller's transitive group closure, once for the whole batch.
        //
        // Skipped entirely for a share-link bearer, and `PrincipalSet::can_hold_group_memberships`
        // carries the reason: `group_members.member_type` cannot store a share link, so the walk
        // could only ever return zero rows. The skip is safe *because* of that constraint and not
        // because of anything here, which is why `migrations/0027` fails if the constraint is ever
        // widened.
        let principals = if principals.can_hold_group_memberships() {
            let direct = principals.direct();
            let groups =
                repo::group_closure(conn, tenant, direct, self.limits.max_group_depth).await?;
            principals.with_groups(groups)
        } else {
            principals
        };

        // Query 3 — the entries on the union of every chain, for every action, once for the whole
        // batch. They come back already separated by action and are never seen together again.
        let mut nodes: Vec<ChainNode> =
            chains.values().flat_map(|chain| chain.nodes().iter().copied()).collect();
        nodes.sort_unstable();
        nodes.dedup();
        let names: Vec<String> = actions.iter().map(ToString::to_string).collect();
        let buckets =
            repo::acl_entries_by_action(conn, tenant, &names, &nodes, &principals, now).await?;

        // Each resource's chain, resolved once and shared by every action. Sharing it is not a
        // saving so much as a guarantee: inheritance does not vary by action, so two actions
        // deciding against two separately-derived chains could only ever differ by a bug.
        let empty = InheritanceChain::default();
        let walked: Vec<&InheritanceChain> = targets
            .iter()
            .map(|target| chain_key(*target).and_then(|key| chains.get(&key)).unwrap_or(&empty))
            .collect();

        // One row per action, each index-aligned with `resources`: one verdict per input,
        // duplicates and refusals included.
        let rows = buckets
            .iter()
            .map(|entries| {
                let index = EffectiveIndex::build(entries, &principals, now);
                walked.iter().map(|chain| index.decide(chain)).collect()
            })
            .collect();
        Ok(EffectiveGrid::from_action_rows(resources.len(), rows))
    }
}

/// A grid that grants nothing, for the paths that refuse before any query runs.
///
/// Full-sized rather than empty: a caller that asked about ten actions must be able to read all ten
/// answers, and an answer that is missing is one a caller has to invent a default for.
fn refusing(actions: usize, resources: usize) -> EffectiveGrid {
    EffectiveGrid::from_action_rows(
        resources,
        vec![vec![Effective::NotGranted; resources]; actions],
    )
}

/// Folds one family's chains into the batch-wide map.
///
/// The key is the *family* the walk was issued for, never the row's own `node_type`. A caller
/// holding a `ResourceRef::file` for a row the database calls a `FOLDER` — which is exactly what a
/// search hit looks like before anything has read the row — must still find its chain. The true
/// kinds are preserved inside the chain's nodes, which is where they matter: that is what ACL
/// entries are matched against.
///
/// Keyed by `(family, id)` rather than by id alone so that a library and a file that somehow shared
/// a UUID could not read each other's chain. That should be impossible; not depending on it being
/// impossible costs nothing.
fn merge_chains(
    into: &mut HashMap<ChainNode, InheritanceChain>,
    family: AclResourceType,
    found: HashMap<Uuid, InheritanceChain>,
) {
    for (id, chain) in found {
        let _replaced = into.insert(ChainNode::new(family, id), chain);
    }
}

/// The map key a classified target's chain was filed under, or `None` for the targets that were
/// refused before any query ran.
fn chain_key(target: Target) -> Option<ChainNode> {
    match target {
        Target::FileTree(id) => Some(ChainNode::new(AclResourceType::File, id)),
        Target::Library(id) => Some(ChainNode::new(AclResourceType::Library, id)),
        Target::Workspace(id) => Some(ChainNode::new(AclResourceType::Workspace, id)),
        // A share link has no chain filed under its own id — it is walked as whatever it points at,
        // and [`resolve_share_targets`] has already rewritten the ones that resolve. Reaching here
        // as a `ShareLink` therefore means the link resolved to nothing.
        Target::ShareLink(_) | Target::ForeignTenant | Target::Unsupported => None,
    }
}

/// [`AuthorizationService`] backed by `acl_entries` in PostgreSQL.
///
/// Holds a pool because the trait hands it no connection: the policy chain is composed once at
/// start-up and called from handlers that have no transaction of their own yet. Every query still
/// runs inside a [`TenantScoped`] transaction opened here — the pool is passed to
/// [`TenantScoped::begin`] and never queried directly, which is the distinction the no-raw-pool
/// gate draws.
#[derive(Debug, Clone)]
pub struct PgAclAuthorization {
    pool: DbPool,
    resolver: AclResolver,
}

impl PgAclAuthorization {
    /// Builds the service over an existing pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool, resolver: AclResolver::new() }
    }

    /// Builds the service with explicit resolver limits.
    #[must_use]
    pub const fn with_limits(pool: DbPool, limits: ResolverLimits) -> Self {
        Self { pool, resolver: AclResolver::with_limits(limits) }
    }

    /// The resolver, for callers that already hold a transaction.
    #[must_use]
    pub const fn resolver(&self) -> &AclResolver {
        &self.resolver
    }

    /// Opens a tenant-scoped transaction and resolves the batch in it.
    async fn resolve(
        &self,
        ctx: &RequestContext,
        actions: &[Action],
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<Vec<StageDecision>>> {
        // The tenant comes from the verified request context and from nowhere else
        // (`CLAUDE.md` rule 3); `ResourceRef::tenant_id` is checked *against* it in `classify`,
        // never used in its place.
        let mut tx = TenantScoped::begin(&self.pool, ctx.tenant_id)
            .await
            .map_err(crate::error::AuthzError::from)?;
        let resolved = self
            .resolver
            .effective_actions_in_tx(
                &mut tx,
                ctx.tenant_id,
                &ctx.actor,
                actions,
                resources,
                Utc::now(),
            )
            .await;
        // Read-only, so the rollback a dropped handle performs would be equivalent; committing
        // explicitly keeps the connection's return to the pool on the success path rather than in
        // `Drop`, where a failure would be invisible.
        let committed = tx.commit().await;
        let resolved = resolved?;
        committed.map_err(crate::error::AuthzError::from)?;
        Ok(resolved
            .rows()
            .map(|row| row.iter().copied().map(Effective::into_stage_decision).collect())
            .collect())
    }

    /// One action's decisions, for the two trait methods that ask about exactly one.
    async fn resolve_one(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        let mut rows = self.resolve(ctx, core::slice::from_ref(&action), resources).await?;
        // One action in, one row out. Unreachable otherwise; the refusing answer is the safe one,
        // and `authorize`'s caller reads a missing verdict as a denial in any case.
        Ok(rows.pop().unwrap_or_default())
    }
}

#[async_trait]
impl AuthorizationService for PgAclAuthorization {
    /// Resolves several actions over a batch of resources in one tenant-scoped transaction.
    ///
    /// The result is one row per element of `actions`, each index-aligned with `resources` — the
    /// shape a capability probe wants, since it asks one action about a whole page at a time.
    ///
    /// This is an inherent method and not a trait one because
    /// [`enclave_core::AuthorizationService`] batches resources only. Widening the trait would
    /// oblige every implementation of it to answer a question most of them answer by looping
    /// anyway; a caller that can name this type gets the saving today, and the trait can grow a
    /// defaulted method when there is a second implementation that benefits.
    ///
    /// # Errors
    ///
    /// Resolution failures, which are never denials (`crate::error`).
    async fn authorize_many_actions(
        &self,
        ctx: &RequestContext,
        actions: &[Action],
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<Vec<StageDecision>>> {
        if resources.is_empty() {
            return Ok(actions.iter().map(|_| Vec::new()).collect());
        }
        self.resolve(ctx, actions, resources).await
    }

    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        // Deliberately the batch path with one element rather than a second implementation. Two
        // code paths for one question is how the singular form ends up enforcing something the
        // batch form does not — and it is the batch form that the search post-filter uses.
        let mut decisions = self.resolve_one(ctx, action, core::slice::from_ref(resource)).await?;
        match decisions.pop() {
            Some(decision) => Ok(decision),
            // Unreachable by construction: the resolver returns one verdict per input. If it ever
            // did not, the safe answer is the refusing one.
            None => Ok(StageDecision::deny(ReasonCode::AccessDenied)),
        }
    }

    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        if resources.is_empty() {
            return Ok(Vec::new());
        }
        self.resolve_one(ctx, action, resources).await
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileId, LibraryId, ShareLinkId, UserId, VersionId, WorkspaceId};

    use super::*;

    #[test]
    fn another_tenants_resource_is_refused_without_a_query() {
        // The batch path does not go through `PolicyEngine::enforce`, so this is the only tenant
        // check on it. `docs/12-TESTING.md` T1.
        let alpha = TenantId::new_v7();
        let beta = TenantId::new_v7();
        let file = FileId::new_v7();
        assert_eq!(classify(alpha, &ResourceRef::file(beta, file)), Target::ForeignTenant);
        assert_eq!(
            classify(alpha, &ResourceRef::file(alpha, file)),
            Target::FileTree(file.as_uuid())
        );
    }

    #[test]
    fn each_supported_kind_reaches_its_own_walk() {
        let tenant = TenantId::new_v7();
        let file = FileId::new_v7();
        assert_eq!(
            classify(tenant, &ResourceRef::folder(tenant, file)),
            Target::FileTree(file.as_uuid())
        );
        let library = LibraryId::new_v7();
        assert_eq!(
            classify(tenant, &ResourceRef::library(tenant, library)),
            Target::Library(library.as_uuid())
        );
        let workspace = WorkspaceId::new_v7();
        assert_eq!(
            classify(tenant, &ResourceRef::workspace(tenant, workspace)),
            Target::Workspace(workspace.as_uuid())
        );
    }

    #[test]
    fn kinds_with_no_inheritance_model_are_refused_rather_than_guessed_at() {
        let tenant = TenantId::new_v7();
        for resource in [
            ResourceRef::version(tenant, VersionId::new_v7()),
            ResourceRef::user(tenant, UserId::new_v7()),
            ResourceRef::tenant(tenant),
        ] {
            assert_eq!(classify(tenant, &resource), Target::Unsupported, "{resource}");
        }

        // **`ENC-879` moved `Share` off this list, and this assertion is the record of that.**
        //
        // The sweep used to include it, with a comment saying a share link was *the one unsupported
        // kind somebody has a live reason to want supported* and asking that the day the resolver
        // learned about shares, this test fail and point at the row. It did, and this is that day.
        // The entry is replaced rather than deleted, because an absence from a list is not something
        // a reader notices: a share reference now classifies to a target of its own and is resolved
        // by one extra hop — the link's own ACL is the ACL of what it exposes — and if that were
        // ever reverted, the sweep above would go quietly green again.
        let share = ResourceRef::share(tenant, ShareLinkId::new_v7());
        assert_ne!(classify(tenant, &share), Target::Unsupported, "{share}");
    }

    /// `ENC-879`. A share reference classifies, and the tenant check still comes first.
    #[test]
    fn a_share_reference_reaches_its_own_resolution_and_another_tenants_does_not() {
        let alpha = TenantId::new_v7();
        let beta = TenantId::new_v7();
        let link = ShareLinkId::new_v7();

        assert_eq!(
            classify(alpha, &ResourceRef::share(alpha, link)),
            Target::ShareLink(link.as_uuid())
        );
        // Layer 3 — the application check inside `classify` — refuses before any query, which is
        // the only layer that covers `authorize_many`'s direct callers. RLS is not what holds this.
        assert_eq!(classify(alpha, &ResourceRef::share(beta, link)), Target::ForeignTenant);
    }

    /// An unresolved share link has no chain to look up, so it refuses like every other miss.
    ///
    /// This is what makes "unknown, revoked, expired and another tenant's are one answer" true at
    /// the resolver rather than only in the SQL: even if `share_targets` returned nothing for a
    /// reason nobody anticipated, the target that survives is one `chain_key` refuses.
    #[test]
    fn an_unresolved_share_link_has_no_chain() {
        assert_eq!(chain_key(Target::ShareLink(Uuid::new_v4())), None);
    }

    #[test]
    fn a_reference_that_calls_a_folder_a_file_still_finds_its_chain() {
        // `ResourceRef::file` and `ResourceRef::folder` share the `FileId` space, and a caller — a
        // search hit especially — routinely holds one without having read the row to learn which it
        // is. If the lookup key came from the reference's kind rather than from the family, half of
        // those would silently resolve against an empty chain, which reads as a clean refusal.
        let tenant = TenantId::new_v7();
        let id = FileId::new_v7();
        assert_eq!(
            chain_key(classify(tenant, &ResourceRef::file(tenant, id))),
            chain_key(classify(tenant, &ResourceRef::folder(tenant, id)))
        );

        let mut into = HashMap::new();
        let chain = InheritanceChain::new(vec![
            ChainNode::new(AclResourceType::Folder, id.as_uuid()),
            ChainNode::new(AclResourceType::Library, Uuid::new_v4()),
        ]);
        merge_chains(&mut into, AclResourceType::File, HashMap::from([(id.as_uuid(), chain)]));
        let key = chain_key(classify(tenant, &ResourceRef::file(tenant, id))).expect("a key");
        // The chain is found, and the node inside it kept the kind the database reported — which is
        // what an ACL entry on the folder is matched against.
        assert_eq!(
            into.get(&key).map(|chain| chain.nodes()[0].kind),
            Some(AclResourceType::Folder)
        );
    }

    #[test]
    fn the_refused_targets_have_no_chain_to_look_up() {
        let tenant = TenantId::new_v7();
        assert_eq!(chain_key(Target::ForeignTenant), None);
        assert_eq!(chain_key(Target::Unsupported), None);
        assert!(chain_key(classify(
            tenant,
            &ResourceRef::workspace(tenant, WorkspaceId::new_v7())
        ))
        .is_some());
    }

    #[test]
    fn the_default_limits_are_the_documented_ones() {
        // `docs/04-DATA-MODEL.md §5` fixes the group default at 8. The inheritance cap is ours, and
        // is an error rather than a truncation when it is reached.
        let limits = ResolverLimits::default();
        assert_eq!(limits.max_group_depth, 8);
        assert_eq!(limits.max_inheritance_depth, 64);
        assert_eq!(AclResolver::new().limits(), limits);
    }
}
