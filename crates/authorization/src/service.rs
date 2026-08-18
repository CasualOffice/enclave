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
    AclResourceType, ChainNode, Effective, EffectiveIndex, InheritanceChain, PrincipalSet,
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
        // Versions, chunks, users, devices, shares, pages, lists and list items are all real
        // resources; none of them resolve through the file inheritance tree. Pages and lists do
        // carry `acl_entries` rows (`docs/04-DATA-MODEL.md §9`) but their containment is not
        // modelled yet, and a chain that guessed at it would be a permission model nobody
        // specified. Refused until each is designed.
        _ => Target::Unsupported,
    }
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
    /// `now` is taken as an argument rather than read from the clock so that every resource in one
    /// batch is judged against a single instant: with two hundred candidates and a `read` grant
    /// expiring mid-flight, a per-resource `Utc::now()` would let two hits of the same search
    /// disagree about whether the same entry had expired.
    ///
    /// # Errors
    ///
    /// Storage failures, unreadable rows, and a chain deeper than the configured limit. None of
    /// these is converted into a denial: an evaluation that could not happen is not an evaluation
    /// that said no (`crates/core/src/engine.rs`).
    pub async fn effective_in_tx(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        actor: &Actor,
        action: Action,
        resources: &[ResourceRef],
        now: DateTime<Utc>,
    ) -> Result<Vec<Effective>> {
        let targets: Vec<Target> = resources.iter().map(|r| classify(tenant, r)).collect();

        // An actor with no ACL principal cannot be named by any entry, so there is nothing to ask
        // the database. Returning before the queries is not just an optimisation: it is what stops
        // `EVERYONE` from being matched by a principal the ACL model has no way to talk about.
        let Some(principals) = PrincipalSet::for_actor(actor) else {
            return Ok(vec![Effective::NotGranted; resources.len()]);
        };

        let mut files = Vec::new();
        let mut libraries = Vec::new();
        let mut workspaces = Vec::new();
        for target in &targets {
            match *target {
                Target::FileTree(id) => files.push(id),
                Target::Library(id) => libraries.push(id),
                Target::Workspace(id) => workspaces.push(id),
                Target::ForeignTenant | Target::Unsupported => {}
            }
        }
        if files.is_empty() && libraries.is_empty() && workspaces.is_empty() {
            return Ok(vec![Effective::NotGranted; resources.len()]);
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
        let direct = principals.direct();
        let groups = repo::group_closure(conn, tenant, direct, self.limits.max_group_depth).await?;
        let principals = principals.with_groups(groups);

        // Query 3 — the entries on the union of every chain, once for the whole batch.
        let mut nodes: Vec<ChainNode> =
            chains.values().flat_map(|chain| chain.nodes().iter().copied()).collect();
        nodes.sort_unstable();
        nodes.dedup();
        let entries =
            repo::acl_entries(conn, tenant, &action.to_string(), &nodes, &principals, now).await?;

        let index = EffectiveIndex::build(&entries, &principals, now);
        let empty = InheritanceChain::default();
        // Index-aligned with `resources`: one verdict per input, duplicates and refusals included.
        Ok(targets
            .into_iter()
            .map(|target| match chain_key(target) {
                None => Effective::NotGranted,
                Some(key) => index.decide(chains.get(&key).unwrap_or(&empty)),
            })
            .collect())
    }
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
        Target::ForeignTenant | Target::Unsupported => None,
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
        action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        // The tenant comes from the verified request context and from nowhere else
        // (`CLAUDE.md` rule 3); `ResourceRef::tenant_id` is checked *against* it in `classify`,
        // never used in its place.
        let mut tx = TenantScoped::begin(&self.pool, ctx.tenant_id)
            .await
            .map_err(crate::error::AuthzError::from)?;
        let resolved = self
            .resolver
            .effective_in_tx(&mut tx, ctx.tenant_id, &ctx.actor, action, resources, Utc::now())
            .await;
        // Read-only, so the rollback a dropped handle performs would be equivalent; committing
        // explicitly keeps the connection's return to the pool on the success path rather than in
        // `Drop`, where a failure would be invisible.
        let committed = tx.commit().await;
        let resolved = resolved?;
        committed.map_err(crate::error::AuthzError::from)?;
        Ok(resolved.into_iter().map(Effective::into_stage_decision).collect())
    }
}

#[async_trait]
impl AuthorizationService for PgAclAuthorization {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        // Deliberately the batch path with one element rather than a second implementation. Two
        // code paths for one question is how the singular form ends up enforcing something the
        // batch form does not — and it is the batch form that the search post-filter uses.
        let mut decisions = self.resolve(ctx, action, core::slice::from_ref(resource)).await?;
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
        self.resolve(ctx, action, resources).await
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileId, LibraryId, UserId, VersionId, WorkspaceId};

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
