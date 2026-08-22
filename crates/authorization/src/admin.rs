//! Who may perform an administrative action — `ENC-619`.
//!
//! The rest of this crate answers *may this principal do this to this file*, by resolving
//! `acl_entries` (`docs/04-DATA-MODEL.md §9`). An [`Action::Admin`] has no such answer: there is no
//! ACL row on a tenant, [`crate::service::classify`] correctly calls a tenant reference
//! `Unsupported`, and so every route under `/api/v1/admin/**` was refused at the authorization
//! stage in a running deployment, whoever the caller was. That failure was closed rather than open,
//! which is why `ENC-603` shipped the surface anyway; it was not usable.
//!
//! # The question is not "is this user an administrator"
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §22` separates *changing conditional access* from *changing
//! branding*, and `docs/01-PRD.md §4` gives those two sentences to different people — a Security
//! Administrator owns DLP, conditional access and barriers; a Tenant Administrator owns domains,
//! branding, storage and quotas. That is why `ENC-603` authorizes with
//! [`AdminAction::ManagePolicy`] and not [`AdminAction::WriteConfig`], and a resolver that answered
//! both from one boolean would hand the network-policy right to everyone who may edit a logo.
//!
//! So the decision here is not a predicate, it is a **set**: [`AdminGrants`] is the administrative
//! actions a principal holds, and the decision is membership. A grant source produces the set; the
//! service applies it. Adding the finer administrator roles is then a change to one implementation
//! of [`AdminRoles`] and to nothing else, because no caller of this module can ask the boolean
//! question.
//!
//! # What a deployment can actually grant today, and why that is one role rather than five
//!
//! [`PgAdminRoles`] reads `users.is_admin`, which is the only administrative grant this schema has
//! (`migrations/0001_foundations.sql`; `docs/04 §5`). It is the tenant's **global administrator** —
//! `docs/06 §22` lists *modifying global admin membership* as itself a privileged operation — and a
//! global administrator holds every [`AdminAction`]. That is not the collapse the paragraph above
//! warns against: the collapse would be answering `ManagePolicy` by asking whether the caller may
//! write *config*, or granting the policy right to a narrower role that should not have it. There
//! is no narrower role yet. `docs/04 §9` specifies `role_definitions` (with `permissions` as an
//! array of action strings) and names `role_assignments` in its `§2` inventory, and
//! `role_assignments` has no DDL — `migrations/0004` says so in as many words. Until it does, a
//! deployment has exactly one administrative role and this module says so out loud rather than
//! implying five.
//!
//! The consequence worth knowing: the seeded `auditor` fixture is not an administrator, so
//! [`AdminAction::ReadAudit`] is held only by the global administrator. An auditor who may read the
//! log and change nothing is `docs/01 §4`'s persona and needs the assignment table.
//!
//! # Three refusals that are structural rather than configured
//!
//! 1. **An `Action::Admin` never reaches the inner service.** It is decided here or refused here,
//!    and the delegation below is only for the actions this module has no opinion about.
//!    `acl_entries.action` is a free-text column (`docs/04 §9`), so a tenant that could reach ACL
//!    resolution with an administrative action would be one grant of `manage_permissions` away from
//!    a workspace owner writing themselves the right to change the tenant's DLP rules.
//! 2. **Only a `User` can hold an administrative grant.** `is_admin` is a column on `users`; a
//!    service account, an MCP client, a guest and `System` have no row there, and the answer for a
//!    principal the grant model cannot name is no.
//! 3. **The resource must be this tenant, and must be the tenant.** The engine compares the two
//!    already (`docs/03-LLD.md §12`), and [`AuthorizationService::authorize_many`] is called by the
//!    search post-filter without passing through it — the same argument [`crate::service::classify`]
//!    makes for checking there too.
//!
//! # What is deliberately not read
//!
//! **The token's scopes.** `ScopeSet` narrows what a caller may do and never widens it
//! (`crates/core/src/context.rs`), so an admin scope would be a second gate rather than a second
//! grant — the right shape, and one this deployment cannot express: no scope vocabulary for the
//! administrative actions exists, `SubjectFacts` resolves scopes from a provider that mints none of
//! them, and requiring a scope nothing issues would close the surface again for a different reason.
//! `ENC-652` is the row.
//!
//! **A cache.** One statement per administrative request, and administrative requests are rare. An
//! administrator demoted mid-session is refused on their next request rather than at the end of a
//! TTL, which is the property worth having on the surface that can rewrite a tenant's access rules.

use async_trait::async_trait;
use enclave_core::{
    Action, Actor, AdminAction, AuthorizationService, ReasonCode, RequestContext, ResourceKind,
    ResourceRef, Result as CoreResult, StageDecision, TenantId, UserId,
};
use enclave_db::{DbPool, TenantScoped};
use sqlx::Row as _;

use crate::error::{AuthzError, Result};

/// The administrative actions a principal holds.
///
/// A set rather than a flag, because the whole risk this type exists to manage is two rights being
/// answered by one question — see the module header. Stored as a bitmask over the five variants of
/// [`AdminAction`]: the set is small, closed, and `Copy`, so a decision can be taken without an
/// allocation on a path that runs inside the policy chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdminGrants(u8);

impl AdminGrants {
    /// The bit an action occupies.
    ///
    /// An exhaustive `match` rather than a `#[repr]` discriminant, so that adding a variant to
    /// [`AdminAction`] fails to compile here — the same argument `docs/03-LLD.md §6` makes for the
    /// action enums not being `#[non_exhaustive]`. A new administrative right must be *granted* to
    /// somebody deliberately, and the compiler is what asks.
    const fn bit(action: AdminAction) -> u8 {
        match action {
            AdminAction::ReadConfig => 1 << 0,
            AdminAction::WriteConfig => 1 << 1,
            AdminAction::ReadAudit => 1 << 2,
            AdminAction::ManageIdentity => 1 << 3,
            AdminAction::ManagePolicy => 1 << 4,
        }
    }

    /// Holds nothing. The answer for every principal a grant source cannot name.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Every administrative action — the tenant's global administrator (`users.is_admin`).
    ///
    /// Built by folding [`AdminAction::all`] rather than written as a literal, so that a variant
    /// added to the enum is included here without anyone remembering to widen a constant. That is
    /// the safe direction *for this role only*: a global administrator is defined as the principal
    /// who holds everything, and it is the role that grants the others.
    #[must_use]
    pub fn global() -> Self {
        AdminAction::all().iter().copied().collect()
    }

    /// Whether this set holds one action.
    #[must_use]
    pub const fn holds(self, action: AdminAction) -> bool {
        self.0 & Self::bit(action) != 0
    }

    /// Whether this set holds nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The same set, with one more action.
    #[must_use]
    pub const fn with(self, action: AdminAction) -> Self {
        Self(self.0 | Self::bit(action))
    }

    /// The actions held, for a log line or an admin surface that shows a principal their rights.
    pub fn iter(self) -> impl Iterator<Item = AdminAction> {
        AdminAction::all().iter().copied().filter(move |action| self.holds(*action))
    }
}

impl FromIterator<AdminAction> for AdminGrants {
    fn from_iter<I: IntoIterator<Item = AdminAction>>(actions: I) -> Self {
        actions.into_iter().fold(Self::none(), Self::with)
    }
}

/// Where a principal's administrative grants come from.
///
/// A trait so that the *decision* — everything in [`AdminAuthorization`] — can be tested without a
/// database, and so that the arrival of `role_assignments` changes one implementation rather than
/// the service. It answers for a principal and a tenant, never for a resource: an administrative
/// right is held over the tenant, and a grant that varied by object would be an oracle for the
/// object.
#[async_trait]
pub trait AdminRoles: Send + Sync + std::fmt::Debug {
    /// What this principal may administer in this tenant.
    ///
    /// # Errors
    ///
    /// Read failures. **A failure is never [`AdminGrants::none`]**: an empty set is a refusal, and a
    /// refusal the caller cannot distinguish from a database outage is one nobody can diagnose —
    /// the same argument `crates/dlp/src/tenant.rs` makes for a rule load. The engine turns the
    /// error into a `500`, and the request does not proceed.
    async fn grants_for(&self, tenant: TenantId, actor: &Actor) -> CoreResult<AdminGrants>;
}

/// Grants read from `users.is_admin`.
///
/// The only administrative grant this schema holds; see the module header for what it means and
/// what it cannot yet express.
#[derive(Debug, Clone)]
pub struct PgAdminRoles {
    pool: DbPool,
}

/// Reads the flag for one user of one tenant.
///
/// `status` and `deleted_at` are in the predicate rather than checked afterwards, and they are not
/// tidiness: a deprovisioned administrator whose token has not yet expired is exactly the principal
/// a revocation is supposed to have stopped, and `SUSPENDED` is the state an incident response puts
/// an account into. The `tenant_id = $1` predicate is layer 1 of `docs/04 §3` beside row-level
/// security, as everywhere else in this crate.
const GRANTS_SQL: &str = "
SELECT is_admin
  FROM users
 WHERE tenant_id = $1
   AND id = $2
   AND status = 'ACTIVE'
   AND deleted_at IS NULL
";

impl PgAdminRoles {
    /// Builds the reader over an existing pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Reads one user's grants inside a tenant-scoped transaction.
    async fn read(&self, tenant: TenantId, user: UserId) -> Result<AdminGrants> {
        let mut tx = TenantScoped::begin(&self.pool, tenant).await?;
        let row = sqlx::query(GRANTS_SQL)
            .bind(tenant.as_uuid())
            .bind(user.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(AuthzError::Storage)?;
        tx.commit().await?;

        // No row is no grant: the user is another tenant's, deprovisioned, suspended or gone. All
        // four are the same answer, for `CLAUDE.md` rule 7's reason one layer down — a caller must
        // not be able to tell which.
        let Some(row) = row else { return Ok(AdminGrants::none()) };
        let is_admin: bool = row.try_get("is_admin").map_err(AuthzError::Storage)?;
        Ok(if is_admin { AdminGrants::global() } else { AdminGrants::none() })
    }
}

#[async_trait]
impl AdminRoles for PgAdminRoles {
    async fn grants_for(&self, tenant: TenantId, actor: &Actor) -> CoreResult<AdminGrants> {
        // Only a directory member can hold one: `is_admin` is a column on `users`, and there is no
        // row a service account, an MCP client, a guest or `System` could be found in. Returning
        // before the query is what makes that a property of the model rather than of a join that
        // happens not to match.
        let Actor::User(user) = actor else { return Ok(AdminGrants::none()) };
        Ok(self.read(tenant, *user).await?)
    }
}

/// The authorization stage, able to answer an administrative question.
///
/// Composition rather than replacement: it decides [`Action::Admin`] itself and delegates every
/// other action to the service it wraps — [`crate::SelfServiceAuthorization`] today, and
/// [`crate::PgAclAuthorization`] when `ENC-126` wires ACL resolution into the binary. Wrapping
/// keeps the two questions in the two places that can answer them, and means the change that brings
/// real content authorization does not have to re-decide what an administrator is.
#[derive(Debug)]
pub struct AdminAuthorization {
    roles: std::sync::Arc<dyn AdminRoles>,
    inner: std::sync::Arc<dyn AuthorizationService>,
}

impl AdminAuthorization {
    /// Composes a grant source with the service that answers everything else.
    #[must_use]
    pub const fn new(
        roles: std::sync::Arc<dyn AdminRoles>,
        inner: std::sync::Arc<dyn AuthorizationService>,
    ) -> Self {
        Self { roles, inner }
    }

    /// Decides one administrative action.
    ///
    /// The two checks before the grant lookup are both refusals of a *malformed question*, and both
    /// are made before anything is read: an administrative action is performed on the tenant, so a
    /// reference to another tenant or to any other kind of resource is not a question this stage
    /// has an answer to. Refusing it silently as "not granted" would be the same outcome by
    /// accident.
    async fn decide(
        &self,
        ctx: &RequestContext,
        action: AdminAction,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        if !targets_own_tenant(ctx.tenant_id, resource) {
            return Ok(StageDecision::deny(ReasonCode::AccessDenied));
        }
        let grants = self.roles.grants_for(ctx.tenant_id, &ctx.actor).await?;
        Ok(if grants.holds(action) {
            StageDecision::allow()
        } else {
            StageDecision::deny(ReasonCode::AccessDenied)
        })
    }
}

/// Whether the reference is this tenant's own tenant record.
///
/// Both halves matter. The tenant comparison is the one [`crate::service::classify`] makes and for
/// the same reason — `authorize_many` is reachable without the engine. The kind comparison is what
/// stops an administrative action being asked about a *file*: `ResourceRef::tenant` is the only
/// reference this stage decides over, so `admin.manage_policy` on a document is a question with no
/// answer rather than a question this stage answers permissively.
fn targets_own_tenant(tenant: TenantId, resource: &ResourceRef) -> bool {
    resource.tenant_id == tenant
        && resource.kind == ResourceKind::Tenant
        && resource.id == tenant.as_uuid()
}

#[async_trait]
impl AuthorizationService for AdminAuthorization {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        match action {
            Action::Admin(admin) => self.decide(ctx, admin, resource).await,
            other => self.inner.authorize(ctx, other, resource).await,
        }
    }

    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        let Action::Admin(admin) = action else {
            return self.inner.authorize_many(ctx, action, resources).await;
        };
        // One grant lookup for the batch, one check per resource: the grant is held over the
        // tenant, and what varies between elements is only whether each reference is the tenant.
        let grants = self.roles.grants_for(ctx.tenant_id, &ctx.actor).await?;
        Ok(resources
            .iter()
            .map(|resource| {
                if grants.holds(admin) && targets_own_tenant(ctx.tenant_id, resource) {
                    StageDecision::allow()
                } else {
                    StageDecision::deny(ReasonCode::AccessDenied)
                }
            })
            .collect())
    }

    /// Splits the batch and hands the inner service **its** actions in one call.
    ///
    /// The default body would loop [`Self::authorize_many`], which delegates one action at a time —
    /// and that would silently undo `ENC-167`'s measurement for the caller that needs it most: a
    /// listing page asks ten capability questions about one page of rows, and
    /// [`crate::PgAclAuthorization`] answers all ten in three round trips. A wrapper is exactly
    /// where a batching optimisation disappears without anyone editing the thing that measured it.
    async fn authorize_many_actions(
        &self,
        ctx: &RequestContext,
        actions: &[Action],
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<Vec<StageDecision>>> {
        let delegated: Vec<Action> =
            actions.iter().copied().filter(|action| !matches!(action, Action::Admin(_))).collect();

        // Only asked when something is delegated: an all-administrative batch must not open a
        // transaction in the inner service for a slice it has nothing to say about.
        let inner = if delegated.is_empty() {
            Vec::new()
        } else {
            self.inner.authorize_many_actions(ctx, &delegated, resources).await?
        };
        let mut inner = inner.into_iter();

        let mut rows = Vec::with_capacity(actions.len());
        for action in actions {
            match action {
                Action::Admin(_) => rows.push(self.authorize_many(ctx, *action, resources).await?),
                _ => rows.push(inner.next().unwrap_or_else(|| {
                    // Unreachable: one row per delegated action, in order. If an implementation
                    // ever returned fewer, the refusing answer is the safe one and it is still the
                    // right length.
                    vec![StageDecision::deny(ReasonCode::AccessDenied); resources.len()]
                })),
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ContainerAction, FileAction, FileId, ServiceAccountId};

    use super::*;

    /// A grant source that answers from a fixed set, for the decisions that are not about reading.
    #[derive(Debug)]
    struct Fixed(AdminGrants);

    #[async_trait]
    impl AdminRoles for Fixed {
        async fn grants_for(&self, _tenant: TenantId, actor: &Actor) -> CoreResult<AdminGrants> {
            // The same restriction `PgAdminRoles` gets from the schema, so a test of the service
            // is not accidentally a test of a source that grants machines.
            Ok(if matches!(actor, Actor::User(_)) { self.0 } else { AdminGrants::none() })
        }
    }

    /// An inner service that allows **everything**.
    ///
    /// The point of the double: if an administrative action could reach the inner service, this one
    /// would grant it. A permissive inner is what makes "the admin action never gets there" an
    /// assertion with a failure mode rather than a restatement of the deny-by-default default.
    #[derive(Debug)]
    struct AllowsEverything;

    #[async_trait]
    impl AuthorizationService for AllowsEverything {
        async fn authorize(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> CoreResult<StageDecision> {
            Ok(StageDecision::allow())
        }

        async fn authorize_many(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            resources: &[ResourceRef],
        ) -> CoreResult<Vec<StageDecision>> {
            Ok(resources.iter().map(|_| StageDecision::allow()).collect())
        }
    }

    fn service(grants: AdminGrants) -> AdminAuthorization {
        AdminAuthorization::new(
            std::sync::Arc::new(Fixed(grants)),
            std::sync::Arc::new(AllowsEverything),
        )
    }

    fn person(tenant: TenantId) -> RequestContext {
        let mut ctx = RequestContext::system(tenant);
        ctx.actor = Actor::User(UserId::new_v7());
        ctx
    }

    #[tokio::test]
    async fn a_global_administrator_holds_every_administrative_action() {
        let tenant = TenantId::new_v7();
        let ctx = person(tenant);
        let service = service(AdminGrants::global());
        for action in AdminAction::all() {
            let decision = service
                .authorize(&ctx, Action::Admin(*action), &ResourceRef::tenant(tenant))
                .await
                .expect("decide");
            assert!(decision.is_allowed(), "a global administrator holds {action}");
        }
    }

    /// The set is a set: holding one administrative right is not holding the next one.
    ///
    /// This is the shape `ENC-619`'s row asks for — *a resolver that collapsed the two would grant
    /// the network-policy right to everyone who may edit a logo* — asserted against the type that
    /// carries the answer, because no source produces a partial set yet.
    #[tokio::test]
    async fn one_administrative_right_is_not_another() {
        let tenant = TenantId::new_v7();
        let ctx = person(tenant);
        let branding = service(AdminGrants::none().with(AdminAction::WriteConfig));

        let writes_config = branding
            .authorize(&ctx, Action::Admin(AdminAction::WriteConfig), &ResourceRef::tenant(tenant))
            .await
            .expect("decide");
        assert!(writes_config.is_allowed(), "the control: the right that was granted");

        let manages_policy = branding
            .authorize(&ctx, Action::Admin(AdminAction::ManagePolicy), &ResourceRef::tenant(tenant))
            .await
            .expect("decide");
        assert!(
            !manages_policy.is_allowed(),
            "editing a logo must not carry the right to decide which networks reach the tenant"
        );
    }

    /// An administrative action is decided here and never delegated.
    ///
    /// The inner service allows everything, so a delegation would be visible as an allow. The
    /// control is in the same test: a *file* action reaches the inner service and is allowed, which
    /// is what stops this passing against a wrapper that refuses everything.
    #[tokio::test]
    async fn an_administrative_action_never_reaches_the_inner_service() {
        let tenant = TenantId::new_v7();
        let ctx = person(tenant);
        let service = service(AdminGrants::none());

        let admin = service
            .authorize(&ctx, Action::Admin(AdminAction::ManagePolicy), &ResourceRef::tenant(tenant))
            .await
            .expect("decide");
        assert!(
            !admin.is_allowed(),
            "an ACL entry naming an admin action must not be able to grant one: acl_entries.action \
             is free text (docs/04 §9)"
        );

        let file = service
            .authorize(
                &ctx,
                Action::File(FileAction::Download),
                &ResourceRef::file(tenant, FileId::new_v7()),
            )
            .await
            .expect("decide");
        assert!(file.is_allowed(), "the control: everything else is the inner service's to answer");
    }

    /// Only a person holds an administrative grant.
    #[tokio::test]
    async fn a_machine_principal_is_never_an_administrator() {
        let tenant = TenantId::new_v7();
        let service = service(AdminGrants::global());

        let mut machine = person(tenant);
        machine.actor = Actor::ServiceAccount(ServiceAccountId::new_v7());
        let decision = service
            .authorize(
                &machine,
                Action::Admin(AdminAction::ManagePolicy),
                &ResourceRef::tenant(tenant),
            )
            .await
            .expect("decide");
        assert!(!decision.is_allowed());

        let mut system = person(tenant);
        system.actor = Actor::System;
        assert!(!allowed_for(&service, &system, tenant).await);

        // The control: the same grant source, the same action, a user.
        assert!(allowed_for(&service, &person(tenant), tenant).await);
    }

    async fn allowed_for(
        service: &AdminAuthorization,
        ctx: &RequestContext,
        tenant: TenantId,
    ) -> bool {
        service
            .authorize(ctx, Action::Admin(AdminAction::ReadConfig), &ResourceRef::tenant(tenant))
            .await
            .expect("decide")
            .is_allowed()
    }

    /// An administrative grant is held over the tenant, and over nothing else.
    #[tokio::test]
    async fn an_administrative_action_is_refused_against_any_other_reference() {
        let tenant = TenantId::new_v7();
        let other = TenantId::new_v7();
        let ctx = person(tenant);
        let service = service(AdminGrants::global());

        for resource in [
            ResourceRef::tenant(other),
            ResourceRef::file(tenant, FileId::new_v7()),
            ResourceRef::new(tenant, ResourceKind::Tenant, uuid::Uuid::new_v4()),
        ] {
            let decision = service
                .authorize(&ctx, Action::Admin(AdminAction::ReadConfig), &resource)
                .await
                .expect("decide");
            assert!(!decision.is_allowed(), "{resource} is not this tenant's tenant record");
        }

        // The control: the reference that *is*.
        assert!(allowed_for(&service, &ctx, tenant).await);
    }

    /// The batch path applies the same rules, including the one the engine would have applied.
    #[tokio::test]
    async fn the_batch_path_refuses_a_foreign_tenants_reference_too() {
        let tenant = TenantId::new_v7();
        let other = TenantId::new_v7();
        let ctx = person(tenant);
        let service = service(AdminGrants::global());

        let decisions = service
            .authorize_many(
                &ctx,
                Action::Admin(AdminAction::ReadConfig),
                &[ResourceRef::tenant(tenant), ResourceRef::tenant(other)],
            )
            .await
            .expect("decide");
        assert_eq!(decisions.len(), 2);
        assert!(decisions[0].is_allowed(), "the control: this tenant's own record");
        assert!(!decisions[1].is_allowed());
    }

    /// Several actions in one pass keep their own answers, and stay index-aligned.
    ///
    /// The interleaving is the risk: the delegated rows are produced in one call and spliced back
    /// in, so an off-by-one would hand one action's verdict to another — which for a mixed batch
    /// means handing a file's `ALLOW` to `admin.manage_policy`.
    #[tokio::test]
    async fn a_mixed_batch_keeps_each_actions_answer_in_its_own_row() {
        let tenant = TenantId::new_v7();
        let ctx = person(tenant);
        let service = service(AdminGrants::none());
        let resources = [ResourceRef::tenant(tenant)];

        let rows = service
            .authorize_many_actions(
                &ctx,
                &[
                    Action::Container(ContainerAction::Read),
                    Action::Admin(AdminAction::ManagePolicy),
                    Action::File(FileAction::Download),
                ],
                &resources,
            )
            .await
            .expect("decide");

        assert_eq!(rows.len(), 3);
        assert!(rows[0][0].is_allowed(), "delegated");
        assert!(!rows[1][0].is_allowed(), "administrative, and not granted");
        assert!(rows[2][0].is_allowed(), "delegated, after the administrative one");
    }

    #[test]
    fn the_grant_set_holds_exactly_what_was_put_in_it() {
        let grants: AdminGrants =
            [AdminAction::ReadAudit, AdminAction::ReadConfig].into_iter().collect();
        assert!(grants.holds(AdminAction::ReadAudit));
        assert!(grants.holds(AdminAction::ReadConfig));
        assert!(!grants.holds(AdminAction::ManagePolicy));
        assert_eq!(grants.iter().count(), 2);
        assert!(AdminGrants::none().is_empty());
        assert!(!AdminGrants::global().is_empty());
        assert_eq!(AdminGrants::global().iter().count(), AdminAction::all().len());
    }
}
