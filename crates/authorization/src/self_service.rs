//! The pre-ACL placeholder, kept for the paths that have no database behind them yet.

use async_trait::async_trait;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, ReasonCode, RequestContext, ResourceKind,
    ResourceRef, Result, StageDecision,
};

/// Authorization before any ACL storage exists: a principal may read **itself** and end its own
/// sessions, and nothing else.
///
/// This is not a stub that returns allow. It is the smallest decision that is actually correct, and
/// it denies by default — the shape the real resolver keeps.
///
/// # The second rule, and the hazard in how it has to be spelled
///
/// `ENC-685` gave `/api/v1/auth/*` a surface, and `logout`, `logout-all` and
/// `DELETE /auth/sessions/{sid}` are authenticated mutations that must go through the chain
/// (`CLAUDE.md` rule 1) — so the chain has to have an answer for them. There is no
/// `ResourceKind::Session` and no session vocabulary in `Action`, and adding either means changing
/// `enclave_core::Action`, which deliberately breaks every exhaustive match in every policy
/// service. That is real work and it is `ENC-689`, not a line to slip into a route change.
///
/// So the pair asked is [`ContainerAction::Delete`] against the caller's **own** `User` resource,
/// and the hazard is that it reads as *"delete my account"*. It is not, and nothing may treat it as
/// though it were: **an account-deletion route must not reuse this pair.** When `ENC-689` gives
/// sessions their own kind, this rule moves to it and the hazard goes away. Until then the rule is
/// as narrow as it can be made — same tenant, same principal, one action — and
/// `a_principal_may_not_delete_another_principal` is the test that keeps it there.
///
/// [`crate::PgAclAuthorization`] supersedes it: that one resolves `acl_entries` with inheritance,
/// group closure and deny-wins (`docs/04-DATA-MODEL.md §9`). This remains only because
/// `GET /api/v1/me` reads the caller's own user record, which has no ACL rows and is not part of
/// the file inheritance tree — so the real resolver correctly refuses it. Retiring this type means
/// deciding how a principal is authorized to read itself, which is an identity question rather than
/// an ACL one, and is not this task's to answer.
///
/// Deliberately *not* named `AllowSelf`. Every rule it enforces is a denial except one.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfServiceAuthorization;

impl SelfServiceAuthorization {
    /// Whether this is a principal acting on its **own** user record, and in one of the two ways
    /// that are permitted.
    pub(crate) fn is_permitted_self_action(
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> bool {
        let permitted = matches!(
            action,
            Action::Container(ContainerAction::Read) | Action::Container(ContainerAction::Delete)
        );
        let own_user = resource.kind == ResourceKind::User
            && resource.tenant_id == ctx.tenant_id
            && ctx.actor.subject_id().is_some_and(|id| id == resource.id);
        permitted && own_user
    }
}

#[async_trait]
impl AuthorizationService for SelfServiceAuthorization {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision> {
        if Self::is_permitted_self_action(ctx, action, resource) {
            Ok(StageDecision::allow())
        } else {
            Ok(StageDecision::deny(ReasonCode::AccessDenied))
        }
    }

    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> Result<Vec<StageDecision>> {
        Ok(resources
            .iter()
            .map(|resource| {
                if Self::is_permitted_self_action(ctx, action, resource) {
                    StageDecision::allow()
                } else {
                    StageDecision::deny(ReasonCode::AccessDenied)
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileAction, TenantId, UserId};

    use super::*;

    fn ctx_for(tenant: TenantId, user: UserId) -> RequestContext {
        let mut ctx = RequestContext::system(tenant);
        ctx.actor = enclave_core::Actor::User(user);
        ctx
    }

    #[tokio::test]
    async fn a_user_may_read_its_own_record() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();
        let decision = SelfServiceAuthorization
            .authorize(
                &ctx_for(tenant, user),
                Action::Container(ContainerAction::Read),
                &ResourceRef::user(tenant, user),
            )
            .await
            .expect("evaluate");
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn a_user_may_not_read_another_users_record() {
        let tenant = TenantId::new_v7();
        let decision = SelfServiceAuthorization
            .authorize(
                &ctx_for(tenant, UserId::new_v7()),
                Action::Container(ContainerAction::Read),
                &ResourceRef::user(tenant, UserId::new_v7()),
            )
            .await
            .expect("evaluate");
        assert!(!decision.is_allowed(), "self-read must not generalise to any user");
    }

    #[tokio::test]
    async fn everything_that_is_not_a_self_read_is_denied() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();
        let ctx = ctx_for(tenant, user);

        // Same resource, a mutating action.
        let update = SelfServiceAuthorization
            .authorize(
                &ctx,
                Action::Container(ContainerAction::Update),
                &ResourceRef::user(tenant, user),
            )
            .await
            .expect("evaluate");
        assert!(!update.is_allowed(), "reading yourself does not imply writing yourself");

        // A file, which this resolver knows nothing about — those go to `PgAclAuthorization`.
        let file = SelfServiceAuthorization
            .authorize(
                &ctx,
                Action::File(FileAction::MetadataRead),
                &ResourceRef::new(tenant, ResourceKind::File, uuid::Uuid::nil()),
            )
            .await
            .expect("evaluate");
        assert!(!file.is_allowed(), "content is never readable through the self-read path");
    }

    /// The rule `ENC-685` needs: `logout`, `logout-all` and `DELETE /auth/sessions/{sid}` ask this
    /// pair, and if it is denied a signed-in user cannot sign out.
    #[tokio::test]
    async fn a_principal_may_end_its_own_sessions() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();
        let decision = SelfServiceAuthorization
            .authorize(
                &ctx_for(tenant, user),
                Action::Container(ContainerAction::Delete),
                &ResourceRef::user(tenant, user),
            )
            .await
            .expect("evaluate");
        assert!(decision.is_allowed());
    }

    /// The hazard the type's note names, held down by a test.
    ///
    /// Both halves are asserted, because "another principal is denied" holds for free against a
    /// resolver that denies everything (`docs/12-TESTING.md §1.2`): the positive control above is
    /// the same action allowed for the *same* principal, so this is proving the `is_some_and`
    /// comparison and not the absence of a rule.
    #[tokio::test]
    async fn a_principal_may_not_delete_another_principal() {
        let tenant = TenantId::new_v7();
        let caller = UserId::new_v7();
        let victim = UserId::new_v7();

        let decision = SelfServiceAuthorization
            .authorize(
                &ctx_for(tenant, caller),
                Action::Container(ContainerAction::Delete),
                &ResourceRef::user(tenant, victim),
            )
            .await
            .expect("evaluate");
        assert!(!decision.is_allowed(), "ending your own sessions must not generalise to anyone");
    }

    /// The same subject id in a different tenant is a different principal.
    ///
    /// Colliding fixture ids are deliberate in this project (`docs/12-TESTING.md §3`), so a check
    /// that compared only the subject would allow a cross-tenant hit whenever the ids matched.
    #[tokio::test]
    async fn a_matching_subject_in_another_tenant_is_not_the_caller() {
        let alpha = TenantId::new_v7();
        let beta = TenantId::new_v7();
        let user = UserId::new_v7();

        for action in
            [Action::Container(ContainerAction::Read), Action::Container(ContainerAction::Delete)]
        {
            let decision = SelfServiceAuthorization
                .authorize(&ctx_for(alpha, user), action, &ResourceRef::user(beta, user))
                .await
                .expect("evaluate");
            assert!(!decision.is_allowed(), "{action:?} crossed a tenant boundary");

            // The positive control: the same action on the same subject *in the caller's tenant*
            // is allowed, so the assertion above is about the tenant and not about the action.
            let control = SelfServiceAuthorization
                .authorize(&ctx_for(alpha, user), action, &ResourceRef::user(alpha, user))
                .await
                .expect("evaluate");
            assert!(control.is_allowed(), "{action:?} must be allowed inside the caller's tenant");
        }
    }

    /// `authorize_many` is the search post-filter's path and must not be a second opinion.
    #[tokio::test]
    async fn the_batch_form_answers_exactly_as_the_single_one_does() {
        let tenant = TenantId::new_v7();
        let caller = UserId::new_v7();
        let other = UserId::new_v7();
        let ctx = ctx_for(tenant, caller);
        let resources = [ResourceRef::user(tenant, caller), ResourceRef::user(tenant, other)];

        let decisions = SelfServiceAuthorization
            .authorize_many(&ctx, Action::Container(ContainerAction::Delete), &resources)
            .await
            .expect("evaluate");

        assert_eq!(decisions.len(), 2);
        assert!(decisions[0].is_allowed(), "the caller's own record");
        assert!(!decisions[1].is_allowed(), "somebody else's");
    }
}

/// Self-service first, then the inner service — `ENC-767`.
///
/// # Why a composition rather than a change to either service
///
/// [`SelfServiceAuthorization`] answers questions about a principal reading *itself*; it is the only
/// thing that can, because a user is not in the file tree. [`PgAclAuthorization`] answers questions
/// about content, and deliberately classifies a `User` resource as unsupported rather than guessing
/// at a permission model nobody specified.
///
/// Both are terminal — each denies what it does not recognise — so wiring either one alone leaves
/// half the product refused. With self-service alone every content route answers `403` for a caller
/// whose token is perfectly valid; with ACL alone `GET /api/v1/me` does. The binary shipped the
/// first of those, and it is worth naming what it looked like from outside: **authentication working
/// and authorization unwired are indistinguishable to a client.** A good token, a correct password,
/// a real session — and `403` on every request. That is not a subtle failure, but it is an invisible
/// one, because every individual component was behaving exactly as written.
///
/// The order matters and is not arbitrary: self-service is asked first because its domain is
/// *narrow and exact* — this principal, this action, itself — so a hit is unambiguous. Anything it
/// does not claim is content, which is the inner service's to decide. Reversing the order would let
/// an ACL miss on a `User` resource shadow the one service that can answer it.
#[derive(Debug)]
pub struct SelfServiceOr<I> {
    inner: I,
}

impl<I> SelfServiceOr<I> {
    /// Wraps `inner`, which decides everything self-service does not claim.
    pub const fn new(inner: I) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<I: AuthorizationService> AuthorizationService for SelfServiceOr<I> {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<StageDecision> {
        if SelfServiceAuthorization::is_permitted_self_action(ctx, action, resource) {
            return Ok(StageDecision::allow());
        }
        self.inner.authorize(ctx, action, resource).await
    }

    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> Result<Vec<StageDecision>> {
        // The batch goes to the inner service whole rather than element by element: the ACL resolver
        // exists to answer many resources in one walk (`ENC-145` measured its cost as ~80% fixed), so
        // splitting it would turn one query into N.
        let mut decided = self.inner.authorize_many(ctx, action, resources).await?;
        for (slot, resource) in decided.iter_mut().zip(resources) {
            if SelfServiceAuthorization::is_permitted_self_action(ctx, action, resource) {
                *slot = StageDecision::allow();
            }
        }
        Ok(decided)
    }
}
