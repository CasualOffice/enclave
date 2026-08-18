//! The pre-ACL placeholder, kept for the paths that have no database behind them yet.

use async_trait::async_trait;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, ReasonCode, RequestContext, ResourceKind,
    ResourceRef, Result, StageDecision,
};

/// Authorization before any ACL storage exists: a principal may read **itself**, and nothing else.
///
/// This is not a stub that returns allow. It is the smallest decision that is actually correct, and
/// it denies by default — the shape the real resolver keeps.
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
    /// Whether this is a principal reading its own user record.
    fn is_self_read(ctx: &RequestContext, action: Action, resource: &ResourceRef) -> bool {
        let reading = matches!(action, Action::Container(ContainerAction::Read));
        let own_user = resource.kind == ResourceKind::User
            && ctx.actor.subject_id().is_some_and(|id| id == resource.id);
        reading && own_user
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
        if Self::is_self_read(ctx, action, resource) {
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
                if Self::is_self_read(ctx, action, resource) {
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
}
