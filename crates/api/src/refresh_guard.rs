//! The [`RefreshGuard`] that makes `docs/03-LLD.md §5.3` rule 3 true — `ENC-709`.
//!
//! # The defect
//!
//! Conditional access is the chain's second stage and it ran on every request *except* the one that
//! decides whether a session continues. `crates/api/src/main.rs` wired
//! [`enclave_auth::UnrestrictedRefreshGuard`], which permits every refresh, and said so at `warn`
//! on every start:
//!
//! > `refresh_guard (every refresh is permitted — a session outlives the network rule that allowed
//! > it, up to the refresh lifetime)`
//!
//! So a user signed in from a permitted network, an administrator tightened the tenant's rules —
//! or the user moved to a blocked network — and the session kept renewing. Rule 3 bounds that at
//! one access-token lifetime, ten minutes. What was actually running bounded it at the refresh
//! lifetime: fourteen days.
//!
//! # It is the same evaluator, deliberately
//!
//! [`ChainRefreshGuard`] holds the [`PolicyEngine`] the rest of the surface holds — the same
//! `Arc`s, so the same `TenantConditionalAccess`, the same per-tenant rule cache and the same zone
//! map. A second evaluator constructed beside it would be a second reading of one rule set, and two
//! readings of one rule drift. Nothing here interprets a rule; this module's whole job is to build
//! an honest [`RequestContext`] for a request that carries no bearer token, and to hand it over.
//!
//! # Where the client address comes from
//!
//! `CLAUDE.md` rule 3. The [`NetworkContext`] is the one `crates/api/src/routes/auth.rs`'s
//! `RefreshParts` extractor already took from [`crate::Edge`], which reads the socket peer and
//! believes `X-Forwarded-For` only from a `server.trusted_proxies` address, hop by hop. With that
//! key empty — the default, and warned about at start-up — the peer *is* the client address and the
//! header is not read at all. Neither configuration lets a caller name its own origin, and nothing
//! in this module can reach a header.
//!
//! # Fail-closed, and it is the answer the stage already gives
//!
//! If the rules cannot be read — PostgreSQL down, a stored rule that will not decode — the refresh
//! **fails**. It is not permitted, and it is not reported as a policy denial either: the caller gets
//! `503 DEPENDENCY_UNAVAILABLE` and may retry, which is the honest statement that nothing was
//! decided.
//!
//! That posture is not invented here. `TenantConditionalAccess::policies_for` already propagates
//! rather than substituting an empty rule set, for the reason its module header gives — *"falling
//! back to no rules on a database blip would turn an outage into an open door, silently, at exactly
//! the moment nobody is reading logs"*. It is the direction DLP's `facts_unavailable: FAIL_CLOSED`
//! default takes for the same question, and the direction `AuthError::RevocationUnavailable` takes
//! for K9. Choosing the other one here would be strictly worse than choosing it anywhere else,
//! because what is handed out on a refresh is not one response — it is another full refresh
//! lifetime of session.
//!
//! What it costs is bounded and worth stating plainly: while the rule store is unreachable nobody's
//! session can be renewed, and every access token minted before the outage keeps working until it
//! expires. That bound is the ten-minute access-token TTL, which is the same bound rule 3 promises.
//!
//! # What the cache TTL means for a tightening
//!
//! `TenantConditionalAccess` caches a tenant's rules for `DEFAULT_CACHE_TTL` — fifteen seconds —
//! and its documentation is explicit that this is the window in which a tightened rule may still be
//! evaluated in its old form, on every replica. That window applies here unchanged: an
//! administrator who tightens a rule and immediately watches a refresh may see one more rotation
//! succeed. Fifteen seconds against the fourteen days this closes; it is the number an
//! administrator is already quoted for every other stage; and a refresh answering from a *second*
//! cache would be exactly the drift this module exists to avoid.

use enclave_auth::{Acr, AuthError, RefreshGuard, RefreshRecord, SessionFacts, StoreUnavailable};
use enclave_core::{
    Action, AuthStrength, ContainerAction, Dependency, DeviceContext, DevicePosture, Error,
    NetworkContext, PolicyEngine, ReasonCode, RequestContext, RequestId, ResourceKind, ResourceRef,
};

/// The action a refresh asks conditional access about.
///
/// `container.read` against the caller's own `User` resource, which is
/// `crates/api/src/routes/auth.rs`'s existing spelling for *"something about my own principal"* and
/// is chosen for that module's stated reason: `enclave_core` has no `ResourceKind::Session` and no
/// session verb in [`Action`], and adding one breaks every exhaustive match in every policy service
/// by design. `ENC-689` is that work. `ENC-709` was recorded as blocked on it and is not, because
/// the question this stage is being asked needs no session vocabulary — it is *"may this principal
/// be reached from here at all"*, and the resource is deliberately not an input to conditional
/// access (`crates/conditional_access/src/lib.rs` says why at length).
///
/// The choice is also the conservative one in the direction that matters. `container.read` is none
/// of the byte-serving actions `PreviewOnly`, `NoDownload` and `NoSync` refuse
/// (`crates/conditional_access/src/rules.rs`), so those effects cannot turn a preview-only user
/// into one who cannot stay signed in. What can still refuse is `Block`, `RequireTrustedNetwork`,
/// `RequireManagedDevice` and `RequireMfa` — precisely the set rule 3 is about.
const CONTINUE_OWN_SESSION: Action = Action::Container(ContainerAction::Read);

/// Re-evaluates conditional access on every refresh, through the deployment's policy engine.
#[derive(Debug, Clone)]
pub struct ChainRefreshGuard {
    policy: PolicyEngine,
}

impl ChainRefreshGuard {
    /// Wraps the engine the rest of the surface enforces through.
    ///
    /// Takes it by value and keeps it: [`PolicyEngine`] is a handle over `Arc`s, so this shares the
    /// stage and its rule cache rather than duplicating either.
    #[must_use]
    pub const fn new(policy: PolicyEngine) -> Self {
        Self { policy }
    }
}

/// The context the stage decides against, built from what the server knows and nothing else.
///
/// Every field is the stored refresh row's, the freshly re-resolved [`SessionFacts`]', or the
/// connection's. None of it is asserted by the caller — a refresh request carries a cookie and a
/// CSRF header and no claims at all — which makes this the *most* trustworthy context in the
/// surface rather than the least.
///
/// Two fields deserve their own note:
///
/// * **`auth_strength`** is derived from the methods the session actually authenticated with, by
///   the same [`Acr::from_methods`] the access-token issuer uses, so a `RequireMfa` rule sees at
///   refresh the strength it sees on every other request of that session. Deriving it is also what
///   lets the break-glass exemption apply here at all: the exemption requires multi-factor *and*
///   the scope, so a guard reporting `Unauthenticated` with no scopes would lock the emergency
///   administrator out of the one exemption that exists to unlock them (`docs/11 §5.6`).
/// * **`device.posture`** is [`DevicePosture::Unknown`], which is exactly what
///   `crates/api/src/auth.rs` supplies for an authenticated request: no device registry is wired
///   yet, and `Unknown` satisfies no posture requirement. The bound device *id* is the refresh
///   row's, because that is the binding `enclave_auth::check_device_binding` already enforces.
fn context_for(
    record: &RefreshRecord,
    facts: &SessionFacts,
    network: &NetworkContext,
) -> RequestContext {
    RequestContext {
        request_id: RequestId::new_v7(),
        tenant_id: record.tenant_id,
        actor: record.actor,
        session_id: Some(record.session_id),
        auth_strength: Acr::from_methods(&facts.methods)
            .map_or(AuthStrength::Unauthenticated, Acr::strength),
        auth_time: facts.auth_time,
        scopes: facts.scopes.clone(),
        client: record.client,
        network: network.clone(),
        device: DeviceContext { device_id: record.device_id, posture: DevicePosture::Unknown },
    }
}

/// The resource a refresh is decided against: the caller's own principal.
///
/// `None` for a principal with no subject — [`enclave_core::Actor::System`], which has no `users`
/// row. Nothing in this workspace issues a refresh token to one
/// (`EnclaveTokenService::issues_refresh_token` excludes it along with service accounts and MCP
/// clients), so this is unreachable rather than merely unusual. It is an `Option` so that becoming
/// reachable is a refusal, and not a nil-UUID resource nobody owns.
fn self_resource(record: &RefreshRecord) -> Option<ResourceRef> {
    record
        .actor
        .subject_id()
        .map(|subject| ResourceRef::new(record.tenant_id, ResourceKind::User, subject))
}

#[async_trait::async_trait]
impl RefreshGuard for ChainRefreshGuard {
    /// # Errors
    ///
    /// [`AuthError::ConditionalAccessDenied`] carrying the stage's own reason code, and
    /// [`AuthError::StorageUnavailable`] when the rules could not be read at all — see the module
    /// header for why the second is not an allow.
    async fn allow_refresh(
        &self,
        record: &RefreshRecord,
        facts: &SessionFacts,
        network: &NetworkContext,
    ) -> Result<(), AuthError> {
        let Some(resource) = self_resource(record) else {
            // A principal that cannot own a `users` row cannot be the subject of a rule either.
            // Refused rather than waved through, with the generic code: `docs/05-API.md §5` keeps
            // our internal reasoning out of error bodies.
            tracing::error!(
                session_id = %record.session_id,
                "a refresh token exists for a principal with no subject; refusing the rotation"
            );
            return Err(AuthError::ConditionalAccessDenied(ReasonCode::AccessDenied));
        };

        let ctx = context_for(record, facts, network);

        // The audit row — allow or deny — is written inside this call, by the engine, keyed by the
        // tenant the *stored family* named (`CLAUDE.md` rule 10). Nothing on this path logs the
        // presented token, the cookie it arrived in, or the contents of the rule that refused.
        let evaluated =
            self.policy.reevaluate_conditional_access(&ctx, CONTINUE_OWN_SESSION, &resource).await;

        let decision = match evaluated {
            Ok(decision) => decision,
            Err(Error::PolicyDenied { code, .. }) => {
                return Err(AuthError::ConditionalAccessDenied(code));
            }
            Err(error) => {
                // Nothing was decided. Fail closed: the rotation does not happen, and the caller is
                // told a dependency is unavailable rather than that policy refused — so a retry is
                // the right next step and a support ticket is not.
                tracing::error!(
                    ?error,
                    session_id = %record.session_id,
                    tenant_id = %record.tenant_id,
                    "conditional access could not be evaluated for a refresh; refusing the rotation"
                );
                return Err(AuthError::StorageUnavailable(StoreUnavailable::new(
                    Dependency::Postgres,
                )));
            }
        };

        // `CLAUDE.md` rule 8, split by the vocabulary's own predicate rather than by a judgement
        // made here. An obligation that **blocks until satisfied** must be satisfied or the
        // operation fails, and this path can collect neither a justification nor an approval, so it
        // refuses with `Obligation::unsatisfied_code`.
        //
        // The rest — `ReadOnly`, `NoDownload`, `NoSync` — *shape a response*, and a refresh has no
        // response to shape: it returns a token, not bytes. Permitting the rotation does not drop
        // them, because the same stage re-derives them from the same rules on every request that
        // actually reads or writes something. Refusing here instead would mean a tenant running a
        // `PreviewOnly` rule could keep nobody signed in.
        let outstanding = decision.into_obligations();
        if let Some(blocking) = outstanding.iter().find(|o| o.blocks_until_satisfied()) {
            tracing::warn!(
                session_id = %record.session_id,
                "conditional access attached a blocking obligation to a refresh, which this path \
                 cannot discharge; refusing the rotation"
            );
            return Err(AuthError::ConditionalAccessDenied(blocking.unsatisfied_code()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use enclave_auth::AuthMethod;
    use enclave_core::{
        Actor, ClientType, ConditionalAccessService, DeviceId, Obligation, Obligations,
        PolicyAuditSink, ScopeSet, SessionId, Stage, StageDecision, TenantId, UserId,
    };
    use uuid::Uuid;

    use super::*;

    /// One recorded audit row, reduced to what a rule-10 assertion needs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Row {
        tenant: TenantId,
        outcome: &'static str,
        stage: Option<Stage>,
        code: Option<ReasonCode>,
    }

    #[derive(Debug, Default)]
    struct RecordingAudit {
        rows: Mutex<Vec<Row>>,
    }

    impl RecordingAudit {
        fn rows(&self) -> Vec<Row> {
            self.rows.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl PolicyAuditSink for RecordingAudit {
        async fn record_allow(
            &self,
            ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
            _obligations: &Obligations,
        ) -> enclave_core::Result<()> {
            self.rows.lock().expect("not poisoned").push(Row {
                tenant: ctx.tenant_id,
                outcome: "ALLOW",
                stage: None,
                code: None,
            });
            Ok(())
        }

        async fn record_deny(
            &self,
            ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
            stage: Stage,
            code: ReasonCode,
        ) -> enclave_core::Result<()> {
            self.rows.lock().expect("not poisoned").push(Row {
                tenant: ctx.tenant_id,
                outcome: "DENY",
                stage: Some(stage),
                code: Some(code),
            });
            Ok(())
        }
    }

    /// A conditional-access stage that answers however the test tells it to.
    #[derive(Debug)]
    enum Stub {
        Deny(ReasonCode),
        Allow,
        AllowWith(Obligation),
        /// The store could not answer. The case that decides fail-open against fail-closed.
        Unavailable,
    }

    #[async_trait]
    impl ConditionalAccessService for Stub {
        async fn evaluate(
            &self,
            _ctx: &RequestContext,
            _action: Action,
            _resource: &ResourceRef,
        ) -> enclave_core::Result<StageDecision> {
            match self {
                Self::Deny(code) => Ok(StageDecision::deny(*code)),
                Self::Allow => Ok(StageDecision::allow()),
                Self::AllowWith(obligation) => {
                    let mut obligations = Obligations::none();
                    obligations.insert(*obligation);
                    Ok(StageDecision::allow_with(obligations))
                }
                Self::Unavailable => {
                    Err(Error::Upstream { dependency: Dependency::Postgres, retryable: true })
                }
            }
        }
    }

    /// An engine whose conditional-access stage is the stub and whose later stages refuse
    /// everything.
    ///
    /// `DenyAll` below conditional access is the control for the claim that this path runs *one*
    /// stage: if `reevaluate_conditional_access` ever grew into `enforce`, every test here would
    /// fail with `ACCESS_DENIED` from authorization instead of the code the stub chose.
    fn engine(stage: Stub) -> (PolicyEngine, Arc<RecordingAudit>) {
        let audit = Arc::new(RecordingAudit::default());
        let engine = PolicyEngine::new(
            Arc::new(stage),
            Arc::new(enclave_core::engine::stub::DenyAll),
            Arc::new(enclave_core::engine::stub::DenyAll),
            Arc::new(enclave_core::engine::stub::DenyAll),
            Arc::new(enclave_core::engine::stub::DenyAll),
            Arc::new(enclave_core::engine::stub::DenyAll),
            Arc::clone(&audit) as Arc<dyn PolicyAuditSink>,
        );
        (engine, audit)
    }

    fn record(tenant: TenantId) -> RefreshRecord {
        RefreshRecord {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            session_id: SessionId::new_v7(),
            actor: Actor::User(UserId::new_v7()),
            token_hash: "not-a-token".to_owned(),
            device_id: Some(DeviceId::new_v7()),
            client: ClientType::Web,
            parent_id: None,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(14),
            absolute_expires_at: chrono::Utc::now() + chrono::Duration::days(90),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
        }
    }

    fn facts(methods: Vec<AuthMethod>) -> SessionFacts {
        SessionFacts {
            scopes: ScopeSet::default(),
            methods,
            auth_time: chrono::Utc::now(),
            epoch: 1,
            max_classification: None,
        }
    }

    /// A refusal carries the stage's own code, and is recorded as a `DENY` against the family's
    /// tenant.
    ///
    /// Both halves in one test on purpose (`docs/12 §1.2`): "the refresh was refused" is satisfied
    /// by a guard that refuses everything, so the allow case below is asserted from the same
    /// builder in the same file, and the audit row is asserted here rather than left to a reader to
    /// assume.
    #[tokio::test]
    async fn a_refusal_carries_the_stages_code_and_is_audited_as_a_denial() {
        let tenant = TenantId::new_v7();
        let (engine, audit) = engine(Stub::Deny(ReasonCode::NetworkNotAllowed));
        let guard = ChainRefreshGuard::new(engine);

        let refused = guard
            .allow_refresh(
                &record(tenant),
                &facts(vec![AuthMethod::Pwd]),
                &NetworkContext::unknown(),
            )
            .await
            .expect_err("a denying stage must refuse the rotation");

        assert!(
            matches!(refused, AuthError::ConditionalAccessDenied(ReasonCode::NetworkNotAllowed)),
            "the code the stage decided must reach the caller unchanged: {refused:?}"
        );
        assert_eq!(
            audit.rows(),
            vec![Row {
                tenant,
                outcome: "DENY",
                stage: Some(Stage::ConditionalAccess),
                code: Some(ReasonCode::NetworkNotAllowed),
            }],
            "CLAUDE.md rule 10: the denial is recorded inside the engine, against the family's \
             tenant, attributed to the stage that took it"
        );
    }

    /// The positive control the test above needs: the same guard, the same builder, an allowing
    /// stage — and the rotation proceeds, with an `ALLOW` row.
    #[tokio::test]
    async fn an_allowing_stage_permits_the_rotation_and_is_audited() {
        let tenant = TenantId::new_v7();
        let (engine, audit) = engine(Stub::Allow);
        let guard = ChainRefreshGuard::new(engine);

        guard
            .allow_refresh(
                &record(tenant),
                &facts(vec![AuthMethod::Pwd]),
                &NetworkContext::unknown(),
            )
            .await
            .expect("nothing refused, so the rotation proceeds");

        assert_eq!(
            audit.rows(),
            vec![Row { tenant, outcome: "ALLOW", stage: None, code: None }],
            "an allowed refresh is audited too — rule 10 is not only about denials"
        );
    }

    /// **The judgement call, asserted.** A stage that cannot answer refuses the refresh, and does
    /// so as a dependency failure rather than as a policy denial.
    ///
    /// The second half matters as much as the first: `AuthError::reason_code` answering `None` is
    /// what makes `routes::auth::refresh_failure` render `503` instead of a `403` telling the user
    /// to change networks over an outage they cannot act on.
    #[tokio::test]
    async fn a_stage_that_cannot_be_read_fails_closed() {
        let (engine, audit) = engine(Stub::Unavailable);
        let guard = ChainRefreshGuard::new(engine);

        let refused = guard
            .allow_refresh(
                &record(TenantId::new_v7()),
                &facts(vec![AuthMethod::Pwd]),
                &NetworkContext::unknown(),
            )
            .await
            .expect_err("an unreadable rule set must not permit a refresh");

        assert!(matches!(refused, AuthError::StorageUnavailable(_)), "{refused:?}");
        assert_eq!(
            refused.reason_code(),
            None,
            "nothing was decided, so nothing may be attributed to the caller"
        );
        assert!(
            audit.rows().is_empty(),
            "no decision was taken, so there is no decision to record"
        );
    }

    /// An obligation that constrains a response does not refuse a refresh; one that blocks does.
    ///
    /// Asserted as a pair because either alone is misleading. `NoDownload` refusing would mean a
    /// preview-only tenant could keep nobody signed in; `RequireJustification` passing would be
    /// rule 8 dropped on the floor.
    #[tokio::test]
    async fn a_constraining_obligation_permits_and_a_blocking_one_refuses() {
        let (permits, _audit) = engine(Stub::AllowWith(Obligation::NoDownload));
        ChainRefreshGuard::new(permits)
            .allow_refresh(
                &record(TenantId::new_v7()),
                &facts(vec![AuthMethod::Pwd]),
                &NetworkContext::unknown(),
            )
            .await
            .expect("NoDownload shapes a response; a refresh has none, and the session continues");

        let (refuses, _audit) = engine(Stub::AllowWith(Obligation::RequireJustification));
        let refused = ChainRefreshGuard::new(refuses)
            .allow_refresh(
                &record(TenantId::new_v7()),
                &facts(vec![AuthMethod::Pwd]),
                &NetworkContext::unknown(),
            )
            .await
            .expect_err("nothing here can collect a justification, so rule 8 forces a refusal");
        assert!(
            matches!(
                refused,
                AuthError::ConditionalAccessDenied(ReasonCode::DlpJustificationRequired)
            ),
            "{refused:?}"
        );
    }

    /// The context is built from the session's own facts, not from the weakest possible values.
    ///
    /// This is what a `RequireMfa` rule and the break-glass exemption both read. A guard that
    /// reported `Unauthenticated` would refuse a session that did authenticate with two factors,
    /// and would deny the emergency administrator the exemption `docs/11 §5.6` grants them.
    #[test]
    fn the_context_reports_the_strength_the_session_actually_authenticated_with() {
        let tenant = TenantId::new_v7();
        let row = record(tenant);

        let single = context_for(&row, &facts(vec![AuthMethod::Pwd]), &NetworkContext::unknown());
        assert_eq!(single.auth_strength, AuthStrength::SingleFactor);

        let multi = context_for(
            &row,
            &facts(vec![AuthMethod::Pwd, AuthMethod::Totp]),
            &NetworkContext::unknown(),
        );
        assert_eq!(
            multi.auth_strength,
            AuthStrength::MultiFactor,
            "a session that used two factors must not be judged as if it used one"
        );

        // And the rest of the context is the row's and the connection's, never a default.
        assert_eq!(multi.tenant_id, tenant);
        assert_eq!(multi.actor, row.actor);
        assert_eq!(multi.session_id, Some(row.session_id));
        assert_eq!(multi.client, ClientType::Web);
        assert_eq!(multi.device.device_id, row.device_id);
        assert_eq!(
            multi.device.posture,
            DevicePosture::Unknown,
            "no device registry is wired; claiming a posture here would be inventing evidence"
        );
    }

    /// The address the stage sees is the one the guard was handed, and there is no other way in.
    ///
    /// `CLAUDE.md` rule 3 at this seam: `allow_refresh` takes a `NetworkContext` and the guard reads
    /// no headers, so the only address it can decide against is the one `Edge` resolved from the
    /// socket peer and `server.trusted_proxies`.
    #[test]
    fn the_network_is_the_one_the_edge_resolved_and_nothing_else() {
        let mut network = NetworkContext::unknown();
        network.source_ip = "203.0.113.9".parse().expect("a fixture address");
        network.zones = vec!["Corporate".to_owned()];

        let ctx = context_for(&record(TenantId::new_v7()), &facts(vec![AuthMethod::Pwd]), &network);
        assert_eq!(ctx.network.source_ip, network.source_ip);
        assert_eq!(ctx.network.zones, network.zones);
    }
}
