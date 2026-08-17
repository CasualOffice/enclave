//! [`TokenService`] — issuing, rotating and revoking, as `docs/03-LLD.md §5.3` specifies it.
//!
//! # The trait's signatures are the specification's, deliberately
//!
//! `revoke_family(&self, sid, reason)` takes no tenant. That looks like an omission and is not: a
//! `sid` is a UUIDv7 and globally unique, so the implementation resolves the tenant *from the
//! stored family*. Accepting a tenant id here would mean accepting one from a caller, and a caller
//! is one layer away from a request body — non-negotiable rule 3. The narrower signature makes the
//! unsafe version unwritable.
//!
//! # What refresh does, in order
//!
//! 1. Look the presented token up by digest.
//! 2. Classify it. A consumed token is theft, and the response to theft happens *before* anything
//!    else: revoke the family, deny the outstanding access tokens, return
//!    [`AuthError::SessionReplay`] so the caller can raise the incident.
//! 3. Check the device binding.
//! 4. Re-evaluate conditional access through the [`RefreshGuard`]. `docs/03-LLD.md §5.3` rule 3 is
//!    the reason this is not optional: a user who moves outside an allowed network zone must lose
//!    access within one access-token lifetime, and refresh is where that is noticed.
//! 5. Rotate, then issue.

use core::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use enclave_core::{
    Actor, ClassificationRank, ClientType, DeviceId, NetworkContext, ScopeSet, SessionId, TenantId,
    UserId,
};
use uuid::Uuid;

use crate::access::{is_privileged, AccessTokenIssuer, TokenTemplate};
use crate::claims::{AccessTokenClaims, Acr, AuthMethod};
use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::keys::KeyProvider;
use crate::refresh::{
    classify, RefreshOutcome, RefreshRecord, RefreshToken, RefreshTokenStore, RevokeReason,
};
use crate::revocation::DenylistStore;

/// Everything a login flow established, and the input to the first token pair.
///
/// Assembled by the identity crate after a password, MFA or federated login completes. It is not
/// derived from a request: every field here is something the server decided.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The tenant the session belongs to.
    pub tenant_id: TenantId,
    /// The principal.
    pub actor: Actor,
    /// The refresh family. `None` starts a new one; `Some` continues an existing one across a
    /// rotation.
    pub session_id: Option<SessionId>,
    /// The client type the session was established through.
    pub client: ClientType,
    /// The bound device, where there is one.
    pub device_id: Option<DeviceId>,
    /// Scopes granted to this session.
    pub scopes: ScopeSet,
    /// Methods actually used. [`Acr`] is derived from these rather than asserted, so a login flow
    /// cannot claim `mfa` while having collected only a password.
    pub methods: Vec<AuthMethod>,
    /// When the authentication event happened.
    pub auth_time: DateTime<Utc>,
    /// The subject's `token_epoch` at issuance.
    pub epoch: i32,
    /// Classification ceiling, for MCP clients (`docs/03-LLD.md §5.6`).
    pub max_classification: Option<ClassificationRank>,
}

/// An access token and, for interactive clients, its refresh token.
#[derive(Debug)]
pub struct TokenPair {
    /// The compact JWS for the `Authorization` header.
    pub access_token: String,
    /// Seconds until the access token expires, for the `expiresIn` field of the login response.
    pub expires_in: i64,
    /// The refresh family id, echoed to the client as `sessionId` and used as the audit
    /// correlation key.
    pub session_id: SessionId,
    /// The refresh token, when one was issued.
    ///
    /// `None` for service accounts and MCP clients: `docs/03-LLD.md §5.6` gives them no refresh
    /// token because they hold their own credentials and can simply re-authenticate. Issuing them
    /// one would create a long-lived bearer credential for a caller that did not need it.
    pub refresh_token: Option<RefreshToken>,
    /// The claims of the issued access token, so the caller can denylist its `jti` on logout
    /// without re-parsing what it was just handed.
    pub claims: AccessTokenClaims,
}

/// The contract from `docs/03-LLD.md §5.3`.
#[async_trait]
pub trait TokenService: Send + Sync {
    /// Issues the first token pair of a session.
    ///
    /// # Errors
    ///
    /// [`AuthError::KeyUnavailable`] or a storage failure.
    async fn issue_pair(&self, ctx: &AuthContext) -> Result<TokenPair, AuthError>;

    /// Exchanges a refresh token for its successor and a new access token.
    ///
    /// # Errors
    ///
    /// [`AuthError::SessionReplay`] when the presented token was already consumed — by which point
    /// the family has already been revoked — [`AuthError::RefreshRejected`],
    /// [`AuthError::DeviceMismatch`] or [`AuthError::NetworkNotAllowed`].
    async fn refresh(
        &self,
        presented: &RefreshToken,
        network: &NetworkContext,
    ) -> Result<TokenPair, AuthError>;

    /// Revokes one refresh family and denies its outstanding access tokens.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn revoke_family(
        &self,
        session_id: SessionId,
        reason: RevokeReason,
    ) -> Result<(), AuthError>;

    /// Revokes every family belonging to a user.
    ///
    /// Note that this does **not** invalidate their outstanding access tokens on its own — that is
    /// what the `token_epoch` bump behind `POST /auth/logout-all` is for. Sessions and access
    /// tokens are revoked by different mechanisms because they have different lifetimes, and
    /// conflating them would leave one of the two half-done.
    ///
    /// # Errors
    ///
    /// Storage failures.
    async fn revoke_all_for_user(
        &self,
        user: UserId,
        reason: RevokeReason,
    ) -> Result<(), AuthError>;
}

/// Re-evaluates conditional access at refresh time (`docs/03-LLD.md §5.3` rule 3, test K6).
///
/// A trait, not a call into the `conditional_access` crate, because `auth` is below the policy
/// services in the dependency order (D1) and a direct dependency would be a sideways edge. The
/// binary wires the real evaluator in.
#[async_trait]
pub trait RefreshGuard: Send + Sync + fmt::Debug {
    /// Whether this family may still be refreshed from this network.
    ///
    /// # Errors
    ///
    /// [`AuthError::NetworkNotAllowed`], or another denial the evaluator determines.
    async fn allow_refresh(
        &self,
        record: &RefreshRecord,
        network: &NetworkContext,
    ) -> Result<(), AuthError>;
}

/// A [`RefreshGuard`] that permits every refresh.
///
/// **Development and tests only.** It is named for what it does rather than being a `Default`, so
/// that wiring it is a visible choice in a binary's startup code and shows up in review. The real
/// evaluator lands with the `conditional_access` crate in M1; until then a deployment profile check
/// is the thing that should refuse to start with this in place.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrestrictedRefreshGuard;

#[async_trait]
impl RefreshGuard for UnrestrictedRefreshGuard {
    async fn allow_refresh(
        &self,
        _record: &RefreshRecord,
        _network: &NetworkContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}

/// What a session asserts, re-established at refresh time.
///
/// Not stored on the refresh row. `refresh_tokens` deliberately holds no scopes, no `acr` and no
/// epoch: a row that carried them would let a fourteen-day-old session keep asserting privileges
/// its owner lost a week ago.
#[derive(Debug, Clone)]
pub struct SessionFacts {
    /// The scopes the subject may currently exercise.
    pub scopes: ScopeSet,
    /// The methods the original authentication used, so `acr` and `amr` survive a refresh without
    /// being *strengthened* by it.
    pub methods: Vec<AuthMethod>,
    /// The original authentication event's time. Unchanged by refreshing — a max-age policy must
    /// measure from the authentication, not from the last rotation.
    pub auth_time: DateTime<Utc>,
    /// The subject's current `token_epoch`.
    pub epoch: i32,
    /// Classification ceiling, for MCP clients.
    pub max_classification: Option<ClassificationRank>,
}

/// Who a session belongs to and how it is reached — the half of a token that never changes across
/// a rotation.
///
/// Private, because it exists to keep [`EnclaveTokenService::issue_access_token`] from taking five
/// interchangeable UUIDs in a row.
#[derive(Debug, Clone, Copy)]
struct SessionIdentity {
    tenant_id: TenantId,
    actor: Actor,
    session_id: SessionId,
    client: ClientType,
    device_id: Option<DeviceId>,
}

/// Re-resolves [`SessionFacts`] at refresh time.
///
/// A trait for the same reason [`RefreshGuard`] is one: the answer lives in the identity and
/// authorization layers, which sit *above* `auth` in the dependency order (D1), so `auth` states
/// the question and the binary wires in the answer.
#[async_trait]
pub trait SessionFactsProvider: Send + Sync + fmt::Debug {
    /// The facts to mint the next access token with.
    ///
    /// # Errors
    ///
    /// [`AuthError::RefreshRejected`] if the subject no longer has a usable session at all —
    /// disabled, deleted or offboarded between rotations.
    async fn facts_for(&self, record: &RefreshRecord) -> Result<SessionFacts, AuthError>;
}

/// Source of the current time.
///
/// Injected rather than read from `Utc::now()` so that lifetime and expiry behaviour is testable at
/// its boundaries. A security property that can only be exercised by changing the system clock is a
/// security property that does not get exercised.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current instant.
    fn now(&self) -> DateTime<Utc>;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// The concrete [`TokenService`].
///
/// Generic over its four collaborators rather than boxing them: this sits on the login and refresh
/// paths, the set is fixed at startup, and monomorphising means a test can substitute an in-memory
/// store without an allocation or a `dyn` call on the hot path.
#[derive(Debug)]
pub struct EnclaveTokenService<K, R, D, G, F, C = SystemClock> {
    config: AuthConfig,
    issuer: AccessTokenIssuer,
    keys: K,
    refresh_store: R,
    denylist: D,
    guard: G,
    facts: F,
    clock: C,
}

impl<K, R, D, G, F> EnclaveTokenService<K, R, D, G, F, SystemClock>
where
    K: KeyProvider,
    R: RefreshTokenStore,
    D: DenylistStore,
    G: RefreshGuard,
    F: SessionFactsProvider,
{
    /// Builds the service against the real clock.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] if [`AuthConfig::validate`] refuses the configuration. Failing
    /// here means a bad configuration is a startup failure rather than a login failure.
    pub fn new(
        config: AuthConfig,
        keys: K,
        refresh_store: R,
        denylist: D,
        guard: G,
        facts: F,
    ) -> Result<Self, AuthError> {
        Self::with_clock(config, keys, refresh_store, denylist, guard, facts, SystemClock)
    }
}

impl<K, R, D, G, F, C> EnclaveTokenService<K, R, D, G, F, C>
where
    K: KeyProvider,
    R: RefreshTokenStore,
    D: DenylistStore,
    G: RefreshGuard,
    F: SessionFactsProvider,
    C: Clock,
{
    /// Builds the service against an explicit clock.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`].
    pub fn with_clock(
        config: AuthConfig,
        keys: K,
        refresh_store: R,
        denylist: D,
        guard: G,
        facts: F,
        clock: C,
    ) -> Result<Self, AuthError> {
        config.validate()?;
        let issuer = AccessTokenIssuer::new(
            config.access_token.issuer.clone(),
            config.access_token.audience.clone(),
        );
        Ok(Self { config, issuer, keys, refresh_store, denylist, guard, facts, clock })
    }

    /// The access-token lifetime for a scope set.
    ///
    /// Privileged tokens get the shorter one, because the denylist — the only mechanism that can
    /// revoke them faster than expiry — is the component `docs/03-LLD.md §5.4` explicitly allows to
    /// be unavailable.
    fn access_ttl(&self, scopes: &ScopeSet) -> Duration {
        Duration::seconds(if is_privileged(scopes) {
            self.config.access_token.privileged_ttl_secs
        } else {
            self.config.access_token.ttl_secs
        })
    }

    /// Signs an access token for a session.
    ///
    /// Takes the session's identity and its facts as two structs rather than a dozen positional
    /// arguments. That is not only tidiness: five of those arguments are UUID-shaped, and a
    /// transposed `tenant_id`/`session_id` pair would compile, run, and mint a token for the wrong
    /// tenant.
    async fn issue_access_token(
        &self,
        identity: SessionIdentity,
        facts: &SessionFacts,
        now: DateTime<Utc>,
    ) -> Result<crate::access::IssuedAccessToken, AuthError> {
        let key = self.keys.active_signing_key().await.map_err(AuthError::KeyUnavailable)?;
        let template = TokenTemplate {
            // `System` has no subject, and a token for it would be a token nobody can revoke. The
            // nil UUID is used only so the claim is well-formed; `typ: system` is what identifies
            // it, and nothing issues one of these in practice.
            sub: identity.actor.subject_id().unwrap_or_else(Uuid::nil),
            tid: identity.tenant_id.as_uuid(),
            sid: identity.session_id.as_uuid(),
            typ: identity.actor.kind(),
            scp: facts.scopes.iter().map(str::to_owned).collect(),
            amr: facts.methods.clone(),
            auth_time: facts.auth_time,
            // Derived from the methods, never asserted: see `AuthContext::methods`.
            acr: Acr::from_methods(&facts.methods).unwrap_or(Acr::SingleFactor),
            dev: identity.device_id.map(|d| d.as_uuid()),
            cli: identity.client,
            epoch: facts.epoch,
            max_cls: facts.max_classification,
        };
        self.issuer.issue(&key, template, now, self.access_ttl(&facts.scopes))
    }

    /// Whether this client is one that receives a refresh token at all.
    const fn issues_refresh_token(actor: Actor) -> bool {
        !matches!(actor, Actor::ServiceAccount(_) | Actor::McpClient(_) | Actor::System)
    }

    /// The response to a detected replay: destroy the family, then deny what it issued.
    ///
    /// Order matters. Revoking first means that even if denylisting fails — the store may be the
    /// very thing that is down — no further refresh can succeed, so the blast radius is bounded by
    /// one access-token lifetime rather than by fourteen days.
    async fn handle_replay(
        &self,
        record: &RefreshRecord,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.refresh_store
            .revoke_family(record.session_id, RevokeReason::SessionReplay, now)
            .await?;

        // Deny every access token in the family. We do not hold their `jti`s, so the denial is by
        // `sid`; see the note on `DenylistStore::deny_session`.
        let until = now + Duration::seconds(self.config.access_token.ttl_secs);
        if let Err(unavailable) = self
            .denylist
            .deny_session(record.tenant_id, record.session_id, until, RevokeReason::SessionReplay)
            .await
        {
            // Not fatal, and not silent. The family is already revoked; what is lost is the
            // immediate kill on access tokens already in flight, which is exactly the sort of
            // partial failure an incident responder needs to know about.
            tracing::error!(
                dependency = %unavailable.dependency,
                session_id = %record.session_id,
                "refresh replay detected but access tokens could not be denylisted"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl<K, R, D, G, F, C> TokenService for EnclaveTokenService<K, R, D, G, F, C>
where
    K: KeyProvider,
    R: RefreshTokenStore,
    D: DenylistStore,
    G: RefreshGuard,
    F: SessionFactsProvider,
    C: Clock,
{
    async fn issue_pair(&self, ctx: &AuthContext) -> Result<TokenPair, AuthError> {
        let now = self.clock.now();
        let session_id = ctx.session_id.unwrap_or_else(SessionId::new_v7);

        let issued = self
            .issue_access_token(
                SessionIdentity {
                    tenant_id: ctx.tenant_id,
                    actor: ctx.actor,
                    session_id,
                    client: ctx.client,
                    device_id: ctx.device_id,
                },
                &SessionFacts {
                    scopes: ctx.scopes.clone(),
                    methods: ctx.methods.clone(),
                    auth_time: ctx.auth_time,
                    epoch: ctx.epoch,
                    max_classification: ctx.max_classification,
                },
                now,
            )
            .await?;

        let refresh_token = if Self::issues_refresh_token(ctx.actor) {
            let token = RefreshToken::generate();
            self.refresh_store
                .insert(RefreshRecord {
                    id: Uuid::new_v4(),
                    tenant_id: ctx.tenant_id,
                    session_id,
                    actor: ctx.actor,
                    token_hash: token.digest().to_hex(),
                    device_id: ctx.device_id,
                    client: ctx.client,
                    parent_id: None,
                    issued_at: now,
                    expires_at: now + Duration::seconds(self.config.refresh_token.idle_ttl_secs),
                    // Anchored to the authentication event, not to now, so that a session cannot
                    // extend its absolute ceiling by being re-issued.
                    absolute_expires_at: ctx.auth_time
                        + Duration::seconds(self.config.refresh_token.absolute_ttl_secs),
                    consumed_at: None,
                    revoked_at: None,
                    revoke_reason: None,
                })
                .await?;
            Some(token)
        } else {
            None
        };

        Ok(TokenPair {
            access_token: issued.token,
            expires_in: issued.claims.exp - now.timestamp(),
            session_id,
            refresh_token,
            claims: issued.claims,
        })
    }

    async fn refresh(
        &self,
        presented: &RefreshToken,
        network: &NetworkContext,
    ) -> Result<TokenPair, AuthError> {
        let now = self.clock.now();
        let stored = self.refresh_store.find_by_hash(&presented.digest().to_hex()).await?;

        let record = match classify(stored, now) {
            RefreshOutcome::Usable(record) => *record,
            RefreshOutcome::Replay(record) => {
                // K4. Act first, then report — a caller that ignored the error must not be able to
                // leave the family alive.
                self.handle_replay(&record, now).await?;
                return Err(AuthError::SessionReplay);
            }
            RefreshOutcome::Rejected => return Err(AuthError::RefreshRejected),
        };

        // Rule 3, and test K6.
        self.guard.allow_refresh(&record, network).await?;

        // K3: consume the presented token and insert its successor atomically.
        let successor_token = RefreshToken::generate();
        let successor = RefreshRecord {
            id: Uuid::new_v4(),
            tenant_id: record.tenant_id,
            session_id: record.session_id,
            actor: record.actor,
            token_hash: successor_token.digest().to_hex(),
            device_id: record.device_id,
            client: record.client,
            parent_id: Some(record.id),
            issued_at: now,
            // The sliding window moves; the absolute ceiling is inherited untouched.
            expires_at: now + Duration::seconds(self.config.refresh_token.idle_ttl_secs),
            absolute_expires_at: record.absolute_expires_at,
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
        };
        self.refresh_store.rotate(record.id, successor, now).await?;

        // Scopes, `epoch` and the authentication facts are **re-resolved**, not copied from the
        // previous token. That is the point of a ten-minute access token: a role removed, a group
        // membership lost or an epoch bumped since the last refresh must be reflected in the token
        // issued now. Carrying the old `scp` forward would make a refresh chain immune to
        // authorization changes for as long as the user kept refreshing.
        let facts = self.facts.facts_for(&record).await?;
        let issued = self
            .issue_access_token(
                SessionIdentity {
                    tenant_id: record.tenant_id,
                    actor: record.actor,
                    session_id: record.session_id,
                    client: record.client,
                    device_id: record.device_id,
                },
                &facts,
                now,
            )
            .await?;

        Ok(TokenPair {
            access_token: issued.token,
            expires_in: issued.claims.exp - now.timestamp(),
            session_id: record.session_id,
            refresh_token: Some(successor_token),
            claims: issued.claims,
        })
    }

    async fn revoke_family(
        &self,
        session_id: SessionId,
        reason: RevokeReason,
    ) -> Result<(), AuthError> {
        let now = self.clock.now();
        let revoked = self.refresh_store.revoke_family(session_id, reason, now).await?;
        let until = now + Duration::seconds(self.config.access_token.ttl_secs);
        // The tenant comes from the stored rows, never from a caller. See the module note.
        if let Some(tenant_id) = revoked.first().map(|r| r.tenant_id) {
            if let Err(unavailable) =
                self.denylist.deny_session(tenant_id, session_id, until, reason).await
            {
                tracing::error!(
                    dependency = %unavailable.dependency,
                    session_id = %session_id,
                    "family revoked but access tokens could not be denylisted"
                );
            }
        }
        Ok(())
    }

    async fn revoke_all_for_user(
        &self,
        user: UserId,
        reason: RevokeReason,
    ) -> Result<(), AuthError> {
        let now = self.clock.now();
        let revoked =
            self.refresh_store.revoke_all_for_subject(user.as_uuid(), reason, now).await?;
        let until = now + Duration::seconds(self.config.access_token.ttl_secs);
        for record in &revoked {
            if let Err(unavailable) =
                self.denylist.deny_session(record.tenant_id, record.session_id, until, reason).await
            {
                tracing::error!(
                    dependency = %unavailable.dependency,
                    session_id = %record.session_id,
                    "family revoked but access tokens could not be denylisted"
                );
            }
        }
        Ok(())
    }
}

/// Enforces `docs/03-LLD.md §5.3` rule 4: a refresh token is bound to its device.
///
/// A free function rather than a step inside [`TokenService::refresh`], because the trait signature
/// in the specification carries a [`NetworkContext`] and no device, and widening it here would put
/// this crate's API out of step with the document that defines it. The API layer holds the attested
/// device and calls this before it calls `refresh`.
///
/// A mismatch is a plain refusal, not a family revocation: a refresh token on a different device is
/// as likely to be a restored backup or a re-enrolled machine as it is to be theft, and destroying
/// a session on that evidence would make device re-enrolment look like an attack.
///
/// # Errors
///
/// [`AuthError::DeviceMismatch`].
pub fn check_device_binding(
    record: &RefreshRecord,
    presented: Option<DeviceId>,
) -> Result<(), AuthError> {
    match record.device_id {
        // Unbound families — an ordinary browser session on an unregistered machine — impose no
        // constraint. Note that `sync` and `editor` clients cannot be unbound: their *access*
        // tokens are rejected without a `dev` claim by `crate::access` (K7).
        None => Ok(()),
        Some(bound) if presented == Some(bound) => Ok(()),
        Some(_) => Err(AuthError::DeviceMismatch),
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::access::AccessTokenVerifier;
    use crate::config::{AccessTokenConfig, Argon2Params, PasswordPolicy};
    use crate::error::KeyProviderError;
    use crate::keys::{KeySet, KeyStatus, PrivateSigningKey, PublicSigningKey};
    use crate::password::PasswordHasher;
    use crate::refresh::InMemoryRefreshStore;
    use crate::revocation::InMemoryDenylist;
    use enclave_core::{DevicePosture, RequestId, ServiceAccountId, TenantId};

    const ISS: &str = "https://workspace.example.com";
    const AUD: &str = "enclave-api";

    /// A clock the test moves by hand, so lifetimes are exercised at their boundaries rather than
    /// by sleeping.
    #[derive(Debug)]
    struct FixedClock(std::sync::Mutex<DateTime<Utc>>);

    impl FixedClock {
        fn new(at: DateTime<Utc>) -> Self {
            Self(std::sync::Mutex::new(at))
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().expect("clock lock") += by;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().expect("clock lock")
        }
    }

    /// One generated key, so the service runs without touching a filesystem.
    #[derive(Debug)]
    struct FixedKeyProvider(PrivateSigningKey);

    #[async_trait]
    impl KeyProvider for FixedKeyProvider {
        async fn active_signing_key(&self) -> Result<PrivateSigningKey, KeyProviderError> {
            PrivateSigningKey::from_pkcs8_der(
                self.0.pkcs8_der(),
                KeyStatus::Active,
                Utc::now(),
                None,
            )
        }

        async fn verification_keys(&self) -> Result<Vec<PublicSigningKey>, KeyProviderError> {
            Ok(vec![self.0.public().clone()])
        }
    }

    /// Stands in for the identity and authorization layers that will resolve these for real.
    #[derive(Debug)]
    struct StaticFacts;

    #[async_trait]
    impl SessionFactsProvider for StaticFacts {
        async fn facts_for(&self, record: &RefreshRecord) -> Result<SessionFacts, AuthError> {
            Ok(SessionFacts {
                scopes: ["files:read"].into_iter().collect(),
                methods: vec![AuthMethod::Pwd],
                auth_time: record.issued_at,
                epoch: 1,
                max_classification: None,
            })
        }
    }

    type Service = EnclaveTokenService<
        FixedKeyProvider,
        InMemoryRefreshStore,
        InMemoryDenylist,
        UnrestrictedRefreshGuard,
        StaticFacts,
        FixedClock,
    >;

    fn config() -> AuthConfig {
        AuthConfig {
            access_token: AccessTokenConfig { issuer: ISS.to_owned(), ..Default::default() },
            ..AuthConfig::default()
        }
    }

    fn service(now: DateTime<Utc>) -> Service {
        EnclaveTokenService::with_clock(
            config(),
            FixedKeyProvider(PrivateSigningKey::generate(now).expect("generate")),
            InMemoryRefreshStore::new(),
            InMemoryDenylist::new(),
            UnrestrictedRefreshGuard,
            StaticFacts,
            FixedClock::new(now),
        )
        .expect("valid configuration")
    }

    fn verifier(svc: &Service) -> AccessTokenVerifier {
        AccessTokenVerifier::new(ISS, AUD, KeySet::new([svc.keys.0.public().clone()]))
    }

    fn login(now: DateTime<Utc>, actor: Actor, client: ClientType) -> AuthContext {
        AuthContext {
            tenant_id: TenantId::new_v7(),
            actor,
            session_id: None,
            client,
            device_id: None,
            scopes: ["files:read"].into_iter().collect(),
            methods: vec![AuthMethod::Pwd],
            auth_time: now,
            epoch: 1,
            max_classification: None,
        }
    }

    #[tokio::test]
    async fn a_login_produces_a_verifiable_token_pair() {
        let now = Utc::now();
        let svc = service(now);
        let pair = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue");

        assert_eq!(pair.expires_in, 600);
        let refresh = pair.refresh_token.as_ref().expect("web clients get a refresh token");
        assert_eq!(refresh.expose().len(), 43, "256 bits, base64url, unpadded");

        let verified = verifier(&svc).verify(&pair.access_token, now).expect("verify");
        assert_eq!(verified.session_id(), pair.session_id);
        assert_eq!(verified.claims().scp, vec!["files:read".to_owned()]);
    }

    #[tokio::test]
    async fn machine_callers_receive_no_refresh_token() {
        let now = Utc::now();
        let svc = service(now);
        let pair = svc
            .issue_pair(&login(
                now,
                Actor::ServiceAccount(ServiceAccountId::new_v7()),
                ClientType::Api,
            ))
            .await
            .expect("issue");
        assert!(
            pair.refresh_token.is_none(),
            "docs/03-LLD.md §5.6: machine callers re-authenticate instead"
        );
    }

    #[tokio::test]
    async fn privileged_sessions_get_the_shorter_access_token_lifetime() {
        let now = Utc::now();
        let svc = service(now);
        let mut ctx = login(now, Actor::User(UserId::new_v7()), ClientType::Web);
        ctx.scopes = ["admin:users"].into_iter().collect();
        assert_eq!(svc.issue_pair(&ctx).await.expect("issue").expires_in, 300);
    }

    #[tokio::test]
    async fn the_absolute_ceiling_is_anchored_to_the_authentication_not_to_issuance() {
        let now = Utc::now();
        let svc = service(now);
        let mut ctx = login(now, Actor::User(UserId::new_v7()), ClientType::Web);
        // A session established a month ago and re-issued now must not gain a fresh 90 days.
        ctx.auth_time = now - Duration::days(30);
        svc.issue_pair(&ctx).await.expect("issue");

        let row = svc.refresh_store.rows().pop().expect("one row");
        assert_eq!(row.absolute_expires_at, ctx.auth_time + Duration::days(90));
    }

    #[tokio::test]
    async fn k3_a_refresh_rotates_and_invalidates_the_presented_token() {
        let now = Utc::now();
        let svc = service(now);
        let first = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.clock.advance(Duration::minutes(30));
        let second = svc
            .refresh(&first, &NetworkContext::internal())
            .await
            .expect("rotation succeeds")
            .refresh_token
            .expect("a successor is issued");
        assert_ne!(first.expose(), second.expose(), "K3: the token must change");

        // The successor works.
        svc.clock.advance(Duration::minutes(1));
        svc.refresh(&second, &NetworkContext::internal()).await.expect("the successor is usable");
    }

    #[tokio::test]
    async fn k3_the_successor_inherits_the_family_and_chains_to_its_parent() {
        let now = Utc::now();
        let svc = service(now);
        let pair = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue");
        let first = pair.refresh_token.expect("refresh token");

        svc.clock.advance(Duration::minutes(1));
        let rotated = svc.refresh(&first, &NetworkContext::internal()).await.expect("rotate");
        assert_eq!(rotated.session_id, pair.session_id, "sid is the family, not the token");

        let rows = svc.refresh_store.rows();
        let original = rows.iter().find(|r| r.parent_id.is_none()).expect("original");
        let successor = rows.iter().find(|r| r.parent_id.is_some()).expect("successor");
        assert_eq!(successor.parent_id, Some(original.id));
        assert_eq!(successor.session_id, original.session_id);
        assert!(original.consumed_at.is_some(), "K3: the presented token is consumed");
        assert_eq!(
            successor.absolute_expires_at, original.absolute_expires_at,
            "rotation must not extend the absolute ceiling"
        );
    }

    #[tokio::test]
    async fn k4_replaying_a_consumed_refresh_token_destroys_the_family() {
        let now = Utc::now();
        let svc = service(now);
        let pair = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue");
        let tenant_id = TenantId::from_uuid(pair.claims.tid);
        let session_id = pair.session_id;
        let stolen = pair.refresh_token.expect("refresh token");

        svc.clock.advance(Duration::minutes(1));
        let legitimate = svc
            .refresh(&stolen, &NetworkContext::internal())
            .await
            .expect("the first use succeeds")
            .refresh_token
            .expect("successor");

        // The thief presents the copy taken before the rotation.
        svc.clock.advance(Duration::minutes(1));
        assert!(
            matches!(
                svc.refresh(&stolen, &NetworkContext::internal()).await,
                Err(AuthError::SessionReplay)
            ),
            "K4: a consumed token is a replay, not a plain rejection"
        );

        // The victim's live token is dead too — that is what revoking the family means.
        svc.clock.advance(Duration::minutes(1));
        assert!(
            matches!(
                svc.refresh(&legitimate, &NetworkContext::internal()).await,
                Err(AuthError::RefreshRejected)
            ),
            "K4: the whole family, not only the replayed token"
        );

        // Every outstanding access token in the family is denied, by `sid`, immediately.
        assert!(
            svc.denylist
                .is_denied(tenant_id, Uuid::new_v4(), session_id)
                .await
                .expect("denylist available"),
            "K4: access tokens issued in the family must stop working at once"
        );
    }

    #[tokio::test]
    async fn k4_the_family_is_destroyed_before_refresh_returns() {
        // Asserts ordering rather than the return value: a caller that discards the error has
        // still had the family revoked by the time it could do so.
        let now = Utc::now();
        let svc = service(now);
        let stolen = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.clock.advance(Duration::minutes(1));
        let _successor = svc.refresh(&stolen, &NetworkContext::internal()).await.expect("rotate");
        svc.clock.advance(Duration::minutes(1));
        let _ignored = svc.refresh(&stolen, &NetworkContext::internal()).await;

        let rows = svc.refresh_store.rows();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.revoked_at.is_some()));
        assert!(rows.iter().all(|r| r.revoke_reason == Some(RevokeReason::SessionReplay)));
    }

    #[tokio::test]
    async fn k4_replay_is_still_reported_when_the_denylist_is_unavailable() {
        // The family revocation must not depend on Redis: losing the denylist costs us the
        // immediate kill on access tokens, never the session.
        let now = Utc::now();
        let svc = service(now);
        let stolen = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.clock.advance(Duration::minutes(1));
        svc.refresh(&stolen, &NetworkContext::internal()).await.expect("rotate");
        svc.denylist.set_available(false);

        svc.clock.advance(Duration::minutes(1));
        assert!(matches!(
            svc.refresh(&stolen, &NetworkContext::internal()).await,
            Err(AuthError::SessionReplay)
        ));
        assert!(svc.refresh_store.rows().iter().all(|r| r.revoked_at.is_some()));
    }

    #[tokio::test]
    async fn k6_the_refresh_guard_can_refuse_a_rotation() {
        #[derive(Debug)]
        struct BlockedZone;

        #[async_trait]
        impl RefreshGuard for BlockedZone {
            async fn allow_refresh(
                &self,
                _record: &RefreshRecord,
                network: &NetworkContext,
            ) -> Result<(), AuthError> {
                if network.in_zone("Corporate India") {
                    Ok(())
                } else {
                    Err(AuthError::NetworkNotAllowed)
                }
            }
        }

        let now = Utc::now();
        let svc: EnclaveTokenService<_, _, _, _, _, FixedClock> = EnclaveTokenService::with_clock(
            config(),
            FixedKeyProvider(PrivateSigningKey::generate(now).expect("generate")),
            InMemoryRefreshStore::new(),
            InMemoryDenylist::new(),
            BlockedZone,
            StaticFacts,
            FixedClock::new(now),
        )
        .expect("valid configuration");

        let token = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.clock.advance(Duration::minutes(1));
        assert!(
            matches!(
                svc.refresh(&token, &NetworkContext::internal()).await,
                Err(AuthError::NetworkNotAllowed)
            ),
            "K6: a refresh from a blocked zone must be refused"
        );

        // ...and refusing must not consume the token, or a transient policy blip would log the
        // user out permanently.
        let mut permitted = NetworkContext::internal();
        permitted.zones = vec!["Corporate India".to_owned()];
        svc.refresh(&token, &permitted).await.expect("the same token still works from a good zone");
    }

    #[tokio::test]
    async fn refreshing_re_resolves_scopes_rather_than_copying_them() {
        // The login grants `admin:users`; the facts provider grants only `files:read`. The
        // refreshed token must reflect the latter — a privilege lost between rotations must not
        // survive.
        let now = Utc::now();
        let svc = service(now);
        let mut ctx = login(now, Actor::User(UserId::new_v7()), ClientType::Web);
        ctx.scopes = ["admin:users"].into_iter().collect();
        let token = svc.issue_pair(&ctx).await.expect("issue").refresh_token.expect("refresh");

        svc.clock.advance(Duration::minutes(1));
        let refreshed = svc.refresh(&token, &NetworkContext::internal()).await.expect("rotate");
        assert_eq!(refreshed.claims.scp, vec!["files:read".to_owned()]);
        assert_eq!(refreshed.expires_in, 600, "and it is no longer a privileged token");
    }

    #[tokio::test]
    async fn an_unknown_refresh_token_is_a_plain_rejection() {
        let now = Utc::now();
        let svc = service(now);
        assert!(matches!(
            svc.refresh(&RefreshToken::generate(), &NetworkContext::internal()).await,
            Err(AuthError::RefreshRejected)
        ));
    }

    #[tokio::test]
    async fn an_expired_refresh_token_is_rejected() {
        let now = Utc::now();
        let svc = service(now);
        let token = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.clock.advance(Duration::days(15));
        assert!(matches!(
            svc.refresh(&token, &NetworkContext::internal()).await,
            Err(AuthError::RefreshRejected)
        ));
    }

    #[tokio::test]
    async fn revoking_a_family_stops_further_refreshes_and_denies_its_access_tokens() {
        let now = Utc::now();
        let svc = service(now);
        let pair = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue");
        let tenant_id = TenantId::from_uuid(pair.claims.tid);
        let token = pair.refresh_token.expect("refresh token");

        svc.revoke_family(pair.session_id, RevokeReason::Logout).await.expect("revoke");
        assert!(matches!(
            svc.refresh(&token, &NetworkContext::internal()).await,
            Err(AuthError::RefreshRejected)
        ));
        assert!(svc
            .denylist
            .is_denied(tenant_id, pair.claims.jti, pair.session_id)
            .await
            .expect("denylist"));
    }

    #[tokio::test]
    async fn revoking_every_session_for_a_user_leaves_none_usable() {
        let now = Utc::now();
        let svc = service(now);
        let user = UserId::new_v7();
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.push(
                svc.issue_pair(&login(now, Actor::User(user), ClientType::Web))
                    .await
                    .expect("issue")
                    .refresh_token
                    .expect("refresh token"),
            );
        }
        // A different user's session must survive.
        let bystander = svc
            .issue_pair(&login(now, Actor::User(UserId::new_v7()), ClientType::Web))
            .await
            .expect("issue")
            .refresh_token
            .expect("refresh token");

        svc.revoke_all_for_user(user, RevokeReason::PasswordChange).await.expect("revoke all");
        svc.clock.advance(Duration::minutes(1));
        for token in &tokens {
            assert!(matches!(
                svc.refresh(token, &NetworkContext::internal()).await,
                Err(AuthError::RefreshRejected)
            ));
        }
        svc.refresh(&bystander, &NetworkContext::internal())
            .await
            .expect("another user's session is untouched");
    }

    #[test]
    fn device_binding_is_enforced_only_where_there_is_a_binding() {
        let now = Utc::now();
        let device = DeviceId::new_v7();
        let mut record = RefreshRecord {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new_v7(),
            session_id: SessionId::new_v7(),
            actor: Actor::User(UserId::new_v7()),
            token_hash: String::new(),
            device_id: Some(device),
            client: ClientType::Sync,
            parent_id: None,
            issued_at: now,
            expires_at: now + Duration::days(14),
            absolute_expires_at: now + Duration::days(90),
            consumed_at: None,
            revoked_at: None,
            revoke_reason: None,
        };

        check_device_binding(&record, Some(device)).expect("the bound device is accepted");
        assert!(matches!(
            check_device_binding(&record, Some(DeviceId::new_v7())),
            Err(AuthError::DeviceMismatch)
        ));
        assert!(matches!(check_device_binding(&record, None), Err(AuthError::DeviceMismatch)));

        record.device_id = None;
        check_device_binding(&record, None).expect("an unbound family imposes no constraint");
    }

    #[tokio::test]
    async fn end_to_end_password_to_verified_request_context() {
        // The M0 exit criterion in miniature, minus the database: password → tokens → verified
        // claims → the context the policy chain runs against.
        let now = Utc::now();
        let hasher = PasswordHasher::new(PasswordPolicy {
            argon2: Argon2Params { memory_kib: 1024, iterations: 1, parallelism: 1 },
            ..PasswordPolicy::default()
        })
        .expect("hasher");
        let stored = hasher.hash("correct horse battery staple").expect("hash");
        assert!(hasher.verify("correct horse battery staple", &stored).is_accepted());

        let svc = service(now);
        let user = UserId::new_v7();
        let pair =
            svc.issue_pair(&login(now, Actor::User(user), ClientType::Web)).await.expect("issue");

        let verified = verifier(&svc).verify(&pair.access_token, now).expect("verify");
        let ctx = verified.to_request_context(
            RequestId::new_v7(),
            NetworkContext::internal(),
            DevicePosture::Unknown,
        );

        assert_eq!(ctx.actor, Actor::User(user));
        assert_eq!(ctx.tenant_id, TenantId::from_uuid(pair.claims.tid));
        assert_eq!(ctx.session_id, Some(pair.session_id));
        assert!(ctx.has_scope("files:read"));
        assert!(!ctx.has_scope("admin:users"));
        assert_eq!(ctx.auth_time.timestamp(), now.timestamp());
    }
}
