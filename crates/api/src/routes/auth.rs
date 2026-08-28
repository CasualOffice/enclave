//! `/api/v1/auth/*` — the endpoints that produce a session, and the ones that end it.
//!
//! `docs/05-API.md §3` is authoritative for every shape here. `crates/auth` is authoritative for
//! every *decision*: this module verifies no password, rotates no refresh token and revokes no
//! family itself. It is transport — parse, call, render, set a cookie — and the value of writing it
//! that way is that the properties `crates/auth`'s tests already hold (K3, K4, K9, K10) are not
//! re-implemented here where they could be weakened.
//!
//! # The tenant on an unauthenticated route
//!
//! `CLAUDE.md` rule 3: tenant identity comes from the verified token or from custom-domain routing,
//! never from the client. Login has no token — it is the endpoint that *makes* one — so the only
//! remaining source is the route. [`RoutedTenant`] is that source, and it is an **extractor** on
//! purpose rather than a line inside the handler: the handler receives a [`TenantId`] it did not
//! choose and has no other one in scope, so "read the tenant out of the body" is not a shortcut
//! somebody can take under time pressure. It is unwritable.
//!
//! The body carries `email` and `password` and nothing else that could steer tenancy. There is no
//! `tenantId` field, no `tenantSlug` field, and adding one would be a security defect rather than a
//! convenience: a caller who could name their own tenant could enumerate which tenants a given
//! email exists in.
//!
//! # Why `login`, `mfa_verify` and `refresh` are on the policy-routing allowlist
//!
//! `xtask policy-routing` proves every handler reaches `PolicyEngine::enforce`. These three do not,
//! and the allowlist carries the reason in the CI log where a reviewer meets it: the chain's second
//! stage is *authentication*, and it presupposes a verified principal. These are the endpoints that
//! produce one. Their controls are Argon2id verification, refresh rotation with reuse detection,
//! and single-use MFA challenges — token-lifecycle controls, not resource-authorization ones.
//!
//! **Everything else here is authenticated and goes through the chain**: `logout`, `logout_all`,
//! `sessions` and `revoke_session` all call `enforce` before they touch anything, and the chain
//! writes their audit row whether it allows or denies.
//!
//! # What never enters a log, an error message or a `Debug`
//!
//! `CLAUDE.md` rule 10. The password, the MFA code, the refresh token and the CSRF token are each
//! held in a type whose [`fmt::Debug`] prints a fixed marker ([`Secret`]), or in `crates/auth`'s
//! own [`RefreshToken`], which does the same. No handler here logs a request body, and no refusal
//! interpolates a credential into its message — `Envelope`'s three prose fields are `&'static str`,
//! so the compiler holds that half.
//!
//! # User enumeration
//!
//! An unknown email and a wrong password must be indistinguishable, in the body **and** in the
//! time taken. `crates/auth` already provides the second half:
//! [`PasswordHasher::verify_absent`] performs a full Argon2 verification against a dummy hash so
//! that the no-such-user branch costs what the wrong-password branch costs. This module's job is
//! not to undo that — [`verify_password`] is the single branch point, and both arms end in the same
//! [`invalid_credentials`] envelope.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use enclave_auth::{
    AuthContext, AuthError, AuthMethod, PasswordHasher, PasswordVerdict, RefreshCookieConfig,
    RefreshToken, RevokeReason, TokenPair, TokenService,
};
use enclave_core::{
    Action, Actor, ClientType, ContainerAction, Dependency, DeviceId, Error, ReasonCode,
    RequestContext, RequestId, ResourceRef, ScopeSet, SessionId, TenantId, UserId,
};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action the session-management routes ask the chain about.
///
/// Reading your own sessions is a self-read of your own principal, which is the one thing
/// `enclave_authorization::SelfServiceAuthorization` allows today.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// The action the three revocation routes ask the chain about.
///
/// `Delete` against the caller's own `User` resource, because there is no `ResourceKind::Session`
/// and inventing one means changing `enclave_core::Action`, which by design breaks every exhaustive
/// match in every policy service (`ENC-689` is that piece of work). What is asked is therefore
/// *"may this principal destroy something of its own?"*, and `SelfServiceAuthorization` answers it
/// for exactly one resource — itself.
const END_OWN_SESSION: Action = Action::Container(ContainerAction::Delete);

/// The name of the double-submit CSRF cookie (`docs/03-LLD.md §5.3` rule 5).
const CSRF_COOKIE: &str = "enclave_csrf";

/// The header the SPA echoes the CSRF cookie back in.
const CSRF_HEADER: &str = "x-csrf-token";

/// How long an MFA challenge stays usable. `docs/05-API.md §3.1`: five minutes, single use.
const CHALLENGE_TTL_SECS: i64 = 300;

// ---------------------------------------------------------------------------------------------
// Secrets in transit
// ---------------------------------------------------------------------------------------------

/// A credential arriving in a request body.
///
/// Exists for one reason: `#[derive(Debug)]` on a request struct is a reflex, and a struct holding
/// a `String` password renders that password into whatever the reflex printed it into. This type
/// makes the reflex safe — deriving `Debug` on a body that holds one prints `Secret([redacted])`,
/// and there is no `Display` and no `Serialize`, so it cannot reach a response either.
///
/// It is deliberately *not* the place to put zeroization. `crates/auth`'s [`RefreshToken`] does
/// that for the value it owns; a password read out of a JSON body has already been copied by the
/// deserializer and the buffer behind it is not ours to clear, so promising otherwise here would be
/// a comment that is not true rather than a control.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Secret {
    /// The value, at the one point it has to be used.
    fn expose(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------------------------
// The surface's collaborators
// ---------------------------------------------------------------------------------------------

/// Verifies a second factor.
///
/// A trait rather than an implementation because the factor itself is not this crate's to hold: a
/// TOTP shared secret is a `secret_ref` in `user_mfa_methods` and resolving it is the secret
/// provider's job, and a WebAuthn assertion needs the credential's public key and a challenge
/// round-trip. `ENC-688` is that work. What matters for the *surface* is that the challenge
/// lifecycle — issued on `MFA_REQUIRED`, single use, five minutes — is real now, so the shape the
/// web shell is written against is the shape it will keep.
#[async_trait::async_trait]
pub trait MfaVerifier: Send + Sync + fmt::Debug {
    /// Whether this code completes this challenge for this principal.
    ///
    /// Returning `Ok(false)` is a wrong code. An `Err` is an infrastructure failure and must not be
    /// reported to the caller as a wrong code, because a caller who can tell the two apart can
    /// probe for which accounts have which methods enrolled.
    ///
    /// # Errors
    ///
    /// [`AuthError`] for a verifier that could not reach what it needed.
    async fn verify(
        &self,
        tenant_id: TenantId,
        subject: UserId,
        method: MfaMethod,
        code: &str,
    ) -> Result<bool, AuthError>;
}

/// The verifier a deployment has when it has configured none.
///
/// Refuses every code. Named for what it does, so that wiring it is a visible choice — the same
/// treatment [`crate::Delivery::unconfigured`] gets, and for the same reason: a deployment that
/// cannot check a second factor must not look like one that checked and was satisfied.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableMfa;

#[async_trait::async_trait]
impl MfaVerifier for UnavailableMfa {
    async fn verify(
        &self,
        _tenant_id: TenantId,
        _subject: UserId,
        _method: MfaMethod,
        _code: &str,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }
}

/// The second factors `user_mfa_methods.kind` can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MfaMethod {
    /// A time-based one-time code.
    Totp,
    /// A passkey.
    Webauthn,
    /// A single-use recovery code.
    RecoveryCode,
}

impl MfaMethod {
    /// Decodes the stored `kind`. Unknown values are dropped rather than erroring: a method this
    /// build does not understand is one it cannot offer, and refusing the whole login because a
    /// newer release enrolled a factor would lock the user out of the older replica.
    fn from_kind(kind: &str) -> Option<Self> {
        match kind {
            "TOTP" => Some(Self::Totp),
            "WEBAUTHN" => Some(Self::Webauthn),
            "RECOVERY_CODE" => Some(Self::RecoveryCode),
            _ => None,
        }
    }

    /// The `amr` value a successful use of this method contributes.
    const fn auth_method(self) -> AuthMethod {
        match self {
            Self::Totp => AuthMethod::Totp,
            Self::Webauthn => AuthMethod::Webauthn,
            Self::RecoveryCode => AuthMethod::RecoveryCode,
        }
    }
}

/// An outstanding `MFA_REQUIRED` challenge.
#[derive(Debug, Clone)]
struct Challenge {
    tenant_id: TenantId,
    subject: UserId,
    device_id: Option<DeviceId>,
    methods: Vec<MfaMethod>,
    expires_at: DateTime<Utc>,
}

/// The outstanding challenges, in process memory.
///
/// # The limitation, stated where it will be read
///
/// This is per-replica. A challenge issued by one replica cannot be completed on another, so a
/// deployment behind a load balancer without session affinity will fail some `mfa/verify` calls
/// with `MFA_CHALLENGE_INVALID` and the user will be asked to sign in again. That is the *safe*
/// direction — a challenge is never accepted where it was not issued — and it is why the failure is
/// a refusal rather than a fallback. `ENC-687` moves it to the shared store, alongside the
/// refresh-token store, which has the same property for the same reason.
///
/// A `Mutex` rather than an async lock: every operation is a map insert or a map remove with no
/// `await` inside the guard.
#[derive(Debug, Default)]
pub struct MfaChallenges {
    outstanding: Mutex<HashMap<Uuid, Challenge>>,
}

impl MfaChallenges {
    /// Records a challenge and returns its id.
    fn issue(&self, challenge: Challenge) -> Uuid {
        let id = Uuid::new_v4();
        let mut outstanding = self.lock();
        // Opportunistic sweep. There is no reaper task, and a map that only ever grows is a slow
        // leak on the one endpoint an attacker can call without credentials.
        let now = Utc::now();
        outstanding.retain(|_, held| held.expires_at > now);
        outstanding.insert(id, challenge);
        id
    }

    /// Takes a challenge, removing it. Single use is this removal, not a flag: a consumed challenge
    /// that stayed in the map would be one edit away from being replayable.
    fn take(&self, id: Uuid) -> Option<Challenge> {
        let challenge = self.lock().remove(&id)?;
        (challenge.expires_at > Utc::now()).then_some(challenge)
    }

    /// The map, recovering from a poisoned lock.
    ///
    /// A panic in a handler while this is held would otherwise make every subsequent MFA login fail
    /// for the life of the process. Nothing in the guarded section can leave the map inconsistent —
    /// it is one insert or one remove — so the contents are still trustworthy.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Challenge>> {
        self.outstanding.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What the authentication routes need, and cannot be registered without.
///
/// The same argument [`crate::Delivery`] makes for the delivery routes: a route whose dependency
/// nobody supplies must not be able to answer `500`. It is held on [`ApiState`] rather than passed
/// to `router()` because two other route groups are being added to that signature concurrently;
/// what keeps the `ENC-170` shape away is [`AuthSurface::unconfigured`] — a deployment without a
/// token service gets a documented `503` it was warned about at start-up, not an unexplained error.
#[derive(Clone)]
pub struct AuthSurface {
    /// Issues, rotates and revokes. Everything security-relevant happens behind this.
    tokens: Arc<dyn TokenService>,
    /// Argon2id verification, including the constant-cost absent-user path.
    passwords: Arc<PasswordHasher>,
    /// The refresh cookie's name and path. Its security attributes are not configurable — see
    /// `enclave_auth::cookie`.
    cookie: RefreshCookieConfig,
    /// `Max-Age` for the refresh cookie: the sliding refresh lifetime, so a browser drops a cookie
    /// the server would refuse anyway.
    refresh_max_age: Duration,
    /// The second-factor verifier.
    mfa: Arc<dyn MfaVerifier>,
    /// Outstanding `MFA_REQUIRED` challenges.
    challenges: Arc<MfaChallenges>,
    /// Whether a real token service was wired. See [`AuthSurface::unconfigured`].
    configured: bool,
}

impl fmt::Debug for AuthSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No hasher parameters, no cookie value, no key material.
        f.debug_struct("AuthSurface").field("configured", &self.configured).finish_non_exhaustive()
    }
}

impl AuthSurface {
    /// Assembles the surface a deployment that can sign users in actually has.
    #[must_use]
    pub fn new(
        tokens: Arc<dyn TokenService>,
        passwords: PasswordHasher,
        cookie: RefreshCookieConfig,
        refresh_max_age: Duration,
    ) -> Self {
        Self {
            tokens,
            passwords: Arc::new(passwords),
            cookie,
            refresh_max_age,
            mfa: Arc::new(UnavailableMfa),
            challenges: Arc::new(MfaChallenges::default()),
            configured: true,
        }
    }

    /// Supplies the second-factor verifier.
    #[must_use]
    pub fn with_mfa(mut self, mfa: Arc<dyn MfaVerifier>) -> Self {
        self.mfa = mfa;
        self
    }

    /// The surface a deployment has when it has wired no token service.
    ///
    /// Every route still registers and every route refuses with `503 DEPENDENCY_UNAVAILABLE`. That
    /// is the honest answer — the deployment genuinely cannot authenticate anyone — and it is
    /// distinguishable from a wrong password, which is the property that matters: an operator
    /// reading `503` looks at their configuration, and one reading `401` looks at the user.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            tokens: Arc::new(UnavailableTokens),
            // The default policy is only ever used to reject: `verify_absent` runs the same Argon2
            // cost as a real verification, so even the unconfigured surface does not answer faster
            // for an unknown user than for a known one.
            passwords: Arc::new(
                PasswordHasher::new(enclave_auth::PasswordPolicy::default())
                    .unwrap_or_else(|_| unreachable!("the default password policy is valid")),
            ),
            cookie: RefreshCookieConfig::default(),
            refresh_max_age: Duration::days(14),
            mfa: Arc::new(UnavailableMfa),
            challenges: Arc::new(MfaChallenges::default()),
            configured: false,
        }
    }

    /// Whether this deployment can sign anyone in, for the start-up banner.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.configured
    }
}

/// The failure an unconfigured deployment reports.
///
/// `Configuration` rather than `InvalidCredentials`, and that choice is the whole point of the
/// type: `AuthError::is_authentication_failure` answers `false` for it, so it can never render as a
/// `401` that an operator would read as "the user typed the wrong password".
const UNCONFIGURED: AuthError = AuthError::Configuration(
    "no authentication surface is wired; ApiState::with_auth was never called",
);

/// The token service an unconfigured deployment has.
///
/// Every method fails with a configuration fault rather than a credential rejection, so the refusal
/// renders as `503` and never as `401`.
#[derive(Debug, Clone, Copy)]
struct UnavailableTokens;

#[async_trait::async_trait]
impl TokenService for UnavailableTokens {
    async fn issue_pair(&self, _ctx: &AuthContext) -> Result<TokenPair, AuthError> {
        Err(UNCONFIGURED)
    }

    async fn refresh(
        &self,
        _presented: &RefreshToken,
        _network: &enclave_core::NetworkContext,
    ) -> Result<TokenPair, AuthError> {
        Err(UNCONFIGURED)
    }

    async fn revoke_family(
        &self,
        _session_id: SessionId,
        _reason: RevokeReason,
    ) -> Result<(), AuthError> {
        Err(UNCONFIGURED)
    }

    async fn revoke_all_for_user(
        &self,
        _user: UserId,
        _reason: RevokeReason,
    ) -> Result<(), AuthError> {
        Err(UNCONFIGURED)
    }
}

// ---------------------------------------------------------------------------------------------
// The tenant, on a route with no token
// ---------------------------------------------------------------------------------------------

/// The tenant the request was **routed** to.
///
/// The whole of `CLAUDE.md` rule 3 for the unauthenticated endpoints, expressed as a type. The
/// value comes from `enclave_db::resolve_routed_tenant`, which reads the routed authority and
/// nothing else; a handler holding one of these has no other tenant in scope and no way to obtain
/// one from the body it is about to parse.
///
/// A host that routes no tenant is a `404`, not a `400`. `docs/05-API.md §5` makes cross-tenant and
/// absent deliberately indistinguishable, and "this hostname serves no tenant" is exactly the
/// question a `400` would answer for an attacker sweeping hostnames.
#[derive(Debug, Clone, Copy)]
pub struct RoutedTenant(pub TenantId);

impl FromRequestParts<ApiState> for RoutedTenant {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = RequestId::new_v7();
        let host = routed_host(parts).unwrap_or_default();

        match enclave_db::resolve_routed_tenant(&state.db, host).await {
            Ok(Some(tenant_id)) => Ok(Self(tenant_id)),
            Ok(None) => Err(ApiError::new(Error::NotFound, request_id)),
            Err(error) => Err(ApiError::new(error.into(), request_id)),
        }
    }
}

/// The authority a request was addressed to.
///
/// `Host` for HTTP/1.1, the `:authority` pseudo-header for HTTP/2 — which axum surfaces as the
/// URI's authority. Both are read; neither is taken from the body.
///
/// `X-Forwarded-Host` is deliberately **not** read. `crates/api/src/edge.rs` establishes what this
/// deployment believes from a proxy about a request's *network origin*, and it believes nothing
/// unless a trusted proxy is configured. A forwarded host would be a second, unconfigured trust
/// decision — and this one selects a tenant, so getting it wrong is a tenancy takeover rather than
/// a wrong IP in an audit row. A deployment behind a proxy must preserve `Host`, which is the
/// default for every reverse proxy in common use.
fn routed_host(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| parts.uri.host())
}

/// A verified caller whose token agrees with the host the request was routed to.
///
/// `docs/03-LLD.md §5.2`: *"`tid` — tenant. Mismatch with the routed custom domain is a hard
/// `401`."* That is leakage-matrix row T6, and this is where it is enforced today.
///
/// # Why the check is conditional on the host routing anything
///
/// A deployment reached at `localhost` or through an internal load-balancer address has not routed
/// a tenant at all, and there is nothing to disagree with — the token's `tid` is then the only
/// source, which is the other half of rule 3 and entirely legitimate. So the rule is: *if* the host
/// names a tenant and the token names a different one, refuse. It is not a hole an attacker gains
/// anything from — sending `Host: localhost` yields the tenant their own token already named.
///
/// # Why it is here rather than in `crate::auth::Authenticated`
///
/// It belongs there, and `ENC-689` is the row for moving it. It is not there yet because that
/// extractor serves every route in the crate, the check needs a database round-trip on the
/// platform connection, and the two other route groups landing beside this one build their test
/// requests without a `Host` header. Enforcing it globally in this change would refuse them.
#[derive(Debug, Clone)]
pub struct AuthenticatedHere {
    /// The context the policy chain runs against.
    pub ctx: RequestContext,
}

impl FromRequestParts<ApiState> for AuthenticatedHere {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let Authenticated { ctx } = Authenticated::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let host = routed_host(parts).unwrap_or_default();
        match enclave_db::resolve_routed_tenant(&state.db, host).await {
            Ok(Some(routed)) if routed != ctx.tenant_id => {
                // Not "the token is for tenant X and you asked for tenant Y" — that sentence
                // confirms both tenants exist to anyone holding one valid token.
                tracing::warn!(
                    request_id = %ctx.request_id,
                    "an access token was presented on a host routed to a different tenant"
                );
                Err(tenant_mismatch().into_response(ctx.request_id))
            }
            Ok(_) => Ok(Self { ctx }),
            Err(error) => Err(ApiError::new(error.into(), ctx.request_id).into_response()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Wire shapes — `docs/05-API.md §3`
// ---------------------------------------------------------------------------------------------

/// `POST /api/v1/auth/login`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    /// The address typed into the sign-in form.
    email: String,
    /// The password. See [`Secret`].
    password: Secret,
    /// The client's own device identifier, where it has one. An assertion, not proof: it is
    /// recorded on the refresh family and checked on rotation (`docs/03-LLD.md §5.3` rule 4), and
    /// it grants nothing on its own.
    #[serde(default)]
    device_id: Option<Uuid>,
}

/// `POST /api/v1/auth/mfa/verify`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaVerifyRequest {
    /// The `challengeId` from the `MFA_REQUIRED` refusal.
    challenge_id: Uuid,
    /// The factor being presented. Defaults to the first method the challenge offered.
    #[serde(default)]
    method: Option<MfaMethod>,
    /// The one-time code. A credential — see [`Secret`].
    code: Secret,
}

/// The body `docs/05-API.md §3.1` specifies, and `§3.2` reuses.
///
/// **The refresh token is not a field here and must never become one.** It leaves the server in a
/// `Set-Cookie` header, `HttpOnly`, so that no script in the SPA can read it. A response body is
/// readable by every script on the page, which is the entire attack `HttpOnly` exists to stop.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    session_id: String,
    user: UserSummary,
}

/// The caller, as the sign-in screen needs to render them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSummary {
    id: String,
    display_name: String,
    is_admin: bool,
}

/// One active refresh family, for `GET /api/v1/auth/sessions`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    /// Whether this is the family the calling token belongs to, so a client can label it and
    /// refuse to end it by accident.
    current: bool,
}

/// The `docs/05-API.md §6` envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionList {
    items: Vec<SessionSummary>,
    page: Page,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    next_cursor: Option<String>,
    has_more: bool,
    limit: usize,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/auth/login`.
///
/// On the policy-routing allowlist: this is the endpoint the chain's authentication stage
/// presupposes. See the module documentation.
///
/// # Errors
///
/// [`ApiError`] for a storage failure or a host that routes no tenant. A wrong credential is an
/// `Ok(401)` rather than an `Err`, because `enclave_core::Error` has no variant that renders `401`
/// — every authentication failure in it is a `PolicyDenied`, which is a `403`, and a `403` on a
/// login form tells the caller that the account exists and something else refused.
pub async fn login(
    State(state): State<ApiState>,
    RoutedTenant(tenant_id): RoutedTenant,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let request_id = RequestId::new_v7();
    let surface = state.auth.clone();

    let normalized = enclave_identity::normalize_email(&body.email);
    let account = load_account(&state, tenant_id, &normalized, request_id).await?;

    // One branch point, and both arms cost the same Argon2 verification. Splitting it — an early
    // return for "no such user" — is the change that turns this endpoint into an enumeration
    // oracle, and it is the change that looks like a harmless tidy-up in review.
    let verdict = verify_password(&surface.passwords, account.as_ref(), body.password.expose());
    if !verdict.is_accepted() {
        if let Some(account) = &account {
            record_failed_attempt(&state, tenant_id, account.id, request_id).await?;
        }
        return Ok(invalid_credentials().into_response(request_id));
    }
    // `verify_password` returns `Rejected` for a `None` account, so reaching here with one would be
    // a hasher that accepted an absent credential. Refusing rather than unwrapping keeps that
    // impossible case a refusal instead of a panic on the login path.
    let Some(account) = account else {
        return Ok(invalid_credentials().into_response(request_id));
    };

    let device_id = body.device_id.map(DeviceId::from_uuid);
    let methods = enrolled_mfa(&state, tenant_id, account.id, request_id).await?;
    if !methods.is_empty() {
        let challenge_id = surface.challenges.issue(Challenge {
            tenant_id,
            subject: account.id,
            device_id,
            methods: methods.clone(),
            expires_at: Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS),
        });
        return Ok(mfa_required(challenge_id, &methods).into_response(request_id));
    }

    record_successful_login(&state, tenant_id, account.id, request_id).await?;
    issue(&state, tenant_id, &account, device_id, vec![AuthMethod::Pwd], request_id).await
}

/// Handles `POST /api/v1/auth/mfa/verify` — the completion of an `MFA_REQUIRED` challenge.
///
/// On the policy-routing allowlist for `login`'s reason: it is the second half of one credential
/// exchange, and the token it produces is the first verified principal in the request's life.
///
/// # Errors
///
/// [`ApiError`] for a storage failure. A bad code or a spent challenge is an `Ok(401)` — see
/// [`login`].
pub async fn mfa_verify(
    State(state): State<ApiState>,
    RoutedTenant(tenant_id): RoutedTenant,
    Json(body): Json<MfaVerifyRequest>,
) -> Result<Response, ApiError> {
    let request_id = RequestId::new_v7();
    let surface = state.auth.clone();

    // Taken, not read: the challenge is spent whether or not the code is right, so a challenge is
    // one attempt rather than a five-minute window to guess six digits in.
    let Some(challenge) = surface.challenges.take(body.challenge_id) else {
        return Ok(invalid_credentials().into_response(request_id));
    };

    // A challenge issued on one tenant's host and presented on another's is not a near miss.
    if challenge.tenant_id != tenant_id {
        tracing::warn!(%request_id, "an MFA challenge was presented on another tenant's host");
        return Ok(invalid_credentials().into_response(request_id));
    }

    let method = body.method.unwrap_or(challenge.methods[0]);
    if !challenge.methods.contains(&method) {
        return Ok(invalid_credentials().into_response(request_id));
    }

    let accepted = surface
        .mfa
        .verify(tenant_id, challenge.subject, method, body.code.expose())
        .await
        .map_err(|error| ApiError::new(unavailable(&error), request_id))?;
    if !accepted {
        return Ok(invalid_credentials().into_response(request_id));
    }

    // Re-read rather than carried on the challenge: five minutes is long enough for an
    // administrator to suspend the account between the password and the code, and a challenge that
    // carried the account's state would authenticate the state as it was.
    let account = load_account_by_id(&state, tenant_id, challenge.subject, request_id).await?;
    let Some(account) = account else {
        return Ok(invalid_credentials().into_response(request_id));
    };

    record_successful_login(&state, tenant_id, account.id, request_id).await?;
    issue(
        &state,
        tenant_id,
        &account,
        challenge.device_id,
        vec![AuthMethod::Pwd, method.auth_method()],
        request_id,
    )
    .await
}

/// Handles `POST /api/v1/auth/refresh` — rotation, per `docs/05-API.md §3.2`.
///
/// On the policy-routing allowlist. Reuse detection is a token-lifecycle control, and the
/// conditional-access re-evaluation `docs/03-LLD.md §5.3` rule 3 requires happens *inside*
/// `TokenService::refresh`, through the `RefreshGuard` the binary wires — which is why this handler
/// does not call the chain and the property is not lost.
///
/// # Errors
///
/// [`ApiError`] when the refresh is refused by conditional access (`403`) or a store is unavailable
/// (`503`). A missing, unknown or replayed token is an `Ok(401)`.
pub async fn refresh(
    State(state): State<ApiState>,
    parts: RefreshParts,
) -> Result<Response, ApiError> {
    let request_id = RequestId::new_v7();
    let surface = state.auth.clone();

    // Double submit (`docs/03-LLD.md §5.3` rule 5). `SameSite=Strict` on the refresh cookie is the
    // first layer and this is the second; a cross-site caller can cause the cookie to be sent in
    // some browser-and-navigation combinations, but cannot read it, so it cannot echo it back in a
    // header it controls.
    let Some(presented_csrf) = parts.csrf_header.as_deref() else {
        return Ok(csrf_missing().into_response(request_id));
    };
    let Some(cookie_csrf) = parts.csrf_cookie.as_deref() else {
        return Ok(csrf_missing().into_response(request_id));
    };
    if !constant_time_eq(presented_csrf.as_bytes(), cookie_csrf.as_bytes()) {
        return Ok(csrf_missing().into_response(request_id));
    }

    let Some(cookie) = parts.refresh_cookie.as_deref() else {
        return Ok(no_refresh_token().into_response(request_id));
    };
    let Ok(token) = RefreshToken::parse(cookie) else {
        // Deliberately identical to an unknown token. `RefreshToken::parse` refuses on length, and
        // a distinguishable "malformed" answer tells an attacker their guesses are the right shape.
        return Ok(no_refresh_token().into_response(request_id));
    };

    match surface.tokens.refresh(&token, &parts.network).await {
        Ok(pair) => Ok(session_response(&surface, pair, parts.user, request_id)),
        Err(AuthError::SessionReplay) => {
            // The family is already revoked by the time this arrives — `TokenService::refresh`
            // does that before returning, which is why the response can safely name the reason.
            Ok(session_replay().into_response(request_id))
        }
        Err(error) if error.is_authentication_failure() => {
            Ok(no_refresh_token().into_response(request_id))
        }
        Err(error) => Err(ApiError::new(refresh_failure(&error), request_id)),
    }
}

/// Handles `POST /api/v1/auth/logout`.
///
/// Revokes the presented token's family and clears both cookies. Authenticated, and therefore
/// through the chain: a logout is audited, and the row is the chain's.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an actor with no subject, or a store failure.
pub async fn logout(
    State(state): State<ApiState>,
    AuthenticatedHere { ctx }: AuthenticatedHere,
) -> Result<Response, ApiError> {
    let (_subject, resource) = self_target(&state, &ctx, END_OWN_SESSION).await?;
    enforce_self(&state, &ctx, END_OWN_SESSION, &resource).await?;

    // A token with no `sid` cannot name a family. Service accounts have no refresh token at all
    // (`docs/03-LLD.md §5.6`), so there is nothing to revoke and clearing the cookie is the whole
    // of what logout means for them.
    if let Some(session_id) = ctx.session_id {
        state
            .auth
            .tokens
            .revoke_family(session_id, RevokeReason::Logout)
            .await
            .map_err(|error| ApiError::new(unavailable(&error), ctx.request_id))?;
    }

    Ok(cleared(&state.auth, StatusCode::NO_CONTENT))
}

/// Handles `POST /api/v1/auth/logout-all`.
///
/// Revokes every family **and** bumps `users.token_epoch`. Both, because they invalidate different
/// things: revoking the families stops any further refresh, and the epoch bump is the only
/// mechanism that reaches the access tokens already issued (`docs/03-LLD.md §5.4`). Doing one
/// without the other leaves a signed-out user with up to ten minutes of live API access.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an actor with no subject, or a store failure.
pub async fn logout_all(
    State(state): State<ApiState>,
    AuthenticatedHere { ctx }: AuthenticatedHere,
) -> Result<Response, ApiError> {
    let (subject, resource) = self_target(&state, &ctx, END_OWN_SESSION).await?;
    enforce_self(&state, &ctx, END_OWN_SESSION, &resource).await?;

    state
        .auth
        .tokens
        .revoke_all_for_user(UserId::from_uuid(subject), RevokeReason::LogoutAll)
        .await
        .map_err(|error| ApiError::new(unavailable(&error), ctx.request_id))?;

    bump_token_epoch(&state, &ctx, subject).await?;

    Ok(cleared(&state.auth, StatusCode::NO_CONTENT))
}

/// Handles `GET /api/v1/auth/sessions`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an actor with no subject, or a storage failure.
pub async fn sessions(
    State(state): State<ApiState>,
    AuthenticatedHere { ctx }: AuthenticatedHere,
) -> Result<Json<SessionList>, ApiError> {
    let (subject, resource) = self_target(&state, &ctx, READ_SELF).await?;
    enforce_self(&state, &ctx, READ_SELF, &resource).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;

    // The tenant predicate is there as well as row-level security: two layers, per
    // `docs/04-DATA-MODEL.md §3`. `actor_id` is the caller's own subject and comes from the
    // verified token, never from a parameter — there is no "whose sessions" input to this endpoint.
    let rows = sqlx::query(SELECT_ACTIVE_FAMILIES)
        .bind(ctx.tenant_id.as_uuid())
        .bind(subject)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), ctx.request_id)
        })?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), ctx.request_id))?;

    let current = ctx.session_id.map(|id| id.as_uuid());
    let mut items: Vec<SessionSummary> = rows
        .iter()
        .map(|row| {
            let id: Uuid = row.get("session_id");
            SessionSummary {
                id: id.to_string(),
                device_id: row.get::<Option<Uuid>, _>("device_id").map(|id| id.to_string()),
                client: row.get("client_type"),
                ip: row.get("ip"),
                user_agent: row.get("user_agent"),
                issued_at: row.get("issued_at"),
                expires_at: row.get("expires_at"),
                current: current == Some(id),
            }
        })
        .collect();
    items.sort_by_key(|item| std::cmp::Reverse(item.issued_at));

    // No cursor. A principal's live refresh families are bounded by how many devices they signed in
    // on, and the query already caps the result; a cursor here would be pagination machinery for a
    // list that cannot reach a second page. The envelope is `docs/05-API.md §6`'s so that a client
    // reading it does not need a special case.
    let limit = items.len();
    Ok(Json(SessionList { items, page: Page { next_cursor: None, has_more: false, limit } }))
}

/// Handles `DELETE /api/v1/auth/sessions/{sid}`.
///
/// # The ownership check that has to come first
///
/// `TokenService::revoke_family` takes a `sid` and no tenant — deliberately, so that a caller
/// cannot supply one (`crates/auth/src/service.rs`). It resolves the tenant *from the stored
/// family*, which means calling it with a `sid` from the path and nothing else would let any
/// authenticated caller end any session in any tenant. So the family is looked up in the caller's
/// own tenant-scoped transaction first, and a family that is not theirs is a `404` — never a `403`,
/// which would confirm that the session id exists (`CLAUDE.md` rule 7).
///
/// # Errors
///
/// [`ApiError`] for a policy denial, a family that is not the caller's, or a store failure.
pub async fn revoke_session(
    State(state): State<ApiState>,
    AuthenticatedHere { ctx }: AuthenticatedHere,
    Path(sid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let (subject, resource) = self_target(&state, &ctx, END_OWN_SESSION).await?;
    enforce_self(&state, &ctx, END_OWN_SESSION, &resource).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    let owned: Option<Uuid> = sqlx::query_scalar(SELECT_OWN_FAMILY)
        .bind(ctx.tenant_id.as_uuid())
        .bind(subject)
        .bind(sid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), ctx.request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), ctx.request_id))?;

    if owned.is_none() {
        return Err(ApiError::new(Error::NotFound, ctx.request_id));
    }

    state
        .auth
        .tokens
        .revoke_family(SessionId::from_uuid(sid), RevokeReason::Logout)
        .await
        .map_err(|error| ApiError::new(unavailable(&error), ctx.request_id))?;

    // Ending the session you are calling from is a logout, so the cookies go with it.
    if ctx.session_id.map(|id| id.as_uuid()) == Some(sid) {
        return Ok(cleared(&state.auth, StatusCode::NO_CONTENT));
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------------------------------------
// The chain, and the pieces the handlers share
// ---------------------------------------------------------------------------------------------

/// The caller's own subject and the resource that stands for it.
///
/// Returns a [`Refused`] rather than an [`ApiError`] for the reason `crates/api/src/me.rs` gives:
/// a refusal constructed in a function that returns one is *audited by construction*, because the
/// only thing that turns it into a response is [`HandlerAudit::refuse`], which writes the row
/// first. `cargo run -p xtask -- audit-coverage` reads exactly that signature.
///
/// # Errors
///
/// [`Refused`] for [`Actor::System`], which has no `users` row and therefore no sessions. It is an
/// actor-eligibility refusal: nothing was attached to the request, the principal simply is not one
/// that can hold a session.
fn self_resource(ctx: &RequestContext) -> Result<(Uuid, ResourceRef), Refused> {
    let subject = ctx.actor.subject_id().ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))?;
    Ok((subject, ResourceRef::new(ctx.tenant_id, enclave_core::ResourceKind::User, subject)))
}

/// [`self_resource`], with the row written when it refuses.
///
/// The four handlers call this rather than the function above so that no call site can hold a
/// `Refused` and forget to record it — which the type already forbids, but a helper that does the
/// right thing once is a helper nobody has to get right four times.
///
/// # Errors
///
/// [`ApiError`] for a principal with no subject, after the refusal has been recorded.
async fn self_target(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
) -> Result<(Uuid, ResourceRef), ApiError> {
    match self_resource(ctx) {
        Ok(target) => Ok(target),
        Err(refused) => {
            // The tenant is the verified token's and the actor is `system`, so the row is
            // attributable; it stands alone because the chain never ran, which is accurate.
            let resource = ResourceRef::tenant(ctx.tenant_id);
            Err(state.audit.refuse(ctx, action, &resource, refused).await)
        }
    }
}

/// Runs the chain and consumes the decision.
///
/// Factored out because four handlers do exactly this and a fifth that quietly did not would be
/// invisible in review — the whole failure mode `xtask policy-routing` exists for, one level below
/// where it can see.
///
/// # Errors
///
/// [`ApiError`] for a denial, and for an obligation this surface cannot discharge: nothing here can
/// watermark a rendition or collect a justification, so an obligation arriving is a refusal
/// (`CLAUDE.md` rule 8, D29).
async fn enforce_self(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<(), ApiError> {
    let decision = state
        .policy
        .enforce(ctx, action, resource)
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;

    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(ctx, action, resource, refused).await);
    }
    Ok(())
}

/// What a login needs to know about the account it is authenticating.
#[derive(Debug, Clone)]
struct Account {
    id: UserId,
    display_name: String,
    is_admin: bool,
    token_epoch: i32,
    /// The stored Argon2 hash, if the account has a local password at all. `None` for an
    /// SSO-only account, and it must be indistinguishable from a wrong password — see
    /// [`verify_password`].
    password_hash: Option<String>,
}

/// Reads the account a login is about, or `None`.
///
/// `None` covers every reason a login cannot proceed that the caller must not be able to tell
/// apart: no such address, a soft-deleted user, a suspended or deprovisioned one, and an account
/// locked by [`record_failed_attempt`]'s counterpart. They differ enormously to an operator and not
/// at all to a caller.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn load_account(
    state: &ApiState,
    tenant_id: TenantId,
    normalized_email: &str,
    request_id: RequestId,
) -> Result<Option<Account>, ApiError> {
    let mut tx =
        state.db.begin(tenant_id).await.map_err(|error| ApiError::new(error.into(), request_id))?;
    let row = sqlx::query(SELECT_ACCOUNT_BY_EMAIL)
        .bind(tenant_id.as_uuid())
        .bind(normalized_email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    Ok(row.as_ref().map(account_from_row))
}

/// Re-reads an account between the password and the second factor.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn load_account_by_id(
    state: &ApiState,
    tenant_id: TenantId,
    subject: UserId,
    request_id: RequestId,
) -> Result<Option<Account>, ApiError> {
    let mut tx =
        state.db.begin(tenant_id).await.map_err(|error| ApiError::new(error.into(), request_id))?;
    let row = sqlx::query(SELECT_ACCOUNT_BY_ID)
        .bind(tenant_id.as_uuid())
        .bind(subject.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    Ok(row.as_ref().map(account_from_row))
}

fn account_from_row(row: &sqlx::postgres::PgRow) -> Account {
    Account {
        id: UserId::from_uuid(row.get("id")),
        display_name: row.get("display_name"),
        is_admin: row.get("is_admin"),
        token_epoch: row.get("token_epoch"),
        password_hash: row.get("password_hash"),
    }
}

/// The confirmed, unrevoked second factors an account holds.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn enrolled_mfa(
    state: &ApiState,
    tenant_id: TenantId,
    subject: UserId,
    request_id: RequestId,
) -> Result<Vec<MfaMethod>, ApiError> {
    let mut tx =
        state.db.begin(tenant_id).await.map_err(|error| ApiError::new(error.into(), request_id))?;
    let rows = sqlx::query(SELECT_ENROLLED_MFA)
        .bind(tenant_id.as_uuid())
        .bind(subject.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let mut methods: Vec<MfaMethod> =
        rows.iter().filter_map(|row| MfaMethod::from_kind(row.get("kind"))).collect();
    methods.dedup();
    Ok(methods)
}

/// Verifies the presented password against the stored hash, in constant cost.
///
/// The `None` arm is the whole point. `verify_absent` runs a real Argon2 verification against a
/// throwaway hash, so "no such user" and "wrong password" take the same time as well as returning
/// the same body. Collapsing this into `account.map_or(false, …)` removes the work and restores the
/// timing oracle, which is why it is a named function with this comment on it.
fn verify_password(
    hasher: &PasswordHasher,
    account: Option<&Account>,
    password: &str,
) -> PasswordVerdict {
    match account.and_then(|account| account.password_hash.as_deref()) {
        Some(stored) => hasher.verify(password, stored),
        None => hasher.verify_absent(password),
    }
}

/// Records a failed password attempt.
///
/// There is no lockout threshold here, and deliberately not: a threshold is a policy value, it
/// belongs beside the rest of the password policy in `enclave_auth::PasswordPolicy`, and inventing
/// one at the transport layer would put an account-lockout denial-of-service in a file nobody would
/// think to look in. What this does is keep the counter honest so that the threshold, when it
/// lands (`ENC-688`), has something to read.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn record_failed_attempt(
    state: &ApiState,
    tenant_id: TenantId,
    subject: UserId,
    request_id: RequestId,
) -> Result<(), ApiError> {
    let mut tx =
        state.db.begin(tenant_id).await.map_err(|error| ApiError::new(error.into(), request_id))?;
    sqlx::query(COUNT_FAILED_ATTEMPT)
        .bind(tenant_id.as_uuid())
        .bind(subject.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    Ok(())
}

/// Resets the failure counter and stamps `last_login_at`.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn record_successful_login(
    state: &ApiState,
    tenant_id: TenantId,
    subject: UserId,
    request_id: RequestId,
) -> Result<(), ApiError> {
    let mut tx =
        state.db.begin(tenant_id).await.map_err(|error| ApiError::new(error.into(), request_id))?;
    sqlx::query(CLEAR_FAILED_ATTEMPTS)
        .bind(tenant_id.as_uuid())
        .bind(subject.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    sqlx::query(STAMP_LAST_LOGIN)
        .bind(tenant_id.as_uuid())
        .bind(subject.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    Ok(())
}

/// Increments the mass-revocation counter, which is what reaches tokens already issued.
///
/// # Errors
///
/// [`ApiError`] for a storage failure.
async fn bump_token_epoch(
    state: &ApiState,
    ctx: &RequestContext,
    subject: Uuid,
) -> Result<(), ApiError> {
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    sqlx::query(BUMP_TOKEN_EPOCH)
        .bind(ctx.tenant_id.as_uuid())
        .bind(subject)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), ctx.request_id)
        })?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), ctx.request_id))?;
    Ok(())
}

/// Issues the pair and renders the `§3.1` response.
///
/// # Errors
///
/// [`ApiError`] when the key provider or a store is unavailable.
async fn issue(
    state: &ApiState,
    tenant_id: TenantId,
    account: &Account,
    device_id: Option<DeviceId>,
    methods: Vec<AuthMethod>,
    request_id: RequestId,
) -> Result<Response, ApiError> {
    let surface = state.auth.clone();
    let auth_ctx = AuthContext {
        tenant_id,
        actor: Actor::User(account.id),
        session_id: None,
        client: ClientType::Web,
        device_id,
        // No scopes. `scp` narrows what a caller may attempt and never widens it, and a session
        // that asserts none is a session the authorization stage decides entirely from the ACL —
        // which is the correct default until `ENC-126` gives scopes something to narrow.
        scopes: ScopeSet::empty(),
        methods,
        auth_time: Utc::now(),
        epoch: account.token_epoch,
        max_classification: None,
    };

    let pair = surface
        .tokens
        .issue_pair(&auth_ctx)
        .await
        .map_err(|error| ApiError::new(unavailable(&error), request_id))?;

    Ok(session_response(
        &surface,
        pair,
        Some(UserSummary {
            id: account.id.as_uuid().to_string(),
            display_name: account.display_name.clone(),
            is_admin: account.is_admin,
        }),
        request_id,
    ))
}

/// Renders a token pair as `docs/05-API.md §3.1`'s body plus its cookies.
///
/// The refresh token goes into a `Set-Cookie` and nowhere else. `SessionResponse` has no field it
/// could occupy, so this is structural rather than a habit — see that type.
fn session_response(
    surface: &AuthSurface,
    pair: TokenPair,
    user: Option<UserSummary>,
    request_id: RequestId,
) -> Response {
    let body = SessionResponse {
        access_token: pair.access_token,
        token_type: "Bearer",
        expires_in: pair.expires_in,
        session_id: pair.session_id.as_uuid().to_string(),
        user: user.unwrap_or(UserSummary {
            // A refresh knows the subject but has not read the directory, and re-reading it on
            // every rotation would put a query on the hot path to render a name the client already
            // has. `GET /api/v1/me` is where a client gets its user record.
            id: pair.claims.sub.to_string(),
            display_name: String::new(),
            is_admin: false,
        }),
    };

    let mut response = Json(body).into_response();
    let headers = response.headers_mut();
    // Never cached, anywhere. The body carries a bearer token.
    headers.insert(header::CACHE_CONTROL, crate::error::NO_STORE);
    if let Some(token) = &pair.refresh_token {
        append_cookie(headers, surface.cookie.set_cookie_header(token, surface.refresh_max_age));
        append_cookie(headers, csrf_cookie());
    }
    let _ = request_id;
    response
}

/// The response that ends a session: no content, and both cookies removed.
///
/// The clearing header carries the same `Path` and attributes as the setting one. A browser matches
/// a deletion on name, path and domain, so a clearing cookie that differs in `Path` leaves the
/// original in the jar and the user believes they logged out while the credential is still there.
fn cleared(surface: &AuthSurface, status: StatusCode) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, crate::error::NO_STORE);
    append_cookie(headers, surface.cookie.clearing_header());
    append_cookie(headers, format!("{CSRF_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Strict"));
    response
}

/// The double-submit CSRF cookie.
///
/// # Why this one is *not* `HttpOnly`
///
/// It is the one cookie here that the SPA has to read, because double-submit means echoing it back
/// in a header. That is safe precisely because it is **not a credential**: on its own it
/// authenticates nothing, and an attacker who can read it through XSS has already lost the page.
/// The refresh token, which *is* a credential, is `HttpOnly` and stays unreadable.
///
/// `Path=/` rather than `/api/v1/auth`, and that is forced rather than chosen: `document.cookie`
/// only exposes cookies whose path matches the document's, so a cookie scoped to the API path is
/// invisible to a SPA served from `/`. The refresh cookie keeps the narrow scope, which is where
/// the narrow scope earns anything.
///
/// 256 bits from two v4 UUIDs — `uuid`'s v4 draws from the operating system's CSPRNG, so this needs
/// no separate random-number dependency to be unguessable.
fn csrf_cookie() -> String {
    let value = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    format!("{CSRF_COOKIE}={value}; Path=/; Max-Age=1209600; Secure; SameSite=Strict")
}

/// Appends a `Set-Cookie` without replacing one already there.
///
/// `insert` would drop the refresh cookie when the CSRF cookie followed it, which is a bug that
/// looks like "the user is logged out at random".
fn append_cookie(headers: &mut axum::http::HeaderMap, value: String) {
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.append(header::SET_COOKIE, value);
    }
}

/// Compares two byte strings without an early return.
///
/// The CSRF value is unguessable and a cross-site attacker cannot read it, so the comparison is
/// what stands between them and forging a refresh. `==` on slices short-circuits at the first
/// differing byte; this does not.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in a.iter().zip(b.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Everything `refresh` needs off the request, gathered by one extractor.
///
/// An extractor rather than four arguments because the refresh endpoint takes **no body** — there
/// is nothing to deserialize, and a `Json<T>` that permitted a `refreshToken` field would be a
/// second way to present the credential, one that a cross-site form post can reach.
#[derive(Debug)]
pub struct RefreshParts {
    refresh_cookie: Option<String>,
    csrf_cookie: Option<String>,
    csrf_header: Option<String>,
    network: enclave_core::NetworkContext,
    user: Option<UserSummary>,
}

impl FromRequestParts<ApiState> for RefreshParts {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = parts.headers.get_all(header::COOKIE);
        let mut refresh_cookie = None;
        let mut csrf_cookie = None;
        for header in cookies {
            let Ok(header) = header.to_str() else { continue };
            refresh_cookie =
                refresh_cookie.or_else(|| cookie_value(header, &state.auth.cookie.name));
            csrf_cookie = csrf_cookie.or_else(|| cookie_value(header, CSRF_COOKIE));
        }

        Ok(Self {
            refresh_cookie,
            csrf_cookie,
            csrf_header: parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            // The network the refresh is being attempted from, so that conditional access can
            // refuse a session that has moved to a blocked zone (`docs/05-API.md §3.2`). It comes
            // from `Edge` — the one thing permitted to populate it — and never from the request.
            network: state.edge.network_context(parts),
            user: None,
        })
    }
}

/// One cookie's value out of a `Cookie` header.
fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

// ---------------------------------------------------------------------------------------------
// Refusals — `docs/05-API.md §5` envelopes for the statuses `Error` cannot express
// ---------------------------------------------------------------------------------------------

/// The one answer a bad credential ever gets.
///
/// Unknown address, wrong password, suspended account, no local password at all, spent MFA
/// challenge, wrong code — all of them, byte for byte apart from the request id. Each of those is a
/// different sentence in the operator's log and the same sentence to the caller, which is the point:
/// a login endpoint that distinguishes them is a directory-enumeration service.
fn invalid_credentials() -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "INVALID_CREDENTIALS",
        "That email address and password do not match an account.",
        "Check the address and password and try again, or reset your password.",
    )
}

/// `MFA_REQUIRED`, with the exact members `docs/05-API.md §3.1` shows.
fn mfa_required(challenge_id: Uuid, methods: &[MfaMethod]) -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "MFA_REQUIRED",
        "This account needs a second factor to sign in.",
        "Complete the challenge at /api/v1/auth/mfa/verify within five minutes.",
    )
    .with_member("challengeId", serde_json::json!(challenge_id.to_string()))
    .with_member("methods", serde_json::json!(methods))
}

/// `SESSION_REPLAY` — `docs/05-API.md §3.2`, `docs/03-LLD.md §5.3` rule 2.
///
/// Naming it is safe and useful: by the time this is rendered the family is already destroyed, so
/// the word tells a legitimate user why they were signed out and tells an attacker only that the
/// token they stole is now worthless.
fn session_replay() -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "SESSION_REPLAY",
        "Your session has ended for security reasons.",
        "Sign in again. If you did not expect this, contact your administrator.",
    )
}

/// A refresh with no usable cookie.
fn no_refresh_token() -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "SESSION_EXPIRED",
        "Your session has expired.",
        "Sign in again.",
    )
}

/// A refresh whose double-submit check failed.
///
/// Its own code rather than `SESSION_EXPIRED`, because the client's correct response differs: a
/// missing CSRF header is a bug in the caller and retrying the same request will fail identically,
/// whereas an expired session means sign in again. It reveals nothing — an attacker who can trigger
/// this already knows they have no CSRF token.
fn csrf_missing() -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "CSRF_TOKEN_INVALID",
        "This request could not be verified.",
        "Reload the application and try again.",
    )
}

/// A token presented on a host routed to a different tenant (`docs/03-LLD.md §5.2`, T6).
fn tenant_mismatch() -> Envelope {
    Envelope::new(
        StatusCode::UNAUTHORIZED,
        "TOKEN_NOT_VALID_HERE",
        "Your session is not valid on this address.",
        "Sign in again at your organisation's address.",
    )
}

/// Maps a token-service failure that is *not* a credential rejection.
///
/// Everything that reaches here is infrastructure: no signing key, an unreachable store. It renders
/// `503` with no detail about which dependency, because `docs/05-API.md §5` keeps our topology out
/// of error bodies — the variant goes to the log instead.
fn unavailable(error: &AuthError) -> Error {
    tracing::error!(?error, "the authentication surface could not complete an operation");
    Error::Upstream { dependency: Dependency::Postgres, retryable: true }
}

/// Maps a refresh failure that is neither replay nor an ordinary rejection.
///
/// `AuthError::ConditionalAccessDenied` is the one that must keep its own status: `docs/05-API.md
/// §3.2` promises `403 NETWORK_NOT_ALLOWED` for a client that has moved to a blocked network, and
/// rendering it as a `503` would tell the user to retry something policy will refuse forever. The
/// code it carries is the stage's own, unchanged, so a session refused for its device or its
/// authentication strength is told which — a caller who is told to change networks when the rule
/// was about a second factor cannot act on what they were told (`ENC-709`).
///
/// This function does **not** audit, and by the time it runs it does not need to: the refusal was
/// taken inside `PolicyEngine::reevaluate_conditional_access`, which recorded it against the tenant
/// the stored refresh family names. Everything else reaching here is infrastructure and is a
/// dependency failure rather than a decision about a caller — including a conditional-access
/// evaluation that could not be *completed*, which arrives as `StorageUnavailable` and renders
/// `503` rather than a denial nobody decided.
fn refresh_failure(error: &AuthError) -> Error {
    match error.reason_code() {
        Some(code) => Error::denied(code),
        None => unavailable(error),
    }
}

// ---------------------------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------------------------

/// The account a login is about, if it is one that may sign in.
///
/// The status filter is in the `WHERE` clause rather than in Rust on purpose: a row that comes back
/// and is then discarded is a row somebody can be tempted to use "just for the error message", and
/// the error message is the enumeration oracle.
const SELECT_ACCOUNT_BY_EMAIL: &str = "SELECT u.id, u.display_name, u.is_admin, u.token_epoch, \
     c.password_hash \
     FROM users u \
     LEFT JOIN user_credentials c ON c.tenant_id = u.tenant_id AND c.user_id = u.id \
     WHERE u.tenant_id = $1 AND u.normalized_email = $2 AND u.deleted_at IS NULL \
       AND u.status = 'ACTIVE' \
       AND (c.locked_until IS NULL OR c.locked_until <= now())";

/// The same account, by id, for the second half of an MFA login.
const SELECT_ACCOUNT_BY_ID: &str = "SELECT u.id, u.display_name, u.is_admin, u.token_epoch, \
     c.password_hash \
     FROM users u \
     LEFT JOIN user_credentials c ON c.tenant_id = u.tenant_id AND c.user_id = u.id \
     WHERE u.tenant_id = $1 AND u.id = $2 AND u.deleted_at IS NULL AND u.status = 'ACTIVE'";

/// The confirmed second factors an account holds.
const SELECT_ENROLLED_MFA: &str = "SELECT DISTINCT kind FROM user_mfa_methods \
     WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND confirmed_at IS NOT NULL \
     ORDER BY kind";

/// The caller's live refresh families, newest token per family.
///
/// `host(ip)` rather than the `inet` itself: the column is an address and the response field is a
/// string, and decoding `inet` would mean a feature flag on `sqlx` for a value that is rendered as
/// text either way.
const SELECT_ACTIVE_FAMILIES: &str = "SELECT DISTINCT ON (session_id) \
     session_id, device_id, client_type, host(ip) AS ip, user_agent, issued_at, expires_at \
     FROM refresh_tokens \
     WHERE tenant_id = $1 AND actor_id = $2 \
       AND revoked_at IS NULL AND consumed_at IS NULL \
       AND expires_at > now() AND absolute_expires_at > now() \
     ORDER BY session_id, issued_at DESC \
     LIMIT 500";

/// Whether a family is the caller's own. Returns the `session_id` or nothing; the caller turns
/// nothing into a `404`.
const SELECT_OWN_FAMILY: &str = "SELECT session_id FROM refresh_tokens \
     WHERE tenant_id = $1 AND actor_id = $2 AND session_id = $3 LIMIT 1";

/// Counts a failed password attempt.
const COUNT_FAILED_ATTEMPT: &str = "UPDATE user_credentials \
     SET failed_attempts = failed_attempts + 1 WHERE tenant_id = $1 AND user_id = $2";

/// Clears the counter after a successful sign-in.
const CLEAR_FAILED_ATTEMPTS: &str = "UPDATE user_credentials \
     SET failed_attempts = 0 WHERE tenant_id = $1 AND user_id = $2";

/// Stamps the directory's `last_login_at`.
const STAMP_LAST_LOGIN: &str =
    "UPDATE users SET last_login_at = now() WHERE tenant_id = $1 AND id = $2";

/// The mass-revocation counter of `docs/03-LLD.md §5.4`.
const BUMP_TOKEN_EPOCH: &str =
    "UPDATE users SET token_epoch = token_epoch + 1 WHERE tenant_id = $1 AND id = $2";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Rule 10, at the one place a body is most likely to be printed.
    ///
    /// The positive control is the email: it *does* appear, so this does not pass against a `Debug`
    /// that prints nothing at all (`docs/12-TESTING.md §1.2`). The needle is assembled at run time
    /// so the test does not fail against its own source.
    #[test]
    fn a_login_body_never_debug_prints_the_password() {
        let secret = format!("hunter{}", 2);
        let body = LoginRequest {
            email: "owner@tenant-alpha.example".to_owned(),
            password: Secret(secret.clone()),
            device_id: None,
        };
        let rendered = format!("{body:?}");

        assert!(!rendered.contains(&secret), "the password reached a Debug output: {rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(
            rendered.contains("owner@tenant-alpha.example"),
            "positive control: a non-secret field must still be printable, or this test would \
             pass against a Debug that printed nothing"
        );
    }

    /// The same rule for the MFA code.
    #[test]
    fn an_mfa_body_never_debug_prints_the_code() {
        let code = format!("{}{}", 123, 456);
        let body = MfaVerifyRequest {
            challenge_id: Uuid::nil(),
            method: Some(MfaMethod::Totp),
            code: Secret(code.clone()),
        };
        let rendered = format!("{body:?}");
        assert!(!rendered.contains(&code), "the code reached a Debug output: {rendered}");
        assert!(rendered.contains("[redacted]"));
        assert!(
            rendered.contains("Totp"),
            "positive control: the non-secret half of the body must still print"
        );
    }

    /// A challenge is one attempt, not a five-minute guessing window.
    #[test]
    fn a_challenge_can_only_be_taken_once() {
        let challenges = MfaChallenges::default();
        let id = challenges.issue(Challenge {
            tenant_id: TenantId::new_v7(),
            subject: UserId::new_v7(),
            device_id: None,
            methods: vec![MfaMethod::Totp],
            expires_at: Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS),
        });
        assert!(challenges.take(id).is_some(), "positive control: the first use must succeed");
        assert!(challenges.take(id).is_none(), "a spent challenge must not be usable again");
    }

    /// An expired challenge is refused even though it is still in the map.
    #[test]
    fn an_expired_challenge_is_refused() {
        let challenges = MfaChallenges::default();
        let id = challenges.issue(Challenge {
            tenant_id: TenantId::new_v7(),
            subject: UserId::new_v7(),
            device_id: None,
            methods: vec![MfaMethod::Totp],
            expires_at: Utc::now() - Duration::seconds(1),
        });
        assert!(challenges.take(id).is_none());
    }

    #[test]
    fn the_csrf_comparison_rejects_every_kind_of_mismatch() {
        assert!(constant_time_eq(b"abc", b"abc"), "positive control");
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn a_cookie_header_yields_the_named_value_only() {
        let header = "enclave_rt=abc123; enclave_csrf=def456; other=x";
        assert_eq!(cookie_value(header, "enclave_rt").as_deref(), Some("abc123"));
        assert_eq!(cookie_value(header, "enclave_csrf").as_deref(), Some("def456"));
        assert_eq!(cookie_value(header, "absent"), None);
        // A name that is a suffix of another must not match it.
        assert_eq!(cookie_value("xenclave_rt=abc", "enclave_rt"), None);
    }

    /// The CSRF cookie is readable by script *and* carries the rest of the attributes. Both halves
    /// matter: without `Secure` it crosses the wire in the clear, and with `HttpOnly` the SPA
    /// cannot echo it and every refresh fails.
    #[test]
    fn the_csrf_cookie_is_readable_but_otherwise_locked_down() {
        let cookie = csrf_cookie();
        assert!(!cookie.contains("HttpOnly"), "the SPA has to read this one: {cookie}");
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(cookie.contains("; SameSite=Strict"), "{cookie}");
        assert!(cookie.contains("; Path=/"), "{cookie}");
        // 64 hex characters of value, so it cannot be guessed.
        let value = cookie_value(&cookie, CSRF_COOKIE).unwrap_or_default();
        let value = value.split(';').next().unwrap_or_default();
        assert_eq!(value.len(), 64, "{cookie}");
    }

    /// `docs/05-API.md §3.1` shows the members by name; the web shell's api client is written
    /// against them.
    #[test]
    fn the_mfa_refusal_carries_the_members_the_document_specifies() {
        let id = Uuid::new_v4();
        let envelope = mfa_required(id, &[MfaMethod::Totp, MfaMethod::Webauthn]);
        assert_eq!(envelope.code(), "MFA_REQUIRED");
        assert_eq!(envelope.status(), StatusCode::UNAUTHORIZED);
        let members = envelope.members();
        assert_eq!(members.get("challengeId"), Some(&serde_json::json!(id.to_string())));
        assert_eq!(members.get("methods"), Some(&serde_json::json!(["TOTP", "WEBAUTHN"])));
    }

    /// Every credential refusal is the same refusal.
    #[test]
    fn every_credential_refusal_is_byte_identical() {
        let first = invalid_credentials();
        let second = invalid_credentials();
        assert_eq!(first.code(), second.code());
        assert_eq!(first.status(), second.status());
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        // The positive control for "they are indistinguishable": a *different* refusal is
        // distinguishable, so this is not passing because every envelope is the same.
        assert_ne!(invalid_credentials().code(), session_replay().code());
    }

    /// The unconfigured surface refuses as an outage, never as a wrong password.
    #[tokio::test]
    async fn an_unconfigured_surface_is_a_dependency_failure_and_not_a_credential_failure() {
        let surface = AuthSurface::unconfigured();
        assert!(!surface.is_configured());

        let error = surface
            .tokens
            .issue_pair(&AuthContext {
                tenant_id: TenantId::new_v7(),
                actor: Actor::User(UserId::new_v7()),
                session_id: None,
                client: ClientType::Web,
                device_id: None,
                scopes: ScopeSet::empty(),
                methods: vec![AuthMethod::Pwd],
                auth_time: Utc::now(),
                epoch: 1,
                max_classification: None,
            })
            .await
            .expect_err("an unconfigured surface must not issue a token");

        assert!(
            !error.is_authentication_failure(),
            "an unwired deployment must not answer like a rejected credential: {error:?}"
        );
        assert_eq!(unavailable(&error).status_code(), 503);
    }

    /// The queries carry the tenant predicate as well as relying on row-level security — the two
    /// layers of `docs/04-DATA-MODEL.md §3`.
    #[test]
    fn every_query_carries_its_own_tenant_predicate() {
        for query in [
            SELECT_ACCOUNT_BY_EMAIL,
            SELECT_ACCOUNT_BY_ID,
            SELECT_ENROLLED_MFA,
            SELECT_ACTIVE_FAMILIES,
            SELECT_OWN_FAMILY,
            COUNT_FAILED_ATTEMPT,
            CLEAR_FAILED_ATTEMPTS,
            STAMP_LAST_LOGIN,
            BUMP_TOKEN_EPOCH,
        ] {
            assert!(query.contains("tenant_id = $1"), "no tenant predicate in: {query}");
        }
    }

    /// A sign-in is for a live, active account and nothing else.
    #[test]
    fn only_an_active_account_can_be_loaded_for_a_sign_in() {
        for query in [SELECT_ACCOUNT_BY_EMAIL, SELECT_ACCOUNT_BY_ID] {
            assert!(query.contains("u.deleted_at IS NULL"), "{query}");
            assert!(query.contains("u.status = 'ACTIVE'"), "{query}");
        }
        assert!(
            SELECT_ACCOUNT_BY_EMAIL.contains("locked_until"),
            "a locked account must not be loadable"
        );
    }
}
