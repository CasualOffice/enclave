//! `enclave-auth` — passwords, access tokens, refresh rotation and revocation.
//!
//! This crate answers exactly one question: **who is calling?** It never answers "may they?" —
//! that is the policy chain's job, and the separation is load-bearing. A token's `scp` claim can
//! only *narrow* what a caller may attempt; authorization re-resolves the ACL from PostgreSQL on
//! every request regardless (`docs/03-LLD.md §5.2`). Nothing here grants access to anything.
//!
//! # The shape of the system
//!
//! ```text
//! login ──▶ PasswordHasher ──▶ TokenService::issue_pair ──┬──▶ access token  (10 min, EdDSA JWT)
//!                                                          └──▶ refresh token (opaque, rotating)
//!
//! request ─▶ AccessTokenVerifier::verify   (no I/O: signature, algorithm, key, claims)
//!            └─▶ RevocationChecker::check  (I/O, and only when a precondition says it is needed)
//!
//! refresh ─▶ TokenService::refresh         (rotate, or detect replay and destroy the family)
//! ```
//!
//! The split between the two verification steps is what lets `docs/03-LLD.md §5.1` promise a
//! stateless hot path. [`AccessTokenVerifier`] does no I/O at all; [`RevocationChecker`] does, and
//! is consulted only when the cheap precondition in `§5.4` says it must be.
//!
//! # The four properties worth knowing before changing anything here
//!
//! 1. **The signature algorithm is a compile-time constant** ([`TOKEN_ALGORITHM`]), never read from
//!    a token header and not configurable. This is test K8; see [`access`] for the reasoning.
//! 2. **Refresh tokens rotate on every use**, and presenting a consumed one destroys the family
//!    (K3, K4). Rotation is not an optimisation to be skipped under load — it is the only thing
//!    that makes a stolen refresh token *detectable*.
//! 3. **Revocation fails closed for privileged scopes and open for ordinary ones** (K9). Both
//!    halves are deliberate; [`revocation`] explains the asymmetry.
//! 4. **Argon2 parameters travel inside every hash**, so raising the cost floor is safe and
//!    triggers a rehash on the next successful login rather than a lockout.
//!
//! # Layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`config`] | The tunable half, shaped like `docs/08-BYO-INFRA.md §19` |
//! | [`password`] | Argon2id hashing, verification and rehash-on-login |
//! | [`keys`] | [`KeyProvider`], the overlap window, and the dev file-backed provider |
//! | [`jwks`] | The `/.well-known/jwks.json` document |
//! | [`claims`] | The `docs/03-LLD.md §5.2` claim set and [`VerifiedAccessToken`] |
//! | [`access`] | Issuing and verifying — the pinned-algorithm defence lives here |
//! | [`refresh`] | Opaque tokens, the store contract, rotation and reuse classification |
//! | [`revocation`] | The `jti` denylist and the `token_epoch` check |
//! | [`cookie`] | The `HttpOnly; Secure; SameSite=Strict` refresh cookie (K10) |
//! | [`service`] | [`TokenService`], the composition of all of the above |
//!
//! # Notes for the integrator
//!
//! Three things this crate needs from elsewhere, recorded here rather than assumed:
//!
//! - **Family-level denial has no table yet.** [`revocation::DenylistStore::deny_session`] denies
//!   every access token in a `sid` with one entry, because revoking a refresh family must stop the
//!   access tokens it issued and `refresh_tokens` records no `jti`s to enumerate. Persisting that
//!   needs a session-scoped row; `token_revocations` in `docs/04-DATA-MODEL.md §6` is keyed
//!   `(tenant_id, jti)` only. Redis can express it today; PostgreSQL cannot.
//! - **`core::Error` cannot express `401`.** Every authentication failure converts to
//!   `PolicyDenied { AccessDenied }`, which is a `403`. The API layer should branch on
//!   [`AuthError::is_authentication_failure`] to emit `401` with a `WWW-Authenticate` challenge —
//!   `docs/05-API.md §3.2` specifies `401 SESSION_REPLAY`, and `ReasonCode::SessionReplay` maps to
//!   `403` in `core`. Worth reconciling in `core` or in `docs/05`.
//! - **Device binding at refresh is a separate call.** The `TokenService::refresh` signature in
//!   `docs/03-LLD.md §5.3` carries a network context and no device, so rule 4 is
//!   [`service::check_device_binding`], which the API layer calls with the attested device.

pub mod access;
pub mod claims;
pub mod config;
pub mod cookie;
pub mod error;
pub mod jwks;
pub mod keys;
pub mod password;
pub mod refresh;
pub mod revocation;
pub mod service;

pub use access::{
    is_privileged, requires_device_binding, AccessTokenIssuer, AccessTokenVerifier,
    IssuedAccessToken, TokenTemplate, CLOCK_SKEW_TOLERANCE_SECS, TOKEN_ALGORITHM,
};
pub use claims::{AccessTokenClaims, Acr, AuthMethod, VerifiedAccessToken};
pub use config::{AccessTokenConfig, Argon2Params, AuthConfig, PasswordPolicy, RefreshTokenConfig};
pub use cookie::{RefreshCookieConfig, DEFAULT_COOKIE_NAME, DEFAULT_COOKIE_PATH};
pub use error::{AuthError, KeyProviderError, StoreUnavailable};
pub use jwks::{Jwk, Jwks};
pub use keys::{
    KeyId, KeyProvider, KeySet, KeyStatus, LocalFileKeyProvider, PrivateSigningKey,
    PublicSigningKey,
};
pub use password::{PasswordHasher, PasswordVerdict};
pub use refresh::{
    classify, InMemoryRefreshStore, RefreshOutcome, RefreshRecord, RefreshToken,
    RefreshTokenDigest, RefreshTokenStore, RevokeReason,
};
pub use revocation::{
    DenylistStore, EpochStore, InMemoryDenylist, InMemoryEpochs, RevocationChecker,
    RevocationVerdict,
};
pub use service::{
    check_device_binding, AuthContext, Clock, EnclaveTokenService, RefreshGuard, SessionFacts,
    SessionFactsProvider, SystemClock, TokenPair, TokenService, UnrestrictedRefreshGuard,
};

/// The crate's own result alias.
///
/// Distinct from `enclave_core::Result` on purpose: everything inside this crate fails with an
/// [`AuthError`], which carries the operational detail, and the conversion to the client-facing
/// `core::Error` happens once, at the boundary, where the detail is deliberately thrown away.
pub type Result<T, E = AuthError> = core::result::Result<T, E>;
