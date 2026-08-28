//! The authentication failure vocabulary.
//!
//! Every variant here answers "why was this caller refused?" for *our* logs. What the caller is
//! told is decided by the single [`From<AuthError>`] conversion at the bottom of this file, and it
//! is deliberately much coarser: nearly every token failure collapses to one
//! [`ReasonCode::AccessDenied`]. An attacker who can tell "unknown `kid`" from "bad signature" from
//! "expired" has an oracle for probing the key set and the clock; an operator reading a log line
//! needs exactly that distinction. Keeping the two apart in the type system is what stops the
//! distinction leaking the first time someone writes `err.to_string()` into a response body.

use enclave_core::{Dependency, Error, FieldError, ReasonCode, ValidationCode};

/// A backing store the hot path depends on could not be reached.
///
/// Deliberately a distinct type rather than an `AuthError` variant: the store traits in
/// [`crate::revocation`] must be able to say "I do not know" *without* deciding what that means.
/// Whether not knowing is fatal depends on the scopes the token carries
/// (`docs/03-LLD.md §5.4`), and only the caller holding the claims can decide that.
#[derive(Debug, thiserror::Error)]
#[error("{dependency} is unavailable")]
pub struct StoreUnavailable {
    /// Which dependency was unreachable, so the fail-closed decision and the audit record can name
    /// it without a free-text string.
    pub dependency: Dependency,
}

impl StoreUnavailable {
    /// Records that a dependency could not answer.
    #[must_use]
    pub const fn new(dependency: Dependency) -> Self {
        Self { dependency }
    }
}

/// Something went wrong obtaining signing key material.
///
/// Separated from [`AuthError`] because a `KeyProvider` is an infrastructure adapter — Vault, KMS,
/// a file on disk — and none of those should have to know about token semantics to report a
/// failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyProviderError {
    /// No key is in a state that permits signing right now. During a botched rotation this is the
    /// difference between "sign with something stale" and "stop": we stop.
    #[error("no signing key is currently active")]
    NoActiveKey,

    /// The operating system declined to provide randomness.
    ///
    /// Fallible since rand 0.10 replaced the infallible `OsRng` with `SysRng`. Reported rather than
    /// unwrapped because this crate forbids panicking paths in production code, and because a key
    /// generated from a degraded entropy source is worse than no key: the failure is recoverable,
    /// the weak key is not.
    #[error("the operating system could not provide randomness")]
    EntropyUnavailable,

    /// Key material could not be read or written.
    #[error("signing key storage failed")]
    Storage(#[source] std::io::Error),

    /// Key material was present but not parseable as an Ed25519 key.
    #[error("signing key material is malformed")]
    Malformed,
}

/// Why authentication failed.
///
/// `#[non_exhaustive]` because the API crate must never `match` this exhaustively to build a
/// response — it converts, and the conversion is here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The presented password did not verify, or the account has no password credential.
    ///
    /// One variant for both cases on purpose: distinguishing them turns the login endpoint into a
    /// user-enumeration oracle.
    #[error("credentials are not valid")]
    InvalidCredentials,

    /// The operating system declined to provide randomness while minting a token.
    ///
    /// See `KeyProviderError::EntropyUnavailable`. A refresh token minted from a degraded source is
    /// worse than a failed request, because the request can be retried and the token cannot be
    /// un-issued.
    #[error("the operating system could not provide randomness")]
    EntropyUnavailable,

    /// A password was rejected before it was ever hashed (`docs/01-PRD.md §189`).
    #[error("password does not satisfy the configured policy")]
    PasswordPolicy {
        /// Which rule it broke, as a closed enumeration the API can render from the i18n catalog.
        code: ValidationCode,
    },

    /// Argon2 itself failed — a parameter combination it refuses, or an unparseable stored hash.
    #[error("password hashing failed")]
    PasswordHashing(#[source] argon2::password_hash::Error),

    /// The token was not three base64url segments, or a segment was not valid JSON.
    #[error("the token is malformed")]
    MalformedToken,

    /// **This is the K8 defense.** The token's header named an algorithm other than `EdDSA`.
    ///
    /// The presented name is retained only for logs and only after sanitisation, because it is
    /// attacker-controlled: it is the payload of an algorithm-confusion attempt, and an
    /// unsanitised copy of it ends up in a log viewer that renders it.
    #[error("token algorithm {presented} is not the pinned EdDSA")]
    AlgorithmNotPinned {
        /// The sanitised algorithm name the token asked for.
        presented: String,
    },

    /// The token named a `kid` that is unknown, or one whose overlap window has closed (K2).
    #[error("no usable signing key for the presented kid")]
    UnknownSigningKey,

    /// The signature did not verify against the named key.
    #[error("token signature did not verify")]
    SignatureInvalid,

    /// `exp` is in the past by more than the bounded skew tolerance (K1).
    #[error("the token has expired")]
    TokenExpired,

    /// `iat` or `auth_time` is in the future by more than the bounded skew tolerance.
    ///
    /// Checked because a token minted with a far-future `iat` would otherwise satisfy every
    /// max-age and step-up policy forever.
    #[error("the token is not yet valid")]
    TokenNotYetValid,

    /// `iss` or `aud` does not match this deployment.
    ///
    /// One variant for both: a caller replaying a token from another deployment learns only that
    /// it does not belong here.
    #[error("the token was not issued for this deployment")]
    WrongAudience,

    /// A `sync` or `editor` token arrived without the `dev` claim those clients require (K7).
    #[error("this client type requires a bound device")]
    DeviceBindingRequired,

    /// The `jti`, or the whole `sid` family, is on the denylist (`docs/03-LLD.md §5.4`).
    #[error("the token has been revoked")]
    TokenRevoked,

    /// The token's `epoch` predates the subject's current `token_epoch` (K5).
    #[error("the token predates the subject's current revocation epoch")]
    EpochStale,

    /// The refresh token is unknown, expired, or was already revoked.
    ///
    /// Note what this is *not*: replay. Replay is [`AuthError::SessionReplay`] and has consequences.
    #[error("the refresh token is not usable")]
    RefreshRejected,

    /// **K4.** An already-consumed refresh token was presented, which means a copy of it exists
    /// somewhere it should not. The family has been revoked by the time this is returned.
    #[error("refresh token replay detected; the session family has been revoked")]
    SessionReplay,

    /// The refresh token was presented from a device other than the one it is bound to
    /// (`docs/03-LLD.md §5.3` rule 4).
    #[error("refresh presented from an unbound device")]
    DeviceMismatch,

    /// Conditional access refused the refresh (K6). Raised by the configured
    /// [`crate::service::RefreshGuard`], not by this crate's own logic.
    ///
    /// # Why it carries the code rather than naming the network
    ///
    /// It used to be `NetworkNotAllowed`, a variant with no payload, because the only refusal the
    /// specification names for this path is `docs/05-API.md §3.2`'s `403 NETWORK_NOT_ALLOWED`. That
    /// is the *common* refusal and not the only possible one: the stage's effects also produce
    /// `DEVICE_NOT_MANAGED` and `STEP_UP_REQUIRED` (`crates/conditional_access/src/rules.rs`), and
    /// a session refused for its authentication strength that was told to change networks is a user
    /// who cannot act on what they were told.
    ///
    /// So the code is carried through unchanged from the stage that decided it, which is the same
    /// vocabulary an authenticated request gets for the same rule (`ENC-709`). One variant rather
    /// than one per code, because two spellings of one refusal drift; the code is a closed
    /// enumeration and never a rule name, so `docs/05-API.md §5`'s "denials never disclose which
    /// policy matched" still holds — see [`crate::service::RefreshGuard`].
    #[error("conditional access refused the refresh")]
    ConditionalAccessDenied(
        /// The reason code the stage decided, verbatim.
        ReasonCode,
    ),

    /// **K9.** A revocation store could not answer and the token holds privileged scopes, so the
    /// check failed closed.
    #[error("revocation state is unknown and the token holds privileged scopes")]
    RevocationUnavailable(#[source] StoreUnavailable),

    /// A store this crate reads through could not answer, so nothing was decided.
    ///
    /// Distinct from [`AuthError::RevocationUnavailable`], and the distinction is the whole reason
    /// the variant exists. That one is a *decision*: the revocation state is unknown, the token is
    /// privileged, and K9 says refuse. This one is the absence of a decision — the refresh row was
    /// never read, the rotation never committed — and it must never render as a credential
    /// rejection. [`AuthError::is_authentication_failure`] answers `false` and
    /// [`AuthError::reason_code`] answers `None`, so a database outage during a login cannot reach
    /// a caller as "your password is wrong".
    ///
    /// The in-memory stores this crate exports cannot produce it, which is exactly why it was
    /// missing until a PostgreSQL-backed [`crate::RefreshTokenStore`] existed (`ENC-687`).
    #[error("an authentication store could not be reached")]
    StorageUnavailable(
        /// Which dependency did not answer.
        #[source]
        StoreUnavailable,
    ),

    /// Signing key material could not be obtained, so no token could be issued.
    #[error("signing key material is unavailable")]
    KeyUnavailable(
        /// The adapter's own report.
        #[source]
        KeyProviderError,
    ),

    /// Serialising or signing the JWT failed. An internal fault, never a caller's fault.
    #[error("token encoding failed")]
    Encoding(#[source] jsonwebtoken::errors::Error),

    /// The deployment's auth configuration is not usable. Raised at construction, so this surfaces
    /// at startup rather than on the first login.
    #[error("invalid auth configuration: {0}")]
    Configuration(&'static str),
}

impl AuthError {
    /// Whether this failure means "you are not authenticated", as opposed to "you are
    /// authenticated and still may not".
    ///
    /// The API crate needs this to choose `401` with a `WWW-Authenticate` challenge over `403`.
    /// It lives here rather than in a handler because the classification is security-relevant and
    /// two handlers deciding it independently will eventually disagree.
    #[must_use]
    pub const fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Self::InvalidCredentials
                | Self::MalformedToken
                | Self::AlgorithmNotPinned { .. }
                | Self::UnknownSigningKey
                | Self::SignatureInvalid
                | Self::TokenExpired
                | Self::TokenNotYetValid
                | Self::WrongAudience
                | Self::DeviceBindingRequired
                | Self::TokenRevoked
                | Self::EpochStale
                | Self::RefreshRejected
                | Self::SessionReplay
                | Self::DeviceMismatch
        )
    }

    /// The reason code the caller is allowed to see, where there is one.
    ///
    /// `None` means the failure is internal and must not be attributed to the caller at all.
    #[must_use]
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Self::SessionReplay => Some(ReasonCode::SessionReplay),
            Self::ConditionalAccessDenied(code) => Some(*code),
            Self::DeviceMismatch | Self::DeviceBindingRequired => {
                Some(ReasonCode::DeviceNotManaged)
            }
            Self::InvalidCredentials
            | Self::MalformedToken
            | Self::AlgorithmNotPinned { .. }
            | Self::UnknownSigningKey
            | Self::SignatureInvalid
            | Self::TokenExpired
            | Self::TokenNotYetValid
            | Self::WrongAudience
            | Self::TokenRevoked
            | Self::EpochStale
            | Self::RefreshRejected
            | Self::RevocationUnavailable(_) => Some(ReasonCode::AccessDenied),
            // Internal failures. `EntropyUnavailable` in particular tells the caller nothing
            // useful and would tell an attacker that the host's entropy source is degraded.
            Self::PasswordPolicy { .. }
            | Self::PasswordHashing(_)
            | Self::KeyUnavailable(_)
            | Self::StorageUnavailable(_)
            | Self::EntropyUnavailable
            | Self::Encoding(_)
            | Self::Configuration(_) => None,
        }
    }
}

/// Keeps an attacker-supplied algorithm name loggable.
///
/// A JOSE header is JSON, so `alg` can be megabytes of arbitrary Unicode. Truncating to sixteen
/// characters and dropping anything outside printable ASCII means the value can be put in a log
/// line and an error message without carrying an injection along with it.
pub(crate) fn sanitize_alg(presented: &str) -> String {
    presented.chars().filter(|c| c.is_ascii_graphic()).take(16).collect()
}

impl From<AuthError> for Error {
    /// The one place an authentication failure becomes something a client sees.
    ///
    /// Note how much detail disappears here. That is the point: `docs/03-LLD.md §5` gives an
    /// attacker no way to distinguish an unknown `kid` from a bad signature from a stale epoch, and
    /// this conversion is what makes that true for every endpoint at once instead of endpoint by
    /// endpoint.
    fn from(value: AuthError) -> Self {
        match value.reason_code() {
            Some(code) => Self::denied(code),
            // No reason code means the caller did nothing wrong and must learn nothing. Passwords
            // are the exception: a rejected new password is a validation failure the user has to be
            // able to act on.
            None => match value {
                AuthError::PasswordPolicy { code } => {
                    Self::Validation(vec![FieldError::new("password", code)])
                }
                AuthError::KeyUnavailable(_) => Self::Upstream {
                    dependency: Dependency::SecretStore,
                    // A missing or unreadable key is a configuration fault, not a blip; retrying
                    // an identical request would only amplify the outage.
                    retryable: false,
                },
                // The opposite judgement, and for the opposite reason: a store that did not answer
                // is the case where retrying is the correct client behaviour. It also names the
                // dependency the adapter reported rather than a fixed one, because the same
                // variant carries a Redis denylist failure as well as a PostgreSQL one.
                AuthError::StorageUnavailable(unavailable) => {
                    Self::Upstream { dependency: unavailable.dependency, retryable: true }
                }
                other => Self::Internal(anyhow::Error::new(other)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn token_failures_collapse_to_one_reason_code() {
        // The oracle test: four structurally different failures must be indistinguishable to a
        // caller. If someone adds a more "helpful" reason code, this fails.
        for err in [
            AuthError::UnknownSigningKey,
            AuthError::SignatureInvalid,
            AuthError::TokenExpired,
            AuthError::EpochStale,
        ] {
            let mapped = Error::from(err);
            assert_eq!(mapped.code(), "ACCESS_DENIED");
        }
    }

    #[test]
    fn internal_failures_never_attribute_blame_to_the_caller() {
        let mapped = Error::from(AuthError::Configuration("issuer must be absolute"));
        assert_eq!(mapped.code(), "INTERNAL_ERROR");
        assert_eq!(mapped.to_string(), "internal error");
    }

    #[test]
    fn algorithm_names_are_sanitized_before_they_reach_a_log() {
        let hostile = "HS256\n\u{1b}[2Jinjected-and-far-too-long-to-print";
        let safe = sanitize_alg(hostile);
        assert_eq!(safe, "HS256[2Jinjected");
        assert!(safe.chars().all(|c| c.is_ascii_graphic()));
    }
}
