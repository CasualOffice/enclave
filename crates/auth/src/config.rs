//! The tunable half of authentication, shaped to match the `auth:` and `security.password:` blocks
//! of `docs/08-BYO-INFRA.md §19`.
//!
//! # Why durations are seconds here
//!
//! The specification writes lifetimes as `"10m"` and `"90d"`. Parsing that spelling belongs to the
//! `config` crate, which owns the layering and the error messages for a bad configuration file;
//! this crate takes the result. Keeping the string form out of these structs means `auth` has no
//! opinion on configuration *format*, and a second format (environment variables, a CLI flag, a
//! test fixture) does not have to reimplement it.
//!
//! # Why there are no secrets in here
//!
//! Nothing on this page is a credential. Signing keys reach the crate through a
//! [`crate::keys::KeyProvider`], never through configuration — non-negotiable rule 11, and the
//! reason `signing_keys.key_ref` in the specification is a `vault://` reference rather than a value.

use serde::{Deserialize, Serialize};

/// Argon2id cost parameters (`docs/06-SECURITY-DLP-ACCESS.md §274`).
///
/// These are stored *inside* every hash as part of its PHC string, which is what makes raising them
/// safe: an existing hash keeps verifying with the parameters it was made with, and
/// [`crate::password::PasswordHasher::verify`] reports that it should be upgraded on this login,
/// while the user's plaintext is still in hand. Raising a cost without that mechanism means either
/// locking every user out or leaving the old cost in place forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Argon2Params {
    /// Memory cost in kibibytes. The dominant term for GPU and ASIC resistance, which is why the
    /// default is deliberately expensive rather than the RFC minimum.
    pub memory_kib: u32,
    /// Time cost: passes over memory.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    /// The values in `docs/08-BYO-INFRA.md §19` — 64 MiB, 3 passes, 4 lanes.
    fn default() -> Self {
        Self { memory_kib: 65_536, iterations: 3, parallelism: 4 }
    }
}

/// Rules a plaintext password must satisfy before it is ever hashed.
///
/// Length bounds are enforced rather than advisory, and the maximum exists for a specific reason:
/// Argon2 cost is independent of input length, but an unbounded password is an unbounded
/// allocation on an unauthenticated endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PasswordPolicy {
    /// Minimum length in Unicode scalar values, not bytes — counting bytes would make a password
    /// in a non-Latin script "long enough" for the wrong reason.
    pub min_length: usize,
    /// Maximum length, bounding the work an anonymous caller can ask for.
    pub max_length: usize,
    /// Cost parameters new hashes are produced with.
    pub argon2: Argon2Params,
}

impl Default for PasswordPolicy {
    /// 12–128 characters, per `docs/01-PRD.md §189`. Note what is absent: no mandatory character
    /// classes and no forced rotation, both of which measurably push users toward weaker, more
    /// predictable passwords.
    fn default() -> Self {
        Self { min_length: 12, max_length: 128, argon2: Argon2Params::default() }
    }
}

/// Access-token issuance settings.
///
/// There is no `algorithm` field. The specification lists one, but a configurable signing algorithm
/// is the ingredient an algorithm-confusion attack needs (K8), and a deployment that could be
/// configured to accept `HS256` is a deployment one bad YAML file away from accepting a token
/// signed with its own public key. `EdDSA` is compiled in — see [`crate::access::TOKEN_ALGORITHM`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AccessTokenConfig {
    /// The `iss` claim, and the value every verifier requires. Typically the tenant-facing origin.
    pub issuer: String,
    /// The `aud` claim.
    pub audience: String,
    /// Lifetime in seconds for an ordinary token.
    pub ttl_secs: i64,
    /// Lifetime in seconds for a token carrying privileged scopes. Shorter because the denylist is
    /// the only thing standing between a stolen privileged token and its expiry, and the denylist
    /// is the component allowed to be unavailable (K9).
    pub privileged_ttl_secs: i64,
}

impl Default for AccessTokenConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: "enclave-api".to_owned(),
            ttl_secs: 600,
            privileged_ttl_secs: 300,
        }
    }
}

/// Refresh-token lifetime settings.
///
/// Rotation and reuse detection are not configurable. `docs/08-BYO-INFRA.md §19` shows
/// `rotation: true` and `reuse_detection: "REVOKE_FAMILY"`; both are the only supported values, and
/// representing them as settings would imply an unsupported one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RefreshTokenConfig {
    /// Sliding window in seconds. Each rotation moves it forward.
    pub idle_ttl_secs: i64,
    /// Hard ceiling in seconds from the original authentication. Never moves, which is what stops a
    /// family living forever through continuous refresh.
    pub absolute_ttl_secs: i64,
}

impl Default for RefreshTokenConfig {
    /// 14 days sliding, 90 days absolute (`docs/03-LLD.md §5.1`).
    fn default() -> Self {
        Self { idle_ttl_secs: 14 * 86_400, absolute_ttl_secs: 90 * 86_400 }
    }
}

/// Everything the token layer needs to be configured with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct AuthConfig {
    /// Access-token issuance and verification.
    pub access_token: AccessTokenConfig,
    /// Refresh-token lifetimes.
    pub refresh_token: RefreshTokenConfig,
    /// Password rules and Argon2 cost.
    pub password: PasswordPolicy,
}

impl AuthConfig {
    /// Rejects a configuration that would be unsafe or nonsensical, at startup.
    ///
    /// Every check here describes a deployment that would otherwise *work* — which is exactly why
    /// it has to fail loudly now rather than behave subtly wrong for a year. An empty issuer, for
    /// instance, verifies fine against tokens this deployment minted and also against tokens minted
    /// by any other deployment with an empty issuer.
    ///
    /// # Errors
    ///
    /// [`crate::AuthError::Configuration`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), crate::AuthError> {
        use crate::AuthError::Configuration;

        if self.access_token.issuer.is_empty() {
            return Err(Configuration("auth.access_token.issuer must be set"));
        }
        if self.access_token.audience.is_empty() {
            return Err(Configuration("auth.access_token.audience must be set"));
        }
        if self.access_token.ttl_secs <= 0 || self.access_token.privileged_ttl_secs <= 0 {
            return Err(Configuration("auth.access_token TTLs must be positive"));
        }
        // A privileged token living longer than an ordinary one inverts the whole point of the
        // shorter privileged lifetime, and is the kind of edit that passes review.
        if self.access_token.privileged_ttl_secs > self.access_token.ttl_secs {
            return Err(Configuration(
                "auth.access_token.privileged_ttl_secs must not exceed ttl_secs",
            ));
        }
        if self.refresh_token.idle_ttl_secs <= 0
            || self.refresh_token.absolute_ttl_secs < self.refresh_token.idle_ttl_secs
        {
            return Err(Configuration(
                "auth.refresh_token.absolute_ttl_secs must be at least idle_ttl_secs",
            ));
        }
        if self.password.min_length < 12 {
            return Err(Configuration("security.password.min_length must be at least 12"));
        }
        if self.password.max_length < self.password.min_length {
            return Err(Configuration("security.password.max_length must be at least min_length"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn valid() -> AuthConfig {
        AuthConfig {
            access_token: AccessTokenConfig {
                issuer: "https://workspace.example.com".to_owned(),
                ..AccessTokenConfig::default()
            },
            ..AuthConfig::default()
        }
    }

    #[test]
    fn defaults_match_the_specification() {
        let cfg = valid();
        assert_eq!(cfg.access_token.ttl_secs, 600);
        assert_eq!(cfg.access_token.privileged_ttl_secs, 300);
        assert_eq!(cfg.refresh_token.idle_ttl_secs, 14 * 86_400);
        assert_eq!(cfg.refresh_token.absolute_ttl_secs, 90 * 86_400);
        assert_eq!(
            cfg.password.argon2,
            Argon2Params { memory_kib: 65_536, iterations: 3, parallelism: 4 }
        );
        cfg.validate().expect("the documented defaults must be a valid configuration");
    }

    #[test]
    fn an_empty_issuer_is_refused_at_startup() {
        let cfg = AuthConfig::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_privileged_ttl_longer_than_the_ordinary_one_is_refused() {
        let mut cfg = valid();
        cfg.access_token.privileged_ttl_secs = cfg.access_token.ttl_secs + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn an_absolute_refresh_ttl_below_the_idle_one_is_refused() {
        let mut cfg = valid();
        cfg.refresh_token.absolute_ttl_secs = cfg.refresh_token.idle_ttl_secs - 1;
        assert!(cfg.validate().is_err());
    }
}
