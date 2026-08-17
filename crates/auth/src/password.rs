//! Argon2id password hashing (`docs/06-SECURITY-DLP-ACCESS.md §274`).
//!
//! # The three properties that matter
//!
//! 1. **Parameters travel with the hash.** A PHC string (`$argon2id$v=19$m=65536,t=3,p=4$salt$hash`)
//!    carries the cost it was produced with. Raising the configured cost therefore does not
//!    invalidate anything: old hashes keep verifying under their own parameters, and
//!    [`PasswordHasher::verify`] says so, so the caller can re-hash while the plaintext is still in
//!    memory. Storing parameters separately — or worse, assuming the current configuration — turns
//!    a cost increase into a mass lockout.
//! 2. **Comparison is constant time.** Handled inside `argon2`/`password-hash`, which compares
//!    derived outputs with `subtle`. Never compare hashes with `==`.
//! 3. **A missing credential costs the same as a wrong one.** [`PasswordHasher::verify_absent`]
//!    exists so the login path can spend the same Argon2 work on an unknown email address as on a
//!    known one. Without it, response latency is a user-enumeration oracle no rate limit hides.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use enclave_core::ValidationCode;
use zeroize::Zeroizing;

use crate::config::{Argon2Params, PasswordPolicy};
use crate::error::AuthError;

/// What verifying a password established.
///
/// Not a `bool`, because the interesting answer is not "did it match" but "did it match, and is the
/// stored hash now below the deployment's cost floor". A `bool` return would leave the rehash
/// opportunity — the only moment the plaintext is available — silently unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a verification result that is not inspected has decided nothing"]
pub enum PasswordVerdict {
    /// The password did not match, or there was nothing to match against.
    Rejected,
    /// The password matched.
    Accepted {
        /// The stored hash used weaker parameters than the current policy. The caller should
        /// re-hash now, in this request, and store the result — `docs/03-LLD.md §5` calls this
        /// rehash-on-next-successful-login.
        needs_rehash: bool,
    },
}

impl PasswordVerdict {
    /// Whether the password matched, discarding the rehash advice.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// Hashes and verifies local account passwords under one policy.
///
/// Construct once per process and share it: building one derives a decoy hash (see
/// [`PasswordHasher::verify_absent`]), which costs a full Argon2 evaluation.
pub struct PasswordHasher {
    policy: PasswordPolicy,
    /// A hash of a random string nobody knows, used to spend real work on accounts that do not
    /// exist. Not a secret — its only property is that no attacker-supplied password matches it —
    /// but generated rather than hard-coded so that a copied constant cannot end up shared between
    /// deployments and recognised.
    decoy: String,
}

impl core::fmt::Debug for PasswordHasher {
    /// The decoy is inert, but hash-shaped values in logs invite someone to try cracking them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordHasher").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl PasswordHasher {
    /// Builds a hasher for a policy, failing if Argon2 refuses its cost parameters.
    ///
    /// Validating at construction rather than at first hash means a deployment configured with, for
    /// example, zero iterations fails to start instead of failing the first login attempt after a
    /// release.
    ///
    /// # Errors
    ///
    /// [`AuthError::PasswordHashing`] if the parameters are not a legal Argon2 configuration.
    pub fn new(policy: PasswordPolicy) -> Result<Self, AuthError> {
        let argon2 = build_argon2(policy.argon2)?;
        let salt = SaltString::generate(&mut OsRng);
        let decoy_secret = Zeroizing::new(SaltString::generate(&mut OsRng).to_string());
        let decoy = argon2
            .hash_password(decoy_secret.as_bytes(), &salt)
            .map_err(AuthError::PasswordHashing)?
            .to_string();
        Ok(Self { policy, decoy })
    }

    /// The policy this hasher enforces.
    #[must_use]
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// Checks a candidate password against the length policy without hashing it.
    ///
    /// Separate from [`PasswordHasher::hash`] because registration and password-change flows want
    /// to report the problem before doing 64 MiB of work, and because the rule is worth being able
    /// to test on its own.
    ///
    /// # Errors
    ///
    /// [`AuthError::PasswordPolicy`] carrying [`ValidationCode::TooShort`] or
    /// [`ValidationCode::TooLong`].
    pub fn check_policy(&self, password: &str) -> Result<(), AuthError> {
        // Scalar values, not bytes: counting bytes would let a twelve-character Devanagari password
        // pass a rule a twelve-character ASCII one fails, for no security reason.
        let length = password.chars().count();
        if length < self.policy.min_length {
            return Err(AuthError::PasswordPolicy { code: ValidationCode::TooShort });
        }
        if length > self.policy.max_length {
            return Err(AuthError::PasswordPolicy { code: ValidationCode::TooLong });
        }
        Ok(())
    }

    /// Hashes a password under the current policy, returning a PHC string ready for
    /// `user_credentials.password_hash`.
    ///
    /// # Errors
    ///
    /// [`AuthError::PasswordPolicy`] if the password fails [`PasswordHasher::check_policy`], or
    /// [`AuthError::PasswordHashing`] if Argon2 fails.
    pub fn hash(&self, password: &str) -> Result<String, AuthError> {
        self.check_policy(password)?;
        let argon2 = build_argon2(self.policy.argon2)?;
        let salt = SaltString::generate(&mut OsRng);
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(AuthError::PasswordHashing)?
            .to_string())
    }

    /// Verifies a password against a stored PHC string.
    ///
    /// The length policy is **not** applied here. A password that predates a tightened policy must
    /// still let its owner in — long enough to be told to change it — and refusing it at this point
    /// would lock out exactly the users a tightened policy is meant to protect.
    ///
    /// A malformed stored hash is [`PasswordVerdict::Rejected`], not an error: from the caller's
    /// point of view a corrupt credential row is indistinguishable from a wrong password, and
    /// surfacing the difference over HTTP would say which accounts have broken rows.
    pub fn verify(&self, password: &str, stored: &str) -> PasswordVerdict {
        let Ok(parsed) = PasswordHash::new(stored) else {
            return PasswordVerdict::Rejected;
        };
        let Ok(argon2) = build_argon2(self.policy.argon2) else {
            return PasswordVerdict::Rejected;
        };
        // `verify_password` re-derives with the parameters embedded in `parsed`, not the ones in
        // `argon2`, and compares in constant time.
        if argon2.verify_password(password.as_bytes(), &parsed).is_err() {
            return PasswordVerdict::Rejected;
        }
        PasswordVerdict::Accepted { needs_rehash: self.is_below_policy(&parsed) }
    }

    /// Spends the same work as a real verification, and always rejects.
    ///
    /// Call this when the account, or its password credential, does not exist. The point is
    /// timing: `docs/06-SECURITY-DLP-ACCESS.md` treats account enumeration as a real finding, and a
    /// login handler that returns in microseconds for unknown emails and 60 ms for known ones has
    /// published its user directory.
    pub fn verify_absent(&self, password: &str) -> PasswordVerdict {
        // The verdict is discarded on purpose: the decoy exists to spend time, and there is no
        // password that matches it. Naming the binding keeps the discard deliberate rather than
        // looking like a dropped result.
        let _discarded = self.verify(password, &self.decoy);
        PasswordVerdict::Rejected
    }

    /// Whether a stored hash was produced with weaker parameters than the policy now demands.
    ///
    /// Only *weaker* counts. A hash that is stronger than the current policy — because the cost was
    /// lowered, or because it came from a stricter deployment during a migration — is left alone;
    /// re-hashing it would be a downgrade performed automatically and invisibly.
    fn is_below_policy(&self, stored: &PasswordHash<'_>) -> bool {
        let Ok(params) = Params::try_from(stored) else {
            // Unparseable parameters mean we cannot show it is adequate, so we upgrade it.
            return true;
        };
        let wanted = self.policy.argon2;
        // Ident and version are part of "weaker": an argon2i or v=16 hash is not what this
        // deployment issues, whatever its cost parameters say.
        let wrong_algorithm = stored.algorithm != Algorithm::Argon2id.ident()
            || stored.version.is_some_and(|v| v != Version::V0x13 as u32);
        wrong_algorithm
            || params.m_cost() < wanted.memory_kib
            || params.t_cost() < wanted.iterations
            || params.p_cost() < wanted.parallelism
    }
}

/// Builds an Argon2id context, mapping a rejected parameter set to our error type.
fn build_argon2(params: Argon2Params) -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(params.memory_kib, params.iterations, params.parallelism, None)
        .map_err(|e| AuthError::PasswordHashing(e.into()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Cheap parameters so the suite stays fast. Cost is exercised by
    /// `rehash_is_requested_when_the_stored_cost_is_below_policy`, not by every test.
    fn cheap(memory_kib: u32, iterations: u32) -> PasswordPolicy {
        PasswordPolicy {
            min_length: 12,
            max_length: 128,
            argon2: Argon2Params { memory_kib, iterations, parallelism: 1 },
        }
    }

    #[test]
    fn a_hash_round_trips_and_embeds_its_parameters() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        let encoded = hasher.hash("correct horse battery").expect("hash");

        assert!(encoded.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"), "PHC string: {encoded}");
        assert_eq!(
            hasher.verify("correct horse battery", &encoded),
            PasswordVerdict::Accepted { needs_rehash: false }
        );
        assert_eq!(hasher.verify("Correct horse battery", &encoded), PasswordVerdict::Rejected);
    }

    #[test]
    fn rehash_is_requested_when_the_stored_cost_is_below_policy() {
        let old = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        let stored = old.hash("correct horse battery").expect("hash");

        // The deployment raises its cost floor.
        let new = PasswordHasher::new(cheap(2048, 2)).expect("valid params");
        assert_eq!(
            new.verify("correct horse battery", &stored),
            PasswordVerdict::Accepted { needs_rehash: true },
            "an existing hash must still verify, and must be flagged for upgrade"
        );

        // ...and lowering it again must not silently downgrade the stronger hash.
        let stronger = new.hash("correct horse battery").expect("hash");
        assert_eq!(
            old.verify("correct horse battery", &stronger),
            PasswordVerdict::Accepted { needs_rehash: false }
        );
    }

    #[test]
    fn the_length_policy_applies_to_new_passwords_only() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        assert!(matches!(
            hasher.hash("short"),
            Err(AuthError::PasswordPolicy { code: ValidationCode::TooShort })
        ));
        assert!(matches!(
            hasher.hash(&"x".repeat(129)),
            Err(AuthError::PasswordPolicy { code: ValidationCode::TooLong })
        ));

        // A pre-existing hash of a now-too-short password still lets its owner in.
        let lenient = PasswordHasher::new(PasswordPolicy { min_length: 4, ..cheap(1024, 1) })
            .expect("valid params");
        let legacy = lenient.hash("short").expect("hash");
        assert!(hasher.verify("short", &legacy).is_accepted());
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        // Twelve scalar values, thirty-six bytes.
        let devanagari = "पासवर्डपासवर्ड"[..].chars().take(12).collect::<String>();
        assert_eq!(devanagari.chars().count(), 12);
        assert!(hasher.check_policy(&devanagari).is_ok());
    }

    #[test]
    fn a_corrupt_stored_hash_rejects_rather_than_erroring() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        assert_eq!(
            hasher.verify("correct horse battery", "not-a-phc-string"),
            PasswordVerdict::Rejected
        );
        assert_eq!(hasher.verify("correct horse battery", ""), PasswordVerdict::Rejected);
    }

    #[test]
    fn verifying_an_absent_credential_always_rejects() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        assert_eq!(hasher.verify_absent("anything at all"), PasswordVerdict::Rejected);
    }

    #[test]
    fn an_argon2i_hash_is_treated_as_below_policy() {
        let hasher = PasswordHasher::new(cheap(1024, 1)).expect("valid params");
        let argon2i = Argon2::new(
            Algorithm::Argon2i,
            Version::V0x13,
            Params::new(1024, 1, 1, None).expect("params"),
        );
        let salt = SaltString::generate(&mut OsRng);
        let stored =
            argon2i.hash_password(b"correct horse battery", &salt).expect("hash").to_string();

        assert_eq!(
            hasher.verify("correct horse battery", &stored),
            PasswordVerdict::Accepted { needs_rehash: true },
            "a legacy algorithm must be upgraded on next login"
        );
    }
}
