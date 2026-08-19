//! Share tokens: minted once, handed over once, and stored only as a digest.
//!
//! `docs/12-TESTING.md §4.4` H1 — *"a share token is unguessable and stored only as a hash"* — is
//! two claims, and they are defended separately.
//!
//! **Unguessable** is [`SHARE_TOKEN_BYTES`] of operating-system entropy. Not a UUID, not a counter,
//! not a slug derived from the file name: a share link is frequently the only credential protecting
//! a document that has left the organisation, so its entire security is the difficulty of guessing
//! it. 256 bits makes that difficulty absolute rather than merely large.
//!
//! **Stored only as a hash** is [`ShareToken::digest`]. A database backup, a read replica, a
//! support export or a `SELECT *` in an incident bridge yields no working link. This mirrors
//! `enclave_auth::RefreshToken` deliberately, down to the method names — two token primitives in
//! one product that make different choices about the same problem is how one of them ends up
//! wrong, and the reviewer of the second one never notices because it looks self-consistent.
//!
//! # Why SHA-256 and not Argon2
//!
//! `share_links.password_hash` *is* Argon2id, and the difference is worth being explicit about,
//! because "use the slow hash" is the usual advice and here it would be wrong twice over.
//!
//! A password is low-entropy and chosen by a person, so it must be made expensive to guess. A share
//! token is 256 bits of uniform randomness: there is no dictionary, no reuse across sites and no
//! meaningful search space, so a work factor buys nothing an attacker would notice. What it costs
//! is real — redemption looks a token up **by** its digest (`uq_share_token`), and a
//! per-row-salted hash is not something you can index, so Argon2 would force either a table scan
//! per redemption or a second unsalted index that defeats the point.
//!
//! # Where the plaintext exists
//!
//! Exactly twice: in the return value of [`ShareToken::generate`], and in the URL the creator
//! copies. It is [`Zeroizing`], and the accessor is named [`ShareToken::expose`] rather than
//! `as_str` so that every place it escapes is one `grep` away.

use core::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rand_core::TryRng as _;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::SharingError;

/// Entropy in a share token, in bytes. 256 bits.
pub const SHARE_TOKEN_BYTES: usize = 32;

/// A share token in plaintext.
///
/// Deliberately not `Clone`, not `Serialize` and not `Display`: every one of those is a way for a
/// credential to reach a log, a span attribute or a response body without anybody deciding it
/// should.
pub struct ShareToken(Zeroizing<String>);

impl fmt::Debug for ShareToken {
    /// Never the value. A token in a bug report is a working link in a bug report.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShareToken(redacted)")
    }
}

impl ShareToken {
    /// Mints 256 bits from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`SharingError::EntropyUnavailable`] if the OS declines to provide randomness. Propagated
    /// rather than unwrapped, for the reason `enclave_auth::RefreshToken::generate` gives: a token
    /// minted from a degraded entropy source is worse than no token, and aborting the process is a
    /// worse answer than an error the caller can report.
    pub fn generate() -> Result<Self, SharingError> {
        let mut bytes = Zeroizing::new([0_u8; SHARE_TOKEN_BYTES]);
        SysRng
            .try_fill_bytes(bytes.as_mut_slice())
            .map_err(|_| SharingError::EntropyUnavailable)?;
        Ok(Self(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()))))
    }

    /// Accepts a token presented by a client.
    ///
    /// The length check is a cheap filter rather than a control — a wrong-length value would miss
    /// in the store anyway — but redemption is an unauthenticated endpoint, and keeping obvious
    /// junk away from a database lookup is worth one comparison.
    ///
    /// # Errors
    ///
    /// [`SharingError::LinkUnusable`], the same error an unknown, expired or revoked token
    /// produces, so that none of the four is distinguishable from the others.
    pub fn parse(presented: &str) -> Result<Self, SharingError> {
        let decoded = URL_SAFE_NO_PAD.decode(presented).map_err(|_| SharingError::LinkUnusable)?;
        if decoded.len() != SHARE_TOKEN_BYTES {
            return Err(SharingError::LinkUnusable);
        }
        Ok(Self(Zeroizing::new(presented.to_owned())))
    }

    /// The value to put in the URL handed to the creator.
    ///
    /// Named `expose` rather than `as_str` so every place the plaintext escapes is greppable.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value stored in `share_links.token_hash`.
    #[must_use]
    pub fn digest(&self) -> ShareTokenDigest {
        ShareTokenDigest(Sha256::digest(self.0.as_bytes()).into())
    }
}

/// SHA-256 of a share token: what the database holds, and the only form ever compared.
#[derive(Clone, Copy)]
pub struct ShareTokenDigest([u8; 32]);

impl fmt::Debug for ShareTokenDigest {
    /// A digest is not a credential, but printing it in full invites somebody to paste it into a
    /// bug report and from there into a `WHERE` clause. Eight hex characters correlate well enough.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareTokenDigest({}…)", &self.to_hex()[..8])
    }
}

impl PartialEq for ShareTokenDigest {
    /// Constant time. A comparison that short-circuits leaks, byte by byte, how much of a guess was
    /// right — which over enough attempts reconstructs a stored digest.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for ShareTokenDigest {}

impl ShareTokenDigest {
    /// Lowercase hex, as stored in `share_links.token_hash`.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_token_never_prints_itself() {
        let token = ShareToken::generate().expect("entropy");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "ShareToken(redacted)");
        assert!(
            !rendered.contains(token.expose()),
            "the Debug impl leaked the token, so any tracing span carrying one is a working link"
        );
    }

    #[test]
    fn two_tokens_are_never_the_same() {
        // Not a statistical claim about the CSPRNG — a check that `generate` reads fresh entropy
        // each call rather than caching, which is the way this goes wrong in practice.
        let a = ShareToken::generate().expect("entropy");
        let b = ShareToken::generate().expect("entropy");
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.digest().to_hex(), b.digest().to_hex());
    }

    #[test]
    fn a_token_carries_the_full_entropy_it_claims() {
        let token = ShareToken::generate().expect("entropy");
        let decoded = URL_SAFE_NO_PAD.decode(token.expose()).expect("base64url");
        assert_eq!(decoded.len(), SHARE_TOKEN_BYTES);
        // All-zero would mean the fill silently did nothing, which `try_fill_bytes` reporting `Ok`
        // on a broken RNG is exactly what would look like.
        assert_ne!(decoded, vec![0_u8; SHARE_TOKEN_BYTES]);
    }

    #[test]
    fn the_digest_is_stable_and_round_trips_through_parse() {
        let token = ShareToken::generate().expect("entropy");
        let presented = ShareToken::parse(token.expose()).expect("well-formed");
        assert_eq!(token.digest(), presented.digest());
        assert_eq!(token.digest().to_hex().len(), 64);
    }

    #[test]
    fn malformed_tokens_are_refused_the_same_way_an_unknown_one_is() {
        for junk in ["", "not base64!!", "short", &"A".repeat(100)] {
            assert!(
                matches!(ShareToken::parse(junk), Err(SharingError::LinkUnusable)),
                "`{junk}` was distinguishable from an unknown token"
            );
        }
    }
}
