//! The `GET /.well-known/jwks.json` document (`docs/03-LLD.md §5.5`, `docs/05-API.md §3`).
//!
//! # What is published, and why it is more than the signing key
//!
//! A JWKS document exists so that other parties can verify tokens Enclave issued, and it is served
//! unauthenticated. Publishing only the currently-signing key would break rotation in both
//! directions:
//!
//! - The **pending** key must appear *before* it signs anything. Clients cache JWKS; a key that
//!   starts signing the moment it is created signs tokens that every cached client rejects. That
//!   gap is the propagation delay in `docs/03-LLD.md §5.5`, and publishing early is what fills it.
//! - The **retiring** key must stay published until its overlap window closes, because tokens it
//!   signed are still in flight.
//!
//! What is never published is a [`crate::keys::KeyStatus::Retired`] key. Leaving one in the
//! document says "this key is still trusted" to every consumer, which is precisely what retiring it
//! was meant to stop.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::keys::PublicSigningKey;

/// One key in a JWKS document, in the OKP form RFC 8037 defines for Ed25519.
///
/// Every field is fixed except `x` and `kid`. `alg` is emitted as a statement of what this key is
/// for, not as an instruction — a consumer that reads `alg` out of the JWKS and then honours the
/// *token's* `alg` has reintroduced the confusion this deployment pins against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type. Always `OKP` for Ed25519.
    pub kty: String,
    /// Curve. Always `Ed25519`.
    pub crv: String,
    /// The public key, base64url without padding.
    pub x: String,
    /// Key identifier, matching the token header's `kid`.
    pub kid: String,
    /// Algorithm. Always `EdDSA`.
    pub alg: String,
    /// Public key use. Always `sig`.
    #[serde(rename = "use")]
    pub key_use: String,
}

impl Jwk {
    /// Renders a public key as a JWK.
    #[must_use]
    pub fn from_public_key(key: &PublicSigningKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(key.public_key),
            kid: key.kid.to_string(),
            alg: "EdDSA".to_owned(),
            key_use: "sig".to_owned(),
        }
    }
}

/// The JWKS document itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The published keys.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Builds the document from everything the key provider knows, at `now`.
    ///
    /// Filtering happens here rather than at the endpoint so that there is one answer to "is this
    /// key published?" — [`PublicSigningKey::usable_at`] — shared with the verifier. If the two
    /// ever disagreed, the deployment would either publish a key it will not accept or accept one
    /// it does not publish, and both are the sort of thing that is only noticed during an incident.
    #[must_use]
    pub fn from_keys<'a>(
        keys: impl IntoIterator<Item = &'a PublicSigningKey>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            keys: keys
                .into_iter()
                .filter(|key| key.status.published() && key.usable_at(now))
                .map(Jwk::from_public_key)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::keys::{KeyStatus, PrivateSigningKey};
    use chrono::Duration;

    fn key(status: KeyStatus, retires_at: Option<DateTime<Utc>>) -> PublicSigningKey {
        let now = Utc::now();
        let generated = PrivateSigningKey::generate(now).expect("generate");
        let mut public = generated.public().clone();
        public.status = status;
        public.retires_at = retires_at;
        public
    }

    #[test]
    fn active_pending_and_retiring_keys_are_published_and_retired_ones_are_not() {
        let now = Utc::now();
        let active = key(KeyStatus::Active, None);
        let pending = key(KeyStatus::Pending, None);
        let retiring = key(KeyStatus::Retiring, Some(now + Duration::hours(24)));
        let expired = key(KeyStatus::Retiring, Some(now - Duration::seconds(1)));
        let retired = key(KeyStatus::Retired, None);

        let all = [&active, &pending, &retiring, &expired, &retired];
        let document = Jwks::from_keys(all, now);

        let published: Vec<&str> = document.keys.iter().map(|k| k.kid.as_str()).collect();
        assert_eq!(published.len(), 3, "{published:?}");
        assert!(published.contains(&active.kid.as_str()));
        assert!(published.contains(&pending.kid.as_str()));
        assert!(published.contains(&retiring.kid.as_str()));
        assert!(!published.contains(&expired.kid.as_str()));
        assert!(!published.contains(&retired.kid.as_str()));
    }

    #[test]
    fn a_jwk_has_the_rfc_8037_shape_and_the_right_key_bytes() {
        let now = Utc::now();
        let active = key(KeyStatus::Active, None);
        let document = Jwks::from_keys([&active], now);
        let jwk = document.keys.first().expect("one key");

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.key_use, "sig");
        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.x).expect("base64url"), active.public_key.to_vec());

        // `use` is a Rust keyword; the serialised name must still be `use`.
        let json = serde_json::to_value(&document).expect("serialize");
        assert_eq!(json["keys"][0]["use"], "sig");
        assert!(json["keys"][0].as_object().expect("object").contains_key("use"));
    }

    #[test]
    fn a_document_with_no_usable_keys_is_empty_rather_than_absent() {
        let now = Utc::now();
        let retired = key(KeyStatus::Retired, None);
        let document = Jwks::from_keys([&retired], now);
        assert!(document.keys.is_empty());
        // An empty `keys` array is a valid JWKS meaning "trust nothing"; omitting the field would
        // make consumers fall back to a cached document.
        let json = serde_json::to_string(&document).expect("serialize");
        assert_eq!(json, r#"{"keys":[]}"#);
    }
}
