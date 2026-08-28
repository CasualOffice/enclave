//! Issuing and verifying Ed25519 access tokens.
//!
//! # The one rule this module exists to enforce
//!
//! **The verification algorithm is a constant in this file. It is never read from the token.**
//!
//! A JWT's header is unauthenticated attacker-controlled input, and `alg` is the field in it that
//! decides how the *rest* of the token is checked. Trusting it produces the two classic breaks:
//! `alg: none`, where the verifier is told not to verify, and algorithm confusion, where an
//! `HS256` token is verified with the deployment's Ed25519 public key as the HMAC secret — a key
//! that is, by design, published at `/.well-known/jwks.json`.
//!
//! [`AccessTokenVerifier::verify`] therefore reads only one thing from the header without checking
//! it — `kid`, which names a key but authorises nothing — and rejects any `alg` other than
//! [`TOKEN_ALGORITHM`] before a signature is looked at. This is test K8, and
//! `plans/M0-FOUNDATIONS.md` ENC-111 is explicit that it is a one-line mistake to get wrong.
//!
//! # Why the clock is a parameter
//!
//! Every time comparison takes `now` from the caller rather than reading the system clock. That
//! makes the bounded 60-second skew tolerance (K1) a property that can be tested at both of its
//! edges instead of an assertion about `Utc::now()`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use enclave_core::{ActorKind, ClientType, ScopeSet};
use jsonwebtoken::{Algorithm, Header, Validation};
use serde::Deserialize;
use uuid::Uuid;

use crate::claims::{AccessTokenClaims, VerifiedAccessToken};
use crate::error::{sanitize_alg, AuthError};
use crate::keys::{KeyId, KeySet, PrivateSigningKey};

/// The only signature algorithm Enclave issues or accepts.
///
/// A constant, not a configuration value. See the module documentation for why a deployment that
/// could be configured to accept `HS256` is a deployment one YAML edit from being compromised.
pub const TOKEN_ALGORITHM: Algorithm = Algorithm::EdDSA;

/// Clock skew tolerated on `exp`, `iat` and `auth_time`, in seconds (K1).
///
/// Bounded, and bounded *here*. Sixty seconds is enough for hosts whose NTP has drifted and not
/// enough to matter against a ten-minute token lifetime. The number being a constant rather than a
/// setting is the point: "just widen the tolerance" is the tempting fix for a clock problem and it
/// silently extends the life of every revoked token in flight.
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

/// Scopes whose loss of revocation coverage is unacceptable (`docs/03-LLD.md §5.4`).
///
/// The `admin:` and `security:` entries are *families* — every scope under them counts. Note that
/// `ScopeSet` matching is exact and does not expand wildcards, which is why this is a prefix check
/// and not a `contains("admin:*")`.
const PRIVILEGED_SCOPE_PREFIXES: [&str; 2] = ["admin:", "security:"];

/// Individually privileged scopes that are not part of a family.
const PRIVILEGED_SCOPES: [&str; 1] = ["share:external"];

/// Whether a scope set is privileged, and therefore fails closed when revocation state is unknown
/// (K9).
///
/// Public because the same question decides the shorter access-token TTL at issuance and the
/// fail-closed behaviour at verification, and two implementations of it would eventually disagree
/// about `share:external`.
#[must_use]
pub fn is_privileged(scopes: &ScopeSet) -> bool {
    PRIVILEGED_SCOPE_PREFIXES.iter().any(|p| scopes.has_prefix(p))
        || scopes.contains_any(&PRIVILEGED_SCOPES)
}

/// Whether a client type may only operate from a registered device (K7).
///
/// `sync` and `editor` replicate or hand off content to software outside the browser sandbox, so
/// `docs/03-LLD.md §5.2` binds them to a device. A token for one of these without a `dev` claim is
/// rejected outright rather than treated as an unmanaged device, because the binding is what makes
/// device revocation (Y7) able to stop it.
#[must_use]
pub const fn requires_device_binding(client: ClientType) -> bool {
    matches!(client, ClientType::Sync | ClientType::Editor)
}

/// The parts of a JOSE header this crate will look at.
///
/// `alg` is `String`, not `jsonwebtoken::Algorithm`, on purpose: parsing it into the library's
/// enum would make `alg: none` a deserialization error indistinguishable from a truncated token,
/// and would lose the value we want to log. Keeping it a string means the comparison against
/// [`TOKEN_ALGORITHM`] is visible in this file.
#[derive(Debug, Deserialize)]
struct UntrustedHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Signs access tokens.
///
/// Holds no key material — the key is passed per call, because
/// [`crate::keys::KeyProvider::active_signing_key`] is what decides which key is current and
/// caching that decision inside an issuer would outlive a rotation.
#[derive(Debug, Clone)]
pub struct AccessTokenIssuer {
    issuer: String,
    audience: String,
}

impl AccessTokenIssuer {
    /// Builds an issuer for one deployment identity.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self { issuer: issuer.into(), audience: audience.into() }
    }

    /// Signs a token for the given claims, stamping `iss`, `aud`, `iat`, `exp` and `jti`.
    ///
    /// Those five are set here rather than accepted from the caller so that no call site can mint a
    /// token for another issuer, or one that never expires.
    ///
    /// # Errors
    ///
    /// [`AuthError::Encoding`] if serialisation or signing fails, and
    /// [`AuthError::ActorKindNotATokenSubject`] for a `typ` this deployment never mints.
    pub fn issue(
        &self,
        key: &PrivateSigningKey,
        template: TokenTemplate,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<IssuedAccessToken, AuthError> {
        // `ENC-879`. Refused at the mint as well as at the door: a token that never exists cannot
        // leak, and a caller that meant to write `ActorKind::Guest` finds out here rather than
        // discovering at redemption time that its token is rejected.
        if !is_token_subject(template.typ) {
            return Err(AuthError::ActorKindNotATokenSubject { kind: template.typ });
        }

        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: template.sub,
            tid: template.tid,
            sid: template.sid,
            typ: template.typ,
            scp: template.scp,
            amr: template.amr,
            auth_time: template.auth_time.timestamp(),
            acr: template.acr,
            dev: template.dev,
            cli: template.cli,
            epoch: template.epoch,
            jti: Uuid::new_v4(),
            iat: now.timestamp(),
            exp: (now + ttl).timestamp(),
            max_cls: template.max_cls,
        };

        let mut header = Header::new(TOKEN_ALGORITHM);
        header.kid = Some(key.kid().to_string());
        let encoded = jsonwebtoken::encode(&header, &claims, &key.encoding_key())
            .map_err(AuthError::Encoding)?;

        Ok(IssuedAccessToken { token: encoded, claims })
    }
}

/// Everything about a token that the caller decides, as opposed to the issuer.
///
/// A struct rather than a long argument list because the fields are almost all UUIDs, and a
/// positional call with six of them is a transposition waiting to happen — `sub` and `tid` swapped
/// would authenticate a user as their own tenant.
#[derive(Debug, Clone)]
pub struct TokenTemplate {
    /// Subject identifier.
    pub sub: Uuid,
    /// Tenant identifier.
    pub tid: Uuid,
    /// Session (refresh family) identifier.
    pub sid: Uuid,
    /// Actor kind, for the `typ` claim.
    pub typ: enclave_core::ActorKind,
    /// Scopes.
    pub scp: Vec<String>,
    /// Authentication methods used.
    pub amr: Vec<crate::claims::AuthMethod>,
    /// When the authentication event happened.
    pub auth_time: DateTime<Utc>,
    /// Authentication context class.
    pub acr: crate::claims::Acr,
    /// Bound device, where there is one.
    pub dev: Option<Uuid>,
    /// Client type.
    pub cli: ClientType,
    /// The subject's `token_epoch` at issuance.
    pub epoch: i32,
    /// Classification ceiling, for MCP clients only.
    pub max_cls: Option<enclave_core::ClassificationRank>,
}

/// A freshly signed token and the claims that went into it.
///
/// The claims come back so the caller can denylist the `jti` on logout and record `exp` without
/// re-parsing what it just produced.
#[derive(Debug, Clone)]
pub struct IssuedAccessToken {
    /// The compact serialisation, for the `Authorization` header.
    pub token: String,
    /// The claims it carries.
    pub claims: AccessTokenClaims,
}

/// Verifies access tokens against a pinned algorithm and a snapshot of the key set.
///
/// Cheap to clone and free of I/O, which is what lets `docs/03-LLD.md §5.1` promise that the hot
/// path does no database or Redis round trip.
#[derive(Debug, Clone)]
pub struct AccessTokenVerifier {
    issuer: String,
    audience: String,
    keys: KeySet,
}

impl AccessTokenVerifier {
    /// Builds a verifier for one deployment identity and key snapshot.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, keys: KeySet) -> Self {
        Self { issuer: issuer.into(), audience: audience.into(), keys }
    }

    /// Replaces the key snapshot after a rotation.
    #[must_use]
    pub fn with_keys(mut self, keys: KeySet) -> Self {
        self.keys = keys;
        self
    }

    /// Verifies a compact JWS and every claim that does not require I/O.
    ///
    /// The order is deliberate and each step is cheap before the one after it: shape, then
    /// algorithm, then key, then signature, then claims. An attacker probing with garbage never
    /// reaches a signature verification, and — more importantly — a token whose header lies about
    /// its algorithm is rejected before any key is selected for it.
    ///
    /// Revocation is **not** checked here; see [`crate::revocation::RevocationChecker`].
    ///
    /// # Errors
    ///
    /// One of the token variants of [`AuthError`]. They are distinct so operators can tell them
    /// apart in logs, and they all collapse to one reason code on the way to the client.
    pub fn verify(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedAccessToken, AuthError> {
        let header = decode_header(token)?;

        // Step 1: the pinned algorithm. Before key selection, before signature verification, and
        // without ever passing `header.alg` to the verification routine. K8.
        if header.alg != algorithm_name() {
            return Err(AuthError::AlgorithmNotPinned { presented: sanitize_alg(&header.alg) });
        }

        // Step 2: `kid` selects a key but authorises nothing — the signature still has to verify
        // against it — so taking it from an unverified header is safe.
        let kid = header.kid.map(KeyId::from_untrusted).ok_or(AuthError::UnknownSigningKey)?;
        let key = self.keys.verification_key(&kid, now).ok_or(AuthError::UnknownSigningKey)?;

        // Step 3: signature. `validation.algorithms` is the library's own pin; we set it from the
        // same constant rather than from anything in the token, so both layers agree by
        // construction.
        let data = jsonwebtoken::decode::<AccessTokenClaims>(
            token,
            &key.decoding_key(),
            &pinned_validation(),
        )
        .map_err(|err| match err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
            | jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName => {
                AuthError::AlgorithmNotPinned { presented: sanitize_alg(&header.alg) }
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::SignatureInvalid,
            _ => AuthError::MalformedToken,
        })?;

        self.check_claims(&data.claims, now)?;
        Ok(VerifiedAccessToken::new(data.claims))
    }

    /// The time, identity and binding checks, all against the caller's `now`.
    fn check_claims(
        &self,
        claims: &AccessTokenClaims,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let skew = Duration::seconds(CLOCK_SKEW_TOLERANCE_SECS);

        // K1. The tolerance is applied once, symmetrically, and is bounded by the constant above.
        if claims.expires_at() + skew <= now {
            return Err(AuthError::TokenExpired);
        }
        if claims.issued_at() - skew > now {
            return Err(AuthError::TokenNotYetValid);
        }
        // A future `auth_time` would make the token permanently satisfy every max-age and step-up
        // policy, which is a quieter failure than a future `iat` and therefore worth its own check.
        if claims.authenticated_at() - skew > now {
            return Err(AuthError::TokenNotYetValid);
        }

        // Constant-time comparison buys nothing here: `iss` and `aud` are public values, and the
        // caller already knows them because it sent them.
        if claims.iss != self.issuer || claims.aud != self.audience {
            return Err(AuthError::WrongAudience);
        }

        // K7.
        if requires_device_binding(claims.cli) && claims.dev.is_none() {
            return Err(AuthError::DeviceBindingRequired);
        }

        // `ENC-879`. The `typ` claim selects which `Actor` variant the request runs as, so a kind
        // that is not a token subject must be refused *here*, before `VerifiedAccessToken` exists:
        // everything downstream reads the actor and none of it re-asks where the actor came from.
        if !is_token_subject(claims.typ) {
            return Err(AuthError::ActorKindNotATokenSubject { kind: claims.typ });
        }

        Ok(())
    }
}

/// Whether an access token may assert this actor kind (`ENC-879`).
///
/// Exhaustive rather than `!matches!(kind, ShareLink)`, so a new [`ActorKind`] cannot inherit the
/// permissive answer: whoever adds one has to say here whether a signed JWT is allowed to claim it,
/// which is the same argument [`crate::routes`]-side matches on `Actor` make elsewhere.
///
/// [`ActorKind::ShareLink`] is the only `false`. See [`AuthError::ActorKindNotATokenSubject`].
const fn is_token_subject(kind: ActorKind) -> bool {
    match kind {
        ActorKind::User
        | ActorKind::Guest
        | ActorKind::ServiceAccount
        | ActorKind::McpClient
        | ActorKind::System => true,
        ActorKind::ShareLink => false,
    }
}

/// The library-level validation, pinned and stripped of the checks we do ourselves.
///
/// Time validation is turned off here and reimplemented in [`AccessTokenVerifier::check_claims`]
/// because `jsonwebtoken` compares against the process clock, and a security property that can only
/// be tested by changing the system time is a security property that does not get tested.
fn pinned_validation() -> Validation {
    let mut validation = Validation::new(TOKEN_ALGORITHM);
    validation.algorithms = vec![TOKEN_ALGORITHM];
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation
}

/// The wire spelling of the pinned algorithm, derived from the constant so the two cannot drift.
fn algorithm_name() -> String {
    // `Algorithm` serialises to its JOSE name; going through serde rather than hard-coding
    // `"EdDSA"` means changing `TOKEN_ALGORITHM` changes this too.
    serde_json::to_value(TOKEN_ALGORITHM)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "EdDSA".to_owned())
}

/// Parses the header segment without trusting anything in it.
///
/// Written by hand rather than using `jsonwebtoken::decode_header` because that function parses
/// `alg` into an enum with no `none` variant, so `alg: none` comes back as a generic parse error —
/// and a rejection we cannot distinguish from a typo is a rejection we cannot prove we made for the
/// right reason.
fn decode_header(token: &str) -> Result<UntrustedHeader, AuthError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::MalformedToken);
    };
    // An unsigned token — `alg: none` conventionally carries an empty third segment — never reaches
    // signature verification, so refuse it by shape as well as by algorithm.
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AuthError::MalformedToken);
    }
    let raw = URL_SAFE_NO_PAD.decode(header).map_err(|_| AuthError::MalformedToken)?;
    serde_json::from_slice(&raw).map_err(|_| AuthError::MalformedToken)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::claims::{Acr, AuthMethod};
    use crate::keys::KeyStatus;
    use enclave_core::ActorKind;

    const ISS: &str = "https://workspace.example.com";
    const AUD: &str = "enclave-api";

    struct Fixture {
        key: PrivateSigningKey,
        issuer: AccessTokenIssuer,
        verifier: AccessTokenVerifier,
        now: DateTime<Utc>,
    }

    fn fixture() -> Fixture {
        let now = Utc::now();
        let key = PrivateSigningKey::generate(now).expect("generate");
        let verifier = AccessTokenVerifier::new(ISS, AUD, KeySet::new([key.public().clone()]));
        Fixture { key, issuer: AccessTokenIssuer::new(ISS, AUD), verifier, now }
    }

    fn template(cli: ClientType, dev: Option<Uuid>) -> TokenTemplate {
        TokenTemplate {
            sub: Uuid::new_v4(),
            tid: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            typ: ActorKind::User,
            scp: vec!["files:read".to_owned()],
            amr: vec![AuthMethod::Pwd],
            auth_time: Utc::now(),
            acr: Acr::SingleFactor,
            dev,
            cli,
            epoch: 1,
            max_cls: None,
        }
    }

    fn tamper_header(token: &str, header_json: &str) -> String {
        let mut parts = token.splitn(3, '.');
        let _original = parts.next();
        let payload = parts.next().expect("payload");
        let signature = parts.next().expect("signature");
        format!("{}.{payload}.{signature}", URL_SAFE_NO_PAD.encode(header_json))
    }

    #[test]
    fn a_freshly_issued_token_verifies() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");

        let verified = f.verifier.verify(&issued.token, f.now).expect("verify");
        assert_eq!(verified.claims(), &issued.claims);
        assert_eq!(verified.claims().iss, ISS);
    }

    #[test]
    fn k1_an_expired_token_is_rejected_and_the_skew_tolerance_is_bounded() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        let expiry = f.now + Duration::minutes(10);

        // Inside the bounded tolerance: accepted, because a host whose clock is 30 s fast must not
        // reject a token that has genuinely not expired.
        f.verifier
            .verify(&issued.token, expiry + Duration::seconds(30))
            .expect("30s past expiry is inside the 60s tolerance");

        // At the boundary and beyond: rejected. This is the assertion that makes the tolerance
        // *bounded* rather than merely present.
        assert!(matches!(
            f.verifier.verify(&issued.token, expiry + Duration::seconds(60)),
            Err(AuthError::TokenExpired)
        ));
        assert!(matches!(
            f.verifier.verify(&issued.token, expiry + Duration::seconds(61)),
            Err(AuthError::TokenExpired)
        ));
        assert!(matches!(
            f.verifier.verify(&issued.token, expiry + Duration::hours(1)),
            Err(AuthError::TokenExpired)
        ));
        assert_eq!(CLOCK_SKEW_TOLERANCE_SECS, 60);
    }

    #[test]
    fn k1_a_token_from_the_future_is_rejected_beyond_the_same_tolerance() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");

        f.verifier
            .verify(&issued.token, f.now - Duration::seconds(30))
            .expect("30s of clock skew the other way is tolerated too");
        assert!(matches!(
            f.verifier.verify(&issued.token, f.now - Duration::seconds(120)),
            Err(AuthError::TokenNotYetValid)
        ));
    }

    #[test]
    fn k2_a_token_signed_by_a_retired_key_is_rejected_after_the_overlap_window() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::hours(48))
            .expect("issue");

        let mut retiring = f.key.public().clone();
        retiring.status = KeyStatus::Retiring;
        retiring.retires_at = Some(f.now + Duration::hours(24));
        let verifier = f.verifier.clone().with_keys(KeySet::new([retiring]));

        verifier
            .verify(&issued.token, f.now + Duration::hours(23))
            .expect("inside the overlap window the token still verifies");
        assert!(
            matches!(
                verifier.verify(&issued.token, f.now + Duration::hours(25)),
                Err(AuthError::UnknownSigningKey)
            ),
            "K2: past the overlap window the key is gone, even though the token has not expired"
        );
    }

    #[test]
    fn k8_alg_none_is_rejected() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");

        let kid = f.key.kid().to_string();
        let forged = tamper_header(&issued.token, &format!(r#"{{"alg":"none","kid":"{kid}"}}"#));
        assert!(matches!(
            f.verifier.verify(&forged, f.now),
            Err(AuthError::AlgorithmNotPinned { .. })
        ));

        // The classic shape: `alg: none` with the signature stripped entirely.
        let payload = issued.token.split('.').nth(1).expect("payload");
        let unsigned = format!(
            "{}.{payload}.",
            URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"none","kid":"{kid}"}}"#))
        );
        assert!(matches!(f.verifier.verify(&unsigned, f.now), Err(AuthError::MalformedToken)));
    }

    #[test]
    fn k8_algorithm_confusion_with_the_public_key_as_an_hmac_secret_is_rejected() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        let kid = f.key.kid().to_string();

        // Re-sign the real claims with HS256, using the published Ed25519 public key as the shared
        // secret — the exact attack that made this class of bug famous.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.clone());
        let forged = jsonwebtoken::encode(
            &header,
            &issued.claims,
            &jsonwebtoken::EncodingKey::from_secret(&f.key.public().public_key),
        )
        .expect("forge");

        assert!(
            matches!(
                f.verifier.verify(&forged, f.now),
                Err(AuthError::AlgorithmNotPinned { presented }) if presented == "HS256"
            ),
            "K8: the header's algorithm must never be honoured"
        );
    }

    #[test]
    fn k8_a_valid_header_over_a_tampered_payload_fails_the_signature() {
        let f = fixture();
        let issued = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");

        let mut claims = issued.claims.clone();
        claims.scp = vec!["admin:everything".to_owned()];
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
        let mut parts = issued.token.splitn(3, '.');
        let header = parts.next().expect("header");
        let signature = parts.nth(1).expect("signature");
        let forged = format!("{header}.{payload}.{signature}");

        assert!(matches!(f.verifier.verify(&forged, f.now), Err(AuthError::SignatureInvalid)));
    }

    #[test]
    fn k8_malformed_and_unknown_key_tokens_are_rejected() {
        let f = fixture();
        for garbage in ["", "not-a-token", "a.b", "a.b.c.d", "!!!.!!!.!!!"] {
            assert!(f.verifier.verify(garbage, f.now).is_err(), "accepted {garbage:?}");
        }

        // A structurally perfect token signed by a key this deployment has never heard of.
        let stranger = PrivateSigningKey::generate(f.now).expect("generate");
        let issued = f
            .issuer
            .issue(&stranger, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        assert!(matches!(
            f.verifier.verify(&issued.token, f.now),
            Err(AuthError::UnknownSigningKey)
        ));
    }

    #[test]
    fn a_token_for_another_deployment_is_rejected() {
        let f = fixture();
        let foreign = AccessTokenIssuer::new("https://evil.example.com", AUD);
        let issued = foreign
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        assert!(matches!(f.verifier.verify(&issued.token, f.now), Err(AuthError::WrongAudience)));

        let wrong_audience = AccessTokenIssuer::new(ISS, "some-other-api");
        let issued = wrong_audience
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        assert!(matches!(f.verifier.verify(&issued.token, f.now), Err(AuthError::WrongAudience)));
    }

    #[test]
    fn k7_sync_and_editor_tokens_require_a_device_claim() {
        let f = fixture();
        for client in [ClientType::Sync, ClientType::Editor] {
            let unbound = f
                .issuer
                .issue(&f.key, template(client, None), f.now, Duration::minutes(10))
                .expect("issue");
            assert!(
                matches!(
                    f.verifier.verify(&unbound.token, f.now),
                    Err(AuthError::DeviceBindingRequired)
                ),
                "K7: {client} without a dev claim must be rejected"
            );

            let bound = f
                .issuer
                .issue(&f.key, template(client, Some(Uuid::new_v4())), f.now, Duration::minutes(10))
                .expect("issue");
            f.verifier.verify(&bound.token, f.now).expect("a bound device is accepted");
        }

        // Ordinary clients are unaffected.
        let web = f
            .issuer
            .issue(&f.key, template(ClientType::Web, None), f.now, Duration::minutes(10))
            .expect("issue");
        f.verifier.verify(&web.token, f.now).expect("web needs no device binding");
    }

    #[test]
    fn privileged_scopes_are_recognised_by_family_and_by_name() {
        let admin: ScopeSet = ["admin:users"].into_iter().collect();
        let security: ScopeSet = ["security:incidents"].into_iter().collect();
        let external: ScopeSet = ["share:external"].into_iter().collect();
        let ordinary: ScopeSet = ["files:read", "search", "share:internal"].into_iter().collect();

        assert!(is_privileged(&admin));
        assert!(is_privileged(&security));
        assert!(is_privileged(&external));
        assert!(!is_privileged(&ordinary));
        assert!(!is_privileged(&ScopeSet::empty()));
    }

    #[test]
    fn the_pinned_algorithm_name_is_derived_from_the_constant() {
        assert_eq!(algorithm_name(), "EdDSA");
    }
}
