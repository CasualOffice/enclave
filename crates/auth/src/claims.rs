//! The access-token claim set (`docs/03-LLD.md §5.2`).
//!
//! Every field here is an **assertion to be checked**, never a permission. `scp` can only narrow
//! what a caller may attempt; authorization still re-resolves the ACL from PostgreSQL on every
//! request. A change that starts treating a claim as authoritative for access is a change to the
//! security model, not an optimisation.

use chrono::{DateTime, TimeZone as _, Utc};
use enclave_core::{
    Actor, ActorKind, AuthStrength, ClassificationRank, ClientType, DeviceContext, DevicePosture,
    GuestId, McpClientId, NetworkContext, RequestContext, RequestId, ScopeSet, ServiceAccountId,
    SessionId, ShareLinkId, TenantId, UserId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication methods used, for the `amr` claim (RFC 8176 where a value exists).
///
/// Kept as a closed enumeration rather than free strings so that a conditional-access rule reading
/// "require `webauthn`" cannot be defeated by an issuer that spells it `WebAuthn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// A local password.
    Pwd,
    /// A time-based one-time code.
    Totp,
    /// A WebAuthn assertion — the only method here that resists real-time phishing.
    Webauthn,
    /// A single-use recovery code.
    #[serde(rename = "rc")]
    RecoveryCode,
    /// An assertion from a federated identity provider (OIDC or SAML).
    Sso,
}

impl AuthMethod {
    /// The strength a single use of this method establishes on its own.
    #[must_use]
    pub const fn strength(self) -> AuthStrength {
        match self {
            // SSO strength is really the provider's business; treating it as one factor here is
            // the conservative reading, and `acr` from the provider can raise it.
            Self::Pwd | Self::Sso => AuthStrength::SingleFactor,
            Self::Totp | Self::RecoveryCode => AuthStrength::MultiFactor,
            Self::Webauthn => AuthStrength::PhishingResistant,
        }
    }
}

/// The authentication context class reference, for the `acr` claim.
///
/// `core::AuthStrength` deliberately does not own the claim vocabulary — the claim belongs to the
/// token format and the strength belongs to the domain — so the mapping between them lives here,
/// in exactly one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Acr {
    /// One factor.
    #[serde(rename = "1fa")]
    SingleFactor,
    /// Two or more factors. The value `docs/03-LLD.md §5.2` shows and the one step-up responses
    /// ask for.
    #[serde(rename = "mfa")]
    MultiFactor,
    /// A phishing-resistant factor.
    #[serde(rename = "phr")]
    PhishingResistant,
}

impl Acr {
    /// The domain-level strength this class represents.
    #[must_use]
    pub const fn strength(self) -> AuthStrength {
        match self {
            Self::SingleFactor => AuthStrength::SingleFactor,
            Self::MultiFactor => AuthStrength::MultiFactor,
            Self::PhishingResistant => AuthStrength::PhishingResistant,
        }
    }

    /// The strongest class the given methods justify.
    ///
    /// Derived rather than asserted by the caller, so that a login flow cannot claim `mfa` in the
    /// token while having only collected a password. `None` when no method was presented at all.
    #[must_use]
    pub fn from_methods(methods: &[AuthMethod]) -> Option<Self> {
        let strongest = methods.iter().map(|m| m.strength()).max()?;
        Some(match strongest {
            AuthStrength::PhishingResistant => Self::PhishingResistant,
            AuthStrength::MultiFactor => Self::MultiFactor,
            // A single factor twice is still a single factor.
            AuthStrength::SingleFactor | AuthStrength::Unauthenticated => Self::SingleFactor,
        })
    }
}

/// The claims of an Enclave access token, exactly as `docs/03-LLD.md §5.2` specifies them.
///
/// Times are seconds since the Unix epoch because that is what RFC 7519 requires, and they are
/// `i64` rather than `u64` so that arithmetic against a skew tolerance cannot silently wrap when a
/// clock is wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer. Checked against this deployment's configured issuer on every verification.
    pub iss: String,
    /// Audience. `enclave-api` for ordinary API access.
    pub aud: String,
    /// Subject: the actor's identifier.
    pub sub: Uuid,
    /// Tenant. A mismatch with the routed custom domain is a hard `401` — and it is the *only*
    /// acceptable source of tenant identity, per non-negotiable rule 3.
    pub tid: Uuid,
    /// Refresh-token family id, and the audit correlation key.
    pub sid: Uuid,
    /// Actor kind.
    pub typ: ActorKind,
    /// Scopes. Narrowing only.
    pub scp: Vec<String>,
    /// Methods used to authenticate.
    pub amr: Vec<AuthMethod>,
    /// When the *authentication event* happened — not when this token was issued. A session
    /// refreshed ten times still reflects one authentication, and that is what max-age and step-up
    /// policies must measure against.
    pub auth_time: i64,
    /// Authentication context class.
    pub acr: Acr,
    /// Bound device. Required for `sync` and `editor` clients (K7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<Uuid>,
    /// Client type.
    pub cli: ClientType,
    /// The subject's `token_epoch` at issuance. Anything below the current epoch is revoked (K5).
    pub epoch: i32,
    /// Unique token id, and the denylist key.
    pub jti: Uuid,
    /// Issued at.
    pub iat: i64,
    /// Expires at.
    pub exp: i64,
    /// Classification ceiling for MCP clients (`docs/03-LLD.md §5.6`).
    ///
    /// Absent for every other actor kind. Present as a claim rather than looked up per request
    /// because it must be pinned to the grant the client was issued, not to whatever the client's
    /// registration says at retrieval time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cls: Option<ClassificationRank>,
}

impl AccessTokenClaims {
    /// The scopes as the domain's set type.
    ///
    /// Converts on demand rather than storing a [`ScopeSet`] in the claims, because the claim is a
    /// JSON array and `ScopeSet` sorts and deduplicates — round-tripping through it would silently
    /// rewrite a token's `scp` and change its signature-covered bytes.
    #[must_use]
    pub fn scopes(&self) -> ScopeSet {
        self.scp.iter().cloned().collect()
    }

    /// The authentication strength this token asserts.
    #[must_use]
    pub const fn auth_strength(&self) -> AuthStrength {
        self.acr.strength()
    }

    /// The principal, reassembled from `typ` and `sub`.
    ///
    /// The two claims are separate on the wire but meaningless apart: a bare `sub` gives no way to
    /// tell a user from a guest, and treating a guest as a user is the exact bug
    /// [`enclave_core::Actor`] exists to make unwritable. Reassembling them here means no caller
    /// ever sees the split.
    #[must_use]
    pub const fn actor(&self) -> Actor {
        match self.typ {
            ActorKind::User => Actor::User(UserId::from_uuid(self.sub)),
            ActorKind::Guest => Actor::Guest(GuestId::from_uuid(self.sub)),
            ActorKind::ServiceAccount => {
                Actor::ServiceAccount(ServiceAccountId::from_uuid(self.sub))
            }
            ActorKind::McpClient => Actor::McpClient(McpClientId::from_uuid(self.sub)),
            // A share link is not a token subject, and this arm is *not* where that is enforced:
            // [`AccessTokenIssuer::issue`] refuses to mint such a token and
            // `AccessTokenVerifier::check_claims` refuses to accept one, so no
            // [`VerifiedAccessToken`] can reach here holding this kind. This function is a pure
            // projection of the claims — it says what the token says — and making it lie about a
            // `typ` it was handed would move the refusal somewhere nobody can test it by name.
            // `ENC-879`: a link bearer is established only by redeeming a token on the redemption
            // path, never by presenting a JWT.
            ActorKind::ShareLink => Actor::LinkBearer(ShareLinkId::from_uuid(self.sub)),
            // `System` has no subject; a token asserting one would be lying, and the identifier is
            // dropped rather than smuggled through.
            ActorKind::System => Actor::System,
        }
    }

    /// `exp` as a timestamp, saturating rather than failing on an absurd value.
    ///
    /// Saturating is safe here: a claim so large it cannot be represented saturates to the maximum
    /// representable instant, and a claim so small it cannot be represented saturates to the
    /// minimum — in both directions the comparison that follows behaves the way the honest value
    /// would have.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        seconds_to_utc(self.exp)
    }

    /// `iat` as a timestamp.
    #[must_use]
    pub fn issued_at(&self) -> DateTime<Utc> {
        seconds_to_utc(self.iat)
    }

    /// `auth_time` as a timestamp.
    #[must_use]
    pub fn authenticated_at(&self) -> DateTime<Utc> {
        seconds_to_utc(self.auth_time)
    }
}

/// Converts a Unix timestamp to a `DateTime`, saturating at the representable bounds.
fn seconds_to_utc(seconds: i64) -> DateTime<Utc> {
    match Utc.timestamp_opt(seconds, 0) {
        chrono::LocalResult::Single(dt) => dt,
        // Out of range in either direction. Which bound we pick matters: a nonsensically large
        // `exp` must read as "far future" and a nonsensically small one as "long expired", which is
        // exactly what the sign tells us.
        _ => {
            if seconds > 0 {
                DateTime::<Utc>::MAX_UTC
            } else {
                DateTime::<Utc>::MIN_UTC
            }
        }
    }
}

/// A token whose signature, algorithm, key, times, issuer and audience have all been checked.
///
/// The type is the proof. Nothing constructs one except [`crate::access::AccessTokenVerifier`], so
/// a function that takes a `VerifiedAccessToken` cannot be handed an unverified one — which is the
/// difference between "we check the signature everywhere" as a convention and as a fact.
///
/// Revocation is *not* part of this proof, deliberately: it needs I/O and is checked separately by
/// [`crate::revocation::RevocationChecker`] so that the cheap precondition in `docs/03-LLD.md §5.4`
/// can skip it.
#[derive(Debug, Clone)]
pub struct VerifiedAccessToken {
    claims: AccessTokenClaims,
}

impl VerifiedAccessToken {
    /// Only the verifier may assert that a token has been verified.
    pub(crate) const fn new(claims: AccessTokenClaims) -> Self {
        Self { claims }
    }

    /// The verified claims.
    #[must_use]
    pub const fn claims(&self) -> &AccessTokenClaims {
        &self.claims
    }

    /// The tenant this token executes inside.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.claims.tid)
    }

    /// The refresh family / audit correlation id.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        SessionId::from_uuid(self.claims.sid)
    }

    /// Builds the [`RequestContext`] the policy chain runs against.
    ///
    /// Network origin and device posture are parameters rather than claims because neither is
    /// something a token can assert: the source address is a property of the connection, and
    /// posture comes from MDM attestation. A token that could assert its own network origin would
    /// make every conditional-access network rule self-certifying.
    ///
    /// The `dev` claim *is* used — it says which device the token is bound to — but its posture is
    /// not, for the same reason.
    #[must_use]
    pub fn to_request_context(
        &self,
        request_id: RequestId,
        network: NetworkContext,
        posture: DevicePosture,
    ) -> RequestContext {
        RequestContext {
            request_id,
            tenant_id: self.tenant_id(),
            actor: self.claims.actor(),
            session_id: Some(self.session_id()),
            auth_strength: self.claims.auth_strength(),
            auth_time: self.claims.authenticated_at(),
            scopes: self.claims.scopes(),
            client: self.claims.cli,
            network,
            device: DeviceContext {
                device_id: self.claims.dev.map(enclave_core::DeviceId::from_uuid),
                posture,
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
    fn the_claim_set_serialises_exactly_as_the_specification_shows_it() {
        let claims = AccessTokenClaims {
            iss: "https://workspace.example.com".to_owned(),
            aud: "enclave-api".to_owned(),
            sub: Uuid::nil(),
            tid: Uuid::nil(),
            sid: Uuid::nil(),
            typ: ActorKind::User,
            scp: vec!["files:read".to_owned(), "search".to_owned()],
            amr: vec![AuthMethod::Pwd, AuthMethod::Webauthn],
            auth_time: 1_755_500_000,
            acr: Acr::MultiFactor,
            dev: Some(Uuid::nil()),
            cli: ClientType::Web,
            epoch: 7,
            jti: Uuid::nil(),
            iat: 1_755_500_000,
            exp: 1_755_500_600,
            max_cls: None,
        };

        let json = serde_json::to_value(&claims).expect("serialize");
        let object = json.as_object().expect("an object");
        // Every claim named in docs/03-LLD.md §5.2, and nothing invented.
        let expected = [
            "iss",
            "aud",
            "sub",
            "tid",
            "sid",
            "typ",
            "scp",
            "amr",
            "auth_time",
            "acr",
            "dev",
            "cli",
            "epoch",
            "jti",
            "iat",
            "exp",
        ];
        for name in expected {
            assert!(object.contains_key(name), "missing claim {name}");
        }
        assert_eq!(object.len(), expected.len(), "unexpected extra claims: {object:?}");
        assert_eq!(object["acr"], "mfa");
        assert_eq!(object["typ"], "user");
        assert_eq!(object["cli"], "web");
        assert_eq!(object["amr"], serde_json::json!(["pwd", "webauthn"]));

        let back: AccessTokenClaims = serde_json::from_value(json).expect("round trip");
        assert_eq!(back, claims);
    }

    #[test]
    fn optional_claims_are_omitted_rather_than_null() {
        let claims = AccessTokenClaims {
            iss: "i".to_owned(),
            aud: "a".to_owned(),
            sub: Uuid::nil(),
            tid: Uuid::nil(),
            sid: Uuid::nil(),
            typ: ActorKind::ServiceAccount,
            scp: Vec::new(),
            amr: Vec::new(),
            auth_time: 0,
            acr: Acr::SingleFactor,
            dev: None,
            cli: ClientType::Api,
            epoch: 1,
            jti: Uuid::nil(),
            iat: 0,
            exp: 1,
            max_cls: None,
        };
        let json = serde_json::to_value(&claims).expect("serialize");
        assert!(!json.as_object().expect("object").contains_key("dev"));
        assert!(!json.as_object().expect("object").contains_key("max_cls"));
    }

    #[test]
    fn acr_is_derived_from_methods_and_never_overstates_them() {
        assert_eq!(Acr::from_methods(&[AuthMethod::Pwd]), Some(Acr::SingleFactor));
        assert_eq!(
            Acr::from_methods(&[AuthMethod::Pwd, AuthMethod::Sso]),
            Some(Acr::SingleFactor),
            "two single factors are still one factor"
        );
        assert_eq!(Acr::from_methods(&[AuthMethod::Pwd, AuthMethod::Totp]), Some(Acr::MultiFactor));
        assert_eq!(
            Acr::from_methods(&[AuthMethod::Pwd, AuthMethod::Webauthn]),
            Some(Acr::PhishingResistant)
        );
        assert_eq!(Acr::from_methods(&[]), None);
    }

    #[test]
    fn absurd_timestamps_saturate_in_the_direction_that_fails_safe() {
        assert_eq!(seconds_to_utc(i64::MIN), DateTime::<Utc>::MIN_UTC);
        assert_eq!(seconds_to_utc(i64::MAX), DateTime::<Utc>::MAX_UTC);
    }
}
