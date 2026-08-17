//! The evidence a request carries with it (`docs/03-LLD.md §3`).
//!
//! [`RequestContext`] is assembled once, at the edge, from a *verified* access token and from
//! properties of the connection. Every layer below reads it and none of them rebuilds it. That is
//! deliberate: the moment two places can construct a context, the second one is where a tenant id
//! taken from a request body ends up (`CLAUDE.md` non-negotiable rule 3).

use core::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::actor::{Actor, ClientType};
use crate::id::{DeviceId, RequestId, SessionId, TenantId};

/// How strongly the caller authenticated, ordered weakest to strongest.
///
/// Ordered so that a policy can be written as `ctx.auth_strength >= AuthStrength::MultiFactor`
/// rather than as a list of acceptable values that someone forgets to extend when a stronger
/// method is added. Derived from the `acr` and `amr` claims by the `auth` crate, which owns the
/// mapping from those claim strings — `core` deliberately does not, because the claim vocabulary
/// belongs to the token format, not to the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrength {
    /// No principal has authenticated: anonymous share-link resolution, health checks, and
    /// internal system work. It is the weakest value, so every step-up comparison fails closed.
    Unauthenticated,
    /// One factor, typically a password or a valid client-credentials grant.
    SingleFactor,
    /// Two or more factors.
    MultiFactor,
    /// A factor that is bound to the origin and cannot be relayed — WebAuthn or a platform
    /// authenticator. Distinguished from `MultiFactor` because it is the only strength that
    /// actually defeats real-time phishing, and high-value policies need to be able to demand it.
    PhishingResistant,
}

impl AuthStrength {
    /// Whether this authentication satisfies a required strength.
    ///
    /// A named method rather than a bare `>=` at each call site, so the comparison direction is
    /// stated once. Inverting that comparison is a silent, total bypass of step-up policy.
    #[must_use]
    pub fn meets(self, required: Self) -> bool {
        self >= required
    }
}

/// The set of OAuth-style scopes carried by the access token (`scp` claim).
///
/// Stored sorted and deduplicated in a boxed slice: scope sets are small (a handful of entries),
/// read on every request and never mutated after construction, so a `HashSet` would pay for
/// hashing and an allocation per entry to serve a lookup that a binary search over eight strings
/// answers faster.
///
/// **Matching is exact.** There is no wildcard expansion: holding `admin:*` does not grant
/// `admin:users`. `admin:*` appears in the specification as *notation for a family of scopes* when
/// describing which are privileged, not as a grantable value, and implementing it as a grant would
/// silently widen every token that carried one. Use [`ScopeSet::has_prefix`] to ask the
/// family-level question explicitly. Remember that scopes only ever *narrow* what a caller may
/// attempt — authorization still re-resolves the ACL (`docs/03-LLD.md §5.2`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<String>", into = "Vec<String>")]
pub struct ScopeSet(Box<[Box<str>]>);

impl ScopeSet {
    /// An empty scope set: a caller who may attempt nothing that requires a scope.
    #[must_use]
    pub fn empty() -> Self {
        Self(Box::default())
    }

    /// Whether the exact scope is present.
    #[must_use]
    pub fn contains(&self, scope: &str) -> bool {
        self.0.binary_search_by(|held| (**held).cmp(scope)).is_ok()
    }

    /// Whether any held scope starts with the given prefix.
    ///
    /// The explicit form of the "does this caller hold anything in the `admin:` family?" question
    /// that the privileged-scope rules in `docs/03-LLD.md §5.4` need. Separate from
    /// [`ScopeSet::contains`] so that a family check can never be mistaken for a grant check.
    #[must_use]
    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.0.iter().any(|held| held.starts_with(prefix))
    }

    /// Whether at least one of the listed scopes is held.
    #[must_use]
    pub fn contains_any(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|scope| self.contains(scope))
    }

    /// Iterates the held scopes in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.0.iter().map(AsRef::as_ref)
    }

    /// Number of distinct scopes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no scopes are held at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<S: Into<String>> FromIterator<S> for ScopeSet {
    /// Sorts and deduplicates on the way in, which is what makes [`ScopeSet::contains`] a binary
    /// search and what makes two tokens listing the same scopes in different orders compare equal.
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        let mut scopes: Vec<Box<str>> =
            iter.into_iter().map(|s| s.into().into_boxed_str()).collect();
        scopes.sort_unstable();
        scopes.dedup();
        Self(scopes.into_boxed_slice())
    }
}

impl From<Vec<String>> for ScopeSet {
    fn from(value: Vec<String>) -> Self {
        value.into_iter().collect()
    }
}

impl From<ScopeSet> for Vec<String> {
    fn from(value: ScopeSet) -> Self {
        value.0.into_vec().into_iter().map(Into::into).collect()
    }
}

/// Where the request came from, after the trusted-proxy chain has been resolved.
///
/// Every field here is an input to conditional access, so the honesty of `via_trusted_proxy`
/// matters more than the rest combined: a forwarded address is only meaningful when the immediate
/// peer was inside a configured trusted-proxy CIDR (`docs/06-SECURITY-DLP-ACCESS.md §7.3`).
/// Carrying that fact alongside the address means a policy can refuse to trust a claimed origin
/// rather than having to assume the edge got it right.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkContext {
    /// The resolved client address. When `via_trusted_proxy` is false this is the immediate peer;
    /// only when it is true has an `X-Forwarded-For` entry been honoured. Geo and ASN lookups run
    /// against this address and no other.
    pub source_ip: IpAddr,
    /// ISO 3166-1 alpha-2 country code, uppercase. `None` when geolocation is unavailable or
    /// disabled — which a geo-fence must treat as "unknown", never as "allowed".
    pub country: Option<String>,
    /// Autonomous system number of the source address, where known. Used to distinguish a
    /// corporate egress from a consumer VPN or a hosting provider.
    pub asn: Option<u32>,
    /// Names of the administrator-defined trusted zones this address falls inside, e.g.
    /// `["Corporate India", "VPN"]`. An address can be in several; an empty list means untrusted.
    pub zones: Vec<String>,
    /// Whether the immediate peer was a configured trusted proxy, and therefore whether any
    /// forwarded address was honoured at all.
    pub via_trusted_proxy: bool,
}

impl NetworkContext {
    /// A context for traffic that never crossed a network: workers, schedulers, tests.
    ///
    /// It is loopback, in no zone and behind no proxy, so it is treated as untrusted by every
    /// network policy. That is the safe default — internal origin is not a reason to skip a check.
    #[must_use]
    pub fn internal() -> Self {
        Self {
            source_ip: IpAddr::V4(core::net::Ipv4Addr::LOCALHOST),
            country: None,
            asn: None,
            zones: Vec::new(),
            via_trusted_proxy: false,
        }
    }

    /// Whether the source address falls inside the named trusted zone.
    #[must_use]
    pub fn in_zone(&self, zone: &str) -> bool {
        self.zones.iter().any(|z| z == zone)
    }

    /// Whether the address falls inside any trusted zone at all.
    #[must_use]
    pub fn is_trusted_zone(&self) -> bool {
        !self.zones.is_empty()
    }
}

/// Management state of the device a request came from.
///
/// Ordered weakest to strongest so policies read as `posture >= DevicePosture::Managed`. The
/// strings match the `devices.posture` `CHECK` constraint in `docs/04-DATA-MODEL.md §6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DevicePosture {
    /// No attestation was presented. Weakest by construction: absence of evidence must never
    /// satisfy a posture requirement.
    Unknown,
    /// Attested, and known not to be enrolled in management.
    Unmanaged,
    /// Enrolled in management.
    Managed,
    /// Enrolled and currently meeting the tenant's compliance baseline.
    Compliant,
}

/// The device a request came from, and how much is known about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceContext {
    /// The registered device (`dev` claim), where one is bound. Required for `sync` and `editor`
    /// clients; `None` for an ordinary browser session on an unregistered machine.
    pub device_id: Option<DeviceId>,
    /// Management state, from MDM attestation where configured.
    pub posture: DevicePosture,
}

impl DeviceContext {
    /// An unidentified device: no binding, no attestation.
    ///
    /// The correct starting point for anything that is not a registered client, and the correct
    /// value for internal work — it fails every posture requirement rather than passing them.
    #[must_use]
    pub const fn unknown() -> Self {
        Self { device_id: None, posture: DevicePosture::Unknown }
    }

    /// Whether the device satisfies a required posture.
    #[must_use]
    pub fn meets(&self, required: DevicePosture) -> bool {
        self.posture >= required
    }
}

/// Everything the policy chain knows about a request (`docs/03-LLD.md §3`).
///
/// # Construction
///
/// Built once, at the edge, from a verified access token plus connection properties. Note that
/// this type implements [`Serialize`] but **not** `Deserialize`: a context that could be parsed
/// from JSON is a context that could be parsed from a request body, and the tenant identity inside
/// it is precisely what must never come from client input. Background work builds its own with
/// [`RequestContext::system`]; nothing reconstitutes a user's context from bytes.
#[derive(Debug, Clone, Serialize)]
pub struct RequestContext {
    /// Correlation id for this request, echoed in the error envelope and every audit row it
    /// produces, so a user-reported failure resolves to exact log lines.
    pub request_id: RequestId,
    /// The tenant this request executes inside. Derived from the verified token or from
    /// custom-domain routing — never from a body field, query parameter or header.
    pub tenant_id: TenantId,
    /// The principal.
    pub actor: Actor,
    /// The refresh-token family (`sid`). Correlation only; it is never used for a server-side
    /// session lookup, which is what keeps token verification free of I/O.
    pub session_id: Option<SessionId>,
    /// How strongly the principal authenticated.
    pub auth_strength: AuthStrength,
    /// When that authentication happened. Separate from token issuance because a token refreshed
    /// ten times still reflects one authentication event, and max-age and step-up policies care
    /// about the event, not the refresh.
    pub auth_time: DateTime<Utc>,
    /// Scopes the token carries. These narrow what may be attempted; they never widen it.
    pub scopes: ScopeSet,
    /// The kind of client the request arrived through.
    pub client: ClientType,
    /// Resolved network origin.
    pub network: NetworkContext,
    /// Device binding and posture.
    pub device: DeviceContext,
}

impl RequestContext {
    /// A context for internal work with no human principal: retention sweeps, outbox publishing,
    /// index maintenance.
    ///
    /// This is **not** a bypass. It is an ordinary context that happens to be attributed to
    /// [`Actor::System`], and work performed under it still runs the full policy chain and is
    /// still audited. Its authentication strength, network and device are all the weakest possible
    /// values, so any policy that requires evidence of something will deny it rather than wave it
    /// through.
    #[must_use]
    pub fn system(tenant_id: TenantId) -> Self {
        Self {
            request_id: RequestId::new_v7(),
            tenant_id,
            actor: Actor::System,
            session_id: None,
            auth_strength: AuthStrength::Unauthenticated,
            auth_time: Utc::now(),
            scopes: ScopeSet::empty(),
            client: ClientType::System,
            network: NetworkContext::internal(),
            device: DeviceContext::unknown(),
        }
    }

    /// Whether the token carries the exact scope named.
    ///
    /// A shorthand for `ctx.scopes.contains(...)` because it is by far the most frequent question
    /// asked of a context, and a shorthand that is present is a shorthand nobody reimplements.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// How long ago the principal authenticated, for max-age and step-up policies.
    ///
    /// Saturates at zero rather than returning a negative duration when clocks disagree: a token
    /// whose `auth_time` is slightly in the future must not read as "authenticated in the future
    /// and therefore never stale".
    #[must_use]
    pub fn auth_age(&self, now: DateTime<Utc>) -> chrono::Duration {
        (now - self.auth_time).max(chrono::Duration::zero())
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::id::UserId;

    fn scopes(items: &[&str]) -> ScopeSet {
        items.iter().copied().collect()
    }

    #[test]
    fn scope_lookup_is_exact() {
        let set = scopes(&["files:read", "files:write", "search"]);
        assert!(set.contains("files:read"));
        assert!(!set.contains("files"));
        assert!(!set.contains("files:read:extra"));
        assert!(set.contains_any(&["nope", "search"]));
        assert!(!set.contains_any(&["nope", "other"]));
    }

    #[test]
    fn a_wildcard_scope_grants_nothing_beyond_itself() {
        // The whole point: `admin:*` must not become a grant of `admin:users`.
        let set = scopes(&["admin:*"]);
        assert!(!set.contains("admin:users"));
        assert!(set.contains("admin:*"));
        assert!(set.has_prefix("admin:"));
    }

    #[test]
    fn scope_sets_are_sorted_deduplicated_and_order_independent() {
        let a = scopes(&["search", "files:read", "search"]);
        let b = scopes(&["files:read", "search"]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.iter().collect::<Vec<_>>(), vec!["files:read", "search"]);
    }

    #[test]
    fn scope_sets_round_trip_through_serde() {
        let set = scopes(&["files:write", "files:read"]);
        let json = serde_json::to_string(&set).expect("serialize");
        assert_eq!(json, r#"["files:read","files:write"]"#);
        let back: ScopeSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(set, back);
    }

    #[test]
    fn empty_scope_set_grants_nothing() {
        let set = ScopeSet::empty();
        assert!(set.is_empty());
        assert!(!set.contains("files:read"));
        assert!(!set.has_prefix(""));
    }

    #[test]
    fn auth_strength_is_ordered_weakest_first() {
        assert!(AuthStrength::PhishingResistant > AuthStrength::MultiFactor);
        assert!(AuthStrength::MultiFactor > AuthStrength::SingleFactor);
        assert!(AuthStrength::SingleFactor > AuthStrength::Unauthenticated);
        assert!(AuthStrength::PhishingResistant.meets(AuthStrength::MultiFactor));
        assert!(!AuthStrength::SingleFactor.meets(AuthStrength::MultiFactor));
    }

    #[test]
    fn device_posture_is_ordered_and_unknown_satisfies_nothing() {
        assert!(DevicePosture::Compliant > DevicePosture::Managed);
        assert!(DevicePosture::Managed > DevicePosture::Unmanaged);
        assert!(DevicePosture::Unmanaged > DevicePosture::Unknown);
        assert!(!DeviceContext::unknown().meets(DevicePosture::Managed));
    }

    #[test]
    fn device_posture_uses_the_database_spelling() {
        let json = serde_json::to_string(&DevicePosture::Compliant).expect("serialize");
        assert_eq!(json, r#""COMPLIANT""#);
    }

    #[test]
    fn internal_network_context_is_trusted_by_nothing() {
        let net = NetworkContext::internal();
        assert!(!net.is_trusted_zone());
        assert!(!net.in_zone("Corporate India"));
        assert!(!net.via_trusted_proxy);
        assert_eq!(net.country, None);
    }

    #[test]
    fn system_context_carries_no_evidence_of_anything() {
        let tenant = TenantId::new_v7();
        let ctx = RequestContext::system(tenant);
        assert_eq!(ctx.tenant_id, tenant);
        assert_eq!(ctx.actor, Actor::System);
        assert_eq!(ctx.actor.subject_id(), None);
        assert!(!ctx.has_scope("admin:tenant"));
        assert!(!ctx.auth_strength.meets(AuthStrength::SingleFactor));
        assert!(!ctx.device.meets(DevicePosture::Managed));
    }

    #[test]
    fn auth_age_never_goes_negative() {
        let mut ctx = RequestContext::system(TenantId::new_v7());
        ctx.actor = Actor::User(UserId::new_v7());
        let now = ctx.auth_time - chrono::Duration::minutes(5);
        assert_eq!(ctx.auth_age(now), chrono::Duration::zero());
        let later = ctx.auth_time + chrono::Duration::minutes(5);
        assert_eq!(ctx.auth_age(later), chrono::Duration::minutes(5));
    }
}
