//! The configuration model.
//!
//! Shapes follow the example in `docs/08-BYO-INFRA.md §15` — that document is authoritative for what
//! an operator writes, and this module is only its typed form. Two rules apply throughout:
//!
//! * every struct implements [`Default`], because the defaults layer of the precedence chain
//!   (`docs/03-LLD.md §21`) *is* those impls, and `#[serde(default)]` fills unset fields from them;
//! * every field that names a credential is a [`SecretRef`], so an inline value is a type error
//!   before it is a validation error (CLAUDE.md rule 11).
//!
//! Sections not modelled yet (storage, search, embedding, preview, sync, mcp, quotas, identity,
//! mail) are deliberately *not* rejected: they land in later milestones, and an operator who writes
//! a complete file today should not be blocked. They are still scanned for inline credentials,
//! which is the part that matters for security.

use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::duration::HumanDuration;
use crate::secret_ref::{SecretRef, SecretScheme};

/// What this deployment is expected to be capable of (`docs/08-BYO-INFRA.md §19`).
///
/// The profile is a *promise* made to the operator, and validation enforces it: an enterprise
/// deployment that quietly ran without antivirus would still call itself enterprise in the admin
/// UI, in the SOC 2 evidence pack, and in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProfile {
    /// Single node, local filesystem or MinIO, embedded ClamAV. The default, because a developer
    /// running `cargo run` must not be held to enterprise requirements.
    #[default]
    Community,
    /// Horizontally scaled, HA data services.
    Production,
    /// Multi-AZ with BYO infrastructure; the strictest validation rules apply.
    Enterprise,
}

impl DeploymentProfile {
    /// Whether the strict startup requirements of `docs/08-BYO-INFRA.md §19` apply.
    #[must_use]
    pub const fn is_enterprise(&self) -> bool {
        matches!(self, Self::Enterprise)
    }
}

/// The whole configuration, after all four layers have been applied.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Which capability promises this deployment makes.
    pub profile: DeploymentProfile,
    /// HTTP listener and proxy trust.
    pub server: ServerConfig,
    /// PostgreSQL — the authoritative store.
    pub database: DatabaseConfig,
    /// Redis, used for caching and rate limiting.
    pub redis: RedisConfig,
    /// NATS JetStream, the outbox destination.
    pub events: EventsConfig,
    /// Token issuance and rotation.
    pub auth: AuthConfig,
    /// Password, MFA and fail-closed behaviour.
    pub security: SecurityConfig,
    /// Data-loss prevention.
    pub dlp: DlpConfig,
    /// Audit trail.
    pub audit: AuditConfig,
    /// Malware scanning.
    pub antivirus: AntivirusConfig,
}

impl Config {
    /// Every secret reference in the configuration, paired with the dotted field path it came from.
    ///
    /// The path is what makes a resolution failure diagnosable ("`database.url` could not be read")
    /// and is the key under which the resolved value is stored, so no caller has to remember which
    /// provider a value came from.
    #[must_use]
    pub fn secret_refs(&self) -> Vec<(String, SecretRef)> {
        let mut refs = Vec::new();
        let mut push = |path: &str, value: Option<SecretRef>| {
            if let Some(value) = value {
                refs.push((path.to_owned(), value));
            }
        };
        push("database.url", self.database.url_ref());
        push("redis.url", self.redis.url_ref());
        push("events.nats_url", self.events.nats_url_ref());
        push("auth.signing_keys.key_ref", self.auth.signing_keys.key_ref.clone());
        push("security.password.pepper", self.security.password.pepper.clone());
        refs
    }
}

/// HTTP listener, public identity and proxy trust.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address to bind. Defaults to loopback rather than `0.0.0.0`: a service should be exposed
    /// deliberately, not by forgetting to set a field.
    pub bind: IpAddr,
    /// TCP port.
    pub port: u16,
    /// The URL clients reach this deployment on, used for token issuer, cookie domain and links in
    /// mail. `None` means "derive from bind and port", which is only sane in development.
    pub public_url: Option<Url>,
    /// Port for the metrics listener, or `None` to not serve metrics at all.
    ///
    /// **A separate listener, deliberately, and not a route on the API.** The exposition carries
    /// `tenant_id` labels — which tenants exist, how much each searches, how far behind each one's
    /// invalidation is. That is customer data in aggregate, and the policy-routing allowlist says in
    /// its own words that an unauthenticated endpoint "must never include a detail that identifies a
    /// tenant or a resource".
    ///
    /// Putting it on its own port is what lets an operator bind it to a private interface while the
    /// API faces the world, without either a policy exemption that would be wrong or an
    /// authentication scheme Prometheus would have to be taught. `None` by default: a deployment
    /// that has not thought about where this port goes should not have it open.
    pub metrics_port: Option<u16>,

    /// Address for the metrics listener. Defaults to loopback, and should stay there unless the
    /// scraper is on another host and the network between them is trusted.
    pub metrics_bind: IpAddr,

    /// Networks whose forwarding headers may be believed, and how many hops each strips.
    ///
    /// Empty by default. An empty list means the peer address is the client address — the only safe
    /// assumption when nothing is known, because trusting `X-Forwarded-For` from an untrusted peer
    /// lets any client claim any source IP and defeat conditional access
    /// (`docs/06-SECURITY-DLP-ACCESS.md`).
    pub trusted_proxies: Vec<TrustedProxy>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            // Off unless a deployment asks for it. The exposition carries tenant labels, so a port
            // nobody chose to open is a port that should not be open.
            metrics_port: None,
            metrics_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            public_url: None,
            trusted_proxies: Vec::new(),
        }
    }
}

/// One trusted reverse-proxy network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedProxy {
    /// The network whose forwarded headers are believed.
    pub cidr: IpNetwork,
    /// How many proxy hops sit in front of the application for this network. Counting hops rather
    /// than taking the left-most `X-Forwarded-For` entry is what stops a client from prepending a
    /// forged address.
    pub hops: u8,
}

/// PostgreSQL connection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Reference to the DSN. A `SecretRef` and not a `String`, because a DSN embeds a password.
    pub url: Option<SecretRef>,
    /// The `url_env: DATABASE_URL` spelling used in `docs/08-BYO-INFRA.md §15`, kept so a
    /// documented file loads unchanged. Equivalent to `url: env://DATABASE_URL`.
    pub url_env: Option<String>,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Connections kept warm.
    pub min_connections: u32,
    /// How long a checkout may wait before failing.
    pub acquire_timeout: HumanDuration,
    /// Server-side statement timeout, so one pathological query cannot hold a pool slot forever.
    pub statement_timeout: HumanDuration,
    /// The non-owner role the application connects as, so row-level security applies to it
    /// (`plans/M0-FOUNDATIONS.md` D3).
    pub application_role: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            url_env: None,
            max_connections: 50,
            min_connections: 1,
            acquire_timeout: HumanDuration::from_secs(10),
            statement_timeout: HumanDuration::from_secs(30),
            application_role: "enclave_app".to_owned(),
        }
    }
}

impl DatabaseConfig {
    /// The effective DSN reference, preferring the explicit `url` over the `url_env` shorthand.
    ///
    /// Returns `None` when neither is set *or* when `url_env` names something that is not a valid
    /// environment variable; the latter is already reported as a validation problem, so silently
    /// dropping it here cannot hide anything.
    #[must_use]
    pub fn url_ref(&self) -> Option<SecretRef> {
        env_ref(self.url.as_ref(), self.url_env.as_deref())
    }
}

/// Redis connection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    /// Reference to the Redis URL, which may embed credentials.
    pub url: Option<SecretRef>,
    /// The `url_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub url_env: Option<String>,
    /// Upper bound on pooled connections.
    pub pool_size: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self { url: None, url_env: None, pool_size: 16 }
    }
}

impl RedisConfig {
    /// The effective Redis URL reference.
    #[must_use]
    pub fn url_ref(&self) -> Option<SecretRef> {
        env_ref(self.url.as_ref(), self.url_env.as_deref())
    }
}

/// NATS JetStream settings for the transactional outbox publisher.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Reference to the NATS URL, which may embed credentials.
    pub nats_url: Option<SecretRef>,
    /// The `nats_url_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub nats_url_env: Option<String>,
    /// Stream name.
    pub stream: String,
    /// How many outbox rows one publish pass claims. Bounded so a backlog is drained steadily
    /// rather than in one transaction that holds locks for minutes.
    pub publish_batch: u32,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self { nats_url: None, nats_url_env: None, stream: "vault".to_owned(), publish_batch: 256 }
    }
}

impl EventsConfig {
    /// The effective NATS URL reference.
    #[must_use]
    pub fn nats_url_ref(&self) -> Option<SecretRef> {
        env_ref(self.nats_url.as_ref(), self.nats_url_env.as_deref())
    }
}

/// Token issuance, rotation and signing.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Short-lived bearer tokens.
    pub access_token: AccessTokenConfig,
    /// Long-lived rotating refresh tokens.
    pub refresh_token: RefreshTokenConfig,
    /// Where signing keys come from and how often they roll.
    pub signing_keys: SigningKeysConfig,
}

/// Access-token issuance (`docs/03-LLD.md §5`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessTokenConfig {
    /// Signature algorithm. A closed enum, and never read from a token header — that is the K8
    /// algorithm-confusion defence and it belongs in configuration, not in the token.
    pub algorithm: SigningAlgorithm,
    /// Lifetime of an ordinary access token. Short by design: revocation of a bearer token is
    /// approximate, so the window is the real control.
    pub ttl: HumanDuration,
    /// Lifetime for privileged sessions, shorter still.
    pub privileged_ttl: HumanDuration,
    /// `iss` claim. Defaults to `None` so it is taken from `server.public_url` rather than being
    /// silently wrong.
    pub issuer: Option<String>,
    /// `aud` claim.
    pub audience: String,
}

impl Default for AccessTokenConfig {
    fn default() -> Self {
        Self {
            algorithm: SigningAlgorithm::EdDsa,
            ttl: HumanDuration::from_secs(600),
            privileged_ttl: HumanDuration::from_secs(300),
            issuer: None,
            audience: "enclave-api".to_owned(),
        }
    }
}

/// Supported JWT signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// Ed25519. The only supported choice: it has no parameter that can be weakened, and a closed
    /// set of one makes downgrade attacks structurally impossible.
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
}

/// Refresh-token rotation (`docs/03-LLD.md §5`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RefreshTokenConfig {
    /// How long a refresh token survives without use.
    pub idle_ttl: HumanDuration,
    /// Hard upper bound regardless of use, so a stolen family cannot live forever.
    pub absolute_ttl: HumanDuration,
    /// Whether presenting a refresh token consumes it and issues a successor. On by default;
    /// turning it off removes the only signal that makes reuse detection possible.
    pub rotation: bool,
    /// What happens when a consumed token is presented again.
    pub reuse_detection: ReuseDetection,
    /// Cookie carrying the refresh token.
    pub cookie: CookieConfig,
}

impl Default for RefreshTokenConfig {
    fn default() -> Self {
        Self {
            idle_ttl: HumanDuration::from_secs(14 * 86_400),
            absolute_ttl: HumanDuration::from_secs(90 * 86_400),
            rotation: true,
            reuse_detection: ReuseDetection::RevokeFamily,
            cookie: CookieConfig::default(),
        }
    }
}

/// Response to a replayed refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReuseDetection {
    /// Revoke the whole token family. The default: a replay means either the client or the
    /// attacker holds a copy, and there is no way to tell which, so both must lose the session.
    #[default]
    RevokeFamily,
    /// Revoke only the replayed token. Weaker; offered because some legacy clients race their own
    /// refreshes.
    RevokeToken,
    /// Record and allow. Diagnostics only — never appropriate in production.
    LogOnly,
}

/// Refresh cookie attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CookieConfig {
    /// Cookie name.
    pub name: String,
    /// `SameSite` attribute.
    pub same_site: SameSite,
    /// Path scope. Narrow by default so the refresh token is not attached to every API call and
    /// therefore not exposed to every handler.
    pub path: String,
    /// `Secure` attribute. On by default; the loader does not relax it for development, because a
    /// development default that disables it has a way of reaching production.
    pub secure: bool,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "enclave_rt".to_owned(),
            same_site: SameSite::Strict,
            path: "/api/v1/auth".to_owned(),
            secure: true,
        }
    }
}

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSite {
    /// Never sent cross-site. The default.
    #[default]
    Strict,
    /// Sent on top-level navigations.
    Lax,
    /// Sent cross-site; requires `Secure`.
    None,
}

/// Where JWT signing keys come from (`plans/M0-FOUNDATIONS.md` D5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningKeysConfig {
    /// Reference to the key material. `None` means the development file provider generates a key
    /// on first run; no key is ever committed, even a throwaway one.
    pub key_ref: Option<SecretRef>,
    /// How often a new signing key is introduced.
    pub rotation_interval: HumanDuration,
    /// How long the retired key stays in the JWKS so tokens signed just before rotation still
    /// verify.
    pub overlap: HumanDuration,
}

impl Default for SigningKeysConfig {
    fn default() -> Self {
        Self {
            key_ref: None,
            rotation_interval: HumanDuration::from_secs(90 * 86_400),
            overlap: HumanDuration::from_secs(86_400),
        }
    }
}

/// Password hashing, MFA and fail-closed behaviour.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Password policy and hashing parameters.
    pub password: PasswordConfig,
    /// Multi-factor requirements.
    pub mfa: MfaConfig,
    /// What to do when the privileged-token denylist cannot be reached. Failing closed means an
    /// outage locks admins out; failing open means a revoked admin token keeps working. The first
    /// is an incident, the second is a breach.
    pub privileged_denylist_failure: FailureMode,
}

/// Password policy and Argon2id parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordConfig {
    /// Minimum length.
    pub min_length: u32,
    /// Maximum length, bounded so a very long password cannot be used to make hashing a denial of
    /// service.
    pub max_length: u32,
    /// Whether to check candidate passwords against a breach corpus.
    pub breach_check: bool,
    /// Argon2id cost parameters.
    pub argon2: Argon2Config,
    /// Optional secret mixed into every password hash, held outside the database so a database dump
    /// alone is not enough to mount an offline attack.
    pub pepper: Option<SecretRef>,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            breach_check: true,
            argon2: Argon2Config::default(),
            pepper: None,
        }
    }
}

/// Argon2id cost parameters (`docs/08-BYO-INFRA.md §15`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Argon2Config {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self { memory_kib: 65_536, iterations: 3, parallelism: 4 }
    }
}

/// Multi-factor requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MfaConfig {
    /// Whether administrators must hold a second factor.
    pub admins_required: bool,
    /// How recently a step-up must have happened for a privileged action to proceed.
    pub step_up_max_age: HumanDuration,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self { admins_required: true, step_up_max_age: HumanDuration::from_secs(900) }
    }
}

/// Behaviour when a control's inputs are unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureMode {
    /// Deny. The default everywhere in this file: a control that cannot evaluate has not allowed.
    #[default]
    FailClosed,
    /// Allow. Must be chosen explicitly, and shows up in a config diff when it is.
    FailOpen,
}

/// Data-loss prevention (`docs/06-SECURITY-DLP-ACCESS.md`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DlpConfig {
    /// Whether DLP evaluates at all.
    pub enabled: bool,
    /// Whether matches are recorded or enforced.
    pub default_mode: DlpMode,
    /// What to do when the facts a rule needs (classification, labels) cannot be loaded.
    pub facts_unavailable: FailureMode,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_mode: DlpMode::Monitor,
            facts_unavailable: FailureMode::FailClosed,
        }
    }
}

/// Whether DLP records or blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DlpMode {
    /// Record matches, allow the action. The default, so a new deployment does not block work
    /// before its rules have been tuned.
    #[default]
    Monitor,
    /// Block on match.
    Enforce,
}

/// Audit trail (`docs/08-BYO-INFRA.md §14`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Whether audit events are written at all. Disabling it is refused in the enterprise profile.
    pub enabled: bool,
    /// Whether each event carries the hash of its predecessor, making retroactive edits detectable.
    pub hash_chain: bool,
    /// Where periodic chain anchors are published, if anywhere. An anchor outside the system is
    /// what makes the chain evidence rather than self-assertion.
    pub external_anchor: Option<Url>,
    /// How long audit events are retained.
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, hash_chain: true, external_anchor: None, retention_days: 400 }
    }
}

/// Malware scanning (`docs/08-BYO-INFRA.md §9`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AntivirusConfig {
    /// Which engine. `none` is refused in the enterprise profile.
    pub provider: AntivirusProvider,
    /// Engine endpoint, e.g. a `clamd` address. Not a secret — a host and port.
    pub endpoint: Option<String>,
    /// The `endpoint_env` spelling from `docs/08-BYO-INFRA.md §15`.
    pub endpoint_env: Option<String>,
    /// Objects larger than this are not scanned inline.
    pub max_scan_bytes: u64,
    /// How deep to descend into archives before treating them as unscannable.
    pub archive_depth: u32,
    /// Per-object scan timeout.
    pub timeout: HumanDuration,
    /// What to do with an object when the scanner is unreachable. `HOLD` keeps the file in
    /// `SCANNING`, which is the only state consistent with "nothing is `AVAILABLE` before antivirus
    /// completes" (CLAUDE.md rule 9).
    pub unavailable_policy: UnavailablePolicy,
}

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            provider: AntivirusProvider::Clamav,
            endpoint: None,
            endpoint_env: None,
            max_scan_bytes: 2_147_483_648,
            archive_depth: 5,
            timeout: HumanDuration::from_secs(120),
            unavailable_policy: UnavailablePolicy::Hold,
        }
    }
}

impl AntivirusConfig {
    /// Whether any scanning happens. Used by profile validation, and by read paths that must refuse
    /// to serve unscanned content.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.provider, AntivirusProvider::None)
    }
}

/// Antivirus engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AntivirusProvider {
    /// Embedded `libclamav` or `clamd` over TCP or socket.
    #[default]
    Clamav,
    /// Enterprise ICAP gateway.
    Icap,
    /// Vendor HTTP scanning API.
    Http,
    /// Explicitly disabled. Spelled out rather than expressed as `enabled: false` so that turning
    /// scanning off is a visible, greppable choice in the configuration diff.
    None,
}

/// What to do when the scanner is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailablePolicy {
    /// Keep the object in `SCANNING` until a scanner is reachable.
    #[default]
    Hold,
    /// Publish and rescan later. Trades a malware window for availability; must be chosen.
    AllowAndRescan,
}

/// Prefer an explicit reference, otherwise interpret a `*_env` field as `env://NAME`.
fn env_ref(explicit: Option<&SecretRef>, env_name: Option<&str>) -> Option<SecretRef> {
    if let Some(reference) = explicit {
        return Some(reference.clone());
    }
    let name = env_name?;
    SecretRef::new(SecretScheme::Env, name, None::<String>).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_safe_choice() {
        let config = Config::default();
        assert_eq!(config.profile, DeploymentProfile::Community);
        assert_eq!(config.server.bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(config.server.trusted_proxies.is_empty());
        assert!(config.auth.refresh_token.rotation);
        assert_eq!(config.auth.refresh_token.reuse_detection, ReuseDetection::RevokeFamily);
        assert!(config.auth.refresh_token.cookie.secure);
        assert_eq!(config.security.privileged_denylist_failure, FailureMode::FailClosed);
        assert_eq!(config.dlp.facts_unavailable, FailureMode::FailClosed);
        assert!(config.audit.enabled);
        assert!(config.audit.hash_chain);
        assert!(config.antivirus.is_enabled());
        assert_eq!(config.antivirus.unavailable_policy, UnavailablePolicy::Hold);
    }

    #[test]
    fn documented_env_shorthands_become_references() {
        let yaml = "
database:
  url_env: DATABASE_URL
redis:
  url_env: REDIS_URL
events:
  nats_url_env: NATS_URL
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.database.url_ref().unwrap().to_string(), "env://DATABASE_URL");
        assert_eq!(config.redis.url_ref().unwrap().to_string(), "env://REDIS_URL");
        assert_eq!(config.events.nats_url_ref().unwrap().to_string(), "env://NATS_URL");
    }

    #[test]
    fn an_explicit_reference_wins_over_the_shorthand() {
        let yaml = "
database:
  url: vault://workspace/db#dsn
  url_env: DATABASE_URL
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.database.url_ref().unwrap().to_string(), "vault://workspace/db#dsn");
    }

    #[test]
    fn secret_refs_are_enumerated_with_their_paths() {
        let yaml = "
database:
  url_env: DATABASE_URL
security:
  password:
    pepper: vault://workspace/password#pepper
auth:
  signing_keys:
    key_ref: vault://workspace/jwt#ed25519
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let refs = config.secret_refs();
        let paths: Vec<&str> = refs.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["database.url", "auth.signing_keys.key_ref", "security.password.pepper"]
        );
    }

    #[test]
    fn unmodelled_sections_do_not_fail_the_parse() {
        // Whole sections land in later milestones; an operator's complete file must still load.
        let yaml = "
storage:
  profile: tenant-default
mcp:
  enabled: true
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn documented_enum_spellings_parse() {
        let yaml = "
profile: enterprise
auth:
  access_token:
    algorithm: EdDSA
  refresh_token:
    reuse_detection: REVOKE_FAMILY
    cookie:
      same_site: strict
antivirus:
  provider: none
  unavailable_policy: HOLD
dlp:
  default_mode: monitor
security:
  privileged_denylist_failure: FAIL_CLOSED
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.profile, DeploymentProfile::Enterprise);
        assert_eq!(config.auth.access_token.algorithm, SigningAlgorithm::EdDsa);
        assert!(!config.antivirus.is_enabled());
    }

    #[test]
    fn trusted_proxies_parse_as_cidr_and_hops() {
        let yaml = "
server:
  trusted_proxies:
    - cidr: 10.20.0.0/16
      hops: 1
";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.trusted_proxies.len(), 1);
        assert_eq!(config.server.trusted_proxies[0].hops, 1);
        assert_eq!(config.server.trusted_proxies[0].cidr.to_string(), "10.20.0.0/16");
    }
}
