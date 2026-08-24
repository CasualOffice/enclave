//! `enclave-config` — layered configuration, secret references and startup validation.
//!
//! Sits at the bottom of the dependency graph with `core` (`docs/02-HLD.md §4`,
//! `plans/M0-FOUNDATIONS.md` D1): it depends on nothing above it, so every crate may depend on it.
//!
//! # The shape of it
//!
//! ```text
//! defaults  ->  YAML file(s)  ->  environment  ->  secret provider
//! ```
//!
//! [`ConfigLoader`] applies the first three layers and produces a [`Loaded`]; the fourth is applied
//! by [`Loaded::resolve_secrets`], which turns every [`SecretRef`] in the configuration into a
//! [`SecretValue`] fetched from a [`SecretProvider`]. Two properties are load-bearing:
//!
//! * **configuration never holds a credential.** A credential-shaped value written inline is
//!   refused at startup, naming the field (`docs/08-BYO-INFRA.md §19, §20`). Secrets live behind
//!   references and arrive as [`SecretValue`], which is redacted in `Debug`, compared in constant
//!   time and zeroized on drop.
//! * **everything fails at startup or not at all.** References are parsed at load, resolved at
//!   load, and profile requirements are checked at load. A deployment that is going to fail should
//!   fail while someone is watching it deploy.
//!
//! # Example
//!
//! ```no_run
//! use enclave_config::{ConfigLoader, SecretRegistry};
//!
//! # async fn example() -> Result<(), enclave_config::ConfigError> {
//! let loaded = ConfigLoader::new()
//!     .with_file("/etc/enclave/enclave.yaml")
//!     .with_optional_file("/etc/enclave/local.yaml")
//!     .load()?;
//!
//! let secrets = loaded.resolve_secrets(&SecretRegistry::local()).await?;
//! let dsn = secrets.get("database.url");
//! # let _ = dsn;
//! # Ok(())
//! # }
//! ```

pub mod duration;
pub mod error;
pub mod loader;
pub mod model;
pub mod secret;
pub mod secret_ref;
pub mod validate;

pub use duration::{DurationParseError, HumanDuration};
pub use error::{ConfigError, Result};
pub use loader::{ConfigLoader, Loaded, ResolvedSecrets, DEFAULT_ENV_PREFIX};
pub use model::{
    AccessTokenConfig, AntivirusConfig, AntivirusProvider, Argon2Config, AuditConfig, AuthConfig,
    ConditionalAccessConfig, Config, CookieConfig, DatabaseConfig, DeploymentProfile, DlpConfig,
    DlpMode, EmbeddingMounts, EventsConfig, FactsUnavailablePolicy, FailureMode, MetricsConfig,
    MfaConfig, MilvusSettings, NetworkZoneConfig, OcrMounts, PasswordConfig, RedisConfig,
    RefreshTokenConfig, ReuseDetection, S3Flavor, S3StorageConfig, SameSite, SearchConfig,
    SearchProvider, SecurityConfig, ServerConfig, SigningAlgorithm, SigningKeysConfig,
    StorageConfig, StorageProvider, TrustedProxy, UnavailablePolicy,
};
pub use secret::{
    EnvSecretProvider, FileSecretProvider, ProviderHealth, SecretError, SecretProvider,
    SecretRegistry, SecretValue,
};
pub use secret_ref::{SecretRef, SecretRefError, SecretScheme};
pub use validate::{Problem, ProblemKind, ValidationReport};
