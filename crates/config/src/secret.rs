//! Secret *values* and the providers that fetch them.
//!
//! The split between [`SecretRef`] (a location, freely printable) and [`SecretValue`] (a value,
//! never printable) is the whole design. Configuration only ever holds the former; the latter
//! exists for as short a time as possible, is compared in constant time, and is zeroized when it
//! drops (`docs/08-BYO-INFRA.md §6`).
//!
//! Only the `env` and `file` providers live here. The remote providers (Vault, AWS/Azure/GCP,
//! Kubernetes) belong to the `secrets` crate, which may depend on HTTP clients and cloud SDKs;
//! `config` sits at the bottom of the dependency graph (`plans/M0-FOUNDATIONS.md` D1) and must not.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret_ref::{SecretRef, SecretScheme};

/// A resolved secret.
///
/// Wraps bytes rather than `String` because signing keys and pepper values are not text, and
/// because `String`'s reallocation on growth would leave copies behind that cannot be zeroized.
/// There is no `Display`, no `Serialize`, and `Debug` is redacted, so it cannot be leaked by a
/// `tracing` field, a `dbg!` left in a branch, or a serialized error body.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    /// Take ownership of secret bytes. Prefer moving a `String`/`Vec<u8>` in rather than copying
    /// from a longer-lived buffer, so there is exactly one copy to zeroize.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self { bytes: bytes.into() }
    }

    /// Borrow the raw bytes. Named `expose_` so that every use site reads as a deliberate act and
    /// greps as one during review.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the value as UTF-8, for the many secrets that are text (DSNs, passwords, tokens).
    ///
    /// # Errors
    /// [`SecretError::NotUtf8`] if the bytes are not valid UTF-8 — typically a binary key
    /// referenced where a password was expected.
    pub fn expose_str(&self) -> Result<&str, SecretError> {
        core::str::from_utf8(&self.bytes).map_err(|_| SecretError::NotUtf8)
    }

    /// Length in bytes. Useful for "is this plausibly the key I think it is" checks without
    /// touching the value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the provider returned nothing. An empty secret is almost always a misconfiguration,
    /// and callers should treat it as one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    /// Redacted on purpose. Length is disclosed because it is useful when diagnosing an empty or
    /// truncated secret and is not, by itself, the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<redacted, {} bytes>)", self.bytes.len())
    }
}

impl PartialEq for SecretValue {
    /// Constant time for equal-length values, so comparing a presented value against a stored one
    /// does not leak the matching prefix through timing. Length is compared first and is therefore
    /// observable; that is a deliberate, standard trade-off.
    fn eq(&self, other: &Self) -> bool {
        self.bytes.len() == other.bytes.len() && bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl Eq for SecretValue {}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

/// What a provider reports about itself, for `GET /health/dependencies` (`docs/03-LLD.md §19`).
///
/// `Degraded` exists so a provider serving cached values through an outage can say so without
/// claiming health: on provider outage, cached values continue to be used within their lease and
/// new fetches fail closed (`docs/08-BYO-INFRA.md §6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderHealth {
    /// Reachable and serving.
    Healthy,
    /// Reachable but impaired, or serving only from cache.
    Degraded {
        /// Operator-facing explanation. Never contains secret material.
        detail: String,
    },
    /// Not serving.
    Unavailable {
        /// Operator-facing explanation. Never contains secret material.
        detail: String,
    },
}

impl ProviderHealth {
    /// True only for [`ProviderHealth::Healthy`] — readiness must not be satisfied by a degraded
    /// provider.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Fetches secret values for the reference kinds it declares.
///
/// One trait rather than one client per backend, so a tenant can be moved from environment
/// variables to Vault by editing configuration (`docs/08-BYO-INFRA.md §6`) with no code path
/// changing. Implementations must be cheap to clone or usable behind `Arc`, and must never log the
/// value they return.
#[async_trait]
pub trait SecretProvider: fmt::Debug + Send + Sync {
    /// A stable name for logs and health output.
    fn name(&self) -> &'static str;

    /// Which reference schemes this provider serves. The registry dispatches on this rather than
    /// asking each provider to fail, so an unserved scheme is a clear configuration error.
    fn schemes(&self) -> &'static [SecretScheme];

    /// Resolve a reference to its value.
    ///
    /// # Errors
    /// [`SecretError`] describing which reference failed and why. Implementations must fail closed:
    /// never substitute a default, an empty value, or a stale value outside its lease.
    async fn read(&self, reference: &SecretRef) -> Result<SecretValue, SecretError>;

    /// Liveness of the backing store, for the dependencies endpoint.
    async fn health(&self) -> ProviderHealth;
}

/// Reads `env://NAME`.
///
/// Present in every deployment because it is how twelve-factor and Docker Compose supply secrets,
/// and because `docs/08-BYO-INFRA.md §15` writes `url_env: DATABASE_URL`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSecretProvider;

impl EnvSecretProvider {
    /// Construct. Stateless — the process environment is the state.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SecretProvider for EnvSecretProvider {
    fn name(&self) -> &'static str {
        "env"
    }

    fn schemes(&self) -> &'static [SecretScheme] {
        &[SecretScheme::Env]
    }

    async fn read(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        expect_scheme(self, reference, SecretScheme::Env)?;
        match std::env::var(reference.path()) {
            Ok(value) => Ok(SecretValue::from(value)),
            Err(std::env::VarError::NotPresent) => {
                Err(SecretError::NotFound { location: reference.to_string() })
            }
            Err(std::env::VarError::NotUnicode(_)) => Err(SecretError::NotUtf8),
        }
    }

    async fn health(&self) -> ProviderHealth {
        // The process environment cannot become unreachable.
        ProviderHealth::Healthy
    }
}

/// Reads `file:///path`, which covers Docker secrets, Kubernetes projected volumes and
/// systemd credentials — all of which present a secret as a file.
///
/// A trailing newline is stripped: every tool that writes these files (`echo`, `kubectl`, an editor)
/// adds one, and a password with an invisible trailing `\n` fails authentication in a way that
/// takes hours to diagnose.
#[derive(Debug, Clone, Default)]
pub struct FileSecretProvider {
    root: Option<PathBuf>,
}

impl FileSecretProvider {
    /// Read any absolute path.
    #[must_use]
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Confine reads to `root`.
    ///
    /// Worth using wherever configuration is tenant- or operator-editable: without it,
    /// `file:///etc/shadow` in a config file is an arbitrary-file-read primitive whose output lands
    /// wherever that secret is used.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: Some(root.into()) }
    }

    fn resolve(&self, reference: &SecretRef) -> Result<PathBuf, SecretError> {
        let path = Path::new(reference.path());
        // `..` is already rejected by `SecretRef` parsing, so a prefix check is sufficient here.
        if let Some(root) = &self.root {
            if !path.starts_with(root) {
                return Err(SecretError::OutsideRoot {
                    location: reference.to_string(),
                    root: root.clone(),
                });
            }
        }
        Ok(path.to_path_buf())
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn schemes(&self) -> &'static [SecretScheme] {
        &[SecretScheme::File]
    }

    async fn read(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        expect_scheme(self, reference, SecretScheme::File)?;
        let path = self.resolve(reference)?;
        match tokio::fs::read(&path).await {
            Ok(mut bytes) => {
                while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                    bytes.pop();
                }
                Ok(SecretValue::new(bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(SecretError::NotFound { location: reference.to_string() })
            }
            Err(err) => {
                Err(SecretError::Unavailable { location: reference.to_string(), source: err })
            }
        }
    }

    async fn health(&self) -> ProviderHealth {
        match &self.root {
            Some(root) if !root.is_dir() => ProviderHealth::Unavailable {
                detail: format!("secret root {} is not a directory", root.display()),
            },
            _ => ProviderHealth::Healthy,
        }
    }
}

/// Routes a reference to the provider that serves its scheme.
///
/// Deployments mix providers — `env` for the DSN in development, `vault` for everything in
/// production — so resolution is a dispatch, not a single client. Registration order decides
/// ties, and a scheme with no provider is an error rather than a silent skip.
#[derive(Debug, Default, Clone)]
pub struct SecretRegistry {
    providers: Vec<Arc<dyn SecretProvider>>,
}

impl SecretRegistry {
    /// An empty registry, which resolves nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { providers: Vec::new() }
    }

    /// The providers this crate can supply on its own: environment variables and files.
    #[must_use]
    pub fn local() -> Self {
        Self::new().with(EnvSecretProvider::new()).with(FileSecretProvider::new())
    }

    /// Add a provider, builder style.
    #[must_use]
    pub fn with(mut self, provider: impl SecretProvider + 'static) -> Self {
        self.providers.push(Arc::new(provider));
        self
    }

    /// Add an already-shared provider, for backends constructed elsewhere.
    #[must_use]
    pub fn with_arc(mut self, provider: Arc<dyn SecretProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// The provider that would serve `scheme`, if any.
    #[must_use]
    pub fn provider_for(&self, scheme: SecretScheme) -> Option<&Arc<dyn SecretProvider>> {
        self.providers.iter().find(|p| p.schemes().contains(&scheme))
    }

    /// Resolve one reference.
    ///
    /// # Errors
    /// [`SecretError::NoProvider`] if no registered provider serves the scheme, otherwise whatever
    /// the provider reports.
    pub async fn read(&self, reference: &SecretRef) -> Result<SecretValue, SecretError> {
        let provider = self
            .provider_for(reference.scheme())
            .ok_or(SecretError::NoProvider { scheme: reference.scheme() })?;
        provider.read(reference).await
    }

    /// Health of every registered provider, by provider name.
    pub async fn health(&self) -> Vec<(&'static str, ProviderHealth)> {
        let mut out = Vec::with_capacity(self.providers.len());
        for provider in &self.providers {
            out.push((provider.name(), provider.health().await));
        }
        out
    }
}

/// Why a secret could not be resolved.
///
/// `location` fields hold the *reference* (`vault://workspace/smtp#password`), never the value —
/// a location is already in the configuration file and is safe to log, which is what makes these
/// errors actionable.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// No registered provider serves this scheme.
    #[error("no secret provider is configured for the `{scheme}` scheme")]
    NoProvider {
        /// The unserved scheme.
        scheme: SecretScheme,
    },

    /// A provider was handed a reference it does not serve — a wiring bug, not a config error.
    #[error("secret provider `{provider}` cannot serve `{scheme}://` references")]
    WrongProvider {
        /// The provider that was asked.
        provider: &'static str,
        /// The scheme it was asked for.
        scheme: SecretScheme,
    },

    /// The reference is well formed but nothing is stored there.
    #[error("secret `{location}` is not set")]
    NotFound {
        /// The reference that resolved to nothing.
        location: String,
    },

    /// The backing store could not be reached or read. Fail closed: never fall back to a default.
    #[error("secret `{location}` could not be read")]
    Unavailable {
        /// The reference that could not be read.
        location: String,
        /// The underlying I/O or transport failure.
        #[source]
        source: std::io::Error,
    },

    /// The reference points outside the directory the provider is confined to.
    #[error("secret `{location}` is outside the permitted secret root {}", root.display())]
    OutsideRoot {
        /// The reference that was refused.
        location: String,
        /// The configured confinement root.
        root: PathBuf,
    },

    /// The value is not valid UTF-8 where text was required. The value itself is never included.
    #[error("secret value is not valid UTF-8")]
    NotUtf8,
}

fn expect_scheme(
    provider: &impl SecretProvider,
    reference: &SecretRef,
    expected: SecretScheme,
) -> Result<(), SecretError> {
    if reference.scheme() == expected {
        Ok(())
    } else {
        Err(SecretError::WrongProvider { provider: provider.name(), scheme: reference.scheme() })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretValue::from("hunter2-correct-horse".to_owned());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "got: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn equality_is_value_based() {
        let a = SecretValue::from("same".to_owned());
        let b = SecretValue::from("same".to_owned());
        let c = SecretValue::from("other".to_owned());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, SecretValue::from("sam".to_owned()));
    }

    #[tokio::test]
    async fn env_provider_reads_and_reports_missing() {
        let name = "ENCLAVE_TEST_SECRET_ENV_PROVIDER";
        std::env::set_var(name, "s3cret");
        let registry = SecretRegistry::local();

        let reference: SecretRef = format!("env://{name}").parse().unwrap();
        let value = registry.read(&reference).await.unwrap();
        assert_eq!(value.expose_str().unwrap(), "s3cret");

        std::env::remove_var(name);
        let err = registry.read(&reference).await.unwrap_err();
        assert!(matches!(err, SecretError::NotFound { .. }), "got: {err:?}");
    }

    #[tokio::test]
    async fn file_provider_strips_the_trailing_newline() {
        let dir = std::env::temp_dir().join("enclave-config-secret-test");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("db-password");
        tokio::fs::write(&path, b"file-secret\n").await.unwrap();

        let reference: SecretRef = format!("file://{}", path.display()).parse().unwrap();
        let value = FileSecretProvider::new().read(&reference).await.unwrap();
        assert_eq!(value.expose_str().unwrap(), "file-secret");

        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn file_provider_refuses_paths_outside_its_root() {
        let provider = FileSecretProvider::with_root("/run/secrets");
        let reference: SecretRef = "file:///etc/shadow".parse().unwrap();
        let err = provider.read(&reference).await.unwrap_err();
        assert!(matches!(err, SecretError::OutsideRoot { .. }), "got: {err:?}");
    }

    #[tokio::test]
    async fn registry_reports_an_unserved_scheme() {
        let registry = SecretRegistry::new().with(EnvSecretProvider::new());
        let reference: SecretRef = "vault://workspace/smtp#password".parse().unwrap();
        let err = registry.read(&reference).await.unwrap_err();
        assert!(
            matches!(err, SecretError::NoProvider { scheme: SecretScheme::Vault }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn local_registry_is_healthy() {
        let health = SecretRegistry::local().health().await;
        assert_eq!(health.len(), 2);
        assert!(health.iter().all(|(_, h)| h.is_healthy()));
    }
}
