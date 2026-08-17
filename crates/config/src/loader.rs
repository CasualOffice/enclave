//! Layered loading: `defaults -> file -> environment -> secret provider`
//! (`docs/03-LLD.md §21`, `docs/08-BYO-INFRA.md §20`).
//!
//! The order is not arbitrary. Defaults are the safe baseline that a developer gets for free; the
//! file is what is reviewed and versioned; the environment is what a deployment system injects per
//! stage; the secret provider is last because it is the only layer allowed to hold actual
//! credentials, and nothing written in an earlier layer may shadow it.
//!
//! Each layer is applied by *deep merge*, so setting `ENCLAVE_SERVER__PORT` overrides the port
//! without discarding the rest of the `server` section — the alternative (whole-section
//! replacement) makes an environment override silently reset neighbouring fields to their defaults.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_yaml::{Mapping, Value};

use crate::error::{ConfigError, Result};
use crate::model::Config;
use crate::secret::{SecretRegistry, SecretValue};
use crate::validate::{Problem, ProblemKind, ValidationReport};

/// Default prefix for environment overrides.
pub const DEFAULT_ENV_PREFIX: &str = "ENCLAVE_";

/// Separator between path segments in an environment variable name.
///
/// Two underscores, because single underscores appear inside field names (`refresh_token`,
/// `max_connections`); `ENCLAVE_AUTH__REFRESH_TOKEN__ROTATION` is unambiguous where
/// `ENCLAVE_AUTH_REFRESH_TOKEN_ROTATION` is not.
const ENV_SEPARATOR: &str = "__";

/// One YAML layer.
#[derive(Debug, Clone)]
enum YamlSource {
    File { path: PathBuf, required: bool },
    Inline { name: String, text: String },
}

/// Builds a [`Config`] by applying the layers in order.
///
/// The environment can be supplied explicitly rather than read from the process, which is what
/// makes precedence testable: tests that mutate the real environment race each other and pass or
/// fail depending on thread scheduling.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    sources: Vec<YamlSource>,
    env_prefix: String,
    env: Option<BTreeMap<String, String>>,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// A loader with defaults only, reading overrides from the process environment.
    #[must_use]
    pub fn new() -> Self {
        Self { sources: Vec::new(), env_prefix: DEFAULT_ENV_PREFIX.to_owned(), env: None }
    }

    /// Add a configuration file that must exist.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(YamlSource::File { path: path.into(), required: true });
        self
    }

    /// Add a configuration file that is used if present.
    ///
    /// Useful for a per-developer overlay: absent in CI, present locally, and never a reason for
    /// the process to fail.
    #[must_use]
    pub fn with_optional_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(YamlSource::File { path: path.into(), required: false });
        self
    }

    /// Add a YAML layer from memory, for tests and for configuration embedded in a deployment
    /// image.
    #[must_use]
    pub fn with_yaml(mut self, name: impl Into<String>, text: impl Into<String>) -> Self {
        self.sources.push(YamlSource::Inline { name: name.into(), text: text.into() });
        self
    }

    /// Change the environment-variable prefix.
    #[must_use]
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = prefix.into();
        self
    }

    /// Use an explicit environment instead of the process environment.
    #[must_use]
    pub fn with_env<K, V>(mut self, vars: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.env = Some(vars.into_iter().map(|(key, value)| (key.into(), value.into())).collect());
        self
    }

    /// Ignore the environment layer entirely.
    #[must_use]
    pub fn without_env(mut self) -> Self {
        self.env = Some(BTreeMap::new());
        self
    }

    /// Apply defaults, files and environment, then run every startup check.
    ///
    /// # Errors
    /// [`ConfigError::Io`] or [`ConfigError::Syntax`] for an unreadable or malformed file,
    /// [`ConfigError::Model`] when the merged tree does not match the model, and
    /// [`ConfigError::Invalid`] with the full [`ValidationReport`] when it parses but breaks a
    /// startup rule.
    pub fn load(&self) -> Result<Loaded> {
        let mut raw = Value::Mapping(Mapping::new());

        for source in &self.sources {
            match source {
                YamlSource::File { path, required } => match std::fs::read_to_string(path) {
                    Ok(text) => merge(&mut raw, parse(path, &text)?),
                    Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => {
                        tracing::debug!(
                            path = %path.display(),
                            "optional configuration file not present"
                        );
                    }
                    Err(err) => return Err(ConfigError::Io { path: path.clone(), source: err }),
                },
                YamlSource::Inline { name, text } => {
                    merge(&mut raw, parse(Path::new(name.as_str()), text)?);
                }
            }
        }

        for (path, value) in self.env_overrides() {
            // The path is logged; the value never is. An environment override is very often
            // exactly where a credential would be (CLAUDE.md rule 10).
            tracing::debug!(field = %path.join("."), "applying environment override");
            let segments: Vec<&str> = path.iter().map(String::as_str).collect();
            set_path(&mut raw, &segments, value);
        }

        // Scanning happens on the *raw* tree, before typing, so that sections this milestone does
        // not model yet are still checked for inline credentials.
        let inline = crate::validate::scan_for_inline_secrets(&raw);
        if !inline.is_empty() {
            let mut report = ValidationReport::new();
            report.extend(inline);
            return Err(ConfigError::Invalid(report));
        }

        let config: Config =
            serde_yaml::from_value(raw.clone()).map_err(|source| ConfigError::Model { source })?;

        crate::validate::validate(&config, &raw)?;
        Ok(Loaded { config, raw })
    }

    /// The environment layer, as `(path segments, scalar)` pairs in deterministic order.
    fn env_overrides(&self) -> Vec<(Vec<String>, Value)> {
        let mut out = Vec::new();
        let mut consider = |key: &str, value: &str| {
            let Some(rest) = key.strip_prefix(&self.env_prefix) else { return };
            let segments: Vec<String> = rest
                .split(ENV_SEPARATOR)
                .filter(|segment| !segment.is_empty())
                .map(str::to_ascii_lowercase)
                .collect();
            if segments.is_empty() {
                return;
            }
            out.push((segments, scalar(value)));
        };

        match &self.env {
            Some(vars) => {
                for (key, value) in vars {
                    consider(key, value);
                }
            }
            None => {
                let mut vars: Vec<(String, String)> = std::env::vars().collect();
                vars.sort();
                for (key, value) in &vars {
                    consider(key, value);
                }
            }
        }
        out
    }
}

/// A configuration that has passed every startup check.
///
/// Keeps the merged raw tree alongside the typed value: `config_versions`
/// (`docs/08-BYO-INFRA.md §21`) stores what the operator wrote, not what the model happened to
/// capture, and a diff of two releases is only meaningful against the raw form.
#[derive(Debug, Clone)]
pub struct Loaded {
    config: Config,
    raw: Value,
}

impl Loaded {
    /// The typed configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// The merged tree exactly as the layers produced it.
    #[must_use]
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    /// Take the typed configuration.
    #[must_use]
    pub fn into_config(self) -> Config {
        self.config
    }

    /// Apply the fourth layer: resolve every secret reference through `registry`.
    ///
    /// Runs at startup rather than at first use, and reports *every* reference that could not be
    /// resolved. A deployment whose Vault path is wrong should fail while it is being deployed, not
    /// when someone tries to reset a password at 02:00.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] listing each reference that could not be read, by field path.
    pub async fn resolve_secrets(&self, registry: &SecretRegistry) -> Result<ResolvedSecrets> {
        let mut resolved = BTreeMap::new();
        let mut report = ValidationReport::new();

        for (path, reference) in self.config.secret_refs() {
            match registry.read(&reference).await {
                Ok(value) if value.is_empty() => report.push(Problem::new(
                    path,
                    ProblemKind::SecretUnresolvable,
                    format!("secret `{reference}` resolved to an empty value"),
                )),
                Ok(value) => {
                    resolved.insert(path, value);
                }
                Err(err) => report.push(Problem::new(
                    path,
                    ProblemKind::SecretUnresolvable,
                    format!("could not resolve `{reference}`: {err}"),
                )),
            }
        }

        report.into_result()?;
        Ok(ResolvedSecrets { values: resolved })
    }
}

/// Secret values resolved at startup, keyed by the configuration path they came from.
///
/// A map rather than fields on `Config` so that the typed configuration stays freely `Debug`- and
/// `Serialize`-able: nothing that can be printed ever holds a secret.
#[derive(Default, Clone)]
pub struct ResolvedSecrets {
    values: BTreeMap<String, SecretValue>,
}

impl ResolvedSecrets {
    /// The value resolved for a configuration path, e.g. `"database.url"`.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&SecretValue> {
        self.values.get(path)
    }

    /// Which paths were resolved. Paths are not secret; the values are.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    /// How many secrets were resolved.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether anything was resolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl core::fmt::Debug for ResolvedSecrets {
    /// Lists the paths and nothing else, so a `Debug` of application state is safe.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResolvedSecrets")
            .field("paths", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn parse(path: &Path, text: &str) -> Result<Value> {
    let value: Value = serde_yaml::from_str(text)
        .map_err(|source| ConfigError::Syntax { path: path.to_path_buf(), source })?;
    Ok(match value {
        // An empty file is a legitimate "nothing overridden".
        Value::Null => Value::Mapping(Mapping::new()),
        other => other,
    })
}

/// Deep-merge `overlay` into `base`; mappings merge key by key, everything else is replaced.
///
/// Sequences are replaced rather than concatenated: `trusted_proxies` is a security-relevant list,
/// and a layer that means to narrow it must be able to.
fn merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(base), Value::Mapping(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) => merge(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// Set `path` in `node`, creating intermediate mappings.
fn set_path(node: &mut Value, path: &[&str], leaf: Value) {
    let Some((head, rest)) = path.split_first() else {
        *node = leaf;
        return;
    };
    if !node.is_mapping() {
        *node = Value::Mapping(Mapping::new());
    }
    let Value::Mapping(map) = node else { return };
    let key = Value::String((*head).to_owned());
    let child = map.entry(key).or_insert(Value::Null);
    set_path(child, rest, leaf);
}

/// Interpret an environment value as a YAML scalar.
///
/// Deliberately narrow: booleans, integers and floats are recognized, everything else stays a
/// string. Handing the value to the YAML parser instead would make `ENCLAVE_AUTH__AUDIENCE=a: b`
/// silently become a mapping, and `no` become `false`.
fn scalar(value: &str) -> Value {
    if let Ok(boolean) = value.parse::<bool>() {
        return Value::Bool(boolean);
    }
    if let Ok(int) = value.parse::<i64>() {
        return Value::Number(int.into());
    }
    if let Ok(float) = value.parse::<f64>() {
        return Value::Number(float.into());
    }
    Value::String(value.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::{AntivirusProvider, DeploymentProfile};
    use crate::secret_ref::SecretScheme;
    use crate::validate::ProblemKind;

    const FILE: &str = "
profile: production
server:
  port: 9090
  bind: 0.0.0.0
database:
  url: env://FILE_DSN
  max_connections: 25
auth:
  refresh_token:
    idle_ttl: 7d
";

    fn loader() -> ConfigLoader {
        ConfigLoader::new().without_env()
    }

    #[test]
    fn layer_one_defaults() {
        let loaded = loader().load().unwrap();
        let config = loaded.config();
        assert_eq!(config.profile, DeploymentProfile::Community);
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.max_connections, 50);
        assert_eq!(config.auth.refresh_token.idle_ttl.as_secs(), 14 * 86_400);
    }

    #[test]
    fn layer_two_file_overrides_defaults() {
        let loaded = loader().with_yaml("test.yaml", FILE).load().unwrap();
        let config = loaded.config();
        assert_eq!(config.profile, DeploymentProfile::Production);
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.database.max_connections, 25);
        assert_eq!(config.auth.refresh_token.idle_ttl.as_secs(), 7 * 86_400);
        // Untouched neighbours keep their defaults.
        assert_eq!(config.auth.refresh_token.absolute_ttl.as_secs(), 90 * 86_400);
        assert_eq!(config.database.application_role, "enclave_app");
    }

    #[test]
    fn layer_three_environment_overrides_the_file() {
        let loaded = ConfigLoader::new()
            .with_yaml("test.yaml", FILE)
            .with_env([
                ("ENCLAVE_SERVER__PORT", "9099"),
                ("ENCLAVE_DATABASE__URL", "env://ENV_DSN"),
                ("ENCLAVE_AUTH__REFRESH_TOKEN__ROTATION", "false"),
                ("ENCLAVE_AUTH__ACCESS_TOKEN__AUDIENCE", "enclave-api-staging"),
                ("UNPREFIXED_SERVER__PORT", "1"),
            ])
            .load()
            .unwrap();
        let config = loaded.config();
        assert_eq!(config.server.port, 9099, "environment must beat the file");
        assert_eq!(config.database.url_ref().unwrap().to_string(), "env://ENV_DSN");
        assert!(!config.auth.refresh_token.rotation);
        assert_eq!(config.auth.access_token.audience, "enclave-api-staging");
        // The file layer still supplies what the environment did not.
        assert_eq!(config.profile, DeploymentProfile::Production);
        assert_eq!(config.database.max_connections, 25);
    }

    #[tokio::test]
    async fn layer_four_the_secret_provider_supplies_the_value() {
        let name = "ENCLAVE_TEST_LOADER_ENV_DSN";
        std::env::set_var(name, "postgres://app@db/enclave");

        let loaded = ConfigLoader::new()
            .with_yaml("test.yaml", FILE)
            .with_env([("ENCLAVE_DATABASE__URL", format!("env://{name}"))])
            .load()
            .unwrap();

        // The configuration holds only the reference...
        assert_eq!(
            loaded.config().database.url_ref().unwrap().to_string(),
            format!("env://{name}")
        );

        // ...and the provider layer turns it into the value.
        let secrets = loaded.resolve_secrets(&SecretRegistry::local()).await.unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets.get("database.url").unwrap().expose_str().unwrap(),
            "postgres://app@db/enclave"
        );
        assert_eq!(secrets.paths().collect::<Vec<_>>(), vec!["database.url"]);

        std::env::remove_var(name);
    }

    #[tokio::test]
    async fn an_unresolvable_secret_fails_startup_naming_the_field() {
        let loaded = ConfigLoader::new()
            .without_env()
            .with_yaml("test.yaml", "database:\n  url: env://ENCLAVE_TEST_ABSENT_DSN\n")
            .load()
            .unwrap();
        let err = loaded.resolve_secrets(&SecretRegistry::local()).await.unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.len(), 1);
        assert_eq!(report.problems()[0].path, "database.url");
        assert_eq!(report.problems()[0].kind, ProblemKind::SecretUnresolvable);
    }

    #[test]
    fn every_layer_at_once() {
        let loaded = ConfigLoader::new()
            .with_yaml("base.yaml", FILE)
            .with_env([("ENCLAVE_SERVER__PORT", "7777")])
            .load()
            .unwrap();
        let config = loaded.config();
        assert_eq!(config.server.port, 7777, "environment");
        assert_eq!(config.database.max_connections, 25, "file");
        assert_eq!(config.security.password.min_length, 12, "default");
        assert_eq!(loaded.config().secret_refs().len(), 1);
    }

    #[test]
    fn later_files_override_earlier_ones() {
        let loaded = loader()
            .with_yaml("base.yaml", "server:\n  port: 1111\n")
            .with_yaml("overlay.yaml", "server:\n  port: 2222\n")
            .load()
            .unwrap();
        assert_eq!(loaded.config().server.port, 2222);
    }

    #[test]
    fn a_missing_optional_file_is_not_an_error() {
        let loaded =
            loader().with_optional_file("/nonexistent/enclave-overlay.yaml").load().unwrap();
        assert_eq!(loaded.config().server.port, 8080);
    }

    #[test]
    fn a_missing_required_file_is_an_error() {
        let err = loader().with_file("/nonexistent/enclave.yaml").load().unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }), "got: {err:?}");
    }

    #[test]
    fn a_malformed_secret_reference_fails_at_load_not_at_first_use() {
        let err = loader()
            .with_yaml("test.yaml", "database:\n  url: \"not-a-reference\"\n")
            .load()
            .unwrap_err();
        assert!(matches!(err, ConfigError::Model { .. }), "got: {err:?}");
        assert!(err.to_string().contains("scheme"), "got: {err}");
    }

    #[test]
    fn an_inline_credential_refuses_startup_and_names_the_field() {
        let err = loader()
            .with_yaml("test.yaml", "mail:\n  smtp:\n    password: \"Xf7!qP2m-Vb93sLdKe0ZtR\"\n")
            .load()
            .unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.len(), 1);
        assert_eq!(report.problems()[0].path, "mail.smtp.password");
        assert_eq!(report.problems()[0].kind, ProblemKind::InlineCredential);
        assert!(!err.to_string().contains("Xf7"), "the value must never be echoed");
    }

    #[test]
    fn enterprise_refuses_to_start_without_antivirus_or_audit() {
        let err = loader()
            .with_yaml(
                "test.yaml",
                "profile: enterprise\nantivirus:\n  provider: none\naudit:\n  enabled: false\n",
            )
            .load()
            .unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.len(), 2, "both problems must be reported: {report}");
        let paths: Vec<&str> = report.problems().iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["antivirus.provider", "audit.enabled"]);
        assert!(report.has_kind(ProblemKind::ProfileRequirement));
    }

    #[test]
    fn enterprise_starts_when_the_requirements_are_met() {
        let loaded = loader().with_yaml("test.yaml", "profile: enterprise\n").load().unwrap();
        assert_eq!(loaded.config().antivirus.provider, AntivirusProvider::Clamav);
        assert!(loaded.config().audit.enabled);
    }

    #[test]
    fn environment_values_are_typed_narrowly() {
        assert_eq!(scalar("true"), Value::Bool(true));
        assert_eq!(scalar("8080"), Value::Number(8080.into()));
        assert_eq!(scalar("no"), Value::String("no".to_owned()));
        assert_eq!(scalar("a: b"), Value::String("a: b".to_owned()));
        assert_eq!(scalar("env://X"), Value::String("env://X".to_owned()));
    }

    #[test]
    fn raw_tree_is_preserved_for_config_versioning() {
        let loaded = loader().with_yaml("test.yaml", "server:\n  port: 9090\n").load().unwrap();
        let raw = loaded.raw();
        assert_eq!(raw["server"]["port"], Value::Number(9090.into()));
    }

    #[tokio::test]
    async fn a_registry_without_the_scheme_reports_it_per_field() {
        let loaded = loader()
            .with_yaml("test.yaml", "database:\n  url: vault://workspace/db#dsn\n")
            .load()
            .unwrap();
        let registry = SecretRegistry::new();
        let err = loaded.resolve_secrets(&registry).await.unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.problems()[0].path, "database.url");
        assert_eq!(report.problems()[0].kind, ProblemKind::SecretUnresolvable);
        assert!(registry.provider_for(SecretScheme::Vault).is_none());
    }
}
