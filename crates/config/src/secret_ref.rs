//! Parsed references to secrets held outside the configuration file.
//!
//! Configuration holds *references*, never values (`docs/08-BYO-INFRA.md §6`, CLAUDE.md rule 11).
//! The reference is a parsed type rather than a `String` because the two failure modes differ
//! enormously in cost: a typo caught while the process is starting is a restart, the same typo
//! caught at first use is an outage in the middle of a request — typically the *first* password
//! reset or the *first* upload after a deploy, hours later, on someone else's shift.
//!
//! Syntax: `{scheme}://{path}#{field}`.
//!
//! Error messages here deliberately never echo the offending value. A malformed reference is very
//! often a credential that was pasted inline by mistake, and a startup error is written to stdout,
//! the container log and probably a monitoring pipeline (CLAUDE.md rule 10).

use core::fmt;
use core::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Where a secret lives. The set is closed: an unknown scheme is a configuration error, never a
/// pass-through to some default provider, because "unknown provider" silently falling back to
/// environment variables is how a production secret ends up read from a developer shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretScheme {
    /// Process environment variable. Path is the variable name.
    Env,
    /// File on the local filesystem, e.g. a Docker or Kubernetes projected secret. Path is
    /// absolute.
    File,
    /// Kubernetes `Secret`. Path is `namespace/name`, field is the data key.
    K8s,
    /// HashiCorp Vault. Path is the KV path, field is the key inside it.
    Vault,
    /// AWS Secrets Manager. Path is the secret id or ARN; the optional field selects a key inside
    /// a JSON secret.
    AwsSm,
    /// Azure Key Vault. Path is `vault-name/secret-name`; the optional field selects a JSON key.
    AzKv,
    /// GCP Secret Manager. Path is `projects/x/secrets/y/versions/z`; the optional field selects a
    /// JSON key.
    GcpSm,
}

impl SecretScheme {
    /// Every scheme, in declaration order — used to build error messages and to let a provider
    /// declare what it can serve.
    pub const ALL: &'static [Self] =
        &[Self::Env, Self::File, Self::K8s, Self::Vault, Self::AwsSm, Self::AzKv, Self::GcpSm];

    /// The wire form, which is also the form written in YAML.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
            Self::K8s => "k8s",
            Self::Vault => "vault",
            Self::AwsSm => "awssm",
            Self::AzKv => "azkv",
            Self::GcpSm => "gcpsm",
        }
    }

    /// Whether a `#field` selector is mandatory.
    ///
    /// Vault and Kubernetes secrets are always key/value maps, so a reference without a key is
    /// ambiguous; the cloud managers can hold a bare string, so there the selector is optional.
    #[must_use]
    pub const fn requires_field(&self) -> bool {
        matches!(self, Self::K8s | Self::Vault)
    }

    /// Whether a `#field` selector is permitted at all. `env` and `file` address a single value,
    /// so a selector there means the author misunderstood the syntax — better to say so than to
    /// ignore it.
    #[must_use]
    pub const fn allows_field(&self) -> bool {
        !matches!(self, Self::Env | Self::File)
    }
}

impl fmt::Display for SecretScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SecretScheme {
    type Err = SecretRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|scheme| scheme.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| SecretRefError::UnknownScheme { scheme: truncate(s, 16) })
    }
}

/// A validated pointer to a secret, e.g. `vault://workspace/smtp#password`.
///
/// Construction is the only way to obtain one, so holding a `SecretRef` is proof the syntax and the
/// per-scheme rules were checked. Nothing in this type is itself sensitive — it is a location, not
/// a value — which is why it is `Debug` and `Display` in full while [`SecretValue`] is not.
///
/// [`SecretValue`]: crate::SecretValue
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRef {
    scheme: SecretScheme,
    path: Box<str>,
    field: Option<Box<str>>,
}

impl SecretRef {
    /// Build a reference from parts, applying exactly the same validation as parsing, so code that
    /// derives a reference (`url_env: DATABASE_URL` becoming `env://DATABASE_URL`) cannot produce
    /// one that the parser would have rejected.
    ///
    /// # Errors
    /// Returns the specific rule that the parts violate.
    pub fn new(
        scheme: SecretScheme,
        path: impl Into<String>,
        field: Option<impl Into<String>>,
    ) -> Result<Self, SecretRefError> {
        let path = path.into();
        let field = field.map(Into::into);
        validate_path(scheme, &path)?;
        match (&field, scheme.allows_field(), scheme.requires_field()) {
            (Some(_), false, _) => return Err(SecretRefError::UnexpectedField { scheme }),
            (None, _, true) => return Err(SecretRefError::MissingField { scheme }),
            (Some(f), true, _) => validate_field(scheme, f)?,
            (None, _, false) => {}
        }
        Ok(Self { scheme, path: path.into(), field: field.map(Into::into) })
    }

    /// Parse `{scheme}://{path}#{field}`.
    ///
    /// # Errors
    /// Returns the first rule violated. The offending value is never included in the error.
    pub fn parse(value: &str) -> Result<Self, SecretRefError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(SecretRefError::Empty);
        }
        let (scheme_str, rest) = value.split_once("://").ok_or(SecretRefError::MissingScheme)?;
        let scheme: SecretScheme = scheme_str.parse()?;
        let (path, field) = match rest.split_once('#') {
            Some((path, field)) => (path, Some(field)),
            None => (rest, None),
        };
        Self::new(scheme, path, field)
    }

    /// Which provider must serve this reference.
    #[must_use]
    pub const fn scheme(&self) -> SecretScheme {
        self.scheme
    }

    /// The provider-specific location, with the `{scheme}://` prefix removed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The key selected inside the secret, if the scheme uses one.
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.path)?;
        match &self.field {
            Some(field) => write!(f, "#{field}"),
            None => Ok(()),
        }
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SecretRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretRefVisitor;

        impl Visitor<'_> for SecretRefVisitor {
            type Value = SecretRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret reference of the form {scheme}://{path}#{field}")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                // `SecretRefError` never contains the value, so surfacing it through serde cannot
                // put a mistyped credential into a startup log.
                SecretRef::parse(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SecretRefVisitor)
    }
}

/// Why a reference was rejected.
///
/// Every variant names the rule and the scheme, and nothing else: the rejected text may itself be
/// the secret someone meant to reference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// The value was empty or whitespace.
    #[error("secret reference is empty")]
    Empty,

    /// No `://` separator, which usually means a literal value was written where a reference
    /// belongs.
    #[error("secret reference is missing a `{{scheme}}://` prefix (expected one of env, file, k8s, vault, awssm, azkv, gcpsm)")]
    MissingScheme,

    /// The scheme is not one this build knows how to resolve.
    #[error("unknown secret scheme `{scheme}` (expected one of env, file, k8s, vault, awssm, azkv, gcpsm)")]
    UnknownScheme {
        /// The offending scheme token, truncated. A scheme is not sensitive.
        scheme: String,
    },

    /// Nothing followed the `://`.
    #[error("`{scheme}://` secret reference has an empty path")]
    EmptyPath {
        /// The scheme that was parsed before the path turned out to be empty.
        scheme: SecretScheme,
    },

    /// The path is present but not usable for this scheme.
    #[error("`{scheme}://` secret reference has an invalid path: {reason}")]
    InvalidPath {
        /// The scheme whose path rules were violated.
        scheme: SecretScheme,
        /// Which rule was violated.
        reason: &'static str,
    },

    /// A `#field` selector is mandatory for this scheme.
    #[error("`{scheme}://` secret reference requires a `#field` selector")]
    MissingField {
        /// The scheme that requires a selector.
        scheme: SecretScheme,
    },

    /// A `#field` selector is meaningless for this scheme.
    #[error("`{scheme}://` secret reference does not take a `#field` selector")]
    UnexpectedField {
        /// The scheme that does not accept a selector.
        scheme: SecretScheme,
    },

    /// The selector is present but empty or malformed.
    #[error("`{scheme}://` secret reference has an invalid `#field` selector: {reason}")]
    InvalidField {
        /// The scheme whose selector rules were violated.
        scheme: SecretScheme,
        /// Which rule was violated.
        reason: &'static str,
    },
}

fn validate_path(scheme: SecretScheme, path: &str) -> Result<(), SecretRefError> {
    if path.is_empty() {
        return Err(SecretRefError::EmptyPath { scheme });
    }
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(SecretRefError::InvalidPath {
            scheme,
            reason: "contains whitespace or control characters",
        });
    }
    match scheme {
        // Shell rules for identifiers. Anything else will not survive the round trip through a
        // container runtime, so rejecting it here beats an empty value later.
        SecretScheme::Env => {
            let valid = path.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && path.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                return Err(SecretRefError::InvalidPath {
                    scheme,
                    reason: "is not a valid environment variable name",
                });
            }
        }
        // Relative paths resolve against a working directory that differs between the shell, the
        // container and systemd. Requiring absolute removes the class.
        SecretScheme::File => {
            if !path.starts_with('/') {
                return Err(SecretRefError::InvalidPath {
                    scheme,
                    reason: "must be an absolute path, e.g. file:///run/secrets/db",
                });
            }
            if path.split('/').any(|segment| segment == "..") {
                return Err(SecretRefError::InvalidPath {
                    scheme,
                    reason: "must not contain `..` segments",
                });
            }
        }
        SecretScheme::K8s => {
            if path.split('/').filter(|s| !s.is_empty()).count() != 2 {
                return Err(SecretRefError::InvalidPath {
                    scheme,
                    reason: "must be `namespace/name`",
                });
            }
        }
        SecretScheme::Vault | SecretScheme::AwsSm | SecretScheme::AzKv | SecretScheme::GcpSm => {}
    }
    Ok(())
}

fn validate_field(scheme: SecretScheme, field: &str) -> Result<(), SecretRefError> {
    if field.is_empty() {
        return Err(SecretRefError::InvalidField { scheme, reason: "is empty" });
    }
    if field.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(SecretRefError::InvalidField {
            scheme,
            reason: "contains whitespace or control characters",
        });
    }
    Ok(())
}

/// Truncate on a character boundary so an error message cannot be enormous or panic on a multi-byte
/// boundary.
fn truncate(value: &str, max: usize) -> String {
    match value.char_indices().nth(max) {
        Some((idx, _)) => format!("{}…", &value[..idx]),
        None => value.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_scheme() {
        let cases = [
            "env://DATABASE_URL",
            "file:///run/secrets/db-password",
            "k8s://enclave/smtp#password",
            "vault://workspace/smtp#password",
            "awssm://prod/enclave/db",
            "awssm://prod/enclave/db#password",
            "azkv://enclave-kv/smtp-password",
            "gcpsm://projects/p/secrets/s/versions/1#password",
        ];
        for case in cases {
            let parsed: SecretRef = case.parse().expect(case);
            assert_eq!(parsed.to_string(), case, "display must reproduce the input");
            let reparsed: SecretRef = parsed.to_string().parse().unwrap();
            assert_eq!(parsed, reparsed);
        }
    }

    #[test]
    fn parses_parts() {
        let r: SecretRef = "vault://workspace/smtp#password".parse().unwrap();
        assert_eq!(r.scheme(), SecretScheme::Vault);
        assert_eq!(r.path(), "workspace/smtp");
        assert_eq!(r.field(), Some("password"));

        let r: SecretRef = "env://DATABASE_URL".parse().unwrap();
        assert_eq!(r.path(), "DATABASE_URL");
        assert_eq!(r.field(), None);
    }

    #[test]
    fn rejects_malformed_references() {
        let cases: &[(&str, SecretRefError)] = &[
            ("", SecretRefError::Empty),
            ("   ", SecretRefError::Empty),
            ("s3cr3t-value", SecretRefError::MissingScheme),
            ("https://example.com/x", SecretRefError::UnknownScheme { scheme: "https".into() }),
            ("vault://", SecretRefError::EmptyPath { scheme: SecretScheme::Vault }),
            (
                "vault://workspace/smtp",
                SecretRefError::MissingField { scheme: SecretScheme::Vault },
            ),
            ("k8s://enclave/smtp", SecretRefError::MissingField { scheme: SecretScheme::K8s }),
            (
                "k8s://enclave#password",
                SecretRefError::InvalidPath {
                    scheme: SecretScheme::K8s,
                    reason: "must be `namespace/name`",
                },
            ),
            (
                "env://DATABASE_URL#field",
                SecretRefError::UnexpectedField { scheme: SecretScheme::Env },
            ),
            (
                "env://not-a-var-name",
                SecretRefError::InvalidPath {
                    scheme: SecretScheme::Env,
                    reason: "is not a valid environment variable name",
                },
            ),
            (
                "file://relative/path",
                SecretRefError::InvalidPath {
                    scheme: SecretScheme::File,
                    reason: "must be an absolute path, e.g. file:///run/secrets/db",
                },
            ),
            (
                "file:///etc/../etc/shadow",
                SecretRefError::InvalidPath {
                    scheme: SecretScheme::File,
                    reason: "must not contain `..` segments",
                },
            ),
            (
                "vault://workspace/smtp#",
                SecretRefError::InvalidField { scheme: SecretScheme::Vault, reason: "is empty" },
            ),
        ];
        for (input, expected) in cases {
            let err = SecretRef::parse(input).expect_err(input);
            assert_eq!(&err, expected, "input: {input}");
        }
    }

    #[test]
    fn errors_never_echo_the_value() {
        // The whole point: a pasted credential must not reach a log line.
        let secret = "aG92ZXJjcmFmdC1mdWxsLW9mLWVlbHM";
        let err = SecretRef::parse(secret).unwrap_err();
        assert!(!err.to_string().contains(secret));
    }

    #[test]
    fn scheme_parsing_is_case_insensitive_but_display_is_canonical() {
        let r: SecretRef = "VAULT://workspace/smtp#password".parse().unwrap();
        assert_eq!(r.to_string(), "vault://workspace/smtp#password");
    }

    #[test]
    fn serde_round_trip() {
        let r: SecretRef = "env://DATABASE_URL".parse().unwrap();
        let yaml = serde_yaml::to_string(&r).unwrap();
        assert_eq!(yaml.trim(), "env://DATABASE_URL");
        let back: SecretRef = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(r, back);

        let err = serde_yaml::from_str::<SecretRef>("\"not a ref\"").unwrap_err();
        assert!(err.to_string().contains("scheme"), "got: {err}");
    }

    #[test]
    fn constructor_applies_the_same_rules_as_the_parser() {
        assert!(SecretRef::new(SecretScheme::Env, "DATABASE_URL", None::<String>).is_ok());
        assert!(SecretRef::new(SecretScheme::Env, "bad name", None::<String>).is_err());
        assert!(SecretRef::new(SecretScheme::Vault, "workspace/smtp", None::<String>).is_err());
    }
}
