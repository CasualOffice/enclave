//! Errors raised while loading configuration.
//!
//! Everything here happens before the process is serving traffic, so these are operator-facing:
//! they name the file, the field and the rule, and they never contain a configuration *value*,
//! because the values most likely to be malformed are the secret ones.

use std::path::PathBuf;

use crate::validate::ValidationReport;

/// Result alias for configuration loading.
pub type Result<T, E = ConfigError> = core::result::Result<T, E>;

/// Why configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read. Distinguished from a parse failure because the
    /// remedy is completely different — a mount or a permission, not an edit.
    #[error("configuration file {} could not be read", path.display())]
    Io {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The file is not valid YAML, or does not match the model. The message comes from `serde` and
    /// includes a line and column where one is available.
    #[error("configuration file {} is not valid: {source}", path.display())]
    Syntax {
        /// The file that failed to parse.
        path: PathBuf,
        /// The parse failure.
        #[source]
        source: serde_yaml::Error,
    },

    /// The merged configuration does not match the model — a wrong type, an unknown enum value, or
    /// a malformed secret reference.
    #[error("configuration is not valid: {source}")]
    Model {
        /// The deserialization failure.
        #[source]
        source: serde_yaml::Error,
    },

    /// The configuration parsed but failed a startup rule. Carries *every* problem found.
    #[error(transparent)]
    Invalid(#[from] ValidationReport),
}

impl ConfigError {
    /// The validation report, when there is one. Lets a caller print the full list rather than the
    /// one-line `Display`.
    #[must_use]
    pub const fn report(&self) -> Option<&ValidationReport> {
        match self {
            Self::Invalid(report) => Some(report),
            _ => None,
        }
    }
}
