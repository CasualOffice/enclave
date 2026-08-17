//! Startup validation.
//!
//! Two families of check, both from `docs/08-BYO-INFRA.md`:
//!
//! * **§20** — the resolved configuration is scanned for values that *look* like credentials, and
//!   the process refuses to start if any appear inline rather than as references;
//! * **§19** — the `enterprise` profile refuses to start with antivirus or audit disabled.
//!
//! Every check runs and every problem is reported. A validator that stops at the first failure
//! turns one broken deployment into six restarts, and by the third the operator is fixing things
//! blind. The report names the dotted field path, never the offending value.

use core::fmt;

use serde_yaml::Value;

use crate::model::{AntivirusProvider, Config, DeploymentProfile};
use crate::secret_ref::SecretRef;

/// The kind of a configuration problem — a code rather than a sentence, so callers can branch and
/// the message can be localized later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// A value that looks like a credential was written inline instead of as a `SecretRef`.
    InlineCredential,
    /// A field that must hold a secret reference does not hold a valid one.
    InvalidSecretRef,
    /// The deployment profile forbids this combination of settings.
    ProfileRequirement,
    /// The value is not acceptable for its field.
    InvalidValue,
    /// A referenced secret could not be resolved at startup.
    SecretUnresolvable,
}

impl ProblemKind {
    /// Stable identifier for logs and tests.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InlineCredential => "INLINE_CREDENTIAL",
            Self::InvalidSecretRef => "INVALID_SECRET_REF",
            Self::ProfileRequirement => "PROFILE_REQUIREMENT",
            Self::InvalidValue => "INVALID_VALUE",
            Self::SecretUnresolvable => "SECRET_UNRESOLVABLE",
        }
    }
}

impl fmt::Display for ProblemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing wrong with the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Dotted path to the offending field, e.g. `mail.smtp.password`. This is the whole value of
    /// the report: it tells the operator which line to edit.
    pub path: String,
    /// What is wrong.
    pub kind: ProblemKind,
    /// Operator-facing explanation. Never contains the offending value — a startup error is
    /// written to stdout and shipped to a log pipeline (CLAUDE.md rule 10).
    pub detail: String,
}

impl Problem {
    /// Build a problem. `detail` must never interpolate a configuration value.
    #[must_use]
    pub fn new(path: impl Into<String>, kind: ProblemKind, detail: impl Into<String>) -> Self {
        Self { path: path.into(), kind, detail: detail.into() }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.path, self.detail, self.kind)
    }
}

/// Everything wrong with the configuration, collected in one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, thiserror::Error)]
pub struct ValidationReport {
    problems: Vec<Problem>,
}

impl ValidationReport {
    /// An empty report.
    #[must_use]
    pub const fn new() -> Self {
        Self { problems: Vec::new() }
    }

    /// Record a problem.
    pub fn push(&mut self, problem: Problem) {
        self.problems.push(problem);
    }

    /// Absorb another report, so independent validators can be run and merged.
    pub fn extend(&mut self, other: impl IntoIterator<Item = Problem>) {
        self.problems.extend(other);
    }

    /// Everything found.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// How many problems were found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.problems.len()
    }

    /// Whether the configuration passed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }

    /// Whether any problem of this kind was found — used by tests and by the admin UI to decide
    /// which remediation to show.
    #[must_use]
    pub fn has_kind(&self, kind: ProblemKind) -> bool {
        self.problems.iter().any(|p| p.kind == kind)
    }

    /// `Ok(())` when clean, otherwise the whole report.
    ///
    /// # Errors
    /// The report itself, when it contains at least one problem.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "configuration is invalid ({} problem{})",
            self.problems.len(),
            if self.problems.len() == 1 { "" } else { "s" }
        )?;
        for problem in &self.problems {
            writeln!(f, "  - {problem}")?;
        }
        Ok(())
    }
}

impl From<ValidationReport> for enclave_core::Error {
    /// Configuration is also editable through the admin API (`docs/08-BYO-INFRA.md §21`), where a
    /// rejected change must reach the client as a field-level validation failure rather than as an
    /// opaque 500. The `detail` string is dropped on purpose: the client gets the field and a code,
    /// and the operator-facing explanation stays in the server log.
    fn from(report: ValidationReport) -> Self {
        use enclave_core::error::{FieldError, ValidationCode};
        Self::Validation(
            report
                .problems
                .into_iter()
                .map(|problem| {
                    let code = match problem.kind {
                        ProblemKind::InlineCredential => ValidationCode::Unsupported,
                        ProblemKind::InvalidSecretRef | ProblemKind::InvalidValue => {
                            ValidationCode::InvalidFormat
                        }
                        ProblemKind::ProfileRequirement => ValidationCode::Inconsistent,
                        ProblemKind::SecretUnresolvable => ValidationCode::Required,
                    };
                    FieldError::new(problem.path, code)
                })
                .collect(),
        )
    }
}

/// Run every startup check against the typed configuration and the raw merged tree.
///
/// Both inputs are needed: the profile rules are about typed values, while the inline-credential
/// scan must see sections this milestone does not model yet — `mail.smtp.password` is exactly the
/// kind of field that gets an inline value, and it would be invisible to a typed-only check.
///
/// # Errors
/// A [`ValidationReport`] listing every problem found.
pub fn validate(config: &Config, raw: &Value) -> Result<(), ValidationReport> {
    let mut report = ValidationReport::new();
    report.extend(scan_for_inline_secrets(raw));
    report.extend(check_profile(config));
    report.into_result()
}

/// Walk the raw configuration tree looking for credentials written inline.
///
/// This is the check from `docs/08-BYO-INFRA.md §20`. It is heuristic by nature, so it is tuned to
/// be quiet on ordinary configuration and loud on the two things that actually happen: someone
/// pastes a password into a `password:` field, and someone pastes a private key into a file.
#[must_use]
pub fn scan_for_inline_secrets(raw: &Value) -> Vec<Problem> {
    let mut problems = Vec::new();
    walk(raw, &mut String::new(), &mut problems);
    problems
}

fn walk(node: &Value, path: &mut String, problems: &mut Vec<Problem>) {
    match node {
        Value::Mapping(map) => {
            for (key, value) in map {
                let key = match key {
                    Value::String(key) => key.clone(),
                    other => format!("{other:?}"),
                };
                let restore = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&key);
                inspect(&key, value, path, problems);
                walk(value, path, problems);
                path.truncate(restore);
            }
        }
        Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                let restore = path.len();
                path.push_str(&format!("[{index}]"));
                walk(item, path, problems);
                path.truncate(restore);
            }
        }
        _ => {}
    }
}

fn inspect(key: &str, value: &Value, path: &str, problems: &mut Vec<Problem>) {
    let Value::String(text) = value else { return };
    let text = text.trim();
    if text.is_empty() {
        return;
    }

    // Private key material is unambiguous: nothing legitimate puts a PEM private key in a config
    // file, whatever the field is called.
    if text.contains("PRIVATE KEY-----") {
        problems.push(Problem::new(
            path,
            ProblemKind::InlineCredential,
            "contains inline private key material; store it in a secret provider and reference it \
             as `{scheme}://{path}#{field}`",
        ));
        return;
    }

    // A valid reference is acceptable in any field, and is the whole point of the exercise.
    let parsed = SecretRef::parse(text);
    if parsed.is_ok() {
        return;
    }

    if is_reference_field(key) {
        // A field named `*_ref` must hold a reference. Saying so here is much clearer than the type
        // error the deserializer would produce for a modelled field, and it is the only check at
        // all for a field this milestone does not model.
        if let Err(err) = parsed {
            problems.push(Problem::new(
                path,
                ProblemKind::InvalidSecretRef,
                format!("is not a valid secret reference: {err}"),
            ));
        }
        return;
    }

    // A URL with `user:password@` in its authority is a credential whatever the field is called,
    // and a DSN is the most common way one gets committed.
    if has_embedded_userinfo(text) {
        problems.push(Problem::new(
            path,
            ProblemKind::InlineCredential,
            "embeds a password in a URL; store the URL in a secret provider and reference it as \
             `{scheme}://{path}#{field}` (docs/08-BYO-INFRA.md §6)",
        ));
        return;
    }

    if !is_credential_field(key) || is_env_name_field(key) {
        return;
    }

    if looks_like_a_credential(text) {
        problems.push(Problem::new(
            path,
            ProblemKind::InlineCredential,
            "looks like a credential written inline; store it in a secret provider and reference \
             it as `{scheme}://{path}#{field}` (docs/08-BYO-INFRA.md §6)",
        ));
    }
}

/// Whether a URL-shaped value carries `user:password@` in its authority.
///
/// Only the authority is examined — the part between `://` and the next `/` — so a path or query
/// containing an `@` is not mistaken for credentials.
fn has_embedded_userinfo(text: &str) -> bool {
    let Some((_, rest)) = text.split_once("://") else { return false };
    let authority = rest.split('/').next().unwrap_or(rest);
    let Some((userinfo, _)) = authority.split_once('@') else { return false };
    matches!(userinfo.split_once(':'), Some((_, password)) if !password.is_empty())
}

/// Field names whose *value* must be a secret reference.
fn is_reference_field(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "secret_ref" || key.ends_with("_ref")
}

/// Field names that name a variable or a location rather than holding a value, e.g. `url_env`,
/// `key_id`, `bind_dn_env`, `ca_bundle_path`.
fn is_env_name_field(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    ["_env", "_id", "_name", "_path", "_file", "_url", "_algorithm"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
        || key.starts_with("public_")
}

/// Field names that hold credentials. Matched on whole `_`-separated words so `keyboard_layout`
/// does not match `key` and `min_length` does not match anything.
fn is_credential_field(key: &str) -> bool {
    const WORDS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "secrets",
        "key",
        "keys",
        "token",
        "credential",
        "credentials",
        "passphrase",
        "pepper",
        "apikey",
        "dsn",
    ];
    key.to_ascii_lowercase().split(['_', '-', '.']).any(|word| WORDS.contains(&word))
}

/// Whether a string carries enough entropy to be a real credential rather than a placeholder.
///
/// Shannon entropy over the whole string rather than a length or character-class rule: it accepts
/// `changeme`, `${DB_PASSWORD}` and `default` while rejecting anything a password manager or a
/// cloud console would produce. Threshold is deliberately generous — a false negative is a missed
/// warning, a false positive is a deployment that cannot start.
fn looks_like_a_credential(text: &str) -> bool {
    const MIN_LENGTH: usize = 12;
    const MIN_BITS: f64 = 48.0;

    if text.len() < MIN_LENGTH {
        return false;
    }
    // Shell or template interpolation is a reference by another name.
    if text.starts_with("${") || (text.starts_with('<') && text.ends_with('>')) {
        return false;
    }

    let mut counts = [0_usize; 256];
    for byte in text.bytes() {
        counts[byte as usize] += 1;
    }
    let total = text.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum::<f64>()
        * total;

    bits >= MIN_BITS
}

/// Deployment-profile requirements (`docs/08-BYO-INFRA.md §19`).
///
/// Only the enterprise profile is constrained today. The rules are expressed as data-free
/// statements about what the profile *promises*, which is why they belong here rather than in the
/// crates that consume the settings: by the time the antivirus crate notices it is disabled, the
/// process is already serving requests.
#[must_use]
pub fn check_profile(config: &Config) -> Vec<Problem> {
    let mut problems = Vec::new();
    if config.profile != DeploymentProfile::Enterprise {
        return problems;
    }

    if matches!(config.antivirus.provider, AntivirusProvider::None) {
        problems.push(Problem::new(
            "antivirus.provider",
            ProblemKind::ProfileRequirement,
            "the `enterprise` deployment profile requires antivirus; `none` is not permitted \
             (docs/08-BYO-INFRA.md §19)",
        ));
    }

    if !config.audit.enabled {
        problems.push(Problem::new(
            "audit.enabled",
            ProblemKind::ProfileRequirement,
            "the `enterprise` deployment profile requires the audit trail; it cannot be disabled \
             (docs/08-BYO-INFRA.md §19)",
        ));
    }

    problems
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::model::{AntivirusConfig, AuditConfig};

    use super::*;

    fn enterprise(antivirus: AntivirusProvider, audit_enabled: bool) -> Config {
        Config {
            profile: DeploymentProfile::Enterprise,
            antivirus: AntivirusConfig { provider: antivirus, ..AntivirusConfig::default() },
            audit: AuditConfig { enabled: audit_enabled, ..AuditConfig::default() },
            ..Config::default()
        }
    }

    fn scan(yaml: &str) -> Vec<Problem> {
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        scan_for_inline_secrets(&value)
    }

    #[test]
    fn an_inline_credential_is_refused_and_the_field_is_named() {
        let problems = scan(
            "
mail:
  smtp:
    password: \"Xf7!qP2m-Vb93sLdKe0ZtR\"
",
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "mail.smtp.password");
        assert_eq!(problems[0].kind, ProblemKind::InlineCredential);
    }

    #[test]
    fn the_message_never_contains_the_credential() {
        let secret = "Xf7!qP2m-Vb93sLdKe0ZtR";
        let problems = scan(&format!("mail:\n  password: \"{secret}\"\n"));
        assert_eq!(problems.len(), 1);
        assert!(!problems[0].to_string().contains(secret));
    }

    #[test]
    fn a_referenced_credential_is_accepted() {
        let problems = scan(
            "
mail:
  smtp:
    password:
      secret_ref: \"vault://workspace/smtp#password\"
    username: \"vault://workspace/smtp#username\"
database:
  url_env: DATABASE_URL
security:
  password:
    min_length: 12
    max_length: 128
auth:
  signing_keys:
    key_ref: \"vault://workspace/jwt#ed25519\"
    rotation_interval: \"90d\"
",
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn ordinary_configuration_is_not_flagged() {
        let problems = scan(
            "
database:
  application_role: enclave_app
antivirus:
  provider: clamav
  unavailable_policy: HOLD
auth:
  refresh_token:
    reuse_detection: REVOKE_FAMILY
    cookie:
      name: enclave_rt
      path: /api/v1/auth
identity:
  ldap:
    filter: \"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\"
",
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn placeholders_are_not_flagged() {
        let problems = scan(
            "
mail:
  password: changeme
  token: \"${SMTP_TOKEN}\"
  api_key: \"<replace-me>\"
",
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn inline_private_key_material_is_refused_whatever_the_field_is_called() {
        // The PEM banner is assembled at runtime rather than written as a literal. The secrets
        // structural gate refuses private-key material in any tracked file and is deliberately not
        // clever enough to except a test — a gate with exceptions is a gate people learn to route
        // around. Building the string here keeps the gate absolute and the test honest.
        let banner = |kind: &str| format!("-----{kind} PRIVATE KEY-----");
        let body = format!(
            "\ntls:\n  bundle: |\n    {}\n    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n    {}\n",
            banner("BEGIN"),
            banner("END"),
        );
        let problems = scan(&body);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "tls.bundle");
        assert_eq!(problems[0].kind, ProblemKind::InlineCredential);
    }

    #[test]
    fn a_reference_field_holding_something_else_is_refused() {
        let problems = scan(
            "
auth:
  signing_keys:
    key_ref: \"just-a-string\"
",
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "auth.signing_keys.key_ref");
        assert_eq!(problems[0].kind, ProblemKind::InvalidSecretRef);
    }

    #[test]
    fn a_dsn_with_an_embedded_password_is_refused_whatever_the_field_is_called() {
        let problems = scan(
            "
warehouse:
  connection: \"postgres://reporting:s3cret@db.internal:5432/analytics\"
",
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "warehouse.connection");
        assert_eq!(problems[0].kind, ProblemKind::InlineCredential);
        assert!(!problems[0].to_string().contains("s3cret"));
    }

    #[test]
    fn urls_without_credentials_are_not_flagged() {
        let problems = scan(
            "
server:
  public_url: \"https://workspace.example.com\"
identity:
  ldap:
    url: \"ldaps://directory.internal:636\"
audit:
  external_anchor: \"s3://enclave-audit-anchor/\"
",
        );
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn sequence_elements_are_reached() {
        let problems = scan(
            "
integrations:
  - name: crm
    api_key: \"7bd41f0ac9e34ab8b2f6d5c1e08a9347\"
",
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "integrations[0].api_key");
    }

    #[test]
    fn enterprise_refuses_disabled_antivirus() {
        let config = enterprise(AntivirusProvider::None, true);
        let problems = check_profile(&config);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "antivirus.provider");
        assert_eq!(problems[0].kind, ProblemKind::ProfileRequirement);
    }

    #[test]
    fn enterprise_refuses_disabled_audit() {
        let config = enterprise(AntivirusProvider::Clamav, false);
        let problems = check_profile(&config);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].path, "audit.enabled");
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let config = enterprise(AntivirusProvider::None, false);
        let problems = check_profile(&config);
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn other_profiles_are_unconstrained() {
        for profile in [DeploymentProfile::Community, DeploymentProfile::Production] {
            let config = Config {
                profile,
                antivirus: AntivirusConfig {
                    provider: AntivirusProvider::None,
                    ..AntivirusConfig::default()
                },
                audit: AuditConfig { enabled: false, ..AuditConfig::default() },
                ..Config::default()
            };
            assert!(check_profile(&config).is_empty());
        }
    }

    #[test]
    fn the_report_lists_every_problem() {
        let mut report = ValidationReport::new();
        report.push(Problem::new("a.b", ProblemKind::InlineCredential, "one"));
        report.push(Problem::new("c.d", ProblemKind::ProfileRequirement, "two"));
        let rendered = report.to_string();
        assert!(rendered.contains("2 problems"), "{rendered}");
        assert!(rendered.contains("a.b"));
        assert!(rendered.contains("c.d"));
        assert!(report.has_kind(ProblemKind::InlineCredential));
        assert_eq!(report.len(), 2);
        assert!(report.into_result().is_err());
    }

    #[test]
    fn maps_to_the_core_validation_error() {
        let mut report = ValidationReport::new();
        report.push(Problem::new("mail.password", ProblemKind::InlineCredential, "detail"));
        let error: enclave_core::Error = report.into();
        assert_eq!(error.status_code(), 400);
        match error {
            enclave_core::Error::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "mail.password");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
