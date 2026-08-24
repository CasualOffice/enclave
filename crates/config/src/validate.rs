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

use crate::model::{
    AntivirusProvider, Config, DeploymentProfile, EmbeddingMounts, OcrMounts, SearchProvider,
    StorageProvider,
};
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
    report.extend(check_mounts(config));
    report.extend(check_embedding(config));
    report.extend(check_storage(config));
    report.extend(check_search(config));
    report.extend(check_relocated_keys(raw));
    report.into_result()
}

/// A provider and its settings block are written together or not at all.
///
/// The same argument as [`check_mounts`], one section along, and the same failure mode: a
/// configuration file that says storage is configured and a deployment that indexes nothing.
///
/// **`provider: s3` with no `s3:` block** would leave `enclave-worker` with a provider it cannot
/// construct. Refusing is better than falling back to "no storage", because the operator who wrote
/// `provider: s3` has said what they want and a silent downgrade answers them with an empty search
/// index months later.
///
/// **An `s3:` block with `provider: none`** — the likelier accident, since `none` is the default and
/// therefore what an operator gets by forgetting a line — is refused for the same reason in the
/// other direction. A fully specified bucket that nothing reads is indistinguishable, from outside,
/// from a bucket nobody configured.
///
/// Neither section configured is **not** a problem. That is every deployment today, it is a
/// documented absence rather than a degradation, and `crates/worker/src/main.rs` logs which passes
/// it is therefore not scheduling.
#[must_use]
pub fn check_storage(config: &Config) -> Vec<Problem> {
    match (config.storage.provider, config.storage.s3.is_some()) {
        (StorageProvider::S3, false) => vec![Problem::new(
            "storage.s3",
            ProblemKind::InvalidValue,
            "`storage.provider` is `s3` but there is no `storage.s3` block to build a client from. \
             Give it `bucket`, `region` and the two credential references, or set `provider: none` \
             — with `none` the indexing pass is not scheduled and says so at start-up, which is a \
             legible absence rather than a pass that burns its retry budget against a store that \
             cannot answer",
        )],
        (StorageProvider::None, true) => vec![Problem::new(
            "storage.provider",
            ProblemKind::InvalidValue,
            "a `storage.s3` block is configured but `storage.provider` is `none`, which is the \
             default and so is also what a missing line looks like. Nothing would read the bucket \
             and nothing downstream is in a position to report it: set `provider: s3`, or remove \
             the block",
        )],
        _ => Vec::new(),
    }
}

/// The vector store's half of [`check_storage`], with the same reasoning.
#[must_use]
pub fn check_search(config: &Config) -> Vec<Problem> {
    match (config.search.provider, config.search.milvus.is_some()) {
        (SearchProvider::Milvus, false) => vec![Problem::new(
            "search.milvus",
            ProblemKind::InvalidValue,
            "`search.provider` is `milvus` but there is no `search.milvus` block to build a client \
             from. Give it a `uri`, or set `provider: none`",
        )],
        (SearchProvider::None, true) => vec![Problem::new(
            "search.provider",
            ProblemKind::InvalidValue,
            "a `search.milvus` block is configured but `search.provider` is `none`, so the \
             coverage probe is not scheduled and `enclave_search_index_observed_chunks` has no \
             series at all. Set `provider: milvus`, or remove the block",
        )],
        _ => Vec::new(),
    }
}

/// Keys that used to exist and now live somewhere else, refused rather than ignored.
///
/// `server.metrics_port` and `server.metrics_bind` moved to `metrics.api_port`,
/// `metrics.worker_port` and `metrics.bind` (`ENC-566`). Nothing in `Config` rejects an unknown key
/// under `server:`, by design — an operator's complete file must load — so an unmigrated file would
/// otherwise load cleanly with the exposition **silently off**, which is the reading that is
/// indistinguishable from a healthy system with nothing to report.
///
/// Checked against the raw tree because the fields are gone from the model, which is the point: a
/// deprecated field left on the struct is a field something eventually reads.
#[must_use]
pub fn check_relocated_keys(raw: &Value) -> Vec<Problem> {
    const MOVED: &[(&str, &str, &str)] = &[
        (
            "metrics_port",
            "server.metrics_port",
            "`metrics.api_port` and `metrics.worker_port`. Both binaries read the single old key, \
             so one `enclave.yaml` on one host asked the API and the worker to bind the same \
             socket and whichever started second died with `Address already in use` (ENC-566)",
        ),
        (
            "metrics_bind",
            "server.metrics_bind",
            "`metrics.bind`, which both listeners share — the interface an unauthenticated, \
             tenant-labelled exposition faces is one decision, not two that can drift apart",
        ),
    ];

    let Some(server) = raw.get("server") else { return Vec::new() };
    MOVED
        .iter()
        .filter(|(key, _, _)| !matches!(server.get(key), None | Some(Value::Null)))
        .map(|(_, path, moved_to)| {
            Problem::new(
                *path,
                ProblemKind::InvalidValue,
                format!(
                    "has moved to {moved_to}. It is refused rather than ignored because an \
                     ignored key here means the exposition is silently off, and metrics nobody \
                     serves read as zero forever"
                ),
            )
        })
        .collect()
}

/// The two OCR volumes are configured together or not at all (`ENC-546`).
///
/// # Why half a mount is a startup failure rather than a warning
///
/// OCR over a scanned PDF needs both: weights to recognise text and PDFium to turn a page into
/// pixels for them to read. A deployment that staged one of the two has a configuration file
/// saying OCR is on and a corpus of scanned PDFs indexing as empty — which is
/// `plans/M3-DISCOVERY.md` D24's failure mode reached through configuration rather than through
/// code. Nothing downstream can report it, either: `NoPageImages` returns `PageImage::Absent` for
/// every page, correctly, because a deployment with no rasteriser has made no finding about
/// anybody's document.
///
/// A log line at startup is what this check replaces, and it is not enough. The whole of the
/// problem is that the symptom appears months later on a surface nobody connects to a mount, so the
/// message has to arrive while somebody is still looking at the configuration.
///
/// **Neither mount configured is not a problem**, and deliberately so. That is what every
/// deployment has today and it is a documented absence, not a degradation: a textless document is
/// recorded `FAILED` / `no_text_extracted`.
///
/// The paths are not checked for existence here. A validator that stats a directory would pass in
/// CI and fail in a container whose volume attaches a second after the process starts, and it
/// cannot distinguish "not mounted" from "mounted and holding the wrong files" — which is the
/// mount's job, and where the message can name what failed to load.
#[must_use]
pub fn check_mounts(config: &Config) -> Vec<Problem> {
    let OcrMounts::Incomplete { present, missing } = config.ocr_mounts() else {
        return Vec::new();
    };

    vec![Problem::new(
        missing,
        ProblemKind::InvalidValue,
        format!(
            "`{present}` is set but `{missing}` is not, and OCR over a scanned PDF needs both: \
             weights to recognise text and PDFium to render a page for them to read. Set both, or \
             neither — with neither, a scanned document is recorded FAILED / no_text_extracted \
             rather than indexed as empty (plans/M3-DISCOVERY.md D24)"
        ),
    )]
}

/// A mounted embedding model needs somewhere to put its vectors (`ENC-661`).
///
/// [`Config::embedding_mounts`] carries the argument for why this pair is checked in one direction
/// only; the short version is that `search.milvus` has purposes that are nothing to do with
/// embedding, while `embedding_model` has exactly one.
///
/// What this catches is an operator who staged 2.2 GB of weights against `search.provider: none`.
/// Nothing would fail: the worker would load the model, find no `VectorWriter` to build a
/// `VectorStage` over, and index text exactly as it did before — a deployment paying for a model
/// it never uses, discovering it when somebody notices dense search has always returned nothing.
///
/// **No mount configured is not a problem**, and deliberately so. That is what every deployment has
/// today, and it is a documented absence rather than a degradation: lexical search still works and
/// `index_manifests.embedding_model` records `""`.
///
/// The path is not checked for existence here, for [`check_mounts`]' reason: a validator that stats
/// a directory passes in CI and fails in a container whose volume attaches a second after the
/// process starts, and it cannot tell "not mounted" from "mounted and holding the wrong files".
#[must_use]
pub fn check_embedding(config: &Config) -> Vec<Problem> {
    let EmbeddingMounts::Incomplete { present, missing } = config.embedding_mounts() else {
        return Vec::new();
    };

    vec![Problem::new(
        missing,
        ProblemKind::InvalidValue,
        format!(
            "`{present}` names a mounted embedding model but `{missing}` is not configured, so \
             there is nowhere for its vectors to go and nothing would be embedded. Configure the \
             vector store, or remove `{present}` — without it a document is still indexed for \
             lexical search and its manifest honestly records no embedding model"
        ),
    )]
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
    use crate::model::{
        AntivirusConfig, AuditConfig, MilvusSettings, S3StorageConfig, SearchConfig, StorageConfig,
    };

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
    fn half_an_ocr_mount_refuses_startup_and_names_the_missing_key() {
        // `ENC-546`. Both directions, because the tempting implementation checks only one.
        for (present, missing, config) in [
            (
                "ocr_models",
                "pdfium",
                Config {
                    ocr_models: Some(std::path::PathBuf::from("/mnt/ocr")),
                    ..Config::default()
                },
            ),
            (
                "pdfium",
                "ocr_models",
                Config {
                    pdfium: Some(std::path::PathBuf::from("/mnt/pdfium")),
                    ..Config::default()
                },
            ),
        ] {
            let problems = check_mounts(&config);
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert_eq!(problems[0].path, missing, "the report must name the key to add");
            assert_eq!(problems[0].kind, ProblemKind::InvalidValue);
            assert!(problems[0].detail.contains(present), "{}", problems[0].detail);
        }
    }

    #[test]
    fn both_mounts_and_neither_mount_are_both_accepted() {
        // The positive control, and it is load-bearing twice over. Without the `Mounted` case, a
        // `check_mounts` that refused every configured mount would pass the test above; without the
        // `Absent` case, one that refused every deployment would.
        let neither = Config::default();
        assert!(check_mounts(&neither).is_empty(), "a deployment with no OCR was refused");

        let both = Config {
            ocr_models: Some(std::path::PathBuf::from("/mnt/ocr")),
            pdfium: Some(std::path::PathBuf::from("/mnt/pdfium")),
            ..Config::default()
        };
        assert!(check_mounts(&both).is_empty(), "a fully configured deployment was refused");
    }

    #[test]
    fn the_mount_check_runs_as_part_of_startup_validation() {
        // `check_mounts` being correct buys nothing if `validate` does not call it. Asserted through
        // the loader, which is the path a process actually takes.
        let err = crate::ConfigLoader::new()
            .without_env()
            .with_yaml("t.yaml", "ocr_models: /mnt/enclave/ocr-models\n")
            .load()
            .unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.len(), 1, "{report}");
        assert_eq!(report.problems()[0].path, "pdfium");
        assert!(report.has_kind(ProblemKind::InvalidValue));
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
    /// A provider and its settings block are written together, in both directions.
    ///
    /// Both, because the tempting implementation checks only one — and the direction it would omit
    /// is the likelier accident: `none` is the default, so `provider` is what a forgotten line looks
    /// like, and a fully specified bucket that nothing reads is invisible from outside.
    ///
    /// Deliberate violation: deleting either arm of `check_storage`'s match makes one iteration of
    /// this loop fail by name.
    #[test]
    fn a_provider_and_its_block_are_written_together_or_not_at_all() {
        let s3 = || S3StorageConfig {
            bucket: "b".to_owned(),
            region: "r".to_owned(),
            endpoint: None,
            path_style: true,
            access_key_id: "env://A".parse().unwrap(),
            secret_access_key: "env://B".parse().unwrap(),
            session_token: None,
            signed_url_ttl: crate::HumanDuration::from_secs(300),
            max_signed_url_ttl: crate::HumanDuration::from_secs(3600),
            flavor: crate::model::S3Flavor::Minio,
        };
        let milvus = || MilvusSettings {
            uri: "http://milvus:19530".parse().unwrap(),
            token: None,
            collection: None,
        };

        // `provider` without the block.
        let named = Config {
            storage: StorageConfig { provider: StorageProvider::S3, s3: None },
            search: SearchConfig { provider: SearchProvider::Milvus, milvus: None },
            ..Config::default()
        };
        assert_eq!(check_storage(&named)[0].path, "storage.s3");
        assert_eq!(check_storage(&named)[0].kind, ProblemKind::InvalidValue);
        assert_eq!(check_search(&named)[0].path, "search.milvus");

        // The block without `provider` — the likelier accident, since `none` is the default.
        let orphaned = Config {
            storage: StorageConfig { provider: StorageProvider::None, s3: Some(s3()) },
            search: SearchConfig { provider: SearchProvider::None, milvus: Some(milvus()) },
            ..Config::default()
        };
        assert_eq!(check_storage(&orphaned)[0].path, "storage.provider");
        assert_eq!(check_search(&orphaned)[0].path, "search.provider");

        // Both halves, and neither half, are the two configurations that must pass.
        let configured = Config {
            storage: StorageConfig { provider: StorageProvider::S3, s3: Some(s3()) },
            search: SearchConfig { provider: SearchProvider::Milvus, milvus: Some(milvus()) },
            ..Config::default()
        };
        assert!(check_storage(&configured).is_empty());
        assert!(check_search(&configured).is_empty());
        assert!(check_storage(&Config::default()).is_empty(), "no storage is a documented absence");
        assert!(check_search(&Config::default()).is_empty(), "and so is no vector store");
    }

    /// A mounted embedding model with no vector store refuses the startup — and only that way round.
    ///
    /// `ENC-661`. The failure it catches is silent in every direction an operator can look: the
    /// worker loads 2.2 GB of weights, finds no `VectorWriter`, builds no stage, and indexes text
    /// exactly as it did before. Nothing errors and dense search returns nothing, for months.
    #[test]
    fn a_model_with_nowhere_to_write_refuses_and_a_store_without_a_model_does_not() {
        let milvus = || MilvusSettings {
            uri: "http://milvus:19530".parse().unwrap(),
            token: None,
            collection: None,
        };

        let stranded = Config {
            embedding_model: Some(std::path::PathBuf::from("/mnt/bge-m3")),
            ..Config::default()
        };
        assert_eq!(check_embedding(&stranded)[0].path, "search.milvus");
        assert_eq!(check_embedding(&stranded)[0].kind, ProblemKind::InvalidValue);

        // The positive control, and it is load-bearing rather than decoration: a `check_embedding`
        // that refused every configuration would satisfy the assertion above, and would refuse
        // every deployment that exists today — none of which mounts a model.
        let wired = Config {
            embedding_model: Some(std::path::PathBuf::from("/mnt/bge-m3")),
            search: SearchConfig { provider: SearchProvider::Milvus, milvus: Some(milvus()) },
            ..Config::default()
        };
        assert!(check_embedding(&wired).is_empty(), "a fully wired deployment was refused");

        let store_only = Config {
            search: SearchConfig { provider: SearchProvider::Milvus, milvus: Some(milvus()) },
            ..Config::default()
        };
        assert!(
            check_embedding(&store_only).is_empty(),
            "a vector store without a model is the ordinary deployment, not a misconfiguration"
        );
        assert!(
            check_embedding(&Config::default()).is_empty(),
            "no embedding model is a documented absence"
        );
    }

    /// The refusal names configuration keys and never the operator's filesystem layout.
    ///
    /// `CLAUDE.md` rule 10, and the reason both fields on the `Incomplete` arm are `&'static str`:
    /// there is no way to reach this message with a path somebody wrote.
    #[test]
    fn the_embedding_refusal_can_carry_only_key_names() {
        let stranded = Config {
            embedding_model: Some(std::path::PathBuf::from("/srv/secret-project/bge-m3")),
            ..Config::default()
        };
        let message = check_embedding(&stranded)[0].detail.clone();
        assert!(message.contains("embedding_model"), "{message}");
        assert!(message.contains("search.milvus"), "{message}");
        assert!(!message.contains("secret-project"), "{message}");
    }

    /// The relocated metrics keys are refused, not ignored, and both of them are.
    ///
    /// Nothing under `server:` rejects an unknown key, by design, so an unmigrated file would
    /// otherwise load cleanly with the exposition **silently off** — and a metric nobody serves
    /// reads as zero forever, which is indistinguishable from a healthy system with nothing to
    /// report. That is the assertion-about-an-absence this check exists to convert into a message.
    ///
    /// Deliberate violation: removing `check_relocated_keys` from `validate`, or emptying its
    /// `MOVED` table, fails this test by name.
    #[test]
    fn the_relocated_metrics_keys_are_refused_rather_than_ignored() {
        let old = "server:\n  port: 8080\n  metrics_port: 9464\n  metrics_bind: 127.0.0.1\n";
        let value: Value = serde_yaml::from_str(old).unwrap();

        let problems = check_relocated_keys(&value);
        let paths: Vec<&str> = problems.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["server.metrics_port", "server.metrics_bind"]);
        assert!(problems[0].detail.contains("metrics.api_port"), "{}", problems[0].detail);
        assert!(problems[0].detail.contains("metrics.worker_port"), "{}", problems[0].detail);
        assert!(problems[1].detail.contains("metrics.bind"), "{}", problems[1].detail);

        // Reached through the whole startup path, not just by calling the function directly.
        let err =
            crate::ConfigLoader::new().without_env().with_yaml("old.yaml", old).load().unwrap_err();
        let report = err.report().expect("a validation report");
        assert_eq!(report.len(), 2, "{report}");

        // The new spelling, and a file with no metrics at all, both pass.
        assert!(check_relocated_keys(&serde_yaml::from_str("server:\n  port: 8080\n").unwrap())
            .is_empty());
        assert!(check_relocated_keys(
            &serde_yaml::from_str("metrics:\n  api_port: 9464\n").unwrap()
        )
        .is_empty());
    }
}
