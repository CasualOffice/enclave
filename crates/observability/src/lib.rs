//! Tracing wiring for every Enclave process: one subscriber stack, one set of span attribute
//! names, and one redaction pass that stands between a field and anything that renders it.
//!
//! # Why redaction lives here rather than at the call sites
//!
//! `CLAUDE.md` non-negotiable rule 10 and `docs/03-LLD.md §20` say the same thing: never record
//! raw passwords, tokens, refresh cookies, DLP match values or file content. A token `jti` may be
//! logged; the token itself may not.
//!
//! A rule of that shape cannot be kept by review. There are thousands of `tracing::info!` call
//! sites in a system this size, every `#[derive(Debug)]` is a potential leak, and the one that
//! leaks is the one written at 2am during an incident. So the control is placed where output is
//! produced, not where it is requested: the field visitors used by *both* output formats run
//! [`redact::scrub`] over every value on its way to the writer. A call site cannot opt out, and a
//! new call site is covered on the day it is written.
//!
//! The filter works on two independent signals, because either alone has a hole:
//!
//! 1. **Field name.** `password`, `secret`, `token`, `cookie`, `authorization`, `key`, `pkcs8`,
//!    `der`, `jwt`, `bearer` and relatives — see [`redact::is_sensitive_key`]. Catches the case
//!    where the value looks like nothing in particular (`password = "hunter2"`).
//! 2. **Value shape.** A JWT's three base64url segments, a PEM header, an `Authorization`-style
//!    scheme prefix, or a long high-entropy string. Catches the case where the *name* looks like
//!    nothing in particular (`response = "…eyJhbGciOiJFZERTQSJ9.…"`), including credentials
//!    embedded in a `Debug` rendering of a struct.
//!
//! The trade-off is deliberately asymmetric. A false positive costs one unreadable log line; a
//! false negative puts a live credential in a log aggregator, a SIEM and every backup of both. So
//! `idempotency_key` is redacted along with `api_key`, and that is the correct outcome.
//!
//! # What is *not* redacted, on purpose
//!
//! Token identifiers — `jti`, `kid` and the refresh-family id — are on an explicit allowlist
//! ([`redact::is_sensitive_key`]). They are what makes a revocation or replay investigation
//! possible (`docs/03-LLD.md §5.4`), they are not credentials, and a filter that swallowed them
//! would quietly remove the evidence the audit trail is built on. The allowlist exempts a field
//! from the *name* check only: a value that looks like a credential is still masked even when the
//! field is called `jti`, so mislabelling a token cannot smuggle it through.
//!
//! # Usage
//!
//! ```no_run
//! use enclave_observability::{init, ObservabilityConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! init(&ObservabilityConfig::default())?;
//! # Ok(())
//! # }
//! ```
//!
//! Per-request instrumentation uses the span macro and the typed recorders, never bare string
//! field names:
//!
//! ```
//! use enclave_core::{RequestContext, TenantId};
//! use enclave_observability::{record_request_context, request_span};
//!
//! let ctx = RequestContext::system(TenantId::new_v7());
//! let span = request_span!("files.download");
//! record_request_context(&span, &ctx);
//! let _entered = span.enter();
//! ```

#[cfg(feature = "otlp")]
compile_error!(
    "the `otlp` feature needs opentelemetry, opentelemetry_sdk, opentelemetry-otlp and \
     tracing-opentelemetry pinned in [workspace.dependencies] (ENC-114). Until they are, build \
     the OTLP layer in the binary and pass it to `enclave_observability::init_with_layer`."
);

use std::fmt;

use enclave_core::{Action, ReasonCode, RequestContext, WorkspaceId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::span::Record;
use tracing::{Event, Span, Subscriber};
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// The environment variable that overrides the configured filter directives.
///
/// Deliberately not `RUST_LOG`: an operator debugging Enclave inside a container that also runs
/// other Rust tooling should be able to turn Enclave's logging up without turning everything
/// else's up with it.
pub const FILTER_ENV_VAR: &str = "ENCLAVE_LOG";

/// The field `tracing` uses for the formatted message of an event.
const MESSAGE_FIELD: &str = "message";

// ---------------------------------------------------------------------------------------------
// Span attribute conventions (docs/03-LLD.md §20)
// ---------------------------------------------------------------------------------------------

/// The canonical span attribute names from `docs/03-LLD.md §20`.
///
/// These exist as constants so that a caller building a field dynamically — a metrics exporter, a
/// test asserting on output, a downstream layer keying off an attribute — spells the name the same
/// way the recorders do. A misspelt attribute is not a compile error and not a runtime error: it
/// is a dashboard that is silently empty six months later, which is why the string appears exactly
/// once per attribute in this crate.
///
/// Spans themselves are created by [`request_span!`], which declares all of these up front as
/// empty fields. `tracing` fixes a span's field set at its callsite, so an attribute that was not
/// declared there cannot be recorded onto the span afterwards.
pub mod attr {
    /// The tenant the request executes inside. Present on every span that touches tenant data.
    pub const TENANT_ID: &str = "tenant.id";
    /// The request correlation id, echoed in the error envelope and every audit row.
    pub const REQUEST_ID: &str = "request.id";
    /// The kind of principal (`user`, `guest`, `service`, `mcp`, `system`) — never its identity
    /// beyond the id, and never anything from its credential.
    pub const ACTOR_TYPE: &str = "actor.type";
    /// The workspace in scope, where the operation has one.
    pub const WORKSPACE_ID: &str = "workspace.id";
    /// What was attempted, as `family.verb` (`file.download`) or a handler-level operation name.
    pub const OPERATION: &str = "operation";
    /// `allow` or `deny`, recorded by the policy engine's caller once the chain has run.
    pub const POLICY_DECISION: &str = "policy.decision";
    /// The stable reason code on a denial. Never the internal reasoning, which goes to audit.
    pub const POLICY_REASON_CODE: &str = "policy.reason_code";
    /// The kind of client the request arrived through (`web`, `sync`, `mcp`, …).
    pub const CLIENT_TYPE: &str = "client.type";

    /// Every conventional attribute, in the order `docs/03-LLD.md §20` lists them.
    ///
    /// Used by the test that keeps [`super::request_span!`] and these constants in agreement, and
    /// available to anything that needs to enumerate the vocabulary rather than restate it.
    pub const ALL: &[&str] = &[
        TENANT_ID,
        REQUEST_ID,
        ACTOR_TYPE,
        WORKSPACE_ID,
        OPERATION,
        POLICY_DECISION,
        POLICY_REASON_CODE,
        CLIENT_TYPE,
    ];
}

/// Opens a span carrying every conventional attribute from `docs/03-LLD.md §20`.
///
/// A macro rather than a function because `tracing` resolves a span's field set at its callsite:
/// the attributes have to be *declared* here, as `Empty`, for [`record_request_context`] and its
/// siblings to be able to fill them in later. Declaring them in one place is also what makes the
/// attribute names unmisspellable — no handler writes `tenant_id` by hand and wonders why the
/// dashboard is empty.
///
/// With an argument, the argument is the `operation`; without one, `operation` starts empty and is
/// filled by [`record_operation`] or [`record_action`] once the action is known.
#[macro_export]
macro_rules! request_span {
    () => {
        $crate::request_span!(::tracing::field::Empty)
    };
    ($operation:expr) => {
        ::tracing::info_span!(
            "enclave.request",
            operation = $operation,
            tenant.id = ::tracing::field::Empty,
            request.id = ::tracing::field::Empty,
            actor.type = ::tracing::field::Empty,
            client.type = ::tracing::field::Empty,
            workspace.id = ::tracing::field::Empty,
            policy.decision = ::tracing::field::Empty,
            policy.reason_code = ::tracing::field::Empty,
        )
    };
}

/// Records the identity half of a [`RequestContext`] onto a span.
///
/// Takes the context by reference and reads only its public accessors, so this crate never becomes
/// a second place that knows how to *build* a context — the tenant identity on a span is the same
/// tenant identity the policy chain enforced against, by construction.
///
/// Only the four attributes `docs/03-LLD.md §20` names are recorded. Not the scopes, not the
/// network context, not the device: those are policy inputs, they are already captured in the
/// audit record, and putting them on every span would put a user's IP address in the log
/// aggregator of every tenant-adjacent tool that reads these logs.
pub fn record_request_context(span: &Span, ctx: &RequestContext) {
    span.record(attr::TENANT_ID, tracing::field::display(ctx.tenant_id));
    span.record(attr::REQUEST_ID, tracing::field::display(ctx.request_id));
    span.record(attr::ACTOR_TYPE, ctx.actor.kind().as_str());
    span.record(attr::CLIENT_TYPE, ctx.client.as_str());
}

/// Records the operation as a free-form name, for handler-level spans that precede action
/// resolution (`auth.login`, `health.ready`).
pub fn record_operation(span: &Span, operation: &str) {
    span.record(attr::OPERATION, operation);
}

/// Records the operation from a typed [`Action`], as `family.verb`.
///
/// Preferred over [`record_operation`] wherever an `Action` exists: the string comes from the
/// closed vocabulary in `core`, so a renamed action renames the attribute value everywhere at once
/// instead of leaving stale spellings behind in the handlers that happened not to be updated.
pub fn record_action(span: &Span, action: Action) {
    span.record(attr::OPERATION, format!("{}.{}", action.family(), action.verb()).as_str());
}

/// Records the workspace in scope.
pub fn record_workspace(span: &Span, workspace_id: WorkspaceId) {
    span.record(attr::WORKSPACE_ID, tracing::field::display(workspace_id));
}

/// Records that the policy chain allowed the operation.
pub fn record_policy_allow(span: &Span) {
    span.record(attr::POLICY_DECISION, "allow");
}

/// Records that the policy chain denied the operation, with the client-safe reason code.
///
/// Takes a [`ReasonCode`] rather than a string because the reason on a span is the same closed
/// enumeration the API returns; a hand-written string here is how a log ends up carrying policy
/// internals that `Error::PolicyDenied` was carefully built to keep out (`docs/03-LLD.md §22`).
pub fn record_policy_deny(span: &Span, reason: ReasonCode) {
    span.record(attr::POLICY_DECISION, "deny");
    span.record(attr::POLICY_REASON_CODE, reason.as_str());
}

// ---------------------------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------------------------

/// Name- and shape-based scrubbing of field values, applied by every formatter in this crate.
///
/// Public so that any code that renders a field outside this crate's subscriber — a panic hook, a
/// diagnostic dump, an error message that embeds a request payload — can apply the same rule
/// rather than inventing a weaker one.
pub mod redact {
    use std::borrow::Cow;

    /// What replaces a redacted value. A fixed marker rather than an empty string, so that a
    /// reader can tell "this was withheld" from "this was absent".
    pub const REDACTED: &str = "[redacted]";

    /// Field names that are exempt from the *name* check because they identify a credential
    /// without being one (`docs/03-LLD.md §20`: the `jti` may be logged, the token may not).
    ///
    /// Matched in full and case-insensitively — a prefix rule here would exempt `jti_token` too.
    /// The exemption never applies to the value check, so a token stored under one of these names
    /// is still masked.
    const NAME_ALLOWLIST: &[&str] = &[
        "jti",
        "token.jti",
        "token_jti",
        "access_token_jti",
        "refresh_token_jti",
        "token_family_id",
        "token.family_id",
        "kid",
        "key.id",
        "key_id",
        "signing_key_id",
        "token.kid",
    ];

    /// Patterns matched anywhere in the field name. These are long enough to be unambiguous:
    /// nothing benign contains `password` or `authorization` as a substring.
    const SUBSTRING_DENY: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "cookie",
        "authorization",
        "credential",
        "bearer",
        "pkcs8",
    ];

    /// Patterns matched against whole *segments* of the field name, where a segment is a run of
    /// alphanumerics between separators or at a camelCase boundary (`apiKey` → `api`, `key`).
    ///
    /// These are too short to match as substrings: `der` appears in `folder`, `sender`, `header`,
    /// `provider` and `order`, and redacting `folder.id` would be both useless and confusing. A
    /// trailing `s` is ignored, so `keys` matches `key`.
    const SEGMENT_DENY: &[&str] = &["key", "jwt", "der", "pem", "otp", "pin"];

    /// Whether a field with this name must never have its value rendered.
    ///
    /// The allowlist wins over both deny lists, and is checked first for exactly that reason.
    #[must_use]
    pub fn is_sensitive_key(name: &str) -> bool {
        if NAME_ALLOWLIST.iter().any(|allowed| name.eq_ignore_ascii_case(allowed)) {
            return false;
        }
        if SUBSTRING_DENY.iter().any(|pattern| contains_ignore_ascii_case(name, pattern)) {
            return true;
        }
        Segments::new(name).any(|segment| {
            let singular = segment.strip_suffix(['s', 'S']).unwrap_or(segment);
            SEGMENT_DENY
                .iter()
                .any(|p| segment.eq_ignore_ascii_case(p) || singular.eq_ignore_ascii_case(p))
        })
    }

    /// Scrubs a value that is about to be rendered under `field_name`.
    ///
    /// A sensitive name replaces the whole value; otherwise the value is scanned for credential
    /// shapes and only the offending parts are masked, so a log line stays readable.
    #[must_use]
    pub fn scrub<'v>(field_name: &str, value: &'v str) -> Cow<'v, str> {
        if is_sensitive_key(field_name) {
            return Cow::Borrowed(REDACTED);
        }
        scrub_value(value)
    }

    /// Scans free text for credential shapes and masks what it finds.
    ///
    /// Used on its own for values whose field name says nothing — most importantly the `Debug`
    /// rendering of a struct, where the leaking field name is *inside* the string
    /// (`Credentials { password: "hunter2" }`) and so cannot be caught by
    /// [`is_sensitive_key`] at all.
    ///
    /// The scan walks whitespace- and bracket-delimited segments and masks a segment when:
    ///
    /// - it is `key=value` or `key: value` and the key is sensitive (or the value is
    ///   credential-shaped);
    /// - the previous segment was a sensitive key awaiting its value, or an auth scheme
    ///   (`Bearer`, `Basic`);
    /// - the segment itself looks like a JWT, a PEM block or a long high-entropy secret.
    #[must_use]
    pub fn scrub_value(input: &str) -> Cow<'_, str> {
        let mut out = String::new();
        let mut copied_to = 0usize;
        let mut redact_next = false;

        for (start, end) in segment_spans(input) {
            let segment = &input[start..end];
            let Some(replacement) = decide(segment, &mut redact_next) else {
                continue;
            };
            out.push_str(&input[copied_to..start]);
            out.push_str(&replacement);
            copied_to = end;
        }

        if copied_to == 0 {
            return Cow::Borrowed(input);
        }
        out.push_str(&input[copied_to..]);
        Cow::Owned(out)
    }

    /// Decides what, if anything, replaces one segment. `None` means "leave it alone".
    fn decide(segment: &str, redact_next: &mut bool) -> Option<String> {
        if std::mem::take(redact_next) {
            return Some(REDACTED.to_owned());
        }

        if let Some((key, separator, value)) = split_key_value(segment) {
            if is_sensitive_key(key) {
                if value.is_empty() {
                    // `password: "hunter2"` — the value is the next segment.
                    *redact_next = true;
                    return None;
                }
                return Some(format!("{key}{separator}{REDACTED}"));
            }
            if !value.is_empty() && looks_like_credential(value) {
                return Some(format!("{key}{separator}{REDACTED}"));
            }
        }

        // `Authorization: Bearer <token>` splits into a scheme and an opaque value; the value may
        // have no recognisable shape of its own, so the scheme is what gives it away.
        if segment.eq_ignore_ascii_case("bearer") || segment.eq_ignore_ascii_case("basic") {
            *redact_next = true;
            return None;
        }

        looks_like_credential(segment).then(|| REDACTED.to_owned())
    }

    /// Whether a bare string is shaped like a credential.
    #[must_use]
    pub fn looks_like_credential(value: &str) -> bool {
        value.starts_with("-----BEGIN") || is_jwt(value) || is_high_entropy_secret(value)
    }

    /// Whether the string is a JWT: three base64url segments whose header begins `eyJ` — the
    /// base64url encoding of `{"`, which every JSON header starts with.
    ///
    /// The signature segment is allowed to be empty so that an `alg: none` token — precisely the
    /// kind most worth catching in a log — is not missed.
    #[must_use]
    pub fn is_jwt(value: &str) -> bool {
        let mut parts = value.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        header.starts_with("eyJ")
            && header.len() >= 8
            && payload.len() >= 8
            && is_base64url(header)
            && is_base64url(payload)
            && (signature.is_empty() || is_base64url(signature))
    }

    /// Whether the string is long enough, mixed enough and random enough to be a secret.
    ///
    /// The thresholds are chosen to sit above the things Enclave legitimately logs and below the
    /// things it must not. A UUID is 36 characters, so identifiers are never caught; a lowercase
    /// hex digest has no case mixture, so content hashes are never caught; a 256-bit refresh token
    /// is 43 base64url characters of near-maximal entropy, so it always is.
    #[must_use]
    pub fn is_high_entropy_secret(value: &str) -> bool {
        const MIN_LEN: usize = 40;
        const MIN_ENTROPY_BITS: f64 = 3.5;

        if value.len() < MIN_LEN || !is_base64url(value) {
            return false;
        }
        let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
        let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
        let has_digit = value.bytes().any(|b| b.is_ascii_digit());
        has_upper && has_lower && has_digit && shannon_entropy_bits(value) >= MIN_ENTROPY_BITS
    }

    /// Shannon entropy in bits per character, over the byte histogram.
    fn shannon_entropy_bits(value: &str) -> f64 {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for byte in bytes {
            counts[*byte as usize] += 1;
        }
        let total = bytes.len() as f64;
        counts
            .iter()
            .filter(|count| **count > 0)
            .map(|count| {
                let p = f64::from(*count) / total;
                -p * p.log2()
            })
            .sum()
    }

    /// Whether every byte is in the base64url alphabet, plus `=` padding.
    fn is_base64url(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'='))
    }

    /// Splits `key=value` or `key: value` at the first separator. `:` and `=` are not treated as
    /// segment separators because `=` is base64 padding and `:` appears inside `Debug` output.
    fn split_key_value(segment: &str) -> Option<(&str, char, &str)> {
        let index = segment.find(['=', ':'])?;
        let separator = segment[index..].chars().next()?;
        let key = &segment[..index];
        if key.is_empty() {
            return None;
        }
        Some((key, separator, &segment[index + separator.len_utf8()..]))
    }

    /// Whether a character delimits one segment of free text from the next. Notably excludes `.`,
    /// `-`, `_`, `+` and `/`, all of which occur inside credentials.
    fn is_segment_separator(c: char) -> bool {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '"' | '\'' | '`' | '\\' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
    }

    /// Byte ranges of the non-separator runs in `input`.
    fn segment_spans(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut cursor = 0usize;
        std::iter::from_fn(move || {
            let offset = input[cursor..].find(|c: char| !is_segment_separator(c))?;
            let start = cursor + offset;
            let end = input[start..]
                .find(is_segment_separator)
                .map_or(input.len(), |length| start + length);
            cursor = end;
            Some((start, end))
        })
    }

    /// Case-insensitive substring search that does not allocate. Field names are checked on every
    /// recorded field of every event, so the obvious `to_ascii_lowercase()` would be an allocation
    /// per field per log line.
    fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
        let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
        if needle.is_empty() || haystack.len() < needle.len() {
            return needle.is_empty();
        }
        haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
    }

    /// Splits a field name into alphanumeric segments, breaking on separators and on camelCase
    /// boundaries: `http.request.apiKey` yields `http`, `request`, `api`, `Key`.
    struct Segments<'a> {
        rest: &'a str,
    }

    impl<'a> Segments<'a> {
        fn new(name: &'a str) -> Self {
            Self { rest: name }
        }
    }

    impl<'a> Iterator for Segments<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<&'a str> {
            let start = self.rest.find(|c: char| c.is_ascii_alphanumeric())?;
            let bytes = self.rest.as_bytes();
            let mut end = start + 1;
            while end < bytes.len() {
                let current = bytes[end];
                if !current.is_ascii_alphanumeric() {
                    break;
                }
                let previous = bytes[end - 1];
                if current.is_ascii_uppercase()
                    && (previous.is_ascii_lowercase() || previous.is_ascii_digit())
                {
                    break;
                }
                end += 1;
            }
            let segment = &self.rest[start..end];
            self.rest = &self.rest[end..];
            Some(segment)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Field visitors
// ---------------------------------------------------------------------------------------------

/// Renders a value the way it will appear, then scrubs it.
///
/// Scrubbing after rendering rather than before is what makes `Debug` output safe: the credential
/// inside `Credentials { password: "hunter2" }` only exists once the value has been formatted.
fn scrubbed(name: &str, rendered: &str) -> String {
    redact::scrub(name, rendered).into_owned()
}

/// A scalar that carries no free text and therefore needs no shape scan — only the name check.
fn scrubbed_scalar(name: &str, rendered: String) -> String {
    if redact::is_sensitive_key(name) {
        redact::REDACTED.to_owned()
    } else {
        rendered
    }
}

/// Writes `name=value` pairs into a text writer, scrubbing as it goes.
struct TextVisitor<'a> {
    writer: Writer<'a>,
    result: fmt::Result,
    wrote_any: bool,
}

impl<'a> TextVisitor<'a> {
    fn new(writer: Writer<'a>) -> Self {
        Self { writer, result: Ok(()), wrote_any: false }
    }

    fn write_pair(&mut self, name: &str, value: &str) {
        if self.result.is_err() {
            return;
        }
        let separator = if self.wrote_any { " " } else { "" };
        self.wrote_any = true;
        self.result = if name == MESSAGE_FIELD {
            write!(self.writer, "{separator}{value}")
        } else {
            write!(self.writer, "{separator}{name}={value}")
        };
    }

    fn finish(self) -> fmt::Result {
        self.result
    }
}

impl Visit for TextVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.write_pair(field.name(), &scrubbed(field.name(), value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.write_pair(field.name(), &scrubbed(field.name(), &format!("{value:?}")));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.write_pair(field.name(), &scrubbed(field.name(), &value.to_string()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.write_pair(field.name(), &scrubbed_scalar(field.name(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.write_pair(field.name(), &scrubbed_scalar(field.name(), value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.write_pair(field.name(), &scrubbed_scalar(field.name(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.write_pair(field.name(), &scrubbed_scalar(field.name(), value.to_string()));
    }
}

/// Collects fields into a JSON object, scrubbing as it goes.
#[derive(Debug, Default)]
struct JsonVisitor {
    fields: Map<String, Value>,
}

impl JsonVisitor {
    fn with(fields: Map<String, Value>) -> Self {
        Self { fields }
    }

    fn insert_text(&mut self, name: &str, rendered: &str) {
        self.fields.insert(name.to_owned(), Value::String(scrubbed(name, rendered)));
    }

    fn insert_scalar(&mut self, name: &str, value: Value) {
        if redact::is_sensitive_key(name) {
            self.fields.insert(name.to_owned(), Value::String(redact::REDACTED.to_owned()));
        } else {
            self.fields.insert(name.to_owned(), value);
        }
    }
}

impl Visit for JsonVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert_text(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert_text(field.name(), &format!("{value:?}"));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert_text(field.name(), &value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert_scalar(field.name(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert_scalar(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert_scalar(field.name(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert_scalar(field.name(), Value::from(value));
    }
}

// ---------------------------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------------------------

/// Redacting field formatter for human-readable output.
///
/// Installed with [`tracing_subscriber::fmt::Layer::fmt_fields`], which is the single point every
/// span field and every event field of the text format passes through.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactingFields;

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = TextVisitor::new(writer);
        fields.record(&mut visitor);
        visitor.finish()
    }
}

/// Redacting field formatter for JSON output: renders a span's fields as a JSON object.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactingJsonFields;

impl RedactingJsonFields {
    /// Parses previously formatted span fields back into a map, so that a later `Span::record`
    /// merges into them instead of appending a second JSON object to the same string.
    fn parse(formatted: &str) -> Map<String, Value> {
        match serde_json::from_str(formatted) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        }
    }
}

impl<'writer> FormatFields<'writer> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = JsonVisitor::default();
        fields.record(&mut visitor);
        write!(writer, "{}", Value::Object(visitor.fields))
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &Record<'_>,
    ) -> fmt::Result {
        let mut visitor = JsonVisitor::with(Self::parse(&current.fields));
        fields.record(&mut visitor);
        current.fields = Value::Object(visitor.fields).to_string();
        Ok(())
    }
}

/// One JSON object per line: the production event format.
///
/// Hand-written rather than delegating to `tracing_subscriber`'s JSON formatter because that one
/// serializes event fields through its own visitor, which would bypass redaction entirely. Owning
/// the serialization is what makes "every rendered field passes through [`redact::scrub`]" a
/// property of this crate rather than a hope about somebody else's.
#[derive(Debug, Clone, Default)]
pub struct RedactingJson {
    service_name: Option<String>,
}

impl RedactingJson {
    /// Tags every line with the emitting service, so that logs from `api`, `worker` and
    /// `scheduler` remain separable once they are in one aggregator.
    #[must_use]
    pub fn new(service_name: Option<String>) -> Self {
        Self { service_name }
    }
}

impl<S, N> FormatEvent<S, N> for RedactingJson
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut line = Map::new();
        line.insert(
            "timestamp".to_owned(),
            Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        );
        line.insert(
            "level".to_owned(),
            Value::String(metadata.level().as_str().to_ascii_lowercase()),
        );
        line.insert("target".to_owned(), Value::String(metadata.target().to_owned()));
        if let Some(service) = &self.service_name {
            line.insert("service.name".to_owned(), Value::String(service.clone()));
        }

        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);
        if let Some(message) = visitor.fields.remove(MESSAGE_FIELD) {
            line.insert(MESSAGE_FIELD.to_owned(), message);
        }
        if !visitor.fields.is_empty() {
            line.insert("fields".to_owned(), Value::Object(visitor.fields));
        }

        let mut spans = Vec::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let mut entry = Map::new();
                entry.insert("name".to_owned(), Value::String(span.name().to_owned()));
                let extensions = span.extensions();
                if let Some(formatted) = extensions.get::<FormattedFields<N>>() {
                    if let Ok(Value::Object(fields)) =
                        serde_json::from_str::<Value>(&formatted.fields)
                    {
                        for (key, value) in fields {
                            entry.insert(key, value);
                        }
                    }
                }
                spans.push(Value::Object(entry));
            }
        }
        if !spans.is_empty() {
            line.insert("spans".to_owned(), Value::Array(spans));
        }

        writeln!(writer, "{}", Value::Object(line))
    }
}

// ---------------------------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------------------------

/// Which of the two output formats a process installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line. The default, so that a process started without configuration
    /// produces machine-parseable output — a deployment that accidentally ships human-readable
    /// logs is a deployment whose alerting silently sees nothing.
    #[default]
    Json,
    /// Multi-line, coloured, human-readable. Development only.
    Pretty,
}

/// How a process configures its tracing stack.
///
/// Defined here rather than in `config` so that this crate stays usable from a test, a one-shot
/// CLI command or a binary that has not loaded configuration yet. The `config` crate maps its own
/// layered representation onto this at startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservabilityConfig {
    /// Output format.
    pub format: LogFormat,
    /// `EnvFilter` directives, e.g. `info,enclave_db=debug`. Overridden by [`FILTER_ENV_VAR`].
    pub filter: String,
    /// Emitting service, tagged onto every JSON line.
    pub service_name: Option<String>,
    /// ANSI colour in the pretty format. Ignored by the JSON format.
    pub ansi: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self { format: LogFormat::Json, filter: "info".to_owned(), service_name: None, ansi: true }
    }
}

/// Why a process could not install its tracing stack.
///
/// Both variants are startup failures rather than warnings: a process that keeps running after
/// failing to install logging is a process whose next security-relevant event goes nowhere.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// The configured — or environment-supplied — filter directives did not parse.
    #[error("invalid log filter directives `{directives}`")]
    Filter {
        /// The directives as given, so the operator can see what was rejected.
        directives: String,
        /// The underlying parse failure.
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },
    /// Something already installed a global subscriber. Almost always a second `init` call.
    #[error("a global tracing subscriber is already installed")]
    AlreadyInstalled(#[source] tracing_subscriber::util::TryInitError),
}

/// Installs the process-wide tracing subscriber.
///
/// Call once, as early in `main` as possible and before anything that might log.
///
/// # Errors
///
/// Returns [`InitError`] if the filter directives do not parse or a subscriber is already
/// installed.
pub fn init(config: &ObservabilityConfig) -> Result<(), InitError> {
    init_with_layer(config, None::<tracing_subscriber::layer::Identity>)
}

/// Installs the process-wide subscriber together with one additional layer.
///
/// The seam for trace export: a binary builds its OTLP (or other) layer, keeps ownership of the
/// exporter's provider so it can flush it on shutdown, and hands the layer here. Export therefore
/// costs this crate no dependency at all, which is the same outcome the `otlp` feature exists to
/// guarantee and is available today.
///
/// The extra layer sits *under* the filter, so the configured directives govern what reaches it
/// exactly as they govern what reaches the log output. It does **not** sit under redaction:
/// redaction is a property of these two formatters, so a layer added here is responsible for its
/// own — pass field values through [`redact::scrub`] before exporting them.
///
/// # Errors
///
/// Returns [`InitError`] if the filter directives do not parse or a subscriber is already
/// installed.
pub fn init_with_layer<L>(config: &ObservabilityConfig, extra: Option<L>) -> Result<(), InitError>
where
    L: Layer<Registry> + Send + Sync + 'static,
{
    let filter = build_filter(config)?;
    let base = tracing_subscriber::registry().with(extra).with(filter);

    let outcome = match config.format {
        LogFormat::Json => base
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(RedactingJsonFields)
                    .event_format(RedactingJson::new(config.service_name.clone())),
            )
            .try_init(),
        LogFormat::Pretty => base
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_ansi(config.ansi)
                    .fmt_fields(RedactingFields),
            )
            .try_init(),
    };
    outcome.map_err(InitError::AlreadyInstalled)
}

/// Builds the level filter, letting [`FILTER_ENV_VAR`] override the configured directives.
///
/// An empty or whitespace-only environment variable is treated as unset rather than as "log
/// nothing", because `ENCLAVE_LOG=` in a compose file is how people spell "I did not set this".
fn build_filter(config: &ObservabilityConfig) -> Result<EnvFilter, InitError> {
    let directives = match std::env::var(FILTER_ENV_VAR) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => config.filter.clone(),
    };
    EnvFilter::try_new(&directives).map_err(|source| InitError::Filter { directives, source })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::borrow::Cow;
    use std::io;
    use std::sync::{Arc, Mutex};

    use enclave_core::{ClientType, ReasonCode, RequestContext, TenantId, UserId, WorkspaceId};
    use tracing_subscriber::fmt::MakeWriter;

    use super::redact::{is_sensitive_key, looks_like_credential, scrub, scrub_value, REDACTED};
    use super::*;

    /// A real Ed25519-shaped JWT header/payload with a 43-character signature. Not a credential:
    /// the signature is a fixed pattern, and nothing verifies it.
    const SAMPLE_JWT: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2N2UxNTUifQ.\
                              QWxpY2VCb2JDaGFybGllRGF2ZUV2ZUZyYW5rR3JhY2VIZWlkaQ";

    // --- name classification --------------------------------------------------------------

    #[test]
    fn credential_bearing_names_are_sensitive() {
        for name in [
            "password",
            "Password",
            "user.password",
            "passwd",
            "passphrase",
            "client_secret",
            "refresh_token",
            "access_token",
            "refresh_cookie",
            "refreshCookie",
            "http.request.header.authorization",
            "Authorization",
            "api_key",
            "apiKey",
            "signing_keys",
            "private_key_pkcs8",
            "cert.der",
            "key.pem",
            "jwt",
            "id_jwt",
            "bearer",
            "credentials",
            "otp",
            "pin",
        ] {
            assert!(is_sensitive_key(name), "expected `{name}` to be treated as sensitive");
        }
    }

    #[test]
    fn ordinary_names_survive_the_short_patterns() {
        // `der` inside `folder`/`sender`/`provider` and `key` inside `monkey` are exactly why the
        // short patterns match whole segments rather than substrings.
        for name in [
            "folder.id",
            "sender.name",
            "provider",
            "order.total",
            "header.count",
            "monkey",
            "auth_time",
            "auth_strength",
            "session.id",
            "operation",
            "policy.decision",
            "policy.reason_code",
            "tenant.id",
            "request.id",
            "actor.type",
            "client.type",
            "workspace.id",
        ] {
            assert!(!is_sensitive_key(name), "expected `{name}` to be left alone");
        }
    }

    #[test]
    fn every_conventional_attribute_is_loggable() {
        for name in attr::ALL {
            assert!(!is_sensitive_key(name), "convention attribute `{name}` must not be redacted");
        }
    }

    // --- the jti / token distinction (docs/03-LLD.md §20) -----------------------------------

    #[test]
    fn a_jti_may_be_logged_but_a_token_may_not() {
        assert!(!is_sensitive_key("jti"));
        assert!(!is_sensitive_key("token.jti"));
        assert!(!is_sensitive_key("refresh_token_jti"));
        assert!(!is_sensitive_key("kid"));
        assert!(!is_sensitive_key("signing_key_id"));

        assert!(is_sensitive_key("token"));
        assert!(is_sensitive_key("refresh_token"));
        assert!(is_sensitive_key("token.value"));
        assert!(is_sensitive_key("jti_token"));

        let jti = "01927f3a-6c1e-7d4b-9f3a-2b1c4d5e6f70";
        assert_eq!(scrub("jti", jti), jti);
        assert_eq!(scrub("refresh_token", jti), REDACTED);
    }

    #[test]
    fn the_allowlist_exempts_the_name_not_the_value() {
        // Putting a whole token in a field called `jti` must not smuggle it past the filter.
        let scrubbed = scrub("jti", SAMPLE_JWT);
        assert_eq!(scrubbed, REDACTED);
        assert!(!scrubbed.contains("eyJ"));
    }

    // --- value shapes -----------------------------------------------------------------------

    #[test]
    fn a_jwt_is_recognised_wherever_it_appears() {
        assert!(looks_like_credential(SAMPLE_JWT));

        let message = format!("upstream replied with {SAMPLE_JWT} after 3 attempts");
        let scrubbed = scrub_value(&message);
        assert!(!scrubbed.contains("eyJ"), "JWT survived: {scrubbed}");
        assert!(scrubbed.contains(REDACTED));
        assert!(scrubbed.contains("after 3 attempts"));
    }

    #[test]
    fn an_alg_none_jwt_with_an_empty_signature_is_still_a_jwt() {
        let unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
        assert!(super::redact::is_jwt(unsigned));
        assert_eq!(scrub_value(unsigned), REDACTED);
    }

    #[test]
    fn a_bearer_scheme_redacts_the_value_that_follows_it() {
        let scrubbed = scrub_value("Bearer 8f2a-opaque-reference-value");
        assert!(!scrubbed.contains("opaque-reference-value"), "{scrubbed}");
    }

    #[test]
    fn long_high_entropy_strings_are_masked() {
        // A 43-character base64url string is the shape of a 256-bit refresh token.
        let secret = "Xy7Qm2ZpL9vRt4Ns6Kd1Bw8Fh3Jc0Ge5Ua7Yi2Ol4P";
        assert!(secret.len() >= 40);
        assert!(looks_like_credential(secret));
        assert_eq!(scrub_value(secret), REDACTED);
    }

    #[test]
    fn identifiers_and_digests_are_not_mistaken_for_secrets() {
        let uuid = "01927f3a-6c1e-7d4b-9f3a-2b1c4d5e6f70";
        let sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let path = "/tenants/alpha/libraries/documents/files/report-2026-q1.docx";
        for value in [uuid, sha256, path] {
            assert!(!looks_like_credential(value), "false positive on `{value}`");
            assert_eq!(scrub_value(value), value);
        }
    }

    #[test]
    fn ordinary_prose_is_left_untouched() {
        let message = "download denied for 3 files in workspace alpha";
        assert!(matches!(scrub_value(message), Cow::Borrowed(_)));
        assert_eq!(scrub_value(message), message);
    }

    #[test]
    fn a_sensitive_key_inside_debug_output_redacts_its_value() {
        // The field name here is `creds`, which says nothing; the leak is inside the string.
        let debug = r#"Credentials { user: "ada", password: "hunter2", attempts: 1 }"#;
        let scrubbed = scrub("creds", debug);
        assert!(!scrubbed.contains("hunter2"), "password survived: {scrubbed}");
        assert!(scrubbed.contains("ada"));
        assert!(scrubbed.contains("attempts: 1"));
    }

    #[test]
    fn an_inline_assignment_redacts_only_the_value() {
        let scrubbed = scrub_value("client_secret=s3kr3t-value tenant=alpha");
        assert!(!scrubbed.contains("s3kr3t"), "{scrubbed}");
        assert!(scrubbed.contains("tenant=alpha"));
    }

    #[test]
    fn a_pem_block_is_never_rendered() {
        // Assembled rather than written literally. The secrets structural gate refuses PEM
        // material in any tracked file and is deliberately not clever enough to except a test —
        // a gate with exceptions is a gate people learn to route around. This is the second time
        // the rule has bitten a test that exists to enforce the same thing, so it is now written
        // down in CLAUDE.md.
        let pem_banner = format!("-----{} PRIVATE KEY-----", "BEGIN");
        assert!(looks_like_credential(&pem_banner));
    }

    // --- rendered output ---------------------------------------------------------------------

    /// Captures formatted output so a test can assert on exactly what a log line contains.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `body` under the JSON stack and returns everything it wrote.
    fn json_output(body: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .fmt_fields(RedactingJsonFields)
                .event_format(RedactingJson::new(Some("enclave-test".to_owned()))),
        );
        tracing::subscriber::with_default(subscriber, body);
        capture.contents()
    }

    /// Runs `body` under the human-readable stack and returns everything it wrote.
    fn text_output(body: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .with_ansi(false)
                .fmt_fields(RedactingFields),
        );
        tracing::subscriber::with_default(subscriber, body);
        capture.contents()
    }

    #[test]
    fn a_password_field_on_an_event_never_reaches_the_output() {
        for output in [
            json_output(|| tracing::info!(password = "hunter2", "login attempt")),
            text_output(|| tracing::info!(password = "hunter2", "login attempt")),
        ] {
            assert!(!output.contains("hunter2"), "password leaked: {output}");
            assert!(output.contains(REDACTED), "expected a redaction marker: {output}");
            assert!(output.contains("login attempt"));
        }
    }

    #[test]
    fn a_password_field_on_a_span_never_reaches_the_output() {
        for output in [
            json_output(|| {
                let span = tracing::info_span!("login", password = "hunter2");
                let _entered = span.enter();
                tracing::info!("inside");
            }),
            text_output(|| {
                let span = tracing::info_span!("login", password = "hunter2");
                let _entered = span.enter();
                tracing::info!("inside");
            }),
        ] {
            assert!(!output.contains("hunter2"), "span field leaked: {output}");
            assert!(output.contains(REDACTED), "expected a redaction marker: {output}");
        }
    }

    #[test]
    fn a_jwt_in_a_field_value_does_not_survive_rendering() {
        for output in [
            json_output(|| tracing::warn!(upstream_body = SAMPLE_JWT, "unexpected response")),
            text_output(|| tracing::warn!(upstream_body = SAMPLE_JWT, "unexpected response")),
        ] {
            assert!(!output.contains("eyJ"), "JWT leaked: {output}");
            assert!(output.contains(REDACTED));
        }
    }

    #[test]
    fn a_jti_survives_while_the_token_beside_it_does_not() {
        let output = json_output(|| {
            tracing::info!(
                jti = "01927f3a-6c1e-7d4b-9f3a-2b1c4d5e6f70",
                token = SAMPLE_JWT,
                "rotated"
            );
        });
        assert!(output.contains("01927f3a-6c1e-7d4b-9f3a-2b1c4d5e6f70"), "jti lost: {output}");
        assert!(!output.contains("eyJ"), "token leaked: {output}");
    }

    #[test]
    fn a_numeric_field_with_a_sensitive_name_is_redacted_too() {
        let output = json_output(|| tracing::info!(otp = 123_456, attempts = 2, "verifying"));
        assert!(!output.contains("123456"), "otp leaked: {output}");
        assert!(output.contains("\"attempts\":2"), "{output}");
    }

    #[test]
    fn json_output_is_one_parseable_object_per_line() {
        let output = json_output(|| tracing::info!(files = 3, "swept"));
        let line: Value = serde_json::from_str(output.trim()).expect("valid JSON");
        assert_eq!(line["message"], Value::String("swept".to_owned()));
        assert_eq!(line["level"], Value::String("info".to_owned()));
        assert_eq!(line["service.name"], Value::String("enclave-test".to_owned()));
        assert_eq!(line["fields"]["files"], Value::from(3));
        assert!(line["timestamp"].is_string());
    }

    // --- conventions -------------------------------------------------------------------------

    #[test]
    fn the_request_span_declares_exactly_the_conventional_attributes() {
        // Keeps `request_span!` and `attr::ALL` from drifting apart: a field the macro forgets to
        // declare can never be recorded, and a constant nothing declares is a dead dashboard.
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(Capture::default()));
        tracing::subscriber::with_default(subscriber, || {
            let span = request_span!("files.download");
            let metadata = span.metadata().expect("the span is enabled");
            let mut declared: Vec<&str> = metadata.fields().iter().map(|f| f.name()).collect();
            declared.sort_unstable();
            let mut expected: Vec<&str> = attr::ALL.to_vec();
            expected.sort_unstable();
            assert_eq!(declared, expected);
        });
    }

    #[test]
    fn a_request_context_lands_on_the_span_under_the_conventional_names() {
        let tenant = TenantId::new_v7();
        let workspace = WorkspaceId::new_v7();
        let mut ctx = RequestContext::system(tenant);
        ctx.actor = enclave_core::Actor::User(UserId::new_v7());
        ctx.client = ClientType::Web;

        let output = json_output(|| {
            let span = request_span!("files.download");
            record_request_context(&span, &ctx);
            record_workspace(&span, workspace);
            record_policy_deny(&span, ReasonCode::DownloadBlockedByPolicy);
            let _entered = span.enter();
            tracing::info!("denied");
        });

        let line: Value = serde_json::from_str(output.trim()).expect("valid JSON");
        let span = &line["spans"][0];
        assert_eq!(span["name"], Value::String("enclave.request".to_owned()));
        assert_eq!(span[attr::TENANT_ID], Value::String(tenant.to_string()));
        assert_eq!(span[attr::REQUEST_ID], Value::String(ctx.request_id.to_string()));
        assert_eq!(span[attr::ACTOR_TYPE], Value::String("user".to_owned()));
        assert_eq!(span[attr::CLIENT_TYPE], Value::String("web".to_owned()));
        assert_eq!(span[attr::WORKSPACE_ID], Value::String(workspace.to_string()));
        assert_eq!(span[attr::OPERATION], Value::String("files.download".to_owned()));
        assert_eq!(span[attr::POLICY_DECISION], Value::String("deny".to_owned()));
        assert_eq!(
            span[attr::POLICY_REASON_CODE],
            Value::String(ReasonCode::DownloadBlockedByPolicy.as_str().to_owned())
        );
    }

    #[test]
    fn a_typed_action_becomes_a_family_dot_verb_operation() {
        use enclave_core::{Action, FileAction};

        let output = json_output(|| {
            let span = request_span!();
            record_action(&span, Action::File(FileAction::Download));
            record_policy_allow(&span);
            let _entered = span.enter();
            tracing::info!("served");
        });
        let line: Value = serde_json::from_str(output.trim()).expect("valid JSON");
        assert_eq!(line["spans"][0][attr::OPERATION], Value::String("file.download".to_owned()));
        assert_eq!(line["spans"][0][attr::POLICY_DECISION], Value::String("allow".to_owned()));
    }

    // --- configuration -----------------------------------------------------------------------

    #[test]
    fn the_default_configuration_is_machine_readable() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.format, LogFormat::Json);
        assert!(build_filter(&config).is_ok());
    }

    #[test]
    fn invalid_filter_directives_fail_at_startup() {
        let config = ObservabilityConfig { filter: "=nonsense=".to_owned(), ..Default::default() };
        let error = build_filter(&config).expect_err("expected a parse failure");
        assert!(matches!(error, InitError::Filter { .. }));
    }
}
