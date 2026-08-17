//! Structural redaction for audit detail payloads.
//!
//! `CLAUDE.md` rule 10 says an audit row never contains passwords, tokens, refresh cookies, DLP
//! match values or file content, and test `U4` asserts it. A rule that lives only in a reviewer's
//! head is a rule that eventually loses to a hurried `detail.insert("token", …)`, so this module
//! makes the rule a *type*: [`Detail`] is the only payload [`crate::AuditEvent`] accepts, and the
//! only ways to build one either reject a credential-shaped field name or replace its value.
//!
//! # What this does and does not catch
//!
//! It matches on **field names**, not values. A token stored under the key `"note"` still gets
//! written, and no name-based filter can prevent that. What the filter does buy is that the
//! *ordinary* mistake — naming the field after what it holds — cannot compile past
//! [`Detail::try_insert`]. Deliberate exfiltration through a misleading key is a code-review and
//! DLP problem, not one this crate can close.
//!
//! Matching is a case-insensitive substring test, so `refreshToken`, `AUTH_TOKEN` and
//! `token_hash` are all refused. False positives are accepted on purpose: failing closed on a
//! harmlessly named field costs one renamed key, while failing open costs a credential in a table
//! that is by design append-only and widely readable by auditors.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// Substrings that mark a field name as credential-shaped.
///
/// Deliberately short and deliberately blunt. Adding an entry is cheap and safe; removing one is a
/// security change and needs the same scrutiny as weakening any other control.
pub const FORBIDDEN_FIELD_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "token",
    "secret",
    "credential",
    "cookie",
    "authorization",
    "apikey",
    "api_key",
    "private_key",
    "privatekey",
];

/// What replaces a forbidden value on the sanitizing path.
///
/// A fixed marker rather than dropping the key, so a reader can tell "this field was removed by
/// policy" from "this field was never set" — the difference matters during an investigation.
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// The maximum number of field names [`RedactionError`] reports.
///
/// Bounded so a pathological payload cannot turn one rejection into an unbounded log line.
const MAX_REPORTED_FIELDS: usize = 16;

/// Whether a field name looks like it holds a credential.
///
/// Public because the same question comes up in structured logging and in request-body scrubbing,
/// and two implementations of "is this a secret-ish name" would inevitably disagree.
#[must_use]
pub fn is_forbidden_field(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    FORBIDDEN_FIELD_MARKERS.iter().any(|marker| lowered.contains(marker))
}

/// A detail payload was rejected because it named credential-shaped fields.
///
/// Reports the offending **names** and never the values — the whole point is that the values do
/// not travel, and an error message is as much a sink as a database column.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct RedactionError {
    /// The offending field names, sorted and deduplicated, truncated to a bounded count.
    fields: Vec<String>,
    /// How many distinct names were found in total, which may exceed `fields.len()`.
    total: usize,
}

impl RedactionError {
    /// The offending field names, sorted, deduplicated and bounded in number.
    #[must_use]
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// How many distinct forbidden names were found, including any not listed in [`Self::fields`].
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }
}

impl fmt::Display for RedactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit detail rejected: {} credential-shaped field name(s): ", self.total)?;
        for (i, field) in self.fields.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(field)?;
        }
        if self.total > self.fields.len() {
            write!(f, ", … ({} more)", self.total - self.fields.len())?;
        }
        Ok(())
    }
}

/// The `detail` payload of an audit event: free-form JSON that has been checked for
/// credential-shaped field names.
///
/// Structurally a JSON object, because the column is queried with `detail->>'key'` and a bare
/// array or scalar would make those queries meaningless.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Detail(Map<String, Value>);

impl Detail {
    /// An empty payload — the common case, and the reason this is not `Option<Detail>` everywhere.
    #[must_use]
    pub fn empty() -> Self {
        Self(Map::new())
    }

    /// Builds a payload, refusing the whole map if any field name anywhere inside it is
    /// credential-shaped.
    ///
    /// Rejecting rather than sanitizing is the right default on the *write* path: a caller that
    /// tried to audit a token has a bug, and silently dropping the field would leave the bug in
    /// place and the audit row subtly wrong.
    ///
    /// # Errors
    ///
    /// [`RedactionError`] listing the offending names.
    pub fn new(map: Map<String, Value>) -> Result<Self, RedactionError> {
        let mut found = BTreeSet::new();
        scan_object(&map, &mut found);
        if found.is_empty() {
            return Ok(Self(map));
        }
        let total = found.len();
        Err(RedactionError { fields: found.into_iter().take(MAX_REPORTED_FIELDS).collect(), total })
    }

    /// Builds a payload by replacing every credential-shaped field's value with
    /// [`REDACTED_PLACEHOLDER`], instead of failing.
    ///
    /// This is the *read* path's constructor. A row that somehow already contains a bad field —
    /// written by an older binary, or by hand — must still be readable for verification and
    /// export; refusing to deserialize it would turn one bad row into an unverifiable chain.
    #[must_use]
    pub fn redacted(mut map: Map<String, Value>) -> Self {
        redact_object(&mut map);
        Self(map)
    }

    /// Adds one field, refusing a credential-shaped name.
    ///
    /// # Errors
    ///
    /// [`RedactionError`] naming the rejected key. The value is neither stored nor reported.
    pub fn try_insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<(), RedactionError> {
        let key = key.into();
        let value = value.into();
        let mut found = BTreeSet::new();
        if is_forbidden_field(&key) {
            found.insert(key.clone());
        }
        scan_value(&value, &mut found);
        if !found.is_empty() {
            let total = found.len();
            return Err(RedactionError {
                fields: found.into_iter().take(MAX_REPORTED_FIELDS).collect(),
                total,
            });
        }
        self.0.insert(key, value);
        Ok(())
    }

    /// Looks a field up.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// The underlying object, for canonical encoding and for binding to the `JSONB` column.
    #[must_use]
    pub const fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    /// Consumes the payload, yielding the underlying object.
    #[must_use]
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }

    /// How many top-level fields the payload has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload has no fields — `NULL` is written to the column in that case.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Map<String, Value>> for Detail {
    type Error = RedactionError;

    fn try_from(value: Map<String, Value>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for Detail {
    /// Transparent: the wire form is the object itself, so a SIEM sees the same JSON the column
    /// holds.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Detail {
    /// Routed through [`Detail::redacted`], never through [`Detail::new`].
    ///
    /// Deserialization happens when reading our own stored rows back; failing the read would mean
    /// a single poisoned row makes a tenant's chain unverifiable, which is a strictly worse outcome
    /// than reading it with the offending values masked.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = Map::deserialize(deserializer)?;
        Ok(Self::redacted(map))
    }
}

/// Collects every credential-shaped key in an object, recursively.
fn scan_object(map: &Map<String, Value>, found: &mut BTreeSet<String>) {
    for (key, value) in map {
        if is_forbidden_field(key) {
            found.insert(key.clone());
        }
        scan_value(value, found);
    }
}

/// Collects every credential-shaped key reachable from a value.
fn scan_value(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => scan_object(map, found),
        Value::Array(items) => {
            for item in items {
                scan_value(item, found);
            }
        }
        _ => {}
    }
}

/// Replaces every credential-shaped field's value with the placeholder, recursively.
fn redact_object(map: &mut Map<String, Value>) {
    for (key, value) in map.iter_mut() {
        if is_forbidden_field(key) {
            *value = Value::String(REDACTED_PLACEHOLDER.to_owned());
        } else {
            redact_value(value);
        }
    }
}

/// Recurses into containers on the sanitizing path.
fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => redact_object(map),
        Value::Array(items) => {
            for item in items {
                redact_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => panic!("test fixture must be a JSON object"),
        }
    }

    #[test]
    fn every_marker_is_recognised_in_any_case() {
        for marker in FORBIDDEN_FIELD_MARKERS {
            assert!(is_forbidden_field(marker), "{marker}");
            assert!(is_forbidden_field(&marker.to_ascii_uppercase()), "{marker}");
            assert!(is_forbidden_field(&format!("user_{marker}_value")), "{marker}");
        }
    }

    #[test]
    fn ordinary_field_names_are_allowed() {
        for name in ["file_id", "bytes", "reason", "workspace", "count", "duration_ms"] {
            assert!(!is_forbidden_field(name), "{name}");
        }
    }

    #[test]
    fn new_rejects_a_credential_shaped_field() {
        let err = Detail::new(object(json!({ "user": "u1", "refreshToken": "abc" })))
            .expect_err("a token field must be refused");
        assert_eq!(err.fields(), ["refreshToken"]);
        assert_eq!(err.total(), 1);
        // The value never appears anywhere in the diagnostic.
        assert!(!err.to_string().contains("abc"));
    }

    #[test]
    fn new_rejects_nested_and_array_nested_fields() {
        let err = Detail::new(object(json!({
            "outer": { "inner": { "api_key": "k" } },
            "list": [ { "ok": 1 }, { "session_cookie": "c" } ],
        })))
        .expect_err("nested credential fields must be refused");
        assert_eq!(err.total(), 2);
        assert_eq!(err.fields(), ["api_key", "session_cookie"]);
    }

    #[test]
    fn try_insert_refuses_and_leaves_the_payload_untouched() {
        let mut detail = Detail::empty();
        detail.try_insert("file_id", "f1").expect("plain field");
        let err = detail.try_insert("password", "hunter2").expect_err("must refuse");
        assert_eq!(err.fields(), ["password"]);
        assert_eq!(detail.len(), 1);
        assert!(detail.get("password").is_none());
    }

    #[test]
    fn redacted_masks_rather_than_fails() {
        let detail = Detail::redacted(object(json!({
            "keep": "yes",
            "auth_token": "abc",
            "nested": { "secret_value": 1, "fine": 2 },
        })));
        assert_eq!(detail.get("keep"), Some(&json!("yes")));
        assert_eq!(detail.get("auth_token"), Some(&json!(REDACTED_PLACEHOLDER)));
        let nested = detail.get("nested").and_then(Value::as_object).expect("nested object");
        assert_eq!(nested.get("secret_value"), Some(&json!(REDACTED_PLACEHOLDER)));
        assert_eq!(nested.get("fine"), Some(&json!(2)));
    }

    #[test]
    fn deserialization_sanitizes_instead_of_failing() {
        let detail: Detail =
            serde_json::from_str(r#"{"token":"leaked","file":"f"}"#).expect("must not fail");
        assert_eq!(detail.get("token"), Some(&json!(REDACTED_PLACEHOLDER)));
        assert_eq!(detail.get("file"), Some(&json!("f")));
    }

    #[test]
    fn reported_field_names_are_bounded() {
        let mut map = Map::new();
        for i in 0..(MAX_REPORTED_FIELDS * 2) {
            map.insert(format!("token_{i:03}"), json!(i));
        }
        let err = Detail::new(map).expect_err("must refuse");
        assert_eq!(err.total(), MAX_REPORTED_FIELDS * 2);
        assert_eq!(err.fields().len(), MAX_REPORTED_FIELDS);
    }
}
