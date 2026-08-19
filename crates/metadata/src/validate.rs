//! Validating a value against its field definition.
//!
//! This is the crate's substance. Everything else stores and retrieves; this decides whether
//! user-controlled data is allowed to become part of a tenant's record.
//!
//! # Reject, never coerce
//!
//! Every validator here refuses a value of the wrong shape rather than converting it. That rule is
//! worth stating because coercion is the natural instinct and it is wrong in a specific way: a
//! `NUMBER` field that accepts `"42"` and stores `42` has silently decided that a client which
//! sends strings is fine, and the next client sends `"1e999"`, or `"0x10"`, or `""`. A `BOOLEAN`
//! that accepts `"false"` will eventually accept `"no"`, and one of those two is truthy in some
//! language a caller is written in.
//!
//! The cost of rejecting is an error message. The cost of coercing is that the type in the field
//! definition stops describing the data, and every consumer downstream — the search index, a
//! filter, an export — has to re-derive what it actually holds.
//!
//! # Where validation is not enough
//!
//! Four types name something: `USER`, `GROUP`, `TAXONOMY` and `REFERENCE`. This module checks that
//! the value is a well-formed identifier and that its shape matches the field's configuration. It
//! does **not** check that the thing exists, and it deliberately cannot — resolving a reference
//! requires a database, and a validator that took a connection would be one that ran inside every
//! loop over every field of every row.
//!
//! Existence is checked by [`crate::repo::validate_references`], in the same transaction as the
//! write, with the tenant predicate that makes a cross-tenant reference unrepresentable. Both
//! halves are required, and the split is why: shape is cheap and total, existence is expensive and
//! needs the tenant. A `REFERENCE` that named another tenant's file would otherwise be a way to
//! confirm that file exists.
//!
//! # `JSON` fields are bounded
//!
//! The `JSON` type exists for data the product does not model. It is still bounded by size and by
//! depth, because an unbounded nested document is a stack-overflow in whatever parses it next —
//! and what parses it next includes the search indexer and every client.

use serde_json::Value;

use crate::error::{FieldViolation, ValidationOutcome};
use crate::model::{FieldConfig, FieldType, MetadataField};

/// The nesting depth a `JSON` value may reach when the field sets no limit of its own.
///
/// Not unlimited, and not a large round number: 32 is past anything anyone writes by hand and short
/// of anything that troubles a recursive parser.
pub const DEFAULT_MAX_JSON_DEPTH: usize = 32;

/// The serialized size a `JSON` value may reach by default. 64 KiB.
pub const DEFAULT_MAX_JSON_BYTES: usize = 64 * 1024;

/// Checks one value against one field.
///
/// Returns every violation rather than the first, because a form with four bad fields should report
/// four problems once rather than one problem four times.
pub fn validate(field: &MetadataField, value: Option<&Value>) -> ValidationOutcome {
    let mut violations = Vec::new();

    let Some(value) = value else {
        if field.required {
            violations.push(FieldViolation::Required);
        }
        return ValidationOutcome::new(violations);
    };

    // `null` is absence written explicitly. Treating it as a present value would let a required
    // field be satisfied by `{"field": null}`, which is the same as omitting it and looks like
    // compliance.
    if value.is_null() {
        if field.required {
            violations.push(FieldViolation::Required);
        }
        return ValidationOutcome::new(violations);
    }

    match field.field_type {
        FieldType::Text => check_text(value, &field.config, &mut violations),
        FieldType::Number => check_number(value, &field.config, &mut violations),
        FieldType::Boolean => {
            if !value.is_boolean() {
                violations.push(FieldViolation::WrongType { expected: "boolean" });
            }
        }
        FieldType::Date => {
            check_string_with(value, &mut violations, is_canonical_date, "a date as YYYY-MM-DD")
        }
        FieldType::DateTime => check_string_with(
            value,
            &mut violations,
            is_canonical_datetime,
            "an RFC 3339 timestamp in UTC",
        ),
        FieldType::User | FieldType::Group | FieldType::Taxonomy | FieldType::Reference => {
            check_string_with(
                value,
                &mut violations,
                |s| uuid::Uuid::parse_str(s).is_ok(),
                "a UUID",
            );
        }
        FieldType::Choice => check_choice(value, &field.config, &mut violations),
        FieldType::MultiChoice => check_multi_choice(value, &field.config, &mut violations),
        FieldType::Url => {
            check_string_with(value, &mut violations, is_permitted_url, "an absolute http(s) URL")
        }
        FieldType::Email => {
            check_string_with(value, &mut violations, is_email_shaped, "an email address")
        }
        FieldType::Json => check_json(value, &field.config, &mut violations),
    }

    ValidationOutcome::new(violations)
}

fn check_text(value: &Value, config: &FieldConfig, violations: &mut Vec<FieldViolation>) {
    let Some(text) = value.as_str() else {
        violations.push(FieldViolation::WrongType { expected: "string" });
        return;
    };

    // Characters, not bytes. A limit of 10 that accepts three emoji and rejects four Japanese
    // characters is a limit that behaves differently depending on the writer's language, which is
    // the sort of thing `docs/14-I18N-L10N.md` exists to prevent.
    let length = text.chars().count();
    if let Some(max) = config.max_length {
        if length > max {
            violations.push(FieldViolation::TooLong { max, actual: length });
        }
    }
    if let Some(min) = config.min_length {
        if length < min {
            violations.push(FieldViolation::TooShort { min, actual: length });
        }
    }
    // A NUL in text reaches PostgreSQL as an invalid byte sequence in a `text` column and reaches
    // most consumers as a truncation point. Refused rather than stripped: silently altering a value
    // and storing it means the record no longer says what the caller sent.
    if text.contains('\0') {
        violations.push(FieldViolation::IllegalCharacter);
    }
}

fn check_number(value: &Value, config: &FieldConfig, violations: &mut Vec<FieldViolation>) {
    let Some(number) = value.as_f64() else {
        // Deliberately not `value.as_str().and_then(parse)`. See the module documentation.
        violations.push(FieldViolation::WrongType { expected: "number" });
        return;
    };
    // JSON has no NaN or infinity, but a `serde_json::Value` built in-process can hold one, and an
    // arbitrary-precision feature can produce a value that is finite as text and not as `f64`.
    if !number.is_finite() {
        violations.push(FieldViolation::WrongType { expected: "a finite number" });
        return;
    }
    if let Some(min) = config.min {
        if number < min {
            violations.push(FieldViolation::OutOfRange);
        }
    }
    if let Some(max) = config.max {
        if number > max {
            violations.push(FieldViolation::OutOfRange);
        }
    }
}

fn check_choice(value: &Value, config: &FieldConfig, violations: &mut Vec<FieldViolation>) {
    let Some(selected) = value.as_str() else {
        violations.push(FieldViolation::WrongType { expected: "string" });
        return;
    };
    match config.choices.as_ref() {
        // A choice field with no choices accepts nothing. The alternative — accept anything — turns
        // a misconfigured field into a free-text field that claims to be constrained.
        None => violations.push(FieldViolation::NotAChoice),
        Some(choices) if !choices.iter().any(|c| c == selected) => {
            violations.push(FieldViolation::NotAChoice);
        }
        Some(_) => {}
    }
}

fn check_multi_choice(value: &Value, config: &FieldConfig, violations: &mut Vec<FieldViolation>) {
    let Some(items) = value.as_array() else {
        violations.push(FieldViolation::WrongType { expected: "array of strings" });
        return;
    };

    if let Some(max) = config.max_selections {
        if items.len() > max {
            violations.push(FieldViolation::TooManySelections { max, actual: items.len() });
        }
    }

    let mut seen: Vec<&str> = Vec::with_capacity(items.len());
    for item in items {
        let Some(selected) = item.as_str() else {
            violations.push(FieldViolation::WrongType { expected: "array of strings" });
            continue;
        };
        // Duplicates are refused rather than deduplicated, for the same reason nothing here
        // coerces: the stored value should be what the caller sent, or an error.
        if seen.contains(&selected) {
            violations.push(FieldViolation::DuplicateSelection);
        }
        seen.push(selected);
        match config.choices.as_ref() {
            None => violations.push(FieldViolation::NotAChoice),
            Some(choices) if !choices.iter().any(|c| c == selected) => {
                violations.push(FieldViolation::NotAChoice);
            }
            Some(_) => {}
        }
    }
}

fn check_json(value: &Value, config: &FieldConfig, violations: &mut Vec<FieldViolation>) {
    let max_depth = config.max_depth.unwrap_or(DEFAULT_MAX_JSON_DEPTH);
    let max_bytes = config.max_bytes.unwrap_or(DEFAULT_MAX_JSON_BYTES);

    // Depth first, and **returning** on failure rather than continuing to the size check. That
    // ordering is not stylistic: `serde_json`'s serializer recurses, so measuring the size of an
    // over-deep value overflows the stack — the defence dying on the input it exists to reject.
    // Found by the test below, which is why it constructs ten thousand levels rather than
    // thirty-three.
    //
    // A value arriving over the wire is already bounded: `serde_json`'s parser refuses beyond 128
    // levels. This check is for the rest — values assembled in-process, or arriving through a
    // future decoder with different limits — and it must not assume the parser ran first.
    if depth(value, max_depth) > max_depth {
        violations.push(FieldViolation::TooDeep { max: max_depth });
        return;
    }

    // Measured on the serialization, because that is what is stored and what every consumer parses.
    let size = serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
    if size > max_bytes {
        violations.push(FieldViolation::TooLarge { max: max_bytes });
    }
}

/// Depth of a JSON value, stopping once the limit is exceeded.
///
/// Bounded rather than exhaustive, and iterative rather than recursive: the input is
/// attacker-controlled, and a recursive depth check on a deeply nested document overflows the stack
/// while measuring whether the document is too deep. Returns `limit + 1` as soon as that is known,
/// which is all the caller needs.
fn depth(value: &Value, limit: usize) -> usize {
    let mut deepest = 0_usize;
    let mut stack = vec![(value, 1_usize)];

    while let Some((node, level)) = stack.pop() {
        deepest = deepest.max(level);
        if level > limit {
            return limit + 1;
        }
        match node {
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, level + 1))),
            Value::Object(entries) => {
                stack.extend(entries.values().map(|entry| (entry, level + 1)));
            }
            _ => {}
        }
    }
    deepest
}

fn check_string_with(
    value: &Value,
    violations: &mut Vec<FieldViolation>,
    predicate: impl Fn(&str) -> bool,
    expected: &'static str,
) {
    match value.as_str() {
        Some(text) if predicate(text) => {}
        Some(_) => violations.push(FieldViolation::WrongFormat { expected }),
        None => violations.push(FieldViolation::WrongType { expected: "string" }),
    }
}

/// Whether a URL is absolute and uses a scheme safe to put in an `href`.
///
/// An allowlist, not a denylist. A metadata value ends up rendered as a link, and `javascript:`,
/// `data:` and `vbscript:` are all URLs — a denylist would need to know every scheme a browser has
/// ever supported, and it would be wrong about the next one.
fn is_permitted_url(raw: &str) -> bool {
    let Some((scheme, rest)) = raw.split_once("://") else { return false };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    // A host is required: `https://` alone parses as a scheme with nothing after it.
    !rest.is_empty() && !rest.starts_with('/') && !rest.contains(char::is_whitespace)
}

/// Whether a date is written in the one form that sorts correctly.
///
/// `chrono` parses `2026-8-2` happily, and it is an unambiguous date — but `metadata_values`
/// projects the value into `value_text`, and that column is what a library sorts and filters by.
/// As text, `2026-8-2` sorts *after* `2026-12-01`, so a lenient parse here produces a column that
/// silently orders wrong.
///
/// The check is a round trip rather than a pattern: parse it, format it canonically, and require
/// the two to be identical. That refuses the non-canonical form without rewriting it, which is the
/// crate's rule — a stored value that differs from what the caller sent is a record that quietly
/// disagrees with the system that sent it.
fn is_canonical_date(raw: &str) -> bool {
    chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .is_ok_and(|date| date.format("%Y-%m-%d").to_string() == raw)
}

/// Whether a timestamp is written in the one form that sorts correctly.
///
/// The same argument as [`is_canonical_date`], and it bites harder: RFC 3339 permits `Z` and
/// `+00:00` for the same instant, and any number of fractional digits. All of those sort
/// differently as text while meaning the same moment, so a column holding a mixture cannot be
/// ordered at all.
///
/// The canonical form is UTC with `Z` and second precision. An offset that is not UTC is refused
/// rather than converted, for the same reason nothing else here is coerced.
fn is_canonical_datetime(raw: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(raw).is_ok_and(|instant| {
        instant.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%SZ").to_string() == raw
    })
}

/// Whether a string is shaped like an email address.
///
/// Deliberately shallow. RFC 5322 permits things no mail server accepts, and a validator that
/// implements it rejects addresses that work while accepting ones that do not. The only way to know
/// an address is real is to send to it, which is `docs/13-IDENTITY-SSO-SCIM.md`'s problem, not this
/// module's. This checks for exactly one `@`, something either side, a dot in the domain, and no
/// whitespace or control characters — which catches typos and injection attempts, and nothing else.
fn is_email_shaped(raw: &str) -> bool {
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let Some((local, domain)) = raw.split_once('@') else { return false };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}
