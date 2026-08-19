//! Field validation, attacked rather than demonstrated.
//!
//! Every test here supplies something a well-behaved client would not, because a validator tested
//! only with valid input is a validator whose failure cases have never executed. The recurring
//! theme is `crate`'s central rule: **reject, never coerce** — so each type is given the value a
//! lenient implementation would happily convert, and the assertion is that it does not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{TenantId, Uuid};
use enclave_metadata::{
    validate, FieldConfig, FieldScope, FieldType, FieldViolation, MetadataField,
    DEFAULT_MAX_JSON_DEPTH,
};
use serde_json::json;

fn field(field_type: FieldType, config: FieldConfig) -> MetadataField {
    MetadataField {
        id: Uuid::nil(),
        tenant_id: TenantId::from(Uuid::nil()),
        scope: FieldScope::Tenant,
        scope_id: None,
        key: "field".to_owned(),
        label: "Field".to_owned(),
        field_type,
        required: false,
        indexed: false,
        config,
        created_at: Utc::now(),
    }
}

fn required(field_type: FieldType) -> MetadataField {
    MetadataField { required: true, ..field(field_type, FieldConfig::default()) }
}

/// The rule, asserted once per type that a lenient implementation would coerce.
///
/// Each of these is something a permissive validator accepts and converts. `"42"` into a number is
/// the one everybody writes; the others follow from it, because once one string is parsed the next
/// reviewer sees a precedent rather than a decision.
#[test]
fn nothing_is_coerced_from_a_string() {
    let cases = [
        (FieldType::Number, json!("42"), "a numeric string"),
        (FieldType::Number, json!("1e999"), "a string that overflows f64"),
        (FieldType::Boolean, json!("true"), "a boolean-looking string"),
        (FieldType::Boolean, json!(1), "the integer one"),
        (FieldType::Boolean, json!("yes"), "a word some languages call truthy"),
        (FieldType::Text, json!(42), "a number where text is expected"),
        (FieldType::Text, json!(true), "a boolean where text is expected"),
        (FieldType::MultiChoice, json!("a"), "a bare string where an array is expected"),
    ];

    for (field_type, value, what) in cases {
        let outcome = validate(&field(field_type, FieldConfig::default()), Some(&value));
        assert!(
            !outcome.is_valid(),
            "{field_type} accepted {what} — once one string is parsed, the next reviewer sees a \
             precedent rather than a decision"
        );
    }
}

/// `null` is absence written out, and must not satisfy a required field.
#[test]
fn an_explicit_null_does_not_satisfy_a_required_field() {
    for value in [None, Some(&json!(null))] {
        let outcome = validate(&required(FieldType::Text), value);
        assert_eq!(outcome.violations(), &[FieldViolation::Required]);
    }
    // And an optional field is content with either.
    assert!(
        validate(&field(FieldType::Text, FieldConfig::default()), Some(&json!(null))).is_valid()
    );
}

/// Length is counted in characters, so a limit does not depend on the writer's language.
#[test]
fn text_length_is_measured_in_characters_not_bytes() {
    let config = FieldConfig { max_length: Some(4), ..FieldConfig::default() };
    let text = field(FieldType::Text, config);

    // Four characters, twelve bytes. A byte-counting validator would reject this while accepting
    // four ASCII characters — a rule that means something different in Japanese than in English.
    assert!(validate(&text, Some(&json!("日本語で"))).is_valid());
    assert!(!validate(&text, Some(&json!("日本語です"))).is_valid());
    assert!(validate(&text, Some(&json!("abcd"))).is_valid());
    assert!(!validate(&text, Some(&json!("abcde"))).is_valid());
}

/// A NUL is refused rather than stripped.
#[test]
fn a_nul_byte_is_refused_rather_than_silently_removed() {
    let outcome = validate(&field(FieldType::Text, FieldConfig::default()), Some(&json!("a\0b")));
    assert!(outcome.violations().contains(&FieldViolation::IllegalCharacter));
}

/// A choice field with no choices accepts nothing.
///
/// The alternative — accept anything when unconfigured — turns a misconfigured field into a
/// free-text field that still claims in its type to be constrained.
#[test]
fn a_choice_field_without_choices_accepts_nothing() {
    let outcome = validate(&field(FieldType::Choice, FieldConfig::default()), Some(&json!("any")));
    assert_eq!(outcome.violations(), &[FieldViolation::NotAChoice]);
}

#[test]
fn multi_choice_refuses_duplicates_rather_than_deduplicating() {
    let config = FieldConfig {
        choices: Some(vec!["a".to_owned(), "b".to_owned()]),
        ..FieldConfig::default()
    };
    let multi = field(FieldType::MultiChoice, config);

    assert!(validate(&multi, Some(&json!(["a", "b"]))).is_valid());

    let duplicated = validate(&multi, Some(&json!(["a", "a"])));
    assert!(duplicated.violations().contains(&FieldViolation::DuplicateSelection));

    let unknown = validate(&multi, Some(&json!(["a", "c"])));
    assert!(unknown.violations().contains(&FieldViolation::NotAChoice));
}

/// URLs are checked against an allowlist of schemes, because a metadata value becomes an `href`.
///
/// A denylist would need to know every scheme a browser has ever supported and would be wrong about
/// the next one.
#[test]
fn only_http_and_https_urls_are_accepted() {
    let url = field(FieldType::Url, FieldConfig::default());

    for good in ["https://example.test/a", "http://example.test"] {
        assert!(validate(&url, Some(&json!(good))).is_valid(), "{good} was rejected");
    }

    for hostile in [
        "javascript://example.test/%0aalert(1)",
        "data://text/html,<script>alert(1)</script>",
        "vbscript://example.test",
        "file:///etc/passwd",
        "//example.test",
        "https://",
        "not a url",
    ] {
        assert!(
            !validate(&url, Some(&json!(hostile))).is_valid(),
            "`{hostile}` was accepted, and a metadata value ends up rendered as a link"
        );
    }
}

#[test]
fn email_validation_catches_typos_without_pretending_to_be_rfc_5322() {
    let email = field(FieldType::Email, FieldConfig::default());

    for good in ["a@example.test", "first.last+tag@sub.example.test"] {
        assert!(validate(&email, Some(&json!(good))).is_valid(), "{good} was rejected");
    }
    for bad in ["", "@example.test", "a@", "a@b", "a@@b.test", "a b@example.test", "a@.test"] {
        assert!(!validate(&email, Some(&json!(bad))).is_valid(), "`{bad}` was accepted");
    }
}

/// A deeply nested `JSON` value is refused — through the path a value actually arrives by.
///
/// The first version of this test built ten thousand levels with the `json!` macro and crashed the
/// test binary. Not in the validator: `serde_json::Value`'s `Drop` is recursive, so *constructing*
/// the input overflowed the stack before anything examined it. Chasing that produced the more
/// useful fact, pinned below — a value arriving over the wire cannot exceed 127 levels, because
/// `serde_json`'s parser refuses at 128.
///
/// So the realistic worst case is 127, and that is what this asserts, parsed from text rather than
/// assembled in-process. The limit being defended is 32; the parser's 128 is the layer above it,
/// and both are worth having, because a future decoder with different limits would sit behind this
/// check and not behind that one.
#[test]
fn the_deepest_json_a_client_can_send_is_refused() {
    let deepest_sendable = format!("{}1{}", "[".repeat(127), "]".repeat(127));
    let value: serde_json::Value =
        serde_json::from_str(&deepest_sendable).expect("127 levels is within the parser's limit");

    let outcome = validate(&field(FieldType::Json, FieldConfig::default()), Some(&value));
    assert!(
        outcome.violations().iter().any(|v| matches!(v, FieldViolation::TooDeep { .. })),
        "the deepest value a client can send was accepted against a limit of {DEFAULT_MAX_JSON_DEPTH}"
    );

    // And the boundary is where it says it is.
    let at_limit: serde_json::Value = serde_json::from_str(&format!(
        "{}1{}",
        "[".repeat(DEFAULT_MAX_JSON_DEPTH - 1),
        "]".repeat(DEFAULT_MAX_JSON_DEPTH - 1)
    ))
    .expect("within the parser's limit");
    assert!(validate(&field(FieldType::Json, FieldConfig::default()), Some(&at_limit)).is_valid());
}

/// The upstream bound this crate's analysis rests on, pinned so it cannot move silently.
///
/// `check_json` returns before measuring size when a value is too deep, because `serde_json`'s
/// serializer recurses. That ordering is only *sufficient* because nothing deeper than 127 can
/// reach it from a client. If a `serde_json` upgrade raised or removed this limit, that reasoning
/// would need redoing — so the limit is asserted here rather than assumed in a comment.
#[test]
fn serde_json_refuses_to_parse_beyond_128_levels() {
    let within = format!("{}1{}", "[".repeat(127), "]".repeat(127));
    assert!(serde_json::from_str::<serde_json::Value>(&within).is_ok());

    let beyond = format!("{}1{}", "[".repeat(128), "]".repeat(128));
    assert!(
        serde_json::from_str::<serde_json::Value>(&beyond).is_err(),
        "serde_json now parses deeper than 128 levels — re-check `check_json`'s ordering, which \
         relies on nothing deeper than that reaching it"
    );
}

#[test]
fn an_oversized_json_value_is_refused() {
    let config = FieldConfig { max_bytes: Some(64), ..FieldConfig::default() };
    let big = json!({ "note": "x".repeat(200) });
    let outcome = validate(&field(FieldType::Json, config), Some(&big));
    assert!(outcome.violations().iter().any(|v| matches!(v, FieldViolation::TooLarge { .. })));
}

#[test]
fn number_bounds_are_inclusive_and_non_finite_values_are_refused() {
    let config = FieldConfig { min: Some(1.0), max: Some(10.0), ..FieldConfig::default() };
    let number = field(FieldType::Number, config);

    assert!(validate(&number, Some(&json!(1))).is_valid());
    assert!(validate(&number, Some(&json!(10))).is_valid());
    assert!(!validate(&number, Some(&json!(0.999))).is_valid());
    assert!(!validate(&number, Some(&json!(10.001))).is_valid());
}

/// Dates and timestamps are parsed, not pattern-matched.
#[test]
fn dates_that_look_right_but_are_not_dates_are_refused() {
    let date = field(FieldType::Date, FieldConfig::default());
    assert!(validate(&date, Some(&json!("2026-08-20"))).is_valid());
    for bad in ["2026-02-30", "2026-13-01", "20-08-2026", "2026-8-2", "2026-08-20T00:00:00Z"] {
        assert!(!validate(&date, Some(&json!(bad))).is_valid(), "`{bad}` was accepted as a date");
    }

    let datetime = field(FieldType::DateTime, FieldConfig::default());
    assert!(validate(&datetime, Some(&json!("2026-08-20T14:07:00Z"))).is_valid());
    for bad in [
        // No offset: an instant without one is a local time, and storing it as an instant picks a
        // time zone on the writer's behalf.
        "2026-08-20T14:07:00",
        // The same instant, three spellings. All sort differently as text, and `value_text` is
        // what a library orders by — so a column holding a mixture cannot be ordered at all.
        "2026-08-20T14:07:00+00:00",
        "2026-08-20T14:07:00.000Z",
        "2026-08-20T15:07:00+01:00",
    ] {
        assert!(
            !validate(&datetime, Some(&json!(bad))).is_valid(),
            "`{bad}` was accepted, so the sort order of this column depends on how each client \
             happens to spell an instant"
        );
    }
}

/// Every violation is reported, not just the first.
#[test]
fn a_value_with_several_problems_reports_all_of_them() {
    let config = FieldConfig {
        choices: Some(vec!["a".to_owned()]),
        max_selections: Some(1),
        ..FieldConfig::default()
    };
    let outcome = validate(&field(FieldType::MultiChoice, config), Some(&json!(["b", "b", "c"])));

    assert!(outcome.violations().len() >= 3, "{:?}", outcome.violations());
    assert!(outcome.violations().contains(&FieldViolation::DuplicateSelection));
    assert!(outcome.violations().contains(&FieldViolation::NotAChoice));
    assert!(outcome
        .violations()
        .iter()
        .any(|v| matches!(v, FieldViolation::TooManySelections { .. })));
}

/// The four naming types accept only well-formed identifiers here; existence is checked elsewhere.
#[test]
fn naming_types_check_shape_and_leave_existence_to_the_repository() {
    for field_type in [FieldType::User, FieldType::Group, FieldType::Taxonomy, FieldType::Reference]
    {
        let f = field(field_type, FieldConfig::default());
        // Well-formed and almost certainly nonexistent — and accepted here, deliberately.
        // `repo::validate_references` is what resolves it, under a tenant predicate, so that an
        // unresolvable reference and another tenant's resource are indistinguishable.
        assert!(validate(&f, Some(&json!(Uuid::now_v7().to_string()))).is_valid());
        assert!(!validate(&f, Some(&json!("not-a-uuid"))).is_valid());
        assert!(!validate(&f, Some(&json!(42))).is_valid());
    }
}
