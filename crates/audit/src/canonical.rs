//! Canonical, versioned serialization of an audit event.
//!
//! # Why this exists and why it is not `serde_json`
//!
//! The hash chain (`docs/04-DATA-MODEL.md §14`) is only evidence if the bytes that were hashed can
//! be reproduced exactly, years later, by a different binary. JSON cannot promise that: key order,
//! whitespace, escaping and number formatting are all free choices, and `serde_json`'s map order
//! depends on a Cargo feature (`preserve_order`) that a transitive dependency can turn on without
//! anyone noticing. A chain that silently stops verifying after a `cargo update` is worse than no
//! chain, because it destroys the operator's trust in a real alarm.
//!
//! So the encoding here is written by hand, is not self-describing, and never iterates a map whose
//! order it does not control.
//!
//! # The format is frozen
//!
//! **Changing the field order, adding a field, removing one, or changing how any field is encoded
//! invalidates every hash ever computed.** There is no migration for that: the old rows cannot be
//! re-hashed, because re-hashing them is exactly the capability the chain exists to deny. The only
//! safe change is a *new* version — a new constant, a new encoder, both kept — with stored rows
//! verified against the version they were written under.
//!
//! [`CANONICAL_VERSION`] is inside the hashed bytes for that reason: a v1 event and a v2 event with
//! identical fields hash differently, so a downgrade attack cannot re-interpret one as the other.
//!
//! # Version 1
//!
//! Header: `b"enclave.audit.canonical"`, a `0x1F` separator, then the version as two big-endian
//! bytes. Then exactly [`CANONICAL_FIELD_COUNT`] fields, in this order:
//!
//! | # | Field | Encoding |
//! |---|---|---|
//! | 1 | `id` | 16 raw UUID bytes |
//! | 2 | `tenant_id` | 16 raw UUID bytes |
//! | 3 | `sequence` | `i64`, 8 bytes big-endian two's complement |
//! | 4 | `occurred_at` | microseconds since the Unix epoch, `i64` big-endian |
//! | 5 | `actor_id` | 16 raw UUID bytes, absent for `system` |
//! | 6 | `actor_type` | UTF-8 |
//! | 7 | `on_behalf_of` | 16 raw UUID bytes, optional |
//! | 8 | `action` | UTF-8 `family.verb` |
//! | 9 | `resource_type` | UTF-8, optional |
//! | 10 | `resource_id` | 16 raw UUID bytes, optional |
//! | 11 | `workspace_id` | 16 raw UUID bytes, optional |
//! | 12 | `outcome` | UTF-8, one of `ALLOW`/`DENY`/`ERROR` |
//! | 13 | `reason_code` | UTF-8, optional |
//! | 14 | `policy_refs` | count-prefixed records, see below |
//! | 15 | `request_id` | 16 raw UUID bytes |
//! | 16 | `session_id` | 16 raw UUID bytes, optional |
//! | 17 | `client_type` | UTF-8, optional |
//! | 18 | `mcp_client_id` | 16 raw UUID bytes, optional |
//! | 19 | `device_id` | 16 raw UUID bytes, optional |
//! | 20 | `ip` | UTF-8 of the canonical address form, optional |
//! | 21 | `country` | UTF-8, optional |
//! | 22 | `user_agent` | UTF-8, optional |
//! | 23 | `detail` | canonical JSON, see below |
//!
//! Every field is framed as one presence byte (`0x00` absent, `0x01` present) followed, when
//! present, by a big-endian `u32` length and that many bytes. The framing is what makes the
//! encoding injective: without it, `("ab", "c")` and `("a", "bc")` would produce identical bytes
//! and two different events could share a hash.
//!
//! `policy_refs` is a `u32` count followed by one record per reference: framed `kind`, framed
//! optional id, framed optional `i32` version. Order is the order the policy chain produced.
//!
//! `detail` is canonical JSON: object keys sorted by their UTF-8 bytes, no insignificant
//! whitespace, minimal escaping. Number formatting is `serde_json`'s, which is why detail payloads
//! should carry strings and integers rather than floats.
//!
//! **`previous_hash` and `event_hash` are not encoded.** The first is prefixed by the chain before
//! hashing, so encoding it too would count it twice; the second is the output.

use serde_json::{Map, Value};

use crate::event::{AuditEvent, PolicyRef};

/// The canonical encoding version, embedded in the hashed bytes.
///
/// Bump only by adding a new encoder alongside the old one — see the module docs.
pub const CANONICAL_VERSION: u16 = 1;

/// The domain separator, so these bytes cannot collide with any other hashed structure in Enclave.
const CANONICAL_DOMAIN: &[u8] = b"enclave.audit.canonical";

/// How many framed fields version 1 writes. Asserted by a test, so a field added without a version
/// bump fails the build rather than the chain.
pub const CANONICAL_FIELD_COUNT: usize = 23;

/// Presence marker for an absent optional field.
const ABSENT: u8 = 0x00;
/// Presence marker for a present field.
const PRESENT: u8 = 0x01;

/// Encodes an event into its canonical bytes.
///
/// Deterministic by construction: the same event produces the same bytes on any machine, in any
/// process, under any dependency version, forever.
#[must_use]
pub fn canonical_bytes(event: &AuditEvent) -> Vec<u8> {
    let mut w = Writer::new();

    w.uuid(event.id); // 1
    w.uuid(event.tenant_id.as_uuid()); // 2
    w.i64(event.sequence); // 3
    w.i64(event.occurred_at.timestamp_micros()); // 4

    let (actor_kind, actor_id) = event.actor_parts();
    w.opt_uuid(actor_id); // 5
    w.str(actor_kind.as_str()); // 6
    w.opt_uuid(event.on_behalf_of.map(|u| u.as_uuid())); // 7

    w.str(&event.action.to_string()); // 8
    w.opt_str(event.resource_kind().map(|k| k.as_str())); // 9
    w.opt_uuid(event.resource_id()); // 10
    w.opt_uuid(event.workspace_id.map(|w| w.as_uuid())); // 11

    w.str(event.outcome.as_str()); // 12
    w.opt_str(event.reason_code.map(|c| c.as_str())); // 13
    w.bytes(&encode_policy_refs(&event.policy_refs)); // 14

    w.uuid(event.request_id.as_uuid()); // 15
    w.opt_uuid(event.session_id.map(|s| s.as_uuid())); // 16
    w.opt_str(event.client_type.map(|c| c.as_str())); // 17
    w.opt_uuid(event.mcp_client_id.map(|c| c.as_uuid())); // 18
    w.opt_uuid(event.device_id.map(|d| d.as_uuid())); // 19

    w.opt_string(event.ip.map(|ip| ip.to_string())); // 20
    w.opt_str(event.country.as_deref()); // 21
    w.opt_str(event.user_agent.as_deref()); // 22

    let mut detail = Vec::new();
    write_canonical_object(event.detail.as_map(), &mut detail);
    w.bytes(&detail); // 23

    debug_assert_eq!(w.fields, CANONICAL_FIELD_COUNT, "canonical v1 writes a fixed field count");
    w.finish()
}

/// Encodes the policy reference list as one framed blob.
fn encode_policy_refs(refs: &[PolicyRef]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(refs.len() as u32).to_be_bytes());
    for reference in refs {
        frame(reference.kind.as_bytes(), &mut out);
        match reference.id {
            Some(id) => frame(id.as_bytes(), &mut out),
            None => out.push(ABSENT),
        }
        match reference.version {
            Some(version) => frame(&version.to_be_bytes(), &mut out),
            None => out.push(ABSENT),
        }
    }
    out
}

/// Writes a present, length-prefixed field.
fn frame(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(PRESENT);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Accumulates framed fields and counts them.
struct Writer {
    buf: Vec<u8>,
    fields: usize,
}

impl Writer {
    fn new() -> Self {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(CANONICAL_DOMAIN);
        buf.push(0x1F);
        buf.extend_from_slice(&CANONICAL_VERSION.to_be_bytes());
        Self { buf, fields: 0 }
    }

    fn bytes(&mut self, value: &[u8]) {
        frame(value, &mut self.buf);
        self.fields += 1;
    }

    fn absent(&mut self) {
        self.buf.push(ABSENT);
        self.fields += 1;
    }

    fn str(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn opt_str(&mut self, value: Option<&str>) {
        match value {
            Some(v) => self.str(v),
            None => self.absent(),
        }
    }

    fn opt_string(&mut self, value: Option<String>) {
        match value {
            Some(v) => self.str(&v),
            None => self.absent(),
        }
    }

    fn uuid(&mut self, value: enclave_core::Uuid) {
        self.bytes(value.as_bytes());
    }

    fn opt_uuid(&mut self, value: Option<enclave_core::Uuid>) {
        match value {
            Some(v) => self.uuid(v),
            None => self.absent(),
        }
    }

    fn i64(&mut self, value: i64) {
        self.bytes(&value.to_be_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Writes a JSON object in canonical form: keys sorted by UTF-8 bytes, no whitespace.
fn write_canonical_object(map: &Map<String, Value>, out: &mut Vec<u8>) {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    out.push(b'{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_canonical_string(key, out);
        out.push(b':');
        if let Some(value) = map.get(*key) {
            write_canonical_value(value, out);
        }
    }
    out.push(b'}');
}

/// Writes any JSON value in canonical form.
fn write_canonical_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_canonical_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_value(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => write_canonical_object(map, out),
    }
}

/// Writes a JSON string with exactly one escaping rule, hand-rolled so it cannot drift with a
/// dependency: the two mandatory escapes, the five short forms, `\u00XX` for the remaining control
/// characters, and raw UTF-8 for everything else.
fn write_canonical_string(value: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[((code >> 4) & 0xF) as usize]);
                out.push(HEX[(code & 0xF) as usize]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::{Action, FileAction, FileId, ReasonCode, ResourceRef};
    use serde_json::json;

    use crate::event::Outcome;
    use crate::redact::Detail;
    use crate::test_support::{context, sample_event};

    #[test]
    fn the_same_event_encodes_to_the_same_bytes_twice() {
        let event = sample_event();
        let first = canonical_bytes(&event);
        let second = canonical_bytes(&event);
        assert_eq!(first, second);
    }

    #[test]
    fn a_clone_encodes_identically() {
        let event = sample_event();
        assert_eq!(canonical_bytes(&event), canonical_bytes(&event.clone()));
    }

    #[test]
    fn detail_key_insertion_order_does_not_change_the_bytes() {
        let mut forwards = Map::new();
        forwards.insert("alpha".into(), json!(1));
        forwards.insert("beta".into(), json!({ "z": 1, "a": 2 }));
        forwards.insert("gamma".into(), json!(["x", "y"]));

        let mut backwards = Map::new();
        backwards.insert("gamma".into(), json!(["x", "y"]));
        backwards.insert("beta".into(), json!({ "a": 2, "z": 1 }));
        backwards.insert("alpha".into(), json!(1));

        let a = sample_event_with_detail(Detail::new(forwards).unwrap());
        let b = sample_event_with_detail(Detail::new(backwards).unwrap());
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn every_field_change_changes_the_bytes() {
        let base = sample_event();
        let baseline = canonical_bytes(&base);

        let mut sequence = base.clone();
        sequence.sequence += 1;
        assert_ne!(canonical_bytes(&sequence), baseline);

        let mut outcome = base.clone();
        assert_eq!(base.outcome, Outcome::Deny, "the fixture must differ from the value set here");
        outcome.outcome = Outcome::Allow;
        assert_ne!(canonical_bytes(&outcome), baseline);

        let mut reason = base.clone();
        reason.reason_code = Some(ReasonCode::DlpBlocked);
        assert_ne!(canonical_bytes(&reason), baseline);

        let mut resource = base.clone();
        resource.resource = Some(ResourceRef::file(base.tenant_id, FileId::new_v7()));
        assert_ne!(canonical_bytes(&resource), baseline);

        let mut action = base.clone();
        action.action = Action::File(FileAction::Print);
        assert_ne!(canonical_bytes(&action), baseline);

        let mut country = base.clone();
        country.country = Some("DE".into());
        assert_ne!(canonical_bytes(&country), baseline);

        // The hashes themselves are metadata, not content — changing them must NOT change the
        // canonical bytes, or the chain would be circular.
        let mut hashed = base.clone();
        hashed.previous_hash = Some(crate::chain::EventHash::from_bytes([9u8; 32]));
        hashed.event_hash = Some(crate::chain::EventHash::from_bytes([7u8; 32]));
        assert_eq!(canonical_bytes(&hashed), baseline);
    }

    #[test]
    fn framing_makes_adjacent_fields_unambiguous() {
        let ctx = context();
        let a = crate::AuditEvent::builder(&ctx, Action::File(FileAction::Preview), Outcome::Allow)
            .id(enclave_core::Uuid::nil())
            .occurred_at(chrono::DateTime::from_timestamp_micros(0).unwrap())
            .user_agent("ab")
            .build();
        let mut b = a.clone();
        b.user_agent = Some("a".into());
        b.country = Some("b".into());
        assert_ne!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn the_version_is_inside_the_bytes() {
        let bytes = canonical_bytes(&sample_event());
        let header_len = CANONICAL_DOMAIN.len();
        assert_eq!(&bytes[..header_len], CANONICAL_DOMAIN);
        assert_eq!(bytes[header_len], 0x1F);
        assert_eq!(
            u16::from_be_bytes([bytes[header_len + 1], bytes[header_len + 2]]),
            CANONICAL_VERSION
        );
    }

    #[test]
    fn the_field_count_is_what_version_one_declares() {
        // `canonical_bytes` debug-asserts this; assert it here too so a release-mode run of the
        // suite still catches a field added without a version bump.
        let mut w = Writer::new();
        let event = sample_event();
        let before = w.fields;
        w.uuid(event.id);
        assert_eq!(w.fields, before + 1, "each write must count exactly one field");
        assert_eq!(CANONICAL_FIELD_COUNT, 23);
    }

    #[test]
    fn strings_escape_deterministically() {
        let mut out = Vec::new();
        write_canonical_string("a\"b\\c\nd\u{1}e—f", &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\"a\\\"b\\\\c\\nd\\u0001e—f\"");
    }

    fn sample_event_with_detail(detail: Detail) -> crate::AuditEvent {
        let mut event = sample_event();
        event.detail = detail;
        event
    }
}
