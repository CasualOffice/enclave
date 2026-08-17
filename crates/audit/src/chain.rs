//! The tamper-evidence hash chain (`docs/04-DATA-MODEL.md §14`).
//!
//! `event_hash = SHA256(previous_hash || canonical_event)`, chained per tenant in `sequence` order.
//!
//! # What a chain does and does not prove
//!
//! It proves that no row was **edited** and that no row was **removed from the middle** without
//! recomputing every hash after it — which an attacker with `UPDATE` cannot do, because migration
//! `0002` grants the application `INSERT` and `SELECT` only.
//!
//! It does not, on its own, detect truncation of the *head*: an attacker who can delete the last
//! `n` rows leaves a shorter but internally consistent chain. That is why `docs/04 §14` anchors the
//! chain head to an external sink. Verification here reports what it can see; the anchor is what
//! makes the head trustworthy.
//!
//! # Reporting the first divergence, not a boolean
//!
//! [`verify_chain`] returns the sequence number where the chain first stops agreeing with itself,
//! because that number is the investigation. "The chain is invalid" tells an operator to restore a
//! backup; "the chain diverges at sequence 4 812 951, content mismatch" tells them which row was
//! edited, when, and by extension roughly when the compromise began.

use sha2::{Digest, Sha256};

use crate::canonical::canonical_bytes;
use crate::error::HashLengthError;
use crate::event::AuditEvent;

/// A SHA-256 digest: one link of the chain.
///
/// A newtype rather than `Vec<u8>` so a 20-byte value or a hex string cannot be mistaken for one,
/// and so `Debug` prints hex instead of an array of integers nobody can compare by eye.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventHash([u8; 32]);

impl EventHash {
    /// The digest length, in bytes.
    pub const LEN: usize = 32;

    /// Wraps a digest that is already the right length.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a digest out of a `BYTEA` column.
    ///
    /// # Errors
    ///
    /// [`HashLengthError`] if the column does not hold exactly 32 bytes, which means the row was
    /// written by something that was not this code.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashLengthError> {
        let array: [u8; Self::LEN] =
            bytes.try_into().map_err(|_| HashLengthError { len: bytes.len() })?;
        Ok(Self(array))
    }

    /// The raw digest, for binding to a `BYTEA` parameter.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The digest as lowercase hex, for logs, anchors and operator-facing output.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0F)] as char);
        }
        out
    }
}

impl std::fmt::Debug for EventHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EventHash({})", self.to_hex())
    }
}

impl std::fmt::Display for EventHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for EventHash {
    /// Hex on the wire: a SIEM record and an anchor file both need something a human can compare.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for EventHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw.len() != Self::LEN * 2 {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut bytes = [0u8; Self::LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let pair = raw
                .get(i * 2..i * 2 + 2)
                .ok_or_else(|| serde::de::Error::custom("hash is not valid hex"))?;
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| serde::de::Error::custom("hash is not valid hex"))?;
        }
        Ok(Self(bytes))
    }
}

/// Computes the hash an event should carry, given the hash of the one before it.
///
/// `previous` is `None` for the first event in a tenant's chain, in which case nothing is prefixed
/// — the literal reading of `SHA256(previous_hash || canonical_event)` with a `NULL` predecessor.
#[must_use]
pub fn compute_hash(previous: Option<&EventHash>, event: &AuditEvent) -> EventHash {
    let mut hasher = Sha256::new();
    if let Some(previous) = previous {
        hasher.update(previous.as_bytes());
    }
    hasher.update(canonical_bytes(event));
    EventHash(hasher.finalize().into())
}

/// Seals an event into the chain: records its predecessor and computes its own hash.
///
/// Must be called *after* the sequence is assigned, because the sequence is inside the canonical
/// bytes. Returns the new head, which is the caller's next `previous`.
pub fn seal(event: &mut AuditEvent, previous: Option<EventHash>) -> EventHash {
    event.previous_hash = previous;
    let hash = compute_hash(previous.as_ref(), event);
    event.event_hash = Some(hash);
    hash
}

/// How a chain stopped agreeing with itself.
///
/// Separate from the sequence number because the *kind* of divergence points at a different
/// culprit: content tampering means a row was edited in place, a broken link means a row was
/// removed or inserted, and a sequence anomaly means the ordering itself was manipulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Divergence {
    /// The row's stored hash is not the hash of its own content: it was edited after being
    /// written.
    ContentTampered {
        /// What the row's content hashes to now.
        expected: EventHash,
        /// What the row claims.
        found: EventHash,
    },
    /// The row's `previous_hash` is not the preceding row's `event_hash`: a row between them was
    /// removed, or this row was inserted.
    LinkBroken {
        /// The preceding row's hash.
        expected: Option<EventHash>,
        /// What this row points at.
        found: Option<EventHash>,
    },
    /// The row has no hash although the rest of the chain does — tamper evidence cannot be turned
    /// off for one row, so this is either corruption or a deliberate gap.
    MissingHash,
    /// Sequence numbers did not strictly increase, so the rows were not presented in chain order
    /// and any verdict on them would be meaningless.
    SequenceNotIncreasing {
        /// The sequence of the preceding row.
        previous: i64,
    },
    /// A row from a different tenant appeared in the chain. The chain is per tenant; mixing them
    /// would let one tenant's rows vouch for another's.
    TenantMismatch,
}

/// The verdict on a run of audit rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyResult {
    /// Every row hashes to what it claims and every link holds.
    Valid {
        /// How many rows were checked.
        events_checked: usize,
        /// Whether the run began at the tenant's first event — a run that starts mid-chain is
        /// internally consistent but says nothing about what came before it.
        from_genesis: bool,
        /// The chain head, to compare against an external anchor. `None` for an empty run.
        head: Option<EventHash>,
    },
    /// No row carried a hash: tamper evidence was off when these were written (`docs/08 §14`).
    /// Reported distinctly because "not chained" is a configuration fact, and calling it "valid"
    /// would let a disabled control look like a passing one.
    NotChained {
        /// How many rows were inspected before concluding this.
        events_checked: usize,
    },
    /// The chain stopped agreeing with itself. Reports the **first** offending sequence: later
    /// rows will also fail, and only the first one is evidence about where the tampering began.
    Diverged {
        /// The sequence number of the first row that did not verify.
        sequence: i64,
        /// What was wrong with it.
        divergence: Divergence,
    },
}

impl VerifyResult {
    /// Whether the run verified. `NotChained` is deliberately **not** valid — see the variant.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// The sequence number where verification first failed, if it did.
    #[must_use]
    pub const fn first_divergence(&self) -> Option<i64> {
        match self {
            Self::Diverged { sequence, .. } => Some(*sequence),
            _ => None,
        }
    }
}

/// Verifies a run of audit rows in ascending sequence order.
///
/// The run may start mid-chain — verification of ten million rows happens in pages — in which case
/// the first row's `previous_hash` is taken as given and [`VerifyResult::Valid::from_genesis`] is
/// `false`. To verify from the beginning, pass a run that starts at the tenant's first event; it is
/// recognised by its `previous_hash` being absent.
///
/// Rows must all belong to one tenant and be sorted ascending by `sequence`; both are checked
/// rather than assumed, because a verifier that trusts its input's ordering can be fooled by
/// changing the ordering.
#[must_use]
pub fn verify_chain(events: &[AuditEvent]) -> VerifyResult {
    if events.is_empty() {
        return VerifyResult::Valid { events_checked: 0, from_genesis: true, head: None };
    }
    if events.iter().all(|e| e.event_hash.is_none() && e.previous_hash.is_none()) {
        return VerifyResult::NotChained { events_checked: events.len() };
    }

    let tenant = events[0].tenant_id;
    let from_genesis = events[0].previous_hash.is_none();
    let mut previous: Option<&AuditEvent> = None;

    for event in events {
        if event.tenant_id != tenant {
            return VerifyResult::Diverged {
                sequence: event.sequence,
                divergence: Divergence::TenantMismatch,
            };
        }

        if let Some(prior) = previous {
            if event.sequence <= prior.sequence {
                return VerifyResult::Diverged {
                    sequence: event.sequence,
                    divergence: Divergence::SequenceNotIncreasing { previous: prior.sequence },
                };
            }
            if event.previous_hash != prior.event_hash {
                return VerifyResult::Diverged {
                    sequence: event.sequence,
                    divergence: Divergence::LinkBroken {
                        expected: prior.event_hash,
                        found: event.previous_hash,
                    },
                };
            }
        }

        let Some(stored) = event.event_hash else {
            return VerifyResult::Diverged {
                sequence: event.sequence,
                divergence: Divergence::MissingHash,
            };
        };

        // Recomputed against the row's *own* `previous_hash`, so an edited row is reported as
        // content tampering and a removed neighbour as a broken link. Conflating the two would
        // point an investigation at the wrong row.
        let expected = compute_hash(event.previous_hash.as_ref(), event);
        if expected != stored {
            return VerifyResult::Diverged {
                sequence: event.sequence,
                divergence: Divergence::ContentTampered { expected, found: stored },
            };
        }

        previous = Some(event);
    }

    VerifyResult::Valid {
        events_checked: events.len(),
        from_genesis,
        head: previous.and_then(|e| e.event_hash),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::TenantId;

    use crate::test_support::chained_events;

    /// The acceptance criterion in `plans/M0-FOUNDATIONS.md` ENC-107.
    #[test]
    fn ten_thousand_events_verify() {
        let events = chained_events(10_000);
        match verify_chain(&events) {
            VerifyResult::Valid { events_checked, from_genesis, head } => {
                assert_eq!(events_checked, 10_000);
                assert!(from_genesis);
                assert_eq!(head, events[9_999].event_hash);
            }
            other => panic!("expected a valid chain, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_run_is_vacuously_valid() {
        assert!(verify_chain(&[]).is_valid());
    }

    #[test]
    fn unchained_events_are_reported_as_not_chained() {
        let mut events = chained_events(5);
        for event in &mut events {
            event.previous_hash = None;
            event.event_hash = None;
        }
        assert_eq!(verify_chain(&events), VerifyResult::NotChained { events_checked: 5 });
    }

    #[test]
    fn a_run_that_starts_mid_chain_is_valid_but_not_from_genesis() {
        let events = chained_events(100);
        match verify_chain(&events[50..]) {
            VerifyResult::Valid { events_checked, from_genesis, .. } => {
                assert_eq!(events_checked, 50);
                assert!(!from_genesis);
            }
            other => panic!("expected valid, got {other:?}"),
        }
    }

    /// Tamper detection must name the first divergent sequence, not merely say "invalid".
    #[test]
    fn an_edited_row_is_detected_and_its_sequence_reported() {
        let mut events = chained_events(10_000);
        let victim = 4_242usize;
        events[victim].country = Some("XX".to_owned());

        let sequence = events[victim].sequence;
        match verify_chain(&events) {
            VerifyResult::Diverged { sequence: reported, divergence } => {
                assert_eq!(reported, sequence);
                assert!(matches!(divergence, Divergence::ContentTampered { .. }));
            }
            other => panic!("tampering went undetected: {other:?}"),
        }
    }

    #[test]
    fn only_the_first_divergence_is_reported() {
        let mut events = chained_events(200);
        events[10].outcome = crate::Outcome::Error;
        events[150].outcome = crate::Outcome::Error;
        assert_eq!(verify_chain(&events).first_divergence(), Some(events[10].sequence));
    }

    #[test]
    fn a_removed_row_breaks_the_link() {
        let mut events = chained_events(50);
        let removed = events.remove(20);
        match verify_chain(&events) {
            VerifyResult::Diverged { sequence, divergence } => {
                assert_eq!(sequence, removed.sequence + 1);
                assert!(matches!(divergence, Divergence::LinkBroken { .. }));
            }
            other => panic!("a deletion went undetected: {other:?}"),
        }
    }

    /// Two orderings that must both be caught: a swap, which shows up as a broken link at the
    /// earlier of the two rows, and a run presented out of order, which shows up as a sequence
    /// anomaly. Either way the *first* offending position is what is reported.
    #[test]
    fn a_reordered_run_is_rejected_rather_than_silently_accepted() {
        let mut swapped = chained_events(10);
        swapped.swap(4, 5);
        match verify_chain(&swapped) {
            VerifyResult::Diverged { sequence, divergence } => {
                assert_eq!(sequence, swapped[4].sequence);
                assert!(matches!(divergence, Divergence::LinkBroken { .. }), "{divergence:?}");
            }
            other => panic!("a swap went undetected: {other:?}"),
        }

        let mut descending = chained_events(10);
        descending.reverse();
        match verify_chain(&descending) {
            VerifyResult::Diverged { divergence, .. } => {
                assert!(
                    matches!(divergence, Divergence::SequenceNotIncreasing { .. }),
                    "{divergence:?}"
                );
            }
            other => panic!("a reversed run went undetected: {other:?}"),
        }
    }

    #[test]
    fn a_row_stripped_of_its_hash_is_a_divergence_not_a_pass() {
        let mut events = chained_events(10);
        events[6].event_hash = None;
        match verify_chain(&events) {
            VerifyResult::Diverged { sequence, divergence } => {
                assert_eq!(sequence, events[6].sequence);
                assert_eq!(divergence, Divergence::MissingHash);
            }
            other => panic!("a stripped hash went undetected: {other:?}"),
        }
    }

    #[test]
    fn a_foreign_tenants_row_cannot_be_spliced_in() {
        let mut events = chained_events(10);
        events[3].tenant_id = TenantId::new_v7();
        match verify_chain(&events) {
            VerifyResult::Diverged { sequence, divergence } => {
                assert_eq!(sequence, events[3].sequence);
                assert_eq!(divergence, Divergence::TenantMismatch);
            }
            other => panic!("a cross-tenant splice went undetected: {other:?}"),
        }
    }

    #[test]
    fn hashes_hex_round_trip_through_serde() {
        let hash = EventHash::from_bytes([0xAB; 32]);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<EventHash>(&json).unwrap(), hash);
        assert!(serde_json::from_str::<EventHash>("\"zz\"").is_err());
    }

    #[test]
    fn a_short_stored_hash_is_rejected() {
        assert_eq!(EventHash::from_slice(&[0u8; 20]).unwrap_err(), HashLengthError { len: 20 });
        assert!(EventHash::from_slice(&[0u8; 32]).is_ok());
    }
}
