//! The crate's error type and its translation into [`enclave_core::Error`].
//!
//! Two properties are deliberate:
//!
//! 1. **No error message ever contains an event payload.** Payloads carry file names, DLP context
//!    and, in some events, excerpts of user content; an error string is the shortest known path
//!    from a payload to a log line (`CLAUDE.md` non-negotiable rule 10). Decode failures therefore
//!    name the *row*, never its contents, and [`EventsError::last_error_text`] truncates whatever
//!    a transport produced before it is written back to `events_outbox.last_error`.
//! 2. **Retryability is carried, not guessed.** The publisher must distinguish "the broker is down,
//!    stop the batch and keep the rows" from "this row will never decode, step over it", and a
//!    caller upstream must distinguish a 503 from a 500. Both questions are answered by the type.

use enclave_core::{Dependency, Error as CoreError};
use uuid::Uuid;

/// The maximum number of bytes of a failure description written back to
/// `events_outbox.last_error`.
///
/// Bounded because the column is `TEXT` and an unbounded driver error (a Postgres message can
/// quote a whole statement) would let one poisoned row bloat the table that the publisher scans
/// on every poll.
const LAST_ERROR_MAX_BYTES: usize = 512;

/// Anything that can go wrong writing, reading or delivering an event.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventsError {
    /// The database rejected or could not serve an outbox statement.
    #[error("outbox storage failure")]
    Storage(#[from] sqlx::Error),

    /// The event's payload could not be encoded for storage.
    ///
    /// In practice this means a domain type serialized to something that is not valid JSON (a map
    /// with non-string keys, a non-finite float). It is a programming error, not a runtime
    /// condition, which is why it is not retryable.
    #[error("event payload could not be encoded")]
    Encode(#[source] serde_json::Error),

    /// A stored outbox row could not be decoded back into an [`Event`](crate::Event).
    ///
    /// Reachable when a row was written by a newer build with an incompatible envelope, or when
    /// the column was edited out of band. The row identifier is carried so an operator can find
    /// it; the payload that failed to decode is not.
    #[error("outbox row {event_id} could not be decoded")]
    Decode {
        /// `events_outbox.id` of the offending row.
        event_id: Uuid,
        /// The underlying serde failure.
        #[source]
        source: serde_json::Error,
    },

    /// The transport refused or failed to accept an event.
    #[error("event transport failure")]
    Transport(#[from] TransportError),
}

impl EventsError {
    /// Whether an identical retry has a chance of succeeding.
    ///
    /// Drives the publisher's decision to pause a batch rather than step over a row: a retryable
    /// failure must never consume an attempt budget indefinitely at the head of the queue, and a
    /// non-retryable one must never wedge the queue behind it.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            // A closed pool or a lost connection is transient; a constraint violation is not, but
            // the outbox issues no statement that can violate a constraint on retry alone.
            Self::Storage(_) => true,
            Self::Encode(_) | Self::Decode { .. } => false,
            Self::Transport(err) => err.is_retryable(),
        }
    }

    /// A bounded, payload-free description suitable for `events_outbox.last_error`.
    ///
    /// Uses `Display` of the error itself rather than the full source chain: the chain can reach a
    /// driver error quoting the statement and its bound parameters, and those parameters are the
    /// payload.
    #[must_use]
    pub fn last_error_text(&self) -> String {
        truncate_utf8(&self.to_string(), LAST_ERROR_MAX_BYTES)
    }
}

impl From<EventsError> for CoreError {
    /// Maps to the vocabulary the API edge renders (`docs/03-LLD.md §22`).
    ///
    /// Storage and transport failures are `Upstream`, so a caller that could not record an event
    /// reports a dependency problem rather than a generic 500. Encode and decode failures are
    /// `Internal`, because they are defects in this process and there is nothing a client can do
    /// with a more specific answer.
    fn from(err: EventsError) -> Self {
        match err {
            EventsError::Storage(_) => {
                Self::Upstream { dependency: Dependency::Postgres, retryable: true }
            }
            EventsError::Transport(ref inner) => {
                let retryable = inner.is_retryable();
                Self::Upstream { dependency: Dependency::Nats, retryable }
            }
            EventsError::Encode(_) | EventsError::Decode { .. } => Self::Internal(err.into()),
        }
    }
}

/// A failure reported by a [`Transport`](crate::Transport) implementation.
///
/// A single opaque type rather than an associated error per transport: the publisher's only two
/// questions are "what do I write to `last_error`" and "should I try again", and a generic
/// parameter for the answer would infect every signature between here and the binary that wires
/// the broker in.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    message: String,
    retryable: bool,
}

impl TransportError {
    /// A failure that a later attempt may survive — broker unreachable, timeout, no quorum.
    ///
    /// The publisher stops the current batch on one of these, leaving the row unpublished. That is
    /// what makes the outbox lossless: an event is only ever marked published after a transport
    /// has accepted it.
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self { message: truncate_utf8(&message.into(), LAST_ERROR_MAX_BYTES), retryable: true }
    }

    /// A failure that will recur identically — a rejected subject, a message over the broker's
    /// maximum size.
    ///
    /// Recorded against the row and counted as an attempt, so the row eventually exceeds
    /// `max_attempts` and is quarantined instead of blocking every event behind it forever.
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self { message: truncate_utf8(&message.into(), LAST_ERROR_MAX_BYTES), retryable: false }
    }

    /// Whether the publisher should keep the row and try again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }
}

/// Truncates on a character boundary, so the result is always valid UTF-8 for a `TEXT` column.
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let end = value
        .char_indices()
        .map(|(idx, _)| idx)
        .take_while(|idx| *idx <= max_bytes)
        .last()
        .unwrap_or(0);
    value[..end].to_owned()
}

/// The crate's result alias.
pub type Result<T, E = EventsError> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn transport_retryability_survives_the_conversion_to_core_error() {
        let err = EventsError::from(TransportError::retryable("broker unreachable"));
        assert!(err.is_retryable());
        match CoreError::from(err) {
            CoreError::Upstream { dependency, retryable } => {
                assert_eq!(dependency, Dependency::Nats);
                assert!(retryable);
            }
            other => panic!("expected Upstream, got {other:?}"),
        }

        let err = EventsError::from(TransportError::permanent("subject rejected"));
        assert!(!err.is_retryable());
        match CoreError::from(err) {
            CoreError::Upstream { retryable, .. } => assert!(!retryable),
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn last_error_text_is_bounded_and_stays_valid_utf8() {
        let long = "é".repeat(4096);
        let err = TransportError::retryable(long);
        let text = err.to_string();
        assert!(text.len() <= LAST_ERROR_MAX_BYTES, "len was {}", text.len());
        // Round-tripping proves no multi-byte character was cut in half.
        assert_eq!(text, String::from_utf8(text.clone().into_bytes()).unwrap());
    }

    #[test]
    fn decode_failures_name_the_row_and_not_its_contents() {
        let source = serde_json::from_str::<serde_json::Value>("{oops").expect_err("must fail");
        let id = Uuid::now_v7();
        let err = EventsError::Decode { event_id: id, source };
        let rendered = err.to_string();
        assert!(rendered.contains(&id.to_string()));
        assert!(!rendered.contains("oops"));
        assert!(!err.is_retryable());
    }
}
