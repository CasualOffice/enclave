//! The event envelope and the closed vocabulary of event types (`docs/02-HLD.md §9`).
//!
//! Two shapes are deliberate here.
//!
//! **The envelope is a struct, not a `serde_json::Value` with conventions.** Every event carries
//! `event_id`, `tenant_id`, `event_type`, `schema_version`, `occurred_at` and `actor` because
//! consumers need all six *before* they understand the payload: `tenant_id` to scope the work,
//! `event_id` to deduplicate, `schema_version` to decide whether they can read the body at all. A
//! convention enforced by review decays; a struct does not.
//!
//! **[`EventType`] is a closed enum, not a free string.** A subject typo is otherwise a silent
//! non-delivery — the publisher succeeds, the consumer's subscription never matches, and nothing
//! anywhere reports an error. Closing the vocabulary turns that into a compile error, and gives
//! consumers exhaustive `match` when a new event type is added.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_core::{Actor, TenantId, UnknownVariant, Uuid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{EventsError, Result};

/// The schema version stamped on events this build produces.
///
/// Matches the `events_outbox.schema_version` default in `docs/04-DATA-MODEL.md §17`. It is
/// per-envelope rather than global so that a payload shape can be revised for one event type
/// without forcing every consumer of every other type to redeploy.
pub const CURRENT_SCHEMA_VERSION: i32 = 1;

/// Identifier of a single event occurrence.
///
/// Its own newtype rather than `enclave_core`'s set, because an event id is not an identifier of a
/// *thing* in the domain — it identifies one delivery-deduplication unit, and it is minted here
/// rather than by any domain crate. It is UUIDv7 for the same reason the core ids are: the outbox
/// is drained in creation order and a time-ordered primary key keeps that scan on the right-hand
/// edge of the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(Uuid);

impl EventId {
    /// Mints a fresh, time-ordered event identifier.
    #[must_use]
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps a UUID that arrived untyped — from the `events_outbox.id` column, or from a message
    /// header on the consuming side.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Unwraps to the raw UUID for those same boundaries in the outward direction.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<Uuid> for EventId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<EventId> for Uuid {
    fn from(value: EventId) -> Self {
        value.0
    }
}

/// Generates [`EventType`] together with the four representations that must never disagree.
///
/// `enclave_core` has an equivalent macro, but it is private to that crate and `core` must not grow
/// an eventing vocabulary to share it (`plans/M0-FOUNDATIONS.md` D1). Twenty-odd hand-written match
/// arms across `as_str` and `FromStr` is precisely the code that acquires a one-variant skew nobody
/// notices until a subject stops matching in production.
macro_rules! event_types {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The canonical subject string, which is also what is stored in
            /// `events_outbox.event_type`.
            ///
            /// Changing one of these is a breaking change to every subscription and every stored
            /// row, not a rename.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self {
                    $( Self::$variant => $wire ),+
                }
            }

            /// Every event type, in declaration order — for tests that assert the vocabulary and
            /// for operator tooling that enumerates subjects instead of hard-coding them.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    _ => Err(UnknownVariant::new(stringify!($name), s)),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                s: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                d: D,
            ) -> ::core::result::Result<Self, D::Error> {
                // Routed through `FromStr` so serde and manual parsing cannot accept different
                // sets of strings.
                let raw = <String as Deserialize>::deserialize(d)?;
                raw.parse().map_err(::serde::de::Error::custom)
            }
        }
    };
}

event_types! {
    /// The subjects Enclave publishes, verbatim from `docs/02-HLD.md §9`.
    ///
    /// Marked `#[non_exhaustive]`: adding a subject must not break a downstream `match`, but the
    /// set is still closed *within* the workspace, so a publisher cannot invent one.
    pub enum EventType {
        /// A new version was committed. First link in the AV → DLP → index chain, which is why
        /// nothing may be served as `AVAILABLE` until its consumers have run
        /// (`CLAUDE.md` non-negotiable rule 9).
        FileVersionCreated => "file.version.created",
        /// A file entered the trash.
        FileDeleted => "file.deleted",
        /// A file was restored from the trash.
        FileRestored => "file.restored",
        /// An ACL entry or a group membership changed. Drives search ACL invalidation
        /// (`docs/07-SEARCH-INDEXING.md §6`) — the reason this event exists at all.
        PermissionChanged => "permission.changed",
        /// A classification label was applied or recomputed.
        ClassificationChanged => "classification.changed",
        /// Content needs a DLP scan: new upload, changed policy, or a changed detector set.
        DlpScanRequested => "dlp.scan.requested",
        /// Content needs an antivirus scan.
        AvScanRequested => "av.scan.requested",
        /// Content or the embedding model changed and the index must be rebuilt for it.
        IndexRequested => "index.requested",
        /// A rendition must be produced for a preview profile.
        PreviewRequested => "preview.requested",
        /// A retention schedule fired.
        RetentionTriggered => "retention.triggered",
        /// A change affected a synchronized path; sync clients must advance their delta cursor.
        SyncInvalidated => "sync.invalidated",
        /// A workflow instance started.
        WorkflowStarted => "workflow.started",
        /// A workflow step received a decision.
        WorkflowStepDecided => "workflow.step.decided",
        /// A workflow instance reached a terminal state.
        WorkflowCompleted => "workflow.completed",
        /// A signing ceremony was requested.
        SignatureRequested => "signature.requested",
        /// One participant signed.
        SignatureSigned => "signature.signed",
        /// Every participant signed and the ceremony is complete.
        SignatureCompleted => "signature.completed",
        /// An outbound webhook must be delivered.
        WebhookRequested => "webhook.requested",
    }
}

/// One event, complete: the six envelope fields plus its body.
///
/// `payload` is a `serde_json::Value` rather than a generic parameter because the outbox, the
/// publisher and the transport are all payload-agnostic — making them generic would push a type
/// parameter through every one of their signatures to be erased at the first storage boundary
/// anyway. Producers build the value from a typed struct with [`Event::new`]; consumers recover a
/// typed struct with [`Event::payload_as`], so the untyped form exists only in transit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Deduplication key. Consumers are idempotent on this and nothing else
    /// (`docs/02-HLD.md §9`).
    pub event_id: EventId,
    /// Owning tenant. Present on every event without exception: a consumer that cannot tell which
    /// tenant a message belongs to cannot scope its work, and cross-tenant work is the one failure
    /// mode this system exists to prevent.
    pub tenant_id: TenantId,
    /// What happened. Doubles as the transport subject.
    pub event_type: EventType,
    /// Version of the `payload` shape for this `event_type`.
    pub schema_version: i32,
    /// When the state change happened — set by the producer inside the writing transaction, not by
    /// the publisher, so it reflects the domain event rather than when delivery got around to it.
    pub occurred_at: DateTime<Utc>,
    /// Who caused it. `Actor::System` for scheduler- and sweep-originated events, which is an
    /// honest answer rather than an absent one.
    pub actor: Actor,
    /// The event body, opaque to this crate.
    pub payload: serde_json::Value,
}

impl Event {
    /// Builds an event from a typed payload, stamping a fresh id and the current time.
    ///
    /// Takes the payload by reference and serializes eagerly so that an unserializable body is a
    /// failure at construction — where the caller still has context — rather than deep inside the
    /// publisher, hours later, against a row nobody can attribute.
    ///
    /// # Errors
    ///
    /// [`EventsError::Encode`] if `payload` does not serialize to JSON.
    pub fn new<P: Serialize>(
        tenant_id: TenantId,
        event_type: EventType,
        actor: Actor,
        payload: &P,
    ) -> Result<Self> {
        Ok(Self {
            event_id: EventId::new_v7(),
            tenant_id,
            event_type,
            schema_version: CURRENT_SCHEMA_VERSION,
            occurred_at: Utc::now(),
            actor,
            payload: serde_json::to_value(payload).map_err(EventsError::Encode)?,
        })
    }

    /// Overrides the schema version, for an event type whose body has been revised.
    #[must_use]
    pub const fn with_schema_version(mut self, version: i32) -> Self {
        self.schema_version = version;
        self
    }

    /// Overrides `occurred_at`.
    ///
    /// Exists for producers that already hold the authoritative timestamp of the state change —
    /// a version's `created_at`, a schedule's fire time — so the event and the row it describes
    /// agree rather than differing by however long the transaction ran.
    #[must_use]
    pub const fn with_occurred_at(mut self, at: DateTime<Utc>) -> Self {
        self.occurred_at = at;
        self
    }

    /// Overrides the event id.
    ///
    /// Reserved for producers that derive a deterministic id from the state change itself, so that
    /// a retried write reuses the same id and [`Outbox::publish`](crate::Outbox::publish) collapses
    /// the duplicate instead of emitting a second event.
    #[must_use]
    pub const fn with_event_id(mut self, event_id: EventId) -> Self {
        self.event_id = event_id;
        self
    }

    /// The transport subject this event is published on.
    #[must_use]
    pub const fn subject(&self) -> &'static str {
        self.event_type.as_str()
    }

    /// Recovers the typed payload.
    ///
    /// # Errors
    ///
    /// [`EventsError::Decode`] if the body does not match `P`. The error names the event id and
    /// never the body, because a payload can contain file names and DLP context
    /// (`CLAUDE.md` non-negotiable rule 10).
    pub fn payload_as<P: DeserializeOwned>(&self) -> Result<P> {
        serde_json::from_value(self.payload.clone())
            .map_err(|source| EventsError::Decode { event_id: self.event_id.as_uuid(), source })
    }

    /// Encodes the whole envelope for a transport that carries bytes.
    ///
    /// The envelope travels in the message body rather than in broker headers so that delivery
    /// semantics do not depend on a particular broker's header support — a consumer reading a
    /// dead-letter dump gets the same six fields it would have got live.
    ///
    /// # Errors
    ///
    /// [`EventsError::Encode`] if the envelope does not serialize, which in practice means the
    /// payload contains a non-finite float.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EventsError::Encode)
    }
}

/// The JSON actually written to `events_outbox.payload`.
///
/// `docs/04-DATA-MODEL.md §17` gives `events_outbox` columns for id, tenant, type, schema version
/// and creation time — but not for `actor`, which `docs/02-HLD.md §9` requires on every event. It
/// is therefore nested inside the payload column rather than dropped, and the nesting is an
/// explicit named type so the wrapping and unwrapping cannot drift apart. If a future migration
/// adds an `actor_kind` / `actor_id` column pair, this type is the single place that changes.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StoredPayload {
    pub(crate) actor: Actor,
    pub(crate) data: serde_json::Value,
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::UserId;
    use std::collections::BTreeSet;

    #[test]
    fn every_documented_subject_is_representable() {
        // The list in `docs/02-HLD.md §9`, spelled out independently of the enum so that a typo in
        // the macro invocation is caught here rather than by a subscription that never fires.
        let documented = [
            "file.version.created",
            "file.deleted",
            "file.restored",
            "permission.changed",
            "classification.changed",
            "dlp.scan.requested",
            "av.scan.requested",
            "index.requested",
            "preview.requested",
            "retention.triggered",
            "sync.invalidated",
            "workflow.started",
            "workflow.step.decided",
            "workflow.completed",
            "signature.requested",
            "signature.signed",
            "signature.completed",
            "webhook.requested",
        ];
        let declared: BTreeSet<&str> = EventType::all().iter().map(|t| t.as_str()).collect();
        let expected: BTreeSet<&str> = documented.into_iter().collect();
        assert_eq!(declared, expected);
    }

    #[test]
    fn event_types_round_trip_through_string_and_serde() {
        for event_type in EventType::all() {
            assert_eq!(event_type.as_str().parse::<EventType>(), Ok(*event_type));
            let json = serde_json::to_string(event_type).expect("serialize");
            assert_eq!(json, format!("\"{event_type}\""));
            let back: EventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, *event_type);
        }
    }

    #[test]
    fn unknown_subjects_are_rejected_rather_than_guessed() {
        // Case sensitivity is deliberate here, unlike the core vocabularies: a subject is a wire
        // token matched literally by the broker, so `File.Deleted` is simply a different subject.
        assert!("file.undeleted".parse::<EventType>().is_err());
        assert!("File.Deleted".parse::<EventType>().is_err());
    }

    #[test]
    fn envelope_round_trips_with_its_payload() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        struct Body {
            file_id: String,
            reason: String,
        }
        let body = Body { file_id: "f-1".to_owned(), reason: "upload".to_owned() };
        let event = Event::new(
            TenantId::new_v7(),
            EventType::AvScanRequested,
            Actor::User(UserId::new_v7()),
            &body,
        )
        .expect("a plain struct must encode");

        assert_eq!(event.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(event.subject(), "av.scan.requested");
        assert_eq!(event.payload_as::<Body>().expect("decode"), body);

        let bytes = event.encode().expect("encode");
        let back: Event = serde_json::from_slice(&bytes).expect("decode envelope");
        assert_eq!(back, event);
    }

    #[test]
    fn a_payload_of_the_wrong_shape_reports_the_id_and_not_the_body() {
        #[derive(Debug, Deserialize)]
        struct Other {
            #[allow(dead_code)]
            missing_field: String,
        }
        let event = Event::new(
            TenantId::new_v7(),
            EventType::IndexRequested,
            Actor::System,
            &serde_json::json!({ "secret_file_name": "salaries.xlsx" }),
        )
        .expect("encode");

        let err = event.payload_as::<Other>().expect_err("must not decode");
        let rendered = err.to_string();
        assert!(rendered.contains(&event.event_id.to_string()));
        assert!(!rendered.contains("salaries.xlsx"));
    }

    #[test]
    fn event_ids_are_time_ordered() {
        // The outbox drain relies on `ORDER BY created_at, id` being generation order.
        let first = EventId::new_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(first < EventId::new_v7());
    }
}
