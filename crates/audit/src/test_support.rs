//! Deterministic fixtures shared by this crate's unit tests.
//!
//! Compiled only under `cfg(test)`: a synthetic request context is exactly the sort of thing that
//! must not be reachable from production code, since it fabricates a tenant identity.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use chrono::DateTime;
use enclave_core::{
    Action, ActorKind, AuthStrength, ClientType, DeviceContext, FileAction, FileId, NetworkContext,
    ReasonCode, RequestContext, RequestId, ResourceRef, ScopeSet, TenantId, UserId, Uuid,
};

use crate::chain::seal;
use crate::event::{AuditEvent, Outcome, PolicyRef};
use crate::redact::Detail;

/// A fixed tenant, so fixtures in different tests can be compared.
pub(crate) fn tenant() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0001))
}

/// A request context with every optional field populated, so encoding tests exercise the present
/// branch of each one rather than the absent branch of all of them.
pub(crate) fn context() -> RequestContext {
    RequestContext {
        request_id: RequestId::from_uuid(Uuid::from_u128(
            0x0192_0000_0000_7000_8000_0000_0000_0002,
        )),
        tenant_id: tenant(),
        actor: enclave_core::Actor::User(UserId::from_uuid(Uuid::from_u128(
            0x0192_0000_0000_7000_8000_0000_0000_0003,
        ))),
        session_id: Some(enclave_core::SessionId::from_uuid(Uuid::from_u128(
            0x0192_0000_0000_7000_8000_0000_0000_0004,
        ))),
        auth_strength: AuthStrength::MultiFactor,
        auth_time: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        scopes: ScopeSet::from(vec!["files:read".to_owned()]),
        client: ClientType::Web,
        network: NetworkContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            country: Some("IN".to_owned()),
            asn: Some(64_500),
            zones: vec!["Corporate".to_owned()],
            via_trusted_proxy: true,
        },
        device: DeviceContext {
            device_id: Some(enclave_core::DeviceId::from_uuid(Uuid::from_u128(
                0x0192_0000_0000_7000_8000_0000_0000_0005,
            ))),
            posture: enclave_core::DevicePosture::Managed,
        },
    }
}

/// One fully populated event, fixed in every field so its canonical bytes are reproducible.
pub(crate) fn sample_event() -> AuditEvent {
    let ctx = context();
    let resource = ResourceRef::file(
        ctx.tenant_id,
        FileId::from_uuid(Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0006)),
    );
    let mut detail = Detail::empty();
    detail.try_insert("bytes", 4_096).unwrap();
    detail.try_insert("rendition", "pdf").unwrap();

    let mut event = AuditEvent::builder(&ctx, Action::File(FileAction::Download), Outcome::Deny)
        .id(Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0007))
        .occurred_at(DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap())
        .resource(&resource)
        .reason(ReasonCode::DownloadBlockedByPolicy)
        .policy_ref(PolicyRef::versioned(
            "dlp",
            Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0008),
            3,
        ))
        .policy_ref(PolicyRef::builtin("classification_ceiling"))
        .on_behalf_of(UserId::from_uuid(Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0009)))
        .user_agent("Mozilla/5.0 (fixture)")
        .detail(detail)
        .build();
    event.sequence = 1;
    debug_assert_eq!(event.actor.kind(), ActorKind::User);
    event
}

/// `count` events, sealed into one valid chain with sequences `1..=count`.
///
/// Ids and timestamps vary per event so that no two events are identical — a chain of identical
/// events would verify even if the encoder ignored half its input.
pub(crate) fn chained_events(count: usize) -> Vec<AuditEvent> {
    let mut events = Vec::with_capacity(count);
    let mut head = None;
    for i in 0..count {
        let mut event = sample_event();
        event.id = Uuid::from_u128(0x0192_0000_0001_7000_8000_0000_0000_0000 + i as u128);
        event.sequence = i as i64 + 1;
        event.occurred_at =
            DateTime::from_timestamp_micros(1_700_000_000_000_000 + i as i64 * 1_000).unwrap();
        head = Some(seal(&mut event, head));
        events.push(event);
    }
    events
}
