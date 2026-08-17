//! Forwarding audit events to an external SIEM (`docs/06-SECURITY-DLP-ACCESS.md §20`).
//!
//! # The rule that shapes this interface
//!
//! *A SIEM outage must not drop security events or block user operations.* Those two requirements
//! pull in opposite directions, and the resolution is that forwarding is **not** on the request
//! path: the authoritative record is the `audit_events` row, which is written synchronously inside
//! the policy engine, and forwarding is an at-least-once read of that table by a worker with a
//! local buffer.
//!
//! So [`SiemSink::forward`] returning an error means "this delivery attempt failed, retry it" —
//! never "fail the user's request". A caller that propagates a forwarding error into a request
//! response has made a SIEM outage into an outage.
//!
//! Correlation is preserved by construction: the forwarded payload is the serialized
//! [`AuditEvent`], which carries both `id` and `request_id`.

use async_trait::async_trait;

use crate::error::Result;
use crate::event::AuditEvent;

/// A destination for forwarded audit events.
///
/// `Debug` is a supertrait for the same reason as on [`crate::AuditSink`]: holders need to derive
/// `Debug`.
#[async_trait]
pub trait SiemSink: std::fmt::Debug + Send + Sync {
    /// Forwards one event.
    ///
    /// Takes the event by reference: forwarding must never be able to mutate or consume the record
    /// the database already holds, and the same event may go to several destinations.
    ///
    /// # Errors
    ///
    /// A delivery failure, which the caller retries from its buffer. Not a request failure.
    async fn forward(&self, event: &AuditEvent) -> Result<()>;

    /// Forwards a batch, defaulting to one call per event.
    ///
    /// Overridden by transports that can amortize a round trip — most SIEM ingest endpoints
    /// accept newline-delimited JSON — because the difference between one request per event and
    /// one per thousand is the difference between keeping up and falling behind.
    ///
    /// # Errors
    ///
    /// The first delivery failure. Events before it may already have been delivered; delivery is
    /// at-least-once, so consumers deduplicate on `id`.
    async fn forward_batch(&self, events: &[AuditEvent]) -> Result<()> {
        for event in events {
            self.forward(event).await?;
        }
        Ok(())
    }

    /// Flushes anything buffered inside the transport.
    ///
    /// Called on shutdown. The default does nothing, which is correct for transports that do not
    /// buffer.
    ///
    /// # Errors
    ///
    /// A failure to flush, which the caller logs — shutdown proceeds either way.
    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// A sink that forwards nowhere.
///
/// The default when no SIEM is configured, so that the forwarding call site is unconditional. A
/// code path guarded by `if let Some(siem)` is a code path that gets an early return added to it
/// eventually; a no-op implementation is not.
///
/// It emits a `trace` record rather than nothing at all, so "is forwarding configured?" is
/// answerable from a running system without reading its configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSiemSink;

#[async_trait]
impl SiemSink for NullSiemSink {
    async fn forward(&self, event: &AuditEvent) -> Result<()> {
        tracing::trace!(
            audit_id = %event.id,
            request_id = %event.request_id,
            "no SIEM configured; audit event not forwarded"
        );
        Ok(())
    }

    async fn forward_batch(&self, events: &[AuditEvent]) -> Result<()> {
        tracing::trace!(count = events.len(), "no SIEM configured; audit batch not forwarded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use std::sync::Arc;

    use crate::test_support::sample_event;

    #[tokio::test]
    async fn the_null_sink_accepts_everything_and_is_object_safe() {
        let sink: Arc<dyn SiemSink> = Arc::new(NullSiemSink);
        let event = sample_event();
        sink.forward(&event).await.unwrap();
        sink.forward_batch(std::slice::from_ref(&event)).await.unwrap();
        sink.flush().await.unwrap();
    }

    #[tokio::test]
    async fn a_forwarded_event_carries_both_correlation_ids() {
        let event = sample_event();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.get("id").and_then(|v| v.as_str()), Some(event.id.to_string().as_str()));
        assert_eq!(
            json.get("request_id").and_then(|v| v.as_str()),
            Some(event.request_id.to_string().as_str())
        );
    }
}
