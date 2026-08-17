//! Where a published event actually goes.
//!
//! NATS JetStream is the production transport (`docs/02-HLD.md §9`), and it is deliberately **not**
//! in this crate's dependency graph yet. M0 ships no consumer (`plans/M0-FOUNDATIONS.md` D6), so
//! linking a broker client now would buy nothing and cost every developer and every CI job a
//! running NATS to compile and test against. The trait is the seam: the JetStream implementation
//! lands in M1 as one more `impl Transport`, and nothing above it changes.
//!
//! [`InMemoryTransport`] is not only a test double. It is what makes the *publisher's* behaviour
//! testable — ordering, at-least-once, halt-on-retryable — without a broker deciding when to fail.

use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::TransportError;
use crate::event::Event;

/// Delivers an event to the message bus.
///
/// Returns `Result<(), TransportError>` rather than the crate's error type because a transport can
/// only fail in one way that matters to the publisher, and the retryable/permanent split in
/// [`TransportError`] is exactly the question the publisher asks. An implementation that cannot
/// classify a failure should say `retryable` — an event delivered twice is the contract;
/// an event dropped is not.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Publishes one event, returning only once the broker has durably accepted it.
    ///
    /// "Durably accepted" is load-bearing: the publisher marks the outbox row published immediately
    /// after this returns `Ok`, so an implementation that returns before the broker has persisted
    /// the message converts at-least-once delivery into at-most-once, silently.
    ///
    /// # Errors
    ///
    /// [`TransportError::retryable`] when a later attempt may succeed — the publisher then stops
    /// the batch and leaves the row unpublished. [`TransportError::permanent`] when it will not —
    /// the row is charged an attempt and the batch continues past it.
    async fn publish(&self, event: &Event) -> Result<(), TransportError>;
}

#[async_trait]
impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    /// So a single transport can be shared by several publishers, or by a publisher and a test,
    /// without every signature in between naming `Arc`.
    async fn publish(&self, event: &Event) -> Result<(), TransportError> {
        (**self).publish(event).await
    }
}

/// State shared between an [`InMemoryTransport`] and any handle that inspects it.
#[derive(Debug, Default)]
struct Inner {
    delivered: Vec<Event>,
    /// Number of further successful deliveries before failures begin; `None` means never fail.
    fail_after: Option<usize>,
    failure_is_retryable: bool,
}

/// An in-process transport that records what it was given.
///
/// Beyond standing in for a broker, it can be told to start failing after *n* successful
/// deliveries. That is what lets the kill-and-resume and halt-on-retryable properties be asserted
/// deterministically: with a real broker those tests would depend on stopping a container at
/// exactly the right instant, which is a flaky test, and a flaky test on a delivery guarantee gets
/// disabled and then the guarantee is gone.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    inner: Mutex<Inner>,
}

impl InMemoryTransport {
    /// A transport that accepts everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `count` more events, then fail every subsequent attempt.
    ///
    /// `retryable` chooses which failure the publisher sees: a retryable one must halt the batch
    /// with the row still unpublished, a permanent one must be stepped over.
    pub fn fail_after(&self, count: usize, retryable: bool) {
        let mut inner = self.lock();
        inner.fail_after = Some(count);
        inner.failure_is_retryable = retryable;
    }

    /// Stop failing, so a resumed publisher can drain what was left behind.
    pub fn recover(&self) {
        self.lock().fail_after = None;
    }

    /// Everything accepted so far, in delivery order.
    #[must_use]
    pub fn delivered(&self) -> Vec<Event> {
        self.lock().delivered.clone()
    }

    /// How many events have been accepted.
    #[must_use]
    pub fn delivered_count(&self) -> usize {
        self.lock().delivered.len()
    }

    /// Recovers from a poisoned mutex rather than panicking.
    ///
    /// A panic in one test thread must not turn every later assertion into a second, misleading
    /// panic about lock poisoning — and `unwrap` is warned on workspace-wide for exactly the
    /// reason that it hides which failure was the real one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    async fn publish(&self, event: &Event) -> Result<(), TransportError> {
        let mut inner = self.lock();
        match inner.fail_after {
            Some(0) => {
                let retryable = inner.failure_is_retryable;
                drop(inner);
                Err(if retryable {
                    TransportError::retryable("in-memory transport: injected failure")
                } else {
                    TransportError::permanent("in-memory transport: injected rejection")
                })
            }
            Some(remaining) => {
                inner.fail_after = Some(remaining - 1);
                inner.delivered.push(event.clone());
                Ok(())
            }
            None => {
                inner.delivered.push(event.clone());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::event::{Event, EventType};
    use enclave_core::{Actor, TenantId};

    fn event() -> Event {
        Event::new(
            TenantId::new_v7(),
            EventType::IndexRequested,
            Actor::System,
            &serde_json::json!({}),
        )
        .expect("encode")
    }

    #[tokio::test]
    async fn records_deliveries_in_order() {
        let transport = InMemoryTransport::new();
        let first = event();
        let second = event();
        transport.publish(&first).await.expect("accepted");
        transport.publish(&second).await.expect("accepted");

        let delivered = transport.delivered();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].event_id, first.event_id);
        assert_eq!(delivered[1].event_id, second.event_id);
    }

    #[tokio::test]
    async fn injected_failures_start_after_the_configured_count_and_carry_their_class() {
        let transport = InMemoryTransport::new();
        transport.fail_after(1, true);
        transport.publish(&event()).await.expect("first is accepted");
        let err = transport.publish(&event()).await.expect_err("second fails");
        assert!(err.is_retryable());
        assert_eq!(transport.delivered_count(), 1);

        transport.fail_after(0, false);
        let err = transport.publish(&event()).await.expect_err("fails immediately");
        assert!(!err.is_retryable());

        transport.recover();
        transport.publish(&event()).await.expect("accepted again");
        assert_eq!(transport.delivered_count(), 2);
    }
}
