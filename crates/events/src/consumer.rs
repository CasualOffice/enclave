//! Making at-least-once delivery safe to act on.
//!
//! The publisher's guarantee is at-least-once (`docs/02-HLD.md §9`), which means every consumer
//! *will* eventually see the same event twice — after a publisher crash, after a broker redelivery,
//! after a rebalance. For most Enclave consumers a second delivery is not merely wasteful: a
//! duplicate `retention.triggered` re-runs a disposition, a duplicate `webhook.requested` posts a
//! second time to a customer's endpoint. Deduplication therefore belongs in shared code that every
//! consumer uses, not in each consumer's own handler where the ninth one forgets.
//!
//! The unit of deduplication is `(consumer, event_id)`, not `event_id` alone: the same event is
//! legitimately delivered to the antivirus worker and the index worker, and they must not
//! deduplicate each other's work.
//!
//! # Claim, then release on failure
//!
//! [`IdempotentConsumer::handle`] claims before running the handler and releases if the handler
//! failed. Claiming afterwards would let a crash mid-handler lose the event entirely — the redelivery
//! would arrive with no claim recorded but the side effect half-applied; claiming before and never
//! releasing would drop every event whose handler hit a transient error. Neither is recoverable
//! from outside, which is why the ordering is fixed here rather than left to each consumer.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::Mutex;

use async_trait::async_trait;
use tracing::warn;

use crate::error::Result;
use crate::event::EventId;

/// What [`IdempotentConsumer::handle`] did with a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The handler ran. First time this consumer has seen the event.
    Processed,
    /// The handler was skipped: this consumer has already processed the event.
    Duplicate,
}

impl Delivery {
    /// Whether the handler actually ran, for metrics that need to distinguish real work from
    /// redelivery — a duplicate rate that quietly climbs is the first sign a publisher is crashing
    /// mid-batch.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate)
    }
}

/// Remembers which events a named consumer has already processed.
///
/// A trait because durability is a deployment choice this crate must not make. An in-process log is
/// right for a consumer whose side effects are themselves idempotent, and wrong for one that posts
/// webhooks — that one needs a store that survives a restart. Both are `impl DeliveryLog`, and the
/// consumer code above is identical.
#[async_trait]
pub trait DeliveryLog: Send + Sync {
    /// Records the intent to process, returning `true` if this consumer has not seen the event.
    ///
    /// Must be atomic: two workers racing on the same redelivery must not both be told `true`, or
    /// the deduplication achieves nothing under precisely the concurrency it exists for.
    ///
    /// # Errors
    ///
    /// Implementation-defined; a durable store reports its storage failures here.
    async fn claim(&self, consumer: &str, event_id: EventId) -> Result<bool>;

    /// Withdraws a claim so a redelivery is processed rather than skipped.
    ///
    /// Called when a handler failed. An implementation may choose to make this a no-op only if its
    /// claims expire, because a claim that is neither released nor expired is a permanently
    /// swallowed event.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    async fn release(&self, consumer: &str, event_id: EventId) -> Result<()>;
}

#[async_trait]
impl<L: DeliveryLog + ?Sized> DeliveryLog for std::sync::Arc<L> {
    /// So several consumers can share one log — which they must, when they run in the same process
    /// and the log is what stops them re-doing each other's redeliveries — without every signature
    /// between here and the worker naming `Arc`.
    async fn claim(&self, consumer: &str, event_id: EventId) -> Result<bool> {
        (**self).claim(consumer, event_id).await
    }

    async fn release(&self, consumer: &str, event_id: EventId) -> Result<()> {
        (**self).release(consumer, event_id).await
    }
}

/// A bounded, in-process delivery log.
///
/// Bounded on purpose. An unbounded set of every event id a long-running worker ever saw is a slow
/// memory leak that only manifests in the busiest tenant's production instance. Evicting the oldest
/// entries trades a vanishingly rare duplicate — one arriving after `capacity` other events, far
/// beyond any redelivery window — for a worker that runs indefinitely.
///
/// It does not survive a restart. Consumers whose side effects are not naturally idempotent should
/// use a durable implementation instead.
#[derive(Debug)]
pub struct InMemoryDeliveryLog {
    inner: Mutex<Seen>,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Seen {
    /// Membership, for the O(1) question the hot path asks.
    ids: HashSet<(String, EventId)>,
    /// Insertion order, so eviction is oldest-first.
    order: VecDeque<(String, EventId)>,
}

impl InMemoryDeliveryLog {
    /// A log remembering the most recent `capacity` claims.
    ///
    /// A capacity of zero would remember nothing and silently disable deduplication, so it is
    /// raised to one — a consumer that asked for a delivery log must never end up without one.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { inner: Mutex::new(Seen::default()), capacity: capacity.max(1) }
    }

    /// How many claims are currently remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().order.len()
    }

    /// Whether nothing has been claimed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Recovers from a poisoned mutex rather than panicking: a panic in one consumer task must not
    /// take down deduplication for every other one.
    fn lock(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for InMemoryDeliveryLog {
    /// Ten thousand entries: comfortably wider than any plausible redelivery window, and a few
    /// hundred kilobytes.
    fn default() -> Self {
        Self::with_capacity(10_000)
    }
}

#[async_trait]
impl DeliveryLog for InMemoryDeliveryLog {
    async fn claim(&self, consumer: &str, event_id: EventId) -> Result<bool> {
        let mut seen = self.lock();
        let key = (consumer.to_owned(), event_id);
        if !seen.ids.insert(key.clone()) {
            return Ok(false);
        }
        seen.order.push_back(key);
        while seen.order.len() > self.capacity {
            if let Some(evicted) = seen.order.pop_front() {
                seen.ids.remove(&evicted);
            }
        }
        Ok(true)
    }

    async fn release(&self, consumer: &str, event_id: EventId) -> Result<()> {
        let mut seen = self.lock();
        let key = (consumer.to_owned(), event_id);
        if seen.ids.remove(&key) {
            seen.order.retain(|entry| entry != &key);
        }
        Ok(())
    }
}

/// Wraps a handler so it runs at most once per event, per consumer.
///
/// The consumer name is part of the type rather than a parameter on every call because it is a
/// deployment identity, not a per-message property: passing it per call is how one code path ends
/// up using `"indexer"` and another `"index-worker"`, at which point the same worker deduplicates
/// against two different histories and the guarantee is gone without any error.
#[derive(Debug)]
pub struct IdempotentConsumer<L> {
    name: String,
    log: L,
}

impl<L: DeliveryLog> IdempotentConsumer<L> {
    /// Names a consumer and gives it a delivery log.
    pub fn new(name: impl Into<String>, log: L) -> Self {
        Self { name: name.into(), log }
    }

    /// This consumer's name, as recorded in its delivery log.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runs `handler` unless this event has already been processed.
    ///
    /// If the handler returns an error the claim is withdrawn, so the broker's redelivery is
    /// processed rather than silently skipped — a failed handler must leave the system in the state
    /// it was in before the delivery, and a retained claim would not.
    ///
    /// The handler's error type is generic with `E: From<EventsError>` so that a consumer keeps its
    /// own error type and still receives log failures through it, rather than every consumer having
    /// to unify two error types at the call site.
    ///
    /// # Errors
    ///
    /// Whatever `handler` returns, or a [`DeliveryLog`] failure converted into `E`.
    pub async fn handle<'a, T, F, Fut, E>(
        &self,
        event: &'a T,
        handler: F,
    ) -> core::result::Result<Delivery, E>
    where
        T: HasEventId,
        F: FnOnce(&'a T) -> Fut,
        Fut: Future<Output = core::result::Result<(), E>>,
        E: From<crate::error::EventsError>,
    {
        let event_id = event.event_id();
        if !self.log.claim(&self.name, event_id).await? {
            return Ok(Delivery::Duplicate);
        }

        match handler(event).await {
            Ok(()) => Ok(Delivery::Processed),
            Err(err) => {
                // Best-effort: if the log itself is unavailable, the handler's error is the one
                // worth reporting — it is the failure the operator has to act on, and the retained
                // claim is recoverable while a swallowed root cause is not.
                if let Err(log_err) = self.log.release(&self.name, event_id).await {
                    warn!(
                        consumer = %self.name,
                        %event_id,
                        error = %log_err,
                        "failed to withdraw a delivery claim; the event may not be reprocessed"
                    );
                }
                Err(err)
            }
        }
    }
}

/// Anything a delivery can be deduplicated on.
///
/// A trait rather than taking [`Event`](crate::Event) directly so that a consumer which has already
/// decoded its typed payload can still use the helper. Requiring it to reconstruct an envelope, or
/// to carry one alongside its own type, is the friction that makes people write the deduplication
/// by hand instead — and by hand is where it gets forgotten.
pub trait HasEventId {
    /// The event's deduplication key.
    fn event_id(&self) -> EventId;
}

impl HasEventId for crate::event::Event {
    fn event_id(&self) -> EventId {
        self.event_id
    }
}

impl HasEventId for EventId {
    fn event_id(&self) -> EventId {
        *self
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::error::EventsError;
    use crate::event::{Event, EventType};
    use enclave_core::{Actor, TenantId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn event() -> Event {
        Event::new(
            TenantId::new_v7(),
            EventType::AvScanRequested,
            Actor::System,
            &serde_json::json!({}),
        )
        .expect("encode")
    }

    #[tokio::test]
    async fn duplicate_delivery_runs_the_handler_exactly_once() {
        let consumer = IdempotentConsumer::new("av-worker", InMemoryDeliveryLog::default());
        let event = event();
        let runs = AtomicUsize::new(0);

        let run = |ev: &Event| {
            let _ = ev;
            runs.fetch_add(1, Ordering::SeqCst);
            async { Ok::<(), EventsError>(()) }
        };

        assert_eq!(consumer.handle(&event, run).await.expect("first"), Delivery::Processed);
        assert_eq!(consumer.handle(&event, run).await.expect("second"), Delivery::Duplicate);
        assert_eq!(consumer.handle(&event, run).await.expect("third"), Delivery::Duplicate);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn two_consumers_do_not_deduplicate_each_others_work() {
        // The same event legitimately goes to antivirus and to indexing; one must not suppress the
        // other. A shared log with a per-consumer key is what makes that safe.
        let log = std::sync::Arc::new(InMemoryDeliveryLog::default());
        let event = event();

        let av = IdempotentConsumer::new("av-worker", log.clone());
        let index = IdempotentConsumer::new("index-worker", log.clone());
        let noop = |_: &Event| async { Ok::<(), EventsError>(()) };

        assert_eq!(av.handle(&event, noop).await.expect("av"), Delivery::Processed);
        assert_eq!(index.handle(&event, noop).await.expect("index"), Delivery::Processed);
        assert_eq!(av.handle(&event, noop).await.expect("av again"), Delivery::Duplicate);
    }

    #[tokio::test]
    async fn a_failed_handler_leaves_the_event_eligible_for_redelivery() {
        let consumer = IdempotentConsumer::new("webhook-worker", InMemoryDeliveryLog::default());
        let event = event();
        let attempts = AtomicUsize::new(0);

        let flaky = |_: &Event| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(EventsError::from(crate::TransportError::retryable("endpoint down")))
                } else {
                    Ok(())
                }
            }
        };

        consumer.handle(&event, flaky).await.expect_err("first attempt fails");
        assert_eq!(
            consumer.handle(&event, flaky).await.expect("redelivery"),
            Delivery::Processed,
            "a failed handler must not consume the event"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_log_is_bounded_and_evicts_oldest_first() {
        let log = InMemoryDeliveryLog::with_capacity(2);
        let first = EventId::new_v7();
        let second = EventId::new_v7();
        let third = EventId::new_v7();

        assert!(log.claim("c", first).await.expect("claim"));
        assert!(log.claim("c", second).await.expect("claim"));
        assert!(!log.claim("c", second).await.expect("claim"), "still remembered");
        assert!(log.claim("c", third).await.expect("claim"));
        assert_eq!(log.len(), 2);
        // `first` fell out of the window, so it is claimable again — the documented trade.
        assert!(log.claim("c", first).await.expect("claim"));
    }

    #[tokio::test]
    async fn a_capacity_of_zero_still_deduplicates() {
        let log = InMemoryDeliveryLog::with_capacity(0);
        let id = EventId::new_v7();
        assert!(log.claim("c", id).await.expect("claim"));
        assert!(!log.claim("c", id).await.expect("claim"));
        assert!(!log.is_empty());
    }
}
