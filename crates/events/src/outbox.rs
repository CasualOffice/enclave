//! The transactional outbox: writing an event *inside* the transaction that caused it.
//!
//! This is design decision D6 (`plans/M0-FOUNDATIONS.md`), and the reason the signature is what it
//! is. [`Outbox::publish`] takes a connection that the caller has already put into a transaction —
//! never a pool. A pool handle would let a caller write the event outside the state change it
//! describes, and the two failure modes that follow are both silent: an event announcing a version
//! that was rolled back, or a version nobody was ever told about. Neither shows up as an error
//! anywhere; both show up weeks later as an index that disagrees with the database.
//!
//! Taking `&mut PgConnection` rather than a concrete transaction type is what lets this work with
//! `db`'s `TenantScoped` handle (`plans/M0-FOUNDATIONS.md` D3) without this crate depending on
//! `db`: `&mut *tx` coerces, and so does the connection a `TenantScoped` transaction is running on.
//! The tenant context `SET LOCAL` has already been issued on that connection, so the insert is
//! covered by the same row-level security as the state change beside it.
//!
//! # Storage shape
//!
//! `events_outbox` is defined in `docs/04-DATA-MODEL.md §17`. It has no `actor` column, so the
//! envelope's actor is nested in the payload column by [`StoredPayload`] — see that type for why,
//! and for what changes if a migration later adds the column.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, Uuid};
use sqlx::{PgConnection, Row};

use crate::error::{EventsError, Result};
use crate::event::{Event, EventId, EventType, StoredPayload};

/// Writes events to `events_outbox`.
///
/// A unit-like namespace rather than a constructed service: it holds no state, and every method
/// takes the connection it must run on. Anything that could be held — a pool, a tenant — is exactly
/// what must *not* be captured here, because capturing it is how an event ends up written outside
/// its transaction.
#[derive(Debug, Clone, Copy)]
pub struct Outbox;

impl Outbox {
    /// Records one event in the caller's open transaction.
    ///
    /// The event becomes visible to the publisher if and only if that transaction commits. There is
    /// no flush, no background queue and no in-memory buffer between here and durability, which is
    /// the entire point.
    ///
    /// Duplicate event ids are collapsed (`ON CONFLICT DO NOTHING`) rather than raising. An id is
    /// UUIDv7-unique per occurrence, so the only way to present the same one twice is a producer
    /// that deliberately derived it from the state change in order to make its own write idempotent
    /// (see [`Event::with_event_id`]) — and for that producer, "already recorded" is success.
    ///
    /// # Errors
    ///
    /// [`EventsError::Encode`] if the envelope's actor and payload cannot be re-serialized;
    /// [`EventsError::Storage`] if the statement fails.
    pub async fn publish(conn: &mut PgConnection, event: &Event) -> Result<()> {
        let stored =
            serde_json::to_value(StoredPayload { actor: event.actor, data: event.payload.clone() })
                .map_err(EventsError::Encode)?;

        sqlx::query(
            "INSERT INTO events_outbox \
             (id, tenant_id, event_type, schema_version, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(event.event_id.as_uuid())
        .bind(event.tenant_id.as_uuid())
        .bind(event.event_type.as_str())
        .bind(event.schema_version)
        .bind(stored)
        .bind(event.occurred_at)
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Records several events in one transaction, in the order given.
    ///
    /// Sequential rather than concurrent on purpose: they share one connection, and the outbox is
    /// drained in `created_at, id` order, so preserving the caller's ordering here preserves the
    /// ordering consumers observe.
    ///
    /// # Errors
    ///
    /// As [`Outbox::publish`]. The first failure aborts, leaving the caller's transaction to be
    /// rolled back — which is correct: a partially recorded set of events would describe a state
    /// change that did not fully happen.
    pub async fn publish_all(conn: &mut PgConnection, events: &[Event]) -> Result<()> {
        for event in events {
            Self::publish(conn, event).await?;
        }
        Ok(())
    }

    /// How many events are still waiting to be delivered.
    ///
    /// Exposed because outbox depth is the one number that tells an operator whether eventing is
    /// healthy: a backlog that grows monotonically means the publisher has lost leadership, lost
    /// the broker, or is wedged behind a poisoned row, and none of those raise an alert on their
    /// own.
    ///
    /// # Errors
    ///
    /// [`EventsError::Storage`] if the query fails.
    pub async fn unpublished_count(conn: &mut PgConnection) -> Result<i64> {
        let row = sqlx::query("SELECT count(*) FROM events_outbox WHERE published_at IS NULL")
            .fetch_one(conn)
            .await?;
        Ok(row.try_get::<i64, _>(0)?)
    }

    /// Reads the oldest undelivered rows, oldest first.
    ///
    /// `attempts < max_attempts` quarantines a row that has repeatedly failed for a reason that
    /// will not change, so it stops blocking every event behind it. Retryable failures do not
    /// consume this budget — see [`record_retryable_failure`](Outbox::record_retryable_failure).
    pub(crate) async fn fetch_unpublished(
        conn: &mut PgConnection,
        max_attempts: i32,
        limit: i64,
    ) -> Result<Vec<OutboxRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, event_type, schema_version, payload, created_at \
             FROM events_outbox \
             WHERE published_at IS NULL AND attempts < $1 \
             ORDER BY created_at ASC, id ASC \
             LIMIT $2",
        )
        .bind(max_attempts)
        .bind(limit)
        .fetch_all(conn)
        .await?;

        rows.into_iter().map(OutboxRow::from_row).collect()
    }

    /// Marks a row delivered.
    ///
    /// Guarded by `published_at IS NULL` so that a second publisher which somehow ran concurrently
    /// cannot rewrite an already-recorded delivery time; the guard is cheap and the alternative is
    /// an audit trail that lies about when an event went out.
    pub(crate) async fn mark_published(conn: &mut PgConnection, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE events_outbox \
             SET published_at = now(), attempts = attempts + 1, last_error = NULL \
             WHERE id = $1 AND published_at IS NULL",
        )
        .bind(id)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Charges a row one attempt and records why it failed.
    ///
    /// Used for failures that will recur identically — an undecodable row, a subject the broker
    /// rejects. Consuming the attempt budget is what eventually quarantines the row instead of
    /// letting it wedge the queue.
    pub(crate) async fn record_permanent_failure(
        conn: &mut PgConnection,
        id: Uuid,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE events_outbox SET attempts = attempts + 1, last_error = $2 \
             WHERE id = $1 AND published_at IS NULL",
        )
        .bind(id)
        .bind(reason)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Records why a row could not be delivered *without* charging it an attempt.
    ///
    /// This asymmetry is deliberate and it is the difference between an outage and data loss. A
    /// broker down for an hour, polled every second, would burn through any finite attempt budget
    /// and quarantine every pending event — permanently dropping traffic because a dependency was
    /// briefly unavailable. Only failures that are the row's own fault consume the budget.
    pub(crate) async fn record_retryable_failure(
        conn: &mut PgConnection,
        id: Uuid,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE events_outbox SET last_error = $2 WHERE id = $1 AND published_at IS NULL",
        )
        .bind(id)
        .bind(reason)
        .execute(conn)
        .await?;
        Ok(())
    }
}

/// One `events_outbox` row, still in its stored form.
///
/// Kept separate from [`Event`] because decoding can fail per row, and the publisher must be able
/// to name and charge the offending row — which it cannot do if the failure happened while building
/// the collection.
#[derive(Debug)]
pub(crate) struct OutboxRow {
    pub(crate) id: Uuid,
    tenant_id: Uuid,
    event_type: String,
    schema_version: i32,
    payload: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl OutboxRow {
    fn from_row(row: sqlx::postgres::PgRow) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            event_type: row.try_get("event_type")?,
            schema_version: row.try_get("schema_version")?,
            payload: row.try_get("payload")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// Rebuilds the envelope, or reports which row could not be rebuilt.
    ///
    /// The event type is parsed through serde rather than `FromStr` so that an unknown subject and
    /// a malformed payload produce the same [`EventsError::Decode`] carrying the same row id; the
    /// publisher's handling of the two is identical, and two error shapes for one disposition is
    /// just a second code path to keep in step.
    pub(crate) fn into_event(self) -> Result<Event> {
        let decode = |source| EventsError::Decode { event_id: self.id, source };
        let event_type: EventType =
            serde_json::from_value(serde_json::Value::String(self.event_type.clone()))
                .map_err(decode)?;
        let stored: StoredPayload = serde_json::from_value(self.payload.clone()).map_err(decode)?;

        Ok(Event {
            event_id: EventId::from_uuid(self.id),
            tenant_id: TenantId::from_uuid(self.tenant_id),
            event_type,
            schema_version: self.schema_version,
            occurred_at: self.created_at,
            actor: stored.actor,
            payload: stored.data,
        })
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::test_support;
    use enclave_core::{Actor, UserId};

    fn sample(tenant: TenantId) -> Event {
        Event::new(
            tenant,
            EventType::FileVersionCreated,
            Actor::User(UserId::new_v7()),
            &serde_json::json!({ "version_id": "v-1" }),
        )
        .expect("encode")
    }

    #[test]
    fn the_stored_form_round_trips_the_actor_the_table_has_no_column_for() {
        let event = sample(TenantId::new_v7());
        let stored =
            serde_json::to_value(StoredPayload { actor: event.actor, data: event.payload.clone() })
                .expect("encode");

        let row = OutboxRow {
            id: event.event_id.as_uuid(),
            tenant_id: event.tenant_id.as_uuid(),
            event_type: event.event_type.as_str().to_owned(),
            schema_version: event.schema_version,
            payload: stored,
            created_at: event.occurred_at,
        };
        assert_eq!(row.into_event().expect("decode"), event);
    }

    #[test]
    fn a_row_with_an_unknown_subject_fails_decoding_against_its_own_id() {
        let id = Uuid::now_v7();
        let row = OutboxRow {
            id,
            tenant_id: Uuid::now_v7(),
            event_type: "file.teleported".to_owned(),
            schema_version: 1,
            payload: serde_json::json!({ "actor": { "kind": "system" }, "data": {} }),
            created_at: Utc::now(),
        };
        let err = row.into_event().expect_err("must not decode");
        assert!(err.to_string().contains(&id.to_string()));
        // A row nobody can decode must never be retried forever; it is quarantined by attempts.
        assert!(!err.is_retryable());
    }

    /// The rollback property, which is the whole reason [`Outbox::publish`] takes a transaction.
    ///
    /// Ignored by default: it asserts a property of PostgreSQL's transaction semantics interacting
    /// with our statements, and mocking either would assert nothing (`plans/M0-FOUNDATIONS.md` D7).
    /// Run with a database from the dev stack: `DATABASE_URL=… cargo test -p enclave-events --
    /// --ignored`.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL with migration 0001 applied (ENC-112 fixtures)"]
    async fn a_rolled_back_transaction_publishes_nothing() {
        let _outbox_guard = test_support::outbox_lock().lock().await;
        let pool = test_support::pool().await;
        let tenant = TenantId::new_v7();
        let event = sample(tenant);

        let mut tx = pool.begin().await.expect("begin");
        Outbox::publish(&mut tx, &event).await.expect("write");
        // Visible inside the transaction that wrote it…
        assert_eq!(
            test_support::count_for(&mut tx, tenant).await,
            1,
            "the event must be visible to its own transaction"
        );
        tx.rollback().await.expect("rollback");

        // …and gone once that transaction did not happen.
        let mut conn = pool.acquire().await.expect("acquire");
        assert_eq!(
            test_support::count_for(&mut conn, tenant).await,
            0,
            "a rolled-back state change must not leave an event announcing it"
        );
    }

    /// The other half of the same property: a commit does publish, exactly once.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL with migration 0001 applied (ENC-112 fixtures)"]
    async fn a_committed_transaction_publishes_once_even_if_the_event_is_written_twice() {
        let _outbox_guard = test_support::outbox_lock().lock().await;
        let pool = test_support::pool().await;
        let tenant = TenantId::new_v7();
        let event = sample(tenant);

        let mut tx = pool.begin().await.expect("begin");
        Outbox::publish(&mut tx, &event).await.expect("write");
        Outbox::publish(&mut tx, &event).await.expect("idempotent rewrite");
        tx.commit().await.expect("commit");

        let mut conn = pool.acquire().await.expect("acquire");
        assert_eq!(test_support::count_for(&mut conn, tenant).await, 1);
        test_support::cleanup(&mut conn, tenant).await;
    }
}
