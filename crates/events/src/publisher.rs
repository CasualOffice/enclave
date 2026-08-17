//! The relay that moves committed outbox rows onto the bus.
//!
//! # Leadership
//!
//! Several `worker` replicas run this loop; only one may drain at a time, or the ordering the
//! outbox went to the trouble of preserving is lost and every consumer sees a much larger duplicate
//! rate than at-least-once implies. Leadership is a PostgreSQL **session advisory lock**
//! (`plans/M0-FOUNDATIONS.md` ENC-108): PostgreSQL is already a hard dependency, whereas a Redis
//! lock would add a second one whose failure mode — a lease that expires while the holder is still
//! working — is exactly the split brain we are trying to avoid. An advisory lock is released by the
//! server the instant the holding session ends, including when the process is killed, so a crashed
//! leader needs no timeout to be replaced.
//!
//! The lock is taken per batch rather than held for the process lifetime. Two publishers therefore
//! alternate batches instead of contending inside one, and neither ever observes the other's rows,
//! because they are never inside the drain at the same time.
//!
//! # Delivery guarantee
//!
//! At-least-once, and the ordering of the two writes is what makes it so: transport first, then
//! `published_at`. A crash between them redelivers on the next run — which is why every consumer
//! deduplicates on `event_id` ([`IdempotentConsumer`](crate::IdempotentConsumer)). Marking the row
//! first would be at-most-once and would lose events on exactly the same crash.
//!
//! # Failure handling
//!
//! A retryable failure **halts the batch**. Stepping over it would deliver later events before an
//! earlier one that has not been delivered at all, turning a broker hiccup into permanent
//! reordering. A permanent failure is stepped over and charged an attempt, so one poisoned row
//! cannot wedge every event behind it forever.

use std::future::Future;
use std::time::Duration;

use sqlx::{PgConnection, PgPool};
use tracing::{debug, info, warn};

use crate::error::{EventsError, Result};
use crate::outbox::Outbox;
use crate::transport::Transport;

/// The advisory-lock key that identifies outbox-publisher leadership.
///
/// A fixed constant rather than a hash of a string: advisory-lock keys share one namespace across
/// the whole database, so every user of one must be greppable. The bytes spell `ENCLEV` followed by
/// a slot number, leaving room for later single-leader loops to take adjacent keys without
/// colliding with this one.
pub const OUTBOX_PUBLISHER_LOCK_KEY: i64 = 0x454E_434C_4556_0001;

/// How the publisher paces and bounds itself.
#[derive(Debug, Clone, Copy)]
pub struct PublisherConfig {
    /// Rows read per drain.
    ///
    /// Bounds how much work is redone after a crash: a batch is the unit that can be partially
    /// delivered, so a larger batch is a larger duplicate burst on recovery, not a lost one.
    pub batch_size: i64,
    /// How many *permanent* failures a row survives before it is quarantined.
    ///
    /// Quarantine means "left unpublished with `last_error` set, and skipped" — never deleted. The
    /// row is evidence, and an operator has to be able to find out what was never delivered.
    pub max_attempts: i32,
    /// Idle wait between drains.
    ///
    /// Polling rather than `LISTEN`/`NOTIFY`: a notification delivered while no publisher held
    /// leadership would simply be missed, so the poll would have to exist anyway as the correctness
    /// path, and then the notification is only a latency optimisation. It can be added later
    /// without changing anything here.
    pub poll_interval: Duration,
    /// The advisory-lock key to contend on. Overridable so that tests, and any future second
    /// publisher over a partitioned subject set, do not serialise against production leadership.
    pub lock_key: i64,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_attempts: 10,
            poll_interval: Duration::from_secs(1),
            lock_key: OUTBOX_PUBLISHER_LOCK_KEY,
        }
    }
}

/// What one drain did.
///
/// Returned rather than only logged so that a caller can drive the publisher from a test or a
/// health check and assert on the result instead of scraping log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchOutcome {
    /// Whether this process held leadership. `false` means another replica is draining, which is
    /// the normal steady state for all but one of them and is not an error.
    pub leader: bool,
    /// Events accepted by the transport and marked published.
    pub published: usize,
    /// Rows charged an attempt for a failure that will recur.
    pub failed: usize,
    /// Whether the batch stopped early on a retryable failure.
    pub halted: bool,
}

/// Drains `events_outbox` onto a [`Transport`].
///
/// Generic over the transport rather than holding `Arc<dyn Transport>` so that the in-memory
/// transport used by tests and the JetStream one used in production are the same code path with no
/// dynamic dispatch in between — `Arc<T>` implements [`Transport`] when `T` does, so sharing one is
/// still available where it is wanted.
#[derive(Debug)]
pub struct Publisher<T> {
    pool: PgPool,
    transport: T,
    config: PublisherConfig,
}

impl<T: Transport> Publisher<T> {
    /// A publisher with default pacing.
    ///
    /// The pool is the platform-admin pool, not a `TenantScoped` handle: draining is inherently
    /// cross-tenant, and it is one of the three code paths `plans/M0-FOUNDATIONS.md` ENC-104 names
    /// as legitimately bypassing tenant scoping. Its safety comes from it never returning data to a
    /// caller — every row it reads goes to a subject keyed by the tenant that wrote it.
    #[must_use]
    pub fn new(pool: PgPool, transport: T) -> Self {
        Self { pool, transport, config: PublisherConfig::default() }
    }

    /// A publisher with explicit pacing.
    #[must_use]
    pub fn with_config(pool: PgPool, transport: T, config: PublisherConfig) -> Self {
        Self { pool, transport, config }
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &PublisherConfig {
        &self.config
    }

    /// Runs until `shutdown` resolves.
    ///
    /// A drain failure is logged and the loop continues, because the failures reachable here are
    /// "the database was briefly unavailable" and "leadership could not be taken" — neither is a
    /// reason to stop relaying events for the lifetime of the process. Anything genuinely
    /// unrecoverable surfaces as an unbounded, and therefore alertable, outbox backlog.
    ///
    /// # Errors
    ///
    /// Never returns `Err` today; the signature is fallible so that a future fatal condition can be
    /// reported without changing every call site.
    pub async fn run<S: Future<Output = ()>>(&self, shutdown: S) -> Result<()> {
        tokio::pin!(shutdown);
        info!(
            batch_size = self.config.batch_size,
            poll_ms = self.config.poll_interval.as_millis() as u64,
            "outbox publisher started"
        );
        loop {
            match self.run_once().await {
                Ok(outcome) if outcome.published > 0 || outcome.failed > 0 => {
                    debug!(
                        published = outcome.published,
                        failed = outcome.failed,
                        halted = outcome.halted,
                        "outbox batch drained"
                    );
                }
                Ok(_) => {}
                // No payload is logged: `EventsError`'s `Display` is payload-free by construction
                // (`CLAUDE.md` non-negotiable rule 10) and the source chain is not expanded here.
                Err(err) => warn!(error = %err, "outbox drain failed; will retry"),
            }

            tokio::select! {
                () = &mut shutdown => {
                    info!("outbox publisher stopping");
                    return Ok(());
                }
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
    }

    /// Attempts leadership and, if it is won, drains one batch.
    ///
    /// Separated from [`run`](Self::run) so that a test can step the publisher deterministically
    /// instead of racing a timer, and so that an operator tool can drain once without owning the
    /// process.
    ///
    /// # Errors
    ///
    /// [`EventsError::Storage`] if leadership or the drain's own statements fail. A transport
    /// failure is not an error here — it is recorded against the row and reported in the outcome,
    /// because it is a routine condition rather than a broken publisher.
    pub async fn run_once(&self) -> Result<BatchOutcome> {
        let mut conn = self.pool.acquire().await?;

        if !acquire_leadership(&mut conn, self.config.lock_key).await? {
            return Ok(BatchOutcome::default());
        }

        // The drain's result is held so that leadership is always released, including on the error
        // path. An advisory lock outlives the statement that took it, and a pooled connection
        // returning to the pool does not drop it — a leaked lock would stop every replica from ever
        // publishing again, which is the worst outcome available here.
        let drained = self.drain(&mut conn).await;
        release_leadership(&mut conn, self.config.lock_key).await;

        drained.map(|mut outcome| {
            outcome.leader = true;
            outcome
        })
    }

    /// Publishes the oldest batch, in order, stopping at the first retryable failure.
    async fn drain(&self, conn: &mut PgConnection) -> Result<BatchOutcome> {
        let rows =
            Outbox::fetch_unpublished(conn, self.config.max_attempts, self.config.batch_size)
                .await?;

        let mut outcome = BatchOutcome::default();
        for row in rows {
            let id = row.id;
            let event = match row.into_event() {
                Ok(event) => event,
                Err(err) => {
                    // Undecodable: the row will never become decodable on its own, so charge it and
                    // move on rather than blocking every event queued behind it.
                    Outbox::record_permanent_failure(conn, id, &err.last_error_text()).await?;
                    outcome.failed += 1;
                    continue;
                }
            };

            match self.transport.publish(&event).await {
                Ok(()) => {
                    Outbox::mark_published(conn, id).await?;
                    outcome.published += 1;
                }
                Err(err) => {
                    let err = EventsError::from(err);
                    let reason = err.last_error_text();
                    if err.is_retryable() {
                        Outbox::record_retryable_failure(conn, id, &reason).await?;
                        outcome.halted = true;
                        break;
                    }
                    Outbox::record_permanent_failure(conn, id, &reason).await?;
                    outcome.failed += 1;
                }
            }
        }

        Ok(outcome)
    }
}

/// Tries to become the single draining publisher, without waiting.
///
/// `pg_try_advisory_lock` rather than `pg_advisory_lock`: blocking would hold a pooled connection
/// hostage for as long as the current leader keeps working, and a pool of blocked followers is a
/// pool that cannot serve anything else. A follower returning immediately and sleeping is both
/// cheaper and self-correcting.
async fn acquire_leadership(conn: &mut PgConnection, key: i64) -> Result<bool> {
    let (acquired,): (bool,) =
        sqlx::query_as("SELECT pg_try_advisory_lock($1)").bind(key).fetch_one(conn).await?;
    Ok(acquired)
}

/// Releases leadership, logging rather than propagating a failure.
///
/// The caller is on its way out with a result it must not lose, and a failed unlock is survivable:
/// the lock is session-scoped, so it disappears when the connection is eventually closed or the
/// process dies. Turning that into a returned error would discard the batch outcome to report
/// something that resolves itself.
async fn release_leadership(conn: &mut PgConnection, key: i64) {
    if let Err(err) = sqlx::query("SELECT pg_advisory_unlock($1)").bind(key).execute(conn).await {
        warn!(error = %err, "failed to release outbox publisher leadership");
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::event::{Event, EventType};
    use crate::test_support;
    use crate::transport::InMemoryTransport;
    use enclave_core::{Actor, TenantId, UserId};

    fn events(tenant: TenantId, count: usize) -> Vec<Event> {
        (0..count)
            .map(|n| {
                Event::new(
                    tenant,
                    EventType::FileVersionCreated,
                    Actor::User(UserId::new_v7()),
                    &serde_json::json!({ "seq": n }),
                )
                .expect("encode")
            })
            .collect()
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let config = PublisherConfig::default();
        assert_eq!(config.lock_key, OUTBOX_PUBLISHER_LOCK_KEY);
        assert!(config.batch_size > 0);
        assert!(config.max_attempts > 0);
    }

    #[test]
    fn a_follower_reports_no_work_rather_than_an_error() {
        // The steady state for every replica but one, and it must be indistinguishable from
        // "nothing to do" to the caller — a follower is not a failure.
        let outcome = BatchOutcome::default();
        assert!(!outcome.leader);
        assert_eq!(outcome.published, 0);
        assert!(!outcome.halted);
    }

    /// A batch that dies part-way through must resume from the oldest undelivered row.
    ///
    /// Simulated by a transport that starts failing mid-batch, which is the same observable
    /// situation as a killed process — some rows delivered and marked, the rest untouched — but
    /// deterministic. `plans/M0-FOUNDATIONS.md` D7: the database is real because the property being
    /// tested is a property of the database.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL with migration 0001 applied (ENC-112 fixtures)"]
    async fn a_publisher_killed_mid_batch_resumes_without_loss() {
        let _outbox_guard = test_support::outbox_lock().lock().await;
        let pool = test_support::pool().await;
        let tenant = TenantId::new_v7();
        let batch = events(tenant, 5);

        let mut tx = pool.begin().await.expect("begin");
        crate::Outbox::publish_all(&mut tx, &batch).await.expect("write");
        tx.commit().await.expect("commit");

        let transport = std::sync::Arc::new(InMemoryTransport::new());
        let config = PublisherConfig {
            batch_size: 10,
            lock_key: test_support::unique_lock_key(),
            ..PublisherConfig::default()
        };
        let publisher = Publisher::with_config(pool.clone(), transport.clone(), config);

        // Die after two: the broker becomes unreachable, which is a retryable failure.
        transport.fail_after(2, true);
        let outcome = publisher.run_once().await.expect("drain");
        assert!(outcome.leader);
        assert_eq!(outcome.published, 2);
        assert!(outcome.halted, "a retryable failure must stop the batch");

        // Recover and resume. Nothing is lost, and the three survivors are the *later* three —
        // proving the drain resumed from the oldest undelivered row rather than restarting.
        transport.recover();
        let outcome = publisher.run_once().await.expect("drain");
        assert_eq!(outcome.published, 3);
        assert!(!outcome.halted);

        let delivered = transport.delivered();
        assert_eq!(delivered.len(), 5, "no event may be lost across the restart");
        let ids: Vec<_> = delivered.iter().map(|e| e.event_id).collect();
        let expected: Vec<_> = batch.iter().map(|e| e.event_id).collect();
        assert_eq!(ids, expected, "delivery must stay in outbox order");

        let mut conn = pool.acquire().await.expect("acquire");
        assert_eq!(test_support::unpublished_for(&mut conn, tenant).await, 0);
        test_support::cleanup(&mut conn, tenant).await;
    }

    /// A row that can never be delivered must not wedge the queue behind it.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL with migration 0001 applied (ENC-112 fixtures)"]
    async fn a_permanently_rejected_row_is_stepped_over_and_eventually_quarantined() {
        let _outbox_guard = test_support::outbox_lock().lock().await;
        let pool = test_support::pool().await;
        let tenant = TenantId::new_v7();
        let batch = events(tenant, 2);

        let mut tx = pool.begin().await.expect("begin");
        crate::Outbox::publish_all(&mut tx, &batch).await.expect("write");
        tx.commit().await.expect("commit");

        let transport = std::sync::Arc::new(InMemoryTransport::new());
        transport.fail_after(0, false);
        let config = PublisherConfig {
            max_attempts: 1,
            lock_key: test_support::unique_lock_key(),
            ..PublisherConfig::default()
        };
        let publisher = Publisher::with_config(pool.clone(), transport.clone(), config);

        let outcome = publisher.run_once().await.expect("drain");
        assert_eq!(outcome.failed, 2, "both rows are charged, neither halts the batch");
        assert!(!outcome.halted);

        // Both have exhausted their single attempt, so the next drain sees nothing at all rather
        // than retrying them forever.
        let outcome = publisher.run_once().await.expect("drain");
        assert_eq!(outcome.published + outcome.failed, 0);

        let mut conn = pool.acquire().await.expect("acquire");
        // Quarantined, not deleted: the rows remain as evidence of what was never delivered.
        assert_eq!(test_support::unpublished_for(&mut conn, tenant).await, 2);
        test_support::cleanup(&mut conn, tenant).await;
    }

    /// Only one replica drains at a time.
    #[tokio::test]
    #[ignore = "requires a live PostgreSQL with migration 0001 applied (ENC-112 fixtures)"]
    async fn only_one_publisher_holds_leadership_at_a_time() {
        let _outbox_guard = test_support::outbox_lock().lock().await;
        let pool = test_support::pool().await;
        let key = test_support::unique_lock_key();

        let mut first = pool.acquire().await.expect("acquire");
        assert!(acquire_leadership(&mut first, key).await.expect("lock"));

        let mut second = pool.acquire().await.expect("acquire");
        assert!(
            !acquire_leadership(&mut second, key).await.expect("lock"),
            "a second session must not win leadership while the first holds it"
        );

        release_leadership(&mut first, key).await;
        assert!(
            acquire_leadership(&mut second, key).await.expect("lock"),
            "leadership must be immediately available once released"
        );
        release_leadership(&mut second, key).await;
    }
}
