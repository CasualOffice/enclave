//! Enclave's eventing substrate: a transactional outbox, a single-leader publisher, and the
//! deduplication every consumer of an at-least-once bus needs.
//!
//! # Why this exists in M0, before anything consumes an event
//!
//! Nothing subscribes until M1. The outbox lands now anyway
//! (`plans/M0-FOUNDATIONS.md` D6) because *writing an event inside the transaction that caused it*
//! is a property of how writes are done, not a feature. Adding it after the first twenty write
//! paths exist means editing twenty write paths, and the nineteenth one gets it subtly wrong.
//!
//! # The shape
//!
//! ```text
//! domain write ──┐
//!                ├── one transaction ──► events_outbox      (Outbox::publish)
//! state change ──┘                            │
//!                                             ▼
//!                          advisory-lock leader, oldest first (Publisher)
//!                                             │
//!                                             ▼
//!                                        Transport            (NATS JetStream in M1)
//!                                             │
//!                                             ▼
//!                              dedupe on event_id            (IdempotentConsumer)
//! ```
//!
//! Three guarantees, and where each is enforced:
//!
//! | Guarantee | Enforced by |
//! |---|---|
//! | An event exists if and only if the state change committed | [`Outbox::publish`] taking a transaction, never a pool |
//! | Every committed event is delivered at least once | [`Publisher`] writing `published_at` only *after* the transport accepts |
//! | A redelivery does not re-run a side effect | [`IdempotentConsumer`] claiming on `event_id` |
//!
//! # NATS is deliberately not linked yet
//!
//! [`Transport`] is a trait with an in-memory implementation, so the crate compiles, and its
//! delivery properties are tested, without a broker. See [`transport`] for why that is a design
//! choice rather than a placeholder.
//!
//! # Example
//!
//! ```no_run
//! # use enclave_core::{Actor, TenantId, UserId};
//! # use enclave_events::{Event, EventType, Outbox};
//! # async fn example(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//! let tenant = TenantId::new_v7();
//! let mut tx = pool.begin().await?;
//!
//! // … the state change itself happens here, on the same `tx` …
//!
//! let event = Event::new(
//!     tenant,
//!     EventType::FileVersionCreated,
//!     Actor::User(UserId::new_v7()),
//!     &serde_json::json!({ "file_id": "…", "version_id": "…" }),
//! )?;
//! Outbox::publish(&mut tx, &event).await?;
//!
//! // Commit publishes both, or neither.
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```

pub mod consumer;
pub mod error;
pub mod event;
pub mod outbox;
pub mod publisher;
pub mod transport;

pub use consumer::{Delivery, DeliveryLog, HasEventId, IdempotentConsumer, InMemoryDeliveryLog};
pub use error::{EventsError, Result, TransportError};
pub use event::{Event, EventId, EventType, CURRENT_SCHEMA_VERSION};
pub use outbox::Outbox;
pub use publisher::{BatchOutcome, Publisher, PublisherConfig, OUTBOX_PUBLISHER_LOCK_KEY};
pub use transport::{InMemoryTransport, Transport};

/// Shared plumbing for the database-backed tests.
///
/// These tests are `#[ignore]` rather than mocked: the properties they assert — that a rollback
/// leaves nothing behind, that an advisory lock excludes a second session — are properties of
/// PostgreSQL, and a mock of PostgreSQL asserting them would only be asserting itself
/// (`plans/M0-FOUNDATIONS.md` D7). Each gets a throwaway database from `enclave_testing::TestDb`,
/// so `DATABASE_URL` need only point at a server these may create databases on:
///
/// ```text
/// DATABASE_URL=postgres://…/enclave cargo test -p enclave-events -- --ignored
/// ```
///
/// They used to connect to `DATABASE_URL` directly and depend on some *other* crate's test having
/// migrated it first — an ordering that was an accident of how Cargo sequences test binaries, and a
/// migration that had no business being applied there at all (`ENC-504`).
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::TenantId;
    use enclave_testing::TestDb;
    use sqlx::{PgConnection, PgPool, Row};
    use std::sync::atomic::{AtomicI64, Ordering};

    /// Serialises every test that touches `events_outbox`.
    ///
    /// The publisher drains the outbox **across all tenants** — that is the whole point of it, and
    /// why it is one of the three cross-tenant platform paths. So per-test tenant ids do not
    /// isolate these tests from each other: a publisher started by one test happily publishes
    /// another test's rows, and both then disagree with their own counts. It showed up as
    /// `published: 7` against an expected `2`.
    ///
    /// A lock rather than a database per test, because it matches the thing being modelled: there
    /// is one publisher per cluster, holding one advisory lock. Tests that run it should queue for
    /// the same reason production instances do.
    ///
    /// `ENC-504` gave every test its own database, which now isolates them on its own, so this is
    /// no longer the only thing keeping them apart. It is kept rather than deleted because it still
    /// models the production shape, and because removing it would be a behavioural change to five
    /// concurrency tests made in the same commit as a change to how they get a database — two
    /// things failing at once is two things nobody can attribute.
    pub(crate) fn outbox_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// A throwaway database, migrated, and a pool onto it.
    ///
    /// Returns a guard rather than a bare [`PgPool`] because the database lives exactly as long as
    /// the `TestDb` inside it: hold the value for the length of the test and the database is
    /// dropped when it goes out of scope. It derefs to the pool, so call sites read as they did.
    pub(crate) async fn pool() -> TestPool {
        let db = TestDb::start().await.expect(
            "these tests need a PostgreSQL they may create databases on; CI provides a service \
             container, locally use deploy/compose/dev.yml and set DATABASE_URL",
        );
        let pool = PgPool::connect(db.url()).await.expect("connect to the test database");
        TestPool { pool, _db: db }
    }

    /// A pool and the throwaway database it addresses, kept together so neither outlives the other.
    pub(crate) struct TestPool {
        pool: PgPool,
        /// Dropped last, which drops the database. Named with a leading underscore because it is
        /// held for its destructor and nothing else.
        _db: TestDb,
    }

    impl std::ops::Deref for TestPool {
        type Target = PgPool;

        fn deref(&self) -> &Self::Target {
            &self.pool
        }
    }

    /// Every outbox row for a tenant, published or not.
    pub(crate) async fn count_for(conn: &mut PgConnection, tenant: TenantId) -> i64 {
        let row = sqlx::query("SELECT count(*) FROM events_outbox WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .fetch_one(conn)
            .await
            .expect("count");
        row.try_get::<i64, _>(0).expect("count column")
    }

    /// Outbox rows for a tenant that have not been delivered.
    pub(crate) async fn unpublished_for(conn: &mut PgConnection, tenant: TenantId) -> i64 {
        let row = sqlx::query(
            "SELECT count(*) FROM events_outbox WHERE tenant_id = $1 AND published_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .fetch_one(conn)
        .await
        .expect("count");
        row.try_get::<i64, _>(0).expect("count column")
    }

    /// Removes a test tenant's rows, so repeated local runs do not accumulate.
    pub(crate) async fn cleanup(conn: &mut PgConnection, tenant: TenantId) {
        sqlx::query("DELETE FROM events_outbox WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .execute(conn)
            .await
            .expect("cleanup");
    }

    /// An advisory-lock key no other test is using.
    ///
    /// Advisory-lock keys share one namespace within a database. Contending on the real publisher
    /// key would make two unrelated tests serialise — or, worse, make one silently observe itself
    /// as a follower and assert nothing. Since `ENC-504` each test has its own database and so its
    /// own namespace, but a test that asserts on leadership must still not use the key production
    /// uses, or a stray publisher in the same database would decide the outcome.
    pub(crate) fn unique_lock_key() -> i64 {
        static NEXT: AtomicI64 = AtomicI64::new(0);
        // Far from `OUTBOX_PUBLISHER_LOCK_KEY`, and distinct per call within a run.
        0x7E57_0000_0000_0000 + NEXT.fetch_add(1, Ordering::SeqCst)
    }
}
