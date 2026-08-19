//! `docs/12-TESTING.md §4.4` — the share-link rows, against a real database.
//!
//! H3 is the reason this file needs a live PostgreSQL and real threads rather than a mock. The
//! wrong implementation — read the counter, compare it, issue, then increment — passes every
//! single-threaded test that could be written for it. It fails only when two callers are inside the
//! gap at once, and no amount of careful reading finds that; running it does.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use chrono::{Duration, Utc};
use enclave_core::{TenantId, UserId};
use enclave_db::{DbPool, TenantScoped};
use enclave_sharing::{
    record_event, redeem, repo, EventContext, NewShareLink, ShareAudience, ShareEventKind,
    SharePermission, ShareResourceKind, ShareToken, SharingError,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use uuid::Uuid;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

fn new_link(resource: Uuid, owner: UserId, max_downloads: Option<i64>) -> NewShareLink {
    NewShareLink {
        resource_type: ShareResourceKind::File,
        resource_id: resource,
        permission: SharePermission::PreviewOnly,
        allow_download: false,
        audience: ShareAudience::Anyone,
        password_hash: None,
        require_otp: false,
        require_mfa: false,
        expires_at: None,
        max_downloads,
        allowed_domains: None,
        created_by: owner,
    }
}

/// Creates a link and returns its plaintext token, which exists nowhere else afterwards.
async fn create_link(
    pool: &DbPool,
    tenant: TenantId,
    spine: &Spine,
    owner: UserId,
    max_downloads: Option<i64>,
) -> (Uuid, ShareToken) {
    let now = Utc::now();
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    spine.insert(&mut tx, owner, now).await.expect("spine");
    let token = ShareToken::generate().expect("entropy");
    let link = repo::create(
        &mut tx,
        tenant,
        token.digest(),
        &new_link(spine.file.as_uuid(), owner, max_downloads),
        now,
    )
    .await
    .expect("create link");
    tx.commit().await.expect("commit");
    (link.id, token)
}

/// **H1** — the token is unguessable and stored only as a hash.
///
/// The second clause is asserted against the row rather than against the type. A type that refuses
/// to hold plaintext is worth having, but what H1 promises is about what a database backup
/// contains, and only the database can answer that.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn h1_the_token_is_never_stored_and_the_digest_is_what_resolves_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let (id, token) = create_link(&pool, alpha, &spine, fixtures.alpha.owner, None).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM share_links WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("read the row");

    assert_eq!(stored, token.digest().to_hex());
    assert_ne!(stored, token.expose());

    // Every column, not only the one we meant to check: a token that leaked into a label or a
    // comment column would be just as usable, and this is the assertion that would notice.
    let row_dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(value, ' '), '') FROM share_links s, \
         jsonb_each_text(to_jsonb(s)) AS kv(key, value) WHERE s.id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("dump the row");
    assert!(
        !row_dump.contains(token.expose()),
        "the plaintext token appears in the row, so a database backup is a set of working links"
    );
    tx.commit().await.expect("commit");
    drop(db);
}

/// **H3** — `max_downloads` holds under 50 concurrent redemptions; exactly N succeed.
///
/// Fifty tasks on a multi-threaded runtime, each in its own transaction, against a limit of seven —
/// and, critically, on a pool with sixteen connections rather than the harness default of two.
///
/// The default is deliberate and right for what it was built for, but it made this test vacuous:
/// with two connections only two transactions are ever in flight, and the naive implementation
/// (read the counter, compare it, then increment) passed. Fifty tasks two at a time is a sequential
/// test wearing `tokio::spawn`. `TestDb::pool_with_connections` exists because of this test.
///
/// The assertion is on the number of *successes*, not on the final counter: a wrong implementation
/// can leave a correct-looking counter and twelve people holding the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn h3_the_download_budget_holds_under_fifty_concurrent_redemptions() {
    const ATTEMPTS: usize = 50;
    const LIMIT: i64 = 7;

    let (db, fixtures, _pool) = start().await;
    // Enough connections that the tasks genuinely overlap. See the doc comment.
    let pool = db.pool_with_connections(16).await.expect("a contended pool");
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let (id, token) = create_link(&pool, alpha, &spine, fixtures.alpha.owner, Some(LIMIT)).await;

    let token = Arc::new(token);
    let pool = Arc::new(pool);

    let mut handles = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS {
        let token = Arc::clone(&token);
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
            let outcome = redeem(&mut tx, &token, Utc::now()).await;
            // Committed either way. A refusal that rolled back would discard the row lock's
            // outcome, and the next caller would contend against stale state.
            tx.commit().await.expect("commit");
            outcome.map(|redemption| redemption.download_count)
        }));
    }

    let mut granted = Vec::new();
    let mut refused = 0_usize;
    for handle in handles {
        match handle.await.expect("task panicked") {
            Ok(count) => granted.push(count),
            Err(SharingError::BudgetExhausted) => refused += 1,
            Err(other) => panic!("unexpected failure: {other:?}"),
        }
    }

    assert_eq!(
        granted.len(),
        usize::try_from(LIMIT).expect("small"),
        "{} redemptions succeeded against a limit of {LIMIT} — the budget was read and acted on \
         rather than spent in one statement",
        granted.len()
    );
    assert_eq!(refused, ATTEMPTS - granted.len());

    // Each winner got a distinct number, 1..=LIMIT. Two callers receiving the same count would mean
    // two increments collapsed into one — the same bug wearing a different symptom.
    granted.sort_unstable();
    assert_eq!(granted, (1..=LIMIT).collect::<Vec<_>>());

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let final_count: i64 =
        sqlx::query_scalar("SELECT download_count FROM share_links WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .expect("read the counter");
    tx.commit().await.expect("commit");
    assert_eq!(final_count, LIMIT);

    drop(db);
}

/// **H4** — an expired or revoked link fails closed.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn h4_expiry_and_revocation_both_fail_closed() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let expired_token = ShareToken::generate().expect("entropy");
    let expired = NewShareLink {
        expires_at: Some(now - Duration::seconds(1)),
        ..new_link(spine.file.as_uuid(), fixtures.alpha.owner, None)
    };
    repo::create(&mut tx, alpha, expired_token.digest(), &expired, now).await.expect("create");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(
        matches!(redeem(&mut tx, &expired_token, now).await, Err(SharingError::LinkUnusable)),
        "an expired link was redeemable"
    );
    tx.commit().await.expect("commit");

    // Revoked. The link is usable when created and revoked afterwards — a link that was never
    // usable would prove nothing about revocation.
    let live = Spine::new(alpha);
    let (id, token) = create_link(&pool, alpha, &live, fixtures.alpha.owner, None).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(
        redeem(&mut tx, &token, now).await.is_ok(),
        "the link was not usable before revocation"
    );
    assert!(repo::revoke(&mut tx, alpha, id, now).await.expect("revoke"));
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    assert!(
        matches!(redeem(&mut tx, &token, now).await, Err(SharingError::LinkUnusable)),
        "a revoked link was still redeemable"
    );
    // Revoking twice is not an error, and does not move the original timestamp.
    assert!(!repo::revoke(&mut tx, alpha, id, now).await.expect("revoke again"));
    tx.commit().await.expect("commit");

    drop(db);
}

/// An unknown token is refused exactly as a malformed one is.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn an_unknown_token_is_indistinguishable_from_a_malformed_one() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    // Well-formed, correct length, simply never issued.
    let stranger = ShareToken::generate().expect("entropy");
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let unknown = redeem(&mut tx, &stranger, Utc::now()).await;
    tx.commit().await.expect("commit");

    assert!(matches!(unknown, Err(SharingError::LinkUnusable)));
    assert!(matches!(ShareToken::parse("nonsense"), Err(SharingError::LinkUnusable)));

    drop(db);
}

/// Refusals are recorded, and the record cannot be edited away.
///
/// A design where only the happy path writes an event is one where the traffic worth investigating
/// — somebody working through guesses — is the traffic that leaves no trace.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn a_refusal_is_recorded_and_cannot_be_edited_away() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();
    let (id, _token) = create_link(&pool, alpha, &spine, fixtures.alpha.owner, None).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    record_event(
        &mut tx,
        alpha,
        id,
        ShareEventKind::AuthFailed,
        EventContext {
            ip: Some("203.0.113.7".parse().expect("an address")),
            country: Some("GB"),
            user_agent: Some("curl/8.4.0"),
        },
        now,
    )
    .await
    .expect("record the refusal");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let recorded: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM share_link_events WHERE share_link_id = $1 AND event = 'AUTH_FAILED'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    assert_eq!(recorded, 1);

    // Migration 0008 grants no UPDATE and no DELETE on this table, so the application role cannot
    // remove the evidence that somebody probed the link. Asserted rather than assumed, because a
    // later migration adding a convenience grant would otherwise go unnoticed.
    let edited =
        sqlx::query("UPDATE share_link_events SET country = 'ZZ' WHERE share_link_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await;
    assert!(edited.is_err(), "the application role can rewrite share-link evidence");

    drop(db);
}

/// **H3, deterministically** — the `WHERE` clause is what enforces the budget, not the check above it.
///
/// # Why this test exists as well as the one above
///
/// The fifty-task test is the realistic one, and on its own it is **not sufficient**. Run against a
/// deliberately naive implementation — read the counter, compare it in Rust, then increment — it
/// passed three times out of three. The window between the stale read and the increment is real but
/// narrow, and hitting it by luck is not something a test should depend on. A concurrency test that
/// only fails sometimes is a test that will be marked flaky and then deleted.
///
/// So this one removes the luck. Every task opens its transaction and performs its read, then waits
/// on a barrier until all of them have, and only then writes. That is precisely the interleaving the
/// naive implementation is wrong about, held open until every contender is inside it.
///
/// With the limit in the `WHERE` clause, exactly `LIMIT` writes succeed however long the window is
/// held. Without it, all of them do — which is what the assertion below reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a live PostgreSQL with migrations 0001–0008; CI runs it with --include-ignored"]
async fn h3_the_limit_lives_in_the_where_clause_and_holds_when_every_reader_is_stale() {
    const CONTENDERS: usize = 20;
    const LIMIT: i64 = 5;

    let (db, fixtures, _pool) = start().await;
    let pool = db.pool_with_connections(24).await.expect("a pool wider than the contention");
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let (id, _token) = create_link(&pool, alpha, &spine, fixtures.alpha.owner, Some(LIMIT)).await;

    // Released once every contender has read; from that point all of them hold a stale count of 0.
    let gate = Arc::new(tokio::sync::Barrier::new(CONTENDERS));
    let pool = Arc::new(pool);

    let mut handles = Vec::with_capacity(CONTENDERS);
    for _ in 0..CONTENDERS {
        let gate = Arc::clone(&gate);
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");

            // The read every implementation does, naive or not.
            let seen: i64 =
                sqlx::query_scalar("SELECT download_count FROM share_links WHERE id = $1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .expect("read the counter");

            // Hold the window open until everybody is inside it.
            gate.wait().await;

            // The statement under test, verbatim from `redeem.rs`.
            let granted: Option<i64> = sqlx::query_scalar(
                "UPDATE share_links
                    SET download_count = download_count + 1
                  WHERE tenant_id = $1
                    AND id = $2
                    AND revoked_at IS NULL
                    AND (max_downloads IS NULL OR download_count < max_downloads)
                RETURNING download_count",
            )
            .bind(alpha.as_uuid())
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .expect("attempt the decrement");

            tx.commit().await.expect("commit");
            (seen, granted)
        }));
    }

    let mut stale_readers = 0_usize;
    let mut granted = Vec::new();
    for handle in handles {
        let (seen, outcome) = handle.await.expect("task panicked");
        if seen == 0 {
            stale_readers += 1;
        }
        if let Some(count) = outcome {
            granted.push(count);
        }
    }

    // The test's own precondition. Without this, a green result could mean the barrier failed to
    // create contention rather than that the statement held — the exact way the fifty-task test
    // above was passing before this one was written.
    assert_eq!(
        stale_readers, CONTENDERS,
        "only {stale_readers} of {CONTENDERS} contenders read a stale count, so the window this \
         test exists to hold open was not actually open"
    );

    assert_eq!(
        granted.len(),
        usize::try_from(LIMIT).expect("small"),
        "{} writes succeeded against a limit of {LIMIT}, with every contender holding a stale \
         read — the limit is not being enforced by the statement",
        granted.len()
    );

    granted.sort_unstable();
    assert_eq!(granted, (1..=LIMIT).collect::<Vec<_>>());

    drop(db);
}
