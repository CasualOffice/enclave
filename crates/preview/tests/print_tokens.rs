//! `print_tokens` against a real PostgreSQL: the single-use property, and the four ways to be
//! refused that must look like one.
//!
//! # Why every one of these needs a live database
//!
//! The property under test **is** a `WHERE` clause. `UPDATE … WHERE redeemed_at IS NULL RETURNING`
//! is safe against itself because of what PostgreSQL does when a second transaction meets a row
//! lock under `READ COMMITTED` — it waits, then re-evaluates the predicate against the *updated*
//! row. Nothing simulated can show that. A mock registry would be asserting the behaviour of the
//! mock.
//!
//! # The sequential test is not the interesting one
//!
//! `a_grant_is_spent_by_being_redeemed` would pass against the `HashMap` this table replaced, and
//! against any implementation that remembers. What `ENC-724` is about is two API replicas, and the
//! only test that speaks to that is [`two_concurrent_redemptions_of_one_grant_produce_one_winner`],
//! which runs both halves on **two separate pooled connections** with a barrier between the read
//! and the write so the interleaving is forced rather than hoped for.
//!
//! One earlier concurrency test in this repository passed 3/3 against a naive implementation
//! because the pool was capped at two connections and the race could not occur (`docs/12 §1.2`).
//! The pool here is opened with eight, the two tasks are spawned rather than awaited in sequence,
//! and the assertion is on the *pair* of outcomes — exactly one `Some` and exactly one `None` —
//! rather than on either one alone, so "both failed" fails just as loudly as "both succeeded".
//!
//! # Everything runs through the harness pool, which `SET ROLE enclave_app`s
//!
//! A test that connected as the cluster superuser would prove nothing about row-level security or
//! about the `DELETE` grant `0027` adds, because a superuser bypasses both. That is PR #22's
//! finding and `ENC-705`/`ENC-686`'s, and it is why the setup writes are on
//! [`TestDb::connect`] and every assertion is on [`TestDb::pool`].

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use enclave_core::{Actor, FileId, SessionId, TenantId, UserId, VersionId};
use enclave_db::DbPool;
use enclave_preview::print::{self, PrintGrant, PrintToken};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use tokio::sync::Barrier;
use uuid::Uuid;

/// The lifetime `docs/05-API.md §9` fixes, restated here so a grant in a test is a realistic one.
const TTL: i64 = 120;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    // Eight, deliberately. A pool of two cannot exhibit the race this file exists to prove, which
    // is how a previous concurrency test here passed 3/3 against a naive implementation.
    let pool = db.pool_with_connections(8).await.expect("application pool");
    (db, fixtures, pool)
}

static MINOR: AtomicI32 = AtomicI32::new(0);

fn next_minor() -> i32 {
    MINOR.fetch_add(1, Ordering::Relaxed)
}

/// A spine and one `AVAILABLE`/`CLEAN` version of its file, written over the admin connection.
async fn content(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> (Spine, VersionId) {
    let now = Utc::now();
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, now).await.expect("insert the spine");

    let version = VersionId::new_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 4096, $6, 'application/pdf', 1, $7, 'AVAILABLE', 'CLEAN',
                 $8, $9)",
    )
    .bind(version.as_uuid())
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("enclave/{tenant}/files/{}/versions/{version}", spine.file))
    .bind(Uuid::now_v7())
    .bind("0".repeat(64))
    .bind(next_minor())
    .bind(Uuid::nil())
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("insert version");

    (spine, version)
}

fn grant_for(
    file: FileId,
    version: VersionId,
    actor: Actor,
    session: Option<SessionId>,
    expires_at: DateTime<Utc>,
) -> PrintGrant {
    PrintGrant { file, version, actor, session, watermark: true, expires_at }
}

/// Mints a grant through the real statement and returns the token nobody but the caller holds.
async fn mint(pool: &DbPool, tenant: TenantId, grant: &PrintGrant) -> PrintToken {
    let token = PrintToken::generate().expect("entropy");
    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    print::issue(&mut tx, tenant, token.digest(), grant).await.expect("issue the grant");
    tx.commit().await.expect("commit");
    token
}

/// Writes a grant that is *already dead*, over the admin connection.
///
/// It cannot go through [`mint`], and that is a property rather than an inconvenience: `0027`
/// carries `CHECK (expires_at > issued_at)`, so a grant that expired before it was issued is not a
/// row the database will accept — see [`a_grant_cannot_be_minted_already_dead`], which asserts
/// exactly that. What an expired grant actually looks like is a row issued ten minutes ago that
/// died eight minutes ago, and that is what this writes. Setup, not subject: every assertion that
/// follows runs over the `enclave_app` pool.
async fn mint_expired(conn: &mut PgConnection, tenant: TenantId, grant: &PrintGrant) -> PrintToken {
    let token = PrintToken::generate().expect("entropy");
    sqlx::query(
        "INSERT INTO print_tokens
           (tenant_id, token_hash, file_id, version_id, actor_type, actor_id, session_id,
            watermark, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() - interval '10 minutes',
                 now() - interval '8 minutes')",
    )
    .bind(tenant.as_uuid())
    .bind(token.digest().to_hex())
    .bind(grant.file.as_uuid())
    .bind(grant.version.as_uuid())
    .bind(grant.actor.kind().as_str())
    .bind(grant.actor.subject_id())
    .bind(grant.session.map(|id| id.as_uuid()))
    .bind(grant.watermark)
    .execute(&mut *conn)
    .await
    .expect("insert an expired grant");
    token
}

/// One redemption, on its own connection, through the real statement.
async fn redeem(
    pool: &DbPool,
    tenant: TenantId,
    file: FileId,
    actor: Actor,
    session: Option<SessionId>,
    token: &PrintToken,
) -> Option<enclave_preview::RedeemedPrint> {
    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let outcome = print::redeem(&mut tx, tenant, file, actor, session, token.digest())
        .await
        .expect("the statement must run");
    tx.commit().await.expect("commit");
    outcome
}

// =================================================================================================
// The property the feature is named for.
// =================================================================================================

/// **A print grant that can be redeemed twice is a download.**
///
/// The first redemption is the positive control, and it is load-bearing rather than decoration: an
/// assertion that the second redemption fails passes for free against a statement that never
/// honours anything, a missing table, or a typo in the digest.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_grant_is_spent_by_being_redeemed() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let grant = grant_for(spine.file, version, actor, session, Utc::now() + Duration::seconds(TTL));
    let token = mint(&pool, tenant, &grant).await;

    let first = redeem(&pool, tenant, spine.file, actor, session, &token).await;
    let first = first.expect("the first redemption must succeed, or nothing below means anything");
    assert_eq!(first.version, version, "the grant came back naming a different version");
    assert!(first.watermark, "the mark requirement was not carried on the grant");

    let second = redeem(&pool, tenant, spine.file, actor, session, &token).await;
    assert!(
        second.is_none(),
        "the same grant was honoured twice, which makes a print token a download: {second:?}"
    );
}

/// **Two replicas, one grant, one winner.**
///
/// This is the test `ENC-724` exists for, and the sequential one above tells you nothing about it:
/// a `HashMap` in one process passes that and cannot pass this.
///
/// Both halves run as spawned tasks on separate pooled connections, and a [`Barrier`] holds each
/// one *after* it has opened its transaction and before it issues the `UPDATE`, so the two
/// statements arrive at the row together instead of by luck. The assertion is on the pair: exactly
/// one `Some` and exactly one `None`. "Both failed" — which a broken predicate, an absent row or a
/// deadlocked pair would produce — fails just as loudly as "both succeeded".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn two_concurrent_redemptions_of_one_grant_produce_one_winner() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let grant = grant_for(spine.file, version, actor, session, Utc::now() + Duration::seconds(TTL));
    let token = Arc::new(mint(&pool, tenant, &grant).await);

    let gate = Arc::new(Barrier::new(2));
    let mut racers = Vec::new();
    for _ in 0_u8..2 {
        let (pool, token, gate) = (pool.clone(), Arc::clone(&token), Arc::clone(&gate));
        let file = spine.file;
        racers.push(tokio::spawn(async move {
            let mut tx = pool.begin(tenant).await.expect("scoped transaction");
            // Both transactions are open and both have their tenant context established. Releasing
            // here is what makes the two `UPDATE`s contend for the row rather than run apart.
            let _wait = gate.wait().await;
            let outcome = print::redeem(&mut tx, tenant, file, actor, session, token.digest())
                .await
                .expect("the statement must run; a serialization failure is not expected at READ COMMITTED");
            tx.commit().await.expect("commit");
            outcome
        }));
    }

    let mut winners = 0_u8;
    let mut losers = 0_u8;
    for racer in racers {
        match racer.await.expect("neither task may panic") {
            Some(redeemed) => {
                assert_eq!(redeemed.version, version);
                winners += 1;
            }
            None => losers += 1,
        }
    }

    assert_eq!(
        (winners, losers),
        (1, 1),
        "two concurrent redemptions of one grant did not produce exactly one winner \
         ({winners} succeeded, {losers} were refused). Two winners is a print token that is a \
         download; two losers is a redemption path that refuses everything, which would make every \
         refusal assertion in this file pass for free."
    );

    // And the row is spent, not merely contended: a third attempt afterwards finds nothing.
    let after = redeem(&pool, tenant, spine.file, actor, session, &token).await;
    assert!(after.is_none(), "the grant survived the race: {after:?}");
}

// =================================================================================================
// Rule 7: four causes, one answer.
// =================================================================================================

/// Unknown, expired, already-redeemed and another tenant's are indistinguishable — and there is a
/// real, live grant in the same run that *is* honoured, so "indistinguishable" is not "all refused".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_way_of_failing_is_answered_the_same_way() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, alpha, fixtures.alpha.owner).await;
    let (beta_spine, beta_version) = content(&mut admin, beta, fixtures.beta.owner).await;

    let live = Utc::now() + Duration::seconds(TTL);

    // (1) A token nobody ever issued.
    let never = PrintToken::generate().expect("entropy");

    // (2) One whose lifetime elapsed. A row issued ten minutes ago that died eight minutes ago —
    //     no clock is moved anywhere, and the statement judges it against the database's `now()`
    //     exactly as it judges a live one.
    let expired_grant = grant_for(spine.file, version, actor, session, live);
    let expired = mint_expired(&mut admin, alpha, &expired_grant).await;

    // (3) One already redeemed.
    let spent_grant = grant_for(spine.file, version, actor, session, live);
    let spent = mint(&pool, alpha, &spent_grant).await;
    assert!(
        redeem(&pool, alpha, spine.file, actor, session, &spent).await.is_some(),
        "the grant that is about to be replayed was never honoured in the first place"
    );

    // (4) One minted in the other tenant, by that tenant's own member, over its own file — a real
    //     row, not a fabricated id (`docs/12 §4.1` T7's discipline).
    let beta_actor = Actor::User(fixtures.beta.member);
    let beta_grant = grant_for(beta_spine.file, beta_version, beta_actor, session, live);
    let foreign = mint(&pool, beta, &beta_grant).await;

    for (name, token) in [
        ("never issued", &never),
        ("expired", &expired),
        ("already spent", &spent),
        ("another tenant's", &foreign),
    ] {
        let answer = redeem(&pool, alpha, spine.file, actor, session, token).await;
        assert!(
            answer.is_none(),
            "a `{name}` token was honoured: {answer:?}. Every one of these must reach the caller \
             as the same absence, because telling a presenter their token was real but expired \
             tells them it was real."
        );
    }

    // The positive control, in the same run and over the same tenant: a real grant is honoured.
    // Without it every assertion above is satisfied by a statement that refuses everything.
    let good = mint(&pool, alpha, &grant_for(spine.file, version, actor, session, live)).await;
    assert!(
        redeem(&pool, alpha, spine.file, actor, session, &good).await.is_some(),
        "no token at all could be redeemed, so the four refusals above prove nothing"
    );
}

/// **A same-tenant colleague who holds the token is still not the grantee**, and row-level security
/// cannot be what refuses them.
///
/// This is the leg that isolates the statement's own binding. `tenant_id` is identical on both
/// sides, so RLS matches the row for either caller; only `actor_id` in the `WHERE` refuses. Deleting
/// that clause leaves every cross-tenant assertion in this file green — which is the failure mode
/// nine separate crates here have already had.
///
/// It also asserts the grant is **not consumed** by the refusal: the rightful holder redeems it
/// afterwards. A thief able to burn a colleague's token would have a denial of service for the
/// price of a value they stole, and an implementation that checked the actor *after* the `UPDATE`
/// would pass every other test in this file and fail this line.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_colleague_in_the_same_tenant_cannot_spend_another_persons_grant() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let grantee = Actor::User(fixtures.alpha.member);
    let colleague = Actor::User(fixtures.alpha.viewer);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let grant =
        grant_for(spine.file, version, grantee, session, Utc::now() + Duration::seconds(TTL));
    let token = mint(&pool, tenant, &grant).await;

    let stolen = redeem(&pool, tenant, spine.file, colleague, session, &token).await;
    assert!(
        stolen.is_none(),
        "a different user in the same tenant spent someone else's print grant: {stolen:?}. \
         Row-level security cannot refuse this — both rows are this tenant's — so what is being \
         proved here is the actor predicate in the statement itself."
    );

    // A different sign-in of the *right* person is refused too: the grant names one session,
    // because docs/06 §5.1 puts a session reference in the mark itself.
    let other_session =
        redeem(&pool, tenant, spine.file, grantee, Some(SessionId::new_v7()), &token).await;
    assert!(other_session.is_none(), "a grant was spendable from a different sign-in");

    // And the right file: a grant for one document is not a grant for another.
    let (other_spine, _other_version) = content(&mut admin, tenant, fixtures.alpha.owner).await;
    let other_file = redeem(&pool, tenant, other_spine.file, grantee, session, &token).await;
    assert!(other_file.is_none(), "a grant for one file was spendable against another");

    // The control, and the part that makes the three refusals above mean something: none of them
    // consumed the grant, and its rightful holder can still spend it.
    let rightful = redeem(&pool, tenant, spine.file, grantee, session, &token).await;
    assert!(
        rightful.is_some(),
        "the rightful holder could not spend their own grant afterwards — either the refusals \
         above consumed it, or nothing here was ever redeemable"
    );
}

/// A grant cannot be minted already dead, and the database is what refuses it.
///
/// `0027`'s `CHECK (expires_at > issued_at)`. It is cheap, and it is the constraint that would catch
/// a mint which started deriving `expires_at` from its own clock: a replica running behind the
/// database would issue grants that are born expired, and every caller would see a `404` on a
/// redemption that had done nothing wrong. Without this test the constraint is a line in a migration
/// that nothing exercises.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_grant_cannot_be_minted_already_dead() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let token = PrintToken::generate().expect("entropy");
    let dead = grant_for(spine.file, version, actor, session, Utc::now() - Duration::seconds(1));
    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let refused = print::issue(&mut tx, tenant, token.digest(), &dead).await;
    assert!(
        refused.is_err(),
        "the database accepted a grant that expired before it was issued: {refused:?}"
    );
    drop(tx);

    // The control: the same grant with a live expiry is accepted, so the refusal above is about the
    // expiry rather than about the row being unwritable for some other reason.
    let good = grant_for(spine.file, version, actor, session, Utc::now() + Duration::seconds(TTL));
    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    print::issue(&mut tx, tenant, PrintToken::generate().expect("entropy").digest(), &good)
        .await
        .expect("a grant with a live expiry must be accepted");
    tx.commit().await.expect("commit");
}

// =================================================================================================
// The reaper, and the grant it needs.
// =================================================================================================

/// Expired rows are deleted, live ones are not, and the `DELETE` runs as `enclave_app`.
///
/// The grant half is the point. `0027` writes `GRANT … DELETE ON print_tokens TO enclave_app`, and
/// the only way to know it took is to delete as that role — which is what the harness pool does and
/// what a superuser connection would silently paper over. `ENC-705` and `ENC-686` were both missing
/// grants with correct code above them and passing tests below them.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_reaper_removes_dead_grants_and_leaves_live_ones() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let dead = grant_for(spine.file, version, actor, session, Utc::now() + Duration::seconds(TTL));
    let _dead_token = mint_expired(&mut admin, tenant, &dead).await;
    let alive = grant_for(spine.file, version, actor, session, Utc::now() + Duration::hours(1));
    let alive_token = mint(&pool, tenant, &alive).await;

    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let reaped = print::reap_expired(&mut tx, tenant, 100).await.expect("the sweep must run");
    tx.commit().await.expect("commit");

    assert_eq!(reaped, 1, "the sweep took {reaped} rows; exactly the one expired grant was dead");

    // The control: the live grant is still redeemable, so the sweep deleted the right row rather
    // than emptying the table.
    assert!(
        redeem(&pool, tenant, spine.file, actor, session, &alive_token).await.is_some(),
        "the sweep took a live grant with it"
    );

    // Idempotent: a second sweep over the same tenant finds nothing left to take.
    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let again = print::reap_expired(&mut tx, tenant, 100).await.expect("the sweep must run");
    tx.commit().await.expect("commit");
    assert_eq!(again, 0, "a second sweep took {again} more rows");
}

/// One tenant's sweep cannot reach another's grants.
///
/// **Recorded as the weaker half, and it was measured rather than guessed.** Deleting
/// `tenant_id = $1` from `REAP_SQL` leaves this test green: row-level security refuses the other
/// tenant's rows on the scoped connection whether or not the predicate is there, and the test
/// cannot tell the two apart. That is the eleventh time that shape has appeared in this repository
/// (`docs/12 §4.1` T5, T8), and the honest thing is to say which mechanism is actually holding the
/// property rather than to let the name imply the other one.
///
/// The leg RLS *cannot* hold is
/// [`a_colleague_in_the_same_tenant_cannot_spend_another_persons_grant`], where both callers are in
/// one tenant. That one fails the moment the actor predicate is removed, which is why it is the
/// isolation test that matters here and this one is the boundary check beside it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_sweep_cannot_reach_anothers_grants() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (beta_spine, beta_version) = content(&mut admin, beta, fixtures.beta.owner).await;

    let beta_actor = Actor::User(fixtures.beta.member);
    let beta_dead = grant_for(
        beta_spine.file,
        beta_version,
        beta_actor,
        session,
        Utc::now() + Duration::seconds(TTL),
    );
    let _token = mint_expired(&mut admin, beta, &beta_dead).await;

    let mut tx = pool.begin(alpha).await.expect("scoped transaction");
    let reaped = print::reap_expired(&mut tx, alpha, 100).await.expect("the sweep must run");
    tx.commit().await.expect("commit");
    assert_eq!(reaped, 0, "alpha's sweep deleted {reaped} of beta's rows");

    // The control: beta's own sweep does take it, so the zero above is a boundary rather than a
    // sweep that deletes nothing at all.
    let mut tx = pool.begin(beta).await.expect("scoped transaction");
    let own = print::reap_expired(&mut tx, beta, 100).await.expect("the sweep must run");
    tx.commit().await.expect("commit");
    assert_eq!(own, 1, "beta's own sweep did not take beta's expired grant");
}

/// The batch is a bound, not a suggestion.
///
/// A sweep that ignored its limit would take an unbounded lock on a busy tenant; one that took
/// nothing would report a healthy pass over a table that grows for ever, which is `ENC-806`'s
/// finding restated.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_sweep_takes_no_more_than_its_batch() {
    let (db, fixtures, pool) = start().await;
    let tenant = fixtures.alpha.id;
    let actor = Actor::User(fixtures.alpha.member);
    let session = Some(SessionId::new_v7());

    let mut admin = db.connect().await.expect("admin connection");
    let (spine, version) = content(&mut admin, tenant, fixtures.alpha.owner).await;

    let dead = grant_for(spine.file, version, actor, session, Utc::now() + Duration::seconds(TTL));
    for _ in 0_u8..5 {
        let _token = mint_expired(&mut admin, tenant, &dead).await;
    }

    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let first = print::reap_expired(&mut tx, tenant, 2).await.expect("the sweep must run");
    tx.commit().await.expect("commit");
    assert_eq!(first, 2, "the sweep ignored its batch and took {first}");

    let mut tx = pool.begin(tenant).await.expect("scoped transaction");
    let rest = print::reap_expired(&mut tx, tenant, 100).await.expect("the sweep must run");
    tx.commit().await.expect("commit");
    assert_eq!(rest, 3, "the remaining rows were not reachable by a later pass");
}
