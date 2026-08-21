//! `docs/12-TESTING.md §4.3` — the search rows that the post-filter is responsible for.
//!
//! # Why the candidate generator is a fake, and why that is the honest choice
//!
//! S5 asks that "deliberately over-permissive index candidates are dropped by the post-filter".
//! Arranging that in Milvus means building an index, letting it go stale, and hoping it goes stale
//! in the direction the test needs. Arranging it here is a `Vec` containing a file the caller cannot
//! see.
//!
//! The fake is not a weaker test — it is a *stronger* one, because it can propose things a real
//! index would only propose by accident: another tenant's file, a deleted file, a file the caller
//! was never granted. The post-filter's contract is that none of that matters, and a fake is the
//! only way to state the contract in full.
//!
//! This is why `plans/M3-DISCOVERY.md` sequences the guarantee before the thing it guards.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::{Duration, Utc};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{Actor, FileId, RequestContext, TenantId, UserId};
use enclave_db::{DbPool, TenantScoped};
use enclave_search::{denylist, Candidate, Excerpt, PostFilter};
use enclave_testing::content::{grant, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::{Fixtures, TestDb};
use uuid::Uuid;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

fn ctx(tenant: TenantId, actor: UserId) -> RequestContext {
    RequestContext { actor: Actor::User(actor), ..RequestContext::system(tenant) }
}

fn candidate(file: FileId, score: f32) -> Candidate {
    Candidate {
        file_id: file,
        score,
        excerpt: Some(Excerpt::unlocated("a snippet of the document".to_owned())),
    }
}

/// **S5** — the index proposes what the caller may not see, and none of it survives.
///
/// The candidate set is deliberately worse than any real index would produce: a file the caller has
/// no grant on, a file that does not exist at all, and a file belonging to another tenant. The
/// post-filter's contract is that the index's opinion is never consulted, so all three go.
///
/// The one the caller *may* see is in the middle, so a filter that dropped everything — the way a
/// broken post-filter and a correct one both look from the outside — fails here.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn s5_over_permissive_candidates_are_dropped_however_confident_the_index_is() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let visible = Spine::new(alpha);
    let ungranted = Spine::new(alpha);
    let theirs = Spine::new(beta);

    let mut admin = db.connect().await.expect("admin connection");
    visible.insert(&mut admin, fixtures.alpha.owner, now).await.expect("visible spine");
    ungranted.insert(&mut admin, fixtures.alpha.owner, now).await.expect("ungranted spine");
    theirs.insert(&mut admin, fixtures.beta.owner, now).await.expect("beta spine");

    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, &visible, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());
    let proposed = vec![
        candidate(ungranted.file, 0.99),
        candidate(visible.file, 0.90),
        candidate(theirs.file, 0.80),
        candidate(FileId::new_v7(), 0.70),
    ];

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (confirmed, counts) =
        PostFilter::confirm(&mut tx, &authorization, &ctx(alpha, caller), proposed)
            .await
            .expect("post-filter");
    tx.commit().await.expect("commit");

    assert_eq!(confirmed.len(), 1, "the post-filter kept {:?}", confirmed);
    assert_eq!(confirmed[0].file_id, visible.file);
    assert_eq!(counts.proposed, 4);
    assert_eq!(counts.unauthorized, 3);
    // Not zero: a post-filter that dropped everything would satisfy every assertion above except
    // this one, and it is the difference between working and refusing.
    assert_eq!(counts.confirmed(), 1);

    drop(db);
}

/// A caller who may see that a document exists, but not read it, gets the hit and no snippet.
///
/// `docs/07 §6.2`'s two disclosure levels. The withheld case is the interesting one: the excerpt is
/// *present in the candidate* — the index had it — and does not reach the caller.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn metadata_without_content_yields_the_hit_and_withholds_the_excerpt() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    // Metadata only. No `file.content_read`.
    grant_action(&mut admin, alpha, &spine, caller, "file.metadata_read").await;

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (confirmed, counts) = PostFilter::confirm(
        &mut tx,
        &authorization,
        &ctx(alpha, caller),
        vec![candidate(spine.file, 0.9)],
    )
    .await
    .expect("post-filter");
    tx.commit().await.expect("commit");

    assert_eq!(confirmed.len(), 1, "the hit itself must survive");
    assert_eq!(
        confirmed[0].excerpt, None,
        "the excerpt reached a caller who may not read the content"
    );
    assert_eq!(counts.excerpt_withheld, 1);

    drop(db);
}

/// **S3** — a revoked file vanishes immediately, before any index update.
///
/// The candidate set is unchanged across the revocation, which is the point: the index still
/// proposes the file, exactly as it would in production until a worker catches up.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn s3_a_revoked_file_leaves_the_results_before_the_index_is_touched() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, &spine, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());
    let proposed = || vec![candidate(spine.file, 0.9)];

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (before, _) = PostFilter::confirm(&mut tx, &authorization, &ctx(alpha, caller), proposed())
        .await
        .expect("before");
    tx.commit().await.expect("commit");
    assert_eq!(before.len(), 1, "the file was not findable to begin with, so nothing is proven");

    // Revocation, and the denylist write, in one transaction — `plans/M3-DISCOVERY.md` D22.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    sqlx::query("DELETE FROM acl_entries WHERE tenant_id = $1 AND resource_id = $2")
        .bind(alpha.as_uuid())
        .bind(spine.file.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("revoke");
    denylist::suppress(&mut tx, alpha, spine.file, "acl_revoked", now, None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");

    // No index update has happened. The candidate generator still proposes it.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (after, counts) =
        PostFilter::confirm(&mut tx, &authorization, &ctx(alpha, caller), proposed())
            .await
            .expect("after");
    tx.commit().await.expect("commit");

    assert!(after.is_empty(), "a revoked file survived the post-filter: {after:?}");
    assert_eq!(counts.denylisted, 1);

    drop(db);
}

/// **S4** — S3 still holds with the invalidation worker stopped.
///
/// There is no worker in this test, which is the whole assertion: nothing ran between the
/// revocation and the search, and the answer is still right. A design that enqueued a job would
/// pass S3 and fail here, and S3 alone is the test somebody writes.
///
/// # What this proves, and what it does not
///
/// Both this and S3 revoke the ACL *and* write the denylist, which is what a revocation does. So
/// neither isolates the denylist: with the ACL gone, the post-filter's own resolution refuses the
/// file, and removing the denylist consultation entirely leaves both tests green. I checked.
///
/// That is not a gap in the design — it is the design. For an ACL revocation the post-filter alone
/// is sufficient, and the denylist is defence in depth. What the denylist is *necessary* for is the
/// staleness an ACL does not capture, and
/// `the_denylist_suppresses_what_the_acl_alone_would_still_admit` is the test that isolates it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn s4_the_answer_is_right_with_no_worker_running_at_all() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, &spine, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    sqlx::query("DELETE FROM acl_entries WHERE tenant_id = $1 AND resource_id = $2")
        .bind(alpha.as_uuid())
        .bind(spine.file.as_uuid())
        .execute(&mut *tx)
        .await
        .expect("revoke");
    denylist::suppress(&mut tx, alpha, spine.file, "acl_revoked", now, None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");

    // Deliberately *not* calling `lift_expired`, and deliberately not running anything that would
    // remove the document from an index. The suppression is permanent until somebody sweeps it, and
    // the answer must be right in the meantime — for as long as "the meantime" lasts.
    for _ in 0..3 {
        let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
        let (results, _) = PostFilter::confirm(
            &mut tx,
            &authorization,
            &ctx(alpha, caller),
            vec![candidate(spine.file, 0.9)],
        )
        .await
        .expect("confirm");
        tx.commit().await.expect("commit");
        assert!(results.is_empty(), "a revoked file resurfaced with no worker running");
    }

    drop(db);
}

/// A suppression with a passed `clears_at` is already lifted, whether or not the sweep has run.
///
/// The mirror of S4: waiting for housekeeping to make a *correct* answer correct is the same
/// mistake in the opposite direction — it would leave a file unfindable long after it should have
/// returned, and "search is missing things" is a report nobody can act on.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn an_expired_suppression_stops_suppressing_before_anything_sweeps_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, &spine, caller, action).await;
    }

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    denylist::suppress(
        &mut tx,
        alpha,
        spine.file,
        "reindexing",
        now,
        Some(now - Duration::seconds(1)),
    )
    .await
    .expect("suppress with a passed expiry");
    tx.commit().await.expect("commit");

    let authorization = PgAclAuthorization::new(pool.clone());
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (results, counts) = PostFilter::confirm(
        &mut tx,
        &authorization,
        &ctx(alpha, caller),
        vec![candidate(spine.file, 0.9)],
    )
    .await
    .expect("confirm");
    assert_eq!(counts.denylisted, 0, "an expired suppression was still suppressing");
    assert_eq!(results.len(), 1);

    // And the sweep is housekeeping, not correctness: it removes the row that had already stopped
    // mattering.
    let lifted = denylist::lift_expired(&mut tx, alpha).await.expect("sweep");
    assert_eq!(lifted, 1);
    tx.commit().await.expect("commit");

    drop(db);
}

/// The denylist earns its place here, where the ACL alone would admit the file.
///
/// A file whose content has been purged, or which has been re-classified above the caller's
/// ceiling, is still granted in `acl_entries` — the post-filter has nothing to refuse it with. This
/// is the case the denylist exists for, and removing the consultation makes *this* test fail where
/// S3 and S4 stay green.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0011; CI runs it with --include-ignored"]
async fn the_denylist_suppresses_what_the_acl_alone_would_still_admit() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let now = Utc::now();

    let spine = Spine::new(alpha);
    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, now).await.expect("spine");
    for action in ["file.metadata_read", "file.content_read"] {
        grant_action(&mut admin, alpha, &spine, caller, action).await;
    }

    let authorization = PgAclAuthorization::new(pool.clone());

    // Granted, and findable.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (before, _) = PostFilter::confirm(
        &mut tx,
        &authorization,
        &ctx(alpha, caller),
        vec![candidate(spine.file, 0.9)],
    )
    .await
    .expect("before");
    tx.commit().await.expect("commit");
    assert_eq!(before.len(), 1, "nothing is proven if the file was not findable to begin with");

    // Suppressed with the grant left completely intact — the content was purged, say, or it was
    // re-classified. The post-filter's resolution will happily allow this file.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    denylist::suppress(&mut tx, alpha, spine.file, "content_purged", now, None)
        .await
        .expect("suppress");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let (after, counts) = PostFilter::confirm(
        &mut tx,
        &authorization,
        &ctx(alpha, caller),
        vec![candidate(spine.file, 0.9)],
    )
    .await
    .expect("after");
    tx.commit().await.expect("commit");

    assert!(
        after.is_empty(),
        "the denylist did not suppress a file the ACL still grants, so it is doing nothing that \
         the post-filter was not already doing"
    );
    assert_eq!(counts.denylisted, 1);
    assert_eq!(
        counts.unauthorized, 0,
        "the ACL still grants this file; the denylist is what stopped it"
    );

    // And the grant really is intact, so the assertion above is about the denylist and not about a
    // revocation that happened by accident.
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let still_granted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM acl_entries WHERE tenant_id = $1 AND resource_id = $2",
    )
    .bind(alpha.as_uuid())
    .bind(spine.file.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    tx.commit().await.expect("commit");
    assert_eq!(still_granted, 2);

    drop(db);
}

/// Grants one action on the spine's file.
async fn grant_action(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    spine: &Spine,
    caller: UserId,
    action: &str,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at)
         VALUES ($1, $2, 'FILE', $3, 'USER', $4, $5, 'ALLOW', $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(caller.as_uuid())
    .bind(action)
    .bind(Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("grant");
}

// `grant`, `AclEffect`, `AclPrincipal` and `AclScope` are imported for the shape the harness
// offers; this file writes its entries directly because it needs two *actions* on one resource,
// which the helper does not express.
const _: fn(AclEffect, AclPrincipal, AclScope) = |_, _, _| ();
const _: () = {
    let _ = grant;
};
