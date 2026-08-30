//! The administrative reader returns one tenant's log and narrows what it is asked to narrow.
//!
//! `ENC-961`. Two properties, and only the first is a security property:
//!
//! 1. **A page contains no other tenant's rows.** `audit_events` is the one table in the product
//!    whose rows describe every other table, so a leak here is a leak of everything at once — file
//!    names, who holds what, which policies refused whom.
//!
//!    **Which layer holds that here, stated plainly, because it is not the obvious one.** Deleting
//!    `WHERE tenant_id = $1` from `SELECT_ADMIN_PAGE_SQL` was tried, and this test still passed.
//!    Unlike the API integration harness — which connects as the cluster superuser, leaving
//!    row-level security inert and the predicate genuinely load-bearing (`docs/12 §1.2`) — this one
//!    builds its pool `.with_application_role("enclave_app")`, so `migrations/0002`'s policy is
//!    live and catches the cross-tenant read on its own. The predicate is still right and still
//!    required by `docs/04 §3`: it is the second layer, and it is the access path that uses
//!    `idx_audit_tenant_time` rather than scanning every partition. But a reader of this file
//!    should not believe it is being proved here, because it is not.
//! 2. **A narrowing narrows.** A filter that is silently ignored hands an auditor a wider answer
//!    than the one they asked for and says nothing about it, which is the failure mode this
//!    surface has that a member listing does not: the reader cannot tell a filtered page from an
//!    unfiltered one by looking at it.
//!
//! Ignored by default because they need a live PostgreSQL; CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_audit::{read_page, record_in_tx, verify_tenant, AuditFilter, ChainMode};
use enclave_core::{Action, AdminAction, FileAction, RequestContext, ResourceRef, TenantId, Uuid};
use enclave_db::{DbConfig, DbPool, TenantScoped};
use enclave_testing::TestDb;

/// A pool over the throwaway database (`ENC-504` — never the one `DATABASE_URL` names).
async fn pool(db: &TestDb) -> DbPool {
    let config = DbConfig::new(enclave_db::ConnectionUrl::new(db.url().to_owned()))
        .with_application_role("enclave_app")
        .with_platform_url(db.url().to_owned());
    DbPool::connect(&config).await.expect("connect")
}

/// Writes `count` allow rows and one deny row for `tenant`, through the ordinary write path.
///
/// Through `record_in_tx` rather than an `INSERT` of my own: an event assembled by hand is an event
/// whose shape I chose, and a reader test that passes only against rows the test wrote in a shape
/// the reader expects proves nothing about the rows the product writes.
async fn write_events(pool: &DbPool, tenant: TenantId, count: usize) {
    let ctx = RequestContext::system(tenant);
    let mut tx = TenantScoped::begin(pool, tenant).await.expect("begin");
    for _ in 0..count {
        let event = enclave_audit::AuditEvent::builder(
            &ctx,
            Action::File(FileAction::Download),
            enclave_audit::Outcome::Allow,
        )
        .resource(&ResourceRef::file(tenant, enclave_core::FileId::from_uuid(Uuid::new_v4())))
        .build();
        record_in_tx(&mut tx, event, ChainMode::Enabled).await.expect("record");
    }
    let denial = enclave_audit::AuditEvent::builder(
        &ctx,
        Action::Admin(AdminAction::ReadAudit),
        enclave_audit::Outcome::Deny,
    )
    .resource(&ResourceRef::tenant(tenant))
    .build();
    record_in_tx(&mut tx, denial, ChainMode::Enabled).await.expect("record");
    tx.commit().await.expect("commit");
}

/// Inserts a tenant row and returns its id.
async fn tenant(db: &TestDb, slug: &str) -> TenantId {
    let id = Uuid::new_v4();
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, status, residency_region, \
         policy_generation, created_at, updated_at) \
         VALUES ($1, $2, $2, 'ACTIVE', 'eu-west-1', 1, now(), now())",
    )
    .bind(id)
    .bind(slug)
    .execute(&mut conn)
    .await
    .expect("insert tenant");
    TenantId::from_uuid(id)
}

/// A page holds this tenant's rows and no other tenant's.
///
/// **The assertion this whole surface turns on.** Every other test here would pass against a reader
/// that returned the entire cluster's audit log, and so would every manual check against a
/// single-tenant dev database — which is exactly the shape of check that has already let two
/// cross-tenant defects through in this repository.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_page_holds_one_tenants_rows_and_no_others() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    let beta = tenant(&db, "beta").await;

    write_events(&pool, alpha, 3).await;
    write_events(&pool, beta, 3).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let page = read_page(&mut tx, &AuditFilter::default(), 100).await.expect("read");
    tx.commit().await.expect("commit");

    assert!(!page.is_empty(), "the control: alpha wrote rows, so an empty page proves nothing");
    for record in &page {
        assert_eq!(
            record.event.tenant_id, alpha,
            "a row belonging to another tenant reached an administrator's page. `audit_events` \
             describes every other table, so this leaks file names, holders and refusals at once"
        );
    }
    assert_eq!(page.len(), 4, "alpha's four rows, and beta's four not among them");
}

/// `outcome` narrows, and narrows to the right rows.
///
/// A filter that is dropped rather than applied is the failure this surface cannot show the caller:
/// an auditor asking for refusals and handed everything reads the first page and concludes wrongly.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn narrowing_to_denials_returns_denials_and_not_the_rest() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    write_events(&pool, alpha, 5).await;

    let filter = AuditFilter { outcome: Some("DENY".to_owned()), ..AuditFilter::default() };
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let denials = read_page(&mut tx, &filter, 100).await.expect("read");
    let everything = read_page(&mut tx, &AuditFilter::default(), 100).await.expect("read");
    tx.commit().await.expect("commit");

    assert_eq!(denials.len(), 1, "one denial was written");
    assert_eq!(
        everything.len(),
        6,
        "the control: without the narrowing the page is wider. Without this, a reader that \
         returned one row whatever it was asked would satisfy the assertion above"
    );
    for record in &denials {
        assert_eq!(record.event.outcome, enclave_audit::Outcome::Deny);
    }
}

/// The page is newest first, and `before` pages backwards from a sequence.
///
/// Cursored on `sequence` rather than `occurred_at`: rows written in one transaction share a
/// timestamp to the microsecond, so a timestamp cursor would repeat one and skip another. That is
/// not a hypothetical here — `write_events` writes its rows in a single transaction, which is why
/// this test would catch it.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn the_page_is_newest_first_and_pages_backwards_without_repeating_a_row() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    write_events(&pool, alpha, 5).await;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let first = read_page(&mut tx, &AuditFilter::default(), 3).await.expect("read");
    let cursor = first.last().expect("a full page").event.sequence;
    let second =
        read_page(&mut tx, &AuditFilter { before: Some(cursor), ..AuditFilter::default() }, 3)
            .await
            .expect("read");
    tx.commit().await.expect("commit");

    let descending: Vec<i64> = first.iter().map(|record| record.event.sequence).collect();
    let mut sorted = descending.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(descending, sorted, "newest first");

    for record in &second {
        assert!(
            record.event.sequence < cursor,
            "sequence {} came back on the page after the cursor {cursor} — a cursor that repeats \
             a row is a cursor an auditor cannot count with",
            record.event.sequence
        );
    }
    assert_eq!(second.len(), 3, "six rows, so the second page of three is full");
}

/// Inserts a user and returns their id.
async fn user(db: &TestDb, tenant: TenantId, name: &str) -> enclave_core::UserId {
    let id = Uuid::new_v4();
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, normalized_email, display_name, status, \
         source, created_at, updated_at) \
         VALUES ($1, $2, $3, $3, $4, 'ACTIVE', 'LOCAL', now(), now())",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(format!("{name}@example.test"))
    .bind(name)
    .execute(&mut conn)
    .await
    .expect("insert user");
    enclave_core::UserId::from_uuid(id)
}

/// An actor with a `users` row is named; one without is not, and is not a UUID either.
///
/// **`ENC-958`'s defect, one surface later.** Two screens could say when something happened and not
/// who did it, because the id was on the wire and the name was not. An audit table is the worst
/// place to repeat that: an investigation is a question about *people*, and a column of UUIDs
/// answers it only for somebody who already has a second window open.
///
/// The `None` leg is the half worth keeping. Most audit rows in a live tenant are written by
/// `system` — sweeps, outbox publishing, index maintenance — and every service account, MCP client
/// and link bearer is also absent from `users`. `None` must reach the client as `null` so it can
/// render *"somebody"*; a join that quietly dropped those rows, or a `COALESCE` to the id, would
/// each be worse than the gap.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn an_actor_with_a_directory_row_is_named_and_one_without_is_not() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    let who = user(&db, alpha, "Ada Lovelace").await;

    let mut ctx = RequestContext::system(alpha);
    ctx.actor = enclave_core::Actor::User(who);
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let event = enclave_audit::AuditEvent::builder(
        &ctx,
        Action::File(FileAction::Download),
        enclave_audit::Outcome::Allow,
    )
    .resource(&ResourceRef::file(alpha, enclave_core::FileId::from_uuid(Uuid::new_v4())))
    .build();
    record_in_tx(&mut tx, event, ChainMode::Enabled).await.expect("record");
    tx.commit().await.expect("commit");
    // A second row from a **service account** — an actor that has an id and no `users` row. Not a
    // `system` row, whose actor id is already null: `COALESCE(u.display_name, a.actor_id::text)`
    // survives that control unnoticed, and it is exactly the plausible "improvement" somebody makes
    // to stop the column looking empty. It would print an internal identifier at a reader for every
    // service account, MCP client and guest in the tenant.
    let mut machine = RequestContext::system(alpha);
    machine.actor = enclave_core::Actor::ServiceAccount(enclave_core::ServiceAccountId::from_uuid(
        Uuid::new_v4(),
    ));
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let event = enclave_audit::AuditEvent::builder(
        &machine,
        Action::File(FileAction::Download),
        enclave_audit::Outcome::Allow,
    )
    .resource(&ResourceRef::file(alpha, enclave_core::FileId::from_uuid(Uuid::new_v4())))
    .build();
    record_in_tx(&mut tx, event, ChainMode::Enabled).await.expect("record");
    tx.commit().await.expect("commit");

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let page = read_page(&mut tx, &AuditFilter::default(), 100).await.expect("read");
    tx.commit().await.expect("commit");

    let named: Vec<&str> =
        page.iter().filter_map(|record| record.actor_display_name.as_deref()).collect();
    assert_eq!(named, ["Ada Lovelace"], "the directory row's name reached the reader");
    assert_eq!(page.len(), 2, "both rows came back — the join drops neither");
    assert!(
        page.iter().any(|record| record.actor_display_name.is_none()),
        "the control: the service account's row must come back with **no** name rather than be dropped by the join or filled in with its identifier"
    );
}

/// A row edited in place is caught, and the walk names the row.
///
/// **This is the assertion the whole hash chain exists for, and until `ENC-969` nothing made it
/// outside `crates/audit`'s own unit tests.** The product spends an advisory lock per tenant, a
/// canonical encoding and a digest on every audit row so that an edit is detectable, and had no
/// caller that would ever detect one.
///
/// The tampering is done as the **cluster superuser**, which is the only way it can be done:
/// `migrations/0002` grants `enclave_app` `SELECT` and `INSERT` on `audit_events` and revokes
/// `UPDATE`, `DELETE` and `TRUNCATE`, so the application cannot rewrite its own trail even if it
/// tried. That is the threat this control is for — somebody with direct database access — and
/// simulating it any other way would be simulating something the grants already prevent.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_row_edited_in_place_is_caught_and_the_walk_names_it() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    write_events(&pool, alpha, 5).await;

    // The control: intact before the edit. Without it, "diverged after tampering" is satisfied by a
    // verifier that reports divergence on every chain it is ever shown.
    let before = verify_tenant(&pool, alpha, 100).await.expect("verify");
    assert!(
        before.is_valid(),
        "the chain did not verify before anything was tampered with, so the assertion below would \
         prove nothing: {before:?}"
    );

    // Rewrite one row's action. The stored `event_hash` still covers the old content.
    let target: i64 = {
        let mut conn = db.connect().await.expect("connect");
        let row: (i64,) = sqlx::query_as(
            "SELECT sequence FROM audit_events WHERE tenant_id = $1 ORDER BY sequence OFFSET 2 \
             LIMIT 1",
        )
        .bind(alpha.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("pick a row");
        sqlx::query(
            "UPDATE audit_events SET action = 'file.delete' WHERE tenant_id = $1 AND sequence = $2",
        )
        .bind(alpha.as_uuid())
        .bind(row.0)
        .execute(&mut conn)
        .await
        .expect("tamper");
        row.0
    };

    let after = verify_tenant(&pool, alpha, 100).await.expect("verify");
    assert!(!after.is_valid(), "an edited row verified as intact: {after:?}");
    assert_eq!(
        after.first_divergence(),
        Some(target),
        "the walk reported the wrong row. Only the *first* offending sequence is evidence about \
         where an edit began, so naming a later one would send an investigation to the wrong place"
    );
}

/// A row removed from the middle breaks the link, and the walk says so at the row after the gap.
///
/// A deletion is the tampering a content digest alone cannot catch — every surviving row still
/// hashes to what it claims. It is the `previous_hash` link that fails, which is why the chain
/// exists on top of the per-row digest rather than instead of it.
#[tokio::test]
#[ignore = "needs a live PostgreSQL"]
async fn a_row_removed_from_the_middle_breaks_the_link() {
    let db = TestDb::start().await.expect("test database");
    let pool = pool(&db).await;
    let alpha = tenant(&db, "alpha").await;
    write_events(&pool, alpha, 5).await;

    let removed: i64 = {
        let mut conn = db.connect().await.expect("connect");
        let row: (i64,) = sqlx::query_as(
            "SELECT sequence FROM audit_events WHERE tenant_id = $1 ORDER BY sequence OFFSET 2 \
             LIMIT 1",
        )
        .bind(alpha.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("pick a row");
        sqlx::query("DELETE FROM audit_events WHERE tenant_id = $1 AND sequence = $2")
            .bind(alpha.as_uuid())
            .bind(row.0)
            .execute(&mut conn)
            .await
            .expect("remove");
        row.0
    };

    let after = verify_tenant(&pool, alpha, 100).await.expect("verify");
    assert!(!after.is_valid(), "a chain with a row cut out of it verified as intact: {after:?}");
    assert!(
        after.first_divergence().is_some_and(|at| at > removed),
        "the gap must be reported at the row *after* it — that is the first row whose \
         `previous_hash` no longer matches — and not at the sequence that is no longer there: {after:?}"
    );
}
