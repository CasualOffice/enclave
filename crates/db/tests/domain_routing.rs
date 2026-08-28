//! Custom-domain routing resolves a tenant, and resolves the *right* one.
//!
//! `ENC-686`. `CLAUDE.md` rule 3 names exactly two sources of tenant identity — a verified token,
//! and custom-domain routing — and the second had never worked. `tenant_domains` is row-level
//! -security policied, `migrations/0002` granted `enclave_platform` nothing on it, and the query
//! therefore failed with `permission denied` rather than returning no rows. So
//! `resolve_routed_tenant` read the leftmost label as a slug and nothing else, and
//! `TenantRepository::find_by_verified_domain` had no caller that could succeed.
//!
//! # What these tests are for, beyond "it works now"
//!
//! The interesting one is `a_custom_domain_wins_over_a_tenant_slugged_like_its_first_label`. Trying
//! the slug first is the obvious implementation and it is a cross-tenant misroute: Acme's verified
//! `docs.acme.example` resolves to whichever tenant happens to be slugged `docs`. Nothing reports
//! it — the caller reaches a real tenant, sees a real sign-in page, and their credentials simply do
//! not work — so it would be diagnosed as a login problem for as long as it took someone to read
//! this function.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_db::{resolve_routed_tenant, DbConfig, DbPool, SqlId as _};
use enclave_testing::TestDb;
use uuid::Uuid;

/// A pool whose platform half points at the throwaway database.
///
/// `resolve_routed_tenant` takes `platform_connection`, which is `None` unless a platform DSN is
/// configured — a deployment without one cannot sign anyone in, and the function says so rather
/// than resolving every host to nothing.
async fn pool(db: &TestDb) -> DbPool {
    let config = DbConfig::new(enclave_db::ConnectionUrl::new(db.url().to_owned()))
        .with_application_role("enclave_app")
        .with_platform_url(db.url().to_owned());
    DbPool::connect(&config).await.expect("connect")
}

/// Inserts a tenant and returns its id.
async fn tenant(db: &TestDb, slug: &str, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, status, residency_region, \
         policy_generation, created_at, updated_at) \
         VALUES ($1, $2, $2, $3, 'eu-west-1', 1, now(), now())",
    )
    .bind(id)
    .bind(slug)
    .bind(status)
    .execute(&mut conn)
    .await
    .expect("insert tenant");
    id
}

/// Claims a domain for a tenant, verified or not.
async fn domain(db: &TestDb, tenant_id: Uuid, name: &str, verified: bool) {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query(
        "INSERT INTO tenant_domains (tenant_id, domain, verified_at, verification_token, \
         certificate_mode, is_primary, created_at) \
         VALUES ($1, $2, CASE WHEN $3 THEN now() ELSE NULL END, 'token', 'AUTOMATIC', TRUE, now())",
    )
    .bind(tenant_id)
    .bind(name)
    .bind(verified)
    .execute(&mut conn)
    .await
    .expect("insert domain");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_verified_custom_domain_resolves_its_tenant() {
    let db = TestDb::start().await.expect("start a test database");
    let acme = tenant(&db, "acme", "ACTIVE").await;
    domain(&db, acme, "workspace.acme.example", true).await;
    let pool = pool(&db).await;

    let resolved = resolve_routed_tenant(&pool, "workspace.acme.example").await.expect("resolve");
    assert_eq!(
        resolved.map(|t| t.to_uuid()),
        Some(acme),
        "a verified custom domain did not resolve. Before ENC-686 this failed with `permission \
         denied` on tenant_domains, which is indistinguishable from `no such domain` to every \
         caller."
    );

    // The same name written the way an intermediary or a browser may legally write it.
    for spelling in
        ["WORKSPACE.Acme.Example", "workspace.acme.example.", "workspace.acme.example:8443"]
    {
        assert_eq!(
            resolve_routed_tenant(&pool, spelling).await.expect("resolve").map(|t| t.to_uuid()),
            Some(acme),
            "{spelling} did not resolve, so routing depends on how the host was spelled"
        );
    }
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_custom_domain_wins_over_a_tenant_slugged_like_its_first_label() {
    // The misroute. `docs.acme.example` is Acme's, and `docs` is somebody else's slug.
    let db = TestDb::start().await.expect("start a test database");
    let acme = tenant(&db, "acme", "ACTIVE").await;
    let docs = tenant(&db, "docs", "ACTIVE").await;
    domain(&db, acme, "docs.acme.example", true).await;
    let pool = pool(&db).await;

    let resolved = resolve_routed_tenant(&pool, "docs.acme.example").await.expect("resolve");
    assert_eq!(
        resolved.map(|t| t.to_uuid()),
        Some(acme),
        "the host resolved to the tenant slugged `docs` rather than the tenant that verified the \
         domain. This is a cross-tenant misroute caused by an unlucky signup, and nothing surfaces \
         it: the caller reaches a real tenant with a real sign-in page and is told only that their \
         credentials are wrong."
    );
    assert_ne!(resolved.map(|t| t.to_uuid()), Some(docs));

    // The control: the slug path still works for a host that names no verified domain.
    assert_eq!(
        resolve_routed_tenant(&pool, "docs.enclave.example")
            .await
            .expect("resolve")
            .map(|t| t.to_uuid()),
        Some(docs),
        "the slug lookup stopped working, so the assertion above passes for the wrong reason"
    );
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unverified_claim_routes_nothing() {
    // A row in `tenant_domains` is a claim until `verified_at` is set. Routing one would let
    // anyone who can add a domain take traffic for a name they do not control.
    let db = TestDb::start().await.expect("start a test database");
    let acme = tenant(&db, "acme", "ACTIVE").await;
    domain(&db, acme, "unproven.example", false).await;
    let pool = pool(&db).await;

    assert_eq!(
        resolve_routed_tenant(&pool, "unproven.example").await.expect("resolve"),
        None,
        "an unverified domain claim routed traffic"
    );

    // The positive control, on the same row: verifying it makes it route. Without this, the
    // assertion above passes against a lookup that resolves nothing at all — which is exactly the
    // state this whole row is about (docs/12-TESTING.md §1.2).
    let mut conn = db.connect().await.expect("connect");
    sqlx::query("UPDATE tenant_domains SET verified_at = now() WHERE domain = 'unproven.example'")
        .execute(&mut conn)
        .await
        .expect("verify");
    assert_eq!(
        resolve_routed_tenant(&pool, "unproven.example")
            .await
            .expect("resolve")
            .map(|t| t.to_uuid()),
        Some(acme),
        "verifying the claim did not make it route, so the refusal above proves nothing"
    );
    drop(db);
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_suspended_tenants_domain_routes_nothing() {
    // The same lifecycle rule the slug path applies, asserted on the domain path so the two cannot
    // disagree about whether a tenant is live.
    let db = TestDb::start().await.expect("start a test database");
    let gone = tenant(&db, "gone", "SUSPENDED").await;
    domain(&db, gone, "still.listed.example", true).await;
    let pool = pool(&db).await;

    assert_eq!(
        resolve_routed_tenant(&pool, "still.listed.example").await.expect("resolve"),
        None,
        "a suspended tenant's verified domain still routed, so its users can still reach a sign-in \
         page for data that is on its way out"
    );
    drop(db);
}
