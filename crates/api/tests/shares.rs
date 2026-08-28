//! `ENC-690` — the share-link management endpoints, end to end, over a real PostgreSQL.
//!
//! # The three properties these exist to hold
//!
//! 1. **Internal and external sharing are two permissions** (`CLAUDE.md` rule 6, `docs/06 §12`).
//!    A caller holding `file.share` and not `file.share_external` can mint an `INTERNAL` link and
//!    cannot mint an `ANYONE` one — and the assertion is run both ways round in one fixture, so
//!    neither half is satisfied by an endpoint that refuses everything or allows everything.
//! 2. **The token exists once.** It is returned by the creation response and stored only as
//!    SHA-256; `docs/12 §4.4` H1 is asserted here at the *API* boundary — the plaintext appears in
//!    no column of the row the endpoint just wrote, and in no later response.
//! 3. **A link in another tenant is indistinguishable from one that does not exist** (rule 7,
//!    `docs/12 §4.1` T1), on every method, and *including redemption* — which is where
//!    [`another_tenants_share_token_is_indistinguishable_from_one_that_was_never_minted`] carries
//!    the evidence for `ENC-692`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use enclave_api::{router, ApiState, Delivery};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, Actor, ClientType, Error, FileAction, FileId, LibraryId, PolicyEngine, RequestContext,
    ResourceRef, ShareAction, ShareLinkId, TenantId, UserId, WorkspaceId,
};
use enclave_db::{sql, DbPool, TenantScoped};
use enclave_sharing::{redeem, ShareToken, SharingError};
use enclave_testing::{Fixtures, TestDb};
use sqlx::{PgConnection, Row as _};
use tower::ServiceExt as _;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// `PolicyDecision` and `Obligations` are both `#[must_use]` (`CLAUDE.md` rule 8), so an allow in a
/// test has to be discharged rather than dropped — a test that dropped one would be a test that
/// ignored a demand the chain made. Every stage in this fixture is `Unconfigured` or `Disabled`, so
/// an obligation appearing at all means a stage has started deciding and the test should say so.
const NO_OBLIGATION: &str = "no stage in this fixture issues an obligation";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(PgAclAuthorization::new(authz_pool))
            as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, state_pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));

    // Sharing reaches no delivery path: no bytes, no renditions.
    Harness { app: router(state, Delivery::unconfigured()), key }
}

fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: enclave_core::ActorKind::User,
        scp: Vec::new(),
        amr: vec![AuthMethod::Pwd],
        auth_time: now,
        acr: Acr::SingleFactor,
        dev: None,
        cli: ClientType::Web,
        epoch: 1,
        max_cls: None,
    };
    AccessTokenIssuer::new(ISSUER, AUDIENCE)
        .issue(key, template, now, chrono::Duration::minutes(10))
        .expect("issue")
        .token
}

async fn call(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)));

    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => request.body(Body::empty()).expect("request"),
    };

    let response = harness.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, json)
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's spine: a workspace, a library and one file.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    file: FileId,
    /// The library above the file, so a test can place an `EVERYONE` grant on an *ancestor* rather
    /// than on the file itself — which is how a tenant-wide grant is actually written.
    library: LibraryId,
}

async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId, slug: &str) -> Spine {
    let workspace = WorkspaceId::new_v7();
    let library = LibraryId::new_v7();
    let file = FileId::new_v7();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO workspaces
           (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
         VALUES ($1, $2, 'ws', $3, 'PRIVATE', $4, $5, $5)",
    )
    .bind(sql(workspace))
    .bind(sql(tenant))
    .bind(slug)
    .bind(sql(owner))
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("insert workspace");

    sqlx::query(
        "INSERT INTO libraries
           (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
            external_sharing, created_at, updated_at)
         VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'ANYONE', $5, $5)",
    )
    .bind(sql(library))
    .bind(sql(tenant))
    .bind(sql(workspace))
    .bind(slug)
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("insert library");

    // The *same* file name in both tenants, which is what `docs/12 §3` says `tenant-beta` exists
    // for: a cross-tenant test that passes only because the other tenant's file was called
    // something else proves nothing.
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, status, inherit_permissions, created_by, modified_by, created_at,
            modified_at)
         VALUES ($1, $2, $3, $4, NULL, 'FILE', 'Board Pack.pdf', 'board pack.pdf',
                 'application/pdf', 'AVAILABLE', TRUE, $5, $5, $6, $6)",
    )
    .bind(sql(file))
    .bind(sql(tenant))
    .bind(sql(workspace))
    .bind(sql(library))
    .bind(sql(owner))
    .bind(now)
    .execute(&mut *conn)
    .await
    .expect("insert file");

    Spine { tenant, file, library }
}

async fn grant(conn: &mut PgConnection, spine: Spine, user: UserId, action: Action) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, 'FILE', $3, 'USER', $4, $5, 'ALLOW', $6, $7, NULL)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(sql(spine.tenant))
    .bind(sql(spine.file))
    .bind(sql(user))
    .bind(action.to_string())
    .bind(uuid::Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert acl entry");
}

/// Everything a link's creator needs, so a test that is about *one* permission grants the rest.
///
/// `file.metadata_read` is in the list and is load-bearing rather than incidental: it is what makes
/// a denial on this file an actionable `403` instead of a `404`. `conceal_if_not_visible` asks
/// whether the caller can see the resource at all, so a fixture that granted `file.share` without
/// it would model a caller who may share a file they cannot see — and every refusal below would
/// arrive as an absence, hiding whether the share permission was the thing that refused.
const MANAGEMENT: [Action; 5] = [
    Action::File(FileAction::MetadataRead),
    Action::File(FileAction::Share),
    Action::Share(ShareAction::Read),
    Action::Share(ShareAction::Update),
    Action::Share(ShareAction::Revoke),
];

/// A creation body.
fn share_body(audience: &str) -> serde_json::Value {
    serde_json::json!({ "permission": "VIEW", "allowDownload": true, "audience": audience })
}

/// Every text-ish column of one row, so a test can look for a leaked token in all of them at once.
///
/// `docs/12 §4.4` H1 asks for exactly this: *the assertion dumps every column looking for the
/// plaintext, because a token that leaked into a label would be just as usable.*
async fn row_dump(db: &TestDb, id: &str) -> String {
    let mut conn = db.connect().await.expect("connect");
    let row =
        sqlx::query("SELECT to_jsonb(l) AS all_columns FROM share_links l WHERE id = $1::uuid")
            .bind(id)
            .fetch_one(&mut conn)
            .await
            .expect("read the row");
    row.get::<serde_json::Value, _>("all_columns").to_string()
}

async fn audit_rows(db: &TestDb, tenant: TenantId) -> Vec<(String, String)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT action, outcome FROM audit_events WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(sql(tenant))
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

/// Two tenants, a spine in each, and each tenant's own member granted the management actions on
/// their own file. Neither is granted `file.share_external` — that is what each test adds.
async fn setup() -> (TestDb, Fixtures, DbPool, Spine, Spine) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let pool = db.pool().await.expect("application pool");

    let mut admin = db.connect().await.expect("admin connection");
    let alpha = spine(&mut admin, fixtures.alpha.id, fixtures.alpha.owner, "alpha-ws").await;
    let beta = spine(&mut admin, fixtures.beta.id, fixtures.beta.owner, "beta-ws").await;

    for action in MANAGEMENT {
        grant(&mut admin, alpha, fixtures.alpha.member, action).await;
        grant(&mut admin, beta, fixtures.beta.member, action).await;
    }
    let _ignored = sqlx::Connection::close(admin).await;

    (db, fixtures, pool, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// `CLAUDE.md` rule 6 and `docs/06 §12`: sharing outside the tenant is a different permission.
///
/// Three legs in one fixture, and each is the other's control:
///
/// * the caller holds `file.share` and mints an `INTERNAL` link — so the endpoint works;
/// * the same caller, the same file, an `ANYONE` audience — refused, so the two are not collapsed;
/// * `file.share_external` is granted and the identical request succeeds — so the refusal was the
///   missing permission and not the audience being rejected outright.
///
/// Without the third leg this passes against a handler that refuses every external audience on
/// principle, which is a different product from one that has the permission.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn sharing_externally_is_a_permission_the_internal_grant_does_not_carry() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let uri = format!("/api/v1/files/{}/shares", alpha.file);

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the internal grant must mint an internal link: {body}"
    );
    assert_eq!(body["audience"], "INTERNAL");

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("ANYONE")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "`file.share` minted a link anyone can redeem, so the two permissions have collapsed: \
         {body}"
    );
    // A `403` rather than a `404` is correct here and is not a rule-7 violation: the caller has
    // already been told the file exists by the internal link they just minted on it.
    assert_eq!(body["error"]["code"], "ACCESS_DENIED");

    // `SPECIFIC` is the one worth naming separately: its recipients are email addresses, and
    // nothing requires them to belong to the tenant.
    let (status, _body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("SPECIFIC")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a named-recipient link is not internal sharing");

    // The third leg. Grant the external action and the identical request succeeds.
    let mut admin = db.connect().await.expect("admin connection");
    grant(&mut admin, alpha, fixtures.alpha.member, Action::File(FileAction::ShareExternal)).await;
    let _ignored = sqlx::Connection::close(admin).await;

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("ANYONE")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["audience"], "ANYONE");

    // Both decisions are in the trail, under the two action names.
    let rows = audit_rows(&db, alpha.tenant).await;
    assert!(rows.iter().any(|(a, o)| a == "file.share" && o == "ALLOW"), "{rows:?}");
    assert!(rows.iter().any(|(a, o)| a == "file.share_external" && o == "DENY"), "{rows:?}");
    assert!(rows.iter().any(|(a, o)| a == "file.share_external" && o == "ALLOW"), "{rows:?}");
}

/// `docs/12 §4.4` H1 at the API boundary: the raw token appears exactly once and is never stored.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_token_is_returned_once_and_stored_nowhere() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let uri = format!("/api/v1/files/{}/shares", alpha.file);

    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let token = created["token"].as_str().expect("the creation response carries the token");
    assert!(token.len() >= 43, "a 256-bit token is 43 base64url characters");
    let id = created["id"].as_str().expect("id").to_owned();

    // Not in any column of the row that was just written — including a text column somebody might
    // add later, because the assertion reads the whole row as JSON rather than a column list.
    let dump = row_dump(&db, &id).await;
    assert!(
        !dump.contains(token),
        "the raw token is stored somewhere in share_links; a backup or a support export would \
         yield a working link"
    );
    // The positive control for that scan: the *digest* is in the dump, so the assertion is about
    // the plaintext and not about a row that was never read.
    assert!(dump.contains("token_hash"), "the dump did not include the token column at all");

    // And never again on the wire. The listing is the endpoint a client would call next.
    let (status, listed) =
        call(&harness, alpha.tenant, fixtures.alpha.member, "GET", &uri, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    assert!(
        !listed.to_string().contains(token),
        "the listing echoed the raw token, so it exists in more places than the creator's clipboard"
    );
    assert!(listed["items"][0]["token"].is_null());
    assert_eq!(listed["items"][0]["hasPassword"], false);
    assert_eq!(listed["items"][0]["downloadCount"], 0);
}

/// `ENC-692`, and `docs/12 §4.1` T1 for the redemption path.
///
/// This is the evidence behind not registering `GET /shares/{token}`. A token minted in
/// `tenant-alpha` is presented to `enclave_sharing::redeem` — the exact call the route would make —
/// under `tenant-beta`'s transaction, and is refused with the same error a token that was never
/// minted gets. Row-level security is what refuses it: the row is invisible, not compared.
///
/// The control is the same token under `tenant-alpha`'s transaction, which **succeeds and spends
/// the budget**. Without it, "beta cannot redeem alpha's token" would hold against a token that
/// nothing could redeem — which, until `ENC-692` is closed, is the situation for every anonymous
/// redeemer, and is exactly the confusion this test exists to keep visible.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_share_token_is_indistinguishable_from_one_that_was_never_minted() {
    let (db, fixtures, pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/files/{}/shares", alpha.file),
        Some(serde_json::json!({
            "permission": "VIEW", "allowDownload": true,
            "audience": "INTERNAL", "maxDownloads": 2
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let raw = created["token"].as_str().expect("token").to_owned();
    let token = ShareToken::parse(&raw).expect("a token this API just minted must parse");

    // Beta's scope. The row exists, in another tenant, and RLS makes it unreachable.
    let mut beta_tx = TenantScoped::begin(&pool, fixtures.beta.id).await.expect("begin");
    let cross_tenant = redeem(&mut beta_tx, &token, Utc::now()).await;
    let stranger = ShareToken::generate().expect("entropy");
    let never_minted = redeem(&mut beta_tx, &stranger, Utc::now()).await;
    beta_tx.rollback().await.expect("rollback");

    assert!(
        matches!(cross_tenant, Err(SharingError::LinkUnusable)),
        "beta resolved alpha's share token: {cross_tenant:?}"
    );
    assert!(matches!(never_minted, Err(SharingError::LinkUnusable)));

    // The control: the same token, alpha's scope. It works, and spending is what it does.
    let mut alpha_tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let redemption = redeem(&mut alpha_tx, &token, Utc::now()).await.expect("alpha may redeem");
    alpha_tx.commit().await.expect("commit");
    assert_eq!(
        redemption.download_count, 1,
        "the budget is spent by the statement that redeems it, so a successful redemption must \
         have moved the counter"
    );

    // The listing reflects the spend, which is the creator's window onto it.
    let (_status, listed) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/files/{}/shares", alpha.file),
        None,
    )
    .await;
    assert_eq!(listed["items"][0]["downloadCount"], 1);
}

/// Rule 7 on the two `/shares/{id}` methods: another tenant's link is a `404`, and so is a
/// fabricated id.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn another_tenants_link_cannot_be_patched_or_revoked() {
    let (db, fixtures, _pool, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (status, betas) = call(
        &harness,
        beta.tenant,
        fixtures.beta.member,
        "POST",
        &format!("/api/v1/files/{}/shares", beta.file),
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{betas}");
    let beta_link = betas["id"].as_str().expect("id").to_owned();

    let (status, alphas) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/files/{}/shares", alpha.file),
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{alphas}");
    let alpha_link = alphas["id"].as_str().expect("id").to_owned();

    for (method, body) in
        [("PATCH", Some(serde_json::json!({ "allowDownload": false }))), ("DELETE", None)]
    {
        // The control first: the caller's own link answers something other than `404`.
        let (own, _) = call(
            &harness,
            alpha.tenant,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/shares/{alpha_link}"),
            body.clone(),
        )
        .await;
        assert_ne!(own, StatusCode::NOT_FOUND, "{method} on the caller's own link answered 404");

        let (cross, _) = call(
            &harness,
            alpha.tenant,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/shares/{beta_link}"),
            body.clone(),
        )
        .await;
        let (fabricated, _) = call(
            &harness,
            alpha.tenant,
            fixtures.alpha.member,
            method,
            &format!("/api/v1/shares/{}", uuid::Uuid::now_v7()),
            body,
        )
        .await;

        assert_eq!(cross, StatusCode::NOT_FOUND, "{method} leaked another tenant's link");
        assert_eq!(
            cross, fabricated,
            "{method} answered another tenant's link differently from one that never existed"
        );
    }

    // Beta's link is exactly as beta left it.
    let (_status, listed) = call(
        &harness,
        beta.tenant,
        fixtures.beta.member,
        "GET",
        &format!("/api/v1/files/{}/shares", beta.file),
        None,
    )
    .await;
    assert_eq!(listed["items"][0]["id"], beta_link);
    assert_eq!(listed["items"][0]["allowDownload"], true);
    assert!(listed["items"][0]["revokedAt"].is_null());
}

/// A patch changes what it names and nothing else, and `null` is an instruction rather than an
/// absence.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_patch_changes_only_what_it_names_and_null_clears() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let expiry = Utc::now() + Duration::days(7);

    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/files/{}/shares", alpha.file),
        Some(serde_json::json!({
            "permission": "VIEW", "allowDownload": true, "audience": "INTERNAL",
            "expiresAt": expiry.to_rfc3339(), "maxDownloads": 5
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("id").to_owned();
    assert!(created["expiresAt"].is_string());

    // One field named. The other three must survive untouched.
    let (status, patched) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "permission": "PREVIEW_ONLY" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["permission"], "PREVIEW_ONLY");
    assert_eq!(patched["allowDownload"], true, "an unnamed field was changed");
    assert_eq!(patched["maxDownloads"], 5, "an unnamed field was changed");
    assert!(patched["expiresAt"].is_string(), "an unnamed field was cleared");

    // An explicit null clears. This is the assertion a plain `Option` cannot satisfy.
    let (status, patched) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "expiresAt": null })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert!(patched["expiresAt"].is_null(), "an explicit null did not clear the expiry");
    assert_eq!(patched["permission"], "PREVIEW_ONLY", "clearing one field changed another");
}

/// The `share_links_within_budget` backstop, reached through the endpoint.
///
/// Lowering the limit below what the link has already issued is well-formed and impossible, which
/// is `422` rather than `400`. The refusal is asserted to have changed *nothing*, and the control —
/// the same patch at a value the spend allows — runs afterwards and succeeds, so the assertion is
/// about the number rather than about a `PATCH` that never writes.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_budget_lowered_below_what_the_link_already_spent_is_refused() {
    let (db, fixtures, pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/files/{}/shares", alpha.file),
        Some(serde_json::json!({
            "permission": "VIEW", "allowDownload": true,
            "audience": "INTERNAL", "maxDownloads": 5
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("id").to_owned();
    let raw = created["token"].as_str().expect("token").to_owned();
    let token = ShareToken::parse(&raw).expect("parse");

    // Spend two of the five, through the statement that spends them.
    for expected in 1..=2 {
        let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
        let redemption = redeem(&mut tx, &token, Utc::now()).await.expect("within budget");
        tx.commit().await.expect("commit");
        assert_eq!(redemption.download_count, expected);
    }

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "maxDownloads": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], "maxDownloads");

    let (_status, listed) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/files/{}/shares", alpha.file),
        None,
    )
    .await;
    assert_eq!(listed["items"][0]["maxDownloads"], 5, "the refused patch changed the row anyway");
    assert_eq!(listed["items"][0]["downloadCount"], 2);

    // The control: at the spend, it is accepted — so the refusal was the arithmetic and not the
    // endpoint.
    let (status, patched) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "maxDownloads": 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["maxDownloads"], 2);

    // And the link is now exhausted, which is what that number means.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let exhausted = redeem(&mut tx, &token, Utc::now()).await;
    tx.rollback().await.expect("rollback");
    assert!(matches!(exhausted, Err(SharingError::BudgetExhausted)), "{exhausted:?}");
}

/// Revocation is idempotent at the edge, stamps rather than deletes, and closes the link.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn revoking_is_idempotent_and_closes_the_link_for_good() {
    let (db, fixtures, pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &format!("/api/v1/files/{}/shares", alpha.file),
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("id").to_owned();
    let token = ShareToken::parse(created["token"].as_str().expect("token")).expect("parse");

    // The link is made usable *first*. `docs/12 §4.4` H4: a link that was never usable proves
    // nothing about revocation.
    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    redeem(&mut tx, &token, Utc::now()).await.expect("a live link redeems");
    tx.commit().await.expect("commit");

    let (status, _body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "DELETE",
        &format!("/api/v1/shares/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Idempotent: revoking again is still `204`, and the first timestamp is the one kept.
    let (status, _body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "DELETE",
        &format!("/api/v1/shares/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let mut tx = TenantScoped::begin(&pool, alpha.tenant).await.expect("begin");
    let after = redeem(&mut tx, &token, Utc::now()).await;
    tx.rollback().await.expect("rollback");
    assert!(matches!(after, Err(SharingError::LinkUnusable)), "{after:?}");

    // The row is still there — `share_link_events` points at it — and it says when.
    let (_status, listed) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "GET",
        &format!("/api/v1/files/{}/shares", alpha.file),
        None,
    )
    .await;
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    assert!(
        listed["items"][0]["revokedAt"].is_string(),
        "a revoked link vanished from the listing"
    );

    // A revoked link is no longer patchable, and says so as an absence rather than reporting a
    // state a caller could probe for.
    let (status, _body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "allowDownload": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A caller who may read the file but holds none of the share actions is refused on every one of
/// the four, and the refusals leave rows.
///
/// The `PATCH` and `DELETE` legs are here because of a deliberate break that failed nothing
/// (`docs/12 §1.2`). Removing `authorize` from both handlers left every other test in this file
/// green: `governing_resource` reads the link inside a tenant-scoped transaction, so row-level
/// security still answered `404` across tenants, and every other fixture's caller held the grant.
/// The case that RLS cannot cover is a second member of the **same** tenant who has learned a link
/// id — from a URL, a screenshot, an audit export — and only the chain can refuse them.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_share_actions_are_not_implied_by_reading_the_file() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    // The viewer can see the file — that is the whole point of granting it — and holds nothing
    // else. Without this grant every assertion below would pass because the file was invisible.
    let mut admin = db.connect().await.expect("admin connection");
    grant(&mut admin, alpha, fixtures.alpha.viewer, Action::File(FileAction::MetadataRead)).await;
    let _ignored = sqlx::Connection::close(admin).await;

    let (status, _body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.viewer,
        "GET",
        &format!("/api/v1/files/{}", alpha.file),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the viewer must be able to see the file");

    let uri = format!("/api/v1/files/{}/shares", alpha.file);
    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.viewer,
        "POST",
        &uri,
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reading a file must not imply sharing it: {body}");

    let (status, body) =
        call(&harness, alpha.tenant, fixtures.alpha.viewer, "GET", &uri, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "reading a file must not imply reading its links: {body}"
    );

    // The member — who holds the management grants — mints a link, and the viewer tries to change
    // and revoke it. Both are ids the viewer could plausibly have; neither is in another tenant, so
    // row-level security has nothing to say and the chain is the only thing that can refuse.
    let (status, created) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.member,
        "POST",
        &uri,
        Some(share_body("INTERNAL")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("id").to_owned();

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.viewer,
        "PATCH",
        &format!("/api/v1/shares/{id}"),
        Some(serde_json::json!({ "allowDownload": false })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "reading a file must not imply patching its links: {body}"
    );

    let (status, body) = call(
        &harness,
        alpha.tenant,
        fixtures.alpha.viewer,
        "DELETE",
        &format!("/api/v1/shares/{id}"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "reading a file must not imply revoking its links: {body}"
    );

    // Nothing the viewer attempted changed the link. The control that this is not vacuous is the
    // `201` above: the link demonstrably exists and demonstrably has these values.
    let (_status, listed) =
        call(&harness, alpha.tenant, fixtures.alpha.member, "GET", &uri, None).await;
    assert_eq!(listed["items"][0]["allowDownload"], true, "the refused patch changed the link");
    assert!(listed["items"][0]["revokedAt"].is_null(), "the refused delete revoked the link");

    let rows = audit_rows(&db, alpha.tenant).await;
    assert!(rows.iter().any(|(a, o)| a == "file.share" && o == "DENY"), "{rows:?}");
    assert!(rows.iter().any(|(a, o)| a == "share.read" && o == "DENY"), "{rows:?}");
    assert!(rows.iter().any(|(a, o)| a == "share.update" && o == "DENY"), "{rows:?}");
    assert!(rows.iter().any(|(a, o)| a == "share.revoke" && o == "DENY"), "{rows:?}");
}

// ---------------------------------------------------------------------------------------------
// `ENC-879` — the chain can authorize the one principal a redemption can present
//
// The redemption **route is deliberately not registered**, and these tests call
// `PolicyEngine::enforce` directly for that reason. `ENC-694` is still open: a link's password,
// OTP, MFA requirement and audience are enforced by nothing, so an endpoint that authorised a
// redemption today would hand out access past every demand the link states. This task makes the
// chain *able to express* a link bearer; `ENC-694` makes the link's own conditions real; only then
// does `ENC-692` register `GET /shares/{token}`.
// ---------------------------------------------------------------------------------------------

/// The link, and the raw token, minted through the real endpoint.
struct MintedLink {
    id: ShareLinkId,
    raw: String,
}

async fn mint(harness: &Harness, spine: Spine, member: UserId, audience: &str) -> MintedLink {
    let (status, created) = call(
        harness,
        spine.tenant,
        member,
        "POST",
        &format!("/api/v1/files/{}/shares", spine.file),
        Some(share_body(audience)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    MintedLink {
        id: created["id"].as_str().expect("id").parse().expect("a ShareLinkId"),
        raw: created["token"].as_str().expect("token").to_owned(),
    }
}

/// Grants an action on a spine's file to the bearer of one link.
///
/// This is the row that could not exist before `ENC-879`: `acl_entries.principal_type` admitted
/// five kinds and none of them was *the bearer of this link*, so `migrations/0027` is what makes
/// this `INSERT` succeed rather than raise a `CHECK` violation.
async fn grant_to_link(conn: &mut PgConnection, spine: Spine, link: ShareLinkId, action: Action) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, 'FILE', $3, 'SHARE_LINK', $4, $5, 'ALLOW', $6, $7, NULL)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(sql(spine.tenant))
    .bind(sql(spine.file))
    .bind(link.as_uuid())
    .bind(action.to_string())
    .bind(uuid::Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert a SHARE_LINK acl entry");
}

/// A tenant-wide `EVERYONE` grant on the spine's *library*, which every member of the tenant holds.
async fn grant_to_everyone(conn: &mut PgConnection, spine: Spine, action: Action) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, 'LIBRARY', $3, 'EVERYONE', NULL, $4, 'ALLOW', $5, $6, NULL)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(sql(spine.tenant))
    .bind(sql(spine.library))
    .bind(action.to_string())
    .bind(uuid::Uuid::nil())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("insert an EVERYONE acl entry");
}

/// A policy engine over the test database, so a test can call `enforce` directly.
async fn engine(db: &TestDb) -> PolicyEngine {
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");
    PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(PgAclAuthorization::new(authz_pool))
            as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    )
}

/// The context a redemption would build: the tenant established by routing, and the *link* as the
/// principal.
///
/// `RequestContext::system` is the starting point only because it is the one constructor that fills
/// the network and device fields with the weakest possible values, which is exactly right here —
/// nothing about a redemption is evidence of anything. The actor is then the link.
fn bearer_ctx(tenant: TenantId, link: ShareLinkId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::LinkBearer(link);
    ctx.client = ClientType::Web;
    ctx
}

fn member_ctx(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx.client = ClientType::Web;
    ctx
}

/// Every audit row's actor, action and outcome, so a test can assert *who* a row names.
type AuditActor = (String, Option<uuid::Uuid>, String, String);

async fn audit_actors(db: &TestDb, tenant: TenantId) -> Vec<AuditActor> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT actor_type, actor_id, action, outcome FROM audit_events
          WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(sql(tenant))
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

/// `ENC-879`. **The specification for this task.**
///
/// Before this change, `PolicyEngine::enforce` could not return an allow for any caller a
/// redemption could construct: `Actor` had no variant naming a link, `acl_entries.principal_type`
/// had no value naming one, `classify` mapped `ResourceKind::Share` to `Target::Unsupported`, and
/// `PrincipalSet::for_actor` refused every actor that was not a user, a guest or a service account.
/// `docs/01-PRD.md §220`'s share links described a product the chain had no vocabulary for.
///
/// The control comes **first**, and it is the whole reason the refusals below mean anything: an
/// assertion that the chain refused something is satisfied for free by a chain that refuses
/// everything, which is precisely the state this test replaces.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_chain_authorizes_the_link_bearer_a_redemption_presents() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let policy = engine(&db).await;

    let link = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;

    let mut admin = db.connect().await.expect("admin connection");
    grant_to_link(&mut admin, alpha, link.id, Action::File(FileAction::Preview)).await;
    let _ignored = sqlx::Connection::close(admin).await;

    let file = ResourceRef::file(alpha.tenant, alpha.file);
    let ctx = bearer_ctx(alpha.tenant, link.id);

    // ---- The control. A row naming this link grants this link. --------------------------------
    policy
        .enforce(&ctx, Action::File(FileAction::Preview), &file)
        .await
        .expect("the chain must be able to allow the principal a redemption presents")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);

    // ---- The grant is the link's, and it is one action. ---------------------------------------
    // A different action on the same file, for the same link, is refused. Without this leg the one
    // above is satisfied by a chain that allows a link bearer anything once any row exists — and
    // preview-versus-download is `CLAUDE.md` rule 6 exactly.
    let denied = policy.enforce(&ctx, Action::File(FileAction::Download), &file).await;
    assert!(
        matches!(denied, Err(Error::PolicyDenied { .. })),
        "a preview grant must not carry download: {denied:?}"
    );

    // ---- The audit row names the link, honestly. ----------------------------------------------
    // `CLAUDE.md` rule 10. The whole reason an `Actor` variant was added rather than a `GuestId`
    // fabricated is that a fabricated principal writes a *false* actor into this table.
    let rows = audit_actors(&db, alpha.tenant).await;
    let allowed = rows
        .iter()
        .find(|(kind, _, action, outcome)| {
            kind == "share_link" && action == "file.preview" && outcome == "ALLOW"
        })
        .expect(
            "the redemption's allow must be audited as a share_link actor; a row attributing it to \
             a user or to the system is the false-actor problem this design exists to avoid",
        );
    assert_eq!(
        allowed.1,
        Some(link.id.as_uuid()),
        "the audit row must name *which* link was used — that is the first question an \
         investigation asks, and a row without it records an event nobody can attribute"
    );
    assert!(
        rows.iter().any(|(kind, id, action, outcome)| kind == "share_link"
            && *id == Some(link.id.as_uuid())
            && action == "file.download"
            && outcome == "DENY"),
        "the denial must be audited too, and as the same link: {rows:?}"
    );

    // The token itself appears nowhere. It exists once, in the response that minted it.
    assert!(!format!("{rows:?}").contains(&link.raw), "the raw token reached the audit trail");
    assert!(
        !row_dump(&db, &link.id.to_string()).await.contains(&link.raw),
        "the raw token reached the share_links row"
    );
}

/// `ENC-879`, and the decision most worth disagreeing with in review.
///
/// An `EVERYONE` grant is how *"all staff may read the handbook library"* is written. It must not
/// silently become *"and so may anyone holding any share link into this tenant"*.
///
/// Three legs, and the first is the control for the second:
///
/// * the identical `EVERYONE` row grants an ordinary member — so the row is live and the fixture is
///   not simply broken;
/// * it does not grant the link bearer;
/// * the link bearer is nonetheless allowed through its *own* row — so the refusal is about
///   `EVERYONE` and not about the principal being unable to hold any permission at all.
///
/// **Which layer holds it: the chain**, in two places — `PrincipalSet::matches` and the `WHERE`
/// clause of `repo::acl_entries_by_action`. Not row-level security, which cannot tell two
/// principals of one tenant apart, and not the migration, which only makes the `SHARE_LINK` row
/// storable. Both legs run inside `tenant-alpha`, so RLS is satisfied throughout and has nothing to
/// contribute either way.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_tenant_wide_grant_does_not_reach_a_share_link_bearer() {
    let (db, fixtures, _pool, alpha, _beta) = setup().await;
    let harness = harness(&db).await;
    let policy = engine(&db).await;

    let link = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;

    let mut admin = db.connect().await.expect("admin connection");
    grant_to_everyone(&mut admin, alpha, Action::File(FileAction::Download)).await;
    grant_to_link(&mut admin, alpha, link.id, Action::File(FileAction::Preview)).await;
    let _ignored = sqlx::Connection::close(admin).await;

    let file = ResourceRef::file(alpha.tenant, alpha.file);

    // Leg 1 — the control. `EVERYONE` reaches a member of this tenant. The `viewer` fixture holds
    // no grant of its own on this file, so if this fails the row is simply not working.
    let member = member_ctx(alpha.tenant, fixtures.alpha.viewer);
    policy
        .enforce(&member, Action::File(FileAction::Download), &file)
        .await
        .expect("an EVERYONE grant must reach a member of the tenant")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);

    // Leg 2 — the finding. The same row does not reach the link bearer.
    let bearer = bearer_ctx(alpha.tenant, link.id);
    let refused = policy.enforce(&bearer, Action::File(FileAction::Download), &file).await;
    assert!(
        matches!(refused, Err(Error::PolicyDenied { .. })),
        "an EVERYONE grant reached a share-link bearer, which would extend every link in this \
         tenant to everything the tenant shares internally: {refused:?}"
    );

    // Leg 3 — the bearer is not simply unable to hold anything. Its own row still grants.
    policy
        .enforce(&bearer, Action::File(FileAction::Preview), &file)
        .await
        .expect("the link's own SHARE_LINK row must still grant it")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);
}

/// `ENC-879` and `CLAUDE.md` rule 7, on the redemption principal.
///
/// A link that never existed, a revoked one, an expired one and another tenant's must all be one
/// answer. The test says **which layer** holds each, because "it refused" and "the right thing
/// refused" are different claims and this repository has repeatedly found the second to be false
/// while the first was true.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_unusable_link_is_the_same_answer_as_one_that_never_existed() {
    let (db, fixtures, _pool, alpha, beta) = setup().await;
    let harness = harness(&db).await;
    let policy = engine(&db).await;

    let live = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;
    let revoked = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;
    let expired = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;
    let betas = mint(&harness, beta, fixtures.beta.member, "INTERNAL").await;

    let mut admin = db.connect().await.expect("admin connection");
    for link in [&live, &revoked, &expired] {
        grant_to_link(&mut admin, alpha, link.id, Action::File(FileAction::Preview)).await;
    }
    // Beta's link is granted preview on *beta's* file, so the cross-tenant leg below presents a
    // link that genuinely works somewhere — not one that would have been refused anyway.
    grant_to_link(&mut admin, beta, betas.id, Action::File(FileAction::Preview)).await;

    sqlx::query("UPDATE share_links SET revoked_at = $2 WHERE id = $1")
        .bind(revoked.id.as_uuid())
        .bind(Utc::now())
        .execute(&mut admin)
        .await
        .expect("revoke");
    sqlx::query("UPDATE share_links SET expires_at = $2 WHERE id = $1")
        .bind(expired.id.as_uuid())
        .bind(Utc::now() - Duration::hours(1))
        .execute(&mut admin)
        .await
        .expect("expire");
    let _ignored = sqlx::Connection::close(admin).await;

    let file = ResourceRef::file(alpha.tenant, alpha.file);
    let preview = Action::File(FileAction::Preview);

    // The control, first: the live link works. Every refusal below is measured against it.
    policy
        .enforce(&bearer_ctx(alpha.tenant, live.id), preview, &file)
        .await
        .expect("the live link must work, or nothing below distinguishes anything")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);

    // Each of the four, asked about alpha's file inside alpha's tenant.
    //
    // **This is the leg that found a real defect.** The revoked and expired links were *allowed*
    // on the first run: their `acl_entries` rows still named them, and nothing in the chain read
    // `share_links.revoked_at`. `docs/12 §4.4` H4 requires revocation to close a link "including
    // for an already-open session", and an authorization stage that answers `ALLOW` for a revoked
    // credential is that requirement failing at the layer that decides. The fix is
    // `AclResolver::link_principal_is_live`, which reads liveness in the same transaction as the
    // decision — not a second write at revocation time, which could half-succeed.
    //
    // **Which layer holds each:** the *unknown* and *revoked/expired* legs are held by the chain
    // alone — three of the four ids are alpha's own, so row-level security has nothing to say. The
    // *cross-tenant* leg is held twice: `share_targets` carries an explicit `tenant_id = $1`
    // predicate (layer 1) and runs on a `TenantScoped` connection where RLS excludes beta's row
    // anyway (layer 2).
    //
    // **Deleting that predicate was tried and failed nothing here** — the tenth time this repository
    // has found that shape. `migrations/0008` `FORCE`s a policy on `share_links`, so beta's row is
    // invisible on a scoped connection whether or not the statement mentions a tenant. The layer-1
    // half is therefore held by
    // `acl_resolution::the_share_lookup_filters_by_tenant_without_help_from_row_level_security`,
    // which asks the same question on a connection with RLS out of the way and *does* fail. This
    // test proves isolation; it does not prove there are two layers of it.
    let never = ShareLinkId::new_v7();
    let cases: [(&str, ShareLinkId); 4] = [
        ("a link that never existed", never),
        ("a revoked link", revoked.id),
        ("an expired link", expired.id),
        ("another tenant's link", betas.id),
    ];
    for (what, id) in cases {
        let outcome = policy.enforce(&bearer_ctx(alpha.tenant, id), preview, &file).await;
        assert!(
            matches!(outcome, Err(Error::PolicyDenied { .. })),
            "{what} was not refused: {outcome:?}"
        );
    }

    // Beta's link, asked about beta's own file, under **alpha's** tenant. Held by
    // `PolicyEngine::enforce`'s stage-1 comparison — the application layer, before any query — and
    // it is `NotFound` rather than a policy denial, because a `403` would confirm that beta's file
    // exists (`CLAUDE.md` rule 7).
    let cross = policy
        .enforce(
            &bearer_ctx(alpha.tenant, betas.id),
            preview,
            &ResourceRef::file(beta.tenant, beta.file),
        )
        .await;
    assert!(
        matches!(cross, Err(Error::NotFound)),
        "a cross-tenant reference must be 404, never 403: {cross:?}"
    );

    // And beta's link *does* work inside beta, so the refusals above are about alpha's scope and
    // not about beta's link being broken.
    policy
        .enforce(
            &bearer_ctx(beta.tenant, betas.id),
            preview,
            &ResourceRef::file(beta.tenant, beta.file),
        )
        .await
        .expect("beta's link must work in beta")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);
}

/// `ENC-879`. The chain can now be asked about the **link itself**, not only about the file.
///
/// `docs/05-API.md §10`'s `PATCH` and `DELETE` are operations on a link. Before this change
/// `classify` mapped `ResourceKind::Share` to `Target::Unsupported`, so the chain denied every such
/// question and `crates/api/src/routes/shares.rs` had to resolve the link's target by hand before
/// asking. The resolver does it now: a share reference walks the ACL of whatever the link exposes.
///
/// The control is first. The refusal that follows is about the link being revoked, and the
/// mechanism is `repo::share_targets`' liveness filter — **not** RLS, since both legs run inside
/// alpha and differ only in `revoked_at`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_share_reference_resolves_to_the_acl_of_what_the_link_exposes() {
    let (db, fixtures, _pool, alpha, beta) = setup().await;
    let harness = harness(&db).await;
    let policy = engine(&db).await;

    let live = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;
    let dead = mint(&harness, alpha, fixtures.alpha.member, "INTERNAL").await;

    let mut admin = db.connect().await.expect("admin connection");
    sqlx::query("UPDATE share_links SET revoked_at = $2 WHERE id = $1")
        .bind(dead.id.as_uuid())
        .bind(Utc::now())
        .execute(&mut admin)
        .await
        .expect("revoke");
    let _ignored = sqlx::Connection::close(admin).await;

    // `setup` granted the member `share.update` on alpha's *file*. Asking about the *link* must
    // reach the same row, because that is what "the permission that governs a link is the
    // permission on the thing it exposes" means.
    let member = member_ctx(alpha.tenant, fixtures.alpha.member);
    policy
        .enforce(
            &member,
            Action::Share(ShareAction::Update),
            &ResourceRef::share(alpha.tenant, live.id),
        )
        .await
        .expect("a share reference must resolve through the file the link points at")
        .into_obligations()
        .is_empty()
        .then_some(())
        .expect(NO_OBLIGATION);

    // A revoked link resolves to nothing, so the same caller with the same grant is refused.
    let refused = policy
        .enforce(
            &member,
            Action::Share(ShareAction::Update),
            &ResourceRef::share(alpha.tenant, dead.id),
        )
        .await;
    assert!(
        matches!(refused, Err(Error::PolicyDenied { .. })),
        "a revoked link must resolve to nothing: {refused:?}"
    );

    // A link id from another tenant, asked inside alpha, is `PolicyDenied` and not an allow —
    // held by the **query**, whose `tenant_id = $1` predicate is layer 1, with RLS behind it as
    // layer 2. A reference that *names* beta's tenant is stage 1 of the engine, and is `NotFound`.
    let betas = mint(&harness, beta, fixtures.beta.member, "INTERNAL").await;
    let smuggled = policy
        .enforce(
            &member,
            Action::Share(ShareAction::Update),
            &ResourceRef::share(alpha.tenant, betas.id),
        )
        .await;
    assert!(matches!(smuggled, Err(Error::PolicyDenied { .. })), "{smuggled:?}");
    let named = policy
        .enforce(
            &member,
            Action::Share(ShareAction::Update),
            &ResourceRef::share(beta.tenant, betas.id),
        )
        .await;
    assert!(matches!(named, Err(Error::NotFound)), "{named:?}");
}

/// `ENC-879`. A link bearer is not a token subject, at the mint and at the door.
///
/// If a signed access token could assert `typ: "share_link"`, then becoming a link bearer would be
/// a matter of asking for a token instead of redeeming a link — skipping the password, the OTP, the
/// MFA requirement and the audience the link states, which is the whole of `ENC-694`. The refusal
/// is therefore at issuance *and* at verification, not merely "we never mint one".
#[test]
fn no_access_token_can_assert_the_share_link_actor_kind() {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");
    let now = Utc::now();
    let template = TokenTemplate {
        sub: ShareLinkId::new_v7().as_uuid(),
        tid: TenantId::new_v7().as_uuid(),
        sid: uuid::Uuid::new_v4(),
        typ: enclave_core::ActorKind::ShareLink,
        scp: Vec::new(),
        amr: vec![AuthMethod::Pwd],
        auth_time: now,
        acr: Acr::SingleFactor,
        dev: None,
        cli: ClientType::Web,
        epoch: 1,
        max_cls: None,
    };
    let issuer = AccessTokenIssuer::new(ISSUER, AUDIENCE);
    let refused = issuer.issue(&key, template.clone(), now, Duration::minutes(10));
    assert!(
        matches!(
            refused,
            Err(enclave_auth::AuthError::ActorKindNotATokenSubject {
                kind: enclave_core::ActorKind::ShareLink
            })
        ),
        "a share-link access token was minted: {refused:?}"
    );

    // The control: every other kind still mints, so the refusal is about this kind and not about
    // `issue` having stopped working.
    for kind in enclave_core::ActorKind::all() {
        if *kind == enclave_core::ActorKind::ShareLink {
            continue;
        }
        let candidate = TokenTemplate { typ: *kind, ..template.clone() };
        assert!(
            issuer.issue(&key, candidate, now, Duration::minutes(10)).is_ok(),
            "{kind} stopped being issuable"
        );
    }
}
