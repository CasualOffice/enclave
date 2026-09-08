//! `GET /files/{id}/metadata` and `GET /libraries/{id}/fields`, over a real PostgreSQL — `ENC-984`.
//!
//! `crates/metadata` had 630 lines of tests and no caller outside them. Those tests prove the crate
//! validates and stores correctly; none of them could tell you whether a request reaches it, which
//! is the gap this file closes and the one `plans/M5A-API-COMPLETION.md` opens by naming: *a task is
//! done when a request returns the right answer, not when its tests pass.*
//!
//! # What is asserted, and the order it is asserted in
//!
//! Rule 7 first, because it is the property that cannot be added later: a caller who may not see a
//! resource must not learn that it exists. Both routes answer `404` for another tenant's id, and
//! both are checked with a **positive control in the same test** — without one, `404` for everything
//! is indistinguishable from a route that resolves nothing, which is exactly how `ENC-893` came to
//! believe a working suite was broken and how `ENC-543` came to believe a broken gate was working.
//!
//! Then the joins, because they are where a read path is quietly wrong: a field that applies but
//! holds no value must come back *without* a `value` key rather than with `null`, and a value whose
//! field belongs to another library must not appear at all.
//!
//! # Fixtures are written directly, and `library_create.rs` states the reason
//!
//! *A fixture built by the surface being tested cannot be trusted to exist when the surface is
//! broken.* There is a second reason here: `crates/metadata`'s repository has no function that
//! creates a field, so there is no route and no crate call that could build one. `ENC-996` is the
//! row for the write half.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_core::{
    Action, ClientType, ContainerAction, FileAction, FileId, LibraryId, PolicyEngine, TenantId,
    UserId, WorkspaceId,
};
use enclave_testing::TestDb;
use sqlx::PgConnection;
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// A fixed instant, so a row's timestamps say nothing about when the suite ran.
fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a real instant")
}

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's workspace, library and file — the chain a metadata scope is resolved through.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    file: FileId,
}

impl Spine {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            file: FileId::new_v7(),
        }
    }

    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, description, visibility, created_by, created_at,
                updated_at)
             VALUES ($1, $2, 'Engineering', $3, 'a description', 'PRIVATE', $4, $5, $5)",
        )
        .bind(self.workspace.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(format!("ws-{}", self.workspace.as_uuid()))
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert workspace");

        sqlx::query(
            "INSERT INTO libraries
               (id, tenant_id, workspace_id, name, slug, inherit_permissions, versioning_mode,
                external_sharing, created_at, updated_at)
             VALUES ($1, $2, $3, 'lib', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert library");

        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, node_type, name, normalized_name,
                mime_type, size_bytes, inherit_permissions, status, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, 'FILE', 'report.pdf', 'report.pdf', 'application/pdf',
                     1024, TRUE, 'AVAILABLE', $5, $5, $6, $6)",
        )
        .bind(self.file.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert file");
    }
}

/// Defines a field, and returns its id so a value can be filed against it.
async fn define_field(
    conn: &mut PgConnection,
    tenant: TenantId,
    scope: &str,
    scope_id: Option<Uuid>,
    key: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO metadata_fields
           (id, tenant_id, scope, scope_id, key, label, field_type, required, indexed, config,
            created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'TEXT', FALSE, FALSE, '{}'::jsonb, $7)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(scope)
    .bind(scope_id)
    .bind(key)
    .bind(format!("Label for {key}"))
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("define field");
    id
}

/// Files a value against a field. `value_text` is never named — it is `GENERATED ALWAYS`.
async fn set_value(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource: Uuid,
    field: Uuid,
    value: &str,
    by: UserId,
) {
    sqlx::query(
        "INSERT INTO metadata_values
           (tenant_id, resource_type, resource_id, field_id, value, updated_by, updated_at)
         VALUES ($1, 'FILE', $2, $3, $4::jsonb, $5, $6)",
    )
    .bind(tenant.as_uuid())
    .bind(resource)
    .bind(field)
    .bind(serde_json::to_string(&serde_json::json!(value)).expect("json"))
    .bind(by.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("set value");
}

async fn grant(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource_id: Uuid,
    user: UserId,
    action: Action,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         VALUES ($1, $2, $3, $4, 'USER', $5, $6, 'ALLOW', $7, $8, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    .bind(user.as_uuid())
    .bind(action.to_string())
    .bind(Uuid::nil())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("grant");
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // `SelfServiceOr` over the real ACL resolver: the composition `crates/api/src/main.rs` ships
    // (`ENC-746`). Wiring the resolver alone would exercise a composition no deployment runs.
    let authorization = Arc::new(enclave_authorization::SelfServiceOr::new(
        enclave_authorization::PgAclAuthorization::new(db.pool().await.expect("authz pool")),
    ));

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization as Arc<dyn enclave_core::AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(
            db.pool().await.expect("audit pool"),
            enclave_audit::ChainMode::Enabled,
        )),
    );

    let state = ApiState::new(
        policy,
        db.pool().await.expect("state pool"),
        ISSUER,
        AUDIENCE,
        KeySet::new([key.public().clone()]),
    );
    Harness { app: router(state, enclave_api::Delivery::unconfigured()), key }
}

fn token(key: &PrivateSigningKey, tenant: TenantId, user: UserId) -> String {
    let now = Utc::now();
    let template = TokenTemplate {
        sub: user.as_uuid(),
        tid: tenant.as_uuid(),
        sid: Uuid::new_v4(),
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

async fn get(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    path: &str,
) -> (StatusCode, serde_json::Value) {
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.expect("body");
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ---------------------------------------------------------------------------------------------
// Rule 7 — a refusal must not confirm existence
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_librarys_fields_are_indistinguishable_from_a_library_that_does_not_exist() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let harness = harness(&db).await;

    let alpha = Spine::new(fixtures.alpha.id);
    let mut admin = db.connect().await.expect("admin");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha.tenant,
        "LIBRARY",
        alpha.library.as_uuid(),
        fixtures.alpha.owner,
        Action::Container(ContainerAction::Read),
    )
    .await;

    let path = format!("/api/v1/libraries/{}/fields", alpha.library.as_uuid());

    // **The positive control, first.** Without it every assertion below is satisfied by a route
    // that resolves nothing at all, which is `ENC-543`'s failure and `ENC-893`'s in the other
    // direction.
    let (status, _) = get(&harness, alpha.tenant, fixtures.alpha.owner, &path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the grant holder must be able to read the library's fields"
    );

    // Beta's token, alpha's library. `404` and not `403`: a `403` confirms the library exists.
    let (status, body) = get(&harness, fixtures.beta.id, fixtures.beta.owner, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another tenant must learn nothing: {body}");

    // A same-tenant caller with no grant is the other half, and it is the one a tenant-isolation
    // test cannot cover: row-level security holds the first, and only the authorization stage
    // holds this. `ENC-731` records the six previous times a deleted predicate left a suite green
    // because RLS was quietly carrying the property alone.
    let stranger = UserId::new_v7();
    let (status, body) = get(&harness, alpha.tenant, stranger, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an ungranted caller in-tenant must get 404: {body}");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_files_metadata_is_indistinguishable_from_a_file_that_does_not_exist() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let harness = harness(&db).await;

    let alpha = Spine::new(fixtures.alpha.id);
    let mut admin = db.connect().await.expect("admin");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha.tenant,
        "FILE",
        alpha.file.as_uuid(),
        fixtures.alpha.owner,
        Action::File(FileAction::MetadataRead),
    )
    .await;

    let path = format!("/api/v1/files/{}/metadata", alpha.file.as_uuid());

    let (status, _) = get(&harness, alpha.tenant, fixtures.alpha.owner, &path).await;
    assert_eq!(status, StatusCode::OK, "the grant holder must be able to read the file's metadata");

    let (status, body) = get(&harness, fixtures.beta.id, fixtures.beta.owner, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another tenant must learn nothing: {body}");

    let stranger = UserId::new_v7();
    let (status, body) = get(&harness, alpha.tenant, stranger, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an ungranted caller in-tenant must get 404: {body}");
}

// ---------------------------------------------------------------------------------------------
// The join — where a read path is quietly wrong
// ---------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_answers_with_what_it_inherits_and_never_with_another_librarys_fields() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let harness = harness(&db).await;

    let alpha = Spine::new(fixtures.alpha.id);
    let other = Spine::new(fixtures.alpha.id);
    let mut admin = db.connect().await.expect("admin");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    other.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha.tenant,
        "LIBRARY",
        alpha.library.as_uuid(),
        fixtures.alpha.owner,
        Action::Container(ContainerAction::Read),
    )
    .await;

    define_field(&mut admin, alpha.tenant, "TENANT", None, "classification").await;
    define_field(
        &mut admin,
        alpha.tenant,
        "WORKSPACE",
        Some(alpha.workspace.as_uuid()),
        "project_code",
    )
    .await;
    define_field(&mut admin, alpha.tenant, "LIBRARY", Some(alpha.library.as_uuid()), "matter_id")
        .await;
    // The one that must not appear: same tenant, different library.
    define_field(&mut admin, alpha.tenant, "LIBRARY", Some(other.library.as_uuid()), "not_mine")
        .await;

    let (status, body) = get(
        &harness,
        alpha.tenant,
        fixtures.alpha.owner,
        &format!("/api/v1/libraries/{}/fields", alpha.library.as_uuid()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let keys: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|f| f["key"].as_str().unwrap())
        .collect();

    // All three scopes, because a client drawing a column set needs the inherited ones too.
    for expected in ["classification", "project_code", "matter_id"] {
        assert!(
            keys.contains(&expected),
            "{expected} must be inherited into this library: {keys:?}"
        );
    }
    assert!(
        !keys.contains(&"not_mine"),
        "a field scoped to another library must not appear: {keys:?}"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_applicable_field_with_no_value_carries_no_value_key_at_all() {
    let db = TestDb::start().await.expect("start");
    let fixtures = db.seed().await.expect("seed");
    let harness = harness(&db).await;

    let alpha = Spine::new(fixtures.alpha.id);
    let mut admin = db.connect().await.expect("admin");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    grant(
        &mut admin,
        alpha.tenant,
        "FILE",
        alpha.file.as_uuid(),
        fixtures.alpha.owner,
        Action::File(FileAction::MetadataRead),
    )
    .await;

    let filled = define_field(
        &mut admin,
        alpha.tenant,
        "LIBRARY",
        Some(alpha.library.as_uuid()),
        "matter_id",
    )
    .await;
    define_field(&mut admin, alpha.tenant, "LIBRARY", Some(alpha.library.as_uuid()), "reviewer")
        .await;
    set_value(
        &mut admin,
        alpha.tenant,
        alpha.file.as_uuid(),
        filled,
        "M-4171",
        fixtures.alpha.owner,
    )
    .await;

    let (status, body) = get(
        &harness,
        alpha.tenant,
        fixtures.alpha.owner,
        &format!("/api/v1/files/{}/metadata", alpha.file.as_uuid()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let fields = body["fields"].as_array().expect("fields");
    let by_key = |key: &str| {
        fields.iter().find(|f| f["key"] == key).unwrap_or_else(|| panic!("{key} must be present"))
    };

    assert_eq!(by_key("matter_id")["value"], "M-4171", "a set value must come back on its field");

    // **Absent, not `null`.** `null` is a value a `JSON` field can legitimately hold, so a client
    // that could not tell "never set" from "set to null" would render a cleared field as an
    // untouched one. `serde(skip_serializing_if)` is what makes this true and this is what pins it.
    let unset = by_key("reviewer");
    assert!(
        unset.get("value").is_none(),
        "an unset field must omit `value` rather than send null: {unset}"
    );
    assert_eq!(unset["required"], false, "the definition still travels with it");
    assert_eq!(unset["label"], "Label for reviewer", "so a client can draw an empty field");
}
