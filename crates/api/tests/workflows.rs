//! `ENC-739` — the eight workflow endpoints, over HTTP, a real policy chain and a real database.
//!
//! `crates/workflows`' own unit tests cover the decisions that are pure: what a quorum counts, when
//! a stage advances, which refusal a snapshot forces. These are the ones that need the whole path —
//! the router, the chain with the **real** ACL resolver, `TenantScoped`, row-level security, and
//! the rows read back.
//!
//! # Which layer each isolation test proves, stated because it is easy to get wrong
//!
//! This repository has now found, in **six separate crates**, that deleting a statement's
//! `tenant_id` predicate fails *nothing* — because row-level security holds that property on its
//! own, and a cross-tenant HTTP test cannot tell the two layers apart. So the tests below are
//! labelled:
//!
//! * `beta_cannot_*` prove **row-level security plus the composite keys**. They are worth having —
//!   they prove the path is isolated end to end — and they prove nothing about authorization.
//! * `a_colleague_*` and `a_stranger_*` prove **authorization**, and they are the ones that matter
//!   for this surface. Every one of them uses a caller in the *same tenant*, so RLS is satisfied
//!   and cannot mask the result: the only thing that can refuse them is the ACL, or this crate's
//!   own step-holdership check.
//!
//! The predicate-level claim — that each statement carries its own `tenant_id` — is asserted by
//! `enclave_workflows::repo`'s unit tests, which read the SQL, because nothing behavioural can.
//!
//! # Every absence is paired with its positive control
//!
//! `docs/12-TESTING.md §1.2`: an assertion about an absence passes for free. *"Simulate wrote no
//! rows"* is true of a broken router, a failed authentication and an empty fixture. So
//! [`simulate_writes_nothing_and_a_real_start_writes_everything`] counts the rows **and** runs the
//! identical input through the real start in the same test, against the same fixture, and asserts
//! that one does change them.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, ActorKind, AuthorizationService, ClientType, ContainerAction, FileAction, FileId,
    RequestContext, ResourceKind, ResourceRef, Result as CoreResult, StageDecision, TenantId,
    UserId, VersionId,
};
use enclave_db::DbPool;
use enclave_testing::content::{grant, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::{Fixtures, TestDb};
use enclave_workflows::WorkflowDefinitionId;
use sqlx::{PgConnection, Row as _};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";
const TASKS: &str = "/api/v1/workflows/tasks";

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a fixed instant")
}

// --- The authorization service these endpoints need ---------------------------------------------

/// `PgAclAuthorization` for content, `SelfServiceAuthorization`'s rule for a self-read.
///
/// Neither alone can serve this surface, and the composition is not a convenience:
///
/// * `GET /workflows/tasks` enforces `container.read` on the caller's own `users` row — the resource
///   a personal inbox *is*, and `crates/api/src/me.rs`'s shape. `PgAclAuthorization::classify`
///   correctly calls a `User` reference `Unsupported`, because a user record is not in the file
///   inheritance tree.
/// * every other endpoint asks a file question, which `SelfServiceAuthorization` correctly denies.
///
/// `crates/api/src/main.rs` composes `AdminAuthorization(PgAdminRoles, SelfServiceAuthorization)`
/// and no ACL resolver at all, so in the deployed binary the inbox answers `200` with an empty list
/// — the self-read is allowed and every per-item trim is denied. That is the fail-closed direction
/// and it is `ENC-746`, logged rather than papered over here; the composed service belongs in
/// `crates/authorization`, not in a test file, and not in this task's scope.
#[derive(Debug)]
struct InboxOrAcl {
    acl: PgAclAuthorization,
}

impl InboxOrAcl {
    /// Whether this is the principal reading its own user record — `SelfServiceAuthorization`'s
    /// exact rule, copied rather than delegated so this file states the whole of what it allows.
    fn is_self_read(ctx: &RequestContext, action: Action, resource: &ResourceRef) -> bool {
        matches!(action, Action::Container(ContainerAction::Read))
            && resource.kind == ResourceKind::User
            && ctx.actor.subject_id().is_some_and(|id| id == resource.id)
    }
}

#[async_trait::async_trait]
impl AuthorizationService for InboxOrAcl {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        if Self::is_self_read(ctx, action, resource) {
            return Ok(StageDecision::allow());
        }
        self.acl.authorize(ctx, action, resource).await
    }

    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        if resources.iter().all(|r| Self::is_self_read(ctx, action, r)) {
            return Ok(resources.iter().map(|_| StageDecision::allow()).collect());
        }
        self.acl.authorize_many(ctx, action, resources).await
    }
}

// --- Harness ------------------------------------------------------------------------------------

struct Client {
    app: axum::Router,
}

impl Client {
    async fn send(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.expect("body");
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).expect("a JSON body")
        };
        (status, json)
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::GET, uri, token, None)).await
    }

    async fn post(
        &self,
        uri: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.send(signed(Method::POST, uri, token, Some(body))).await
    }
}

fn signed(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    match body {
        Some(body) => builder.body(Body::from(body.to_string())).expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    }
}

/// The chain a deployment runs, with the real ACL resolver behind the inbox rule.
fn engine(pool: &DbPool) -> enclave_core::PolicyEngine {
    enclave_core::PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        Arc::new(InboxOrAcl { acl: PgAclAuthorization::new(pool.clone()) }),
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        // `DisabledDlp`, not `TenantDlp`: these endpoints are about *who may decide a step*, and a
        // DLP stage reading an empty rule set would add a second reason for every refusal that a
        // failing assertion could not tell apart from the one under test.
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(pool.clone(), enclave_audit::ChainMode::Enabled)),
    )
}

fn app(pool: &DbPool, key: &PrivateSigningKey) -> Client {
    let state = ApiState::new(
        engine(pool),
        pool.clone(),
        ISSUER,
        AUDIENCE,
        KeySet::new([key.public().clone()]),
    );
    Client { app: router(state, enclave_api::Delivery::unconfigured()) }
}

fn token(key: &PrivateSigningKey, tenant: TenantId, subject: UserId) -> String {
    let now = Utc::now();
    AccessTokenIssuer::new(ISSUER, AUDIENCE)
        .issue(
            key,
            TokenTemplate {
                sub: subject.as_uuid(),
                tid: tenant.as_uuid(),
                sid: Uuid::new_v4(),
                typ: ActorKind::User,
                scp: Vec::new(),
                amr: vec![AuthMethod::Pwd, AuthMethod::Totp],
                auth_time: now,
                acr: Acr::MultiFactor,
                dev: None,
                cli: ClientType::Web,
                epoch: 1,
                max_cls: None,
            },
            now,
            chrono::Duration::minutes(10),
        )
        .expect("issue")
        .token
}

// --- Fixture writing ----------------------------------------------------------------------------

/// Everything one tenant needs: the content spine, a current version, and a definition.
struct World {
    spine: Spine,
    version: VersionId,
    definition: WorkflowDefinitionId,
}

/// Commits a version and points the file at it.
///
/// `major` is taken from a count of what is already there rather than hard-coded, because
/// `uq_version_number` is `(tenant_id, file_id, major, minor)` — a fixed `1.0` makes the second
/// call for one file a constraint violation, which is how the W3 test first failed. Deriving it
/// means "publish a new version" is one call whatever has gone before.
async fn insert_version(
    conn: &mut PgConnection,
    spine: &Spine,
    file: FileId,
    owner: UserId,
) -> VersionId {
    let id = VersionId::new_v7();
    let major: i64 =
        sqlx::query_scalar("SELECT count(*) + 1 FROM file_versions WHERE file_id = $1")
            .bind(file.as_uuid())
            .fetch_one(&mut *conn)
            .await
            .expect("next version number");

    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, av_status, encryption_mode, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 1024, $6, 'application/pdf', $7, 0, 'AVAILABLE', 'CLEAN',
                 'PROVIDER', $8, $9)",
    )
    .bind(id.as_uuid())
    .bind(spine.tenant.as_uuid())
    .bind(file.as_uuid())
    .bind(format!("tenants/{}/blobs/{}", spine.tenant.as_uuid(), id.as_uuid()))
    .bind(Uuid::new_v4())
    .bind("0".repeat(64))
    .bind(i32::try_from(major).unwrap_or(i32::MAX))
    .bind(owner.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert version");

    sqlx::query("UPDATE files SET current_version_id = $2 WHERE id = $1")
        .bind(file.as_uuid())
        .bind(id.as_uuid())
        .execute(&mut *conn)
        .await
        .expect("point at current version");
    id
}

/// Writes a definition. `stages` is the document `enclave_workflows::definition` decodes.
#[allow(clippy::too_many_arguments)]
async fn insert_definition(
    conn: &mut PgConnection,
    tenant: TenantId,
    author: UserId,
    stages: serde_json::Value,
    allow_self_approval: bool,
    delegation: &str,
    on_new_version: &str,
    scope: (&str, Option<Uuid>),
) -> WorkflowDefinitionId {
    let id = WorkflowDefinitionId::new_v7();
    sqlx::query(
        "INSERT INTO workflow_definitions
           (tenant_id, id, scope_type, scope_id, name, version, definition, enabled,
            allow_self_approval, delegation, on_new_version, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 1, $6, TRUE, $7, $8, $9, $10, $11, $11)",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .bind(scope.0)
    .bind(scope.1)
    .bind(format!("definition-{id}"))
    .bind(serde_json::json!({ "stages": stages }))
    .bind(allow_self_approval)
    .bind(delegation)
    .bind(on_new_version)
    .bind(author.as_uuid())
    .bind(fixed_time())
    .execute(&mut *conn)
    .await
    .expect("insert definition");
    id
}

/// The default fixture: one stage, one `APPROVAL` step, one assignee.
fn one_approver(assignee: UserId) -> serde_json::Value {
    serde_json::json!([{
        "name": "review",
        "steps": [{ "type": "APPROVAL", "assignees": [assignee.as_uuid()] }],
    }])
}

/// Grants a user everything the workflow endpoints ask the chain about.
///
/// All four, because the endpoints deliberately do not collapse them: `content_read` for a
/// decision, `edit` for a start or a cancel, `metadata_read` for a read and for the inbox trim.
/// A helper that granted one and hoped would make every test below prove the wrong thing.
async fn grant_workflow_access(conn: &mut PgConnection, spine: &Spine, user: UserId) {
    for action in [
        Action::File(FileAction::MetadataRead),
        Action::File(FileAction::ContentRead),
        Action::File(FileAction::Edit),
    ] {
        grant(
            conn,
            spine.tenant,
            AclScope::File(spine.file),
            AclPrincipal::User(user),
            action,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("grant");
    }
}

/// Builds a tenant's world and returns it.
async fn world(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: UserId,
    assignee: UserId,
) -> World {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, fixed_time()).await.expect("spine");
    let version = insert_version(conn, &spine, spine.file, owner).await;
    let definition = insert_definition(
        conn,
        tenant,
        owner,
        one_approver(assignee),
        false,
        "ONCE",
        "INVALIDATE",
        ("TENANT", None),
    )
    .await;
    World { spine, version, definition }
}

/// Which table a row count is over.
///
/// An enum rather than a `&str`, because sqlx 0.9 refuses a dynamically built statement outright
/// (`SqlSafeStr`) — and the refusal is right: the alternative is `AssertSqlSafe`, and a test file
/// that reaches for that once is a file the next person reaches for it in again.
#[derive(Debug, Clone, Copy)]
enum Table {
    Instances,
    Steps,
    Audit,
}

async fn count(conn: &mut PgConnection, table: Table) -> i64 {
    let sql = match table {
        Table::Instances => "SELECT count(*) FROM workflow_instances",
        Table::Steps => "SELECT count(*) FROM workflow_steps",
        Table::Audit => "SELECT count(*) FROM audit_events",
    };
    sqlx::query_scalar(sql).fetch_one(&mut *conn).await.expect("count")
}

async fn step_state(conn: &mut PgConnection, step: &str) -> String {
    sqlx::query_scalar("SELECT state FROM workflow_steps WHERE id = $1::uuid")
        .bind(step)
        .fetch_one(&mut *conn)
        .await
        .expect("step state")
}

async fn instance_state(conn: &mut PgConnection, instance: &str) -> String {
    sqlx::query_scalar("SELECT state FROM workflow_instances WHERE id = $1::uuid")
        .bind(instance)
        .fetch_one(&mut *conn)
        .await
        .expect("instance state")
}

/// The first step of an instance, from the instance view.
fn first_step(view: &serde_json::Value) -> String {
    view["steps"][0]["id"].as_str().expect("a step id").to_owned()
}

async fn harness() -> (TestDb, Fixtures, DbPool, PrivateSigningKey) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(8).await.expect("application pool");
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");
    (db, fixtures, pool, key)
}

// --- D28: simulate must not mutate, and the positive control that makes that mean something ------

/// `ENC-741`. The whole point of the crate's shape, asserted end to end.
///
/// # Why the positive control is in the same test
///
/// `docs/12-TESTING.md §1.2`: an assertion about an absence passes for free. *"Simulate wrote no
/// rows"* would be equally true if the route were unregistered, the token were rejected, the
/// fixture were empty, or the whole request had `404`-ed. So the same input, over the same fixture,
/// in the same run, is put through the **real** start — and the counts are asserted to move. The
/// absence is only evidence because the presence is demonstrated beside it.
///
/// The simulation is also asserted to have *described* the right thing. A `simulate` that answered
/// `{}` would satisfy "wrote nothing" perfectly.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn simulate_writes_nothing_and_a_real_start_writes_everything() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);

    let before_instances = count(&mut conn, Table::Instances).await;
    let before_steps = count(&mut conn, Table::Steps).await;

    let (status, body) = client
        .post(
            &format!("/api/v1/workflows/definitions/{}/simulate", world.definition),
            &owner,
            serde_json::json!({ "fileId": world.spine.file.to_string() }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // It described the run it would have made.
    assert_eq!(body["simulated"], serde_json::json!(true));
    assert_eq!(body["versionId"], serde_json::json!(world.version.to_string()));
    assert_eq!(body["steps"].as_array().expect("steps").len(), 1);
    assert_eq!(body["steps"][0]["assigneeId"], serde_json::json!(alpha.member.to_string()));
    assert_eq!(body["steps"][0]["state"], serde_json::json!("ASSIGNED"));

    // And it changed nothing.
    assert_eq!(
        count(&mut conn, Table::Instances).await,
        before_instances,
        "simulate wrote an instance row"
    );
    assert_eq!(count(&mut conn, Table::Steps).await, before_steps, "simulate wrote step rows");

    // The positive control: the identical input, really executed.
    let (status, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    assert_eq!(
        count(&mut conn, Table::Instances).await,
        before_instances + 1,
        "the real start wrote no instance, so the absence above proves nothing"
    );
    assert_eq!(
        count(&mut conn, Table::Steps).await,
        before_steps + 1,
        "the real start wrote no steps, so the absence above proves nothing"
    );
}

/// A caller who may not start a workflow may not rehearse one either.
///
/// D28 from the other side: if `simulate` enforced a cheaper action, this would answer `200` where
/// the real start answers `404`, and a rehearsal would tell somebody a workflow would run that will
/// not. Both halves are asserted, because asserting only the refusal would pass against a route
/// that refuses everybody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_colleague_who_cannot_start_a_workflow_cannot_simulate_one_either() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;
    // The viewer is in the same tenant and holds *metadata_read only*. Row-level security is
    // satisfied for them, so nothing but the ACL can produce this refusal — which is what makes it
    // an authorization test rather than an isolation one.
    grant(
        &mut conn,
        alpha.id,
        AclScope::File(world.spine.file),
        AclPrincipal::User(alpha.viewer),
        Action::File(FileAction::MetadataRead),
        AclEffect::Allow,
        None,
    )
    .await
    .expect("grant");

    let client = app(&pool, &key);
    let viewer = token(&key, alpha.id, alpha.viewer);
    let owner = token(&key, alpha.id, alpha.owner);
    let simulate = format!("/api/v1/workflows/definitions/{}/simulate", world.definition);
    let body = serde_json::json!({ "fileId": world.spine.file.to_string() });

    let (refused, _) = client.post(&simulate, &viewer, body.clone()).await;
    let (started, _) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &viewer,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    assert_eq!(
        refused, started,
        "simulate and start answered a caller who holds only metadata_read differently, so a \
         rehearsal measures something other than what enforcement will do (D28)"
    );
    assert_eq!(refused, StatusCode::NOT_FOUND);

    // The control: the same request from somebody who does hold `file.edit` succeeds.
    let (allowed, _) = client.post(&simulate, &owner, body).await;
    assert_eq!(allowed, StatusCode::OK, "the refusal above is not merely a route that refuses all");
}

// --- Step authority ------------------------------------------------------------------------------

/// **The authorization test for this surface**, and the one that RLS cannot mask.
///
/// The colleague is in the same tenant *and* holds every ACL grant the endpoint asks the chain
/// about — `content_read` included — so the chain allows them. They are refused solely because the
/// step is not theirs. That is the property `crates/workflows/src/authority.rs` exists for:
/// holding the file confers no part of the right to approve a step about it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_colleague_who_can_read_the_file_still_cannot_approve_somebody_elses_step() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.member).await;
    // The auditor holds everything the chain is asked about. Nothing in the ACL refuses them.
    grant_workflow_access(&mut conn, &world.spine, alpha.auditor).await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);
    let auditor = token(&key, alpha.id, alpha.auditor);

    let (status, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let instance = body["id"].as_str().expect("instance id").to_owned();

    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let step = first_step(&view);
    let approve = format!("/api/v1/workflows/steps/{step}/approve");

    let (refused, _) = client.post(&approve, &auditor, serde_json::json!({})).await;
    assert_eq!(
        refused,
        StatusCode::FORBIDDEN,
        "a colleague with full ACL access approved a step that was never assigned to them"
    );
    assert_eq!(step_state(&mut conn, &step).await, "ASSIGNED", "the refused approval still wrote");

    // The control: the assignee, over the same fixture, in the same run.
    let (allowed, body) = client.post(&approve, &member, serde_json::json!({})).await;
    assert_eq!(allowed, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(step_state(&mut conn, &step).await, "APPROVED");
    assert_eq!(instance_state(&mut conn, &instance).await, "COMPLETED");
}

/// `docs/15 §4`: self-approval is rejected unless the definition permits it. `docs/15 §12` W2.
///
/// Both legs, over two definitions that differ in exactly one column, so the assertion is about the
/// column rather than about the fixture.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn self_approval_is_refused_by_default_and_permitted_only_when_the_definition_says_so() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let spine = Spine::new(alpha.id);
    spine.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
    insert_version(&mut conn, &spine, spine.file, alpha.owner).await;
    grant_workflow_access(&mut conn, &spine, alpha.owner).await;

    let strict = insert_definition(
        &mut conn,
        alpha.id,
        alpha.owner,
        one_approver(alpha.owner),
        false,
        "ONCE",
        "INVALIDATE",
        ("TENANT", None),
    )
    .await;
    let permissive = insert_definition(
        &mut conn,
        alpha.id,
        alpha.owner,
        one_approver(alpha.owner),
        true,
        "ONCE",
        "INVALIDATE",
        ("TENANT", None),
    )
    .await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);

    for (definition, expected) in
        [(strict, StatusCode::FORBIDDEN), (permissive, StatusCode::NO_CONTENT)]
    {
        let (status, body) = client
            .post(
                &format!("/api/v1/files/{}/workflows", spine.file),
                &owner,
                serde_json::json!({ "definitionId": definition.to_string() }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let instance = body["id"].as_str().expect("instance id").to_owned();
        let (_, view) =
            client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
        let step = first_step(&view);

        let (status, body) = client
            .post(&format!("/api/v1/workflows/steps/{step}/approve"), &owner, serde_json::json!({}))
            .await;
        assert_eq!(
            status,
            expected,
            "self-approval under allow_self_approval={} answered {status}: {body}",
            expected == StatusCode::NO_CONTENT
        );
    }
}

/// `docs/05-API.md §16`: the comment on a rejection is required.
///
/// A rejection terminates the instance for everybody; *"rejected, no reason given"* is the state a
/// workflow exists to avoid.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rejection_without_a_comment_is_refused_and_one_with_a_comment_ends_the_workflow() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.member).await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let step = first_step(&view);
    let reject = format!("/api/v1/workflows/steps/{step}/reject");

    let (status, body) = client.post(&reject, &member, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], serde_json::json!("comment"));
    assert_eq!(step_state(&mut conn, &step).await, "ASSIGNED");

    let (status, body) = client
        .post(&reject, &member, serde_json::json!({ "comment": "the indemnity clause is wrong" }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(instance_state(&mut conn, &instance).await, "REJECTED");
}

// --- Delegation ----------------------------------------------------------------------------------

/// `ENC-740` end to end: a step may be handed on once, and never onward.
///
/// The onward attempt is made by the **delegate**, who genuinely holds the step at that moment —
/// so the refusal is the bound firing and not a holdership check. The first delegation succeeding
/// in the same test is what makes the second refusal mean something.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_step_is_delegated_once_and_the_delegate_cannot_pass_it_on() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    for user in [alpha.owner, alpha.member, alpha.viewer, alpha.auditor] {
        grant_workflow_access(&mut conn, &world.spine, user).await;
    }

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);
    let viewer = token(&key, alpha.id, alpha.viewer);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let step = first_step(&view);
    let delegate = format!("/api/v1/workflows/steps/{step}/delegate");

    // The assignee hands it to the viewer.
    let (status, body) = client
        .post(
            &delegate,
            &member,
            serde_json::json!({ "toUserId": alpha.viewer.to_string(), "reason": "on leave" }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // The viewer tries to hand it to the auditor. They *are* the holder, so this is the bound.
    let (status, body) = client
        .post(
            &delegate,
            &viewer,
            serde_json::json!({ "toUserId": alpha.auditor.to_string(), "reason": "also away" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the delegate handed the step onward, so authority now sits with somebody the original \
         assignee never examined ({body})"
    );

    // And the original assignee cannot reclaim it by delegating again either.
    let (status, _) = client
        .post(
            &delegate,
            &member,
            serde_json::json!({ "toUserId": alpha.auditor.to_string(), "reason": "changed mind" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The delegate is the one who can decide it, and the assignee is not.
    let approve = format!("/api/v1/workflows/steps/{step}/approve");
    let (status, _) = client.post(&approve, &member, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the assignee decided a step they had given away");

    let (status, body) = client.post(&approve, &viewer, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // `docs/15 §4`: never a silent substitution. Both names are on the row.
    let row = sqlx::query(
        "SELECT assignee_id, delegated_to, decided_by, delegation_reason
           FROM workflow_steps WHERE id = $1::uuid",
    )
    .bind(&step)
    .fetch_one(&mut conn)
    .await
    .expect("the decided step");
    assert_eq!(row.get::<Uuid, _>("assignee_id"), alpha.member.as_uuid());
    assert_eq!(row.get::<Option<Uuid>, _>("delegated_to"), Some(alpha.viewer.as_uuid()));
    assert_eq!(
        row.get::<Option<Uuid>, _>("decided_by"),
        Some(alpha.viewer.as_uuid()),
        "the row cannot say whether the assignee or the delegate decided"
    );
    assert_eq!(row.get::<Option<String>, _>("delegation_reason").as_deref(), Some("on leave"));
}

/// `docs/15 §2`, fourth core property: a workflow cannot grant access it does not already hold.
///
/// The proposed delegate is in the *same tenant* and has no grant on the file, so RLS is satisfied
/// and the ACL is the only thing that can refuse — an authorization test, not an isolation one.
/// Paired with the same delegation succeeding once the grant exists.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_step_cannot_be_delegated_to_somebody_who_cannot_read_the_file() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.member).await;
    // `alpha.viewer` is deliberately granted nothing.

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let step = first_step(&view);
    let delegate = format!("/api/v1/workflows/steps/{step}/delegate");
    let request =
        serde_json::json!({ "toUserId": alpha.viewer.to_string(), "reason": "please cover" });

    let (status, body) = client.post(&delegate, &member, request.clone()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], serde_json::json!("DELEGATE_NOT_ELIGIBLE"));

    // The control: grant the viewer the right the step requires, and the same request succeeds.
    grant_workflow_access(&mut conn, &world.spine, alpha.viewer).await;
    let (status, body) = client.post(&delegate, &member, request).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the refusal above is not merely a delegate endpoint that refuses everybody ({body})"
    );
}

// --- Cancellation ---------------------------------------------------------------------------------

/// `docs/15 §4`: the initiator or an owner, a reason, and audited.
///
/// **And the property the whole cancel path is arranged around**: a decision already made survives
/// the cancellation. Cancelling ends what is happening; it does not rewrite what happened.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn cancelling_needs_a_reason_and_an_owner_and_keeps_the_approvals_already_made() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let spine = Spine::new(alpha.id);
    spine.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
    insert_version(&mut conn, &spine, spine.file, alpha.owner).await;
    for user in [alpha.owner, alpha.member, alpha.viewer] {
        grant_workflow_access(&mut conn, &spine, user).await;
    }
    // Two approvers, quorum ALL: one approves, then the workflow is cancelled with the other still
    // outstanding — which is the only shape in which "what happens to approved steps" is visible.
    let definition = insert_definition(
        &mut conn,
        alpha.id,
        alpha.owner,
        serde_json::json!([{
            "name": "review",
            "steps": [{
                "type": "APPROVAL",
                "assignees": [alpha.member.as_uuid(), alpha.viewer.as_uuid()],
                "quorum": "all",
            }],
        }]),
        false,
        "ONCE",
        "INVALIDATE",
        ("TENANT", None),
    )
    .await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", spine.file),
            &owner,
            serde_json::json!({ "definitionId": definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let steps: Vec<String> = view["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|s| s["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(steps.len(), 2);

    // The member approves theirs.
    let approved = steps
        .iter()
        .find(|id| {
            view["steps"]
                .as_array()
                .expect("steps")
                .iter()
                .any(|s| s["id"] == **id && s["assigneeId"] == alpha.member.to_string())
        })
        .expect("the member's step")
        .clone();
    let (status, body) = client
        .post(
            &format!("/api/v1/workflows/steps/{approved}/approve"),
            &member,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(instance_state(&mut conn, &instance).await, "RUNNING", "ALL quorum, one of two");

    let cancel = format!("/api/v1/workflows/instances/{instance}/cancel");

    // No reason.
    let (status, body) = client.post(&cancel, &owner, serde_json::json!({ "reason": "  " })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["details"][0]["field"], serde_json::json!("reason"));

    // The member is neither the initiator nor an owner of the file — they hold read and edit, not
    // `manage_permissions`. Same tenant, so this is an authorization refusal.
    let (status, body) =
        client.post(&cancel, &member, serde_json::json!({ "reason": "no longer needed" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(instance_state(&mut conn, &instance).await, "RUNNING");

    // The initiator can.
    let (status, body) = client
        .post(&cancel, &owner, serde_json::json!({ "reason": "the counterparty withdrew" }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(instance_state(&mut conn, &instance).await, "CANCELLED");

    // The property.
    assert_eq!(
        step_state(&mut conn, &approved).await,
        "APPROVED",
        "cancelling erased the record that a named person approved something"
    );
    let outstanding = steps.iter().find(|id| **id != approved).expect("the other step");
    assert_eq!(step_state(&mut conn, outstanding).await, "SKIPPED");

    let row: (Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT decided_by, outcome_reason FROM workflow_steps s
           JOIN workflow_instances i ON i.id = s.instance_id
          WHERE s.id = $1::uuid",
    )
    .bind(&approved)
    .fetch_one(&mut conn)
    .await
    .expect("the decided step and its instance");
    assert_eq!(row.0, Some(alpha.member.as_uuid()), "the decider was erased");
    assert_eq!(row.1.as_deref(), Some("the counterparty withdrew"));
}

// --- The task inbox ---------------------------------------------------------------------------

/// `ENC-742`. The inbox returns what the caller must act on, and nothing that would reveal a file
/// they cannot see.
///
/// Three claims in one run, because each is meaningless without the others:
///
/// 1. the assignee sees their step (**the positive control** — an empty inbox satisfies claims 2
///    and 3 perfectly);
/// 2. a colleague who is not the assignee does not see it, even holding every grant on the file;
/// 3. the assignee *stops* seeing it once their access to the file is revoked — the trim — and gets
///    an empty list rather than a `403`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_task_inbox_shows_only_the_holders_own_steps_and_drops_files_they_cannot_see() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    for user in [alpha.owner, alpha.member, alpha.auditor] {
        grant_workflow_access(&mut conn, &world.spine, user).await;
    }

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);
    let auditor = token(&key, alpha.id, alpha.auditor);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    assert!(body["id"].is_string(), "{body}");

    // 1. The assignee.
    let (status, body) = client.get(TASKS, &member).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().expect("items").len(), 1);
    assert_eq!(body["items"][0]["fileId"], serde_json::json!(world.spine.file.to_string()));
    assert_eq!(body["items"][0]["delegated"], serde_json::json!(false));

    // 2. A colleague with every grant on the file, who was never asked.
    let (status, body) = client.get(TASKS, &auditor).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["items"].as_array().expect("items").is_empty(),
        "a colleague sees a step nobody assigned them: {body}"
    );

    // 3. The trim. Revoke the assignee's *metadata_read* only — they keep the step, and the step's
    //    file becomes something they may not know about.
    sqlx::query(
        "DELETE FROM acl_entries
          WHERE tenant_id = $1 AND resource_id = $2 AND principal_id = $3",
    )
    .bind(alpha.id.as_uuid())
    .bind(world.spine.file.as_uuid())
    .bind(alpha.member.as_uuid())
    .execute(&mut conn)
    .await
    .expect("revoke");

    let (status, body) = client.get(TASKS, &member).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the trim answered with a status instead of an absence, which confirms the step exists \
         (CLAUDE.md rule 7): {body}"
    );
    assert!(
        body["items"].as_array().expect("items").is_empty(),
        "a step over a file the caller may no longer read was rendered with its file id: {body}"
    );
}

// --- Isolation (row-level security, not authorization) -------------------------------------------

/// Cross-tenant, and it proves **the path is isolated**, not that any predicate is right.
///
/// Stated plainly because six sessions in this repository have mistaken one for the other: deleting
/// a `tenant_id` predicate from `enclave_workflows::repo` leaves this test green, because RLS holds
/// the property alone. The predicates are asserted by that module's own unit tests, and the
/// *authorization* claims by the same-tenant tests above.
///
/// Paired with alpha succeeding on the identical request, so it is not a test of a route that
/// refuses everybody.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn beta_cannot_see_or_act_on_alphas_workflow() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let (alpha, beta) = (&fixtures.alpha, &fixtures.beta);

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.member).await;

    let client = app(&pool, &key);
    let alpha_owner = token(&key, alpha.id, alpha.owner);
    let alpha_member = token(&key, alpha.id, alpha.member);
    // A legitimate owner *of beta*, refused only because the workflow is not theirs.
    let beta_owner = token(&key, beta.id, beta.owner);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &alpha_owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) =
        client.get(&format!("/api/v1/workflows/instances/{instance}"), &alpha_owner).await;
    let step = first_step(&view);

    let read = format!("/api/v1/workflows/instances/{instance}");
    let approve = format!("/api/v1/workflows/steps/{step}/approve");
    let cancel = format!("/api/v1/workflows/instances/{instance}/cancel");

    let (status, _) = client.get(&read, &beta_owner).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a 403 would confirm the instance exists (rule 7)");
    let (status, _) = client.post(&approve, &beta_owner, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = client.post(&cancel, &beta_owner, serde_json::json!({ "reason": "x" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = client.get(TASKS, &beta_owner).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().expect("items").is_empty(), "{body}");

    // The controls: alpha can do all three.
    let (status, _) = client.get(&read, &alpha_owner).await;
    assert_eq!(status, StatusCode::OK, "the 404s above are not a route that refuses everybody");
    let (status, _) = client.post(&approve, &alpha_member, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// --- Idempotent triggering (docs/15 §12 W4) -------------------------------------------------------

/// `docs/15 §5`: a redelivered event cannot start a duplicate instance.
///
/// Held by `uq_workflow_instances_trigger` rather than by a read-then-write, so two concurrent
/// deliveries cannot both find "no instance" and both insert. Asserted through the constraint's
/// visible effect: the second request is a `409` and the row count does not move.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn starting_the_same_workflow_twice_on_one_version_creates_exactly_one_instance() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    grant_workflow_access(&mut conn, &world.spine, alpha.owner).await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let uri = format!("/api/v1/files/{}/workflows", world.spine.file);
    let body = serde_json::json!({ "definitionId": world.definition.to_string() });

    let (first, _) = client.post(&uri, &owner, body.clone()).await;
    assert_eq!(first, StatusCode::CREATED);
    let after_first = count(&mut conn, Table::Instances).await;

    let (second, response) = client.post(&uri, &owner, body).await;
    assert_eq!(second, StatusCode::CONFLICT, "{response}");
    assert_eq!(response["error"]["code"], serde_json::json!("WORKFLOW_ALREADY_RUNNING"));
    assert_eq!(
        count(&mut conn, Table::Instances).await,
        after_first,
        "a second instance was created for one (definition, file, version)"
    );
}

// --- W3: a superseded version ----------------------------------------------------------------------

/// `docs/15 §2.1` and `§12` W3: a new version invalidates in-flight approvals by default.
///
/// Held at the gate — the moment somebody tries to approve superseded content — rather than by a
/// sweep, which is where the property actually bites. `ENC-743` carries the proactive half.
///
/// Paired with `on_new_version = CONTINUE`, the documented opt-out, over the identical fixture, so
/// the assertion is about the pinned policy rather than about the version bump.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_superseded_version_expires_the_workflow_unless_the_definition_pinned_continue() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);

    for (policy, expected_status, expected_state) in [
        ("INVALIDATE", StatusCode::CONFLICT, "EXPIRED"),
        ("CONTINUE", StatusCode::NO_CONTENT, "COMPLETED"),
    ] {
        let spine = Spine::new(alpha.id);
        spine.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
        insert_version(&mut conn, &spine, spine.file, alpha.owner).await;
        grant_workflow_access(&mut conn, &spine, alpha.owner).await;
        grant_workflow_access(&mut conn, &spine, alpha.member).await;
        let definition = insert_definition(
            &mut conn,
            alpha.id,
            alpha.owner,
            one_approver(alpha.member),
            false,
            "ONCE",
            policy,
            ("TENANT", None),
        )
        .await;

        let (_, body) = client
            .post(
                &format!("/api/v1/files/{}/workflows", spine.file),
                &owner,
                serde_json::json!({ "definitionId": definition.to_string() }),
            )
            .await;
        let instance = body["id"].as_str().expect("instance id").to_owned();
        let (_, view) =
            client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
        let step = first_step(&view);

        // A new version lands under the running workflow.
        insert_version(&mut conn, &spine, spine.file, alpha.owner).await;

        let (status, body) = client
            .post(
                &format!("/api/v1/workflows/steps/{step}/approve"),
                &member,
                serde_json::json!({}),
            )
            .await;
        assert_eq!(status, expected_status, "on_new_version = {policy}: {body}");
        if expected_status == StatusCode::CONFLICT {
            assert_eq!(body["error"]["code"], serde_json::json!("VERSION_SUPERSEDED"));
        }
        assert_eq!(
            instance_state(&mut conn, &instance).await,
            expected_state,
            "on_new_version = {policy} left the instance in the wrong state"
        );
    }
}

// --- Scope, and the step types that take no decision ------------------------------------------------

/// `migrations/0024` keeps `scope_type`/`scope_id` because the evaluator reads them.
///
/// A `LIBRARY`-scoped definition run against a file in another library is refused, and the same
/// definition against a file in *its* library succeeds — so the assertion is about the scope rather
/// than about a definition that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_library_scoped_definition_cannot_be_started_on_another_librarys_file() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let inside = Spine::new(alpha.id);
    inside.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
    insert_version(&mut conn, &inside, inside.file, alpha.owner).await;
    grant_workflow_access(&mut conn, &inside, alpha.owner).await;

    let outside = Spine::new(alpha.id);
    outside.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
    insert_version(&mut conn, &outside, outside.file, alpha.owner).await;
    grant_workflow_access(&mut conn, &outside, alpha.owner).await;

    let definition = insert_definition(
        &mut conn,
        alpha.id,
        alpha.owner,
        one_approver(alpha.member),
        false,
        "ONCE",
        "INVALIDATE",
        ("LIBRARY", Some(inside.library.as_uuid())),
    )
    .await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let body = serde_json::json!({ "definitionId": definition.to_string() });

    let (status, response) = client
        .post(&format!("/api/v1/files/{}/workflows", outside.file), &owner, body.clone())
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
    assert_eq!(response["error"]["code"], serde_json::json!("DEFINITION_OUT_OF_SCOPE"));

    let (status, response) =
        client.post(&format!("/api/v1/files/{}/workflows", inside.file), &owner, body).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
}

/// A `SIGNATURE` step is not decided by clicking approve, and a `REVIEW` step has no gate to
/// reject (`docs/15 §3`, §6, §11).
///
/// Paired with the acknowledgement of the same `REVIEW` step succeeding, so the refusal is about
/// the *decision* and not about the step.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_signature_is_not_obtained_by_approving_and_a_review_cannot_be_rejected() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let spine = Spine::new(alpha.id);
    spine.insert(&mut conn, alpha.owner, fixed_time()).await.expect("spine");
    insert_version(&mut conn, &spine, spine.file, alpha.owner).await;
    grant_workflow_access(&mut conn, &spine, alpha.owner).await;
    grant_workflow_access(&mut conn, &spine, alpha.member).await;

    let definition = insert_definition(
        &mut conn,
        alpha.id,
        alpha.owner,
        serde_json::json!([{
            "name": "review and sign",
            "steps": [
                { "type": "REVIEW", "assignees": [alpha.member.as_uuid()] },
                { "type": "SIGNATURE", "assignees": [alpha.member.as_uuid()] },
            ],
        }]),
        false,
        "ONCE",
        "INVALIDATE",
        ("TENANT", None),
    )
    .await;

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", spine.file),
            &owner,
            serde_json::json!({ "definitionId": definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let steps = view["steps"].as_array().expect("steps");
    let review = steps
        .iter()
        .find(|s| s["stepType"] == "REVIEW")
        .and_then(|s| s["id"].as_str())
        .expect("the review step")
        .to_owned();
    let signature = steps
        .iter()
        .find(|s| s["stepType"] == "SIGNATURE")
        .and_then(|s| s["id"].as_str())
        .expect("the signature step")
        .to_owned();

    let (status, body) = client
        .post(
            &format!("/api/v1/workflows/steps/{review}/reject"),
            &member,
            serde_json::json!({ "comment": "no" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], serde_json::json!("WRONG_STEP_TYPE"));

    let (status, body) = client
        .post(
            &format!("/api/v1/workflows/steps/{signature}/approve"),
            &member,
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a click on /approve marked a SIGNATURE step decided, so the workflow reports it obtained \
         a signature it never obtained: {body}"
    );

    // The control: the review step *can* be acknowledged.
    let (status, body) = client
        .post(&format!("/api/v1/workflows/steps/{review}/approve"), &member, serde_json::json!({}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(step_state(&mut conn, &review).await, "APPROVED");
    assert_eq!(instance_state(&mut conn, &instance).await, "RUNNING", "the signature is pending");
}

// --- Audit (CLAUDE.md rule 10) -------------------------------------------------------------------

/// Every refusal this layer takes is a row before it is a response (`ENC-606`).
///
/// The assertion that could be false is not *"a DENY row exists"* — that would pass against a
/// system that wrote one for every request. It is that the refusal's row carries the **handler's**
/// control marker, `handler:actor`, and that the *allowed* request beside it does not: the chain
/// allowed both, and only one produced a second row.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_step_refused_at_the_handler_is_recorded_before_the_caller_is_told() {
    let (db, fixtures, pool, key) = harness().await;
    let mut conn = db.connect().await.expect("admin connection");
    let alpha = &fixtures.alpha;

    let world = world(&mut conn, alpha.id, alpha.owner, alpha.member).await;
    for user in [alpha.owner, alpha.member, alpha.auditor] {
        grant_workflow_access(&mut conn, &world.spine, user).await;
    }

    let client = app(&pool, &key);
    let owner = token(&key, alpha.id, alpha.owner);
    let member = token(&key, alpha.id, alpha.member);
    let auditor = token(&key, alpha.id, alpha.auditor);

    let (_, body) = client
        .post(
            &format!("/api/v1/files/{}/workflows", world.spine.file),
            &owner,
            serde_json::json!({ "definitionId": world.definition.to_string() }),
        )
        .await;
    let instance = body["id"].as_str().expect("instance id").to_owned();
    let (_, view) = client.get(&format!("/api/v1/workflows/instances/{instance}"), &owner).await;
    let step = first_step(&view);
    let approve = format!("/api/v1/workflows/steps/{step}/approve");

    let before = count(&mut conn, Table::Audit).await;
    let (status, _) = client.post(&approve, &auditor, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let denials: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE outcome = 'DENY' AND policy_refs::text LIKE '%handler:actor%'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("count handler denials");
    assert_eq!(denials, 1, "the handler's refusal reached the caller without a row");
    assert!(
        count(&mut conn, Table::Audit).await > before + 1,
        "the chain's own ALLOW for file.content_read is missing, so the two rows are not paired"
    );

    // The allowed request writes no `handler:actor` row: the chain allowed both, and only the
    // refused one produced a second. Counting allows could never have shown that.
    let (status, _) = client.post(&approve, &member, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let denials: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events
          WHERE outcome = 'DENY' AND policy_refs::text LIKE '%handler:actor%'",
    )
    .fetch_one(&mut conn)
    .await
    .expect("count handler denials");
    assert_eq!(denials, 1, "an allowed approval wrote a handler denial");
}
