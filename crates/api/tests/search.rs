//! `ENC-695` — `POST /api/v1/search`, end to end, over a real PostgreSQL.
//!
//! # What these prove that the unit tests cannot
//!
//! `crates/api/src/routes/search.rs`'s own tests prove the *shape*: that markup from a document
//! cannot escape through an excerpt, that a narrowing filter is refused by name, that the candidate
//! budget over-fetches. None of that is the property the endpoint exists to hold.
//!
//! That property is an **absence** — *a result the caller may not read never appears* — and
//! `docs/12-TESTING.md §1.2` is explicit about what an absence is worth on its own: it passes for
//! free against a handler that returns nothing. So every assertion below is paired with a positive
//! control, and the controls are chosen to fail the specific wrong implementation:
//!
//! | Absence asserted | Control that makes it mean something |
//! |---|---|
//! | `hidden` is not in the page | `readable` **is**, for the same caller, same query, same folder |
//! | a `MetadataRead`-only hit carries no excerpt | a hit with `ContentRead` carries one, with `<em>` in it |
//! | beta's query never surfaces alpha's ids | beta's own identically-named file **is** returned |
//!
//! # The fixture, and why both tenants are identical
//!
//! `docs/12-TESTING.md §3`: *"`tenant-beta` exists solely so every cross-tenant assertion has a
//! realistic counterpart with the same names — a test that passes only because the other tenant's
//! file was called something else proves nothing."* So alpha and beta get the same workspace name,
//! the same library name, the same folder name, the same three file names and the **same body
//! text**. Every string in the response is a string that exists in both tenants; only the ids
//! differ, which is why every cross-tenant assertion here is about ids.
//!
//! `hidden` is the point of the within-tenant half. It is an ordinary file in the same folder as
//! `readable`, created by the same owner, with the same word in its body, differing only in that
//! `inherit_permissions = FALSE` stops the library's grant reaching it. There is no way to observe
//! it that is not also a way to observe a file somebody was actually meant to be denied.
//!
//! # What the cross-tenant test proves, and at which layer
//!
//! Worth stating plainly, because `docs/12-TESTING.md §1.2` records that dropping a `tenant_id`
//! predicate has failed to fail in four separate crates — row-level security held the property
//! alone and the test named the wrong mechanism.
//!
//! [`beta_sees_its_own_documents_and_never_alphas`] is an **end-to-end** assertion and does not
//! isolate a layer. Three things hold it at once: the `f.tenant_id = $1` predicate in
//! `crates/search/src/lexical.rs`, row-level security on `files` and `chunk_text` under the
//! `enclave_app` role, and `crates/authorization`'s `classify`, which refuses a foreign-tenant
//! reference without a query. Removing any one of them would leave this test green.
//! `crates/search/tests/lexical_content.rs` (S5) is where the generator's half is isolated.
//!
//! [`the_tenant_cannot_be_named_by_the_caller`] is the half that **is** this layer's, and it is the
//! one `CLAUDE.md` rule 3 is about: the tenant reaches the query from the verified token and from
//! nowhere else. There is no body field, query parameter or header that can carry one — the request
//! type is `deny_unknown_fields`, so an attempt to supply one is a `400` rather than a value the
//! handler might read — and the same caller's own results are unaffected, which is what stops the
//! assertion passing because the request failed for some unrelated reason.
//!
//! # The audit assertions are exact counts
//!
//! One search, one row. Not one row per confirmed hit and not one per capability probe: the
//! post-filter resolves through the authorization stage directly, which decides without auditing
//! (`docs/07 §6.2`), and a route that audited its per-candidate resolutions would write a hundred
//! `ALLOW`s for reads nobody performed.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, TimeZone as _, Utc};
use enclave_api::{router, ApiState};
use enclave_auth::{AccessTokenIssuer, Acr, AuthMethod, KeySet, PrivateSigningKey, TokenTemplate};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, AuthorizationService, ClientType, ContainerAction, FileAction, FileId, LibraryId,
    PolicyEngine, RequestContext, ResourceKind, ResourceRef, Result as CoreResult, StageDecision,
    TenantId, UserId, VersionId, WorkspaceId,
};
use enclave_testing::{Fixtures, TestDb};
use sqlx::{Connection as _, PgConnection};
use tower::ServiceExt as _;
use uuid::Uuid;

const ISSUER: &str = "https://enclave.test";
const AUDIENCE: &str = "enclave-api";

/// The word every fixture document contains, in both tenants.
///
/// Distinctive enough that `!body.contains(TERM)` would be meaningless — every file matches it —
/// which is deliberate: the cross-tenant assertions are about ids precisely because the words are
/// shared.
const TERM: &str = "perihelion";

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// One tenant's searchable content, identical in shape and in every string between the two tenants.
#[derive(Debug, Clone, Copy)]
struct Spine {
    tenant: TenantId,
    workspace: WorkspaceId,
    library: LibraryId,
    /// A folder at the library root, inheriting. Gives every hit a path with a segment in it.
    folder: FileId,
    /// Inherits the library's grants. The caller may read its metadata *and* its content.
    readable: FileId,
    /// Inheritance broken, no entries. Invisible to the granted caller by construction.
    hidden: FileId,
    /// Inheritance broken, with an entry for `file.metadata_read` and nothing else.
    titles_only: FileId,
}

impl Spine {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            workspace: WorkspaceId::new_v7(),
            library: LibraryId::new_v7(),
            folder: FileId::new_v7(),
            readable: FileId::new_v7(),
            hidden: FileId::new_v7(),
            titles_only: FileId::new_v7(),
        }
    }

    /// The three files, with the name and the body each carries.
    ///
    /// Every body holds [`TERM`], so all three are candidates for one query and the page is decided
    /// entirely by the post-filter rather than by which documents matched.
    fn documents(&self) -> [(FileId, &'static str, &'static str); 3] {
        [
            (
                self.readable,
                "Deployment Plan.pdf",
                "the perihelion review procedure for the platform",
            ),
            (self.hidden, "Deployment Notes.pdf", "the perihelion redundancy list nobody may read"),
            (
                self.titles_only,
                "Deployment Index.pdf",
                "the perihelion index of restricted material",
            ),
        ]
    }

    async fn insert(&self, conn: &mut PgConnection, owner: UserId) {
        sqlx::query(
            "INSERT INTO workspaces
               (id, tenant_id, name, slug, visibility, created_by, created_at, updated_at)
             VALUES ($1, $2, 'Engineering', $3, 'PRIVATE', $4, $5, $5)",
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
             VALUES ($1, $2, $3, 'Specs', $4, TRUE, 'MAJOR', 'DISABLED', $5, $5)",
        )
        .bind(self.library.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(format!("lib-{}", self.library.as_uuid()))
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert library");

        self.insert_node(conn, self.folder, None, "FOLDER", "Architecture", true, owner).await;

        for (id, name, body) in self.documents() {
            // `readable` inherits; the other two do not, which is the only difference between them
            // and the reason the trim has anything to do.
            let inherits = id == self.readable;
            self.insert_node(conn, id, Some(self.folder), "FILE", name, inherits, owner).await;
            let version = VersionId::new_v7();
            self.insert_version(conn, id, version, owner).await;
            self.insert_chunk(conn, id, version, body).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_node(
        &self,
        conn: &mut PgConnection,
        id: FileId,
        parent: Option<FileId>,
        node_type: &str,
        name: &str,
        inherit: bool,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO files
               (id, tenant_id, workspace_id, library_id, parent_id, node_type, name,
                normalized_name, mime_type, status, inherit_permissions, created_by, modified_by,
                created_at, modified_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'application/pdf', 'AVAILABLE', $9, $10, $10,
                     $11, $11)",
        )
        .bind(id.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(self.workspace.as_uuid())
        .bind(self.library.as_uuid())
        .bind(parent.map(|id| id.as_uuid()))
        .bind(node_type)
        .bind(name)
        .bind(name.to_lowercase())
        .bind(inherit)
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert file node");
    }

    async fn insert_version(
        &self,
        conn: &mut PgConnection,
        file: FileId,
        version: VersionId,
        owner: UserId,
    ) {
        sqlx::query(
            "INSERT INTO file_versions
               (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
                mime_type, major, minor, status, av_status, encryption_mode, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, 1024, $6, 'application/pdf', 1, 0, 'AVAILABLE', 'CLEAN',
                     'PROVIDER', $7, $8)",
        )
        .bind(version.as_uuid())
        .bind(self.tenant.as_uuid())
        .bind(file.as_uuid())
        // The value the "no object key on the wire" assertion searches for.
        .bind(format!("tenants/{}/blobs/{}", self.tenant.as_uuid(), version.as_uuid()))
        .bind(Uuid::new_v4())
        .bind("0".repeat(64))
        .bind(owner.as_uuid())
        .bind(fixed_time())
        .execute(&mut *conn)
        .await
        .expect("insert version");

        sqlx::query("UPDATE files SET current_version_id = $2 WHERE id = $1")
            .bind(file.as_uuid())
            .bind(version.as_uuid())
            .execute(&mut *conn)
            .await
            .expect("point at current version");
    }

    /// Writes one chunk of extracted text, which is what makes the body searchable and what the
    /// excerpt is cut from.
    async fn insert_chunk(
        &self,
        conn: &mut PgConnection,
        file: FileId,
        version: VersionId,
        text: &str,
    ) {
        sqlx::query(
            "INSERT INTO chunk_text
               (tenant_id, chunk_id, file_id, version_id, ordinal, chunker_version, text)
             VALUES ($1, $2, $3, $4, 0, 'test', $5)",
        )
        .bind(self.tenant.as_uuid())
        .bind(Uuid::new_v4())
        .bind(file.as_uuid())
        .bind(version.as_uuid())
        .bind(text)
        .execute(&mut *conn)
        .await
        .expect("insert chunk text");
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("a valid fixed instant")
}

/// Grants one action on one resource to one user.
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
    .expect("insert acl entry");
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// The authorization service the search route needs, and the reason it has to be composed here.
///
/// **This is `ENC-696` wearing a test harness, and it is worth reading rather than skipping.**
///
/// The route asks the chain one question — `container.read` against the caller's own principal —
/// and the post-filter asks it a different one, `file.metadata_read`/`file.content_read` against a
/// page of files. No service in the workspace answers both. `PgAclAuthorization` resolves
/// `acl_entries` and correctly refuses a `User` reference, which carries no ACL rows;
/// `SelfServiceAuthorization` allows a principal to read itself and refuses everything else.
///
/// So the entry point delegates to the first and everything else to the second — and **everything
/// this file asserts runs through the second**. The self-read arm opens the door and decides
/// nothing about a document: it cannot allow a file, because it only ever fires for
/// `ResourceKind::User`, and `PgAclAuthorization` is what answers every question the post-filter and
/// the capability probe ask. A composite that allowed more than that would make the tests below
/// pass for the wrong reason, which is why the arm is written as narrowly as it can be and asserted
/// on in [`the_self_read_arm_decides_nothing_about_a_document`].
#[derive(Debug)]
struct SelfReadOrAcl {
    acl: Arc<PgAclAuthorization>,
}

impl SelfReadOrAcl {
    /// Whether this is a principal reading its own user record — the only thing the first arm
    /// answers. A copy of `SelfServiceAuthorization::is_self_read`, kept here because that method is
    /// private and because a reader of this file has to be able to see exactly how wide the arm is.
    fn is_self_read(ctx: &RequestContext, action: Action, resource: &ResourceRef) -> bool {
        matches!(action, Action::Container(ContainerAction::Read))
            && resource.kind == ResourceKind::User
            && ctx.actor.subject_id().is_some_and(|id| id == resource.id)
    }
}

#[async_trait]
impl AuthorizationService for SelfReadOrAcl {
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
        self.acl.authorize_many(ctx, action, resources).await
    }

    async fn authorize_many_actions(
        &self,
        ctx: &RequestContext,
        actions: &[Action],
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<Vec<StageDecision>>> {
        self.acl.authorize_many_actions(ctx, actions, resources).await
    }
}

struct Harness {
    app: axum::Router,
    key: PrivateSigningKey,
}

async fn harness(db: &TestDb) -> Harness {
    let key = PrivateSigningKey::generate(Utc::now()).expect("generate signing key");

    // Three pools, each tiny. A search holds its own transaction open across the post-filter, which
    // opens a second one of its own, and the audit sink needs a third — one shared pool of two
    // connections is a deadlock rather than a slow test (`crates/api/tests/content.rs`).
    let state_pool = db.pool().await.expect("state pool");
    let authz_pool = db.pool().await.expect("authorization pool");
    let audit_pool = db.pool().await.expect("audit pool");

    let authorization =
        Arc::new(SelfReadOrAcl { acl: Arc::new(PgAclAuthorization::new(authz_pool)) });

    let policy = PolicyEngine::new(
        Arc::new(enclave_conditional_access::UnconfiguredConditionalAccess),
        authorization as Arc<dyn AuthorizationService>,
        Arc::new(enclave_information_barriers::UnconfiguredBarriers),
        Arc::new(enclave_classification::UnconfiguredClassification),
        Arc::new(enclave_dlp::DisabledDlp),
        Arc::new(enclave_retention::UnconfiguredRetention),
        Arc::new(enclave_audit::PgAuditSink::new(audit_pool, enclave_audit::ChainMode::Enabled)),
    );

    let state =
        ApiState::new(policy, state_pool, ISSUER, AUDIENCE, KeySet::new([key.public().clone()]));
    // Search reaches no delivery path: it returns rows and quotations, never bytes.
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

/// Issues one search and returns the status and the parsed body.
async fn post_search(
    harness: &Harness,
    tenant: TenantId,
    user: UserId,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search")
                .header("authorization", format!("Bearer {}", token(&harness.key, tenant, user)))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.expect("body");
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json")
    };
    (status, json)
}

/// The default query body: just the term.
fn query(term: &str) -> serde_json::Value {
    serde_json::json!({ "query": term })
}

fn result_ids(body: &serde_json::Value) -> Vec<String> {
    body["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|hit| hit["fileId"].as_str().expect("fileId").to_owned())
        .collect()
}

fn hit_for(body: &serde_json::Value, file: FileId) -> &serde_json::Value {
    body["results"]
        .as_array()
        .expect("results array")
        .iter()
        .find(|hit| hit["fileId"] == file.to_string())
        .unwrap_or_else(|| panic!("{file} is not in the page: {body}"))
}

async fn audit_rows(db: &TestDb, tenant: TenantId) -> Vec<(String, String, Option<Uuid>)> {
    let mut conn = db.connect().await.expect("connect");
    sqlx::query_as(
        "SELECT action, outcome, resource_id FROM audit_events WHERE tenant_id = $1 \
         ORDER BY sequence",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut conn)
    .await
    .expect("read audit rows")
}

/// Both tenants seeded and written, with alpha's member granted on alpha's library and beta's
/// member granted identically on beta's.
///
/// The mirror is what makes the cross-tenant assertions realistic: beta's member can search beta,
/// so a beta query that returns nothing is a failure rather than a pass.
async fn setup() -> (TestDb, Fixtures, Spine, Spine) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let alpha = Spine::new(fixtures.alpha.id);
    let beta = Spine::new(fixtures.beta.id);

    let mut admin = db.connect().await.expect("admin connection");
    alpha.insert(&mut admin, fixtures.alpha.owner).await;
    beta.insert(&mut admin, fixtures.beta.owner).await;

    for (spine, user) in [(alpha, fixtures.alpha.member), (beta, fixtures.beta.member)] {
        // On the library, so it reaches the folder and every inheriting file under it.
        for action in [
            Action::Container(ContainerAction::Read),
            Action::File(FileAction::MetadataRead),
            Action::File(FileAction::ContentRead),
            Action::File(FileAction::Preview),
            Action::File(FileAction::Download),
        ] {
            grant(&mut admin, spine.tenant, "LIBRARY", spine.library.as_uuid(), user, action).await;
        }
        // And on `titles_only` alone, which does not inherit: metadata and nothing else.
        grant(
            &mut admin,
            spine.tenant,
            "FILE",
            spine.titles_only.as_uuid(),
            user,
            Action::File(FileAction::MetadataRead),
        )
        .await;
    }

    let _ignored = admin.close().await;
    (db, fixtures, alpha, beta)
}

// ---------------------------------------------------------------------------------------------
// The central claim
// ---------------------------------------------------------------------------------------------

/// **The assertion the route exists for, with its control.**
///
/// `hidden` matches the query, sits in the same folder as `readable`, was created by the same owner
/// and contains the same word. The only difference is that the library's grant does not reach it.
/// The candidate generator proposes all three files — that is what makes this a post-filter test
/// rather than a query test — and exactly two survive.
///
/// Without the `readable` half, every assertion here passes against a handler that returns an empty
/// page, which is `docs/12-TESTING.md §1.2`'s recurring shape.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_result_the_caller_may_not_read_never_appears_and_one_they_may_does() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.member, query(TERM)).await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let mut returned = result_ids(&body);
    returned.sort();
    let mut expected = vec![alpha.readable.to_string(), alpha.titles_only.to_string()];
    expected.sort();
    assert_eq!(returned, expected, "the page must be exactly the confirmed hits: {body}");

    let text = serde_json::to_string(&body).expect("render");
    assert!(!text.contains(&alpha.hidden.to_string()), "the hidden id reached the caller: {text}");
    assert!(
        !text.contains("redundancy list"),
        "the hidden document's body reached the caller: {text}"
    );

    // The control, stated as its own assertion so a failure says which half broke.
    let readable = hit_for(&body, alpha.readable);
    assert_eq!(readable["title"], "Deployment Plan.pdf");
    assert_eq!(readable["path"], "Engineering / Specs / Architecture");
    assert_eq!(readable["workspace"], "Engineering");

    // The trim is invisible: nothing on the wire says three candidates were proposed and one was
    // dropped, which is the same rule the browse listing follows.
    let page = body["page"].as_object().expect("page");
    for leak in ["total", "totalCount", "count", "dropped", "trimmed", "filtered"] {
        assert!(!page.contains_key(leak), "{leak} would say how much the caller cannot see");
    }

    // One request, one decision, one row — not one per confirmed hit and not one per capability
    // probe.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "container.read");
    assert_eq!(rows[0].1, "ALLOW");
}

/// **`docs/12-TESTING.md §4.3` S6, at the HTTP layer.**
///
/// A caller holding `MetadataRead` and not `ContentRead` gets the title and no quotation — and
/// cannot tell that from a document that had none, because both are `null`.
///
/// `titles_only` is load-bearing in a specific way: its body **does** contain the term, so the
/// generator cut a real excerpt for it and the post-filter withheld one that existed. A fixture
/// whose body did not match would make this pass against a route that never produced an excerpt at
/// all — which is exactly why `readable`'s excerpt is asserted to be present, with markup in it.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_metadata_only_hit_carries_a_title_and_no_quotation() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let withheld = hit_for(&body, alpha.titles_only);
    assert_eq!(withheld["title"], "Deployment Index.pdf", "the hit itself must be visible");
    assert_eq!(
        withheld["excerpt"],
        serde_json::Value::Null,
        "an excerpt was disclosed: {withheld}"
    );
    assert!(
        !serde_json::to_string(withheld).expect("render").contains("restricted material"),
        "the withheld body reached the caller: {withheld}"
    );

    // The control. Without it every assertion above holds against a route that returns `null` for
    // every excerpt, which is the pre-`ENC-529` behaviour wearing a passing test.
    let disclosed = hit_for(&body, alpha.readable);
    let excerpt = disclosed["excerpt"].as_str().expect("the readable hit must carry an excerpt");
    assert!(
        excerpt.contains("review procedure"),
        "the quotation must be the document's: {excerpt}"
    );
    assert!(
        excerpt.contains("<em>perihelion</em>"),
        "docs/05 §11's markup must be applied from the offsets: {excerpt}"
    );

    // Neither hit carries anything that locates the bytes (`CLAUDE.md` rule 6).
    let text = serde_json::to_string(&body).expect("render");
    for leak in ["objectKey", "object_key", "tenants/", "storageProfileId", "encryptionKeyRef"] {
        assert!(!text.contains(leak), "{leak} reached a search result: {text}");
    }
}

// ---------------------------------------------------------------------------------------------
// Cross-tenant
// ---------------------------------------------------------------------------------------------

/// **End to end, and it does not isolate a layer** — see the module documentation for which three
/// hold the property and where each is isolated.
///
/// What it does prove is that the composition holds it: beta's member, searching the word every
/// document in both tenants contains, receives beta's documents and nothing of alpha's. The control
/// is that beta's page is *not empty* and carries the same file names alpha's does — so an
/// implementation that returned nothing for beta, or that failed the request, fails here rather
/// than passing as an absence.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn beta_sees_its_own_documents_and_never_alphas() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        post_search(&harness, fixtures.beta.id, fixtures.beta.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let mut returned = result_ids(&body);
    returned.sort();
    let mut expected = vec![beta.readable.to_string(), beta.titles_only.to_string()];
    expected.sort();
    assert_eq!(returned, expected, "beta must get beta's confirmed hits and only those: {body}");

    // The control: the names are identical across tenants, so a page carrying them proves the query
    // matched rather than that beta happens to hold nothing.
    assert_eq!(hit_for(&body, beta.readable)["title"], "Deployment Plan.pdf");

    let text = serde_json::to_string(&body).expect("render");
    for id in [alpha.readable, alpha.hidden, alpha.titles_only, alpha.folder] {
        assert!(!text.contains(&id.to_string()), "an alpha id reached beta: {text}");
    }

    // Alpha's audit chain records nothing: beta's request never became a question about alpha.
    assert!(audit_rows(&db, fixtures.alpha.id).await.is_empty());
}

/// **`CLAUDE.md` rule 3, and the half of the cross-tenant property that is this layer's.**
///
/// The tenant reaches the query from the verified token. There is no body field for one — the
/// request type is `deny_unknown_fields` — so an attempt to supply a tenant is a `400` rather than a
/// value the handler might prefer, and nothing about alpha appears in the refusal.
///
/// The control is the second half: the same caller, the same body without the smuggled field, gets
/// their own results. Without it the assertion is satisfied by an endpoint that refuses everything.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_tenant_cannot_be_named_by_the_caller() {
    let (db, fixtures, alpha, beta) = setup().await;
    let harness = harness(&db).await;

    for field in ["tenantId", "tenant_id", "tid"] {
        let (status, body) = post_search(
            &harness,
            fixtures.beta.id,
            fixtures.beta.member,
            serde_json::json!({ "query": TERM, field: alpha.tenant.to_string() }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "`{field}` was accepted: {body}");
        let text = serde_json::to_string(&body).expect("render");
        assert!(!text.contains("results"), "a refused request answered with a page: {text}");
        assert!(!text.contains(&alpha.readable.to_string()), "alpha content reached beta: {text}");
    }

    // The control.
    let (status, body) =
        post_search(&harness, fixtures.beta.id, fixtures.beta.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(result_ids(&body).contains(&beta.readable.to_string()), "{body}");
}

/// The composite in this file's harness allows exactly one thing, and it is not a document.
///
/// Asserted rather than argued, because a harness that quietly allowed more than the real
/// deployment would make every test above pass for a reason the product does not have. `hidden` is
/// the probe: if the self-read arm were reachable for a file, `hidden` would be in the page.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_self_read_arm_decides_nothing_about_a_document() {
    let (db, fixtures, alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    // A caller with no grants at all. The entry point still admits them — that is the self-read arm
    // doing its whole job — and the page is empty, which is the post-filter doing its.
    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.viewer, query(TERM)).await;

    assert_eq!(status, StatusCode::OK, "an ungranted caller must still be able to search: {body}");
    assert!(result_ids(&body).is_empty(), "an ungranted caller received results: {body}");

    let text = serde_json::to_string(&body).expect("render");
    for id in [alpha.readable, alpha.hidden, alpha.titles_only] {
        assert!(!text.contains(&id.to_string()), "{text}");
    }

    // And the request was still a decision the chain took and recorded.
    let rows = audit_rows(&db, fixtures.alpha.id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].1, "ALLOW");
}

// ---------------------------------------------------------------------------------------------
// The degraded indicator, and the contract around it
// ---------------------------------------------------------------------------------------------

/// **`ENC-675`, `docs/09 §10`.** The response says the search was degraded, on a request that
/// returned results.
///
/// The non-empty page is the control and it is the whole point: `degraded: true` beside an empty
/// page is what a broken route looks like, and would prove nothing. This is a route answering
/// normally and still telling the caller their recall is reduced.
///
/// The cause is asserted **absent**: `crates/search/src/degraded.rs` puts the boolean on the wire
/// and keeps the cause for the operator, and a response naming `VectorStoreUnreachable` would be
/// our topology in a client's hands.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_search_that_returned_results_still_reports_that_recall_was_reduced() {
    let (db, fixtures, _alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert!(!result_ids(&body).is_empty(), "the control: a degraded flag on an empty page is free");
    assert_eq!(body["diagnostics"]["degraded"], true, "docs/09 §10's header has nothing to read");
    assert_eq!(body["diagnostics"]["mode"], "lexical", "the mode must be the one that ran");

    let diagnostics = serde_json::to_string(&body["diagnostics"]).expect("render");
    for internal in ["Unreachable", "unreachable", "Depleted", "Denylist", "cause"] {
        assert!(!diagnostics.contains(internal), "the cause is operator-facing: {diagnostics}");
    }
}

/// A page shorter than what the post-filter confirmed says so, and issues no cursor to reach the
/// rest.
///
/// `limit: 1` against a caller with two confirmed hits is the interesting case, and both halves are
/// asserted because they fail separately. `hasMore: false` beside a discarded confirmed hit is the
/// same lie `diagnostics.degraded` exists to prevent, in a smaller field; `nextCursor` non-null
/// would be a cursor that resolves to nothing (`ENC-697`).
///
/// The control is the unlimited query, whose `hasMore` is `false` — without it this passes against a
/// route that hardcodes `true`.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_page_that_hides_confirmed_hits_says_so_and_offers_no_cursor() {
    let (db, fixtures, _alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = post_search(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        serde_json::json!({ "query": TERM, "limit": 1 }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(result_ids(&body).len(), 1, "the page must honour the limit: {body}");
    assert_eq!(body["page"]["hasMore"], true, "a truncated page must say so: {body}");
    assert_eq!(body["page"]["nextCursor"], serde_json::Value::Null, "{body}");

    // The control: a page that holds everything must not claim otherwise.
    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(result_ids(&body).len(), 2);
    assert_eq!(body["page"]["hasMore"], false, "{body}");
}

/// A narrowing filter that cannot be applied is refused by name rather than ignored.
///
/// The control is the same body without the filter, which succeeds — otherwise this passes against
/// an endpoint that refuses every request.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_filter_that_cannot_be_applied_is_refused_rather_than_dropped() {
    let (db, fixtures, _alpha, _beta) = setup().await;
    let harness = harness(&db).await;

    let (status, body) = post_search(
        &harness,
        fixtures.alpha.id,
        fixtures.alpha.member,
        serde_json::json!({ "query": TERM, "classificationMax": "PUBLIC" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "VALIDATION_FAILED");
    let details = body["error"]["details"].as_array().expect("details");
    assert!(
        details
            .iter()
            .any(|entry| entry["field"] == "classificationMax" && entry["code"] == "UNSUPPORTED"),
        "the refused field must be named: {body}"
    );
    assert!(
        !serde_json::to_string(&body).expect("render").contains("results"),
        "an unapplied filter must not answer with a page: {body}"
    );

    // The control.
    let (status, body) =
        post_search(&harness, fixtures.alpha.id, fixtures.alpha.member, query(TERM)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!result_ids(&body).is_empty(), "{body}");
}
