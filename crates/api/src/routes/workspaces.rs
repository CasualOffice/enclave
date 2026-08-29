//! The workspace surface — enumerate the containers a caller is in, read one, and make one.
//!
//! `docs/05-API.md §7.1` is authoritative for everything on the wire here. That section was
//! **written for this module** (`ENC-794`): before it, the document specified `§7`'s file surface,
//! `§12`'s `/workspaces/{id}/lists` and `§14`'s `/admin/workspaces`, and no client-facing way to
//! *find* a workspace or a library at all. Where the document and this code disagree the document
//! wins and this module is the bug.
//!
//! # Why these two endpoints exist
//!
//! `ENC-778`. `crates/api` registered `GET /libraries/{id}/items` and nothing above it, so a client
//! could browse a library only if the id already sat in its URL — and `crates/workspaces`, complete
//! and tested at 1,923 lines, was reached by no HTTP surface whatsoever. A backend nothing can
//! enumerate is a backend with no navigation.
//!
//! # The property this module exists to hold
//!
//! **A listing must not become a way to enumerate what you cannot see.** It is the same property
//! `crates/api/src/content.rs` holds for files, and it is *more* load-bearing here, because
//! [`WorkspaceRepository::list_by_tenant`] returns every workspace in the tenant by design — the
//! repository makes no authorization decision (`plans/M1-CONTENT-CORE.md` D11), so the endpoint's
//! entire security is the trim in [`readable_workspaces`].
//!
//! Three consequences are visible on the wire and are deliberate, exactly as they are for `browse`:
//!
//! * A page may hold **fewer items than `limit`** and still report `hasMore: true`. The cursor
//!   tracks the last row the *database* returned, not the last row that survived the trim.
//! * There is **no total count** (`docs/05-API.md §6`): a count over an ACL-trimmed set tells the
//!   caller how much exists that they may not see.
//! * The trim is silent. Nothing distinguishes "you are in two workspaces" from "there are nine and
//!   two are yours".
//!
//! # Where the chain runs, and on what
//!
//! | Endpoint | Resource enforced | Action |
//! |---|---|---|
//! | `GET /workspaces` | **the caller's own `users` row** | `container.read` |
//! | `GET /workspaces/{id}` | the workspace | `container.read` |
//! | `POST /workspaces` | **the tenant** | `admin.write_config` |
//!
//! # Why there is a write here at all, and what the document still says
//!
//! `docs/05-API.md §7.1` ends with *"These four are reads. Creating, renaming and trashing a
//! container are administrative operations and live under `/admin/**` (`§14`); nothing here
//! mutates."* That sentence is now half true and needs amending, and until it is amended a reader
//! is entitled to be confused — so the reasoning is recorded here rather than left implicit.
//!
//! [`WorkspaceRepository::create`] has existed since M1, is covered by its own tests, and had **no
//! caller in any binary**. `enclave-cli seed` writes tenants, users and groups and no workspace, so
//! a freshly installed deployment answered `GET /workspaces` with an empty page and offered no way
//! to make it non-empty. Every write path below a workspace — libraries, folders, uploads, shares —
//! is reachable only from a workspace that exists, so the missing create was not one missing
//! feature but the reason the product could not be started at all. `/admin/workspaces` is the
//! surface `§14` reserves for the administrative *lifecycle* — rename, quota, trash, transfer — and
//! none of it is built; waiting for it would have kept the floor missing for the sake of a table
//! row. What lands here is creation and only creation.
//!
//! The first row is the one that needs an argument (`ENC-795`). A tenant-wide listing has no parent
//! container: the thing above a workspace is the tenant, and `crates/authorization/src/service.rs`
//! classifies a `Tenant` reference as `Unsupported` — correctly, since `acl_entries` has no row that
//! could hang on one — so enforcing `container.read` on `ResourceRef::tenant` would refuse every
//! caller in the composed binary while looking principled. What this endpoint actually is, is *the
//! caller's own view of their memberships*, and the resource such a view is about is the caller.
//! `crates/api/src/me.rs` and `GET /workflows/tasks` already make that call for the same reason, so
//! this is the third instance of one shape rather than a new invention. The per-workspace question
//! is then asked per workspace, in the trim, where it belongs.
//!
//! It costs something and the cost is stated rather than hidden: the audited resource of a workspace
//! listing is a **user id**, not a workspace id, so an investigator reading `audit_events` sees who
//! enumerated and not what came back. The individual rows are not audited on purpose — a trim that
//! audited would write one speculative `ALLOW` per candidate for a question nobody asked
//! (`docs/07-SEARCH-INDEXING.md §6.2`, and the exact-count assertions in `crates/api/tests/`).
//!
//! # `404`, never `403`
//!
//! `CLAUDE.md` rule 7. [`conceal`] renders an `ACCESS_DENIED` denial on these read paths as
//! [`Error::NotFound`], so another tenant's workspace id, an id that never existed, and an id in
//! this tenant with no grant are one answer. Every other reason code keeps its own status, for the
//! reason `content.rs` sets out at length: those are produced by stages that run either before
//! authorization (and refuse identically for a nonexistent id) or after it (by which point the
//! caller already holds a grant).
//!
//! # This module owns the container vocabulary
//!
//! [`Page`], [`ContainerCapabilities`], [`WireObligations`] and [`capabilities_for_containers`] are
//! defined here and used by [`crate::routes::libraries`] as well. One copy, deliberately: a
//! second implementation of "what may this caller do with this container" is a second answer, and
//! the day the two disagree a client will offer an action on a library that it hides on the
//! workspace holding it. They live here rather than in a module of their own because a workspace is
//! the outermost container — the vocabulary is defined where the hierarchy starts.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestExt as _};
use chrono::Utc;
use enclave_authorization::{AclResourceType, ChainNode, Effect, Grant, Principal, PrincipalKind};
use enclave_core::{
    Action, Actor, AdminAction, AuthorizationService, ContainerAction, Error, FieldError,
    FileAction, Obligation, Obligations, PolicyDecision, ReasonCode, RequestContext, RequestId,
    ResourceRef, StageOutcome, UserId, ValidationCode, WorkspaceId,
};
use enclave_workspaces::{
    normalize_slug, PageSize, Visibility, Workspace, WorkspaceError, WorkspaceFilter,
    WorkspaceRepository, WorkspaceSettings,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, CapabilityReasons, Envelope};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

// ---------------------------------------------------------------------------------------------
// The page envelope and the container vocabulary — shared with `routes::libraries`
// ---------------------------------------------------------------------------------------------

/// The page envelope of `docs/05-API.md §6`.
///
/// Its own type rather than a reuse of `content::Page`, whose fields are private to that module.
/// The three field names are the document's, so a client pages a workspace listing, a library
/// listing and a browse listing with one piece of code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    pub(crate) items: Vec<T>,
    pub(crate) page: PageInfo,
}

/// The cursor half of the page envelope. `total` is absent by design and there is no field for it
/// to be added to carelessly.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    /// The opaque cursor for the next page, absent at the end of the listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
    /// Whether another page exists. **Not** implied by a short page — see the module documentation.
    pub(crate) has_more: bool,
    /// The size actually used, after clamping.
    pub(crate) limit: u32,
}

/// What the caller may do with a container, one field per [`ContainerAction`].
///
/// Six booleans and not one `canManage`, for `CLAUDE.md` rule 6's reason applied one level up:
/// adding a library, renaming the workspace, adding a member and re-permissioning it are four
/// different grants, and a response shape that collapses them makes a UI that cannot express the
/// common case — a member who may create content in a workspace they may not administer.
///
/// Every field is the answer this deployment's authorization stage gives for that action on that
/// container. See [`capabilities_for_containers`] for why it is that stage and not a second
/// implementation.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContainerCapabilities {
    /// True by construction on every row: the caller could not be seeing this without it.
    pub(crate) read: bool,
    pub(crate) create: bool,
    pub(crate) update: bool,
    pub(crate) delete: bool,
    pub(crate) manage_members: bool,
    pub(crate) manage_permissions: bool,
}

/// The obligations the caller must satisfy, rendered as `docs/05-API.md §7` shapes them.
///
/// The same three fields the file surface carries, under the same three names, so a client has one
/// obligation renderer rather than two.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireObligations {
    /// Every rendition of content in this container must be watermarked before it is shown.
    pub(crate) watermark: bool,
    /// The actions that cannot proceed without a written justification, by capability name.
    pub(crate) justification_required: Vec<&'static str>,
    /// The actions that must be routed for approval rather than executed.
    pub(crate) approval_required: Vec<&'static str>,
}

/// The capability actions, paired with the wire name each answers to.
///
/// A table rather than six call sites, so that adding a container operation means adding a row and
/// the response, the obligation mapping and the resolution stay in step by construction.
const CONTAINER_ACTIONS: &[(&str, ContainerAction)] = &[
    ("create", ContainerAction::Create),
    ("update", ContainerAction::Update),
    ("delete", ContainerAction::Delete),
    ("manageMembers", ContainerAction::ManageMembers),
    ("managePermissions", ContainerAction::ManagePermissions),
];

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// One workspace, as `GET /workspaces` and `GET /workspaces/{id}` render it.
///
/// One type for both, deliberately, and the same argument `content.rs` makes for `Item` and
/// `FileMetadata` sharing their `capabilities` type: a row and the resource it links to that
/// answered differently would make a UI change its mind about what a user may do purely because
/// they clicked into it. Here the two are not merely consistent, they are the same struct.
///
/// `defaultClassificationId` and `storageProfileId` are **not** on the wire. They are internal
/// references — one into the classification catalogue, one into `docs/08-BYO-INFRA.md`'s storage
/// profiles — and a navigation response is not where a client learns which bucket a tenant's
/// content lands in. `/admin/workspaces` is the surface that administers them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceView {
    id: String,
    name: String,
    slug: String,
    /// Absent rather than null when the workspace has none, per `docs/05-API.md §4`.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Discoverability, as administered. An input to the policy chain and never a permission — the
    /// answer to "may this caller do anything here" is `capabilities`, not this.
    visibility: &'static str,
    /// The optimistic-concurrency counter `docs/05-API.md §9` puts on the wire as the `ETag`.
    revision: i64,
    /// What this caller may attempt, from the stage that will decide it.
    capabilities: ContainerCapabilities,
    /// Why each `false` above is `false` (`ENC-674`). See [`CapabilityReasons`].
    capability_reasons: CapabilityReasons,
    obligations: WireObligations,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl WorkspaceView {
    /// Builds a row from a record and the capability answer resolved for it.
    ///
    /// There is deliberately no `From<&Workspace>` alongside this, for [`content`]'s reason: a
    /// conversion taking the record alone would have to invent a capabilities object, and the only
    /// value available to invent is the default — six `false`s, indistinguishable on the wire from
    /// a caller who may do nothing here. A row can only be built by someone holding a real answer.
    ///
    /// [`content`]: crate::content
    fn new(
        workspace: &Workspace,
        capabilities: ContainerCapabilities,
        capability_reasons: CapabilityReasons,
        obligations: WireObligations,
    ) -> Self {
        Self {
            id: workspace.id.to_string(),
            name: workspace.name.clone(),
            slug: workspace.slug.clone(),
            description: workspace.description.clone(),
            visibility: visibility_str(workspace.visibility),
            revision: workspace.revision,
            capabilities,
            capability_reasons,
            obligations,
            created_at: workspace.created_at,
            updated_at: workspace.updated_at,
        }
    }
}

/// The stored spelling of a visibility, which is also the wire spelling.
///
/// Exhaustive rather than `as_str()` through a borrow, so that a variant added to
/// `enclave_workspaces::Visibility` breaks this match and somebody decides what a client is told
/// rather than inheriting a string.
const fn visibility_str(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Private => "PRIVATE",
        Visibility::MembersOnly => "MEMBERS_ONLY",
        Visibility::TenantVisible => "TENANT_VISIBLE",
        Visibility::Restricted => "RESTRICTED",
    }
}

/// `?cursor=&limit=`.
///
/// Every field is an owned `String` and nothing is parsed by `serde`, for the reason
/// `content::BrowseParams` gives: a typed `Option<u32>` makes `?limit=abc` a *deserialization*
/// failure, which axum answers with plain text outside the single error envelope
/// `docs/05-API.md §5` requires.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListParams {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: Option<String>,
}

/// The body of `POST /workspaces`.
///
/// `camelCase` per `§1`. Four fields, and the two that are *absent* are the point:
///
/// * There is no `tenantId`. Tenant identity comes from the verified token or from custom-domain
///   routing and never from a body field (`CLAUDE.md` rule 3). A field a client could send would be
///   a field somebody eventually trusts.
/// * There is no `defaultClassificationId` and no `storageProfileId`. [`WorkspaceView`] deliberately
///   keeps both off the wire — they are references into the classification catalogue and into
///   `docs/08-BYO-INFRA.md`'s storage profiles — and a create that accepted what the read will not
///   return would let a caller set a value they can then never see. Both are stored as `NULL`, which
///   means *inherit the tenant's*, and `/admin/workspaces` is the surface that pins them.
///
/// `visibility` is a `String` rather than a typed [`Visibility`] for the reason [`ListParams`]
/// gives about `limit`: an unrecognised member must be this handler's field-level `400`, naming
/// `visibility`, and not a serde rejection that axum answers with plain text outside `§5`'s
/// envelope.
///
/// **Every field defaults**, including the two that are required. Nothing here is optional as far as
/// the caller is concerned — [`settings_from`] refuses an empty `name` and an empty `slug` — but a
/// field serde may not omit is a field whose absence is a *deserialization* failure, and this
/// handler can only report that as `body`. Defaulting moves the refusal into the validator, where
/// the answer is `slug: REQUIRED` and a form can attach it to the input the user did not fill in.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateWorkspaceRequest {
    /// The display name as the user typed it.
    #[serde(default)]
    name: String,
    /// The URL-safe short name. Folded by [`normalize_slug`] before it is validated, so what is
    /// checked is what is stored.
    #[serde(default)]
    slug: String,
    /// Free text, or absent.
    #[serde(default)]
    description: Option<String>,
    /// Discoverability, or absent for [`Visibility::Private`].
    #[serde(default)]
    visibility: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/workspaces` — the workspaces this caller can see, one page at a time.
///
/// # Errors
///
/// [`ApiError`]: `400` for an unusable `limit`, or a cursor issued for a different tenant or filter
/// set; the denial's own status for a policy refusal on the caller's own record.
pub async fn list(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<ListParams>,
) -> Result<Json<Page<WorkspaceView>>, ApiError> {
    let request_id = ctx.request_id;
    let limit = page_size(params.limit.as_deref(), request_id)?;

    // The caller's own record: the resource a personal enumeration is about. See the module
    // documentation for why this is not `ResourceRef::tenant`, and what it costs.
    let resource = self_resource(&ctx, request_id)?;

    let decision = state
        .policy
        .enforce(&ctx, Action::Container(ContainerAction::Read), &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;
    // Listing containers carries no obligation any current stage can attach, and this path could not
    // satisfy one if it did — there is nothing in a list of names a watermark could be burned into.
    // An unsatisfiable obligation is a refusal (D29, `CLAUDE.md` rule 8). Not a `debug_assert!`:
    // `ENC-582` is the row where three handlers dropped their obligations in release builds.
    consume(decision).require_none().map_err(|error| ApiError::new(error, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Every live workspace in the tenant, not "the caller's". The repository is unauthorized by
    // construction and says so; the trim below is what makes this endpoint safe.
    let page = WorkspaceRepository::list_by_tenant(
        &mut tx,
        ctx.tenant_id,
        &WorkspaceFilter::default(),
        limit,
        params.cursor.as_deref(),
    )
    .await
    .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Committed before the ACL batches below, deliberately: each `authorize_many` opens its own
    // tenant-scoped transaction, and a handler holding this one open while waiting needs two
    // connections per request — which on a small pool is a deadlock waiting for load.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let items = readable_workspaces(state.policy.authorization().as_ref(), &ctx, &page.workspaces)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    Ok(Json(Page {
        items,
        page: PageInfo {
            next_cursor: page.next_cursor,
            has_more: page.has_more,
            limit: u32::try_from(page.limit.get()).unwrap_or(u32::MAX),
        },
    }))
}

/// Handles `GET /api/v1/workspaces/{id}` — one workspace and the caller's capabilities on it.
///
/// # Errors
///
/// [`ApiError`]: `404` when the workspace is another tenant's, absent, trashed or not granted to
/// this caller; the denial's own status for any other policy refusal.
pub async fn read(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(workspace): Path<String>,
) -> Result<Json<WorkspaceView>, ApiError> {
    let request_id = ctx.request_id;

    // An id that does not parse names no resource. `404` rather than a validation failure, because
    // `GET /workspaces/<garbage>` and `GET /workspaces/<another tenant's id>` must not be
    // distinguishable, and a `400` on one of them is a distinction.
    let workspace: WorkspaceId =
        workspace.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::workspace(ctx.tenant_id, workspace);

    let decision = state
        .policy
        .enforce(&ctx, Action::Container(ContainerAction::Read), &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;
    let obligations = consume(decision);

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let record = WorkspaceRepository::find_by_id(&mut tx, ctx.tenant_id, workspace)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Authorized but absent: trashed or deleted between the chain and the read, or an id that never
    // existed and was refused by no grant. Same answer either way.
    let record = record.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let (capabilities, reasons, wire) = capabilities_for_container(
        state.policy.authorization().as_ref(),
        &ctx,
        &resource,
        &obligations,
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok(Json(WorkspaceView::new(&record, capabilities, reasons, wire)))
}

/// Handles `POST /api/v1/workspaces` — provision a workspace the creator can actually open.
///
/// # Why the action is `admin.write_config` and not `container.create`
///
/// The obvious reading — *creating a container is `container.create` on the thing above it* — is the
/// reading [`crate::routes::folders::create`] uses, and it does not survive one level higher. The
/// thing above a workspace is the tenant, and [`enclave_authorization`]'s `service::classify` maps
/// `ResourceKind::Tenant` onto `Target::Unsupported`, which resolves to `None` — an unconditional
/// refusal. A `container.create` on a tenant reference is therefore not *strict*, it is *dead*: it
/// would refuse every caller in every deployment while looking perfectly principled, which is
/// exactly the failure `ENC-619` found across the whole of `/api/v1/admin/**`.
///
/// `crates/authorization/src/admin.rs` is the decorator that answers an [`Action::Admin`] by role
/// instead of by ACL, from `users.is_admin`, and `crates/api/src/admin/dlp.rs`'s `create_rule` is
/// the existing shape of a tenant-level create: enforce against [`ResourceRef::tenant`], take no
/// obligation, then write. This handler follows it deliberately rather than inventing a third
/// pattern.
///
/// [`AdminAction::WriteConfig`] is the narrow fix and not the right long-term answer. Provisioning a
/// workspace deserves an `AdminAction` of its own — it is closer to `docs/01-PRD.md §4`'s Tenant
/// Administrator than to branding, but it is not branding — and naming one today would be a
/// distinction the schema cannot yet carry: `docs/04 §9` specifies `role_definitions` and names
/// `role_assignments` in its inventory, and `role_assignments` **has no DDL** (`migrations/0004`
/// says so in as many words). Until it does, a deployment has exactly one administrative role, the
/// global administrator holds every [`AdminAction`], and any of the five would admit and refuse
/// precisely the same set of people. `WriteConfig` is chosen because a workspace is tenant
/// configuration rather than tenant *policy*: giving this to `ManagePolicy` would have handed the
/// person who may provision containers the right to rewrite the tenant's DLP rules on the day the
/// finer roles land, and that is the collapse `admin.rs` is written against.
///
/// # The creator's grant is written in the same transaction as the workspace
///
/// A workspace with no ACL entry on it is a workspace **nobody** can open — not even the
/// administrator who made it, because being an administrator answers `Action::Admin` and says
/// nothing about `container.read`. Shipping the insert alone would have produced the twelfth
/// instance of this repository's signature failure: a route that is built, tested, green, and
/// reaches a thing no caller can subsequently use. So [`enclave_authorization::grant::grant`] writes
/// [`FOUNDING_GRANT`] onto the new workspace inside the *same* [`crate::state::ApiState::db`]
/// transaction as the insert, and the two commit together or neither does. A half-done create is a
/// workspace nobody can reach and nobody can delete, which is worse than no workspace.
///
/// # Errors
///
/// [`ApiError`]: the denial's own status — `403`, not `404` — when the caller holds no
/// administrative grant; `400` for a body that will not decode and for a name, slug or visibility
/// the tenant cannot store; `409` when a live workspace already holds the folded slug.
///
/// `CLAUDE.md` rule 7 is deliberately **not** applied to the refusal. Rule 7 conceals resources
/// whose existence is itself the secret; the resource here is the caller's own tenant, whose
/// existence their token already asserts, and a `404` on `POST /workspaces` would tell a
/// non-administrator that the endpoint does not exist rather than that they may not use it.
/// `admin/dlp.rs` makes the same call for the same reason.
pub async fn create(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let tenant = ResourceRef::tenant(ctx.tenant_id);

    // The chain runs before the body is looked at, exactly as `admin::dlp::create_rule` orders it: a
    // caller the chain refuses learns nothing about the request schema — not even that their JSON
    // was malformed.
    let decision = state
        .policy
        .enforce(&ctx, PROVISION, &tenant)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it here is what proves nothing was dropped. No
    // stage attaches an obligation to an administrative action today, and this path could
    // discharge none if one arrived — there is no rendition to watermark, no content to reclassify
    // and nowhere synchronous to route an approval — so an obligation is a refusal (D29,
    // `CLAUDE.md` rule 8) and it is audited as one (rule 10).
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, PROVISION, &tenant, refused).await);
    }

    // `docs/05-API.md §14` requires recent multi-factor authentication for a privileged mutation,
    // and provisioning a workspace is one: it is the act that creates a container and, in the same
    // transaction, writes the founding grant over it. Ordered after the chain for the reason
    // `crate::admin::require_step_up` records — the chain decides first, at the cost of an `ALLOW`
    // row for a request this then refuses (`ENC-620`). It reads `state.step_up` rather than a
    // constant, so a deployment that has configured no second factor is not locked out of its own
    // provisioning path, which is `ENC-771`'s finding and the reason this endpoint is usable at all
    // on a stack that has not configured MFA.
    if let Err(envelope) = crate::admin::require_step_up(&ctx, state.step_up, "workspace.provision")
    {
        return Ok(envelope.into_response(request_id));
    }

    let created_by = match founder(&ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(&ctx, PROVISION, &tenant, refused).await),
    };

    let body: Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Err(ApiError::new(unreadable_body(), request_id)),
    };
    let body: CreateWorkspaceRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Err(ApiError::new(unreadable_body(), request_id)),
    };

    let settings = settings_from(&body).map_err(|error| ApiError::new(error, request_id))?;

    let record = match provision(&state, &ctx, &settings, created_by).await {
        Ok(record) => record,
        Err(ProvisionFailure::SlugTaken) => return Ok(slug_in_use().into_response(request_id)),
        Err(ProvisionFailure::Other(error)) => return Err(ApiError::new(error, request_id)),
    };

    // Resolved **after** the commit, and that ordering is the whole point of the response. The
    // authorization stage reads `acl_entries` over a pool of its own, so a capabilities object
    // computed inside the transaction above would be resolved against an ACL the resolver's
    // connection cannot see yet, and every field would come back `false` — a `201` telling the
    // creator they may do nothing with what they just made.
    //
    // With **no** obligations to subtract: `none_dischargeable` above refuses the request outright
    // unless the decision carried none, so the empty set is a property this path has established
    // rather than an omission here.
    let resource = ResourceRef::workspace(ctx.tenant_id, record.id);
    let (capabilities, reasons, wire) = capabilities_for_container(
        state.policy.authorization().as_ref(),
        &ctx,
        &resource,
        &Obligations::none(),
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, format!("/api/v1/workspaces/{}", record.id))],
        Json(WorkspaceView::new(&record, capabilities, reasons, wire)),
    )
        .into_response())
}

// ---------------------------------------------------------------------------------------------
// The pieces creation is made of
// ---------------------------------------------------------------------------------------------

/// The action `POST /workspaces` is decided by. See [`create`] for the argument.
const PROVISION: Action = Action::Admin(AdminAction::WriteConfig);

/// The rights the creating user is given on the workspace they just made.
///
/// The **whole** container vocabulary, and it is a founding grant rather than a role: there is no
/// `role_assignments` table to name a role in yet (`migrations/0004`), so the only durable place a
/// right can be written today is `acl_entries`, one action per row.
///
/// All six rather than a cautious subset, because every smaller set produces a workspace its
/// creator cannot finish setting up. Without `create` they cannot add the library that makes the
/// workspace useful; without `manage_permissions` they cannot let anybody else in, and — since
/// nothing else in the product writes an ACL entry on a workspace — the container would be
/// permanently single-occupant; without `delete` a mistyped slug is unrecoverable, because the slug
/// index only releases a name when the row holding it is trashed. This is the same set
/// `crates/api/tests/navigation.rs` asserts the resolver against action by action, and the spelling
/// each entry lands under is `Action`'s own `Display` — `container.read` — which
/// `enclave_authorization::grant` renders and `enclave_testing::content::grant` writes, so a grant
/// and the decision it is meant to permit cannot come to name different things.
///
/// It is a grant to the **user**, not to `EVERYONE` and not to a group. `Principal::everyone` on a
/// brand-new container would be the most permissive entry the schema can express, written by a
/// request that asked for nothing of the kind.
///
/// # Why the file half is here too, and why it is not all of it
///
/// The container vocabulary alone left the creator one step short in a way that would have read as
/// a bug in something else. `POST /uploads` enforces `Action::Container(ContainerAction::Create)`,
/// so an upload into a freshly provisioned workspace **succeeded**; `content::file_metadata`
/// enforces `Action::File(FileAction::MetadataRead)`, and `repo::acl_entries_by_action` matches
/// `a.action = ANY($2::text[])` — a literal string comparison with no implication from
/// `container.*` to `file.*`. So the founder could create the workspace, create the library, create
/// the folder, upload the file, and then get a `404` opening it. That is this repository's
/// signature failure moved down one level, and it is why the two halves are granted together.
///
/// The file half is the seeded owner's set (`crates/testing/src/content.rs`, and the rows a
/// `SELECT DISTINCT action FROM acl_entries` returns against the development fixture), plus
/// `restore` and `move`, which `ENC-807` added and which the seeded fixture predates.
///
/// **`restore` is here because `delete` is.** Granting one without the other makes the trash a
/// one-way door: a founder could trash a folder and the product would serve no request that brought
/// it back, forever, on every fresh install. It was excluded in the first draft of this grant on the
/// argument below — that a founding grant is an automatic act nobody reviewed and should be narrow —
/// and that argument is simply wrong about this action, because restoring is *less* dangerous than
/// the deletion already conferred. A narrow grant that removes a safety net is not narrow, it is
/// lopsided.
///
/// **`move` is here because `container.create` already is.** A founder holds `container.create`
/// across the workspace they provisioned, so every destination a move could reach inside it is one
/// they may already write to — and `PATCH /files/{id}` asks `container.create` of the destination
/// separately, so a move *out* of their reach is refused by that question rather than by this
/// omission. Withholding it bought nothing and left the founder unable to organise the tree they are
/// the only principal in. What it deliberately leaves out is as much
/// of the decision as what it includes: **`print`, `export`, `share_external`, `share`, `copy`,
/// `move`, `restore` and `version_restore` are not conferred.** `CLAUDE.md` rule 6 says preview,
/// download, print, export and sync are five permissions and never one, and a founding grant is an
/// automatic act nobody reviewed — the least appropriate place to hand out the ones that put
/// content outside the tenant. A founder who wants them holds `container.manage_permissions` and
/// can write them deliberately, which is the second act rule 6 exists to require.
///
/// This grant was, for one release, the *only* way any principal obtained access to a workspace:
/// `container.manage_permissions` was a right nothing could exercise, because no HTTP route wrote
/// an `acl_entries` row. `ENC-917` closed that — [`crate::routes::permissions`] is where a founder
/// now admits anybody else — which is what makes the narrowness above affordable. A founding grant
/// that withholds `print` and `share_external` is a sensible default when there is a second act
/// that can add them, and was a dead end when there was not.
const FOUNDING_GRANT: [Action; 15] = [
    Action::Container(ContainerAction::Read),
    Action::Container(ContainerAction::Create),
    Action::Container(ContainerAction::Update),
    Action::Container(ContainerAction::Delete),
    Action::Container(ContainerAction::ManageMembers),
    Action::Container(ContainerAction::ManagePermissions),
    Action::File(FileAction::MetadataRead),
    Action::File(FileAction::Preview),
    Action::File(FileAction::ContentRead),
    Action::File(FileAction::Download),
    Action::File(FileAction::Edit),
    Action::File(FileAction::Delete),
    Action::File(FileAction::Restore),
    Action::File(FileAction::Move),
    Action::File(FileAction::VersionRead),
];

/// The founding grant, as a value, so that one definition is both used and testable.
///
/// It was written inline in [`provision`] and asserted by a unit test that rebuilt the same literal
/// in its own body — which meant the test would have stayed green if `provision` had started
/// granting [`Principal::everyone`], the exact thing its name says it prevents. A test that
/// constructs its subject is a test about the test. This function is the subject.
fn founding_grant_for(workspace: WorkspaceId, created_by: UserId) -> Grant {
    Grant {
        resource: ChainNode::new(AclResourceType::Workspace, workspace.as_uuid()),
        principal: Principal::new(PrincipalKind::User, created_by.as_uuid()),
        effect: Effect::Allow,
        granted_by: created_by,
        // No expiry. A founding grant that lapsed would leave a workspace with an owner who has
        // become a stranger to it, and nothing in the product to notice.
        expires_at: None,
    }
}

/// What a failed provisioning was.
///
/// Two cases rather than one [`Error`], for [`crate::routes::folders`]'s reason: the collision is
/// the one this handler has to answer with a status [`Error`] cannot express.
enum ProvisionFailure {
    /// A live workspace in this tenant already holds the folded slug.
    SlugTaken,
    /// Anything else, already mapped onto the error type the API layer renders.
    Other(Error),
}

/// Opens one transaction, writes the workspace, grants the creator the container, commits.
///
/// Separate from the handler so that the atomicity [`create`] argues for is visible as a single
/// scope with one `commit` at the bottom, and so the `SlugTaken` interception is one `match` on a
/// two-variant type rather than a nested `if let` in the request path.
///
/// The grant is written through [`enclave_authorization::grant::grant`] rather than by an `INSERT`
/// here. That module exists precisely to stop this statement being re-derived at a call site: the
/// conflict target is an expression list, an `ALLOW` may not land on a `DENY`, `inherited_from` has
/// to be cleared, and duplicate actions abort the whole statement — five decisions that are silent
/// when they are wrong. It authorizes nothing, which is correct: [`create`] has already been through
/// `PolicyEngine::enforce`, and a second check here would be a second answer that could disagree
/// with the one that audited (`CLAUDE.md` rules 1 and 10).
///
/// `granted_by` is the creator themselves. `acl_entries.granted_by` carries no foreign key and is
/// checked by the grant engine against this tenant's `users`, so it has to name somebody real; the
/// person who provisioned the workspace is the honest answer, and the alternative — the nil UUID
/// that fixtures use — would put a row in the audit trail that no review could ever explain.
async fn provision(
    state: &ApiState,
    ctx: &RequestContext,
    settings: &WorkspaceSettings,
    created_by: UserId,
) -> Result<Workspace, ProvisionFailure> {
    // One clock for the row and for its ACL, so the entry can never be timestamped before the
    // resource it hangs on.
    let now = Utc::now();

    let mut tx =
        state.db.begin(ctx.tenant_id).await.map_err(|e| ProvisionFailure::Other(e.into()))?;

    let record = match WorkspaceRepository::create(
        &mut tx,
        ctx.tenant_id,
        settings,
        created_by,
        now,
    )
    .await
    {
        Ok(record) => record,
        // The transaction is dropped without committing. A refused insert has aborted it in any
        // case — `ENC-691`'s finding was that `COMMIT` on an aborted transaction *is* a
        // rollback, which is why nothing here relies on that and simply drops.
        Err(WorkspaceError::SlugTaken) => return Err(ProvisionFailure::SlugTaken),
        Err(error) => return Err(ProvisionFailure::Other(error.into())),
    };

    let founding = founding_grant_for(record.id, created_by);
    enclave_authorization::grant::grant(&mut tx, ctx.tenant_id, &founding, &FOUNDING_GRANT, now)
        .await
        .map_err(|error| ProvisionFailure::Other(error.into()))?;

    tx.commit().await.map_err(|e| ProvisionFailure::Other(e.into()))?;
    Ok(record)
}

/// Validates the request and turns it into the settings the repository stores.
///
/// Every rejection names a field and never its value (`CLAUDE.md` rule 10, and
/// `enclave_workspaces::error`'s note): a workspace name can carry organizational structure —
/// *Project Ravenwood — acquisition* — and a validation message is the shortest path from a value to
/// a log line.
///
/// The bounds are the ones the rest of the product already uses. 255 characters is
/// `enclave_files::normalize::MAX_NAME_CHARS`, adopted rather than re-chosen so that a name a folder
/// may carry is a name a workspace may carry. The slug's character class is narrower than the
/// column's — `workspaces.slug` is bare `TEXT` with only a uniqueness index over it — because
/// `docs/04-DATA-MODEL.md §7` calls it a *URL-safe short name* and a slug holding a slash or a space
/// is neither, whatever the column will accept.
///
/// # Errors
///
/// [`Error::Validation`] listing **every** offending field rather than the first, so a client
/// correcting a form is not made to submit it once per mistake.
fn settings_from(body: &CreateWorkspaceRequest) -> Result<WorkspaceSettings, Error> {
    let mut fields: Vec<FieldError> = Vec::new();

    let name = body.name.trim();
    if name.is_empty() {
        fields.push(FieldError::new("name", ValidationCode::Required));
    } else if name.chars().count() > MAX_NAME_CHARS {
        fields.push(FieldError::new("name", ValidationCode::TooLong));
    }

    // Folded first, so what is validated is what `WorkspaceRepository::create` will store and what
    // `uq_workspace_slug` will compare. Validating the raw value and storing the folded one is how
    // an accepted slug becomes a stored slug the caller cannot look up.
    let slug = normalize_slug(&body.slug);
    if slug.is_empty() {
        fields.push(FieldError::new("slug", ValidationCode::Required));
    } else if slug.chars().count() > MAX_SLUG_CHARS {
        fields.push(FieldError::new("slug", ValidationCode::TooLong));
    } else if !slug.chars().all(is_slug_char) {
        fields.push(FieldError::new("slug", ValidationCode::InvalidFormat));
    }

    // Absent is `PRIVATE`: the least discoverable member of the vocabulary. A default that widened
    // visibility would make an omitted field a disclosure, which is the wrong direction for a
    // field whose whole subject is who can see the thing.
    let visibility = match body.visibility.as_deref() {
        None => Some(Visibility::Private),
        Some(raw) => match raw.trim().parse::<Visibility>() {
            Ok(visibility) => Some(visibility),
            Err(_unknown) => {
                // `UNSUPPORTED` rather than `INVALID_FORMAT`: the value is well-formed text that
                // names a member this deployment's `CHECK` constraint does not have.
                fields.push(FieldError::new("visibility", ValidationCode::Unsupported));
                None
            }
        },
    };

    if !fields.is_empty() {
        return Err(Error::Validation(fields));
    }

    Ok(WorkspaceSettings {
        name: name.to_owned(),
        slug,
        // An empty description is no description. Storing `""` would put a value in the column that
        // renders as an empty paragraph in every client and reads as "somebody wrote nothing here".
        description: body
            .description
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned),
        visibility: visibility.unwrap_or(Visibility::Private),
        // Both `NULL`, meaning *inherit the tenant's*. See [`CreateWorkspaceRequest`] for why
        // neither is a field a client may send.
        default_classification_id: None,
        storage_profile_id: None,
    })
}

/// The longest workspace name this surface accepts, in characters rather than bytes.
///
/// `enclave_files::normalize::MAX_NAME_CHARS`'s value, adopted rather than re-chosen — see
/// [`settings_from`]. Counted in `chars` for that function's reason: a byte limit rejects a name in
/// Japanese at a third of the length of the same name in English.
const MAX_NAME_CHARS: usize = 255;

/// The longest slug this surface accepts. The same bound, for the same reason.
const MAX_SLUG_CHARS: usize = 255;

/// Whether one folded character may appear in a slug.
///
/// ASCII alphanumerics, `-` and `_`. Uppercase is absent because [`normalize_slug`] has already
/// lowercased, so an uppercase character reaching here is impossible rather than forbidden — and a
/// predicate that accepted it would quietly permit a spelling the index can never produce.
const fn is_slug_char(character: char) -> bool {
    character.is_ascii_lowercase()
        || character.is_ascii_digit()
        || character == '-'
        || character == '_'
}

/// The user a workspace is attributed to and granted to.
///
/// `workspaces.created_by` is a `NOT NULL` reference to a `users` row, and `acl_entries` can only
/// name a principal the tenant's directory holds — the same argument `routes::folders::author` and
/// `admin::dlp::author` make. In the composed binary this is unreachable, because
/// `AdminAuthorization` has already refused every actor that is not a `User` (its structural refusal
/// 2: `is_admin` is a column on `users`, and a principal the grant model cannot name is refused).
/// It is asserted here anyway, because a handler that depends on a *composition* for a property it
/// needs is a handler that breaks silently the day the composition changes.
///
/// A [`Refused`] rather than an [`Error`] because the chain has already allowed by the time this is
/// asked, so the refusal needs an audit row of its own (`ENC-606`).
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`].
fn founder(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        // A link bearer least of all (`ENC-879`): `Actor::subject_id` answers `Some` with a
        // `share_links.id`, which is a real row in the wrong table entirely.
        Actor::Guest(_)
        | Actor::ServiceAccount(_)
        | Actor::McpClient(_)
        | Actor::LinkBearer(_)
        | Actor::System => Err(Refused::actor(ReasonCode::AccessDenied)),
    }
}

/// `409`, per `docs/05-API.md §5`'s status table: "name collision".
///
/// `NAME_IN_USE` rather than a `SLUG_IN_USE` invented here. `§5`'s code vocabulary is published and
/// a client switches on it; adding a member is a documentation change, and this collision is the
/// same event the published code already names — the `details` entry is what says *which* field
/// collided, which is exactly what `§7`'s folder rule uses it for.
///
/// The status assertion is load-bearing in both directions. [`WorkspaceError::SlugTaken`] converts
/// to `Error::Validation`, which is a `400` — right for the four other conversions beside it and
/// wrong for this one — so a handler that let the blanket conversion run would answer `400`. Rather
/// than change a conversion other call sites depend on, this intercepts before it, on the precedent
/// `routes::folders::name_in_use` and `admin::dlp::write_failure` set.
///
/// The slug is **not** echoed back. The caller sent it, but a collision report is the one place a
/// workspace the caller has not been shown could be named to them — and on this endpoint that is
/// sharper than it is for a folder, because the refusal is proof that a live workspace in the tenant
/// holds exactly that slug.
fn slug_in_use() -> Envelope {
    Envelope::new(
        StatusCode::CONFLICT,
        "NAME_IN_USE",
        "A workspace in this tenant already uses that slug.",
        "Choose another slug, or trash the workspace that holds it.",
    )
    .with_details(vec![serde_json::json!({
        "field": "slug",
        "code": ValidationCode::NotUnique.as_str(),
    })])
}

/// `400` for a body that will not decode, inside `§5`'s envelope.
///
/// Built from [`Error::Validation`] rather than as a hand-rolled [`Envelope`] like
/// `routes::folders::unreadable_body`: the canonical conversion already renders
/// `VALIDATION_FAILED`, the `400`, and a `details` array, so the only thing a literal envelope would
/// add here is a fourth copy of two English sentences that could drift from the other three.
///
/// The serde error is deliberately dropped rather than reported. `serde_json`'s message quotes the
/// offending input, and an error path that echoes an unparsed request body is a log line containing
/// whatever the client sent (`CLAUDE.md` rule 10).
fn unreadable_body() -> Error {
    Error::Validation(vec![FieldError::new("body", ValidationCode::InvalidFormat)])
}

// ---------------------------------------------------------------------------------------------
// The pieces the container handlers share
// ---------------------------------------------------------------------------------------------

/// Trims a page of workspaces to the ones this caller may see, and answers what they may do.
///
/// One [`AuthorizationService::authorize_many`] call for the whole page — never a loop calling
/// `authorize` per row, which is what turns a tenant with five hundred workspaces into five hundred
/// ACL resolutions and what the batch form exists on the trait to prevent.
///
/// The trim's decision is not discarded once it has said yes. It *is* the decision that authorised
/// this row, so its obligations are what [`capabilities_for_containers`] subtracts for that row —
/// the same input [`read`] hands it from its own `container.read` decision. Re-resolving
/// `container.read` a second time to obtain them would be a second decision that could disagree
/// with the one the row was admitted by.
async fn readable_workspaces(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    workspaces: &[Workspace],
) -> Result<Vec<WorkspaceView>, Error> {
    if workspaces.is_empty() {
        return Ok(Vec::new());
    }

    let refs: Vec<ResourceRef> = workspaces
        .iter()
        .map(|workspace| ResourceRef::workspace(ctx.tenant_id, workspace.id))
        .collect();

    let admitted = admit(authorization, ctx, workspaces, refs).await?;
    let computed = capabilities_for_containers(
        authorization,
        ctx,
        &admitted
            .iter()
            .map(|(_, resource, obligations)| (*resource, obligations.clone()))
            .collect::<Vec<_>>(),
    )
    .await?;

    Ok(admitted
        .into_iter()
        .zip(computed)
        .map(|((workspace, _, _), (capabilities, reasons, wire))| {
            WorkspaceView::new(workspace, capabilities, reasons, wire)
        })
        .collect())
}

/// Runs the `container.read` trim over a page and returns the survivors with their obligations.
///
/// Generic over the record so that [`crate::routes::libraries`] runs the identical trim rather than
/// a second one that could drift. The `refs` argument is index-aligned with `records` by the
/// caller's construction, and both are consumed together so an edit cannot desynchronise them.
pub(crate) async fn admit<'a, T>(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    records: &'a [T],
    refs: Vec<ResourceRef>,
) -> Result<Vec<(&'a T, ResourceRef, Obligations)>, Error> {
    let decisions =
        authorization.authorize_many(ctx, Action::Container(ContainerAction::Read), &refs).await?;

    // Index-aligned with `refs` by contract. If an implementation ever returned a shorter vector,
    // `zip` drops the tail — which trims *more* than necessary rather than less, and a listing that
    // is too short is a bug while a listing that is too long is a disclosure.
    let mut admitted = Vec::with_capacity(records.len());
    for ((record, resource), decision) in records.iter().zip(refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        // Allowed, so this cannot be an `Err`; taking the obligations rather than dropping the
        // decision is what keeps a restriction attached to the read from evaporating between the
        // trim and the row it produces.
        admitted.push((record, resource, decision.ensure_allowed()?));
    }
    Ok(admitted)
}

/// Computes `capabilities` and `obligations` for one container — the batch form, with one input.
///
/// The whole body is the delegation, on the same reasoning `content::capabilities_for` gives: two
/// implementations of one question are how the singular form ends up answering something the batch
/// form does not. Here that would be a `GET /workspaces/{id}` offering an action the row for the
/// same workspace in the same caller's listing does not.
pub(crate) async fn capabilities_for_container(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    resource: &ResourceRef,
    enforced: &Obligations,
) -> Result<(ContainerCapabilities, CapabilityReasons, WireObligations), Error> {
    let batch = [(*resource, enforced.clone())];
    let mut computed = capabilities_for_containers(authorization, ctx, &batch).await?;
    match computed.pop() {
        Some(answer) => Ok(answer),
        // Unreachable: one input, one answer. If it ever stopped holding, the refusing object is the
        // safe one — a capability wrongly withheld costs a button, and the action itself is enforced
        // by the chain either way. The reasons object stays empty on this branch for `content.rs`'s
        // reason: nothing decided, so there is nothing to report and no reason to invent.
        None => Ok((
            ContainerCapabilities::default(),
            CapabilityReasons::default(),
            WireObligations::default(),
        )),
    }
}

/// Computes `capabilities` and `obligations` for a page of containers, in **one** resolution.
///
/// # Why the engine's own authorization stage
///
/// `docs/05-API.md §7`: *"`capabilities` is computed by the same policy engine that will enforce the
/// action — it is a UI hint derived from the real decision, not a parallel implementation."* It
/// arrives here as `state.policy.authorization()`: the very `Arc` the chain will consult when the
/// caller actually clicks *New library*.
///
/// That stage handle is also *all* this is given — not [`ApiState`]. A probe that could reach the
/// engine could call `enforce`, which is how a helper quietly becomes a second enforcement point the
/// `ENC-110` policy-routing lint does not check; a probe that could reach the pool could answer from
/// a query of its own. Narrowing the argument makes both impossible rather than discouraged, and it
/// is what lets the unit tests below drive this with a scripted stage instead of a database.
///
/// # The cost
///
/// `authorize_many_actions` batches actions as well as resources (`ENC-167`), so a page of any size
/// costs one resolution here — plus the trim's — whatever the page holds. `ENC-145` measured the
/// resolution's price as ~80% fixed: 1.4 ms for one candidate against 7.0 ms for two hundred. The
/// question is therefore asked once per page and never once per row, and what scales with the page
/// is the size of the `id = ANY($1)` array rather than the number of round trips.
///
/// # What it is not
///
/// Not the whole chain. Conditional access, classification, DLP and retention can each refuse an
/// action this reports as available, and the engine will refuse it when the action is attempted —
/// the correct failure direction for a hint, since an optimistic capability produces a refusal the
/// user can be told about while a pessimistic one hides a button they are entitled to.
///
/// # The obligations from the *enforced* decision are applied, not merely reported
///
/// `CLAUDE.md` rule 8. [`Obligation::ReadOnly`] suppresses every mutation, and the suppression runs
/// *after* the ACL answer, so an obligation can only ever take a capability away.
pub(crate) async fn capabilities_for_containers(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    admitted: &[(ResourceRef, Obligations)],
) -> Result<Vec<(ContainerCapabilities, CapabilityReasons, WireObligations)>, Error> {
    if admitted.is_empty() {
        return Ok(Vec::new());
    }

    // Paired in the argument rather than passed as two slices, so a resource and the obligations of
    // the decision that admitted it cannot be zipped out of step by an edit here.
    let resources: Vec<ResourceRef> = admitted.iter().map(|(resource, _)| *resource).collect();

    let mut computed: Vec<(ContainerCapabilities, CapabilityReasons, WireObligations)> = admitted
        .iter()
        .map(|(_, enforced)| {
            (
                // `read` is true by construction: nothing reaches this function that the
                // `container.read` decision above did not admit.
                ContainerCapabilities { read: true, ..ContainerCapabilities::default() },
                CapabilityReasons::default(),
                WireObligations {
                    watermark: enforced.contains(&Obligation::Watermark),
                    ..WireObligations::default()
                },
            )
        })
        .collect();

    let actions: Vec<Action> =
        CONTAINER_ACTIONS.iter().map(|(_, action)| Action::Container(*action)).collect();
    let grid = authorization.authorize_many_actions(ctx, &actions, &resources).await?;

    // Index-aligned with `actions`, which is index-aligned with `CONTAINER_ACTIONS`. A short outer
    // vector leaves the tail *actions* unanswered and a short inner one leaves the tail *rows*
    // unanswered; both withhold a capability rather than offering one that will be refused, which is
    // the direction an absent verdict has to fail in.
    for ((name, action), decisions) in CONTAINER_ACTIONS.iter().zip(grid) {
        for ((capabilities, reasons, wire), decision) in computed.iter_mut().zip(decisions) {
            if !decision.is_allowed() {
                // `ENC-674`, and the container half is the one the shipped client actually renders:
                // the library Upload control reads `capabilities.create`, and until this line the
                // only explanation available to it was one the client wrote itself.
                if let StageOutcome::Deny(code) = decision.outcome() {
                    reasons.withheld(name, *code);
                }
                continue;
            }
            // The stage allowed, so this cannot be an `Err`; taking the obligations rather than
            // discarding the decision is what keeps a `RequireJustification` from evaporating.
            let attached = decision.ensure_allowed()?;
            if attached.contains(&Obligation::RequireJustification) {
                wire.justification_required.push(name);
            }
            if attached.contains(&Obligation::RequireApproval) {
                wire.approval_required.push(name);
            }
            if attached.contains(&Obligation::Watermark) {
                wire.watermark = true;
            }
            set_capability(capabilities, *action);
        }
    }

    for ((capabilities, reasons, _), (_, enforced)) in computed.iter_mut().zip(admitted) {
        apply_obligations(capabilities, reasons, enforced);
    }
    Ok(computed)
}

/// Sets the field one action answers to.
///
/// Exhaustive over [`ContainerAction`] on purpose: the enum is deliberately not `#[non_exhaustive]`
/// (`crates/core/src/action.rs`), so a new container operation breaks this match and forces someone
/// to decide whether the UI may offer it, rather than inheriting a silent `false`.
fn set_capability(capabilities: &mut ContainerCapabilities, action: ContainerAction) {
    match action {
        ContainerAction::Read => capabilities.read = true,
        ContainerAction::Create => capabilities.create = true,
        ContainerAction::Update => capabilities.update = true,
        ContainerAction::Delete => capabilities.delete = true,
        ContainerAction::ManageMembers => capabilities.manage_members = true,
        ContainerAction::ManagePermissions => capabilities.manage_permissions = true,
    }
}

/// Subtracts from `capabilities` whatever the enforced decision's obligations forbid.
///
/// Only ever subtracts. An obligation is a restriction a stage attached to an *allow*, and one that
/// could add a capability would be a stage granting access outside the authorization stage.
fn apply_obligations(
    capabilities: &mut ContainerCapabilities,
    reasons: &mut CapabilityReasons,
    obligations: &Obligations,
) {
    /// Turns one container capability off and records why, but only if it was on.
    ///
    /// `content::withdraw`'s reasoning exactly: a capability already `false` here was refused by the
    /// ACL and carries that stage's code, and overwriting it would report an obligation taking away
    /// something the caller never had.
    fn withdraw(
        field: &mut bool,
        reasons: &mut CapabilityReasons,
        capability: &'static str,
        code: ReasonCode,
    ) {
        if *field {
            *field = false;
            reasons.withheld(capability, code);
        }
    }

    for obligation in obligations {
        match obligation {
            // "Suppress every mutation path in the response" (`crates/core/src/policy.rs`). On a
            // container that is all five of the non-read actions: creating a library in a workspace
            // is as much a write as renaming it.
            //
            // `ACCESS_DENIED` on all five, and it is the same weak answer `content.rs` records:
            // the published vocabulary has no code for *readable but not writable*. `ENC-895`.
            Obligation::ReadOnly => {
                let code = ReasonCode::AccessDenied;
                withdraw(&mut capabilities.create, reasons, "create", code);
                withdraw(&mut capabilities.update, reasons, "update", code);
                withdraw(&mut capabilities.delete, reasons, "delete", code);
                withdraw(&mut capabilities.manage_members, reasons, "manageMembers", code);
                withdraw(&mut capabilities.manage_permissions, reasons, "managePermissions", code);
            }
            // Both are restrictions on *content*, and a container carries none. They are listed
            // rather than swept into a catch-all so that the reasoning is visible: neither can be
            // satisfied or violated by a name and a revision counter, and neither has a container
            // capability it could plausibly suppress.
            Obligation::NoDownload | Obligation::NoSync => {}
            // Reported in `obligations` for the client to satisfy; reclassification belongs to the
            // classification path.
            Obligation::Watermark
            | Obligation::RequireJustification
            | Obligation::RequireApproval
            | Obligation::Reclassify { .. } => {}
        }
    }
}

/// The caller's own `users` row, as a resource reference.
///
/// A service account or an MCP client has no `users` row, so it is not a principal a personal
/// enumeration can be about. Rather than enforce on a fabricated reference, those callers are
/// refused with the same `404` an unknown workspace gets: the endpoint has no answer for them and
/// saying so more precisely would describe the actor model to an unauthenticated guess.
fn self_resource(ctx: &RequestContext, request_id: RequestId) -> Result<ResourceRef, ApiError> {
    match ctx.actor {
        enclave_core::Actor::User(user) => Ok(ResourceRef::user(ctx.tenant_id, user)),
        _ => Err(ApiError::new(Error::NotFound, request_id)),
    }
}

/// Renders an `ACCESS_DENIED` denial on a container read path as [`Error::NotFound`].
///
/// The one place `CLAUDE.md` rule 7's `403`/`404` decision is made for these four endpoints, so they
/// cannot answer it four ways. `content::existence_gate` is the same function for the file surface;
/// they are separate because the two modules are separate compilation concerns and neither exports
/// it, and the duplication is two lines of `match` rather than two policies.
pub(crate) fn conceal(error: Error) -> Error {
    match error {
        Error::PolicyDenied { code: ReasonCode::AccessDenied, .. } => Error::NotFound,
        other => other,
    }
}

/// Consumes a [`PolicyDecision`], yielding the obligations the caller now has to satisfy.
///
/// A named function rather than an inline `.into_obligations()` so that "the decision was looked at"
/// is a call a reader can find, and so the `#[must_use]` on [`PolicyDecision`] is discharged in one
/// place per module.
pub(crate) fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

/// Parses and clamps `?limit=`.
///
/// Clamped, not rejected (`crates/db/src/cursor.rs`): a client asking for a million rows wants as
/// many as it can have, and `docs/05-API.md §6` fixes the ceiling at 500. Only an unparseable value
/// is a client error, because that one is a bug rather than an appetite.
pub(crate) fn page_size(raw: Option<&str>, request_id: RequestId) -> Result<PageSize, ApiError> {
    match raw {
        None => Ok(PageSize::DEFAULT),
        Some(text) => text.trim().parse::<u32>().map(PageSize::new).map_err(|_| {
            ApiError::new(
                Error::Validation(vec![FieldError::new("limit", ValidationCode::InvalidFormat)]),
                request_id,
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use enclave_core::{Remediation, StageDecision, TenantId};
    use uuid::Uuid;

    use super::*;

    /// An authorization stage that answers from a table, and counts how often it is asked.
    ///
    /// Two things need a stage that can be *told* what to say. One is a page whose rows differ: a
    /// listing where every row resolves the same way passes whether the batch is keyed by resource
    /// or ignores the resource entirely, so the interesting fixture is two rows with two answers.
    /// The other is the call count — "one resolution per page, not per row" is a claim about the
    /// number of calls that no assertion about the returned JSON can make.
    #[derive(Debug)]
    struct Scripted {
        allowed: Vec<(Uuid, ContainerAction)>,
        calls: AtomicUsize,
    }

    impl Scripted {
        fn new(allowed: Vec<(Uuid, ContainerAction)>) -> Self {
            Self { allowed, calls: AtomicUsize::new(0) }
        }
    }

    #[async_trait]
    impl AuthorizationService for Scripted {
        async fn authorize(
            &self,
            ctx: &RequestContext,
            action: Action,
            resource: &ResourceRef,
        ) -> Result<StageDecision, Error> {
            let mut decisions =
                self.authorize_many(ctx, action, core::slice::from_ref(resource)).await?;
            Ok(decisions.pop().unwrap_or_else(|| StageDecision::deny(ReasonCode::AccessDenied)))
        }

        async fn authorize_many(
            &self,
            _ctx: &RequestContext,
            action: Action,
            resources: &[ResourceRef],
        ) -> Result<Vec<StageDecision>, Error> {
            let _previous = self.calls.fetch_add(1, Ordering::Relaxed);
            let Action::Container(action) = action else {
                panic!("a container probe asks only container actions, not {action}")
            };
            Ok(resources
                .iter()
                .map(|resource| {
                    if self.allowed.contains(&(resource.id, action)) {
                        StageDecision::allow()
                    } else {
                        StageDecision::deny(ReasonCode::AccessDenied)
                    }
                })
                .collect())
        }
    }

    fn probe_context() -> RequestContext {
        RequestContext::system(TenantId::new_v7())
    }

    /// The object as it would reach the wire, so comparisons are of rendered JSON rather than of a
    /// struct whose fields a future edit might add to unnoticed.
    fn rendered(
        answer: &(ContainerCapabilities, CapabilityReasons, WireObligations),
    ) -> serde_json::Value {
        serde_json::json!({
            "capabilities": answer.0,
            "capabilityReasons": answer.1,
            "obligations": answer.2,
        })
    }

    #[tokio::test]
    async fn rows_in_one_page_get_the_answers_their_own_grants_give() {
        // The failure this catches is a batch that resolves once and copies the verdict across the
        // page — cheap, plausible, and it hands every row the first row's permissions.
        let ctx = probe_context();
        let creatable = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let administrable = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let neither = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let authorization = Scripted::new(vec![
            (creatable.id, ContainerAction::Create),
            (administrable.id, ContainerAction::ManageMembers),
            (administrable.id, ContainerAction::Delete),
        ]);

        let admitted = [
            (creatable, Obligations::none()),
            (administrable, Obligations::none()),
            (neither, Obligations::none()),
        ];
        let computed =
            capabilities_for_containers(&authorization, &ctx, &admitted).await.expect("probe");

        assert_eq!(computed.len(), 3);
        assert!(computed[0].0.create && !computed[0].0.manage_members);
        assert!(computed[1].0.manage_members && computed[1].0.delete && !computed[1].0.create);
        assert!(!computed[2].0.create && !computed[2].0.delete && !computed[2].0.manage_members);
        // Every row survived the trim to get here, so every row can be read — and that is the only
        // field the three have in common.
        assert!(computed.iter().all(|(capabilities, _, _)| capabilities.read));
        // …and no row carries a reason for `read`: it was never withheld, so a reason for it would
        // be a refusal the server never made (`ENC-674`).
        assert!(computed.iter().all(|(_, reasons, _)| reasons.get("read").is_none()));
        // The positive control for the line above. Every row refuses *something* — the fixture is
        // three rows with three different grants — so an empty reasons object anywhere here would
        // mean the codes are not being recorded at all rather than correctly withheld.
        assert!(computed.iter().all(|(_, reasons, _)| reasons.len() > 0));
        assert_eq!(computed[2].1.get("create"), Some(ReasonCode::AccessDenied));
    }

    #[tokio::test]
    async fn a_row_answers_exactly_as_the_same_container_asked_for_alone() {
        // The property `GET /workspaces/{id}` and `GET /workspaces` are held to over HTTP, asserted
        // here at the function both go through — including the middle of a page, where an off-by-one
        // in the zip would show up as a neighbour's answer.
        let ctx = probe_context();
        let subject = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let before = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let after = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let authorization = Scripted::new(vec![
            (subject.id, ContainerAction::Create),
            (subject.id, ContainerAction::Update),
            (before.id, ContainerAction::Delete),
            (after.id, ContainerAction::ManagePermissions),
        ]);

        let alone =
            capabilities_for_container(&authorization, &ctx, &subject, &Obligations::none())
                .await
                .expect("one");
        let page = capabilities_for_containers(
            &authorization,
            &ctx,
            &[
                (before, Obligations::none()),
                (subject, Obligations::none()),
                (after, Obligations::none()),
            ],
        )
        .await
        .expect("page");

        assert_eq!(rendered(&page[1]), rendered(&alone));
        assert_ne!(rendered(&page[0]), rendered(&alone), "the fixture must not be uniform");
    }

    #[tokio::test]
    async fn a_read_only_obligation_takes_every_mutation_away_and_does_not_reach_a_neighbour() {
        // Obligations arrive per row, from the decision that admitted that row. Applying them to the
        // page would suppress a capability its caller holds; applying none would drop a restriction.
        // Both are visible here as the difference between the two rows.
        let ctx = probe_context();
        let restricted = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let unrestricted = ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7());
        let authorization = Scripted::new(vec![
            (restricted.id, ContainerAction::Create),
            (restricted.id, ContainerAction::Update),
            (unrestricted.id, ContainerAction::Create),
            (unrestricted.id, ContainerAction::Update),
        ]);

        let computed = capabilities_for_containers(
            &authorization,
            &ctx,
            &[
                (restricted, Obligations::from_iter([Obligation::ReadOnly, Obligation::Watermark])),
                (unrestricted, Obligations::none()),
            ],
        )
        .await
        .expect("probe");

        assert!(!computed[0].0.create && !computed[0].0.update, "ReadOnly must suppress writes");
        assert!(
            computed[0].0.read,
            "ReadOnly suppresses mutations, never the read that carried it"
        );
        assert!(computed[0].2.watermark);
        assert!(computed[1].0.create, "a neighbour's obligation took a capability away");
        assert!(!computed[1].2.watermark);
        // The reason travels per row exactly as the obligation does (`ENC-674`). The neighbour
        // holds `create`, so it carries no reason for it — a reason on a capability the caller has
        // would render a refusal that never happened.
        assert_eq!(computed[0].1.get("create"), Some(ReasonCode::AccessDenied));
        assert_eq!(computed[1].1.get("create"), None);
        assert!(computed[0].1.get("read").is_none(), "the read that carried the obligation");
    }

    #[tokio::test]
    async fn a_page_costs_the_same_resolution_however_many_rows_it_holds() {
        // The reason capabilities are affordable on a listing at all. `ENC-145` puts a resolution's
        // cost at ~80% fixed, so a per-row loop over two hundred workspaces would be two hundred
        // resolutions of which 160 rows' worth is pure setup.
        //
        // What this counts is `Scripted`'s `authorize_many`, and `Scripted` does not override
        // `authorize_many_actions` — so it gets the trait's default body, which loops over actions.
        // That is deliberate and worth stating plainly: this proves the count does not scale with
        // the *page*, which is the API layer's responsibility. It cannot prove the count does not
        // scale with the number of *actions*; that belongs to `PgAclAuthorization`'s override and is
        // measured in `crates/authorization/tests/authorize_many_cost.rs`.
        let ctx = probe_context();
        let page: Vec<(ResourceRef, Obligations)> = (0..200)
            .map(|_| {
                (ResourceRef::workspace(ctx.tenant_id, WorkspaceId::new_v7()), Obligations::none())
            })
            .collect();
        let authorization = Scripted::new(Vec::new());

        let computed =
            capabilities_for_containers(&authorization, &ctx, &page).await.expect("probe");

        assert_eq!(computed.len(), 200);
        assert_eq!(
            authorization.calls.load(Ordering::Relaxed),
            CONTAINER_ACTIONS.len(),
            "the probe asked once per action; a per-row loop would be 200 times that"
        );
    }

    #[test]
    fn an_access_denied_denial_becomes_a_not_found_and_nothing_else_does() {
        // Rule 7 in one assertion, plus the half that is easy to over-apply: a `PREVIEW_ONLY` or a
        // `STEP_UP_REQUIRED` on a container read keeps its own status, because reaching a
        // post-authorization stage means the caller already holds a grant and has already been told
        // the resource exists.
        assert!(matches!(conceal(Error::denied(ReasonCode::AccessDenied)), Error::NotFound));
        assert!(matches!(
            conceal(Error::denied(ReasonCode::StepUpRequired)),
            Error::PolicyDenied { code: ReasonCode::StepUpRequired, .. }
        ));
        assert!(matches!(conceal(Error::NotFound), Error::NotFound));
    }

    #[test]
    fn a_limit_is_clamped_and_only_a_malformed_one_is_refused() {
        let id = RequestId::new_v7();
        assert_eq!(page_size(None, id).expect("default").get(), 50);
        assert_eq!(page_size(Some("10"), id).expect("ten").get(), 10);
        assert_eq!(page_size(Some("100000"), id).expect("clamped").get(), 500);
        assert_eq!(page_size(Some("0"), id).expect("clamped up").get(), 1);
        let refused = page_size(Some("abc"), id).expect_err("a malformed limit is a 400");
        assert!(matches!(refused.error(), Error::Validation(fields) if fields[0].field == "limit"));
    }

    /// A denial carries no remediation the caller could mine for the resource's existence.
    #[test]
    fn concealment_drops_the_remediation_with_the_status() {
        let denial = Error::denied_with(ReasonCode::AccessDenied, Remediation::RequestAccess);
        assert!(matches!(conceal(denial), Error::NotFound));
    }

    // -----------------------------------------------------------------------------------------
    // Creation
    // -----------------------------------------------------------------------------------------

    /// A request body with the required two fields and nothing else.
    fn minimal(name: &str, slug: &str) -> CreateWorkspaceRequest {
        CreateWorkspaceRequest {
            name: name.to_owned(),
            slug: slug.to_owned(),
            description: None,
            visibility: None,
        }
    }

    /// The founding grant covers every action the response then reports on, and one more.
    ///
    /// Two lists that must agree: [`CONTAINER_ACTIONS`] is what `capabilities` resolves, and
    /// [`FOUNDING_GRANT`] is what the creator is given. If a container operation is added to the
    /// vocabulary and only one of them is updated, the endpoint starts answering `201` with a
    /// capability the creator does not hold — a button the chain will refuse. Asserted over both
    /// arrays rather than by reading either, so the drift is what fails.
    ///
    /// `container.read` is the "one more": [`CONTAINER_ACTIONS`] omits it because
    /// [`capabilities_for_containers`] sets `read` by construction on a row that survived the trim,
    /// and a creator who was never granted it would not survive that trim at all.
    #[test]
    fn the_founding_grant_covers_every_capability_the_response_reports() {
        assert!(
            FOUNDING_GRANT.contains(&Action::Container(ContainerAction::Read)),
            "without container.read the creator cannot open what they just made"
        );
        for (name, action) in CONTAINER_ACTIONS {
            assert!(
                FOUNDING_GRANT.contains(&Action::Container(*action)),
                "capabilities reports `{name}` but the creator is never granted it"
            );
        }
        let containers =
            FOUNDING_GRANT.iter().filter(|a| matches!(a, Action::Container(_))).count();
        assert_eq!(
            containers,
            CONTAINER_ACTIONS.len() + 1,
            "the container half of the founding grant must be the container vocabulary and \
             nothing wider"
        );
    }

    /// The founding grant confers no permission that puts content outside the tenant.
    ///
    /// `CLAUDE.md` rule 6: preview, download, print, export and sync are five permissions and never
    /// one. The file half of [`FOUNDING_GRANT`] exists so that a creator can open the file they
    /// just uploaded — not so that provisioning becomes a way to acquire the rights rule 6 exists
    /// to keep separate. This is the assertion that keeps the next person from widening it by one
    /// convenient variant: adding `print` here would make every provisioning an unreviewed grant of
    /// a delivery path, and `share_external` would make it a grant of egress.
    ///
    /// Written as a deny-list over the exact variants rather than a count, because a count fails
    /// for the wrong reason — it also fails when something harmless is added — and tells whoever
    /// reads it nothing about which line crossed which rule.
    #[test]
    fn the_founding_grant_confers_no_egress_and_no_external_sharing() {
        // `Move` and `Restore` were on this list until `ENC-807` and are deliberately off it now.
        // Neither puts content outside the tenant, which is what this assertion is about: `restore`
        // is strictly less dangerous than the `delete` this grant already confers, and withholding
        // it made the trash a one-way door on every fresh install; `move` reaches only destinations
        // the founder already holds `container.create` on, and a move beyond them is refused by
        // `PATCH /files/{id}`'s separate question about the destination rather than by an omission
        // here. What stays on the list is the set that either exports content or hands rights to
        // somebody else.
        for forbidden in [
            FileAction::Print,
            FileAction::Export,
            FileAction::Share,
            FileAction::ShareExternal,
            FileAction::Sync,
            FileAction::Copy,
            FileAction::VersionRestore,
            FileAction::ManagePermissions,
        ] {
            assert!(
                !FOUNDING_GRANT.contains(&Action::File(forbidden)),
                "provisioning a workspace must not confer `file.{}` without a second, deliberate \
                 act (CLAUDE.md rule 6)",
                forbidden.as_str()
            );
        }
    }

    /// The grant is written for the creator alone, and it never reaches `EVERYONE`.
    ///
    /// The failure this catches is not a typo. `Principal::everyone` is one call away and is the
    /// most permissive entry `acl_entries` can hold; a provisioning path that reached for it would
    /// make every new workspace tenant-readable from the instant it existed, and nothing on the
    /// wire would say so — `capabilities` would look identical to the creator.
    #[test]
    fn the_founding_grant_names_the_creator_and_not_everyone() {
        let user = UserId::new_v7();
        let workspace = WorkspaceId::new_v7();
        // The value `provision` actually writes, not a copy of it assembled here.
        let founding = founding_grant_for(workspace, user);

        assert_eq!(founding.principal.kind, PrincipalKind::User);
        assert_eq!(founding.principal.id, Some(user.as_uuid()));
        assert_ne!(founding.principal, Principal::everyone());
        assert_eq!(founding.resource.kind, AclResourceType::Workspace);
        assert_eq!(founding.effect, Effect::Allow);
        assert!(founding.expires_at.is_none(), "a founding grant that lapses orphans a workspace");
    }

    /// An omitted `visibility` is the least discoverable member, never the most.
    ///
    /// The positive control is the explicit `TENANT_VISIBLE`: without it this would pass against an
    /// implementation that ignored the field entirely and hard-coded `PRIVATE`.
    #[test]
    fn an_omitted_visibility_defaults_to_private() {
        let settings = settings_from(&minimal("Engineering", "engineering")).expect("valid");
        assert_eq!(settings.visibility, Visibility::Private);

        let mut body = minimal("Engineering", "engineering");
        body.visibility = Some("TENANT_VISIBLE".to_owned());
        let settings = settings_from(&body).expect("valid");
        assert_eq!(settings.visibility, Visibility::TenantVisible);
    }

    /// A visibility outside the `CHECK` constraint's vocabulary is a field-level `400`.
    ///
    /// Not a `500` from the insert and not a serde rejection: both would leave the caller outside
    /// `docs/05-API.md §5`'s envelope, and the second would do it before this handler ran at all.
    #[test]
    fn an_unknown_visibility_names_the_field_it_came_from() {
        let mut body = minimal("Engineering", "engineering");
        body.visibility = Some("PUBLIC".to_owned());

        match settings_from(&body).expect_err("PUBLIC is not a member") {
            Error::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "visibility");
                assert_eq!(fields[0].code, ValidationCode::Unsupported);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    /// The slug that is validated is the slug that is stored.
    ///
    /// `WorkspaceRepository::create` folds through `normalize_slug` on the way in, so a handler that
    /// validated the raw value would accept ` Engineering ` and store `engineering` — and the
    /// caller's own `GET` by slug would then miss the row they just made.
    #[test]
    fn the_slug_is_folded_before_it_is_validated_and_stored() {
        let settings = settings_from(&minimal("Engineering", "  Engineering  ")).expect("valid");
        assert_eq!(settings.slug, "engineering");
        assert_eq!(settings.name, "Engineering", "the display name keeps its case");
    }

    /// Every offending field is reported, not the first one.
    ///
    /// A form corrected one refusal at a time is a form submitted four times, and each submission
    /// of *this* one is a write attempt against the tenant's workspace table.
    #[test]
    fn a_request_that_is_wrong_twice_is_told_about_both() {
        let mut body = minimal("   ", "not a slug");
        body.visibility = Some("PUBLIC".to_owned());

        match settings_from(&body).expect_err("three bad fields") {
            Error::Validation(fields) => {
                let named: Vec<&str> = fields.iter().map(|field| field.field.as_str()).collect();
                assert!(named.contains(&"name"), "{named:?}");
                assert!(named.contains(&"slug"), "{named:?}");
                assert!(named.contains(&"visibility"), "{named:?}");
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    /// A slug that is not URL-safe is refused, and the ones that are stay accepted.
    ///
    /// The accepted half is the control: a predicate that refused everything would satisfy every
    /// rejection below while making the endpoint unusable.
    #[test]
    fn a_slug_must_be_url_safe() {
        for accepted in ["engineering", "eng-2026", "eng_2026", "a", "0"] {
            assert!(
                settings_from(&minimal("Name", accepted)).is_ok(),
                "`{accepted}` is URL-safe and must be accepted"
            );
        }
        for refused in ["eng ineering", "eng/ineering", "eng.ineering", "engineering?", "eñe", ""]
        {
            let error = settings_from(&minimal("Name", refused)).expect_err("not a URL-safe slug");
            assert!(
                matches!(error, Error::Validation(ref fields) if fields[0].field == "slug"),
                "`{refused}` must be refused as a slug, got {error:?}"
            );
        }
    }

    /// A name at the bound is accepted and one character past it is not.
    ///
    /// Counted in `chars`: the multi-byte input is what stops the bound being re-implemented as a
    /// byte length, which would refuse a Japanese name at a third of the permitted length.
    #[test]
    fn a_name_is_bounded_in_characters_and_not_in_bytes() {
        let at_limit = "é".repeat(MAX_NAME_CHARS);
        assert!(at_limit.len() > MAX_NAME_CHARS, "the input must be multi-byte to prove anything");
        assert!(settings_from(&minimal(&at_limit, "slug")).is_ok());

        let over = "é".repeat(MAX_NAME_CHARS + 1);
        match settings_from(&minimal(&over, "slug")).expect_err("one character too long") {
            Error::Validation(fields) => {
                assert_eq!(fields[0].field, "name");
                assert_eq!(fields[0].code, ValidationCode::TooLong);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    /// An empty description is stored as absent, and a real one survives trimming.
    #[test]
    fn an_empty_description_is_no_description() {
        let mut body = minimal("Engineering", "engineering");
        body.description = Some("   ".to_owned());
        assert!(settings_from(&body).expect("valid").description.is_none());

        body.description = Some("  Platform and infrastructure  ".to_owned());
        assert_eq!(
            settings_from(&body).expect("valid").description.as_deref(),
            Some("Platform and infrastructure")
        );
    }

    /// A create never sets the two references [`WorkspaceView`] refuses to return.
    ///
    /// A field a caller can write and can never read back is a field they cannot correct. Asserted
    /// over the settings rather than by reading [`CreateWorkspaceRequest`], so adding either as a
    /// body field fails here rather than shipping.
    #[test]
    fn a_create_pins_neither_a_classification_nor_a_storage_profile() {
        let settings = settings_from(&minimal("Engineering", "engineering")).expect("valid");
        assert!(settings.default_classification_id.is_none());
        assert!(settings.storage_profile_id.is_none());
    }

    /// A taken slug is `409` and it does not echo the slug.
    ///
    /// The status is asserted because `WorkspaceError::SlugTaken`'s blanket conversion is a `400`,
    /// so a handler that let it run would answer `400` and this fails. The absence of the value is
    /// asserted because that conversion would not have leaked it either — without this assertion
    /// the interception could later start echoing the slug and nothing would notice.
    #[test]
    fn a_taken_slug_is_a_conflict_that_does_not_echo_the_slug() {
        let envelope = slug_in_use();
        assert_eq!(envelope.status(), StatusCode::CONFLICT);
        assert_eq!(envelope.code(), "NAME_IN_USE");

        let rendered = serde_json::to_string(envelope.details()).expect("render");
        assert!(rendered.contains("NOT_UNIQUE"), "the field diagnosis must survive: {rendered}");
        assert!(rendered.contains("slug"), "the details must say which field collided: {rendered}");
    }

    /// The provisioning action is administrative, and it is decided against the tenant.
    ///
    /// A single assertion, and it is the one that would catch the plausible wrong implementation:
    /// `Action::Container(ContainerAction::Create)` compiles, reads correctly, and is refused
    /// unconditionally by `service::classify`, so an endpoint written that way would be `403` for
    /// every caller in every deployment while looking principled. See [`create`].
    #[test]
    fn provisioning_is_an_administrative_action_and_not_a_container_one() {
        assert_eq!(PROVISION, Action::Admin(AdminAction::WriteConfig));
        assert!(!matches!(PROVISION, Action::Container(_)));
    }

    /// A body that will not decode is `400`, and the refusal quotes none of it.
    #[test]
    fn an_unreadable_body_names_the_body_and_repeats_none_of_it() {
        match unreadable_body() {
            Error::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "body");
                assert_eq!(fields[0].code, ValidationCode::InvalidFormat);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
        assert_eq!(unreadable_body().status_code(), 400);
    }
}
