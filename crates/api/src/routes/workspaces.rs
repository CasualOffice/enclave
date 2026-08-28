//! The workspace read paths — enumerate the containers a caller is in, and read one.
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

use axum::extract::{Path, Query, State};
use axum::Json;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, Error, FieldError, Obligation, Obligations,
    PolicyDecision, ReasonCode, RequestContext, RequestId, ResourceRef, StageOutcome,
    ValidationCode, WorkspaceId,
};
use enclave_workspaces::{PageSize, Visibility, Workspace, WorkspaceFilter, WorkspaceRepository};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, CapabilityReasons};
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
}
