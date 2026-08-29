//! The library endpoints — enumerate a workspace's libraries, read one, and create one.
//!
//! `docs/05-API.md §7.1` is authoritative for everything on the wire here; see
//! [`crate::routes::workspaces`] for why that section had to be written before this module could be
//! (`ENC-794`), and for the container vocabulary — the page envelope, the six capabilities, the
//! trim and the `404` gate — which is defined there once and used here rather than reimplemented.
//!
//! # Why these two endpoints exist
//!
//! `ENC-778`, the other half. `crates/libraries` had `list_by_workspace`, 1,820 lines, a full test
//! suite and no HTTP surface, so the only way a client could reach a library was to already know its
//! id: `GET /libraries/{id}/items` was registered and *nothing* that told you which id to pass. The
//! web shell's library picker was rendered as unbuilt for exactly this reason.
//!
//! # The two things this module decides that `workspaces.rs` does not
//!
//! **The workspace in the path is authorized, and the libraries under it are authorized again.**
//! `GET /workspaces/{id}/libraries` enforces `container.read` on the *workspace* — a caller who
//! cannot see the workspace must not learn how many libraries it holds, and must not be able to tell
//! that from a workspace that does not exist — and then trims each library with the same action. The
//! second pass is not redundant: a library may break inheritance
//! (`libraries.inherit_permissions = FALSE`, `docs/04-DATA-MODEL.md §9`), so a caller who may read
//! the workspace may be denied a library inside it, and only the per-row question can see that.
//! `crates/api/tests/navigation.rs` asserts precisely that case.
//!
//! **What a library's settings say on the wire.** A library is where policy is configured
//! (`docs/01-PRD.md §7`) and seventeen settings are stored. Eleven are here, chosen by one rule:
//! *does a client need it to decide what to offer?* Versioning, checkout and approval decide whether
//! an editor shows a check-out control; the extension lists and the size ceiling decide whether an
//! upload is worth starting; `externalSharing`, `syncEnabled` and `mcpVisible` are ceilings a client
//! must not present as available. The other six are absent and each absence is deliberate:
//! `defaultClassificationId`, `storageProfileId` and `retentionPolicyId` are internal references —
//! into the classification catalogue, into `docs/08-BYO-INFRA.md`'s storage profiles, into the
//! retention schedule — and a navigation response is not where a client learns which bucket a
//! tenant's content lands in; `inheritPermissions` describes the *shape* of the ACL rather than the
//! caller's position in it, and `capabilities` already answers the question a client has.
//!
//! **A ceiling is not a permission.** `externalSharing: "ANYONE"` says what the library permits at
//! most; whether *this* caller may share externally is `file.share_external` on the file, decided by
//! the chain at the moment they try. A client that read the ceiling as a grant would offer an action
//! the server refuses — which is the client-side re-derivation `CLAUDE.md` forbids, arrived at from
//! the other direction.
//!
//! # Why creation is here too, and why it is one field short of the record
//!
//! [`LibraryRepository::create`] has existed since M1 with **no caller in any binary**. The visible
//! consequence is the same shape `ENC-788` closed one container down: `POST /uploads` and
//! `POST /libraries/{id}/folders` both need a library to aim at, and nothing a client could call
//! made one — so every library in every deployment arrived by a hand-written `INSERT`, and a tenant
//! that had none had no way to obtain one. A library that only a DBA can create is a product with no
//! first step.
//!
//! **The question is `container.create` on the workspace**, resolved through the ordinary ACL path:
//! `classify` maps `ResourceKind::Workspace` onto `Target::Workspace`, so the workspace's own
//! entries decide, and a resource that does not exist yet has no ACL that could. [`create`] is
//! therefore the same shape as [`crate::routes::folders::create`] one level up the tree, down to
//! [`conceal`] and the `404`-not-`403` discipline, and it is deliberately written to read like it.
//!
//! **The new library inherits, and that is what makes it reachable.** `LIBRARY_CHAIN_SQL`
//! (`crates/authorization/src/repo.rs`) walks a library to its workspace exactly when
//! `libraries.inherit_permissions` is `TRUE`, so a library created with the flag set is governed by
//! the workspace grant that authorized its creation — the caller can browse it, and upload into it,
//! without a second ACL write. Creating one detached would produce a library with an empty chain:
//! every question about it refused, including the caller's own, which is a `201` for a container
//! nobody can open. There is consequently no `inheritPermissions` field on the request, for
//! `ENC-141`'s reason as much as this one — breaking inheritance has to copy the effective entries
//! down in the same transaction or every ancestor `DENY` stops applying, and that is
//! `enclave_authorization::break_library_inheritance`, asked separately.
//!
//! **The body carries two of the seventeen settings.** `name` and `slug`; everything else takes the
//! column's own default where `migrations/0004` states one, and an argued choice where it does not.
//! A create that accepted all seventeen would let one `container.create` grant provision a library at
//! `externalSharing: "ANYONE"` with `mcpVisible` and `syncEnabled` on, in a single unreviewed
//! request — the ceilings that decide what leaves the tenant, set by the one grant that is about
//! nothing but making a container. Changing them afterwards is a settings replacement under
//! `If-Match`, which is a different question with a different audit row. See [`default_settings`]
//! for the two columns the schema declines to choose for, and what this route chooses instead.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestExt as _};
use chrono::Utc;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, Error, FieldError, LibraryId, Obligation,
    Obligations, RequestContext, ResourceRef, ValidationCode, WorkspaceId,
};
use enclave_db::DbError;
use enclave_libraries::{
    normalize_slug, ExternalSharing, Library, LibraryError, LibraryFilter, LibraryRepository,
    LibrarySettings, VersioningMode,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, CapabilityReasons, Envelope};
use crate::refusal::Refused;
use crate::routes::workspaces::{
    admit, capabilities_for_container, capabilities_for_containers, conceal, consume, page_size,
    ContainerCapabilities, ListParams, Page, PageInfo, WireObligations,
};
use crate::state::ApiState;

/// The ceiling on a library's display name, borrowed from the file tree's rather than chosen again.
///
/// `libraries.name` is an unconstrained `text` column, so the bound has to come from somewhere, and
/// a second number invented here would be a second answer to "how long may a thing in this product
/// be called" — one that a user meets as an inconsistency the first time a folder accepts a name a
/// library refuses. `enclave_files::MAX_NAME_CHARS` is that number, and it is 255 because that is
/// what every filesystem a synced copy might land on accepts.
const MAX_NAME_CHARS: usize = enclave_files::MAX_NAME_CHARS;

/// The unique index a slug collision surfaces from
/// (`migrations/0017_slug_uniqueness.sql`, `ENC-544`).
///
/// Matched by name rather than by SQLSTATE alone: `23505` on this insert could in principle come
/// from the primary key or from `libraries_tenant_id_id_key`, and a duplicate UUIDv7 is a `500`
/// rather than a `409` — telling a caller their *slug* was taken when the id collided would send
/// them to rename something that is not the problem.
const LIVE_SLUG_INDEX: &str = "uq_library_slug";

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// One library, as `GET /workspaces/{id}/libraries` and `GET /libraries/{id}` render it.
///
/// One type for both, for the reason `WorkspaceView` gives: a row and the resource it links to that
/// answered differently would make a UI change its mind about what a user may do purely because they
/// clicked into it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryView {
    id: String,
    /// The workspace it belongs to. Immutable — moving a library changes what it inherits from — so
    /// a client may cache the pair.
    workspace_id: String,
    name: String,
    slug: String,
    /// The optimistic-concurrency counter `docs/05-API.md §9` puts on the wire as the `ETag`.
    revision: i64,
    /// The settings a client needs to decide what to offer. See the module documentation for the
    /// six that are deliberately absent.
    settings: LibrarySettingsView,
    /// What this caller may attempt on the library itself, from the stage that will decide it.
    /// Actions on the *content* are on each item (`GET /libraries/{id}/items`).
    capabilities: ContainerCapabilities,
    /// Why each `false` above is `false` (`ENC-674`). See [`CapabilityReasons`].
    capability_reasons: CapabilityReasons,
    obligations: WireObligations,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// The subset of `libraries`' settings that a client renders from.
///
/// Every field here is a **ceiling or a mode**, never a permission. See the module documentation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LibrarySettingsView {
    /// How content here is versioned.
    versioning_mode: &'static str,
    /// How many versions are kept, or absent for unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    version_limit: Option<i32>,
    /// Whether editing requires an explicit checkout.
    require_checkout: bool,
    /// Whether a new version needs approval before it is published.
    require_approval: bool,
    /// Extensions permitted here, or absent for "no allow-list".
    ///
    /// An empty list is **not** the same as absent — it permits nothing — which is why this is an
    /// `Option<Vec<_>>` and why it is skipped rather than rendered as `[]` when there is no list.
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_extensions: Option<Vec<String>>,
    /// Extensions refused here, or absent for "no deny-list".
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_extensions: Option<Vec<String>>,
    /// Largest file accepted, in bytes, or absent for the tenant default.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_file_size_bytes: Option<i64>,
    /// The external-sharing **ceiling**. Not a grant — see the module documentation.
    external_sharing: &'static str,
    /// Whether content here may be indexed for AI retrieval.
    ai_indexing_enabled: bool,
    /// Whether this library is visible over MCP.
    mcp_visible: bool,
    /// Whether desktop sync may pull content from here.
    sync_enabled: bool,
}

impl LibraryView {
    /// Builds a row from a record and the capability answer resolved for it.
    ///
    /// No `From<&Library>` alongside it, for the reason `WorkspaceView::new` gives: a conversion
    /// taking the record alone would have to invent six `false`s, which are indistinguishable on the
    /// wire from a caller who may do nothing here.
    fn new(
        library: &Library,
        capabilities: ContainerCapabilities,
        capability_reasons: CapabilityReasons,
        obligations: WireObligations,
    ) -> Self {
        let settings = &library.settings;
        Self {
            id: library.id.to_string(),
            workspace_id: library.workspace_id.to_string(),
            name: settings.name.clone(),
            slug: settings.slug.clone(),
            revision: library.revision,
            capability_reasons,
            settings: LibrarySettingsView {
                versioning_mode: versioning_str(settings.versioning_mode),
                version_limit: settings.version_limit,
                require_checkout: settings.require_checkout,
                require_approval: settings.require_approval,
                allowed_extensions: settings.allowed_extensions.clone(),
                blocked_extensions: settings.blocked_extensions.clone(),
                max_file_size_bytes: settings.max_file_size_bytes,
                external_sharing: sharing_str(settings.external_sharing),
                ai_indexing_enabled: settings.ai_indexing_enabled,
                mcp_visible: settings.mcp_visible,
                sync_enabled: settings.sync_enabled,
            },
            capabilities,
            obligations,
            created_at: library.created_at,
            updated_at: library.updated_at,
        }
    }
}

/// The stored spelling of a versioning mode, which is also the wire spelling.
///
/// Exhaustive rather than a borrow of `as_str()`, so a variant added to
/// `enclave_libraries::VersioningMode` breaks this match and somebody decides what a client is told.
const fn versioning_str(mode: VersioningMode) -> &'static str {
    match mode {
        VersioningMode::None => "NONE",
        VersioningMode::Major => "MAJOR",
        VersioningMode::MajorMinor => "MAJOR_MINOR",
    }
}

/// The stored spelling of an external-sharing ceiling, which is also the wire spelling.
const fn sharing_str(sharing: ExternalSharing) -> &'static str {
    match sharing {
        ExternalSharing::Disabled => "DISABLED",
        ExternalSharing::ExistingGuests => "EXISTING_GUESTS",
        ExternalSharing::NewGuests => "NEW_GUESTS",
        ExternalSharing::Anyone => "ANYONE",
    }
}

/// The body of `POST /workspaces/{workspaceId}/libraries`.
///
/// `camelCase` per `docs/05-API.md §1`. The workspace is in the path and is **not** a body field:
/// a request that could name its workspace twice is a request that can disagree with itself, and
/// the path is the one the router matched and the policy chain was pointed at (`CLAUDE.md` rule 3
/// read one level down — tenant identity is never the client's, and neither is the container the
/// chain decided about).
///
/// Two fields, and see the module documentation for why the other fifteen settings are not here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateLibraryRequest {
    /// The display name, as the user typed it. Trimmed, never folded: `libraries.name` is what a
    /// picker renders, and case is the author's to choose.
    name: String,
    /// The URL-safe short name, folded by [`normalize_slug`] on the way in.
    ///
    /// **Required, and not derived from `name`.** [`normalize_slug`] trims and lowercases and does
    /// nothing else, so deriving would turn `"Quarterly Reports"` into `"quarterly reports"` — a
    /// slug with a space in it, which is not the URL-safe short name the column is documented to
    /// hold (`enclave_libraries::LibrarySettings`). Deriving properly would mean inventing a
    /// transliteration this workspace does not have, and a second answer to "what is a slug" is how
    /// the writer and the reader of a library's identity come to disagree. The caller names it.
    slug: String,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/workspaces/{id}/libraries` — the libraries in one workspace.
///
/// # Errors
///
/// [`ApiError`]: `404` when the workspace is another tenant's, absent, trashed or not granted to
/// this caller; `400` for an unusable `limit` or a cursor issued for a different tenant, workspace
/// or filter set; the denial's own status for any other policy refusal.
pub async fn list_in_workspace(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(workspace): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Page<LibraryView>>, ApiError> {
    let request_id = ctx.request_id;

    // An id that does not parse names no resource. `404` rather than a validation failure, so that
    // a garbage id and another tenant's id cannot be told apart.
    let workspace: WorkspaceId =
        workspace.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let limit = page_size(params.limit.as_deref(), request_id)?;

    // The container being listed is the resource whose ACL governs the answer. Enforced here, before
    // any repository is reached (`plans/M1-CONTENT-CORE.md` D11) — a caller who cannot read the
    // workspace must not learn how many libraries it holds, or that it exists at all.
    let resource = ResourceRef::workspace(ctx.tenant_id, workspace);
    let decision = state
        .policy
        .enforce(&ctx, Action::Container(ContainerAction::Read), &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;
    // Nothing in a list of library names can carry a watermark or a justification, so an obligation
    // here is unsatisfiable and refusing is the only honest answer (D29, `CLAUDE.md` rule 8). Not a
    // `debug_assert!` — `ENC-582` is the row where that shipped as a dropped obligation.
    consume(decision).require_none().map_err(|error| ApiError::new(error, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Every live library in the workspace, not "the caller's". The repository is unauthorized by
    // construction and says so; the trim below is what makes this endpoint safe.
    let page = LibraryRepository::list_by_workspace(
        &mut tx,
        ctx.tenant_id,
        workspace,
        &LibraryFilter::default(),
        limit,
        params.cursor.as_deref(),
    )
    .await
    .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Committed before the ACL batches, for the reason `workspaces::list` gives: each
    // `authorize_many` opens its own tenant-scoped transaction, and holding this one meanwhile costs
    // two connections per request.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let items = readable_libraries(state.policy.authorization().as_ref(), &ctx, &page.libraries)
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

/// Handles `GET /api/v1/libraries/{id}` — one library, its settings, and the caller's capabilities.
///
/// The companion to `GET /libraries/{id}/items`, which has been registered since M1: a client that
/// could list a library's contents could not name the library it was in.
///
/// # Errors
///
/// [`ApiError`]: `404` when the library is another tenant's, absent, trashed or not granted to this
/// caller; the denial's own status for any other policy refusal.
pub async fn read(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(library): Path<String>,
) -> Result<Json<LibraryView>, ApiError> {
    let request_id = ctx.request_id;
    let library: LibraryId =
        library.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::library(ctx.tenant_id, library);

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
    let record = LibraryRepository::find_by_id(&mut tx, ctx.tenant_id, library)
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

    Ok(Json(LibraryView::new(&record, capabilities, reasons, wire)))
}

/// Handles `POST /api/v1/workspaces/{id}/libraries` — create a library in a workspace.
///
/// Answers `201` with the library rendered exactly as [`read`] renders it — the same
/// [`LibraryView`], built by the same [`capabilities_for_container`], against the same
/// `ResourceRef::library`. Not a shape of its own, for the reason [`LibraryView`] gives about
/// serving both the row and the detail: a client that saw one object on creation and a different one
/// a second later would have to hold two decoders for one thing, and the day they disagree it offers
/// an action the listing hides.
///
/// # Why the chain is asked before anything else is
///
/// The workspace's ACL governs whether a library may be added to it, and `enforce` runs before the
/// body is validated and before any repository is reached. Both orderings are deliberate. Reaching
/// the repository first would let a caller with no grant learn from a `404`-vs-`409` difference
/// whether a slug is taken in a workspace they cannot see; validating first would let them learn the
/// same thing from a `400`-vs-`404` difference, using a body they never intended to be accepted.
/// After the chain has allowed, a `400` tells them only about the request they sent.
///
/// # Why there is no actor check
///
/// [`crate::routes::folders::create`] refuses every non-[`Actor::User`](enclave_core::Actor)
/// principal because `files.created_by` is a `NOT NULL` reference to a `users` row and a service
/// account has none to point at. `libraries` has **no** `created_by` column
/// (`docs/04-DATA-MODEL.md §7`), so there is no attribution this route could get wrong, and adding a
/// principal-kind test would be this handler inventing an authorization rule beside the one the
/// chain just answered — which is `CLAUDE.md` rule 1 from the permissive side. An MCP client holding
/// `container.create` on a workspace may create a library in it; that is the ACL's decision, and the
/// audit row the engine wrote names the actor.
///
/// # Errors
///
/// [`ApiError`]: `404` when the workspace is another tenant's, absent, trashed or not granted to
/// this caller — and for a `workspaceId` that does not parse, which must not be distinguishable from
/// it (`CLAUDE.md` rule 7); `400` for a body that will not decode or a name or slug the column will
/// not hold; `409` when a live library in this workspace already holds the folded slug; `403` with
/// the obligation's own code when the decision carried one this path cannot discharge.
pub async fn create(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(workspace): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    // An id that does not parse names no resource. `404` rather than a validation failure, so that
    // a garbage id and another tenant's id cannot be told apart (`CLAUDE.md` rule 7).
    let workspace: WorkspaceId =
        workspace.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;

    let resource = ResourceRef::workspace(ctx.tenant_id, workspace);
    const CREATE: Action = Action::Container(ContainerAction::Create);

    // The chain runs before the body is looked at, which is what this handler's heading claims and
    // for a while was not what it did — the body was decoded first, so a caller the chain was about
    // to refuse could still learn that their JSON was malformed. That is not an existence oracle,
    // because a `400` about the caller's own bytes says nothing about the workspace; it is a
    // narrower thing worth fixing anyway. The sibling this endpoint is modelled on
    // (`routes::workspaces::create`) orders it this way and documents the ordering as discipline,
    // and two siblings that disagree about when the chain runs are two places to have the argument
    // again. `ENC-916`.
    let decision = state
        .policy
        .enforce(&ctx, CREATE, &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;

    let obligations = consume(decision);
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, CREATE, &resource, refused).await);
    }

    let body: Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let body: CreateLibraryRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };

    let settings = match settings_for(&body) {
        Ok(settings) => settings,
        Err(fields) => return Err(ApiError::new(Error::Validation(fields), request_id)),
    };

    let library = match write(&state, &ctx, workspace, &settings).await {
        Ok(library) => library,
        Err(WriteFailure::SlugTaken) => return Ok(slug_in_use().into_response(request_id)),
        Err(WriteFailure::Other(error)) => return Err(ApiError::new(error, request_id)),
    };

    // Resolved against the library that now exists, with **no** obligations to subtract: [`satisfy`]
    // above refuses the request outright unless the decision carried none, so "nothing to subtract"
    // is a property this path has already established rather than an omission here. The obligations
    // of a `container.create` on the *workspace* would in any case be the wrong set to apply to the
    // library.
    let created = ResourceRef::library(ctx.tenant_id, library.id);
    let (capabilities, reasons, wire) = capabilities_for_container(
        state.policy.authorization().as_ref(),
        &ctx,
        &created,
        &Obligations::none(),
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok((StatusCode::CREATED, Json(LibraryView::new(&library, capabilities, reasons, wire)))
        .into_response())
}

// ---------------------------------------------------------------------------------------------
// The trim
// ---------------------------------------------------------------------------------------------

/// Trims a page of libraries to the ones this caller may see, and answers what they may do.
///
/// The same two batch calls `workspaces::readable_workspaces` makes, through the same two shared
/// functions — [`admit`] for `container.read`, then [`capabilities_for_containers`] for the rest —
/// so a library row and a workspace row cannot come to differ in how they were computed.
///
/// The trim's decision is not discarded once it has said yes: its obligations are what the
/// capability pass subtracts for that row, which is the same input [`read`] hands it from its own
/// `container.read` decision.
async fn readable_libraries(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    libraries: &[Library],
) -> Result<Vec<LibraryView>, Error> {
    if libraries.is_empty() {
        return Ok(Vec::new());
    }

    let refs: Vec<ResourceRef> =
        libraries.iter().map(|library| ResourceRef::library(ctx.tenant_id, library.id)).collect();

    let admitted = admit(authorization, ctx, libraries, refs).await?;
    let batch: Vec<_> = admitted
        .iter()
        .map(|(_, resource, obligations)| (*resource, obligations.clone()))
        .collect();
    let computed = capabilities_for_containers(authorization, ctx, &batch).await?;

    Ok(admitted
        .into_iter()
        .zip(computed)
        .map(|((library, _, _), (capabilities, reasons, wire))| {
            LibraryView::new(library, capabilities, reasons, wire)
        })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// The pieces `create` is made of
// ---------------------------------------------------------------------------------------------

/// What a failed insert was.
///
/// Two cases rather than one [`Error`], because the collision is the one this handler has to answer
/// with a status [`Error`] cannot express — `enclave_libraries` routes an unclassified `23505`
/// through [`DbError::Query`], which becomes `Error::Internal` and a `500`. The shape is
/// [`crate::routes::folders::create`]'s, and so is the argument for it.
enum WriteFailure {
    /// A live library in this workspace already holds the folded slug.
    SlugTaken,
    /// Anything else, already mapped onto the error type the API layer renders.
    Other(Error),
}

/// Opens the transaction, writes the library, commits.
///
/// Separate from the handler so the [`WriteFailure::SlugTaken`] interception is one `match` on a
/// two-variant type rather than a nested `if let` in the request path, and so the transaction's
/// scope is visible: it is opened after the chain has allowed and closed before the capability
/// resolution, which is [`list_in_workspace`]'s ordering and for its reason — the resolution opens a
/// tenant-scoped transaction of its own, and holding this one meanwhile costs two connections per
/// request.
///
/// The workspace is **not** read first. The composite foreign key `(tenant_id, workspace_id)` proves
/// atomically with the insert that the parent exists and is this tenant's, and it keeps proving it
/// after the row is written, which a prior `SELECT` cannot (`enclave_libraries::library_repo`).
/// [`LibraryError::NoSuchWorkspace`] already converts to [`Error::NotFound`], so a workspace trashed
/// between the chain's allow and this statement is the same `404` as one that never existed.
async fn write(
    state: &ApiState,
    ctx: &RequestContext,
    workspace: WorkspaceId,
    settings: &LibrarySettings,
) -> Result<Library, WriteFailure> {
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| WriteFailure::Other(e.into()))?;

    let library =
        match LibraryRepository::create(&mut tx, ctx.tenant_id, workspace, settings, Utc::now())
            .await
        {
            Ok(library) => library,
            // The transaction is dropped without committing. A refused insert has aborted it in any
            // case — `ENC-691`'s finding was that `COMMIT` on an aborted transaction *is* a
            // rollback, which is why nothing here relies on that and simply drops.
            Err(error) if is_slug_collision(&error) => return Err(WriteFailure::SlugTaken),
            Err(error) => return Err(WriteFailure::Other(error.into())),
        };

    tx.commit().await.map_err(|e| WriteFailure::Other(e.into()))?;
    Ok(library)
}

/// Whether a failed insert was `uq_library_slug` refusing a duplicate.
///
/// `enclave_libraries` deliberately classifies only the foreign key (`parent_aware`) and says so:
/// *"turning it into a field-level 'that name is taken' belongs with the handler that has a form to
/// attach it to"*. This is that handler. Written here rather than in the repository for the reason
/// [`crate::routes::folders::create`] gives about `NameTaken` — the repository's blanket conversion
/// has four other call sites, and changing it to serve this one would change what they answer.
///
/// Matched on the constraint's name and not on the SQLSTATE, so that the primary key and
/// `libraries_tenant_id_id_key` — the other two `23505`s this statement can raise — stay `500`s.
fn is_slug_collision(error: &LibraryError) -> bool {
    matches!(
        error,
        LibraryError::Database(DbError::Query(sqlx::Error::Database(db)))
            if db.constraint() == Some(LIVE_SLUG_INDEX)
    )
}

/// Honours every obligation the chain attached to the create, or turns it into a refusal.
///
/// Exhaustive on purpose, exactly as `routes::folders::satisfy` is: [`Obligation`] is deliberately
/// not `#[non_exhaustive]`, so a new obligation breaks this match and forces somebody to decide what
/// a library creation does about it rather than inheriting a shrug. A copy rather than a shared
/// helper because the two modules answer for different resources and the duplication is a `match`
/// rather than a policy — but the *answers* agree, and they have to: a caller who may make a
/// container here and not one level down would be two readings of one obligation.
///
/// **Nothing here is satisfiable and almost everything is therefore a refusal** (`CLAUDE.md` rule 8,
/// `plans/M4-GOVERNANCE.md` D29). A library is a name, a slug and seventeen settings: there is no
/// rendition a watermark could be burned into, no content a classification could restrict, and no
/// approval this synchronous path could route and wait for.
///
/// The two exceptions are restrictions on *content*, and a library is created empty. They are
/// **not** translated into the library's `syncEnabled` ceiling, which is the tempting move and the
/// wrong one: an obligation restricts the caller who made this request, and writing it into a stored
/// setting would apply it to every future caller of a container they had no part in creating. That
/// is the handler manufacturing policy out of a decision that was about one request.
fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            // A library has no bytes to withhold and no rendition to mark at the moment it is made.
            // Ignoring these is not a dropped obligation: there is no exposure here for either to
            // be about.
            Obligation::NoDownload | Obligation::NoSync => {}
            // "Suppress every mutation path" — and this request *is* a mutation.
            Obligation::ReadOnly => return Err(Refused::obligation(Obligation::ReadOnly)),
            Obligation::Watermark => return Err(Refused::obligation(Obligation::Watermark)),
            Obligation::RequireJustification => {
                return Err(Refused::obligation(Obligation::RequireJustification))
            }
            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }
            // A library holds no content, so there is nothing to reclassify; the column that could
            // carry the result — `default_classification_id` — is a *default for content created
            // later*, not a classification of the container, and writing a DLP finding about this
            // request into it would misfile it as a tenant policy. Refused rather than ignored: a
            // stage that asked for a classification change and got silence is a stage whose
            // decision was dropped.
            Obligation::Reclassify { to } => {
                return Err(Refused::obligation(Obligation::Reclassify { to }))
            }
        }
    }
    Ok(())
}

/// Validates the two fields the caller sent and fills in the other fifteen.
///
/// Every failure is collected rather than returned at the first one, because `docs/05-API.md §5`'s
/// `details` array is what a form attaches messages to, and a client that has to re-submit twice to
/// discover two problems is a client whose user gives up on the second round trip.
///
/// # Errors
///
/// One [`FieldError`] per rejected field: `REQUIRED` for an empty `name` or `slug`, `TOO_LONG` past
/// [`MAX_NAME_CHARS`], and `INVALID_FORMAT` for a slug holding anything outside
/// [`is_slug_char`] — the check that makes the column's documented "URL-safe short name" true
/// rather than merely intended.
fn settings_for(body: &CreateLibraryRequest) -> Result<LibrarySettings, Vec<FieldError>> {
    let name = body.name.trim();
    // Folded here as well as by the repository's own bind, so that what is validated is what is
    // stored. Validating the raw value and storing the folded one would let `"Board "` pass a
    // length check the stored `"board"` did not need, and — the direction that matters — would let a
    // slug whose folding introduced no new characters be judged on characters it no longer has.
    let slug = normalize_slug(&body.slug);

    let mut failures = Vec::new();
    if name.is_empty() {
        failures.push(FieldError::new("name", ValidationCode::Required));
    } else if name.chars().count() > MAX_NAME_CHARS {
        failures.push(FieldError::new("name", ValidationCode::TooLong));
    }
    if slug.is_empty() {
        failures.push(FieldError::new("slug", ValidationCode::Required));
    } else if slug.chars().count() > MAX_NAME_CHARS {
        failures.push(FieldError::new("slug", ValidationCode::TooLong));
    } else if !slug.chars().all(is_slug_char) {
        failures.push(FieldError::new("slug", ValidationCode::InvalidFormat));
    }

    if !failures.is_empty() {
        return Err(failures);
    }
    Ok(default_settings(name.to_owned(), slug))
}

/// Whether one character may appear in a folded slug.
///
/// Deliberately narrow. A slug is what a URL and a breadcrumb will eventually carry, so the set is
/// the one that survives both without escaping; anything else is refused now rather than stored and
/// met later by whatever does the escaping. Uppercase is not in the set and is not a rejection
/// either — [`normalize_slug`] has already folded it, which is forgiving in the one direction that
/// cannot surprise anybody.
const fn is_slug_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')
}

/// The fifteen settings the request does not carry.
///
/// One rule decides every line: **the column's own default where `migrations/0004` states one, and
/// an argued choice where it does not.** A route that quietly disagreed with the schema would make
/// libraries created through the API differ from libraries created by any other means, which is a
/// difference nobody would look for when one of them behaved unexpectedly.
///
/// Two columns are `NOT NULL` with no default, so the schema declines to choose and this route must:
///
/// * `external_sharing` — [`ExternalSharing::Disabled`]. It is the one setting here whose wrong
///   value sends content *out of the tenant*, and the grant that reached this handler is
///   `container.create`: permission to make a container, which is not permission to decide the
///   tenant's sharing posture for everything that will ever be put in it. Raising the ceiling is a
///   settings replacement under `If-Match` — a separate act, with its own audit row.
/// * `versioning_mode` — [`VersioningMode::Major`]. [`VersioningMode::None`] is the only mode under
///   which a write *replaces* content with no history, so it is not something anyone should receive
///   by not asking; [`VersioningMode::MajorMinor`] implies a draft-and-publish workflow this route
///   configures none of the rest of (`require_approval`, `require_checkout`).
///
/// `default_classification_id`, `storage_profile_id` and `retention_policy_id` are `None` — inherit
/// the workspace's — for the reason they are absent from [`LibrarySettingsView`]: they are internal
/// references, and a container-creation request is not where a tenant's classification catalogue or
/// storage placement is decided.
fn default_settings(name: String, slug: String) -> LibrarySettings {
    LibrarySettings {
        name,
        slug,
        // The flag that makes the library reachable at all — see the module documentation.
        inherit_permissions: true,
        default_classification_id: None,
        versioning_mode: VersioningMode::Major,
        version_limit: None,
        require_checkout: false,
        require_approval: false,
        allowed_extensions: None,
        blocked_extensions: None,
        max_file_size_bytes: None,
        external_sharing: ExternalSharing::Disabled,
        ai_indexing_enabled: true,
        mcp_visible: true,
        sync_enabled: true,
        storage_profile_id: None,
        retention_policy_id: None,
    }
}

/// `409`, per `docs/05-API.md §5`'s status table: "name collision".
///
/// `NAME_IN_USE` rather than a code of its own, because it is the code
/// [`crate::routes::folders::create`] already answers a collision with and a client should not need
/// a second one to mean the same thing. The `details` entry names `slug` because that is the field
/// the unique index guards and therefore the input a form has to put the message on — `name` is not
/// unique and never was.
///
/// Every string is a literal and the offending slug is not among them: the caller sent it, but a
/// collision report is the one place a library the caller has not been shown could be named to them.
fn slug_in_use() -> Envelope {
    Envelope::new(
        StatusCode::CONFLICT,
        "NAME_IN_USE",
        "A library in this workspace already has that short name.",
        "Choose another short name, or rename the library that holds it.",
    )
    .with_details(vec![serde_json::json!({
        "field": "slug",
        "code": ValidationCode::NotUnique.as_str(),
    })])
}

/// `400` for a body that will not decode, inside `docs/05-API.md §5`'s envelope.
///
/// A copy of `routes::folders::unreadable_body` rather than a shared helper, because that one is
/// private to its module and the duplication is four literals rather than a policy. It exists at all
/// because axum's own rejection is plain text outside the envelope, and a client that has one error
/// decoder should not need a second for the case where it sent nonsense.
fn unreadable_body() -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "The request body could not be read.",
        "Correct the field named in `details` and retry.",
    )
    .with_details(vec![serde_json::json!({
        "field": "body",
        "code": ValidationCode::InvalidFormat.as_str(),
    })])
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ClassificationRank, TenantId, Uuid};
    use enclave_libraries::LibrarySettings;

    use super::*;

    fn library(sharing: ExternalSharing, mode: VersioningMode) -> Library {
        Library {
            id: LibraryId::new_v7(),
            tenant_id: TenantId::new_v7(),
            workspace_id: WorkspaceId::new_v7(),
            settings: LibrarySettings {
                name: "Board".to_owned(),
                slug: "board".to_owned(),
                inherit_permissions: true,
                default_classification_id: Some(Uuid::now_v7()),
                versioning_mode: mode,
                version_limit: Some(10),
                require_checkout: true,
                require_approval: false,
                allowed_extensions: Some(vec!["pdf".to_owned()]),
                blocked_extensions: None,
                max_file_size_bytes: Some(1024),
                external_sharing: sharing,
                ai_indexing_enabled: true,
                mcp_visible: false,
                sync_enabled: true,
                storage_profile_id: Some(Uuid::now_v7()),
                retention_policy_id: Some(Uuid::now_v7()),
            },
            revision: 3,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        }
    }

    /// The three internal references are not on the wire, asserted over the **rendered JSON** rather
    /// than by reading the struct — a field added to `LibrarySettingsView` later would be invisible
    /// to a field-by-field check written today.
    ///
    /// `storageProfileId` is the one that matters most: `CLAUDE.md` rule 6 exists so a metadata path
    /// cannot hand out a route to the bytes, and a storage profile names the bucket.
    #[test]
    fn the_internal_references_never_reach_the_wire() {
        let record = library(ExternalSharing::Disabled, VersioningMode::Major);
        let view = LibraryView::new(
            &record,
            ContainerCapabilities::default(),
            CapabilityReasons::default(),
            WireObligations::default(),
        );
        let rendered = serde_json::to_string(&view).expect("render");

        for absent in
            ["storageProfile", "retentionPolicy", "defaultClassification", "inheritPermissions"]
        {
            assert!(!rendered.contains(absent), "{absent} reached the wire: {rendered}");
        }
        // The control: the settings block is populated, so the four absences above are choices
        // rather than an empty object passing for free.
        assert!(rendered.contains("\"versioningMode\":\"MAJOR\""), "{rendered}");
        assert!(rendered.contains("\"externalSharing\":\"DISABLED\""), "{rendered}");
    }

    /// Every ceiling spells itself exactly as the `CHECK` constraint does.
    ///
    /// A client switches on these strings; a lowercase or abbreviated spelling would be a wire
    /// change nobody noticed until a UI stopped matching.
    #[test]
    fn every_ceiling_renders_the_stored_spelling() {
        for sharing in ExternalSharing::all() {
            assert_eq!(sharing_str(*sharing), sharing.as_str());
        }
        for mode in VersioningMode::all() {
            assert_eq!(versioning_str(*mode), mode.as_str());
        }
    }

    /// An absent extension list is absent, not `[]`.
    ///
    /// `enclave_libraries` documents the distinction — an empty list permits *nothing* while `None`
    /// means "no allow-list" — so a serializer that rendered one as the other would invert the
    /// meaning of the field for every library that has no list.
    #[test]
    fn no_allow_list_is_an_absent_field_and_never_an_empty_array() {
        let mut record = library(ExternalSharing::Anyone, VersioningMode::None);
        record.settings.allowed_extensions = None;
        record.settings.blocked_extensions = Some(Vec::new());
        let rendered = serde_json::to_value(LibraryView::new(
            &record,
            ContainerCapabilities::default(),
            CapabilityReasons::default(),
            WireObligations::default(),
        ))
        .expect("render");

        let settings = rendered["settings"].as_object().expect("settings");
        assert!(!settings.contains_key("allowedExtensions"), "{settings:?}");
        assert_eq!(settings["blockedExtensions"], serde_json::json!([]), "{settings:?}");
    }

    // --- creation ------------------------------------------------------------------------------

    fn body(name: &str, slug: &str) -> CreateLibraryRequest {
        CreateLibraryRequest { name: name.to_owned(), slug: slug.to_owned() }
    }

    /// A library created here inherits, and its outward ceilings start closed.
    ///
    /// Two properties in one test because they are the two that would make a `201` a lie in opposite
    /// directions. `inherit_permissions` is what `LIBRARY_CHAIN_SQL` walks to the workspace — a
    /// library created without it has an empty chain, so every question about it including the
    /// creator's own is refused, and the endpoint would return a container nobody can open.
    /// `external_sharing` is the setting whose wrong value carries content out of the tenant, and
    /// the schema states no default for it, so nothing but this assertion holds the choice in place.
    #[test]
    fn a_library_created_here_inherits_and_shares_with_nobody() {
        let settings = settings_for(&body("Board Papers", "board-papers")).expect("valid");

        assert!(
            settings.inherit_permissions,
            "a library that does not inherit resolves to an empty chain and is unreachable"
        );
        assert_eq!(
            settings.external_sharing,
            ExternalSharing::Disabled,
            "container.create is not permission to set the tenant's sharing posture"
        );
        assert_ne!(
            settings.versioning_mode,
            VersioningMode::None,
            "NONE is the one mode under which a write destroys history, so it is not a default"
        );
        // The positive control: the two fields the caller actually sent survive, so the assertions
        // above are about defaults rather than about a struct that was never populated.
        assert_eq!(settings.name, "Board Papers");
        assert_eq!(settings.slug, "board-papers");
    }

    /// A slug is folded before it is judged, and what is judged is what is stored.
    ///
    /// The repository folds on the way in regardless (`bind_settings`), so validating the raw value
    /// would mean this route accepted a slug on the strength of characters the database never sees.
    #[test]
    fn a_slug_is_folded_before_it_is_validated_and_stored() {
        let settings = settings_for(&body("Board", "  Board-Papers  ")).expect("valid");
        assert_eq!(settings.slug, "board-papers", "the stored slug must be the folded one");
    }

    /// Every rejected field is named, and all of them are named at once.
    ///
    /// The multi-failure case is the point: `docs/05-API.md §5`'s `details` array exists so a form
    /// can mark two inputs in one round trip, and a validator that returned at the first problem
    /// would satisfy every single-field assertion below while making a two-field mistake take two
    /// submissions to find.
    #[test]
    fn every_rejected_field_is_named_in_one_answer() {
        let both = settings_for(&body("   ", "")).expect_err("an empty name and slug are refused");
        assert_eq!(both.len(), 2, "both failures must be reported together: {both:?}");
        assert!(both.iter().all(|f| f.code == ValidationCode::Required), "{both:?}");

        let long =
            settings_for(&body(&"a".repeat(MAX_NAME_CHARS + 1), "ok")).expect_err("too long");
        assert_eq!(long, vec![FieldError::new("name", ValidationCode::TooLong)]);

        // The positive control for the length bound: exactly at the ceiling is accepted, so the
        // assertion above is about the boundary rather than about long names in general.
        assert!(settings_for(&body(&"a".repeat(MAX_NAME_CHARS), "ok")).is_ok());
    }

    /// A slug that is not URL-safe is refused rather than stored and escaped later.
    ///
    /// `libraries.slug` is documented as a URL-safe short name and nothing in the schema or the
    /// repository enforces it, so this is the only place the documentation becomes true. The space
    /// is the case that matters most: it is what a derivation from the display name would have
    /// produced, which is why the request carries the slug explicitly.
    #[test]
    fn a_slug_that_is_not_url_safe_is_refused() {
        for bad in ["board papers", "board/papers", "board?papers", "boârd", "board#1"] {
            let failures = settings_for(&body("Board", bad))
                .err()
                .unwrap_or_else(|| panic!("{bad:?} is not URL-safe and must be refused"));
            assert_eq!(
                failures,
                vec![FieldError::new("slug", ValidationCode::InvalidFormat)],
                "{bad:?} must be reported against the slug field"
            );
        }

        // The positive control: the punctuation the set does admit is still accepted, so the
        // assertions above are about a narrow set rather than about a validator that refuses
        // everything that is not a letter.
        assert!(settings_for(&body("Board", "board-papers_2026.v1")).is_ok());
    }

    /// Every obligation a stage can attach is either refused or argued, and the two that are
    /// ignored are ignored for a stated reason.
    ///
    /// The positive control is the empty set: a `satisfy` that simply refused everything would pass
    /// every "this is refused" assertion below while making the endpoint unusable, and only the
    /// empty case can tell the two apart.
    #[test]
    fn an_obligation_this_path_cannot_discharge_refuses_the_creation() {
        assert!(satisfy(&Obligations::none()).is_ok(), "an unconditional allow must proceed");

        for obligation in [
            Obligation::ReadOnly,
            Obligation::Watermark,
            Obligation::RequireJustification,
            Obligation::RequireApproval,
            Obligation::Reclassify { to: ClassificationRank::new(40) },
        ] {
            let set: Obligations = [obligation].into_iter().collect();
            let refused = satisfy(&set).expect_err("an undischargeable obligation must refuse");
            assert_eq!(
                refused.code(),
                obligation.unsatisfied_code(),
                "the refusal must carry D29's standard code for {obligation:?}"
            );
        }

        // The two that are restrictions on content a library does not hold at the moment it is made.
        for obligation in [Obligation::NoDownload, Obligation::NoSync] {
            let set: Obligations = [obligation].into_iter().collect();
            assert!(
                satisfy(&set).is_ok(),
                "{obligation:?} restricts content, and a new library holds none"
            );
        }
    }

    /// A collision is `409` and never `400` or `500`, and it does not echo what collided.
    ///
    /// The status is load-bearing: `enclave_libraries` routes an unclassified `23505` through
    /// `DbError::Query`, which becomes `Error::Internal` and a `500`, so without the interception a
    /// caller who picked a taken slug would be told the server was broken. The *absence* of the slug
    /// is asserted because the `500` would not have leaked it either — so without this assertion the
    /// interception could later start echoing it and nothing would notice.
    #[test]
    fn a_slug_collision_is_a_conflict_that_does_not_echo_the_slug() {
        let envelope = slug_in_use();
        assert_eq!(envelope.status(), StatusCode::CONFLICT);
        assert_eq!(envelope.code(), "NAME_IN_USE");

        let rendered = serde_json::to_string(envelope.details()).expect("render");
        assert!(rendered.contains("NOT_UNIQUE"), "the field diagnosis must survive: {rendered}");
        assert!(rendered.contains("slug"), "the collision must name the field it is about");
    }
}
