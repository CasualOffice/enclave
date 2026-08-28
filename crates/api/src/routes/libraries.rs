//! The library read paths — enumerate a workspace's libraries, and read one.
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

use axum::extract::{Path, Query, State};
use axum::Json;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, Error, LibraryId, RequestContext, ResourceRef,
    WorkspaceId,
};
use enclave_libraries::{
    ExternalSharing, Library, LibraryFilter, LibraryRepository, VersioningMode,
};
use serde::Serialize;

use crate::auth::Authenticated;
use crate::error::{ApiError, CapabilityReasons};
use crate::routes::workspaces::{
    admit, capabilities_for_container, capabilities_for_containers, conceal, consume, page_size,
    ContainerCapabilities, ListParams, Page, PageInfo, WireObligations,
};
use crate::state::ApiState;

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

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{TenantId, Uuid};
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
}
