//! `GET /files/{id}/metadata` and `GET /libraries/{id}/fields` — the custom-field surface.
//!
//! `ENC-984`. `crates/metadata` is 1,169 lines with 630 lines of tests and, until this module, no
//! caller outside its own suite: `crates/api` did not even depend on it. `docs/05-API.md §12` has
//! documented four verbs across these two paths since the API was drawn, and a client had no way to
//! read a single custom field. That is this repository's signature failure — built, tested,
//! reachable by nothing — and `unwired_report.py`'s own docstring lists four prior instances.
//!
//! # Only the reads are here, and the reason is a permission that does not exist
//!
//! `docs/05 §12` documents `PUT /files/{id}/metadata` and `POST /libraries/{id}/fields` as well.
//! Neither is registered, and the missing piece is not plumbing:
//!
//! **`enclave_core::FileAction` has `MetadataRead` and no `MetadataWrite`.** No document names the
//! action that authorizes writing a field value — `docs/06` does not, and `docs/05 §12` gives the
//! paths without an authorization note. So a `PUT` today would have to pick one, and the two
//! candidates decide different products:
//!
//!   * **`FileAction::Edit`** costs no enum change and says that anyone who may change a document's
//!     *content* may change its *properties*. In a system whose libraries sort, filter and apply
//!     retention on those properties, that is a real conflation: "may tag, may not edit" and "may
//!     edit, may not reclassify" are both ordinary requirements this would make inexpressible.
//!   * **A new `FileAction::MetadataWrite`** is expressive and is the larger change by far. It
//!     breaks every exhaustive match on `FileAction`, and `ENC-879` is the row arguing that this is
//!     the *point* of the design rather than its cost — the compiler produces the list and each one
//!     gets decided. It also reaches `acl_entries`, `docs/05`, `docs/06`, the `capabilities` object
//!     every client renders from, and the i18n catalog.
//!
//! `CLAUDE.md`'s working style makes that a design conversation rather than a judgement call to
//! take quietly inside a task about wiring, so the writes are **not registered** rather than
//! registered against a guessed permission. `ENC-692` is the precedent and the shape is the same:
//! a route that answers with an invented authorization is worse than a route that is honestly
//! absent, because the invention is what nobody re-examines. The row is `ENC-996`.
//!
//! `POST /libraries/{id}/fields` has a second reason on top of the first: `crates/metadata`'s
//! repository can read field definitions and read and write *values*, and has no function that
//! creates a field at all. That half is missing code as well as a missing decision.
//!
//! # What the reads answer, and why the fields come with them
//!
//! [`file_metadata`] returns the fields that *apply* to the file joined to the values that are
//! *set* on it, rather than the values alone. A client rendering a property panel needs the label,
//! the type and whether the field is required in order to draw an empty one, and a value-only
//! response would make it fetch the definitions separately and join them itself — which is the
//! `capabilities` argument in `CLAUDE.md` applied to a different object: the server knows, so the
//! server says.
//!
//! Scopes are assembled here and not in the crate, exactly as `crates/metadata`'s own module
//! documentation asks: the handler knows the file's workspace and library because
//! `FileRepository` told it, and resolving that chain inside the metadata crate would be a second
//! implementation of something `crates/files` already owns.
//!
//! `FieldScope::ContentType` is deliberately not in the scope list. Nothing in the workspace
//! assigns a content type to a file yet, so including it would mean passing `None` for the id and
//! matching every content-type field in the tenant — the wrong answer, arrived at silently.

use axum::extract::{Path, State};
use axum::Json;
use enclave_core::{
    Action, ContainerAction, Error, FileAction, FileId, LibraryId, Obligations, PolicyDecision,
    ReasonCode, ResourceRef,
};
use enclave_files::{FileRepository, NodeType};
use enclave_libraries::LibraryRepository;
use enclave_metadata::{FieldScope, MetadataField, ValueResourceKind};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Capabilities, WireObligations};
use crate::error::{ApiError, CapabilityReasons};
use crate::routes::workspaces::{
    capabilities_for_container, ContainerCapabilities, WireObligations as ContainerObligations,
};
use crate::state::ApiState;

/// One field definition, with the value set on the resource when there is one.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldValue {
    /// The stable key a caller filters and sorts on. Not the label, which is translated and edited.
    key: String,
    /// What a person sees, already localized by whoever defined the field.
    label: String,
    /// What the field holds, as `docs/04 §10`'s `field_type`.
    field_type: &'static str,
    /// Whether a value must be present for the resource to be complete.
    required: bool,
    /// Where the field comes from — tenant-wide, or this workspace's, or this library's.
    scope: &'static str,
    /// The value, absent when the field applies and nothing has been set.
    ///
    /// Absent rather than `null`: `null` is a value a `JSON` field can legitimately hold, and a
    /// client that could not tell "unset" from "set to null" would render a cleared field as an
    /// untouched one.
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
}

/// The body of `GET /files/{id}/metadata`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadataView {
    /// The file these fields belong to, echoed so a response can be cached against it.
    file_id: String,
    /// Every field that applies, whether or not it holds a value.
    fields: Vec<FieldValue>,
    /// What this caller may attempt, from the same engine that will enforce it.
    capabilities: Capabilities,
    /// Why each `false` above is `false` (`ENC-674`).
    capability_reasons: CapabilityReasons,
    obligations: WireObligations,
}

/// The body of `GET /libraries/{id}/fields`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryFieldsView {
    /// The library whose fields these are.
    library_id: String,
    /// The definitions, with no values — a library has fields, a resource has values.
    items: Vec<FieldValue>,
    /// What this caller may attempt on the library itself, from the stage that will decide it.
    capabilities: ContainerCapabilities,
    /// Why each `false` above is `false` (`ENC-674`).
    capability_reasons: CapabilityReasons,
    obligations: ContainerObligations,
}

/// Renders a definition, with an optional value beside it.
fn render(field: &MetadataField, value: Option<serde_json::Value>) -> FieldValue {
    FieldValue {
        key: field.key.clone(),
        label: field.label.clone(),
        field_type: field.field_type.as_str(),
        required: field.required,
        scope: field.scope.as_str(),
        value,
    }
}

/// Handles `GET /api/v1/files/{id}/metadata` — the custom fields that apply to a file.
///
/// Authorized as `file.metadata_read`, which is the action the name describes and the same one
/// `GET /files/{id}` asks for: a custom field is metadata, and a caller who may see the file's name
/// and size may see the properties filed beside them. Nothing here exposes content —
/// `Action::exposes_content` is `false` for `MetadataRead`, and that stays true of this route.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file belongs to another tenant, does not exist, or is refused by a
/// grant — the three are one answer by rule 7, because a `403` confirms existence. The denial's own
/// status for any other refusal.
pub async fn file_metadata(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Json<FileMetadataView>, ApiError> {
    let request_id = ctx.request_id;
    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    let decision = state
        .policy
        .enforce(&ctx, Action::File(FileAction::MetadataRead), &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;
    let obligations = consume(decision);

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Authorized but absent: trashed or deleted between the chain and the read, or an id that never
    // existed and was refused by no grant. Same answer either way, and the transaction is closed
    // before the answer is decided so a `404` does not hold a connection.
    let Some(node) = node else {
        tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    let scopes = [
        (FieldScope::Tenant, None),
        (FieldScope::Workspace, Some(node.workspace_id.as_uuid())),
        (FieldScope::Library, Some(node.library_id.as_uuid())),
    ];
    let fields = enclave_metadata::repo::fields_for_scopes(&mut tx, ctx.tenant_id, &scopes)
        .await
        .map_err(|error| ApiError::new(metadata_failure(&error), request_id))?;
    // **The kind follows the node, not the path.** `/files/{id}` serves folders as well as files —
    // `crates/files` calls both nodes and `GET /files/{id}` renders either — and `metadata_values`
    // discriminates on `resource_type`. Hardcoding `FILE` here would file a folder's values under a
    // kind nothing reads them back with, so they would be written once and never returned, which is
    // the quietest kind of data loss.
    let kind = match node.node_type {
        NodeType::File => ValueResourceKind::File,
        NodeType::Folder => ValueResourceKind::Folder,
    };
    let values = enclave_metadata::repo::values_for(&mut tx, ctx.tenant_id, kind, file.as_uuid())
        .await
        .map_err(|error| ApiError::new(metadata_failure(&error), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let rendered = join(&fields, &values);

    let (capabilities, capability_reasons, obligations) =
        capabilities_for(state.policy.authorization().as_ref(), &ctx, &resource, &obligations)
            .await
            .map_err(|error| ApiError::new(error, request_id))?;

    Ok(Json(FileMetadataView {
        file_id: file.as_uuid().to_string(),
        fields: rendered,
        capabilities,
        capability_reasons,
        obligations,
    }))
}

/// Handles `GET /api/v1/libraries/{id}/fields` — the field definitions a library's contents carry.
///
/// Authorized as `container.read` on the library, which is what `GET /libraries/{id}` asks and is
/// the right question: a field definition describes the *library's* shape, not any one file's, and
/// a caller who may see the library may see the columns it sorts by. It deliberately does **not**
/// ask `file.metadata_read` of anything — there is no file in this request, and asking about a
/// resource the caller did not name would be an authorization decision about the wrong object.
///
/// # Errors
///
/// [`ApiError`]: `404` when the library is another tenant's, absent, or not granted to this caller;
/// the denial's own status for any other refusal.
pub async fn library_fields(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(library): Path<String>,
) -> Result<Json<LibraryFieldsView>, ApiError> {
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

    let Some(record) = record else {
        tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    // The library's own fields *and* the ones it inherits from its workspace and the tenant, because
    // a field defined tenant-wide applies to this library's contents and a client drawing a column
    // set needs all three. Reading only `LIBRARY` here would answer a narrower question than the
    // path asks.
    let scopes = [
        (FieldScope::Tenant, None),
        (FieldScope::Workspace, Some(record.workspace_id.as_uuid())),
        (FieldScope::Library, Some(record.id.as_uuid())),
    ];
    let fields = enclave_metadata::repo::fields_for_scopes(&mut tx, ctx.tenant_id, &scopes)
        .await
        .map_err(|error| ApiError::new(metadata_failure(&error), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let (capabilities, capability_reasons, obligations) = capabilities_for_container(
        state.policy.authorization().as_ref(),
        &ctx,
        &resource,
        &obligations,
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok(Json(LibraryFieldsView {
        library_id: library.as_uuid().to_string(),
        items: fields.iter().map(|field| render(field, None)).collect(),
        capabilities,
        capability_reasons,
        obligations,
    }))
}

/// Joins definitions to values by field id, in definition order.
///
/// Definition order and not value order, because the response is a form: a client renders these
/// top to bottom and a field that happens to have no value must not jump to the end. A value whose
/// field is not in the applicable set is dropped rather than rendered — that is a value left behind
/// by a field whose scope changed, and showing it would offer a column the library no longer has.
fn join(fields: &[MetadataField], values: &[(Uuid, serde_json::Value)]) -> Vec<FieldValue> {
    fields
        .iter()
        .map(|field| {
            let value = values
                .iter()
                .find(|(field_id, _)| *field_id == field.id)
                .map(|(_, value)| value.clone());
            render(field, value)
        })
        .collect()
}

/// Renders a metadata storage failure as a dependency error.
///
/// Nothing from [`enclave_metadata::MetadataError`] reaches the caller. Its variants name columns,
/// field keys and validation detail about data the caller may not have been able to read, and a
/// read path has no reason to describe the shape of the tenant's schema in an error body.
fn metadata_failure(error: &enclave_metadata::MetadataError) -> Error {
    tracing::error!(?error, "reading metadata failed");
    Error::Upstream { dependency: enclave_core::Dependency::Postgres, retryable: true }
}

/// Rule 7, on both routes: a refusal must not confirm that the resource exists.
///
/// A local copy rather than an import for the reason `crates/api/src/workflows.rs` gives about its
/// own: the mapping is one line, and a shared helper would be a place to add an exception to.
fn conceal(error: Error) -> Error {
    match error {
        Error::PolicyDenied { code: ReasonCode::AccessDenied, .. } => Error::NotFound,
        other => other,
    }
}

/// Consumes a [`PolicyDecision`], yielding the obligations the caller now has to satisfy.
///
/// Named, so that "the decision was looked at" is a call a reader can find and the `#[must_use]`
/// is discharged in one place per module (rule 8).
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}
