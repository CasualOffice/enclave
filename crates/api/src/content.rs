//! The read paths over the content tree — browse a container, read a file, read its history.
//!
//! `docs/05-API.md §6` (pagination) and `§7` (files and folders) are authoritative for everything
//! on the wire here. This is the first code to implement them, so where the document and the code
//! disagree the document wins and this module is the bug.
//!
//! # The property this module exists to hold
//!
//! **A listing must not become a way to enumerate what you cannot read.** A browse endpoint is the
//! cheapest enumeration oracle in any content system: it takes a container id and returns a list,
//! and if that list is not trimmed by the same rules that would refuse each item individually, then
//! "I cannot open it but I can see it is called `Redundancy List Q3.xlsx`" is a disclosure the
//! access-control model never agreed to. So every child returned by [`browse`] has been through
//! [`enclave_core::AuthorizationService::authorize_many`] for `file.metadata_read`, in one query for the whole
//! page rather than one per row.
//!
//! Three consequences of that trimming are visible on the wire and are deliberate:
//!
//! * A page may hold **fewer items than `limit`** and still report `hasMore: true`. The cursor
//!   tracks the last row the *database* returned, not the last row that survived the trim — the
//!   other way round silently skips every trimmed row's successors. Clients page until `hasMore`
//!   is false, never until a short page arrives.
//! * There is **no total count** (`docs/05-API.md §6`). Counting an ACL-trimmed set costs a second
//!   pass over the same rows, and — worse — a count that includes trimmed rows tells the caller
//!   exactly how much exists that they may not see. `?includeApproximateCount=true` is specified
//!   as an opt-in and is deliberately not implemented yet rather than implemented as a raw count;
//!   see the note handed to the integrator in [`crate`].
//! * The trim is silent. Nothing in the response distinguishes "this folder holds three items" from
//!   "this folder holds nine, six of which are not yours".
//!
//! # `404`, and why the read paths do not return `403`
//!
//! `CLAUDE.md` rule 7 and `docs/12-TESTING.md` T1: a resource in another tenant must be
//! indistinguishable from one that does not exist. On these endpoints that is not a special case to
//! detect — it is a consequence of never being able to detect it. The resource reference is always
//! built with the tenant from the verified token (rule 3), so another tenant's file id arrives as
//! *this* tenant's id for a row this tenant cannot see; row-level security means the ACL walk finds
//! no chain, and the answer is the same one a fabricated UUID gets.
//!
//! [`existence_gate`] is where that becomes an invariant rather than an accident: on a read entry
//! point, an `ACCESS_DENIED` denial is rendered as `404`. Three cases collapse into it — another
//! tenant's id, an id that never existed, and an id in this tenant with no grant — and the endpoint
//! cannot be used to tell them apart. Denials with any *other* reason code keep their own status,
//! and that is safe: every one of them is produced by a stage that runs either before authorization
//! (conditional access, which refuses identically for a nonexistent id) or after it (classification,
//! DLP, retention), and reaching a post-authorization stage means the caller already holds a grant
//! and has therefore already been told the resource exists.
//!
//! The real reason is not lost, it is just not in the response: `PolicyEngine::enforce` audits every
//! denial with its stage and its code before returning (`CLAUDE.md` rule 10).
//!
//! # Where the policy chain runs
//!
//! In the handler, before any repository is reached (`plans/M1-CONTENT-CORE.md` D11). The
//! repositories in `enclave-files` and `enclave-versions` make no authorization decision and must
//! not start: a second enforcement point is one the ENC-110 policy-routing lint does not check.
//!
//! Each handler enforces exactly once, on the resource whose ACL governs the answer:
//!
//! | Endpoint | Resource enforced | Action |
//! |---|---|---|
//! | `GET /libraries/{id}/items` | the container being listed — the library, or `parentId` when given | `container.read` |
//! | `GET /files/{id}` | the file | `file.metadata_read` |
//! | `GET /files/{id}/versions` | the **file**, not the version | `file.version_read` |
//!
//! The last row is worth stating out loud: a version carries no ACL rows of its own and
//! `crates/authorization` refuses to guess an inheritance model for one, so history is authorized
//! against the file's current ACL. That is also the behaviour `docs/12-TESTING.md` A7 requires —
//! a version read respects the ACL the file has *now*, not the one it had when the version was
//! written.
//!
//! # `capabilities` on every row
//!
//! A listing used to omit `capabilities` because nine ACL resolutions per row turns a five-hundred
//! item folder into four and a half thousand of them, and a client was told to open an item before
//! it could draw a button for it. That trade was wrong in the one direction that matters: a row
//! with no capabilities leaves a UI two options, render every action and discover the refusal on
//! click, or infer permission from whatever else the row carries — and the second is exactly the
//! client-side re-derivation `CLAUDE.md` forbids, arrived at because the server declined to answer.
//!
//! The cost is now paid per *page* rather than per row. [`capabilities_for_many`] resolves one
//! action across every surviving row in a single [`enclave_core::AuthorizationService::authorize_many`]
//! call, so a page costs ten batch resolutions — the trim's `file.metadata_read`, then one per
//! capability action — whether it holds one row or five hundred. What scales with the page is the
//! size of the `id = ANY($1)` array, not the number of round trips.
//!
//! [`browse`] and [`file_metadata`] then render the object from *the same function*, over the same
//! table of actions, against the same `Arc` the chain will consult when the action is attempted;
//! [`capabilities_for_many`] records why that identity is structural rather than a coincidence two
//! call sites currently share. It has to be: a listing whose capabilities disagreed with the file
//! response for the same file and caller would make the UI change its mind about what a user may do
//! purely because they clicked into the item.
//!
//! # What the wire deliberately omits
//!
//! `object_key`, `storage_profile_id` and `encryption_key_ref` never appear in a version listing.
//! They are the coordinates of the bytes in object storage, and `CLAUDE.md` rule 6 exists precisely
//! so that a metadata path cannot hand out a route to the original object. A version's *existence*
//! is metadata; its location is not.
//!
//! Version history lists every version, including ones no read path will serve — a user who cannot
//! see that version 3.0 exists and was quarantined reports the file as silently corrupted. The
//! listing is rows, not bytes; every content path goes back through
//! `VersionRepository::find_readable`, which is where rule 9 lives.
//!
//! # Agreeing with the delivery routes about what is servable
//!
//! A metadata response and a delivery route must not disagree about the same version. Before
//! `ENC-825` they did: `currentVersion` carried `{id, major, minor, status}`, and `status` is only
//! *half* of rule 9's predicate. A deployment with its antivirus engine disabled records an
//! admitted version `AVAILABLE` / `SKIPPED`, so this endpoint answered `AVAILABLE` —
//! indistinguishable, field for field, from a version that previews — while
//! `GET /files/{id}/preview` answered `404`. A correct client drew a button that could not work,
//! and could only discover that by pressing it.
//!
//! `ENC-828` then fixed the *other* side of that disagreement: `AVAILABLE` / `SKIPPED` is now
//! served, because it is what `docs/06 §6.2`'s `ALLOW_WITH_FLAG` means and refusing it made the
//! setting a no-op. Nothing in this module changed for it, which is the point — `isReadable` is the
//! predicate's own answer, so it followed the predicate without an edit here. The pair that still
//! disagrees is `AVAILABLE` / `PENDING` (`ENC-646`), and this endpoint reports it truthfully too.
//!
//! [`VersionState`] closes it, and closes it *structurally* rather than by adding a field someone
//! must remember to compute: `isReadable` is rendered from
//! [`enclave_versions::FileVersion::is_readable`], which is the Rust twin of the
//! [`enclave_versions::READABLE_PREDICATE`] the delivery routes' own query splices. The two cannot
//! drift while both keep reading the one definition, which is why neither of them spells the rule
//! out. `crates/api/tests/content.rs` asserts the agreement over the whole cross-product of
//! `status` × `av_status` rather than over the two states that happen to be interesting today.
//!
//! Note what this does **not** change: nothing here decides readability, and no read path consults
//! this struct. Rule 9 still lives in `VersionRepository::find_readable`. This module only reports
//! the same answer that route will give, which is the whole of the fix.

use axum::extract::{Path, Query, State};
use axum::Json;
use enclave_core::{
    Action, AuthorizationService, ContainerAction, Error, FieldError, FileAction, FileId,
    LibraryId, Obligation, Obligations, PolicyDecision, ReasonCode, RequestContext, RequestId,
    ResourceRef, StageOutcome, ValidationCode,
};
use enclave_files::{ChildFilter, FileNode, FileRepository, NodeType, PageSize, Parent};
use enclave_versions::{FileVersion, PageLimit, VersionNumber, VersionRepository};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, CapabilityReasons};
use crate::state::ApiState;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The page envelope of `docs/05-API.md §6`.
///
/// Generic over the item so that all three listings put the same three fields on the wire under the
/// same three names. `total` is absent by design and there is no field for it to be added to
/// carelessly.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T> {
    items: Vec<T>,
    page: PageInfo,
}

/// The cursor half of the page envelope.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    /// The opaque cursor for the next page, absent at the end of the listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    /// Whether another page exists. Not implied by a short page — see the module documentation.
    has_more: bool,
    /// The size actually used, after clamping.
    limit: u32,
}

/// One row of a browse listing.
///
/// Lighter than [`FileMetadata`] — no `currentVersion`, no `aclRevision`, no `governance` — but not
/// lighter in the one place a client renders from: `capabilities` and `obligations` are the same
/// two types the file response carries, populated by the same function, so a row and a file
/// response are interchangeable inputs to whatever draws the action menu. Sharing the *types*, not
/// merely the field names, is what stops the two from drifting into a shape a client has to
/// special-case.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    id: String,
    node_type: &'static str,
    name: String,
    mime_type: String,
    size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    library_id: String,
    status: &'static str,
    revision: i64,
    /// What this caller may attempt on this row, from the stage that will decide it.
    capabilities: Capabilities,
    /// Why each `false` above is `false` (`ENC-674`). See [`CapabilityReasons`].
    capability_reasons: CapabilityReasons,
    obligations: WireObligations,
    created_at: chrono::DateTime<chrono::Utc>,
    modified_at: chrono::DateTime<chrono::Utc>,
}

impl Item {
    /// Builds a row from a node and the capability answer resolved for it.
    ///
    /// There is deliberately no `From<&FileNode>` alongside this. A conversion that took the node
    /// alone would have to invent a capabilities object, and the only value available to invent is
    /// the default — nine `false`s, indistinguishable on the wire from a caller who may do nothing
    /// with the file. A row can therefore only be built by someone holding a resolved answer.
    pub(crate) fn new(
        node: &FileNode,
        capabilities: Capabilities,
        capability_reasons: CapabilityReasons,
        obligations: WireObligations,
    ) -> Self {
        Self {
            id: node.id.to_string(),
            node_type: node.node_type.as_str(),
            name: node.name.clone(),
            mime_type: node.mime_type.clone(),
            size_bytes: node.size_bytes,
            parent_id: node.parent_id.map(|id| id.to_string()),
            library_id: node.library_id.to_string(),
            status: node.status.as_str(),
            revision: node.revision,
            capabilities,
            capability_reasons,
            obligations,
            created_at: node.created_at,
            modified_at: node.modified_at,
        }
    }
}

/// `GET /files/{id}` — metadata plus what the caller may do with it (`docs/05-API.md §7`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    id: String,
    node_type: &'static str,
    name: String,
    mime_type: String,
    size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    library_id: String,
    status: &'static str,
    /// The version the file currently points at, or absent while the node has no version at all.
    ///
    /// Present is **not** the same as servable — `isReadable` on it is what says that (`ENC-825`).
    #[serde(skip_serializing_if = "Option::is_none")]
    current_version: Option<VersionState>,
    revision: i64,
    acl_revision: i64,
    /// What this caller may attempt, from the same engine that will enforce it.
    capabilities: Capabilities,
    /// Why each `false` above is `false` (`ENC-674`). See [`CapabilityReasons`].
    capability_reasons: CapabilityReasons,
    obligations: WireObligations,
    governance: Governance,
    created_at: chrono::DateTime<chrono::Utc>,
    modified_at: chrono::DateTime<chrono::Utc>,
}

/// The pointer to a version, as `docs/05-API.md §7` shapes it.
///
/// # Why `isReadable` is on the wire (`ENC-825`)
///
/// `status` alone cannot answer the only question a client actually has — *will the preview
/// button work?* — because `AVAILABLE` does not mean servable. `CLAUDE.md` rule 9 is two
/// conditions, and the delivery routes filter on both:
/// [`enclave_versions::READABLE_PREDICATE`] is both. A version whose scan has not completed is
/// `AVAILABLE` / `PENDING` under `ALLOW_AND_RESCAN` (`ENC-646`) — `AVAILABLE`, and not servable —
/// so this response used to be byte-identical for a file that previews and one that answers `404`,
/// and the only way to tell them apart was to try.
///
/// `AVAILABLE` / `SKIPPED` was the other such pair until `ENC-828`, and it was the common one: it
/// is what a deployment with `antivirus.provider: none` and `unsupported_policy: ALLOW_WITH_FLAG`
/// records for *every* upload. That version is now served, so `isReadable` answers `true` for it —
/// which is the same fact reported truthfully, not a relaxation here.
///
/// [`is_readable`](Self::is_readable) is therefore rendered from
/// [`FileVersion::is_readable`](enclave_versions::FileVersion::is_readable) — the Rust twin of
/// that predicate, and the *same* function the delivery routes' query is checked against — rather
/// than recomputed here from `status` and `avStatus`. That identity is the point: a second
/// implementation would be a second answer, and the two endpoints would drift the first time the
/// predicate changed.
///
/// # Why `avStatus` is here too, and why it is not a leak
///
/// A boolean says *no* without saying *why*, and `docs/09-UX-WHITE-LABELING.md §8` requires
/// truthful progress — `Uploading → Scanning → Processing → Indexing → Ready`, plus the
/// `Quarantined` / `Failed` terminals. "Not readable" collapses six of those into one, so a client
/// holding only the boolean can draw a spinner that never resolves and cannot tell it from a file
/// that will never resolve. `status` and `avStatus` are what separate them.
///
/// It discloses nothing the caller has not already been told. Reaching this struct at all means
/// the chain allowed `file.metadata_read` on the file, and `status` — which already carried
/// `QUARANTINED`, the *most* sensitive of these values — has been on the wire since the endpoint
/// existed. `CLAUDE.md` rule 7 is about existence, and existence was established before this field
/// was rendered; a caller with no grant gets `404` and never sees the object at all. The one fact
/// `avStatus` adds over `status` is whether this deployment's scanner ran, which is deployment
/// configuration rather than anything about the file.
///
/// The same three fields appear on `VersionEntry` in the history listing and on `ProgressView` in
/// `crate::routes::uploads`, from this one type. Sharing the type rather than the field names is
/// what stops the three from drifting into shapes a client has to special-case — the argument the
/// module documentation makes for [`Capabilities`], for the same reason.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionState {
    id: String,
    major: i32,
    minor: i32,
    status: &'static str,
    /// The antivirus verdict, so a client can say *why* rather than only *no*.
    av_status: &'static str,
    /// Whether a delivery route would serve this version. The predicate, not a paraphrase of it.
    is_readable: bool,
}

impl From<&FileVersion> for VersionState {
    fn from(version: &FileVersion) -> Self {
        Self {
            id: version.id.to_string(),
            major: version.number.major,
            minor: version.number.minor,
            status: version.status.as_str(),
            av_status: version.av.status.as_str(),
            // Not `status == AVAILABLE && av == CLEAN` written out here. See the type's docs.
            is_readable: version.is_readable(),
        }
    }
}

/// What the caller may do, one field per distinct exposure.
///
/// Nine separate booleans and not one `canRead`, because `CLAUDE.md` rule 6 is that preview,
/// download, print, export and sync are five different exposures of the same bytes. A UI that
/// collapses them cannot express "view it in the browser, but it never leaves the browser", and a
/// response shape that collapses them makes that UI the only possible one.
///
/// Every field is the answer this deployment's authorization stage gives for that action on this
/// resource — see [`capabilities_for_many`] for why it is that stage and not a second
/// implementation, and why a row of a listing and a file response cannot answer differently.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Capabilities {
    /// True by construction: the caller could not be reading this without it.
    metadata_read: bool,
    preview: bool,
    download: bool,
    print: bool,
    export: bool,
    edit: bool,
    share: bool,
    share_external: bool,
    delete: bool,
    /// `ENC-807`. Present because `PATCH /files/{id}` can now move a node and
    /// `POST /files/{id}/restore` can bring one back. `CLAUDE.md`'s React rule is that a client
    /// renders actions from this object and never re-derives them, so a verb the product serves and
    /// this struct cannot express is a control a conforming UI is unable to draw at all.
    #[serde(rename = "move")]
    move_: bool,
    restore: bool,
    sync: bool,
}

/// The obligations the caller must satisfy, rendered as `docs/05-API.md §7` shapes them.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireObligations {
    /// Every rendition of this resource must be watermarked before it is shown.
    watermark: bool,
    /// The actions that cannot proceed without a written justification, by capability name.
    justification_required: Vec<&'static str>,
    /// The actions that must be routed for approval rather than executed.
    approval_required: Vec<&'static str>,
}

/// Retention and records state (`docs/05-API.md §7`).
///
/// `retentionPolicy` is absent rather than null: the retention crate does not exist yet, and a
/// field that always reports "no policy" is indistinguishable from one that reports the truth right
/// up to the day a policy is configured and it keeps saying it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Governance {
    on_legal_hold: bool,
    is_record: bool,
}

/// One entry of a file's version history.
///
/// Note what is not here: `objectKey`, `storageProfileId` and `encryptionKeyRef`. See the module
/// documentation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    id: String,
    major: i32,
    minor: i32,
    status: &'static str,
    /// The antivirus verdict, so a client can explain a version it is not being allowed to open.
    av_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_state: Option<&'static str>,
    size_bytes: i64,
    mime_type: String,
    checksum_sha256: String,
    /// Whether a content path would serve this version — the Rust twin of the predicate that
    /// decides it, so a client never has to reimplement rule 9 from `status` and `avStatus`.
    is_readable: bool,
    created_by: String,
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

impl From<&FileVersion> for VersionEntry {
    fn from(version: &FileVersion) -> Self {
        Self {
            id: version.id.to_string(),
            major: version.number.major,
            minor: version.number.minor,
            status: version.status.as_str(),
            av_status: version.av.status.as_str(),
            approval_state: version.approval_state.map(|state| state.as_str()),
            size_bytes: version.size_bytes,
            mime_type: version.mime_type.clone(),
            checksum_sha256: version.checksum_sha256.clone(),
            is_readable: version.is_readable(),
            created_by: version.created_by.to_string(),
            created_at: version.created_at,
            comment: version.comment.clone(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------------------------

/// `?parentId=&cursor=&limit=`.
///
/// Every field is an owned `String` and nothing is parsed by `serde`. A typed `Option<u32>` would
/// make `?limit=abc` a *deserialization* failure, which axum answers with its own plain-text `400`
/// — outside the single error envelope `docs/05-API.md §5` requires. Parsing here keeps every
/// rejection in the envelope, with the field named in `details`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowseParams {
    parent_id: Option<String>,
    cursor: Option<String>,
    limit: Option<String>,
}

/// `?cursor=&limit=` for version history.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryParams {
    cursor: Option<String>,
    limit: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/libraries/{id}/items` — browse a library root or a folder within it.
///
/// # Errors
///
/// [`ApiError`]: `404` when the container is another tenant's, absent, or not granted to this
/// caller (see [`existence_gate`]); `400` for an unusable `limit` or a cursor that was issued for a
/// different tenant, container or filter set; the denial's own status for any other policy refusal.
pub async fn browse(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(library): Path<String>,
    Query(params): Query<BrowseParams>,
) -> Result<Json<Page<Item>>, ApiError> {
    let request_id = ctx.request_id;

    // An id that does not parse names no resource. `404` rather than a validation failure, for the
    // same reason the rest of this module answers `404`: `GET /libraries/<garbage>/items` and
    // `GET /libraries/<another tenant's id>/items` must not be distinguishable, and a `400` on one
    // of them is a distinction.
    let library: LibraryId =
        library.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let parent_folder = match params.parent_id.as_deref() {
        Some(raw) => {
            Some(raw.parse::<FileId>().map_err(|_| ApiError::new(Error::NotFound, request_id))?)
        }
        None => None,
    };
    let limit = page_size(params.limit.as_deref(), request_id)?;

    let parent = parent_folder.map_or(Parent::Library(library), Parent::Folder);

    // The container being listed is the resource whose ACL governs the answer: a folder inherits
    // from its library, so enforcing on the folder covers both, while enforcing on the library
    // alone would let a caller who may read the library read a folder inside it whose inheritance
    // has been broken.
    let resource = match parent {
        Parent::Library(id) => ResourceRef::library(ctx.tenant_id, id),
        Parent::Folder(id) => ResourceRef::folder(ctx.tenant_id, id),
    };

    // The chain, before any repository is touched.
    let decision = state
        .policy
        .enforce(&ctx, Action::Container(ContainerAction::Read), &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    let obligations = consume(decision);

    // Listing a container carries no obligation any current stage can attach, and this path could
    // not satisfy one if it did — a watermark on the names themselves has nowhere to be burned in.
    // An unsatisfiable obligation is a refusal (D29, `CLAUDE.md` rule 8).
    //
    // A `debug_assert!` until `ENC-582`, which meant the release build dropped it and returned the
    // listing — the check ran only where nobody was looking, which is `ENC-544` again.
    obligations.require_none().map_err(|error| ApiError::new(error, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // With a `parentId`, confirm the folder is what the URL claims it is. Policy has already run,
    // so this is a structural check and not an authorization one: it stops `libraryId` and
    // `parentId` from disagreeing, which would otherwise let the path segment become decoration
    // while the real container came from a query parameter.
    if let Some(folder) = parent_folder {
        let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, folder)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;
        match node {
            Some(node) if node.is_folder() && node.library_id == library => {}
            // Absent, trashed, not a folder, or in a different library. All `404`: the caller was
            // authorized for *a* container, and this is not the one they named.
            _ => return Err(ApiError::new(Error::NotFound, request_id)),
        }
    }

    let page = FileRepository::list_children(
        &mut tx,
        ctx.tenant_id,
        parent,
        &ChildFilter::default(),
        limit,
        params.cursor.as_deref(),
    )
    .await
    .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Committed before the ACL batches below, deliberately. Each `authorize_many` opens its own
    // tenant-scoped transaction, and a handler that held this one open while waiting for those
    // needs two connections per request — which on a small pool is a deadlock waiting for load.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // A failed resolution is not a denial (`crates/core/src/engine.rs`): a listing that could not
    // be trimmed must not be served untrimmed, and one whose capabilities could not be resolved
    // must not be served with the object a default would produce.
    let items = readable_children(state.policy.authorization().as_ref(), &ctx, &page.nodes)
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

/// Handles `GET /api/v1/files/{id}` — metadata and the caller's capabilities.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file is another tenant's, absent, trashed or not granted to this
/// caller; the denial's own status for any other policy refusal.
pub async fn file_metadata(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Json<FileMetadata>, ApiError> {
    let request_id = ctx.request_id;
    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    let decision = state
        .policy
        .enforce(&ctx, Action::File(FileAction::MetadataRead), &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    let obligations = consume(decision);

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // `current` resolves through `files.current_version_id` rather than taking the highest number,
    // because immediately after a commit the newest version is still `SCANNING` and the pointer is
    // what the rest of the system agrees on.
    let current = match node.as_ref() {
        Some(_) => VersionRepository::current(&mut tx, ctx.tenant_id, file)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?,
        None => None,
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Authorized but absent: deleted between the chain and the read, or an id that never existed
    // and was refused by no grant. Same answer either way.
    let node = node.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let (capabilities, capability_reasons, wire_obligations) =
        capabilities_for(state.policy.authorization().as_ref(), &ctx, &resource, &obligations)
            .await
            .map_err(|error| ApiError::new(error, request_id))?;

    // "You opened it." Last, on the success path only: recording a read the chain refused would put
    // a row in `recent_files` for a file this caller may not see, and `GET /me/recent` counts every
    // such row into `filteredCount` — turning that counter into the enumeration oracle rule 7
    // exists to forbid. It cannot fail this response and does not return one to ignore; the whole
    // argument is in `crate::routes::recent`.
    //
    // Files only. A folder is excluded because browsing is not opening — and because the recency
    // read filters `node_type = 'FOLDER'` out, so a row for one could never be read back.
    if !node.is_folder() {
        crate::routes::recent::record(&state, &ctx, file).await;
    }

    Ok(Json(FileMetadata {
        id: node.id.to_string(),
        node_type: node.node_type.as_str(),
        name: node.name,
        mime_type: node.mime_type,
        size_bytes: node.size_bytes,
        parent_id: node.parent_id.map(|id| id.to_string()),
        library_id: node.library_id.to_string(),
        status: node.status.as_str(),
        current_version: current.as_ref().map(VersionState::from),
        revision: node.revision,
        acl_revision: node.acl_revision,
        capabilities,
        capability_reasons,
        obligations: wire_obligations,
        governance: Governance { on_legal_hold: node.on_legal_hold, is_record: node.is_record },
        created_at: node.created_at,
        modified_at: node.modified_at,
    }))
}

/// Handles `GET /api/v1/files/{id}/versions` — the file's history, newest first.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file is another tenant's, absent, trashed or not granted to this
/// caller; `400` for an unusable `limit` or `cursor`.
pub async fn file_versions(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<Page<VersionEntry>>, ApiError> {
    let request_id = ctx.request_id;
    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let limit = history_limit(params.limit.as_deref(), request_id)?;
    let before = history_cursor(params.cursor.as_deref(), request_id)?;

    // Enforced on the file, not on the version: `crates/authorization` refuses to guess an
    // inheritance model for a version, and `docs/12-TESTING.md` A7 requires history to respect the
    // ACL the file holds *now* rather than the one it held when the version was written.
    let resource = ResourceRef::file(ctx.tenant_id, file);
    let decision = state
        .policy
        .enforce(&ctx, Action::File(FileAction::VersionRead), &resource)
        .await
        .map_err(|error| ApiError::new(existence_gate(error), request_id))?;
    let obligations = consume(decision);
    // A watermark obligation on history means the client must not render it bare, and this handler
    // returns JSON rather than a rendition — so there is nothing here that could carry the mark.
    // Refusing is the only honest answer (D29). Was a `debug_assert!`, so the release build served
    // the history and dropped the obligation; `ENC-582` made the check one that ships.
    obligations.require_none().map_err(|error| ApiError::new(error, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // The file has to exist as a live node before its history is served: a trashed file's versions
    // belong to the trash view, which has its own decision to make about them.
    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    if node.is_none() {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    let page = VersionRepository::list(&mut tx, ctx.tenant_id, file, before, limit)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(Json(Page {
        items: page.versions.iter().map(VersionEntry::from).collect(),
        page: PageInfo {
            next_cursor: page.next_before.map(|number| number.to_string()),
            has_more: page.has_more,
            limit: u32::try_from(page.limit.get()).unwrap_or(u32::MAX),
        },
    }))
}

// ---------------------------------------------------------------------------------------------
// The pieces the handlers share
// ---------------------------------------------------------------------------------------------

/// Renders an `ACCESS_DENIED` denial on a read path as [`Error::NotFound`].
///
/// The one place the `403`/`404` decision of `CLAUDE.md` rule 7 is made, so that three endpoints
/// cannot answer it three ways. See the module documentation for why `ACCESS_DENIED` specifically,
/// and why every other reason code keeps its own status.
fn existence_gate(error: Error) -> Error {
    match error {
        Error::PolicyDenied { code: ReasonCode::AccessDenied, .. } => Error::NotFound,
        other => other,
    }
}

/// Consumes a [`PolicyDecision`], yielding the obligations the caller now has to satisfy.
///
/// A named function rather than an inline `.into_obligations()` so that "the decision was looked
/// at" is a call a reader can find, and so the `#[must_use]` on [`PolicyDecision`] is discharged in
/// exactly one place across this module.
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

/// Parses and clamps `?limit=` for a browse listing.
fn page_size(raw: Option<&str>, request_id: RequestId) -> Result<PageSize, ApiError> {
    match raw {
        None => Ok(PageSize::DEFAULT),
        // Clamped, not rejected (`crates/db/src/cursor.rs`): a client asking for a million rows
        // wants as many as it can have, and `docs/05-API.md §6` fixes the ceiling at 500. Only an
        // unparseable value is a client error, because that one is a bug rather than an appetite.
        Some(text) => text.trim().parse::<u32>().map(PageSize::new).map_err(|_| {
            ApiError::new(
                Error::Validation(vec![FieldError::new("limit", ValidationCode::InvalidFormat)]),
                request_id,
            )
        }),
    }
}

/// Parses and clamps `?limit=` for version history.
///
/// A different ceiling from [`page_size`] — `crates/versions` caps history at 200 — and the
/// response reports the value actually used, so a client never has to know which listing it is on.
fn history_limit(raw: Option<&str>, request_id: RequestId) -> Result<PageLimit, ApiError> {
    match raw {
        None => Ok(PageLimit::DEFAULT),
        Some(text) => text.trim().parse::<i64>().map(PageLimit::new).map_err(|_| {
            ApiError::new(
                Error::Validation(vec![FieldError::new("limit", ValidationCode::InvalidFormat)]),
                request_id,
            )
        }),
    }
}

/// Parses the `?cursor=` of a version listing, which is a version number.
///
/// Unlike the browse cursor this is not an encoded, tenant-bound token, and that is a considered
/// difference rather than an omission. A browse cursor hides a row id that the caller has not been
/// shown and binds the position to a filter set that would silently skip rows if it changed. A
/// version cursor is `3.0` — a number already printed in the response it came from, in a history
/// that has exactly one ordering and is already scoped to one file by the path. There is nothing to
/// hide and no filter set to bind it to, so an encoded form would add a format to keep compatible
/// without adding a property. `crates/versions/src/repo.rs` records the same reasoning for the
/// repository half.
fn history_cursor(
    raw: Option<&str>,
    request_id: RequestId,
) -> Result<Option<VersionNumber>, ApiError> {
    let Some(text) = raw else { return Ok(None) };
    let invalid = || {
        ApiError::new(
            Error::Validation(vec![FieldError::new("cursor", ValidationCode::InvalidFormat)]),
            request_id,
        )
    };
    let (major, minor) = text.trim().split_once('.').ok_or_else(invalid)?;
    let major: i32 = major.parse().map_err(|_| invalid())?;
    let minor: i32 = minor.parse().map_err(|_| invalid())?;
    Ok(Some(VersionNumber::new(major, minor)))
}

/// Trims a page of children to the ones this caller may see at all, and answers what they may do
/// with each.
///
/// One [`enclave_core::AuthorizationService::authorize_many`] call for the whole page — never a loop calling
/// `authorize` per row, which is what turns a 500-item folder into 500 ACL resolutions and what the
/// batch form exists on the trait to prevent (`docs/07-SEARCH-INDEXING.md §6.2`).
///
/// `file.metadata_read` for folders as well as files. A folder's *contents* are gated by
/// `container.read`, enforced when the caller browses into it; appearing as a row in its parent's
/// listing is a metadata disclosure and nothing more, and holding folders to the stricter action
/// would hide folders a user may legitimately see the name of. The reference still carries the
/// right kind — `crates/authorization` maps `File` and `Folder` to the same tree walk, so the kind
/// does not change the verdict, but a reference that lied about it would be wrong the day something
/// else reads it.
///
/// The trim's decision is not discarded once it has said yes. It *is* the decision that authorised
/// this row's metadata read, so its obligations are what [`capabilities_for_many`] subtracts for
/// that row — the same input `GET /files/{id}` hands it from its own `file.metadata_read` decision.
/// Re-resolving `file.metadata_read` a second time to obtain them would be a second decision that
/// could disagree with the one the row was admitted by.
///
/// Folders are not special-cased out of the capability pass. `GET /files/{id}` serves a folder and
/// computes the same nine actions for it, and a row that answered differently from the endpoint it
/// links to would be the exact disagreement this is built to make impossible.
async fn readable_children(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    nodes: &[FileNode],
) -> Result<Vec<Item>, Error> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }

    let refs: Vec<ResourceRef> = nodes
        .iter()
        .map(|node| match node.node_type {
            NodeType::Folder => ResourceRef::folder(ctx.tenant_id, node.id),
            NodeType::File => ResourceRef::file(ctx.tenant_id, node.id),
        })
        .collect();

    let decisions =
        authorization.authorize_many(ctx, Action::File(FileAction::MetadataRead), &refs).await?;

    // Index-aligned with `refs` by contract. If an implementation ever returned a shorter vector,
    // `zip` drops the tail — which trims *more* than necessary rather than less, and a listing that
    // is too short is a bug while a listing that is too long is a disclosure.
    let mut readable: Vec<&FileNode> = Vec::with_capacity(nodes.len());
    let mut admitted: Vec<(ResourceRef, Obligations)> = Vec::with_capacity(nodes.len());
    for ((node, resource), decision) in nodes.iter().zip(refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        // Allowed, so this cannot be an `Err`; taking the obligations rather than dropping the
        // decision is what keeps a restriction attached to the read from evaporating between the
        // trim and the row it produces.
        admitted.push((resource, decision.ensure_allowed()?));
        readable.push(node);
    }

    let computed = capabilities_for_many(authorization, ctx, &admitted).await?;

    Ok(readable
        .into_iter()
        .zip(computed)
        .map(|(node, (capabilities, reasons, obligations))| {
            Item::new(node, capabilities, reasons, obligations)
        })
        .collect())
}

/// The capability actions of `docs/05-API.md §7`, paired with the wire name each answers to.
///
/// A table rather than nine call sites, so that adding an exposure means adding a row and the
/// response, the obligation mapping and the resolution stay in step by construction.
const CAPABILITY_ACTIONS: &[(&str, FileAction)] = &[
    ("preview", FileAction::Preview),
    ("download", FileAction::Download),
    ("print", FileAction::Print),
    ("export", FileAction::Export),
    ("edit", FileAction::Edit),
    ("share", FileAction::Share),
    ("shareExternal", FileAction::ShareExternal),
    ("delete", FileAction::Delete),
    ("move", FileAction::Move),
    ("restore", FileAction::Restore),
    ("sync", FileAction::Sync),
];

/// Computes `capabilities` and `obligations` for one file — the batch form, with one input.
///
/// The whole body is the delegation, on the same reasoning `PgAclAuthorization::authorize` gives
/// for delegating to its own batch path: two implementations of one question are how the singular
/// form ends up answering something the batch form does not. Here that would be a `GET /files/{id}`
/// that offers an action the row for the same file in the same caller's listing does not — a UI
/// that changes its mind about what a user may do because they clicked into the item.
pub(crate) async fn capabilities_for(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    resource: &ResourceRef,
    enforced: &Obligations,
) -> Result<(Capabilities, CapabilityReasons, WireObligations), Error> {
    let batch = [(*resource, enforced.clone())];
    let mut computed = capabilities_for_many(authorization, ctx, &batch).await?;
    match computed.pop() {
        Some(answer) => Ok(answer),
        // Unreachable: one input, one answer — `capabilities_for_many` sizes its vector from the
        // batch it was handed and never shortens it. If that ever stopped holding, the refusing
        // object is the safe one: a capability wrongly withheld costs a button, and the action
        // itself is enforced by the chain either way.
        //
        // The reasons object is empty rather than filled with `ACCESS_DENIED`. On this branch
        // nothing was decided, so there is no reason to report, and asserting one would be the
        // client-facing half of the same invention this type exists to prevent — a sentence
        // explaining a refusal that no stage made.
        None => {
            Ok((Capabilities::default(), CapabilityReasons::default(), WireObligations::default()))
        }
    }
}

/// Computes `capabilities` and `obligations` for a page of resources, one batch per action.
///
/// # The single-file endpoint and the listing cannot disagree
///
/// Both reach this function, and this function is the only place either one's object is built —
/// [`capabilities_for`] is a one-element call to it, not a parallel path. That closes three of the
/// four ways the two could have drifted: they read the same [`CAPABILITY_ACTIONS`] table, they call
/// the same `state.policy.authorization()` handle, and they run the same suppression in
/// [`apply_obligations`]. The fourth way is the inputs, and there are exactly two — the
/// [`ResourceRef`], built identically from the caller's own tenant in both handlers, and the
/// obligations of the decision that authorised *that resource's* `file.metadata_read`.
///
/// Those obligation sets are not merely both called "the enforced decision": the listing's comes
/// from the trim decision that admitted the row, and `GET /files/{id}`'s from the chain decision
/// that admitted the request, and `PolicyEngine::enforce` builds the latter by merging the former
/// with what the stages after authorization attach. So the listing's set is a subset of the file
/// endpoint's, and since [`apply_obligations`] only ever subtracts, a listing can never hide an
/// action the file response would offer — it can only, if a post-authorization stage ever attaches
/// an obligation to a metadata read, still offer one the file response has suppressed. That is the
/// same direction of error the whole object already tolerates by design (see below): optimistic, so
/// the failure is a refusal the user can be told about rather than an entitlement silently removed.
/// With today's chain the two sets are identical — the ACL stage attaches no obligations
/// (`crates/authorization/src/resolve.rs`) and every stage after it is unconfigured
/// ([`crate::unconfigured_stages`]) — which is what
/// `a_listings_capabilities_are_exactly_what_the_file_endpoint_returns` asserts over HTTP.
///
/// # Why the engine's own authorization stage
///
/// `docs/05-API.md §7`: *"`capabilities` is computed by the same policy engine that will enforce the
/// action — it is a UI hint derived from the real decision, not a parallel implementation."* That
/// sentence is a constraint on where the answer comes from, not just on what it says. It arrives
/// here as `state.policy.authorization()`: the very `Arc` the chain will consult when the caller
/// actually clicks download. A `PgAclAuthorization` constructed alongside the engine would resolve
/// the same rows today and be a second implementation to keep in step forever.
///
/// That stage handle is also *all* this is given — not [`ApiState`]. A probe that could reach the
/// engine could call `enforce`, which is how a helper quietly becomes a second enforcement point
/// the ENC-110 lint does not check; a probe that could reach the pool could answer from a query of
/// its own. Narrowing the argument makes both impossible rather than merely discouraged, and it is
/// what lets the unit tests below drive this with a scripted stage instead of a database.
///
/// # What it is not
///
/// It is not the whole chain. Conditional access, classification, DLP and retention can each refuse
/// an action this reports as available, and the engine will refuse it when the action is attempted —
/// which is the correct failure direction for a hint: a capability that is optimistic produces a
/// refusal the user can be told about, while one that is pessimistic hides a button the user is
/// entitled to. Reporting the whole chain needs a batch `enforce`, which the engine does not have
/// and which would have to answer what auditing nine speculative decisions means; see the note
/// handed to the integrator in [`crate`].
///
/// # The obligations from the *enforced* decision are applied, not merely reported
///
/// `CLAUDE.md` rule 8: obligations are satisfied, never dropped. Three of them shape this object
/// directly — [`Obligation::ReadOnly`] suppresses every mutation, [`Obligation::NoDownload`]
/// suppresses the paths that yield original bytes, and [`Obligation::NoSync`] suppresses sync — and
/// the suppression is applied *after* the ACL answer, so an obligation can only ever take a
/// capability away.
///
/// # The cost, and where it now falls
///
/// **One resolution for all of them.** `authorize_many_actions` batches actions as well as
/// resources (`ENC-167`), so a page of any size costs one resolution here — around three statements,
/// whatever the page holds — plus the trim's.
///
/// It used to cost one per action, and the measurement is why that changed rather than a guess:
/// ten actions over 200 candidates take **8.1 ms** in one pass and **68.5 ms** in ten, because
/// resolution's price is transaction setup plus three round trips rather than the size of the
/// batch. Sixty milliseconds per page against a 300 ms budget for metadata (`docs/03 §23`) is not
/// a micro-optimisation.
///
/// The approximation that was available and deliberately not taken — deriving `download` from
/// `preview`, say — is exactly the parallel implementation this function's contract forbids. What
/// changed is where the batching happens, not what is asked.
///
async fn capabilities_for_many(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    admitted: &[(ResourceRef, Obligations)],
) -> Result<Vec<(Capabilities, CapabilityReasons, WireObligations)>, Error> {
    if admitted.is_empty() {
        return Ok(Vec::new());
    }

    // Paired in the argument rather than passed as two slices, so that a resource and the
    // obligations of the decision that admitted it cannot be zipped out of step by an edit here.
    let resources: Vec<ResourceRef> = admitted.iter().map(|(resource, _)| *resource).collect();

    let mut computed: Vec<(Capabilities, CapabilityReasons, WireObligations)> = admitted
        .iter()
        .map(|(_, enforced)| {
            (
                Capabilities { metadata_read: true, ..Capabilities::default() },
                CapabilityReasons::default(),
                WireObligations {
                    watermark: enforced.contains(&Obligation::Watermark),
                    ..WireObligations::default()
                },
            )
        })
        .collect();

    // One resolution for every action, not one per action. See the cost note above.
    let actions: Vec<Action> =
        CAPABILITY_ACTIONS.iter().map(|(_, action)| Action::File(*action)).collect();
    let grid = authorization.authorize_many_actions(ctx, &actions, &resources).await?;

    // Index-aligned with `actions`, which is index-aligned with `CAPABILITY_ACTIONS`. A short outer
    // vector leaves the tail *actions* unanswered and a short inner one leaves the tail *rows*
    // unanswered; both withhold a capability rather than offering one that will be refused, which
    // is the direction an absent verdict has to fail in.
    for ((name, action), decisions) in CAPABILITY_ACTIONS.iter().zip(grid) {
        for ((capabilities, reasons, wire), decision) in computed.iter_mut().zip(decisions) {
            if !decision.is_allowed() {
                // `ENC-674`. This `continue` used to be the whole arm, and the stage's reason died
                // here: the response said `download: false` and the client, having nothing else,
                // had to compose an explanation of a decision it did not make.
                //
                // The code travels and nothing else does. `StageOutcome::Deny` carries a
                // `ReasonCode` and has no field a rule name could be written into, so rule 10 holds
                // by construction rather than by care taken at this line.
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
/// Exhaustive over [`FileAction`] on purpose: the enum is deliberately not `#[non_exhaustive]`
/// (`crates/core/src/action.rs`), so a new exposure breaks this match and forces someone to decide
/// whether the UI is allowed to offer it, rather than inheriting a silent `false`.
fn set_capability(capabilities: &mut Capabilities, action: FileAction) {
    match action {
        FileAction::MetadataRead => capabilities.metadata_read = true,
        FileAction::Preview => capabilities.preview = true,
        FileAction::Download => capabilities.download = true,
        FileAction::Print => capabilities.print = true,
        FileAction::Export => capabilities.export = true,
        FileAction::Edit => capabilities.edit = true,
        FileAction::Share => capabilities.share = true,
        FileAction::ShareExternal => capabilities.share_external = true,
        FileAction::Delete => capabilities.delete = true,
        FileAction::Move => capabilities.move_ = true,
        FileAction::Restore => capabilities.restore = true,
        FileAction::Sync => capabilities.sync = true,
        // Real actions with no field in `docs/05-API.md §7`'s capabilities object. They are not
        // silently ignored — they are listed here so that adding a field for one is a visible edit
        // rather than a discovery.
        FileAction::ContentRead
        | FileAction::Copy
        | FileAction::VersionRead
        | FileAction::VersionRestore
        | FileAction::ManagePermissions => {}
    }
}

/// Turns one capability off and records why, but only if it was on.
///
/// The guard is what keeps the reason honest. `apply_obligations` runs *after* the authorization
/// pass, so a capability that is already `false` here was refused by the ACL and already carries
/// that stage's code; overwriting it would tell the caller an obligation took away something they
/// were never granted. A capability that is `true` here was granted and is being taken away by this
/// obligation, which makes the obligation the proximate reason and the right one to report.
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

/// Subtracts from `capabilities` whatever the enforced decision's obligations forbid, recording the
/// code for each subtraction (`ENC-674`).
///
/// Only ever subtracts. An obligation is a restriction a stage attached to an *allow*, and one that
/// could add a capability would be a stage granting access outside the authorization stage.
///
/// # Why the codes are chosen here and not taken from `Obligation::unsatisfied_code`
///
/// That method answers a different question — *what is the caller told when they fail to satisfy
/// this obligation* — and it knows only the obligation. This site knows the **pair**: the
/// obligation and the specific capability it is suppressing. The extra fact changes the answer, and
/// on one pair it changes it from false to true.
///
/// `unsatisfied_code` maps [`Obligation::NoSync`] to `ACCESS_DENIED`, whose sentence is "You do not
/// have access to this." For a file the caller may preview, download and print, that is simply
/// untrue — the only thing they may not do is replicate it to a device, and `SYNC_NOT_PERMITTED`
/// ("This file is available on the web only.") says exactly that. Reporting the generic code here
/// would put a false statement in front of a user, which is the class of defect `ENC-673`–`ENC-675`
/// exist to close, so the pair is mapped rather than the obligation.
///
/// [`Obligation::ReadOnly`] does report `ACCESS_DENIED`, and that is the weakest answer in this
/// function: the vocabulary has no code for *you may read this but not change it*. `ENC-895` is
/// where that is recorded — it is a change to a published enumeration in `docs/05-API.md §5`, which
/// is wider than this row.
fn apply_obligations(
    capabilities: &mut Capabilities,
    reasons: &mut CapabilityReasons,
    obligations: &Obligations,
) {
    for obligation in obligations {
        match obligation {
            // "Suppress every mutation path in the response — no edit affordance, no write
            // capability in the returned `capabilities` object" (`crates/core/src/policy.rs`).
            Obligation::ReadOnly => {
                let code = ReasonCode::AccessDenied;
                withdraw(&mut capabilities.edit, reasons, "edit", code);
                withdraw(&mut capabilities.delete, reasons, "delete", code);
                withdraw(&mut capabilities.share, reasons, "share", code);
                withdraw(&mut capabilities.share_external, reasons, "shareExternal", code);
                // `ENC-807`. Relocating a node and bringing one back from the trash are both
                // mutations, and this arm's own comment says *every* mutation path. Adding a
                // capability field without adding it here is how a read-only file acquires a Move
                // control — the failure would be silent, because the field would simply stay `true`
                // and nothing asserts on a capability nobody thought to list.
                withdraw(&mut capabilities.move_, reasons, "move", code);
                withdraw(&mut capabilities.restore, reasons, "restore", code);
            }
            // Serve a rendition but never the original bytes. Print and export are here as well as
            // download because both yield content outside the viewer — collapsing them is the
            // mistake `CLAUDE.md` rule 6 is about.
            Obligation::NoDownload => {
                // `PREVIEW_ONLY` — "This file can be viewed but not downloaded" — is `docs/06 §24`'s
                // own worked example, and it is exactly what this obligation means.
                let egress = ReasonCode::PreviewOnly;
                withdraw(&mut capabilities.download, reasons, "download", egress);
                withdraw(&mut capabilities.print, reasons, "print", egress);
                withdraw(&mut capabilities.export, reasons, "export", egress);
                // Sync is suppressed by the same obligation but for a reason a user reads
                // differently: the file is not leaving the web viewer at all. Its own code says so.
                withdraw(&mut capabilities.sync, reasons, "sync", ReasonCode::SyncNotPermitted);
            }
            Obligation::NoSync => {
                withdraw(&mut capabilities.sync, reasons, "sync", ReasonCode::SyncNotPermitted);
            }
            // Shape nothing here: a watermark and a justification are reported in `obligations` for
            // the client to satisfy, and reclassification is the classification path's to apply.
            Obligation::Watermark
            | Obligation::RequireJustification
            | Obligation::RequireApproval
            | Obligation::Reclassify { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use enclave_core::{Remediation, StageDecision, TenantId};
    use uuid::Uuid;

    use super::*;

    fn request_id() -> RequestId {
        RequestId::new_v7()
    }

    /// An authorization stage that answers from a table, and counts how often it is asked.
    ///
    /// Two things need a stage that can be *told* what to say. One is a page whose rows differ: a
    /// listing where every row resolves the same way passes whether the batch is keyed by resource
    /// or ignores the resource entirely, so the interesting fixture is two rows with two answers.
    /// The other is the call count — the reason this work was postponed was cost, and "one
    /// resolution per action rather than per row" is a claim about the number of calls that no
    /// assertion about the returned JSON can make.
    #[derive(Debug)]
    struct Scripted {
        /// The `(resource, action)` pairs that are allowed. Everything absent is refused, which is
        /// the same default the real resolver reaches when no grant is found.
        allowed: Vec<(Uuid, FileAction)>,
        /// Resolutions asked for, counted across every action.
        calls: AtomicUsize,
    }

    impl Scripted {
        fn new(allowed: Vec<(Uuid, FileAction)>) -> Self {
            Self { allowed, calls: AtomicUsize::new(0) }
        }
    }

    #[async_trait::async_trait]
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
            self.calls.fetch_add(1, Ordering::Relaxed);
            let Action::File(action) = action else {
                panic!("a capability probe asks only file actions, not {action}")
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

    /// The capabilities object as it would reach the wire, so comparisons are of rendered JSON
    /// rather than of a struct whose fields a future edit might add to unnoticed.
    fn rendered(answer: &(Capabilities, CapabilityReasons, WireObligations)) -> serde_json::Value {
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
        let previewable = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let editable = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let neither = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let authorization = Scripted::new(vec![
            (previewable.id, FileAction::Preview),
            (editable.id, FileAction::Edit),
            (editable.id, FileAction::Delete),
        ]);

        let admitted = [
            (previewable, Obligations::none()),
            (editable, Obligations::none()),
            (neither, Obligations::none()),
        ];
        let computed = capabilities_for_many(&authorization, &ctx, &admitted).await.expect("probe");

        assert_eq!(computed.len(), 3);
        assert!(computed[0].0.preview && !computed[0].0.edit);
        assert!(computed[1].0.edit && computed[1].0.delete && !computed[1].0.preview);
        assert!(!computed[2].0.preview && !computed[2].0.edit && !computed[2].0.delete);
        // Every row survived the trim to get here, so every row can read metadata — and that is the
        // only field the three have in common.
        assert!(computed.iter().all(|(capabilities, _, _)| capabilities.metadata_read));
        // …and no row carries a reason for it, because it was never withheld (`ENC-674`). A reason
        // for a capability the caller holds is a sentence about a refusal that did not happen.
        assert!(computed.iter().all(|(_, reasons, _)| reasons.get("metadataRead").is_none()));
    }

    #[tokio::test]
    async fn a_row_answers_exactly_as_the_same_resource_asked_for_alone() {
        // The property `GET /files/{id}` and `GET /libraries/{id}/items` are held to over HTTP by
        // `a_listings_capabilities_are_exactly_what_the_file_endpoint_returns`, asserted here at the
        // function both endpoints go through — including the middle of a page, where an off-by-one
        // in the zip would show up as a neighbour's answer.
        let ctx = probe_context();
        let subject = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let before = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let after = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let authorization = Scripted::new(vec![
            (subject.id, FileAction::Preview),
            (subject.id, FileAction::Share),
            (before.id, FileAction::Download),
            (after.id, FileAction::Sync),
        ]);

        let alone = capabilities_for(&authorization, &ctx, &subject, &Obligations::none())
            .await
            .expect("one");
        let page = capabilities_for_many(
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
    async fn an_obligation_on_one_row_does_not_travel_to_its_neighbours() {
        // Obligations arrive per row, from the decision that admitted that row. Applying them to
        // the page would suppress a capability its caller holds; applying none would drop a
        // restriction. Both are visible here as the difference between the two rows.
        let ctx = probe_context();
        let restricted = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let unrestricted = ResourceRef::file(ctx.tenant_id, FileId::new_v7());
        let authorization = Scripted::new(vec![
            (restricted.id, FileAction::Download),
            (restricted.id, FileAction::Preview),
            (unrestricted.id, FileAction::Download),
            (unrestricted.id, FileAction::Preview),
        ]);

        let computed = capabilities_for_many(
            &authorization,
            &ctx,
            &[
                (
                    restricted,
                    Obligations::from_iter([Obligation::NoDownload, Obligation::Watermark]),
                ),
                (unrestricted, Obligations::none()),
            ],
        )
        .await
        .expect("probe");

        assert!(!computed[0].0.download && computed[0].0.preview);
        assert!(computed[0].2.watermark);
        assert!(computed[1].0.download, "a neighbour's obligation took a capability away");
        assert!(!computed[1].2.watermark);
        // The reason travels per row for the same reason the obligation does (`ENC-674`). The
        // neighbour holds `download`, so it must carry no reason for it — a reason on an available
        // capability would render a refusal the server never made.
        assert_eq!(computed[0].1.get("download"), Some(ReasonCode::PreviewOnly));
        assert_eq!(computed[1].1.get("download"), None);
    }

    #[tokio::test]
    async fn a_page_costs_the_same_resolution_however_many_rows_it_holds() {
        // The reason capabilities were left off a listing in the first place: a per-row loop over
        // two hundred rows would have been eighteen hundred resolutions.
        //
        // What this counts is `Scripted`'s `authorize_many`, and `Scripted` does not override
        // `authorize_many_actions` — so it gets the trait's default body, which loops. That is
        // deliberate and worth stating plainly: this test proves the count does not scale with the
        // *page*, which is the property the API layer is responsible for. It cannot prove the count
        // does not scale with the number of *actions*, because for this stub it does. That property
        // belongs to `PgAclAuthorization`'s override and is measured where it can be — in
        // `crates/authorization/tests/authorize_many_cost.rs`, which puts one pass at 8.1 ms
        // against 68.5 ms for ten (`ENC-167`).
        let ctx = probe_context();
        let page: Vec<(ResourceRef, Obligations)> = (0..200)
            .map(|_| (ResourceRef::file(ctx.tenant_id, FileId::new_v7()), Obligations::none()))
            .collect();

        let authorization = Scripted::new(Vec::new());
        let computed = capabilities_for_many(&authorization, &ctx, &page).await.expect("probe");
        assert_eq!(computed.len(), 200);
        let for_two_hundred = authorization.calls.load(Ordering::Relaxed);

        let one = Scripted::new(Vec::new());
        let _ = capabilities_for_many(&one, &ctx, &page[..1]).await.expect("probe");
        let for_one = one.calls.load(Ordering::Relaxed);

        assert_eq!(
            for_two_hundred, for_one,
            "two hundred rows cost more resolutions than one, so the page is being resolved per row"
        );
        assert!(
            for_two_hundred <= CAPABILITY_ACTIONS.len(),
            "a page cost {for_two_hundred} resolutions for {} actions",
            CAPABILITY_ACTIONS.len()
        );
    }

    #[tokio::test]
    async fn an_empty_page_asks_the_stage_nothing() {
        // A folder whose every row was trimmed must not spend nine resolutions proving it.
        let ctx = probe_context();
        let authorization = Scripted::new(Vec::new());
        let computed = capabilities_for_many(&authorization, &ctx, &[]).await.expect("probe");
        assert!(computed.is_empty());
        assert_eq!(authorization.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_access_denied_read_is_indistinguishable_from_an_absence() {
        // The single rule of `CLAUDE.md` 7, asserted rather than described: another tenant's id, a
        // fabricated one and an ungranted one all reach the chain as `ACCESS_DENIED` and all leave
        // as `NotFound`.
        let denied =
            Error::PolicyDenied { code: ReasonCode::AccessDenied, remediation: Remediation::None };
        assert!(matches!(existence_gate(denied), Error::NotFound));
    }

    #[test]
    fn a_denial_that_does_not_speak_to_existence_keeps_its_own_answer() {
        // These are produced either before authorization (so they refuse a nonexistent id the same
        // way) or after it (so the caller already holds a grant). Flattening them into `404` would
        // tell a user on a blocked network that their own file does not exist.
        for code in [
            ReasonCode::NetworkNotAllowed,
            ReasonCode::StepUpRequired,
            ReasonCode::ClassificationCeiling,
            ReasonCode::DlpBlocked,
            ReasonCode::LegalHoldActive,
        ] {
            let error = Error::PolicyDenied { code, remediation: Remediation::None };
            assert!(
                matches!(existence_gate(error), Error::PolicyDenied { code: kept, .. } if kept == code),
                "{code} must keep its own status"
            );
        }
    }

    #[test]
    fn limits_clamp_rather_than_reject_and_default_to_fifty() {
        // `docs/05-API.md §6`: default 50, maximum 500.
        assert_eq!(page_size(None, request_id()).unwrap().get(), 50);
        assert_eq!(page_size(Some("100"), request_id()).unwrap().get(), 100);
        assert_eq!(page_size(Some("100000"), request_id()).unwrap().get(), 500);
        // Zero clamps up: a page size of zero returns nothing forever, which is an infinite paging
        // loop rather than an empty answer.
        assert_eq!(page_size(Some("0"), request_id()).unwrap().get(), 1);
        assert!(page_size(Some("all of them"), request_id()).is_err());
    }

    #[test]
    fn a_history_limit_is_clamped_to_the_repositorys_own_ceiling() {
        assert_eq!(history_limit(None, request_id()).unwrap().get(), 50);
        assert_eq!(history_limit(Some("1000"), request_id()).unwrap().get(), PageLimit::MAX);
        assert!(history_limit(Some(""), request_id()).is_err());
    }

    #[test]
    fn a_history_cursor_round_trips_the_number_it_was_rendered_from() {
        let number = VersionNumber::new(3, 2);
        let rendered = number.to_string();
        assert_eq!(history_cursor(Some(&rendered), request_id()).unwrap(), Some(number));
        assert_eq!(history_cursor(None, request_id()).unwrap(), None);
        for bad in ["3", "", "3.", ".2", "x.y", "3.2.1"] {
            assert!(history_cursor(Some(bad), request_id()).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn read_only_and_no_download_only_ever_subtract() {
        let full = || Capabilities {
            metadata_read: true,
            preview: true,
            download: true,
            print: true,
            export: true,
            edit: true,
            share: true,
            share_external: true,
            delete: true,
            move_: true,
            restore: true,
            sync: true,
        };

        let mut caps = full();
        let mut why = CapabilityReasons::default();
        apply_obligations(&mut caps, &mut why, &Obligations::from_iter([Obligation::ReadOnly]));
        assert!(!caps.edit && !caps.delete && !caps.share && !caps.share_external);
        assert!(
            !caps.move_ && !caps.restore,
            "relocating and restoring are mutations, and read-only means every mutation (`ENC-807`)"
        );
        assert!(caps.preview && caps.download, "read-only restricts writing, not reading");
        // Every suppression names itself (`ENC-674`), and only the suppressions do: `preview` and
        // `download` survived, so a reason for either would be an invented refusal.
        assert_eq!(why.get("edit"), Some(ReasonCode::AccessDenied));
        assert_eq!(why.get("shareExternal"), Some(ReasonCode::AccessDenied));
        assert_eq!(why.get("move"), Some(ReasonCode::AccessDenied));
        assert_eq!(why.get("restore"), Some(ReasonCode::AccessDenied));
        assert_eq!(why.get("preview"), None);
        assert_eq!(why.get("download"), None);
        // Six, not four: `ENC-807` added `move` and `restore` to the object and therefore to what
        // read-only takes away. The count is asserted rather than left implicit because it is the
        // only assertion here that fails when a *future* mutation capability is added to the struct
        // and not to the arm above — the named `get`s all pass while the new field stays `true`.
        assert_eq!(why.len(), 6, "one reason per capability actually taken away");

        let mut caps = full();
        let mut why = CapabilityReasons::default();
        apply_obligations(&mut caps, &mut why, &Obligations::from_iter([Obligation::NoDownload]));
        assert!(!caps.download && !caps.print && !caps.export && !caps.sync);
        assert!(caps.preview, "a rendition is exactly what NoDownload still permits");
        // `docs/06 §24`'s worked example, on the three content-egress capabilities.
        assert_eq!(why.get("download"), Some(ReasonCode::PreviewOnly));
        assert_eq!(why.get("print"), Some(ReasonCode::PreviewOnly));
        assert_eq!(why.get("export"), Some(ReasonCode::PreviewOnly));
        // Sync is suppressed by the same obligation and reported with its own code, because
        // "available on the web only" is what a user needs to hear about a replica that will not
        // appear. See `apply_obligations` for why this is not `Obligation::unsatisfied_code`.
        assert_eq!(why.get("sync"), Some(ReasonCode::SyncNotPermitted));

        // Nothing an obligation can do turns a `false` into a `true`.
        let mut none = Capabilities::default();
        let mut none_why = CapabilityReasons::default();
        for obligation in [
            Obligation::ReadOnly,
            Obligation::NoDownload,
            Obligation::NoSync,
            Obligation::Watermark,
            Obligation::RequireJustification,
        ] {
            apply_obligations(&mut none, &mut none_why, &Obligations::from_iter([obligation]));
        }
        // …and an obligation cannot manufacture a reason for a capability it did not take away.
        // Every field was already `false` on entry, so the suppression pass fired on none of them
        // and the object stays empty — which is what stops a client being told an obligation
        // refused something the ACL had already refused for a different reason.
        assert_eq!(none_why.len(), 0);
        let rendered = serde_json::to_value(&none).expect("serialize");
        assert!(
            rendered.as_object().expect("object").values().all(|value| value == false),
            "{rendered}"
        );
    }

    #[test]
    fn every_capability_name_maps_to_the_field_it_claims() {
        // The table and the setter are two lists that must not drift: a row whose name says
        // `download` and whose action sets `print` is a UI that offers the wrong button.
        for (name, action) in CAPABILITY_ACTIONS {
            let mut caps = Capabilities::default();
            set_capability(&mut caps, *action);
            let rendered = serde_json::to_value(&caps).expect("serialize");
            let object = rendered.as_object().expect("object");
            assert_eq!(object.get(*name), Some(&serde_json::Value::Bool(true)), "{name}");
            assert_eq!(
                object.values().filter(|value| *value == &serde_json::Value::Bool(true)).count(),
                1,
                "{name} set more than its own field"
            );
        }
    }

    #[test]
    fn the_capability_table_covers_every_field_the_contract_names() {
        // `docs/05-API.md §7` lists nine. `metadataRead` is the tenth field and is true by
        // construction rather than resolved, so it is not in the table.
        let rendered = serde_json::to_value(Capabilities::default()).expect("serialize");
        let fields: Vec<String> = rendered.as_object().expect("object").keys().cloned().collect();
        assert_eq!(fields.len(), CAPABILITY_ACTIONS.len() + 1);
        for (name, _) in CAPABILITY_ACTIONS {
            assert!(fields.iter().any(|field| field == name), "{name} has no field");
        }
    }

    #[test]
    fn a_page_never_carries_a_total() {
        // The field does not exist, so it cannot be added by accident (`docs/05-API.md §6`).
        let page: Page<Item> = Page {
            items: Vec::new(),
            page: PageInfo { next_cursor: None, has_more: true, limit: 50 },
        };
        let rendered = serde_json::to_value(&page).expect("serialize");
        let info = rendered.get("page").and_then(serde_json::Value::as_object).expect("page");
        assert!(!info.contains_key("total"));
        assert!(!info.contains_key("totalCount"));
        assert!(!info.contains_key("count"));
        assert_eq!(info.get("hasMore"), Some(&serde_json::Value::Bool(true)));
        // Absent rather than null, so a client cannot mistake "no next page" for "cursor omitted".
        assert!(!info.contains_key("nextCursor"));
    }

    #[test]
    fn a_resource_reference_always_carries_the_callers_own_tenant() {
        // `CLAUDE.md` rule 3, as a property of the construction: there is no path by which a
        // reference built here can name a tenant other than the context's, which is what makes
        // another tenant's id arrive as an unresolvable id of this one.
        let tenant = TenantId::new_v7();
        let file = FileId::new_v7();
        assert_eq!(ResourceRef::file(tenant, file).tenant_id, tenant);
        assert_eq!(ResourceRef::folder(tenant, file).tenant_id, tenant);
        assert_eq!(ResourceRef::library(tenant, LibraryId::new_v7()).tenant_id, tenant);
    }

    #[test]
    fn a_version_entry_never_carries_the_coordinates_of_the_bytes() {
        // `CLAUDE.md` rule 6: a metadata path must not hand out a route to the original object.
        // Asserted against the rendered field names rather than by reading the struct, because the
        // failure this guards against is someone adding a field, not someone rewriting the module.
        let entry = VersionEntry {
            id: "01937fa1-0000-7000-8000-000000000001".to_owned(),
            major: 1,
            minor: 0,
            status: "AVAILABLE",
            av_status: "CLEAN",
            approval_state: None,
            size_bytes: 42,
            mime_type: "application/pdf".to_owned(),
            checksum_sha256: "0".repeat(64),
            is_readable: true,
            created_by: "01937fa2-0000-7000-8000-000000000001".to_owned(),
            created_at: chrono::Utc::now(),
            comment: None,
        };
        let rendered = serde_json::to_value(&entry).expect("serialize");
        let fields = rendered.as_object().expect("object");
        for forbidden in
            ["objectKey", "object_key", "storageProfileId", "encryptionKeyRef", "url", "signedUrl"]
        {
            assert!(!fields.contains_key(forbidden), "{forbidden} reached the wire");
        }
    }

    /// `ENC-825`: the file response has to answer "will a preview work", and answer it in the
    /// vocabulary `docs/09-UX-WHITE-LABELING.md §8` needs rather than as a bare boolean.
    ///
    /// A field-name assertion rather than a struct read, for the reason the test above gives: the
    /// regression this guards against is somebody *removing* a field on the argument that `status`
    /// already says enough — which is exactly the belief that made `AVAILABLE` / `SKIPPED`
    /// indistinguishable from `AVAILABLE` / `CLEAN` on this endpoint.
    #[test]
    fn a_version_state_says_whether_a_delivery_route_would_serve_it_and_why() {
        let state = VersionState {
            id: "01937fa1-0000-7000-8000-000000000001".to_owned(),
            major: 1,
            minor: 0,
            status: "AVAILABLE",
            av_status: "SKIPPED",
            is_readable: false,
        };
        let rendered = serde_json::to_value(&state).expect("serialize");
        let fields = rendered.as_object().expect("object");

        for required in ["status", "avStatus", "isReadable"] {
            assert!(
                fields.contains_key(required),
                "`{required}` is gone from currentVersion. Without all three a client cannot tell \
                 a file that is still being scanned from one that will never be servable, and \
                 `status` alone reports this very version — AVAILABLE, SKIPPED, refused by every \
                 delivery route — as though it were ready (ENC-825)"
            );
        }
        // The state this row exists for: published, unscanned, and not servable.
        assert_eq!(fields["status"], "AVAILABLE");
        assert_eq!(fields["isReadable"], serde_json::Value::Bool(false));

        // Rule 6 still holds of the new shape, not only of the history entry.
        for forbidden in ["objectKey", "storageProfileId", "encryptionKeyRef", "url"] {
            assert!(!fields.contains_key(forbidden), "{forbidden} reached the wire");
        }
    }

    /// The half the assertion above cannot make: that `isReadable` is *the predicate*, not a
    /// paraphrase of it.
    ///
    /// `FileVersion` is `#[non_exhaustive]`, so no test in this crate can build one and compare
    /// the two answers directly — `crates/api/tests/content.rs` does that over real rows, across
    /// the whole cross-product. What is checkable here is the thing that makes the cross-product
    /// test stay true: both renderings call `is_readable()`, and neither writes rule 9 out.
    ///
    /// The needles are assembled at run time. `docs/12-TESTING.md §1.2`: a source-scanning test
    /// whose needle appears in its own source fails against itself, and two tests in this
    /// repository already have.
    #[test]
    fn readability_is_rendered_from_the_predicates_twin_and_never_recomputed_here() {
        let source = include_str!("content.rs");
        let all = source.split("mod tests {").next().expect("the module has a body");
        // Comments are excluded, and deliberately: the documentation above *quotes* the predicate,
        // which is how a reader learns what the code is refusing to restate. What must not exist
        // is an executable copy.
        let module: String = all
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        // Both places that put a readability answer on the wire read the one function.
        assert_eq!(
            module.matches("is_readable: version.is_readable()").count(),
            2,
            "`VersionState` and `VersionEntry` must both render readability from \
             `FileVersion::is_readable` — the Rust twin of the predicate the delivery routes' \
             query splices. A hand-written answer in either is a second implementation of rule 9, \
             and the endpoints drift the first time the predicate moves"
        );

        // And rule 9 is not spelled out anywhere in this module, in either language.
        for needle in [
            format!("{}Status::Available", "Version"),
            format!("{}Status::Clean", "Av"),
            format!("status = '{}'", "AVAILABLE"),
        ] {
            assert!(
                !module.contains(&needle),
                "`{needle}` appears in this module. Whether a version may be served is decided in \
                 `enclave_versions` and nowhere else (CLAUDE.md rule 9); a copy here is a copy \
                 that can disagree with the route that actually refuses the request"
            );
        }
    }
}
