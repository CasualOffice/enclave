//! `GET /api/v1/trash` — the recycle bin, and the endpoint that makes `POST /files/{id}/restore`
//! reachable.
//!
//! # What was missing
//!
//! `ENC-807` shipped `DELETE /api/v1/files/{id}` and `POST /api/v1/files/{id}/restore`, and left
//! them unconnected. `GET /libraries/{id}/items` filters trashed rows out and
//! `FileRepository::find_including_trashed` resolves an id the caller already holds, so **nothing
//! listed the trash**: a document deleted through the product disappeared from every surface in it
//! and could be restored only by somebody who had written its UUID down beforehand.
//!
//! That is this repository's signature failure — a complete, tested engine that nothing calls —
//! arriving in the form where it costs a person their work. `crates/api/tests/trash.rs` therefore
//! runs against the shipped [`crate::router`] and mounts nothing of its own, and its first test does
//! the whole journey the long way round: delete a file over HTTP, find it here, restore it with the
//! revision this response carried.
//!
//! # The question is `file.restore`, and it is asked of the container
//!
//! **Not `file.metadata_read`.** A recency row is a link and is decided by what it discloses
//! (`routes::recent`); a trash row exists to be *acted on*, and it has exactly one action. Showing
//! somebody a row they cannot restore is offering them a button that will refuse them, which is
//! worse than not showing the row: the refusal arrives after they have decided the document is
//! recoverable. So the action every candidate is put to is the action the next request will take.
//!
//! **And it is asked of the container the node returns into, never of the node.**
//! `crates/authorization/src/repo.rs`'s `FILE_CHAIN_SQL` joins `files` with `deleted_at IS NULL` on
//! the walk's own root, so **a trashed node has an empty inheritance chain** and every question
//! about it resolves to `NotGranted`. Asking `file.restore` on the trashed node would refuse every
//! row for every caller forever — an endpoint that answers `200` with an empty list and a
//! `filteredCount` equal to the size of the bin. That is the `ENC-170` shape reached through the
//! authorization layer, and it is the same trap `routes::lifecycle::restore` documents; this module
//! asks the identical question of the identical resource, through [`container_of`], which mirrors
//! `lifecycle::destination_of` so the listing and the restore cannot come to disagree about one
//! folder.
//!
//! The consequence is honest and is stated rather than hidden: when a node's parent folder is
//! *itself* still in the trash, that folder's chain is empty too, so the row is dropped here and
//! `POST /restore` would answer `404` for it. Both are refusals, neither writes, and the remedy is
//! the same one `lifecycle` names — restore the folder above it first, which is a row this listing
//! does show.
//!
//! # A dropped row is counted, never refused
//!
//! The read model is **tenant-wide** (`enclave_db::trash`), which is deliberate: a person looking
//! for something they deleted does not remember which library it was in, and that is most of why
//! they are looking. It also means the candidate window routinely holds other people's deletions in
//! libraries this caller has never seen.
//!
//! Every candidate therefore goes to the authorization stage in one
//! [`AuthorizationService::authorize_many`], and a candidate that is refused is **dropped and
//! counted** into `filteredCount` — never turned into a `403` or a `404` for the whole page.
//! `CLAUDE.md` rule 7: a per-row status would confirm that a particular file exists, was deleted,
//! and by implication where. The count says how many rows were withheld; nothing in the response
//! says which, and no name or id of a withheld row appears anywhere in the body.
//!
//! # `filteredCount` is a floor, and it is exact where a client reads it
//!
//! `enclave_db::trash::roots` over-fetches and reports
//! [`TrashCandidates::more_beyond_window`](enclave_db::trash::TrashCandidates::more_beyond_window)
//! when it stopped short of the end of the bin. The wire contract has no field for that flag and
//! this handler does not widen and re-ask, for `routes::recent`'s reason: the number a client acts
//! on is the one that separates *"your recycle bin is empty"* from *"some deleted items are not
//! yours to restore"*, and that distinction is only ever read when the page came back short — which
//! is exactly when the window was consumed and the count is exact. When the page is full the number
//! may under-report and no state depends on it.
//!
//! # The chain runs once for the request, and the stage runs once for the page
//!
//! [`list`] calls [`PolicyEngine::enforce`](enclave_core::PolicyEngine::enforce) on the caller's own
//! user record — the same question `GET /api/v1/me` and `GET /me/recent` ask — and then decides the
//! rows through the authorization stage in one batch. It does **not** call `enforce` per candidate,
//! and that is a deliberate departure from the literal reading of rule 1 rather than an oversight:
//! the engine audits every decision it takes (rule 10), so a window of two hundred candidates would
//! write two hundred `audit_events` rows for one listing, most of them about resources the caller
//! never learns exist. `routes::recent` and `content::readable_children` are the two precedents and
//! this is the third; what they have in common is that the *request* is enforced by the chain and
//! each *row* is trimmed by the stage the chain would consult.
//!
//! The request-level question is a gate on the principal, not on the bin. There is no `acl_entries`
//! row anywhere that names "this tenant's trash", and inventing a tenant-level permission to guard
//! this endpoint would be a second, quieter policy vocabulary; the access control that matters is
//! the per-row one below.
//!
//! # Connection discipline
//!
//! The read and the ACL batch never overlap. `crates/api/src/content.rs` states the rule — each
//! `authorize_many` takes its **own** connection from the same pool, so a handler holding a
//! transaction across one needs two per request, and on the default pool of sixteen with a
//! five-second acquire timeout that is a deadlock waiting for load. `routes::lifecycle::trash` is
//! the worked example: read in a short transaction, close it, then decide. This does the same.
//!
//! # What `capabilities` means on a trash row, exactly
//!
//! The object is the twelve-key one `GET /files/{id}` returns, built by the same
//! `crate::content::capabilities_for` — `ENC-929` is what a second copy costs. It is resolved
//! **against the container**, because that is the only resource in this request with a chain to
//! resolve: against the trashed node every key would come back `false`, including `restore`, and a
//! conforming client renders its actions from this object and never re-derives them, so an
//! all-`false` object would draw a recycle bin in which nothing can be restored.
//!
//! What that buys is a `restore` key that is exactly the answer `POST /files/{id}/restore` will
//! give, which is the one key a trash row needs. What it costs is stated plainly because a reader
//! will otherwise assume more: **the other eleven keys answer about the container, not about the
//! deleted node.** A caller holding `file.download` on the library sees `download: true` on a trash
//! row, and a download of a trashed file is refused by the delivery path regardless. The surface
//! specification gives a trash row one control, and this is the object it is rendered from; a client
//! that draws the other ten from it is reading a field that was never about them.
//!
//! # What the wire deliberately omits
//!
//! `capabilityReasons` and the `obligations` object that `GET /files/{id}` carries, for
//! `routes::recent`'s reason: a trash row has one interaction. `sizeBytes`, `status` and the
//! timestamps a browse row carries are omitted for a sharper one — the fields on this row are the
//! ones a person needs to recognise what they deleted and the ones the *next request* needs, and
//! nothing else. `revision` is on it for exactly that reason and is not decoration: the restore
//! requires `If-Match`, and a trashed file answers `404` to the `GET` a client would otherwise read
//! its `ETag` from.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, AuthorizationService, ContainerAction, Error, FieldError, FileAction, FileId,
    LibraryId, Obligations, PolicyDecision, ReasonCode, RequestContext, RequestId, ResourceRef,
    TenantId, UserId, ValidationCode,
};
use enclave_db::trash::{TrashCandidate, TrashCandidates};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Capabilities};
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The question this endpoint asks about the caller themselves.
///
/// The same action `GET /api/v1/me` and `GET /me/recent` ask on the same resource, so a caller who
/// can read their own record can open the recycle bin and the three cannot come to disagree.
/// `enclave_authorization::SelfServiceOr` is what answers it; nothing in `acl_entries` names a
/// user's own row. See the module header for why the *request* is gated on the principal while every
/// *row* is decided on its own.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// The question asked of every candidate, and the one a dropped row was dropped by.
///
/// `file.restore`, asked of the container the node returns into — the module header argues both
/// halves, and `routes::lifecycle::REINSTATE` is the same constant for the same reason. A row that
/// survives this question is a row whose restore this deployment's authorization stage has already
/// said yes to.
const REINSTATE: Action = Action::File(FileAction::Restore);

/// Rows returned when the caller names no `limit`.
///
/// Fifty. A recycle bin is read to find one thing, so it wants a page long enough that a person
/// scrolling recognises what they are after without paging; fifty is the contract's own example
/// (`?limit=50`).
pub const DEFAULT_LIMIT: u32 = 50;

/// The most rows one request can render.
///
/// Equal to [`DEFAULT_LIMIT`], as `routes::recent`'s cap is equal to its default, and for the same
/// measured reason: [`item`] costs **one capability resolution per rendered row**, because
/// `content::capabilities_for_many` is private to `crate::content` and this module may not widen it.
/// So this constant bounds the only cost in the handler that is not batched — fifty resolutions,
/// off any critical path, on a screen a person opens deliberately.
///
/// If it is ever raised, the change is to export `capabilities_for_many` and call it once. It is
/// **not** to build a second capabilities object here; that is `ENC-929`, which is a client that
/// changes its mind about what a user may do depending on which screen it read the file from.
pub const MAX_LIMIT: u32 = 50;

/// The fewest rows a request can ask for.
///
/// One rather than zero. A `limit=0` would answer with an empty list and `filteredCount: 0` — byte
/// for byte the response somebody with an empty recycle bin receives — and those two states must
/// stay distinguishable (`docs/09 §11`). A request that cannot be answered honestly is clamped to
/// the smallest one that can be.
const MIN_LIMIT: u32 = 1;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// `?limit=` and nothing else.
///
/// A `String` rather than a `u32` so that an unparseable value reaches [`limit`] and becomes
/// `docs/05-API.md §5`'s validation envelope, instead of axum's own rejection — which would answer a
/// different shape from every other listing in the surface. `routes::recent::RecentParams` and
/// `content::BrowseParams` take it the same way for the same reason.
#[derive(Debug, Deserialize)]
pub struct TrashParams {
    limit: Option<String>,
}

/// The body of `GET /api/v1/trash`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashPage {
    /// The rows this caller may restore, most recently deleted first.
    items: Vec<TrashItem>,
    /// How many candidates the authorization stage dropped.
    ///
    /// Never *which*. See the module header for why this is a floor and why the floor is exact
    /// wherever a client reads it.
    filtered_count: usize,
}

/// One item in the recycle bin.
///
/// Every field is either what a person needs to recognise what they deleted — the name, the kind,
/// who deleted it, when — or what the *next request* needs. `revision` is the second kind and is the
/// reason this endpoint exists in the shape it does.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrashItem {
    file_id: String,
    name: String,
    /// `FILE` or `FOLDER`. A folder's restore brings back everything trashed with it, which is a
    /// different confirmation dialog and a different icon.
    node_type: &'static str,
    mime_type: String,
    library_id: String,
    /// The folder this item will return into, or `null` at the library root.
    parent_folder_id: Option<String>,
    deleted_at: DateTime<Utc>,
    /// When permanent deletion may first be *considered*, or `null` when the row carries none.
    ///
    /// On the wire so a client can say how long is left. `null` rather than an invented date: a
    /// countdown over a retention nobody configured is worse than no countdown.
    purge_after: Option<DateTime<Utc>>,
    deleted_by: Deleter,
    /// The value the next `If-Match` must carry.
    ///
    /// `POST /files/{id}/restore` requires the precondition and a trashed file answers `404` to the
    /// `GET` that would otherwise supply its `ETag`, so a listing that omitted this would show a
    /// caller a document they cannot restore.
    revision: i64,
    /// What this caller may do — resolved against the container, which is where a trashed node's
    /// permissions live. The module header is explicit about what the other keys mean here.
    capabilities: Capabilities,
}

/// Who moved the item to the trash.
///
/// From `files.modified_by`, which the trash write stamps. `displayName` is `null` when no `users`
/// row answers to the id, which the read model reports rather than hiding the row over — see
/// `enclave_db::trash`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Deleter {
    id: String,
    display_name: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/trash`.
///
/// # The order of the five steps
///
/// 1. **The chain decides**, on the caller's own user record, before `limit` is looked at and before
///    any row is read. A caller the chain refuses learns nothing about the request schema —
///    `routes::permissions::replace_acl` orders it the same way.
/// 2. **The window is read in a short transaction**, which is committed before anything else runs.
/// 3. **Every candidate is put to the authorization stage in one batch**, on the container it would
///    return into, and a refusal drops the row rather than the request.
/// 4. **The survivors are truncated to `limit`**, and only then do they cost a capability
///    resolution each.
/// 5. **`filteredCount` is candidates presented minus candidates that survived**, not minus
///    candidates rendered: a row left out because the page was full was not filtered by anything,
///    and reporting it as one would tell a user that deleted documents were withheld from them when
///    none were.
///
/// # Errors
///
/// [`ApiError`]: `400` for a `limit` that is not a number; the denial's own status when the chain
/// refuses the self-read; `403` with the obligation's own code when that decision carried an
/// obligation this path cannot discharge; a storage failure's mapped form.
pub async fn list(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<TrashParams>,
) -> Result<Json<TrashPage>, ApiError> {
    let request_id = ctx.request_id;

    // Refused before the chain runs, so the audit row this writes stands alone and asserts nothing
    // about a policy decision that was never taken. `me::subject` and `routes::recent::subject` make
    // the same call for the same reason.
    let user = match subject(&ctx) {
        Ok(user) => user,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ_SELF, &resource, refused).await);
        }
    };

    let resource = ResourceRef::user(ctx.tenant_id, user);
    let decision = state
        .policy
        .enforce(&ctx, READ_SELF, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // No stage attaches an obligation to opening your own recycle bin, and this path could satisfy
    // none if one arrived: there is no rendition to watermark, no bytes to withhold and nowhere to
    // collect a justification. An unsatisfiable obligation is a refusal, never a shrug
    // (`CLAUDE.md` rule 8, D29). `none_dischargeable` rather than `Obligations::require_none`
    // because the chain has already written its `ALLOW` — an `Error` here is `ENC-606`.
    let obligations = consume(decision);
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, READ_SELF, &resource, refused).await);
    }

    let limit = limit(params.limit.as_deref(), request_id)?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let window: TrashCandidates = enclave_db::trash::roots(&mut tx, limit)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    // Committed before the batch below, deliberately. See the module header's connection note.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let (survivors, filtered_count) =
        admit(state.policy.authorization().as_ref(), &ctx, &window.candidates, limit)
            .await
            .map_err(|error| ApiError::new(error, request_id))?;

    let mut items = Vec::with_capacity(survivors.len());
    for (candidate, container, enforced) in survivors {
        items.push(
            item(state.policy.authorization().as_ref(), &ctx, candidate, &container, &enforced)
                .await
                .map_err(|error| ApiError::new(error, request_id))?,
        );
    }

    Ok(Json(TrashPage { items, filtered_count }))
}

/// One candidate that survived: the row, the container it was decided against, and the obligations
/// of the decision that admitted it.
///
/// A triple rather than three parallel vectors for `capabilities_for_many`'s reason: a resource and
/// the obligations of the decision that admitted *it* must not be zippable out of step by a later
/// edit.
type Admitted<'a> = (&'a TrashCandidate, ResourceRef, Obligations);

/// Puts the whole window to the authorization stage and keeps the rows it allowed.
///
/// Returns the survivors, truncated to `limit`, and the number of candidates the stage dropped.
/// **The count is over the whole window, not over what is returned**: a candidate left behind
/// because the page was already full was not filtered by policy.
///
/// One [`AuthorizationService::authorize_many`] for the window — never a call per row, which is what
/// the batch form exists on the trait to prevent.
///
/// The references are the **containers**, and duplicates among them are passed through rather than
/// deduplicated: a folder's worth of separately deleted files shares one container, so the batch
/// often holds the same reference many times. Keeping it index-aligned with the candidates is what
/// makes it impossible for the loop below to attribute one row's verdict to another; if the
/// duplication ever costs anything measurable, the deduplication belongs inside `authorize_many`,
/// where every caller gets it.
///
/// A resolution that *fails* refuses the request rather than returning an untrimmed page:
/// `crates/core/src/engine.rs` is explicit that a failed resolution is not a denial, and a recycle
/// bin that could not be trimmed is a listing of every deletion in the tenant.
///
/// # Errors
///
/// Resolution failures, mapped onto the vocabulary the API edge speaks.
async fn admit<'a>(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    candidates: &'a [TrashCandidate],
    limit: u32,
) -> Result<(Vec<Admitted<'a>>, usize), Error> {
    if candidates.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let refs: Vec<ResourceRef> = candidates
        .iter()
        .map(|candidate| {
            container_of(ctx.tenant_id, candidate.library_id, candidate.parent_folder_id)
        })
        .collect();
    let decisions = authorization.authorize_many(ctx, REINSTATE, &refs).await?;

    // Index-aligned with `refs` by contract. A shorter answer leaves the tail undecided, and `zip`
    // drops it — which counts those rows as filtered and shows fewer of them. That is the direction
    // an absent verdict has to fail in here: over-reporting how much was withheld costs a user a
    // sentence, and under-reporting it offers a restore nobody decided about.
    let mut survivors: Vec<Admitted<'a>> = Vec::new();
    let mut survived = 0_usize;
    for ((candidate, container), decision) in candidates.iter().zip(refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        // The stage allowed, so this cannot be an `Err`. Taking the obligations rather than dropping
        // the decision is what keeps a `READ_ONLY` attached to this container from evaporating
        // between the trim and the capabilities built from it.
        let enforced = decision.ensure_allowed()?;
        survived += 1;
        if survivors.len() < limit as usize {
            survivors.push((candidate, container, enforced));
        }
    }

    Ok((survivors, candidates.len() - survived))
}

/// Renders one surviving candidate, capabilities included.
///
/// The capabilities are resolved against the **container**, which is the resource the row was
/// admitted by and the only one in this request with an inheritance chain to walk — the module
/// header says what that buys and what it costs. The obligations passed in are the ones from the
/// decision that admitted this row, exactly as `content::readable_children` passes the trim's; they
/// only ever subtract.
///
/// One resolution per rendered row, because `content::capabilities_for` is a one-element call to a
/// batch form that is private to `crate::content`. [`MAX_LIMIT`] is what bounds it.
///
/// # Errors
///
/// Resolution failures.
async fn item(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    candidate: &TrashCandidate,
    container: &ResourceRef,
    enforced: &Obligations,
) -> Result<TrashItem, Error> {
    // The reasons and the obligation object are discarded rather than rendered: the contract's row
    // has no field for either, and the module header says why a trash row does not need them.
    let (capabilities, _reasons, _wire) =
        capabilities_for(authorization, ctx, container, enforced).await?;

    Ok(TrashItem {
        file_id: candidate.file_id.to_string(),
        name: candidate.name.clone(),
        node_type: candidate.kind.as_str(),
        mime_type: candidate.mime_type.clone(),
        library_id: candidate.library_id.to_string(),
        parent_folder_id: candidate.parent_folder_id.map(|id| id.to_string()),
        deleted_at: candidate.deleted_at,
        purge_after: candidate.purge_after,
        deleted_by: Deleter {
            id: candidate.deleted_by.to_string(),
            display_name: candidate.deleted_by_display_name.clone(),
        },
        revision: candidate.revision,
        capabilities,
    })
}

// ---------------------------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------------------------

/// The container a trashed node would return into.
///
/// Deliberately identical in shape to `routes::lifecycle::destination_of`, which is what
/// `POST /files/{id}/restore` decides against: the named folder when there is one, the library
/// otherwise. The two must not drift, because a caller who is shown a restorable row and then
/// refused the restore has been told a lie by this endpoint — and one who is *not* shown a row they
/// could have restored has lost a document.
const fn container_of(tenant: TenantId, library: LibraryId, parent: Option<FileId>) -> ResourceRef {
    match parent {
        Some(folder) => ResourceRef::folder(tenant, folder),
        None => ResourceRef::library(tenant, library),
    }
}

/// The user a recycle bin can be opened by.
///
/// A function returning [`Refused`] rather than an inline `ok_or_else`, so that
/// `cargo run -p xtask -- audit-coverage` can classify the refusal by this signature — the same rule
/// that makes `me::subject` and `routes::recent::subject` functions.
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`]. Not merely because
/// [`ResourceRef::user`] needs a `users` row to name: `routes::lifecycle::author` refuses every one
/// of these actors from restoring anything at all, because `files.modified_by` is a `NOT NULL`
/// reference into `users` and a guest, a service account, an MCP client and a link bearer each
/// answer `Some` to `Actor::subject_id` while naming a row in a different table (`ENC-879`). Serving
/// them this list would be handing them a page of actions none of which they can take.
fn subject(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        Actor::Guest(_)
        | Actor::ServiceAccount(_)
        | Actor::McpClient(_)
        | Actor::LinkBearer(_)
        | Actor::System => Err(Refused::actor(ReasonCode::AccessDenied)),
    }
}

/// Consumes a [`PolicyDecision`], yielding the obligations the caller now has to satisfy.
///
/// A named function rather than an inline call for `crate::content::consume`'s reason: "the decision
/// was looked at" should be a call a reader can find, and the `#[must_use]` on [`PolicyDecision`] is
/// then discharged in exactly one place in this module.
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

/// Parses and clamps `?limit=`.
///
/// Clamped rather than rejected above the cap, which is `content::page_size`'s rule and
/// `crates/db/src/cursor.rs`'s before it: a client asking for a thousand rows wants as many as it
/// can have, and refusing the request teaches it nothing the answer could not have told it. Only an
/// unparseable value is a client error, because that one is a bug rather than an appetite.
///
/// # Errors
///
/// [`Error::Validation`] naming `limit`, in `docs/05-API.md §5`'s envelope.
fn limit(raw: Option<&str>, request_id: RequestId) -> Result<u32, ApiError> {
    match raw {
        None => Ok(DEFAULT_LIMIT),
        Some(text) => {
            text.trim().parse::<u32>().map(|asked| asked.clamp(MIN_LIMIT, MAX_LIMIT)).map_err(
                |_error| {
                    ApiError::new(
                        Error::Validation(vec![FieldError::new(
                            "limit",
                            ValidationCode::InvalidFormat,
                        )]),
                        request_id,
                    )
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{GuestId, McpClientId, ServiceAccountId, ShareLinkId};

    use super::*;

    fn context(tenant: TenantId, actor: Actor) -> RequestContext {
        RequestContext { actor, ..RequestContext::system(tenant) }
    }

    /// The recycle bin asks the question the restore will ask, spelled the way the resolver matches.
    ///
    /// `crates/authorization/src/repo.rs` matches `a.action = ANY($2::text[])` — string equality,
    /// with no implication from one verb to another — so a listing decided by `file.metadata_read`
    /// would show rows the restore then refuses, and one decided by any other spelling of restore
    /// would match no grant at all and show nothing. Asserted over the rendered form because that
    /// spelling is what `acl_entries.action` stores.
    #[test]
    fn a_trash_row_is_decided_by_the_action_the_restore_will_take() {
        assert_eq!(REINSTATE.to_string(), "file.restore");
        assert_eq!(READ_SELF.to_string(), "container.read");
        assert_ne!(
            REINSTATE,
            Action::File(FileAction::MetadataRead),
            "the list exists to be acted on; a row admitted by what it discloses is a button that \
             refuses"
        );
    }

    /// The container is the named folder, and the library only when there is none.
    ///
    /// The property that keeps this endpoint and `POST /files/{id}/restore` from disagreeing about
    /// one folder: a caller shown a restorable row and then refused the restore has been told a lie
    /// here. Asserted over the output rather than by reading the source, so an edit that changed the
    /// resource *kind* — to the library in both arms, say — fails here.
    #[test]
    fn a_nested_item_is_decided_against_its_folder_and_a_root_item_against_its_library() {
        let tenant = TenantId::new_v7();
        let library = LibraryId::new_v7();
        let folder = FileId::new_v7();

        assert_eq!(
            container_of(tenant, library, Some(folder)),
            ResourceRef::folder(tenant, folder),
            "a nested item returns into its folder, which is the resource the restore decides"
        );
        assert_eq!(
            container_of(tenant, library, None),
            ResourceRef::library(tenant, library),
            "an item at the library root returns into the library"
        );
    }

    /// `limit` is honoured below the cap, clamped above it, floored at one, and only a value that is
    /// not a number is refused.
    ///
    /// The positive control is the second assertion: a `limit` function that returned
    /// [`DEFAULT_LIMIT`] unconditionally would satisfy every clamping assertion here and make the
    /// parameter decoration.
    #[test]
    fn a_limit_is_honoured_below_the_cap_and_clamped_above_it() {
        let request_id = RequestId::new_v7();

        assert_eq!(limit(None, request_id).expect("a default"), DEFAULT_LIMIT);
        assert_eq!(limit(Some("3"), request_id).expect("honoured"), 3, "a smaller page is served");
        assert_eq!(limit(Some(" 5 "), request_id).expect("trimmed"), 5);
        assert_eq!(limit(Some("5000"), request_id).expect("clamped"), MAX_LIMIT);
        assert_eq!(
            limit(Some("0"), request_id).expect("floored"),
            MIN_LIMIT,
            "an empty page and an empty recycle bin must not be the same response (docs/09 §11)"
        );

        let refused = limit(Some("fifty"), request_id).expect_err("a non-number is a client error");
        let rendered = format!("{refused:?}");
        assert!(rendered.contains("limit"), "the refusal must name the field: {rendered}");
    }

    /// Only a directory user opens a recycle bin.
    ///
    /// The positive control is the user: without it this passes against a `subject` that refuses
    /// everybody, which makes the endpoint unreachable rather than safe — and unreachable is the
    /// exact defect this module exists to fix.
    #[test]
    fn only_a_directory_user_opens_a_recycle_bin() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();

        assert_eq!(
            subject(&context(tenant, Actor::User(user))).expect("a user opens their own bin"),
            user
        );

        for actor in [
            Actor::Guest(GuestId::new_v7()),
            Actor::ServiceAccount(ServiceAccountId::new_v7()),
            Actor::McpClient(McpClientId::new_v7()),
            Actor::LinkBearer(ShareLinkId::new_v7()),
            Actor::System,
        ] {
            let refused = subject(&context(tenant, actor))
                .expect_err("no `users` row, no restore, no listing of restores");
            assert_eq!(refused.code(), ReasonCode::AccessDenied);
        }
    }
}
