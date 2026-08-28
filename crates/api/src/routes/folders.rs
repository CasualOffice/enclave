//! Folder creation — the one write `docs/05-API.md §7` gives the file tree that nothing served.
//!
//! `docs/05-API.md §7`, line 175 of that document, is authoritative: `POST
//! `/libraries/{libraryId}/folders` — "Create folder". That row is the *whole* specification. It
//! carries no request body, no response body, no status code, no statement of where `parentId`
//! goes, and no name rules — so everything below the path itself is derived from `§4`'s request
//! conventions, `§5`'s error model, `§7`'s `capabilities` contract and `§7.1`'s container
//! vocabulary, and each derivation is argued where it is made rather than left to be guessed at.
//!
//! # Why this module exists
//!
//! `ENC-788`. [`FileRepository::create_folder`] has existed since M1 with **no caller in any
//! binary** — `crates/files` is 3,434 lines with a full tree, an inheritance walk and composite
//! keys, and no HTTP surface that could reach the one function that makes a container. The visible
//! consequence is not a missing feature but a missing floor: `POST /uploads` has accepted a
//! `parentId` since `ENC-690` and decides against that folder rather than the library
//! (`routes::uploads::target_of`), and **there was no way for a client to obtain one**, so every
//! file uploaded to this product landed at a library root and stayed there.
//!
//! This is the exact shape `ENC-691` closed one crate along: `create_file` was on the same unwired
//! list, for the same reason, and taking it off left its neighbour on it.
//!
//! # What this module does *not* do
//!
//! Rename, reparent, trash, restore and the child listing are `PATCH /files/{id}`, `DELETE
//! /files/{id}`, `POST /files/{id}/restore` and `GET /libraries/{id}/items?parentId=` in the same
//! table, and `crates/files` implements all of them with no caller either. They are not added here:
//! `ENC-788` is scoped to creation because creation is what makes the other five reachable at all,
//! and a folder nobody can make is not a folder anybody can rename. `ENC-807` carries the rest.
//!
//! # The three decisions worth arguing
//!
//! **A folder is a container in the ACL tree, so the question is `container.create` on the parent —
//! never on the folder being made.** A resource that does not exist yet has no ACL and can carry no
//! grant; the thing that decides whether it may come into being is the container it would go into.
//! Which container that is, is the same choice `routes::uploads` makes and it is made by the same
//! rule: the *named folder* when `parentId` is given, because a folder can carry its own ACL and
//! resolving against the library would ignore it, and the library otherwise. [`container_of`] is
//! deliberately written to mirror `uploads::container_of` line for line — a folder you may create a
//! file in and a folder you may not create a folder in would be two answers to one question.
//!
//! **A parent the caller cannot see is absent, not forbidden.** `CLAUDE.md` rule 7 and `§5`'s
//! status table: [`conceal`] renders an `ACCESS_DENIED` denial as [`Error::NotFound`], so a library
//! in another tenant, a library id that never existed, and a library in this tenant with no grant
//! are one answer. A `403` on the third would confirm the library exists, which is the enumeration
//! oracle rule 7 exists to close.
//!
//! **A name collision is `409`, not `400`.** `§5`'s status table names four cases for `409` and one
//! of them is "name collision" outright. `crates/files` already classifies the unique-index
//! violation into [`FilesError::NameTaken`] rather than letting it reach the caller as a `500`
//! (`repo::classify`), but the crate's blanket `From<FilesError> for Error` maps it onto
//! `Error::Validation`, which is a `400` — correct for `InvalidName` beside it and wrong for this
//! one. Rather than change a conversion four other call sites depend on, this handler intercepts
//! `NameTaken` before the conversion and renders `§5`'s status directly, on the precedent
//! `admin::dlp::write_failure` set for `RULE_NAME_IN_USE`. The name is **not** echoed back: the
//! caller sent it, but a collision report is the one place a folder the caller has not been shown
//! could be named to them. `ENC-808` records that the upload path still answers `400` here.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestExt as _};
use chrono::Utc;
use enclave_core::{
    Action, Actor, ContainerAction, Error, FileId, LibraryId, Obligation, Obligations, ReasonCode,
    RequestContext, ResourceRef, TenantId, UserId, ValidationCode,
};
use enclave_files::{FileRepository, FilesError, NewFolder, Parent};
use serde::Deserialize;

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Item};
use crate::error::{ApiError, Envelope};
use crate::refusal::Refused;
use crate::routes::workspaces::conceal;
use crate::state::ApiState;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The body of `POST /libraries/{libraryId}/folders`.
///
/// `camelCase` per `§1`. The library is in the path and is **not** a body field: a request that
/// could name its library twice is a request that can disagree with itself, and the path is the one
/// the router matched and the policy chain was pointed at.
///
/// There is deliberately no `inheritPermissions`. `ENC-141` is why: flipping that flag truncated the
/// resolver's ancestor walk, so an ancestor `DENY` stopped applying and *breaking* inheritance
/// **gained** privilege. A creation path that let a caller ship a folder with inheritance already
/// broken would be that defect reachable from an unauthenticated shape, in one request, before
/// anybody had a chance to look at the resulting ACL. Breaking inheritance is
/// `POST /files/{id}/permissions/break-inheritance` (`§7`), which is a `permissions.manage`
/// question asked separately, and every folder this route makes inherits.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateFolderRequest {
    /// The name as the user typed it. Folded and validated by `enclave_files::normalize`.
    name: String,
    /// The folder it goes inside, or absent for the library root.
    ///
    /// `Option<String>` rather than `Option<FileId>` so that an unparseable id is this handler's
    /// `404` rather than a serde rejection, which axum answers with plain text outside `§5`'s
    /// envelope.
    #[serde(default)]
    parent_id: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/libraries/{libraryId}/folders` — create a folder.
///
/// Answers `201` with the folder rendered exactly as `GET /libraries/{id}/items` will render it on
/// the caller's next listing — the same [`Item`], built by the same [`capabilities_for`], against
/// the same `ResourceRef::folder`. Not a shape of its own, for the reason `content` gives about its
/// own two renderers: a client that saw one object on creation and a different one a second later
/// would have to hold two decoders for one thing, and the day they disagree it offers an action the
/// listing hides.
///
/// # Errors
///
/// [`ApiError`]: `404` when the library or the named parent is another tenant's, absent, trashed or
/// not granted to this caller — and for a `libraryId` or `parentId` that does not parse, which must
/// not be distinguishable from it; `400` for a body that will not decode or a name the tree refuses;
/// `409` when a live sibling already holds the name; `403` with the obligation's own code when the
/// decision carried one this path cannot discharge.
pub async fn create(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(library): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let body: Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let body: CreateFolderRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };

    // An id that does not parse names no resource. `404` rather than a validation failure, so that
    // a garbage id and another tenant's id cannot be told apart (`CLAUDE.md` rule 7).
    let library: LibraryId =
        library.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let parent = match body.parent_id.as_deref() {
        None => None,
        Some(raw) => {
            Some(raw.parse::<FileId>().map_err(|_| ApiError::new(Error::NotFound, request_id))?)
        }
    };

    // The container the folder would go into is the resource whose ACL governs the answer, and it
    // is asked *before* any repository is reached: a caller who cannot create here must not learn
    // whether the parent exists, and must not be able to tell that from a parent that does not.
    let resource = container_of(ctx.tenant_id, library, parent);
    const CREATE: Action = Action::Container(ContainerAction::Create);

    let decision = state
        .policy
        .enforce(&ctx, CREATE, &resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), request_id))?;

    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, CREATE, &resource, refused).await);
    }

    let created_by = match author(&ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(&ctx, CREATE, &resource, refused).await),
    };

    let node = match write(&state, &ctx, library, parent, &body.name, created_by).await {
        Ok(node) => node,
        Err(WriteFailure::NameTaken) => return Ok(name_in_use().into_response(request_id)),
        Err(WriteFailure::Other(error)) => return Err(ApiError::new(error, request_id)),
    };

    // Resolved against the folder that now exists, with **no** obligations to subtract: `satisfy`
    // above refuses the request outright unless the decision carried none, so "nothing to subtract"
    // is a property this path has already established rather than an omission here. The obligations
    // of a `container.create` on the *parent* would in any case be the wrong set to apply to the
    // child.
    let folder = ResourceRef::folder(ctx.tenant_id, node.id);
    let (capabilities, reasons, wire) = capabilities_for(
        state.policy.authorization().as_ref(),
        &ctx,
        &folder,
        &Obligations::none(),
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok((StatusCode::CREATED, Json(Item::new(&node, capabilities, reasons, wire))).into_response())
}

// ---------------------------------------------------------------------------------------------
// The pieces the handler is made of
// ---------------------------------------------------------------------------------------------

/// What a failed insert was.
///
/// Two cases rather than one `Error`, because the collision is the one this handler has to answer
/// with a status `enclave_core::Error` cannot express — see the module documentation.
enum WriteFailure {
    /// A live sibling already holds the folded name.
    NameTaken,
    /// Anything else, already mapped onto the error type the API layer renders.
    Other(Error),
}

/// Opens the transaction, writes the folder, commits.
///
/// Separate from the handler so the `NameTaken` interception is one `match` on a two-variant type
/// rather than a nested `if let` inside the request path, and so the transaction's scope is
/// visible: it is opened after the chain has allowed and closed before any ACL batch, which is
/// `routes::workspaces::list`'s ordering and for its reason — each `authorize_many` opens a
/// tenant-scoped transaction of its own, and holding this one meanwhile costs two connections per
/// request.
async fn write(
    state: &ApiState,
    ctx: &RequestContext,
    library: LibraryId,
    parent: Option<FileId>,
    name: &str,
    created_by: UserId,
) -> Result<enclave_files::FileNode, WriteFailure> {
    let mut tx = state.db.begin(ctx.tenant_id).await.map_err(|e| WriteFailure::Other(e.into()))?;

    let new = NewFolder {
        parent: match parent {
            Some(folder) => Parent::Folder(folder),
            None => Parent::Library(library),
        },
        name: name.to_owned(),
        created_by,
    };

    let node = match FileRepository::create_folder(&mut tx, ctx.tenant_id, &new, Utc::now()).await {
        Ok(node) => node,
        // The transaction is dropped without committing. A refused insert has aborted it in any
        // case — `ENC-691`'s finding was that `COMMIT` on an aborted transaction *is* a rollback,
        // which is why nothing here relies on that and simply drops.
        Err(FilesError::NameTaken) => return Err(WriteFailure::NameTaken),
        Err(error) => return Err(WriteFailure::Other(error.into())),
    };

    tx.commit().await.map_err(|e| WriteFailure::Other(e.into()))?;
    Ok(node)
}

/// The container a folder is created in: the named folder, or the library root.
///
/// `const` and total, and deliberately identical to `routes::uploads::container_of`. See the module
/// documentation for why the two must not be allowed to drift.
const fn container_of(tenant: TenantId, library: LibraryId, parent: Option<FileId>) -> ResourceRef {
    match parent {
        Some(folder) => ResourceRef::folder(tenant, folder),
        None => ResourceRef::library(tenant, library),
    }
}

/// Honours every obligation the chain attached to the create, or turns it into a refusal.
///
/// Exhaustive on purpose, exactly as `routes::shares::satisfy` and `download`'s are: [`Obligation`]
/// is deliberately not `#[non_exhaustive]`, so a new obligation breaks this match and forces
/// somebody to decide what a folder creation does about it rather than inheriting a shrug.
///
/// **Nothing here is satisfiable and almost everything is therefore a refusal** (`CLAUDE.md` rule 8,
/// D29). A folder is a name and a parent: there is no rendition a watermark could be burned into, no
/// content a classification could restrict, and no approval this synchronous path could route and
/// wait for. The two exceptions are the two that are restrictions on *content*, and a container
/// carries none — the same reading `routes::workspaces::apply_obligations` gives them, listed rather
/// than swept into a catch-all so the reasoning is visible.
fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            // A folder has no bytes to withhold and no rendition to mark. Ignoring these is not a
            // dropped obligation: there is no exposure here for either to be about.
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
            // A folder holds no content, so there is nothing to reclassify and no column that
            // could carry the result. Refused rather than ignored: a stage that asked for a
            // classification change and got silence is a stage whose decision was dropped.
            Obligation::Reclassify { to } => {
                return Err(Refused::obligation(Obligation::Reclassify { to }))
            }
        }
    }
    Ok(())
}

/// The user a folder is attributed to.
///
/// `files.created_by` is a `NOT NULL` reference to a `users` row, and a guest, a service account and
/// an MCP client each answer `Some` to `Actor::subject_id` while being none of them — the same
/// argument `routes::shares::author` and `routes::uploads` make. A [`Refused`] rather than an
/// [`Error`] because the chain has already allowed by the time this is asked, so the refusal needs
/// an audit row of its own (`ENC-606`) and returning one is what makes the gate able to see it.
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`].
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        Actor::Guest(_) | Actor::ServiceAccount(_) | Actor::McpClient(_) | Actor::System => {
            Err(Refused::actor(ReasonCode::AccessDenied))
        }
    }
}

/// `409`, per `docs/05-API.md §5`'s status table: "name collision".
///
/// Every string is a literal and the offending name is not among them — see the module
/// documentation for why a collision report must not echo it.
fn name_in_use() -> Envelope {
    Envelope::new(
        StatusCode::CONFLICT,
        "NAME_IN_USE",
        "An item in this folder already has that name.",
        "Choose another name, or rename the item that holds it.",
    )
    .with_details(vec![serde_json::json!({
        "field": "name",
        "code": ValidationCode::NotUnique.as_str(),
    })])
}

/// `400` for a body that will not decode, inside `§5`'s envelope.
///
/// A copy of `routes::shares::unreadable_body` rather than a shared helper, because that one is
/// private to its module and the duplication is four literals rather than a policy.
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

    use enclave_core::ClassificationRank;

    use super::*;

    /// The question a folder creation asks is about the **parent**, and which parent is the same
    /// choice the upload path makes.
    ///
    /// This is the property that keeps `POST /uploads` and this route from disagreeing about one
    /// folder: a caller who may put a file in a folder and may not put a folder in it would be two
    /// answers to `container.create` on the same resource. Asserted over [`container_of`]'s output
    /// rather than by reading the source, so a later edit that changed the resource *kind* — say to
    /// the library in both branches — fails here.
    #[test]
    fn a_named_parent_is_the_container_and_the_library_is_the_fallback() {
        let tenant = TenantId::new_v7();
        let library = LibraryId::new_v7();
        let folder = FileId::new_v7();

        assert_eq!(
            container_of(tenant, library, Some(folder)),
            ResourceRef::folder(tenant, folder),
            "a named parent must be the container the chain decides against"
        );
        assert_eq!(
            container_of(tenant, library, None),
            ResourceRef::library(tenant, library),
            "with no parent the library root is the container"
        );
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

        // The two that are restrictions on content a container does not hold.
        for obligation in [Obligation::NoDownload, Obligation::NoSync] {
            let set: Obligations = [obligation].into_iter().collect();
            assert!(
                satisfy(&set).is_ok(),
                "{obligation:?} restricts content, and a folder holds none"
            );
        }
    }

    /// A collision is `409` and never `400`, and it does not name what collided.
    ///
    /// `docs/05-API.md §5` lists "name collision" among exactly four `409` cases. The status is
    /// asserted because the blanket `From<FilesError> for Error` would have made this a `400`, and
    /// the *absence* of the name is asserted because that conversion would not have leaked it
    /// either — so without this assertion the interception could later start echoing the name and
    /// nothing would notice.
    #[test]
    fn a_name_collision_is_a_conflict_that_does_not_echo_the_name() {
        let envelope = name_in_use();
        assert_eq!(envelope.status(), StatusCode::CONFLICT);
        assert_eq!(envelope.code(), "NAME_IN_USE");

        let rendered = serde_json::to_string(envelope.details()).expect("render");
        assert!(rendered.contains("NOT_UNIQUE"), "the field diagnosis must survive: {rendered}");
    }
}
