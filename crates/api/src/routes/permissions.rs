//! The permissions surface — the request that lets somebody *else* into a container.
//!
//! `ENC-917`, and it is the last link of `ENC-916`'s chain. `enclave_authorization::grant` can write
//! an `acl_entries` row and is tested against a real database; its only caller in any binary is the
//! founding grant `POST /admin/workspaces` writes over the workspace it just made. So every
//! workspace this product can provision is **permanently single-occupant**: its founder holds
//! `container.manage_permissions`, `capabilities.managePermissions` comes back `true` on every
//! container endpoint, and there is no request in the surface that acts on it. The API describes a
//! button whose handler was never written — this repository's signature failure arriving one level
//! above the one `ENC-916` closed.
//!
//! `docs/05-API.md §7` specifies the file half of what follows in three rows, and nothing else:
//!
//! | `GET` | `/files/{id}/permissions` | Effective + explicit ACL |
//! | `PUT` | `/files/{id}/permissions` | Replace ACL; bumps `aclRevision` |
//! | `POST` | `/files/{id}/permissions/break-inheritance` | Materializes inherited entries |
//!
//! Everything below the paths is derived from `§4`'s request conventions, `§5`'s error model and
//! `docs/04-DATA-MODEL.md §9`'s resolution rules, and each derivation is argued where it is made.
//!
//! # One implementation, three paths
//!
//! [`ChainNode`] covers exactly four resource kinds and
//! [`enclave_authorization`]'s `classify` supports exactly those four: workspace, library, folder
//! and file. Folders and files share `/files/{id}` because they share the [`FileId`] space and the
//! permission model, so the surface is three paths over four kinds — and it is **one** pair of
//! functions parameterised by [`Surface`], not three copies. Three copies of an authorization
//! decision is three chances to weaken one, and the one that gets weakened is the one nobody
//! re-reads. The public handlers below are registration adapters and hold no decision of their own.
//!
//! # Where the chain runs, and on what
//!
//! | Path | Resource enforced | Action |
//! |---|---|---|
//! | `/workspaces/{id}/permissions` | the workspace | `container.manage_permissions` |
//! | `/libraries/{id}/permissions` | the library | `container.manage_permissions` |
//! | `/files/{id}/permissions` | the file or folder | `file.manage_permissions` |
//!
//! The question is asked **before any repository is reached**, on the resource the path names. A
//! caller who may not manage permissions here must not learn whether the resource exists, and must
//! not be able to tell that answer apart from one for a resource that does not. So [`conceal`]
//! renders an `ACCESS_DENIED` denial as [`Error::NotFound`], an id that does not parse is the same
//! `404` before anything is queried, and neither carries a body detail (`CLAUDE.md` rules 7 and 10).
//!
//! `file.manage_permissions` and `container.manage_permissions` are two actions and stay two:
//! `crates/authorization/src/repo.rs` matches `a.action = ANY($2::text[])` — a literal string
//! comparison with no implication from one family to the other — so asking the container action on
//! a folder would resolve against entries nobody wrote. The split is `CLAUDE.md` rule 6's, applied
//! to the action that can grant every other action.
//!
//! # The write and its own safety check share one transaction
//!
//! A replace that committed and then failed the check meant to protect the caller is a locked-out
//! caller, and the only way back is the `psql` session this surface exists to remove. So
//! [`replace_acl`] opens one [`crate::state::ApiState::db`] transaction, writes the desired set,
//! re-resolves the caller's own `manage_permissions` **inside it**, and commits only if the answer
//! is still yes. A refusal drops the transaction, which is what makes "changes nothing" a property
//! of the code rather than a promise in a comment.
//!
//! [`refuse_self_lockout`] is a `409` and deliberately not a `403`: the caller *is* allowed to do
//! this, and it is the resulting **state** that is rejected. `crates/api/src/admin/dlp.rs`'s
//! function of the same name is the precedent, and the two differ in exactly one way worth stating —
//! that one asks a structural question about a rule's scope and can answer it before touching the
//! database, while this one has to ask the resolver, because inheritance may still grant
//! `manage_permissions` after every explicit row naming the caller is gone. The check is therefore
//! about the *effective* answer and never about whether a particular row survived.
//!
//! **A tenant administrator is not exempt.** `crates/authorization/src/admin.rs` answers
//! [`Action::Admin`] from `users.is_admin` and says nothing whatever about `container.*` or
//! `file.*`, so exempting administrators here would be a fiction: the exemption would let them
//! write a set that locks them out, and the resolver would then refuse them exactly as it refuses
//! anybody else. It is the same fact `routes::workspaces::create` records about the founding grant,
//! read from the other end.
//!
//! # What `effective` means on the wire, precisely
//!
//! `explicit` is the rows stored **on** the resource. `effective` is every entry that bears on it —
//! its own and its ancestors' — each tagged with the [`ChainNode`] it is stored on. A UI that cannot
//! tell the two apart cannot show *why* somebody has access, which is the whole content of a
//! permissions screen: "Finance has read here" and "Finance has read on the workspace above" are
//! different facts with different remedies.
//!
//! It is deliberately **not** collapsed into one winning row per `(principal, action)`.
//! [`enclave_authorization::grant::entries_on`] says why in as many words: a second implementation
//! of the chain walk or of the deny-wins rule is one refactor away from disagreeing with the one
//! that enforces, and a permissions screen that disagreed with the enforcement would be worse than
//! no screen. The chain itself is borrowed from [`enclave_authorization::repo`] — the very queries
//! `crate::service`'s resolver and `crate::materialise`'s copy both walk — for the same reason.
//! The per-caller verdict, collapsed by those rules, is the `capabilities` object on
//! `GET /files/{id}` and `GET /workspaces/{id}`; this endpoint answers the other question.
//!
//! # One thing in here is not where it belongs, and says so
//!
//! [`write_desired_set`] composes the replace out of `enclave_authorization::grant`'s public
//! functions instead of calling a `replace` in that crate, because at the time this landed the crate
//! held the whole vocabulary of the operation — [`MAX_REPLACE_ENTRIES`], [`DesiredEntry`],
//! [`ReplaceOutcome`], [`GrantError::TooManyEntries`], [`GrantError::ContradictoryEntries`] — and no
//! function to go with it, and `crates/authorization/src/grant.rs` is not a file `ENC-917` owns. No
//! SQL is written here and none may be; what is composed is the bookkeeping, and that function
//! carries the argument and the one-line swap that retires it.
//!
//! # What is deliberately not here
//!
//! No `PATCH`, and no per-entry `DELETE`. `docs/05-API.md §7` specifies a replace, and a replace is
//! the operation a permissions dialog actually performs: the screen holds the whole set, and the
//! entry the administrator removed is the one they will not re-send. An incremental surface beside
//! it would make "the entry I deleted is gone" and "the entry I forgot to send is gone" two
//! different requests that look the same in a log.
//!
//! No step-up. `docs/05-API.md §14` requires a recent second factor for administrative mutations
//! under `/admin/**`, and none of these is one: managing permissions on a container is a grant the
//! container's own ACL answers for, held by workspace owners who are not tenant administrators.
//! Requiring MFA here would demand a factor of every workspace owner in the tenant, which is
//! `ENC-771`'s failure shape — a control that cannot be operated — rather than a control.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, State};
use axum::response::{IntoResponse as _, Response};
use axum::{Json, RequestExt as _};
use chrono::{DateTime, Utc};
use enclave_authorization::grant::{
    DesiredEntry, Grant, GrantError, GrantedEntry, ReplaceOutcome, MAX_GRANT_ACTIONS,
    MAX_REPLACE_ENTRIES,
};
use enclave_authorization::{
    materialise, repo, AclResolver, ChainNode, Effect, Effective, InheritanceChain, Principal,
    PrincipalKind, ResolverLimits,
};
use enclave_core::{
    Action, Actor, AdminAction, ContainerAction, Error, FieldError, FileAction, FileId, LibraryId,
    Obligation, Obligations, ReasonCode, RequestContext, RequestId, ResourceRef, ShareAction,
    TenantId, UserId, ValidationCode, WorkspaceId,
};
use enclave_files::FileRepository;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope};
use crate::refusal::Refused;
use crate::routes::workspaces::{conceal, consume};
use crate::state::ApiState;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// One stored `acl_entries` row, as a permissions screen needs to see it.
///
/// `camelCase` per `docs/05-API.md §1`. Every field is a fact about the row rather than a verdict
/// derived from it, with the single exception of `expired` — which
/// [`GrantedEntry::expired`] computes from [`AclEntry::is_live_at`](enclave_authorization::AclEntry),
/// the same line the resolver applies, so a screen and an enforcement cannot disagree about whether
/// an entry has lapsed.
///
/// `action` is a string and not an enumeration on purpose. `acl_entries.action` is `TEXT` with no
/// `CHECK` (`docs/04-DATA-MODEL.md §9`), so a row may hold a spelling this build does not know — one
/// written by an older release or by a tenant's own tooling — and parsing it here would make exactly
/// those rows invisible to the only screen that could remove them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryView {
    /// The row's primary key, so a client can address one entry.
    id: Uuid,
    /// Where the row is stored. Equal to the requested resource for everything in `explicit`, and
    /// an ancestor for the rest of `effective` — this field is the whole difference between the two
    /// lists once they are rendered.
    source: ResourceView,
    /// Who the entry names.
    principal: PrincipalView,
    /// The action, in the `family.verb` spelling `Action`'s own `Display` produces.
    action: String,
    /// `ALLOW` or `DENY`.
    effect: &'static str,
    /// The ancestor this entry was copied down from when inheritance was broken, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    inherited_from: Option<Uuid>,
    /// The user who answered for it.
    granted_by: Uuid,
    /// When they did.
    granted_at: DateTime<Utc>,
    /// When it stops applying, if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    /// Whether `expiresAt` has already passed — `true` means the row is stored and inert.
    ///
    /// Reported rather than filtered, because a lapsed `DENY` is the specific thing that makes a
    /// new `ALLOW` fail (`enclave_authorization::grant::grant`), and an administrator who cannot
    /// see it cannot act on it.
    expired: bool,
}

/// A resource, as a kind and an id.
///
/// The kind is the ACL spelling — `WORKSPACE`, `LIBRARY`, `FOLDER`, `FILE` — and not the
/// `ResourceKind` wire name, because it is the value `acl_entries.resource_type` holds and the one
/// a client comparing `source` against the resource it asked about has to match.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceView {
    kind: &'static str,
    id: Uuid,
}

/// A principal, as `acl_entries` stores one.
///
/// `id` is absent for `EVERYONE` and present for every other kind — the one consistency rule the
/// schema cannot state, and the one the grant engine refuses a write for breaking.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalView {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Uuid>,
}

/// The body of `GET …/permissions`, and of everything that writes and then re-renders it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionsView {
    /// The resource the ACL belongs to, with the kind resolved — a `/files/{id}` request is
    /// answered with `FOLDER` when the id names one, which is the only place a client learns which
    /// it asked about.
    resource: ResourceView,
    /// Whether entries above this resource still reach it.
    ///
    /// `false` means inheritance has been broken here, and is what makes `effective` and `explicit`
    /// identical. A workspace is always `false`: nothing is above it, so there is nothing to
    /// inherit from and no break to perform.
    inherits: bool,
    /// `files.acl_revision`, the counter the search index carries as `acl_epoch`
    /// (`docs/07-SEARCH-INDEXING.md §6`), for the two kinds that have one.
    ///
    /// Absent for a workspace and a library, and that absence is honest rather than an omission:
    /// `docs/04-DATA-MODEL.md §7` gives the column to `files` alone, so reporting a number for a
    /// container would mean inventing one. `docs/05-API.md §7`'s "bumps `aclRevision`" is a
    /// statement about the file surface, and it is the file surface that carries the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    acl_revision: Option<i64>,
    /// The rows stored on this resource. A subset of `effective`, in `entries_on`'s order.
    explicit: Vec<EntryView>,
    /// Every row that bears on this resource, its ancestors' included. See the module note for what
    /// this is and — just as importantly — what it is not.
    effective: Vec<EntryView>,
}

/// The body of `PUT …/permissions`, and of `POST …/break-inheritance`.
///
/// The counts are the half of a replace nobody typed. "The ACL is now this" is not an answer to
/// "what did I just do": a `PUT` that silently removed eleven entries and a `PUT` that changed
/// nothing produce the same final set, and the difference between them is what a permissions screen
/// has to show back to whoever pressed save.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangedView {
    /// Entries this resource did not hold under this `(principal, action)` and now does.
    added: usize,
    /// Entries it already held and that were rewritten.
    updated: usize,
    /// Explicit entries it held and the caller did not declare, now gone.
    removed: usize,
    /// The state afterwards, read inside the same transaction as the write so that the ACL rendered
    /// and the `aclRevision` reported describe one instant.
    #[serde(flatten)]
    permissions: PermissionsView,
}

/// The body of `PUT /api/v1/{workspaces|libraries|files}/{id}/permissions`.
///
/// `entries` is the resource's **whole** explicit ACL. An entry the caller does not repeat is an
/// entry the caller is removing, which is what "replace" means and why there is no separate delete.
///
/// `deny_unknown_fields` on every shape here, for `crates/api/src/admin/dlp.rs`'s reason: a lenient
/// decoder accepts a body it then silently drops half of, and the half that goes missing on a
/// permissions request is somebody's access.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplaceRequest {
    entries: Vec<DesiredEntryRequest>,
}

/// One row of the set a replace declares.
///
/// Flat — one principal, one action — because a replace has to be able to say things a list of
/// grants cannot: that this principal keeps `file.download` until Friday and `file.preview`
/// forever. That is [`DesiredEntry`]'s shape and this is its wire form.
///
/// There is deliberately no `grantedBy`. Provenance is a fact about who acted, not an input, and a
/// per-row granter would be a body field that lets a client stamp somebody else's name on an entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DesiredEntryRequest {
    principal: PrincipalRequest,
    /// `family.verb`, exactly as [`Action`]'s `Display` renders it and as `acl_entries.action`
    /// stores it. A string rather than a tagged enum so that the accepted spelling and the stored
    /// one are the same characters — a grant written as `"download"` matches nothing and looks
    /// correct in every UI.
    action: String,
    /// `ALLOW` or `DENY`.
    effect: String,
    /// When the entry stops applying. Absent means never.
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// The principal half of one declared entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrincipalRequest {
    kind: String,
    #[serde(default)]
    id: Option<Uuid>,
}

// ---------------------------------------------------------------------------------------------
// Handlers — registration adapters over one implementation
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/workspaces/{id}/permissions`.
///
/// # Errors
///
/// As [`read`].
pub async fn read_workspace(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    read(&state, &ctx, Surface::Workspace, &id).await
}

/// Handles `GET /api/v1/libraries/{id}/permissions`.
///
/// # Errors
///
/// As [`read`].
pub async fn read_library(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    read(&state, &ctx, Surface::Library, &id).await
}

/// Handles `GET /api/v1/files/{id}/permissions` — for a file or a folder.
///
/// # Errors
///
/// As [`read`].
pub async fn read_file(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    read(&state, &ctx, Surface::Content, &id).await
}

/// Handles `PUT /api/v1/workspaces/{id}/permissions`.
///
/// # Errors
///
/// As [`replace_acl`].
pub async fn replace_workspace(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    replace_acl(&state, &ctx, Surface::Workspace, &id, request).await
}

/// Handles `PUT /api/v1/libraries/{id}/permissions`.
///
/// # Errors
///
/// As [`replace_acl`].
pub async fn replace_library(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    replace_acl(&state, &ctx, Surface::Library, &id, request).await
}

/// Handles `PUT /api/v1/files/{id}/permissions` — for a file or a folder.
///
/// # Errors
///
/// As [`replace_acl`].
pub async fn replace_file(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    replace_acl(&state, &ctx, Surface::Content, &id, request).await
}

/// Handles `POST /api/v1/files/{id}/permissions/break-inheritance`.
///
/// # Errors
///
/// As [`break_inheritance`].
pub async fn break_file_inheritance(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    break_inheritance(&state, &ctx, Breakable::Content, &id).await
}

/// Handles `POST /api/v1/libraries/{id}/permissions/break-inheritance`.
///
/// `docs/05-API.md §7` names only the file row, and the library one exists because the escalation
/// does: `libraries` carries its own `inherit_permissions`, the resolver's walk stops at it exactly
/// as it does on a file, and `enclave_authorization::materialise::break_library_inheritance` was
/// written for that reason and has had no non-test caller. Serving one door and not the other would
/// leave the operation reachable for a file and unreachable for the container above it.
///
/// There is no workspace row: nothing is above a workspace, so it inherits nothing and there is no
/// break to perform. [`Breakable`] has no variant for it, which is why that is a fact about the type
/// rather than a `404` somebody has to remember to write.
///
/// # Errors
///
/// As [`break_inheritance`].
pub async fn break_library_inheritance(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    break_inheritance(&state, &ctx, Breakable::Library, &id).await
}

// ---------------------------------------------------------------------------------------------
// The implementation
// ---------------------------------------------------------------------------------------------

/// Which of the four ACL resource kinds a path named.
///
/// Three variants for four kinds: `/files/{id}` addresses a file and a folder alike, because they
/// share the [`FileId`] space and the whole of the permission model, and which of the two it turned
/// out to be is read from the chain walk rather than guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// `/workspaces/{id}` — the outermost container.
    Workspace,
    /// `/libraries/{id}`.
    Library,
    /// `/files/{id}` — a file or a folder.
    Content,
}

impl Surface {
    /// The action this surface's permissions are managed under.
    ///
    /// Two actions, and they are not interchangeable: `crates/authorization/src/repo.rs` matches
    /// the action column by string equality, so `container.manage_permissions` and
    /// `file.manage_permissions` resolve against disjoint sets of rows. Deciding a folder's ACL by
    /// the container action would consult entries nobody has ever written.
    const fn manage(self) -> Action {
        match self {
            Self::Workspace | Self::Library => {
                Action::Container(ContainerAction::ManagePermissions)
            }
            Self::Content => Action::File(FileAction::ManagePermissions),
        }
    }

    /// The resource the chain is pointed at, or `None` when the path segment is not an id.
    ///
    /// Parsing through the typed identifiers rather than through [`Uuid`] is what keeps the newtype
    /// discipline at the boundary: a `Path<String>` that reached [`ResourceRef::new`] as a raw
    /// `Uuid` would accept a library id on the file path and produce a reference the resolver would
    /// walk as a file tree.
    ///
    /// A `/files/{id}` reference is built as [`ResourceRef::file`] whether the id names a file or a
    /// folder. That is `crate::content::file_metadata`'s existing choice on the same path and it is
    /// safe for one specific reason: `classify` maps `ResourceKind::File` and `ResourceKind::Folder`
    /// onto the same `Target::FileTree`, so the decision, the chain and the audited action are
    /// identical either way — and the alternative would be a repository read *before* the chain
    /// runs, which is the ordering `CLAUDE.md` rule 7 exists to forbid.
    fn resource(self, tenant: TenantId, raw: &str) -> Option<ResourceRef> {
        match self {
            Self::Workspace => {
                raw.parse::<WorkspaceId>().ok().map(|id| ResourceRef::workspace(tenant, id))
            }
            Self::Library => {
                raw.parse::<LibraryId>().ok().map(|id| ResourceRef::library(tenant, id))
            }
            Self::Content => raw.parse::<FileId>().ok().map(|id| ResourceRef::file(tenant, id)),
        }
    }
}

/// The two surfaces that have something above them to stop inheriting from.
///
/// A type rather than a `Surface` with a refusal arm, so that "a workspace cannot break
/// inheritance" is unrepresentable instead of handled. The workspace arm would be unreachable —
/// nothing registers a route for it — and an unreachable arm is one somebody later makes reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Breakable {
    /// A library, which inherits from its workspace.
    Library,
    /// A file or folder, which inherits from its parent, then its library, then its workspace.
    Content,
}

impl Breakable {
    /// The surface this addresses, so the authorization decision has one definition.
    const fn surface(self) -> Surface {
        match self {
            Self::Library => Surface::Library,
            Self::Content => Surface::Content,
        }
    }
}

/// `GET …/permissions` — the explicit ACL and everything that reaches this resource.
///
/// # Errors
///
/// [`ApiError`]: `404` when the resource is another tenant's, absent, trashed or not granted to this
/// caller — and for an id that does not parse, which must not be distinguishable from it; the
/// denial's own status for any other policy refusal; `403` with the obligation's own code when the
/// decision carried one this path cannot discharge.
async fn read(
    state: &ApiState,
    ctx: &RequestContext,
    surface: Surface,
    raw: &str,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let now = Utc::now();

    let resource = subject(surface, ctx, raw, request_id)?;
    let action = surface.manage();
    let obligations = decide(state, ctx, action, &resource).await?;
    if let Err(refused) = satisfy(&obligations, Intent::Read) {
        return Err(state.audit.refuse(ctx, action, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let view = match render(&mut tx, ctx.tenant_id, surface, resource.id, now).await {
        Ok(view) => view,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    Ok(Json(view).into_response())
}

/// `PUT …/permissions` — replace the explicit ACL, and refuse to leave the caller locked out.
///
/// # The order of the four steps, and why none of them may move
///
/// 1. **The chain decides**, on the resource the path names, before the body is looked at. A caller
///    the chain refuses learns nothing about the request schema — not even that their JSON was
///    malformed. `admin::dlp::create_rule` orders it the same way.
/// 2. **The desired set is validated into typed values**, so that what reaches the grant engine is
///    an [`Action`] rather than a string somebody typed. A grant spelled `"download"` matches no
///    decision the product will ever take.
/// 3. **The write and the lockout check run in one transaction.** See the module note: a replace
///    that committed and then failed its own safety check is a locked-out caller.
/// 4. **The response is rendered from that same transaction**, before the commit, so the ACL a
///    client renders and the `aclRevision` beside it describe one state that existed at one instant.
///
/// # Errors
///
/// [`ApiError`]: `404` as [`read`]; `400` for a body that will not decode, an action or effect this
/// build does not know, or a principal whose kind and identifier disagree; `409` when the set would
/// remove the caller's own ability to manage permissions here, and when an `ALLOW` was asked to land
/// on a stored `DENY`; `403` with the obligation's own code when the decision carried one this path
/// cannot discharge.
async fn replace_acl(
    state: &ApiState,
    ctx: &RequestContext,
    surface: Surface,
    raw: &str,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let now = Utc::now();

    let resource = subject(surface, ctx, raw, request_id)?;
    let action = surface.manage();
    let obligations = decide(state, ctx, action, &resource).await?;
    if let Err(refused) = satisfy(&obligations, Intent::Write) {
        return Err(state.audit.refuse(ctx, action, &resource, refused).await);
    }

    // The user the entries will be attributed to. `acl_entries.granted_by` is a reference to a
    // `users` row, and a guest, a service account and an MCP client each answer `Some` to
    // `Actor::subject_id` while being none of them — `routes::folders::author`'s argument exactly.
    let granted_by = match author(ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(ctx, action, &resource, refused).await),
    };

    let body: axum::body::Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let body: ReplaceRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let desired = match desired_entries(&body) {
        Ok(desired) => desired,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // The chain is walked before the write for one reason that is not about rendering: its first
    // node is the resource's own `ChainNode`, which for `/files/{id}` is where `FILE` and `FOLDER`
    // are told apart. Writing entries under the wrong `resource_type` would store rows the resolver
    // never joins back — a replace that reports success and grants nobody anything.
    let chain = match chain_of(&mut tx, ctx.tenant_id, surface, resource.id).await {
        Ok(chain) => chain,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };
    let node = match chain.nodes().first().copied() {
        Some(node) => node,
        // A chain with no nodes is a resource the walk could not see. `chain_of` already refuses
        // that; this is the unreachable half, and `404` is the answer that cannot leak.
        None => return Err(ApiError::new(Error::NotFound, request_id)),
    };

    let outcome =
        match write_desired_set(&mut tx, ctx.tenant_id, node, &desired, granted_by, now).await {
            Ok(outcome) => outcome,
            Err(error) => return Err(ApiError::new(error.into(), request_id)),
        };

    // The safety check, inside the transaction the write is in. Asked of the resolver rather than
    // of `outcome.entries`, because an explicit row is not the only way the caller can hold this:
    // a grant on the workspace above still reaches a library that inherits, and refusing a replace
    // that leaves inheritance doing the work would forbid a correct and ordinary change.
    let retained = match retains_management(&mut tx, ctx, action, &resource, now).await {
        Ok(retained) => retained,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };
    if !retained {
        // Dropped without committing, which is what makes "changes nothing" structural. A refused
        // statement has aborted the transaction in any case — `ENC-691`'s finding was that `COMMIT`
        // on an aborted transaction *is* a rollback — so nothing here relies on that.
        drop(tx);
        return Ok(refuse_self_lockout().into_response(request_id));
    }

    let permissions = match render(&mut tx, ctx.tenant_id, surface, resource.id, now).await {
        Ok(view) => view,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(Json(ChangedView {
        added: outcome.added,
        updated: outcome.updated,
        removed: outcome.removed,
        permissions,
    })
    .into_response())
}

/// `POST …/permissions/break-inheritance` — copy the effective set down, then stop inheriting.
///
/// The operation is neutral by construction and that is the whole point of it: immediately
/// afterwards every principal resolves exactly as they did immediately before, because the entries
/// that decided their access now sit on the resource itself. What changes is that later edits to an
/// ancestor no longer reach it. `ENC-141` is the defect that made the copy necessary — flipping the
/// flag alone truncated the resolver's walk, so an ancestor `DENY` stopped applying and *breaking*
/// inheritance **gained** privilege.
///
/// Its own action is `manage_permissions` on the resource, the same question the replace asks:
/// deciding where a resource's ACL comes from is deciding its permissions.
///
/// # Errors
///
/// [`ApiError`]: `404` as [`read`]; `409` when inheritance was already broken here — an error rather
/// than a no-op, because two callers who both believe they are establishing this resource's ACL must
/// not both be told they succeeded; `400` when the effective set is larger than
/// [`materialise::MAX_MATERIALISED_ENTRIES`]; `403` for an undischargeable obligation.
async fn break_inheritance(
    state: &ApiState,
    ctx: &RequestContext,
    breakable: Breakable,
    raw: &str,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let now = Utc::now();
    let surface = breakable.surface();

    let resource = subject(surface, ctx, raw, request_id)?;
    let action = surface.manage();
    let obligations = decide(state, ctx, action, &resource).await?;
    if let Err(refused) = satisfy(&obligations, Intent::Write) {
        return Err(state.audit.refuse(ctx, action, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // `ResolverLimits::DEFAULT` and not a limit of this module's own: passing anything else lets
    // the copy walk a different distance from the enforcement it is supposed to preserve, and a
    // chain truncated below the enforced one is missing exactly the topmost ancestors, which is
    // where an organisation-wide `DENY` lives.
    let broken = match breakable {
        Breakable::Content => {
            materialise::break_file_inheritance(
                &mut tx,
                ctx.tenant_id,
                resource.id,
                ResolverLimits::DEFAULT,
                now,
            )
            .await
        }
        Breakable::Library => {
            materialise::break_library_inheritance(&mut tx, ctx.tenant_id, resource.id, now).await
        }
    };
    if let Err(error) = broken {
        return Err(ApiError::new(error.into(), request_id));
    }

    let permissions = match render(&mut tx, ctx.tenant_id, surface, resource.id, now).await {
        Ok(view) => view,
        Err(error) => return Err(ApiError::new(error, request_id)),
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Rendered as a change with no additions: a break writes entries that were already in force, so
    // reporting them as `added` would tell an administrator they had granted something. What it
    // did is visible where it matters — `explicit` now holds what `effective` holds, and `inherits`
    // is `false`.
    Ok(Json(ChangedView { added: 0, updated: 0, removed: 0, permissions }).into_response())
}

// ---------------------------------------------------------------------------------------------
// The pieces the three handlers share
// ---------------------------------------------------------------------------------------------

/// The resource the path named, or the `404` that names nothing.
///
/// An id that does not parse is refused here, before the chain and before any query, and with the
/// same status a resource in another tenant gets. A `400` on one of them would be a distinction, and
/// a distinction is an enumeration oracle: it tells an attacker which of their guesses were
/// well-formed.
fn subject(
    surface: Surface,
    ctx: &RequestContext,
    raw: &str,
    request_id: RequestId,
) -> Result<ResourceRef, ApiError> {
    surface.resource(ctx.tenant_id, raw).ok_or_else(|| ApiError::new(Error::NotFound, request_id))
}

/// Runs the policy chain and yields the obligations the caller now has to satisfy.
///
/// The one place `CLAUDE.md` rule 7's concealment is applied for this surface, so the three
/// endpoints cannot answer it three ways. `ACCESS_DENIED` becomes [`Error::NotFound`]; every other
/// reason code keeps its own status, for the reason `crate::content` sets out at length — those are
/// produced by stages that run either before authorization, and refuse identically for a nonexistent
/// id, or after it, by which point the caller already holds a grant.
async fn decide(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<Obligations, ApiError> {
    let decision = state
        .policy
        .enforce(ctx, action, resource)
        .await
        .map_err(|error| ApiError::new(conceal(error), ctx.request_id))?;
    Ok(consume(decision))
}

/// Whether the request reads the ACL or rewrites it.
///
/// The one input [`satisfy`] needs that the obligation set does not carry, and it is needed for
/// exactly one obligation: [`Obligation::ReadOnly`] is satisfied by a read and violated by a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intent {
    /// `GET`.
    Read,
    /// `PUT`, and the break.
    Write,
}

/// Honours every obligation the chain attached, or turns it into a refusal.
///
/// Exhaustive on purpose, exactly as `routes::folders::satisfy` and `download`'s are: [`Obligation`]
/// is deliberately not `#[non_exhaustive]`, so a new obligation breaks this match and forces
/// somebody to decide what a permissions request does about it rather than inheriting a shrug.
///
/// **Almost nothing here is satisfiable, and an unsatisfiable obligation is a refusal** (`CLAUDE.md`
/// rule 8, D29). An ACL is a list of principals and verbs: there is no rendition a watermark could
/// be burned into, no content a classification could restrict, and no approval this synchronous path
/// could route and wait for. The two that are ignored are ignored because they are restrictions on
/// *content*, and an access-control list is not content — the same reading
/// `routes::workspaces::apply_obligations` gives them, listed rather than swept into a catch-all so
/// the reasoning is visible.
fn satisfy(obligations: &Obligations, intent: Intent) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            // Neither restricts a list of grants: there are no bytes to withhold and no replica to
            // refuse. Ignoring them is not a dropped obligation — there is no exposure here for
            // either to be about.
            Obligation::NoDownload | Obligation::NoSync => {}
            // "Suppress every mutation path." A read of the ACL is not one; a replace and a break
            // are.
            Obligation::ReadOnly => {
                if intent == Intent::Write {
                    return Err(Refused::obligation(Obligation::ReadOnly));
                }
            }
            Obligation::Watermark => return Err(Refused::obligation(Obligation::Watermark)),
            Obligation::RequireJustification => {
                return Err(Refused::obligation(Obligation::RequireJustification))
            }
            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }
            // There is no content here to reclassify and no column that could carry the result.
            // Refused rather than ignored: a stage that asked for a classification change and got
            // silence is a stage whose decision was dropped.
            Obligation::Reclassify { to } => {
                return Err(Refused::obligation(Obligation::Reclassify { to }))
            }
        }
    }
    Ok(())
}

/// The user a written entry is attributed to.
///
/// `acl_entries.granted_by` is checked by the grant engine against this tenant's `users`, so it has
/// to name somebody real, and only [`Actor::User`] is. A [`Refused`] rather than an [`Error`]
/// because the chain has already allowed by the time this is asked, so the refusal needs an audit
/// row of its own (`ENC-606`) and returning one is what makes the gate able to see it.
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`]. A link bearer least of all (`ENC-879`):
/// `Actor::subject_id` answers `Some` with a `share_links.id`, which is a real row in the wrong
/// table entirely, and a link that could re-permission what it exposes would be a link that grants
/// itself more than it was given.
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        Actor::Guest(_)
        | Actor::ServiceAccount(_)
        | Actor::McpClient(_)
        | Actor::LinkBearer(_)
        | Actor::System => Err(Refused::actor(ReasonCode::AccessDenied)),
    }
}

/// Turns the request body into the typed set the grant engine writes.
///
/// Every value is parsed rather than passed through, and that is the property this function exists
/// for: [`Action`]'s `Display` is what `acl_entries.action` holds and what the resolver reads, so
/// accepting a string the round trip does not survive would store a row that matches no decision the
/// product will ever take and looks correct on every screen.
///
/// # Errors
///
/// [`Error::Validation`] naming `entries` and nothing else. The offending value is **not** echoed:
/// a permissions request carries principal identifiers, and an error body is the shortest path from
/// one of those to a log line (`CLAUDE.md` rule 10).
fn desired_entries(body: &ReplaceRequest) -> Result<Vec<DesiredEntry>, Error> {
    let mut desired = Vec::with_capacity(body.entries.len());
    for entry in &body.entries {
        let (Some(action), Some(effect), Some(kind)) = (
            parse_action(&entry.action),
            Effect::parse(&entry.effect),
            PrincipalKind::parse(&entry.principal.kind),
        ) else {
            return Err(malformed_entry());
        };
        desired.push(DesiredEntry {
            // `Principal` is built from the two fields as they arrived, including the case the
            // schema cannot state — a `USER` with no identifier. It is refused by the grant engine
            // rather than here, so that "which principals are well formed" has one definition:
            // `uq_acl_entry` folds a `NULL` identifier into the nil UUID, so such a row does not
            // merely fail to match its user, it competes for the row `EVERYONE` occupies.
            principal: Principal { kind, id: entry.principal.id },
            action,
            effect,
            expires_at: entry.expires_at,
        });
    }
    Ok(desired)
}

/// Parses `family.verb` back into an [`Action`].
///
/// The exact inverse of [`Action`]'s `Display`, which is what makes a grant and the decision it is
/// meant to permit name the same thing. All four families are accepted, `admin` included, and that
/// is deliberate: `enclave_authorization::grant` refuses an administrative action with an argument
/// of its own — `acl_entries.action` is free text and `crate::admin` decides administrative actions
/// from `users.is_admin` without consulting the table, so a row spelling `admin.manage_policy` would
/// grant nothing today and be honoured the day somebody wires the two together. Refusing it here as
/// well would be a second definition of "grantable" that could come to disagree with the engine's.
fn parse_action(raw: &str) -> Option<Action> {
    let (family, verb) = raw.split_once('.')?;
    match family {
        "file" => verb.parse::<FileAction>().ok().map(Action::File),
        "container" => verb.parse::<ContainerAction>().ok().map(Action::Container),
        "share" => verb.parse::<ShareAction>().ok().map(Action::Share),
        "admin" => verb.parse::<AdminAction>().ok().map(Action::Admin),
        _ => None,
    }
}

/// Makes the resource's explicit ACL equal `desired`, in the caller's transaction.
///
/// # This is a seam, and it is temporary — `ENC-917`'s one honest compromise
///
/// `enclave_authorization::grant` is where a replace belongs, and at the time this landed the crate
/// held [`MAX_REPLACE_ENTRIES`], [`DesiredEntry`], [`ReplaceOutcome`],
/// [`GrantError::TooManyEntries`] and [`GrantError::ContradictoryEntries`] — the whole vocabulary of
/// the operation — and **no `replace` function**. `crates/authorization/src/grant.rs` is not a file
/// this item owns. So the operation is composed here, out of that crate's own public functions and
/// out of nothing else: [`enclave_authorization::grant::entries_on`] reads the current set,
/// [`enclave_authorization::grant::revoke`] removes what the caller did not declare, and
/// [`enclave_authorization::grant::grant`] writes what they did.
///
/// **No SQL is written here, and none may be.** Every decision that is invisible in the DDL — the
/// conflict target is an expression list, an `ALLOW` may not land on a `DENY`, `inherited_from` has
/// to be cleared, duplicate actions abort the whole statement, a file's `acl_revision` has to move —
/// stays inside the engine, which is the mistake `grant`'s module documentation is written against.
/// What is re-derived here is only the bookkeeping a replace adds on top: the set difference, the
/// three counts, and the two refusals the error variants above already specify.
///
/// When `enclave_authorization::grant::replace` lands, **this body becomes one line** —
/// `grant::replace(conn, tenant, resource, desired, granted_by, now).await` — and the swap is
/// behaviour-preserving, because the semantics implemented below are the ones [`ReplaceOutcome`]'s
/// and [`GrantError`]'s own documentation specifies. The signature is deliberately that call's.
///
/// # The order of the two writes is not arbitrary
///
/// Revocations run **only** over the keys the caller did not declare. Revoking the whole set first
/// and re-granting it would be simpler and would quietly lift every stored `DENY`, because a
/// re-grant onto an empty slot cannot trip [`GrantError::DenyInPlace`] — that is the undetectable
/// privilege gain the guard exists to prevent, arriving through a supported operation. A declared
/// `ALLOW` over a stored `DENY` is therefore refused here exactly as it is anywhere else, and
/// lifting a denial stays two deliberate acts.
///
/// # Inherited rows are not removable
///
/// A row carrying `inherited_from` was copied down by a break of inheritance
/// ([`materialise`]), and it is not part of the set this operation replaces: it is not counted in
/// `removed` and it is never revoked. A declared entry that collides with one overwrites it and is
/// counted as an update, which is what clears `inherited_from` and turns a copy into a direct grant.
///
/// # Errors
///
/// [`GrantError::TooManyEntries`], [`GrantError::ContradictoryEntries`], and everything
/// [`enclave_authorization::grant::grant`] and [`enclave_authorization::grant::revoke`] can raise —
/// including [`GrantError::DenyInPlace`] and the resource being invisible to this transaction.
async fn write_desired_set(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    resource: ChainNode,
    desired: &[DesiredEntry],
    granted_by: UserId,
    now: DateTime<Utc>,
) -> Result<ReplaceOutcome, GrantError> {
    if desired.len() > MAX_REPLACE_ENTRIES {
        return Err(GrantError::TooManyEntries { limit: MAX_REPLACE_ENTRIES });
    }

    // Collapsed into the one slot `uq_acl_entry` allows per key, refusing a set that disagrees with
    // itself. Not resolved by a rule — last-wins, deny-wins, anything — because every such rule
    // silently discards half of what the caller sent, and the row it drops is the one nobody looks
    // at again.
    let mut declared: HashMap<EntryKey, DesiredEntry> = HashMap::with_capacity(desired.len());
    for entry in desired {
        match declared.entry(key_of(entry.principal, &entry.action.to_string())) {
            std::collections::hash_map::Entry::Occupied(slot) => {
                if *slot.get() != *entry {
                    return Err(GrantError::ContradictoryEntries {
                        action: entry.action.to_string(),
                    });
                }
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                let _inserted = slot.insert(*entry);
            }
        }
    }

    let before = enclave_authorization::grant::entries_on(conn, tenant, resource, now).await?;
    let held: HashSet<EntryKey> =
        before.iter().map(|row| key_of(row.entry.principal, &row.action)).collect();

    // Everything stored directly on the resource that this replace has to clear out of the way,
    // grouped by the principal `revoke` takes one call for. Two populations, and the second is the
    // one that is easy to miss.
    //
    // The obvious one is an entry the caller did not re-declare: that is what makes this a replace
    // rather than a merge.
    //
    // The other is a stored **`DENY`** the caller re-declared as an `ALLOW`. It cannot simply be
    // written over, because `grant` refuses to overwrite a `DENY` (`GrantError::DenyInPlace`) — and
    // that refusal is correct where it lives, since a grant is an *incremental* act and erasing a
    // decisive denial as a side effect of one is exactly the weakening `ENC-916` refused. A replace
    // is not incremental: it is a caller holding `manage_permissions` stating the complete intended
    // set, and a permissions screen that could not lift a deny would leave `DENY` unremovable by
    // any route this product serves. So the deny is revoked first and re-granted as an allow, which
    // makes lifting it two statements inside one transaction rather than one silent overwrite.
    //
    // Without this the failure is narrow enough to ship: omitting a `DENY` removes it, so only
    // *changing* one to an `ALLOW` in a single `PUT` fails, and it fails with a `409` rather than
    // wrongly. That is why it needs a test rather than an argument —
    // `a_stored_deny_can_be_lifted_to_an_allow_in_one_replace`.
    let mut doomed: HashMap<PrincipalKey, (Principal, Vec<Action>)> = HashMap::new();
    let mut removed = 0_usize;
    for row in &before {
        if row.inherited_from.is_some() {
            continue;
        }
        if let Some(want) = declared.get(&key_of(row.entry.principal, &row.action)) {
            // Re-declared. Only a deny being lifted needs clearing, and it is not a removal: the
            // `(principal, action)` slot survives this call, so it is counted as an update below.
            if !(row.entry.effect == Effect::Deny && want.effect == Effect::Allow) {
                continue;
            }
            if let Some(action) = parse_action(&row.action) {
                doomed
                    .entry(principal_key(row.entry.principal))
                    .or_insert_with(|| (row.entry.principal, Vec::new()))
                    .1
                    .push(action);
            }
            continue;
        }
        // A stored spelling this build cannot parse is left where it is rather than guessed at.
        // `acl_entries.action` is free text (`docs/04-DATA-MODEL.md §9`), so a row written by an
        // older release would otherwise be removed by a client that never saw it — and `revoke`
        // takes an [`Action`], so there is no way to name it here in any case.
        let Some(action) = parse_action(&row.action) else { continue };
        doomed
            .entry(principal_key(row.entry.principal))
            .or_insert_with(|| (row.entry.principal, Vec::new()))
            .1
            .push(action);
        removed += 1;
    }
    for (principal, actions) in doomed.values() {
        for chunk in actions.chunks(MAX_GRANT_ACTIONS) {
            let _gone =
                enclave_authorization::grant::revoke(conn, tenant, resource, *principal, chunk)
                    .await?;
        }
    }

    // Everything declared, grouped by the three things one [`Grant`] fixes — the principal, the
    // effect and the expiry — so that only the action list varies within a group.
    let mut writes: HashMap<GrantKey, (Grant, Vec<Action>)> = HashMap::new();
    let mut added = 0_usize;
    let mut updated = 0_usize;
    for (key, entry) in &declared {
        if held.contains(key) {
            updated += 1;
        } else {
            added += 1;
        }
        let write = Grant {
            resource,
            principal: entry.principal,
            effect: entry.effect,
            granted_by,
            expires_at: entry.expires_at,
        };
        writes
            .entry((principal_key(entry.principal), entry.effect.as_str(), entry.expires_at))
            .or_insert_with(|| (write, Vec::new()))
            .1
            .push(entry.action);
    }
    for (write, actions) in writes.values() {
        for chunk in actions.chunks(MAX_GRANT_ACTIONS) {
            let _written =
                enclave_authorization::grant::grant(conn, tenant, write, chunk, now).await?;
        }
    }

    // Re-read inside the same transaction, so the set a handler renders and the revision it reports
    // describe one state that existed at one instant.
    let entries = enclave_authorization::grant::entries_on(conn, tenant, resource, now).await?;
    Ok(ReplaceOutcome { added, updated, removed, entries })
}

/// The one slot `uq_acl_entry` allows: a principal and an action.
///
/// The identifier is folded exactly as the index folds it — `COALESCE(principal_id, nil)` — because
/// that is what makes `EVERYONE` a key at all, and because a `USER` written without an identifier
/// does not merely fail to match its user, it competes for the row `EVERYONE` occupies.
type EntryKey = (&'static str, Uuid, String);

/// The principal half of that key.
type PrincipalKey = (&'static str, Uuid);

/// A principal, an effect and an expiry — everything one [`Grant`] fixes except the actions.
type GrantKey = (PrincipalKey, &'static str, Option<DateTime<Utc>>);

/// The key one stored or declared entry occupies.
fn key_of(principal: Principal, action: &str) -> EntryKey {
    let (kind, id) = principal_key(principal);
    (kind, id, action.to_owned())
}

/// The two columns that identify a principal, folded as the unique index folds them.
fn principal_key(principal: Principal) -> PrincipalKey {
    (principal.kind.as_str(), principal.id.unwrap_or_else(Uuid::nil))
}

/// Whether the caller still resolves to `manage_permissions` on this resource.
///
/// Asked of [`AclResolver`] inside the caller's own transaction, so the answer is about the state
/// the replace has just written and not about the state it replaced. The resolver is the same code
/// the authorization stage runs — this is not a second implementation of the rule, it is the rule,
/// asked a second time about a different state of the world.
///
/// It is **only** the ACL resolver, with no administrative or self-service layer above it, and that
/// is the point rather than an oversight: `users.is_admin` grants `admin.*`, not
/// `container.manage_permissions`, so a check that composed the administrative layer in would report
/// that a tenant administrator retained a right the resolver will refuse them the moment they use
/// it.
///
/// # Errors
///
/// Storage failures and unreadable rows, mapped onto the vocabulary the API edge speaks. A
/// resolution that could not happen is not a resolution that said no, so a failure here refuses the
/// **request** rather than being read as a lockout.
async fn retains_management(
    conn: &mut sqlx::PgConnection,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
    now: DateTime<Utc>,
) -> Result<bool, Error> {
    let effective = AclResolver::new()
        .effective_in_tx(conn, ctx.tenant_id, &ctx.actor, action, &[*resource], now)
        .await
        .map_err(Error::from)?;
    // One resource in, one answer out. A missing answer is treated as a lockout, which refuses the
    // replace — the direction an absent verdict has to fail in, because the alternative commits a
    // set nobody has confirmed the caller can undo.
    Ok(effective.first().copied().is_some_and(Effective::is_allowed))
}

/// The resource's inheritance chain — itself first, then everything above it that still reaches it.
///
/// Borrowed from [`enclave_authorization::repo`] rather than walked here. These are the very queries
/// `crate::service`'s resolver decides against and `crate::materialise`'s copy reads, and a second
/// similar-looking walk written at the API edge would be one refactor away from disagreeing with
/// them — at which point this screen would explain an access the product does not grant, or hide one
/// it does.
///
/// A resource absent from the walk is one this transaction cannot see: another tenant's,
/// soft-deleted, or never real. All three are [`Error::NotFound`], on purpose.
///
/// # Errors
///
/// [`Error::NotFound`] for a resource the walk could not see, and the mapped form of a storage
/// failure, an unreadable row or a chain deeper than the resolver's own limit.
async fn chain_of(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    surface: Surface,
    id: Uuid,
) -> Result<InheritanceChain, Error> {
    let ids = [id];
    let mut chains = match surface {
        Surface::Workspace => repo::workspace_chains(conn, tenant, &ids).await,
        Surface::Library => repo::library_chains(conn, tenant, &ids).await,
        Surface::Content => {
            repo::file_chains(conn, tenant, &ids, ResolverLimits::DEFAULT.max_inheritance_depth)
                .await
        }
    }
    .map_err(Error::from)?;

    chains.remove(&id).ok_or(Error::NotFound)
}

/// Reads the resource's ACL and everything above it, and renders `docs/05-API.md §7`'s object.
///
/// One round trip per chain node, through [`enclave_authorization::grant::entries_on`] — the same
/// reader the write path uses, so the set a caller sees after a replace is read by the code that
/// wrote it. The cost is bounded by [`ResolverLimits::max_inheritance_depth`] and is in practice
/// three or four queries: a file, its folders, its library and its workspace. A single statement
/// over the whole chain would be faster and would be a second definition of "the entries on a
/// resource", which is the trade this deliberately does not take.
///
/// # Errors
///
/// [`Error::NotFound`] for a resource this transaction cannot see, and the mapped form of a storage
/// failure or an unreadable row.
async fn render(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    surface: Surface,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<PermissionsView, Error> {
    let chain = chain_of(conn, tenant, surface, id).await?;
    let node = chain.nodes().first().copied().ok_or(Error::NotFound)?;

    let mut effective: Vec<EntryView> = Vec::new();
    let mut explicit: Vec<EntryView> = Vec::new();
    for ancestor in chain.nodes() {
        let rows = enclave_authorization::grant::entries_on(conn, tenant, *ancestor, now)
            .await
            .map_err(Error::from)?;
        for row in &rows {
            let view = entry_view(*ancestor, row);
            if *ancestor == node {
                explicit.push(entry_view(*ancestor, row));
            }
            effective.push(view);
        }
    }

    Ok(PermissionsView {
        resource: ResourceView { kind: node.kind.as_str(), id: node.id },
        // A chain of one node is a resource with nothing above it reaching it: a workspace, or a
        // resource whose inheritance has been broken. The walk stops at a node that does not
        // inherit, so this is read from the same fact the resolver decides on rather than from a
        // column re-read here.
        inherits: chain.nodes().len() > 1,
        acl_revision: acl_revision(conn, tenant, surface, id).await?,
        explicit,
        effective,
    })
}

/// `files.acl_revision`, for the two resource kinds that have one.
///
/// `None` for a workspace and a library because `docs/04-DATA-MODEL.md §7` gives the column to
/// `files` alone. Reporting a fabricated counter for a container would give a client something to
/// compare that means nothing, and the comparison a client makes with this value is whether its
/// cached ACL is stale.
///
/// # Errors
///
/// [`Error::NotFound`] when the node is not visible to this transaction, and the mapped form of a
/// storage failure.
async fn acl_revision(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    surface: Surface,
    id: Uuid,
) -> Result<Option<i64>, Error> {
    if surface != Surface::Content {
        return Ok(None);
    }
    let node = FileRepository::find_by_id(conn, tenant, FileId::from_uuid(id))
        .await
        .map_err(Error::from)?
        .ok_or(Error::NotFound)?;
    Ok(Some(node.acl_revision))
}

/// Renders one stored row, tagged with the resource it is stored on.
///
/// The tag is what makes `effective` explicable: without it, an entry inherited from the workspace
/// and an entry written on the file are the same object on the wire, and the screen that has to
/// explain access can only say that it exists.
fn entry_view(source: ChainNode, row: &GrantedEntry) -> EntryView {
    EntryView {
        id: row.id,
        source: ResourceView { kind: source.kind.as_str(), id: source.id },
        principal: PrincipalView {
            kind: row.entry.principal.kind.as_str(),
            id: row.entry.principal.id,
        },
        action: row.action.clone(),
        effect: row.entry.effect.as_str(),
        inherited_from: row.inherited_from,
        granted_by: row.granted_by,
        granted_at: row.granted_at,
        expires_at: row.entry.expires_at,
        expired: row.expired,
    }
}

/// `409`, for the set that would leave its author unable to change it back.
///
/// Not a `403`: the caller is permitted to perform this operation, and it is the **state** the
/// operation would produce that is refused. A `403` would tell an administrator they lack a right
/// they demonstrably hold, and would send them looking for the grant rather than at the set they
/// sent. `admin::dlp::refuse_self_lockout` makes the same distinction for the same reason.
///
/// Every string is a literal, and the set that was refused is not echoed. The caller sent it; a
/// refusal is not the place to read a tenant's principal identifiers back out.
fn refuse_self_lockout() -> Envelope {
    Envelope::new(
        axum::http::StatusCode::CONFLICT,
        "WOULD_REMOVE_OWN_MANAGE_PERMISSIONS",
        "This set would leave you unable to manage permissions here.",
        "Keep an entry that grants you manage_permissions on this resource, or ask somebody who \
         also holds it to make the change.",
    )
    .with_details(vec![serde_json::json!({
        "field": "entries",
        "code": ValidationCode::Inconsistent.as_str(),
        "detail": "the resolver was asked how this set would decide manage_permissions for the \
                   caller, inside the transaction that wrote it, and answered no; inheritance was \
                   included in that answer, so an entry on an ancestor would have been enough",
    })])
}

/// `400` for an entry this build cannot turn into a grant, inside `§5`'s envelope.
///
/// Names the array and not the element. An index would be a value the caller sent, and the fields
/// that could have been wrong — a principal identifier, an action — are the two a permissions error
/// must not repeat back.
fn malformed_entry() -> Error {
    Error::Validation(vec![FieldError::new("entries", ValidationCode::InvalidFormat)])
}

/// `400` for a body that will not decode, inside `§5`'s envelope.
///
/// A copy of `routes::folders::unreadable_body` rather than a shared helper, because that one is
/// private to its module and the duplication is four literals rather than a policy.
fn unreadable_body() -> Envelope {
    Envelope::new(
        axum::http::StatusCode::BAD_REQUEST,
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

    use enclave_authorization::AclResourceType;
    use enclave_core::ClassificationRank;

    use super::*;

    /// A context for one actor, built from the one constructor `RequestContext` offers.
    ///
    /// The type deliberately implements no `Deserialize` — a context that could be parsed from bytes
    /// is a context whose tenant could come from a request body — so a test builds one by taking the
    /// system context and naming the principal it is about.
    fn context(tenant: TenantId, actor: Actor) -> RequestContext {
        RequestContext { actor, ..RequestContext::system(tenant) }
    }

    /// The container action and the file action are two actions, and the surface never confuses
    /// them.
    ///
    /// `crates/authorization/src/repo.rs` matches `a.action = ANY($2::text[])` — string equality
    /// with no implication from one family to the other — so a folder decided by
    /// `container.manage_permissions` would resolve against entries nobody wrote, and would answer
    /// `404` to the very founder who holds the file action on it. Asserted over
    /// [`Surface::manage`]'s output rather than by reading the source, so a later edit that
    /// collapsed the two fails here.
    #[test]
    fn a_container_and_a_file_are_managed_under_two_different_actions() {
        assert_eq!(
            Surface::Workspace.manage(),
            Action::Container(ContainerAction::ManagePermissions)
        );
        assert_eq!(
            Surface::Library.manage(),
            Action::Container(ContainerAction::ManagePermissions)
        );
        assert_eq!(Surface::Content.manage(), Action::File(FileAction::ManagePermissions));

        // The spelling is the one `acl_entries.action` stores and the resolver reads. A grant
        // written any other way matches nothing and looks correct everywhere.
        assert_eq!(Surface::Content.manage().to_string(), "file.manage_permissions");
        assert_eq!(Surface::Workspace.manage().to_string(), "container.manage_permissions");
    }

    /// An id that does not parse names no resource, and a well-formed one is pointed at the right
    /// kind.
    ///
    /// The positive control is on the same line as the negative: without it, "garbage is refused"
    /// passes against a function that refuses everything, which would make every endpoint here a
    /// `404`.
    #[test]
    fn an_unparseable_id_names_no_resource_and_a_parseable_one_names_its_own_kind() {
        let tenant = TenantId::new_v7();
        let id = Uuid::new_v4();
        let raw = id.to_string();

        assert_eq!(
            Surface::Workspace.resource(tenant, &raw).map(|r| r.kind),
            Some(enclave_core::ResourceKind::Workspace)
        );
        assert_eq!(
            Surface::Library.resource(tenant, &raw).map(|r| r.kind),
            Some(enclave_core::ResourceKind::Library)
        );
        assert_eq!(
            Surface::Content.resource(tenant, &raw).map(|r| r.kind),
            Some(enclave_core::ResourceKind::File)
        );

        for surface in [Surface::Workspace, Surface::Library, Surface::Content] {
            assert!(
                surface.resource(tenant, "not-a-uuid").is_none(),
                "an unparseable id must produce no reference at all, so the handler can only 404"
            );
        }
    }

    /// Every action string this endpoint accepts round-trips through the spelling the resolver
    /// reads.
    ///
    /// The property that makes a grant and the decision it is meant to permit name the same thing.
    /// The whole vocabulary is walked rather than a sample, because the failure this catches is one
    /// verb rendering differently from the way it parses.
    #[test]
    fn every_action_parses_back_into_the_action_it_prints_as() {
        let vocabulary = FileAction::all()
            .iter()
            .map(|a| Action::File(*a))
            .chain(ContainerAction::all().iter().map(|a| Action::Container(*a)))
            .chain(ShareAction::all().iter().map(|a| Action::Share(*a)))
            .chain(AdminAction::all().iter().map(|a| Action::Admin(*a)));

        for action in vocabulary {
            let rendered = action.to_string();
            assert_eq!(
                parse_action(&rendered),
                Some(action),
                "`{rendered}` does not survive the round trip the ACL column depends on"
            );
        }

        // The negative half, which is what stops the loop above passing against a parser that
        // returns `Some` for anything: neither an unknown family, nor an unknown verb, nor a bare
        // verb with no family is an action.
        for rejected in ["file.teleport", "workspace.read", "download", "", "file.", ".read"] {
            assert!(parse_action(rejected).is_none(), "`{rejected}` must not parse as an action");
        }
    }

    /// A well-formed body becomes typed values; a body this build cannot spell is a `400` that
    /// names the array and repeats nothing.
    #[test]
    fn a_desired_set_is_parsed_rather_than_passed_through() {
        let user = Uuid::new_v4();
        let body = ReplaceRequest {
            entries: vec![
                DesiredEntryRequest {
                    principal: PrincipalRequest { kind: "USER".to_owned(), id: Some(user) },
                    action: "container.read".to_owned(),
                    effect: "ALLOW".to_owned(),
                    expires_at: None,
                },
                DesiredEntryRequest {
                    principal: PrincipalRequest { kind: "EVERYONE".to_owned(), id: None },
                    action: "file.download".to_owned(),
                    effect: "DENY".to_owned(),
                    expires_at: None,
                },
            ],
        };

        let desired = desired_entries(&body).expect("a well-formed set is accepted");
        assert_eq!(desired.len(), 2);
        assert_eq!(desired[0].action, Action::Container(ContainerAction::Read));
        assert_eq!(desired[0].effect, Effect::Allow);
        assert_eq!(desired[0].principal, Principal::new(PrincipalKind::User, user));
        assert_eq!(desired[1].effect, Effect::Deny);
        assert_eq!(desired[1].principal, Principal::everyone());

        // An action this build does not know is refused, and the refusal names `entries` and
        // carries no value the caller sent.
        let refused = ReplaceRequest {
            entries: vec![DesiredEntryRequest {
                principal: PrincipalRequest { kind: "USER".to_owned(), id: Some(user) },
                action: "file.teleport".to_owned(),
                effect: "ALLOW".to_owned(),
                expires_at: None,
            }],
        };
        let error = desired_entries(&refused).expect_err("an unknown action must be refused");
        let rendered = format!("{error:?}");
        assert!(rendered.contains("entries"), "the refusal must name the field: {rendered}");
        assert!(
            !rendered.contains(&user.to_string()),
            "a refusal must not repeat a principal identifier: {rendered}"
        );
    }

    /// Every obligation a stage can attach is either refused or argued, and the one that depends on
    /// the request's intent is asserted in both directions.
    ///
    /// The positive control is the empty set: a `satisfy` that simply refused everything would pass
    /// every "this is refused" assertion below while making the endpoint unusable, and only the
    /// empty case can tell the two apart.
    #[test]
    fn an_obligation_this_path_cannot_discharge_refuses_the_request() {
        for intent in [Intent::Read, Intent::Write] {
            assert!(
                satisfy(&Obligations::none(), intent).is_ok(),
                "an unconditional allow must proceed"
            );
        }

        for obligation in [
            Obligation::Watermark,
            Obligation::RequireJustification,
            Obligation::RequireApproval,
            Obligation::Reclassify { to: ClassificationRank::new(40) },
        ] {
            let set: Obligations = [obligation].into_iter().collect();
            for intent in [Intent::Read, Intent::Write] {
                let refused =
                    satisfy(&set, intent).expect_err("an undischargeable obligation must refuse");
                assert_eq!(
                    refused.code(),
                    obligation.unsatisfied_code(),
                    "the refusal must carry D29's standard code for {obligation:?}"
                );
            }
        }

        // The two that restrict content, which an access-control list is not.
        for obligation in [Obligation::NoDownload, Obligation::NoSync] {
            let set: Obligations = [obligation].into_iter().collect();
            for intent in [Intent::Read, Intent::Write] {
                assert!(
                    satisfy(&set, intent).is_ok(),
                    "{obligation:?} restricts content, and an ACL is not content"
                );
            }
        }

        // The one that is a question about the request rather than about the resource.
        let read_only: Obligations = [Obligation::ReadOnly].into_iter().collect();
        assert!(
            satisfy(&read_only, Intent::Read).is_ok(),
            "a read is what READ_ONLY permits, so reading the ACL must proceed"
        );
        assert_eq!(
            satisfy(&read_only, Intent::Write)
                .expect_err("READ_ONLY must suppress a replace")
                .code(),
            Obligation::ReadOnly.unsatisfied_code()
        );
    }

    /// Only a directory user may answer for an entry.
    ///
    /// `acl_entries.granted_by` is checked against `users`, and four of the five other actors
    /// answer `Some` to `Actor::subject_id` while naming a row in another table entirely. The
    /// positive control is the user, without which this passes against an `author` that refuses
    /// everybody and makes the endpoint unusable.
    #[test]
    fn only_a_user_can_answer_for_a_grant() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();

        let ctx = context(tenant, Actor::User(user));
        assert_eq!(author(&ctx).expect("a user answers for their own grants"), user);

        for actor in [
            Actor::Guest(enclave_core::GuestId::new_v7()),
            Actor::ServiceAccount(enclave_core::ServiceAccountId::new_v7()),
            Actor::LinkBearer(enclave_core::ShareLinkId::new_v7()),
            Actor::System,
        ] {
            let ctx = context(tenant, actor);
            let refused = author(&ctx).expect_err("only a directory user may grant");
            assert_eq!(refused.code(), ReasonCode::AccessDenied);
        }
    }

    /// The lockout refusal is a `409` and it does not read the caller's set back to them.
    ///
    /// The status is the assertion that matters: a `403` here would tell an administrator they lack
    /// a right they demonstrably hold — the chain allowed them one step earlier — and would send
    /// them looking for a grant instead of at the entries they sent.
    #[test]
    fn a_self_lockout_is_a_conflict_and_echoes_nothing() {
        let envelope = refuse_self_lockout();
        assert_eq!(envelope.status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(envelope.code(), "WOULD_REMOVE_OWN_MANAGE_PERMISSIONS");

        let rendered = serde_json::to_string(envelope.details()).expect("render");
        assert!(rendered.contains("entries"), "the refusal must name the field: {rendered}");
        assert!(
            rendered.contains("inheritance"),
            "the detail must say that inheritance was included in the answer: {rendered}"
        );
    }

    /// An entry carries the resource it is stored on, which is the whole difference between the two
    /// lists on the wire.
    #[test]
    fn an_entry_is_tagged_with_the_resource_it_is_stored_on() {
        let workspace = Uuid::new_v4();
        let file = Uuid::new_v4();
        let source = ChainNode::new(AclResourceType::Workspace, workspace);
        let row = GrantedEntry {
            id: Uuid::new_v4(),
            entry: enclave_authorization::AclEntry {
                resource: ChainNode::new(AclResourceType::File, file),
                principal: Principal::everyone(),
                effect: Effect::Deny,
                expires_at: None,
            },
            action: "file.download".to_owned(),
            inherited_from: None,
            granted_by: Uuid::new_v4(),
            granted_at: Utc::now(),
            expired: false,
        };

        let view = entry_view(source, &row);
        assert_eq!(view.source.kind, "WORKSPACE");
        assert_eq!(view.source.id, workspace, "the tag names where the row is, not what it is on");
        assert_eq!(view.principal.kind, "EVERYONE");
        assert_eq!(view.principal.id, None, "EVERYONE carries no identifier");
        assert_eq!(view.effect, "DENY");
    }
}
