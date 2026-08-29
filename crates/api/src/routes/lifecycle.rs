//! The file lifecycle — rename, move, trash and restore (`ENC-807`).
//!
//! `docs/05-API.md §7` gives three rows to what this module serves, and they are the whole
//! specification:
//!
//! | `PATCH` | `/files/{id}` | Rename, reparent, change content type; `If-Match` required |
//! | `DELETE` | `/files/{id}` | Soft delete to trash |
//! | `POST` | `/files/{id}/restore` | Restore from trash |
//!
//! Everything below the paths is derived from `§4`'s request conventions, `§5`'s error model and
//! `§7`'s `capabilities` contract, and each derivation is argued where it is made.
//!
//! # Why this module exists
//!
//! `ENC-807`, the remainder of `ENC-788`. [`FileRepository::rename`], [`FileRepository::reparent`],
//! [`FileRepository::trash`] and [`FileRepository::restore`] have existed since M1 — with the
//! composite keys, the recursive cycle guard, the cascade and the exact-timestamp restore
//! discriminator — and **not one of them had a caller in any binary**. A document repository in
//! which a file cannot be renamed, moved or deleted is not a document repository, and this is the
//! last large functional gap in `§7`'s table.
//!
//! It is this repository's signature failure one more time: a complete, tested engine that nothing
//! calls. `crates/api/tests/lifecycle.rs` therefore runs against the shipped [`crate::router`] and
//! mounts nothing of its own, because a suite that registers the handlers it tests says only that
//! the handlers work.
//!
//! # `PATCH` is two actions, and they are enforced separately
//!
//! A rename is `file.edit`. A move is `file.move`. They are two entries in
//! [`enclave_core::FileAction`] and `crates/authorization/src/repo.rs` matches
//! `a.action = ANY($2::text[])` — string equality, with no implication from one to the other — so a
//! body asking for both has to satisfy **both**, asked as two questions. That is `CLAUDE.md` rule 6
//! applied to the file surface: collapsing them into one `edit` question would let a caller who may
//! correct a typo relocate the document into a folder with a different inherited ACL, which is the
//! whole reason `Move` is a separate verb ("Relocate, which changes inherited permissions").
//!
//! # A move authorizes against the destination as well
//!
//! `container.create` on the container the node would land in, exactly as
//! [`crate::routes::folders::create`] asks it of the container a folder goes into, and
//! [`destination_of`] mirrors `folders::container_of` for the same reason the two upload paths
//! mirror each other: a folder a caller may create a folder in and may not move a file into would be
//! two answers to one question. Without it, "move" is an escalation dressed as an edit — the
//! caller's own `file.move` on the *source* would be enough to place content wherever they liked.
//!
//! The destination question is asked with [`conceal`], so a caller who may not write there cannot
//! learn whether it exists (`CLAUDE.md` rule 7).
//!
//! # `If-Match` is required and never defaulted
//!
//! [`Mutation::expected_revision`] says it in as many words: *"`None` is for server-initiated
//! maintenance, not for handlers: a user-facing write that skips this silently overwrites whatever
//! changed in between."* Every write below therefore passes `Some`, and the value comes from the
//! caller's header rather than from a read of the row — a handler that read the revision and passed
//! it back would be an optimistic-concurrency check against itself.
//!
//! **The statuses are `§5`'s and not the ones an HTTP reflex suggests.** A missing precondition is
//! not `428` and a stale one is not `412`, because `§5`'s status table names neither: `§4`'s own row
//! says `If-Match` is *"Optimistic concurrency; `409` on mismatch"*, and `§5` gives `409` to
//! "revision conflict" by name. So a stale `If-Match` is **`409`**, rendered by
//! [`enclave_core::Error::Conflict`], which carries the current revision so a client can re-read and
//! retry without a round trip to discover it. A missing one is **`400`** — `§5`'s "malformed request
//! or failed validation", the only row it can be — with the stable code `IF_MATCH_REQUIRED` and a
//! `details` entry that separates absent from unparseable.
//!
//! Every response that reports a file carries the `ETag` the next request must send back, because a
//! required precondition a client cannot obtain from the response is a required precondition
//! clients guess at.
//!
//! # `DELETE` cascades, and so does the authorization
//!
//! [`FileRepository::trash`] moves the **whole subtree** with one `deleted_at`. Authorizing only the
//! addressed node would let a caller trash a descendant they hold no `file.delete` on, which is
//! reachable the moment a descendant carries `inherit_permissions = FALSE`: the resolver's walk
//! stops there, so the grant that admitted the root does not reach the child. That is `ENC-141`'s
//! shape — a truncated walk failing towards *gained* privilege — and it is why every node in the
//! subtree is asked, in one [`AuthorizationService::authorize_many`], and why a single denial
//! refuses the entire operation. A half-trashed subtree is worse than a refusal: it is a folder
//! whose contents are partly invisible and partly not, with no request that repairs it.
//!
//! **The check runs inside the transaction that wrote, and a denial drops it.** The instruction this
//! was built to was to enumerate the subtree before writing anything; there is no enumeration
//! primitive in `crates/files` short of the trash statement's own `RETURNING`, and a `list_children`
//! walk would be a *different* set from the one the `UPDATE` goes on to touch — a child created
//! between the walk and the write would be trashed having been authorized by nobody. Writing first
//! and rolling back is therefore strictly stronger on the property that matters: the set that is
//! authorized is, by construction, exactly the set that was written. Nothing partial is observable
//! either way, because nothing commits. It is `routes::permissions::replace_acl`'s ordering and its
//! argument.
//!
//! That works for one specific reason worth stating, because it is fragile: the resolution runs on
//! the authorization stage's **own** connection, which cannot see this transaction's uncommitted
//! delete, so the question it answers is about the caller's rights over the live tree. Were the
//! resolver ever handed this transaction, every node would resolve against a deleted ancestor and
//! every delete in the product would refuse — loudly, and in the safe direction.
//!
//! # `restore` cannot ask about the file, and the reason is in the resolver
//!
//! `crates/authorization/src/repo.rs`'s `FILE_CHAIN_SQL` joins `files` with `deleted_at IS NULL` on
//! the walk's own root row. **A trashed node therefore has an empty inheritance chain**, every
//! question about it resolves to `NotGranted`, and enforcing `file.restore` on the node itself would
//! make restore unreachable for every caller forever — the `ENC-170` shape, arrived at through the
//! authorization layer instead of the router.
//!
//! So the question is asked of the container the node would come **back into**, which is exactly
//! `routes::folders::create`'s argument read from the other end: a resource whose own ACL cannot be
//! reached is decided by the container that would hold it. Naming that container costs one
//! repository read before the chain runs, and that read discloses nothing — it is
//! [`crate::state::ApiState::db`]-scoped, so another tenant's row is not visible to it at all, and
//! every way it can fail answers the same `404` a caller with no grant receives.
//!
//! The consequence is honest and is stated rather than hidden: when the parent folder is *also*
//! still in the trash, its chain is empty too, so a restore under it answers `404` rather than the
//! `422` [`FilesError::ParentInTrash`] would have produced. Both refuse and neither writes;
//! `ParentInTrash` is still mapped below, because the parent can be trashed by somebody else between
//! the decision and the write.
//!
//! # What this module does *not* do
//!
//! **"Change content type"** — the third clause of `§7`'s `PATCH` row. `files.content_type_id` is a
//! nullable reference into a metadata catalogue that does not exist: `enclave_core::id` has no
//! `ContentTypeId` newtype, [`enclave_files::FileNode`] deliberately omits the column (surfacing it
//! as a bare `Uuid` would put an untyped identifier on a public boundary), and [`FileRepository`] has
//! no mutation for it. Accepting the field would mean writing SQL at the API edge for a catalogue
//! with no rows in it. The body therefore refuses unknown fields, so `contentTypeId` is a `400`
//! rather than a value silently dropped, and the gap is the metadata crate's to close.
//!
//! **`POST /files/{id}/copy` and `/move`** are separate rows of `§7` — bulk-capable, with DLP
//! evaluated per destination. `PATCH`'s reparent is the single-node operation on one resource; the
//! bulk surface is a different contract and is not implied by this one.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, RequestExt as _};
use chrono::{Duration, Utc};
use enclave_core::{
    Action, Actor, ContainerAction, Error, FileAction, FileId, LibraryId, Obligation, Obligations,
    ReasonCode, RequestContext, RequestId, ResourceRef, TenantId, UserId, ValidationCode,
};
use enclave_files::{FileNode, FileRepository, FilesError, Mutation, NodeType, Parent};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Item};
use crate::error::{ApiError, Envelope};
use crate::refusal::Refused;
use crate::routes::workspaces::{conceal, consume};
use crate::state::ApiState;

// ---------------------------------------------------------------------------------------------
// The actions, named once
// ---------------------------------------------------------------------------------------------

/// A rename. `file.edit`, because the name is part of what the file *is*.
const RENAME: Action = Action::File(FileAction::Edit);

/// A move. Never `file.edit` — see the module note on rule 6.
const REPARENT: Action = Action::File(FileAction::Move);

/// The question asked of the destination a move lands in.
const ACCEPT: Action = Action::Container(ContainerAction::Create);

/// A soft delete.
const DISCARD: Action = Action::File(FileAction::Delete);

/// A restore, asked of the container the node returns into.
const REINSTATE: Action = Action::File(FileAction::Restore);

/// How long a trashed subtree is nominally kept before purging may be *considered*.
///
/// `files.purge_after` is supplied by the caller of [`FileRepository::trash`] rather than computed
/// there, on the stated grounds that "how long the trash keeps something is a tenant retention
/// setting, and `plans/M1-CONTENT-CORE.md` Q7 has not been answered; a default invented in a
/// repository would become the answer by accident". The column is `NOT NULL`-free but the function
/// is not, so this endpoint has to supply *something*.
///
/// Thirty days, and it is a placeholder rather than a policy: nothing reads it. [`enclave_files`]'s
/// purge is [`FilesError::PurgeUnavailable`] in every build, so no row is destroyed on the strength
/// of this value; when the retention setting lands it replaces this constant and the stored value
/// becomes meaningful for the first time. Naming it here, rather than inlining `Utc::now() + 30
/// days` at the call site, is what makes it findable on that day.
const TRASH_RETENTION_DAYS: i64 = 30;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The body of `PATCH /api/v1/files/{id}`.
///
/// `camelCase` per `§1`, and `deny_unknown_fields` for `crates/api/src/admin/dlp.rs`'s reason: a
/// lenient decoder accepts a body it then silently drops half of, and the half that goes missing
/// here is a rename the user watched succeed. It is also what makes `contentTypeId` a visible `400`
/// rather than a field this build pretends to honour — see the module note.
///
/// Both fields are optional and at least one must be present; a `PATCH` that asks for nothing is
/// refused rather than answered `200`, because "I changed nothing" and "I changed what you asked"
/// must not be the same response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateRequest {
    /// The new name, as the user typed it. Folded and validated by `enclave_files::normalize`.
    #[serde(default)]
    name: Option<String>,

    /// Where the node should end up.
    ///
    /// Three states, and the schema has to carry all three: **absent** means "do not move me",
    /// **`null`** means "move me to the library root", and **a string** names the destination
    /// folder. A plain `Option<String>` collapses the first two, which would make every rename a
    /// move to the root.
    ///
    /// `Option<Option<String>>` rather than `Option<Option<FileId>>` so that an unparseable id is
    /// this handler's `404` rather than a serde rejection, which axum answers with plain text
    /// outside `§5`'s envelope.
    #[serde(default, deserialize_with = "explicit_null")]
    parent_id: Option<Option<String>>,
}

/// Keeps `null` distinguishable from an absent field.
///
/// `serde` maps both onto `None` for an `Option<T>` field, so the outer `Option` has to be produced
/// by the deserializer itself: it runs only when the key is present, and answers `Some(None)` for a
/// literal `null`. The standard double-option shim, written out because the alternative — a bespoke
/// `Visitor` — is more code for the same three states.
fn explicit_null<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

/// The body of `DELETE /files/{id}` and `POST /files/{id}/restore`.
///
/// One type for both, deliberately. They are the two halves of one operation and a client that had
/// to hold two decoders for "the subtree moved" would be a client that can get the pair wrong.
///
/// It is **not** [`Item`], which is what `PATCH` answers with, and the difference is not laziness. A
/// trash and a restore are subtree operations whose result is a count and a fresh precondition;
/// rendering the addressed node as a browse row would mean resolving a `capabilities` object for a
/// node that has just left the tree — and the ACL walk stops at a deleted ancestor, so every field
/// of it would come back `false`. A client reading `"delete": false, "restore": false` off a
/// successful delete would draw exactly the wrong conclusion.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleView {
    /// The node the request addressed.
    id: String,
    /// Its revision afterwards — the value the next `If-Match` must carry, and the `ETag` beside it.
    revision: i64,
    /// How many nodes moved, the addressed one included.
    ///
    /// The half nobody typed. "It worked" is not an answer to "what did I just delete": a folder
    /// with eleven documents under it and an empty one produce the same `200`, and the difference is
    /// what a confirmation dialog has to be able to show.
    affected: usize,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `PATCH /api/v1/files/{id}` — rename, move, or both at once.
///
/// # The order of the steps, and why none of them may move
///
/// 1. **The id is parsed**, and a value that is not one is `404` before anything else happens. A
///    `400` there would tell a caller which of their guesses were well-formed (`CLAUDE.md` rule 7).
/// 2. **The precondition is read.** `If-Match` names no resource, so refusing it early discloses
///    nothing, and it is refused before the body is decoded because it is a condition on the
///    *request* rather than on what the request asks for.
/// 3. **The body is decoded**, which is where this path differs from
///    `routes::permissions::replace_acl` and has to: the body decides *which question* the chain is
///    asked, so it cannot be read afterwards. What a refused caller learns from a `400` here is a
///    fact about their own JSON.
/// 4. **The chain decides, once per requested action**, on the file, before any repository is
///    reached.
/// 5. **The node is read**, for the library a move-to-root names and for the destination question.
/// 6. **The destination is decided**, before any write.
/// 7. **The writes run in one transaction**, each guarded by a revision.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file, or a named destination, is another tenant's, absent, trashed
/// or not granted to this caller — and for an id that does not parse, which must not be
/// distinguishable from it; `400` for a body that will not decode, a body that asks for nothing, a
/// missing or unreadable `If-Match`, or a name the tree refuses; `409` for a stale `If-Match` and
/// for a live sibling already holding the name; `422` for a move the tree structurally refuses;
/// `403` with the obligation's own code when a decision carried one this path cannot discharge.
pub async fn update(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;

    let expected = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(failure) => return Ok(precondition(failure).into_response(request_id)),
    };

    let body: Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let body: UpdateRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let change = match requested_change(body, request_id)? {
        Some(change) => change,
        None => return Ok(nothing_to_change().into_response(request_id)),
    };

    // Two questions, asked separately, about the resource the path names. A body that asks for both
    // must satisfy both: see the module note on rule 6.
    let subject = ResourceRef::file(ctx.tenant_id, file);
    if change.name.is_some() {
        let obligations = decide(&state, &ctx, RENAME, &subject).await?;
        if let Err(refused) = satisfy(&obligations) {
            return Err(state.audit.refuse(&ctx, RENAME, &subject, refused).await);
        }
    }
    if change.destination.is_some() {
        let obligations = decide(&state, &ctx, REPARENT, &subject).await?;
        if let Err(refused) = satisfy(&obligations) {
            return Err(state.audit.refuse(&ctx, REPARENT, &subject, refused).await);
        }
    }

    // Read after the chain has allowed, and closed before the destination question: each `enforce`
    // takes a connection of its own, and holding this one meanwhile costs two per request
    // (`routes::folders::write` makes the same trade). Nothing depends on the two transactions
    // seeing one state — every write below is conditioned on a revision, so a row that changed in
    // between fails the precondition rather than being overwritten.
    let node = read_node(&state, &ctx, file).await?;

    if let Some(destination) = change.destination {
        let container = destination_of(ctx.tenant_id, node.library_id, destination);
        let obligations = decide(&state, &ctx, ACCEPT, &container).await?;
        if let Err(refused) = satisfy(&obligations) {
            return Err(state.audit.refuse(&ctx, ACCEPT, &container, refused).await);
        }
    }

    // The action the *body* asked for, not whichever was written first. A service account sending
    // `{"parentId": …}` was leaving a `file.edit` DENY row for a request that never asked
    // `file.edit`, which is a lie in the one table an investigation reads. When both were asked the
    // rename is the first the chain allowed, so it is the one this refusal is attributed to.
    let attempted = if change.name.is_some() { RENAME } else { REPARENT };
    let actor = match author(&ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(&ctx, attempted, &subject, refused).await),
    };

    let node = match apply(&state, &ctx, file, &change, node.library_id, expected, actor).await {
        Ok(node) => node,
        Err(WriteFailure::Refused(envelope)) => return Ok(envelope.into_response(request_id)),
        Err(WriteFailure::Fatal(error)) => return Err(ApiError::new(error, request_id)),
    };

    // Rendered exactly as `GET /libraries/{id}/items` will render it on the caller's next listing —
    // the same `Item`, the same `capabilities_for`, the same `ResourceRef` — for `content`'s reason:
    // a client that saw one object here and a different one a second later would need two decoders
    // for one thing, and the day they disagree it offers an action the listing hides.
    //
    // With **no** obligations to subtract: `satisfy` refuses the request outright unless every
    // decision carried none, so "nothing to subtract" is a property this path has established rather
    // than an omission here.
    let resource = reference(ctx.tenant_id, &node);
    let (capabilities, reasons, wire) = capabilities_for(
        state.policy.authorization().as_ref(),
        &ctx,
        &resource,
        &Obligations::none(),
    )
    .await
    .map_err(|error| ApiError::new(error, request_id))?;

    Ok(tagged(node.revision, Json(Item::new(&node, capabilities, reasons, wire)).into_response()))
}

/// Handles `DELETE /api/v1/files/{id}` — move the node, and everything under it, to the trash.
///
/// The cascade and the authorization of the cascade are the whole content of this handler; see the
/// module note for why every node in the subtree is asked and why the check runs inside the
/// transaction that wrote.
///
/// The refusal is `403` and deliberately not `404`. Rule 7 conceals resources whose *existence* is
/// the secret, and the resource this request addresses is one the chain has just allowed the caller
/// to delete — answering `404` would tell them that a file they can open does not exist. What the
/// `403` does disclose is that *something* under a folder they may read denies them `file.delete`,
/// and that is stated rather than pretended away: the alternative is an incoherent `404` on a
/// resource the same caller can `GET`.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file is another tenant's, absent, already trashed or not granted to
/// this caller, and for an id that does not parse; `400` for a missing or unreadable `If-Match`;
/// `409` for a stale one; `403` when any node in the subtree denies this caller `file.delete`, and
/// with the obligation's own code when the decision carried one this path cannot discharge.
pub async fn trash(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let expected = match expected_revision(&headers) {
        Ok(revision) => revision,
        Err(failure) => return Ok(precondition(failure).into_response(request_id)),
    };

    let subject = ResourceRef::file(ctx.tenant_id, file);
    let obligations = decide(&state, &ctx, DISCARD, &subject).await?;
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, DISCARD, &subject, refused).await);
    }

    let actor = match author(&ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(&ctx, DISCARD, &subject, refused).await),
    };

    let now = Utc::now();
    let change = Mutation { actor, expected_revision: Some(expected), at: now };
    let purge_after = now + Duration::days(TRASH_RETENTION_DAYS);

    // --- read, decide, write: three steps, and never two connections at once --------------------
    //
    // The obvious shape is to write the cascade first and authorize what came back, because `trash`
    // returns the subtree it changed. It is also wrong, and not subtly: `authorize_many` takes a
    // *second* connection from the same pool, so a handler that held its write transaction across
    // the batch would need two per request. `crates/api/src/content.rs` states the rule — "a
    // handler that held this one open while waiting for those needs two connections per request,
    // which on a small pool is a deadlock waiting for load" — and the default pool is sixteen with
    // a five-second acquire timeout, so sixteen concurrent deletes would each hold one connection,
    // each block on the second, and all sixteen would fail as `500`s with the `UPDATE`'s row locks
    // held throughout. `ENC-807`.
    //
    // So: enumerate in a short read, close it, decide, then write.

    let mut read = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let planned = match FileRepository::live_subtree(&mut read, ctx.tenant_id, file).await {
        Ok(subtree) => subtree,
        Err(error) => match classify(error) {
            WriteFailure::Refused(envelope) => return Ok(envelope.into_response(request_id)),
            WriteFailure::Fatal(error) => return Err(ApiError::new(error, request_id)),
        },
    };
    drop(read);

    // The addressed node is included in the batch even though the chain has already allowed it. One
    // uniform question over the whole set is what makes "every node was asked" a property of the
    // code rather than of a reader's attention.
    let resources: Vec<ResourceRef> =
        planned.iter().map(|node| reference(ctx.tenant_id, node)).collect();
    let decisions = state
        .policy
        .authorization()
        .authorize_many(&ctx, DISCARD, &resources)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // Length before content. `zip` would silently drop the tail of a short answer, and a tail that
    // is dropped here is a node nobody decided about — the one direction this check must not fail
    // in. `content::readable_children` can tolerate the same shortfall because trimming *more* rows
    // is safe; trashing more is not.
    let denied = if decisions.len() == resources.len() {
        resources
            .iter()
            .zip(&decisions)
            .find(|(_, decision)| !decision.is_allowed())
            .map(|(r, _)| *r)
    } else {
        resources.first().copied()
    };
    if let Some(resource) = denied {
        return Err(refuse_subtree(&state, &ctx, &resource).await);
    }

    let authorized: std::collections::HashSet<FileId> =
        planned.iter().map(|node| node.id).collect();

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let subtree =
        match FileRepository::trash(&mut tx, ctx.tenant_id, file, purge_after, &change).await {
            Ok(subtree) => subtree,
            Err(error) => match classify(error) {
                WriteFailure::Refused(envelope) => return Ok(envelope.into_response(request_id)),
                WriteFailure::Fatal(error) => return Err(ApiError::new(error, request_id)),
            },
        };

    // The snapshot above is a snapshot: a node can be created inside the subtree between the read
    // and this write, and it would be trashed by a cascade nobody authorized it for. Checking the
    // *written* set against the *authorized* set is what makes "the set authorized is the set
    // written" true rather than likely — and the transaction is dropped rather than committed, so a
    // caller who loses this race gets a refusal and an unchanged tree, not a partial delete.
    if let Some(surprise) = subtree.iter().find(|node| !authorized.contains(&node.id)) {
        let resource = reference(ctx.tenant_id, surprise);
        drop(tx);
        return Err(refuse_subtree(&state, &ctx, &resource).await);
    }

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let root = match subtree.first() {
        Some(node) => node,
        // Unreachable: `trash` answers `Err` for an empty result and puts the addressed node first.
        // An internal error rather than a panic, per the workspace's lint set.
        None => {
            return Err(ApiError::new(
                Error::Internal(anyhow::anyhow!("a trash returned no rows and no error")),
                request_id,
            ))
        }
    };

    Ok(tagged(
        root.revision,
        Json(LifecycleView {
            id: root.id.to_string(),
            revision: root.revision,
            affected: subtree.len(),
        })
        .into_response(),
    ))
}

/// Handles `POST /api/v1/files/{id}/restore` — bring a node, and what was trashed with it, back.
///
/// The question is `file.restore` **on the container the node returns into**, not on the node: a
/// trashed node has no inheritance chain at all, so a question about it can only ever answer no. The
/// module note carries the resolver line that makes that true and what it costs.
///
/// Only the subtree that was trashed *together with* this node comes back —
/// [`FileRepository::restore`] discriminates on the exact `deleted_at` the cascade stamped — so a
/// child deleted separately, before its parent was, stays deleted, which is what its own delete
/// meant.
///
/// Unlike the trash, the restored subtree is **not** re-authorized node by node, and the asymmetry
/// is deliberate: a trash makes content unreachable for everyone and a caller who may not delete a
/// node must not be able to, while a restore returns rows to exactly the ACL they had before a
/// delete somebody was permitted to make. Nothing becomes reachable that was not reachable before.
///
/// # Errors
///
/// [`ApiError`]: `404` when the node is another tenant's, absent, *not* in the trash, or when the
/// container it would return into is not granted to this caller — including the case where that
/// container is itself still trashed; `400` for a missing or unreadable `If-Match`; `409` for a
/// stale one and for a sibling that took the name while this node was away; `422` when the parent
/// was trashed between the decision and the write; `403` for an undischargeable obligation.
pub async fn restore(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let file: FileId = file.parse().map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let expected = match expected_revision(&headers) {
        Ok(revision) => revision,
        Err(failure) => return Ok(precondition(failure).into_response(request_id)),
    };

    // The one read this crate performs *before* the chain, and the module note argues it: without
    // the node's parent there is no container to ask about, and asking about the node itself is a
    // question the resolver cannot answer for anything in the trash. It leaks nothing — the
    // transaction is tenant-scoped, so another tenant's row is not visible to it, and every failure
    // here is the same `404` a caller with no grant receives.
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let found = FileRepository::find_including_trashed(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let node = found.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let container = destination_of(
        ctx.tenant_id,
        node.library_id,
        node.parent_id.map_or(Destination::Root, Destination::Folder),
    );

    let obligations = decide(&state, &ctx, REINSTATE, &container).await?;
    if let Err(refused) = satisfy(&obligations) {
        return Err(state.audit.refuse(&ctx, REINSTATE, &container, refused).await);
    }

    let actor = match author(&ctx) {
        Ok(user) => user,
        Err(refused) => return Err(state.audit.refuse(&ctx, REINSTATE, &container, refused).await),
    };

    let change = Mutation { actor, expected_revision: Some(expected), at: Utc::now() };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let subtree = match FileRepository::restore(&mut tx, ctx.tenant_id, file, &change).await {
        Ok(subtree) => subtree,
        Err(error) => match classify(error) {
            WriteFailure::Refused(envelope) => return Ok(envelope.into_response(request_id)),
            WriteFailure::Fatal(error) => return Err(ApiError::new(error, request_id)),
        },
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let root = match subtree.first() {
        Some(node) => node,
        // Unreachable, as in `trash`: an empty result is an `Err` in the repository.
        None => {
            return Err(ApiError::new(
                Error::Internal(anyhow::anyhow!("a restore returned no rows and no error")),
                request_id,
            ))
        }
    };

    Ok(tagged(
        root.revision,
        Json(LifecycleView {
            id: root.id.to_string(),
            revision: root.revision,
            affected: subtree.len(),
        })
        .into_response(),
    ))
}

// ---------------------------------------------------------------------------------------------
// What a `PATCH` asked for
// ---------------------------------------------------------------------------------------------

/// Where a move puts a node.
///
/// A type rather than an `Option<FileId>`, because `None` would have to mean both "no move was
/// asked for" and "move it to the library root", and those are the two states a `PATCH` body has to
/// keep apart. Which library the root belongs to is never taken from the request: it is read from
/// the node, so a body cannot relocate a file across libraries by naming a different one — a
/// crossing `crates/files` refuses in any case ([`FilesError::CrossLibraryMove`]) and that this
/// cannot even be expressed here is the stronger of the two guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    /// The library root, whichever library the node already belongs to.
    Root,
    /// A folder.
    Folder(FileId),
}

/// The two things a `PATCH` can ask for, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    /// The new name, if one was asked for.
    name: Option<String>,
    /// The new parent, if a move was asked for.
    destination: Option<Destination>,
}

/// Turns the decoded body into the change it describes, or `None` when it describes nothing.
///
/// # Errors
///
/// [`ApiError`] with [`Error::NotFound`] when `parentId` is a string that is not an id. That is
/// rule 7 and not politeness: `404` is also the answer for a destination in another tenant, and a
/// `400` on the unparseable one would tell a caller which of their guesses were well-formed.
fn requested_change(
    body: UpdateRequest,
    request_id: RequestId,
) -> Result<Option<Change>, ApiError> {
    let destination = match body.parent_id {
        None => None,
        Some(None) => Some(Destination::Root),
        Some(Some(raw)) => Some(Destination::Folder(
            raw.parse::<FileId>().map_err(|_| ApiError::new(Error::NotFound, request_id))?,
        )),
    };
    if body.name.is_none() && destination.is_none() {
        return Ok(None);
    }
    Ok(Some(Change { name: body.name, destination }))
}

/// The container a move — or a restore — lands in.
///
/// Deliberately identical in shape to `routes::folders::container_of` and
/// `routes::uploads::container_of`: the named folder when there is one, the library otherwise. See
/// the module documentation for why the three must not be allowed to drift.
const fn destination_of(
    tenant: TenantId,
    library: LibraryId,
    destination: Destination,
) -> ResourceRef {
    match destination {
        Destination::Folder(folder) => ResourceRef::folder(tenant, folder),
        Destination::Root => ResourceRef::library(tenant, library),
    }
}

/// The reference a node is decided against — folder or file, by its own kind.
///
/// The distinction is not enforcement-relevant (`classify` maps both onto `Target::FileTree`) and it
/// is kept anyway, because the reference travels into the audit row and into `capabilities_for`, and
/// a folder recorded as a file is a log a reader cannot trust. `content::readable_children` makes the
/// same choice.
fn reference(tenant: TenantId, node: &FileNode) -> ResourceRef {
    match node.node_type {
        NodeType::Folder => ResourceRef::folder(tenant, node.id),
        NodeType::File => ResourceRef::file(tenant, node.id),
    }
}

// ---------------------------------------------------------------------------------------------
// The precondition
// ---------------------------------------------------------------------------------------------

/// Why an `If-Match` could not be turned into a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precondition {
    /// No `If-Match` header at all.
    Missing,
    /// Present, and not a revision this build can read — including `*`.
    Malformed,
}

/// The revision the caller asserts they are editing.
///
/// **Never defaulted.** [`Mutation::expected_revision`] documents `None` as being for
/// server-initiated maintenance, and a handler that substituted one would turn every `PATCH` into a
/// last-writer-wins overwrite of whatever changed in between — silently, which is the failure mode
/// optimistic concurrency exists to remove.
///
/// `W/"12"`, `"12"` and `12` are all accepted. The quoted form is what `§4` shows and what a client
/// echoes back from the `ETag`; the weak validator is what some HTTP stacks add on their own; the
/// bare number is what a hand-written client sends first. Being liberal about the wrapping and
/// strict about the number is the trade that costs nothing — a value that is not an integer cannot
/// be a revision under any reading.
///
/// `*` is refused rather than treated as "whatever is there". It means *"if the resource exists"*,
/// which is a weaker precondition than the one this endpoint requires, and honouring it would be
/// this function inventing the default the paragraph above refuses to invent.
///
/// # Errors
///
/// [`Precondition::Missing`] when the header is absent, [`Precondition::Malformed`] when it is
/// present and unreadable. Two variants and not one, because the `details` entry a client is shown
/// differs — `REQUIRED` sends them to add a header, `INVALID_FORMAT` to look at the one they sent.
fn expected_revision(headers: &HeaderMap) -> Result<i64, Precondition> {
    let raw = headers.get(header::IF_MATCH).ok_or(Precondition::Missing)?;
    let raw = raw.to_str().map_err(|_| Precondition::Malformed)?.trim();
    let raw = raw.strip_prefix("W/").unwrap_or(raw);
    let unquoted = raw.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(raw);
    unquoted.parse::<i64>().map_err(|_| Precondition::Malformed)
}

/// The `ETag` a client must echo back on its next mutation.
///
/// `files.revision` is the counter (`docs/03-LLD.md §14`), and `routes::workspaces` and
/// `routes::libraries` already put the same number on the wire as a body field. It is here as a
/// header as well because `§4` writes the precondition as `If-Match: "{revision}"`, and a required
/// precondition a client cannot read off the response it just received is a precondition clients
/// guess at.
///
/// A revision is an `i64`, so the value is always a legal header; the fallback is to omit the header
/// rather than to send a wrong one, because a client that trusts a fabricated `ETag` would send a
/// precondition that can never match.
fn tagged(revision: i64, mut response: Response) -> Response {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{revision}\"")) {
        let _replaced = response.headers_mut().insert(header::ETAG, value);
    }
    response
}

// ---------------------------------------------------------------------------------------------
// The pieces the three handlers share
// ---------------------------------------------------------------------------------------------

/// Runs the policy chain and yields the obligations the caller now has to satisfy.
///
/// The one place `CLAUDE.md` rule 7's concealment is applied for this surface, so the three
/// endpoints cannot answer it three ways. `ACCESS_DENIED` becomes [`Error::NotFound`]; every other
/// reason code keeps its own status, for the reason `crate::content` sets out at length — those come
/// from stages that run either before authorization, and refuse identically for a nonexistent id, or
/// after it, by which point the caller already holds a grant.
///
/// # Errors
///
/// [`ApiError`] carrying the denial, concealed where rule 7 requires it.
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

/// Reads the node the chain has just allowed an action on.
///
/// Separate from the handler so that "the read happens after the decision" is visible as an ordering
/// rather than inferred from line numbers. Authorized-but-absent — deleted between the chain and the
/// read, or an id that never existed and was refused by no grant — is the same `404`.
///
/// # Errors
///
/// [`ApiError`]: `404` when the node is not visible to this transaction, and the mapped form of a
/// storage failure.
async fn read_node(
    state: &ApiState,
    ctx: &RequestContext,
    file: FileId,
) -> Result<FileNode, ApiError> {
    let request_id = ctx.request_id;
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;
    node.ok_or_else(|| ApiError::new(Error::NotFound, request_id))
}

/// Performs the rename, the move, or both, in one transaction.
///
/// # Why the rename goes first
///
/// Both orders can produce a collision the caller did not ask for, because a name has to be free in
/// whichever parent holds the node at the moment each statement runs. Rename-then-move needs the new
/// name free in the **source** as well as the destination; move-then-rename needs the *old* name free
/// in the **destination**. The first is the better failure: the source folder is one the caller is
/// looking at and can rename the other item in, while a collision with a name in a folder they may
/// not list is a `409` they cannot act on or even explain.
///
/// # Why the second statement does not use the caller's revision
///
/// The rename bumps `revision`, so passing the caller's `If-Match` to the move would fail every
/// combined request. The caller's value is the precondition for the operation as a whole; the second
/// statement is conditioned on the revision the first produced, inside the same transaction, so
/// there is no instant at which another writer could have intervened between them.
///
/// # Errors
///
/// [`WriteFailure::Refused`] for the four refusals `docs/05-API.md §5` gives a status
/// [`enclave_core::Error`] cannot express; [`WriteFailure::Fatal`] for everything else, already
/// mapped onto the type the API edge renders.
async fn apply(
    state: &ApiState,
    ctx: &RequestContext,
    file: FileId,
    change: &Change,
    library: LibraryId,
    expected: i64,
    actor: UserId,
) -> Result<FileNode, WriteFailure> {
    let now = Utc::now();
    let mut tx =
        state.db.begin(ctx.tenant_id).await.map_err(|error| WriteFailure::Fatal(error.into()))?;

    let mut revision = expected;
    let mut written: Option<FileNode> = None;

    if let Some(name) = change.name.as_deref() {
        let mutation = Mutation { actor, expected_revision: Some(revision), at: now };
        let node = FileRepository::rename(&mut tx, ctx.tenant_id, file, name, &mutation)
            .await
            .map_err(classify)?;
        revision = node.revision;
        written = Some(node);
    }

    if let Some(destination) = change.destination {
        let parent = match destination {
            Destination::Root => Parent::Library(library),
            Destination::Folder(folder) => Parent::Folder(folder),
        };
        let mutation = Mutation { actor, expected_revision: Some(revision), at: now };
        written = Some(
            FileRepository::reparent(&mut tx, ctx.tenant_id, file, parent, &mutation)
                .await
                .map_err(classify)?,
        );
    }

    let node = match written {
        Some(node) => node,
        // Unreachable: `requested_change` answers `None` when neither field was sent, and this is
        // only ever called with what it returned. An internal error rather than a panic.
        None => {
            return Err(WriteFailure::Fatal(Error::Internal(anyhow::anyhow!(
                "a change with neither a name nor a destination reached the write path"
            ))))
        }
    };

    tx.commit().await.map_err(|error| WriteFailure::Fatal(error.into()))?;
    Ok(node)
}

/// Refuses the whole delete because one node in the subtree denied it, and leaves an audit row.
///
/// The batch above is the *authorization stage*, asked directly — the same handle
/// `content::capabilities_for` uses — and a stage answers questions without writing audit rows; the
/// engine is what audits (`CLAUDE.md` rule 10). So the node that failed is put back through
/// [`enclave_core::PolicyEngine::enforce`], which decides it again through the whole chain and writes
/// the `DENY` the batch could not. That is one extra resolution on a path that is about to fail
/// anyway, and it buys a denial an auditor can find with `WHERE outcome = 'DENY'`.
///
/// The two can in principle disagree — the chain has stages the authorization batch does not — and
/// the disagreement is resolved towards refusing: a decision that has been taken is not allowed to
/// evaporate because a second, broader question answered differently. The obligations of that second
/// decision are consumed and discarded, which is sound only because the request is being refused;
/// nothing proceeds on the strength of them.
async fn refuse_subtree(
    state: &ApiState,
    ctx: &RequestContext,
    resource: &ResourceRef,
) -> ApiError {
    match state.policy.enforce(ctx, DISCARD, resource).await {
        // The engine refused and audited the refusal inside itself. The status is then **concealed
        // to `404`**, which is a change from this function's first draft and the reason is rule 7.
        //
        // The draft argued that a `403` is safe here because the caller can already read the folder
        // they addressed. That is true of the folder and not of the *child* that refused: a caller
        // holding `file.delete` on a folder could attempt a delete and learn from the `403` that it
        // contains something walled off from them — a node they may hold no `file.metadata_read`
        // on, which no listing would ever have shown them. "A `403` confirms existence" is exactly
        // what rule 7 is about, and the thing whose existence it confirms here is not the thing the
        // request named.
        //
        // The cost is a `404` on a path whose `GET` answers `200`, which reads oddly until you know
        // why. That is the same trade every rule-7 refusal makes, and the alternative was to ask a
        // second batch whether each denying node is readable — one more resolution, on a path that
        // is already failing, to decide how precisely to say no.
        Err(error) => ApiError::new(conceal(error), ctx.request_id),
        Ok(decision) => {
            let _obligations = consume(decision);
            tracing::warn!(
                %ctx.request_id,
                "the authorization stage denied a node the chain then allowed; refusing the delete"
            );
            ApiError::new(Error::NotFound, ctx.request_id)
        }
    }
}

/// Honours every obligation the chain attached, or turns it into a refusal.
///
/// Exhaustive on purpose, exactly as `routes::folders::satisfy` and `download`'s are:
/// [`Obligation`] is deliberately not `#[non_exhaustive]`, so a new obligation breaks this match and
/// forces somebody to decide what a lifecycle change does about it rather than inheriting a shrug.
///
/// **Every request this module serves is a mutation, so almost nothing here is satisfiable**
/// (`CLAUDE.md` rule 8, D29). A rename is a name; a move is a parent id; a trash is a timestamp.
/// There is no rendition a watermark could be burned into, no content a classification could
/// restrict, and no approval this synchronous path could route and wait for. The two that are
/// ignored are ignored because they restrict *content*, and none of these operations exposes any —
/// the same reading `routes::workspaces::apply_obligations` gives them, listed rather than swept
/// into a catch-all so the reasoning is visible.
///
/// # Errors
///
/// [`Refused`] carrying D29's standard code for the obligation that could not be discharged.
fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            // Neither is about a name or a parent id: there are no bytes to withhold here and no
            // replica to refuse. Ignoring them is not a dropped obligation — there is no exposure
            // for either to be about.
            Obligation::NoDownload | Obligation::NoSync => {}
            // "Suppress every mutation path" — and every request in this module is one.
            Obligation::ReadOnly => return Err(Refused::obligation(Obligation::ReadOnly)),
            Obligation::Watermark => return Err(Refused::obligation(Obligation::Watermark)),
            Obligation::RequireJustification => {
                return Err(Refused::obligation(Obligation::RequireJustification))
            }
            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }
            // There is no column here that could carry a new classification and no content to
            // reclassify. Refused rather than ignored: a stage that asked for a classification
            // change and got silence is a stage whose decision was dropped.
            Obligation::Reclassify { to } => {
                return Err(Refused::obligation(Obligation::Reclassify { to }))
            }
        }
    }
    Ok(())
}

/// The user a change is attributed to.
///
/// `files.modified_by` is a `NOT NULL` reference to a `users` row, and a guest, a service account
/// and an MCP client each answer `Some` to `Actor::subject_id` while being none of them — the same
/// argument `routes::folders::author` and `routes::permissions::author` make. A [`Refused`] rather
/// than an [`Error`] because the chain has already allowed by the time this is asked, so the refusal
/// needs an audit row of its own (`ENC-606`).
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`]. A link bearer least of all (`ENC-879`):
/// `Actor::subject_id` answers `Some` with a `share_links.id`, a real row in the wrong table
/// entirely, and a link that could rename or delete what it exposes would be a link acting beyond
/// what it was given.
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

// ---------------------------------------------------------------------------------------------
// Refusals `enclave_core::Error` cannot express
// ---------------------------------------------------------------------------------------------

/// What a failed write was.
///
/// Two cases rather than one [`Error`], because `Error::status_code` is derived from the variant and
/// there is no way through it to send a non-revision `409` or a `422` at all — which is the
/// [`Envelope`] type's own stated reason for existing, and `ENC-808`'s finding: the files crate's
/// blanket `From<FilesError>` maps a name collision and a circular move alike onto
/// `Error::Validation`, a `400`, where `§5` names `409` and `422`.
enum WriteFailure {
    /// A refusal with a status only the envelope can carry.
    Refused(Envelope),
    /// Anything else, already mapped onto the error type the API layer renders.
    Fatal(Error),
}

/// Maps the tree's own vocabulary onto `docs/05-API.md §5`'s statuses.
///
/// Written out variant by variant rather than delegating to `From<FilesError> for Error`, because
/// that conversion is correct for its four other call sites and wrong for this one: it renders a
/// name collision and a circular move as `400`, and `§5` gives the first to `409` ("name collision",
/// by name) and the second to `422` ("well-formed but semantically rejected (e.g. circular folder
/// move)", also by name). `routes::folders::create` set the precedent of intercepting rather than
/// changing a conversion four call sites depend on; `ENC-808` carries the wider fix.
///
/// **No refusal echoes a name.** A collision report is the one place a file the caller has not been
/// shown could be named to them (`CLAUDE.md` rule 10).
fn classify(error: FilesError) -> WriteFailure {
    match error {
        // `§5`: "Revision conflict, name collision, …".
        FilesError::NameTaken => WriteFailure::Refused(name_in_use()),

        // `§5`: "Well-formed but semantically rejected (e.g. circular folder move)". The example in
        // the document is this exact case.
        FilesError::CycleDetected => WriteFailure::Refused(unprocessable(
            "CIRCULAR_MOVE",
            "A folder cannot be moved inside itself.",
            "Choose a destination that is not this folder or one of the folders inside it.",
            ValidationCode::Inconsistent,
        )),
        FilesError::CrossLibraryMove => WriteFailure::Refused(unprocessable(
            "CROSS_LIBRARY_MOVE",
            "An item cannot be moved into a different library.",
            "Copy it into the other library instead, then delete the original.",
            ValidationCode::Unsupported,
        )),
        FilesError::ParentInTrash => WriteFailure::Refused(unprocessable(
            "PARENT_IN_TRASH",
            "The folder this item belongs to is still in the recycle bin.",
            "Restore the folder above it first, then restore this item.",
            ValidationCode::Inconsistent,
        )),
        // Also well-formed and also structurally refused. Not reachable through these four
        // repository functions today — the ancestor walk that raises it belongs to
        // `enclave_files::path` — and mapped anyway, so that a future move which does walk the
        // ancestry cannot arrive at a caller as a `500`.
        FilesError::PathTooDeep => WriteFailure::Refused(unprocessable(
            "PATH_TOO_DEEP",
            "This destination is too deep for the item to be moved into.",
            "Choose a destination closer to the library root.",
            ValidationCode::OutOfRange,
        )),

        // `Error::Conflict` renders `409 REVISION_CONFLICT` and carries the current revision, so a
        // client can re-read and retry without a round trip to discover it. This is the stale
        // `If-Match`, and the status is `§4`'s own: "Optimistic concurrency; `409` on mismatch".
        FilesError::Conflict { current_revision } => {
            WriteFailure::Fatal(Error::Conflict { current_revision })
        }

        // A node that is gone, in the trash, another tenant's, or a parent that is any of those —
        // one answer, per `CLAUDE.md` rule 7 and the files crate's own module note.
        FilesError::NotFound | FilesError::ParentNotFound => WriteFailure::Fatal(Error::NotFound),

        // Storage failures, unreadable rows, an invalid name, an unusable cursor: the blanket
        // conversion is right for all of them.
        other => WriteFailure::Fatal(other.into()),
    }
}

/// `409`, per `docs/05-API.md §5`'s status table: "name collision".
///
/// A copy of `routes::folders::name_in_use` rather than a shared helper, because that one is private
/// to its module and the duplication is four literals rather than a policy. The offending name is
/// not among them.
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

/// `422`, per `docs/05-API.md §5`: "well-formed but semantically rejected".
///
/// Every refusal built here names `parentId`, because every one of them is a statement about the
/// destination rather than about the syntax of the request — which is exactly the distinction `422`
/// carries and `400` does not.
fn unprocessable(
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
    validation: ValidationCode,
) -> Envelope {
    Envelope::new(StatusCode::UNPROCESSABLE_ENTITY, code, message, remediation).with_details(vec![
        serde_json::json!({
            "field": "parentId",
            "code": validation.as_str(),
        }),
    ])
}

/// `400` for a mutation that did not say which revision it expects.
///
/// **Not `428 Precondition Required`, and the deviation is deliberate.** `§5`'s status table is the
/// vocabulary this API answers in and it has no `428` row; the closest thing it says is `400`,
/// "malformed request or failed validation". A request that omits a header the endpoint requires is
/// a failed validation of the request. `§5` wins over the HTTP reflex, as it does for the mismatch
/// case, which `§4` fixes at `409` rather than `412`.
fn precondition(failure: Precondition) -> Envelope {
    let code = match failure {
        Precondition::Missing => ValidationCode::Required,
        Precondition::Malformed => ValidationCode::InvalidFormat,
    };
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "IF_MATCH_REQUIRED",
        "This request must state the revision it expects to be changing.",
        "Read the item, then send its revision back as `If-Match`.",
    )
    .with_details(vec![serde_json::json!({
        "field": "If-Match",
        "code": code.as_str(),
    })])
}

/// `400` for a `PATCH` that asks for nothing.
///
/// A no-op is refused rather than answered `200`, because a client that sent the wrong field name
/// would otherwise watch a request succeed and a name stay as it was. `deny_unknown_fields` catches
/// the misspelling; this catches the omission.
fn nothing_to_change() -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "The request did not ask for any change.",
        "Send a `name`, a `parentId`, or both.",
    )
    .with_details(vec![serde_json::json!({
        "field": "body",
        "code": ValidationCode::Required.as_str(),
    })])
}

/// `400` for a body that will not decode, inside `§5`'s envelope.
///
/// A copy of `routes::folders::unreadable_body`, for the reason given there.
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

    /// A rename and a move are two actions, and this surface never confuses them.
    ///
    /// `crates/authorization/src/repo.rs` matches `a.action = ANY($2::text[])` — string equality
    /// with no implication from one verb to another — so a move decided by `file.edit` would resolve
    /// against entries nobody wrote for it, and a caller granted only `file.edit` would be able to
    /// relocate content into a folder with a different inherited ACL. Asserted over the constants'
    /// rendered spelling, because that spelling is what `acl_entries.action` stores: a grant written
    /// any other way matches nothing and looks correct everywhere.
    #[test]
    fn a_rename_and_a_move_are_two_actions_and_stay_two() {
        assert_ne!(RENAME, REPARENT, "rule 6: an edit and a relocation are not one question");
        assert_eq!(RENAME.to_string(), "file.edit");
        assert_eq!(REPARENT.to_string(), "file.move");
        assert_eq!(ACCEPT.to_string(), "container.create");
        assert_eq!(DISCARD.to_string(), "file.delete");
        assert_eq!(REINSTATE.to_string(), "file.restore");

        // And the destination question is a *container* question, not a file one: a folder is
        // written into, not edited.
        assert_ne!(ACCEPT, REPARENT);
    }

    /// The destination a move asks about is the named folder, and the library only when none was
    /// named.
    ///
    /// The property that keeps this route and `POST /libraries/{id}/folders` from disagreeing about
    /// one folder: a caller who may create a folder inside it and may not move a file into it would
    /// be two answers to `container.create` on the same resource. Asserted over the output rather
    /// than by reading the source, so an edit that changed the resource *kind* — to the library in
    /// both arms, say — fails here.
    #[test]
    fn a_named_destination_is_the_container_and_the_library_is_the_fallback() {
        let tenant = TenantId::new_v7();
        let library = LibraryId::new_v7();
        let folder = FileId::new_v7();

        assert_eq!(
            destination_of(tenant, library, Destination::Folder(folder)),
            ResourceRef::folder(tenant, folder),
            "a named destination must be the container the chain decides against"
        );
        assert_eq!(
            destination_of(tenant, library, Destination::Root),
            ResourceRef::library(tenant, library),
            "with no destination folder the library root is the container"
        );
    }

    /// An absent `parentId`, a `null` one and a named one are three different requests.
    ///
    /// The distinction the wire type exists for. Collapsing the first two — which is what a plain
    /// `Option<String>` does — would make every rename a move to the library root, silently, and the
    /// only visible symptom would be documents leaving their folders.
    #[test]
    fn an_absent_parent_a_null_parent_and_a_named_parent_are_three_requests() {
        let request_id = RequestId::new_v7();
        let folder = FileId::new_v7();

        let rename: UpdateRequest =
            serde_json::from_value(serde_json::json!({ "name": "Q3 Report" })).expect("decode");
        assert_eq!(
            requested_change(rename, request_id).expect("a rename is well formed"),
            Some(Change { name: Some("Q3 Report".to_owned()), destination: None }),
            "an absent parentId must not be read as a move"
        );

        let to_root: UpdateRequest =
            serde_json::from_value(serde_json::json!({ "parentId": null })).expect("decode");
        assert_eq!(
            requested_change(to_root, request_id).expect("a move to the root is well formed"),
            Some(Change { name: None, destination: Some(Destination::Root) }),
            "an explicit null is a move to the library root"
        );

        let into_folder: UpdateRequest =
            serde_json::from_value(serde_json::json!({ "parentId": folder.to_string() }))
                .expect("decode");
        assert_eq!(
            requested_change(into_folder, request_id).expect("a move is well formed"),
            Some(Change { name: None, destination: Some(Destination::Folder(folder)) })
        );

        // The two refusals. An empty body asks for nothing, and a `parentId` that is not an id
        // names no resource — `404`, never `400`, so that a garbage id and another tenant's id
        // cannot be told apart (rule 7).
        let empty: UpdateRequest = serde_json::from_value(serde_json::json!({})).expect("decode");
        assert_eq!(
            requested_change(empty, request_id).expect("an empty body is not an error here"),
            None,
            "a PATCH that asks for nothing must be refused rather than answered 200"
        );

        let garbage: UpdateRequest =
            serde_json::from_value(serde_json::json!({ "parentId": "not-a-uuid" }))
                .expect("decode");
        let refused = requested_change(garbage, request_id).expect_err("an unparseable id");
        assert!(matches!(refused.error(), Error::NotFound), "rule 7: never a 400");

        // And a field this build does not know is a visible refusal rather than a silent drop —
        // which is what makes `contentTypeId` a `400` instead of a change the caller thinks
        // happened. See the module note.
        let unknown = serde_json::from_value::<UpdateRequest>(
            serde_json::json!({ "name": "x", "contentTypeId": "01937fa0-0000-7000-8000-000000000000" }),
        );
        assert!(unknown.is_err(), "an unknown field must not decode");
    }

    /// The precondition is read, never defaulted, and every wrapping a client sends is accepted.
    ///
    /// The negative half is the point: without it, "a quoted revision parses" passes against a
    /// function that answers `Some(0)` for anything, which would turn every mutation into an
    /// unconditional overwrite — the failure `Mutation::expected_revision` documents in as many
    /// words.
    #[test]
    fn an_if_match_is_required_and_never_defaulted() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            let _previous =
                headers.insert(header::IF_MATCH, HeaderValue::from_str(value).expect("a header"));
            expected_revision(&headers)
        };

        assert_eq!(with("\"12\""), Ok(12), "the quoted form is what §4 shows");
        assert_eq!(with("W/\"12\""), Ok(12), "a weak validator names the same revision");
        assert_eq!(with("12"), Ok(12), "the bare form is what a hand-written client sends");
        assert_eq!(with(" \"12\" "), Ok(12), "surrounding space is not a different revision");

        assert_eq!(with("*"), Err(Precondition::Malformed), "`*` is a weaker precondition");
        assert_eq!(with("\"\""), Err(Precondition::Malformed));
        assert_eq!(with("twelve"), Err(Precondition::Malformed));
        assert_eq!(
            expected_revision(&HeaderMap::new()),
            Err(Precondition::Missing),
            "an absent header must never be defaulted into a revision"
        );
    }

    /// A missing precondition is `400` and says which of the two problems it was.
    ///
    /// The status is the assertion that matters, and it is the one place this module knowingly
    /// departs from an HTTP reflex: `428` is not in `§5`'s table and `§5` is what this API answers
    /// in. The `details` code is asserted because it is the only thing separating "you sent none"
    /// from "the one you sent is unreadable", and the two send a client to different places.
    #[test]
    fn a_missing_precondition_is_a_validation_failure_and_names_the_header() {
        let missing = precondition(Precondition::Missing);
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        assert_eq!(missing.code(), "IF_MATCH_REQUIRED");
        let rendered = serde_json::to_string(missing.details()).expect("render");
        assert!(rendered.contains("If-Match"), "the header must be named: {rendered}");
        assert!(rendered.contains("REQUIRED"), "{rendered}");

        let malformed = precondition(Precondition::Malformed);
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        let rendered = serde_json::to_string(malformed.details()).expect("render");
        assert!(rendered.contains("INVALID_FORMAT"), "{rendered}");
    }

    /// The tree's refusals arrive at the caller with `§5`'s statuses, not the blanket conversion's.
    ///
    /// This is `ENC-808`'s finding applied to four more variants. `From<FilesError> for Error` maps
    /// every one of these onto `Error::Validation` — a `400` — and `§5` names `409` for a collision
    /// and `422` for a circular move outright. Without the interception, a client cannot tell a
    /// malformed request from a destination the tree refuses.
    ///
    /// The positive control is on the same line: a stale revision must **not** be intercepted, since
    /// `Error::Conflict` already renders `§4`'s `409` and carries the current revision with it.
    #[test]
    fn a_structural_refusal_is_422_and_a_collision_is_409() {
        let collision = classify(FilesError::NameTaken);
        match collision {
            WriteFailure::Refused(envelope) => {
                assert_eq!(envelope.status(), StatusCode::CONFLICT);
                assert_eq!(envelope.code(), "NAME_IN_USE");
                let rendered = serde_json::to_string(envelope.details()).expect("render");
                assert!(rendered.contains("NOT_UNIQUE"), "{rendered}");
            }
            WriteFailure::Fatal(error) => panic!("a collision must not be a {error:?}"),
        }

        for (error, code) in [
            (FilesError::CycleDetected, "CIRCULAR_MOVE"),
            (FilesError::CrossLibraryMove, "CROSS_LIBRARY_MOVE"),
            (FilesError::ParentInTrash, "PARENT_IN_TRASH"),
            (FilesError::PathTooDeep, "PATH_TOO_DEEP"),
        ] {
            match classify(error) {
                WriteFailure::Refused(envelope) => {
                    assert_eq!(
                        envelope.status(),
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "§5 gives a well-formed but semantically rejected move a 422: {code}"
                    );
                    assert_eq!(envelope.code(), code);
                    let rendered = serde_json::to_string(envelope.details()).expect("render");
                    assert!(rendered.contains("parentId"), "{rendered}");
                }
                WriteFailure::Fatal(error) => panic!("{code} must not be a {error:?}"),
            }
        }

        // The two that keep the statuses `enclave_core::Error` already gives them.
        match classify(FilesError::Conflict { current_revision: 7 }) {
            WriteFailure::Fatal(Error::Conflict { current_revision }) => {
                assert_eq!(current_revision, 7, "a client must be told what to retry with");
            }
            _ => panic!("a stale revision is §4's 409 and needs no envelope"),
        }
        for absent in [FilesError::NotFound, FilesError::ParentNotFound] {
            match classify(absent) {
                WriteFailure::Fatal(Error::NotFound) => {}
                _ => panic!("rule 7: absent, trashed and another tenant's are one answer"),
            }
        }
    }

    /// No refusal this module renders can carry a file name.
    ///
    /// A collision report is the one place a file the caller has not been shown could be named to
    /// them (`CLAUDE.md` rule 10). The envelope's prose fields are `&'static str`, so the compiler
    /// holds the rule for three of the four fields; `details` is the one that could carry a value,
    /// and this asserts that it does not.
    #[test]
    fn no_refusal_echoes_a_name_or_an_id() {
        let envelopes = [
            name_in_use(),
            unprocessable("CIRCULAR_MOVE", "m", "r", ValidationCode::Inconsistent),
            precondition(Precondition::Missing),
            nothing_to_change(),
            unreadable_body(),
        ];
        for envelope in &envelopes {
            let rendered = serde_json::to_string(envelope.details()).expect("render");
            assert!(
                !rendered.contains("Q3") && !rendered.contains('/'),
                "a refusal must carry a field and a code and nothing else: {rendered}"
            );
        }
    }

    /// Every obligation a stage can attach is either refused or argued.
    ///
    /// The positive control is the empty set: a `satisfy` that simply refused everything would pass
    /// every "this is refused" assertion below while making all three endpoints unusable, and only
    /// the empty case can tell the two apart.
    #[test]
    fn an_obligation_this_path_cannot_discharge_refuses_the_change() {
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

        // The two that restrict content, which a name and a parent id are not.
        for obligation in [Obligation::NoDownload, Obligation::NoSync] {
            let set: Obligations = [obligation].into_iter().collect();
            assert!(
                satisfy(&set).is_ok(),
                "{obligation:?} restricts content, and a rename exposes none"
            );
        }
    }

    /// Only a directory user may be recorded as having changed a file.
    ///
    /// `files.modified_by` is a `NOT NULL` reference to `users`, and four of the five other actors
    /// answer `Some` to `Actor::subject_id` while naming a row in another table entirely. The
    /// positive control is the user, without which this passes against an `author` that refuses
    /// everybody and makes all three endpoints unusable.
    #[test]
    fn only_a_user_can_be_recorded_as_having_made_a_change() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();

        let ctx = RequestContext { actor: Actor::User(user), ..RequestContext::system(tenant) };
        assert_eq!(author(&ctx).expect("a user answers for their own changes"), user);

        for actor in [
            Actor::Guest(enclave_core::GuestId::new_v7()),
            Actor::ServiceAccount(enclave_core::ServiceAccountId::new_v7()),
            Actor::LinkBearer(enclave_core::ShareLinkId::new_v7()),
            Actor::System,
        ] {
            let ctx = RequestContext { actor, ..RequestContext::system(tenant) };
            let refused = author(&ctx).expect_err("only a directory user may be stamped");
            assert_eq!(refused.code(), ReasonCode::AccessDenied);
        }
    }

    /// The `ETag` a response carries is the revision the next `If-Match` must send back.
    ///
    /// Asserted as a round trip rather than as a string, because the property that matters is that
    /// the two functions agree: a header this module emits and cannot itself read would make every
    /// second mutation in a client's sequence fail.
    #[test]
    fn the_etag_a_response_carries_is_the_precondition_the_next_request_sends() {
        let response = tagged(12, StatusCode::OK.into_response());
        let tag = response.headers().get(header::ETAG).expect("an ETag").clone();
        assert_eq!(tag.to_str().expect("ascii"), "\"12\"");

        let mut headers = HeaderMap::new();
        let _previous = headers.insert(header::IF_MATCH, tag);
        assert_eq!(expected_revision(&headers), Ok(12), "the round trip must close");
    }
}
