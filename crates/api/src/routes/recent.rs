//! `GET /api/v1/me/recent` — the documents this caller was last working in, and the reads that
//! feed it.
//!
//! Two halves that only make sense together. [`recent`] is the read: eight rows, each one confirmed
//! against the policy chain before it is rendered. [`record`] is the write, called from the three
//! handlers that serve a file to a person, and it is the reason the read has anything to return.
//!
//! `web/design-system/specs/home.md` §C is the surface: a *Continue working* list, unvirtualized,
//! eight rows, each linking to the containing folder with `?peek={fileId}`. It is the first thing a
//! session renders, which shapes almost every decision below.
//!
//! # The read model is not authorized, and this module is where that is fixed
//!
//! [`enclave_db::recent`] says it at length and it bears repeating at the consuming end:
//! `recent_files` records that a person opened a file *at some point*. Between that instant and
//! this request the file can have moved under a folder the caller cannot reach, an `acl_entries`
//! row can have been revoked, a barrier can have been declared, a classification can have been
//! raised past what this device may see. Every one of those turns a stored row into a row that must
//! not be shown, and none of them is visible from the table.
//!
//! So every candidate is put to the authorization stage — one
//! [`AuthorizationService::authorize_many`] for the whole window, never a call per row — and a
//! candidate that is refused is **dropped and counted**, never turned into a `403` or a `404` for
//! the whole page. `CLAUDE.md` rule 7 is why: a per-row status would confirm that a particular file
//! exists and that this caller once opened it. The count says how many they cannot see; nothing in
//! the response says which.
//!
//! # `filteredCount` is a floor, and it is exact where a client reads it
//!
//! [`enclave_db::recent::recent`] over-fetches ([`enclave_db::recent::OVER_FETCH`] candidates per
//! rendered row) and reports [`RecentCandidates::more_beyond_window`] when it stopped short of the
//! end of the user's history. The wire contract has no field for that flag, and this handler does
//! not widen and re-ask when it is set. Both are deliberate:
//!
//! * The count `docs/09-UX-WHITE-LABELING.md §11` needs is the one that separates *"you have no
//!   recent files"* from *"some were withheld"*, and that distinction is only ever read when the
//!   list came back short. A short list after filtering means the window was consumed and did not
//!   fill the page — so `filteredCount` is non-zero exactly when something was withheld, which is
//!   the whole of what the two empty states turn on. When the page is full the number may
//!   under-report and no state depends on it.
//! * Widening costs a second index scan and a second resolution over up to
//!   [`enclave_db::recent::MAX_CANDIDATES`] rows, on the first request of a session, in order to
//!   backfill a *continue working* list out of documents from further back. That is not the
//!   feature, and the home screen's budget (`docs/03-LLD.md §23`) is not the place to spend it.
//!
//! # The cap is eight, and eight is also the default
//!
//! `home.md` fixes the list at eight rows and says the API hard-caps there; `enclave_db::recent`
//! was written against that number. Two things follow and both are load-bearing. The window this
//! reads is bounded at `8 × OVER_FETCH = 32` rows, which is a trivial index range scan. And the
//! `capabilities` object costs **one resolution per rendered row** — see [`item`] — so a cap that
//! rose would multiply the one cost here that is not batched. `limit` below eight is honoured,
//! because a caller rendering four rows should not pay for eight.
//!
//! # Connection discipline
//!
//! The recency read and the ACL batch never overlap. `crates/api/src/content.rs` states the rule —
//! each `authorize_many` takes its **own** connection from the same pool, so a handler holding a
//! transaction across one needs two per request, and on the default pool of sixteen with a
//! five-second acquire timeout that is a deadlock waiting for load. `routes::lifecycle::discard` is
//! the worked example: read in a short transaction, close it, then decide. This does the same.
//!
//! # The writes: a recency row may never fail the read it records
//!
//! A *Recent* list missing a row is cosmetic. A file that will not open because its recency row
//! could not be written is an outage, and it is the kind of outage that arrives all at once — a
//! lock, a statement timeout, a disk — on the one path every user takes. So [`record`] is
//! deliberately not part of the read it follows:
//!
//! * **It is a transaction of its own, opened after the read's has committed.** PostgreSQL aborts
//!   the *whole* transaction on any statement error, so an upsert sharing the read's transaction
//!   would turn a failed recency write into a failed `GET /files/{id}`. There is no way to write it
//!   in that transaction and keep this property; the separate transaction is the property.
//! * **It returns nothing.** There is no error for a caller to receive and none for a handler to
//!   forget to ignore. A failure is logged and the request proceeds.
//!
//! What that costs is one extra connection acquisition per served read. It is sequential — the
//! handler holds no other connection at that point — so it is latency, not contention.
//!
//! # What is recorded, and what deliberately is not
//!
//! Recorded on `GET /files/{id}` for a **file**, on a preview that produced a rendition, and on a
//! download that produced a URL. That is "you opened it", from the three doors it can be opened
//! through.
//!
//! Not on browse. Listing a folder is not opening its contents, and recording it would make
//! *Continue working* a list of the folders you walked past on the way to the one document you
//! actually read. Not on `GET /files/{id}` for a folder either, for the same reason and one more:
//! `enclave_db::recent`'s read excludes `node_type = 'FOLDER'`, so such a row is a write nothing can
//! ever read.
//!
//! **Not on a read the chain refused**, and this is the one that is a security decision rather than
//! a product one. Recording a refused read would put a row in the table for a file the caller may
//! not see; the chain would drop it here, and it would land in `filteredCount`. That turns a
//! counter into an enumeration oracle: guess ids, collect `404`s, then read back how many of the
//! guesses named a real file in this tenant. It is `CLAUDE.md` rule 7 defeated through the back
//! door, so the write sits after the decision and after every obligation has been discharged, on
//! the success path only.
//!
//! # What the wire deliberately omits
//!
//! `capabilityReasons` and the `obligations` object that `GET /files/{id}` carries. The contract's
//! row has nine fields and a *Recent* row is a **link**, not an action surface — `home.md` §C gives
//! it exactly one interaction, navigate-and-peek. The client that needs to know a download will
//! demand a justification learns it from the file response it fetches on arrival, which is the same
//! decision taken one navigation later. The `capabilities` object is still here because a row whose
//! `preview` is `false` must not be drawn as a peek link, and re-deriving that client-side is the
//! one thing `CLAUDE.md` forbids outright.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, AuthorizationService, ContainerAction, Error, FieldError, FileAction, FileId,
    Obligations, PolicyDecision, ReasonCode, RequestContext, RequestId, ResourceRef, UserId,
    ValidationCode,
};
use enclave_db::recent::{RecentCandidate, RecentCandidates};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::content::{capabilities_for, Capabilities};
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The question this endpoint asks about the caller themselves.
///
/// The same action `GET /api/v1/me` asks on the same resource, so a caller who can read their own
/// record can read their own recency and the two cannot come to disagree.
/// `enclave_authorization::SelfServiceOr` is what answers it; nothing in `acl_entries` names a
/// user's own row.
const READ_SELF: Action = Action::Container(ContainerAction::Read);

/// The question asked of every candidate, and the one a dropped row was dropped by.
///
/// `file.metadata_read` and not a container action: what this endpoint discloses per row is a name,
/// a MIME type and a classification chip, which is exactly the disclosure
/// `crate::content::readable_children` trims a listing by. Asking anything else would let a row
/// appear here that the folder listing it links into would hide.
const METADATA_READ: Action = Action::File(FileAction::MetadataRead);

/// Rows returned when the caller names no `limit`.
///
/// Eight, because `web/design-system/specs/home.md` §C renders eight and says the API caps there.
pub const DEFAULT_LIMIT: u32 = 8;

/// The most rows one request can render.
///
/// Equal to [`DEFAULT_LIMIT`] on purpose — the module header argues it. The number is not
/// arbitrary in either direction: `enclave_db::recent` reads `OVER_FETCH` candidates per row, so
/// this bounds the range scan, and [`item`] costs one ACL resolution per *rendered* row, so this
/// bounds the only cost in the handler that is not batched.
pub const MAX_LIMIT: u32 = 8;

/// The fewest rows a request can ask for.
///
/// One rather than zero. A `limit=0` would answer with an empty list and `filteredCount: 0` — byte
/// for byte the response a user with no recency at all receives — and `docs/09 §11` requires those
/// two states to be distinguishable. A request that cannot be answered honestly is clamped to the
/// smallest one that can be.
const MIN_LIMIT: u32 = 1;

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// `?limit=` and nothing else.
///
/// A `String` rather than a `u32` so that an unparseable value reaches [`limit`] and becomes
/// `docs/05-API.md §5`'s validation envelope, instead of axum's own rejection — which would answer
/// a different shape from every other listing in the surface. `crate::content::BrowseParams` takes
/// it the same way for the same reason.
#[derive(Debug, Deserialize)]
pub struct RecentParams {
    limit: Option<String>,
}

/// The body of `GET /api/v1/me/recent`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentPage {
    /// The rows this caller may see, most recently opened first.
    items: Vec<RecentItem>,
    /// How many candidates the policy chain dropped.
    ///
    /// The distinction `docs/09 §11` renders two different empty states for. See the module header
    /// for why this is a floor and why the floor is exact wherever a client reads it.
    filtered_count: usize,
}

/// One row of *Continue working*.
///
/// `fileId`, `libraryId` and `parentFolderId` are the three coordinates `home.md` §C composes the
/// row's link out of — `/w/:wid/l/:libraryId/f/:folderId?peek=:fileId`. `parentFolderId` is `null`
/// for a file at the library root, which the client renders by linking to the library itself.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecentItem {
    file_id: String,
    name: String,
    /// The name after its last dot, or `null` when it has none.
    ///
    /// Derived here rather than in SQL, and that is [`enclave_db::recent`]'s own decision: it is
    /// presentation — the client renders it in a dimmer span inside the file name — and the day
    /// `tar.gz` needs to render as one unit, the rule has to change in one place rather than in a
    /// query and a component.
    extension: Option<String>,
    mime_type: String,
    /// The label on the file's own row, or `null`.
    ///
    /// Not the inherited chain maximum. `enclave_db::recent` argues that at length; the short form
    /// is that resolving it would be a second walk that could drift from the one that enforces, and
    /// that a missing chip is a display gap rather than an access one — the chain still refuses
    /// what the inherited label forbids, and such a row is dropped above rather than shown.
    classification: Option<ClassificationView>,
    last_accessed_at: DateTime<Utc>,
    library_id: String,
    parent_folder_id: Option<String>,
    /// What this caller may do with this file, from the stage that will enforce it.
    ///
    /// Built by `crate::content::capabilities_for`, which is also what `GET /files/{id}` and every
    /// row of a folder listing is built by. `ENC-929` is what a second copy of this object costs: a
    /// UI that changes its mind about what a user may do depending on which screen it read the file
    /// from.
    capabilities: Capabilities,
}

/// A classification as the chip renders it.
///
/// All three fields, because the client needs all three at once and has no second request to make:
/// `key` selects the locked colour token (`.cls--{key}`), `label` is what a person reads, and
/// `rank` is what anything comparing sensitivity uses. `rank` is the raw ordinal rather than
/// [`enclave_core::ClassificationRank`]'s own `Serialize`, so that the wire type states its shape
/// where a reader of this file can see it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassificationView {
    key: String,
    label: String,
    rank: i32,
}

// ---------------------------------------------------------------------------------------------
// The read
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/me/recent`.
///
/// # The order of the five steps
///
/// 1. **The chain decides**, on the caller's own user record, before `limit` is looked at and
///    before any row is read. A caller the chain refuses learns nothing about the request schema —
///    `routes::permissions::replace_acl` orders it the same way.
/// 2. **The window is read in a short transaction**, which is committed before anything else runs.
/// 3. **Every candidate is put to the authorization stage in one batch**, and a refusal drops the
///    row rather than the request.
/// 4. **The survivors are truncated to `limit`**, and only then do they cost a capability
///    resolution each.
/// 5. **`filteredCount` is candidates presented minus candidates that survived**, not minus
///    candidates rendered: a row left out because the page was full was not filtered by anything.
///
/// # Errors
///
/// [`ApiError`]: `400` for a `limit` that is not a number; the denial's own status when the chain
/// refuses the self-read; `403` with the obligation's own code when that decision carried an
/// obligation this path cannot discharge; a storage failure's mapped form.
pub async fn recent(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<RecentParams>,
) -> Result<Json<RecentPage>, ApiError> {
    let request_id = ctx.request_id;

    // A principal with no `users` row has no recency and could not have written one — the composite
    // foreign key in `migrations/0029_recent_files.sql` refuses it. Refused before the chain runs,
    // so the row this writes stands alone and asserts nothing about a policy decision that was
    // never taken. `me::subject` makes the same call for the same reason.
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

    // No stage attaches an obligation to reading your own recency today, and this path could
    // satisfy none if one arrived: there is no rendition to watermark, no bytes to withhold and
    // nowhere to collect a justification. An unsatisfiable obligation is a refusal, never a shrug
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
    let window: RecentCandidates = enclave_db::recent::recent(&mut tx, user, limit)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    // Committed before the batch below, deliberately. See the module header's connection note.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let (survivors, filtered_count) =
        admit(state.policy.authorization().as_ref(), &ctx, &window.candidates, limit)
            .await
            .map_err(|error| ApiError::new(error, request_id))?;

    let mut items = Vec::with_capacity(survivors.len());
    for (candidate, resource, enforced) in survivors {
        items.push(
            item(state.policy.authorization().as_ref(), &ctx, candidate, &resource, &enforced)
                .await
                .map_err(|error| ApiError::new(error, request_id))?,
        );
    }

    Ok(Json(RecentPage { items, filtered_count }))
}

/// One candidate that survived the chain: the row, the reference it was decided as, and the
/// obligations of the decision that admitted it.
///
/// Carried as a triple rather than three parallel vectors for `capabilities_for_many`'s reason: a
/// resource and the obligations of the decision that admitted *it* must not be zippable out of step
/// by a later edit.
type Admitted<'a> = (&'a RecentCandidate, ResourceRef, Obligations);

/// Puts the whole window to the authorization stage and keeps the rows it allowed.
///
/// Returns the survivors, truncated to `limit`, and the number of candidates the stage dropped.
/// **The count is over the whole window, not over what is returned**: a candidate left behind
/// because the page was already full was not filtered by policy, and counting it would tell a user
/// that documents were withheld from them when none were.
///
/// One [`AuthorizationService::authorize_many`] for the window — never a call per row, which is
/// what the batch form exists on the trait to prevent, and what would turn the home screen's first
/// request into thirty-two resolutions.
///
/// A resolution that *fails* refuses the request rather than returning an untrimmed page:
/// `crates/core/src/engine.rs` is explicit that a failed resolution is not a denial, and a recency
/// list that could not be trimmed is precisely the enumeration surface this module exists to
/// prevent.
///
/// # Errors
///
/// Resolution failures, mapped onto the vocabulary the API edge speaks.
async fn admit<'a>(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    candidates: &'a [RecentCandidate],
    limit: u32,
) -> Result<(Vec<Admitted<'a>>, usize), Error> {
    if candidates.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let refs: Vec<ResourceRef> = candidates
        .iter()
        .map(|candidate| ResourceRef::file(ctx.tenant_id, candidate.file_id))
        .collect();
    let decisions = authorization.authorize_many(ctx, METADATA_READ, &refs).await?;

    // Index-aligned with `refs` by contract. A shorter answer leaves the tail undecided, and `zip`
    // drops it — which counts those rows as filtered and shows fewer of them. That is the direction
    // an absent verdict has to fail in here: over-reporting how much was withheld costs a user a
    // sentence, and under-reporting it shows them a file nobody decided about.
    let mut survivors: Vec<Admitted<'a>> = Vec::new();
    let mut survived = 0_usize;
    for ((candidate, resource), decision) in candidates.iter().zip(refs).zip(decisions) {
        if !decision.is_allowed() {
            continue;
        }
        // The stage allowed, so this cannot be an `Err`. Taking the obligations rather than
        // dropping the decision is what keeps a `READ_ONLY` attached to this row's metadata read
        // from evaporating between the trim and the capabilities built from it.
        let enforced = decision.ensure_allowed()?;
        survived += 1;
        if survivors.len() < limit as usize {
            survivors.push((candidate, resource, enforced));
        }
    }

    Ok((survivors, candidates.len() - survived))
}

/// Renders one surviving candidate, capabilities included.
///
/// # One resolution per row, and why that is the shape here
///
/// `crate::content::capabilities_for` is a one-element call to `capabilities_for_many`, so a page
/// of eight costs eight resolutions rather than one. That is the cost `ENC-167` measured and
/// deliberately removed from the listing path, and it is accepted here for two reasons: the cap is
/// eight, which puts the total inside the home screen's budget, and the batch form is private to
/// `crate::content`, which is not a module this item may widen. If [`MAX_LIMIT`] is ever raised,
/// exporting `capabilities_for_many` and calling it once is the change — not a second
/// implementation of the object.
///
/// The obligations passed in are the ones from the decision that *admitted this row*, exactly as
/// `readable_children` passes the trim's. They only ever subtract, so a row here can never offer an
/// action the file endpoint suppresses.
///
/// # Errors
///
/// Resolution failures.
async fn item(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    candidate: &RecentCandidate,
    resource: &ResourceRef,
    enforced: &Obligations,
) -> Result<RecentItem, Error> {
    // The reasons and the obligation object are discarded rather than rendered: the contract's row
    // has no field for either, and the module header says why a *Recent* row does not need them.
    let (capabilities, _reasons, _wire) =
        capabilities_for(authorization, ctx, resource, enforced).await?;

    Ok(RecentItem {
        file_id: candidate.file_id.to_string(),
        extension: extension(&candidate.name),
        name: candidate.name.clone(),
        mime_type: candidate.mime_type.clone(),
        classification: candidate.classification.as_ref().map(|label| ClassificationView {
            key: label.key.clone(),
            label: label.label.clone(),
            rank: label.rank.get(),
        }),
        last_accessed_at: candidate.last_accessed_at,
        library_id: candidate.library_id.to_string(),
        parent_folder_id: candidate.parent_folder_id.map(|id| id.to_string()),
        capabilities,
    })
}

// ---------------------------------------------------------------------------------------------
// The write
// ---------------------------------------------------------------------------------------------

/// Records that this caller opened this file, and cannot fail the request that did.
///
/// Called from `crate::content::file_metadata`, `crate::preview::preview` and
/// `crate::download::download`, at the point each of them has *succeeded* — after the chain
/// allowed, after every obligation was discharged, and after the transaction that read the file has
/// committed.
///
/// # Why it returns nothing
///
/// Because there is no answer a caller could use and no failure a handler should propagate. The
/// module header has the argument in full; the short form is that a *Recent* list missing a row is
/// cosmetic and a file that will not open is an outage, so the only correct thing to do with an
/// error here is to log it and serve the read. Returning a `Result` would put that judgement at
/// three call sites instead of one, and one of them would eventually get it wrong with a `?`.
///
/// # Its own transaction, and not the caller's
///
/// PostgreSQL aborts an entire transaction on any statement error, so an upsert sharing the read's
/// transaction turns a lock timeout on `recent_files` into a failed `GET /files/{id}`. There is no
/// way to write it there and keep the property in this function's first line. It is
/// [`enclave_db::recent::record`] rather than `record_on`, so the tenant comes from the scoped
/// transaction and this cannot be asked to write into another one (`CLAUDE.md` rule 3).
///
/// # Only a directory user
///
/// `recent_files` has a composite foreign key into `users`, and a guest, a service account, an MCP
/// client and a link bearer each answer `Some` to `Actor::subject_id` while naming a row in a
/// different table entirely (`ENC-879`). Skipped rather than refused: they are reading legitimately
/// and there is simply nowhere to record it. `System` has no subject at all.
pub(crate) async fn record(state: &ApiState, ctx: &RequestContext, file: FileId) {
    let Actor::User(user) = ctx.actor else {
        return;
    };

    let mut tx = match state.db.begin(ctx.tenant_id).await {
        Ok(tx) => tx,
        Err(error) => return unrecorded(&error, file),
    };
    if let Err(error) = enclave_db::recent::record(&mut tx, user, file).await {
        // Dropped, which rolls back. Nothing else is in this transaction, so there is nothing to
        // preserve and nothing partial to observe.
        return unrecorded(&error, file);
    }
    if let Err(error) = tx.commit().await {
        unrecorded(&error, file);
    }
}

/// Notes a recency write that did not happen.
///
/// `warn` rather than `error`, because the request it belongs to succeeded: this is a degraded
/// feature, not a failed one, and an `error` here would page somebody for a missing list row.
///
/// The file's id travels and its **name does not** (`CLAUDE.md` rule 10) — a document title is a
/// fact about a tenant's content, and a log line is the cheapest place to leak one. The id is the
/// same value `audit_events` already carries for the read that produced it, so an operator can
/// still join the two.
fn unrecorded(error: &enclave_db::DbError, file: FileId) {
    tracing::warn!(
        file_id = %file,
        error = %error,
        "recency not recorded; the read it followed succeeded"
    );
}

// ---------------------------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------------------------

/// The user a recency list can be about.
///
/// A function returning [`Refused`] rather than an inline `ok_or_else`, so that
/// `cargo run -p xtask -- audit-coverage` can classify the refusal by this signature — the same
/// rule that makes `me::subject` and `routes::permissions::author` functions.
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`]. See [`record`] for why none of the
/// others can have a row in `recent_files` to read.
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
/// A named function rather than an inline call for `crate::content::consume`'s reason: "the
/// decision was looked at" should be a call a reader can find, and the `#[must_use]` on
/// [`PolicyDecision`] is then discharged in exactly one place in this module.
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

/// Parses and clamps `?limit=`.
///
/// Clamped rather than rejected above the cap, which is `crate::content::page_size`'s rule and
/// `crates/db/src/cursor.rs`'s before it: a client asking for a hundred rows wants as many as it
/// can have, and refusing the request teaches it nothing it could not have been told by the answer.
/// Only an unparseable value is a client error, because that one is a bug rather than an appetite.
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

/// A file name's extension — everything after its last dot.
///
/// `None` when there is nothing to show rather than an empty string, so a client renders the dimmed
/// span or does not, with no third case to handle. Three names have no extension by this rule and
/// all three are deliberate: `README` has no dot, `.env` is a dotfile whose whole name is the
/// "extension" and must render as one, and `report.` ends in a dot with nothing after it.
///
/// `archive.tar.gz` yields `gz`. That is today's rule, stated so the day it changes there is one
/// function to change — which is the whole reason `enclave_db::recent` declines to derive this in
/// SQL.
fn extension(name: &str) -> Option<String> {
    let (stem, extension) = name.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }
    Some(extension.to_owned())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{GuestId, McpClientId, ServiceAccountId, ShareLinkId, TenantId};

    use super::*;

    fn context(tenant: TenantId, actor: Actor) -> RequestContext {
        RequestContext { actor, ..RequestContext::system(tenant) }
    }

    /// `limit` is honoured below the cap, clamped above it, floored at one, and only a value that
    /// is not a number is refused.
    ///
    /// The positive control is the middle assertion: a `limit` function that returned
    /// [`DEFAULT_LIMIT`] unconditionally would satisfy every clamping assertion here and make the
    /// parameter decoration.
    #[test]
    fn a_limit_is_honoured_below_the_cap_and_clamped_above_it() {
        let request_id = RequestId::new_v7();

        assert_eq!(limit(None, request_id).expect("a default"), DEFAULT_LIMIT);
        assert_eq!(limit(Some("3"), request_id).expect("honoured"), 3, "a smaller page is served");
        assert_eq!(limit(Some(" 5 "), request_id).expect("trimmed"), 5);
        assert_eq!(limit(Some("500"), request_id).expect("clamped"), MAX_LIMIT);
        assert_eq!(
            limit(Some("0"), request_id).expect("floored"),
            MIN_LIMIT,
            "a page of nothing is indistinguishable from an empty history (docs/09 §11)"
        );

        let refused = limit(Some("eight"), request_id).expect_err("a non-number is a client error");
        let rendered = format!("{refused:?}");
        assert!(rendered.contains("limit"), "the refusal must name the field: {rendered}");
    }

    /// Only a directory user has a recency list.
    ///
    /// The positive control is the user: without it this passes against a `subject` that refuses
    /// everybody, which makes the endpoint unreachable rather than safe.
    #[test]
    fn only_a_directory_user_has_a_recency_list() {
        let tenant = TenantId::new_v7();
        let user = UserId::new_v7();

        assert_eq!(
            subject(&context(tenant, Actor::User(user))).expect("a user reads their own recency"),
            user
        );

        for actor in [
            Actor::Guest(GuestId::new_v7()),
            Actor::ServiceAccount(ServiceAccountId::new_v7()),
            Actor::McpClient(McpClientId::new_v7()),
            Actor::LinkBearer(ShareLinkId::new_v7()),
            Actor::System,
        ] {
            let refused = subject(&context(tenant, actor)).expect_err("no `users` row, no list");
            assert_eq!(refused.code(), ReasonCode::AccessDenied);
        }
    }

    /// The extension is the last dot's tail, and the three names that have none say so.
    #[test]
    fn an_extension_is_what_follows_the_last_dot_or_nothing_at_all() {
        assert_eq!(extension("fox.txt").as_deref(), Some("txt"));
        assert_eq!(
            extension("archive.tar.gz").as_deref(),
            Some("gz"),
            "today's rule, and the reason this is not in SQL"
        );
        assert_eq!(extension("Quarterly Plan.pdf").as_deref(), Some("pdf"));

        assert_eq!(extension("README"), None, "no dot, no extension");
        assert_eq!(extension(".env"), None, "a dotfile's whole name is its name");
        assert_eq!(extension("report."), None, "a trailing dot introduces nothing");
    }
}
