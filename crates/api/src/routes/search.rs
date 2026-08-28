//! `POST /api/v1/search` — the surface `crates/search` never had.
//!
//! `docs/05-API.md §11` is authoritative for everything on the wire here.
//! `docs/07-SEARCH-INDEXING.md §5` and `§6` are authoritative for the pipeline behind it. Where this
//! module and either document disagree, the document wins and this module is the bug.
//!
//! # The one sentence
//!
//! **The index is a candidate generator. PostgreSQL is the authority.** (`CLAUDE.md` rule 5.)
//! `enclave_search` is what makes that true; this module is what makes it *reachable*, and its whole
//! job is to hand that crate a request and hand its answer back without inventing a way around it.
//!
//! There is exactly one path from a query to a response and it runs through
//! [`SearchResults::confirm_degraded`], which runs [`enclave_search::PostFilter::confirm`], which
//! resolves `file.metadata_read` and `file.content_read` for every candidate against this caller's
//! ACL. No candidate reaches [`SearchResponse`] that the post-filter did not confirm. There is no
//! parameter that skips it, no cache that outlives the request, and no branch that returns
//! `results` from anywhere else — [`hydrate`] and [`capabilities_for`] are given
//! [`enclave_search::Confirmed`] values and cannot be given anything else.
//!
//! # When this route says `degraded: true`, and why it used to say it always
//!
//! `docs/09-UX-WHITE-LABELING.md §10`: *"A degraded search (vector store unavailable) says so in the
//! results header rather than quietly returning less."*
//!
//! Until `ENC-698` this route said so on **every** request, and it was telling the truth for a
//! reason that had nothing to do with the deployment: [`ApiState`] held no
//! [`enclave_search::vector::VectorIndex`], so from inside this process the store was not merely
//! empty, it was unreachable — and [`Retrieval::decide`] was handed a hardcoded
//! [`VectorStore::Unreachable`]. The flag was therefore a constant wearing a decision's clothes.
//! When a corpus existed, nothing here would have changed and a healthy index would have kept being
//! reported as a degraded search.
//!
//! [`ApiState::vector`] is the fix, and it is what [`plan`] reads. Three states, all honest:
//!
//! * **No pair on the state** — no `search.milvus`, or no mounted embedding model. This process
//!   cannot reach the store, [`VectorStore::Unreachable`] is the honest reading, and the lexical
//!   fallback runs. This is the ordinary deployment and it is not a defect.
//! * **A pair, and the store answers** — [`Retrieval::Complete`], the dense path, `degraded: false`.
//! * **A pair, and the store is unreachable, depleted, or the tenant's denylist has outgrown its
//!   limit** — the lexical fallback, `degraded: true`, with the cause in a log line.
//!
//! The flag is still not set here. It is *decided* by [`Retrieval::decide`] and *carried* by the
//! type: [`enclave_search::DegradedReason`] has a private field and `decide` is its only
//! constructor, [`enclave_search::lexical::candidates`] demands one, and [`SearchResults`] has no
//! constructor taking a `bool` — [`SearchResults::confirm`] is complete and
//! [`SearchResults::confirm_degraded`] is degraded, and which one runs is decided by which generator
//! produced the candidates. So `diagnostics.degraded` cannot be forgotten at this boundary, which is
//! the boundary `plans/M3-DISCOVERY.md` D25 exists to protect: a client that cannot tell reduced
//! recall from complete recall tells a user their document is gone.
//!
//! **What is not on the wire is the *cause*.** `enclave_search::degraded` draws that line and this
//! module keeps it: the boolean is caller-facing, the cause is operator-facing. A caller needs to
//! know their recall is reduced; telling them *which internal component is unwell* is a fact about
//! our topology. The cause goes to a log line.
//!
//! # The dense path is a *generator* change and nothing else
//!
//! This is the sentence `CLAUDE.md` rule 5 is about, so it is worth being exact. The two paths
//! differ in **where candidates come from** and in nothing else:
//!
//! ```text
//! lexical:  lexical::candidates(tx, tenant, query, budget, reason)
//! dense:    embedder.embed(query) -> index.candidates(VectorQuery { .. })
//!                     |                          |
//!                     +--------- Vec<Candidate> -+
//!                                     |
//!                        PostFilter::confirm(tx, authorization, ctx, candidates)
//! ```
//!
//! [`SearchResults::confirm`] and [`SearchResults::confirm_degraded`] are two callers of one
//! [`enclave_search::PostFilter::confirm`], with no argument between them that changes what is
//! checked. There is **no second post-filter** in this module and there must not be: the vector
//! store's candidates are resolved against `acl_entries` by the same batched
//! `file.metadata_read`/`file.content_read` call the lexical ones are, in the same transaction, and a
//! candidate that resolves to nothing is dropped silently rather than reported as a hit. That matters
//! more here than on the lexical path, because `crates/search/src/vector.rs` says plainly that
//! `acl_tokens` and `barrier_tokens` are **not** in the emitted filter — nothing computes them — so
//! on the dense path the post-filter is doing all of the access control rather than confirming any
//! of it.
//!
//! Everything after the post-filter — [`hydrate`], [`capabilities_for`], the trim, the markup — is
//! shared, takes [`Confirmed`] values, and cannot be given anything else.
//!
//! # Where the policy chain runs, and the gap that is worth naming
//!
//! In the handler, before the database is reached, exactly once —
//! [`ContainerAction::Read`] against the caller's own principal, the same reference
//! `GET /api/v1/me` enforces on.
//!
//! That is not a satisfying answer and it should not be read as one. A tenant-wide search names no
//! resource, and the resource it *would* name — the tenant — is one the ACL model cannot answer
//! about: `crates/authorization/src/service.rs` classifies a tenant reference as `Unsupported` and
//! refuses it, which is precisely the defect `ENC-619` had to close for `/api/v1/admin/**`, where
//! every route was refused at the authorization stage whoever the caller was. Enforcing on the
//! tenant here would make search a route that denies everyone.
//!
//! So the chain runs for the stages that *can* decide a search — tenant isolation, conditional
//! access (`docs/07 §5`: search may be permitted while download is not), classification, DLP,
//! retention — and the per-resource authorization question is answered where `docs/07 §6.2` says it
//! is answered: once per candidate, in the post-filter, in one batched resolution. The consequence
//! is recorded rather than hidden: **the chain's authorization stage is not asking "may you
//! search"**, and the audit row this route writes is indistinguishable from the one `GET /me`
//! writes. `ENC-696` is the row, and closing it means an `Action::Search` in `crates/core` with a
//! resource kind the resolver can answer — a change this task did not own.
//!
//! # What is refused rather than ignored
//!
//! `docs/05-API.md §11`'s request carries `workspaceIds`, `libraryIds`, `types`,
//! `classificationMax`, `modifiedAfter` and `cursor`. [`enclave_search::lexical::candidates`] takes
//! a tenant, a query and a candidate budget, and nothing else. A narrowing filter that is accepted
//! and then not applied returns **more** than the caller asked for — a `classificationMax` of
//! `INTERNAL` answered with `CONFIDENTIAL` hits is a disclosure produced by a field that read as
//! working — so each of them is a `400` naming the field, and the request body is
//! `deny_unknown_fields` so that a misspelled filter is refused rather than dropped.
//!
//! `cursor` is refused for the neighbouring reason: there is no cursor to issue, so a client that
//! sent one would page into nothing. `page.hasMore` is still answered truthfully — the post-filter
//! confirmed more hits than the page shows — because reporting `false` while discarding confirmed
//! results is the same lie in a smaller field. `ENC-697` carries both.
//!
//! # What is absent rather than invented
//!
//! `location` (`{ page, sectionPath }`) and `classification` are in `docs/05-API.md §11`'s response
//! and are **not** in this one.
//!
//! `location` needs the page or section a passage sits on. The lexical path quotes `chunk_text`,
//! whose `ordinal` is a position in a chunk sequence and not a page — rendering it as one would
//! deep-link a reader to the wrong place with no way to tell.
//!
//! `classification` needs the *effective* label, which is a walk up the classification chain
//! (`enclave_db::effective_classification_on`) with no batch form and no key on its result. A badge
//! computed from the file's own `classification_id` would report an inherited `CONFIDENTIAL` as
//! unlabelled — a badge that under-reports sensitivity is worse than no badge. `ENC-699`.
//!
//! And one thing is absent because the search crate refuses to grow it: **no per-file index
//! freshness indicator**. `crates/search/src/denylist.rs` records that refusal in full — a
//! "is this file's index current?" predicate is the one a search eventually calls to skip work —
//! and a response field would be the same predicate with a client asking it.
//!
//! # The excerpt, and the markup this layer adds
//!
//! `docs/05-API.md §11`: the `<em>` is applied **here**, from offsets retrieval carries, because
//! interpolating document content into a markup string in the retrieval crate is how stored XSS is
//! delivered. [`marked_up`] is that application and it does two things in one pass: it wraps each
//! span of [`Highlights::Terms`], and it **escapes the document's own text** for the markup context
//! the field now has. Everything outside the `<em>` tags is the document's text — escaped, because a
//! field that is defined to carry markup and also carries an unescaped `<script>` from a document
//! body is a stored-XSS delivery mechanism whichever crate assembled the string.
//!
//! A dense hit would arrive [`Highlights::Unlocated`] and be escaped with no markup at all; the
//! absence of `<em>` is not a failure, and a client must not read it as one.
//!
//! Whether an excerpt is disclosed at all is **not** decided here. The post-filter withheld it, or
//! did not, by resolving `file.content_read`; a withheld excerpt and an absent one are the same
//! `None` and reach the wire as the same `null`, which is `docs/12-TESTING.md §4.3` S6.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::State;
use axum::Json;
use enclave_core::{
    Action, AuthorizationService, ClassificationRank, ContainerAction, Error, FieldError,
    FileAction, FileId, Obligations, PolicyDecision, ReasonCode, RequestContext, ResourceKind,
    ResourceRef, TenantId, ValidationCode,
};
use enclave_embeddings::ClassifiedText;
use enclave_search::{
    lexical, Candidate, Confirmed, Excerpt, Highlights, Prefilter, Retrieval, SearchResults,
    VectorQuery, VectorStore, DEFAULT_DENYLIST_LIMIT,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action this endpoint asks the chain about, and the one a refusal here is recorded against.
///
/// See the module documentation for why it is this action against this resource, and why that is a
/// gap with a row (`ENC-696`) rather than a design.
const SEARCH: Action = Action::Container(ContainerAction::Read);

/// Results per page when the caller does not say.
///
/// `docs/05-API.md §11`'s own example. `§6`'s general default of 50 is for listings, where a page is
/// bounded by a container; a search page is bounded by what the post-filter confirms out of a
/// capped candidate set, and asking for more than can be confirmed produces a short page that reads
/// as absence.
const DEFAULT_LIMIT: u32 = 20;

/// The most results one page may hold.
///
/// Lower than `docs/05-API.md §6`'s 500 for listings, and the reason is arithmetic rather than
/// taste: `docs/07-SEARCH-INDEXING.md §5` caps over-fetch at [`MAX_CANDIDATES`] candidates, so a
/// page beyond a small multiple of that cannot be honestly filled — every result past the cap would
/// be reported absent because the generator was never asked, not because nothing matched.
/// Clamped rather than rejected, on `crates/api/src/content.rs`'s reasoning: a client asking for a
/// million rows wants as many as it can have.
const MAX_LIMIT: u32 = 50;

/// How many candidates are asked for per requested result (`docs/07-SEARCH-INDEXING.md §5`).
const OVERFETCH: u32 = 3;

/// The ceiling on candidates in one pass (`docs/07-SEARCH-INDEXING.md §5`).
///
/// `§5` also specifies a single deeper re-issue when post-filtering removes more than half a page.
/// It is deliberately not implemented, and `ENC-145`'s measurement is why: resolution is ~80% fixed
/// cost — 1.4 ms for one candidate, 7.0 ms for two hundred — so a second pass costs more than
/// tripling the batch while raising over-fetch is close to free. Fetching to the cap in one pass is
/// the same recall for less work; it is a deviation from the document and `ENC-697` carries it.
const MAX_CANDIDATES: u32 = 200;

/// The longest query string accepted.
///
/// A bound rather than a limit anyone will meet: `plainto_tsquery` will happily tokenize a megabyte
/// of pasted document, and the work that follows is proportional to it.
const MAX_QUERY_CHARS: usize = 512;

/// How far the path walk climbs before giving up, matching the walk `enclave_files` performs.
const MAX_PATH_DEPTH: i32 = enclave_files::MAX_DEPTH;

/// The retrieval modes a request may name.
///
/// Accepted and validated, and none of them changes what runs. Which path answers is decided by
/// [`plan`] from the health of the store, never by the request: a deployment with no reachable
/// index answers a `semantic` request lexically and says `degraded: true`, which is exactly what
/// degraded mode is for — refusing the mode would tell a caller their query is invalid when the
/// truth is that our index is unavailable. `ENC-697` carries honouring the mode as a *narrowing*
/// (a caller asking for `lexical` over a healthy index gets more than they asked for, which is the
/// safe direction of the two and the one this route already takes for every other filter).
const MODES: [&str; 3] = ["hybrid", "semantic", "lexical"];

/// What `diagnostics.mode` reports when the lexical fallback answered.
const MODE_LEXICAL: &str = "lexical";

/// What `diagnostics.mode` reports when the vector index answered.
///
/// `semantic` and not `hybrid`, because [`enclave_search::VectorIndex::candidates`] runs a dense
/// search over `dense_vector` alone. `docs/07-SEARCH-INDEXING.md §5` specifies a hybrid query fused
/// with the sparse side; the collection has a `sparse_vector` field and the writer populates it, but
/// nothing issues a hybrid request yet. Reporting `hybrid` would be the same lie `degraded` exists
/// to prevent, one field along — a caller told their query was answered by a fusion that did not
/// run. `ENC-891`.
const MODE_SEMANTIC: &str = "semantic";

/// The capability actions a search result carries (`docs/05-API.md §11`).
///
/// Two, not `§7`'s nine. A search result is a link into a document, and the two exposures a result
/// row offers are opening the preview and taking the bytes — which `CLAUDE.md` rule 6 keeps apart
/// and this table therefore keeps apart. An action with no entry here is absent from the object and
/// reads as `false`, which is the direction an unanswered capability has to fail in: a hidden button
/// costs a click, an offered one that the chain then refuses costs trust.
const CAPABILITY_ACTIONS: [(&str, FileAction); 2] =
    [("preview", FileAction::Preview), ("download", FileAction::Download)];

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The request body of `docs/05-API.md §11`.
///
/// `deny_unknown_fields` is load-bearing rather than tidy. Every field on this type except `query`,
/// `mode` and `limit` is a **narrowing** filter, and a narrowing filter that is silently ignored
/// returns more than the caller asked for. A misspelled `classificationMaximum` accepted and
/// dropped is that failure with no field to name in the refusal, so the decoder refuses it.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchRequest {
    /// What to look for.
    query: Option<String>,
    /// Which retrieval mode is wanted. See [`MODES`].
    mode: Option<String>,
    /// Narrow to these workspaces. Refused — see [`unsupported_narrowing`].
    workspace_ids: Option<Vec<String>>,
    /// Narrow to these libraries. Refused.
    library_ids: Option<Vec<String>>,
    /// Narrow to these file types. Refused.
    types: Option<Vec<String>>,
    /// Narrow to this classification ceiling. Refused.
    classification_max: Option<String>,
    /// Narrow to files modified after this instant. Refused.
    modified_after: Option<String>,
    /// Results per page.
    limit: Option<u32>,
    /// Page cursor. Refused — none is ever issued.
    cursor: Option<String>,
}

/// The response body of `docs/05-API.md §11`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    results: Vec<Hit>,
    page: PageInfo,
    diagnostics: Diagnostics,
}

/// One confirmed result.
///
/// Every field is either the index's own (`score`), the post-filter's (`excerpt`), or read from
/// PostgreSQL for a file the post-filter already confirmed. There is no constructor that takes
/// anything else.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Hit {
    file_id: String,
    /// The version a read path would serve, absent while the file has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    title: String,
    path: String,
    workspace: String,
    mime_type: String,
    score: f32,
    /// The quotation, with `<em>` around the matched terms — or `null`, which means *there was
    /// none* and *you may not read the content* at once, deliberately indistinguishable
    /// (`docs/07 §6.2`, `docs/12 §4.3` S6).
    excerpt: Option<String>,
    capabilities: Capabilities,
}

/// The page envelope `docs/05-API.md §11` shows.
///
/// `nextCursor` is serialized as `null` rather than omitted: a client checking for the field's
/// presence and a client checking for a value must reach the same conclusion.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    next_cursor: Option<String>,
    has_more: bool,
}

/// `docs/05-API.md §11`'s diagnostics: what ran, and whether recall was reduced.
#[derive(Debug, Serialize)]
struct Diagnostics {
    mode: &'static str,
    degraded: bool,
}

/// What the caller may do with a result (`docs/05-API.md §11`).
///
/// Answered by the same authorization handle the chain will consult when the caller clicks, for the
/// reason `docs/05-API.md §7` gives: a UI hint derived from the real decision, never a parallel
/// implementation.
#[derive(Debug, Default, Serialize)]
struct Capabilities {
    preview: bool,
    download: bool,
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/search`.
///
/// # Errors
///
/// [`ApiError`]: `400` for an unreadable body, an empty or over-long query, or any narrowing filter
/// or cursor this deployment cannot honour; the denial's own status for a policy refusal; `503` when
/// PostgreSQL or authorization resolution cannot answer — never an empty result standing in for an
/// outage (`crates/search/src/error.rs`).
pub async fn search(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    body: Bytes,
) -> Result<Json<SearchResponse>, ApiError> {
    let request_id = ctx.request_id;

    // Parsed and validated before the chain runs. Nothing here reads tenant data — it reads the
    // request — and refusing a request that could never be answered before auditing an allow for it
    // keeps the log free of decisions nothing acted on. `crates/api/src/content.rs` parses its path
    // and page size in the same position and for the same reason.
    let request: SearchRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError::new(unreadable_body(), request_id))?;
    let query = accepted_query(request.query.as_deref())
        .map_err(|error| ApiError::new(error, request_id))?;
    accepted_mode(request.mode.as_deref()).map_err(|error| ApiError::new(error, request_id))?;
    unsupported_narrowing(&request).map_err(|error| ApiError::new(error, request_id))?;
    let limit = accepted_limit(request.limit);

    // A principal with no subject has no `users` row and no ACL identity, so there is nothing for
    // the post-filter to resolve against. Refused before the chain, which is why it is a `Refused`
    // and leaves a row of its own — the same shape `GET /api/v1/me` takes.
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, SEARCH, &resource, refused).await);
        }
    };
    let resource = ResourceRef::new(ctx.tenant_id, ResourceKind::User, subject);

    // The chain. Not a check beside the query — nothing below runs unless this returns, and the
    // audit row is written inside it whether it allows or denies.
    let decision = state
        .policy
        .enforce(&ctx, SEARCH, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it here is what proves nothing was dropped. This
    // path returns JSON: there is no rendition to watermark and nowhere to collect a justification,
    // so an obligation arriving here is undischargeable and therefore a refusal (D29, rule 8).
    let obligations = consume(decision);
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, SEARCH, &resource, refused).await);
    }

    let budget = (limit.saturating_mul(OVERFETCH)).min(MAX_CANDIDATES);

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Which generator answers, decided before anything is retrieved and inside the transaction the
    // post-filter will run in — so the denylist size the decision reads and the denylist the
    // post-filter drops by are one snapshot of one table.
    let path = plan(&state, &mut tx, ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // The post-filter runs on both arms and it is the same one: `SearchResults::confirm` and
    // `SearchResults::confirm_degraded` are two callers of `PostFilter::confirm`, in this
    // transaction, with no argument between them that changes what is checked. The arms differ in
    // where the candidates came from and in what `diagnostics.mode` says about it.
    let authorization = state.policy.authorization();
    let (confirmed, mode) = match path {
        Path::Dense(vector) => {
            let candidates = propose(vector, ctx.tenant_id, &query, budget)
                .await
                .map_err(|error| ApiError::new(error, request_id))?;
            let confirmed =
                SearchResults::confirm(&mut tx, authorization.as_ref(), &ctx, candidates)
                    .await
                    .map_err(|error| ApiError::new(Error::from(error), request_id))?;
            (confirmed, MODE_SEMANTIC)
        }
        Path::Lexical(reason) => {
            tracing::debug!(cause = ?reason.cause(), "search degraded to the lexical path");
            let candidates = lexical::candidates(&mut tx, ctx.tenant_id, &query, budget, reason)
                .await
                .map_err(|error| ApiError::new(Error::from(error), request_id))?;
            let confirmed =
                SearchResults::confirm_degraded(&mut tx, authorization.as_ref(), &ctx, candidates)
                    .await
                    .map_err(|error| ApiError::new(Error::from(error), request_id))?;
            (confirmed, MODE_LEXICAL)
        }
    };

    let counts = confirmed.counts();
    tracing::debug!(
        proposed = counts.proposed,
        denylisted = counts.denylisted,
        unauthorized = counts.unauthorized,
        drop_ratio = counts.drop_ratio(),
        "search post-filter pass"
    );

    // Trimmed before anything is read for it: a hit past the page is a hit whose title, path and
    // capabilities nobody is going to see.
    //
    // `has_more` is *confirmed hits beyond this page*, which under-reports at exactly one boundary:
    // a caller whose matches exceed the candidate budget gets `has_more` from what the budget held
    // rather than from what the tenant holds. That is the safe direction of the two — it can only
    // say "no more" when the generator was never asked — and it is the direction `ENC-697` closes
    // with a cursor rather than with a count, because the count is the thing `docs/05-API.md §6`
    // refuses to return.
    let hits = confirmed.hits();
    let page_size = limit as usize;
    let has_more = hits.len() > page_size;
    let page: Vec<&Confirmed> = hits.iter().take(page_size).collect();

    let ids: Vec<FileId> = page.iter().map(|hit| hit.file_id).collect();
    let rows = hydrate(&mut tx, ctx.tenant_id, &ids)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // Committed before the capability resolution, deliberately: `authorize_many_actions` opens its
    // own tenant-scoped transaction, and a handler holding this one open while waiting for that
    // needs two connections per request — which on a small pool is a deadlock waiting for load
    // (`crates/api/src/content.rs`).
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // A hit whose row did not come back was deleted, trashed or moved out of `AVAILABLE` between
    // the generator and this read. Dropping it is the same answer every other read path gives.
    let present: Vec<&Confirmed> =
        page.into_iter().filter(|hit| rows.contains_key(&hit.file_id)).collect();
    let present_ids: Vec<FileId> = present.iter().map(|hit| hit.file_id).collect();

    let capabilities = capabilities_for(state.policy.authorization().as_ref(), &ctx, &present_ids)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    let results = present
        .into_iter()
        .zip(capabilities)
        .filter_map(|(hit, capabilities)| {
            let row = rows.get(&hit.file_id)?;
            Some(Hit {
                file_id: hit.file_id.to_string(),
                version_id: row.version_id.map(|id| id.to_string()),
                title: row.title.clone(),
                path: row.path.clone(),
                workspace: row.workspace.clone(),
                mime_type: row.mime_type.clone(),
                score: hit.score,
                excerpt: hit.excerpt.as_ref().map(marked_up),
                capabilities,
            })
        })
        .collect();

    Ok(Json(SearchResponse {
        results,
        page: PageInfo { next_cursor: None, has_more },
        // Neither field is a literal. `is_degraded` is the envelope's own answer and the envelope is
        // the only thing that can produce one; `mode` comes from the arm that produced the
        // envelope, so the two cannot disagree about which path ran.
        diagnostics: Diagnostics { mode, degraded: confirmed.is_degraded() },
    }))
}

// ---------------------------------------------------------------------------------------------
// Which generator answers
// ---------------------------------------------------------------------------------------------

/// Where this search's candidates come from.
///
/// Two variants rather than a `Retrieval` plus an `Option<&VectorRetrieval>`, so that "complete
/// path, no index to run it on" is not a state a caller has to handle. [`plan`] is the only
/// constructor and it can only produce [`Path::Dense`] on the branch that is holding the pair.
enum Path<'a> {
    /// The vector index answers, with its full recall.
    Dense(&'a crate::state::VectorRetrieval),
    /// The lexical fallback answers, carrying the reason it is running.
    Lexical(enclave_search::DegradedReason),
}

/// Decides which generator answers, from the health of the store and the pressure on the denylist.
///
/// # Both inputs are real, and one of them used to be a literal
///
/// `ENC-695` passed `VectorStore::Unreachable` and `0`. The first was truthful — this process held
/// no index — and the second was inert only *because* of the first: [`Retrieval::decide`] is a
/// `const fn` whose `Unreachable` arm ignores both denylist arguments, so no value of the second
/// could change the answer. The moment a store became reachable that stopped being true, and a
/// hardcoded `0` would have said "invalidation is keeping up" about a tenant whose denylist had
/// overflowed — which is `docs/07-SEARCH-INDEXING.md §6.4`'s third degradation trigger, silently
/// disarmed. [`enclave_search::in_force`] supplies it, counting by the same `clears_at` rule the
/// post-filter drops by.
///
/// The `None` branch still passes `0`, and still cannot be wrong about it, for exactly the reason
/// above — asserted by `a_process_with_no_index_degrades_whatever_the_denylist_holds` rather than
/// left as a claim. It is *not* read there because a `count(*)` on every search of every deployment
/// that has no vector store is work with no consumer.
///
/// # The reachability probe is a network round trip, taken per request
///
/// There is no circuit breaker in front of it yet — `crates/search/src/milvus.rs` says so and sizes
/// `MilvusConfig::connect_timeout` short *because* of it: while the store is down, every request
/// pays one connect attempt. That is the cost of the honest answer, and the alternative is the one
/// `enclave_search::degraded` refuses — caching the store's health per process would make the same
/// query answer completely on one replica and degraded on another with no state change between
/// them.
///
/// # Errors
///
/// A failed denylist read, propagated. **Never a degradation**: a storage failure that quietly
/// engaged the fallback would answer an outage with a smaller result set and a flag the caller
/// cannot distinguish from a real one.
async fn plan<'a>(
    state: &'a ApiState,
    conn: &mut PgConnection,
    tenant: TenantId,
) -> Result<Path<'a>, Error> {
    let Some(vector) = state.vector.as_ref() else {
        return no_index_in_this_process().map(Path::Lexical);
    };

    let store = vector.index().reachability().await;
    let denylisted = enclave_search::in_force(conn, tenant).await.map_err(Error::from)?;

    Ok(match Retrieval::decide(store, denylisted, DEFAULT_DENYLIST_LIMIT) {
        Retrieval::Complete => Path::Dense(vector),
        Retrieval::Degraded(reason) => Path::Lexical(reason),
    })
}

/// The reason a process holding no vector index gives for running the fallback.
///
/// Taken through [`Retrieval::decide`] rather than assembled, because
/// [`enclave_search::DegradedReason`] has a private field and `decide` is its only constructor —
/// [`lexical::candidates`] demands one, so there is no way to reach the fallback without having
/// decided to take it.
///
/// # Errors
///
/// [`Error::Internal`] for a `Complete` that cannot happen: `decide` maps
/// [`VectorStore::Unreachable`] to `Degraded` unconditionally, whatever the denylist arguments. It
/// is a fall-through rather than a possibility, and it fails rather than falling into the dense arm
/// because a search that reported itself complete while running on the lexical fallback is the one
/// outcome this route exists to prevent. The message says *this process cannot query the store*,
/// which is the narrower and now-accurate claim: a store may be perfectly reachable from a worker
/// that has the pair while this replica has neither half of it.
fn no_index_in_this_process() -> Result<enclave_search::DegradedReason, Error> {
    match Retrieval::decide(VectorStore::Unreachable, 0, DEFAULT_DENYLIST_LIMIT) {
        Retrieval::Degraded(reason) => Ok(reason),
        Retrieval::Complete => Err(Error::Internal(anyhow::anyhow!(
            "retrieval reported a complete path from a store this process cannot query"
        ))),
    }
}

/// Asks the vector index for candidates, having first put the query through the embedder.
///
/// # What this function is allowed to be wrong about: everything
///
/// It proposes. `crates/search/src/vector.rs` states the contract and it is not softened here — a
/// candidate for a file the caller has no grant on, a deleted file, a file re-classified upward an
/// hour ago, or a file of another tenant entirely is dropped by
/// [`enclave_search::PostFilter::confirm`], which the caller runs on this output before anything
/// reaches a response. Nothing downstream reads a field the index matched on.
///
/// [`Prefilter::unnarrowed`] is therefore the correct narrowing and not a shortcut: this route
/// refuses every narrowing filter `docs/05-API.md §11` defines (`ENC-697`), so the caller asked a
/// tenant-wide question and an unnarrowed scan is the answer to it. `docs/07 §6.1`'s library
/// pre-filter is a **cost** optimisation whose values must come from PostgreSQL; supplying it from
/// anywhere else — or supplying a guess to look busy — loses recall for a narrowing nobody can
/// verify.
///
/// # The query is embedded at the ceiling, deliberately
///
/// [`ClassificationRank::RESTRICTED`] is the rank attached to the query text, and it is not the
/// query's "classification" — a query has none, because it is the caller's own words rather than a
/// document's contents. It is a routing decision: the words someone types looking for a
/// `RESTRICTED` document are as sensitive as the document, and this is the one rank that can never
/// be admitted to a remote provider (`crates/embeddings/src/text.rs`). Today every deployment is
/// air-gapped so the rank changes nothing; the day a remote provider exists it is the difference
/// between a search box and an egress channel, and the safe value is the one to have written down
/// before then.
///
/// # Errors
///
/// An embedding failure or a vector-store failure, propagated. Never an empty candidate set
/// standing in for either — `crates/search/src/error.rs` and `crates/embeddings/src/error.rs` both
/// hold that line, and a search that answered an outage with "no matches" would tell a caller their
/// document is not there.
async fn propose(
    vector: &crate::state::VectorRetrieval,
    tenant: TenantId,
    query: &str,
    budget: u32,
) -> Result<Vec<Candidate>, Error> {
    let text = ClassifiedText::new(ClassificationRank::RESTRICTED, vec![query.to_owned()]);
    let embedded = vector.embedder().embed(text).await.map_err(Error::from)?;

    // One chunk in, one vector out. `EmbeddingRouter::embed` already refuses a batch that comes
    // back short, so this is the second guard and it is a refusal rather than a `None` candidate
    // set: a search that returned nothing because the model returned nothing would report an
    // embedding outage as a tenant with no matching documents.
    let Some(embedding) = embedded.embeddings().first() else {
        return Err(Error::Internal(anyhow::anyhow!(
            "the embedder returned no vector for a one-chunk query batch"
        )));
    };

    let prefilter = Prefilter::unnarrowed();
    vector
        .index()
        .candidates(VectorQuery {
            tenant,
            embedding: embedding.as_slice(),
            budget,
            prefilter: &prefilter,
        })
        .await
        .map_err(Error::from)
}

// ---------------------------------------------------------------------------------------------
// Request acceptance
// ---------------------------------------------------------------------------------------------

/// The body could not be read as a search request.
///
/// One code for every decoding failure, including an unknown field: the offending name came from
/// the request, and echoing it is how a decoder message becomes a reflection channel. The field
/// path is `body` because that is the input the caller can act on.
fn unreadable_body() -> Error {
    Error::Validation(vec![FieldError::new("body", ValidationCode::InvalidFormat)])
}

/// The query, trimmed, or the reason it cannot be one.
fn accepted_query(raw: Option<&str>) -> Result<String, Error> {
    let query = raw.unwrap_or_default().trim();
    if query.is_empty() {
        return Err(Error::Validation(vec![FieldError::new("query", ValidationCode::Required)]));
    }
    if query.chars().count() > MAX_QUERY_CHARS {
        return Err(Error::Validation(vec![FieldError::new("query", ValidationCode::TooLong)]));
    }
    Ok(query.to_owned())
}

/// Accepts a retrieval mode, or refuses a word that names none.
///
/// The value is validated and discarded: see [`MODES`] for why every mode currently runs the same
/// path, and why that is reported by `diagnostics.degraded` rather than by refusing the request.
fn accepted_mode(raw: Option<&str>) -> Result<(), Error> {
    match raw {
        None => Ok(()),
        Some(mode) if MODES.contains(&mode) => Ok(()),
        Some(_) => {
            Err(Error::Validation(vec![FieldError::new("mode", ValidationCode::Unsupported)]))
        }
    }
}

/// Clamps `limit` into the range this route can honestly fill.
const fn accepted_limit(raw: Option<u32>) -> u32 {
    match raw {
        None => DEFAULT_LIMIT,
        Some(0) => DEFAULT_LIMIT,
        Some(limit) if limit > MAX_LIMIT => MAX_LIMIT,
        Some(limit) => limit,
    }
}

/// Refuses every narrowing this deployment cannot apply, naming each one.
///
/// Every field here would make the result set **smaller**. Accepting one and not applying it returns
/// results the caller excluded, which for `classificationMax` is a disclosure and for the others is
/// a filter chip that visibly does nothing. All of them are reported at once rather than one per
/// round trip, because a client fixing a query wants the whole list.
///
/// An empty array is not a filter and is accepted: `docs/05-API.md §11`'s own example sends
/// `"workspaceIds": []` to mean *everywhere*.
fn unsupported_narrowing(request: &SearchRequest) -> Result<(), Error> {
    let mut refused: Vec<FieldError> = Vec::new();
    let mut refuse = |field: &str| {
        refused.push(FieldError::new(field, ValidationCode::Unsupported));
    };

    if request.workspace_ids.as_ref().is_some_and(|ids| !ids.is_empty()) {
        refuse("workspaceIds");
    }
    if request.library_ids.as_ref().is_some_and(|ids| !ids.is_empty()) {
        refuse("libraryIds");
    }
    if request.types.as_ref().is_some_and(|types| !types.is_empty()) {
        refuse("types");
    }
    if request.classification_max.is_some() {
        refuse("classificationMax");
    }
    if request.modified_after.is_some() {
        refuse("modifiedAfter");
    }
    if request.cursor.is_some() {
        refuse("cursor");
    }

    if refused.is_empty() {
        Ok(())
    } else {
        Err(Error::Validation(refused))
    }
}

/// The subject a search can be attributed to.
///
/// A function rather than an inline `ok_or_else` so that the refusal is constructed in a function
/// that returns one, which is what `cargo run -p xtask -- audit-coverage` reads to decide it is
/// audited.
///
/// # Errors
///
/// [`Refused`] for a principal with no subject id — [`enclave_core::Actor::System`], which has no
/// `users` row and therefore no ACL identity for the post-filter to resolve against.
fn subject(ctx: &RequestContext) -> Result<Uuid, Refused> {
    ctx.actor.subject_id().ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))
}

/// Consumes a [`PolicyDecision`], yielding the obligations the caller now has to satisfy.
fn consume(decision: PolicyDecision) -> Obligations {
    decision.into_obligations()
}

// ---------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------

/// Applies `docs/05-API.md §11`'s `<em>` markup to a confirmed excerpt.
///
/// Two things happen in one pass and both have to: the located spans are wrapped, and the
/// document's own text is escaped for the markup context this field has just acquired. Escaping
/// after wrapping would escape our own tags; escaping before would move every offset. So the string
/// is assembled span by span from the raw text, and each piece is escaped as it is appended.
///
/// [`Highlights::Unlocated`] — the dense path — emits **no** markup, not markup around the whole
/// quotation: "the whole chunk matched" is true of the retrieval and says nothing about which words
/// answered the query.
///
/// The bounds check is belt-and-braces. [`Excerpt::located`] already refuses spans that are empty,
/// out of order, out of range or off a character boundary; a span that somehow failed those is
/// skipped rather than sliced, because the alternative is a panic on input derived from a document.
fn marked_up(excerpt: &Excerpt) -> String {
    let text = excerpt.text();
    let Highlights::Terms(spans) = excerpt.highlights() else {
        return escape(text);
    };

    let mut out = String::with_capacity(text.len() + spans.len() * "<em></em>".len());
    let mut cursor = 0usize;
    for span in spans {
        if span.start < cursor
            || span.end > text.len()
            || span.start >= span.end
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            continue;
        }
        out.push_str(&escape(&text[cursor..span.start]));
        out.push_str("<em>");
        out.push_str(&escape(&text[span.start..span.end]));
        out.push_str("</em>");
        cursor = span.end;
    }
    out.push_str(&escape(&text[cursor..]));
    out
}

/// Escapes the five characters that can change the meaning of markup.
///
/// `"` and `'` are escaped as well as `&<>` because a client that interpolates an excerpt into an
/// attribute — a `title`, an `aria-label` — is a client we cannot see, and the cost of escaping them
/// is two characters in a quotation that already carries elision marks.
///
/// Nothing else is touched. In particular the bidirectional controls are **not** stripped: an
/// excerpt is a verbatim quotation and a caller shown one must be able to find it in the file
/// (`docs/07 §6.2.1`). Isolating them is the renderer's job (`docs/14-I18N-L10N.md §7`).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Hydration
// ---------------------------------------------------------------------------------------------

/// What a confirmed hit needs from PostgreSQL to become a result.
#[derive(Debug)]
struct Metadata {
    title: String,
    path: String,
    workspace: String,
    mime_type: String,
    version_id: Option<Uuid>,
}

/// Reads the display metadata for files the post-filter has already confirmed.
///
/// **Only for confirmed hits.** The caller passes ids that came out of
/// [`enclave_search::PostFilter`]; this function makes no authorization decision and must never be
/// given a candidate. It is the same relationship `crates/api/src/content.rs` has with its
/// repositories: the trim decides, the read renders.
///
/// One statement for the page, not one per row. The path is the expensive half — it is an ancestor
/// walk — so the walk is done for every hit at once and grouped, rather than a recursive query per
/// result.
///
/// The tenant predicate is stated explicitly as well as enforced by row-level security, for
/// `crates/search/src/lexical.rs`'s reason: RLS is the control, and the predicate is what makes the
/// index usable and the statement readable as tenant-scoped.
///
/// **And it is not load-bearing, which was checked rather than assumed.** Deleting `f.tenant_id = $1`
/// from the statement below — and from both joins — fails **no test in this file or in
/// `crates/api/tests/search.rs`**, because row-level security under the `enclave_app` role holds the
/// property on its own. That is the fifth time this workspace has performed that deliberate
/// violation and watched nothing happen (`docs/12-TESTING.md §1.2` counted four), and it is recorded
/// here rather than papered over, because the honest reading of the line above is *this predicate is
/// for the planner and for the reader; RLS is the control*. A test that could tell them apart would
/// have to run as a role RLS does not apply to, which is not a role any request path holds.
///
/// `status = 'AVAILABLE'` and `deleted_at IS NULL` are restated here even though the generator
/// already applies them, because time passes between the two and `CLAUDE.md` rule 9 is not a
/// property to assert once: a file that entered `SCANNING` since it was proposed drops out of the
/// page rather than being described in it.
///
/// # Errors
///
/// Storage failures, propagated. Never an empty map standing in for one — that would report a
/// database outage as a search that matched nothing.
async fn hydrate(
    conn: &mut PgConnection,
    tenant: TenantId,
    files: &[FileId],
) -> Result<HashMap<FileId, Metadata>, Error> {
    if files.is_empty() {
        return Ok(HashMap::new());
    }

    let ids: Vec<Uuid> = files.iter().map(FileId::as_uuid).collect();
    let rows = sqlx::query(HYDRATE_SQL)
        .bind(tenant.as_uuid())
        .bind(&ids)
        .bind(MAX_PATH_DEPTH)
        .fetch_all(&mut *conn)
        .await
        .map_err(|error| Error::from(enclave_db::DbError::Query(error)))?;

    let mut out = HashMap::with_capacity(rows.len());
    for row in &rows {
        let id: Uuid = row.try_get("id").map_err(decode_failure)?;
        let workspace: String = row.try_get("workspace").map_err(decode_failure)?;
        let library: String = row.try_get("library").map_err(decode_failure)?;
        let folders: Option<String> = row.try_get("folders").map_err(decode_failure)?;

        // `docs/05-API.md §11` shows the path as the containers above the document, not including
        // the document itself — the title is already its own field, and repeating it in the path
        // costs a line of a result row to say nothing.
        let mut path = format!("{workspace} / {library}");
        if let Some(folders) = folders {
            path.push_str(" / ");
            path.push_str(&folders);
        }

        out.insert(
            FileId::from(id),
            Metadata {
                title: row.try_get("name").map_err(decode_failure)?,
                path,
                workspace,
                mime_type: row.try_get("mime_type").map_err(decode_failure)?,
                version_id: row.try_get("current_version_id").map_err(decode_failure)?,
            },
        );
    }
    Ok(out)
}

/// A row that could not be read as the schema says it is shaped.
///
/// Reported as a storage failure rather than as a missing result: a column this code cannot decode
/// is a defect, and answering it with a shorter page would hide it behind a plausible search.
fn decode_failure(error: sqlx::Error) -> Error {
    Error::from(enclave_db::DbError::Query(error))
}

/// The display metadata and the container path for a page of confirmed hits.
///
/// `UNION ALL` with an explicit depth bound rather than `UNION`, for the reason
/// `crates/files/src/path.rs` gives: `UNION` would hide a cycle by deduplicating it into a plausible
/// path, while `UNION ALL` climbs to the bound and stops.
///
/// Every step of the walk restates the tenant, so the climb cannot leave the tenant even where
/// row-level security is not in force, and `deleted_at IS NULL` at every step means a file under a
/// trashed folder contributes no path rather than a path through the trash.
const HYDRATE_SQL: &str = "
WITH RECURSIVE hit AS (
    SELECT f.id, f.parent_id, f.name, f.mime_type, f.current_version_id,
           f.workspace_id, f.library_id
      FROM files f
     WHERE f.tenant_id = $1
       AND f.id = ANY($2)
       AND f.deleted_at IS NULL
       AND f.node_type = 'FILE'
       AND f.status = 'AVAILABLE'
), up AS (
    SELECT h.id AS hit_id, a.id AS id, a.parent_id AS parent_id, a.name AS name, 1 AS depth
      FROM hit h
      JOIN files a
        ON a.tenant_id = $1 AND a.id = h.parent_id AND a.deleted_at IS NULL
    UNION ALL
    SELECT u.hit_id, a.id, a.parent_id, a.name, u.depth + 1
      FROM up u
      JOIN files a
        ON a.tenant_id = $1 AND a.id = u.parent_id AND a.deleted_at IS NULL
     WHERE u.depth < $3
), folders AS (
    SELECT hit_id, string_agg(name, ' / ' ORDER BY depth DESC) AS folders
      FROM up
     GROUP BY hit_id
)
SELECT h.id AS id,
       h.name AS name,
       h.mime_type AS mime_type,
       h.current_version_id AS current_version_id,
       w.name AS workspace,
       l.name AS library,
       k.folders AS folders
  FROM hit h
  JOIN workspaces w ON w.tenant_id = $1 AND w.id = h.workspace_id
  JOIN libraries  l ON l.tenant_id = $1 AND l.id = h.library_id
  LEFT JOIN folders k ON k.hit_id = h.id
";

// ---------------------------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------------------------

/// Resolves `docs/05-API.md §11`'s capability object for a page of confirmed hits.
///
/// One `authorize_many_actions` for the whole page and both actions, not one per action and not one
/// per row: `ENC-145` measured resolution as ~80% fixed cost, so the number of *calls* is what a
/// page costs, and `ENC-167` made one call able to answer a grid.
///
/// The handle is `state.policy.authorization()` — the very `Arc` the chain will consult when the
/// caller clicks — for the reason `docs/05-API.md §7` states: a capability is a UI hint derived from
/// the real decision, not a parallel implementation. Only that handle is passed in, never
/// [`ApiState`]: a probe that could reach the engine could call `enforce`, which is how a helper
/// quietly becomes a second enforcement point the ENC-110 lint does not check.
///
/// This is not the whole chain, and the direction of the error is deliberate. Conditional access,
/// classification, DLP and retention can each refuse an action reported here as available, and the
/// engine will refuse it when it is attempted — a capability that is optimistic produces a refusal
/// the user can be told about, while one that is pessimistic hides a button they are entitled to.
///
/// # Errors
///
/// A failed resolution, propagated. A page whose capabilities could not be resolved is not served
/// with the object a default would produce (`crates/core/src/engine.rs`: a failed resolution is not
/// a denial).
async fn capabilities_for(
    authorization: &dyn AuthorizationService,
    ctx: &RequestContext,
    files: &[FileId],
) -> Result<Vec<Capabilities>, Error> {
    if files.is_empty() {
        return Ok(Vec::new());
    }

    let resources: Vec<ResourceRef> =
        files.iter().map(|file| ResourceRef::file(ctx.tenant_id, *file)).collect();
    let actions: Vec<Action> =
        CAPABILITY_ACTIONS.iter().map(|(_, action)| Action::File(*action)).collect();

    let grid = authorization.authorize_many_actions(ctx, &actions, &resources).await?;

    let mut computed: Vec<Capabilities> = files.iter().map(|_| Capabilities::default()).collect();

    // Index-aligned with `actions`, which is index-aligned with `CAPABILITY_ACTIONS`. A short outer
    // vector leaves the tail *actions* unanswered and a short inner one leaves the tail *rows*
    // unanswered; both withhold the capability rather than offering one that will be refused, which
    // is the direction an absent verdict has to fail in — the same `first`/`get` shape the
    // post-filter uses on the same grid.
    for ((_, action), decisions) in CAPABILITY_ACTIONS.iter().zip(grid) {
        for (capabilities, decision) in computed.iter_mut().zip(decisions) {
            if !decision.is_allowed() {
                continue;
            }
            match action {
                FileAction::Preview => capabilities.preview = true,
                FileAction::Download => capabilities.download = true,
                // Every other action is absent from `CAPABILITY_ACTIONS` and therefore from the
                // object. Listed rather than wildcarded so that adding an exposure to the table is a
                // visible edit here rather than a silent `false` on the wire.
                FileAction::MetadataRead
                | FileAction::ContentRead
                | FileAction::Print
                | FileAction::Export
                | FileAction::Edit
                | FileAction::Copy
                | FileAction::Move
                | FileAction::Share
                | FileAction::ShareExternal
                | FileAction::Delete
                | FileAction::Restore
                | FileAction::VersionRead
                | FileAction::VersionRestore
                | FileAction::ManagePermissions
                | FileAction::Sync => {}
            }
        }
    }

    Ok(computed)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a production
    // hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The needle these tests look for, assembled at run time.
    ///
    /// `docs/12-TESTING.md §1.2`: a test that asserts a string does *not* appear is a test whose
    /// needle appears in its own source. Two tests in this repository have already failed against
    /// themselves that way. The script tag is built rather than written so that a source-scanning
    /// gate reading this file finds no markup in it.
    fn script_open() -> String {
        format!("{}script{}", '<', '>')
    }

    fn field_codes(error: &Error) -> Vec<(String, ValidationCode)> {
        match error {
            Error::Validation(fields) => {
                fields.iter().map(|field| (field.field.clone(), field.code)).collect()
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_document_that_contains_markup_cannot_deliver_it_through_an_excerpt() {
        // The excerpt is document content and the field is defined to carry `<em>`. A body holding
        // a script tag must arrive as text, or every result row is a stored-XSS delivery vector.
        let body = format!("the {}alert(1) clause", script_open());
        let rendered = marked_up(&Excerpt::unlocated(body.clone()));

        assert!(!rendered.contains(&script_open()), "markup from a document survived: {rendered}");
        assert!(rendered.contains("&lt;script&gt;"), "the text must still be readable: {rendered}");
        assert!(!rendered.contains("<em>"), "an unlocated excerpt carries no markup: {rendered}");
    }

    #[test]
    fn a_located_excerpt_marks_the_matched_span_and_nothing_else() {
        // The positive control for the test above: without it, every assertion there passes against
        // a function that escapes everything and marks nothing.
        let text = "the perihelion review".to_owned();
        let excerpt =
            Excerpt::located(text, std::iter::once(4..14).collect()).expect("a well-formed span");

        assert_eq!(marked_up(&excerpt), "the <em>perihelion</em> review");
    }

    #[test]
    fn markup_is_applied_to_the_raw_offsets_and_escaping_does_not_move_them() {
        // The bug this forbids is escaping first and then slicing: `&` becomes five characters, so
        // every offset after it points into the middle of an entity and the `<em>` lands in the
        // wrong place — or panics.
        let text = "R&D perihelion".to_owned();
        let start = text.find("perihelion").expect("the fixture contains the term");
        let span = start..start + "perihelion".len();
        let excerpt = Excerpt::located(text, std::iter::once(span).collect()).expect("well-formed");

        assert_eq!(marked_up(&excerpt), "R&amp;D <em>perihelion</em>");
    }

    #[test]
    fn a_narrowing_filter_this_deployment_cannot_apply_is_refused_by_name() {
        let request = SearchRequest {
            query: Some("q".to_owned()),
            library_ids: Some(vec!["01937fa0-0000-7000-8000-000000000000".to_owned()]),
            classification_max: Some("INTERNAL".to_owned()),
            cursor: Some("opaque".to_owned()),
            ..SearchRequest::default()
        };

        let error = unsupported_narrowing(&request).expect_err("three filters must be refused");
        let codes = field_codes(&error);
        assert_eq!(
            codes,
            vec![
                ("libraryIds".to_owned(), ValidationCode::Unsupported),
                ("classificationMax".to_owned(), ValidationCode::Unsupported),
                ("cursor".to_owned(), ValidationCode::Unsupported),
            ],
            "every unapplied narrowing must be named at once"
        );
    }

    #[test]
    fn an_empty_filter_array_is_not_a_filter() {
        // `docs/05-API.md §11`'s own example sends `"workspaceIds": []` to mean everywhere. The
        // control that keeps the test above from passing for the wrong reason.
        let request = SearchRequest {
            query: Some("q".to_owned()),
            workspace_ids: Some(Vec::new()),
            library_ids: Some(Vec::new()),
            types: Some(Vec::new()),
            ..SearchRequest::default()
        };
        assert!(unsupported_narrowing(&request).is_ok());
    }

    #[test]
    fn an_unknown_request_field_is_refused_rather_than_dropped() {
        // A misspelled narrowing accepted and ignored returns more than the caller asked for, and
        // there is no field left to name in the refusal.
        let body = br#"{"query":"q","classificationMaximum":"INTERNAL"}"#;
        let decoded: Result<SearchRequest, _> = serde_json::from_slice(body);
        assert!(decoded.is_err(), "an unknown field must not decode");
    }

    #[test]
    fn a_limit_is_clamped_rather_than_rejected() {
        assert_eq!(accepted_limit(None), DEFAULT_LIMIT);
        assert_eq!(accepted_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(accepted_limit(Some(5)), 5);
        assert_eq!(accepted_limit(Some(10_000)), MAX_LIMIT);
    }

    #[test]
    fn an_empty_query_is_a_named_field_error() {
        assert_eq!(
            field_codes(&accepted_query(Some("   ")).expect_err("blank is not a query")),
            vec![("query".to_owned(), ValidationCode::Required)]
        );
        assert_eq!(
            field_codes(&accepted_query(None).expect_err("absent is not a query")),
            vec![("query".to_owned(), ValidationCode::Required)]
        );
        assert_eq!(accepted_query(Some("  budget  ")).expect("a real query"), "budget");
    }

    #[test]
    fn a_mode_this_route_does_not_know_is_refused_and_every_documented_one_is_accepted() {
        for mode in MODES {
            assert!(accepted_mode(Some(mode)).is_ok(), "{mode} is documented in docs/05 §11");
        }
        assert_eq!(
            field_codes(&accepted_mode(Some("magic")).expect_err("an invented mode")),
            vec![("mode".to_owned(), ValidationCode::Unsupported)]
        );
        assert!(accepted_mode(None).is_ok());
    }

    #[test]
    fn the_candidate_budget_over_fetches_and_stops_at_the_documented_cap() {
        // `docs/07 §5`: 3x, capped at 200. A budget equal to the page size is the bug this guards —
        // the post-filter drops what the caller may not see, so a page of 20 asked for as 20
        // candidates comes back short during exactly the incident the fallback exists for.
        let budget = |limit: u32| (limit.saturating_mul(OVERFETCH)).min(MAX_CANDIDATES);
        assert_eq!(budget(20), 60);
        assert_eq!(budget(MAX_LIMIT), 150);
        assert_eq!(budget(10_000), MAX_CANDIDATES);
    }
}
