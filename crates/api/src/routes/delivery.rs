//! Export, print and thumbnail — the three delivery verbs that had no way in.
//!
//! `CLAUDE.md` rule 6 splits delivery five ways: **preview ≠ download ≠ print ≠ export ≠ sync**.
//! `crates/core` has had five separate actions since M0, `crates/authorization` has resolved them
//! independently since `ENC-126`, and `docs/05-API.md §9` documents five paths. Until this module
//! the router registered two of them, so three-fifths of the control the product is sold on could
//! be configured, audited and simulated — and never exercised.
//!
//! | Route | Action asked of the chain | What it can serve |
//! |---|---|---|
//! | `POST /files/{id}/export` | [`FileAction::Export`] | A rendition, streamed once |
//! | `POST /files/{id}/print-token` | [`FileAction::Print`] | A capability, never a byte |
//! | `GET /files/{id}/thumbnail` | [`FileAction::Preview`] | A rendition, streamed once |
//!
//! # Why each route asks a different question, and how that is kept true
//!
//! Each handler names its action in a `const` at the top of its section, and passes that same
//! `const` to both `PolicyEngine::enforce` and [`HandlerAudit::refuse`](crate::refusal::HandlerAudit::refuse) —
//! the technique `crates/api/src/download.rs` established, so an audit row can never be attributed
//! to a different action from the decision it followed.
//!
//! The temptation this module exists to resist is reusing `Download`'s action because the work is
//! the same shape. It is not the same question: `docs/12-TESTING.md §4.2` A2 requires export and
//! print to be *independently* deniable, and a caller holding `download` and not `export` must be
//! refused here. `tests/delivery_routes.rs` asserts that in both directions, each paired with the
//! positive control — the same caller, with the grant, succeeding.
//!
//! **The thumbnail is deliberately not a sixth verb.** It asks [`FileAction::Preview`], because a
//! thumbnail *is* a preview rendition: `docs/05-API.md §9` lists it under preview, and `§7`'s
//! `capabilities` object — which `CLAUDE.md` requires the UI to render from, and which
//! `crates/api/src/content.rs` builds from nine named actions — has no `thumbnail` key to enforce
//! against. Inventing a `FileAction::Thumbnail` would put an action on the wire that no ACL row, no
//! DLP rule and no simulation can name. What rule 6 forbids is collapsing the five *delivery*
//! verbs into one; answering a thumbnail with `Download`'s action is what that collapse would have
//! looked like here.
//!
//! # No original ever leaves by these routes, and not because they decline to send one
//!
//! Neither [`export`] nor [`thumbnail`] takes a [`BlobStore`](enclave_storage::BlobStore). They
//! take [`PreviewPipeline`], whose single method accepts a [`ReadableVersion`] and a profile and
//! returns bytes: there is no argument that can name an object key and no method that mints a URL.
//! The request "give me the original" is not something the vocabulary these handlers hold can
//! express — the same property `crates/api/src/preview.rs` documents at length, and the reason
//! `tests/delivery_routes.rs` asserts the store's call list is *empty* rather than asserting the
//! response body looks right.
//!
//! [`print_token`] holds neither. It mints a capability and cannot render, so there is no path
//! from it to any byte of anything.
//!
//! # Rule 9, on all three
//!
//! Every path reaches content through [`crate::preview::readable_version`], which returns a
//! [`ReadableVersion`] — a type with private fields whose only constructor is a query filtering
//! `status = 'AVAILABLE' AND av_status = 'CLEAN'`. Nothing here can express a request to render or
//! grant something antivirus has not cleared.
//!
//! # Rule 8, on all three
//!
//! Every obligation is matched exhaustively, and every arm either discharges it or returns a
//! [`Refused`] — which has no conversion into an error except
//! [`HandlerAudit::refuse`](crate::refusal::HandlerAudit::refuse), so the second audit row is
//! written by the type system rather than by remembering (`ENC-606`). The three `satisfy` functions
//! differ, and each difference is a decision worth reading:
//!
//! * **`NO_DOWNLOAD` refuses an export.** `docs/06-SECURITY-DLP-ACCESS.md §5.2` defines no-download
//!   as *the product will not deliver an original or downloadable representation*, and a flattened
//!   export is a downloadable representation. This is the arm `FileAction::Export`'s own
//!   documentation calls "the download path that a naive download-blocking policy misses".
//! * **`NO_DOWNLOAD` does not refuse a print grant.** A grant carries no bytes and no URL, which is
//!   exactly what that obligation constrains. Printing is refused by denying `file.print`, which is
//!   a different question and has its own answer — treating the obligation as an implicit no-print
//!   would be rule 6's collapse arriving through the obligation set instead of through the action.
//! * **`WATERMARK` is discharged where it can be and refuses where it cannot.** An export as `png`
//!   is composited (`ENC-169`); an export as `pdf` is refused, because `crates/preview` has no PDF
//!   compositor (`ENC-723`). A print grant records the requirement on the capability and refuses a
//!   principal the mark could not name.

use core::str::FromStr as _;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, Error, FileAction, FileId, Obligation, Obligations, RequestContext, RequestId,
    ResourceRef, SessionId, TenantId, VersionId,
};
use enclave_preview::{Delivery, PreviewPipeline, ReadableVersion, RenditionProfile};
use rand::rand_core::TryRng as _;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::auth::Authenticated;
use crate::download::conceal_if_not_visible;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::preview::{mark, readable_version, rendition_response, stampable, viewer_identity};
use crate::refusal::Refused;
use crate::state::ApiState;

// =============================================================================================
// POST /api/v1/files/{id}/export — ENC-719
// =============================================================================================

/// The action the export route asks the chain about, and the one its refusals are recorded against.
///
/// Never [`FileAction::Download`]. The two are separately grantable in `acl_entries`, separately
/// answerable by `authorize_many`, and separately reported in `capabilities`; a handler that asked
/// the download question here would make all three of those decorative.
const EXPORT: Action = Action::File(FileAction::Export);

/// The request body of `docs/05-API.md §9`: `{ "format": "pdf" }`.
///
/// `justification` is not in the document's example and is accepted because the obligation is:
/// [`Obligation::RequireJustification`] can reach an export exactly as it reaches a download, and a
/// path that could not carry the justification would have to refuse every DLP policy that asks for
/// one. It is never logged and never echoed — user-authored text about a file (`CLAUDE.md` rule 10).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// The artefact to produce. Required: an export with no format is not a defaulting question,
    /// because the two supported formats differ in whether a watermark can be applied at all.
    #[serde(default)]
    pub format: Option<String>,
    /// Business justification, when policy demands one.
    #[serde(default)]
    pub justification: Option<String>,
}

/// Handles `POST /api/v1/files/{id}/export`.
///
/// A `POST` for the reason `docs/05-API.md §9` gives for download: it is not a read. It runs the
/// chain, writes an audit row, may demand a justification, and produces an artefact that leaves the
/// building.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an obligation this path cannot discharge, an absent or
/// unscanned file, or a rendition pipeline that could not answer. Absence and denial are
/// deliberately indistinguishable — see [`conceal_if_not_visible`].
pub async fn export(
    State(state): State<ApiState>,
    // Not a `BlobStore`. See the module header: this is the whole storage vocabulary the export
    // path is given, and it cannot express "the original bytes".
    Extension(pipeline): Extension<Arc<dyn PreviewPipeline>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    // Caller-controlled input, validated before the chain is asked anything. It reveals nothing
    // about the tenant's content: the answer is the same for a file that exists and one that does
    // not, which is why it is safe to answer first.
    let request = match parse_export(&body) {
        Ok(request) => request,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    // `Export`, and only `Export`. A caller who may download this file and may not export it does
    // not get past this line.
    let decision = match state.policy.enforce(&ctx, EXPORT, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    let obligations = decision.into_obligations();
    let required = match satisfy_export(&obligations, request.justification.as_deref()) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, EXPORT, &resource, refused).await),
    };

    // Asked before the transaction opens, and only when a mark is required — the same ordering
    // `crates/api/src/preview.rs` uses and for the same two reasons: the audit write below takes
    // its own connection, and a refusal must not happen while this request holds a tenant-scoped
    // transaction open across somebody else's network.
    let stamp = if required.watermark {
        match stampable(&ctx) {
            Ok(actor) => Some(actor),
            Err(refused) => return Err(state.audit.refuse(&ctx, EXPORT, &resource, refused).await),
        }
    } else {
        None
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let version = readable_version(&mut tx, &ctx, file, request_id).await?;

    let viewer = match stamp {
        Some(actor) => Some(viewer_identity(&mut tx, &ctx, actor, request_id).await?),
        None => None,
    };

    let delivery = pipeline
        .deliver(&mut tx, ctx.tenant_id, &version, request.profile, Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    match delivery {
        // No export for this version in this format, and re-asking will not change it. A `404`
        // rather than a `415`: telling the caller *why* would distinguish "this format has no
        // export" from "this file has none", which is a fact about content.
        Delivery::Unavailable(refusal) => {
            tracing::debug!(refusal = refusal.as_str(), "no export for this version");
            Err(ApiError::new(Error::NotFound, request_id))
        }
        Delivery::Available { bytes, media_type, .. } => {
            let bytes = if required.watermark {
                // `mark` refuses anything that is not `image/png`, which is what makes a
                // watermarked `pdf` export a refusal rather than an unmarked artefact leaving the
                // building (`ENC-723`). Rule 8 has no third answer.
                match mark(bytes, &media_type, viewer.as_ref(), &ctx, file) {
                    Ok(marked) => marked,
                    Err(refused) => {
                        return Err(state.audit.refuse(&ctx, EXPORT, &resource, refused).await)
                    }
                }
            } else {
                bytes
            };
            Ok(export_response(bytes, &media_type, request_id))
        }
    }
}

/// A validated export request: the caller's format resolved to a pipeline profile.
#[derive(Debug, PartialEq, Eq)]
struct ValidatedExport {
    profile: RenditionProfile,
    justification: Option<String>,
}

/// The formats this endpoint answers to, and the profile each names.
///
/// `pdf` is the format `docs/05-API.md §9` writes in its example and the one
/// `docs/06-SECURITY-DLP-ACCESS.md §5.1` contemplates flattening a watermark into. `png` is here
/// because it is the one the deployed renderer can actually produce today — `RasterRenderer`
/// supports `thumb` and `page-png-1x`, and `pdf-sanitized` is still answered by `NoRenderer` until
/// D17's out-of-process worker lands. Offering only `pdf` would have shipped an endpoint that
/// returns `404` for every file in the product.
///
/// A closed list rather than a `RenditionProfile` parsed from the wire: `html-sanitized` is not an
/// export, and a caller naming a profile directly would be choosing the pipeline's internals.
fn export_profile(format: &str) -> Option<RenditionProfile> {
    match format {
        "pdf" => Some(RenditionProfile::PdfSanitized),
        "png" => Some(RenditionProfile::PagePng1x),
        _ => None,
    }
}

/// Parses and validates the export body.
///
/// # Errors
///
/// A `400` envelope naming the offending field, per `docs/05-API.md §5`. The message never repeats
/// the caller's input: `serde_json`'s own text quotes the body, and the body of a request this
/// endpoint has decided nothing about is not something to echo.
fn parse_export(body: &Bytes) -> Result<ValidatedExport, Envelope> {
    let malformed = || {
        Envelope::new(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "The request body could not be read.",
            "Send an object with a `format` field, for example `{\"format\":\"pdf\"}`.",
        )
    };

    let request: ExportRequest = if body.is_empty() {
        ExportRequest::default()
    } else {
        serde_json::from_slice(body).map_err(|_error| malformed())?
    };

    let Some(format) = request.format.as_deref() else {
        return Err(Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "An export must say which format it wants.",
            "Send `format` as one of `pdf` or `png`.",
        )
        .with_details(vec![serde_json::json!({ "field": "format", "code": "REQUIRED" })]));
    };

    let Some(profile) = export_profile(format) else {
        return Err(Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "That export format is not supported.",
            "Send `format` as one of `pdf` or `png`.",
        )
        .with_details(vec![serde_json::json!({ "field": "format", "code": "UNSUPPORTED" })]));
    };

    Ok(ValidatedExport { profile, justification: request.justification })
}

/// Honours every obligation the chain attached to an export, or turns it into a refusal.
///
/// Exhaustive on purpose, like its siblings on the download and preview paths: [`Obligation`] is
/// not `#[non_exhaustive]`, so a new obligation breaks this function and forces somebody to decide
/// what it means for a caller about to receive an artefact they can keep.
///
/// # Errors
///
/// [`Refused`] when an obligation cannot be satisfied here. Recorded by the caller before it
/// becomes the client's `403` (`ENC-606`); the codes come from [`Obligation::unsatisfied_code`],
/// which is where D29 puts them so two surfaces cannot answer the same obligation differently.
fn satisfy_export(
    obligations: &Obligations,
    justification: Option<&str>,
) -> Result<crate::preview::Required, Refused> {
    let mut required = crate::preview::Required::default();
    for obligation in obligations {
        match *obligation {
            // The arm `FileAction::Export` exists for. `docs/06 §5.2`: no-download means the
            // product will not deliver an original *or a downloadable representation*, and a
            // flattened export is the second of those. A path that treated this as satisfied —
            // "these are not the original bytes" — is precisely the naive download-blocking policy
            // the export action was split out to defeat.
            Obligation::NoDownload => return Err(Refused::obligation(Obligation::NoDownload)),

            // Recorded, not discharged here. The caller composites it into the artefact before any
            // byte leaves, and refuses if it cannot — which for a `pdf` export it cannot, because
            // nothing in `crates/preview` marks a PDF (`ENC-723`).
            Obligation::Watermark => required.watermark = true,

            Obligation::RequireJustification => {
                let supplied = justification.is_some_and(|text| !text.trim().is_empty());
                if !supplied {
                    // The row records that a justification was required and absent. It never
                    // records the text of one that was supplied (`CLAUDE.md` rule 10).
                    return Err(Refused::obligation(Obligation::RequireJustification));
                }
            }

            // A workflow this endpoint cannot start. Refusing with the code that names it is what
            // lets a client offer the right next step instead of a dead end.
            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }

            // Satisfied by construction: the response is one artefact and carries no mutation
            // affordance, and this is not the sync path — `FileAction::Sync` is a separate action
            // against a separate endpoint, which is the point of them being separate (rule 6).
            Obligation::ReadOnly | Obligation::NoSync => {}

            // A write this handler does not perform. Refused rather than dropped (rule 8); the rank
            // stays out of the row, being DLP's finding about the content (rule 10).
            Obligation::Reclassify { to } => {
                tracing::warn!(
                    "a reclassification obligation reached the export path, which cannot apply \
                     one; refusing rather than exporting under a stale label"
                );
                return Err(Refused::obligation(Obligation::Reclassify { to }));
            }
        }
    }
    Ok(required)
}

/// Builds the response around an exported artefact.
///
/// Differs from [`rendition_response`] in exactly one header, and that header is the difference
/// between the two endpoints: `attachment` rather than `inline`. An export is a take-away — that is
/// what makes it a separate permission — so the disposition says so, and the caller's browser
/// treats it as a file rather than as a document to display.
///
/// No `filename` is offered. The name is the tenant's content, and this response is already
/// `no-store`; a caller who may export a file can read its name from `GET /files/{id}`, which is a
/// separately authorized read.
fn export_response(bytes: Vec<u8>, media_type: &str, request_id: RequestId) -> Response {
    let mut response = Response::new(bytes.into());
    let headers = response.headers_mut();

    if let Ok(value) = HeaderValue::from_str(media_type) {
        let _previous = headers.insert(header::CONTENT_TYPE, value);
    }
    // An export of `PREVIEW_ONLY`-adjacent content sitting in a shared cache is that content
    // available without the policy chain, and a watermarked artefact in one is a viewer's identity
    // served to somebody else (`docs/06 §5.1`).
    let _previous = headers.insert(header::CACHE_CONTROL, NO_STORE);
    let _previous = headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    let _previous =
        headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        let _previous = headers.insert("x-request-id", value);
    }
    response
}

// =============================================================================================
// POST /api/v1/files/{id}/print-token — ENC-720
// =============================================================================================

/// The action the print route asks the chain about, and the one its refusals are recorded against.
const PRINT: Action = Action::File(FileAction::Print);

/// How long a print grant is valid for.
///
/// The same 120 seconds `docs/05-API.md §9` fixes for a signed download URL, and for the same
/// reason `plans/M1-CONTENT-CORE.md` D14 gives: the lifetime *is* the revocation window. A grant
/// is minted at the moment a person asks to print and is meant to be spent immediately; a longer
/// window buys nothing a second request would not, and costs the difference between a capability
/// and a standing right.
const PRINT_TOKEN_TTL: Duration = Duration::from_secs(120);

/// Bytes of entropy in a print token.
///
/// 256 bits, with no structure. The same size and the same reasoning as `crates/auth`'s refresh
/// token: there is nothing in it to guess, nothing to enumerate, and no field an attacker can vary.
const PRINT_TOKEN_BYTES: usize = 32;

/// The request body of `POST /files/{id}/print-token`.
///
/// `docs/05-API.md §9` documents no body. One is accepted, and may be absent, for the reason
/// [`ExportRequest::justification`] is accepted: the obligation can arrive here.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrintTokenRequest {
    /// Business justification, when policy demands one.
    #[serde(default)]
    pub justification: Option<String>,
}

/// What a caller receives: the token, once, and the terms it comes with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrintGrant {
    /// The capability. Returned here and nowhere else — only its SHA-256 is retained, so this
    /// response is the only time the value exists outside the caller's process.
    token: String,
    /// Seconds of validity, so a client can decide whether to re-request rather than spend a dead
    /// grant.
    expires_in: u64,
    /// Whether redeeming it consumes it. Always `true`, and reported rather than assumed for the
    /// reason `DownloadGrant::single_use` is reported: a client that displayed a property the
    /// server did not enforce would be making a promise the deployment cannot keep. Here the
    /// server does enforce it — [`PrintTokens::redeem`] removes the entry — so the field is a
    /// statement of what happened, and it is asserted by a test that redeems twice.
    single_use: bool,
    /// Whether whatever redeems this grant must carry the viewer's mark.
    ///
    /// Carried on the grant rather than re-derived at redemption, because the obligation belongs to
    /// the decision that was taken *here*, with this actor's context, and a redemption that asked
    /// the question again could get a different answer from a policy edited in between — in the
    /// permissive direction.
    watermark: bool,
}

/// Handles `POST /api/v1/files/{id}/print-token`.
///
/// # What the grant is, and what it is not
///
/// It is a single-use, 120-second capability naming one tenant, one file, one version, one actor
/// and one session. It is **not** a token any endpoint accepts yet: `docs/05-API.md §9` documents
/// the mint and no redemption path, and inventing one in an implementation change would be adding
/// a delivery surface that no document describes and no leakage-matrix row covers. `ENC-724` closes
/// that, specification first.
///
/// What exists today is therefore the mint, the binding and the single-use registry that makes
/// "redeemed twice" unrepresentable — [`PrintTokens::redeem`] removes the entry it returns, so a
/// second presentation of the same value finds nothing whether it arrives in a millisecond or an
/// hour. A print token that could be redeemed twice would be a download with extra steps.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an obligation this path cannot discharge, an absent or
/// unscanned file, or an operating system that declined to provide entropy.
pub async fn print_token(
    State(state): State<ApiState>,
    // No pipeline and no store. This handler mints a capability; it has no vocabulary in which to
    // ask for a byte of anything, which is why "did the print path leak the original" is not a
    // question that can be asked of it.
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let request = match parse_print_token(&body) {
        Ok(request) => request,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    // `Print`, and only `Print`. "May print but may not keep a copy" is the policy
    // `FileAction::Print` exists to express, so a caller with `download` and no `print` is refused
    // here and a caller with `print` and no `download` is not.
    let decision = match state.policy.enforce(&ctx, PRINT, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    let obligations = decision.into_obligations();
    let required = match satisfy_print(&obligations, request.justification.as_deref(), &ctx) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await),
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Rule 9. The grant names a version, and the only version it can name is one antivirus has
    // cleared — so a grant cannot outlive a quarantine by referring to something that was readable
    // when it was minted.
    let version = readable_version(&mut tx, &ctx, file, request_id).await?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let now = Utc::now();
    let capability = PrintCapability {
        tenant: ctx.tenant_id,
        file,
        version: version.id(),
        actor: ctx.actor,
        session: ctx.session_id,
        watermark: required.watermark,
        expires_at: now + PRINT_TOKEN_TTL,
    };

    let token = PRINT_TOKENS
        .issue(capability, now)
        .map_err(|error| ApiError::new(Error::Internal(error), request_id))?;

    let grant = PrintGrant {
        token,
        expires_in: PRINT_TOKEN_TTL.as_secs(),
        single_use: true,
        watermark: required.watermark,
    };

    // `no-store`, without exception. A response body that *is* a bearer capability must not be
    // written to a disk cache by anything between here and the caller.
    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(grant)).into_response())
}

/// Parses the optional print-token body.
///
/// # Errors
///
/// A `400` envelope when a body is present and unreadable. An absent body is the ordinary case —
/// a print with no justification obligation sends nothing.
fn parse_print_token(body: &Bytes) -> Result<PrintTokenRequest, Envelope> {
    if body.is_empty() {
        return Ok(PrintTokenRequest::default());
    }
    serde_json::from_slice(body).map_err(|_error| {
        Envelope::new(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "The request body could not be read.",
            "Send nothing, `{}`, or an object with `justification`.",
        )
    })
}

/// Honours every obligation the chain attached to a print grant, or turns it into a refusal.
///
/// # Errors
///
/// [`Refused`] when an obligation cannot be satisfied here — including a watermark required of a
/// principal that is not a person. Recorded before it reaches the caller (`ENC-606`).
fn satisfy_print(
    obligations: &Obligations,
    justification: Option<&str>,
    ctx: &RequestContext,
) -> Result<crate::preview::Required, Refused> {
    let mut required = crate::preview::Required::default();
    for obligation in obligations {
        match *obligation {
            // Satisfied by construction, and the reasoning is the opposite of the export path's.
            // [`Obligation::NoDownload`] constrains what may be *served*: no original bytes, no
            // object-storage URL. This response carries neither, and cannot — the handler holds no
            // store and no pipeline. Whether this caller may print at all is `file.print`, which
            // the chain has just answered on its own terms; reading `NO_DOWNLOAD` as an implicit
            // no-print would be rule 6's collapse arriving through the obligation set.
            //
            // Nor is it the sync path, and the response carries no mutation affordance.
            Obligation::NoDownload | Obligation::NoSync | Obligation::ReadOnly => {}

            // Recorded onto the capability. Nothing is served here, so nothing can be served
            // unmarked; what must not happen is a grant that is redeemable without the mark, and
            // the flag on the stored capability is what stops it.
            //
            // The principal is checked *here*, inside the function that decides the obligations,
            // rather than at the call site the preview and export paths use — and that is the
            // finding rather than a preference. With the check at the call site, deleting it
            // entirely failed **nothing**: every caller in every HTTP test is a signed-in person,
            // and no unit test can reach a line inside an `async fn` taking `State`, three
            // extractors and a database.
            //
            // A mark exists to attribute a leak to a person, and a print carries it onto paper
            // where the only forensic trace is what was drawn. So a grant that would have to be
            // marked is refused unless the principal is somebody the mark can name — refused, not
            // stamped "system", which satisfies the obligation on paper and not in fact.
            Obligation::Watermark => {
                let _actor = stampable(ctx)?;
                required.watermark = true;
            }

            Obligation::RequireJustification => {
                let supplied = justification.is_some_and(|text| !text.trim().is_empty());
                if !supplied {
                    return Err(Refused::obligation(Obligation::RequireJustification));
                }
            }

            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }

            Obligation::Reclassify { to } => {
                tracing::warn!(
                    "a reclassification obligation reached the print path, which cannot apply one; \
                     refusing rather than granting a print under a stale label"
                );
                return Err(Refused::obligation(Obligation::Reclassify { to }));
            }
        }
    }
    Ok(required)
}

// ---------------------------------------------------------------------------------------------
// The print capability, and the registry that makes it single-use.
// ---------------------------------------------------------------------------------------------

/// What one print grant permits, and to whom.
///
/// Every field narrows it. A capability that named only the file would be redeemable by anyone who
/// obtained the token; one that named only the actor would survive the version being replaced. The
/// session is here because `docs/06 §5.1` puts a session reference in the watermark itself — a
/// printed page is attributable to one sign-in, and the grant that produced it should be too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintCapability {
    /// The tenant the grant was minted in. Never taken from a redeeming request (`CLAUDE.md`
    /// rule 3) — compared against the redeemer's verified tenant.
    pub tenant: TenantId,
    /// The file. One grant, one document.
    pub file: FileId,
    /// The version, resolved at mint time from [`readable_version`], so a grant cannot come to
    /// refer to content uploaded after it was issued.
    pub version: VersionId,
    /// Who asked. A grant is not transferable.
    pub actor: Actor,
    /// Which sign-in. `None` only for principals that have no session.
    pub session: Option<SessionId>,
    /// Whether the artefact this grant is spent on must carry the viewer's mark.
    pub watermark: bool,
    /// When it stops being redeemable, whether or not anything has swept it.
    expires_at: DateTime<Utc>,
}

/// Why a presented print token was not honoured.
///
/// Two variants, and callers should render them as one answer. They are distinguished here so a
/// metric can tell a client that is too slow from a client that is replaying, and *not* so that a
/// response body can: telling a presenter that their token was real but expired confirms that it
/// was real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintRedemption {
    /// No live grant hashes to this value: never issued, already spent, or already swept.
    Unknown,
    /// A grant was found and its lifetime had elapsed. It is removed by the attempt.
    Expired,
}

/// The live print grants this process has issued.
///
/// # What is stored, and what is not
///
/// The key is `SHA-256(token)`; the token itself is never retained. That is
/// `plans/M2-ACCESS-DELIVERY.md` D19 — *a share link's token is never stored* — applied to the
/// other capability in the delivery surface, and for the same reason: what is not held cannot be
/// read out of a dump, a core file or a `Debug` line. A 256-bit uniform value needs no
/// key-stretching for the reason `crates/auth::refresh` gives; there is no dictionary.
///
/// # Why single use is a removal rather than a flag
///
/// A `used: bool` is a read, a decision and a write, which is the shape that lets two concurrent
/// redemptions both observe `false` — the same defect `plans/M2-ACCESS-DELIVERY.md` D18 forbids for
/// download budgets. [`HashMap::remove`] under one lock is atomic, so exactly one caller can
/// receive any capability.
///
/// # The limit, stated
///
/// This map is process-local. A grant minted on one replica cannot be redeemed on another, which
/// makes print unusable behind a load balancer and is recorded as `ENC-724` rather than hidden. It
/// fails in the safe direction — a cross-replica presentation is *refused*, never honoured a second
/// time — and the fix is a `print_tokens` table, which is a migration this change did not own.
#[derive(Debug, Default)]
pub struct PrintTokens {
    live: Mutex<HashMap<[u8; 32], PrintCapability>>,
}

/// The process-wide registry.
///
/// A `static` rather than a field on [`ApiState`], deliberately and temporarily: the durable home
/// for a print grant is a table (`ENC-724`), and threading a map through the state, the router and
/// `main.rs` would build the wiring for a component that is about to be replaced by one which needs
/// none of it — while touching two files another change is editing.
static PRINT_TOKENS: LazyLock<PrintTokens> = LazyLock::new(PrintTokens::default);

impl PrintTokens {
    /// Mints a token for a capability and returns it, once.
    ///
    /// Expired entries are swept on every issue, so the map is bounded by the number of grants
    /// minted inside one TTL rather than by the process's lifetime.
    ///
    /// # Errors
    ///
    /// [`anyhow::Error`] when the operating system declines to provide randomness. Propagated
    /// rather than unwrapped, for the reason `crates/auth`'s equivalent gives: a capability minted
    /// from a degraded entropy source is worse than no capability at all, and a caller can retry.
    pub fn issue(&self, capability: PrintCapability, now: DateTime<Utc>) -> anyhow::Result<String> {
        let mut bytes = [0_u8; PRINT_TOKEN_BYTES];
        SysRng.try_fill_bytes(&mut bytes).map_err(|_error| {
            anyhow::anyhow!("the operating system declined to provide entropy")
        })?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();

        let mut live = self.live.lock().map_err(|_error| {
            anyhow::anyhow!("the print-token registry lock was poisoned by a panicking holder")
        })?;
        live.retain(|_digest, held| held.expires_at > now);
        let _previous = live.insert(digest, capability);
        Ok(token)
    }

    /// Spends a token, returning the capability it named.
    ///
    /// The entry is removed whether the outcome is success *or* expiry: an expired grant has no
    /// further use, and leaving it in place would let a presenter distinguish "expired" from
    /// "unknown" by presenting it twice.
    ///
    /// # Errors
    ///
    /// [`PrintRedemption`] when nothing live hashes to this value. A second presentation of a
    /// successfully redeemed token lands on [`PrintRedemption::Unknown`], which is the property
    /// that keeps a print grant from being a download.
    pub fn redeem(
        &self,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<PrintCapability, PrintRedemption> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut live = self.live.lock().map_err(|_error| PrintRedemption::Unknown)?;
        let Some(capability) = live.remove(&digest) else {
            return Err(PrintRedemption::Unknown);
        };
        if capability.expires_at <= now {
            return Err(PrintRedemption::Expired);
        }
        Ok(capability)
    }

    /// How many grants are live. For tests and for a future gauge; never for a response body.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.lock().map_or(0, |live| live.len())
    }

    /// Whether any grant is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================================
// GET /api/v1/files/{id}/thumbnail — ENC-721
// =============================================================================================

/// The action the thumbnail route asks the chain about.
///
/// [`FileAction::Preview`] — see the module header for why a thumbnail is not a sixth delivery
/// verb, and why answering it with `Download`'s action is the mistake that reasoning rules out.
const THUMBNAIL: Action = Action::File(FileAction::Preview);

/// The thumbnail sizes a caller may ask for.
///
/// A closed set rather than a range, because `size` is caller-controlled input that will one day
/// become part of a rendition cache key: an open integer turns a typo into a permanent cache miss
/// and an attacker's loop into a renderer that never idles.
const THUMBNAIL_SIZES: &[u32] = &[64, 128, 256, 512];

/// The size served when a caller names none — `docs/05-API.md §9`'s own example value.
const DEFAULT_THUMBNAIL_SIZE: u32 = 256;

/// Query parameters of `GET /files/{id}/thumbnail?size=256`.
///
/// Unknown parameters are ignored rather than rejected, as on the preview path: clients add
/// cache-busters, and a thumbnail that failed because of one is a support ticket, not a control.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThumbnailQuery {
    /// The longest edge the caller wants, in pixels.
    ///
    /// A `String` rather than a `u32` so `?size=abc` is refused with the `docs/05-API.md §5`
    /// envelope rather than with axum's own extractor rejection, which answers in a shape no client
    /// of this API parses.
    #[serde(default)]
    pub size: Option<String>,
}

/// Handles `GET /api/v1/files/{id}/thumbnail`.
///
/// A `GET`, unlike its two neighbours here, because it *is* a read: it spends no budget, grants
/// nothing, and produces the same identity-free artefact for every caller who may see it — until a
/// watermark obligation applies, at which point the response stops being cacheable and the headers
/// say so.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an obligation this path cannot discharge, or an absent,
/// trashed or unscanned file — the last three being deliberately indistinguishable from the first.
pub async fn thumbnail(
    State(state): State<ApiState>,
    // Not a `BlobStore`. A thumbnail is a rendition; there is no version of this endpoint that
    // answers with the original, because there is no way to ask for one from here.
    Extension(pipeline): Extension<Arc<dyn PreviewPipeline>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    Query(query): Query<ThumbnailQuery>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let _size = match validate_size(&query) {
        Ok(size) => size,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    let decision = match state.policy.enforce(&ctx, THUMBNAIL, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    // The preview path's obligation logic, not a copy of it. A thumbnail is a preview rendition, so
    // an obligation that shapes one must shape the other; two functions that had to be kept in step
    // by hand is how the two would eventually disagree about what a watermark means.
    let obligations = decision.into_obligations();
    let required = match crate::preview::satisfy(&obligations) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, THUMBNAIL, &resource, refused).await),
    };

    let stamp = if required.watermark {
        match stampable(&ctx) {
            Ok(actor) => Some(actor),
            Err(refused) => {
                return Err(state.audit.refuse(&ctx, THUMBNAIL, &resource, refused).await)
            }
        }
    } else {
        None
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let version: ReadableVersion = readable_version(&mut tx, &ctx, file, request_id).await?;

    let viewer = match stamp {
        Some(actor) => Some(viewer_identity(&mut tx, &ctx, actor, request_id).await?),
        None => None,
    };

    let delivery = pipeline
        .deliver(&mut tx, ctx.tenant_id, &version, RenditionProfile::Thumb, Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    match delivery {
        Delivery::Unavailable(refusal) => {
            tracing::debug!(refusal = refusal.as_str(), "no thumbnail for this version");
            Err(ApiError::new(Error::NotFound, request_id))
        }
        Delivery::Available { bytes, media_type, .. } => {
            let bytes = if required.watermark {
                match mark(bytes, &media_type, viewer.as_ref(), &ctx, file) {
                    Ok(marked) => marked,
                    Err(refused) => {
                        return Err(state.audit.refuse(&ctx, THUMBNAIL, &resource, refused).await)
                    }
                }
            } else {
                bytes
            };
            // The preview path's response, header for header. `docs/05-API.md §9` requires
            // `private, no-store` on preview responses and `docs/06 §5.1` requires that a
            // watermarked image is never cached; a thumbnail that carried a `max-age` would be the
            // one delivery response in the product a shared cache could serve without the chain,
            // and it would be the smallest and most-requested one. Caching a rendition is the
            // *rendition store's* job (`plans/M2-ACCESS-DELIVERY.md` D15), keyed by version and
            // profile, behind the policy chain — not the browser's, keyed by URL, in front of it.
            Ok(rendition_response(bytes, &media_type, request_id))
        }
    }
}

/// Validates the requested thumbnail size.
///
/// # What the returned value does today, honestly
///
/// Nothing. `crates/preview` has one `thumb` profile whose longest edge is a constant 320 px, so
/// every accepted size resolves to the same artefact. The parameter is nonetheless parsed and
/// bounded here rather than ignored, for two reasons: `docs/05-API.md §9` documents it, so a client
/// sending it must not be rejected; and the moment a per-size profile exists, the thing that
/// decides which sizes are renderable must already be a closed list rather than a caller-supplied
/// integer that has been reaching the pipeline unchecked in the meantime.
///
/// # Errors
///
/// A `400` envelope naming `size`, per `docs/05-API.md §5`.
fn validate_size(query: &ThumbnailQuery) -> Result<u32, Envelope> {
    let Some(raw) = query.size.as_deref() else {
        return Ok(DEFAULT_THUMBNAIL_SIZE);
    };
    match raw.parse::<u32>() {
        Ok(size) if THUMBNAIL_SIZES.contains(&size) => Ok(size),
        _ => Err(Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "That thumbnail size is not one this service produces.",
            "Omit `size`, or send one of 64, 128, 256 or 512.",
        )
        .with_details(vec![serde_json::json!({ "field": "size", "code": "OUT_OF_RANGE" })])),
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ClassificationRank, ReasonCode, UserId};

    use super::*;

    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }

    /// A request from an ordinary signed-in person — the principal a watermark can name.
    fn person() -> RequestContext {
        let mut ctx = RequestContext::system(TenantId::new_v7());
        ctx.actor = Actor::User(UserId::new_v7());
        ctx
    }

    /// The code a refusal carries, or `None` when the obligations were satisfiable.
    fn refused<T>(result: Result<T, Refused>) -> Option<ReasonCode> {
        result.err().map(Refused::code)
    }

    // -----------------------------------------------------------------------------------------
    // Export
    // -----------------------------------------------------------------------------------------

    /// The arm `FileAction::Export` was split out of `Download` to provide.
    #[test]
    fn no_download_refuses_an_export_because_an_export_is_a_downloadable_representation() {
        assert_eq!(
            refused(satisfy_export(&obligations([Obligation::NoDownload]), None)),
            Some(ReasonCode::PreviewOnly),
            "a no-download obligation must refuse an export (docs/06 §5.2)"
        );
    }

    /// A watermark is a *requirement* on an export, not a refusal and not a shrug.
    ///
    /// The third assertion is the control: an ordinary export must carry no such requirement, or
    /// every response would pay for a composite and an identity lookup it does not need — and this
    /// test would pass against a function that set the flag unconditionally.
    #[test]
    fn a_watermark_obligation_is_recorded_on_an_export_rather_than_dropped() {
        let required = satisfy_export(&obligations([Obligation::Watermark]), None)
            .expect("a watermark is dischargeable on a png export, so it is not a refusal");
        assert!(required.watermark);

        let plain = satisfy_export(&Obligations::none(), None).expect("an unconditional allow");
        assert!(!plain.watermark);
    }

    #[test]
    fn an_export_requires_a_justification_and_whitespace_is_not_one() {
        let required = obligations([Obligation::RequireJustification]);
        assert_eq!(
            refused(satisfy_export(&required, None)),
            Some(ReasonCode::DlpJustificationRequired)
        );
        assert_eq!(
            refused(satisfy_export(&required, Some("  \t "))),
            Some(ReasonCode::DlpJustificationRequired)
        );
        assert!(satisfy_export(&required, Some("Client audit request #4412")).is_ok());
    }

    #[test]
    fn approval_and_reclassification_refuse_an_export_rather_than_proceed() {
        assert_eq!(
            refused(satisfy_export(&obligations([Obligation::RequireApproval]), Some("why"))),
            Some(ReasonCode::DlpApprovalRequired)
        );
        assert_eq!(
            refused(satisfy_export(
                &obligations([Obligation::Reclassify { to: ClassificationRank::new(40) }]),
                Some("why")
            )),
            Some(ReasonCode::AccessDenied)
        );
    }

    #[test]
    fn obligations_that_shape_a_response_do_not_block_an_export() {
        assert!(
            satisfy_export(&obligations([Obligation::ReadOnly, Obligation::NoSync]), None).is_ok()
        );
    }

    #[test]
    fn the_export_vocabulary_is_closed_and_names_no_pipeline_internal() {
        assert_eq!(export_profile("pdf"), Some(RenditionProfile::PdfSanitized));
        assert_eq!(export_profile("png"), Some(RenditionProfile::PagePng1x));
        // A caller must not be able to choose the pipeline's internals. `html-sanitized` is a
        // preview form, not an artefact anyone exports, and `thumb` is not an export at all.
        for name in ["html-sanitized", "thumb", "page-png-2x", "pdf-sanitized", "", "PDF"] {
            assert!(export_profile(name).is_none(), "`{name}` must not name an export format");
        }
    }

    #[test]
    fn an_export_without_a_format_is_refused_rather_than_defaulted() {
        // Defaulting would pick between `pdf` and `png`, and those two differ in whether a
        // watermark can be applied at all — so the choice is not the server's to make silently.
        let refusal = parse_export(&Bytes::new()).expect_err("an empty body names no format");
        assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
        let refusal =
            parse_export(&Bytes::from_static(b"{}")).expect_err("an empty object names no format");
        assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn an_export_body_carries_the_documented_shape() {
        let parsed = parse_export(&Bytes::from_static(
            br#"{"format":"pdf","justification":"Client audit request #4412"}"#,
        ))
        .expect("the shape docs/05-API.md §9 documents");
        assert_eq!(parsed.profile, RenditionProfile::PdfSanitized);
        assert_eq!(parsed.justification.as_deref(), Some("Client audit request #4412"));

        for body in [&b"not json"[..], br#"{"format":"docx"}"#, br#"{"format":42}"#] {
            let refusal = parse_export(&Bytes::from_static(body))
                .expect_err("an unusable export body must be refused");
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
        }
    }

    /// An export says it is a take-away; a preview says it is not. That is the one header apart.
    #[test]
    fn an_export_response_is_an_attachment_and_is_never_cached() {
        let response =
            export_response(vec![b'%', b'P', b'D', b'F'], "application/pdf", RequestId::new_v7());
        let headers = response.headers();
        assert_eq!(
            headers.get(header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()),
            Some("attachment"),
            "an export is a take-away and the disposition must say so"
        );
        assert_eq!(
            headers.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("private, no-store")
        );
        assert_eq!(
            headers.get("x-content-type-options").and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/pdf")
        );
        // And no filename, which would be the tenant's content on a header that survives caching
        // proxies and shell history.
        let disposition =
            headers.get(header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(
            !disposition.contains("filename"),
            "a filename reached the response: {disposition}"
        );
    }

    // -----------------------------------------------------------------------------------------
    // Print
    // -----------------------------------------------------------------------------------------

    /// The obligation asymmetry between print and export, asserted as a pair.
    ///
    /// Written as one test because the two arms are one decision: `NO_DOWNLOAD` constrains what may
    /// be *served*, a grant serves nothing, and an export serves a downloadable representation. A
    /// change that made them agree would be a change to what no-download means, and it should fail
    /// here rather than pass quietly on whichever half somebody edited.
    #[test]
    fn no_download_refuses_an_export_and_does_not_refuse_a_print_grant() {
        let no_download = obligations([Obligation::NoDownload]);
        assert!(
            satisfy_print(&no_download, None, &person()).is_ok(),
            "a print grant carries no bytes and no URL, so a no-download obligation constrains \
             nothing about it; whether this caller may print is `file.print`, which the chain \
             answered on its own terms"
        );
        assert_eq!(
            refused(satisfy_export(&no_download, None)),
            Some(ReasonCode::PreviewOnly),
            "an export delivers a downloadable representation and must be refused"
        );
    }

    #[test]
    fn a_print_grant_records_a_watermark_requirement_rather_than_dropping_it() {
        let required = satisfy_print(&obligations([Obligation::Watermark]), None, &person())
            .expect("a watermark is recorded on the grant, not refused at the mint");
        assert!(required.watermark);

        let plain = satisfy_print(&obligations([Obligation::NoDownload]), None, &person())
            .expect("ordinary");
        assert!(!plain.watermark, "an ordinary print grant must not demand a mark");
    }

    #[test]
    fn blocking_obligations_refuse_a_print_grant() {
        assert_eq!(
            refused(satisfy_print(
                &obligations([Obligation::RequireJustification]),
                None,
                &person()
            )),
            Some(ReasonCode::DlpJustificationRequired)
        );
        assert!(satisfy_print(
            &obligations([Obligation::RequireJustification]),
            Some("Board pack, hard copy for the meeting"),
            &person()
        )
        .is_ok());
        assert_eq!(
            refused(satisfy_print(
                &obligations([Obligation::RequireApproval]),
                Some("why"),
                &person()
            )),
            Some(ReasonCode::DlpApprovalRequired)
        );
        assert_eq!(
            refused(satisfy_print(
                &obligations([Obligation::Reclassify { to: ClassificationRank::new(40) }]),
                Some("why"),
                &person()
            )),
            Some(ReasonCode::AccessDenied)
        );
    }

    /// A print grant that would have to be marked names a person, or is refused.
    ///
    /// `ENC-720`'s own finding, and the reason the check moved into [`satisfy_print`]: while it sat
    /// at the handler's call site, deleting it entirely failed **nothing** — the whole workspace
    /// stayed green, because every caller in every HTTP test is a signed-in person.
    ///
    /// The last case is the control that keeps this from being "refuse every machine": a service
    /// account with no watermark obligation may hold a print grant. The refusal is about an
    /// obligation this principal cannot discharge, not about the principal.
    #[test]
    fn a_watermarked_print_grant_names_a_person_or_is_refused() {
        let tenant = TenantId::new_v7();

        let system = RequestContext::system(tenant);
        assert_eq!(
            refused(satisfy_print(&obligations([Obligation::Watermark]), None, &system)),
            Some(ReasonCode::AccessDenied),
            "the system actor has no name to stamp onto a printed page"
        );

        let mut machine = RequestContext::system(tenant);
        machine.actor = Actor::ServiceAccount(enclave_core::ServiceAccountId::new_v7());
        assert_eq!(
            refused(satisfy_print(&obligations([Obligation::Watermark]), None, &machine)),
            Some(ReasonCode::AccessDenied),
            "a service account is not a person either"
        );

        // The controls. A real viewer is granted, or nothing prints at all...
        assert!(
            satisfy_print(&obligations([Obligation::Watermark]), None, &person()).is_ok(),
            "a person must be able to hold a watermarked print grant"
        );
        // ...and the same machine is granted an *unmarked* print, so the refusal above is about an
        // obligation this principal cannot discharge rather than about the principal.
        assert!(
            satisfy_print(&Obligations::none(), None, &machine).is_ok(),
            "a service account was refused a print grant that required no mark"
        );
    }

    fn capability(now: DateTime<Utc>) -> PrintCapability {
        PrintCapability {
            tenant: TenantId::new_v7(),
            file: FileId::new_v7(),
            version: VersionId::new_v7(),
            actor: Actor::User(UserId::new_v7()),
            session: Some(SessionId::new_v7()),
            watermark: true,
            expires_at: now + PRINT_TOKEN_TTL,
        }
    }

    /// **A print token that can be redeemed twice is a download.**
    ///
    /// The first redemption is the positive control, and it is not decoration: an assertion that
    /// the second redemption fails passes for free against a registry that never honours anything.
    #[test]
    fn a_print_token_is_spent_by_being_redeemed() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let minted = capability(now);

        let token = tokens.issue(minted, now).expect("mint");
        assert_eq!(tokens.len(), 1);

        let redeemed = tokens.redeem(&token, now).expect("the first redemption must succeed");
        assert_eq!(redeemed, minted, "the grant that came back is not the grant that went in");

        assert_eq!(
            tokens.redeem(&token, now),
            Err(PrintRedemption::Unknown),
            "the same token was honoured twice, which makes a print grant a download"
        );
        assert!(tokens.is_empty(), "a spent grant must not be left in the registry");
    }

    /// The lifetime is the whole revocation window, so it has to actually bound something.
    #[test]
    fn a_print_token_stops_being_redeemable_when_its_lifetime_elapses() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let token = tokens.issue(capability(now), now).expect("mint");

        let one_tick_early = now + PRINT_TOKEN_TTL - chrono::Duration::seconds(1);
        let expired = now + PRINT_TOKEN_TTL + chrono::Duration::seconds(1);

        // Control first: it is redeemable inside the window, or the assertion below proves nothing.
        let live = PrintTokens::default();
        let live_token = live.issue(capability(now), now).expect("mint");
        assert!(live.redeem(&live_token, one_tick_early).is_ok());

        assert_eq!(
            tokens.redeem(&token, expired),
            Err(PrintRedemption::Expired),
            "an elapsed grant was still honoured"
        );
        assert!(tokens.is_empty(), "an expired grant must be removed by the attempt");
    }

    #[test]
    fn a_token_nobody_issued_is_refused_and_is_not_distinguishable_from_a_spent_one() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let spent = tokens.issue(capability(now), now).expect("mint");
        let _capability = tokens.redeem(&spent, now).expect("spend it");

        for presented in [spent.as_str(), "", "not-a-token", &"A".repeat(43)] {
            assert_eq!(
                tokens.redeem(presented, now),
                Err(PrintRedemption::Unknown),
                "presenting `{presented}` must be answered exactly as an unknown token"
            );
        }
    }

    /// The token itself is never retained — only its digest (`D19`).
    ///
    /// A source-level assertion would be the wrong kind of check here; this one is behavioural. The
    /// registry is asked for its entire contents through the one accessor it has, and the token is
    /// not derivable from anything in it.
    #[test]
    fn the_registry_holds_a_digest_and_never_the_token() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let token = tokens.issue(capability(now), now).expect("mint");

        let live = tokens.live.lock().expect("lock");
        assert_eq!(live.len(), 1);
        let (digest, _capability) = live.iter().next().expect("one entry");
        let expected: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        assert_eq!(digest, &expected, "the key is not SHA-256 of the token");
        assert_ne!(
            &digest[..],
            token.as_bytes(),
            "the token itself is in the registry, which D19 forbids"
        );
    }

    #[test]
    fn expired_grants_are_swept_so_the_registry_is_bounded_by_the_lifetime() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let _stale = tokens.issue(capability(now), now).expect("mint");
        assert_eq!(tokens.len(), 1);

        // The next mint, after the first has expired, must not leave two entries behind.
        let later = now + PRINT_TOKEN_TTL + chrono::Duration::seconds(1);
        let _fresh = tokens.issue(capability(later), later).expect("mint");
        assert_eq!(tokens.len(), 1, "an expired grant survived a later mint");
    }

    #[test]
    fn two_grants_never_share_a_token() {
        let tokens = PrintTokens::default();
        let now = Utc::now();
        let first = tokens.issue(capability(now), now).expect("mint");
        let second = tokens.issue(capability(now), now).expect("mint");
        assert_ne!(first, second, "two mints produced one token");
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&first).expect("base64url").len(),
            PRINT_TOKEN_BYTES,
            "a print token is not 256 bits of entropy"
        );
    }

    #[test]
    fn a_print_token_lifetime_matches_the_signed_url_window() {
        // Both are 120 s and both are the whole revocation window (D14). A change here is a change
        // to how long a capability outlives the decision that produced it.
        assert_eq!(PRINT_TOKEN_TTL.as_secs(), 120);
    }

    // -----------------------------------------------------------------------------------------
    // Thumbnail
    // -----------------------------------------------------------------------------------------

    #[test]
    fn an_omitted_thumbnail_size_falls_back_to_the_documented_default() {
        assert_eq!(
            validate_size(&ThumbnailQuery::default()).expect("no parameters is valid"),
            DEFAULT_THUMBNAIL_SIZE
        );
        assert_eq!(DEFAULT_THUMBNAIL_SIZE, 256, "docs/05-API.md §9 writes ?size=256");
    }

    #[test]
    fn a_thumbnail_size_outside_the_closed_set_is_refused() {
        for size in ["0", "255", "1024", "abc", "-1", "", "256 "] {
            let query = ThumbnailQuery { size: Some(size.to_owned()) };
            let refusal = validate_size(&query).expect_err("an unusable size must fail");
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST, "`{size}` was accepted");
        }
        // The control: every documented size is accepted, or the assertion above is passing
        // because the function refuses everything.
        for size in THUMBNAIL_SIZES {
            let query = ThumbnailQuery { size: Some(size.to_string()) };
            assert_eq!(validate_size(&query).expect("a permitted size"), *size);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Rule 6, at the level where it is easiest to break
    // -----------------------------------------------------------------------------------------

    /// The three routes ask three different questions of the chain.
    ///
    /// A unit test rather than only an HTTP one, because the failure it guards against is a
    /// copy-paste: these constants are what both `enforce` and the audit row are built from, and
    /// two of them being equal would silently make one endpoint enforce the other's permission
    /// while every status code in the suite stayed the same.
    #[test]
    fn each_delivery_route_enforces_its_own_action() {
        assert_eq!(EXPORT, Action::File(FileAction::Export));
        assert_eq!(PRINT, Action::File(FileAction::Print));
        assert_eq!(THUMBNAIL, Action::File(FileAction::Preview));

        assert_ne!(EXPORT, PRINT);
        assert_ne!(EXPORT, THUMBNAIL);
        assert_ne!(PRINT, THUMBNAIL);

        // And none of them is `Download`, which is the specific collapse rule 6 names.
        for action in [EXPORT, PRINT, THUMBNAIL] {
            assert_ne!(
                action,
                Action::File(FileAction::Download),
                "a delivery route is asking the download question"
            );
        }

        // The audit vocabulary follows the action, so the three are distinguishable in the log too.
        assert_eq!(EXPORT.verb(), "export");
        assert_eq!(PRINT.verb(), "print");
        assert_eq!(THUMBNAIL.verb(), "preview");
    }
}
