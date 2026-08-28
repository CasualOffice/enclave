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
//! | `POST /files/{id}/print` | [`FileAction::Print`] | A page image, once, against a spent grant |
//! | `GET /files/{id}/thumbnail` | [`FileAction::Preview`] | A rendition, streamed once |
//!
//! The fourth is `ENC-724`. `ENC-720` shipped the mint and no way to spend what it minted, which
//! made the capability a value with nowhere to go; and it kept its live grants in a process-local
//! `HashMap`, which made single use a property of one replica's memory rather than of the system.
//! Both close together, because either alone is a half-feature: a redemption path over a map is
//! unusable behind a load balancer, and a table with nothing that reads it is a schema change.
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
//! [`print`] holds the pipeline, because it does serve bytes — and it holds no store, for the same
//! structural reason [`export`] does not. What it returns is a re-rendered page image, `inline` and
//! `no-store`, never the original and never a URL to one; the four independent reasons a print
//! cannot become a download are on that function.
//!
//! # Rule 9, on all three
//!
//! Every path reaches content through [`crate::preview::readable_version`], which returns a
//! [`ReadableVersion`] — a type with private fields whose only constructor is a query filtering
//! `enclave_preview::repo::READABLE_PREDICATE`. Nothing here can express a request to render or
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
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use chrono::Utc;
use enclave_core::{
    Action, Error, FileAction, FileId, Obligation, Obligations, RequestContext, RequestId,
    ResourceRef,
};
// `PrintGrant` is aliased because this module already has one: the wire type below is what a
// *caller* receives, and `StoredGrant` is what the database keeps. They are deliberately different
// shapes — the response carries the token and no version, the row carries the version and no token.
use enclave_preview::print::{self, PrintGrant as StoredGrant, PrintToken};
use enclave_preview::{Delivery, PreviewPipeline, ReadableVersion, RenditionProfile};
use serde::{Deserialize, Serialize};

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

/// The profile a redeemed print grant is served as.
///
/// `page-png-2x`, the highest-fidelity raster profile `crates/preview` can produce (`ENC-800`), and
/// deliberately **not** the same profile as `export`'s `png`, which is `page-png-1x`. Print goes to
/// paper at a physical resolution; a preview does not. It is also the reason the artefact is
/// composited rather than flattened: `mark` refuses anything that is not `image/png`, so a print
/// that had to carry a watermark and could not is a refusal rather than an unmarked page
/// (`ENC-723`).
const PRINT_PROFILE: RenditionProfile = RenditionProfile::PagePng2x;

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
    /// server does enforce it, and it enforces it in the *database* rather than in this process —
    /// `enclave_preview::print::redeem` is one `UPDATE … WHERE redeemed_at IS NULL … RETURNING`, so
    /// the property survives two replicas racing (`ENC-724`).
    single_use: bool,
    /// Where to spend it. `docs/05-API.md §9`'s redemption path, so a client does not have to
    /// assemble the URL from a convention nothing checks.
    redeem_at: String,
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
/// # What the grant is
///
/// A single-use, 120-second capability naming one tenant, one file, one version, one actor and one
/// session, spendable at [`print`] and nowhere else. Every one of those narrows it: a capability
/// naming only the file would be redeemable by whoever obtained the value, and one naming only the
/// actor would survive the version being replaced.
///
/// # Where the single-use property lives, and why it moved
///
/// In `print_tokens`, not in this process. `ENC-720` kept the live grants in a `HashMap` and said
/// so; that made "redeemed twice" unrepresentable *within one replica* and unenforceable across
/// two, which is every real deployment. `ENC-724` replaced it with one statement whose predicate
/// names the column it writes, so two concurrent redemptions on two machines produce exactly one
/// winner. A print token that could be redeemed twice would be a download with extra steps.
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
    // when it was minted. [`print`] asks the same question again of the *pinned* version, so a
    // quarantine that lands inside the 120-second window closes the grant too.
    let version = readable_version(&mut tx, &ctx, file, request_id).await?;

    let token = PrintToken::generate()
        .map_err(|error| ApiError::new(Error::Internal(error.into()), request_id))?;

    // Written inside the same transaction that established the version, so a grant is never
    // recorded against a version this request could not read. The token is not passed — only its
    // digest — so there is no path from here to a plaintext capability in the database or in a
    // statement log.
    let stored = StoredGrant {
        file,
        version: version.id(),
        actor: ctx.actor,
        session: ctx.session_id,
        watermark: required.watermark,
        expires_at: Utc::now() + PRINT_TOKEN_TTL,
    };
    print::issue(&mut tx, ctx.tenant_id, token.digest(), &stored)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let grant = PrintGrant {
        // The one and only time this value exists outside the caller's process. Only its SHA-256
        // was retained (`plans/M2-ACCESS-DELIVERY.md` D19).
        token: token.expose().to_owned(),
        expires_in: PRINT_TOKEN_TTL.as_secs(),
        single_use: true,
        redeem_at: format!("/api/v1/files/{}/print", file.as_uuid()),
        watermark: required.watermark,
    };

    // `no-store`, without exception. A response body that *is* a bearer capability must not be
    // written to a disk cache by anything between here and the caller.
    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(grant)).into_response())
}

// ---------------------------------------------------------------------------------------------
// POST /api/v1/files/{id}/print — ENC-724, the redemption
// ---------------------------------------------------------------------------------------------

/// The request body of `POST /files/{id}/print`.
///
/// The token is in the **body**, not the path. A capability in a URL is a capability in an access
/// log, a proxy log, a `Referer` header and a browser history entry, and this one is worth 120
/// seconds of somebody's confidential document. `docs/05-API.md §10`'s `GET /shares/{token}` puts a
/// share token in the path because a share link *is* a URL that gets pasted into an email; a print
/// grant is never seen by a human and has no such excuse.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrintRequest {
    /// The capability, as [`print_token`] returned it.
    #[serde(default)]
    pub token: Option<String>,
    /// Business justification, when policy demands one. Accepted here as well as at the mint
    /// because the chain runs again at redemption and may answer differently.
    #[serde(default)]
    pub justification: Option<String>,
}

/// Handles `POST /api/v1/files/{id}/print` — spends a grant and serves the page to print.
///
/// # Why this cannot be turned into a download
///
/// Four independent reasons, in the order they stop being bypassable:
///
/// 1. **It holds no [`BlobStore`](enclave_storage::BlobStore).** Like [`export`] and [`thumbnail`],
///    it takes a [`PreviewPipeline`], whose single method accepts a [`ReadableVersion`] and a
///    profile and returns bytes. There is no argument that can name an object key and no method
///    that mints a URL — "give me the original" is not expressible in the vocabulary this handler
///    holds. `docs/12-TESTING.md §4.2` A15 asserts that from the store's side, which is the only
///    side that can see the difference: the store's call list must be *empty* while this route
///    returns the pipeline's bytes.
/// 2. **What it returns is a re-rendered page, not the document.** [`PRINT_PROFILE`] is a raster
///    profile: the response is pixels. A PDF's embedded fonts, its attachments, its form fields,
///    its metadata, its revision history and its selectable text do not survive rasterisation. An
///    original round-trips; this does not.
/// 3. **It is `inline`, `no-store`, `nosniff` and sandboxed** — [`rendition_response`], the same
///    response the preview path builds, and deliberately *not* [`export_response`], whose single
///    difference is `Content-Disposition: attachment`. That header is the difference between a
///    document to display and a file to keep, which is why export is a separate permission.
/// 4. **It asks [`FileAction::Print`], not [`FileAction::Download`].** A caller holding `download`
///    and not `print` is refused here, and a caller holding `print` and not `download` is served —
///    which is `docs/12-TESTING.md §4.2` A2, asserted in both directions.
///
/// What it is *not* is a preview by another name: the artefact is the same class, and the
/// permission is not. Rule 6 splits the five verbs by the question each asks, not by the bytes each
/// happens to move.
///
/// # Why the chain runs again
///
/// `CLAUDE.md` rule 1 admits no exception for an entry point that already had a decision taken for
/// it: a grant minted 90 seconds ago is not a decision about *this* request, and an ACL withdrawn,
/// a barrier raised or a DLP rule added in between must take effect. Re-asking can only be
/// stricter, because the obligations of the two decisions are **unioned** — a mark required by
/// either the grant or the fresh decision is required.
///
/// Rule 9 is re-asked too, and against the *pinned* version rather than the file's current one:
/// [`enclave_preview::repo::readable_version`] re-evaluates `READABLE_PREDICATE`, so a version
/// quarantined inside the grant's lifetime closes the grant with it.
///
/// # Why a refusal rolls back rather than consuming the grant
///
/// The redemption happens inside the request's transaction, and every refusal below rolls it back
/// before it records anything. A caller refused for a reason that is not their fault — a mark this
/// principal cannot carry, a pipeline that has no rendition for this format — must not also lose
/// the capability they were legitimately issued. The rollback is what makes "spent" mean *served*.
///
/// The rollback happens **before** [`HandlerAudit::refuse`](crate::refusal::HandlerAudit::refuse),
/// never inside the open transaction: the audit write takes its own connection, and a handler that
/// held one while acquiring another is a pool deadlock waiting for load.
///
/// # Errors
///
/// [`ApiError`]. A `404` for an unknown, expired, already-redeemed, wrong-file, wrong-actor,
/// wrong-session or other-tenant token — **all of them the same answer**, because telling a
/// presenter their token was real but expired tells them it was real (`CLAUDE.md` rule 7).
pub async fn print(
    State(state): State<ApiState>,
    // A pipeline, and no store. See "why this cannot be turned into a download" above: this is the
    // whole storage vocabulary the print path is given.
    Extension(pipeline): Extension<Arc<dyn PreviewPipeline>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let request = match parse_print(&body) {
        Ok(request) => request,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    // Asked before the token is looked at, so a caller who may not print this file learns nothing
    // about whether their token was real — and so that no row is read before a decision exists.
    let decision = match state.policy.enforce(&ctx, PRINT, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    let obligations = decision.into_obligations();
    let required = match satisfy_print_redemption(&obligations, request.justification.as_deref()) {
        Ok(required) => required,
        Err(refused) => return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await),
    };

    // A value of the wrong shape is answered exactly as one that hashed to nothing. Distinguishing
    // them would be an oracle for the encoding, and there is no legitimate caller who benefits.
    let Some(token) = request.token.as_deref().and_then(PrintToken::parse) else {
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // One statement, and the only place the grant's contents are read. Seven ways to fail, one
    // `None` — see `enclave_preview::print::redeem`.
    let redeemed =
        print::redeem(&mut tx, ctx.tenant_id, file, ctx.actor, ctx.session_id, token.digest())
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;
    let Some(redeemed) = redeemed else {
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    // The union, not the grant's flag alone. The grant carries the mint-time decision so a policy
    // relaxed in between cannot un-require a mark; the fresh decision is honoured so a policy
    // *tightened* in between takes effect. Either side requiring it requires it.
    let watermark = required.watermark || redeemed.watermark;

    // Rule 9, re-asked against the version the grant pinned rather than the file's current one.
    // `None` here is a version that has been quarantined, deleted or superseded since the mint, and
    // it is the same `404` as an unknown token.
    let Some(version) =
        enclave_preview::repo::readable_version(&mut tx, ctx.tenant_id, redeemed.version)
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?
    else {
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    let viewer = if watermark {
        // A mark exists to attribute a leak to a person, and a print carries it onto paper where
        // the only forensic trace is what was drawn. A principal the mark cannot name is refused
        // rather than stamped "system", which satisfies the obligation on paper and not in fact.
        //
        // The grant should already make this unreachable — `satisfy_print` refuses a watermarked
        // mint to a non-person, and `redeem` binds the grant to that same actor — but the check is
        // here as well, because the *fresh* decision can add a `WATERMARK` the mint's did not have.
        let actor = match stampable(&ctx) {
            Ok(actor) => actor,
            Err(refused) => {
                tx.rollback().await.map_err(|error| ApiError::new(error.into(), request_id))?;
                return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await);
            }
        };
        Some(viewer_identity(&mut tx, &ctx, actor, request_id).await?)
    } else {
        None
    };

    let delivery = pipeline
        .deliver(&mut tx, ctx.tenant_id, &version, PRINT_PROFILE, Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let Delivery::Available { bytes, media_type, .. } = delivery else {
        // Nothing to print, and re-asking will not change it. The grant is *not* spent — the
        // rollback below is what makes that true — because a caller cannot be charged a capability
        // for a rendition this deployment cannot produce.
        tx.rollback().await.map_err(|error| ApiError::new(error.into(), request_id))?;
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    let bytes = if watermark {
        // `mark` refuses anything that is not `image/png`, which is what makes an unmarkable print
        // a refusal rather than an unmarked page leaving the building (`ENC-723`). Rule 8 has no
        // third answer, and this is composited *before* the commit so a refusal keeps the grant.
        match mark(bytes, &media_type, viewer.as_ref(), &ctx, file) {
            Ok(marked) => marked,
            Err(refused) => {
                tx.rollback().await.map_err(|error| ApiError::new(error.into(), request_id))?;
                return Err(state.audit.refuse(&ctx, PRINT, &resource, refused).await);
            }
        }
    } else {
        bytes
    };

    // The grant is spent here and nowhere earlier: everything above this line can still roll back.
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(rendition_response(bytes, &media_type, request_id))
}

/// Parses and validates the redemption body.
///
/// # Errors
///
/// A `400` envelope for a body that is absent, unreadable, or carries no `token` at all. That is
/// deliberately *not* the `404` a wrong token gets, and it leaks nothing: "you did not send a
/// token" is a statement about the request, while "your token is unknown" would be a statement
/// about what this tenant holds. A token that is present and unusable is answered by the handler as
/// an unknown one.
fn parse_print(body: &Bytes) -> Result<PrintRequest, Envelope> {
    let missing = || {
        Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "A print redemption must carry the grant it is spending.",
            "Send `token` with the value `POST /files/{id}/print-token` returned.",
        )
        .with_details(vec![serde_json::json!({ "field": "token", "code": "REQUIRED" })])
    };

    if body.is_empty() {
        return Err(missing());
    }
    let request: PrintRequest = serde_json::from_slice(body).map_err(|_error| {
        Envelope::new(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "The request body could not be read.",
            "Send an object with a `token` field.",
        )
    })?;

    if request.token.as_deref().is_none_or(str::is_empty) {
        return Err(missing());
    }
    Ok(request)
}

/// Honours every obligation the chain attached to a *redemption*, or turns it into a refusal.
///
/// Exhaustive, like its three siblings, and it differs from [`satisfy_print`] in exactly one arm —
/// which is the arm worth reading.
///
/// # `NO_DOWNLOAD` does not refuse a print, and this is the same answer the mint gives
///
/// `docs/06-SECURITY-DLP-ACCESS.md §5.2` defines no-download as *the product will not deliver an
/// original or a downloadable representation*. The export path refuses under it because a flattened
/// export **is** one: it is served `attachment`, it is a take-away, and that is what the verb means.
/// A redeemed print is the other thing — a server-composed page image, served `inline` and
/// `no-store`, the same artefact class `crates/api/src/preview.rs` already serves under this same
/// obligation without refusing, because "may look, may not keep" is precisely what no-download
/// says.
///
/// Reading it the other way would be rule 6's collapse arriving through the obligation set: a
/// tenant who wrote "no download, print allowed" would find `file.print` decides nothing, and the
/// separate permission the whole feature exists for would be decorative. Printing is refused by
/// denying `file.print`, which is a different question with its own answer.
///
/// # Errors
///
/// [`Refused`] when an obligation cannot be satisfied here. Recorded before it reaches the caller
/// (`ENC-606`).
fn satisfy_print_redemption(
    obligations: &Obligations,
    justification: Option<&str>,
) -> Result<crate::preview::Required, Refused> {
    let mut required = crate::preview::Required::default();
    for obligation in obligations {
        match *obligation {
            // See the header. Nor is this the sync path, and the response carries no mutation
            // affordance.
            Obligation::NoDownload | Obligation::NoSync | Obligation::ReadOnly => {}

            // Recorded, not discharged here. The caller composites it into the artefact before any
            // byte leaves and before the grant is spent, and refuses if it cannot.
            Obligation::Watermark => required.watermark = true,

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
                    "a reclassification obligation reached the print redemption path, which \
                     cannot apply one; refusing rather than printing under a stale label"
                );
                return Err(Refused::obligation(Obligation::Reclassify { to }));
            }
        }
    }
    Ok(required)
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

    use enclave_core::{Actor, ClassificationRank, ReasonCode, TenantId, UserId};

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
