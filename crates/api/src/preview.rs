//! `GET /api/v1/files/{id}/preview` — viewing without taking away.
//!
//! `docs/01-PRD.md §18`: a user may hold `FILE_PREVIEW=ALLOW` with `FILE_DOWNLOAD=DENY`. That
//! sentence is the product's central claim, and the only thing that makes it true is that this
//! handler asks the policy chain a *different question* from the download handler and has no way
//! to answer it with the original bytes.
//!
//! Two properties keep it honest, and both are structural rather than remembered:
//!
//! 1. **The action is [`FileAction::Preview`].** Never `Download`, never a generic read — there is
//!    no generic read (`enclave_core::FileAction` explains why at length).
//! 2. **This module cannot reach object storage.** The handler takes no
//!    [`BlobStore`](enclave_storage::BlobStore): not "it does not call it", but it is not in scope.
//!    A future edit that wanted to serve the original from here would have to add the extractor,
//!    which is a diff a reviewer notices.
//!
//! # What it serves, and what it structurally cannot
//!
//! A base rendition, produced by `crates/preview` and read back through
//! [`PreviewPipeline`](enclave_preview::PreviewPipeline). That trait has one method, taking a
//! version and a profile and returning bytes: no way to name an object key, no method that mints a
//! URL. So the handler still cannot ask for the original — not because it declines to, but because
//! the vocabulary it holds cannot express the request. Property 2 above, one level in.
//!
//! This endpoint returned `501` until `ENC-148`, and the reason is worth keeping: streaming
//! originals "until renditions land" would have collapsed `preview` and `download` into one
//! permission on the path where the collapse is least visible — a caller with
//! `preview=ALLOW, download=DENY` receiving exactly what the deny was about.
//!
//! # The obligation the `501` was hiding
//!
//! `satisfy` used to treat [`Obligation::Watermark`] as satisfied, on the honest grounds that
//! nothing was rendered at all so nothing could be served unwatermarked. Removing the `501` turned
//! that arm into a silent obligation drop — `CLAUDE.md` rule 8, and the one this module would have
//! violated by succeeding.
//!
//! So a watermark obligation now **refuses** the preview. `crates/preview` composes the layer
//! (`ENC-147`) but nothing rasterises SVG over a PNG server-side yet, and the alternative — send
//! the base and an overlay and let the client combine them — is not a control: a client that
//! simply does not draw the overlay gets an unmarked page. Refusing is the safe direction and the
//! honest one; `ENC-169` is the compositor that lifts it.
//!
use core::str::FromStr as _;

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use enclave_core::{
    Action, Error, FileAction, FileId, Obligation, Obligations, ReasonCode, RequestContext,
    RequestId, ResourceRef,
};
use enclave_files::FileRepository;
use enclave_preview::{Delivery, PreviewPipeline, ReadableVersion, RenditionProfile};
use serde::Deserialize;

use crate::auth::Authenticated;
use crate::download::{conceal_if_not_visible, Envelope};
use crate::error::ApiError;
use crate::state::ApiState;

/// The rendition profile used when a caller names none.
///
/// `docs/05-API.md §9` uses `page-png-2x` in its example; it is the profile a browser at the usual
/// device pixel ratio wants.
const DEFAULT_PROFILE: &str = "page-png-2x";

/// The hard page limit of `docs/06-SECURITY-DLP-ACCESS.md §5`.
///
/// Document parsers are a large attack surface and a page number is caller-controlled input, so it
/// is bounded before it reaches anything that would allocate per page.
const MAX_PAGE: u32 = 10_000;

/// The longest profile name that can name a real profile.
const MAX_PROFILE_LEN: usize = 64;

/// Query parameters of `GET /files/{id}/preview` (`docs/05-API.md §9`).
///
/// Unknown parameters are ignored rather than rejected: clients add cache-busters, and a preview
/// that failed because of one would be a support ticket, not a control.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewQuery {
    /// 1-based page of a paginated document.
    ///
    /// A `String` rather than a `u32` so that `?page=abc` is refused by [`validate`] with the
    /// `docs/05-API.md §5` envelope, rather than by `axum`'s own extractor rejection, which
    /// answers in a shape no client of this API is parsing.
    #[serde(default)]
    pub page: Option<String>,
    /// The rendition profile to produce.
    #[serde(default)]
    pub profile: Option<String>,
}

/// What the rendition pipeline will be asked for, once validated.
#[derive(Debug, PartialEq, Eq)]
struct Rendition {
    profile: String,
    page: u32,
}

/// Handles `GET /api/v1/files/{id}/preview`.
///
/// Returns `501` with a machine-readable reason once the chain has allowed and the file has been
/// found: a caller who may not preview this file learns that first, so the unimplemented pipeline
/// never becomes a way to probe for files.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or an absent, trashed or unscanned file — the two being
/// deliberately indistinguishable (see [`conceal_if_not_visible`]).
pub async fn preview(
    State(state): State<ApiState>,
    // Not a `BlobStore`. See the module documentation: this is the whole of the storage vocabulary
    // this handler is given, and it cannot express "the original".
    Extension(pipeline): Extension<Arc<dyn PreviewPipeline>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    Query(query): Query<PreviewQuery>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let rendition = match validate(&query) {
        Ok(rendition) => rendition,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;
    let resource = ResourceRef::file(ctx.tenant_id, file);

    // `Preview`, and only `Preview`. A caller whose download is denied reaches this line; a caller
    // whose preview is denied does not, whatever their download rights say.
    let decision =
        match state.policy.enforce(&ctx, Action::File(FileAction::Preview), &resource).await {
            Ok(decision) => decision,
            Err(error) => {
                let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
                return Err(ApiError::new(error, request_id));
            }
        };

    let obligations = decision.into_obligations();
    let required = satisfy(&obligations).map_err(|error| ApiError::new(error, request_id))?;

    let profile = profile_for(&rendition.profile)
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Rule 9, on the read path where it matters most: a preview of a file antivirus has not cleared
    // is still a parse of hostile bytes by our own renderer. The witness this returns is the only
    // way to reach the pipeline, so an unscanned version cannot be rendered even by mistake.
    let version = readable_version(&mut tx, &ctx, file, request_id).await?;

    // Read inside the same tenant-scoped transaction as everything else, and only when a mark is
    // actually required — a preview with no watermark obligation must not pay for a lookup, and
    // must not read a viewer's email at all.
    let viewer = if required.watermark {
        Some(viewer_identity(&mut tx, &ctx, request_id).await?)
    } else {
        None
    };

    let delivery = pipeline
        .deliver(&mut tx, ctx.tenant_id, &version, profile, chrono::Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    match delivery {
        // A document that will not render is a `404`, not a `415` or a `501`. The caller asked for
        // the preview of a file, and there is none — telling them *why* would distinguish "this
        // format has no preview" from "this file has none", which is a fact about content they may
        // not be able to read.
        Delivery::Unavailable(refusal) => {
            tracing::debug!(refusal = refusal.as_str(), "no rendition for this version");
            Err(ApiError::new(Error::NotFound, request_id))
        }
        Delivery::Available { bytes, media_type, .. } => {
            let bytes = if required.watermark {
                mark(bytes, &media_type, &viewer, &ctx, file, request_id)?
            } else {
                bytes
            };
            Ok(rendition_response(bytes, &media_type, request_id))
        }
    }
}

/// Who is looking, for the mark.
///
/// Read here rather than carried on [`RequestContext`] because a token says *which* principal, not
/// what they are called — and a display name and an email are exactly the fields that must be
/// current at the moment of viewing, not as of whenever the token was issued.
#[derive(Debug, Clone)]
struct Viewer {
    display_name: String,
    email: String,
}

/// Reads the viewer's name and email inside the caller's transaction.
///
/// # Errors
///
/// `404` if the actor has no user row in this tenant, which is the same answer as a missing file —
/// a session whose subject has been deleted must not be told that it has been.
async fn viewer_identity(
    tx: &mut enclave_db::TenantScoped,
    ctx: &RequestContext,
    request_id: RequestId,
) -> Result<Viewer, ApiError> {
    use sqlx::Row as _;

    let enclave_core::Actor::User(actor) = ctx.actor else {
        // A service account or the system has no name to stamp. Refused rather than marked
        // "system": a watermark exists to attribute a leak to a person, and one naming nobody in
        // particular is a mark that satisfies the obligation on paper and not in fact.
        return Err(ApiError::new(Error::denied(ReasonCode::AccessDenied), request_id));
    };

    let row = sqlx::query("SELECT email, display_name FROM users WHERE tenant_id = $1 AND id = $2")
        .bind(ctx.tenant_id.as_uuid())
        .bind(actor.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| ApiError::new(enclave_db::DbError::Query(error).into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    Ok(Viewer {
        email: row.try_get("email").map_err(|_| ApiError::new(Error::NotFound, request_id))?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| ApiError::new(Error::NotFound, request_id))?,
    })
}

/// Burns the viewer's identity into the rendition, or refuses.
///
/// The refusal is the point. `CLAUDE.md` rule 8: an obligation is satisfied or the operation fails.
/// There is no arm here that serves the bytes anyway — not for an unsupported media type, not for a
/// name the bundled face cannot draw, not for a base the compositor cannot decode.
fn mark(
    bytes: Vec<u8>,
    media_type: &str,
    viewer: &Option<Viewer>,
    ctx: &RequestContext,
    file: FileId,
    request_id: RequestId,
) -> Result<Vec<u8>, ApiError> {
    let Some(viewer) = viewer.as_ref() else {
        // Unreachable while `required.watermark` is the only thing that populates it; kept as a
        // refusal rather than an `expect` so that a future edit which separates the two cannot turn
        // a missing viewer into an unmarked page.
        return Err(ApiError::new(Error::denied(ReasonCode::AccessDenied), request_id));
    };

    // Raster profiles only. `HtmlSanitized` wants the SVG overlay `enclave_preview::watermark`
    // already produces, inside the markup — a different composition, not this one, and serving
    // unmarked HTML while that is unwritten is precisely what rule 8 forbids.
    if media_type != "image/png" {
        tracing::info!(media_type, "no watermark compositor for this rendition; refusing");
        return Err(ApiError::new(Error::denied(ReasonCode::AccessDenied), request_id));
    }

    let facts = enclave_preview::WatermarkFacts {
        viewer_name: viewer.display_name.clone(),
        viewer_email: viewer.email.clone(),
        // Formatted here, in UTC with an explicit offset, because `docs/14-I18N-L10N.md` puts a
        // watermark in the *viewer's* locale and time zone and this handler does not yet know
        // either. UTC stated plainly is honest; a local-looking time that is actually UTC is not.
        issued_at: chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
        // The file and the session, which is what makes a photographed screen attributable to one
        // document and one sign-in rather than to an account. Identifiers rather than names: a file
        // name is content, and content does not belong in a mark that will be screenshotted and
        // pasted into a ticket.
        file_reference: file.as_uuid().to_string(),
        session_reference: ctx
            .session_id
            .map(|session| session.as_uuid().to_string())
            .unwrap_or_default(),
        // The classification label belongs here (`docs/06 §5.1`) and the classification stage is
        // still a deny-by-default stub, so there is nothing truthful to write. Omitted rather than
        // guessed: a mark asserting "Confidential" on content nobody classified is worse than one
        // that says nothing about sensitivity.
        classification: None,
    };

    enclave_preview::composite_watermark(&bytes, &facts, enclave_preview::WatermarkStyle::DEFAULT)
        .map_err(|refusal| {
            tracing::info!(?refusal, "the watermark could not be composited; refusing the preview");
            ApiError::new(Error::denied(ReasonCode::AccessDenied), request_id)
        })
}

/// Builds the response around a rendition's bytes.
///
/// Every header here is a control rather than a nicety:
///
/// * **`no-store`.** A rendition of `PREVIEW_ONLY` content in a shared cache is that content
///   available without the policy chain. The same header the download path sets, for the same
///   reason.
/// * **`nosniff`.** The media type comes from the profile, and without this a browser is free to
///   disagree with it — which is how a rendition gets interpreted as something it is not.
/// * **`Content-Disposition: inline`.** Preview is viewing; an `attachment` would put a
///   download-shaped affordance on the path whose entire purpose is that downloading is separable.
/// * **`sandbox`.** `docs/05-API.md` requires it for HTML renditions; it is set for every profile
///   because a header that is only correct for some responses is one somebody forgets to set on the
///   next one.
fn rendition_response(bytes: Vec<u8>, media_type: &str, request_id: RequestId) -> Response {
    let mut response = Response::new(bytes.into());
    let headers = response.headers_mut();

    if let Ok(value) = HeaderValue::from_str(media_type) {
        let _previous = headers.insert(header::CONTENT_TYPE, value);
    }
    let _previous = headers.insert(header::CACHE_CONTROL, NO_STORE);
    let _previous = headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    let _previous = headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    let _previous = headers.insert(
        "content-security-policy",
        HeaderValue::from_static("sandbox; default-src 'none'; img-src 'self' data:"),
    );
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        let _previous = headers.insert("x-request-id", value);
    }
    response
}

/// A rendition is never cached by anything between here and the viewer.
const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

/// Maps the wire profile name onto the pipeline's vocabulary.
///
/// `None` for a name no profile answers to. The caller gets the same `404` as for a file that does
/// not exist: a distinct error would let an unauthenticated probe enumerate which profiles a
/// deployment's renderer supports, which is a description of its attack surface.
fn profile_for(name: &str) -> Option<RenditionProfile> {
    name.parse::<RenditionProfile>().ok()
}

/// Obtains the witness that a servable version exists behind this file, or reports absence.
///
/// Returns `enclave_preview::ReadableVersion`, which has private fields and one constructor — a
/// query filtering `status = 'AVAILABLE' AND av_status = 'CLEAN'`. That is what makes rule 9
/// structural on this path rather than remembered: the pipeline takes the witness by reference, so
/// a caller cannot express a request to render something quarantined.
///
/// The file row is still read first, and separately, because `files` is where "folder", "trashed"
/// and "belongs to another tenant" live — three answers that must be the same `404` as "no readable
/// version" and would otherwise have three different shapes.
async fn readable_version(
    tx: &mut enclave_db::TenantScoped,
    ctx: &RequestContext,
    file: FileId,
    request_id: RequestId,
) -> Result<ReadableVersion, ApiError> {
    // Row-level security is the second layer here, independent of the chain above: `TenantScoped`
    // has set `app.tenant_id`, so a file belonging to another tenant is not filtered out of this
    // query — it is invisible to the transaction (PR #22).
    let node = FileRepository::find_by_id(tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    if node.is_folder() {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    let current =
        node.current_version_id.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    enclave_preview::repo::readable_version(tx, ctx.tenant_id, current)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))
}

/// Honours every obligation the chain attached to a preview, or turns it into a refusal.
///
/// Exhaustive for the same reason as the download path's version: adding an obligation must break
/// this function rather than fall into a wildcard that ignores it.
///
/// # Errors
///
/// [`Error::PolicyDenied`] when an obligation cannot be satisfied on this path.
fn satisfy(obligations: &Obligations) -> Result<Required, Error> {
    let mut required = Required::default();
    for obligation in obligations {
        match *obligation {
            // The expected pair on a preview, and both are satisfied by what this path is: a
            // rendition, never the original, and never a URL to it. That is a property of the
            // module (it holds no `BlobStore`), not a decision taken here.
            Obligation::NoDownload | Obligation::NoSync => {}

            // Recorded, not discharged here. This function decides nothing about the mark; it
            // says the response must carry one, and the caller composites it into the pixels before
            // any byte leaves. If that composition fails, the caller refuses — an obligation is
            // satisfied or the operation fails (`CLAUDE.md` rule 8), and there is no third answer
            // in which a rendition is served unmarked.
            //
            // It is burned into the artefact rather than sent alongside it, because an overlay the
            // client is asked to draw is an overlay a client can decline to draw, and the
            // obligation exists precisely because the page must identify whoever is looking at it.
            Obligation::Watermark => required.watermark = true,

            // A preview mutates nothing, and the response carries no mutation affordance.
            Obligation::ReadOnly => {}

            // Blocking obligations. The caller must do something before *any* exposure, and a
            // rendition is an exposure.
            Obligation::RequireJustification => {
                return Err(Error::denied(ReasonCode::DlpJustificationRequired))
            }
            Obligation::RequireApproval => {
                return Err(Error::denied(ReasonCode::DlpApprovalRequired))
            }

            // A write this handler cannot perform. Refused rather than dropped (`CLAUDE.md`
            // rule 8); the audit row the chain wrote carries the obligation for the operator.
            Obligation::Reclassify { .. } => {
                tracing::warn!(
                    "a reclassification obligation reached the preview path, which cannot apply \
                     one; refusing rather than rendering under a stale label"
                );
                return Err(Error::denied(ReasonCode::AccessDenied));
            }
        }
    }
    Ok(required)
}

/// What the response must carry before it may leave.
///
/// A struct rather than a `bool` because the next obligation this path learns to discharge — a
/// print restriction, a classification banner — belongs beside it, and a second `bool` returned
/// from the same function is how call sites start passing them in the wrong order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Required {
    /// The rendition must be marked with the viewer's identity.
    watermark: bool,
}

/// Validates the caller-controlled query parameters.
///
/// # Errors
///
/// A `400` envelope naming the offending field, per `docs/05-API.md §5`.
fn validate(query: &PreviewQuery) -> Result<Rendition, Envelope> {
    let page = match query.page.as_deref() {
        None => 1,
        Some(raw) => match raw.parse::<u32>() {
            Ok(page) if (1..=MAX_PAGE).contains(&page) => page,
            _ => {
                return Err(Envelope::new(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_FAILED",
                    "That page number is outside the permitted range.",
                    "Request a page between 1 and the document's page count.",
                )
                .with_details(vec![
                    serde_json::json!({ "field": "page", "code": "OUT_OF_RANGE" }),
                ]));
            }
        },
    };

    let profile = query.profile.clone().unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    // Syntax only. Which profiles exist is the rendition pipeline's vocabulary and it does not
    // exist yet; inventing a catalog here would have to be un-invented when it does. What is
    // checked is that the value is a bounded, inert identifier rather than a path or a payload.
    let well_formed = !profile.is_empty()
        && profile.len() <= MAX_PROFILE_LEN
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !well_formed {
        return Err(Envelope::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_FAILED",
            "That rendition profile is not a valid name.",
            "Omit `profile` to use the default.",
        )
        .with_details(vec![serde_json::json!({ "field": "profile", "code": "INVALID_FORMAT" })]));
    }

    Ok(Rendition { profile, page })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::ClassificationRank;

    use super::*;

    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }

    #[test]
    fn the_obligations_a_preview_exists_to_carry_do_not_block_it() {
        // `NoDownload` on a preview is the ordinary case — it is the policy this endpoint is for.
        // A handler that treated it as a denial would make "view but do not download" mean
        // "view nothing".
        //
        // `Watermark` used to be in this list and is deliberately no longer: it was satisfiable
        // only while nothing was rendered. See
        // `a_watermark_obligation_refuses_rather_than_serving_an_unmarked_rendition`.
        assert!(satisfy(&obligations([
            Obligation::NoDownload,
            Obligation::NoSync,
            Obligation::ReadOnly,
        ]))
        .is_ok());
    }

    #[test]
    fn blocking_obligations_refuse_before_any_rendition() {
        assert!(matches!(
            satisfy(&obligations([Obligation::RequireJustification])),
            Err(Error::PolicyDenied { code: ReasonCode::DlpJustificationRequired, .. })
        ));
        assert!(matches!(
            satisfy(&obligations([Obligation::RequireApproval])),
            Err(Error::PolicyDenied { code: ReasonCode::DlpApprovalRequired, .. })
        ));
        assert!(matches!(
            satisfy(&obligations([Obligation::Reclassify { to: ClassificationRank::new(40) }])),
            Err(Error::PolicyDenied { code: ReasonCode::AccessDenied, .. })
        ));
    }

    #[test]
    fn an_omitted_profile_falls_back_to_the_documented_default() {
        let rendition = validate(&PreviewQuery::default()).expect("no parameters is valid");
        assert_eq!(rendition.profile, DEFAULT_PROFILE);
        assert_eq!(rendition.page, 1, "a document's first page is the one a viewer opens on");
    }

    #[test]
    fn a_page_outside_the_hard_limit_is_refused() {
        // `abc` and `-1` are in the list because the parameter is parsed here rather than by the
        // extractor: both must produce the documented envelope, not axum's own rejection.
        for page in ["0", "10001", "abc", "-1", ""] {
            let query = PreviewQuery { page: Some(page.to_owned()), profile: None };
            let refusal = validate(&query).expect_err("an unusable page must fail");
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
        }
        let query = PreviewQuery { page: Some(MAX_PAGE.to_string()), profile: None };
        assert_eq!(validate(&query).expect("the last permitted page").page, MAX_PAGE);
    }

    #[test]
    fn a_profile_that_is_not_an_inert_identifier_is_refused() {
        for profile in ["../../etc/passwd", "Page PNG", "", &"p".repeat(MAX_PROFILE_LEN + 1)] {
            let query = PreviewQuery { page: None, profile: Some(profile.to_owned()) };
            let refusal = validate(&query)
                .expect_err("a profile that is not an inert identifier must be refused");
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn a_rendition_response_can_neither_be_cached_nor_reinterpreted() {
        // Both headers are controls rather than niceties. A rendition of `PREVIEW_ONLY` content in
        // a shared cache is that content available without the policy chain; and a media type a
        // browser is free to disagree with is a rendition interpreted as something it is not.
        let response =
            rendition_response(vec![0x89, b'P', b'N', b'G'], "image/png", RequestId::new_v7());

        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers.get(axum::http::header::CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("private, no-store")
        );
        assert_eq!(
            headers.get("x-content-type-options").and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        // Viewing, not taking away. An `attachment` disposition would put a download-shaped
        // affordance on the path whose entire purpose is that downloading is separable.
        assert_eq!(
            headers.get(axum::http::header::CONTENT_DISPOSITION).and_then(|v| v.to_str().ok()),
            Some("inline")
        );
    }

    #[test]
    fn a_watermark_obligation_is_recorded_rather_than_quietly_dropped() {
        // The history of this arm is the point. It was a no-op while the endpoint returned `501`
        // (nothing rendered, so nothing served unmarked), then a refusal once a rendition was
        // served, and now a *requirement* the caller must discharge — because `ENC-169` gave it
        // something to discharge it with. What it has never been is silently satisfied.
        let required = satisfy(&obligations([Obligation::Watermark]))
            .expect("a watermark is dischargeable, so it is not a refusal");
        assert!(required.watermark);

        // And an ordinary preview carries no such requirement, or every response would pay for a
        // composite and an identity lookup it does not need.
        let plain = satisfy(&obligations([Obligation::NoDownload])).expect("ordinary");
        assert!(!plain.watermark);
    }

    #[test]
    fn every_wire_profile_name_maps_onto_the_pipeline_or_onto_nothing() {
        // The default has to resolve, or the endpoint refuses every request that names no profile.
        assert!(profile_for(DEFAULT_PROFILE).is_some());
        for name in ["thumb", "page-png-1x", "page-png-2x", "pdf-sanitized", "html-sanitized"] {
            assert!(profile_for(name).is_some(), "`{name}` names no profile");
        }
        // And an unknown name is `None` rather than a default, so a typo cannot silently serve a
        // different profile than the caller asked for.
        assert!(profile_for("page-png-3x").is_none());
        assert!(profile_for("").is_none());
    }
}
