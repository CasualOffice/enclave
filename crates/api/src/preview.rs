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
//! # Why this returns `501` instead of the file
//!
//! `crates/preview` is a stub: there is no rendition pipeline, no sanitizer and no watermark
//! compositor (`docs/06-SECURITY-DLP-ACCESS.md §5`). The tempting shortcut — stream the original
//! bytes until renditions land — would silently collapse `preview` and `download` into one
//! permission, which is precisely the failure the split exists to prevent, and it would do so on
//! the path where the collapse is least visible: a caller with `preview=ALLOW, download=DENY`
//! would receive exactly what the deny was about.
//!
//! So the endpoint refuses, loudly and with a reason. A `501` is the honest status: the request is
//! well-formed and the caller may be perfectly entitled to it — the server has not implemented the
//! capability. `docs/12-TESTING.md §4.2` A1 is asserted against this behaviour in
//! `tests/delivery.rs`: the response carries no signed URL, and the blob store is never asked for
//! one.
//!
//! # What arrives with the pipeline
//!
//! The obligations this handler already refuses to drop — [`Obligation::Watermark`] above all —
//! become the rendition's composition step (`docs/06 §5.1`: identity-free base rendition, cached;
//! watermark layer composed per request and never cached). The 501 is replaced by the rendition
//! response; the policy code above it does not change.

use core::str::FromStr as _;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use enclave_core::{
    Action, Error, FileAction, FileId, Obligation, Obligations, ReasonCode, RequestContext,
    RequestId, ResourceRef,
};
use enclave_files::FileRepository;
use enclave_versions::VersionRepository;
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
    satisfy(&obligations).map_err(|error| ApiError::new(error, request_id))?;

    // Rule 9, on the read path where it matters most: a preview of a file that antivirus has not
    // cleared is still a parse of hostile bytes by our own renderer. Checked before the `501` so
    // that the eventual pipeline inherits the order rather than the other way round.
    ensure_readable(&state, &ctx, file, request_id).await?;

    // Everything above this line is the real endpoint. What is missing is the renderer.
    Ok(not_implemented(&rendition, request_id))
}

/// Confirms that a servable version exists behind this file, or reports absence.
///
/// The version is loaded and dropped: nothing is served from it. It is loaded anyway because the
/// answer this endpoint gives must not depend on the pipeline being absent — a caller must get the
/// same `404` for a quarantined file today as they will when renditions exist.
async fn ensure_readable(
    state: &ApiState,
    ctx: &RequestContext,
    file: FileId,
    request_id: RequestId,
) -> Result<(), ApiError> {
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Row-level security is the second layer here, independent of the chain above: `TenantScoped`
    // has set `app.tenant_id`, so a file belonging to another tenant is not filtered out of this
    // query — it is invisible to the transaction (PR #22).
    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    if node.is_folder() {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    let current =
        node.current_version_id.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    // `find_readable`, never `find`: a `SCANNING`, `QUARANTINED` or failed version must be
    // indistinguishable from one that does not exist (`CLAUDE.md` rule 9).
    let version = VersionRepository::find_readable(&mut tx, ctx.tenant_id, file, current)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if version.is_none() {
        return Err(ApiError::new(Error::NotFound, request_id));
    }
    Ok(())
}

/// Honours every obligation the chain attached to a preview, or turns it into a refusal.
///
/// Exhaustive for the same reason as the download path's version: adding an obligation must break
/// this function rather than fall into a wildcard that ignores it.
///
/// # Errors
///
/// [`Error::PolicyDenied`] when an obligation cannot be satisfied on this path.
fn satisfy(obligations: &Obligations) -> Result<(), Error> {
    for obligation in obligations {
        match *obligation {
            // The expected pair on a preview, and both are satisfied by what this path is: a
            // rendition, never the original, and never a URL to it. That is a property of the
            // module (it holds no `BlobStore`), not a decision taken here.
            Obligation::NoDownload | Obligation::NoSync => {}

            // Satisfied by the rendition pipeline's composition step when it lands
            // (`docs/06 §5.1`). Until then nothing is rendered at all, so nothing is served
            // unwatermarked — the `501` below is what keeps this arm honest.
            Obligation::Watermark => {}

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
    Ok(())
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

/// The refusal itself.
///
/// Carries what the client needs to distinguish "you may not" from "we cannot yet": the code is
/// stable, and `details` states in machine-readable form that the original bytes are not the
/// fallback. A client that retries this endpoint after a deployment gets the rendition; a client
/// that treats it as a download denial and calls `POST /download` instead is told the truth by
/// *that* endpoint's own policy decision, not by this one.
fn not_implemented(rendition: &Rendition, request_id: RequestId) -> Response {
    Envelope::new(
        StatusCode::NOT_IMPLEMENTED,
        "PREVIEW_NOT_IMPLEMENTED",
        "Previews are not available in this deployment yet.",
        "Try again after the rendition service is enabled; the original file is not served here.",
    )
    .with_details(vec![serde_json::json!({
        "renditionProfile": rendition.profile,
        "page": rendition.page,
        // Stated rather than implied: this endpoint has no fallback to the original bytes, in
        // this release or any other (`CLAUDE.md` rule 6, `docs/02-HLD.md §16`).
        "servesOriginal": false,
    })])
    .into_response(request_id)
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
        assert!(satisfy(&obligations([
            Obligation::NoDownload,
            Obligation::Watermark,
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
    fn the_refusal_says_not_implemented_and_promises_no_original() {
        let rendition = Rendition { profile: DEFAULT_PROFILE.to_owned(), page: 1 };
        let response = not_implemented(&rendition, RequestId::new_v7());
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        // The body is asserted end to end in `tests/delivery.rs`, where it can be read back; here
        // the header is the part worth pinning, because a cached preview response is a preview
        // served without a policy decision.
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL).map(|v| v.to_str().unwrap()),
            Some("private, no-store")
        );
    }
}
