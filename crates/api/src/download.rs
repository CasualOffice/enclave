//! `POST /api/v1/files/{id}/download` — the only endpoint that hands over original bytes.
//!
//! `docs/05-API.md §9` makes this a `POST` rather than a `GET` because it is not a read: it
//! consumes a share-link download budget, it records an audit event, and it may require a
//! justification. A `GET` would also be prefetchable, cacheable and link-shareable, which is the
//! wrong shape for the one call in the product that produces a URL an unauthenticated party can
//! follow.
//!
//! # The central claim, and where it is kept
//!
//! `docs/02-HLD.md §16`: *for no-download policies, a signed original URL is never generated — the
//! endpoint returns a policy denial, not an empty success.* The distinction is the whole feature.
//! A handler that minted the URL and then decided not to send it would be indistinguishable from
//! this one in every test that reads the response body, and would leak the moment a log line, an
//! error path or a trace attribute carried the URL it had already asked the store for.
//!
//! So the ordering here is load-bearing and is asserted rather than described:
//! [`crate::download::download`] reaches [`BlobStore::signed_download`] on exactly one path, after
//! the chain has allowed *and* after every obligation has been satisfied. `tests/delivery.rs`
//! holds a store that counts the calls and asserts the count is zero on every denial.
//!
//! # What is not here yet
//!
//! * **Share-link budgets.** `crates/sharing` is a stub, so there is no budget to consume. When it
//!   lands, the decrement belongs between the chain and the URL — a budget consumed for a request
//!   that was then denied is a budget spent on nothing.
//! * **The justification's destination.** A [`Obligation::RequireJustification`] is *enforced* here
//!   — the request is refused without one — but the text is not yet persisted, because the audit
//!   row is written inside `PolicyEngine::enforce` and no port exists for a handler to add a detail
//!   to it. Recording it is a follow-up on the audit crate, not on this handler.

use core::str::FromStr as _;
use core::time::Duration;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Extension, Json};
use enclave_core::{
    Action, Error, FileAction, FileId, Obligation, Obligations, ReasonCode, RequestContext,
    RequestId, ResourceRef, VersionId,
};
use enclave_files::FileRepository;
use enclave_storage::BlobStore;
use enclave_versions::{FileVersion, VersionRepository};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::ApiError;
use crate::state::ApiState;

/// How long a minted URL is valid for.
///
/// `docs/05-API.md §9` specifies 120 seconds. `plans/M1-CONTENT-CORE.md` D14 is why it is not
/// longer: no S3-compatible backend can invalidate a pre-signed URL before it expires, so the TTL
/// *is* the revocation window. One URL per authorized request, minted at the last moment, never
/// cached.
const SIGNED_URL_TTL: Duration = Duration::from_secs(120);

/// `Cache-Control` for a response carrying a signed URL.
///
/// A shared cache holding this response would hand the URL to the next caller without a policy
/// decision — the exact standing grant D14 exists to prevent.
const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

/// The request body of `docs/05-API.md §9`.
///
/// Both fields are optional and the whole body may be absent; a caller downloading the current
/// version of a file that needs no justification sends `{}` or nothing at all.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadRequest {
    /// Business justification, when policy demands one.
    ///
    /// Never logged and never echoed: it is user-authored text about a file, which is exactly the
    /// class of string `CLAUDE.md` rule 10 keeps out of logs.
    #[serde(default)]
    pub justification: Option<String>,
    /// A specific version, or `None` for whatever `files.current_version_id` points at.
    #[serde(default)]
    pub version_id: Option<VersionId>,
}

/// A minted, short-lived download URL.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadGrant {
    /// The pre-signed URL. Valid for [`DownloadGrant::expires_in`] seconds from now.
    url: String,
    /// Seconds of validity, so a client can decide whether to re-request rather than retry a dead
    /// URL.
    expires_in: u64,
    /// Whether the provider invalidates the URL after one use.
    ///
    /// Reported rather than assumed: `docs/05-API.md §9` says "single-use where the storage
    /// provider supports it", and a client that displayed "single use" over a provider that does
    /// not support it would be making a promise the deployment cannot keep.
    single_use: bool,
}

/// Handles `POST /api/v1/files/{id}/download`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unreadable or absent file, or an object-storage failure.
/// Concealment of absence is deliberate — see [`conceal_if_not_visible`].
pub async fn download(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let request = match parse_body(&body) {
        Ok(request) => request,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    // A malformed id is answered exactly as an absent one. Reporting "that is not a UUID" is
    // harmless in itself, but it makes the endpoint answer two different ways for two different
    // kinds of miss, and the discipline of one answer is easier to keep than to re-derive.
    let file =
        FileId::from_str(&file).map_err(|_error| ApiError::new(Error::NotFound, request_id))?;

    let resource = ResourceRef::file(ctx.tenant_id, file);

    // The chain. Note what is *not* above this line: no file lookup, no version lookup, no call to
    // the store. Nothing has been read about this file yet, so nothing can leak through a timing
    // difference or an error message before the decision exists.
    let decision =
        match state.policy.enforce(&ctx, Action::File(FileAction::Download), &resource).await {
            Ok(decision) => decision,
            Err(error) => {
                let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
                return Err(ApiError::new(error, request_id));
            }
        };

    // `PolicyDecision` is `#[must_use]`; taking the obligations by value is this handler accepting
    // responsibility for them, and `satisfy` is where each one is either honoured or turned into a
    // refusal. None of them may be dropped (`CLAUDE.md` rule 8).
    let obligations = decision.into_obligations();
    satisfy(&obligations, request.justification.as_deref())
        .map_err(|error| ApiError::new(error, request_id))?;

    // A specific version is a second, separately deniable exposure: version history can hold
    // content that was later redacted from the current version (`FileAction::VersionRead`). It is
    // asked about the *file*, not the version row, because `docs/12-TESTING.md §4.2` A7 requires a
    // version read to respect the current file ACL rather than the ACL at version creation.
    if request.version_id.is_some() {
        match state.policy.enforce(&ctx, Action::File(FileAction::VersionRead), &resource).await {
            Ok(decision) => {
                let obligations = decision.into_obligations();
                satisfy(&obligations, request.justification.as_deref())
                    .map_err(|error| ApiError::new(error, request_id))?;
            }
            Err(error) => {
                let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
                return Err(ApiError::new(error, request_id));
            }
        }
    }

    let version = readable_version(&state, &ctx, file, request.version_id, request_id).await?;

    // Minted here and nowhere else in this crate. The transaction is already committed: an
    // external call inside a database transaction holds a connection for the duration of somebody
    // else's network, and this one is the last thing the request does.
    let url = store
        .signed_download(&version.object_key, SIGNED_URL_TTL)
        .await
        .map_err(|error| ApiError::new(storage_failure(&error), request_id))?;

    let grant = DownloadGrant {
        url: url.to_string(),
        expires_in: SIGNED_URL_TTL.as_secs(),
        single_use: store.capabilities().single_use_signed_urls,
    };

    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(grant)).into_response())
}

/// Loads the version whose bytes may be served, or fails as though the file did not exist.
///
/// Every miss on this path — no file row, a folder, no current version, a version that antivirus
/// has not cleared — is the same [`Error::NotFound`]. `CLAUDE.md` rule 9 is enforced by
/// [`VersionRepository::find_readable`] rather than by a status comparison here, so a read path
/// cannot forget it.
async fn readable_version(
    state: &ApiState,
    ctx: &RequestContext,
    file: FileId,
    version: Option<VersionId>,
    request_id: RequestId,
) -> Result<FileVersion, ApiError> {
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // No tenant predicate is written into these calls beyond the one the repositories already
    // carry: `TenantScoped` has set `app.tenant_id` and row-level security applies the second,
    // independent predicate. PR #22's lesson is that the two layers catch different things — the
    // chain above allowed a cross-tenant read that RLS is what actually stopped.
    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    // A folder has no bytes. Not a 422: whether the id names a folder is information about the
    // tenant's content, and this endpoint has one miss answer.
    if node.is_folder() {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    let version = match version.or(node.current_version_id) {
        Some(version) => version,
        None => return Err(ApiError::new(Error::NotFound, request_id)),
    };

    let version = VersionRepository::find_readable(&mut tx, ctx.tenant_id, file, version)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(version)
}

/// Honours every obligation the chain attached, or turns it into a refusal.
///
/// The match is exhaustive on purpose. [`Obligation`] is deliberately not `#[non_exhaustive]`, so a
/// new obligation breaks this function and forces someone to decide what it means for a caller who
/// is about to receive original bytes — rather than inheriting a wildcard arm that treats it as
/// nothing.
///
/// # Errors
///
/// [`Error::PolicyDenied`] when an obligation cannot be satisfied on this path.
fn satisfy(obligations: &Obligations, justification: Option<&str>) -> Result<(), Error> {
    for obligation in obligations {
        match *obligation {
            // The claim in `docs/02-HLD.md §16`, at the only place it can be kept: before the URL
            // exists. `PREVIEW_ONLY` rather than `ACCESS_DENIED` because it is the honest one —
            // the caller may well be able to view this file, just not take it away.
            Obligation::NoDownload => return Err(Error::denied(ReasonCode::PreviewOnly)),

            // A watermark identifies the viewer inside a rendition. Original bytes cannot carry
            // one, so this obligation cannot be satisfied on this path — and an unsatisfiable
            // obligation is a refusal, never a shrug (`CLAUDE.md` rule 8). Watermarked *export* is
            // a different endpoint producing a different artifact.
            Obligation::Watermark => return Err(Error::denied(ReasonCode::PreviewOnly)),

            Obligation::RequireJustification => {
                let supplied = justification.is_some_and(|text| !text.trim().is_empty());
                if !supplied {
                    return Err(Error::denied(ReasonCode::DlpJustificationRequired));
                }
            }

            // Routing for approval is a workflow this endpoint cannot start. Refusing with the
            // code that says so is what lets the client offer the right next step.
            Obligation::RequireApproval => {
                return Err(Error::denied(ReasonCode::DlpApprovalRequired))
            }

            // Satisfied by construction: a download response carries no mutation affordance and
            // no write capability, because it carries nothing but a URL and its lifetime.
            Obligation::ReadOnly => {}

            // Satisfied by construction: this is not the sync path. `FileAction::Sync` is a
            // separate action against a separate endpoint, which is the point of them being
            // separate (`CLAUDE.md` rule 6).
            Obligation::NoSync => {}

            // Raising a resource's classification is a write, and this handler performs none. It
            // cannot be quietly skipped either, so the operation is refused and the discrepancy is
            // left where an operator will meet it: in the audit row the chain already wrote.
            Obligation::Reclassify { .. } => {
                tracing::warn!(
                    "a reclassification obligation reached the download path, which cannot apply \
                     one; refusing rather than serving the file with a stale label"
                );
                return Err(Error::denied(ReasonCode::AccessDenied));
            }
        }
    }
    Ok(())
}

/// Turns a bare "no grant" denial into an absence.
///
/// `CLAUDE.md` rule 7 and `docs/12-TESTING.md §4.1` T1: a `tenant-beta` file id requested by a
/// `tenant-alpha` user must return `404`, never `403`. The chain cannot make that decision — it
/// deliberately collapses *explicitly denied* and *never granted* into one
/// [`ReasonCode::AccessDenied`], for the reason `enclave_authorization::Effective` documents, and
/// that code alone tells the caller nothing about whether the resource exists.
///
/// So the API edge asks one further question, through the same chain and nothing else: *may this
/// caller read this file's metadata?* If yes, they already know it exists and deserve the
/// actionable `403`. If no, they learn nothing at all, which is what a cross-tenant probe must get.
/// Every other reason code passes through unchanged: `DEVICE_NOT_MANAGED` is decided before the
/// resource is looked at, and `DLP_BLOCKED` and its neighbours are only reachable once
/// authorization has already allowed.
///
/// Shared with [`crate::preview`] rather than written twice: if the two endpoints rendered denials
/// differently, the pair would become the existence oracle that neither is on its own.
pub(crate) async fn conceal_if_not_visible(
    state: &ApiState,
    ctx: &RequestContext,
    resource: &ResourceRef,
    denial: Error,
) -> Error {
    if !matches!(denial, Error::PolicyDenied { code: ReasonCode::AccessDenied, .. }) {
        return denial;
    }

    match state.policy.enforce(ctx, Action::File(FileAction::MetadataRead), resource).await {
        Ok(decision) => {
            // Nothing is performed on the strength of this decision — it was asked as a question,
            // not as permission — but its obligations are still taken by value rather than
            // dropped, because `Obligations` is `#[must_use]` and the ability to ignore one
            // silently is what rule 8 removes.
            let _obligations = decision.into_obligations();
            denial
        }
        // The caller may not know this file exists, so they are told it does not.
        Err(Error::PolicyDenied { .. } | Error::NotFound) => Error::NotFound,
        // A chain that could not evaluate is not a chain that denied. Surfacing the real failure
        // keeps a database outage from being reported to every caller as a missing file.
        Err(other) => other,
    }
}

/// Parses the optional request body.
///
/// An absent or empty body is the documented shape for "the current version, no justification", so
/// it is a default rather than a rejection.
fn parse_body(body: &Bytes) -> Result<DownloadRequest, Envelope> {
    if body.is_empty() {
        return Ok(DownloadRequest::default());
    }
    serde_json::from_slice(body).map_err(|_error| {
        // The parser's message quotes the input, and the input is a body this endpoint has just
        // decided nothing about. The client is told which field shape was expected and no more.
        Envelope::new(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "The request body could not be read.",
            "Send `{}`, or an object with `justification` and `versionId`.",
        )
    })
}

/// The `docs/05-API.md §5` error envelope, for a status [`ApiError`] cannot yet express.
///
/// `ApiError` maps [`Error`], and [`Error`] has no variant for "not implemented" and no way to
/// carry a status that is not derived from a variant. Rather than let each handler invent its own
/// error shape, this builds the one envelope `§5` defines, and both delivery endpoints use it.
///
/// A description rather than a rendered [`Response`] because it travels in the `Err` arm of the
/// small helpers below, and an `axum` response is a large error variant to move around
/// (`clippy::result_large_err`). Rendering is the last step, where the request id is in scope.
#[derive(Debug)]
pub(crate) struct Envelope {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
    details: Vec<serde_json::Value>,
}

impl Envelope {
    /// Describes a refusal. Every string is a literal: `§5` requires user-safe, localizable text,
    /// which rules out interpolating anything the request supplied.
    pub(crate) const fn new(
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self { status, code, message, remediation, details: Vec::new() }
    }

    /// Attaches the `details` array — validation fields, or the diagnostic facts of a `501`.
    pub(crate) fn with_details(mut self, details: Vec<serde_json::Value>) -> Self {
        self.details = details;
        self
    }

    /// The status this envelope will be sent with.
    ///
    /// Test-only: on the production paths the envelope is rendered rather than inspected, and a
    /// reader of one of these helpers wants to assert the refusal without building a whole
    /// response to read it back out of.
    #[cfg(test)]
    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    /// Renders it, stamping the request id that ties a client's report to a log line.
    pub(crate) fn into_response(self, request_id: RequestId) -> Response {
        let body = serde_json::json!({
            "error": {
                "code": self.code,
                "message": self.message,
                "remediation": self.remediation,
                "requestId": request_id.to_string(),
                "details": self.details,
            }
        });
        (self.status, [(header::CACHE_CONTROL, NO_STORE)], Json(body)).into_response()
    }
}

/// Maps an object-storage failure onto the one error type the API renders.
///
/// `enclave-storage` has no conversion of its own, deliberately: it is an infrastructure crate and
/// does not know what an HTTP status is. The distinction that matters to a caller is whether an
/// identical retry could work, and [`enclave_storage::StorageError::retryable`] already decides it
/// in one place.
fn storage_failure(error: &enclave_storage::StorageError) -> Error {
    tracing::error!(?error, "minting a signed download URL failed");
    Error::Upstream {
        dependency: enclave_core::Dependency::ObjectStorage,
        retryable: error.retryable(),
    }
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
    fn no_download_refuses_before_anything_can_mint_a_url() {
        let error = satisfy(&obligations([Obligation::NoDownload]), None)
            .expect_err("a no-download obligation must refuse");
        assert!(matches!(error, Error::PolicyDenied { code: ReasonCode::PreviewOnly, .. }));
    }

    #[test]
    fn a_watermark_obligation_cannot_be_satisfied_by_original_bytes() {
        let error = satisfy(&obligations([Obligation::Watermark]), Some("audit request"))
            .expect_err("original bytes cannot carry a watermark");
        assert!(matches!(error, Error::PolicyDenied { code: ReasonCode::PreviewOnly, .. }));
    }

    #[test]
    fn a_justification_is_required_and_whitespace_is_not_one() {
        let required = obligations([Obligation::RequireJustification]);
        assert!(matches!(
            satisfy(&required, None),
            Err(Error::PolicyDenied { code: ReasonCode::DlpJustificationRequired, .. })
        ));
        assert!(matches!(
            satisfy(&required, Some("   ")),
            Err(Error::PolicyDenied { code: ReasonCode::DlpJustificationRequired, .. })
        ));
        assert!(satisfy(&required, Some("Client audit request #4412")).is_ok());
    }

    #[test]
    fn approval_and_reclassification_refuse_rather_than_proceed() {
        assert!(matches!(
            satisfy(&obligations([Obligation::RequireApproval]), Some("why")),
            Err(Error::PolicyDenied { code: ReasonCode::DlpApprovalRequired, .. })
        ));
        assert!(matches!(
            satisfy(
                &obligations([Obligation::Reclassify { to: ClassificationRank::new(40) }]),
                Some("why")
            ),
            Err(Error::PolicyDenied { code: ReasonCode::AccessDenied, .. })
        ));
    }

    #[test]
    fn obligations_that_shape_a_response_do_not_block_a_download() {
        // A download response carries a URL and two scalars; there is no mutation affordance for
        // `ReadOnly` to suppress, and this is not the sync path. Asserting it so that a future
        // change that starts returning capabilities here has to revisit the claim.
        assert!(satisfy(&obligations([Obligation::ReadOnly, Obligation::NoSync]), None).is_ok());
    }

    #[test]
    fn an_unconditional_allow_needs_no_justification() {
        assert!(satisfy(&Obligations::none(), None).is_ok());
    }

    #[test]
    fn an_absent_body_is_the_documented_default() {
        let request = parse_body(&Bytes::new()).expect("an empty body is valid");
        assert!(request.justification.is_none());
        assert!(request.version_id.is_none());
    }

    #[test]
    fn a_body_carries_camel_case_fields() {
        let version = VersionId::new_v7();
        let body = Bytes::from(format!(
            r#"{{"justification":"Client audit request #4412","versionId":"{version}"}}"#
        ));
        let request = parse_body(&body).expect("a well-formed body");
        assert_eq!(request.justification.as_deref(), Some("Client audit request #4412"));
        assert_eq!(request.version_id, Some(version));
    }

    #[test]
    fn a_malformed_body_is_rejected_rather_than_defaulted() {
        let refusal =
            parse_body(&Bytes::from_static(b"not json")).expect_err("malformed JSON must fail");
        assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_ttl_matches_the_documented_default() {
        // `docs/05-API.md §9` states 120 s. A change here is a change to the revocation window,
        // which is the only revocation a pre-signed URL has (D14).
        assert_eq!(SIGNED_URL_TTL.as_secs(), 120);
    }
}
