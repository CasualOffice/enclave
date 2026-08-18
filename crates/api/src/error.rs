//! Mapping domain failures onto the wire.
//!
//! One place, so the rule in `docs/05-API.md §5` — a stable code, a user-safe message, a
//! remediation, and *nothing else* — cannot be observed by one handler and forgotten by the next.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use enclave_core::{Error, ReasonCode, RequestId};
use serde::Serialize;

/// The error envelope from `docs/05-API.md §5`.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorDetail {
    code: String,
    message: String,
    remediation: String,
    request_id: String,
    details: Vec<serde_json::Value>,
}

/// An error on its way to a client, carrying the request id for correlation.
#[derive(Debug)]
pub struct ApiError {
    error: Error,
    request_id: RequestId,
}

impl ApiError {
    /// Attaches the request id, which is the only thing tying a client's report to a log line.
    #[must_use]
    pub const fn new(error: Error, request_id: RequestId) -> Self {
        Self { error, request_id }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = self.request_id.to_string();

        // `details` is empty for every error except a validation failure, which is the one shape
        // `docs/05-API.md §5` says must populate it.
        let mut details: Vec<serde_json::Value> = Vec::new();

        let (status, code, message, remediation) = match &self.error {
            // Deliberately identical to a genuine absence. A 403 here would confirm that the
            // resource exists in another tenant, or behind a barrier (docs/06 §24, test T1).
            Error::NotFound => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND".to_owned(),
                "The requested resource does not exist.".to_owned(),
                String::new(),
            ),
            Error::PolicyDenied { code, remediation } => (
                StatusCode::from_u16(code.status_code()).unwrap_or(StatusCode::FORBIDDEN),
                code.as_str().to_owned(),
                user_message(*code),
                remediation.as_str().to_owned(),
            ),
            Error::Conflict { current_revision } => (
                StatusCode::CONFLICT,
                "REVISION_CONFLICT".to_owned(),
                format!("This resource has changed; its current revision is {current_revision}."),
                "Re-read the resource and retry with the current revision.".to_owned(),
            ),
            // A `400` with the offending fields named, per `docs/05-API.md §5`. Without this arm a
            // rejected pagination cursor or a malformed field fell through to `500`, which tells a
            // client to retry something that will never succeed. `FieldError` carries a field path
            // and a closed [`enclave_core::ValidationCode`] and nothing else — never the value that
            // was rejected, which for a cursor is opaque state and for a name is user content.
            Error::Validation(fields) => {
                details.extend(fields.iter().filter_map(|field| serde_json::to_value(field).ok()));
                (
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_FAILED".to_owned(),
                    "The request could not be accepted as sent.".to_owned(),
                    "Correct the fields listed in `details` and retry.".to_owned(),
                )
            }
            // Everything else is internal. The variant is logged; the caller is told nothing that
            // would describe our topology or our failure modes back to them.
            other => {
                tracing::error!(error = ?other, %request_id, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL".to_owned(),
                    "The request could not be completed.".to_owned(),
                    "Retry shortly. If it persists, quote the request id.".to_owned(),
                )
            }
        };

        let body =
            ErrorBody { error: ErrorDetail { code, message, remediation, request_id, details } };
        (status, Json(body)).into_response()
    }
}

/// The user-facing sentence for a reason code.
///
/// English here; `docs/14-I18N-L10N.md §5` has the client rendering its own localised string from
/// the stable `code`, which is why this stays a default rather than the source of truth.
fn user_message(code: ReasonCode) -> String {
    // Exhaustive on purpose. `ReasonCode` is deliberately not `#[non_exhaustive]` (see its doc
    // comment): adding a denial reason should break this match and force someone to decide what
    // the user is told, rather than silently inheriting a generic sentence.
    match code {
        ReasonCode::AccessDenied => "You do not have access to this.",
        ReasonCode::DownloadBlockedByPolicy => {
            "Downloading this file is restricted outside the corporate network."
        }
        ReasonCode::ExternalShareBlocked => "This file cannot be shared outside your organisation.",
        ReasonCode::PreviewOnly => "This file can be viewed but not downloaded.",
        ReasonCode::NetworkNotAllowed => "This action is not permitted from your current network.",
        ReasonCode::DeviceNotManaged => "This action requires a managed device.",
        ReasonCode::StepUpRequired => "This action needs a fresher sign-in.",
        ReasonCode::DlpBlocked => "This content cannot be shared or exported.",
        ReasonCode::DlpJustificationRequired => "This action needs a written justification.",
        ReasonCode::DlpApprovalRequired => "This action needs approval before it can proceed.",
        ReasonCode::ClassificationCeiling => {
            "This content is above the sensitivity level available here."
        }
        ReasonCode::LegalHoldActive => "This item is under legal hold and cannot be changed.",
        ReasonCode::RetentionBlocksDelete => {
            "A retention policy prevents this item from being deleted."
        }
        ReasonCode::RecordImmutable => "This item is a declared record and cannot be modified.",
        ReasonCode::QuotaExceeded => "Your organisation has reached a storage or usage limit.",
        ReasonCode::SyncNotPermitted => "This file is available on the web only.",
        ReasonCode::MalwareDetected => "This file did not pass a security scan.",
        ReasonCode::SessionReplay => "Your session has ended for security reasons.",
    }
    .to_owned()
}
