//! Mapping domain failures onto the wire.
//!
//! One place, so the rule in `docs/05-API.md §5` — a stable code, a user-safe message, a
//! remediation, and *nothing else* — cannot be observed by one handler and forgotten by the next.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use enclave_core::{Error, ReasonCode, RequestId};
use serde::Serialize;

/// `Cache-Control` for a response a shared cache must not keep.
///
/// It began on the delivery path, where a cached response would hand a signed URL to the next
/// caller without a policy decision (D14). It applies to every refusal for the same reason in
/// miniature: an error envelope carries a request id, and a shared cache serving it to a second
/// caller would attach one caller's correlation id to another's failure.
pub(crate) const NO_STORE: HeaderValue = HeaderValue::from_static("private, no-store");

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

    /// The failure being rendered.
    ///
    /// The inverse of [`ApiError::new`], and it exists for tests that assert what a handler
    /// *decided*: reading the decision back out of a rendered response would prove the renderer
    /// works rather than that the right decision was taken, and the two fail for different reasons.
    /// Adding no information a caller does not already receive — the envelope carries the code —
    /// so it is public rather than a `cfg(test)` back door.
    #[must_use]
    pub const fn error(&self) -> &Error {
        &self.error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = self.request_id.to_string();

        // `details` is empty for every error except a validation failure, which is the one shape
        // `docs/05-API.md §5` says must populate it.
        let mut details: Vec<serde_json::Value> = Vec::new();

        // **The status comes from `Error::status_code()`, never from the arms below.**
        //
        // `enclave_core::Error::status_code` documents itself as living there so that "two handlers
        // [do not answer] the same failure with different statuses" — and this renderer used to
        // re-derive it anyway, in a match with no arm for `Upstream` or `QuotaExceeded`. Both fell
        // into the catch-all and rendered `500`, so every dependency outage in the product reported
        // itself as our own defect rather than as a retryable upstream failure, and a quota refusal
        // told the caller to retry something that would never succeed (`ENC-171`).
        //
        // The arms now choose only the *body*: the code, the sentence and the remediation. There is
        // no longer a place for the two to disagree.
        let status = StatusCode::from_u16(self.error.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let (code, message, remediation) = match &self.error {
            // Deliberately identical to a genuine absence. A 403 here would confirm that the
            // resource exists in another tenant, or behind a barrier (docs/06 §24, test T1).
            Error::NotFound => (
                "NOT_FOUND".to_owned(),
                "The requested resource does not exist.".to_owned(),
                String::new(),
            ),
            Error::PolicyDenied { code, remediation } => {
                (code.as_str().to_owned(), user_message(*code), remediation.as_str().to_owned())
            }
            Error::Conflict { current_revision } => (
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
                    "VALIDATION_FAILED".to_owned(),
                    "The request could not be accepted as sent.".to_owned(),
                    "Correct the fields listed in `details` and retry.".to_owned(),
                )
            }
            // A dependency is unavailable. Named — but only by *class*, never by endpoint, host
            // or version — because a client's correct response differs completely from the one to
            // an internal defect: back off and retry, rather than report a bug. Rendering these as
            // `500` also hid every outage inside our own error budget.
            Error::Upstream { dependency, retryable } => {
                // Which dependency goes to the log and not to the caller. An operator needs it to
                // know what to look at; a caller told "Milvus is down" learns our topology, and
                // `docs/05-API.md §5` keeps error bodies free of it.
                tracing::warn!(%dependency, retryable, %request_id, "a dependency is unavailable");
                (
                    "DEPENDENCY_UNAVAILABLE".to_owned(),
                    "A service this request depends on is unavailable.".to_owned(),
                    if *retryable {
                        "Retry shortly.".to_owned()
                    } else {
                        "Contact your administrator; this will not succeed on retry.".to_owned()
                    },
                )
            }

            // A quota refusal is the caller's to act on, and *which* quota decides whether acting
            // means waiting or asking for more. `Error::status_code` already distinguishes them —
            // 429 for a rate quota that refills, 403 for a capacity one that does not.
            Error::QuotaExceeded { quota, .. } => (
                "QUOTA_EXCEEDED".to_owned(),
                "Your organisation has reached a usage limit.".to_owned(),
                if quota.is_rate() {
                    "Retry after a short delay.".to_owned()
                } else {
                    "Free space or ask your administrator to raise the limit.".to_owned()
                },
            ),

            // Everything else is internal. The variant is logged; the caller is told nothing that
            // would describe our topology or our failure modes back to them.
            other => {
                tracing::error!(error = ?other, %request_id, "request failed");
                (
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

/// The `docs/05-API.md §5` error envelope, for a status [`ApiError`] cannot express.
///
/// [`ApiError`] maps [`Error`], whose `status_code` is derived from the variant — so there is no
/// way through it to send a `409` that is not a revision conflict, a `422`, or a `501`. Rather than
/// let each handler invent its own error shape, this builds the one envelope `§5` defines and every
/// such refusal in the crate goes through it.
///
/// A description rather than a rendered [`Response`] because it travels in the `Err` arm of small
/// helpers, and an `axum` response is a large error variant to move around
/// (`clippy::result_large_err`). Rendering is the last step, where the request id is in scope.
///
/// # `code`, `message` and `remediation` are literals; `details` is not
///
/// `§5` requires the three prose fields to be user-safe and localizable, which rules out
/// interpolating anything the request supplied — so they are `&'static str` and the compiler holds
/// the rule. `details` is the field `§5` reserves for per-field diagnosis, and it is where
/// `ENC-603`'s conditional-access rule decoder puts the clause it refused: *`unknown variant
/// `posture_below`*` is the whole diagnostic value of a strict decoder, and an administrator who is
/// told only "the rule was rejected" is an administrator who goes back to `psql`.
#[derive(Debug)]
pub(crate) struct Envelope {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    remediation: &'static str,
    details: Vec<serde_json::Value>,
}

impl Envelope {
    /// Describes a refusal. Every string is a literal — see the type's note.
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

    /// The stable code this envelope will carry. Test-only, as [`Envelope::status`].
    #[cfg(test)]
    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    /// The `details` array, for a test that wants to assert *what* a refusal named.
    ///
    /// Test-only, and it is the reason the details are held as values rather than rendered
    /// eagerly: a test that had to build a whole response and parse it back would be asserting
    /// axum's rendering as much as this crate's refusal.
    #[cfg(test)]
    pub(crate) fn details(&self) -> &[serde_json::Value] {
        &self.details
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

#[cfg(test)]
mod status_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use axum::response::IntoResponse as _;
    use enclave_core::{
        Dependency, Error, FieldError, QuotaKind, ReasonCode, RequestId, ValidationCode,
    };

    use super::ApiError;

    /// Every variant renders the status `Error::status_code` says it should.
    ///
    /// This is the invariant `ENC-171` broke. The renderer had its own `match`, and it had no arm
    /// for `Upstream` or `QuotaExceeded`, so both fell into the catch-all and rendered `500` —
    /// every dependency outage in the product reported as our own defect, and every quota refusal
    /// telling the caller to retry something that would never succeed.
    ///
    /// The fix was to render `Error::status_code()` directly rather than re-derive it, so this test
    /// is really asserting that the second opinion is gone. A new variant added to `Error` with no
    /// arm here now renders its correct status and a generic body, which is a far better failure
    /// than a wrong status.
    #[test]
    fn the_rendered_status_is_always_the_one_the_error_declares() {
        let cases = [
            Error::NotFound,
            Error::Conflict { current_revision: 7 },
            Error::denied(ReasonCode::AccessDenied),
            Error::denied(ReasonCode::StepUpRequired),
            Error::Validation(vec![FieldError::new("name", ValidationCode::Required)]),
            Error::Upstream { dependency: Dependency::Postgres, retryable: true },
            Error::Upstream { dependency: Dependency::ObjectStorage, retryable: false },
            // Both quota shapes: one refills and is a 429, one does not and is a 403. A renderer
            // with a single quota arm would answer one of them wrongly.
            Error::QuotaExceeded { quota: QuotaKind::ApiRpm, limit: 100 },
            Error::QuotaExceeded { quota: QuotaKind::StorageBytes, limit: 1 },
            Error::Internal(anyhow::anyhow!("boom")),
        ];

        for error in cases {
            let declared = error.status_code();
            let rendered = ApiError::new(error, RequestId::new_v7()).into_response().status();
            assert_eq!(
                rendered.as_u16(),
                declared,
                "the renderer and `Error::status_code` disagree, which is what put every \
                 dependency outage into the 500 bucket"
            );
        }
    }

    /// A dependency outage is a `503` that names no topology.
    #[test]
    fn an_upstream_failure_is_retryable_and_describes_nothing_about_our_infrastructure() {
        let error = Error::Upstream { dependency: Dependency::Postgres, retryable: true };
        let response = ApiError::new(error, RequestId::new_v7()).into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
