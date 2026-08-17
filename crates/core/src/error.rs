//! The canonical error type (`docs/03-LLD.md §22`) and the closed vocabularies it carries.
//!
//! # Why `PolicyDenied` looks the way it does
//!
//! A policy denial is the one error where the difference between "what happened" and "what the
//! caller may be told" is a security property. Telling a user *which* rule blocked them, what its
//! threshold was, or that a resource exists at all in another tenant, hands them a map of the
//! controls (`docs/05-API.md §5`, `docs/06-SECURITY-DLP-ACCESS.md §24`).
//!
//! The usual approach is a free-form message plus a note in the code review checklist saying
//! "remember to sanitize". That fails eventually and silently. Instead
//! [`Error::PolicyDenied`] carries two **closed enumerations** — a [`ReasonCode`] and a
//! [`Remediation`]. There is no `String` field, so there is nowhere for internal reasoning to be
//! written even by mistake. The reasoning still exists; it goes to audit, inside the policy
//! engine, where it belongs.

use core::fmt;

use serde::{Deserialize, Serialize};

/// The workspace-wide result alias.
///
/// Domain crates define their own error types (`thiserror`) and convert at their edge; this is the
/// one type the API layer maps to HTTP, so a signature returning `core::Result<T>` is saying "the
/// failures here are already expressible on the wire".
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Rejection of a string that does not name any variant of a fixed vocabulary.
///
/// Unlike [`IdParseError`](crate::id::IdParseError) this *does* retain the offending value,
/// truncated: these vocabularies are short enum tokens rather than anything that could be a
/// credential, and knowing which unexpected token arrived is most of the diagnostic value when a
/// client or a migration disagrees with the code about a spelling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{value}` is not a valid {expected}")]
pub struct UnknownVariant {
    /// Name of the enumeration that rejected the value, e.g. `"ClientType"`.
    pub expected: &'static str,
    /// The rejected token, truncated to a bounded length so a hostile client cannot inflate log
    /// lines by sending a megabyte where an enum token was expected.
    pub value: String,
}

impl UnknownVariant {
    /// Maximum number of bytes of the offending value retained.
    const MAX_VALUE_BYTES: usize = 64;

    /// Builds the error, truncating the recorded value on a character boundary.
    #[must_use]
    pub fn new(expected: &'static str, value: &str) -> Self {
        let mut end = Self::MAX_VALUE_BYTES.min(value.len());
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        Self { expected, value: value[..end].to_owned() }
    }
}

wire_enum! {
    /// The stable, machine-readable reason a request was denied by policy.
    ///
    /// These are the codes in `docs/05-API.md §5`; they appear verbatim in the `code` field of the
    /// error envelope, in audit rows, and in client code that branches on them. Treat each string
    /// as a published API constant.
    ///
    /// The enumeration is intentionally *not* `#[non_exhaustive]`: a new denial reason should force
    /// every place that maps codes to messages, statuses and remediations to be revisited, and an
    /// exhaustive `match` is what forces it.
    pub enum ReasonCode {
        /// The caller is not permitted to perform this action on this resource by ACL.
        AccessDenied => "ACCESS_DENIED",
        /// Download specifically is blocked; other access to the same file may be permitted.
        DownloadBlockedByPolicy => "DOWNLOAD_BLOCKED_BY_POLICY",
        /// Sharing outside the tenant is not permitted for this resource or by this caller.
        ExternalShareBlocked => "EXTERNAL_SHARE_BLOCKED",
        /// The caller may view a rendition but may not obtain the bytes.
        PreviewOnly => "PREVIEW_ONLY",
        /// The request originated outside a network zone this policy requires.
        NetworkNotAllowed => "NETWORK_NOT_ALLOWED",
        /// The request came from a device that is not managed to the required posture.
        DeviceNotManaged => "DEVICE_NOT_MANAGED",
        /// Authentication succeeded but is not strong or recent enough; a step-up is required.
        StepUpRequired => "STEP_UP_REQUIRED",
        /// Data-loss-prevention policy blocked the operation outright.
        DlpBlocked => "DLP_BLOCKED",
        /// DLP will permit the operation once the caller records a justification.
        DlpJustificationRequired => "DLP_JUSTIFICATION_REQUIRED",
        /// DLP will permit the operation once an approver signs off.
        DlpApprovalRequired => "DLP_APPROVAL_REQUIRED",
        /// The resource's classification exceeds the ceiling for this caller or client type.
        ClassificationCeiling => "CLASSIFICATION_CEILING",
        /// A legal hold prevents the operation.
        LegalHoldActive => "LEGAL_HOLD_ACTIVE",
        /// A retention policy prevents deletion before its period elapses.
        RetentionBlocksDelete => "RETENTION_BLOCKS_DELETE",
        /// The item is a declared record and is immutable.
        RecordImmutable => "RECORD_IMMUTABLE",
        /// A configured quota is exhausted.
        QuotaExceeded => "QUOTA_EXCEEDED",
        /// Replication to a device is not permitted, independently of read access.
        SyncNotPermitted => "SYNC_NOT_PERMITTED",
        /// The content is or may be malicious and is not being served.
        MalwareDetected => "MALWARE_DETECTED",
        /// A consumed refresh token was presented again; the token family has been revoked.
        SessionReplay => "SESSION_REPLAY",
    }
}

impl ReasonCode {
    /// The HTTP status this denial maps to.
    ///
    /// Everything is `403` except the step-up case, which is a `401` because the caller can fix it
    /// by authenticating more strongly rather than by asking someone for permission
    /// (`docs/05-API.md §5`).
    ///
    /// Note what is *not* here: cross-tenant and information-barrier denials. Those never become a
    /// `ReasonCode` at all — they are [`Error::NotFound`], because a `403` confirms existence
    /// (`CLAUDE.md` non-negotiable rule 7).
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::StepUpRequired => 401,
            _ => 403,
        }
    }

    /// The remediation ordinarily offered with this code.
    ///
    /// Pairing lives here so that eighteen call sites cannot each invent their own advice, and so
    /// that a new code cannot ship without someone deciding what the user is supposed to do about
    /// it. A caller with better context may still pass a different [`Remediation`].
    #[must_use]
    pub const fn default_remediation(&self) -> Remediation {
        match self {
            Self::AccessDenied | Self::PreviewOnly | Self::ClassificationCeiling => {
                Remediation::RequestAccess
            }
            Self::DownloadBlockedByPolicy | Self::NetworkNotAllowed => {
                Remediation::ConnectToTrustedNetwork
            }
            Self::ExternalShareBlocked | Self::SyncNotPermitted | Self::DlpBlocked => {
                Remediation::RequestException
            }
            Self::DeviceNotManaged => Remediation::UseManagedDevice,
            Self::StepUpRequired => Remediation::CompleteStepUp,
            Self::DlpJustificationRequired => Remediation::ProvideJustification,
            Self::DlpApprovalRequired => Remediation::RequestApproval,
            Self::LegalHoldActive | Self::RetentionBlocksDelete | Self::RecordImmutable => {
                Remediation::ContactAdministrator
            }
            Self::QuotaExceeded => Remediation::FreeSpaceOrRaiseQuota,
            Self::MalwareDetected => Remediation::None,
            Self::SessionReplay => Remediation::SignInAgain,
        }
    }
}

wire_enum! {
    /// What the user can actually *do* about a denial.
    ///
    /// A closed set of keys rather than a sentence, for two reasons. First, it is the second half
    /// of the guarantee that a denial cannot carry internal reasoning: there is no free-text
    /// channel. Second, the user-facing wording is localizable content and belongs in the i18n
    /// catalog (`CLAUDE.md` convention 12) — the API resolves each key to a translated string, and
    /// the UI can attach an action to it (connect to VPN, open the request form) precisely because
    /// it is a key and not prose.
    pub enum Remediation {
        /// Nothing the caller can do; the operation will not be permitted by any action of theirs.
        None => "NONE",
        /// Ask the resource owner for access.
        RequestAccess => "REQUEST_ACCESS",
        /// Ask a security administrator for a policy exception.
        RequestException => "REQUEST_EXCEPTION",
        /// Retry from a corporate network or VPN.
        ConnectToTrustedNetwork => "CONNECT_TO_TRUSTED_NETWORK",
        /// Retry from an enrolled, compliant device.
        UseManagedDevice => "USE_MANAGED_DEVICE",
        /// Complete a stronger or more recent authentication and retry.
        CompleteStepUp => "COMPLETE_STEP_UP",
        /// Resubmit with a business justification.
        ProvideJustification => "PROVIDE_JUSTIFICATION",
        /// Submit the operation for approval.
        RequestApproval => "REQUEST_APPROVAL",
        /// Delete content or ask an administrator to raise the quota.
        FreeSpaceOrRaiseQuota => "FREE_SPACE_OR_RAISE_QUOTA",
        /// Sign in again; the previous session was terminated.
        SignInAgain => "SIGN_IN_AGAIN",
        /// Contact a tenant administrator; the block is organizational, not technical.
        ContactAdministrator => "CONTACT_ADMINISTRATOR",
        /// The condition is transient; retry later.
        RetryLater => "RETRY_LATER",
    }
}

wire_enum! {
    /// The measurable limits an administrator can set, from `docs/04-DATA-MODEL.md §16`.
    ///
    /// The strings match the `quotas.quota_kind` `CHECK` constraint exactly; they are the same
    /// vocabulary, and duplicating it with different spellings would guarantee a mismatch.
    pub enum QuotaKind {
        /// Total stored bytes.
        StorageBytes => "STORAGE_BYTES",
        /// Total number of files.
        FileCount => "FILE_COUNT",
        /// Largest permitted single file.
        MaxFileBytes => "MAX_FILE_BYTES",
        /// Retained versions per file.
        VersionDepth => "VERSION_DEPTH",
        /// Licensed member seats.
        Seats => "SEATS",
        /// Admitted external guests.
        Guests => "GUESTS",
        /// API requests per minute.
        ApiRpm => "API_RPM",
        /// MCP tool invocations per day.
        McpCallsPerDay => "MCP_CALLS_PER_DAY",
        /// Bytes exported per day.
        ExportBytesPerDay => "EXPORT_BYTES_PER_DAY",
    }
}

impl QuotaKind {
    /// Whether this quota refills over time rather than describing stored capacity.
    ///
    /// It decides the HTTP status: a rate quota is `429` with a `Retry-After` because waiting
    /// fixes it, while an exhausted capacity quota is `403` because waiting does not
    /// (`docs/05-API.md §5`).
    #[must_use]
    pub const fn is_rate(&self) -> bool {
        matches!(self, Self::ApiRpm | Self::McpCallsPerDay | Self::ExportBytesPerDay)
    }
}

wire_enum! {
    /// An external system Enclave depends on, as enumerated in `02-HLD.md §24`.
    ///
    /// Naming the dependency in the error is what lets the health surface and the operator see
    /// *which* thing is degraded, while the client only ever sees a generic `503`.
    pub enum Dependency {
        /// The authoritative database.
        Postgres => "POSTGRES",
        /// The object store holding file content.
        ObjectStorage => "OBJECT_STORAGE",
        /// The cache and denylist store.
        Redis => "REDIS",
        /// The vector index.
        Milvus => "MILVUS",
        /// The event bus.
        Nats => "NATS",
        /// The embedding provider used by indexing.
        EmbeddingProvider => "EMBEDDING_PROVIDER",
        /// The antivirus engine.
        Antivirus => "ANTIVIRUS",
        /// Outbound mail.
        Smtp => "SMTP",
        /// The secret store backing `vault://` references.
        SecretStore => "SECRET_STORE",
        /// An external document editor integration.
        ExternalEditor => "EXTERNAL_EDITOR",
        /// The tenant's identity provider (SSO/SCIM).
        IdentityProvider => "IDENTITY_PROVIDER",
    }
}

wire_enum! {
    /// Why a single field failed validation.
    ///
    /// Populates the `details` array of the error envelope as
    /// `{ "field": "name", "code": "TOO_LONG" }` (`docs/05-API.md §5`). A code rather than a
    /// sentence, so the client can localize it and highlight the right input.
    pub enum ValidationCode {
        /// The field is required and was absent or empty.
        Required => "REQUIRED",
        /// The value exceeds the maximum length or size.
        TooLong => "TOO_LONG",
        /// The value is below the minimum length or size.
        TooShort => "TOO_SHORT",
        /// The value does not match the expected syntax.
        InvalidFormat => "INVALID_FORMAT",
        /// The value is outside the permitted range.
        OutOfRange => "OUT_OF_RANGE",
        /// The value collides with an existing one.
        NotUnique => "NOT_UNIQUE",
        /// The value names something this deployment does not support.
        Unsupported => "UNSUPPORTED",
        /// The field cannot be changed after creation.
        Immutable => "IMMUTABLE",
        /// The value is well-formed but inconsistent with another field.
        Inconsistent => "INCONSISTENT",
    }
}

/// One entry in the `details` array of a validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    /// Dotted path to the offending field as the *client* sent it, e.g. `"parent.name"`, so the UI
    /// can attach the message to the input the user actually typed into.
    pub field: String,
    /// Why it was rejected.
    pub code: ValidationCode,
}

impl FieldError {
    /// Convenience constructor; validation code tends to build these in bulk.
    #[must_use]
    pub fn new(field: impl Into<String>, code: ValidationCode) -> Self {
        Self { field: field.into(), code }
    }
}

/// The single error type the API layer maps to HTTP (`docs/03-LLD.md §22`).
///
/// Every variant answers a question the client is allowed to ask. Note what has no variant:
/// "denied because rule 47 matched at threshold 0.8", "denied, and by the way the resource exists
/// in tenant B". Cross-tenant and barrier denials are [`Error::NotFound`] deliberately, so that a
/// probe cannot distinguish absence from denial (`CLAUDE.md` non-negotiable rule 7).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The resource does not exist — *or* it does and the caller may not know that.
    ///
    /// Cross-tenant access and information-barrier blocks both land here. Anything that would
    /// distinguish the two cases goes to audit instead.
    #[error("not found")]
    NotFound,

    /// Optimistic concurrency failure: the caller's `If-Match` did not match.
    ///
    /// The current revision is returned so the client can re-read, merge and retry without a
    /// second round trip to discover it.
    #[error("revision conflict")]
    Conflict {
        /// The revision the resource actually holds now.
        current_revision: i64,
    },

    /// The policy chain denied the request.
    ///
    /// Carries only what the client may see. See the [module documentation](self) for why both
    /// fields are closed enumerations rather than strings.
    #[error("denied by policy: {code}")]
    PolicyDenied {
        /// Stable machine-readable reason.
        code: ReasonCode,
        /// What the caller can do about it, as a catalog key.
        remediation: Remediation,
    },

    /// A configured quota is exhausted.
    #[error("quota {quota} exceeded (limit {limit})")]
    QuotaExceeded {
        /// Which quota.
        quota: QuotaKind,
        /// The configured limit, so the client can show headroom rather than a bare refusal.
        limit: i64,
    },

    /// The request was malformed or semantically invalid, per field.
    #[error("validation failed for {} field(s)", .0.len())]
    Validation(Vec<FieldError>),

    /// A dependency failed.
    ///
    /// `retryable` is part of the type rather than inferred from the dependency, because the same
    /// dependency fails both ways: an object-storage timeout is retryable, an object-storage
    /// permission error is not.
    #[error("dependency {dependency} unavailable")]
    Upstream {
        /// Which dependency.
        dependency: Dependency,
        /// Whether an identical retry is likely to succeed.
        retryable: bool,
    },

    /// An unexpected internal failure.
    ///
    /// The `Display` text is deliberately the bare phrase "internal error" and nothing else: this
    /// is the one variant that can carry arbitrary context, and `to_string()` on an error is
    /// exactly how that context reaches a response body by accident. The full chain remains
    /// available through [`std::error::Error::source`] for logging.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl Error {
    /// Builds a policy denial using the code's standard remediation.
    ///
    /// The overwhelmingly common case; the explicit-remediation form exists for callers with
    /// context that changes the advice.
    #[must_use]
    pub const fn denied(code: ReasonCode) -> Self {
        Self::PolicyDenied { code, remediation: code.default_remediation() }
    }

    /// Builds a policy denial with a specific remediation.
    #[must_use]
    pub const fn denied_with(code: ReasonCode, remediation: Remediation) -> Self {
        Self::PolicyDenied { code, remediation }
    }

    /// The stable `code` for the error envelope (`docs/05-API.md §5`).
    ///
    /// Lives beside the enum so that the wire vocabulary and the internal one are edited together;
    /// an API crate that derived this independently would drift the first time a variant was added.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "NOT_FOUND",
            Self::Conflict { .. } => "CONFLICT",
            Self::PolicyDenied { code, .. } => code.as_str(),
            Self::QuotaExceeded { .. } => "QUOTA_EXCEEDED",
            Self::Validation(_) => "VALIDATION_FAILED",
            Self::Upstream { .. } => "DEPENDENCY_UNAVAILABLE",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// The HTTP status per `docs/05-API.md §5`.
    ///
    /// Returned as a plain `u16` because `core` will not depend on a web framework; the `api`
    /// crate converts. Keeping the mapping here rather than in a handler is what stops two
    /// handlers answering the same failure with different statuses.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Conflict { .. } => 409,
            Self::PolicyDenied { code, .. } => code.status_code(),
            // A rate quota refills, so the caller should retry; a capacity quota does not, so a
            // retry would be pure noise and it is a refusal instead.
            Self::QuotaExceeded { quota, .. } => {
                if quota.is_rate() {
                    429
                } else {
                    403
                }
            }
            Self::Validation(_) => 400,
            Self::Upstream { .. } => 503,
            Self::Internal(_) => 500,
        }
    }

    /// Whether an identical retry could plausibly succeed, for client back-off and for worker
    /// retry decisions.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Upstream { retryable, .. } => *retryable,
            Self::QuotaExceeded { quota, .. } => quota.is_rate(),
            _ => false,
        }
    }
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn reason_codes_round_trip_through_their_wire_form() {
        for code in ReasonCode::all() {
            let parsed: ReasonCode = code.as_str().parse().expect("canonical form must parse");
            assert_eq!(*code, parsed);
        }
    }

    #[test]
    fn vocabularies_parse_case_insensitively() {
        // A JWT says `"cli": "web"` while the database says `'WEB'`; both must resolve.
        assert_eq!("dlp_blocked".parse::<ReasonCode>(), Ok(ReasonCode::DlpBlocked));
        assert_eq!("Storage_Bytes".parse::<QuotaKind>(), Ok(QuotaKind::StorageBytes));
    }

    #[test]
    fn unknown_variant_is_truncated() {
        let huge = "x".repeat(4096);
        let err = huge.parse::<ReasonCode>().expect_err("must reject");
        assert_eq!(err.expected, "ReasonCode");
        assert!(err.value.len() <= 64);
    }

    #[test]
    fn every_reason_code_has_a_remediation_and_a_status() {
        for code in ReasonCode::all() {
            let status = code.status_code();
            assert!((400..500).contains(&status), "{code} mapped to {status}");
            // MALWARE_DETECTED is the only code the user genuinely cannot act on.
            if *code != ReasonCode::MalwareDetected {
                assert_ne!(code.default_remediation(), Remediation::None, "{code}");
            }
        }
    }

    #[test]
    fn cross_tenant_denial_is_indistinguishable_from_absence() {
        // Non-negotiable rule 7: a 403 confirms existence, so the barrier/tenant path must be 404.
        assert_eq!(Error::NotFound.status_code(), 404);
        assert_eq!(Error::NotFound.code(), "NOT_FOUND");
    }

    #[test]
    fn internal_errors_do_not_leak_their_context_through_display() {
        let err = Error::Internal(anyhow::anyhow!("connection string user=app password=hunter2"));
        assert_eq!(err.to_string(), "internal error");
    }

    #[test]
    fn policy_denials_render_only_the_code() {
        let err = Error::denied(ReasonCode::DownloadBlockedByPolicy);
        assert_eq!(err.to_string(), "denied by policy: DOWNLOAD_BLOCKED_BY_POLICY");
        assert_eq!(err.status_code(), 403);
        match err {
            Error::PolicyDenied { remediation, .. } => {
                assert_eq!(remediation, Remediation::ConnectToTrustedNetwork);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn step_up_is_a_401_because_the_caller_can_fix_it() {
        assert_eq!(Error::denied(ReasonCode::StepUpRequired).status_code(), 401);
    }

    #[test]
    fn rate_quotas_are_retryable_and_capacity_quotas_are_not() {
        let rate = Error::QuotaExceeded { quota: QuotaKind::ApiRpm, limit: 600 };
        let capacity = Error::QuotaExceeded { quota: QuotaKind::StorageBytes, limit: 1 };
        assert_eq!(rate.status_code(), 429);
        assert!(rate.is_retryable());
        assert_eq!(capacity.status_code(), 403);
        assert!(!capacity.is_retryable());
    }

    #[test]
    fn validation_errors_carry_their_fields() {
        let err = Error::Validation(vec![
            FieldError::new("name", ValidationCode::TooLong),
            FieldError::new("parent.id", ValidationCode::Required),
        ]);
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.to_string(), "validation failed for 2 field(s)");
    }
}
