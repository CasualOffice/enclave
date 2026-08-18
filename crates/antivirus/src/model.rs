//! What a scanner is asked and what it answers.
//!
//! [`ScanVerdict`] and [`EngineInfo`] are `docs/06-SECURITY-DLP-ACCESS.md §6.1` verbatim. That is
//! deliberate down to the absence of payloads: `Unsupported` carries no reason and
//! `Error { retryable }` carries no message, because the moment a verdict can carry engine text,
//! that text starts appearing in responses to uploaders — and `§6.2` is explicit that the uploader
//! is told the upload failed policy, never what the engine said. Reasons go to `tracing` and to
//! the [`crate::outcome::Incident`], both of which are security-facing.

use serde::{Deserialize, Serialize};

/// What the scanner concluded about the content.
///
/// `#[must_use]` because the whole of `CLAUDE.md` rule 9 is downstream of this value: a verdict
/// computed and dropped is a version that stayed in whatever state it was already in, which for a
/// fresh upload is `SCANNING` (harmless) and for a rescan is the previous verdict (not harmless).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanVerdict {
    /// The engine scanned the content and found nothing.
    Clean,

    /// The engine matched a signature.
    ///
    /// The signature is for the incident and for audit. It must not reach the uploader — see
    /// [`crate::outcome::UploaderNotice`] for the mechanism that makes that structural rather than
    /// a habit.
    Infected {
        /// The engine's signature name, e.g. `Eicar-Test-Signature`.
        signature: String,
    },

    /// The engine could not form an opinion about this content: an encrypted archive, an object
    /// past the size ceiling, a container deeper than the configured limit.
    ///
    /// Distinct from [`ScanVerdict::Error`] because it is a *property of the content* and will
    /// recur on every retry, whereas an error is a property of the moment. They therefore have
    /// different policies attached (`docs/06-SECURITY-DLP-ACCESS.md §6.2`): unsupported content
    /// follows tenant policy, an outage follows `av.unavailable_policy`.
    Unsupported,

    /// The scan did not happen.
    ///
    /// This is a *verdict*, not an `Err`. "We could not decide" is a case `§6.2` has a written
    /// answer for, so it travels through the same channel as the answers rather than through the
    /// error path where a caller might turn it into a `500` and lose the `HOLD` policy.
    Error {
        /// Whether an identical retry is likely to succeed. A connection refused is `true`; a
        /// malformed configuration is `false` and needs an operator.
        retryable: bool,
    },
}

impl ScanVerdict {
    /// The `av_status` value this verdict maps to, for logs and metrics.
    ///
    /// Note this is *not* the value written to `file_versions.av_status` — that is
    /// [`crate::outcome::ScanOutcome::av_status`], which also accounts for policy. A `Clean`
    /// verdict on content the tenant blocks still lands in the database as blocked.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Infected { .. } => "INFECTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Error { .. } => "ERROR",
        }
    }
}

/// What the caller knows about the content before it is scanned.
///
/// Every field is a *claim*, from the client or from an earlier pipeline stage, and none of it is
/// trusted for a decision. It exists so an engine can pick a better strategy — telling clamd a
/// declared type lets it skip format probing — and so the size ceiling can be applied before a
/// connection is opened rather than after 5 GB have crossed the network.
///
/// # What is not here
///
/// The file name. An extension is enough for every engine hint that exists, and a full name is
/// user-supplied text that would end up in scanner logs on the far side of a socket we do not
/// own. `CLAUDE.md` rule 10 is about our logs; the same reasoning applies to somebody else's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanHint {
    /// The MIME type the upload declared, if any.
    pub declared_mime: Option<String>,
    /// The lowercase extension without a dot, e.g. `zip`.
    pub extension: Option<String>,
    /// The size the caller expects, used to apply the ceiling before connecting.
    pub declared_size: Option<u64>,
}

impl ScanHint {
    /// A hint that claims nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Sets the declared MIME type.
    #[must_use]
    pub fn with_mime(mut self, mime: impl Into<String>) -> Self {
        self.declared_mime = Some(mime.into());
        self
    }

    /// Sets the extension, normalized to lowercase and stripped of a leading dot.
    #[must_use]
    pub fn with_extension(mut self, extension: &str) -> Self {
        self.extension = Some(extension.trim_start_matches('.').to_ascii_lowercase());
        self
    }

    /// Sets the declared size.
    #[must_use]
    pub const fn with_size(mut self, bytes: u64) -> Self {
        self.declared_size = Some(bytes);
        self
    }
}

/// Which engine answered, and with which signatures.
///
/// Recorded on the version as `av_engine` and `av_signature_version`
/// (`docs/04-DATA-MODEL.md`, `file_versions`) so that a later signature update can identify what
/// was scanned by which generation, which is what makes the rescan sweep in
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2` targetable rather than a full re-scan of the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineInfo {
    /// Engine name and version, e.g. `ClamAV 1.4.1`.
    pub engine: String,

    /// The signature database generation, e.g. `27621`. `None` when the engine will not say.
    pub signature_version: Option<String>,

    /// Whether this engine actually inspects content.
    ///
    /// Not in `§6.1`, and added for one reason: [`crate::NoScanningPerformed`] has to be
    /// distinguishable from a real engine *at runtime*, by a health endpoint or a start-up banner,
    /// without string-matching the `engine` field. An operator who has accidentally shipped with
    /// `antivirus.provider: none` outside the enterprise profile — where `§19` would have refused
    /// to start — finds out from this flag.
    pub scans_content: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn an_extension_is_normalized_so_two_hints_for_the_same_file_agree() {
        assert_eq!(ScanHint::empty().with_extension(".ZIP").extension.as_deref(), Some("zip"));
        assert_eq!(ScanHint::empty().with_extension("Zip").extension.as_deref(), Some("zip"));
    }

    #[test]
    fn a_hint_claims_nothing_by_default() {
        let hint = ScanHint::empty();
        assert!(hint.declared_mime.is_none());
        assert!(hint.extension.is_none());
        assert!(hint.declared_size.is_none());
    }

    #[test]
    fn verdict_labels_match_the_av_status_vocabulary() {
        assert_eq!(ScanVerdict::Clean.label(), "CLEAN");
        assert_eq!(ScanVerdict::Infected { signature: "X".into() }.label(), "INFECTED");
        assert_eq!(ScanVerdict::Error { retryable: true }.label(), "ERROR");
    }
}
