//! What the client declared, what the store observed, and the comparison between them.
//!
//! `docs/05-API.md §8`: *`complete` verifies size and SHA-256 against what was declared.* This
//! module is that verification, and [`VerifiedContent`] is its result — a value that cannot be
//! constructed any other way, so "the bytes were checked" is something the type system knows
//! rather than something a reviewer has to trace.
//!
//! # Why a mismatch is a value and not an error
//!
//! [`VerifiedContent::verify`] returns `Result<_, FailureReason>`, and the service turns a
//! `FailureReason` into a *persisted* `FAILED` session before reporting it. If a mismatch were an
//! ordinary `Err` propagating out of the handler, the caller's transaction would roll back and the
//! session would still be `UPLOADING` — inviting the client to retry a completion that can never
//! succeed, against staged bytes that are already wrong. The checksum is what makes a version
//! immutable later (`plans/M1-CONTENT-CORE.md` D12); a failed check has to leave a mark.
//!
//! # Three numbers, not two
//!
//! * **Declared** — `upload_sessions.declared_size`, written when the session was created and
//!   before any URL existed.
//! * **Reported** — what the client says it sent, in the `complete` request.
//! * **Observed** — what the object store says it holds, from `HeadObject`.
//!
//! All three must agree. Comparing only reported against observed would accept a client that
//! declared 1 MB, uploaded 5 GB and reported 5 GB — the declaration is what the library's size
//! limit was checked against, so it is the one that must hold.
//!
//! # The checksum the provider did not compute
//!
//! S3-compatible backends only return `x-amz-checksum-sha256` for objects uploaded with a checksum
//! header. When the provider has no digest of its own, the reported one is *unconfirmed*: nothing
//! has yet compared it against the bytes. That is recorded in [`ChecksumEvidence`] rather than
//! quietly treated as verified, and it is carried through to the antivirus stage — which streams
//! every byte anyway and is therefore the cheapest honest place to confirm it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_storage::ObjectMeta;

/// The number of hex characters in a SHA-256.
const SHA256_HEX_LEN: usize = 64;

/// The number of bytes in a SHA-256.
const SHA256_BYTES: usize = 32;

/// What the client says it uploaded, from the `complete` request.
///
/// Untrusted by construction: every field here is checked against the session's declaration and
/// against the object store before any of it is believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportedContent {
    /// Bytes the client says it sent.
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 the client says the object has.
    pub sha256_hex: String,
}

/// Who computed the checksum that is about to be recorded.
///
/// Not cosmetic. A version row's `checksum_sha256` is immutable once written
/// (`plans/M1-CONTENT-CORE.md` D12), so recording a digest nobody verified would make an unchecked
/// client claim permanent. Carrying the distinction lets the antivirus stage — which reads every
/// byte regardless — confirm the ones that arrived unconfirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChecksumEvidence {
    /// The object store computed a SHA-256 and it matched what the client reported.
    ProviderConfirmed,
    /// The provider computed no digest. The value is the client's, and is not yet evidence of
    /// anything.
    ClientDeclared,
}

impl ChecksumEvidence {
    /// Whether something other than the client has attested to this digest.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        matches!(self, Self::ProviderConfirmed)
    }
}

/// Why a completion was refused.
///
/// Every variant is a fixed phrase and carries no sizes or digests. A size is not secret, but a
/// failure message is the wrong channel for it — the audit row and the structured log fields carry
/// the numbers, and an error string is the value most likely to end up in a response body
/// (`CLAUDE.md` rule 10 and the reasoning in [`enclave_core::Error::Internal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum FailureReason {
    /// The size reported at completion is not the size declared when the session was created.
    #[error("the reported size is not the size this upload session was created for")]
    SizeDiffersFromDeclaration,

    /// The object store holds a different number of bytes than the client reported.
    #[error("the object store holds a different number of bytes than the client reported")]
    SizeDiffersFromStore,

    /// The store's SHA-256 is not the one the client reported.
    #[error("the stored object's SHA-256 is not the one the client reported")]
    ChecksumMismatch,

    /// The reported checksum is not 64 lowercase hex characters.
    #[error("the reported checksum is not a lowercase hex SHA-256")]
    MalformedChecksum,

    /// The session carries no declared size, so nothing can be verified against it.
    ///
    /// Only reachable for a row written outside [`crate::UploadService::create`], which always
    /// declares one. Refusing is the safe reading: an unverifiable upload is not a verified one.
    #[error("the upload session declared no size, so the upload cannot be verified")]
    NoDeclaredSize,
}

impl FailureReason {
    /// A stable token for logs and audit payloads.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SizeDiffersFromDeclaration => "SIZE_DIFFERS_FROM_DECLARATION",
            Self::SizeDiffersFromStore => "SIZE_DIFFERS_FROM_STORE",
            Self::ChecksumMismatch => "CHECKSUM_MISMATCH",
            Self::MalformedChecksum => "MALFORMED_CHECKSUM",
            Self::NoDeclaredSize => "NO_DECLARED_SIZE",
        }
    }

    /// The canonical error a handler returns for this failure.
    ///
    /// All five are `400`s naming the field the client got wrong, because all five *are* client
    /// mistakes: the platform's own numbers came from the object store.
    #[must_use]
    pub fn to_error(self) -> CoreError {
        let field = match self {
            Self::SizeDiffersFromDeclaration
            | Self::SizeDiffersFromStore
            | Self::NoDeclaredSize => "sizeBytes",
            Self::ChecksumMismatch | Self::MalformedChecksum => "sha256",
        };
        let code = match self {
            Self::MalformedChecksum => ValidationCode::InvalidFormat,
            _ => ValidationCode::Inconsistent,
        };
        CoreError::Validation(vec![FieldError::new(field, code)])
    }
}

/// The size and checksum a version row may be written from.
///
/// Constructible only through [`VerifiedContent::verify`]. The fields are private so that a caller
/// cannot assemble one from a client's numbers and hand it to the state machine as though it had
/// been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContent {
    size_bytes: u64,
    sha256_hex: String,
    checksum: ChecksumEvidence,
}

impl VerifiedContent {
    /// Compares the declaration, the client's report and the store's observation.
    ///
    /// # Errors
    ///
    /// A [`FailureReason`] for each way the three can disagree. The caller is expected to persist
    /// the session as `FAILED` rather than to propagate this directly — see the
    /// [module documentation](self).
    pub fn verify(
        declared_size: Option<i64>,
        reported: &ReportedContent,
        observed: &ObjectMeta,
    ) -> Result<Self, FailureReason> {
        if !is_lowercase_sha256_hex(&reported.sha256_hex) {
            return Err(FailureReason::MalformedChecksum);
        }

        let declared = declared_size.ok_or(FailureReason::NoDeclaredSize)?;
        // A negative `declared_size` is not a size; it can only come from a row this crate did not
        // write, and treating it as "no declaration" is the reading that refuses rather than the
        // one that guesses.
        let declared = u64::try_from(declared).map_err(|_| FailureReason::NoDeclaredSize)?;

        if reported.size_bytes != declared {
            return Err(FailureReason::SizeDiffersFromDeclaration);
        }
        if observed.size_bytes != reported.size_bytes {
            return Err(FailureReason::SizeDiffersFromStore);
        }

        let checksum = match observed.checksum_sha256.as_deref().and_then(decode_provider_sha256) {
            Some(provider_hex) if provider_hex == reported.sha256_hex => {
                ChecksumEvidence::ProviderConfirmed
            }
            Some(_) => return Err(FailureReason::ChecksumMismatch),
            None => ChecksumEvidence::ClientDeclared,
        };

        Ok(Self {
            size_bytes: reported.size_bytes,
            sha256_hex: reported.sha256_hex.clone(),
            checksum,
        })
    }

    /// The verified size, in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The lowercase hex SHA-256.
    #[must_use]
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    /// Who attested to the checksum.
    #[must_use]
    pub const fn checksum_evidence(&self) -> ChecksumEvidence {
        self.checksum
    }
}

/// Turns a provider's base64 SHA-256 into the lowercase hex the platform records.
///
/// Returns `None` when the provider sent no usable digest — absent, not base64, or not 32 bytes.
/// A malformed provider digest is a provider defect and is downgraded to "unverified" rather than
/// failing the upload: refusing here would make a backend's misbehaviour look like a client's
/// corrupted transfer, and the antivirus stage still confirms the digest from the bytes.
fn decode_provider_sha256(value: &str) -> Option<String> {
    let raw = STANDARD.decode(value).ok()?;
    if raw.len() != SHA256_BYTES {
        tracing::warn!(
            reported_len = raw.len(),
            "the object store returned a SHA-256 that is not 32 bytes; treating it as absent"
        );
        return None;
    }

    // Built from a nibble table rather than with `write!`: formatting returns a `Result` that is
    // infallible for a `String`, and the workspace forbids both discarding it and unwrapping it.
    const NIBBLES: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(SHA256_HEX_LEN);
    for byte in raw {
        hex.push(char::from(NIBBLES[usize::from(byte >> 4)]));
        hex.push(char::from(NIBBLES[usize::from(byte & 0x0f)]));
    }
    Some(hex)
}

/// Whether a string is exactly 64 lowercase hex characters.
///
/// `pub(crate)` because the same check runs at session creation, on the checksum the client
/// declares up front — one definition of "is a SHA-256", not two.
///
/// Lowercase specifically, and not case-insensitively: the value is compared byte-for-byte against
/// a digest this module renders in lowercase, and against `file_versions.checksum_sha256` later.
/// Accepting both cases would make two spellings of the same digest compare unequal somewhere
/// downstream, which is the kind of bug that only appears for one client library.
pub(crate) fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileId, TenantId, VersionId};
    use enclave_storage::ObjectKey;

    use super::*;

    const DIGEST_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// The same digest, base64, as a provider returns it.
    const DIGEST_B64: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    fn observed(size: u64, checksum: Option<&str>) -> ObjectMeta {
        ObjectMeta {
            key: ObjectKey::version(TenantId::new_v7(), FileId::new_v7(), VersionId::new_v7()),
            size_bytes: size,
            etag: None,
            checksum_sha256: checksum.map(ToOwned::to_owned),
            content_type: None,
            last_modified: None,
            provider_version_id: None,
            server_side_encryption: None,
        }
    }

    fn reported(size: u64) -> ReportedContent {
        ReportedContent { size_bytes: size, sha256_hex: DIGEST_HEX.to_owned() }
    }

    #[test]
    fn the_provider_digest_decodes_to_the_hex_the_platform_records() {
        assert_eq!(decode_provider_sha256(DIGEST_B64).as_deref(), Some(DIGEST_HEX));
    }

    #[test]
    fn a_provider_confirmed_digest_is_marked_as_such() {
        let verified =
            VerifiedContent::verify(Some(10), &reported(10), &observed(10, Some(DIGEST_B64)))
                .unwrap();
        assert_eq!(verified.size_bytes(), 10);
        assert_eq!(verified.sha256_hex(), DIGEST_HEX);
        assert!(verified.checksum_evidence().is_confirmed());
    }

    #[test]
    fn a_provider_that_computed_no_digest_leaves_the_checksum_unconfirmed() {
        let verified =
            VerifiedContent::verify(Some(10), &reported(10), &observed(10, None)).unwrap();
        assert_eq!(verified.checksum_evidence(), ChecksumEvidence::ClientDeclared);
    }

    #[test]
    fn a_digest_the_provider_disagrees_with_is_a_failure_and_not_a_warning() {
        // The provider holds a digest of 32 zero bytes; the client reported the empty-string
        // digest. Different objects, and completion must refuse rather than record either.
        let meta = observed(10, Some(&STANDARD.encode([0_u8; 32])));
        let err = VerifiedContent::verify(Some(10), &reported(10), &meta).unwrap_err();
        assert_eq!(err, FailureReason::ChecksumMismatch);
    }

    #[test]
    fn all_three_sizes_must_agree() {
        // Declared 10, reported 5.
        assert_eq!(
            VerifiedContent::verify(Some(10), &reported(5), &observed(5, None)).unwrap_err(),
            FailureReason::SizeDiffersFromDeclaration
        );
        // Declared 10, reported 10, store holds 11 — the case that catches a truncated multipart
        // upload the client believes succeeded.
        assert_eq!(
            VerifiedContent::verify(Some(10), &reported(10), &observed(11, None)).unwrap_err(),
            FailureReason::SizeDiffersFromStore
        );
    }

    #[test]
    fn a_missing_or_impossible_declaration_refuses_rather_than_guesses() {
        assert_eq!(
            VerifiedContent::verify(None, &reported(10), &observed(10, None)).unwrap_err(),
            FailureReason::NoDeclaredSize
        );
        assert_eq!(
            VerifiedContent::verify(Some(-1), &reported(10), &observed(10, None)).unwrap_err(),
            FailureReason::NoDeclaredSize
        );
    }

    #[test]
    fn a_checksum_that_is_not_lowercase_hex_is_refused_before_anything_else() {
        for bad in [
            "",
            "deadbeef",
            &DIGEST_HEX.to_uppercase(),
            &format!("{DIGEST_HEX}0"),
            &"g".repeat(64),
            &" ".repeat(64),
        ] {
            let report = ReportedContent { size_bytes: 10, sha256_hex: (*bad).to_owned() };
            assert_eq!(
                VerifiedContent::verify(Some(10), &report, &observed(10, None)).unwrap_err(),
                FailureReason::MalformedChecksum,
                "`{bad}` was accepted as a SHA-256"
            );
        }
    }

    #[test]
    fn a_provider_digest_of_the_wrong_length_is_treated_as_absent() {
        let meta = observed(10, Some(&STANDARD.encode([0_u8; 16])));
        let verified = VerifiedContent::verify(Some(10), &reported(10), &meta).unwrap();
        assert_eq!(verified.checksum_evidence(), ChecksumEvidence::ClientDeclared);
    }

    #[test]
    fn every_failure_reason_renders_a_client_error_naming_a_field() {
        for reason in [
            FailureReason::SizeDiffersFromDeclaration,
            FailureReason::SizeDiffersFromStore,
            FailureReason::ChecksumMismatch,
            FailureReason::MalformedChecksum,
            FailureReason::NoDeclaredSize,
        ] {
            let error = reason.to_error();
            assert_eq!(error.status_code(), 400, "{reason}");
            assert!(!reason.as_str().is_empty());
            // No digest and no byte count in the message the client can see.
            let rendered = reason.to_string();
            assert!(!rendered.contains(DIGEST_HEX), "{rendered}");
        }
    }
}
