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
//! S3-compatible backends only return `x-amz-checksum-sha256` for objects uploaded *with* a
//! checksum header, so whether there is a provider digest to compare against is decided long before
//! this module runs — at `POST /uploads`, where
//! [`BlobStore::create_upload`](enclave_storage::BlobStore::create_upload) signs the header into the
//! URL and thereby obliges the client to send it.
//!
//! When the provider has no digest of its own anyway, [`VerifiedContent::verify`] **refuses**
//! ([`FailureReason::ChecksumUnconfirmed`]). It used to record the client's value and mark it
//! unconfirmed with a `ChecksumEvidence` enum that nothing outside this module read except one log
//! field — which is `ENC-820`: a client could declare a digest of all zeroes over a real object and
//! get `202`, with the zeroes persisted on an immutable column that a later integrity check reads as
//! evidence. A digest nobody verified is worse than an absent one, because absent reads as unknown
//! and stored reads as proof.
//!
//! So there is no longer any evidence level to carry. [`VerifiedContent`] exists **only** when the
//! object store computed the digest itself and it matched, and that is now a fact about the type
//! rather than a field on it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use enclave_core::{Dependency, Error as CoreError, FieldError, ValidationCode};
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

    /// The object store holds no SHA-256 of its own, so nothing has checked the reported one.
    ///
    /// Not reachable through a session this crate created against a store that honoured
    /// `UploadRequest::checksum_sha256` — the header is signed into the pre-signed URL, so a `PUT`
    /// that omitted it never succeeded. What it catches is the deployment where that stopped being
    /// true: a BYO S3-compatible backend that accepts the header and does not report the digest, or
    /// a session whose bytes arrived by some other route.
    ///
    /// Refusing is the only honest answer available. `file_versions.checksum_sha256` is `NOT NULL`
    /// and immutable once written (`plans/M1-CONTENT-CORE.md` D12), so there is no way to record
    /// *"this digest is the client's word"* on the row — the choice is between a verified digest and
    /// no version at all, and `ENC-820` is what choosing the third, unavailable option looked like.
    #[error("the object store computed no SHA-256, so the reported one is unverified")]
    ChecksumUnconfirmed,

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
            Self::ChecksumUnconfirmed => "CHECKSUM_UNCONFIRMED",
            Self::MalformedChecksum => "MALFORMED_CHECKSUM",
            Self::NoDeclaredSize => "NO_DECLARED_SIZE",
        }
    }

    /// The canonical error a handler returns for this failure.
    ///
    /// Five of the six are `400`s naming the field the client got wrong, because five of the six
    /// *are* client mistakes: the platform's own numbers came from the object store.
    ///
    /// [`FailureReason::ChecksumUnconfirmed`] is the exception and is a `503`. Nothing the client
    /// sent is wrong — the deployment's object store did not produce a digest it was asked for — and
    /// answering `400 sha256` would tell a user their file was corrupt when what is actually broken
    /// is the backend behind them. The session is still persisted `FAILED`, because retrying against
    /// the same store cannot succeed.
    #[must_use]
    pub fn to_error(self) -> CoreError {
        if matches!(self, Self::ChecksumUnconfirmed) {
            return CoreError::Upstream { dependency: Dependency::ObjectStorage, retryable: false };
        }
        let field = match self {
            Self::SizeDiffersFromDeclaration
            | Self::SizeDiffersFromStore
            | Self::NoDeclaredSize => "sizeBytes",
            Self::ChecksumMismatch | Self::ChecksumUnconfirmed | Self::MalformedChecksum => {
                "sha256"
            }
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
///
/// **Its existence is the guarantee.** One of these means the object store computed this digest
/// over the bytes it holds and it matched what the client reported — not that the value was
/// plausible, and not that it was the client's word marked as such. There is no unconfirmed
/// variant to check for, and therefore none for a caller to forget to check for, which is exactly
/// what `ENC-820` was: the distinction existed, was correct, and was read by one log field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContent {
    size_bytes: u64,
    sha256_hex: String,
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

        match observed.checksum_sha256.as_deref().and_then(decode_provider_sha256) {
            Some(provider_hex) if provider_hex == reported.sha256_hex => {}
            Some(_) => return Err(FailureReason::ChecksumMismatch),
            // The provider has no digest of its own, so nothing has compared the reported one
            // against the bytes. Refused rather than recorded — see the module documentation and
            // `FailureReason::ChecksumUnconfirmed`.
            None => return Err(FailureReason::ChecksumUnconfirmed),
        }

        Ok(Self { size_bytes: reported.size_bytes, sha256_hex: reported.sha256_hex.clone() })
    }

    /// The verified size, in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The lowercase hex SHA-256, as the object store computed it and the client reported it.
    #[must_use]
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

/// Turns a provider's base64 SHA-256 into the lowercase hex the platform records.
///
/// The inverse of `enclave_storage`'s hex-to-base64 conversion, which is what puts the digest on
/// the pre-signed `PUT` in the first place; both are tested against the same vector.
///
/// Returns `None` when the provider sent no usable digest — absent, not base64, or not 32 bytes.
/// A malformed provider digest is treated exactly as an absent one: the caller refuses the
/// completion either way, so it is not classified as a mismatch, which would tell the client its
/// bytes were wrong when what is wrong is the backend.
///
/// A composite multipart checksum (`…=-4`) lands here too and fails to decode, which is the safe
/// reading: it is a checksum of part checksums and is *not* the whole-object SHA-256 being
/// compared. `enclave_storage` refuses to issue a checksum-bearing multipart session at all, so
/// this is a second line rather than the only one.
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

    /// The positive control for every refusal below: a digest the provider confirmed is accepted,
    /// so "refused" is not the only answer this function knows.
    #[test]
    fn a_provider_confirmed_digest_is_the_only_way_to_build_verified_content() {
        let verified =
            VerifiedContent::verify(Some(10), &reported(10), &observed(10, Some(DIGEST_B64)))
                .unwrap();
        assert_eq!(verified.size_bytes(), 10);
        assert_eq!(verified.sha256_hex(), DIGEST_HEX);
    }

    /// `ENC-820`. This is the case that used to return `Ok` with the client's word attached.
    ///
    /// MinIO returns no `ChecksumSHA256` for an ordinary pre-signed `PUT`, so this arm was the
    /// *ordinary* path rather than an edge: every upload on the shipped stack took it, and every
    /// digest it produced was the client's unverified claim recorded on an immutable column.
    #[test]
    fn a_provider_that_computed_no_digest_is_refused_rather_than_recorded() {
        assert_eq!(
            VerifiedContent::verify(Some(10), &reported(10), &observed(10, None)).unwrap_err(),
            FailureReason::ChecksumUnconfirmed
        );
    }

    /// And the refusal is not a `400` blaming the client, because the client did nothing wrong.
    #[test]
    fn an_unconfirmable_digest_reports_the_backend_and_not_the_clients_field() {
        let error = FailureReason::ChecksumUnconfirmed.to_error();
        assert_eq!(error.status_code(), 503, "a backend that cannot confirm is not a bad request");
        assert!(
            !matches!(error, CoreError::Validation(_)),
            "the client's `sha256` was not the problem"
        );
        // Every other reason stays the `400` naming a field that `to_error` promises.
        for reason in [
            FailureReason::SizeDiffersFromDeclaration,
            FailureReason::SizeDiffersFromStore,
            FailureReason::ChecksumMismatch,
            FailureReason::MalformedChecksum,
            FailureReason::NoDeclaredSize,
        ] {
            assert_eq!(reason.to_error().status_code(), 400, "{reason}");
        }
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
        // Declared 10, reported 5. The store's digest is present and correct throughout, so a size
        // failure is what is being asserted rather than the checksum refusal beneath it.
        assert_eq!(
            VerifiedContent::verify(Some(10), &reported(5), &observed(5, Some(DIGEST_B64)))
                .unwrap_err(),
            FailureReason::SizeDiffersFromDeclaration
        );
        // Declared 10, reported 10, store holds 11 — the case that catches a truncated multipart
        // upload the client believes succeeded.
        assert_eq!(
            VerifiedContent::verify(Some(10), &reported(10), &observed(11, Some(DIGEST_B64)))
                .unwrap_err(),
            FailureReason::SizeDiffersFromStore
        );
    }

    #[test]
    fn a_missing_or_impossible_declaration_refuses_rather_than_guesses() {
        assert_eq!(
            VerifiedContent::verify(None, &reported(10), &observed(10, Some(DIGEST_B64)))
                .unwrap_err(),
            FailureReason::NoDeclaredSize
        );
        assert_eq!(
            VerifiedContent::verify(Some(-1), &reported(10), &observed(10, Some(DIGEST_B64)))
                .unwrap_err(),
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
                VerifiedContent::verify(Some(10), &report, &observed(10, Some(DIGEST_B64)))
                    .unwrap_err(),
                FailureReason::MalformedChecksum,
                "`{bad}` was accepted as a SHA-256"
            );
        }
    }

    /// A provider digest this code cannot read is treated as no digest at all — and therefore
    /// refused, not accepted. The three shapes are the ones a real backend produces: a truncated
    /// value, something that is not base64, and a *composite* multipart checksum, whose `-N` suffix
    /// is the provider saying "this is a checksum of checksums, not of your object".
    #[test]
    fn a_provider_digest_this_code_cannot_read_is_refused_and_not_waved_through() {
        for unreadable in
            [STANDARD.encode([0_u8; 16]), "not base64 at all".to_owned(), format!("{DIGEST_B64}-4")]
        {
            let meta = observed(10, Some(&unreadable));
            assert_eq!(
                VerifiedContent::verify(Some(10), &reported(10), &meta).unwrap_err(),
                FailureReason::ChecksumUnconfirmed,
                "`{unreadable}` was accepted as evidence"
            );
        }
    }

    #[test]
    fn no_failure_reason_puts_a_digest_or_a_byte_count_in_the_message() {
        for reason in [
            FailureReason::SizeDiffersFromDeclaration,
            FailureReason::SizeDiffersFromStore,
            FailureReason::ChecksumMismatch,
            FailureReason::ChecksumUnconfirmed,
            FailureReason::MalformedChecksum,
            FailureReason::NoDeclaredSize,
        ] {
            assert!(!reason.as_str().is_empty());
            // No digest and no byte count in the message the client can see.
            let rendered = reason.to_string();
            assert!(!rendered.contains(DIGEST_HEX), "{rendered}");
        }
    }
}
