//! The object key an upload's bytes are staged under, and the identifiers it carries.
//!
//! # Why the staged key *is* the final version key
//!
//! `docs/03-LLD.md §15` says bytes are staged under an upload-scoped key and promoted on commit,
//! because blob storage cannot join a SQL transaction. What "promotion" means is the decision this
//! module makes, and it makes it by **allocating the version's identifiers when the session is
//! created** rather than when the version row is written.
//!
//! The session therefore stages straight to `tenant/{t}/files/{f}/versions/{v}`
//! (`docs/02-HLD.md §7`), and commit is the `INSERT` that makes a row point at those bytes. Nothing
//! is copied. The alternative — a separate staging prefix followed by a server-side copy on commit
//! — was rejected for two reasons:
//!
//! 1. **The 5 GB exit criterion.** `S3:CopyObject` tops out at 5 GB, so anything larger needs a
//!    multipart copy, which [`BlobStore`](enclave_storage::BlobStore) deliberately does not
//!    expose. The commit path for the largest supported upload would be the one path with no
//!    implementation.
//! 2. **A copy is a second set of bytes.** Until the copy finished, the same content would exist
//!    twice under two keys, and a failure between the two would leave an orphan that looks exactly
//!    like a legitimate object.
//!
//! What the LLD asks for is preserved exactly: the key is scoped to one upload (its `VersionId` is
//! minted by the session and never reused), the bytes are unreachable until a row references them,
//! and an orphan — a session that expired or was aborted — is released by
//! [`crate::reaper`].
//!
//! # Where the identifiers come back from
//!
//! `upload_sessions` has one column for the key and no columns for the identifiers inside it
//! (`docs/04-DATA-MODEL.md §8`), so [`StagedObject::parse`] recovers them from the key. The layout
//! is validated by [`ObjectKey::parse`] first — this module never decides whether a key is
//! canonical — and only then split. `key_round_trips_through_the_parser` fails loudly if
//! `enclave-storage` ever changes the layout, which is the check that makes the split safe.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId, VersionId};
use enclave_storage::{CompletedPart, ObjectKey, PartTarget, UploadSession, UploadTarget};
use url::Url;

use crate::error::{Result, UploadError};

/// The segment that distinguishes the version layout from the rendition layout.
const FILES_SEGMENT: &str = "files";

/// Where one upload session's bytes live, and the identifiers the eventual version will carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedObject {
    key: ObjectKey,
    file: FileId,
    version: VersionId,
}

impl StagedObject {
    /// Allocates the key for a new session.
    ///
    /// `file` is the existing file when this is a new version of one, and a freshly minted
    /// [`FileId`] when the upload will create the file — in which case the same id becomes the
    /// file's own when the commit happens, so the key never has to be rewritten.
    #[must_use]
    pub fn allocate(tenant: TenantId, file: FileId) -> Self {
        let version = VersionId::new_v7();
        Self { key: ObjectKey::version(tenant, file, version), file, version }
    }

    /// Recovers a staged object from the stored key.
    ///
    /// # Errors
    ///
    /// [`UploadError::MalformedRow`] if the key is not a canonical *version* key. A rendition key
    /// parses as canonical and is still wrong here, so the layout is checked as well as the shape.
    pub fn parse(raw: &str) -> Result<Self> {
        let malformed = || UploadError::MalformedRow {
            column: "staged_key",
            reason: "not a canonical version object key (docs/02-HLD.md §7)",
        };

        let key = ObjectKey::parse(raw).map_err(|_| malformed())?;

        // `ObjectKey::parse` has already established that this is one of the two canonical layouts
        // and that every identifier in it is a UUID. All that is left is to decide which layout,
        // and to lift the two identifiers out of it.
        let segments: Vec<&str> = raw.split('/').collect();
        if segments.get(2) != Some(&FILES_SEGMENT) {
            return Err(malformed());
        }
        let file: FileId =
            segments.get(3).ok_or_else(malformed)?.parse().map_err(|_| malformed())?;
        let version: VersionId =
            segments.get(5).ok_or_else(malformed)?.parse().map_err(|_| malformed())?;

        Ok(Self { key, file, version })
    }

    /// The key itself.
    #[must_use]
    pub const fn key(&self) -> &ObjectKey {
        &self.key
    }

    /// The key as the provider and the `staged_key` column see it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.key.as_str()
    }

    /// The file these bytes belong to — existing, or the one the commit will create.
    #[must_use]
    pub const fn file(&self) -> FileId {
        self.file
    }

    /// The version these bytes will become, allocated when the session was created.
    #[must_use]
    pub const fn version(&self) -> VersionId {
        self.version
    }

    /// The tenant the key is under, read from the key rather than from a parameter beside it.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.key.tenant()
    }
}

/// Rebuilds the [`enclave_storage::UploadSession`] that `complete_upload` needs, from the row and
/// the parts the client reported.
///
/// # The part list, and why it is the client's
///
/// [`BlobStore::create_upload`](enclave_storage::BlobStore::create_upload) returns pre-signed part
/// URLs, and none of them is stored: they are short-lived by design
/// (`plans/M1-CONTENT-CORE.md` D14) and re-deriving them at completion would mean minting URLs
/// nobody asked for. `complete_upload` reads only `parts.len()` from that list — it uses
/// `completed_parts` for the actual completion — so the reconstruction gives it the client's own
/// list and lets the provider be the judge — which it is: `CompleteMultipartUpload` rejects a
/// missing part or a wrong ETag itself, and the size the platform records comes from `HeadObject`
/// afterwards, never from this list.
///
/// The `url` on each rebuilt part is a `https://…invalid/` sentinel. RFC 2606 reserves `.invalid`
/// precisely so that a name can never resolve, and these values are never returned to a client —
/// see `rebuilt_part_urls_can_never_resolve`.
pub(crate) fn completion_session(
    staged: &StagedObject,
    content_length: u64,
    multipart_id: Option<&str>,
    reported_parts: Vec<CompletedPart>,
    expires_at: DateTime<Utc>,
) -> Result<UploadSession> {
    let target = match multipart_id {
        None => UploadTarget::Single { url: sentinel_url(0)? },
        Some(upload_id) => {
            let mut parts = Vec::with_capacity(reported_parts.len());
            for part in &reported_parts {
                parts.push(PartTarget {
                    part_number: part.part_number,
                    offset: 0,
                    length: 0,
                    url: sentinel_url(part.part_number)?,
                });
            }
            UploadTarget::Multipart { upload_id: upload_id.to_owned(), parts }
        }
    };

    let mut session = UploadSession {
        key: staged.key().clone(),
        content_length,
        target,
        expires_at,
        completed_parts: Vec::new(),
    };
    for part in reported_parts {
        session.record_part(part);
    }
    Ok(session)
}

/// A URL that cannot resolve, for the rebuilt part list described on [`completion_session`].
fn sentinel_url(part_number: u32) -> Result<Url> {
    format!("https://upload.invalid/part/{part_number}").parse().map_err(|_| {
        // Unreachable: the string is a literal with a decimal number in it. Reported rather than
        // unwrapped because the workspace warns on `unwrap`, and an "impossible" panic in the
        // completion path would take a 5 GB upload with it.
        UploadError::MalformedRow {
            column: "staged_key",
            reason: "the completion placeholder URL failed to parse",
        }
    })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn ids() -> (TenantId, FileId) {
        (TenantId::new_v7(), FileId::new_v7())
    }

    /// The check that makes [`StagedObject::parse`]'s split safe: everything this module knows
    /// about the layout is re-derived from what `enclave-storage` builds.
    #[test]
    fn key_round_trips_through_the_parser() {
        let (tenant, file) = ids();
        let staged = StagedObject::allocate(tenant, file);

        let parsed = StagedObject::parse(staged.as_str()).unwrap();
        assert_eq!(parsed, staged);
        assert_eq!(parsed.file(), file);
        assert_eq!(parsed.version(), staged.version());
        assert_eq!(parsed.tenant(), tenant);
    }

    #[test]
    fn every_session_gets_its_own_version_id() {
        let (tenant, file) = ids();
        assert_ne!(
            StagedObject::allocate(tenant, file).version(),
            StagedObject::allocate(tenant, file).version(),
            "two sessions for the same file would stage over each other"
        );
    }

    #[test]
    fn a_rendition_key_is_canonical_and_still_refused() {
        let (tenant, _) = ids();
        let rendition =
            ObjectKey::rendition(tenant, VersionId::new_v7(), "thumb", "a.webp").unwrap();
        assert!(ObjectKey::parse(rendition.as_str()).is_ok());
        assert!(StagedObject::parse(rendition.as_str()).is_err());
    }

    #[test]
    fn anything_outside_the_layout_is_refused() {
        for hostile in ["", "/", "etc/passwd", "tenant/x/files/y/versions/z", "../../elsewhere"] {
            assert!(StagedObject::parse(hostile).is_err(), "`{hostile}` parsed");
        }
    }

    #[test]
    fn rebuilt_part_urls_can_never_resolve() {
        let (tenant, file) = ids();
        let staged = StagedObject::allocate(tenant, file);
        let parts = vec![
            CompletedPart { part_number: 2, etag: "b".to_owned() },
            CompletedPart { part_number: 1, etag: "a".to_owned() },
        ];

        let session = completion_session(&staged, 42, Some("upload-1"), parts, Utc::now()).unwrap();

        assert_eq!(session.expected_parts(), 2);
        // Ordered and de-duplicated by `record_part`, which is what S3 requires.
        let numbers: Vec<u32> = session.completed_parts.iter().map(|p| p.part_number).collect();
        assert_eq!(numbers, vec![1, 2]);

        let UploadTarget::Multipart { parts, upload_id } = &session.target else {
            panic!("a session with a multipart id must rebuild as multipart");
        };
        assert_eq!(upload_id, "upload-1");
        for part in parts {
            assert_eq!(
                part.url.host_str().and_then(|host| host.rsplit('.').next()),
                Some("invalid"),
                "a rebuilt part URL must be unresolvable (RFC 2606)"
            );
        }
    }

    #[test]
    fn a_session_without_a_multipart_id_rebuilds_as_single_shot() {
        let (tenant, file) = ids();
        let staged = StagedObject::allocate(tenant, file);
        let session = completion_session(&staged, 42, None, Vec::new(), Utc::now()).unwrap();
        assert!(matches!(session.target, UploadTarget::Single { .. }));
        assert_eq!(session.expected_parts(), 1);
    }
}
