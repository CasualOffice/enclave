//! The canonical object key, built in exactly one place.
//!
//! `docs/02-HLD.md §7` fixes two layouts:
//!
//! ```text
//! tenant/{tenant_id}/files/{file_id}/versions/{version_id}
//! tenant/{tenant_id}/renditions/{version_id}/{profile}/{artifact}
//! ```
//!
//! Every call site goes through [`ObjectKey`] rather than through `format!`. That is not tidiness.
//! A key layout assembled at each call site drifts — one path writes `versions/`, another writes
//! `version/`, and the divergence is invisible until a migration, a lifecycle rule or a
//! per-tenant deletion has to enumerate objects by prefix and silently misses half of them. The
//! prefix is also the unit that IAM policies and bucket lifecycle rules are written against
//! (`docs/08-BYO-INFRA.md §5`), so a key outside the layout is a key outside the access control
//! that was scoped to it.
//!
//! The parser matters as much as the builders. [`ObjectKey::parse`] is what the store calls on
//! every `&str` key arriving through the [`BlobStore`](crate::BlobStore) trait, so a caller cannot
//! ask the store to sign, copy or delete an arbitrary path — and cannot ask it to touch a key
//! belonging to another tenant without that tenant id being visible in the request.

use core::fmt;

use enclave_core::{FileId, TenantId, VersionId};

/// The root segment of every key. Named so that a bucket shared with other software (or with a
/// future non-object payload) stays partitionable by prefix.
const ROOT: &str = "tenant";
const FILES: &str = "files";
const VERSIONS: &str = "versions";
const RENDITIONS: &str = "renditions";

/// The longest a caller-supplied segment (`profile`, `artifact`) may be.
///
/// S3 keys may be 1024 bytes; this is far below that on purpose. The limit exists to keep a
/// generated key bounded and greppable, not to approach the provider maximum.
const MAX_SEGMENT: usize = 64;

/// A validated object key in the canonical layout.
///
/// Construct one through [`ObjectKey::version`], [`ObjectKey::rendition`] or [`ObjectKey::parse`].
/// There is deliberately no `From<String>`: a key that did not come from one of those three has
/// not been checked against the layout.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    key: String,
    tenant: TenantId,
}

impl ObjectKey {
    /// The key holding one immutable version's bytes.
    ///
    /// Infallible: every component is a UUID, so there is nothing a caller can pass that would
    /// produce an invalid key.
    #[must_use]
    pub fn version(tenant: TenantId, file: FileId, version: VersionId) -> Self {
        Self { key: format!("{ROOT}/{tenant}/{FILES}/{file}/{VERSIONS}/{version}"), tenant }
    }

    /// The key holding one derived preview artifact.
    ///
    /// # Errors
    ///
    /// [`KeyError::Segment`] if `profile` or `artifact` is empty, over-long, or contains anything
    /// outside `[A-Za-z0-9._-]`. The character restriction is the whole point of the fallibility:
    /// `profile` and `artifact` are the only parts of any key that are not UUIDs, so they are the
    /// only place a `../` or an injected `/` could reach the key space.
    pub fn rendition(
        tenant: TenantId,
        version: VersionId,
        profile: &str,
        artifact: &str,
    ) -> Result<Self, KeyError> {
        check_segment("profile", profile)?;
        check_segment("artifact", artifact)?;
        Ok(Self {
            key: format!("{ROOT}/{tenant}/{RENDITIONS}/{version}/{profile}/{artifact}"),
            tenant,
        })
    }

    /// The prefix under which everything belonging to one tenant lives.
    ///
    /// Trailing slash included, because every consumer of this — a `ListObjectsV2` prefix, an IAM
    /// `Resource` ARN, a lifecycle rule — needs one, and a prefix without it also matches a
    /// different tenant whose id happens to share a leading substring.
    #[must_use]
    pub fn tenant_prefix(tenant: TenantId) -> String {
        format!("{ROOT}/{tenant}/")
    }

    /// Re-validates a key that arrived as a string.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the key is not one of the two canonical layouts. Callers should treat a
    /// failure as a bug in the caller, not as a missing object: the only legitimate source of a
    /// key is this module, and a key that does not parse was assembled somewhere it should not
    /// have been.
    pub fn parse(raw: &str) -> Result<Self, KeyError> {
        let parts: Vec<&str> = raw.split('/').collect();
        let malformed = || KeyError::Malformed { key: raw.to_owned() };

        if parts.first() != Some(&ROOT) {
            return Err(malformed());
        }
        let tenant: TenantId =
            parts.get(1).ok_or_else(malformed)?.parse().map_err(|_| malformed())?;

        match parts.get(2).copied() {
            // tenant/{t}/files/{f}/versions/{v}
            Some(FILES) if parts.len() == 6 && parts.get(4) == Some(&VERSIONS) => {
                parts[3].parse::<FileId>().map_err(|_| malformed())?;
                parts[5].parse::<VersionId>().map_err(|_| malformed())?;
            }
            // tenant/{t}/renditions/{v}/{profile}/{artifact}
            Some(RENDITIONS) if parts.len() == 6 => {
                parts[3].parse::<VersionId>().map_err(|_| malformed())?;
                check_segment("profile", parts[4])?;
                check_segment("artifact", parts[5])?;
            }
            _ => return Err(malformed()),
        }

        Ok(Self { key: raw.to_owned(), tenant })
    }

    /// The key as the provider sees it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The tenant this key belongs to, taken from the key itself rather than from a parameter
    /// travelling beside it — the two cannot disagree if there is only one of them.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Whether this key lives under `tenant`'s prefix.
    ///
    /// The guard for any path that has a `RequestContext` in hand and a key from somewhere else:
    /// object storage has no row-level security, so this is where the equivalent check happens.
    #[must_use]
    pub fn belongs_to(&self, tenant: TenantId) -> bool {
        self.tenant == tenant
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)
    }
}

impl AsRef<str> for ObjectKey {
    fn as_ref(&self) -> &str {
        &self.key
    }
}

/// Why a key could not be built or parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// A caller-supplied segment is empty, too long, or contains a disallowed character.
    #[error(
        "object key segment `{field}` must be 1-{max} characters of [A-Za-z0-9._-] \
         and not `.` or `..`"
    )]
    Segment {
        /// Which segment: `profile` or `artifact`.
        field: &'static str,
        /// The configured maximum length.
        max: usize,
    },

    /// The string is not in either canonical layout.
    ///
    /// Carries the key, which is safe to log: a key is composed of identifiers that already appear
    /// in audit rows, and contains no file name, no content and no credential.
    #[error("`{key}` is not a canonical object key (docs/02-HLD.md §7)")]
    Malformed {
        /// The rejected key.
        key: String,
    },
}

/// Accepts only what a key may safely contain.
///
/// An allowlist rather than a denylist. A denylist of `..` and `/` would still admit `%2f`,
/// leading whitespace, a newline, and the Unicode characters that render as a slash — each of
/// which is a way to make two different keys look like one in an audit row.
fn check_segment(field: &'static str, value: &str) -> Result<(), KeyError> {
    let bad = value.is_empty()
        || value.len() > MAX_SEGMENT
        || value == "."
        || value == ".."
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));

    if bad {
        Err(KeyError::Segment { field, max: MAX_SEGMENT })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn ids() -> (TenantId, FileId, VersionId) {
        (
            "11111111-1111-7111-8111-111111111111".parse().unwrap(),
            "22222222-2222-7222-8222-222222222222".parse().unwrap(),
            "33333333-3333-7333-8333-333333333333".parse().unwrap(),
        )
    }

    /// The exact string from `docs/02-HLD.md §7`. Written out literally rather than rebuilt from
    /// the constants, so that renaming a constant fails this test instead of silently changing the
    /// layout of every object already in the bucket.
    #[test]
    fn version_key_matches_the_documented_layout() {
        let (tenant, file, version) = ids();
        assert_eq!(
            ObjectKey::version(tenant, file, version).as_str(),
            "tenant/11111111-1111-7111-8111-111111111111\
             /files/22222222-2222-7222-8222-222222222222\
             /versions/33333333-3333-7333-8333-333333333333"
        );
    }

    #[test]
    fn rendition_key_matches_the_documented_layout() {
        let (tenant, _, version) = ids();
        let key = ObjectKey::rendition(tenant, version, "thumb-256", "page-0001.webp").unwrap();
        assert_eq!(
            key.as_str(),
            "tenant/11111111-1111-7111-8111-111111111111\
             /renditions/33333333-3333-7333-8333-333333333333\
             /thumb-256/page-0001.webp"
        );
    }

    #[test]
    fn tenant_prefix_ends_in_a_slash() {
        let (tenant, _, _) = ids();
        let prefix = ObjectKey::tenant_prefix(tenant);
        assert!(prefix.ends_with('/'), "got: {prefix}");
        assert!(ObjectKey::version(tenant, ids().1, ids().2).as_str().starts_with(&prefix));
    }

    #[test]
    fn rendition_segments_cannot_escape_the_layout() {
        let (tenant, _, version) = ids();
        for hostile in ["..", ".", "", "a/b", "a%2fb", "a b", "a\nb", "../../etc", "ä"] {
            assert!(
                ObjectKey::rendition(tenant, version, hostile, "ok.webp").is_err(),
                "profile `{hostile}` was accepted"
            );
            assert!(
                ObjectKey::rendition(tenant, version, "thumb", hostile).is_err(),
                "artifact `{hostile}` was accepted"
            );
        }
    }

    #[test]
    fn rendition_segments_have_a_length_bound() {
        let (tenant, _, version) = ids();
        let long = "a".repeat(MAX_SEGMENT + 1);
        assert!(ObjectKey::rendition(tenant, version, &long, "ok").is_err());
        assert!(ObjectKey::rendition(tenant, version, &"a".repeat(MAX_SEGMENT), "ok").is_ok());
    }

    #[test]
    fn parse_round_trips_both_layouts_and_recovers_the_tenant() {
        let (tenant, file, version) = ids();
        for built in [
            ObjectKey::version(tenant, file, version),
            ObjectKey::rendition(tenant, version, "pdf", "doc.pdf").unwrap(),
        ] {
            let parsed = ObjectKey::parse(built.as_str()).unwrap();
            assert_eq!(parsed, built);
            assert_eq!(parsed.tenant(), tenant);
            assert!(parsed.belongs_to(tenant));
        }
    }

    #[test]
    fn parse_rejects_anything_outside_the_layout() {
        let (tenant, file, version) = ids();
        let good = ObjectKey::version(tenant, file, version);
        for hostile in [
            "",
            "/",
            "etc/passwd",
            "tenant/not-a-uuid/files/x/versions/y",
            // Right shape, wrong vocabulary.
            "tenant/11111111-1111-7111-8111-111111111111/file/22222222-2222-7222-8222-222222222222/versions/33333333-3333-7333-8333-333333333333",
            // Right prefix, extra segment appended.
            &format!("{good}/../../elsewhere"),
            // Right prefix, truncated.
            "tenant/11111111-1111-7111-8111-111111111111/files",
        ] {
            assert!(ObjectKey::parse(hostile).is_err(), "`{hostile}` parsed as a canonical key");
        }
    }

    #[test]
    fn a_key_does_not_belong_to_another_tenant() {
        let (tenant, file, version) = ids();
        let other: TenantId = "44444444-4444-7444-8444-444444444444".parse().unwrap();
        assert!(!ObjectKey::version(tenant, file, version).belongs_to(other));
    }
}
