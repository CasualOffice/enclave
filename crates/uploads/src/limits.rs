//! What a library will accept, checked before a single byte moves.
//!
//! `docs/05-API.md §8`: *`POST /uploads` runs the full policy chain **before** issuing URLs,
//! including quota and file-type checks, so a rejected upload never consumes bandwidth.* That is
//! the whole reason this module exists as a separate step rather than as a check on completion — a
//! 4 GB upload refused after the fact has already cost the user their afternoon and the tenant
//! their egress.
//!
//! # Comparison rules, decided here and nowhere else
//!
//! `enclave_libraries::LibrarySettings` stores extensions *exactly as an administrator typed them*
//! and says so: the upload path decides how an extension is compared. This module is that decision.
//!
//! * The leading dot is optional on both sides — `.docx`, `docx` and `..docx` are the same rule.
//! * Comparison is ASCII-lowercase. `PDF` and `pdf` are the same extension; a non-ASCII extension
//!   is compared as-is after lowercasing, which is the conservative reading — nothing exotic is
//!   silently folded into something an administrator did not write.
//! * **Deny wins.** An extension on both lists is refused, the same way the policy chain resolves a
//!   conflicting grant and deny (`docs/03-LLD.md §12`).
//! * An empty allow-list permits nothing. `Option<Vec<_>>` is not `Vec<_>` precisely so that
//!   "no allow-list" and "an allow-list with nothing on it" stay distinguishable, and the second
//!   one means what it says.
//! * A name with no extension is refused whenever an allow-list exists, because it cannot be on it.
//!
//! # What this module does not do
//!
//! It makes no authorization decision, reads no ACL and consults no quota beyond the per-file
//! ceiling it was handed. Tenant storage quota, classification and DLP are stages of the policy
//! chain and run in the handler before this is reached (`plans/M1-CONTENT-CORE.md` D11).

use enclave_libraries::LibrarySettings;

use crate::error::{Result, UploadError};

/// The longest a file name may be, in characters.
///
/// The same limit `enclave_files::MAX_NAME_CHARS` enforces when the file row is written. Checked
/// here as well, and deliberately duplicated rather than depended upon: this crate refuses the
/// upload *before* URLs exist, and a name that will be rejected at commit is a name that should
/// never have earned a signed URL.
pub const MAX_NAME_CHARS: usize = 255;

/// What a library accepts, resolved into the form the upload path compares against.
///
/// Built from [`LibrarySettings`] rather than assembled field by field at the call site, so a
/// handler cannot pass the blocked list where the allowed one goes and quietly invert the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadLimits {
    max_file_size_bytes: u64,
    allowed: Option<Vec<String>>,
    blocked: Option<Vec<String>>,
}

impl UploadLimits {
    /// Resolves a library's settings against the tenant's default ceiling.
    ///
    /// `libraries.max_file_size_bytes` is nullable and means "use the tenant default"
    /// (`docs/04-DATA-MODEL.md §7`), so the default has to arrive from the caller — this crate has
    /// no tenant-settings reader and inventing one would be a second answer to the same question.
    ///
    /// A negative stored ceiling is impossible through the API and would still decode; it is
    /// treated as zero rather than as "unlimited", because the only safe reading of a nonsensical
    /// limit is the restrictive one.
    #[must_use]
    pub fn from_library(settings: &LibrarySettings, tenant_default_max_bytes: u64) -> Self {
        let max_file_size_bytes = settings
            .max_file_size_bytes
            .map_or(tenant_default_max_bytes, |bytes| u64::try_from(bytes).unwrap_or(0));

        Self {
            max_file_size_bytes,
            allowed: settings.allowed_extensions.as_deref().map(normalize_list),
            blocked: settings.blocked_extensions.as_deref().map(normalize_list),
        }
    }

    /// Limits with no extension rules and one ceiling — the shape a tenant default alone produces.
    #[must_use]
    pub const fn unrestricted_up_to(max_file_size_bytes: u64) -> Self {
        Self { max_file_size_bytes, allowed: None, blocked: None }
    }

    /// The ceiling in force, in bytes.
    #[must_use]
    pub const fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_bytes
    }

    /// Refuses an upload the library will not accept.
    ///
    /// Runs before any URL is issued. The order — name, then extension, then size — is the order
    /// that reports the most actionable failure first; all three are checked against values the
    /// client supplied and none of them against the object store, which has not been touched yet.
    ///
    /// # Errors
    ///
    /// * [`UploadError::InvalidName`] — a name that could not be stored or addressed.
    /// * [`UploadError::ExtensionNotAllowed`] — blocked, or absent from a non-empty allow-list.
    /// * [`UploadError::FileTooLarge`] — over the ceiling.
    pub fn check(&self, name: &str, declared_size: u64) -> Result<()> {
        check_name(name)?;

        let extension = extension_of(name);
        if let Some(blocked) = &self.blocked {
            if let Some(extension) = &extension {
                if blocked.iter().any(|candidate| candidate == extension) {
                    return Err(UploadError::ExtensionNotAllowed { extension: extension.clone() });
                }
            }
        }
        if let Some(allowed) = &self.allowed {
            let permitted = extension
                .as_ref()
                .is_some_and(|extension| allowed.iter().any(|candidate| candidate == extension));
            if !permitted {
                return Err(UploadError::ExtensionNotAllowed {
                    extension: extension.unwrap_or_default(),
                });
            }
        }

        if declared_size > self.max_file_size_bytes {
            return Err(UploadError::FileTooLarge { limit: self.max_file_size_bytes });
        }

        Ok(())
    }
}

/// The comparable form of one configured extension.
fn normalize_extension(value: &str) -> String {
    value.trim().trim_start_matches('.').to_lowercase()
}

/// The comparable form of a configured list, with empty entries dropped.
///
/// An entry that normalizes to nothing — `"."`, `"  "` — would otherwise match every name that has
/// no extension, turning a typo in an allow-list into a rule that admits extensionless files.
fn normalize_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| normalize_extension(value))
        .filter(|value| !value.is_empty())
        .collect()
}

/// The extension of a file name, in comparable form, or `None` when it has none.
///
/// A leading dot does not make an extension: `.gitignore` is a name, not an extensionless file
/// called `gitignore`, and treating it as the latter would let a `.exe` block be evaded by a
/// leading dot on some filesystems. Only a dot with something before it separates an extension.
#[must_use]
pub fn extension_of(name: &str) -> Option<String> {
    let trimmed = name.trim();
    let (stem, extension) = trimmed.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }
    Some(normalize_extension(extension))
}

/// The name checks that must happen before a URL exists.
///
/// Mirrors `enclave_files::validate_name`, whose failures are the ones the commit would hit. See
/// [`MAX_NAME_CHARS`] for why this is a deliberate duplicate rather than a dependency.
fn check_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(UploadError::InvalidName { reason: "a name cannot be empty" });
    }
    if trimmed.chars().count() > MAX_NAME_CHARS {
        return Err(UploadError::InvalidName { reason: "a name is at most 255 characters" });
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(UploadError::InvalidName { reason: "a name cannot contain a path separator" });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(UploadError::InvalidName {
            reason: "a name cannot contain a control character",
        });
    }
    if trimmed == "." || trimmed == ".." {
        return Err(UploadError::InvalidName { reason: "`.` and `..` are reserved" });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_libraries::{ExternalSharing, VersioningMode};

    use super::*;

    fn settings(
        allowed: Option<&[&str]>,
        blocked: Option<&[&str]>,
        max: Option<i64>,
    ) -> LibrarySettings {
        let owned = |list: Option<&[&str]>| {
            list.map(|items| items.iter().map(|item| (*item).to_owned()).collect::<Vec<_>>())
        };
        LibrarySettings {
            name: "Contracts".to_owned(),
            slug: "contracts".to_owned(),
            inherit_permissions: true,
            default_classification_id: None,
            versioning_mode: VersioningMode::MajorMinor,
            version_limit: None,
            require_checkout: false,
            require_approval: false,
            allowed_extensions: owned(allowed),
            blocked_extensions: owned(blocked),
            max_file_size_bytes: max,
            external_sharing: ExternalSharing::Disabled,
            ai_indexing_enabled: false,
            mcp_visible: false,
            sync_enabled: false,
            storage_profile_id: None,
            retention_policy_id: None,
        }
    }

    #[test]
    fn the_extension_is_taken_case_insensitively_and_without_its_dot() {
        assert_eq!(extension_of("Report.PDF").as_deref(), Some("pdf"));
        assert_eq!(extension_of("archive.tar.gz").as_deref(), Some("gz"));
        assert_eq!(extension_of("  spaced.docx  ").as_deref(), Some("docx"));
        assert_eq!(extension_of("README"), None);
        // A dotfile is a name, not an extension. Treating `.exe` as the extension `exe` here
        // would be right; treating `.gitignore` as `gitignore` is what must not happen.
        assert_eq!(extension_of(".gitignore"), None);
        assert_eq!(extension_of("trailing."), None);
    }

    #[test]
    fn a_blocked_extension_is_refused_however_it_is_spelled() {
        let limits =
            UploadLimits::from_library(&settings(None, Some(&[".EXE", "bat"]), None), 1024);
        for name in ["setup.exe", "setup.EXE", "setup.ExE", "run.bat"] {
            let err = limits.check(name, 10).unwrap_err();
            assert!(matches!(err, UploadError::ExtensionNotAllowed { .. }), "{name}: {err:?}");
        }
        assert!(limits.check("notes.txt", 10).is_ok());
    }

    #[test]
    fn deny_wins_over_allow() {
        let limits = UploadLimits::from_library(
            &settings(Some(&["pdf", "exe"]), Some(&["exe"]), None),
            1024,
        );
        assert!(limits.check("brief.pdf", 10).is_ok());
        assert!(limits.check("brief.exe", 10).is_err());
    }

    #[test]
    fn an_empty_allow_list_permits_nothing() {
        let limits = UploadLimits::from_library(&settings(Some(&[]), None, None), 1024);
        assert!(limits.check("brief.pdf", 10).is_err());
        assert!(limits.check("brief", 10).is_err());
    }

    #[test]
    fn no_allow_list_permits_anything_not_blocked() {
        let limits = UploadLimits::from_library(&settings(None, None, None), 1024);
        assert!(limits.check("brief.pdf", 10).is_ok());
        assert!(limits.check("brief", 10).is_ok());
    }

    #[test]
    fn a_name_with_no_extension_cannot_satisfy_an_allow_list() {
        let limits = UploadLimits::from_library(&settings(Some(&["pdf"]), None, None), 1024);
        let err = limits.check("Makefile", 10).unwrap_err();
        assert!(
            matches!(err, UploadError::ExtensionNotAllowed { extension } if extension.is_empty())
        );
    }

    #[test]
    fn a_junk_entry_in_a_list_does_not_become_a_rule_that_matches_everything() {
        let limits =
            UploadLimits::from_library(&settings(None, Some(&[".", "  ", ""]), None), 1024);
        assert!(limits.check("brief.pdf", 10).is_ok());
        assert!(limits.check("Makefile", 10).is_ok());
    }

    #[test]
    fn the_librarys_ceiling_overrides_the_tenant_default_and_the_default_applies_when_it_is_null() {
        let library = UploadLimits::from_library(&settings(None, None, Some(100)), 10_000);
        assert_eq!(library.max_file_size_bytes(), 100);
        assert!(library.check("brief.pdf", 100).is_ok(), "the ceiling itself is allowed");
        assert!(matches!(
            library.check("brief.pdf", 101).unwrap_err(),
            UploadError::FileTooLarge { limit: 100 }
        ));

        let inherited = UploadLimits::from_library(&settings(None, None, None), 10_000);
        assert_eq!(inherited.max_file_size_bytes(), 10_000);
    }

    #[test]
    fn a_nonsensical_stored_ceiling_refuses_rather_than_becoming_unlimited() {
        let limits = UploadLimits::from_library(&settings(None, None, Some(-1)), 10_000);
        assert_eq!(limits.max_file_size_bytes(), 0);
        assert!(limits.check("brief.pdf", 1).is_err());
        // A zero-byte file is still a legitimate file.
        assert!(limits.check("brief.pdf", 0).is_ok());
    }

    #[test]
    fn a_name_that_could_not_be_stored_is_refused_before_the_extension_is_even_considered() {
        let limits = UploadLimits::from_library(&settings(Some(&["pdf"]), None, None), 1024);
        for (name, _) in [
            ("", "empty"),
            ("   ", "whitespace"),
            ("../escape.pdf", "separator"),
            ("dir\\escape.pdf", "separator"),
            ("bell\u{7}.pdf", "control"),
            (".", "reserved"),
            ("..", "reserved"),
        ] {
            assert!(
                matches!(limits.check(name, 1), Err(UploadError::InvalidName { .. })),
                "`{name}` was not refused as a name"
            );
        }

        let long = format!("{}.pdf", "a".repeat(MAX_NAME_CHARS));
        assert!(matches!(limits.check(&long, 1), Err(UploadError::InvalidName { .. })));
    }

    #[test]
    fn unrestricted_up_to_is_a_ceiling_and_nothing_else() {
        let limits = UploadLimits::unrestricted_up_to(64);
        assert!(limits.check("setup.exe", 64).is_ok());
        assert!(limits.check("setup.exe", 65).is_err());
    }
}
