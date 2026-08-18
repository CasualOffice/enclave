//! The canonical form of a node name, and what a name may be at all.
//!
//! # Why this is a function and not a convention
//!
//! `files.normalized_name` backs `uq_files_sibling_name`, the partial unique index that makes
//! "two things called the same thing in one folder" impossible (`docs/04-DATA-MODEL.md §8`). A
//! writer and a reader that fold differently do not fail loudly: they produce a *second* row that
//! the index was supposed to reject, and then a lookup that finds whichever one it happens to sort
//! to. The fold therefore lives in one place, and every write goes through it.
//!
//! # The rules, and where they come from
//!
//! The DDL comment fixes two of them — *casefolded + NFC* — and `crates/identity/src/normalize.rs`
//! supplies the other two, because the problem is the same problem. [`enclave_identity::normalize_group_name`] trims
//! and collapses internal whitespace runs before folding case, on the grounds that
//! `"Finance  Leads"` and `"Finance Leads"` naming two different groups is a model nobody can
//! reason about. A folder holding both `Q1  Report.pdf` and `Q1 Report.pdf` is that same
//! unreasonable model, arrived at by the same route (names are typed, and pasted from somewhere
//! else). So the fold here is identity's fold plus the NFC composition the column asks for:
//!
//! 1. split on whitespace and rejoin with single spaces — which trims as a side effect;
//! 2. lowercase;
//! 3. compose to NFC.
//!
//! Composing *after* folding case is deliberate. `"É"` (U+00C9) and `"E"` + U+0301 lowercase to
//! `"é"` and `"e"` + U+0301, and only the final composition makes those the same string. Composing
//! first would work for that example and not for the general case, where a case mapping can emit a
//! decomposed sequence.
//!
//! # Folding happens in Rust, never in SQL
//!
//! No query in this crate calls `lower()` or `normalize()`. PostgreSQL's `lower()` is
//! collation-dependent and the collation is a property of the database, so a restore into a
//! differently-configured cluster would quietly change what collides with what. Folding in the
//! application makes the stored value and the compared value come from the same code path.
//!
//! # Normalization is not validation
//!
//! [`normalize_name`] answers "are these the same name". [`validate_name`] answers "is this a name
//! at all", and it is the one that rejects `/`, `..` and control characters — because
//! [`crate::path`] renders a breadcrumb as a path, and a name containing a separator makes that
//! rendering ambiguous.

use unicode_normalization::UnicodeNormalization as _;

use crate::error::{FilesError, Result};

/// The longest a node name may be, in characters.
///
/// Characters rather than bytes, because the limit a user experiences is the one they can count.
/// 255 is the common denominator of the filesystems a synchronization client will write to
/// (`docs/10-SYNC-AND-EDITING.md`), so a name accepted here can be materialized there.
pub const MAX_NAME_CHARS: usize = 255;

/// Folds a node name into the form stored in `files.normalized_name`.
///
/// See the [module documentation](self) for the four steps and why they are in that order. This
/// function never rejects anything — [`validate_name`] does that — so it is safe to call on a name
/// that came out of the database as well as one on its way in.
#[must_use]
pub fn normalize_name(name: &str) -> String {
    let mut folded = String::with_capacity(name.len());
    for (index, word) in name.split_whitespace().enumerate() {
        if index > 0 {
            folded.push(' ');
        }
        folded.push_str(word);
    }
    folded.to_lowercase().nfc().collect()
}

/// The name as it will be *displayed*, with surrounding whitespace removed.
///
/// Stored in `files.name`. Internal spacing is preserved — the collapse in [`normalize_name`] is
/// about deciding what collides, not about editing what the user typed — but a leading or trailing
/// space is not something anyone means, and it is a classic way to make two rows look identical in
/// a listing.
#[must_use]
pub fn display_name(name: &str) -> String {
    name.trim().to_owned()
}

/// Rejects names that cannot be stored, addressed or rendered.
///
/// # Errors
///
/// [`FilesError::InvalidName`] with a fixed reason:
///
/// * empty, or nothing but whitespace — there is no such node;
/// * longer than [`MAX_NAME_CHARS`];
/// * containing `/` or `\` — [`crate::path::Breadcrumb::to_path`] joins on `/`, and a name that
///   contains the separator makes a path ambiguous to anything that parses one, including the sync
///   client and the object-storage key builder;
/// * containing a control character, `NUL` included — those survive a database round trip and then
///   truncate a C string, a log line or a `Content-Disposition` header somewhere downstream;
/// * `.` or `..` — reserved by every filesystem this can be materialized onto.
pub fn validate_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(FilesError::InvalidName { reason: "a name cannot be empty" });
    }
    if trimmed.chars().count() > MAX_NAME_CHARS {
        return Err(FilesError::InvalidName { reason: "a name is at most 255 characters" });
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err(FilesError::InvalidName { reason: "a name cannot contain a path separator" });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(FilesError::InvalidName {
            reason: "a name cannot contain a control character",
        });
    }
    if trimmed == "." || trimmed == ".." {
        return Err(FilesError::InvalidName { reason: "`.` and `..` are reserved" });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_fold_matches_identitys_rules_for_case_and_whitespace() {
        // Same inputs as `normalize_group_name`'s tests, so a divergence between the two folds is
        // visible here rather than discovered as a duplicate row.
        assert_eq!(normalize_name("  Q1   Report.pdf "), "q1 report.pdf");
        assert_eq!(normalize_name("Q1 Report.pdf"), "q1 report.pdf");
        assert_eq!(normalize_name("budget-2026.xlsx"), "budget-2026.xlsx");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn a_composed_and_a_decomposed_name_fold_to_the_same_string() {
        // The whole reason the column says NFC. Without the composition step these are two
        // different `normalized_name` values, the partial unique index accepts both, and a folder
        // holds two files that render identically in every UI.
        let composed = "Réunion.docx"; // U+00E9
        let decomposed = "Re\u{301}union.docx"; // e + combining acute
        assert_ne!(composed, decomposed, "the test inputs must differ before folding");
        assert_eq!(normalize_name(composed), normalize_name(decomposed));
    }

    #[test]
    fn case_folding_happens_before_composition() {
        // "E" + combining acute must reach U+00E9, which only holds if the compose runs last.
        assert_eq!(normalize_name("E\u{301}"), "\u{e9}");
        assert_eq!(normalize_name("\u{c9}"), "\u{e9}");
    }

    #[test]
    fn the_display_name_keeps_internal_spacing_that_the_fold_collapses() {
        assert_eq!(display_name("  Q1   Report.pdf "), "Q1   Report.pdf");
        assert_eq!(normalize_name("  Q1   Report.pdf "), "q1 report.pdf");
    }

    #[test]
    fn names_that_would_break_a_path_are_rejected() {
        for bad in ["", "   ", "a/b.txt", "a\\b.txt", "with\u{0}nul", "with\ttab", ".", ".."] {
            assert!(
                matches!(validate_name(bad), Err(FilesError::InvalidName { .. })),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn ordinary_names_including_unicode_and_dots_are_accepted() {
        for good in ["report.pdf", "Réunion du 3 mars.docx", "..hidden", "a.b.c", "日本語.txt"]
        {
            assert!(validate_name(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn the_length_limit_counts_characters_and_not_bytes() {
        let at_limit: String = "é".repeat(MAX_NAME_CHARS);
        assert!(at_limit.len() > MAX_NAME_CHARS, "the test input must be multi-byte");
        assert!(validate_name(&at_limit).is_ok());
        assert!(validate_name(&"é".repeat(MAX_NAME_CHARS + 1)).is_err());
    }
}
