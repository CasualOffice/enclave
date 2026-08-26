//! Whether one file may be placed on one device, and what the client is told when it may not.
//!
//! `docs/10-SYNC-AND-EDITING.md §5` lists six conditions and says a file is eligible only when
//! **all** of them hold. This module is that sentence as a type: [`Eligibility`] has one field per
//! condition, none of them optional and none defaulted, so a caller cannot assemble a verdict
//! having forgotten to ask one of the six. A missing answer is a compile error rather than an
//! `Ok(Eligible)`.
//!
//! # The tombstone is not a consolation prize — it is a disclosure, and it is bounded
//!
//! `docs/10 §4` requires that an ineligible file appear as a `TOMBSTONE` **with a reason** rather
//! than being silently omitted, so a client can say *"available on the web only"* instead of losing
//! a file. That is right for a file the caller can see. It would be catastrophic for one they
//! cannot: a tombstone carries a path — a file name, a folder name — and a delta that emitted one
//! for every file in a library would be the cheapest enumeration oracle in the product, handing a
//! caller with no grant at all the entire contents listing of a library they may not browse.
//!
//! So the two are separated, and the separation is [`Visibility`]:
//!
//! * A file the caller **cannot** `file.metadata_read` is **omitted**. Nothing on the wire records
//!   that it exists. This is exactly what `crates/api/src/content.rs`'s listing trim does for the
//!   same reason, and the delta is a listing.
//! * A file the caller **can** read the metadata of, but may not sync, is a **tombstone** naming
//!   the reason. They already know it exists; what they gain is why it is not on their disk.
//!
//! `docs/10 §4`'s sentence is therefore honoured for its actual subject — the file that disappeared
//! from a device — and not extended into an answer about files the caller was never entitled to
//! learn about.
//!
//! # Why the reason has a fixed precedence
//!
//! Several conditions fail together all the time: a `RESTRICTED` document in a sync-disabled
//! library, with no grant. If the reason depended on which check ran first, two replicas could
//! answer the same request differently and a client's UI would flicker between two explanations of
//! one absence. [`Eligibility::verdict`] evaluates in one written order and the order is asserted.

use serde::Serialize;

/// Why a file the caller can see is not on their device.
///
/// The vocabulary is `docs/10 §4`'s, exactly and completely. It is closed for the reason
/// [`enclave_core::ReasonCode`] is closed: a client branches on these strings to decide what to
/// show, and an unrecognised one is a file that silently gets no explanation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(into = "&'static str")]
pub enum TombstoneReason {
    /// The library has `sync_enabled = false`. An administrator's decision about the container,
    /// listed first because it explains every file in it at once and no per-file reason adds
    /// anything.
    LibrarySyncDisabled,
    /// The classification sets `sync_blocked`.
    ClassificationBlocked,
    /// The caller may not take the original bytes at all, so they certainly may not keep a copy.
    /// Distinct from [`Self::PolicyNotEligible`] because it is the one reason with an obvious next
    /// step: the file is still previewable.
    NoDownload,
    /// The caller's grant on this file no longer includes `file.sync`.
    AccessRevoked,
    /// A conditional-access or DLP decision refuses this client, device or network.
    PolicyNotEligible,
    /// Antivirus has not cleared the current version, or there is no readable version.
    /// `CLAUDE.md` rule 9: no read path serves `SCANNING` content, and a sync is a read path.
    Quarantined,
    /// The file was trashed.
    Deleted,
}

impl TombstoneReason {
    /// The wire form, as `docs/10 §4` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LibrarySyncDisabled => "LIBRARY_SYNC_DISABLED",
            Self::ClassificationBlocked => "CLASSIFICATION_BLOCKED",
            Self::NoDownload => "NO_DOWNLOAD",
            Self::AccessRevoked => "ACCESS_REVOKED",
            Self::PolicyNotEligible => "POLICY_NOT_ELIGIBLE",
            Self::Quarantined => "QUARANTINED",
            Self::Deleted => "DELETED",
        }
    }

    /// Every variant, so a test can assert the whole vocabulary against `docs/10 §4`.
    pub const ALL: [Self; 7] = [
        Self::LibrarySyncDisabled,
        Self::ClassificationBlocked,
        Self::NoDownload,
        Self::AccessRevoked,
        Self::PolicyNotEligible,
        Self::Quarantined,
        Self::Deleted,
    ];
}

impl From<TombstoneReason> for &'static str {
    fn from(reason: TombstoneReason) -> Self {
        reason.as_str()
    }
}

/// Whether the caller may be told this file exists at all.
///
/// See the module header. This is a separate question from eligibility and is asked first, because
/// the answer decides between *omit* and *explain*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// The caller may read this file's metadata. A tombstone may name it.
    Visible,
    /// The caller may not. Nothing about it goes on the wire.
    Hidden,
}

/// What the delta does with one feed entry for one caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an eligibility verdict that is neither rendered nor omitted is a file that silently \
              vanished from a device — the failure docs/10 §4 exists to prevent"]
pub enum Verdict {
    /// Place it on the device.
    Eligible,
    /// Tell the caller it exists and why it is not there.
    Tombstone(TombstoneReason),
    /// Say nothing at all.
    Omit,
}

/// The six answers `docs/10 §5` requires, plus the visibility question that precedes them.
///
/// Every field is required. There is no `Default`, no builder with optional steps and no
/// constructor that fills one in — a caller who has not asked one of the six cannot construct this
/// value, which is the whole point of it being a struct rather than a chain of `if`s in a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eligibility {
    /// May the caller know this file exists? Answered by `file.metadata_read` through the chain.
    pub visibility: Visibility,
    /// Is the file live, or has it been trashed?
    pub deleted: bool,
    /// Condition 1: `libraries.sync_enabled`.
    pub library_sync_enabled: bool,
    /// Condition 2: the effective classification does **not** set `sync_blocked`.
    pub classification_permits_sync: bool,
    /// Condition 3a: the chain allowed `file.download`.
    pub download_allowed: bool,
    /// Condition 3b: the chain allowed `file.sync`. **Not** implied by the line above — that is
    /// `CLAUDE.md` rule 6 and the reason both fields exist.
    pub sync_allowed: bool,
    /// Conditions 4 and 5: no stage attached an obligation this path cannot discharge — a
    /// `NO_SYNC` or `NO_DOWNLOAD` from conditional access or DLP.
    pub obligations_dischargeable: bool,
    /// Condition 6: the current version is `AVAILABLE` with `av_status = 'CLEAN'`
    /// (`enclave_versions::READABLE_PREDICATE`).
    pub version_readable: bool,
}

impl Eligibility {
    /// Decides, in one fixed order.
    ///
    /// The order is: visibility, deletion, container, label, permission, obligation, scan. It runs
    /// container-before-file because a sync-disabled library explains every file in it at once, and
    /// permission-before-scan because *"you may not have this"* is the more actionable of the two
    /// for a caller who cannot act on either.
    ///
    /// `download_allowed` is checked before `sync_allowed`, and the pair is checked at all,
    /// because `docs/10 §5` condition 3 requires *both* and `docs/10 §1` states the governing rule
    /// in the same breath: *a client that may not download a file may not sync it*. A caller who
    /// holds `file.download` and not `file.sync` reaches the `AccessRevoked` arm and gets a
    /// tombstone, never bytes (`CLAUDE.md` rule 6).
    pub const fn verdict(self) -> Verdict {
        if matches!(self.visibility, Visibility::Hidden) {
            return Verdict::Omit;
        }
        if self.deleted {
            return Verdict::Tombstone(TombstoneReason::Deleted);
        }
        if !self.library_sync_enabled {
            return Verdict::Tombstone(TombstoneReason::LibrarySyncDisabled);
        }
        if !self.classification_permits_sync {
            return Verdict::Tombstone(TombstoneReason::ClassificationBlocked);
        }
        if !self.download_allowed {
            return Verdict::Tombstone(TombstoneReason::NoDownload);
        }
        if !self.sync_allowed {
            return Verdict::Tombstone(TombstoneReason::AccessRevoked);
        }
        if !self.obligations_dischargeable {
            return Verdict::Tombstone(TombstoneReason::PolicyNotEligible);
        }
        if !self.version_readable {
            return Verdict::Tombstone(TombstoneReason::Quarantined);
        }
        Verdict::Eligible
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Everything holds. The positive control for every negative case below: without it, a bug that
    /// made `verdict` always return a tombstone would pass every other test in this module.
    const fn eligible() -> Eligibility {
        Eligibility {
            visibility: Visibility::Visible,
            deleted: false,
            library_sync_enabled: true,
            classification_permits_sync: true,
            download_allowed: true,
            sync_allowed: true,
            obligations_dischargeable: true,
            version_readable: true,
        }
    }

    #[test]
    fn all_six_conditions_holding_is_the_only_way_to_be_eligible() {
        assert_eq!(eligible().verdict(), Verdict::Eligible);
    }

    /// `CLAUDE.md` rule 6, at the one place the sync path decides it.
    ///
    /// The pair is the assertion: a caller who may download and may not sync is refused, and the
    /// caller who may do both is not — so the refusal is coming from the `sync` answer and not from
    /// something that refuses everybody.
    #[test]
    fn download_does_not_imply_sync() {
        let may_download_may_not_sync = Eligibility { sync_allowed: false, ..eligible() };
        assert_eq!(
            may_download_may_not_sync.verdict(),
            Verdict::Tombstone(TombstoneReason::AccessRevoked),
            "a caller holding file.download and not file.sync was made eligible; that is rule 6 \
             collapsed"
        );
        assert_eq!(eligible().verdict(), Verdict::Eligible, "the positive control");
    }

    /// And the converse, which is the half `docs/10 §1` states outright.
    #[test]
    fn sync_does_not_survive_a_missing_download() {
        let may_sync_may_not_download = Eligibility { download_allowed: false, ..eligible() };
        assert_eq!(
            may_sync_may_not_download.verdict(),
            Verdict::Tombstone(TombstoneReason::NoDownload)
        );
    }

    /// `CLAUDE.md` rule 9. A sync is a read path and unscanned content is not served on one.
    #[test]
    fn an_unscanned_version_is_never_placed_on_a_device() {
        assert_eq!(
            Eligibility { version_readable: false, ..eligible() }.verdict(),
            Verdict::Tombstone(TombstoneReason::Quarantined)
        );
    }

    /// A file the caller may not see produces nothing at all — not even a reason.
    #[test]
    fn an_invisible_file_is_omitted_rather_than_tombstoned() {
        let hidden = Eligibility { visibility: Visibility::Hidden, ..eligible() };
        assert_eq!(
            hidden.verdict(),
            Verdict::Omit,
            "a tombstone carries a path; emitting one for a file the caller may not read turns the \
             delta into a library listing"
        );
        // And it stays omitted whatever else is wrong with it: visibility is asked first, so no
        // combination of the other six can promote a hidden file into an explained one.
        let hidden_and_blocked = Eligibility {
            visibility: Visibility::Hidden,
            deleted: true,
            library_sync_enabled: false,
            classification_permits_sync: false,
            download_allowed: false,
            sync_allowed: false,
            obligations_dischargeable: false,
            version_readable: false,
        };
        assert_eq!(hidden_and_blocked.verdict(), Verdict::Omit);
    }

    /// Each remaining condition, alone, produces its own reason.
    #[test]
    fn every_condition_has_a_reason_of_its_own() {
        let cases: [(Eligibility, TombstoneReason); 4] = [
            (Eligibility { deleted: true, ..eligible() }, TombstoneReason::Deleted),
            (
                Eligibility { library_sync_enabled: false, ..eligible() },
                TombstoneReason::LibrarySyncDisabled,
            ),
            (
                Eligibility { classification_permits_sync: false, ..eligible() },
                TombstoneReason::ClassificationBlocked,
            ),
            (
                Eligibility { obligations_dischargeable: false, ..eligible() },
                TombstoneReason::PolicyNotEligible,
            ),
        ];
        for (eligibility, expected) in cases {
            assert_eq!(eligibility.verdict(), Verdict::Tombstone(expected));
        }
    }

    /// The precedence is fixed, so two replicas cannot explain one absence two ways.
    #[test]
    fn the_reason_does_not_depend_on_which_check_ran_first() {
        let everything_wrong = Eligibility {
            visibility: Visibility::Visible,
            deleted: true,
            library_sync_enabled: false,
            classification_permits_sync: false,
            download_allowed: false,
            sync_allowed: false,
            obligations_dischargeable: false,
            version_readable: false,
        };
        assert_eq!(
            everything_wrong.verdict(),
            Verdict::Tombstone(TombstoneReason::Deleted),
            "deletion is first among the failures a visible file can have"
        );
        // One step in: with the file live, the container's setting is the next explanation.
        assert_eq!(
            Eligibility { deleted: false, ..everything_wrong }.verdict(),
            Verdict::Tombstone(TombstoneReason::LibrarySyncDisabled)
        );
    }

    /// The vocabulary is `docs/10 §4`'s, completely.
    #[test]
    fn the_reason_vocabulary_is_the_documented_one() {
        let rendered: Vec<&str> = TombstoneReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            rendered,
            [
                "LIBRARY_SYNC_DISABLED",
                "CLASSIFICATION_BLOCKED",
                "NO_DOWNLOAD",
                "ACCESS_REVOKED",
                "POLICY_NOT_ELIGIBLE",
                "QUARANTINED",
                "DELETED",
            ]
        );
    }
}
