//! Bounded archive expansion: depth, entry count, expanded size and expansion ratio.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §6.2`: *"Archives are expanded to a configured depth (default 5)
//! with total-size and entry-count caps, to resist decompression bombs."*
//!
//! # Where the expansion actually happens, and why this is here anyway
//!
//! **This crate does not decompress anything.** It has no zip, tar or 7z parser and should not
//! acquire one: writing an archive walker means parsing hostile input in the API process, which is
//! a larger attack surface than the bomb it defends against. clamd already expands containers, in
//! its own process, with `MaxRecursion`, `MaxFiles`, `MaxScanSize` and `MaxFileSize`.
//!
//! What this module owns is the *budget* — the numbers, in one place, in a form that can be
//! asserted against:
//!
//! * [`ArchiveLimits`] is the single definition of the caps. `clamd.conf` is generated from it
//!   (see [`ArchiveLimits::clamd_settings`]), so the engine and the platform cannot drift into
//!   disagreeing about what "depth 5" means.
//! * [`ArchiveBudget`] is the accounting an expansion drives, used by the ingest worker when it
//!   walks a container itself — for extraction and text indexing — and by every future engine that
//!   reports per-entry progress rather than enforcing limits for us.
//! * [`LimitExceeded`] is what both paths turn into
//!   [`ScanVerdict::Unsupported`](crate::ScanVerdict::Unsupported), which is exactly the verdict
//!   `§6.2` attaches "exceeding depth limits" to.
//!
//! The property worth stating: [`ArchiveBudget`] refuses **before** the work, not after. A cap
//! checked against bytes already written is not a defence against a bomb — it is a record of
//! having been hit by one.

use enclave_config::AntivirusConfig;

/// The caps applied to a container.
///
/// # Defaults
///
/// `max_depth` is `docs/06-SECURITY-DLP-ACCESS.md §6.2`'s stated default of 5, and is the one
/// number [`AntivirusConfig`] currently carries (`antivirus.archive_depth`). The other three have
/// no configuration field yet; the values here are the ClamAV upstream defaults, which are known
/// to hold against the classic `42.zip` family. They are `pub` fields so a caller can lower them,
/// and should gain configuration keys when a tenant needs to — flagged to the integrator rather
/// than added to `enclave-config`, which this task does not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// How many nested containers to descend through. `0` means "do not open archives at all".
    pub max_depth: u32,
    /// How many entries may be examined across the whole container tree.
    pub max_entries: u32,
    /// Total expanded bytes across the whole container tree.
    pub max_expanded_bytes: u64,
    /// Maximum expanded:compressed ratio for a single entry.
    ///
    /// The cap that catches the bomb the other three miss: one 4 GB entry inside a 4 MB archive
    /// is within any plausible entry count and depth, and is refused here at 1000:1 before a byte
    /// of it is written.
    pub max_ratio: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_entries: 10_000,
            max_expanded_bytes: 1024 * 1024 * 1024,
            max_ratio: 1000,
        }
    }
}

impl ArchiveLimits {
    /// Takes the depth from `antivirus.archive_depth` and leaves the rest at their defaults.
    #[must_use]
    pub fn from_config(config: &AntivirusConfig) -> Self {
        Self { max_depth: config.archive_depth, ..Self::default() }
    }

    /// The `clamd.conf` directives that mirror these caps.
    ///
    /// Returned as pairs rather than written to a file: this crate does not own deployment. The
    /// point is that the numbers are derived from [`ArchiveLimits`] rather than typed a second
    /// time into a config template, so lowering `max_depth` here cannot leave clamd descending
    /// further than the platform believes it does.
    #[must_use]
    pub fn clamd_settings(&self) -> Vec<(&'static str, String)> {
        vec![
            ("MaxRecursion", self.max_depth.to_string()),
            ("MaxFiles", self.max_entries.to_string()),
            ("MaxScanSize", format!("{}", self.max_expanded_bytes)),
            ("MaxFileSize", format!("{}", self.max_expanded_bytes)),
        ]
    }

    /// A fresh budget under these limits.
    #[must_use]
    pub const fn budget(self) -> ArchiveBudget {
        ArchiveBudget { limits: self, depth: 0, entries: 0, expanded_bytes: 0 }
    }
}

/// Which cap an expansion hit.
///
/// Every variant carries the limit that was in force, because the operator's next question is
/// always "what is it set to", and the alternative is a log line that says only "too deep".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LimitExceeded {
    /// The container nests deeper than `max_depth`.
    #[error("archive nests deeper than the configured limit of {limit}")]
    Depth {
        /// The configured `max_depth`.
        limit: u32,
    },

    /// More entries than `max_entries`.
    #[error("archive holds more than the configured limit of {limit} entries")]
    Entries {
        /// The configured `max_entries`.
        limit: u32,
    },

    /// Expanding the next entry would pass `max_expanded_bytes`.
    #[error("expanding this archive would exceed the configured limit of {limit} bytes")]
    ExpandedBytes {
        /// The configured `max_expanded_bytes`.
        limit: u64,
    },

    /// One entry expands by more than `max_ratio`.
    #[error("an archive entry expands {ratio}:1, above the configured limit of {limit}:1")]
    Ratio {
        /// The observed ratio.
        ratio: u64,
        /// The configured `max_ratio`.
        limit: u64,
    },
}

/// Running account of what an expansion has spent.
///
/// Drive it around the walk:
///
/// ```
/// use enclave_antivirus::{ArchiveLimits, LimitExceeded};
///
/// let mut budget = ArchiveLimits::default().budget();
/// budget.descend()?;                        // entering a container
/// budget.admit(1_024, 4_096)?;              // one entry: compressed, expanded
/// budget.ascend();                          // leaving it
/// # Ok::<(), LimitExceeded>(())
/// ```
///
/// [`admit`](ArchiveBudget::admit) is called with the entry's *declared* sizes, from the container
/// header, before extraction starts. That is what makes the caps a defence rather than a postmortem
/// — a bomb declares its expanded size honestly, because the format requires it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveBudget {
    limits: ArchiveLimits,
    depth: u32,
    entries: u32,
    expanded_bytes: u64,
}

impl ArchiveBudget {
    /// Enters a nested container.
    ///
    /// # Errors
    ///
    /// [`LimitExceeded::Depth`] if the container is deeper than `max_depth`. The caller must not
    /// open it — this is the check, not a warning about one.
    pub fn descend(&mut self) -> Result<(), LimitExceeded> {
        if self.depth >= self.limits.max_depth {
            return Err(LimitExceeded::Depth { limit: self.limits.max_depth });
        }
        self.depth += 1;
        Ok(())
    }

    /// Leaves the container most recently entered.
    ///
    /// Note that `entries` and `expanded_bytes` are deliberately *not* refunded. They are budgets
    /// for the whole tree, not per level; refunding them would let a wide-but-shallow archive
    /// spend the entry cap once per sibling.
    pub const fn ascend(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Accounts for one entry before extracting it.
    ///
    /// # Errors
    ///
    /// [`LimitExceeded::Entries`], [`LimitExceeded::ExpandedBytes`] or [`LimitExceeded::Ratio`],
    /// whichever is hit first. On any error the budget is left unchanged, so a caller that logs
    /// and skips one entry rather than abandoning the archive still has a coherent account.
    pub fn admit(&mut self, compressed: u64, expanded: u64) -> Result<(), LimitExceeded> {
        if self.entries >= self.limits.max_entries {
            return Err(LimitExceeded::Entries { limit: self.limits.max_entries });
        }

        // Zero-length input is not an infinite ratio; it is an empty entry. Only a non-empty
        // expansion from a non-empty source has a ratio worth testing.
        if compressed > 0 && expanded > 0 {
            let ratio = expanded / compressed;
            if ratio > self.limits.max_ratio {
                return Err(LimitExceeded::Ratio { ratio, limit: self.limits.max_ratio });
            }
        }

        let total = self.expanded_bytes.saturating_add(expanded);
        if total > self.limits.max_expanded_bytes {
            return Err(LimitExceeded::ExpandedBytes { limit: self.limits.max_expanded_bytes });
        }

        self.entries += 1;
        self.expanded_bytes = total;
        Ok(())
    }

    /// How deep the walk currently is.
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// How many entries have been admitted.
    #[must_use]
    pub const fn entries(&self) -> u32 {
        self.entries
    }

    /// How many expanded bytes have been admitted.
    #[must_use]
    pub const fn expanded_bytes(&self) -> u64 {
        self.expanded_bytes
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> ArchiveLimits {
        self.limits
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_default_depth_is_the_one_the_document_states() {
        assert_eq!(ArchiveLimits::default().max_depth, 5);
    }

    #[test]
    fn config_supplies_the_depth_and_nothing_else_silently_changes() {
        let config = AntivirusConfig { archive_depth: 2, ..AntivirusConfig::default() };
        let limits = ArchiveLimits::from_config(&config);
        assert_eq!(limits.max_depth, 2);
        assert_eq!(limits.max_entries, ArchiveLimits::default().max_entries);
        assert_eq!(limits.max_expanded_bytes, ArchiveLimits::default().max_expanded_bytes);
    }

    #[test]
    fn descending_past_the_depth_limit_is_refused_at_the_boundary_not_after_it() {
        let mut budget = ArchiveLimits { max_depth: 3, ..ArchiveLimits::default() }.budget();
        for expected in 1..=3 {
            budget.descend().expect("within depth");
            assert_eq!(budget.depth(), expected);
        }
        assert_eq!(budget.descend(), Err(LimitExceeded::Depth { limit: 3 }));
        assert_eq!(budget.depth(), 3, "a refused descend must not consume a level");
    }

    #[test]
    fn ascending_frees_depth_but_never_refunds_entries_or_bytes() {
        let mut budget = ArchiveLimits::default().budget();
        budget.descend().unwrap();
        budget.admit(100, 1_000).unwrap();
        budget.ascend();
        assert_eq!(budget.depth(), 0);
        assert_eq!(budget.entries(), 1);
        assert_eq!(budget.expanded_bytes(), 1_000);
    }

    #[test]
    fn the_entry_cap_is_a_whole_tree_budget_not_a_per_level_one() {
        let limits = ArchiveLimits { max_entries: 4, ..ArchiveLimits::default() };
        let mut budget = limits.budget();
        for _ in 0..4 {
            budget.descend().unwrap();
            budget.admit(1, 1).unwrap();
        }
        assert_eq!(budget.admit(1, 1), Err(LimitExceeded::Entries { limit: 4 }));
    }

    #[test]
    fn a_refused_entry_leaves_the_budget_untouched() {
        let limits = ArchiveLimits { max_expanded_bytes: 1_000, ..ArchiveLimits::default() };
        let mut budget = limits.budget();
        budget.admit(10, 900).unwrap();
        assert!(budget.admit(10, 200).is_err());
        assert_eq!(budget.entries(), 1);
        assert_eq!(budget.expanded_bytes(), 900);
    }

    /// G2's core: a bomb that is neither deep nor wide, only dense. 4 KiB expanding to 4 GiB sits
    /// inside every depth and entry-count cap and is caught by the ratio alone.
    #[test]
    fn a_single_entry_bomb_is_refused_on_ratio_before_any_bytes_are_written() {
        let mut budget = ArchiveLimits::default().budget();
        budget.descend().unwrap();
        let result = budget.admit(4 * 1024, 4 * 1024 * 1024 * 1024);
        assert!(matches!(result, Err(LimitExceeded::Ratio { limit: 1000, .. })));
        assert_eq!(budget.expanded_bytes(), 0, "nothing was spent, so nothing was extracted");
    }

    /// G2, the `42.zip` shape: 6 levels of 16 entries. It is refused at the depth boundary, and
    /// the walk stops there rather than after 16^6 entries.
    #[test]
    fn a_nested_bomb_stops_at_the_depth_limit_rather_than_exploring_the_tree() {
        let mut budget = ArchiveLimits::default().budget();
        let mut levels = 0_u32;
        let mut visited = 0_u32;

        loop {
            match budget.descend() {
                Ok(()) => levels += 1,
                Err(LimitExceeded::Depth { limit }) => {
                    assert_eq!(limit, 5);
                    break;
                }
                Err(other) => panic!("unexpected {other}"),
            }
            for _ in 0..16 {
                budget.admit(1_024, 16 * 1_024).expect("each entry is within the ratio");
                visited += 1;
            }
        }

        assert_eq!(levels, 5);
        assert_eq!(visited, 80, "5 levels of 16, not 16^6");
    }

    #[test]
    fn a_zero_depth_limit_means_do_not_open_archives_at_all() {
        let mut budget = ArchiveLimits { max_depth: 0, ..ArchiveLimits::default() }.budget();
        assert_eq!(budget.descend(), Err(LimitExceeded::Depth { limit: 0 }));
    }

    #[test]
    fn an_empty_entry_is_not_an_infinite_ratio() {
        let mut budget = ArchiveLimits::default().budget();
        budget.admit(0, 0).expect("a zero-length entry is ordinary, not a bomb");
        budget.admit(0, 10).expect("a stored entry with no compressed size is not a bomb either");
    }

    #[test]
    fn clamd_settings_are_derived_from_the_limits_rather_than_restated() {
        let limits = ArchiveLimits { max_depth: 3, max_entries: 7, ..ArchiveLimits::default() };
        let settings = limits.clamd_settings();
        assert!(settings.contains(&("MaxRecursion", "3".to_owned())));
        assert!(settings.contains(&("MaxFiles", "7".to_owned())));
    }
}
