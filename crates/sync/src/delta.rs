//! The change feed's own vocabulary, and one entry as it comes out of the database.
//!
//! `docs/10-SYNC-AND-EDITING.md §4`. The types that go *on the wire* live in
//! `crates/api/src/sync.rs`, because `docs/05-API.md` is authoritative for that and this crate has
//! no business deciding field names. What is here is what the feed *stores* and what a verdict is
//! taken from.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_core::{FileId, LibraryId, VersionId};

use crate::error::SyncError;

/// What happened to a file, as `sync_change_log.op` records it.
///
/// Two variants and deliberately not three: there is no `MOVE` and no `RENAME`, because
/// `docs/10 §6` requires those to be transmitted as metadata operations rather than as
/// delete-plus-create, and an `UPSERT` carrying the file's current path *is* that. A third variant
/// would be a second way to say the same thing, and the second way is the one a client eventually
/// handles differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeOp {
    /// The file exists and something about it changed — content, name, location, or the
    /// permissions on it.
    Upsert,
    /// The file was trashed.
    Delete,
}

impl ChangeOp {
    /// The stored form, exactly as `migrations/0023_sync_devices.sql` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "UPSERT",
            Self::Delete => "DELETE",
        }
    }

    /// Every variant, for a test that asserts the vocabulary rather than the half it remembers.
    pub const ALL: [Self; 2] = [Self::Upsert, Self::Delete];
}

impl fmt::Display for ChangeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ChangeOp {
    type Err = SyncError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "UPSERT" => Ok(Self::Upsert),
            "DELETE" => Ok(Self::Delete),
            other => {
                Err(SyncError::UnknownVariant { vocabulary: "ChangeOp", value: other.to_owned() })
            }
        }
    }
}

/// One feed entry joined to everything a verdict and a wire row need.
///
/// Assembled by one query rather than a row per table, because the alternative — a feed read
/// followed by a file read followed by a version read, per entry — is three round trips times a
/// page of five hundred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    /// The position of this entry in its scope's sequence. Monotonic, allocated under the scope
    /// counter's row lock — see `migrations/0023_sync_devices.sql`.
    pub seq: i64,
    /// The file the entry is about.
    pub file_id: FileId,
    /// What happened to it in the tree.
    pub op: ChangeOp,
    /// The library it is in now.
    pub library_id: LibraryId,
    /// The file's current name.
    pub name: String,
    /// Its folder, or `None` at the library root.
    pub parent_id: Option<FileId>,
    /// Whether it is a folder. Folders are replicated as structure, never as bytes.
    pub is_folder: bool,
    /// Whether the file has been trashed. Drives [`crate::TombstoneReason::Deleted`].
    pub deleted: bool,
    /// When the file last changed.
    pub modified_at: DateTime<Utc>,
    /// The current version, **only if antivirus has cleared it**. `None` covers three cases the
    /// verdict treats alike — no version, a version still scanning, and a quarantined one — which
    /// is `CLAUDE.md` rule 9 held by the query rather than by a comparison here.
    pub readable_version: Option<ReadableVersion>,
    /// Whether the library permits sync at all (`docs/10 §5` condition 1).
    pub library_sync_enabled: bool,
}

/// The part of a version a sync client needs to decide whether it already has the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableVersion {
    /// The version's id.
    pub id: VersionId,
    /// Its size.
    pub size_bytes: i64,
    /// Its lowercase-hex SHA-256, which is what lets a client skip a download it does not need.
    pub checksum_sha256: String,
}

/// One page of the feed, and the position to resume from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a page that is not rendered is a set of changes a device will never see"]
pub struct FeedPage {
    /// The entries in the window, in `seq` order.
    pub entries: Vec<FeedEntry>,
    /// The highest `seq` **scanned**, which is what the client must resume from.
    ///
    /// Not the highest `seq` *emitted*. Entries are dropped from a page for two reasons — the
    /// caller may not see the file, and several entries in the window name one file — and a cursor
    /// that tracked the surviving rows would skip every dropped row's successors on the next call.
    /// `crates/api/src/content.rs` states the same rule for the same reason on the browse listing:
    /// the cursor tracks the last row the *database* returned.
    pub next_cursor: crate::DeltaCursor,
    /// Whether the window was full, and therefore whether another page exists.
    ///
    /// Not implied by a short page: a page can be empty and still have more, because every entry in
    /// the window may have been for a file the caller cannot see. Clients page until this is false.
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_op_vocabulary_matches_the_check_constraint() {
        let rendered: Vec<&str> = ChangeOp::ALL.iter().map(|op| op.as_str()).collect();
        assert_eq!(rendered, ["UPSERT", "DELETE"]);
        for op in ChangeOp::ALL {
            assert_eq!(op.as_str().parse::<ChangeOp>().expect("round trip"), op);
        }
        assert!(matches!("MOVE".parse::<ChangeOp>(), Err(SyncError::UnknownVariant { .. })));
    }
}
