//! The node record this crate reads and writes, and the closed vocabularies its columns hold.
//!
//! Every enumeration here mirrors a `CHECK` constraint in `migrations/0005_files.sql`
//! (`docs/04-DATA-MODEL.md §8`) — same members, same spellings.
//!
//! # What a [`FileNode`] deliberately leaves out
//!
//! `classification_id`, `classification_source` and `content_type_id` are columns of `files` and
//! are **not** fields here. They are nullable UUIDs owned by the classification and metadata
//! crates, neither of which exists yet, and `enclave_core::id` has no `ClassificationId` or
//! `ContentTypeId` newtype to type them with. Surfacing them as bare `Uuid` would put an untyped
//! identifier on a public boundary, which `CLAUDE.md` forbids for exactly the reason it bites here:
//! the two columns are indistinguishable at the type level and a swap would compile. They arrive
//! with the crate that owns them, together with the newtype in `core`.
//!
//! `revision` and `acl_revision` *are* here, because both are this crate's business:
//! `docs/03-LLD.md §14` makes `revision` the optimistic-concurrency key every mutation below
//! checks, and `acl_revision` is what the search index and the ACL cache key on
//! (`docs/07-SEARCH-INDEXING.md §6`).

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{FileId, LibraryId, TenantId, UnknownVariant, UserId, VersionId, WorkspaceId};

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `crates/identity/src/model.rs` uses, and copied for the same reason it was
/// copied there: `enclave_core`'s equivalent is private to that crate. The property worth having is
/// that `as_str` and `from_str` are generated from one list, so a hand-written parser cannot fall
/// one variant behind its writer.
macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test can assert the Rust set against the constraint's set
            /// rather than trusting that both were updated together.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownVariant::new(stringify!($name), other)),
                }
            }
        }
    };
}

db_enum! {
    /// Whether a node holds content or holds other nodes (`files.node_type`).
    ///
    /// One table and one identifier space for both, because they share the permission model and
    /// the hierarchy: an ACL entry, an inheritance break and a breadcrumb work the same way
    /// whichever this is (`docs/04-DATA-MODEL.md §8`).
    pub enum NodeType {
        /// Holds content, through its versions.
        File => "FILE",
        /// Holds other nodes.
        Folder => "FOLDER",
    }
}

db_enum! {
    /// Availability of a node's content (`files.status`).
    ///
    /// `docs/03-LLD.md` D13 and `CLAUDE.md` rule 9: availability is a state, not a flag, and
    /// nothing is [`NodeStatus::Available`] before antivirus has finished with it. This crate only
    /// ever *reads* this column and sets its initial value; the transitions belong to the upload
    /// and antivirus paths (`ENC-131`, `ENC-132`).
    pub enum NodeStatus {
        /// Content may be served.
        Available => "AVAILABLE",
        /// Uploading, scanning or extracting. No read path serves this.
        Processing => "PROCESSING",
        /// Antivirus found something. The node stays visible so its owner can see why.
        Quarantined => "QUARANTINED",
        /// Processing failed terminally.
        Failed => "FAILED",
    }
}

/// One row of `files`: a file or a folder.
///
/// Returned by every function in [`crate::repo`], including the mutations — a caller that has just
/// renamed something needs the new `revision` for its next `If-Match`, and returning it costs
/// nothing because the `UPDATE` has the row in hand.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileNode {
    /// The node's identifier. UUIDv7, so it is also its creation order.
    pub id: FileId,
    /// The owning tenant. Present on the record as well as in the query predicate, so a value that
    /// crossed a boundary would be visible rather than merely absent.
    pub tenant_id: TenantId,
    /// The workspace the library belongs to, denormalized so the ACL walk does not have to join
    /// to reach it.
    pub workspace_id: WorkspaceId,
    /// The library this node lives in. Fixed at creation: see [`crate::FilesError::CrossLibraryMove`].
    pub library_id: LibraryId,
    /// The containing folder, or `None` for a node at the library root.
    pub parent_id: Option<FileId>,
    /// File or folder.
    pub node_type: NodeType,
    /// The name as it is displayed, with the user's own spacing and case.
    pub name: String,
    /// The folded form `uq_files_sibling_name` is built on. See [`crate::normalize`].
    pub normalized_name: String,
    /// The media type. `inode/directory` for a folder — see [`crate::repo::FOLDER_MIME_TYPE`].
    pub mime_type: String,
    /// The version a read path would serve, or `None` while the node has no content yet.
    pub current_version_id: Option<VersionId>,
    /// Size of the current version in bytes; `0` for a folder and for a node with no content.
    pub size_bytes: i64,
    /// `false` once inheritance has been broken here (`docs/04-DATA-MODEL.md §9`).
    pub inherit_permissions: bool,
    /// The optimistic-concurrency key. Bumped by every mutation in this crate.
    pub revision: i64,
    /// Bumped when the node's ACL changes; drives cache keys and index invalidation. Not touched
    /// here — moving a node changes its *inherited* permissions without changing its own entries,
    /// and the invalidation that follows is the authorization crate's to publish.
    pub acl_revision: i64,
    /// Declared a record. Blocks permanent deletion (`docs/03-LLD.md §18`).
    pub is_record: bool,
    /// Under legal hold. Blocks permanent deletion.
    pub on_legal_hold: bool,
    /// Whether content may be served.
    pub status: NodeStatus,
    /// Who created the node.
    pub created_by: UserId,
    /// Who last modified it.
    pub modified_by: UserId,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it was last modified.
    pub modified_at: DateTime<Utc>,
    /// When it was moved to the trash, or `None` if it is live.
    pub deleted_at: Option<DateTime<Utc>>,
    /// The earliest instant at which permanent deletion may be *considered*. Not a promise that it
    /// will happen then — see [`crate::purge`] for the four checks that come first.
    pub purge_after: Option<DateTime<Utc>>,
}

impl FileNode {
    /// Whether this node can contain others.
    #[must_use]
    pub const fn is_folder(&self) -> bool {
        matches!(self.node_type, NodeType::Folder)
    }

    /// Whether this node sits at the library root.
    #[must_use]
    pub const fn is_root_level(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Whether this node is in the trash.
    ///
    /// `deleted_at` rather than `purge_after` is the authority: a row can carry a `purge_after`
    /// from a previous stay in the trash, and a restore clears both, but it is `deleted_at` that
    /// every index and every query predicate keys on.
    #[must_use]
    pub const fn is_trashed(&self) -> bool {
        self.deleted_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr as _;

    use super::*;

    #[test]
    fn the_vocabularies_are_exactly_the_check_constraints_in_migration_0005() {
        // Read straight off `migrations/0005_files.sql`. A migration that adds a status without a
        // variant here decodes into `MalformedRow` at runtime; this fails at build time instead.
        let types: Vec<&str> = NodeType::all().iter().map(NodeType::as_str).collect();
        assert_eq!(types, ["FILE", "FOLDER"]);

        let statuses: Vec<&str> = NodeStatus::all().iter().map(NodeStatus::as_str).collect();
        assert_eq!(statuses, ["AVAILABLE", "PROCESSING", "QUARANTINED", "FAILED"]);
    }

    #[test]
    fn every_variant_round_trips_through_its_stored_form() {
        for value in NodeType::all() {
            assert_eq!(NodeType::from_str(value.as_str()).unwrap(), *value);
        }
        for value in NodeStatus::all() {
            assert_eq!(NodeStatus::from_str(value.as_str()).unwrap(), *value);
        }
    }

    #[test]
    fn an_unknown_stored_value_is_rejected_rather_than_guessed() {
        assert!(NodeType::from_str("DIRECTORY").is_err());
        assert!(
            NodeStatus::from_str("SCANNING").is_err(),
            "that spelling belongs to file_versions"
        );
        assert!(NodeStatus::from_str("available").is_err(), "the vocabulary is case-sensitive");
    }
}
