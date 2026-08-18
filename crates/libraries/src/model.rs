//! The records this crate reads and writes, and the closed vocabularies their columns hold.
//!
//! Every enumeration mirrors a `CHECK` constraint in `migrations/0004_content_and_acl.sql`
//! (`docs/04-DATA-MODEL.md §7`) — same members, same spellings.
//!
//! # `inherit_permissions` is persisted, never interpreted
//!
//! It is the flag the ACL resolver's inheritance walk stops at: `FALSE` means this library's own
//! entries apply and nothing above it does, and the break is materialised as copied entries with
//! `inherited_from` set (`docs/04-DATA-MODEL.md §9`). `enclave-authorization` is the authority on
//! what that means — see `LIBRARY_CHAIN_SQL` there. This crate stores the boolean faithfully and
//! draws no conclusion from it. A second interpretation would be a second answer to "who can read
//! this", and the two would eventually disagree.
//!
//! Storing it faithfully does not mean storing it on request. `LibrarySettings` carries the flag
//! because it is a replacement of the whole record, but only `create` writes it: at creation there
//! is no prior effective ACL to preserve, so starting out detached escalates nothing, whereas
//! *changing* it later does unless the effective set is copied down in the same transaction
//! (`ENC-141`).

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{LibraryId, TenantId, UnknownVariant, Uuid, WorkspaceId};

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `enclave_identity::model` and `enclave_workspaces::model` carry: `as_str` and
/// `from_str` come from one list, so a writer and a reader cannot fall out of step.
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

            /// Every variant, so a test can assert the Rust set against the constraint's set.
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
    /// How a library versions its content (`libraries.versioning_mode`).
    ///
    /// Stored and returned only. What a mode *does* on commit belongs to `enclave-versions`
    /// (`ENC-131`); duplicating that judgement here would put two crates in charge of whether a
    /// write creates a new version.
    pub enum VersioningMode {
        /// No version history: a write replaces the current content.
        None => "NONE",
        /// Whole-number versions only.
        Major => "MAJOR",
        /// Draft (minor) and published (major) versions.
        MajorMinor => "MAJOR_MINOR",
    }
}

db_enum! {
    /// How far outside the tenant content in this library may be shared
    /// (`libraries.external_sharing`).
    ///
    /// A *ceiling* that the sharing service and the policy chain enforce, not a permission granted
    /// by this crate. Nothing here consults it.
    pub enum ExternalSharing {
        /// No external sharing at all.
        Disabled => "DISABLED",
        /// Only guests who already exist in the tenant.
        ExistingGuests => "EXISTING_GUESTS",
        /// New guests may be invited.
        NewGuests => "NEW_GUESTS",
        /// Anonymous links are permitted, subject to the rest of the policy chain.
        Anyone => "ANYONE",
    }
}

/// A library, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    /// The library id.
    pub id: LibraryId,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The workspace it belongs to. Immutable: moving a library changes what it inherits from, so
    /// it is a re-parenting operation with its own ACL consequences, not a settings change.
    pub workspace_id: WorkspaceId,
    /// The complete mutable state.
    pub settings: LibrarySettings,
    /// Optimistic-concurrency counter; `docs/05-API.md §9` puts it on the wire as the `ETag`.
    pub revision: i64,
    /// When the library was created.
    pub created_at: DateTime<Utc>,
    /// When it last changed.
    pub updated_at: DateTime<Utc>,
    /// When it was trashed, or `None` while it is live.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// The complete mutable state of a library.
///
/// One structure for both `create` and `update`, deliberately: two structures are two places for a
/// column to be forgotten, and the one that gets forgotten in the update path is the setting that
/// then cannot be changed after creation without anyone noticing. With seventeen fields — several
/// of them governing what leaves the tenant — that is not a hypothetical.
///
/// **Replacement, not patch.** Every field is the value the library will hold, so `None` means
/// `NULL` rather than "leave it alone". That is what `If-Match` already implies: the caller read
/// revision *n*, decided the whole desired state, and is asserting nothing changed underneath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibrarySettings {
    /// Display name.
    pub name: String,
    /// URL-safe short name, folded through
    /// [`normalize_slug`](crate::normalize_slug) on the way in.
    pub slug: String,
    /// Whether ACL inheritance from the workspace continues into this library.
    ///
    /// Persisted faithfully and interpreted nowhere in this crate — see the
    /// [module documentation](self).
    pub inherit_permissions: bool,
    /// Classification applied to content created here when nothing else sets one.
    ///
    /// A `Uuid` rather than a newtype because `core` has no `ClassificationId` yet; the same is
    /// true of the storage-profile and retention-policy references below.
    pub default_classification_id: Option<Uuid>,
    /// How content here is versioned.
    pub versioning_mode: VersioningMode,
    /// How many versions to keep, or `None` for unlimited.
    pub version_limit: Option<i32>,
    /// Whether editing requires an explicit checkout.
    pub require_checkout: bool,
    /// Whether a new version needs approval before it is published.
    pub require_approval: bool,
    /// Extensions permitted here, or `None` for "no allow-list".
    ///
    /// Stored exactly as given: the upload path decides how an extension is compared, and folding
    /// case here would make this crate a second opinion on that. An empty list is *not* the same as
    /// `None` — it permits nothing — which is why the type is `Option<Vec<_>>` and not `Vec<_>`.
    pub allowed_extensions: Option<Vec<String>>,
    /// Extensions refused here, or `None` for "no deny-list".
    pub blocked_extensions: Option<Vec<String>>,
    /// Largest file accepted, in bytes, or `None` for the tenant default.
    pub max_file_size_bytes: Option<i64>,
    /// The external-sharing ceiling.
    pub external_sharing: ExternalSharing,
    /// Whether content here may be indexed for AI retrieval.
    pub ai_indexing_enabled: bool,
    /// Whether this library is visible over MCP.
    pub mcp_visible: bool,
    /// Whether desktop sync may pull content from here.
    pub sync_enabled: bool,
    /// Pinned storage profile, or `None` to inherit the workspace's.
    pub storage_profile_id: Option<Uuid>,
    /// Retention policy, or `None` to inherit.
    pub retention_policy_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr;

    use super::*;

    /// The vocabularies are copies of `CHECK` constraints. If one drifts, rows written by an older
    /// release stop decoding — so assert the exact sets, spelled as migration 0004 spells them.
    #[test]
    fn every_vocabulary_matches_its_check_constraint() {
        let render = |v: &[&str]| v.join(",");

        assert_eq!(
            render(&VersioningMode::all().iter().map(VersioningMode::as_str).collect::<Vec<_>>()),
            "NONE,MAJOR,MAJOR_MINOR"
        );
        assert_eq!(
            render(&ExternalSharing::all().iter().map(ExternalSharing::as_str).collect::<Vec<_>>()),
            "DISABLED,EXISTING_GUESTS,NEW_GUESTS,ANYONE"
        );
    }

    #[test]
    fn every_variant_round_trips_through_its_stored_form() {
        for mode in VersioningMode::all() {
            assert_eq!(VersioningMode::from_str(mode.as_str()).unwrap(), *mode);
        }
        for sharing in ExternalSharing::all() {
            assert_eq!(ExternalSharing::from_str(sharing.as_str()).unwrap(), *sharing);
        }
    }

    #[test]
    fn a_value_outside_the_constraint_is_rejected_rather_than_guessed_at() {
        assert!(VersioningMode::from_str("major").is_err());
        assert!(ExternalSharing::from_str("EVERYONE").is_err());
        // `PUBLIC` is what an author might expect the most permissive value to be called. It is
        // not one, and quietly mapping it onto `ANYONE` would be the widest possible guess.
        assert!(ExternalSharing::from_str("PUBLIC").is_err());
    }
}
