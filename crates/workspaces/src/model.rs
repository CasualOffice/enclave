//! The records this crate reads and writes, and the closed vocabularies their columns hold.
//!
//! Every enumeration here mirrors a `CHECK` constraint in `migrations/0004_content_and_acl.sql`
//! (`docs/04-DATA-MODEL.md §7`) — same members, same spellings. A Rust set that drifts from its
//! constraint does not fail at the boundary; it fails when a row written by an older release stops
//! decoding, which is a read outage rather than a write error.
//!
//! Two identifiers are defined here rather than imported from `enclave_core::id`, and both are
//! marked for promotion:
//!
//! * [`PrincipalId`] — `workspace_members.principal_id` is polymorphic over users, groups, guests
//!   and service accounts (which is exactly why it carries no foreign key), so no existing core id
//!   fits it. A bare `Uuid` on this boundary is what `CLAUDE.md` forbids, and it is also the key
//!   the member listing paginates on, so it needs to be a type.
//! * [`RoleId`] — `role_definitions.id`. `enclave-authorization` currently names the same value as
//!   a `Uuid`; the newtype belongs in `core` next to the others, and until it lands there this is
//!   the one place in this crate that knows the column is not just any UUID.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UnknownVariant, UserId, Uuid, WorkspaceId};
use enclave_db::SqlId;

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `enclave_identity::model` carries, and for the same reason: `as_str` and
/// `from_str` are generated from one list, so a writer and a reader cannot fall out of step. It is
/// copied rather than shared because the alternative is a dependency between two domain crates
/// that exists only to move a macro.
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

/// Defines an identifier newtype over `Uuid` that binds to a PostgreSQL `uuid`.
///
/// Same shape as `enclave_core::id`'s macro, plus the [`SqlId`] implementation `enclave_db` writes
/// for the core ids — these types are local, so the orphan rule permits it here.
macro_rules! local_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// A newtype over [`Uuid`]. No `Default`: a nil identifier is never a meaningful value.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// The type's own name, for diagnostics that need to say which kind of identifier
            /// failed without hard-coding a string at the call site.
            pub const TYPE_NAME: &'static str = stringify!($name);

            /// Wraps an existing UUID, for the boundaries where one legitimately arrives untyped.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Unwraps to the raw UUID, for those same boundaries in the outward direction.
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl SqlId for $name {
            const TYPE_NAME: &'static str = stringify!($name);

            fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            fn to_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

local_id! {
    /// Whatever `workspace_members.principal_type` says this row points at.
    ///
    /// Polymorphic by design: a membership may name a user, a group, a guest or a service account,
    /// which is why the column carries no foreign key and why the type discriminator travels beside
    /// it. Resolving one without also reading [`PrincipalType`] would follow a user id into the
    /// groups table.
    PrincipalId
}

local_id! {
    /// A row in `role_definitions` — the permission set a membership grants.
    ///
    /// The repository stores and returns it and never interprets it. What a role *permits* is
    /// resolved by the authorization stage (`docs/04-DATA-MODEL.md §9`), and a repository that
    /// started expanding roles would be a second, unlinted enforcement point.
    RoleId
}

db_enum! {
    /// Who can discover a workspace (`workspaces.visibility`, `docs/01-PRD.md §6`).
    ///
    /// This is an *input* to the policy chain, never a decision. Nothing in this crate consults it:
    /// a repository that filtered listings by visibility would be making an authorization decision
    /// outside `PolicyEngine::enforce` (`plans/M1-CONTENT-CORE.md` D11).
    pub enum Visibility {
        /// Visible only to its members, and not discoverable by anyone else.
        Private => "PRIVATE",
        /// Visible to its members; discoverable as a name by others.
        MembersOnly => "MEMBERS_ONLY",
        /// Discoverable by everyone in the tenant.
        TenantVisible => "TENANT_VISIBLE",
        /// Members only, plus whatever additional restriction the deployment's policy attaches —
        /// information barriers, conditional access, or a classification floor.
        Restricted => "RESTRICTED",
    }
}

db_enum! {
    /// What kind of principal a `workspace_members` row points at
    /// (`workspace_members.principal_type`).
    ///
    /// Deliberately its own type rather than a reuse of `enclave_identity::MemberType`, even though
    /// the two vocabularies are identical today: they mirror two different `CHECK` constraints, and
    /// a shared type would make a value one table permits constructible for the other.
    pub enum PrincipalType {
        /// `principal_id` is a `users.id`.
        User => "USER",
        /// `principal_id` is a `groups.id`.
        Group => "GROUP",
        /// `principal_id` is a `guests.id`.
        Guest => "GUEST",
        /// `principal_id` is a `service_accounts.id`.
        ServiceAccount => "SERVICE_ACCOUNT",
    }
}

/// A workspace, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The workspace id.
    pub id: WorkspaceId,
    /// The owning tenant. Carried so a caller cannot lose track of which isolation boundary a
    /// record came from when it is passed onward.
    pub tenant_id: TenantId,
    /// Display name, as administered.
    pub name: String,
    /// URL-safe short name, unique among this tenant's *live* workspaces.
    pub slug: String,
    /// Free-text description.
    pub description: Option<String>,
    /// Discoverability. An input to the policy chain, not a permission.
    pub visibility: Visibility,
    /// The classification applied to content created here when nothing else sets one.
    ///
    /// A `Uuid` rather than a newtype because `core` has no `ClassificationId` yet; see the
    /// [module documentation](self).
    pub default_classification_id: Option<Uuid>,
    /// The storage profile new content lands on, when the tenant pins one (`docs/08-BYO-INFRA.md`).
    pub storage_profile_id: Option<Uuid>,
    /// Optimistic-concurrency counter. Every accepted write increments it; `docs/05-API.md §9`
    /// puts it on the wire as the `ETag`.
    pub revision: i64,
    /// Who created it. Retained for audit attribution even after the user is deprovisioned.
    pub created_by: UserId,
    /// When the workspace was created.
    pub created_at: DateTime<Utc>,
    /// When it last changed.
    pub updated_at: DateTime<Utc>,
    /// When it was trashed, or `None` while it is live. A soft-deleted workspace releases its slug.
    pub deleted_at: Option<DateTime<Utc>>,
}

/// The complete mutable state of a workspace.
///
/// One structure for both `create` and `update`, deliberately: two structures are two places for a
/// column to be forgotten, and the column that gets forgotten in the update path is the one that
/// then cannot be changed after creation without anyone noticing.
///
/// **Replacement, not patch.** Every field is the value the workspace will hold, so `None` means
/// `NULL` rather than "leave it alone". That is the semantics `If-Match` already implies: the
/// caller read revision *n*, decided the whole desired state, and is asserting nothing has changed
/// underneath. A partial patch would need a third state per field — absent, set, cleared — and
/// every field where that distinction is dropped becomes a value that can never be cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSettings {
    /// Display name.
    pub name: String,
    /// URL-safe short name. Folded through [`normalize_slug`](crate::normalize_slug) on the way in.
    pub slug: String,
    /// Free-text description, or `None` to clear it.
    pub description: Option<String>,
    /// Discoverability.
    pub visibility: Visibility,
    /// Default classification for new content, or `None` to inherit the tenant's.
    pub default_classification_id: Option<Uuid>,
    /// Pinned storage profile, or `None` to use the tenant default.
    pub storage_profile_id: Option<Uuid>,
}

/// One membership row.
///
/// A membership is *not* an answer to "may this principal do X". It is one of the inputs the
/// authorization stage resolves alongside ACL entries, group closure and inheritance
/// (`docs/04-DATA-MODEL.md §9`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMember {
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The workspace the membership is in.
    pub workspace_id: WorkspaceId,
    /// The principal. Meaningless without [`WorkspaceMember::principal_type`].
    pub principal_id: PrincipalId,
    /// Which principal table `principal_id` points at.
    pub principal_type: PrincipalType,
    /// The role the membership grants.
    pub role_id: RoleId,
    /// Who granted it. Retained for audit attribution.
    pub added_by: UserId,
    /// When it was granted.
    pub added_at: DateTime<Utc>,
    /// When it lapses, or `None` for an open-ended membership.
    ///
    /// The repository does not evaluate this — listings can exclude expired rows on request (see
    /// [`MemberFilter`](crate::MemberFilter)), but whether an expired membership grants anything is
    /// the authorization stage's decision, made against its own clock.
    pub expires_at: Option<DateTime<Utc>>,
}

/// The membership to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMember {
    /// The principal to add.
    pub principal_id: PrincipalId,
    /// Which principal table it lives in.
    pub principal_type: PrincipalType,
    /// The role to grant.
    pub role_id: RoleId,
    /// Who is granting it.
    pub added_by: UserId,
    /// When it lapses, or `None` for open-ended.
    pub expires_at: Option<DateTime<Utc>>,
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
            render(&Visibility::all().iter().map(Visibility::as_str).collect::<Vec<_>>()),
            "PRIVATE,MEMBERS_ONLY,TENANT_VISIBLE,RESTRICTED"
        );
        assert_eq!(
            render(&PrincipalType::all().iter().map(PrincipalType::as_str).collect::<Vec<_>>()),
            "USER,GROUP,GUEST,SERVICE_ACCOUNT"
        );
    }

    #[test]
    fn every_variant_round_trips_through_its_stored_form() {
        for visibility in Visibility::all() {
            assert_eq!(Visibility::from_str(visibility.as_str()).unwrap(), *visibility);
        }
        for kind in PrincipalType::all() {
            assert_eq!(PrincipalType::from_str(kind.as_str()).unwrap(), *kind);
        }
    }

    /// Case matters: the column is governed by a `CHECK` that fixes the spelling, so accepting
    /// `"private"` would only ever mean something wrote a row the constraint should have rejected.
    #[test]
    fn a_lowercase_stored_value_is_rejected_rather_than_guessed_at() {
        assert!(Visibility::from_str("private").is_err());
        assert!(PrincipalType::from_str("user").is_err());
        assert!(Visibility::from_str("PUBLIC").is_err());
    }

    #[test]
    fn the_local_identifiers_round_trip_through_their_uuid() {
        let raw = Uuid::now_v7();
        assert_eq!(PrincipalId::from_uuid(raw).as_uuid(), raw);
        assert_eq!(RoleId::from_uuid(raw).as_uuid(), raw);
        // The rendered form is the plain hyphenated UUID, interchangeable with the column and the
        // JSON wire format — the same contract `enclave_core::id` makes.
        assert_eq!(PrincipalId::from_uuid(raw).to_string(), raw.to_string());
    }

    #[test]
    fn a_principal_id_and_a_role_id_are_not_interchangeable() {
        // The whole point of the newtypes: `add_member` takes both, adjacent, and a transposition
        // has to be a compile error rather than a grant of the wrong role to the wrong principal.
        let raw = Uuid::now_v7();
        let principal = PrincipalId::from_uuid(raw);
        let role = RoleId::from_uuid(raw);
        assert_eq!(principal.as_uuid(), role.as_uuid());
        // They are distinct types; this file would not compile if `principal == role` were written.
        assert_eq!(PrincipalId::TYPE_NAME, "PrincipalId");
        assert_eq!(RoleId::TYPE_NAME, "RoleId");
    }
}
