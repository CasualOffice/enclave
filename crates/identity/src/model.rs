//! The principal records this crate reads, and the closed vocabularies their columns hold.
//!
//! Every enumeration here mirrors a `CHECK` constraint in `migrations/0001_foundations.sql`
//! (`docs/04-DATA-MODEL.md §4`, `§5`) — same members, same spellings. That is why [`GroupSource`]
//! exists separately from [`UserSource`] even though it is a strict subset: the users table permits
//! `JIT`, the groups table does not, and collapsing them into one type would make a value that the
//! database will reject constructible in Rust.
//!
//! The structures are deliberately *not* the whole row. `tenants.branding` and `tenants.settings`
//! belong to the branding and configuration crates; reading them here would make this crate the
//! second authority on their shape.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{GroupId, TenantId, UnknownVariant, UserId};

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// `enclave_core` has an equivalent macro, but it is private to that crate and adds serde
/// implementations these types do not need. The property worth copying is the one that matters:
/// `as_str` and `from_str` are generated from a single list, so they cannot fall out of step —
/// a hand-written parser one variant behind its writer is exactly how a value round-trips into a
/// different meaning.
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
    /// Lifecycle of a tenant (`tenants.status`).
    ///
    /// Only [`TenantStatus::Active`] and [`TenantStatus::ReadOnly`] are states in which a request
    /// should be served at all; the repositories here do not enforce that, because refusing a
    /// suspended tenant is a policy-chain decision and not a query concern.
    pub enum TenantStatus {
        /// Normal operation.
        Active => "ACTIVE",
        /// Administratively suspended; no request should be served.
        Suspended => "SUSPENDED",
        /// Reads are served, writes are refused.
        ReadOnly => "READ_ONLY",
        /// Scheduled for deletion; being drained.
        Deleting => "DELETING",
    }
}

db_enum! {
    /// Lifecycle of a user (`users.status`).
    pub enum UserStatus {
        /// Provisioned and able to sign in.
        Active => "ACTIVE",
        /// Invited but has not completed sign-up.
        Invited => "INVITED",
        /// Sign-in refused; the record and its grants remain.
        Suspended => "SUSPENDED",
        /// Offboarded. Grants are removed but the record is retained for audit attribution.
        Deprovisioned => "DEPROVISIONED",
    }
}

db_enum! {
    /// Where a user record came from (`users.source`).
    pub enum UserSource {
        /// Created in Enclave.
        Local => "LOCAL",
        /// Synchronized from a directory.
        Ldap => "LDAP",
        /// Provisioned over SCIM.
        Scim => "SCIM",
        /// Created just-in-time on first federated sign-in.
        Jit => "JIT",
    }
}

db_enum! {
    /// Where a group came from (`groups.source`).
    ///
    /// No `JIT`: a group is never invented during sign-in, because a group that appears from a
    /// token assertion is a grant of access that nobody administered.
    pub enum GroupSource {
        /// Created in Enclave.
        Local => "LOCAL",
        /// Synchronized from a directory.
        Ldap => "LDAP",
        /// Provisioned over SCIM.
        Scim => "SCIM",
    }
}

db_enum! {
    /// What kind of principal a `group_members` row points at (`group_members.member_type`).
    ///
    /// The column is a discriminator, not a foreign key: `member_id` refers to `users`, `groups`,
    /// `guests` or `service_accounts` depending on this value. Group closure therefore has to
    /// filter on it — walking members without checking the type would follow a user id into the
    /// groups table and, with a colliding UUID, resolve to a group nobody is a member of.
    pub enum MemberType {
        /// `member_id` is a `users.id`.
        User => "USER",
        /// `member_id` is a `groups.id` — the nesting edge.
        Group => "GROUP",
        /// `member_id` is a `guests.id`.
        Guest => "GUEST",
        /// `member_id` is a `service_accounts.id`.
        ServiceAccount => "SERVICE_ACCOUNT",
    }
}

/// A tenant, as far as identity resolution is concerned.
///
/// `branding` and `settings` are omitted on purpose — see the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// The tenant id. This is the value that becomes `app.tenant_id`, and it never comes from
    /// client input (`CLAUDE.md` rule 3) — resolving a slug or a domain to it *is* the trusted
    /// derivation.
    pub id: TenantId,
    /// URL-safe short name, unique across the deployment.
    pub slug: String,
    /// Human-readable name for display.
    pub display_name: String,
    /// Lifecycle state.
    pub status: TenantStatus,
    /// Data-residency region, when the deployment pins one.
    pub residency_region: Option<String>,
    /// Bumped on any security-policy change; the cache-invalidation key for compiled policies
    /// (`docs/03-LLD.md §16`). Carried here so a caller that caches per tenant has the key without
    /// a second query.
    pub policy_generation: i64,
    /// When the tenant was created.
    pub created_at: DateTime<Utc>,
    /// When the tenant record last changed.
    pub updated_at: DateTime<Utc>,
}

/// A member of a tenant's directory.
///
/// Credentials are deliberately absent: they live in `user_credentials` and are the `auth` crate's
/// concern. A repository that returned a password hash alongside a profile would make it very easy
/// for one to end up in a response body or a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The user id.
    pub id: UserId,
    /// The owning tenant. Present so a caller cannot lose track of which isolation boundary a
    /// record came from when it is passed onward.
    pub tenant_id: TenantId,
    /// The address as the user typed it, for display.
    pub email: String,
    /// The address as it is matched on — see [`normalize_email`](crate::normalize_email).
    pub normalized_email: String,
    /// Display name.
    pub display_name: String,
    /// Lifecycle state.
    pub status: UserStatus,
    /// Tenant administrator flag. Not a permission by itself: the authorization stage still
    /// decides, and this is one of its inputs.
    pub is_admin: bool,
    /// Mass-revocation counter (`docs/03-LLD.md §5.4`). A token whose `epoch` claim is below this
    /// is revoked, so incrementing it invalidates every outstanding access token for this user.
    pub token_epoch: i32,
    /// Where the record came from.
    pub source: UserSource,
    /// The identifier the source system knows this user by, when there is one.
    pub external_id: Option<String>,
    /// Department, as provisioned. Used by information barriers.
    pub department: Option<String>,
    /// BCP-47 locale preference.
    pub locale: Option<String>,
    /// Last successful sign-in, or `None` if the user has never signed in.
    pub last_login_at: Option<DateTime<Utc>>,
    /// When the record was created.
    pub created_at: DateTime<Utc>,
    /// When the record last changed. Not touched by a sign-in — see
    /// [`UserRepository::update_last_login_at`](crate::UserRepository::update_last_login_at).
    pub updated_at: DateTime<Utc>,
}

/// A group used for authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group id.
    pub id: GroupId,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The name as administered, for display.
    pub name: String,
    /// The name as it is matched on and uniqueness is enforced on.
    pub normalized_name: String,
    /// Free-text description.
    pub description: Option<String>,
    /// Where the group came from.
    pub source: GroupSource,
    /// The identifier the source system knows this group by, when there is one.
    pub external_id: Option<String>,
    /// When the group was created.
    pub created_at: DateTime<Utc>,
    /// When the group last changed. `docs/04-DATA-MODEL.md §5` makes this the cache key for a
    /// resolved closure, which is why it is carried rather than dropped.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr;

    use super::*;

    /// The vocabularies are copies of `CHECK` constraints. If one drifts, rows written by an older
    /// release stop decoding — so assert the exact sets, spelled as the migration spells them.
    #[test]
    fn every_vocabulary_matches_its_check_constraint() {
        let render = |v: &[&str]| v.join(",");

        assert_eq!(
            render(&TenantStatus::all().iter().map(TenantStatus::as_str).collect::<Vec<_>>()),
            "ACTIVE,SUSPENDED,READ_ONLY,DELETING"
        );
        assert_eq!(
            render(&UserStatus::all().iter().map(UserStatus::as_str).collect::<Vec<_>>()),
            "ACTIVE,INVITED,SUSPENDED,DEPROVISIONED"
        );
        assert_eq!(
            render(&UserSource::all().iter().map(UserSource::as_str).collect::<Vec<_>>()),
            "LOCAL,LDAP,SCIM,JIT"
        );
        assert_eq!(
            render(&GroupSource::all().iter().map(GroupSource::as_str).collect::<Vec<_>>()),
            "LOCAL,LDAP,SCIM"
        );
        assert_eq!(
            render(&MemberType::all().iter().map(MemberType::as_str).collect::<Vec<_>>()),
            "USER,GROUP,GUEST,SERVICE_ACCOUNT"
        );
    }

    #[test]
    fn every_variant_round_trips_through_its_stored_form() {
        for status in TenantStatus::all() {
            assert_eq!(TenantStatus::from_str(status.as_str()).unwrap(), *status);
        }
        for status in UserStatus::all() {
            assert_eq!(UserStatus::from_str(status.as_str()).unwrap(), *status);
        }
        for source in UserSource::all() {
            assert_eq!(UserSource::from_str(source.as_str()).unwrap(), *source);
        }
        for source in GroupSource::all() {
            assert_eq!(GroupSource::from_str(source.as_str()).unwrap(), *source);
        }
        for kind in MemberType::all() {
            assert_eq!(MemberType::from_str(kind.as_str()).unwrap(), *kind);
        }
    }

    /// Case matters here, unlike the wire vocabularies in `core`. These values come from a column
    /// governed by a `CHECK` that fixes the spelling, so accepting `"active"` would only ever mean
    /// something wrote a row the constraint should have rejected.
    #[test]
    fn a_lowercase_stored_value_is_rejected_rather_than_guessed_at() {
        assert!(UserStatus::from_str("active").is_err());
        assert!(MemberType::from_str("group").is_err());
    }

    #[test]
    fn a_group_can_never_claim_to_be_jit_provisioned() {
        // The groups CHECK has no JIT. Making it unrepresentable is the point of the second enum.
        assert!(GroupSource::from_str("JIT").is_err());
        assert!(UserSource::from_str("JIT").is_ok());
    }
}
