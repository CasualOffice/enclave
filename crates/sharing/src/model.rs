//! The records this crate reads and writes, and the closed vocabularies their columns hold.
//!
//! Every enumeration mirrors a `CHECK` constraint in `migrations/0008_sharing.sql`
//! (`docs/04-DATA-MODEL.md §7`) — same members, same spellings.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UnknownVariant, UserId, Uuid};

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
    /// What a link points at (`share_links.resource_type`).
    pub enum ShareResourceKind {
        /// A whole library.
        Library => "LIBRARY",
        /// A folder and what it contains.
        Folder => "FOLDER",
        /// One file.
        File => "FILE",
    }
}

db_enum! {
    /// What the holder of a link may do (`share_links.permission`).
    ///
    /// `PreviewOnly` is not a weaker `View` — it is the product's central claim
    /// (`docs/01-PRD.md §18`) expressed as a share setting, and `allow_download` is a separate
    /// column precisely so that the two cannot be collapsed by accident (`CLAUDE.md` rule 6).
    pub enum SharePermission {
        /// Read, including download if `allow_download` also permits it.
        View => "VIEW",
        /// Rendition only. No original bytes reach the holder by any path.
        PreviewOnly => "PREVIEW_ONLY",
        /// Read and write.
        Edit => "EDIT",
    }
}

db_enum! {
    /// Who may redeem a link (`share_links.audience`).
    pub enum ShareAudience {
        /// Members of this tenant only.
        Internal => "INTERNAL",
        /// Named recipients, listed in `share_link_grants`.
        Specific => "SPECIFIC",
        /// Anyone who can authenticate somewhere the tenant trusts.
        ExternalAuthenticated => "EXTERNAL_AUTHENTICATED",
        /// Anyone with an email address in `allowed_domains`.
        DomainRestricted => "DOMAIN_RESTRICTED",
        /// Anyone holding the token. The setting most tenants disable outright.
        Anyone => "ANYONE",
    }
}

db_enum! {
    /// What happened to a link (`share_link_events.event`).
    ///
    /// The refusals are as important as the successes: `AuthFailed` and `Blocked` rows are the
    /// evidence that somebody probed a link, which is why migration 0008 grants no `UPDATE` or
    /// `DELETE` on that table.
    pub enum ShareEventKind {
        /// The resource was viewed through the link.
        Viewed => "VIEWED",
        /// Content was downloaded through it.
        Downloaded => "DOWNLOADED",
        /// A password or OTP was wrong.
        AuthFailed => "AUTH_FAILED",
        /// Policy refused the redemption — audience, domain, network, DLP.
        Blocked => "BLOCKED",
        /// The link had expired.
        Expired => "EXPIRED",
    }
}

/// A share link as stored.
///
/// Carries no token and no password: the digest columns are read only by the lookup that matches
/// them, and a struct that held either would eventually be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    /// The link's identifier.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// What kind of thing it points at.
    pub resource_type: ShareResourceKind,
    /// Which one.
    pub resource_id: Uuid,
    /// What the holder may do.
    pub permission: SharePermission,
    /// Whether original bytes may leave. Separate from `permission` on purpose.
    pub allow_download: bool,
    /// Who may redeem it.
    pub audience: ShareAudience,
    /// Whether a password is set. The hash itself never leaves the database.
    pub has_password: bool,
    /// Whether a one-time code is required per redemption.
    pub require_otp: bool,
    /// Whether the redeemer must have completed MFA.
    pub require_mfa: bool,
    /// When it stops working, if ever.
    pub expires_at: Option<DateTime<Utc>>,
    /// How many downloads it permits in total, if limited.
    pub max_downloads: Option<i64>,
    /// How many it has issued.
    pub download_count: i64,
    /// Which email domains may redeem it, for `DOMAIN_RESTRICTED`.
    pub allowed_domains: Option<Vec<String>>,
    /// Who created it.
    pub created_by: UserId,
    /// When.
    pub created_at: DateTime<Utc>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ShareLink {
    /// Whether the link is usable at `now`, ignoring the download budget.
    ///
    /// The budget is deliberately **not** consulted here. Reading a counter and acting on what it
    /// said is the race that `crate::redeem` exists to avoid; a helper that answered "there is
    /// budget left" would be the exact shape of the bug, wrapped in a name that makes it look
    /// checked.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr as _;

    use super::*;

    /// The Rust vocabularies and the migration's `CHECK` constraints are one list, read from the
    /// migration rather than restated — a test carrying its own copy passes when both are wrong.
    #[test]
    fn every_vocabulary_matches_its_check_constraint() {
        let migration = include_str!("../../../migrations/0008_sharing.sql");

        let cases: [(&str, Vec<&'static str>); 4] = [
            (
                "resource_type   TEXT NOT NULL CHECK (resource_type IN (",
                ShareResourceKind::all().iter().map(|v| v.as_str()).collect(),
            ),
            (
                "permission      TEXT NOT NULL CHECK (permission IN (",
                SharePermission::all().iter().map(|v| v.as_str()).collect(),
            ),
            (
                "audience        TEXT NOT NULL CHECK (audience IN (",
                ShareAudience::all().iter().map(|v| v.as_str()).collect(),
            ),
            (
                "event         TEXT NOT NULL CHECK (event IN (",
                ShareEventKind::all().iter().map(|v| v.as_str()).collect(),
            ),
        ];

        for (needle, variants) in cases {
            let clause = migration
                .split_once(needle)
                .unwrap_or_else(|| panic!("constraint not found: {needle}"))
                .1
                .split_once(')')
                .expect("the constraint's closing paren")
                .0;

            for variant in &variants {
                assert!(
                    clause.contains(&format!("'{variant}'")),
                    "`{variant}` is missing from the constraint, so writing one would be refused"
                );
            }
            assert_eq!(
                clause.matches('\'').count() / 2,
                variants.len(),
                "the constraint permits a value this crate cannot name: {clause}"
            );
        }
    }

    #[test]
    fn every_vocabulary_round_trips() {
        for value in ShareAudience::all() {
            assert_eq!(ShareAudience::from_str(value.as_str()), Ok(*value));
        }
        assert!(ShareAudience::from_str("EVERYONE").is_err());
    }

    fn link(expires_at: Option<DateTime<Utc>>, revoked_at: Option<DateTime<Utc>>) -> ShareLink {
        ShareLink {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            resource_type: ShareResourceKind::File,
            resource_id: Uuid::nil(),
            permission: SharePermission::PreviewOnly,
            allow_download: false,
            audience: ShareAudience::Specific,
            has_password: false,
            require_otp: false,
            require_mfa: false,
            expires_at,
            max_downloads: Some(3),
            download_count: 3,
            allowed_domains: None,
            created_by: UserId::from(Uuid::nil()),
            created_at: DateTime::<Utc>::MIN_UTC,
            revoked_at,
        }
    }

    #[test]
    fn expiry_and_revocation_both_close_a_link() {
        let now = Utc::now();
        assert!(link(None, None).is_live(now));
        assert!(link(Some(now + chrono::Duration::hours(1)), None).is_live(now));
        assert!(!link(Some(now - chrono::Duration::seconds(1)), None).is_live(now));
        assert!(!link(None, Some(now)).is_live(now));
        // Revocation beats a future expiry, not the other way round.
        assert!(!link(Some(now + chrono::Duration::days(30)), Some(now)).is_live(now));
    }

    #[test]
    fn liveness_deliberately_ignores_the_download_budget() {
        // `download_count == max_downloads` here. If `is_live` consulted the counter, callers would
        // read it and act on what it said, which is precisely the race `crate::redeem` avoids by
        // putting the limit in the UPDATE's WHERE clause.
        let exhausted = link(None, None);
        assert_eq!(exhausted.download_count, exhausted.max_downloads.expect("set"));
        assert!(exhausted.is_live(Utc::now()));
    }
}
