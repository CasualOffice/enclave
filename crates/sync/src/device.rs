//! The registered device, and what a remote wipe does to it.
//!
//! `docs/10-SYNC-AND-EDITING.md §3` and `§3.1`; `docs/04-DATA-MODEL.md §15`.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_core::{DeviceId, DevicePosture, TenantId, UserId};
use serde::Serialize;

use crate::error::SyncError;

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `crates/versions/src/model.rs` and `crates/files/src/model.rs` use, copied for
/// the reason those give: `enclave_core`'s equivalent is private to that crate. What matters is
/// that `as_str` and `from_str` come from one list, so a hand-written parser cannot fall a variant
/// behind its writer.
macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test asserts the Rust set against the constraint's set rather
            /// than trusting that both were updated together.
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

        impl FromStr for $name {
            type Err = SyncError;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(SyncError::UnknownVariant {
                        vocabulary: stringify!($name),
                        value: other.to_owned(),
                    }),
                }
            }
        }
    };
}

db_enum! {
    /// Where a device sits in its life cycle (`sync_devices.state`).
    ///
    /// `WIPING` is the one that carries information a user needs: it is a wipe that has been
    /// *requested* and not acknowledged, which for a device that never comes back online is where
    /// it stays. Collapsing it into `WIPED` would let an administrator believe a laptop had been
    /// cleaned when nothing had run on it — which is the exact misreading `docs/10 §3.1` says the
    /// admin UI must not permit.
    pub enum DeviceState {
        /// Syncing.
        Active => "ACTIVE",
        /// Registered, not currently syncing. The user's own pause, or a policy pause.
        Paused => "PAUSED",
        /// Its token family is dead and it may not sync again. Not deleted — see the migration.
        Revoked => "REVOKED",
        /// A wipe has been requested and the device has not acknowledged it.
        Wiping => "WIPING",
        /// The device confirmed it deleted its cache and its tokens.
        Wiped => "WIPED",
    }
}

impl DeviceState {
    /// Whether a device in this state may be served a delta or reserve an upload.
    ///
    /// Only `ACTIVE`. A `PAUSED` device is one whose owner or administrator has said "not now", and
    /// serving it changes is the paused state having no effect; a `REVOKED`, `WIPING` or `WIPED`
    /// device is one the tenant has decided must hold no more content, and handing it a delta is
    /// the wipe being undone by the next poll.
    #[must_use]
    pub const fn may_sync(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A registered sync client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDevice {
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// The device's identifier.
    pub device_id: DeviceId,
    /// The single user it is bound to (`docs/10 §3`).
    pub user_id: UserId,
    /// What the user sees in the device list.
    pub name: String,
    /// `windows`, `macos`, `ios`, … — a client-build fact, not a policy vocabulary.
    pub platform: String,
    /// The client build, which `docs/10 §10`'s minimum-version refusal reads.
    pub client_version: String,
    /// MDM's answer, feeding conditional access.
    pub posture: DevicePosture,
    /// Where it sits in its life cycle.
    pub state: DeviceState,
    /// When it last completed a delta.
    pub last_sync_at: Option<DateTime<Utc>>,
    /// When a wipe was asked for.
    pub wipe_requested_at: Option<DateTime<Utc>>,
    /// When the device confirmed it had wiped. Never set on the server's own initiative.
    pub wiped_at: Option<DateTime<Utc>>,
    /// When it was registered.
    pub created_at: DateTime<Utc>,
    /// When the row last changed.
    pub updated_at: DateTime<Utc>,
}

impl SyncDevice {
    /// Whether this device may be served a delta or allowed to reserve an upload.
    #[must_use]
    pub const fn may_sync(&self) -> bool {
        self.state.may_sync()
    }

    /// Whether a wipe has been asked for and not yet confirmed.
    #[must_use]
    pub const fn wipe_outstanding(&self) -> bool {
        self.wipe_requested_at.is_some() && self.wiped_at.is_none()
    }
}

/// What a device registration declares.
///
/// `docs/10 §3`: `{ name, platform, clientVersion, publicKey }`. The public key is deliberately
/// absent from this type — see [`crate`] for why, and `ENC-736`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The user the device is bound to. From the verified context, never from the body.
    pub user_id: UserId,
    /// Display name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Client build.
    pub client_version: String,
}

/// The maximum number of `ACTIVE` devices one user may hold.
///
/// `docs/10 §3`: `sync.max_devices_per_user`, default 5. A constant here rather than a
/// configuration read because `crates/config` has no sync section and inventing one would be a
/// second answer to a question `docs/08-BYO-INFRA.md` owns; making it configurable is `ENC-738`.
/// The bound is on *fan-out* — how many copies of a tenant's content exist on machines — which is
/// why revoked and wiped devices do not count against it.
pub const MAX_DEVICES_PER_USER: usize = 5;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The vocabulary is a copy of a `CHECK` constraint; if one drifts, rows stop decoding.
    #[test]
    fn the_state_vocabulary_matches_the_check_constraint() {
        let rendered: Vec<&str> = DeviceState::all().iter().map(|s| s.as_str()).collect();
        assert_eq!(rendered, ["ACTIVE", "PAUSED", "REVOKED", "WIPING", "WIPED"]);
    }

    #[test]
    fn every_state_round_trips_through_its_stored_form() {
        for state in DeviceState::all() {
            assert_eq!(state.as_str().parse::<DeviceState>().expect("round trip"), *state);
        }
        assert!(matches!(
            "TELEPORTED".parse::<DeviceState>(),
            Err(SyncError::UnknownVariant { .. })
        ));
    }

    /// Only `ACTIVE` syncs, and the three terminal states are the point.
    #[test]
    fn a_device_that_has_been_told_to_wipe_is_not_served_more_content() {
        assert!(DeviceState::Active.may_sync());
        for refused in
            [DeviceState::Paused, DeviceState::Revoked, DeviceState::Wiping, DeviceState::Wiped]
        {
            assert!(!refused.may_sync(), "{refused} was served a delta");
        }
    }

    #[test]
    fn an_unacknowledged_wipe_is_visible_as_outstanding() {
        let base = SyncDevice {
            tenant_id: TenantId::new_v7(),
            device_id: DeviceId::new_v7(),
            user_id: UserId::new_v7(),
            name: "laptop".to_owned(),
            platform: "macos".to_owned(),
            client_version: "1.0.0".to_owned(),
            posture: DevicePosture::Unknown,
            state: DeviceState::Wiping,
            last_sync_at: None,
            wipe_requested_at: Some(Utc::now()),
            wiped_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(base.wipe_outstanding(), "a requested, unacknowledged wipe is outstanding");
        let acknowledged =
            SyncDevice { wiped_at: Some(Utc::now()), state: DeviceState::Wiped, ..base.clone() };
        assert!(!acknowledged.wipe_outstanding());
        let never_asked =
            SyncDevice { wipe_requested_at: None, state: DeviceState::Active, ..base };
        assert!(!never_asked.wipe_outstanding());
    }

    #[test]
    fn the_documented_device_bound_is_the_one_enforced() {
        // `docs/10 §3` states five. A change here is a change to how many machines hold a copy of
        // a tenant's content.
        assert_eq!(MAX_DEVICES_PER_USER, 5);
    }
}
