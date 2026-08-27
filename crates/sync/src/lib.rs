//! `enclave-sync` — the device registry, the delta cursor and sync eligibility.
//!
//! Delivery surface. `docs/02-HLD.md §4` for where this crate sits; `docs/10-SYNC-AND-EDITING.md`
//! is authoritative for everything it does, and `docs/05-API.md §13` for the four endpoints that
//! use it.
//!
//! # The one sentence the whole crate exists to keep
//!
//! `docs/10 §1`: **a client that may not download a file may not sync it.** `FileAction::Sync` is a
//! separate action from `FileAction::Download` for that reason and not as a naming preference —
//! `CLAUDE.md` rule 6 — and [`Eligibility`] is where the two are required *together* rather than
//! one being inferred from the other. A caller holding `download` and not `sync` is refused, and
//! `download_does_not_imply_sync` is the test that fails when someone collapses them.
//!
//! # The cursor, and why it is not a timestamp
//!
//! A sync client asks *"what changed since X"* and must neither miss a change nor apply one twice.
//! `X` here is a per-scope sequence number allocated from a **transactional counter row** whose
//! incrementing `UPDATE` holds a row lock until the writer commits, so allocation order is commit
//! order and the visible sequence is always a contiguous prefix. The two obvious alternatives — a
//! timestamp and a PostgreSQL `SEQUENCE` — both lose changes silently under concurrent commits.
//! The full argument, with the failure each one produces, is the header of
//! `migrations/0023_sync_devices.sql`; it lives there because that is where the guarantee is
//! actually implemented and a doc comment cannot enforce it.
//!
//! # What a remote wipe guarantees, and what it cannot
//!
//! `docs/10 §3.1`, restated here because it is the thing most likely to be over-read: the wipe is
//! **cooperative**. [`SyncRepository::request_wipe`] stamps `wipe_requested_at`, moves the device to
//! `WIPING` and — this is the half that actually stops content moving — makes every subsequent
//! delta and reservation refuse, because [`DeviceState::may_sync`] is true only for `ACTIVE`. What
//! it cannot do is delete anything already on the machine. `wiped_at` is stamped only when the
//! client says it has, and a device that never comes back online stays in `WIPING` for ever, which
//! is the honest rendering. The control that matters for a stolen laptop is the local cache being
//! encrypted at rest with a key in the OS keystore, and that is the client's, not this crate's.
//!
//! # What is deliberately not here
//!
//! * **Any authorization decision.** The chain decides; this crate is handed the answers.
//!   [`Eligibility`] has a field per condition rather than a policy handle, so nothing here can
//!   become a second, quieter enforcement point (`CLAUDE.md` rule 1).
//! * **The device's public key and the `dev` claim.** `docs/10 §3` registers a device with a
//!   `publicKey` and binds a token to it. Token binding is `crates/auth`'s, `devices` in
//!   `migrations/0001` is the table it would use, and nothing writes that table yet — so a
//!   `publicKey` accepted here would be a key stored and never checked, which reads as a control
//!   and is not one. `ENC-736` reconciles the two registries when device-bound tokens land, and
//!   until then a sync token is an ordinary access token and conditional access decides posture.
//! * **Change-log pruning.** `docs/10 §4`'s 30-day window needs a scheduled job; `crates/scheduler`
//!   owns those. The read path already refuses a cursor that has fallen off the window, so the
//!   behaviour is correct before the pruner exists — the table simply grows. `ENC-738`.

pub mod delta;
pub mod device;
pub mod eligibility;
pub mod error;
pub mod repo;
pub mod scope;

pub use delta::{ChangeOp, FeedEntry, FeedPage, ReadableVersion};
pub use device::{DeviceState, Registration, SyncDevice, MAX_DEVICES_PER_USER};
pub use eligibility::{Eligibility, TombstoneReason, Verdict, Visibility};
pub use error::{Result, SyncError};
pub use repo::{ReservationTarget, SyncRepository};
pub use scope::{DeltaCursor, ScopeKind, SyncScope};
