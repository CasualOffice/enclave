//! `enclave-versions` — immutable file versions: the atomic commit, restore, and version history.
//!
//! Content domain. See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # What this crate is
//!
//! The `file_versions` half of `docs/04-DATA-MODEL.md §8`, and the transaction of
//! `docs/03-LLD.md §15` that maintains it:
//!
//! * [`VersionService::commit`] — the atomic version commit. One transaction: point the file at
//!   the new version and bump its revision, insert the version, record the event, record the audit
//!   row.
//! * [`VersionService::restore`] — bring an old version back by committing a **new** one with its
//!   content. Nothing is mutated, nothing is renumbered, and the history only ever grows.
//! * [`VersionRepository`] — read one version, read the current one, page through history.
//!
//! # Immutability is the database's job
//!
//! Once a version is `AVAILABLE`, its `object_key`, `checksum_sha256`, `size_bytes`, `major` and
//! `minor` cannot be changed. That is enforced by the `file_versions_immutable` trigger in
//! `migrations/0006_versions_and_uploads.sql`, not by this crate
//! (`plans/M1-CONTENT-CORE.md` D12). The distinction is the whole point: a Rust type can only bind
//! the code that goes through it, and the exit criterion says *reject*, which a trigger does and a
//! code review only asks for. [`VersionsError::Immutable`] is what that rejection looks like coming
//! back, and `crates/versions/tests/versions.rs` proves it by trying to violate it — a guarantee
//! nobody has watched refuse is not a guarantee.
//!
//! # Availability is a state
//!
//! Every version this crate writes starts `SCANNING` with `av_status = 'PENDING'`, always, with no
//! parameter that could say otherwise (`plans/M1-CONTENT-CORE.md` D13, `CLAUDE.md` rule 9). Reading
//! is split for the same reason: [`VersionRepository::find`] returns history, and
//! [`VersionRepository::find_readable`] — the one every content path calls — applies
//! [`READABLE_PREDICATE`] in SQL. A boolean parameter shared between the two would be a boolean
//! that eventually gets passed wrongly.
//!
//! # The shape every function takes
//!
//! ```text
//! let mut tx = pool.begin(ctx.tenant_id).await?;                     // TenantScoped
//! let committed = VersionService::commit(&mut tx, &ctx, chain, &new, Utc::now()).await?;
//! tx.commit().await?;
//! ```
//!
//! The caller owns the transaction, which is what lets the version, its event, its audit row and
//! its **quota charge** commit together. [`VersionRepository`]'s reads take the `&mut PgConnection`
//! a [`enclave_db::TenantScoped`] derefs to (`plans/M1-CONTENT-CORE.md` D10); the commit path takes
//! the `TenantScoped` itself, because [`enclave_db::charge_storage`] does — a charge that could be
//! handed a bare connection could be committed apart from the bytes it pays for, which is the one
//! thing `plans/M4-GOVERNANCE.md` D31 exists to prevent.
//!
//! # It makes no authorization decision
//!
//! Nothing here reads an ACL. The policy chain runs in the handler, before a domain service is
//! reached (`plans/M1-CONTENT-CORE.md` D11), so a repository that started deciding would be a
//! second, unlinted enforcement point.
//!
//! # Three notes handed to the integrator
//!
//! **The stored-byte quota is charged here and released nowhere.** `ENC-589` wires
//! [`enclave_db::charge_storage`] into [`VersionService::commit`] and
//! [`VersionService::restore`]; there is no corresponding release, because no path in this
//! workspace destroys stored bytes yet. The trash is a soft delete and its bytes are still stored,
//! so releasing there would under-count; `enclave_files::purge_permanently` refuses by
//! construction until retention and legal hold exist. See [`commit`] for the whole argument.
//!
//! **`storage_profile_id` is a bare `Uuid`.** `enclave_core::id` has no `StorageProfileId` newtype,
//! and defining one here would collide with the real one the day the storage crate defines it.
//! `crates/libraries` and `crates/workspaces` carry the same column the same way. It has no
//! foreign key either, because `docs/04 §4`'s `storage_profiles` table is not created by any
//! migration — a caller with no profile to name passes
//! [`UNPROVISIONED_STORAGE_PROFILE`](commit::UNPROVISIONED_STORAGE_PROFILE), which documents the
//! absence and is greppable by the backfill that will end it (`ENC-573`, `ENC-691`).
//!
//! **`docs/04-DATA-MODEL.md §8` does not spell out foreign keys for `upload_sessions` and
//! `file_locks`.** Migration 0006 adds them, because §3.3 requires composite keys including
//! `tenant_id` between tenant-scoped tables and both tables reference `files` and `libraries`. The
//! document should be updated to match; that edit was out of scope here.

pub mod commit;
pub mod error;
pub mod model;
pub mod repo;

mod row;

pub use commit::{
    CommittedVersion, NewVersion, RestoreVersion, VersionService, UNPROVISIONED_STORAGE_PROFILE,
};
pub use error::{classify_write, Result, VersionsError};
pub use model::{
    is_readable_pair, ApprovalState, AvScan, AvStatus, FileVersion, StorageTier, VersionBump,
    VersionNumber, VersionStatus, READABLE_PREDICATE,
};
pub use repo::{PageLimit, VersionPage, VersionRepository};
