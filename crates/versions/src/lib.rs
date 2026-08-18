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
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller owns the
//! transaction, which is what lets the version, its event and its audit row commit together — and
//! what lets a caller put a quota update or a metadata write in the same transaction later.
//!
//! # It makes no authorization decision
//!
//! Nothing here reads an ACL. The policy chain runs in the handler, before a domain service is
//! reached (`plans/M1-CONTENT-CORE.md` D11), so a repository that started deciding would be a
//! second, unlinted enforcement point.
//!
//! # Three notes handed to the integrator
//!
//! **Quota accounting is not performed.** `docs/03-LLD.md §15` lists `UPDATE quota_usage` in the
//! commit transaction. `quotas` and `quota_usage` (`docs/04-DATA-MODEL.md §16`) have no migration
//! yet, so the step is named and skipped rather than faked; see [`commit`] for where it goes.
//!
//! **`storage_profile_id` is a bare `Uuid`.** `enclave_core::id` has no `StorageProfileId` newtype,
//! and defining one here would collide with the real one the day the storage crate defines it.
//! `crates/libraries` and `crates/workspaces` carry the same column the same way.
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

pub use commit::{CommittedVersion, NewVersion, RestoreVersion, VersionService};
pub use error::{classify_write, Result, VersionsError};
pub use model::{
    ApprovalState, AvScan, AvStatus, FileVersion, VersionBump, VersionNumber, VersionStatus,
    READABLE_PREDICATE,
};
pub use repo::{PageLimit, VersionPage, VersionRepository};
