//! `enclave-libraries` — libraries: the container inside a workspace that owns settings.
//!
//! Content domain. See `docs/02-HLD.md §4` for where this crate sits, and
//! `docs/04-DATA-MODEL.md §7` for the table it owns: `libraries`.
//!
//! # What this crate is
//!
//! [`LibraryRepository`] and the types it returns: create a library in a workspace, look one up,
//! page through a workspace's libraries, replace the settings under an `If-Match` revision, and
//! trash.
//!
//! A library is where policy is actually configured — versioning, approval, checkout, allowed and
//! blocked extensions, external sharing, AI indexing, MCP visibility, sync eligibility, storage
//! profile, retention (`docs/01-PRD.md §7`). All seventeen settings are stored and returned; none
//! of them are interpreted here. The crates that act on them are the authorities on what they
//! mean, and a second interpretation in a repository is a second answer that eventually disagrees.
//!
//! # `inherit_permissions` in particular
//!
//! It is the flag `enclave-authorization`'s inheritance walk stops at: `FALSE` means the library's
//! own ACL entries apply and the workspace's do not (`docs/04-DATA-MODEL.md §9`). This crate
//! persists the boolean faithfully and draws no conclusion from it — not even "a library that does
//! not inherit is private". See [`model`].
//!
//! # What this crate is not
//!
//! **It makes no authorization decision.** The policy chain is called from the handler, before a
//! domain service is reached (`plans/M1-CONTENT-CORE.md` D11), so everything here is unauthorized
//! by construction and assumes the caller already ran `PolicyEngine::enforce`.
//!
//! # The shape every function takes
//!
//! ```text
//! let mut tx = pool.begin(ctx.tenant_id).await?;                       // TenantScoped
//! let library = LibraryRepository::find_by_id(&mut tx, ctx.tenant_id, id).await?;
//! tx.commit().await?;
//! ```
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10), so a repository physically
//! cannot run without a tenant context; the `no-raw-pool` gate keeps it that way. Every statement
//! also carries its own `tenant_id = $1` predicate — the second of the two layers
//! `docs/04-DATA-MODEL.md §3` specifies, and the one that stays correct if the first is ever not in
//! force. `ENC-124` is why that is worth insisting on.
//!
//! # Three things to know before changing anything here
//!
//! **The parent workspace is proved by the foreign key**, not by a prior `SELECT` — atomically with
//! the insert, and identically for a workspace that does not exist and one in another tenant. Both
//! produce [`LibraryError::NoSuchWorkspace`], which the edge renders as `404` (`CLAUDE.md` rule 7).
//!
//! **There is no uniqueness constraint on a library slug.** `docs/04-DATA-MODEL.md §7` defines none
//! and migration 0004 creates none, so two live libraries in one workspace can share a slug today.
//! This crate does not simulate the missing index with a read-then-write check, which would lose
//! the race it claims to prevent; it folds slugs consistently so the index can be added later
//! without a repair migration, and the gap is reported rather than papered over. See
//! [`library_repo`].
//!
//! **A refused write ends the caller's transaction.** [`LibraryError::NoSuchWorkspace`] comes from
//! a constraint, and a constraint violation aborts the PostgreSQL transaction it happened in: every
//! later statement on that connection fails with `25P02` until it is rolled back. The error is a
//! well-formed domain answer but it is not recoverable in place.
//!
//! # Borrowed from `enclave-db`, and why
//!
//! [`Cursor`], [`PageSize`], [`FilterFingerprint`] and [`normalize_slug`] are re-exported from
//! `enclave-db` rather than reimplemented. The cursor is a security primitive — it binds a listing
//! position to a tenant and a filter set — and two copies of a security primitive drift. They were
//! borrowed from `enclave-identity` until `ENC-137`, which was the wrong shape: a domain crate
//! reaching sideways into a peer domain crate inverts `plans/M0-FOUNDATIONS.md` D1. `enclave-db`
//! sits below every domain crate, so the edge now points down.

pub mod error;
pub mod library_repo;
pub mod model;

mod row;

pub use error::{LibraryError, Result};
pub use library_repo::{LibraryFilter, LibraryPage, LibraryRepository};
pub use model::{ExternalSharing, Library, LibrarySettings, VersioningMode};

/// Pagination primitives, shared with every other listing — see the note in the crate documentation.
pub use enclave_db::{normalize_slug, Cursor, FilterFingerprint, PageSize};
