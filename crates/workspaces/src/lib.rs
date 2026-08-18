//! `enclave-workspaces` — the top-level content container, its membership, and its visibility.
//!
//! Content domain. See `docs/02-HLD.md §4` for where this crate sits in the architecture, and
//! `docs/04-DATA-MODEL.md §7` for the tables it owns: `workspaces` and `workspace_members`.
//!
//! # What this crate is
//!
//! Two repositories and the types they return:
//!
//! * [`WorkspaceRepository`] — create, look up by id or slug, page through a tenant's workspaces,
//!   replace mutable state under an `If-Match` revision, and trash.
//! * [`WorkspaceMemberRepository`] — grant and revoke membership, list a workspace's members, and
//!   list the workspaces a principal is directly a member of.
//!
//! # What this crate is not
//!
//! **It makes no authorization decision.** The policy chain is called from the handler, before a
//! domain service is reached (`plans/M1-CONTENT-CORE.md` D11), so everything here is *unauthorized
//! by construction* — it assumes the caller already ran `PolicyEngine::enforce`. Two consequences
//! worth stating rather than discovering:
//!
//! * `visibility` is stored and returned and never consulted. It is an input to the policy chain.
//! * [`WorkspaceMemberRepository::list_for_principal`] is direct membership, not reachability. A
//!   principal also reaches a workspace through a group, through tenant visibility, and through an
//!   ACL entry below it.
//!
//! # The shape every function takes
//!
//! ```text
//! let mut tx = pool.begin(ctx.tenant_id).await?;                       // TenantScoped
//! let ws = WorkspaceRepository::find_by_id(&mut tx, ctx.tenant_id, id).await?;
//! tx.commit().await?;
//! ```
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without a tenant context — and
//! the `no-raw-pool` structural gate keeps it that way. Every statement *also* carries its own
//! `tenant_id = $1` predicate: that is the second of the two layers `docs/04-DATA-MODEL.md §3`
//! specifies, and the one that keeps a query correct if it is ever run somewhere the first layer is
//! not in force. `ENC-124` is the reason to take that seriously.
//!
//! # Two rules that are easy to get subtly wrong
//!
//! **Slug uniqueness belongs to the index.** `uq_workspace_slug` is
//! `UNIQUE (tenant_id, slug) WHERE deleted_at IS NULL`, so it is per tenant and it ignores trashed
//! rows. Writes here catch its violation and report [`WorkspaceError::SlugTaken`]; none of them
//! check first. See [`workspace_repo`] for the race a read-then-write loses.
//!
//! **A refused write ends the caller's transaction.** [`WorkspaceError::SlugTaken`],
//! [`WorkspaceError::AlreadyMember`] and [`WorkspaceError::NoSuchWorkspace`] are raised by
//! PostgreSQL constraints, and a constraint violation aborts the transaction it happened in — every
//! subsequent statement on that connection fails with `25P02` until it is rolled back. These are
//! well-formed domain answers, but they are not recoverable *in place*: a handler that catches one
//! must roll back (or have taken a `SAVEPOINT` first), not catch it and carry on writing.
//!
//! **Optimistic concurrency is part of the write.** The `If-Match` revision is compared inside the
//! `UPDATE`'s `WHERE` clause, never in Rust between a read and a write, and a mismatch returns
//! [`WorkspaceError::RevisionConflict`] carrying the current revision — never a silent overwrite.
//!
//! # Borrowed from `enclave-identity`, and why
//!
//! [`Cursor`], [`PageSize`], [`FilterFingerprint`] and [`normalize_slug`] are re-exported from
//! `enclave-identity` rather than reimplemented. The cursor is a security primitive — it binds a
//! listing position to a tenant and a filter set — and two copies of a security primitive drift.
//! The dependency edge is the wrong shape and is deliberate: these types belong in a crate below
//! both, and moving them is a change to `enclave-db` (or a new crate) that this task does not own.
//! It is recorded for the integrator rather than worked around by copying the code.

pub mod error;
pub mod member_repo;
pub mod model;
pub mod workspace_repo;

mod row;
mod violation;

pub use error::{Result, WorkspaceError};
pub use member_repo::{MemberFilter, MemberPage, WorkspaceMemberRepository};
pub use model::{
    NewMember, PrincipalId, PrincipalType, RoleId, Visibility, Workspace, WorkspaceMember,
    WorkspaceSettings,
};
pub use workspace_repo::{WorkspaceFilter, WorkspacePage, WorkspaceRepository};

/// Pagination primitives, shared with `enclave-identity` — see the note in the crate documentation.
pub use enclave_identity::{normalize_slug, Cursor, FilterFingerprint, PageSize};
