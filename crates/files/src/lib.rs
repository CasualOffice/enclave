//! `enclave-files` — the metadata tree: files, folders, moves and the trash.
//!
//! Content domain. See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # What this crate is
//!
//! One repository over the `files` table of `docs/04-DATA-MODEL.md §8`, plus the two things that
//! table's shape implies:
//!
//! * [`FileRepository`] — create a folder or a file node, read one, page through the children of a
//!   folder or of a library root, rename, move, trash and restore.
//! * [`FileRepository::breadcrumb`] — walk a node to its library root in one statement
//!   ([`path`]).
//! * [`purge`] — permanent deletion, deliberately **not** implemented, with the four checks
//!   `docs/03-LLD.md §18` requires written down where the gap is visible.
//!
//! # What this crate is not
//!
//! **It does not upload, version or scan.** `file_versions`, `upload_sessions` and `file_locks` are
//! `ENC-129` and `ENC-131`; antivirus is `ENC-132`. A file node created here has no content:
//! `current_version_id` is `NULL`, `size_bytes` is `0`, and its status is
//! [`NodeStatus::Processing`] rather than `AVAILABLE`, because `CLAUDE.md` rule 9 says nothing is
//! available before antivirus has finished and this crate can never truthfully say that it has.
//!
//! **It makes no authorization decision.** Nothing here reads an ACL. The policy chain is called
//! from the handler, before a domain service is reached (`plans/M1-CONTENT-CORE.md` D11), so a
//! repository that started deciding would be a second, unlinted enforcement point. What it does
//! enforce is structural: a parent that is a folder, a library a move cannot leave, and a tree that
//! cannot contain a cycle.
//!
//! # The shape every function takes
//!
//! ```text
//! let mut tx = pool.begin(ctx.tenant_id).await?;                        // TenantScoped
//! let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, id).await?;
//! tx.commit().await?;
//! ```
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without a tenant context — and
//! the `no-raw-pool` structural gate keeps it that way. Every statement *also* carries its own
//! `tenant_id = $1` predicate: the second of the two layers `docs/04-DATA-MODEL.md §3` specifies,
//! and the one that keeps a query correct if it is ever run where the first is not in force.
//! `ENC-124` is the reason to take that seriously — the policies were right for months and nothing
//! had ever executed as the application role, so nothing had ever proved it.
//!
//! # Two notes handed to the integrator
//!
//! **Pagination is borrowed from `enclave-identity`.** [`Cursor`], [`PageSize`] and
//! [`FilterFingerprint`] live in that crate because that is where the first listing needed them,
//! and nothing about them is about principals. This crate depends on `enclave-identity` for those
//! three types and for nothing else. They belong in a crate both can depend on — `enclave-db`
//! alongside `TenantScoped`, or `enclave-core` — and moving them is a mechanical change that
//! touches two crates this task was not allowed to edit.
//!
//! **Three columns of `files` are not read here.** `classification_id`, `classification_source`
//! and `content_type_id` are owned by crates that do not exist yet, and `enclave_core::id` has no
//! newtype for either identifier. See [`model`] for why they are absent rather than typed as bare
//! `Uuid`.

pub mod error;
pub mod model;
pub mod normalize;
pub mod path;
pub mod purge;
pub mod repo;

mod row;

pub use error::{FilesError, Result};
pub use model::{FileNode, NodeStatus, NodeType};
pub use normalize::{display_name, normalize_name, validate_name, MAX_NAME_CHARS};
pub use path::{Breadcrumb, PathSegment, MAX_DEPTH};
pub use purge::purge_permanently;
pub use repo::{
    ChildFilter, FilePage, FileRepository, Mutation, NewFile, NewFolder, Parent, FOLDER_MIME_TYPE,
};

// Re-exported so a caller does not have to depend on `enclave-identity` to page through a folder.
// See the note above: this is the seam that moves when pagination finds a better home.
pub use enclave_identity::{Cursor, FilterFingerprint, PageSize};
