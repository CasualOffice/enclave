//! `enclave-uploads` — upload sessions, the state machine, and multipart.
//!
//! Content domain (`docs/02-HLD.md §4`). This crate owns `upload_sessions`
//! (`docs/04-DATA-MODEL.md §8`), the state machine of `docs/03-LLD.md §15`, and the endpoints of
//! `docs/05-API.md §8` up to — and only up to — the point where antivirus takes over.
//!
//! # The one thing to know before using it
//!
//! **Nothing here can make content readable.** The machine this crate implements ends at
//! `SCANNING`:
//!
//! ```text
//! CREATED -> UPLOADING -> UPLOADED -> SCANNING | PROCESSING -> AVAILABLE
//!                                    this crate |  someone else
//! ```
//!
//! `PROCESSING`, `AVAILABLE` and `QUARANTINED` are values of the `state` column and are *not*
//! phases of the type-level machine, so no transition in this crate targets them and
//! [`UploadRepository::apply`] — the only statement that writes `state` — has nothing to write
//! them from. That is `CLAUDE.md` rule 9 expressed as a type error rather than as a review
//! comment: a future caller cannot skip the scan by passing a flag, because no flag exists.
//! [`UploadService::complete`] returns a [`ScanHandoff`], and that value is the entire interface
//! between an accepted upload and everything that has to happen before anyone can read it.
//!
//! # What it does
//!
//! * [`UploadService::create`] — checks the library's extension rules and size ceiling **before**
//!   asking the object store for a single URL (`docs/05-API.md §8`: a rejected upload must never
//!   consume bandwidth), reserves a staging key, and records the session.
//! * [`UploadService::complete`] — verifies the reported size and SHA-256 against the declaration
//!   *and* against what the store observed, then advances to `SCANNING`. A mismatch is a persisted
//!   [`Completion::Refused`], not a warning: the checksum is what makes the version immutable later
//!   (`plans/M1-CONTENT-CORE.md` D12).
//! * [`UploadService::abort`] and [`reaper::reap_expired`] — release staged bytes, bytes first and
//!   row second, so a failed delete leaves an orphan that is retried rather than one that is
//!   forgotten.
//!
//! # What it does not do
//!
//! No authorization. The policy chain runs in the handler, before this service is reached
//! (`plans/M1-CONTENT-CORE.md` D11), and nothing here reads an ACL, a classification or a quota
//! beyond the per-file ceiling it is handed. It also creates no file and writes no version row —
//! those are `enclave-files` and `enclave-versions`, downstream of the scan.
//!
//! # Shape
//!
//! Repositories take the `&mut PgConnection` a `TenantScoped` transaction derefs to, never a pool
//! (`plans/M1-CONTENT-CORE.md` D10), and every statement carries an explicit `tenant_id` predicate
//! as well (`docs/04-DATA-MODEL.md §3`).

pub mod content;
pub mod error;
pub mod id;
pub mod limits;
pub mod reaper;
pub mod repo;
pub mod service;
pub mod session;
pub mod staged;
pub mod state;

mod row;

pub use content::{ChecksumEvidence, FailureReason, ReportedContent, VerifiedContent};
pub use error::{Result, UploadError};
pub use id::UploadSessionId;
pub use limits::{extension_of, UploadLimits, MAX_NAME_CHARS};
pub use reaper::{reap_expired, ReapReport};
pub use repo::UploadRepository;
pub use service::{Completion, IssuedUpload, NewUpload, UploadIntent, UploadService};
pub use session::{LoadedSession, Resumable, ScanHandoff, Session, SessionRecord, SettledSession};
pub use staged::StagedObject;
pub use state::{
    Aborted, Created, Expired, Failed, Live, Phase, Scanning, Transition, UploadState, Uploaded,
    Uploading,
};
