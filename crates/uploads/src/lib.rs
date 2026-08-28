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
//! * [`UploadService::create`] — checks the library's extension rules, its size ceiling and the
//!   tenant's stored-byte headroom **before** asking the object store for a single URL
//!   (`docs/05-API.md §8`: a rejected upload must never consume bandwidth), reserves a staging key,
//!   and records the session.
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
//! (`plans/M1-CONTENT-CORE.md` D11), and nothing here reads an ACL or a classification. It also
//! creates no file and writes no version row — those are `enclave-files` and `enclave-versions`,
//! downstream of the scan.
//!
//! **It does not charge the storage quota, and cannot.** [`quota::preflight`] is a read that can
//! only refuse; the counter is moved by `enclave_versions::VersionService::commit`, in the
//! transaction that writes the `file_versions` row the bytes are accounted by
//! (`plans/M4-GOVERNANCE.md` D31). [`quota`] carries the argument, including what that leaves open
//! for many concurrent sessions and why the alternative is worse.
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
pub mod quota;
pub mod reaper;
pub mod repo;
pub mod service;
pub mod session;
pub mod staged;
pub mod state;

mod row;

pub use content::{FailureReason, ReportedContent, VerifiedContent};
pub use error::{Result, UploadError};
pub use id::UploadSessionId;
pub use limits::{extension_of, UploadLimits, MAX_NAME_CHARS};
pub use quota::{preflight, Preflight};
pub use reaper::{reap_expired, reclaim_stranded, ReapReport, ReclaimReport};
pub use repo::UploadRepository;
pub use service::{Completion, IssuedUpload, NewUpload, UploadIntent, UploadService};
pub use session::{
    LoadedSession, Resumable, ScanHandoff, Session, SessionRecord, SettledSession, StrandedSession,
};
pub use staged::StagedObject;
pub use state::{
    Aborted, Created, Expired, Failed, Live, Phase, Scanning, Transition, UploadState, Uploaded,
    Uploading,
};

#[cfg(test)]
mod flat_memory {
    //! `ENC-144` — the structural half of "5 GB resumable upload with flat API memory".
    //!
    //! M1's fifth exit criterion is a claim about *memory*, and the reason it holds is not that the
    //! buffers here are small: it is that there are none. The client sends bytes to object storage
    //! over pre-signed URLs and they never enter this process ([`crate::staged`]), so what this
    //! crate handles for a 5 GB upload is a key, a part list and three integers — the same thing it
    //! handles for a 5 KB one.
    //!
    //! That is a property of the crate's *shape*, so the shape is what is asserted. A volume test
    //! cannot run in CI, and one that could would pass just as happily against an implementation
    //! that streamed 5 GB through this process in 8 KiB pieces — the peak stays flat and every byte
    //! still crosses the API. The question is not how much is held at once; it is whether we are on
    //! the path at all.
    //!
    //! A regression that put us back on it has to do one of two things: name a type that holds a
    //! run of bytes, or ask the store to stream content through us. Both are refused below.
    //!
    //! The runtime half is `tests/sessions.rs`'s
    //! `a_five_gigabyte_upload_is_completed_without_the_api_touching_a_byte`, which drives the state
    //! machine at the criterion's size against a store that fails loudly if it is ever asked to
    //! move content.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    /// Every module in this crate, with its source. Kept honest by
    /// [`every_module_is_scanned`].
    const SOURCES: &[(&str, &str)] = &[
        ("content.rs", include_str!("content.rs")),
        ("error.rs", include_str!("error.rs")),
        ("id.rs", include_str!("id.rs")),
        ("limits.rs", include_str!("limits.rs")),
        ("quota.rs", include_str!("quota.rs")),
        ("reaper.rs", include_str!("reaper.rs")),
        ("repo.rs", include_str!("repo.rs")),
        ("row.rs", include_str!("row.rs")),
        ("service.rs", include_str!("service.rs")),
        ("session.rs", include_str!("session.rs")),
        ("staged.rs", include_str!("staged.rs")),
        ("state.rs", include_str!("state.rs")),
    ];

    /// What a byte buffer looks like when it arrives, and the one store call that produces one.
    ///
    /// Every entry denotes a run of bytes whose length is decided at runtime — which is the only
    /// kind that can grow with an upload. A fixed-size `[u8; N]` is deliberately not here: its
    /// length is a compile-time constant, so it cannot hold content, and the crate has exactly one
    /// (`content.rs`'s sixteen-byte hex table).
    ///
    /// [`enclave_storage::BlobStore::read_range`] is on the list because it is the *only* method on
    /// that trait that puts object bytes in this process's memory. Preview and antivirus call it
    /// and must; an upload path that called it would be reading back what it just told the client
    /// to send directly.
    const BYTE_BEARING: &[&str] = &[
        "Vec<u8>",
        "Box<[u8]>",
        "&[u8]",
        "&mut [u8]",
        "Bytes",
        "BytesMut",
        "ByteStream",
        "read_range",
        "AsyncRead",
        "AsyncWrite",
        "std::fs",
        "tokio::fs",
    ];

    /// The source with comments removed.
    ///
    /// Prose says "Bytes the client says it sent" in several places and means the count, not a
    /// buffer. Cutting each line at its first `//` also truncates the one line holding a `https://`
    /// literal, which is a blind spot in the harmless direction: it can only remove text from the
    /// scan, never add a match, and `every_module_is_scanned` covers the axis that would matter.
    fn code_only(source: &str) -> String {
        source
            .lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether `token` appears as its own identifier rather than inside a longer one.
    ///
    /// Without this, `MaxFileBytes` and `sizeBytes` would both read as `Bytes`.
    fn mentions(code: &str, token: &str) -> bool {
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        code.match_indices(token).any(|(at, _)| {
            boundary(code[..at].chars().next_back())
                && boundary(code[at + token.len()..].chars().next())
        })
    }

    #[test]
    fn nothing_in_this_crate_can_hold_a_run_of_content_bytes() {
        for (module, source) in SOURCES {
            let code = code_only(source);
            for token in BYTE_BEARING {
                assert!(
                    !mentions(&code, token),
                    "`{module}` names `{token}`, so this crate has started handling upload bytes. \
                     M1's fifth exit criterion — 5 GB with flat API memory — holds because the \
                     bytes go client-to-store over signed URLs and never reach us (see \
                     `staged.rs`). If a byte buffer genuinely belongs here, that is a change to \
                     what the criterion means and needs to be argued rather than merged."
                );
            }
        }
    }

    #[test]
    fn every_module_is_scanned() {
        // A gate over a hardcoded file list stops being a gate the moment someone adds a module,
        // and does it silently. This is what makes the list above self-maintaining: a new `mod`
        // fails here by name until it is scanned too.
        for line in include_str!("lib.rs").lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("pub mod ").or_else(|| line.strip_prefix("mod "))
            else {
                continue;
            };
            let Some(name) = rest.strip_suffix(';') else { continue };
            assert!(
                SOURCES.iter().any(|(module, _)| *module == format!("{name}.rs")),
                "`{name}` is a module of this crate that the byte-buffer scan does not read; add \
                 it to SOURCES"
            );
        }
    }
}
