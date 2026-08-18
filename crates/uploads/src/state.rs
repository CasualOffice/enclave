//! The upload state machine of `docs/03-LLD.md §15`, as types rather than as a string column.
//!
//! ```text
//! CREATED -> UPLOADING -> UPLOADED -> SCANNING -> PROCESSING -> AVAILABLE
//! ```
//!
//! Failure states: `QUARANTINED`, `FAILED`, `ABORTED`, `EXPIRED`.
//!
//! # Two layers, and why both exist
//!
//! [`UploadState`] is the *vocabulary*: one variant per member of the `CHECK` constraint on
//! `upload_sessions.state` (`docs/04-DATA-MODEL.md §8`). It has to enumerate every state, including
//! the three this crate must never write, because a row written by another crate still has to
//! decode.
//!
//! [`Phase`] is the *machine*. Each phase is a distinct zero-sized type, a [`Session`] is generic
//! over one, and a transition is a method that consumes the session and returns a
//! [`Transition`] to a different phase. There is no function anywhere that takes a `from` and a
//! `to` and writes whatever it is given, so there is no if-ladder to get wrong and no
//! `state = "AVAILABLE"` to slip past review.
//!
//! [`Session`]: crate::session::Session
//!
//! # The boundary this module exists to make unrepresentable
//!
//! **`CLAUDE.md` rule 9: nothing is `AVAILABLE` before antivirus completes.**
//!
//! `Phase` is sealed, and it is implemented for exactly seven types: [`Created`], [`Uploading`],
//! [`Uploaded`], [`Scanning`], [`Aborted`], [`Expired`] and [`Failed`]. There is deliberately **no
//! `Processing`, `Quarantined` or `Available` phase**. Those three states belong to
//! `enclave-antivirus` and the processing pipeline, which decide them from a scan result this crate
//! never sees.
//!
//! Since every write goes through `UploadRepository::apply`, which takes a `Transition<To: Phase>`
//! and writes `To::STATE`, and since no `Transition` exists whose target is any of those three, an
//! upload session cannot leave this crate in a state that implies content is readable. A future
//! caller cannot skip the scan by passing a flag, because there is no flag: the last thing this
//! crate can produce is [`Scanning`], and the only way past it is a crate that has actually
//! scanned the bytes.
//!
//! There is no `#[non_exhaustive]` escape hatch and no `Phase` implementation a downstream crate
//! can add — the sealing trait is private to this module.

use core::fmt;

use enclave_core::UnknownVariant;

use crate::content::{FailureReason, VerifiedContent};
use crate::session::Session;

/// Generates a closed vocabulary that mirrors a database `CHECK` constraint.
///
/// The same macro `enclave_libraries::model` and `enclave_identity::model` carry: `as_str` and
/// `from_str` come from one list, so a writer and a reader cannot fall out of step.
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
    /// Every value `upload_sessions.state` may hold.
    ///
    /// The vocabulary, not the machine — see the [module documentation](self). Three of these are
    /// written by other crates and only ever *read* here.
    pub enum UploadState {
        /// The session exists and URLs have been issued. No bytes have been reported yet.
        Created => "CREATED",
        /// The client is sending bytes.
        Uploading => "UPLOADING",
        /// Every byte is in the staging object and its size and checksum have been verified.
        Uploaded => "UPLOADED",
        /// Handed to antivirus. **The furthest this crate can advance a session.**
        Scanning => "SCANNING",
        /// Antivirus passed; extraction, preview and indexing are running. Written by the
        /// processing pipeline, never here.
        Processing => "PROCESSING",
        /// Readable. Written by the pipeline once every gate has passed, never here
        /// (`CLAUDE.md` rule 9).
        Available => "AVAILABLE",
        /// Antivirus found something. Written by `enclave-antivirus`, never here.
        Quarantined => "QUARANTINED",
        /// The upload failed in a way that is not the client's to retry in place — a size or
        /// checksum mismatch, or a provider rejection.
        Failed => "FAILED",
        /// The client abandoned the upload and the staged bytes were released.
        Aborted => "ABORTED",
        /// The session passed `expires_at` before completing; the reaper released its bytes.
        Expired => "EXPIRED",
    }
}

impl UploadState {
    /// Whether a session in this state still owns staged bytes that a release must delete.
    ///
    /// `UPLOADED` is included: the bytes are in the store and no version row references them yet,
    /// so an abandoned `UPLOADED` session is exactly the orphan the reaper exists for.
    #[must_use]
    pub const fn holds_staged_bytes(&self) -> bool {
        matches!(self, Self::Created | Self::Uploading | Self::Uploaded)
    }

    /// Whether this crate may still act on a session in this state.
    ///
    /// False for everything from [`UploadState::Scanning`] onward. That is the antivirus boundary
    /// expressed as a predicate, for the callers that need to answer the question at runtime; the
    /// type-level form is [`Phase`].
    #[must_use]
    pub const fn is_resumable(&self) -> bool {
        matches!(self, Self::Created | Self::Uploading)
    }
}

mod sealed {
    /// Private supertrait of [`super::Phase`]. Its privacy is what stops a downstream crate from
    /// adding an eighth phase — in particular one whose `STATE` is `AVAILABLE`.
    pub trait Sealed {}
}

/// One state of the machine, as a type.
///
/// Implemented for exactly seven marker types, all in this module. See the
/// [module documentation](self) for the three states that deliberately have no phase.
pub trait Phase: sealed::Sealed + Copy + Clone + fmt::Debug + Send + Sync + 'static {
    /// The value written to `upload_sessions.state` for a session in this phase.
    const STATE: UploadState;

    /// What a session must carry to *be* in this phase.
    ///
    /// `()` for the phases that need no evidence. [`Uploaded`] and [`Scanning`] carry a
    /// [`VerifiedContent`], which can only be built by comparing the client's declaration against
    /// what the object store observed — so "the bytes were checked" is a fact the type system
    /// holds, not a comment.
    type Evidence: fmt::Debug + Clone + Send + Sync;
}

/// A phase this crate may still advance from: [`Created`] or [`Uploading`].
///
/// The transitions that apply to both — abort, expire, fail — are written once against this bound
/// rather than twice, so the two phases cannot drift apart.
pub trait Live: Phase {}

macro_rules! phase {
    ($(#[$meta:meta])* $name:ident, $state:ident, $evidence:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Phase for $name {
            const STATE: UploadState = UploadState::$state;
            type Evidence = $evidence;
        }
    };
}

phase! {
    /// URLs issued, no bytes reported.
    Created, Created, ()
}

phase! {
    /// The client has begun sending. `bytes_received` is meaningful from here on.
    Uploading, Uploading, ()
}

phase! {
    /// Every byte is staged, and its size and checksum have been checked against the declaration.
    Uploaded, Uploaded, VerifiedContent
}

phase! {
    /// Handed to antivirus.
    ///
    /// **The terminal phase of this crate.** No method on `Session<Scanning>` returns a
    /// `Transition`, so there is no way from here to `PROCESSING` or `AVAILABLE` without a crate
    /// that has read the bytes.
    Scanning, Scanning, VerifiedContent
}

phase! {
    /// The client abandoned the upload.
    Aborted, Aborted, ()
}

phase! {
    /// The session outlived `expires_at`.
    Expired, Expired, ()
}

phase! {
    /// Completion was attempted and refused. The reason is the evidence.
    Failed, Failed, FailureReason
}

impl Live for Created {}
impl Live for Uploading {}

/// A state change that has been decided but not yet written.
///
/// The only value `UploadRepository::apply` accepts, and the only way to build one is a transition
/// method on a [`Session`]. It carries the state it came *from* as well as the state it goes to,
/// because the write is a compare-and-swap: the `UPDATE` matches on the old state, so two
/// concurrent completions of the same session cannot both succeed and the second one is told it
/// lost rather than silently overwriting the first (`docs/03-LLD.md §14`).
#[derive(Debug, Clone)]
#[must_use = "a transition changes nothing until UploadRepository::apply writes it"]
pub struct Transition<To: Phase> {
    from: UploadState,
    session: Session<To>,
}

impl<To: Phase> Transition<To> {
    /// Builds a transition. Crate-private: the public way in is a method on a session.
    pub(crate) const fn new(from: UploadState, session: Session<To>) -> Self {
        Self { from, session }
    }

    /// The state the row must still be in for this write to apply.
    ///
    /// Named `from_state` rather than `from` so that it cannot be mistaken — by a reader or by
    /// `clippy::should_implement_trait` — for a conversion.
    #[must_use]
    pub const fn from_state(&self) -> UploadState {
        self.from
    }

    /// The state the row moves to.
    #[must_use]
    pub const fn to_state(&self) -> UploadState {
        To::STATE
    }

    /// The session as it will be once the write lands.
    #[must_use]
    pub const fn session(&self) -> &Session<To> {
        &self.session
    }

    /// Unwraps the session. Crate-private so that a caller cannot obtain a `Session<Scanning>`
    /// without the write that justifies it.
    pub(crate) fn into_session(self) -> Session<To> {
        self.session
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr as _;

    use super::*;

    /// The vocabulary is a copy of a `CHECK` constraint. Spelled out literally rather than rebuilt
    /// from the variants, so a rename fails here instead of writing values the constraint refuses.
    #[test]
    fn the_vocabulary_matches_the_check_constraint() {
        let rendered: Vec<&str> = UploadState::all().iter().map(UploadState::as_str).collect();
        assert_eq!(
            rendered.join(","),
            "CREATED,UPLOADING,UPLOADED,SCANNING,PROCESSING,AVAILABLE,\
             QUARANTINED,FAILED,ABORTED,EXPIRED"
        );
    }

    #[test]
    fn every_state_round_trips_through_its_stored_form() {
        for state in UploadState::all() {
            assert_eq!(UploadState::from_str(state.as_str()).unwrap(), *state);
        }
        assert!(UploadState::from_str("available").is_err());
        assert!(UploadState::from_str("CLEAN").is_err());
    }

    /// `CLAUDE.md` rule 9, as an assertion rather than a convention.
    ///
    /// Every phase this crate defines maps to a state that is not `AVAILABLE`, not `PROCESSING`
    /// and not `QUARANTINED`. `UploadRepository::apply` writes `To::STATE` and nothing else, so a
    /// phase list that satisfies this is a crate that cannot publish unscanned content.
    ///
    /// Adding a phase means editing this list, which is the point: it is not possible to add one
    /// quietly.
    #[test]
    fn no_phase_in_this_crate_maps_to_a_state_that_implies_scanning_finished() {
        let phases = [
            Created::STATE,
            Uploading::STATE,
            Uploaded::STATE,
            Scanning::STATE,
            Aborted::STATE,
            Expired::STATE,
            Failed::STATE,
        ];

        for state in phases {
            assert!(
                !matches!(
                    state,
                    UploadState::Available | UploadState::Processing | UploadState::Quarantined
                ),
                "{state} is reachable from a phase in this crate; \
                 antivirus decides those three (CLAUDE.md rule 9)"
            );
        }

        // And the vocabulary still carries them, because rows written elsewhere must decode.
        assert!(UploadState::all().contains(&UploadState::Available));
    }

    #[test]
    fn only_the_two_pre_completion_states_are_resumable() {
        for state in UploadState::all() {
            assert_eq!(
                state.is_resumable(),
                matches!(state, UploadState::Created | UploadState::Uploading),
                "{state}"
            );
        }
    }

    #[test]
    fn staged_bytes_are_owned_up_to_and_including_uploaded() {
        assert!(UploadState::Created.holds_staged_bytes());
        assert!(UploadState::Uploading.holds_staged_bytes());
        assert!(UploadState::Uploaded.holds_staged_bytes());
        // Once scanning owns them, releasing them is not this crate's decision.
        assert!(!UploadState::Scanning.holds_staged_bytes());
        assert!(!UploadState::Aborted.holds_staged_bytes());
        assert!(!UploadState::Expired.holds_staged_bytes());
    }
}
