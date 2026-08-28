//! `enclave-antivirus` — malware scanning, and the rule that nothing is readable before it runs.
//!
//! Infrastructure provider: the [`AntivirusScanner`] trait plus its implementations, and the one
//! piece of policy that is not engine-specific. See `docs/02-HLD.md §4` for where this crate sits.
//!
//! # The rule this crate exists to make true
//!
//! `CLAUDE.md` rule 9: **nothing is `AVAILABLE` before antivirus completes, and no read path
//! serves `SCANNING` content.** Everything below is arranged so that satisfying it is the path of
//! least resistance rather than a thing to remember.
//!
//! # What is here
//!
//! | Item | What it is |
//! |---|---|
//! | [`AntivirusScanner`] | The two-member trait from `docs/06-SECURITY-DLP-ACCESS.md §6.1`, verbatim |
//! | [`ScanVerdict`] | `Clean`, `Infected`, `Unsupported`, `Error { retryable }` — also verbatim |
//! | [`ClamavScanner`] | `clamd` over INSTREAM on TCP, with a hand-written protocol client |
//! | [`NoScanningPerformed`] | What `antivirus.provider: none` gets, named so it cannot be mistaken |
//! | [`outcome::decide`] | `§6.2`'s rules as one pure function — quarantine, hold, flag, incident |
//! | [`ArchiveLimits`] | The decompression-bomb budget: depth, entries, expanded size, ratio |
//! | [`eicar`] | The standard test signature, assembled at runtime so no scanner eats the checkout |
//!
//! # Four decisions worth knowing before using it
//!
//! ### 1. Failure to scan is a verdict, not an error
//!
//! A refused connection, a timeout and an engine that answers `ERROR` all come back as
//! `Ok(ScanVerdict::Error { retryable })`. They are not `Err`, because `§6.2` attaches a written
//! policy to them — `av.unavailable_policy`, `HOLD` by default — and that policy has to be
//! applied. Routed through the error path, the first handler that maps errors to `500` would drop
//! it, and the version would sit in whatever state it was already in with nobody deciding. The
//! error type is reserved for the caller's own inputs breaking; see [`AntivirusError`].
//!
//! ### 2. The rules live in [`outcome`], not in the scanners
//!
//! A scanner produces a verdict and knows nothing about versions, tenants or read paths.
//! [`outcome::decide`] turns `(verdict, policy, classification)` into a [`ScanOutcome`], which is
//! a pure function — so `docs/12-TESTING.md §4.8` G1 and G6 are table tests that run without an
//! engine, a database or a worker, and a new provider cannot implement the rules differently.
//!
//! ### 3. The uploader cannot be told what matched
//!
//! [`UploaderNotice`] is a closed enumeration with no free text. The signature travels on
//! [`Incident`], which is security-facing. `§6.2` requires this, and a type that cannot hold a
//! string is a better guarantee of it than a review comment. A blocked-because-unscannable upload
//! and an infected one produce the *identical* notice, on the same reasoning as rule 7's
//! `404`-not-`403`: distinguishable refusals are a probe for which containers get through.
//!
//! ### 4. Clean is the only verdict that can publish
//!
//! Under the default policy, [`ScanVerdict::Clean`] is the only input to [`outcome::decide`] that
//! yields [`VersionDisposition::Publish`]. There is exactly one configured exception,
//! `ALLOW_AND_RESCAN`, which an operator chooses in writing and which always carries the
//! unscanned flag and a scheduled rescan.
//!
//! # Wiring
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use enclave_antivirus::{
//!     AntivirusError, AntivirusScanner, ClamavConfig, ClamavScanner, NoScanningPerformed,
//! };
//! use enclave_config::{AntivirusProvider, Config};
//!
//! # fn wire(config: &Config) -> Result<Arc<dyn AntivirusScanner>, AntivirusError> {
//! let scanner: Arc<dyn AntivirusScanner> = match config.antivirus.provider {
//!     AntivirusProvider::Clamav => {
//!         Arc::new(ClamavScanner::new(ClamavConfig::from_config(&config.antivirus)?))
//!     }
//!
//!     // Only when the operator asked for it in writing. `docs/08-BYO-INFRA.md §19` refuses this
//!     // in the `enterprise` profile, and that check lives in `enclave-config`'s validation
//!     // because by the time this line runs the process is already coming up.
//!     AntivirusProvider::None => Arc::new(NoScanningPerformed::new()),
//!
//!     // `icap` and `http` are `docs/08-BYO-INFRA.md §9` providers with no implementation yet.
//!     // They refuse to start rather than falling through to `NoScanningPerformed`: an operator
//!     // who configured a scanning gateway and silently got no scanning is the worst outcome
//!     // available here, and it would look correct in every dashboard.
//!     provider @ (AntivirusProvider::Icap | AntivirusProvider::Http) => {
//!         return Err(AntivirusError::Configuration {
//!             reason: format!("antivirus.provider `{provider:?}` is not implemented yet"),
//!         });
//!     }
//! };
//! # Ok(scanner)
//! # }
//! ```

pub mod clamav;
pub mod disabled;
pub mod eicar;
pub mod error;
pub mod limits;
pub mod model;
pub mod outcome;
pub mod scanner;

pub use clamav::{ClamavConfig, ClamavScanner};
pub use disabled::NoScanningPerformed;
pub use eicar::{eicar_test_file, is_eicar};
pub use error::{AntivirusError, Result};
pub use limits::{ArchiveBudget, ArchiveLimits, LimitExceeded};
pub use model::{EngineInfo, ScanHint, ScanVerdict};
pub use outcome::{
    decide, AvStatus, Incident, IncidentKind, IncidentSeverity, Rescan, ScanOutcome, ScanPolicy,
    UnsupportedPolicy, UploaderNotice, VersionDisposition, CONFIDENTIAL_RANK,
};
pub use scanner::AntivirusScanner;
