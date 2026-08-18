//! The `AntivirusScanner` trait.
//!
//! Two members, exactly as `docs/06-SECURITY-DLP-ACCESS.md §6.1` states them.

use async_trait::async_trait;
use enclave_storage::ByteStream;

use crate::error::Result;
use crate::model::{EngineInfo, ScanHint, ScanVerdict};

/// Malware scanning for uploaded content.
///
/// Implementations are held behind `Arc` and shared across the process; they must be cheap to
/// clone internally and safe to call concurrently. A scan holds no lock and shares no connection
/// between calls, so the worker's concurrency is bounded by the engine's configuration rather than
/// by this trait.
///
/// # The contract that matters
///
/// **`scan` consumes the stream and returns a verdict about the whole of it.** There is no partial
/// verdict, no "first N bytes look fine", and no way to ask for one. `CLAUDE.md` rule 9 says
/// nothing is `AVAILABLE` before antivirus completes; a header-only scan would satisfy the letter
/// of that while being exactly the shortcut it exists to prevent.
///
/// **Failure to scan is a verdict, not an `Err`.** See [`crate::AntivirusError`] for why, and
/// [`crate::outcome::decide`] for what is then done about it.
///
/// # What this trait deliberately does not have
///
/// No `quarantine`, no `is_readable`, no database handle. A scanner produces a verdict and knows
/// nothing about versions, tenants or read paths — those live in [`crate::outcome`] as a pure
/// function, so the rules in `§6.2` can be tested without an engine, and so a new provider cannot
/// accidentally implement them differently.
#[async_trait]
pub trait AntivirusScanner: Send + Sync {
    /// Scans the whole stream.
    ///
    /// `hint` is advisory. An implementation may use it to choose a strategy or to apply a size
    /// ceiling before opening a connection, but must never let it change a verdict: a client that
    /// declares `text/plain` for a PE binary would otherwise have found the bypass.
    ///
    /// # Errors
    ///
    /// [`crate::AntivirusError::Source`] if the content stream broke before the end. Engine
    /// failures are [`ScanVerdict::Error`], not errors.
    async fn scan(&self, stream: ByteStream, hint: ScanHint) -> Result<ScanVerdict>;

    /// The engine's name and signature generation.
    ///
    /// Called at start-up for the banner, per scan for the columns recorded on the version, and by
    /// the health endpoint. Implementations should make it cheap — clamd's `VERSION` is one
    /// round-trip — but must not cache it forever: the signature generation is the value a rescan
    /// sweep keys on, and a cached one would make the sweep look up to date when it is not.
    ///
    /// # Errors
    ///
    /// [`crate::AntivirusError::Configuration`] when the engine cannot be identified at all.
    async fn engine_info(&self) -> Result<EngineInfo>;
}
