//! ClamAV over `clamd`'s INSTREAM protocol on TCP.
//!
//! `docs/08-BYO-INFRA.md §9` lists the `clamav` provider as "embedded `libclamav` or `clamd` over
//! TCP/socket". This is the `clamd`-over-TCP half, and it is the half that should be used:
//! embedding `libclamav` puts a large C parser for every archive and document format ever devised
//! inside the process that also holds database credentials and signing keys. `clamd` puts the same
//! parsers behind a socket, in a process that can be given no credentials, resource-limited, and
//! restarted when it falls over. The cost is a network hop per object.
//!
//! Unix-socket transport is not implemented. It is a two-line addition to `instream::Connection`
//! whenever a deployment wants the daemon co-located; nothing above that type knows which
//! transport it is on.

mod instream;
mod scanner;

pub use scanner::{ClamavConfig, ClamavScanner};
