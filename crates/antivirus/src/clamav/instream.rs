//! clamd's wire protocol, the four commands we use, and the reply grammar.
//!
//! # The protocol, in full
//!
//! clamd accepts a command on a TCP or Unix socket in one of three framings. We use `z`: the
//! command is prefixed with `z` and terminated with `NUL`, and clamd's reply is `NUL`-terminated
//! too. The alternative, `n`/newline, is ambiguous the moment a signature name contains a
//! newline — which is not supposed to happen and is exactly the kind of thing to not rely on.
//!
//! `zINSTREAM\0` then switches the connection into a chunked upload:
//!
//! ```text
//! -> "zINSTREAM\0"
//! -> <u32 big-endian length><length bytes>      (repeated)
//! -> <u32 big-endian 0>                         (end of stream)
//! <- "stream: OK\0"
//!    "stream: Eicar-Test-Signature FOUND\0"
//!    "INSTREAM size limit exceeded. ERROR\0"
//! ```
//!
//! # The behaviour that is easy to get wrong
//!
//! When the stream passes clamd's `StreamMaxLength`, clamd **writes its reply and closes the
//! connection while we are still sending**. Our next write fails with `EPIPE` or `ECONNRESET`. The
//! naive client reports a broken pipe and loses the reply that was already sitting in the socket
//! buffer — turning "we know this object is too large to scan" into "the engine is unavailable",
//! which under `HOLD` retries forever. The caller of [`Connection::send_chunk`] therefore treats a
//! write failure as a cue to read, not as a failure.

use core::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::debug;

/// The maximum bytes we put in one INSTREAM chunk.
///
/// clamd's own `StreamMaxLength` bounds the *total*, not the chunk, and its buffer is 128 KiB.
/// 64 KiB keeps us comfortably inside it while making the syscall count reasonable for a
/// multi-gigabyte version.
pub(crate) const CHUNK_BYTES: usize = 64 * 1024;

/// A bound on how much of a reply we will read before giving up.
///
/// clamd's replies are short. A peer that streams megabytes at us instead of a `NUL` is either
/// broken or not clamd, and either way is not something to buffer.
const MAX_REPLY_BYTES: usize = 4 * 1024;

/// What clamd said, parsed but not yet interpreted as policy.
///
/// Interpretation — which `FOUND` names mean [`Unsupported`](crate::ScanVerdict::Unsupported)
/// rather than [`Infected`](crate::ScanVerdict::Infected) — lives in
/// [`crate::clamav::scanner`], because it is a reading of
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2` rather than a fact about the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    /// `… OK`
    Ok,
    /// `… <name> FOUND`
    Found {
        /// The signature name, with the `stream: ` prefix and ` FOUND` suffix removed.
        signature: String,
    },
    /// `… ERROR`
    Error {
        /// The engine's text, for logs and incidents. Never returned to an uploader.
        text: String,
    },
    /// Something that is none of the three. Kept distinct from `Error` so a protocol change shows
    /// up in logs as "unrecognized" rather than as an engine fault we would blame clamd for.
    Unrecognized {
        /// The whole reply line.
        text: String,
    },
}

impl Reply {
    /// Parses one reply line.
    pub(crate) fn parse(line: &str) -> Self {
        let line = line.trim_end_matches(['\0', '\n', '\r']).trim();

        if let Some(rest) = line.strip_suffix(" FOUND") {
            // `stream: Name` for INSTREAM, `/path: Name` for SCAN. Take everything after the last
            // `: ` so both shapes work and a signature containing a colon survives.
            let signature = rest.rsplit_once(": ").map_or(rest, |(_, name)| name).trim();
            return Self::Found { signature: signature.to_owned() };
        }

        if line.ends_with(" OK") || line == "OK" {
            return Self::Ok;
        }

        if line.ends_with("ERROR") {
            return Self::Error { text: line.to_owned() };
        }

        Self::Unrecognized { text: line.to_owned() }
    }
}

/// One clamd connection. Not pooled: a connection is per scan by construction, because INSTREAM
/// consumes it.
#[derive(Debug)]
pub(crate) struct Connection {
    stream: TcpStream,
}

impl Connection {
    /// Opens a connection, failing after `timeout`.
    ///
    /// # Errors
    ///
    /// Any connect failure, including the timeout, as `std::io::Error`.
    pub(crate) async fn connect(address: &str, timeout: Duration) -> std::io::Result<Self> {
        let stream =
            tokio::time::timeout(timeout, TcpStream::connect(address)).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??;

        // clamd replies are small and latency matters more than packet count here; without this a
        // 40-byte command waits on Nagle behind nothing. A platform that will not set it is not a
        // reason to refuse the scan, so the failure is logged rather than propagated.
        if let Err(error) = stream.set_nodelay(true) {
            debug!(%error, "could not disable Nagle on the clamd connection");
        }
        Ok(Self { stream })
    }

    /// Sends a `z`-framed command.
    ///
    /// # Errors
    ///
    /// Any write failure.
    pub(crate) async fn command(&mut self, command: &str) -> std::io::Result<()> {
        let mut framed = Vec::with_capacity(command.len() + 2);
        framed.push(b'z');
        framed.extend_from_slice(command.as_bytes());
        framed.push(0);
        self.stream.write_all(&framed).await?;
        self.stream.flush().await
    }

    /// Sends one INSTREAM chunk.
    ///
    /// # Errors
    ///
    /// Any write failure — which the caller must treat as "read the reply", not as a fault. See
    /// the module documentation.
    pub(crate) async fn send_chunk(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        debug_assert!(!chunk.is_empty(), "a zero-length chunk terminates the stream");
        let length = u32::try_from(chunk.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "chunk too large")
        })?;
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(chunk).await
    }

    /// Sends the zero-length terminator.
    ///
    /// # Errors
    ///
    /// Any write failure.
    pub(crate) async fn finish_stream(&mut self) -> std::io::Result<()> {
        self.stream.write_all(&0_u32.to_be_bytes()).await?;
        self.stream.flush().await
    }

    /// Reads one `NUL`-terminated reply, failing after `timeout`.
    ///
    /// A clean EOF with bytes already buffered is a reply: clamd closes immediately after writing
    /// on some error paths, and discarding those bytes would lose the only explanation we get.
    ///
    /// # Errors
    ///
    /// A read failure, a timeout, or a peer that sent more than [`MAX_REPLY_BYTES`] without a
    /// terminator.
    pub(crate) async fn read_reply(&mut self, timeout: Duration) -> std::io::Result<String> {
        let read = async {
            let mut buffer = Vec::with_capacity(128);
            let mut byte = [0_u8; 1];
            loop {
                match self.stream.read(&mut byte).await? {
                    0 => break,
                    _ if byte[0] == 0 => break,
                    _ => buffer.push(byte[0]),
                }
                if buffer.len() > MAX_REPLY_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "reply exceeded the bound without a terminator",
                    ));
                }
            }
            if buffer.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the engine closed the connection without replying",
                ));
            }
            Ok(String::from_utf8_lossy(&buffer).into_owned())
        };

        tokio::time::timeout(timeout, read)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "reply timed out"))?
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_stream_parses_as_ok() {
        assert_eq!(Reply::parse("stream: OK\0"), Reply::Ok);
        assert_eq!(Reply::parse("stream: OK"), Reply::Ok);
    }

    #[test]
    fn a_detection_yields_the_signature_without_the_framing() {
        assert_eq!(
            Reply::parse("stream: Win.Test.EICAR_HDB-1 FOUND\0"),
            Reply::Found { signature: "Win.Test.EICAR_HDB-1".to_owned() }
        );
    }

    #[test]
    fn a_signature_containing_a_colon_survives_parsing() {
        // Real ClamAV signature names do contain colons in some third-party databases; taking
        // everything after the *last* `: ` is what keeps those intact.
        assert_eq!(
            Reply::parse("stream: Foo:Bar.Baz-1 FOUND"),
            Reply::Found { signature: "Foo:Bar.Baz-1".to_owned() }
        );
    }

    #[test]
    fn the_size_limit_reply_is_an_error_carrying_its_own_explanation() {
        let reply = Reply::parse("INSTREAM size limit exceeded. ERROR\0");
        match reply {
            Reply::Error { text } => assert!(text.contains("size limit exceeded")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn anything_unfamiliar_is_unrecognized_rather_than_blamed_on_the_engine() {
        match Reply::parse("HTTP/1.1 400 Bad Request") {
            Reply::Unrecognized { text } => assert!(text.starts_with("HTTP")),
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn parsing_is_indifferent_to_trailing_framing() {
        assert_eq!(Reply::parse("stream: OK\n\0"), Reply::Ok);
        assert_eq!(Reply::parse("stream: OK\r\n"), Reply::Ok);
    }
}
