//! Hashing a version's bytes on their way past — `ENC-829`.
//!
//! # Why this is a tap and not a read
//!
//! The antivirus pass already streams the whole of every version to the engine, because
//! [`AntivirusScanner::scan`](enclave_antivirus::AntivirusScanner::scan) is a verdict about the
//! whole object and a header-only scan is the shortcut `CLAUDE.md` rule 9 exists to prevent. So the
//! bytes needed to compute a whole-object SHA-256 are already crossing this process. Reading the
//! object a second time to hash it would double the egress bill on a 5 GB version to produce a
//! number that was in hand the first time.
//!
//! [`DigestTap::wrap`] therefore sits *between* the store and the engine. The engine sees an
//! ordinary [`ByteStream`] and cannot behave differently because it is being watched.
//!
//! # The property that makes the result trustworthy, and the one that would not
//!
//! **A digest is only reported when the stream was consumed to its end and delivered exactly the
//! number of bytes the version row claims.** Both halves are load-bearing, and neither is
//! hypothetical:
//!
//! * The scanner is entitled to stop early. `ClamavScanner` returns
//!   [`ScanVerdict::Unsupported`](enclave_antivirus::ScanVerdict::Unsupported) the moment a stream
//!   passes `max_scan_bytes`, and clamd closes the connection when it has decided from the first
//!   block — in both cases the tail is never read. A hasher that reported whatever it happened to
//!   see would produce the SHA-256 of a *prefix*, which matches nothing and would quarantine
//!   perfectly good content as a digest mismatch.
//! * A store can end a stream early without erroring. The byte count is compared against
//!   `file_versions.size_bytes` for that case, so a truncated read is [`Digest::Partial`] rather
//!   than a mismatch blamed on the uploader.
//!
//! The two failures point in opposite directions and this module refuses to guess between them:
//! [`Digest::Partial`] means *"no opinion"*, and the caller leaves the version's digest unconfirmed
//! rather than settling it wrongly in either direction.
//!
//! # Nothing here is content
//!
//! `CLAUDE.md` rule 10. The tap holds a hasher state and a counter; it never retains a chunk, and
//! [`Digest`] carries a hex digest and a byte count. The bytes themselves are borrowed on their way
//! to the engine and dropped.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclave_storage::{ByteStream, StorageError};
use futures::Stream;
use sha2::{Digest as _, Sha256};

/// What the tap can say about the bytes that went past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Digest {
    /// The stream ran to its end and delivered the expected number of bytes.
    ///
    /// The lowercase hex SHA-256 of the whole object, in the spelling
    /// `file_versions.checksum_sha256` uses, so the comparison is a string equality and not a
    /// conversion that could differ in case.
    Whole(String),

    /// The stream did not run out, or delivered a different number of bytes than the row claims.
    ///
    /// **Not a mismatch.** A prefix of an object hashes to something unrelated to the object, so
    /// treating this as a failed comparison would quarantine content on the strength of the
    /// scanner having stopped reading. The caller records nothing and the version's digest stays
    /// unconfirmed.
    Partial {
        /// How many bytes were hashed before the stream stopped being read.
        seen: u64,
        /// How many `file_versions.size_bytes` says there are.
        expected: u64,
    },
}

impl Digest {
    /// The hex digest, if the whole object was hashed.
    #[must_use]
    pub fn whole(&self) -> Option<&str> {
        match self {
            Self::Whole(hex) => Some(hex),
            Self::Partial { .. } => None,
        }
    }
}

/// Hashing state shared between the wrapped stream and whoever reads the result afterwards.
///
/// `std::sync::Mutex` and not tokio's: every critical section is a `Sha256::update` with no `await`
/// inside it, and an async mutex here would add a scheduling point per chunk to a hot loop for no
/// mutual-exclusion benefit.
#[derive(Debug)]
struct TapState {
    hasher: Sha256,
    seen: u64,
    /// Whether the underlying stream signalled end-of-stream. `false` after an error, because an
    /// error is not an end — the object may have more bytes that were never read.
    finished: bool,
}

/// Watches a [`ByteStream`] go past and hashes it.
///
/// Constructed by [`DigestTap::wrap`], which returns the tap and the stream to hand onwards. The
/// tap is read *after* the consumer has finished with the stream — [`DigestTap::finish`] — because
/// until then there is nothing to say.
#[derive(Debug, Clone)]
pub struct DigestTap {
    state: Arc<Mutex<TapState>>,
    expected: u64,
}

impl DigestTap {
    /// Wraps `stream` so that every chunk delivered from it is hashed on its way to the consumer.
    ///
    /// `expected` is `file_versions.size_bytes` — what the row claims the object is. It is not
    /// trusted as a size, only used to decide whether the stream was read to the end.
    #[must_use]
    pub fn wrap(stream: ByteStream, expected: u64) -> (Self, ByteStream) {
        let state =
            Arc::new(Mutex::new(TapState { hasher: Sha256::new(), seen: 0, finished: false }));
        let content_length = stream.content_length();
        let tapped = TappedStream { inner: stream, state: Arc::clone(&state) };
        (Self { state, expected }, ByteStream::new(tapped, content_length))
    }

    /// What the tap saw, once the consumer has let the stream go.
    ///
    /// Answers [`Digest::Partial`] unless the stream both reached its end *and* delivered exactly
    /// `expected` bytes. See the module documentation for why both conditions are needed and why a
    /// short read is not reported as a mismatch.
    ///
    /// A poisoned lock is [`Digest::Partial`] too: the only way to poison it is a panic inside the
    /// hashing path, and a digest assembled around a panic is not evidence.
    #[must_use]
    pub fn finish(&self) -> Digest {
        let Ok(state) = self.state.lock() else {
            return Digest::Partial { seen: 0, expected: self.expected };
        };

        if !state.finished || state.seen != self.expected {
            return Digest::Partial { seen: state.seen, expected: self.expected };
        }

        Digest::Whole(hex(state.hasher.clone().finalize().as_slice()))
    }
}

/// The stream the consumer actually holds.
///
/// A hand-written [`Stream`] rather than a `map` over the inner one, because the fact this needs is
/// *end of stream* — a `None` from `poll_next` — and a combinator that only sees items cannot
/// observe it. That is exactly the distinction between "hashed the whole object" and "hashed as
/// much of it as somebody wanted", so it cannot be inferred.
struct TappedStream {
    inner: ByteStream,
    state: Arc<Mutex<TapState>>,
}

impl Stream for TappedStream {
    type Item = Result<Bytes, StorageError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = Pin::new(&mut self.inner).poll_next(cx);

        match &polled {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Ok(mut state) = self.state.lock() {
                    state.hasher.update(chunk);
                    state.seen = state.seen.saturating_add(chunk.len() as u64);
                }
            }
            Poll::Ready(None) => {
                if let Ok(mut state) = self.state.lock() {
                    state.finished = true;
                }
            }
            // A broken stream leaves `finished` false, so the tap reports `Partial`. The bytes that
            // did arrive are honestly hashed and honestly useless: the object has more.
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }

        polled
    }
}

/// Lowercase hex, built from a nibble table.
///
/// Not `write!`: formatting returns a `Result` that is infallible for a `String`, and the workspace
/// forbids both discarding it and unwrapping it. `crates/uploads`' provider-digest decoder builds
/// its hex the same way for the same reason.
fn hex(bytes: &[u8]) -> String {
    const NIBBLES: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(NIBBLES[usize::from(byte >> 4)]));
        out.push(char::from(NIBBLES[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use futures::StreamExt as _;

    use super::*;

    /// The SHA-256 of the empty string, and of `abc` — the two vectors every implementation is
    /// checked against, so this test is not asserting that our hasher agrees with itself.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /// A stream that delivers `body` in chunks of `chunk`, so the tap is exercised across several
    /// `poll_next` calls rather than one.
    fn chunked(body: &'static [u8], chunk: usize) -> ByteStream {
        let pieces: Vec<Bytes> = body.chunks(chunk).map(Bytes::from_static).collect();
        let length = body.len() as u64;
        ByteStream::new(
            futures::stream::iter(pieces.into_iter().map(Ok::<_, StorageError>)),
            Some(length),
        )
    }

    async fn drain(mut stream: ByteStream) {
        while let Some(chunk) = stream.next().await {
            chunk.expect("the fixture stream does not break");
        }
    }

    #[tokio::test]
    async fn a_stream_read_to_the_end_hashes_to_the_known_vector() {
        let (tap, stream) = DigestTap::wrap(chunked(b"abc", 1), 3);
        drain(stream).await;
        assert_eq!(tap.finish(), Digest::Whole(ABC.to_owned()));
    }

    #[tokio::test]
    async fn an_empty_object_is_a_whole_object() {
        let (tap, stream) = DigestTap::wrap(chunked(b"", 1), 0);
        drain(stream).await;
        assert_eq!(
            tap.finish(),
            Digest::Whole(EMPTY.to_owned()),
            "a zero-byte version has a digest like any other and must not read as unread"
        );
    }

    /// **The case the whole module exists for**: a consumer that stops reading part-way.
    ///
    /// This is what `ClamavScanner` does when a stream passes `max_scan_bytes`, and what clamd
    /// causes when it decides from the first block and closes the connection. Reporting the hash of
    /// what was seen would be the SHA-256 of a prefix — a value that matches nothing and would
    /// quarantine the version as corrupt.
    #[tokio::test]
    async fn a_consumer_that_stops_early_gets_no_digest_rather_than_the_digest_of_a_prefix() {
        let (tap, mut stream) = DigestTap::wrap(chunked(b"abcdef", 1), 6);
        // Two chunks, then drop the stream exactly as a scanner that has decided would.
        stream.next().await.expect("a chunk").expect("no error");
        stream.next().await.expect("a chunk").expect("no error");
        drop(stream);

        assert_eq!(tap.finish(), Digest::Partial { seen: 2, expected: 6 });
        assert_eq!(tap.finish().whole(), None);
    }

    /// A stream that ended cleanly but delivered fewer bytes than the row claims is also no answer.
    ///
    /// Distinct from the test above and both are needed: that one is a consumer stopping, this one
    /// is a *store* stopping, and a tap that checked only `finished` would report a confident hash
    /// of a truncated object — which is a mismatch the uploader would be blamed for.
    #[tokio::test]
    async fn a_stream_that_ends_short_of_the_rows_size_is_no_answer_either() {
        let (tap, stream) = DigestTap::wrap(chunked(b"abc", 1), 9);
        drain(stream).await;
        assert_eq!(tap.finish(), Digest::Partial { seen: 3, expected: 9 });
    }

    /// A stream that breaks leaves the tap with no opinion, not with the hash of the good prefix.
    #[tokio::test]
    async fn a_broken_stream_leaves_no_digest() {
        let broken = ByteStream::new(
            futures::stream::iter(vec![
                Ok(Bytes::from_static(b"ab")),
                Err(StorageError::NotFound { key: "k".to_owned() }),
            ]),
            Some(6),
        );
        let (tap, mut stream) = DigestTap::wrap(broken, 6);
        stream.next().await.expect("a chunk").expect("the first chunk is fine");
        assert!(stream.next().await.expect("an item").is_err(), "the fixture breaks");
        assert_eq!(tap.finish(), Digest::Partial { seen: 2, expected: 6 });
    }

    /// The consumer sees exactly the bytes the store produced, in the same pieces.
    ///
    /// The tap must be invisible: an engine that received different framing because hashing was
    /// switched on would be a second code path with its own bugs, and the one it would have is a
    /// verdict that differs from the unwrapped case.
    #[tokio::test]
    async fn the_tap_changes_nothing_the_consumer_sees() {
        let (_tap, mut stream) = DigestTap::wrap(chunked(b"abcdef", 2), 6);
        let mut pieces = Vec::new();
        while let Some(chunk) = stream.next().await {
            pieces.push(chunk.expect("no error").to_vec());
        }
        assert_eq!(pieces, vec![b"ab".to_vec(), b"cd".to_vec(), b"ef".to_vec()]);
    }

    #[test]
    fn hex_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }
}
