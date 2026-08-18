//! [`ClamavScanner`] against an in-process daemon that speaks clamd's INSTREAM protocol.
//!
//! # Why this exists alongside `tests/eicar.rs`
//!
//! `tests/eicar.rs` runs against a real clamd and is the interop proof, but it needs a container
//! and cannot be made to fail on demand — there is no way to ask a real daemon to hang up
//! mid-stream, or to answer with a heuristic name, or to time out. The failure paths are exactly
//! where `CLAUDE.md` rule 9 is won or lost: an engine that half-answers must not produce a
//! readable version.
//!
//! So the protocol is pinned here against a server we control, with no infrastructure and no
//! `#[ignore]`, and the same client is then checked against the genuine article in CI. Between
//! them: every branch is covered, and clamd protocol drift still shows up.
//!
//! What this file does *not* do is fake the verdict. The fake daemon detects EICAR by comparing
//! the bytes it received, so `an_eicar_upload_is_quarantined_and_never_readable` still proves the
//! bytes travelled correctly end to end.

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclave_antivirus::{
    decide, is_eicar, AntivirusScanner, ArchiveLimits, AvStatus, ClamavConfig, ClamavScanner,
    IncidentKind, IncidentSeverity, ScanHint, ScanPolicy, ScanVerdict, UnsupportedPolicy,
    UploaderNotice, VersionDisposition,
};
use enclave_config::UnavailablePolicy;
use enclave_core::ClassificationRank;
use enclave_storage::{ByteStream, StorageError};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// The fake daemon
// ---------------------------------------------------------------------------

/// How the fake daemon should misbehave, if at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Read the whole stream, then answer honestly about what arrived.
    Honest,
    /// Answer `FOUND` with a fixed signature whatever arrives. For the heuristic names, which we
    /// cannot make a real engine emit on demand.
    AlwaysFound(&'static str),
    /// Write clamd's size-limit error and hang up while the client is still sending.
    RefuseMidStream,
    /// Accept the connection and immediately drop it, saying nothing.
    HangUpSilently,
    /// Accept, read everything, and never reply.
    NeverReply,
    /// Answer something that is not the protocol at all.
    WrongProtocol,
}

/// A listener that serves one connection per accept, on the loopback interface.
struct FakeClamd {
    address: SocketAddr,
    /// What the daemon received on the most recent INSTREAM, for tests that assert the bytes
    /// arrived intact rather than merely that a verdict came back.
    received: Arc<Mutex<Vec<u8>>>,
}

impl FakeClamd {
    async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);

        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    // A connection the client abandoned mid-scan — several tests do exactly that
                    // — leaves this returning `Err`, which is not a test failure.
                    drop(serve(socket, behaviour, sink).await);
                });
            }
        });

        Self { address, received }
    }

    fn config(&self, timeout: Duration) -> ClamavConfig {
        ClamavConfig {
            address: self.address.to_string(),
            timeout,
            max_scan_bytes: 64 * 1024 * 1024,
            archive_limits: ArchiveLimits::default(),
        }
    }

    fn scanner(&self) -> ClamavScanner {
        ClamavScanner::new(self.config(Duration::from_secs(5)))
    }

    fn received(&self) -> Vec<u8> {
        self.received.lock().expect("the fake daemon's sink is never poisoned").clone()
    }
}

/// Reads a `z`-framed command: `z<COMMAND>\0`.
async fn read_command(socket: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if socket.read(&mut byte).await? == 0 {
            break;
        }
        if byte[0] == 0 {
            break;
        }
        buffer.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buffer).trim_start_matches('z').to_owned())
}

async fn serve(
    mut socket: TcpStream,
    behaviour: Behaviour,
    sink: Arc<Mutex<Vec<u8>>>,
) -> std::io::Result<()> {
    if behaviour == Behaviour::HangUpSilently {
        return Ok(());
    }

    let command = read_command(&mut socket).await?;

    if behaviour == Behaviour::WrongProtocol {
        socket.write_all(b"HTTP/1.1 400 Bad Request\0").await?;
        return socket.flush().await;
    }

    match command.as_str() {
        "PING" => {
            socket.write_all(b"PONG\0").await?;
            socket.flush().await
        }
        "VERSION" => {
            socket.write_all(b"ClamAV 1.4.1/27621/Thu Aug 14 09:12:33 2025\0").await?;
            socket.flush().await
        }
        "INSTREAM" => {
            if behaviour == Behaviour::RefuseMidStream {
                // Exactly what clamd does past `StreamMaxLength`: reply, then hang up while the
                // client is still writing.
                socket.write_all(b"INSTREAM size limit exceeded. ERROR\0").await?;
                socket.flush().await?;
                drop(socket);
                return Ok(());
            }

            let mut body = Vec::new();
            loop {
                let mut length = [0_u8; 4];
                if socket.read_exact(&mut length).await.is_err() {
                    break;
                }
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 {
                    break;
                }
                let mut chunk = vec![0_u8; length];
                socket.read_exact(&mut chunk).await?;
                body.extend_from_slice(&chunk);
            }
            *sink.lock().expect("the fake daemon's sink is never poisoned") = body.clone();

            if behaviour == Behaviour::NeverReply {
                // Hold the socket open, saying nothing, until the test drops the runtime.
                tokio::time::sleep(Duration::from_secs(60)).await;
                return Ok(());
            }

            let reply = match behaviour {
                Behaviour::AlwaysFound(signature) => format!("stream: {signature} FOUND\0"),
                // The detection is a real comparison against the bytes that arrived, so a client
                // that mangles the stream fails this test rather than passing it.
                _ if is_eicar(&body) => "stream: Win.Test.EICAR_HDB-1 FOUND\0".to_owned(),
                _ => "stream: OK\0".to_owned(),
            };
            socket.write_all(reply.as_bytes()).await?;
            socket.flush().await
        }
        other => {
            socket.write_all(format!("UNKNOWN COMMAND {other}\0").as_bytes()).await?;
            socket.flush().await
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A single-chunk stream.
fn stream_of(bytes: Vec<u8>) -> ByteStream {
    let length = bytes.len() as u64;
    ByteStream::new(
        futures::stream::once(async move { Ok::<_, StorageError>(Bytes::from(bytes)) }),
        Some(length),
    )
}

/// A stream delivered in many small chunks, so the client's chunking is exercised rather than
/// bypassed by a single `write_all`.
fn chunked_stream(bytes: Vec<u8>, chunk: usize) -> ByteStream {
    let length = bytes.len() as u64;
    let pieces: Vec<Bytes> = bytes.chunks(chunk).map(Bytes::copy_from_slice).collect();
    ByteStream::new(
        futures::stream::iter(pieces.into_iter().map(Ok::<_, StorageError>)),
        Some(length),
    )
}

/// A stream that fails part-way, standing in for object storage dropping a connection.
fn broken_stream() -> ByteStream {
    ByteStream::new(
        futures::stream::iter(vec![
            Ok(Bytes::from_static(b"the first half arrived")),
            Err(StorageError::NotFound { key: "versions/…".to_owned() }),
        ]),
        None,
    )
}

// ---------------------------------------------------------------------------
// G1 — EICAR
// ---------------------------------------------------------------------------

/// `docs/12-TESTING.md §4.8` G1: an EICAR upload is quarantined and never becomes readable.
///
/// Three assertions, because the row says three things: the verdict identifies it, the outcome
/// quarantines it and reports it unreadable, and an incident is raised.
#[tokio::test]
async fn an_eicar_upload_is_quarantined_and_never_readable() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;

    let verdict = clamd
        .scanner()
        .scan(stream_of(enclave_antivirus::eicar_test_file()), ScanHint::empty())
        .await
        .expect("the stream was intact, so this is a verdict rather than an error");

    assert_eq!(
        verdict,
        ScanVerdict::Infected { signature: "Win.Test.EICAR_HDB-1".to_owned() },
        "the bytes must have arrived intact for the daemon to have recognized them"
    );

    let outcome = decide(&verdict, ScanPolicy::default(), None);

    assert_eq!(outcome.disposition, VersionDisposition::Quarantine);
    assert!(!outcome.readable(), "no read path may serve this version");
    assert_eq!(outcome.av_status, AvStatus::Infected);

    let incident = outcome.incident.expect("G1 requires an incident");
    assert_eq!(incident.severity, IncidentSeverity::Critical);
    assert_eq!(incident.kind, IncidentKind::MalwareDetected);
    assert!(incident.notify_security);
    assert_eq!(incident.signature.as_deref(), Some("Win.Test.EICAR_HDB-1"));
}

/// The other half of G1: what the uploader learns. `docs/06-SECURITY-DLP-ACCESS.md §6.2` says the
/// upload failed policy, not which signature matched — and the signature is nowhere in what the
/// uploader receives.
#[tokio::test]
async fn the_uploader_is_told_the_upload_failed_policy_and_nothing_about_the_signature() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let verdict = clamd
        .scanner()
        .scan(stream_of(enclave_antivirus::eicar_test_file()), ScanHint::empty())
        .await
        .unwrap();

    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.uploader, UploaderNotice::RejectedByPolicy);

    // `UploaderNotice` is a fieldless enum, so there is no field a signature could occupy. Its
    // serialized form is the whole of what a client could ever see from it.
    let rendered = serde_json::to_string(&outcome.uploader).unwrap_or_default();
    assert!(!rendered.contains("EICAR"), "rendered as {rendered}");
    assert!(!rendered.contains("Win.Test"), "rendered as {rendered}");
}

/// EICAR arriving in 8-byte pieces still detects. Nothing in the client may depend on the object
/// arriving as one chunk, because object storage does not deliver it that way.
#[tokio::test]
async fn eicar_split_across_many_chunks_is_still_detected() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let verdict = clamd
        .scanner()
        .scan(chunked_stream(enclave_antivirus::eicar_test_file(), 8), ScanHint::empty())
        .await
        .unwrap();

    assert!(matches!(verdict, ScanVerdict::Infected { .. }));
    assert_eq!(clamd.received(), enclave_antivirus::eicar_test_file());
}

/// A payload larger than one INSTREAM chunk arrives byte-for-byte. The client splits at 64 KiB;
/// an off-by-one in the length prefix would show up here and nowhere else.
#[tokio::test]
async fn a_payload_larger_than_one_chunk_arrives_intact() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let payload: Vec<u8> = (0..300_000_u32).map(|index| (index % 251) as u8).collect();

    let verdict =
        clamd.scanner().scan(stream_of(payload.clone()), ScanHint::empty()).await.unwrap();

    assert_eq!(verdict, ScanVerdict::Clean);
    assert_eq!(clamd.received(), payload, "every byte, in order");
}

#[tokio::test]
async fn ordinary_content_is_clean_and_publishable() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let verdict = clamd
        .scanner()
        .scan(stream_of(b"a perfectly ordinary quarterly report".to_vec()), ScanHint::empty())
        .await
        .unwrap();

    assert_eq!(verdict, ScanVerdict::Clean);
    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.disposition, VersionDisposition::Publish);
    assert!(outcome.readable());
    assert_eq!(outcome.av_status, AvStatus::Clean);
    assert!(!outcome.flagged_unscanned);
    assert!(outcome.incident.is_none());
}

// ---------------------------------------------------------------------------
// G6 — the engine is down
// ---------------------------------------------------------------------------

/// `docs/12-TESTING.md §4.8` G6: with the AV engine down and `HOLD`, the version stays in
/// `SCANNING` and unreadable. Nothing is listening on the port at all.
#[tokio::test]
async fn with_no_engine_at_all_and_hold_the_version_waits_in_scanning() {
    // Bind and drop, so the port is one nothing is listening on rather than one we guessed.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);

    let scanner = ClamavScanner::new(ClamavConfig {
        address,
        timeout: Duration::from_millis(500),
        max_scan_bytes: 1024 * 1024,
        archive_limits: ArchiveLimits::default(),
    });

    let verdict = scanner.scan(stream_of(b"content".to_vec()), ScanHint::empty()).await.unwrap();
    assert_eq!(verdict, ScanVerdict::Error { retryable: true });

    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.disposition, VersionDisposition::Hold);
    assert!(!outcome.readable(), "an outage must not make content readable");
    assert_eq!(outcome.av_status, AvStatus::Pending);
    assert_eq!(outcome.uploader, UploaderNotice::StillScanning);
}

/// G6 with the engine present but useless: it accepts the connection and hangs up without a word.
/// The distinction matters because "connection refused" and "connection accepted then closed" take
/// different code paths, and only one of them was obvious.
#[tokio::test]
async fn an_engine_that_hangs_up_without_answering_holds_rather_than_publishes() {
    let clamd = FakeClamd::start(Behaviour::HangUpSilently).await;
    let scanner = ClamavScanner::new(clamd.config(Duration::from_millis(500)));

    let verdict = scanner.scan(stream_of(b"content".to_vec()), ScanHint::empty()).await.unwrap();
    assert_eq!(verdict, ScanVerdict::Error { retryable: true });
    assert!(!decide(&verdict, ScanPolicy::default(), None).readable());
}

/// G6 with a hung engine. The timeout is the scanner's, not the test harness's — an engine that
/// never answers must not hold a worker thread until something else notices.
#[tokio::test]
async fn an_engine_that_never_answers_times_out_and_holds() {
    let clamd = FakeClamd::start(Behaviour::NeverReply).await;
    let scanner = ClamavScanner::new(clamd.config(Duration::from_millis(300)));

    let started = std::time::Instant::now();
    let verdict = scanner.scan(stream_of(b"content".to_vec()), ScanHint::empty()).await.unwrap();

    assert_eq!(verdict, ScanVerdict::Error { retryable: true });
    assert!(started.elapsed() < Duration::from_secs(5), "the configured timeout must bound this");
    assert!(!decide(&verdict, ScanPolicy::default(), None).readable());
}

/// A peer that is not clamd — someone has pointed `antivirus.endpoint` at an HTTP service. Not
/// retryable, because retrying produces the same thing, and under `HOLD` that raises an incident
/// so an operator finds out rather than watching a queue grow.
#[tokio::test]
async fn a_peer_that_is_not_clamd_is_a_permanent_error_that_reaches_an_operator() {
    let clamd = FakeClamd::start(Behaviour::WrongProtocol).await;
    let verdict =
        clamd.scanner().scan(stream_of(b"content".to_vec()), ScanHint::empty()).await.unwrap();

    assert_eq!(verdict, ScanVerdict::Error { retryable: false });

    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.disposition, VersionDisposition::Hold);
    assert_eq!(outcome.av_status, AvStatus::Error);
    assert_eq!(
        outcome.incident.expect("a permanent outage must be visible").kind,
        IncidentKind::ScannerFailed
    );
}

/// The one configured way an outage publishes. It is `ALLOW_AND_RESCAN`, it is not the default,
/// and it still flags and schedules — `docs/06-SECURITY-DLP-ACCESS.md §6.2`.
#[tokio::test]
async fn allow_and_rescan_is_the_only_configuration_where_an_outage_publishes() {
    let clamd = FakeClamd::start(Behaviour::HangUpSilently).await;
    let scanner = ClamavScanner::new(clamd.config(Duration::from_millis(500)));
    let verdict = scanner.scan(stream_of(b"content".to_vec()), ScanHint::empty()).await.unwrap();

    let policy =
        ScanPolicy { unavailable: UnavailablePolicy::AllowAndRescan, ..ScanPolicy::default() };
    let outcome = decide(&verdict, policy, None);

    assert_eq!(outcome.disposition, VersionDisposition::Publish);
    assert!(outcome.flagged_unscanned);
    assert_ne!(outcome.av_status, AvStatus::Clean);
}

// ---------------------------------------------------------------------------
// Unsupported content and the archive caps
// ---------------------------------------------------------------------------

/// An encrypted archive. clamd reports it through the same `FOUND` reply a detection uses, and it
/// must not become a `CRITICAL` malware incident.
#[tokio::test]
async fn an_encrypted_archive_follows_tenant_policy_rather_than_paging_security() {
    let clamd = FakeClamd::start(Behaviour::AlwaysFound("Heuristics.Encrypted.Zip")).await;
    let verdict = clamd
        .scanner()
        .scan(stream_of(b"PK\x03\x04 encrypted".to_vec()), ScanHint::empty())
        .await
        .unwrap();

    assert_eq!(verdict, ScanVerdict::Unsupported);

    let blocked = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(blocked.disposition, VersionDisposition::Quarantine);
    assert_eq!(
        blocked.incident.expect("blocking is still worth recording").severity,
        IncidentSeverity::High,
        "unscannable is not malware; a CRITICAL here would train the security team to ignore them"
    );

    let allowed = decide(
        &verdict,
        ScanPolicy { unsupported: UnsupportedPolicy::AllowWithFlag, ..ScanPolicy::default() },
        None,
    );
    assert_eq!(allowed.disposition, VersionDisposition::Publish);
    assert!(allowed.flagged_unscanned);
}

/// G2's engine-side half: clamd hitting its recursion cap reports
/// `Heuristics.Limits.Exceeded.MaxRecursion`, and that has to arrive as unsupported so the tenant
/// policy — `BLOCK` by default — decides. The budget arithmetic is unit-tested in `limits`.
#[tokio::test]
async fn an_archive_past_the_depth_cap_is_blocked_by_default() {
    let clamd =
        FakeClamd::start(Behaviour::AlwaysFound("Heuristics.Limits.Exceeded.MaxRecursion")).await;
    let verdict = clamd
        .scanner()
        .scan(stream_of(b"PK\x03\x04 nested".to_vec()), ScanHint::empty())
        .await
        .unwrap();

    assert_eq!(verdict, ScanVerdict::Unsupported);
    assert_eq!(
        decide(&verdict, ScanPolicy::default(), None).disposition,
        VersionDisposition::Quarantine
    );
}

/// Unscannable content is refused at `CONFIDENTIAL` and above whatever the tenant asked for.
#[tokio::test]
async fn unscannable_confidential_content_is_blocked_even_under_allow_with_flag() {
    let clamd = FakeClamd::start(Behaviour::AlwaysFound("Heuristics.Encrypted.Zip")).await;
    let verdict =
        clamd.scanner().scan(stream_of(b"PK\x03\x04".to_vec()), ScanHint::empty()).await.unwrap();

    let policy =
        ScanPolicy { unsupported: UnsupportedPolicy::AllowWithFlag, ..ScanPolicy::default() };
    let outcome = decide(&verdict, policy, Some(ClassificationRank::new(30)));

    assert_eq!(outcome.disposition, VersionDisposition::Quarantine);
    assert!(!outcome.readable());
}

/// clamd deciding mid-stream and hanging up. The naive client reports a broken pipe and loses the
/// reply already sitting in the socket; this asserts the reply wins.
#[tokio::test]
async fn a_daemon_that_replies_and_hangs_up_mid_stream_still_yields_its_verdict() {
    let clamd = FakeClamd::start(Behaviour::RefuseMidStream).await;
    let scanner = ClamavScanner::new(clamd.config(Duration::from_secs(5)));

    // Large enough that the client is still writing when the socket closes.
    let verdict = scanner
        .scan(chunked_stream(vec![0_u8; 8 * 1024 * 1024], 64 * 1024), ScanHint::empty())
        .await
        .unwrap();

    assert_eq!(
        verdict,
        ScanVerdict::Unsupported,
        "clamd's own size ceiling is a property of the object, not an outage"
    );
    assert_ne!(
        verdict,
        ScanVerdict::Error { retryable: true },
        "reporting this as retryable would retry a too-large object forever"
    );
}

/// The size ceiling, applied to the declared size before a socket is opened. Cheap, and not
/// trusted — the in-flight check below is the one that binds.
#[tokio::test]
async fn an_object_declaring_more_than_the_ceiling_is_not_sent_to_the_engine() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let scanner = ClamavScanner::new(ClamavConfig {
        max_scan_bytes: 1024,
        ..clamd.config(Duration::from_secs(5))
    });

    let verdict = scanner
        .scan(stream_of(b"small".to_vec()), ScanHint::empty().with_size(64 * 1024))
        .await
        .unwrap();

    assert_eq!(verdict, ScanVerdict::Unsupported);
    assert!(clamd.received().is_empty(), "no connection should have been made");
}

/// A client that lies about the size does not get past the ceiling. The declared size is a claim;
/// the bytes are the fact.
#[tokio::test]
async fn a_lied_about_size_is_still_caught_in_flight() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let scanner = ClamavScanner::new(ClamavConfig {
        max_scan_bytes: 1024,
        ..clamd.config(Duration::from_secs(5))
    });

    // Declares 10 bytes, sends 8 KiB.
    let verdict = scanner
        .scan(chunked_stream(vec![7_u8; 8 * 1024], 512), ScanHint::empty().with_size(10))
        .await
        .unwrap();

    assert_eq!(verdict, ScanVerdict::Unsupported);
    assert_ne!(verdict, ScanVerdict::Clean, "a lie must not buy a clean verdict");
}

// ---------------------------------------------------------------------------
// The error path proper
// ---------------------------------------------------------------------------

/// A broken content stream is the one thing that is an `Err`. No verdict about bytes we never saw
/// is honest — least of all `Clean`.
#[tokio::test]
async fn a_broken_content_stream_is_an_error_and_never_a_verdict() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let result = clamd.scanner().scan(broken_stream(), ScanHint::empty()).await;

    let error = result.expect_err("a truncated read cannot produce a verdict");
    assert!(matches!(error, enclave_antivirus::AntivirusError::Source(_)));
}

// ---------------------------------------------------------------------------
// engine_info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn engine_info_reports_the_engine_and_its_signature_generation() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    let info = clamd.scanner().engine_info().await.unwrap();

    assert_eq!(info.engine, "ClamAV 1.4.1");
    assert_eq!(info.signature_version.as_deref(), Some("27621"));
    assert!(info.scans_content, "a real engine must be distinguishable from the disabled one");
}

#[tokio::test]
async fn engine_info_fails_rather_than_inventing_a_version_when_the_engine_is_gone() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);

    let scanner = ClamavScanner::new(ClamavConfig {
        address,
        timeout: Duration::from_millis(500),
        max_scan_bytes: 1024,
        archive_limits: ArchiveLimits::default(),
    });

    assert!(matches!(
        scanner.engine_info().await,
        Err(enclave_antivirus::AntivirusError::Unreachable)
    ));
}

#[tokio::test]
async fn ping_round_trips() {
    let clamd = FakeClamd::start(Behaviour::Honest).await;
    clamd.scanner().ping().await.expect("PONG");
}
