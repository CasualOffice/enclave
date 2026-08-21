//! `docs/12-TESTING.md §4.8` G1 against a real ClamAV daemon.
//!
//! Every test here is `#[ignore]`d and runs against the `clamav/clamav` container the CI test job
//! starts — the same arrangement `crates/storage/tests/minio.rs` uses for MinIO, and for the same
//! reason: `.github/workflows/ci.yml` invokes the suite with `--include-ignored`, so these run in
//! CI and are merely skipped on a laptop with no daemon.
//!
//! ```text
//! docker run -d --name enclave-clamav -p 3310:3310 \
//!   -e CLAMAV_NO_FRESHCLAMD=true -e CLAMAV_NO_MILTERD=true clamav/clamav:1.4
//! cargo test -p enclave-antivirus --test eicar -- --include-ignored
//! ```
//!
//! # Why a real engine, given `tests/fake_clamd.rs` exists
//!
//! Because the fake daemon is a statement of what we *believe* clamd does. It was written from the
//! protocol documentation by the same person who wrote the client, so the two agree by
//! construction and would go on agreeing after clamd changed. This file is the only place where
//! that belief meets the software.
//!
//! It is deliberately three tests rather than twenty. `plans/M1-CONTENT-CORE.md §4` lists "ClamAV
//! in CI is slow or flaky" as a risk and mitigates it with "EICAR only" — the failure modes belong
//! in the fake, which can produce them on demand and in milliseconds.

// Assertions are the point of a test; the workspace warns on these constructs elsewhere.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use bytes::Bytes;
use enclave_antivirus::{
    decide, eicar_test_file, AntivirusScanner, ArchiveLimits, AvStatus, ClamavConfig,
    ClamavScanner, IncidentKind, IncidentSeverity, ScanHint, ScanPolicy, ScanVerdict,
    UploaderNotice, VersionDisposition,
};
use enclave_storage::{ByteStream, StorageError};

/// Attached to every `#[ignore]` so the harness is named at the test rather than in a comment
/// somebody has to go looking for.
const NEEDS_CLAMD: &str = "requires a clamd on TEST_CLAMD_ADDR (default 127.0.0.1:3310); \
                           CI starts one and runs this with --include-ignored";

/// Where clamd is. Defaults rather than requiring the variable, so that the CI job needs one new
/// step and no change to the `env:` block it shares with the database and object-storage tests.
///
/// No `ENCLAVE_` prefix: that namespace belongs to `ConfigLoader`, which reads the whole process
/// environment and turns anything in it into a configuration field. This variable was
/// `ENCLAVE_TEST_CLAMD_ADDR` until `ENC-544` renamed the family; `deploy/README.md` states the rule
/// and `crates/config/tests/ambient_environment.rs` enforces it.
const ADDRESS_ENV: &str = "TEST_CLAMD_ADDR";
const DEFAULT_ADDRESS: &str = "127.0.0.1:3310";

/// A scanner pointed at the daemon, having first confirmed it answers.
///
/// The `PING` is not ceremony: without it, a daemon that is still loading its signature database
/// produces `ScanVerdict::Error { retryable: true }`, the outcome is `Hold`, and every assertion
/// below still passes — a green G1 that proved nothing. Failing loudly here is the difference.
async fn scanner() -> ClamavScanner {
    let address = std::env::var(ADDRESS_ENV).unwrap_or_else(|_| DEFAULT_ADDRESS.to_owned());
    let scanner = ClamavScanner::new(ClamavConfig {
        address: address.clone(),
        timeout: Duration::from_secs(60),
        max_scan_bytes: 64 * 1024 * 1024,
        archive_limits: ArchiveLimits::default(),
    });

    scanner
        .ping()
        .await
        .unwrap_or_else(|error| panic!("no clamd at {address} ({error}): {NEEDS_CLAMD}"));

    scanner
}

fn stream_of(bytes: Vec<u8>) -> ByteStream {
    let length = bytes.len() as u64;
    ByteStream::new(
        futures::stream::once(async move { Ok::<_, StorageError>(Bytes::from(bytes)) }),
        Some(length),
    )
}

/// G1: *an EICAR upload is quarantined and never becomes readable, previewable or searchable.*
///
/// The three clauses of the row map onto the three groups of assertions below. "Previewable" and
/// "searchable" are not separate checks because they are not separate mechanisms:
/// `plans/M1-CONTENT-CORE.md` D13 makes every read path filter on the version's state, so
/// `readable() == false` is the property all three inherit. A preview path that could serve this
/// version would have to have taken a boolean parameter, which D13 forbids.
#[tokio::test]
#[ignore = "requires clamd; CI runs it with --include-ignored"]
async fn g1_an_eicar_upload_is_quarantined_and_never_becomes_available() {
    let verdict =
        scanner().await.scan(stream_of(eicar_test_file()), ScanHint::empty()).await.unwrap();

    // 1. A real engine, with a real signature database, identified it.
    let ScanVerdict::Infected { signature } = &verdict else {
        panic!("clamd did not detect EICAR — got {verdict:?}; is a signature database loaded?");
    };
    assert!(
        signature.to_ascii_lowercase().contains("eicar"),
        "expected an EICAR signature name, got {signature}"
    );

    // 2. It never becomes available, and every read path is closed to it.
    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.disposition, VersionDisposition::Quarantine);
    assert!(!outcome.readable(), "no read path — download, preview or search — may serve this");
    assert_eq!(outcome.av_status, AvStatus::Infected);
    assert_ne!(outcome.av_status, AvStatus::Clean);

    // 3. An incident is raised, at CRITICAL, and security is notified.
    let incident = outcome.incident.expect("G1 requires an incident");
    assert_eq!(incident.severity, IncidentSeverity::Critical);
    assert_eq!(incident.kind, IncidentKind::MalwareDetected);
    assert!(incident.notify_security);
    assert_eq!(incident.signature.as_deref(), Some(signature.as_str()));

    // And the uploader learns only that it failed policy.
    assert_eq!(outcome.uploader, UploaderNotice::RejectedByPolicy);
}

/// The control. Without it, a client that failed every scan for an unrelated reason would still
/// pass G1 — an `Infected` verdict is only evidence of detection if `Clean` is reachable.
#[tokio::test]
#[ignore = "requires clamd; CI runs it with --include-ignored"]
async fn ordinary_content_reaches_a_clean_verdict_against_the_same_daemon() {
    let content = b"Q3 revenue was up. Nothing here resembles a signature.".to_vec();
    let verdict = scanner().await.scan(stream_of(content), ScanHint::empty()).await.unwrap();

    assert_eq!(verdict, ScanVerdict::Clean);
    let outcome = decide(&verdict, ScanPolicy::default(), None);
    assert_eq!(outcome.disposition, VersionDisposition::Publish);
    assert!(outcome.readable());
    assert_eq!(outcome.av_status, AvStatus::Clean);
    assert!(!outcome.flagged_unscanned);
}

/// The signature generation has to be real, because it is what the rescan sweep in
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2` keys on. A daemon with no database loaded reports none,
/// and this is where that would be caught.
#[tokio::test]
#[ignore = "requires clamd; CI runs it with --include-ignored"]
async fn engine_info_reports_a_real_engine_and_a_loaded_signature_database() {
    let info = scanner().await.engine_info().await.unwrap();

    assert!(info.engine.to_ascii_lowercase().contains("clamav"), "got {}", info.engine);
    assert!(info.scans_content);
    let generation = info.signature_version.expect("a daemon with no database cannot detect EICAR");
    assert!(
        generation.chars().all(|character| character.is_ascii_digit()),
        "expected a numeric signature generation, got {generation}"
    );
}
