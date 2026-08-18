//! [`ClamavScanner`] — `AntivirusScanner` over clamd's INSTREAM protocol.

use core::time::Duration;

use async_trait::async_trait;
use enclave_config::{AntivirusConfig, AntivirusProvider};
use enclave_storage::ByteStream;
use futures::StreamExt as _;
use tracing::{debug, warn};

use crate::clamav::instream::{Connection, Reply, CHUNK_BYTES};
use crate::error::{AntivirusError, Result};
use crate::limits::ArchiveLimits;
use crate::model::{EngineInfo, ScanHint, ScanVerdict};
use crate::scanner::AntivirusScanner;

/// clamd's default TCP port.
const DEFAULT_PORT: u16 = 3310;

/// Signature-name prefixes that mean "I could not open this", not "this is malware".
///
/// ClamAV reports both through the same `FOUND` reply, and the difference matters a great deal:
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2` sends encrypted archives and depth-limit hits down the
/// *unsupported* path, where tenant policy decides, while a signature match is an unconditional
/// quarantine and a `CRITICAL` incident. Treating an encrypted zip as malware would page the
/// security team every time somebody uploaded a password-protected archive, and a team that is
/// paged for that stops reading the pages.
const UNSCANNABLE_PREFIXES: [&str; 2] = ["Heuristics.Encrypted", "Heuristics.Limits.Exceeded"];

/// How to reach clamd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamavConfig {
    /// `host:port`. Not a secret — `docs/08-BYO-INFRA.md §9` calls the endpoint a host and a port,
    /// and it is the one field in this crate that is not a [`SecretRef`](enclave_config::SecretRef)
    /// because there is nothing to keep.
    pub address: String,
    /// Per-object ceiling on the whole scan, connect included.
    pub timeout: Duration,
    /// Objects larger than this are not sent to the engine at all.
    ///
    /// The check happens against [`ScanHint::declared_size`] before a connection is opened, and
    /// again against the bytes actually seen. The first saves a pointless transfer; the second is
    /// the one that is load-bearing, because the declared size is a client's claim.
    pub max_scan_bytes: u64,
    /// The archive caps, mirrored into `clamd.conf` — see [`ArchiveLimits::clamd_settings`].
    pub archive_limits: ArchiveLimits,
}

impl ClamavConfig {
    /// Reads the settings out of `antivirus:` in the platform configuration.
    ///
    /// # Errors
    ///
    /// [`AntivirusError::Configuration`] when the provider is not `clamav`, or when no endpoint is
    /// configured. Both are refused here, at construction, rather than at the first scan: a
    /// deployment that fails to start is an operator's problem for ten minutes, and a deployment
    /// that holds every upload in `SCANNING` is one nobody diagnoses until the queue is deep.
    pub fn from_config(config: &AntivirusConfig) -> Result<Self> {
        if config.provider != AntivirusProvider::Clamav {
            return Err(AntivirusError::Configuration {
                reason: format!(
                    "antivirus.provider is {:?}, not `clamav`; construct the matching scanner",
                    config.provider
                ),
            });
        }

        let address = config
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
            .ok_or_else(|| AntivirusError::Configuration {
                reason: "antivirus.endpoint is required for the `clamav` provider, as `host:port`"
                    .to_owned(),
            })?;

        // A host with no port is the commonest configuration mistake and produces a connect error
        // that says nothing useful, so complete it here rather than reporting it later.
        let address = if address.rsplit_once(':').is_some_and(|(_, port)| {
            !port.is_empty() && port.chars().all(|character| character.is_ascii_digit())
        }) {
            address.to_owned()
        } else {
            format!("{address}:{DEFAULT_PORT}")
        };

        Ok(Self {
            address,
            timeout: config.timeout.as_duration(),
            max_scan_bytes: config.max_scan_bytes,
            archive_limits: ArchiveLimits::from_config(config),
        })
    }
}

/// Scans content by streaming it to a `clamd` daemon.
///
/// # What this type does not do
///
/// It does not hold a connection. INSTREAM consumes one per scan by design — the daemon reads
/// until the zero-length terminator and then answers — so pooling would buy nothing and would add
/// a class of bug where one scan's tail is read as another's verdict.
///
/// It also does not decompress anything; see [`crate::limits`] for where archive expansion
/// happens and why it is not here.
#[derive(Debug, Clone)]
pub struct ClamavScanner {
    config: ClamavConfig,
}

impl ClamavScanner {
    /// Builds a scanner. Does not connect — see [`ClamavScanner::ping`] for the readiness probe.
    #[must_use]
    pub const fn new(config: ClamavConfig) -> Self {
        Self { config }
    }

    /// The settings in force.
    #[must_use]
    pub const fn config(&self) -> &ClamavConfig {
        &self.config
    }

    /// Round-trips clamd's `PING`.
    ///
    /// For the start-up banner and the health endpoint. Not called before every scan: a scan that
    /// pings first has raced anyway, and the second round trip only widens the window.
    ///
    /// # Errors
    ///
    /// [`AntivirusError::Unreachable`] if clamd does not answer `PONG`.
    pub async fn ping(&self) -> Result<()> {
        let mut connection = Connection::connect(&self.config.address, self.config.timeout)
            .await
            .map_err(|_| AntivirusError::Unreachable)?;
        connection.command("PING").await.map_err(|_| AntivirusError::Unreachable)?;
        let reply = connection
            .read_reply(self.config.timeout)
            .await
            .map_err(|_| AntivirusError::Unreachable)?;

        if reply.trim() == "PONG" {
            Ok(())
        } else {
            Err(AntivirusError::Unreachable)
        }
    }

    /// Turns a clamd reply into a verdict, applying `§6.2`'s split between "malware" and "could
    /// not scan".
    fn verdict_for(reply: &Reply) -> ScanVerdict {
        match reply {
            Reply::Ok => ScanVerdict::Clean,

            Reply::Found { signature } => {
                if UNSCANNABLE_PREFIXES.iter().any(|prefix| signature.starts_with(prefix)) {
                    debug!(
                        signature = %signature,
                        "clamd could not open the content; treating as unsupported"
                    );
                    ScanVerdict::Unsupported
                } else {
                    ScanVerdict::Infected { signature: signature.clone() }
                }
            }

            Reply::Error { text } => {
                // clamd's own size ceiling. A property of the object, so it recurs on every retry
                // — which makes it unsupported rather than an outage, and stops `HOLD` from
                // retrying a too-large object until somebody notices the queue.
                if text.to_ascii_lowercase().contains("size limit exceeded") {
                    debug!("clamd refused the object as larger than its StreamMaxLength");
                    ScanVerdict::Unsupported
                } else {
                    warn!(reply = %text, "clamd reported an error");
                    // Retryable: clamd answers ERROR while reloading its signature database, and
                    // that resolves on its own. Under the default `HOLD` policy a retryable error
                    // holds rather than publishes, so guessing generously here is safe.
                    ScanVerdict::Error { retryable: true }
                }
            }

            Reply::Unrecognized { text } => {
                warn!(reply = %text, "unrecognized reply from the antivirus endpoint");
                // Not retryable: this is a peer that is not clamd, or a protocol change. Retrying
                // will produce the same thing, and `HOLD` will raise an incident for an operator.
                ScanVerdict::Error { retryable: false }
            }
        }
    }

    /// The INSTREAM exchange, without the timeout wrapper.
    async fn scan_inner(&self, mut stream: ByteStream, ceiling: u64) -> Result<ScanVerdict> {
        let mut connection =
            match Connection::connect(&self.config.address, self.config.timeout).await {
                Ok(connection) => connection,
                Err(error) => {
                    warn!(address = %self.config.address, %error, "cannot reach clamd");
                    return Ok(ScanVerdict::Error { retryable: true });
                }
            };

        if let Err(error) = connection.command("INSTREAM").await {
            warn!(%error, "clamd refused the INSTREAM command");
            return Ok(ScanVerdict::Error { retryable: true });
        }

        let mut sent: u64 = 0;
        let mut peer_closed_early = false;

        'outer: while let Some(chunk) = stream.next().await {
            // A read failure is the *caller's* input breaking, not the engine's. It is the one
            // path in this function that is an `Err`: no verdict about content we never saw is
            // honest, including `Clean`.
            let chunk = chunk?;

            sent = sent.saturating_add(chunk.len() as u64);
            if sent > ceiling {
                debug!(ceiling, "object passed the configured scan ceiling mid-stream");
                return Ok(ScanVerdict::Unsupported);
            }

            for piece in chunk.chunks(CHUNK_BYTES) {
                if connection.send_chunk(piece).await.is_err() {
                    // clamd writes its reply and closes when it has decided early — a detection in
                    // the first block, or its own size limit. Stop writing and go read; see the
                    // note in `instream`.
                    peer_closed_early = true;
                    break 'outer;
                }
            }
        }

        if !peer_closed_early {
            if let Err(error) = connection.finish_stream().await {
                debug!(%error, "clamd closed before the stream terminator; reading its reply");
            }
        }

        match connection.read_reply(self.config.timeout).await {
            Ok(line) => {
                let reply = Reply::parse(&line);
                debug!(bytes = sent, ?reply, "clamd verdict");
                Ok(Self::verdict_for(&reply))
            }
            Err(error) => {
                warn!(%error, "no verdict from clamd");
                Ok(ScanVerdict::Error { retryable: true })
            }
        }
    }
}

#[async_trait]
impl AntivirusScanner for ClamavScanner {
    /// # Errors
    ///
    /// [`AntivirusError::Source`] if the content stream broke before the end. Every engine-side
    /// failure is a [`ScanVerdict`], not an error — see [`crate::error`].
    async fn scan(&self, stream: ByteStream, hint: ScanHint) -> Result<ScanVerdict> {
        let ceiling = self.config.max_scan_bytes;

        // Refuse on the declared size before opening a socket. The claim is not trusted — the
        // in-flight check in `scan_inner` is what actually bounds us — but when it is honest this
        // saves streaming gigabytes to a daemon that will refuse them.
        if hint.declared_size.is_some_and(|declared| declared > ceiling) {
            debug!(ceiling, "object declares a size past the scan ceiling; not sent to the engine");
            return Ok(ScanVerdict::Unsupported);
        }

        match tokio::time::timeout(self.config.timeout, self.scan_inner(stream, ceiling)).await {
            Ok(result) => result,
            Err(_) => {
                warn!(timeout = ?self.config.timeout, "the scan timed out");
                // Retryable, and therefore held under the default policy. A timeout is usually a
                // saturated engine, which is the definition of transient.
                Ok(ScanVerdict::Error { retryable: true })
            }
        }
    }

    /// # Errors
    ///
    /// [`AntivirusError::Unreachable`] when clamd does not answer `VERSION`.
    async fn engine_info(&self) -> Result<EngineInfo> {
        let mut connection = Connection::connect(&self.config.address, self.config.timeout)
            .await
            .map_err(|_| AntivirusError::Unreachable)?;
        connection.command("VERSION").await.map_err(|_| AntivirusError::Unreachable)?;
        let reply = connection
            .read_reply(self.config.timeout)
            .await
            .map_err(|_| AntivirusError::Unreachable)?;

        Ok(parse_version(reply.trim()))
    }
}

/// Splits clamd's `VERSION` reply into an engine name and a signature generation.
///
/// The reply is `ClamAV 1.4.1/27621/Thu Aug 14 09:12:33 2025` when a database is loaded, and bare
/// `ClamAV 1.4.1` when one is not. Both are handled, and the absent generation stays `None` rather
/// than becoming an empty string, because `None` is what a rescan sweep needs to see to know it
/// cannot compare generations.
fn parse_version(reply: &str) -> EngineInfo {
    let mut parts = reply.split('/');
    let engine = parts.next().unwrap_or(reply).trim();
    let signature_version =
        parts.next().map(str::trim).filter(|part| !part.is_empty()).map(ToOwned::to_owned);

    EngineInfo {
        engine: if engine.is_empty() { "ClamAV".to_owned() } else { engine.to_owned() },
        signature_version,
        scans_content: true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use enclave_config::HumanDuration;

    use super::*;

    #[test]
    fn a_signature_match_is_infected_and_keeps_the_engine_s_own_name() {
        let verdict = ClamavScanner::verdict_for(&Reply::Found {
            signature: crate::eicar::CLAMAV_SIGNATURE.to_owned(),
        });
        assert_eq!(
            verdict,
            ScanVerdict::Infected { signature: crate::eicar::CLAMAV_SIGNATURE.to_owned() }
        );
    }

    #[test]
    fn an_encrypted_archive_is_unsupported_rather_than_malware() {
        for signature in ["Heuristics.Encrypted.Zip", "Heuristics.Encrypted.PDF"] {
            assert_eq!(
                ClamavScanner::verdict_for(&Reply::Found { signature: signature.to_owned() }),
                ScanVerdict::Unsupported,
                "{signature} is a container we cannot open, not a detection"
            );
        }
    }

    /// The archive caps, end to end on the engine side: clamd hitting `MaxRecursion`, `MaxFiles`
    /// or `MaxFileSize` reports this family, and it has to arrive as `Unsupported` so tenant
    /// policy decides — `BLOCK` by default, and unconditionally at `CONFIDENTIAL` and above.
    #[test]
    fn an_archive_past_the_caps_is_unsupported() {
        for signature in [
            "Heuristics.Limits.Exceeded.MaxFileSize",
            "Heuristics.Limits.Exceeded.MaxFiles",
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ] {
            assert_eq!(
                ClamavScanner::verdict_for(&Reply::Found { signature: signature.to_owned() }),
                ScanVerdict::Unsupported,
                "{signature}"
            );
        }
    }

    #[test]
    fn a_heuristic_that_is_not_a_limit_or_encryption_is_still_a_detection() {
        // `Heuristics.Phishing.Email.SpoofedDomain` is a finding, not an inability to scan.
        assert!(matches!(
            ClamavScanner::verdict_for(&Reply::Found {
                signature: "Heuristics.Phishing.Email.SpoofedDomain".to_owned()
            }),
            ScanVerdict::Infected { .. }
        ));
    }

    #[test]
    fn clamd_s_own_size_ceiling_is_unsupported_not_an_outage() {
        assert_eq!(
            ClamavScanner::verdict_for(&Reply::Error {
                text: "INSTREAM size limit exceeded. ERROR".to_owned()
            }),
            ScanVerdict::Unsupported
        );
    }

    #[test]
    fn an_engine_error_is_retryable_and_an_unrecognized_peer_is_not() {
        assert_eq!(
            ClamavScanner::verdict_for(&Reply::Error { text: "reloading ERROR".to_owned() }),
            ScanVerdict::Error { retryable: true }
        );
        assert_eq!(
            ClamavScanner::verdict_for(&Reply::Unrecognized { text: "220 smtp".to_owned() }),
            ScanVerdict::Error { retryable: false }
        );
    }

    #[test]
    fn version_is_split_into_an_engine_and_a_signature_generation() {
        let info = parse_version("ClamAV 1.4.1/27621/Thu Aug 14 09:12:33 2025");
        assert_eq!(info.engine, "ClamAV 1.4.1");
        assert_eq!(info.signature_version.as_deref(), Some("27621"));
        assert!(info.scans_content);
    }

    #[test]
    fn a_version_without_a_database_reports_no_generation_rather_than_an_empty_one() {
        let info = parse_version("ClamAV 1.4.1");
        assert_eq!(info.engine, "ClamAV 1.4.1");
        assert_eq!(info.signature_version, None);
    }

    fn config(endpoint: Option<&str>) -> AntivirusConfig {
        AntivirusConfig {
            provider: AntivirusProvider::Clamav,
            endpoint: endpoint.map(ToOwned::to_owned),
            timeout: HumanDuration::from_secs(30),
            ..AntivirusConfig::default()
        }
    }

    #[test]
    fn a_missing_endpoint_is_refused_at_construction_not_at_the_first_scan() {
        assert!(matches!(
            ClamavConfig::from_config(&config(None)),
            Err(AntivirusError::Configuration { .. })
        ));
        assert!(matches!(
            ClamavConfig::from_config(&config(Some("  "))),
            Err(AntivirusError::Configuration { .. })
        ));
    }

    #[test]
    fn a_bare_host_gains_clamd_s_default_port() {
        let built = ClamavConfig::from_config(&config(Some("clamd.internal"))).unwrap();
        assert_eq!(built.address, "clamd.internal:3310");
    }

    #[test]
    fn an_explicit_port_is_kept() {
        let built = ClamavConfig::from_config(&config(Some("clamd.internal:3311"))).unwrap();
        assert_eq!(built.address, "clamd.internal:3311");
    }

    #[test]
    fn the_wrong_provider_is_refused_rather_than_scanned_with_the_wrong_client() {
        let mut wrong = config(Some("gateway:1344"));
        wrong.provider = AntivirusProvider::Icap;
        assert!(matches!(
            ClamavConfig::from_config(&wrong),
            Err(AntivirusError::Configuration { .. })
        ));
    }

    #[test]
    fn the_archive_caps_come_from_configuration() {
        let mut settings = config(Some("clamd:3310"));
        settings.archive_depth = 3;
        let built = ClamavConfig::from_config(&settings).unwrap();
        assert_eq!(built.archive_limits.max_depth, 3);
    }
}
