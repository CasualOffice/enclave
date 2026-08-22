//! `docs/06-SECURITY-DLP-ACCESS.md §6.2`, as one pure function.
//!
//! # Why the rules are here and not in the scanners
//!
//! Every rule in `§6.2` is a statement about what happens *after* a verdict — quarantine, hold,
//! flag, raise an incident. None of them is engine-specific. Written inside each
//! [`AntivirusScanner`](crate::AntivirusScanner) they would be four copies that drift; written in
//! the ingest worker they would be unreachable from a test without a worker, a database and an
//! engine. As [`decide`], a pure function over `(verdict, policy, classification)`, G1 and G6 from
//! `docs/12-TESTING.md §4.8` are table tests that run in microseconds and cannot be satisfied by
//! accident.
//!
//! # The invariant the tests actually pin
//!
//! **[`ScanVerdict::Clean`] is the only input that can produce a readable version.** Everything
//! else produces [`VersionDisposition::Hold`] or [`VersionDisposition::Quarantine`], regardless of
//! policy — with exactly one configured exception, `ALLOW_AND_RESCAN`, which `§6.2` names and
//! which an operator has to choose in writing. `plans/M1-CONTENT-CORE.md` D13 says availability is
//! a state rather than a flag; this is where the state is chosen.

use enclave_config::UnavailablePolicy;
use enclave_core::{ClassificationRank, ReasonCode};
use serde::{Deserialize, Serialize};

use crate::model::ScanVerdict;

/// The rank of the seeded `CONFIDENTIAL` label (`docs/04-DATA-MODEL.md`, `classifications.rank`
/// — `10, 20, 30, 40, 50`; `docs/05-API.md §…` shows `CONFIDENTIAL` at `30`).
///
/// A default, not a constant of nature: ranks are tenant-defined, and a tenant that renumbers its
/// labels sets [`ScanPolicy::block_unsupported_at_or_above`] to match. It is named here so that
/// "default for `CONFIDENTIAL` and above" in `§6.2` has one interpretation rather than one per
/// call site.
pub const CONFIDENTIAL_RANK: ClassificationRank = ClassificationRank::new(30);

/// What the tenant does with content the engine could not form an opinion about.
///
/// `docs/06-SECURITY-DLP-ACCESS.md §6.2`. Named `Block`/`AllowWithFlag` in the document and
/// spelled the same here so a reader can grep from one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnsupportedPolicy {
    /// Refuse it. The default at `CONFIDENTIAL` and above.
    #[default]
    Block,
    /// Publish it, marked as unscanned, so a later signature update can revisit it.
    AllowWithFlag,
}

/// The two tenant-level knobs `§6.2` defines, resolved for one version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPolicy {
    /// What to do with [`ScanVerdict::Unsupported`].
    pub unsupported: UnsupportedPolicy,
    /// What to do with [`ScanVerdict::Error`] — `av.unavailable_policy`.
    pub unavailable: UnavailablePolicy,
    /// At or above this rank, [`UnsupportedPolicy::Block`] applies whatever `unsupported` says.
    ///
    /// A ceiling rather than a default, so that a tenant which sets `ALLOW_WITH_FLAG` globally
    /// does not thereby publish unscanned confidential content. `§6.2` calls `BLOCK` the default
    /// for `CONFIDENTIAL` and above; a default is something an administrator can turn off by
    /// accident, and this one should take a deliberate act.
    pub block_unsupported_at_or_above: ClassificationRank,
}

impl Default for ScanPolicy {
    /// The safe end of every knob: block what we could not scan, hold what we could not reach.
    fn default() -> Self {
        Self {
            unsupported: UnsupportedPolicy::Block,
            unavailable: UnavailablePolicy::Hold,
            block_unsupported_at_or_above: CONFIDENTIAL_RANK,
        }
    }
}

impl ScanPolicy {
    /// The policy a deployment's `antivirus:` section resolves to.
    ///
    /// One knob comes from configuration and one deliberately does not, and the asymmetry is the
    /// point:
    ///
    /// * [`ScanPolicy::unavailable`] is `av.unavailable_policy`, which `docs/06 §6.2` names as a
    ///   tenant-settable trade — availability against a malware window — and which
    ///   `enclave_config` already parses, defaulting to [`UnavailablePolicy::Hold`].
    /// * [`ScanPolicy::unsupported`] is **always** [`UnsupportedPolicy::Block`], because
    ///   `AntivirusConfig` has no key for it and this function does not invent one. That absence is
    ///   load-bearing rather than an omission: `ALLOW_WITH_FLAG` is the single setting that would
    ///   let content nobody scanned become `AVAILABLE`, and a control expressed as a configuration
    ///   default is a control somebody turns off — the shape `ENC-157` removed from
    ///   `preview.watermark_cache`. In particular it is what stops `antivirus.provider: none`,
    ///   whose scanner answers [`ScanVerdict::Unsupported`] for every object, from becoming a
    ///   deployment-wide bypass of `CLAUDE.md` rule 9.
    ///
    /// A tenant that genuinely needs `ALLOW_WITH_FLAG` therefore needs a change to `docs/06`, a
    /// configuration key and a review — which is the price the setting should cost.
    #[must_use]
    pub const fn from_config(config: &enclave_config::AntivirusConfig) -> Self {
        Self {
            unsupported: UnsupportedPolicy::Block,
            unavailable: config.unavailable_policy,
            block_unsupported_at_or_above: CONFIDENTIAL_RANK,
        }
    }

    /// Whether unsupported content at this rank must be blocked, accounting for the ceiling.
    #[must_use]
    pub fn blocks_unsupported(&self, rank: Option<ClassificationRank>) -> bool {
        if matches!(self.unsupported, UnsupportedPolicy::Block) {
            return true;
        }
        rank.is_some_and(|rank| rank >= self.block_unsupported_at_or_above)
    }
}

/// What the version's lifecycle should do next.
///
/// An instruction rather than a status. The `file_versions.status` vocabulary belongs to
/// `docs/04-DATA-MODEL.md` and to whichever crate owns the state machine; naming the *decision*
/// separately means antivirus does not have to agree with the database about how many states there
/// are, only about what should happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VersionDisposition {
    /// Antivirus is finished and content is clean: the version may proceed towards `AVAILABLE`.
    Publish,
    /// Leave it in `SCANNING`. Not readable, not previewable, not indexed, and it will be tried
    /// again. This is what `HOLD` means (`§6.2`) and what G6 asserts.
    Hold,
    /// Move it to `QUARANTINED`. Every read path is blocked, including preview and search.
    Quarantine,
}

impl VersionDisposition {
    /// Whether a version in this disposition may be served to anyone.
    ///
    /// `plans/M1-CONTENT-CORE.md` D13: read paths filter on state, and exactly one state is
    /// readable. Expressed as a method so the answer is in one place rather than re-derived by
    /// each caller that happens to remember.
    #[must_use]
    pub const fn readable(self) -> bool {
        matches!(self, Self::Publish)
    }
}

/// The value written to `file_versions.av_status`.
///
/// The strings in [`AvStatus::as_str`] are the `CHECK` constraint in `docs/04-DATA-MODEL.md`
/// verbatim. They are declared here because this crate is what produces them; anything else
/// needing the vocabulary should use this type rather than restate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AvStatus {
    /// Not yet scanned, or scanned inconclusively and due to be tried again.
    Pending,
    /// Scanned, nothing found.
    Clean,
    /// A signature matched.
    Infected,
    /// Deliberately not scanned — too large, unsupported container, or no engine configured.
    Skipped,
    /// The engine failed in a way that will not resolve on its own.
    Error,
}

impl AvStatus {
    /// The database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Clean => "CLEAN",
            Self::Infected => "INFECTED",
            Self::Skipped => "SKIPPED",
            Self::Error => "ERROR",
        }
    }
}

/// How severe the incident this scan raises is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentSeverity {
    /// Malware in the tenancy. `§6.2` names this level explicitly and requires security be
    /// notified.
    Critical,
    /// Something an operator must look at, but no malware is known to be present.
    High,
}

/// What the incident is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentKind {
    /// A signature matched.
    MalwareDetected,
    /// Content that could not be scanned was refused.
    UnscannableContentBlocked,
    /// The engine failed in a way retrying will not fix.
    ScannerFailed,
}

/// The incident this scan requires be raised.
///
/// `#[must_use]` on purpose: `§6.2` says `Infected` *raises* a `CRITICAL` incident and notifies
/// security. An incident that the caller received and dropped is a control that silently did not
/// happen, which is the same failure mode `CLAUDE.md` rule 8 makes a compiler diagnostic for
/// obligations.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// How bad.
    pub severity: IncidentSeverity,
    /// What happened.
    pub kind: IncidentKind,
    /// The engine's signature name, when there was one.
    ///
    /// Security-facing only. There is no path from this field to [`ScanOutcome::uploader`],
    /// because that type cannot hold a string.
    pub signature: Option<String>,
    /// Whether the security team is paged rather than merely informed.
    pub notify_security: bool,
}

/// What the uploader is told.
///
/// A closed enumeration with no free text, which is the whole mechanism behind "the uploader is
/// told the upload failed policy — not which signature matched" (`§6.2`). It is not possible to
/// pass a signature through this type; that is a stronger guarantee than a review comment asking
/// people not to.
///
/// Note that a blocked *unsupported* upload and an *infected* one produce the identical notice.
/// That is deliberate and follows the same reasoning as `CLAUDE.md` rule 7's `404`-not-`403`: if
/// the two were distinguishable, an uploader could probe which archives the engine cannot open,
/// which is the first step in choosing a container that gets through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UploaderNotice {
    /// The upload proceeds.
    Accepted,
    /// Still being scanned; the client should poll rather than treat this as failure.
    StillScanning,
    /// Refused. See the type-level note on why this carries nothing.
    RejectedByPolicy,
}

impl UploaderNotice {
    /// The API-edge reason code, if this notice denies the request.
    ///
    /// [`ReasonCode::MalwareDetected`] carries [`enclave_core::Remediation::None`], which is the
    /// correct advice: there is nothing the uploader can do to make this file acceptable.
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Self::Accepted | Self::StillScanning => None,
            Self::RejectedByPolicy => Some(ReasonCode::MalwareDetected),
        }
    }
}

/// When to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Rescan {
    /// Retry with backoff; the failure looked transient.
    Soon,
    /// Do not retry on a timer. Revisit when the signature database updates — `§6.2`'s sweep of
    /// "everything currently flagged `Unsupported`".
    OnSignatureUpdate,
}

/// Everything that follows from one verdict.
///
/// `#[must_use]` for the reason in [`Incident`]'s documentation: this value *is* the set of things
/// that must now happen, and a dropped outcome leaves a version in whatever state it was in.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// What the version lifecycle does next.
    pub disposition: VersionDisposition,
    /// What is written to `file_versions.av_status`.
    pub av_status: AvStatus,
    /// The incident to raise, if any.
    pub incident: Option<Incident>,
    /// When to scan again, if ever.
    pub rescan: Option<Rescan>,
    /// What the uploader sees.
    pub uploader: UploaderNotice,
    /// Whether the version carries a "not scanned" flag once published.
    ///
    /// Only ever `true` alongside [`VersionDisposition::Publish`], and it is what makes
    /// `ALLOW_WITH_FLAG` and `ALLOW_AND_RESCAN` distinguishable from a clean scan afterwards. A
    /// published version with no flag and no `CLEAN` status would be indistinguishable from one
    /// that had been scanned, which is how "we will rescan later" becomes "we forgot".
    pub flagged_unscanned: bool,
}

impl ScanOutcome {
    /// Whether this outcome leaves content anyone can read.
    #[must_use]
    pub const fn readable(&self) -> bool {
        self.disposition.readable()
    }
}

/// Applies `docs/06-SECURITY-DLP-ACCESS.md §6.2` to a verdict.
///
/// `rank` is the version's classification, used only for the unsupported-content ceiling. `None`
/// means unclassified, which is treated as below the ceiling — an unclassified file is not
/// confidential merely because nobody said otherwise, and treating it as such would block every
/// encrypted archive in a tenant that chose `ALLOW_WITH_FLAG`.
///
/// # The three things this function guarantees
///
/// 1. `Infected` quarantines whatever the policy says. `ALLOW_AND_RESCAN` is about outages, not
///    about malware, and reading it as "publish anyway" would be a rule 9 violation with an
///    audit trail saying an administrator asked for it.
/// 2. `Error` under `HOLD` never publishes. That is G6.
/// 3. Nothing but `Clean` produces `AvStatus::Clean`.
pub fn decide(
    verdict: &ScanVerdict,
    policy: ScanPolicy,
    rank: Option<ClassificationRank>,
) -> ScanOutcome {
    match verdict {
        ScanVerdict::Clean => ScanOutcome {
            disposition: VersionDisposition::Publish,
            av_status: AvStatus::Clean,
            incident: None,
            rescan: None,
            uploader: UploaderNotice::Accepted,
            flagged_unscanned: false,
        },

        // Unconditional. There is no policy value that publishes this, and no `rank` that softens
        // it. `§6.2`: quarantined, every read path blocked, `CRITICAL` incident, security notified,
        // and the uploader told only that the upload failed policy.
        ScanVerdict::Infected { signature } => ScanOutcome {
            disposition: VersionDisposition::Quarantine,
            av_status: AvStatus::Infected,
            incident: Some(Incident {
                severity: IncidentSeverity::Critical,
                kind: IncidentKind::MalwareDetected,
                signature: Some(signature.clone()),
                notify_security: true,
            }),
            // Re-scanning a known-infected object buys nothing: the bytes are immutable
            // (`plans/M1-CONTENT-CORE.md` D12), so the answer cannot change in our favour.
            rescan: None,
            uploader: UploaderNotice::RejectedByPolicy,
            flagged_unscanned: false,
        },

        ScanVerdict::Unsupported => {
            if policy.blocks_unsupported(rank) {
                ScanOutcome {
                    disposition: VersionDisposition::Quarantine,
                    av_status: AvStatus::Skipped,
                    incident: Some(Incident {
                        severity: IncidentSeverity::High,
                        kind: IncidentKind::UnscannableContentBlocked,
                        signature: None,
                        notify_security: false,
                    }),
                    // Quarantined rather than failed, and `SKIPPED` rather than `INFECTED`,
                    // precisely so the signature-update sweep in `§6.2` can find it again. A
                    // container this engine cannot open today may be openable after an update.
                    rescan: Some(Rescan::OnSignatureUpdate),
                    uploader: UploaderNotice::RejectedByPolicy,
                    flagged_unscanned: false,
                }
            } else {
                ScanOutcome {
                    disposition: VersionDisposition::Publish,
                    av_status: AvStatus::Skipped,
                    incident: None,
                    rescan: Some(Rescan::OnSignatureUpdate),
                    uploader: UploaderNotice::Accepted,
                    flagged_unscanned: true,
                }
            }
        }

        ScanVerdict::Error { retryable } => match policy.unavailable {
            // G6. The version waits in `SCANNING` and is unreadable, whether or not a retry is
            // expected to help. A non-retryable error additionally raises an incident, because
            // holding forever without telling anyone is an outage nobody is looking at.
            UnavailablePolicy::Hold => ScanOutcome {
                disposition: VersionDisposition::Hold,
                av_status: if *retryable { AvStatus::Pending } else { AvStatus::Error },
                incident: (!*retryable).then_some(Incident {
                    severity: IncidentSeverity::High,
                    kind: IncidentKind::ScannerFailed,
                    signature: None,
                    notify_security: false,
                }),
                rescan: retryable.then_some(Rescan::Soon),
                uploader: UploaderNotice::StillScanning,
                flagged_unscanned: false,
            },

            // The one configured way unscanned content becomes readable. It trades a malware
            // window for availability, `§6.2` requires it be chosen explicitly, and
            // `docs/08-BYO-INFRA.md §9` keeps `HOLD` the default. The flag and the rescan are not
            // optional extras here — they are the entire compensating control.
            UnavailablePolicy::AllowAndRescan => ScanOutcome {
                disposition: VersionDisposition::Publish,
                av_status: AvStatus::Pending,
                incident: None,
                rescan: Some(Rescan::Soon),
                uploader: UploaderNotice::Accepted,
                flagged_unscanned: true,
            },
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn infected() -> ScanVerdict {
        ScanVerdict::Infected { signature: "Eicar-Test-Signature".into() }
    }

    #[test]
    fn clean_is_the_only_verdict_that_can_publish_under_default_policy() {
        let policy = ScanPolicy::default();
        assert!(decide(&ScanVerdict::Clean, policy, None).readable());
        assert!(!decide(&infected(), policy, None).readable());
        assert!(!decide(&ScanVerdict::Unsupported, policy, None).readable());
        assert!(!decide(&ScanVerdict::Error { retryable: true }, policy, None).readable());
        assert!(!decide(&ScanVerdict::Error { retryable: false }, policy, None).readable());
    }

    /// G1, the decision half: a signature match quarantines and is never readable, under every
    /// combination of policy knobs and classification a tenant can set.
    #[test]
    fn infected_quarantines_under_every_policy_combination() {
        for unsupported in [UnsupportedPolicy::Block, UnsupportedPolicy::AllowWithFlag] {
            for unavailable in [UnavailablePolicy::Hold, UnavailablePolicy::AllowAndRescan] {
                for rank in [None, Some(ClassificationRank::new(10)), Some(CONFIDENTIAL_RANK)] {
                    let policy = ScanPolicy {
                        unsupported,
                        unavailable,
                        block_unsupported_at_or_above: CONFIDENTIAL_RANK,
                    };
                    let outcome = decide(&infected(), policy, rank);
                    assert_eq!(
                        outcome.disposition,
                        VersionDisposition::Quarantine,
                        "unsupported={unsupported:?} unavailable={unavailable:?} rank={rank:?}"
                    );
                    assert!(!outcome.readable());
                    assert_eq!(outcome.av_status, AvStatus::Infected);
                }
            }
        }
    }

    #[test]
    fn infected_raises_a_critical_incident_that_notifies_security_and_keeps_the_signature() {
        let outcome = decide(&infected(), ScanPolicy::default(), None);
        let incident = outcome.incident.expect("infected content raises an incident");
        assert_eq!(incident.severity, IncidentSeverity::Critical);
        assert_eq!(incident.kind, IncidentKind::MalwareDetected);
        assert!(incident.notify_security);
        assert_eq!(incident.signature.as_deref(), Some("Eicar-Test-Signature"));
    }

    /// The uploader is told the upload failed policy, not what matched. The type makes carrying a
    /// signature impossible; this pins that the *blocked-unsupported* case is byte-identical to
    /// the infected one, so the two cannot be told apart from the outside.
    #[test]
    fn a_blocked_upload_looks_the_same_to_the_uploader_whatever_caused_it() {
        let policy = ScanPolicy::default();
        let malware = decide(&infected(), policy, None).uploader;
        let unscannable = decide(&ScanVerdict::Unsupported, policy, None).uploader;
        assert_eq!(malware, UploaderNotice::RejectedByPolicy);
        assert_eq!(malware, unscannable);
        assert_eq!(malware.reason_code(), Some(ReasonCode::MalwareDetected));
    }

    #[test]
    fn unsupported_follows_tenant_policy() {
        let block = ScanPolicy { unsupported: UnsupportedPolicy::Block, ..ScanPolicy::default() };
        assert_eq!(
            decide(&ScanVerdict::Unsupported, block, None).disposition,
            VersionDisposition::Quarantine
        );

        let allow =
            ScanPolicy { unsupported: UnsupportedPolicy::AllowWithFlag, ..ScanPolicy::default() };
        let outcome = decide(&ScanVerdict::Unsupported, allow, None);
        assert_eq!(outcome.disposition, VersionDisposition::Publish);
        assert_eq!(outcome.av_status, AvStatus::Skipped);
        assert!(outcome.flagged_unscanned, "published-but-unscanned must be distinguishable");
        assert_eq!(outcome.rescan, Some(Rescan::OnSignatureUpdate));
    }

    #[test]
    fn allow_with_flag_still_blocks_at_confidential_and_above() {
        let allow =
            ScanPolicy { unsupported: UnsupportedPolicy::AllowWithFlag, ..ScanPolicy::default() };

        for rank in [CONFIDENTIAL_RANK, ClassificationRank::new(40), ClassificationRank::new(50)] {
            assert_eq!(
                decide(&ScanVerdict::Unsupported, allow, Some(rank)).disposition,
                VersionDisposition::Quarantine,
                "rank {rank:?} is at or above the ceiling"
            );
        }
        for rank in [ClassificationRank::new(10), ClassificationRank::new(20)] {
            assert_eq!(
                decide(&ScanVerdict::Unsupported, allow, Some(rank)).disposition,
                VersionDisposition::Publish,
                "rank {rank:?} is below the ceiling"
            );
        }
    }

    /// G6: with the engine down and `HOLD`, the version stays in `SCANNING` and unreadable.
    #[test]
    fn an_outage_under_hold_waits_in_scanning_rather_than_becoming_readable() {
        let policy = ScanPolicy { unavailable: UnavailablePolicy::Hold, ..ScanPolicy::default() };

        let transient = decide(&ScanVerdict::Error { retryable: true }, policy, None);
        assert_eq!(transient.disposition, VersionDisposition::Hold);
        assert!(!transient.readable());
        assert_eq!(transient.av_status, AvStatus::Pending);
        assert_eq!(transient.rescan, Some(Rescan::Soon));
        assert_eq!(transient.uploader, UploaderNotice::StillScanning);
        assert!(!transient.flagged_unscanned);

        let permanent = decide(&ScanVerdict::Error { retryable: false }, policy, None);
        assert_eq!(permanent.disposition, VersionDisposition::Hold);
        assert!(!permanent.readable());
        assert_eq!(permanent.av_status, AvStatus::Error);
        assert_eq!(permanent.rescan, None);
        let incident = permanent.incident.expect("a permanent outage must reach an operator");
        assert_eq!(incident.kind, IncidentKind::ScannerFailed);
    }

    #[test]
    fn hold_is_the_default_so_an_unconfigured_tenant_gets_the_safe_behaviour() {
        assert_eq!(ScanPolicy::default().unavailable, UnavailablePolicy::Hold);
        assert_eq!(ScanPolicy::default().unsupported, UnsupportedPolicy::Block);
    }

    #[test]
    fn allow_and_rescan_publishes_only_with_a_flag_and_a_scheduled_rescan() {
        let policy =
            ScanPolicy { unavailable: UnavailablePolicy::AllowAndRescan, ..ScanPolicy::default() };
        let outcome = decide(&ScanVerdict::Error { retryable: true }, policy, None);
        assert_eq!(outcome.disposition, VersionDisposition::Publish);
        assert!(outcome.flagged_unscanned, "the flag is the compensating control, not a detail");
        assert_eq!(outcome.rescan, Some(Rescan::Soon));
        assert_ne!(outcome.av_status, AvStatus::Clean, "nothing but a clean scan is CLEAN");
    }

    #[test]
    fn no_verdict_other_than_clean_ever_records_av_status_clean() {
        for unavailable in [UnavailablePolicy::Hold, UnavailablePolicy::AllowAndRescan] {
            for unsupported in [UnsupportedPolicy::Block, UnsupportedPolicy::AllowWithFlag] {
                let policy = ScanPolicy {
                    unsupported,
                    unavailable,
                    block_unsupported_at_or_above: CONFIDENTIAL_RANK,
                };
                for verdict in [
                    infected(),
                    ScanVerdict::Unsupported,
                    ScanVerdict::Error { retryable: true },
                    ScanVerdict::Error { retryable: false },
                ] {
                    assert_ne!(decide(&verdict, policy, None).av_status, AvStatus::Clean);
                }
            }
        }
    }

    /// No configuration a deployment can write makes unscannable content publishable.
    ///
    /// The one setting that would — `ALLOW_WITH_FLAG` — has no key, and this asserts that the
    /// resolved policy is `BLOCK` for every provider and every unavailable policy a `Config` can
    /// express. Without it, `antivirus.provider: none` plus a future `unsupported_policy` key would
    /// be a rule-9 bypass written entirely in YAML.
    #[test]
    fn no_antivirus_configuration_resolves_to_a_policy_that_publishes_unscanned_content() {
        use enclave_config::{AntivirusConfig, AntivirusProvider};

        for provider in [
            AntivirusProvider::Clamav,
            AntivirusProvider::Icap,
            AntivirusProvider::Http,
            AntivirusProvider::None,
        ] {
            for unavailable in [UnavailablePolicy::Hold, UnavailablePolicy::AllowAndRescan] {
                let config = AntivirusConfig {
                    provider,
                    unavailable_policy: unavailable,
                    ..AntivirusConfig::default()
                };
                let policy = ScanPolicy::from_config(&config);
                assert_eq!(policy.unsupported, UnsupportedPolicy::Block, "{provider:?}");
                assert!(policy.blocks_unsupported(None), "{provider:?}");
                assert!(
                    !decide(&ScanVerdict::Unsupported, policy, None).readable(),
                    "{provider:?}"
                );

                // The positive control, so the three assertions above are not passing against a
                // `from_config` that returns a policy refusing everything: the same policy still
                // publishes a clean scan.
                assert!(decide(&ScanVerdict::Clean, policy, None).readable(), "{provider:?}");
            }
        }
    }

    /// The one knob that *is* configuration reaches the policy.
    ///
    /// Paired with the test above so neither can pass by `from_config` ignoring its argument.
    #[test]
    fn the_unavailable_policy_comes_from_configuration() {
        use enclave_config::AntivirusConfig;

        let hold = AntivirusConfig {
            unavailable_policy: UnavailablePolicy::Hold,
            ..AntivirusConfig::default()
        };
        let allow = AntivirusConfig {
            unavailable_policy: UnavailablePolicy::AllowAndRescan,
            ..AntivirusConfig::default()
        };
        assert_eq!(ScanPolicy::from_config(&hold).unavailable, UnavailablePolicy::Hold);
        assert_eq!(ScanPolicy::from_config(&allow).unavailable, UnavailablePolicy::AllowAndRescan);
        assert!(!decide(
            &ScanVerdict::Error { retryable: true },
            ScanPolicy::from_config(&hold),
            None
        )
        .readable());
    }

    #[test]
    fn av_status_strings_match_the_database_check_constraint() {
        // `docs/04-DATA-MODEL.md`, `file_versions.av_status`:
        // CHECK (av_status IN ('PENDING','CLEAN','INFECTED','SKIPPED','ERROR'))
        assert_eq!(AvStatus::Pending.as_str(), "PENDING");
        assert_eq!(AvStatus::Clean.as_str(), "CLEAN");
        assert_eq!(AvStatus::Infected.as_str(), "INFECTED");
        assert_eq!(AvStatus::Skipped.as_str(), "SKIPPED");
        assert_eq!(AvStatus::Error.as_str(), "ERROR");
    }
}
