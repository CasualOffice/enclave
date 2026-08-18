//! The startup self-check: *is the configured bucket readable by the public?*
//!
//! `docs/08-BYO-INFRA.md §3` lists "a bucket that is **not** publicly readable, verified by a
//! startup self-check" as a requirement for any provider used in production, and `§19` makes the
//! `enterprise` deployment profile refuse to start when the check fails.
//!
//! # Why this is the most important code in the crate
//!
//! Every other read control in the platform — the policy chain, preview-versus-download
//! separation, watermarking, short-TTL signed URLs, `av_status = 'CLEAN'` — assumes that the only
//! way to reach an object's bytes is through a URL this process minted. A bucket with a public
//! read policy removes that assumption in one line of someone else's Terraform, and nothing in the
//! application will ever notice: uploads work, downloads work, audit rows are written, and the
//! content is simultaneously on the open internet under a guessable key. It is the single most
//! common way object storage leaks, and it fails *silently*, which is why it has to be checked at
//! startup rather than reasoned about at review time.
//!
//! # Why it is a supertrait of `BlobStore`
//!
//! `docs/08-BYO-INFRA.md §2` states the `BlobStore` trait with seven members and no self-check.
//! Those seven appear here verbatim; the check is added as a **supertrait**
//! ([`PublicAccessCheck`]) rather than as an eighth method, for two reasons:
//!
//! 1. It stays reachable through `&dyn BlobStore`, so the composition root can hold one object and
//!    still be required to ask the question.
//! 2. It makes the question unavoidable for every future provider — local filesystem, Azure Blob,
//!    GCS. A provider cannot be registered without answering it, and "we did not implement the
//!    check for this backend yet" is a compile error rather than an omission.
//!
//! # Two kinds of evidence, and why both are needed
//!
//! *Authenticated* probes (bucket policy, ACL, public-access block) say precisely what is wrong and
//! therefore what to change — but `docs/08-BYO-INFRA.md §5` scopes storage credentials to
//! `GetObject`/`PutObject`/`DeleteObject`/`AbortMultipartUpload`/`ListBucket`, so on a correctly
//! least-privileged credential every one of them returns `AccessDenied`. A check that only did
//! this would be inconclusive exactly when the deployment is configured properly.
//!
//! The *unauthenticated* probe needs no permissions at all: it is an ordinary unsigned HTTP GET,
//! the same request an attacker makes. It works on AWS, on MinIO, and on anything else speaking
//! the S3 API, and it is the probe that actually answers the question that matters. The
//! authenticated probes are kept because when they do run they turn "this bucket is public" into
//! "this bucket is public *because of this statement in its policy*".
//!
//! An inconclusive result — every probe denied or unreachable — is a **failure**, not a pass. The
//! unauthenticated probe requires nothing, so the only way for it to be inconclusive is that the
//! endpoint could not be reached, and a store that cannot be reached at startup is not a store the
//! process should start against.

use core::fmt;

use async_trait::async_trait;

/// Answers "is this bucket publicly readable?".
///
/// A supertrait of [`BlobStore`](crate::BlobStore) — see the [module documentation](self) for why.
#[async_trait]
pub trait PublicAccessCheck: Send + Sync {
    /// Runs every probe the backend supports and rules on the result.
    ///
    /// Implementations must run *all* probes rather than returning on the first `Private` verdict:
    /// the report is an operator-facing artifact, and "the ACL is clean" is a misleading thing to
    /// print when the bucket policy is not.
    ///
    /// # Errors
    ///
    /// [`PublicAccessError::Exposed`] when any probe proves public reachability, and
    /// [`PublicAccessError::Inconclusive`] when none could rule either way. Both must abort
    /// startup; see the [module documentation](self) for why the inconclusive case is not a pass.
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError>;
}

/// Which question a single probe asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Probe {
    /// `GetPublicAccessBlock` — the AWS account/bucket-level switch that overrides everything else.
    PublicAccessBlock,
    /// `GetBucketPolicyStatus` — AWS's own verdict on whether the policy makes the bucket public.
    BucketPolicyStatus,
    /// `GetBucketPolicy`, parsed for `Allow` statements granting a wildcard principal.
    BucketPolicy,
    /// `GetBucketAcl`, checked for the `AllUsers` and `AuthenticatedUsers` grantee groups.
    BucketAcl,
    /// An unsigned `GET` of a key that does not exist. `403` means anonymous reads are refused;
    /// anything else means the request was authorized without a credential.
    AnonymousRead,
    /// An unsigned `ListObjectsV2`. A `200` means the bucket's contents can be enumerated by
    /// anyone, which is how guessable-key arguments stop being relevant.
    AnonymousList,
}

impl Probe {
    /// A short label for logs and the operator-facing report.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PublicAccessBlock => "public-access-block",
            Self::BucketPolicyStatus => "bucket-policy-status",
            Self::BucketPolicy => "bucket-policy",
            Self::BucketAcl => "bucket-acl",
            Self::AnonymousRead => "anonymous-read",
            Self::AnonymousList => "anonymous-list",
        }
    }
}

impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one probe concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// This probe proves the bucket is not publicly readable by the route it examined.
    Private,
    /// This probe proves the bucket *is* publicly reachable. Startup must not continue.
    Public,
    /// The probe could not rule — usually `AccessDenied` on a least-privileged credential, or a
    /// backend that does not implement the API. Carries no weight in either direction.
    Inconclusive,
}

/// One probe's result, with the sentence an operator needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// Which probe ran.
    pub probe: Probe,
    /// What it concluded.
    pub verdict: Verdict,
    /// Operator-facing detail: the offending policy statement, the HTTP status, or the reason the
    /// probe could not run. Never contains a credential — the probes are either unauthenticated or
    /// read metadata only.
    pub detail: String,
}

impl fmt::Display for ProbeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {:?}: {}", self.probe, self.verdict, self.detail)
    }
}

/// The full outcome of a passing self-check.
///
/// Worth logging at startup even on success: it records *which* probes could run, so an operator
/// reading the log later can tell "verified by an unsigned request" apart from "verified by
/// reading the bucket policy", and can see that a credential broad enough to read the policy is in
/// use when the least-privilege policy says it should not be.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct PublicAccessReport {
    /// The bucket that was checked.
    pub bucket: String,
    /// The endpoint it was checked at, when one is configured (MinIO, Ceph, R2). `None` means the
    /// provider's default AWS endpoint.
    pub endpoint: Option<String>,
    /// Every probe that ran, in the order it ran.
    pub probes: Vec<ProbeResult>,
}

impl PublicAccessReport {
    /// The probes that returned a definite verdict, for the startup log line.
    #[must_use]
    pub fn conclusive(&self) -> Vec<&ProbeResult> {
        self.probes.iter().filter(|p| p.verdict != Verdict::Inconclusive).collect()
    }
}

impl fmt::Display for PublicAccessReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bucket `{}`", self.bucket)?;
        if let Some(endpoint) = &self.endpoint {
            write!(f, " at {endpoint}")?;
        }
        write!(f, " is not publicly readable")?;
        for probe in &self.probes {
            write!(f, "; {probe}")?;
        }
        Ok(())
    }
}

/// A refusal to start.
///
/// `Display` is deliberately long and deliberately imperative. This message is read once, by
/// somebody whose deployment has just refused to boot, and it has to answer "which bucket" and
/// "what do I change" without a documentation lookup — the alternative is that they reach for the
/// configuration flag that turns the check off.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PublicAccessError {
    /// At least one probe proved the bucket is publicly reachable.
    Exposed {
        /// The bucket. Named in the message because a deployment has several.
        bucket: String,
        /// The endpoint, when not the provider default.
        endpoint: Option<String>,
        /// Every probe, so the passing ones are visible too and the report is not misread as "only
        /// this one thing was checked".
        probes: Vec<ProbeResult>,
    },

    /// No probe could rule either way.
    Inconclusive {
        /// The bucket.
        bucket: String,
        /// The endpoint, when not the provider default.
        endpoint: Option<String>,
        /// Every probe and why each could not conclude.
        probes: Vec<ProbeResult>,
    },
}

impl fmt::Display for PublicAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exposed { bucket, endpoint, probes } => {
                writeln!(f, "REFUSING TO START: object storage bucket `{bucket}`")?;
                if let Some(endpoint) = endpoint {
                    writeln!(f, "  endpoint: {endpoint}")?;
                }
                writeln!(f, "  is PUBLICLY READABLE.")?;
                writeln!(f)?;
                writeln!(
                    f,
                    "  Every access control in Enclave — the policy chain, preview-vs-download \
                     separation,\n  watermarking, short-lived signed URLs, and the rule that \
                     nothing is served before\n  antivirus completes — assumes object bytes are \
                     reachable only through a URL this\n  process minted. A public bucket makes \
                     all of it decorative."
                )?;
                writeln!(f)?;
                writeln!(f, "  Evidence:")?;
                for probe in probes.iter().filter(|p| p.verdict == Verdict::Public) {
                    writeln!(f, "    [PUBLIC] {} — {}", probe.probe, probe.detail)?;
                }
                for probe in probes.iter().filter(|p| p.verdict != Verdict::Public) {
                    writeln!(f, "    [{:?}] {} — {}", probe.verdict, probe.probe, probe.detail)?;
                }
                writeln!(f)?;
                writeln!(f, "  Fix, then restart:")?;
                writeln!(
                    f,
                    "    AWS   — enable S3 Block Public Access on bucket `{bucket}` \
                     (all four settings),\n            remove any bucket-policy statement with \
                     \"Principal\": \"*\", and remove the\n            AllUsers / \
                     AuthenticatedUsers ACL grants."
                )?;
                writeln!(
                    f,
                    "    MinIO — `mc anonymous set none <alias>/{bucket}` \
                     (or delete the bucket policy)."
                )?;
                write!(
                    f,
                    "  Enclave signs its own download URLs; no client ever needs anonymous read \
                     on this bucket."
                )
            }
            Self::Inconclusive { bucket, endpoint, probes } => {
                writeln!(
                    f,
                    "REFUSING TO START: could not verify that object storage bucket `{bucket}` \
                     is private."
                )?;
                if let Some(endpoint) = endpoint {
                    writeln!(f, "  endpoint: {endpoint}")?;
                }
                writeln!(f)?;
                writeln!(
                    f,
                    "  No probe reached a conclusion. The unauthenticated probe needs no \
                     permissions at all,\n  so this almost always means the endpoint is \
                     unreachable from this process — a wrong\n  endpoint URL, a firewall, or a \
                     TLS failure — rather than a permissions problem."
                )?;
                writeln!(f)?;
                writeln!(f, "  What was tried:")?;
                for probe in probes {
                    writeln!(f, "    [{:?}] {} — {}", probe.verdict, probe.probe, probe.detail)?;
                }
                write!(
                    f,
                    "  This is treated as a failure, not a pass: an unverified bucket is \
                     indistinguishable\n  from a public one, and the difference is every file in \
                     the tenant."
                )
            }
        }
    }
}

/// Accumulates probe results and applies the ruling.
///
/// The ruling lives here, once, rather than in each provider: "any `Public` fails; no `Private`
/// also fails" is the security decision, and a provider should not be able to get it subtly wrong
/// by writing its own `if`.
#[derive(Debug, Clone)]
pub(crate) struct ReportBuilder {
    bucket: String,
    endpoint: Option<String>,
    probes: Vec<ProbeResult>,
}

impl ReportBuilder {
    pub(crate) fn new(bucket: impl Into<String>, endpoint: Option<String>) -> Self {
        Self { bucket: bucket.into(), endpoint, probes: Vec::new() }
    }

    pub(crate) fn record(&mut self, probe: Probe, verdict: Verdict, detail: impl Into<String>) {
        self.probes.push(ProbeResult { probe, verdict, detail: detail.into() });
    }

    /// Applies the ruling: any `Public` fails, and no `Private` at all also fails.
    pub(crate) fn finish(self) -> Result<PublicAccessReport, PublicAccessError> {
        let Self { bucket, endpoint, probes } = self;

        if probes.iter().any(|p| p.verdict == Verdict::Public) {
            return Err(PublicAccessError::Exposed { bucket, endpoint, probes });
        }
        if !probes.iter().any(|p| p.verdict == Verdict::Private) {
            return Err(PublicAccessError::Inconclusive { bucket, endpoint, probes });
        }
        Ok(PublicAccessReport { bucket, endpoint, probes })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn builder() -> ReportBuilder {
        ReportBuilder::new("enclave-content", Some("http://localhost:9000".to_owned()))
    }

    #[test]
    fn one_public_probe_fails_even_when_others_pass() {
        let mut b = builder();
        b.record(Probe::BucketAcl, Verdict::Private, "no AllUsers grant");
        b.record(Probe::AnonymousRead, Verdict::Public, "unsigned GET returned 404, not 403");
        let err = b.finish().unwrap_err();
        assert!(matches!(err, PublicAccessError::Exposed { .. }), "got: {err:?}");
    }

    #[test]
    fn no_conclusive_probe_is_a_failure_not_a_pass() {
        let mut b = builder();
        b.record(Probe::BucketPolicy, Verdict::Inconclusive, "AccessDenied");
        b.record(Probe::AnonymousRead, Verdict::Inconclusive, "connection refused");
        let err = b.finish().unwrap_err();
        assert!(matches!(err, PublicAccessError::Inconclusive { .. }), "got: {err:?}");
    }

    #[test]
    fn an_empty_check_cannot_pass() {
        let err = builder().finish().unwrap_err();
        assert!(matches!(err, PublicAccessError::Inconclusive { .. }), "got: {err:?}");
    }

    #[test]
    fn one_private_probe_passes_alongside_inconclusive_ones() {
        let mut b = builder();
        b.record(Probe::BucketPolicy, Verdict::Inconclusive, "AccessDenied");
        b.record(Probe::AnonymousRead, Verdict::Private, "unsigned GET returned 403");
        let report = b.finish().unwrap();
        assert_eq!(report.conclusive().len(), 1);
        assert_eq!(report.bucket, "enclave-content");
    }

    /// The message is the whole control surface for an operator at 02:00. If it stops naming the
    /// bucket or stops saying what to change, the next person turns the check off instead.
    #[test]
    fn the_refusal_names_the_bucket_and_the_fix() {
        let mut b = builder();
        b.record(Probe::AnonymousList, Verdict::Public, "unsigned ListObjectsV2 returned 200");
        let rendered = b.finish().unwrap_err().to_string();

        assert!(rendered.contains("enclave-content"), "{rendered}");
        assert!(rendered.contains("http://localhost:9000"), "{rendered}");
        assert!(rendered.contains("PUBLICLY READABLE"), "{rendered}");
        assert!(rendered.contains("Block Public Access"), "{rendered}");
        assert!(rendered.contains("mc anonymous set none"), "{rendered}");
        assert!(rendered.contains("unsigned ListObjectsV2 returned 200"), "{rendered}");
    }

    #[test]
    fn the_inconclusive_refusal_explains_why_it_is_not_a_pass() {
        let mut b = builder();
        b.record(Probe::AnonymousRead, Verdict::Inconclusive, "connection refused");
        let rendered = b.finish().unwrap_err().to_string();
        assert!(rendered.contains("enclave-content"), "{rendered}");
        assert!(rendered.contains("connection refused"), "{rendered}");
        assert!(rendered.contains("not a pass"), "{rendered}");
    }
}
