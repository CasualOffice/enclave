//! The S3 implementation of the public-access self-check.
//!
//! Read [`crate::public_access`] first — it holds the argument for why this exists and why an
//! inconclusive result is a failure. This module is the mechanics: five probes, each recording a
//! verdict and a sentence, with the ruling applied by
//! [`ReportBuilder::finish`](crate::public_access::ReportBuilder).

use async_trait::async_trait;
use aws_sdk_s3::error::ProvideErrorMetadata;

use crate::public_access::{
    Probe, PublicAccessCheck, PublicAccessError, PublicAccessReport, ReportBuilder, Verdict,
};
use crate::s3::anonymous::AnonymousOutcome;
use crate::s3::store::S3BlobStore;

#[async_trait]
impl PublicAccessCheck for S3BlobStore {
    async fn verify_not_public(&self) -> Result<PublicAccessReport, PublicAccessError> {
        let config = self.config();
        let endpoint = config.endpoint.as_ref().map(ToString::to_string);
        let mut report = ReportBuilder::new(config.bucket.clone(), endpoint);

        if crate::s3::config::has_aws_public_access_apis(config.flavor) {
            self.probe_public_access_block(&mut report).await;
            self.probe_bucket_policy_status(&mut report).await;
        }
        self.probe_bucket_policy(&mut report).await;
        self.probe_bucket_acl(&mut report).await;
        self.probe_anonymously(&mut report).await;

        report.finish()
    }
}

impl S3BlobStore {
    /// `GetPublicAccessBlock` — AWS's master switch. All four settings on means nothing else can
    /// make the bucket public, so this is the strongest single piece of evidence available.
    async fn probe_public_access_block(&self, report: &mut ReportBuilder) {
        let bucket = &self.config().bucket;
        match self.client().get_public_access_block().bucket(bucket).send().await {
            Ok(response) => {
                let Some(block) = response.public_access_block_configuration() else {
                    report.record(
                        Probe::PublicAccessBlock,
                        Verdict::Inconclusive,
                        "the bucket has no public-access block configuration",
                    );
                    return;
                };
                let all = block.block_public_acls().unwrap_or(false)
                    && block.ignore_public_acls().unwrap_or(false)
                    && block.block_public_policy().unwrap_or(false)
                    && block.restrict_public_buckets().unwrap_or(false);
                if all {
                    report.record(
                        Probe::PublicAccessBlock,
                        Verdict::Private,
                        "S3 Block Public Access is on for all four settings",
                    );
                } else {
                    // Not itself proof of exposure — the policy and ACL probes decide that — but
                    // it is the reason a bucket *can* become public later, so it is worth saying.
                    report.record(
                        Probe::PublicAccessBlock,
                        Verdict::Inconclusive,
                        format!(
                            "S3 Block Public Access is incomplete (acls={:?} ignore_acls={:?} \
                             policy={:?} restrict={:?}); enable all four",
                            block.block_public_acls(),
                            block.ignore_public_acls(),
                            block.block_public_policy(),
                            block.restrict_public_buckets()
                        ),
                    );
                }
            }
            Err(err) => {
                report.record(
                    Probe::PublicAccessBlock,
                    Verdict::Inconclusive,
                    describe(&err, "GetPublicAccessBlock"),
                );
            }
        }
    }

    /// `GetBucketPolicyStatus` — AWS evaluating its own policy, which is more authoritative than
    /// anything this crate can conclude by parsing the document.
    async fn probe_bucket_policy_status(&self, report: &mut ReportBuilder) {
        let bucket = &self.config().bucket;
        match self.client().get_bucket_policy_status().bucket(bucket).send().await {
            Ok(response) => match response.policy_status().and_then(|s| s.is_public()) {
                Some(true) => report.record(
                    Probe::BucketPolicyStatus,
                    Verdict::Public,
                    "AWS reports the bucket policy makes this bucket public",
                ),
                Some(false) => report.record(
                    Probe::BucketPolicyStatus,
                    Verdict::Private,
                    "AWS reports the bucket policy does not make this bucket public",
                ),
                None => report.record(
                    Probe::BucketPolicyStatus,
                    Verdict::Inconclusive,
                    "AWS returned no policy status",
                ),
            },
            Err(err) => report.record(
                Probe::BucketPolicyStatus,
                Verdict::Inconclusive,
                describe(&err, "GetBucketPolicyStatus"),
            ),
        };
    }

    /// `GetBucketPolicy`, parsed.
    ///
    /// This is the probe that catches a MinIO bucket opened with `mc anonymous set download`,
    /// which writes exactly the wildcard-principal statement [`policy_verdict`] looks for. MinIO
    /// implements neither of the two AWS APIs above, so without this one the only evidence on the
    /// most common self-hosted backend would be the unsigned request.
    async fn probe_bucket_policy(&self, report: &mut ReportBuilder) {
        let bucket = &self.config().bucket;
        match self.client().get_bucket_policy().bucket(bucket).send().await {
            Ok(response) => match response.policy() {
                Some(document) => {
                    let (verdict, detail) = policy_verdict(document);
                    report.record(Probe::BucketPolicy, verdict, detail);
                }
                None => report.record(
                    Probe::BucketPolicy,
                    Verdict::Private,
                    "the bucket has no policy attached",
                ),
            },
            Err(err) => {
                // "No such bucket policy" is the healthy state, not a failure to observe.
                if matches!(err.code(), Some("NoSuchBucketPolicy")) {
                    report.record(
                        Probe::BucketPolicy,
                        Verdict::Private,
                        "the bucket has no policy attached",
                    )
                } else {
                    report.record(
                        Probe::BucketPolicy,
                        Verdict::Inconclusive,
                        describe(&err, "GetBucketPolicy"),
                    )
                }
            }
        };
    }

    /// `GetBucketAcl`, checked for the two grantee groups that mean "everyone".
    ///
    /// `AuthenticatedUsers` counts as public: it means every AWS account in the world, not every
    /// user of this deployment, and mistaking the two is a well-worn way to publish a bucket.
    async fn probe_bucket_acl(&self, report: &mut ReportBuilder) {
        const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
        const AUTHENTICATED: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

        let bucket = &self.config().bucket;
        match self.client().get_bucket_acl().bucket(bucket).send().await {
            Ok(response) => {
                let offending: Vec<String> = response
                    .grants()
                    .iter()
                    .filter_map(|grant| {
                        let uri = grant.grantee()?.uri()?;
                        (uri == ALL_USERS || uri == AUTHENTICATED).then(|| {
                            format!(
                                "{} granted to {uri}",
                                grant.permission().map_or("?", |p| p.as_str())
                            )
                        })
                    })
                    .collect();

                if offending.is_empty() {
                    report.record(
                        Probe::BucketAcl,
                        Verdict::Private,
                        "no AllUsers or AuthenticatedUsers grant on the bucket ACL",
                    );
                } else {
                    report.record(Probe::BucketAcl, Verdict::Public, offending.join("; "));
                }
            }
            Err(err) => {
                report.record(
                    Probe::BucketAcl,
                    Verdict::Inconclusive,
                    describe(&err, "GetBucketAcl"),
                );
            }
        };
    }

    /// The two unsigned requests. See [`crate::s3::anonymous`].
    async fn probe_anonymously(&self, report: &mut ReportBuilder) {
        let Some(bucket_url) = self.anonymous_bucket_url() else {
            report.record(
                Probe::AnonymousRead,
                Verdict::Inconclusive,
                "could not build an unsigned probe URL from the configured endpoint",
            );
            return;
        };

        for (probe, outcome) in [
            (Probe::AnonymousRead, self.anonymous().probe_read(&bucket_url).await),
            (Probe::AnonymousList, self.anonymous().probe_list(&bucket_url).await),
        ] {
            match outcome {
                Ok(AnonymousOutcome::Refused(status)) => report.record(
                    probe,
                    Verdict::Private,
                    format!("an unsigned request to {bucket_url} was refused with HTTP {status}"),
                ),
                Ok(AnonymousOutcome::Allowed(status)) => report.record(
                    probe,
                    Verdict::Public,
                    format!(
                        "an unsigned request to {bucket_url} returned HTTP {status} rather than \
                         403 — this bucket answers requests that carry no credential"
                    ),
                ),
                Err(detail) => report.record(probe, Verdict::Inconclusive, detail),
            };
        }
    }
}

/// Decides whether a bucket policy document grants read to the world.
///
/// Conservative in the one place it matters: a statement with a wildcard principal *and* a
/// `Condition` is reported as inconclusive rather than private, because the condition might be
/// `aws:SourceVpce` (a genuine restriction) or `s3:ExistingObjectTag` (no restriction at all), and
/// this crate is not an IAM evaluator. Reporting it as private would be a claim it cannot support.
///
/// Returns the verdict and the sentence to show the operator.
fn policy_verdict(document: &str) -> (Verdict, String) {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(document) else {
        return (
            Verdict::Inconclusive,
            "the bucket policy is attached but is not valid JSON".to_owned(),
        );
    };

    let statements = match parsed.get("Statement") {
        Some(serde_json::Value::Array(items)) => items.clone(),
        Some(single) => vec![single.clone()],
        None => return (Verdict::Private, "the bucket policy has no statements".to_owned()),
    };

    let mut public = Vec::new();
    let mut conditional = Vec::new();

    for statement in &statements {
        if statement.get("Effect").and_then(serde_json::Value::as_str) != Some("Allow") {
            continue;
        }
        if !principal_is_wildcard(statement.get("Principal")) {
            continue;
        }
        let sid = statement
            .get("Sid")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unnamed statement>")
            .to_owned();
        let actions = render_actions(statement.get("Action"));

        if statement.get("Condition").is_some() {
            conditional.push(format!("`{sid}` allows {actions} to everyone, under a Condition"));
        } else {
            public.push(format!("`{sid}` allows {actions} to Principal \"*\""));
        }
    }

    if !public.is_empty() {
        return (Verdict::Public, public.join("; "));
    }
    if !conditional.is_empty() {
        return (
            Verdict::Inconclusive,
            format!(
                "{} — this crate does not evaluate IAM conditions, so it cannot confirm the \
                 restriction; review it by hand",
                conditional.join("; ")
            ),
        );
    }
    (Verdict::Private, "no bucket-policy statement allows a wildcard principal".to_owned())
}

/// `"*"`, `{"AWS": "*"}` and `{"AWS": ["*", …]}` all mean everyone.
fn principal_is_wildcard(principal: Option<&serde_json::Value>) -> bool {
    fn is_star(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(s) => s == "*",
            serde_json::Value::Array(items) => items.iter().any(is_star),
            serde_json::Value::Object(map) => map.values().any(is_star),
            _ => false,
        }
    }
    principal.is_some_and(is_star)
}

fn render_actions(action: Option<&serde_json::Value>) -> String {
    match action {
        Some(serde_json::Value::String(one)) => one.clone(),
        Some(serde_json::Value::Array(many)) => {
            many.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", ")
        }
        _ => "an unspecified action".to_owned(),
    }
}

/// Turns an SDK failure into the sentence a probe records.
///
/// `AccessDenied` gets its own phrasing because on a correctly least-privileged credential it is
/// the *expected* answer, and an operator reading "AccessDenied" in a startup log should not
/// conclude something is broken.
fn describe<E: ProvideErrorMetadata>(err: &E, operation: &'static str) -> String {
    match err.code() {
        Some(code @ ("AccessDenied" | "AccessDeniedException" | "MethodNotAllowed")) => format!(
            "{operation} returned {code} — expected on a least-privilege credential \
             (docs/08-BYO-INFRA.md §5); this probe cannot rule"
        ),
        Some("NotImplemented") => {
            format!("{operation} is not implemented by this backend")
        }
        Some(code) => format!("{operation} failed with {code}"),
        None => format!("{operation} failed"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Exactly what `mc anonymous set download <alias>/<bucket>` writes. If this stops being
    /// recognised, the MinIO integration test is the only thing left catching a public bucket.
    const MINIO_PUBLIC_DOWNLOAD: &str = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::enclave-content/*"]
        }]
    }"#;

    #[test]
    fn the_minio_public_download_policy_is_recognised_as_public() {
        let (verdict, detail) = policy_verdict(MINIO_PUBLIC_DOWNLOAD);
        assert_eq!(verdict, Verdict::Public);
        assert!(detail.contains("s3:GetObject"), "{detail}");
    }

    #[test]
    fn a_bare_star_principal_is_recognised_as_public() {
        let (verdict, _) = policy_verdict(
            r#"{"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:*"}}"#,
        );
        assert_eq!(verdict, Verdict::Public);
    }

    #[test]
    fn a_named_principal_is_private() {
        let (verdict, _) = policy_verdict(
            r#"{"Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave"},
                "Action": "s3:GetObject"
            }]}"#,
        );
        assert_eq!(verdict, Verdict::Private);
    }

    #[test]
    fn an_explicit_deny_to_everyone_is_not_an_exposure() {
        let (verdict, _) = policy_verdict(
            r#"{"Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }]}"#,
        );
        assert_eq!(verdict, Verdict::Private);
    }

    /// A wildcard principal behind a condition is not claimed to be safe. The check does not
    /// evaluate IAM conditions, and pretending otherwise would be the kind of "it is probably
    /// fine" that this whole module exists to refuse.
    #[test]
    fn a_conditional_wildcard_is_inconclusive_rather_than_private() {
        let (verdict, detail) = policy_verdict(
            r#"{"Statement": [{
                "Sid": "VpcOnly",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"}}
            }]}"#,
        );
        assert_eq!(verdict, Verdict::Inconclusive);
        assert!(detail.contains("VpcOnly"), "{detail}");
    }

    #[test]
    fn an_unparseable_policy_is_inconclusive_not_private() {
        let (verdict, _) = policy_verdict("{not json");
        assert_eq!(verdict, Verdict::Inconclusive);
    }

    #[test]
    fn wildcard_detection_covers_every_principal_spelling() {
        for raw in [r#""*""#, r#"{"AWS": "*"}"#, r#"{"AWS": ["arn:…", "*"]}"#, r#"["*"]"#] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(principal_is_wildcard(Some(&value)), "`{raw}` was not seen as a wildcard");
        }
        for raw in [r#""arn:aws:iam::1:root""#, r#"{"AWS": "arn:aws:iam::1:root"}"#, "null"] {
            let value: serde_json::Value = serde_json::from_str(raw).unwrap();
            assert!(!principal_is_wildcard(Some(&value)), "`{raw}` was seen as a wildcard");
        }
        assert!(!principal_is_wildcard(None));
    }
}
