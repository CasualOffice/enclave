//! The unauthenticated half of the public-access self-check.
//!
//! An ordinary unsigned HTTP `GET` — the request an attacker makes. It carries no credential, so
//! it works under the least-privilege IAM policy of `docs/08-BYO-INFRA.md §5`, where every
//! authenticated probe returns `AccessDenied`. That is what makes it the probe that actually
//! answers the question.
//!
//! It reuses smithy's HTTP client rather than introducing a second HTTP stack, so the process has
//! exactly one TLS implementation (rustls over aws-lc-rs, the same backend the workspace pins for
//! `jsonwebtoken`) and cargo-deny's licence allowlist gains nothing new.

use core::time::Duration;

use aws_smithy_http_client::{tls, Connector};
use aws_smithy_runtime_api::client::http::{HttpConnector as _, HttpConnectorSettings};
use aws_smithy_runtime_api::http::Request;
use aws_smithy_types::body::SdkBody;

use crate::error::StorageError;

/// Startup must not hang on an unreachable endpoint; it must fail and say so.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The key the read probe asks for.
///
/// It must not exist, and it must be obvious in an access log what it was. A *present* key would
/// make `200` ambiguous — it would mean "public" on a public bucket and nothing at all if the
/// probe raced a deletion. Because the key is absent, the response separates cleanly: `403` means
/// anonymous reads are refused, and anything else means the request was authorized without a
/// credential.
const PROBE_KEY: &str = "enclave-public-access-self-check-DOES-NOT-EXIST";

/// What an unsigned request came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnonymousOutcome {
    /// The request was refused without a credential. This is the healthy answer.
    Refused(u16),
    /// The request was *not* refused. Anonymous access is possible.
    Allowed(u16),
}

/// Sends unsigned requests at a bucket.
#[derive(Debug)]
pub(crate) struct AnonymousProbe {
    connector: Connector,
}

impl AnonymousProbe {
    /// Builds the client.
    pub(crate) fn new() -> Self {
        let settings = HttpConnectorSettings::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build();

        Self {
            connector: Connector::builder()
                .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::AwsLc))
                .connector_settings(settings)
                .build(),
        }
    }

    /// The base URL of the bucket, in whichever addressing style is configured.
    ///
    /// Built here rather than borrowed from the SDK because the SDK will not hand back a URL for a
    /// request it has not signed, and the probe's entire point is to be unsigned.
    pub(crate) fn bucket_url(
        endpoint: Option<&url::Url>,
        region: &str,
        bucket: &str,
        path_style: bool,
    ) -> Result<String, StorageError> {
        let base = match (endpoint, path_style) {
            (Some(endpoint), true) => {
                format!("{}/{bucket}", endpoint.as_str().trim_end_matches('/'))
            }
            (Some(endpoint), false) => {
                let host = endpoint.host_str().ok_or_else(|| StorageError::Config {
                    problem: format!("`endpoint` {endpoint} has no host"),
                })?;
                let port = endpoint.port().map(|p| format!(":{p}")).unwrap_or_default();
                format!("{}://{bucket}.{host}{port}", endpoint.scheme())
            }
            (None, true) => format!("https://s3.{region}.amazonaws.com/{bucket}"),
            (None, false) => format!("https://{bucket}.s3.{region}.amazonaws.com"),
        };
        Ok(base)
    }

    /// Unsigned `GET` of a key that does not exist.
    ///
    /// `403` (or `401`) means anonymous reads are refused. Anything else — including the `404`
    /// that a public bucket returns for a missing key — means the request was *authorized* and
    /// only the object was absent, which is exactly the exposure this check exists to find.
    ///
    /// The `404`-means-public reading is only sound because the caller has already confirmed the
    /// bucket exists with an authenticated `HeadBucket`; without that, a `404` could equally be
    /// `NoSuchBucket`. See [`super::store::S3BlobStore::connect`].
    pub(crate) async fn probe_read(&self, bucket_url: &str) -> Result<AnonymousOutcome, String> {
        self.probe(&format!("{bucket_url}/{PROBE_KEY}")).await
    }

    /// Unsigned `ListObjectsV2`.
    ///
    /// A `200` means anyone can enumerate the bucket, which retires every argument that depends on
    /// object keys being unguessable.
    pub(crate) async fn probe_list(&self, bucket_url: &str) -> Result<AnonymousOutcome, String> {
        self.probe(&format!("{bucket_url}/?list-type=2&max-keys=1")).await
    }

    async fn probe(&self, url: &str) -> Result<AnonymousOutcome, String> {
        let mut request = Request::new(SdkBody::empty());
        request.set_uri(url).map_err(|err| format!("could not build a probe URL: {err}"))?;

        let response = self
            .connector
            .call(request)
            .await
            .map_err(|err| format!("unsigned request to {url} failed: {err}"))?;

        let status = response.status().as_u16();
        Ok(if matches!(status, 401 | 403) {
            AnonymousOutcome::Refused(status)
        } else {
            AnonymousOutcome::Allowed(status)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn url(raw: &str) -> url::Url {
        raw.parse().unwrap()
    }

    #[test]
    fn path_style_addresses_the_bucket_under_the_endpoint() {
        let built = AnonymousProbe::bucket_url(
            Some(&url("http://localhost:9000")),
            "us-east-1",
            "enclave-content",
            true,
        )
        .unwrap();
        assert_eq!(built, "http://localhost:9000/enclave-content");
    }

    #[test]
    fn path_style_does_not_double_the_slash_on_a_trailing_endpoint() {
        let built = AnonymousProbe::bucket_url(
            Some(&url("http://localhost:9000/")),
            "us-east-1",
            "enclave-content",
            true,
        )
        .unwrap();
        assert_eq!(built, "http://localhost:9000/enclave-content");
    }

    #[test]
    fn virtual_host_style_prefixes_the_bucket_and_keeps_the_port() {
        let built = AnonymousProbe::bucket_url(
            Some(&url("https://storage.example.com:8443")),
            "us-east-1",
            "enclave-content",
            false,
        )
        .unwrap();
        assert_eq!(built, "https://enclave-content.storage.example.com:8443");
    }

    #[test]
    fn without_an_endpoint_it_addresses_aws_in_the_configured_region() {
        assert_eq!(
            AnonymousProbe::bucket_url(None, "ap-south-1", "enclave-content", false).unwrap(),
            "https://enclave-content.s3.ap-south-1.amazonaws.com"
        );
        assert_eq!(
            AnonymousProbe::bucket_url(None, "ap-south-1", "enclave-content", true).unwrap(),
            "https://s3.ap-south-1.amazonaws.com/enclave-content"
        );
    }
}
