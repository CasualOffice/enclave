//! Where a request's network origin is established, once (`ENC-583`).
//!
//! `RequestContext` is assembled at the edge from a verified token *and from properties of the
//! connection* (`crates/core/src/context.rs`). The token half has been honest since M0; this module
//! is the connection half, which until now was a hard-coded `NetworkContext::internal()` with a
//! comment saying so.
//!
//! # Why it is one type rather than two extractors
//!
//! Resolving the client address and resolving its zones are the same decision made twice if they
//! are separated: zones must be computed from the *resolved* address (`docs/06 §7.3`), and a second
//! call site that computed them from the peer would put every request behind a load balancer inside
//! the load balancer's zone — which is usually a trusted one. [`Edge`] holds both halves so there is
//! one place that can get it wrong and one place to read to see that it does not.
//!
//! # The one header that is read, and why no others are
//!
//! `X-Forwarded-For` only. Not `X-Real-IP`, not `True-Client-IP`, not `CF-Connecting-IP`, and not
//! RFC 7239 `Forwarded`. Each additional header is another string a client can send and another
//! chance for two of them to disagree, and a deployment whose proxy writes one of the others can
//! configure it to write this one. `Forwarded` is the standardised spelling and is worth adding
//! when a deployment needs it — as a *parsed* alternative to this header, never as a fallback
//! consulted when this one is absent, because "whichever header is present wins" hands the choice
//! back to the client.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use enclave_conditional_access::{ProxyTrust, ZoneMap};
use enclave_core::NetworkContext;

/// The header carrying the forwarding chain.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// What the edge needs in order to describe where a request came from.
#[derive(Debug, Clone, Default)]
pub struct Edge {
    trust: ProxyTrust,
    zones: ZoneMap,
}

impl Edge {
    /// Builds an edge from configured proxies and zones.
    #[must_use]
    pub fn new(trust: ProxyTrust, zones: ZoneMap) -> Self {
        Self { trust, zones }
    }

    /// An edge that trusts no proxy and knows no zone.
    ///
    /// Named rather than reached through `Default` so that choosing it is visible in review. It is
    /// the correct configuration for a deployment with no reverse proxy — the peer address is the
    /// client address — and it is what a router built without an `Edge` gets, which is why it must
    /// be the *cautious* option rather than a convenient one.
    #[must_use]
    pub fn untrusting() -> Self {
        Self::default()
    }

    /// Builds an edge from what an operator wrote in `enclave.yaml`.
    #[must_use]
    pub fn from_config(config: &enclave_config::Config) -> Self {
        Self::new(
            ProxyTrust::new(config.server.trusted_proxies.iter().cloned()),
            ZoneMap::from_config(&config.conditional_access.zones),
        )
    }

    /// Whether this edge trusts any proxy at all, for the start-up banner.
    #[must_use]
    pub fn trusts_no_proxy(&self) -> bool {
        self.trust.is_empty()
    }

    /// Describes one request's network origin.
    ///
    /// Country and ASN are `None`: no geolocation provider is wired yet, and `NetworkContext`
    /// documents that a geo-fence must read `None` as "unknown" rather than as "allowed" —
    /// `HumanCondition::CountryNotIn` does exactly that, so a fence configured today refuses a
    /// caller it cannot place instead of admitting them.
    #[must_use]
    pub fn network_context(&self, parts: &Parts) -> NetworkContext {
        let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
            // The router was served without `into_make_service_with_connect_info`. In the binary
            // that cannot happen (`main.rs`); in a test harness that builds a router and calls it
            // directly it always does. Either way the honest answer is that we do not know where
            // this came from, and `NetworkContext::unknown` is refused by every network rule.
            tracing::warn!(
                "no peer address on the request: serve the router with \
                 `into_make_service_with_connect_info::<SocketAddr>()` or every network rule will \
                 refuse"
            );
            return NetworkContext::unknown();
        };

        let origin = self.trust.resolve(peer.ip(), forwarded_for(&parts.headers));

        NetworkContext {
            source_ip: origin.ip(),
            country: None,
            asn: None,
            // Against the resolved address and no other (`docs/06 §7.3`).
            zones: self.zones.zones_for(origin.ip()),
            via_trusted_proxy: origin.via_trusted_proxy(),
        }
    }
}

/// The `X-Forwarded-For` values, in arrival order.
///
/// `HeaderMap::get_all` preserves the order the lines arrived in, which the walk depends on: the
/// rightmost entry of the *last* line is the one the nearest proxy appended.
///
/// A value that is not valid UTF-8 discards the **whole** chain rather than being skipped. Skipping
/// it would silently renumber the remaining entries, so a walk that strips one hop would strip past
/// a different address than the one the proxy wrote — a wrong answer dressed as a successful parse.
/// Discarding leaves the peer as the client address, which is the same answer as no header at all.
fn forwarded_for(headers: &HeaderMap) -> Vec<&str> {
    let mut values = Vec::new();
    for value in headers.get_all(FORWARDED_FOR) {
        match value.to_str() {
            Ok(text) => values.push(text),
            Err(_) => {
                tracing::debug!("x-forwarded-for is not valid UTF-8; the chain is discarded");
                return Vec::new();
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use axum::http::{HeaderValue, Request};
    use enclave_conditional_access::NetworkZone;
    use enclave_config::TrustedProxy;

    /// Builds the `Parts` a handler's extractor sees, with the peer address axum's
    /// `ConnectInfo` layer would have attached.
    fn parts(peer: Option<&str>, forwarded: &[&str]) -> Parts {
        let mut request = Request::builder();
        for value in forwarded {
            request = request.header(FORWARDED_FOR, *value);
        }
        let mut request = request.body(()).expect("request builds");
        if let Some(peer) = peer {
            let addr: SocketAddr = format!("{peer}:54321").parse().expect("peer address");
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        request.into_parts().0
    }

    fn edge() -> Edge {
        Edge::new(
            ProxyTrust::new([TrustedProxy { cidr: "10.0.0.0/8".parse().expect("cidr"), hops: 1 }]),
            ZoneMap::new([NetworkZone::new(
                "Corporate India",
                ["203.0.113.0/24".parse().expect("cidr")],
            )]),
        )
    }

    /// The M4 exit criterion, asserted through the code the HTTP path actually runs, with the
    /// positive control that stops it passing for free.
    ///
    /// The forged header, the configuration and the call are identical in both halves; only the
    /// peer differs. An `Edge` that never read the header would fail the second half, and one that
    /// always believed it would fail the first.
    #[test]
    fn a_forged_forwarded_for_reaches_the_context_only_from_a_trusted_peer() {
        let edge = edge();
        let forged = "203.0.113.9";

        let untrusted = edge.network_context(&parts(Some("198.51.100.66"), &[forged]));
        assert_eq!(untrusted.source_ip, "198.51.100.66".parse::<std::net::IpAddr>().unwrap());
        assert!(!untrusted.via_trusted_proxy);
        // And the zone that address would have bought is not granted either — this is the failure
        // that matters, since `Corporate India` is what a rule would let through.
        assert!(untrusted.zones.is_empty(), "a forged address bought a trusted zone");

        let trusted = edge.network_context(&parts(Some("10.0.0.7"), &[forged]));
        assert_eq!(trusted.source_ip, forged.parse::<std::net::IpAddr>().unwrap());
        assert!(trusted.via_trusted_proxy);
        assert_eq!(trusted.zones, ["Corporate India"]);
    }

    /// Zones are computed from the resolved address, not from the peer.
    ///
    /// Without this the load balancer's own address decides the zone, and the load balancer is
    /// nearly always inside a trusted one — so every request through it would arrive trusted.
    #[test]
    fn zones_are_resolved_against_the_client_address_and_not_the_proxy() {
        let edge = Edge::new(
            ProxyTrust::new([TrustedProxy {
                cidr: "203.0.113.0/24".parse().expect("cidr"),
                hops: 1,
            }]),
            ZoneMap::new([NetworkZone::new(
                "Corporate India",
                ["203.0.113.0/24".parse().expect("cidr")],
            )]),
        );

        // The proxy itself is inside the zone; the client it forwards for is not.
        let context = edge.network_context(&parts(Some("203.0.113.7"), &["192.0.2.44"]));
        assert_eq!(context.source_ip, "192.0.2.44".parse::<std::net::IpAddr>().unwrap());
        assert!(context.zones.is_empty(), "the proxy's zone was attributed to its client");

        // Positive control: a client that really is in the zone gets it.
        let context = edge.network_context(&parts(Some("203.0.113.7"), &["203.0.113.9"]));
        assert_eq!(context.zones, ["Corporate India"]);
    }

    #[test]
    fn several_forwarded_for_lines_are_one_chain_in_arrival_order() {
        let edge = Edge::new(
            ProxyTrust::new([TrustedProxy { cidr: "10.0.0.0/8".parse().expect("cidr"), hops: 2 }]),
            ZoneMap::empty(),
        );
        let context =
            edge.network_context(&parts(Some("10.0.0.7"), &["8.8.8.8", "192.0.2.44, 10.0.0.9"]));
        assert_eq!(context.source_ip, "192.0.2.44".parse::<std::net::IpAddr>().unwrap());
    }

    /// A header value that is not UTF-8 discards the chain rather than shifting it.
    #[test]
    fn a_header_value_that_cannot_be_read_discards_the_whole_chain() {
        let mut request = Request::builder()
            .header(FORWARDED_FOR, HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque bytes"))
            .header(FORWARDED_FOR, "192.0.2.44")
            .body(())
            .expect("request builds");
        request
            .extensions_mut()
            .insert(ConnectInfo("10.0.0.7:1234".parse::<SocketAddr>().expect("peer")));
        let context = edge().network_context(&request.into_parts().0);
        assert_eq!(context.source_ip, "10.0.0.7".parse::<std::net::IpAddr>().unwrap());
        assert!(!context.via_trusted_proxy);
    }

    /// No peer address means no claim about the network at all.
    #[test]
    fn a_request_with_no_peer_address_is_described_as_unknown_rather_than_local() {
        let context = edge().network_context(&parts(None, &["203.0.113.9"]));
        assert_eq!(context, NetworkContext::unknown());
        assert!(context.source_ip.is_unspecified());
        assert!(context.zones.is_empty());
    }

    /// The default edge trusts nothing, which is what a router built without one gets.
    #[test]
    fn the_default_edge_believes_no_forwarding_header() {
        let context =
            Edge::untrusting().network_context(&parts(Some("10.0.0.7"), &["203.0.113.9"]));
        assert_eq!(context.source_ip, "10.0.0.7".parse::<std::net::IpAddr>().unwrap());
        assert!(!context.via_trusted_proxy);
        assert!(Edge::untrusting().trusts_no_proxy());
    }
}
