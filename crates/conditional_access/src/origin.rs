//! Resolving the true client address from the connection and the forwarding chain.
//!
//! `plans/M4-GOVERNANCE.md` D30 and `docs/06-SECURITY-DLP-ACCESS.md §7.3` state the rule this
//! module implements, and both state it as a prohibition first:
//!
//! > The peer address is the client address unless the peer is in a trusted network, in which case
//! > exactly the configured number of hops is stripped. **Never "take the leftmost", never "take
//! > the first public address"** — both let a client claim any source IP by sending enough headers.
//!
//! # Why those two shortcuts are wrong, concretely
//!
//! `X-Forwarded-For` is *appended to* by each proxy: the rightmost entry is what the proxy nearest
//! us observed, and everything to its left is hearsay it copied from the request it received.
//! A client that sends `X-Forwarded-For: 8.8.8.8` on its very first hop produces
//! `8.8.8.8, <real client>` after one honest proxy, so the leftmost entry is *always* the one under
//! the attacker's control. "First public address" is the same defect wearing a disguise: the
//! attacker simply sends a public address of their choosing.
//!
//! The only address in the chain we have any reason to believe is the one written by a hop we
//! trust — which is why this walks the chain **right to left**, and only while the address it is
//! stepping past is itself inside a configured trusted network.
//!
//! # What "believing a hop" means step by step
//!
//! Start at the socket peer, which is the one address nobody can forge. If it is not a configured
//! proxy, stop: the header is not read at all. Otherwise, take the rightmost chain entry — that is
//! the peer's statement about *who connected to it* — and adopt it. To take another step we need
//! the address we just adopted to be a configured proxy too, because otherwise the next entry is a
//! statement made by a machine we have no reason to trust. The budget is `hops` from the peer's
//! configuration; anything beyond it is discarded, never merged.
//!
//! # Failure is always "keep what we already believed"
//!
//! An unparseable entry, an exhausted chain, an untrusted intermediate — every one of them stops
//! the walk and leaves the last address we had a reason to believe in place. There is no branch
//! that widens trust in response to a malformed input.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use enclave_config::TrustedProxy;

/// Where a request actually came from, and how much of that was taken on trust.
///
/// Carries the peer alongside the resolved address because the difference between "we observed
/// this address on a socket" and "a proxy told us this address" is the fact a network rule needs
/// and the fact that is easiest to lose. A struct that returned only an `IpAddr` would make the
/// two indistinguishable one line later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedOrigin {
    ip: IpAddr,
    peer: IpAddr,
    peer_is_trusted_proxy: bool,
    hops_honoured: u8,
}

impl ResolvedOrigin {
    /// The client address: the peer, or the last forwarded entry a trusted hop vouched for.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The address observed on the socket. Never forgeable, and never discarded.
    #[must_use]
    pub const fn peer(&self) -> IpAddr {
        self.peer
    }

    /// Whether the immediate peer was inside a configured trusted-proxy network.
    ///
    /// Distinct from [`ResolvedOrigin::via_trusted_proxy`]: a trusted proxy that sends no
    /// forwarding header yields `true` here and `false` there, because the address in hand is then
    /// the one we observed rather than one we were told.
    #[must_use]
    pub const fn peer_is_trusted_proxy(&self) -> bool {
        self.peer_is_trusted_proxy
    }

    /// How many forwarded entries were actually believed.
    ///
    /// Exposed because it is the number an operator needs when a proxy chain is misconfigured:
    /// `hops: 2` configured and `1` honoured means the second proxy is not in the trusted list, and
    /// nothing else in the system would say so.
    #[must_use]
    pub const fn hops_honoured(&self) -> u8 {
        self.hops_honoured
    }

    /// Whether [`ResolvedOrigin::ip`] came from a forwarding header rather than from the socket.
    ///
    /// This is the honest reading of `NetworkContext::via_trusted_proxy`: it answers "is this
    /// address a claim relayed to us?", which is the question a policy needs, rather than "was the
    /// peer on a list", which is a fact about our own deployment.
    #[must_use]
    pub const fn via_trusted_proxy(&self) -> bool {
        self.hops_honoured > 0
    }
}

/// The set of networks whose forwarding headers may be believed, and how deep.
///
/// Empty by default and empty is the safe state: with no configured proxy, the peer address is the
/// client address and no forwarding header is read at all. `ServerConfig::trusted_proxies` has
/// always defaulted to empty; what changed in M4 is that conditional access now *uses* the client
/// address, so the emptiness stopped being cautious and became load-bearing.
#[derive(Debug, Clone, Default)]
pub struct ProxyTrust {
    proxies: Vec<TrustedProxy>,
}

impl ProxyTrust {
    /// Trust no proxy: every request's client address is its socket peer.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Trusts the configured networks.
    #[must_use]
    pub fn new(proxies: impl IntoIterator<Item = TrustedProxy>) -> Self {
        Self { proxies: proxies.into_iter().collect() }
    }

    /// Whether any proxy is trusted at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// The hop budget configured for the network containing `addr`, if any.
    ///
    /// Longest prefix wins, as it would in a routing table: an operator who writes both
    /// `10.0.0.0/8` and `10.1.2.0/24` means the second to describe that subnet, and picking the
    /// first match in file order would make the answer depend on the order lines happen to be in.
    /// Equal prefixes are broken by the **smaller** hop count, because a hop budget is permission
    /// to discard observed information and the conservative reading of an ambiguous configuration
    /// is the one that discards less.
    fn hops_for(&self, addr: IpAddr) -> Option<u8> {
        self.proxies
            .iter()
            .filter(|proxy| proxy.cidr.contains(addr))
            .min_by_key(|proxy| (core::cmp::Reverse(proxy.cidr.prefix()), proxy.hops))
            .map(|proxy| proxy.hops)
    }

    /// Resolves one request's client address (D30).
    ///
    /// `forwarded` yields the raw `X-Forwarded-For` header values **in the order they arrived** —
    /// one item per header line, each of which may itself hold a comma-separated list. Both forms
    /// are flattened here rather than at the call site, because a caller that concatenated them in
    /// the wrong order would silently shift which entry the walk pops first, and that is a change
    /// of answer rather than a parse failure.
    ///
    /// The header is not read at all unless the peer is a configured proxy. That ordering is the
    /// whole control: there is no code path in which an untrusted peer's header influences the
    /// result, not even to be validated and rejected.
    #[must_use]
    pub fn resolve<'a>(
        &self,
        peer: IpAddr,
        forwarded: impl IntoIterator<Item = &'a str>,
    ) -> ResolvedOrigin {
        let peer = canonical(peer);

        let Some(budget) = self.hops_for(peer) else {
            return ResolvedOrigin {
                ip: peer,
                peer,
                peer_is_trusted_proxy: false,
                hops_honoured: 0,
            };
        };

        let chain: Vec<&str> = forwarded.into_iter().flat_map(|value| value.split(',')).collect();

        let mut remaining = budget;
        let mut index = chain.len();
        let mut current = peer;
        let mut honoured: u8 = 0;

        // Invariant, restated on every iteration rather than assumed: `current` is inside a
        // configured trusted network, so the entry it wrote is worth reading. The first pass
        // satisfies it from the check above; every later pass re-earns it against the address just
        // adopted. Dropping this condition is exactly the "trust the whole chain" bug.
        while remaining > 0 && self.hops_for(current).is_some() {
            if index == 0 {
                // Fewer entries than hops. The chain ran out; keep what we have rather than
                // inventing a hop.
                break;
            }
            index -= 1;
            let Some(claimed) = parse_entry(chain[index]) else {
                // Malformed, obfuscated (`unknown`, `_hidden`) or simply not an address. We cannot
                // step past what we cannot read, so the walk stops here with the last address we
                // had a reason to believe.
                break;
            };
            current = claimed;
            honoured = honoured.saturating_add(1);
            remaining -= 1;
        }

        ResolvedOrigin { ip: current, peer, peer_is_trusted_proxy: true, hops_honoured: honoured }
    }
}

/// Parses one `X-Forwarded-For` entry into an address.
///
/// Accepts the four shapes that occur in practice — bare IPv4, bare IPv6, `IPv4:port` and
/// `[IPv6]:port` — and rejects everything else, including RFC 7239's `unknown` and obfuscated
/// identifiers. Rejection is not a soft failure: it stops the walk, so a rejected entry costs the
/// caller nothing worse than being seen as the proxy that wrote it.
fn parse_entry(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // `[2001:db8::1]:443` — the bracketed form must be tried first, because the brackets make it
    // unparseable as a bare address and the port-splitting branch below would mangle it.
    if let Some(rest) = raw.strip_prefix('[') {
        let (inside, _port) = rest.split_once(']')?;
        return inside.parse::<Ipv6Addr>().ok().map(|v6| canonical(IpAddr::V6(v6)));
    }

    // Bare IPv4 or bare IPv6. Tried before port splitting so that `2001:db8::1` is read as an
    // address rather than as a host `2001:db8:` with a port `:1`.
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(canonical(ip));
    }

    // `203.0.113.7:41234`. Only IPv4 reaches here: an unbracketed IPv6 with a port is ambiguous by
    // construction and was already consumed as an address by the branch above.
    let (host, port) = raw.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Collapses an IPv4-mapped IPv6 address to its IPv4 form.
///
/// A dual-stack listener hands us `::ffff:10.0.0.1` for a peer that the operator wrote as
/// `10.0.0.0/8`, and `IpNetwork::contains` compares families, so the two would never match. The
/// failure is safe — a trusted proxy stops being recognised and its header is ignored — but it is
/// silent and it looks exactly like a configuration mistake, so it is worth removing rather than
/// documenting.
///
/// Only the *mapped* form is collapsed. The deprecated IPv4-compatible form (`::a.b.c.d`) is left
/// alone deliberately: it is not what a dual-stack socket produces, and treating it as equivalent
/// would let a client name an IPv4 network in an IPv6 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn entries_parse_in_every_shape_that_occurs_in_practice() {
        assert_eq!(parse_entry("203.0.113.7"), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(parse_entry("  203.0.113.7  "), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(parse_entry("203.0.113.7:41234"), Some("203.0.113.7".parse().unwrap()));
        assert_eq!(parse_entry("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_entry("[2001:db8::1]"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_entry("[2001:db8::1]:443"), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn entries_that_are_not_addresses_are_rejected_rather_than_guessed_at() {
        assert_eq!(parse_entry(""), None);
        assert_eq!(parse_entry("   "), None);
        assert_eq!(parse_entry("unknown"), None);
        assert_eq!(parse_entry("_obfuscated"), None);
        assert_eq!(parse_entry("203.0.113.7:notaport"), None);
        assert_eq!(parse_entry("203.0.113.999"), None);
        assert_eq!(parse_entry("[2001:db8::1"), None);
        assert_eq!(parse_entry("example.com"), None);
    }

    #[test]
    fn an_ipv4_mapped_address_is_collapsed_to_its_ipv4_form() {
        assert_eq!(parse_entry("::ffff:10.0.0.1"), Some("10.0.0.1".parse().unwrap()));
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let plain: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(canonical(mapped), plain);
        // The deprecated IPv4-compatible form is deliberately left as IPv6.
        assert!(canonical("::10.0.0.1".parse().unwrap()).is_ipv6());
    }

    #[test]
    fn longest_prefix_wins_and_ties_go_to_the_smaller_hop_count() {
        let trust = ProxyTrust::new([
            TrustedProxy { cidr: "10.0.0.0/8".parse().unwrap(), hops: 3 },
            TrustedProxy { cidr: "10.1.2.0/24".parse().unwrap(), hops: 1 },
            TrustedProxy { cidr: "10.1.2.0/24".parse().unwrap(), hops: 2 },
        ]);
        assert_eq!(trust.hops_for("10.9.9.9".parse().unwrap()), Some(3));
        assert_eq!(trust.hops_for("10.1.2.5".parse().unwrap()), Some(1));
        assert_eq!(trust.hops_for("192.0.2.1".parse().unwrap()), None);
    }
}
