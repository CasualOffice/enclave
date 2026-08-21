//! D30 — a forwarding header is believed only from a configured network, hop by hop.
//!
//! `plans/M4-GOVERNANCE.md`'s exit criterion is *"a forged `X-Forwarded-For` from an untrusted peer
//! is ignored"*, which is an assertion about an absence and therefore passes for free against a
//! resolver that ignores the header unconditionally — or against one that never runs at all
//! (`docs/12-TESTING.md §1.2`). Every negative assertion here is paired with a **positive control**
//! that runs the same call with the peer genuinely trusted and requires the header to be honoured.
//!
//! The two classic wrong implementations each have a test named for them, and the fixtures are
//! chosen so that "leftmost", "first public address" and the correct answer are three *different*
//! addresses. A table where any two coincided would let a wrong implementation pass.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::net::IpAddr;

use enclave_conditional_access::ProxyTrust;
use enclave_config::TrustedProxy;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test fixture is an address")
}

fn proxy(cidr: &str, hops: u8) -> TrustedProxy {
    TrustedProxy { cidr: cidr.parse().expect("test fixture is a CIDR"), hops }
}

/// One trusted edge at `10.0.0.0/8`, one hop deep — the commonest real deployment.
fn one_hop() -> ProxyTrust {
    ProxyTrust::new([proxy("10.0.0.0/8", 1)])
}

// --- The exit criterion, with its positive control ---------------------------------------------

/// The M4 exit criterion, and the control that stops it passing for free.
///
/// Both halves call the *same* `resolve` on the *same* header with the *same* configuration. The
/// only thing that differs is the peer address. A resolver that ignored `X-Forwarded-For`
/// unconditionally would satisfy the first assertion and fail the second; one that believed it
/// unconditionally would fail the first.
#[test]
fn a_forged_forwarded_for_is_ignored_from_an_untrusted_peer_and_honoured_from_a_trusted_one() {
    let trust = one_hop();
    let forged = "8.8.8.8";

    // The attacker connects directly and claims to be Google's resolver.
    let untrusted = trust.resolve(ip("198.51.100.66"), [forged]);
    assert_eq!(untrusted.ip(), ip("198.51.100.66"), "the forged value became the source address");
    assert_ne!(untrusted.ip(), ip(forged));
    assert!(!untrusted.via_trusted_proxy());
    assert!(!untrusted.peer_is_trusted_proxy());
    assert_eq!(untrusted.hops_honoured(), 0);

    // Positive control: the identical header, believed, because the peer is a configured proxy.
    let trusted = trust.resolve(ip("10.0.0.7"), [forged]);
    assert_eq!(trusted.ip(), ip(forged), "a trusted proxy's forwarded address was not honoured");
    assert!(trusted.via_trusted_proxy());
    assert_eq!(trusted.hops_honoured(), 1);
}

// --- The two shortcuts D30 forbids by name -----------------------------------------------------

/// `X-Forwarded-For: 10.9.9.9, 203.0.113.9, 192.0.2.44` with one trusted hop.
///
/// The three candidate answers are deliberately distinct:
///
/// * leftmost — `10.9.9.9`, entirely attacker-controlled;
/// * first public address — `203.0.113.9`, also attacker-controlled;
/// * correct — `192.0.2.44`, the entry the trusted proxy itself appended.
#[test]
fn the_leftmost_entry_is_never_the_answer() {
    let resolved = one_hop().resolve(ip("10.0.0.7"), ["10.9.9.9, 203.0.113.9, 192.0.2.44"]);
    assert_eq!(resolved.ip(), ip("192.0.2.44"));
    assert_ne!(resolved.ip(), ip("10.9.9.9"), "leftmost-wins: a client can claim any address");
}

#[test]
fn the_first_public_address_is_never_the_answer() {
    let resolved = one_hop().resolve(ip("10.0.0.7"), ["10.9.9.9, 203.0.113.9, 192.0.2.44"]);
    assert_eq!(resolved.ip(), ip("192.0.2.44"));
    assert_ne!(
        resolved.ip(),
        ip("203.0.113.9"),
        "first-public-address: the same defect wearing a disguise"
    );
}

// --- Hop stripping, table driven ---------------------------------------------------------------

struct Case {
    /// What the case is proving, used as the assertion message.
    name: &'static str,
    trust: ProxyTrust,
    peer: &'static str,
    /// Raw header values, in arrival order — one entry per header line.
    forwarded: &'static [&'static str],
    expect_ip: &'static str,
    expect_hops: u8,
}

#[test]
fn hop_stripping_walks_the_chain_from_the_right_and_stops_when_it_stops_believing() {
    let cases = [
        Case {
            name: "no header at all: the peer is the client, and nothing was relayed",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &[],
            expect_ip: "10.0.0.7",
            expect_hops: 0,
        },
        Case {
            name: "an empty trusted-proxy list never reads the header",
            trust: ProxyTrust::none(),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44"],
            expect_ip: "10.0.0.7",
            expect_hops: 0,
        },
        Case {
            name: "exactly one hop configured, exactly one entry",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44"],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
        Case {
            name: "more entries than hops: the excess is discarded, not merged",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["203.0.113.9, 198.51.100.7, 192.0.2.44"],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
        Case {
            name: "two hops, both intermediates trusted: two entries are believed",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 2)]),
            peer: "10.0.0.7",
            forwarded: &["203.0.113.9, 192.0.2.44, 10.0.0.9"],
            expect_ip: "192.0.2.44",
            expect_hops: 2,
        },
        Case {
            name: "two hops but the intermediate is not trusted: the walk stops after one",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 2)]),
            peer: "10.0.0.7",
            forwarded: &["203.0.113.9, 192.0.2.44, 198.51.100.7"],
            expect_ip: "198.51.100.7",
            expect_hops: 1,
        },
        Case {
            name: "fewer entries than hops: the chain runs out and no hop is invented",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 3)]),
            peer: "10.0.0.7",
            forwarded: &["10.0.0.9"],
            expect_ip: "10.0.0.9",
            expect_hops: 1,
        },
        Case {
            name: "no entries at all with hops configured: the peer survives",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 3)]),
            peer: "10.0.0.7",
            forwarded: &[""],
            expect_ip: "10.0.0.7",
            expect_hops: 0,
        },
        Case {
            name: "a malformed rightmost entry stops the walk at the peer",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44, unknown"],
            expect_ip: "10.0.0.7",
            expect_hops: 0,
        },
        Case {
            name: "a malformed entry mid-walk stops the walk where it is",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 3)]),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44, _obfuscated, 10.0.0.9"],
            expect_ip: "10.0.0.9",
            expect_hops: 1,
        },
        Case {
            name: "hops: 0 on a trusted network strips nothing",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 0)]),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44"],
            expect_ip: "10.0.0.7",
            expect_hops: 0,
        },
        Case {
            name: "several header lines are one chain, read in arrival order",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 2)]),
            peer: "10.0.0.7",
            forwarded: &["203.0.113.9", "192.0.2.44, 10.0.0.9"],
            expect_ip: "192.0.2.44",
            expect_hops: 2,
        },
        Case {
            name: "several header lines: the rightmost entry of the last line is popped first",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["203.0.113.9", "192.0.2.44"],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
        Case {
            name: "an IPv4 entry carrying a port",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44:41234"],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
        Case {
            name: "a bare IPv6 entry",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["2001:db8::beef"],
            expect_ip: "2001:db8::beef",
            expect_hops: 1,
        },
        Case {
            name: "a bracketed IPv6 entry carrying a port",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["[2001:db8::beef]:443"],
            expect_ip: "2001:db8::beef",
            expect_hops: 1,
        },
        Case {
            name: "an IPv6 trusted proxy strips an IPv6 chain",
            trust: ProxyTrust::new([proxy("2001:db8:aaaa::/48", 1)]),
            peer: "2001:db8:aaaa::1",
            forwarded: &["[2001:db8::beef]:443"],
            expect_ip: "2001:db8::beef",
            expect_hops: 1,
        },
        Case {
            name: "an IPv4-mapped peer still matches the IPv4 network it is written as",
            trust: one_hop(),
            peer: "::ffff:10.0.0.7",
            forwarded: &["192.0.2.44"],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
        Case {
            name: "an IPv4-mapped chain entry is collapsed before it is trusted onwards",
            trust: ProxyTrust::new([proxy("10.0.0.0/8", 2)]),
            peer: "10.0.0.7",
            forwarded: &["192.0.2.44, ::ffff:10.0.0.9"],
            expect_ip: "192.0.2.44",
            expect_hops: 2,
        },
        Case {
            name: "whitespace around entries is not a parse failure",
            trust: one_hop(),
            peer: "10.0.0.7",
            forwarded: &["  203.0.113.9 ,   192.0.2.44  "],
            expect_ip: "192.0.2.44",
            expect_hops: 1,
        },
    ];

    for case in &cases {
        let resolved = case.trust.resolve(ip(case.peer), case.forwarded.iter().copied());
        assert_eq!(resolved.ip(), ip(case.expect_ip), "{}", case.name);
        assert_eq!(resolved.hops_honoured(), case.expect_hops, "{}", case.name);
        assert_eq!(
            resolved.via_trusted_proxy(),
            case.expect_hops > 0,
            "{}: via_trusted_proxy must say whether the address was relayed",
            case.name
        );
    }
}

/// `via_trusted_proxy` is about the *address*, not about the peer's membership of a list.
///
/// A trusted proxy that forwards nothing leaves us holding an address we observed ourselves, and
/// saying "this came through a proxy" about it would be a claim we cannot support. The two facts
/// are separate accessors precisely so neither has to stand in for the other.
#[test]
fn a_trusted_peer_that_forwards_nothing_did_not_relay_an_address() {
    let resolved = one_hop().resolve(ip("10.0.0.7"), Vec::<&str>::new());
    assert!(resolved.peer_is_trusted_proxy());
    assert!(!resolved.via_trusted_proxy());
    assert_eq!(resolved.ip(), resolved.peer());
}

/// A client one hop behind a trusted proxy cannot buy extra hops by sending more entries.
///
/// This is the attack the hop count exists to stop: the attacker prepends as many addresses as they
/// like, and every one of them stays to the left of the entry the proxy appended.
#[test]
fn an_attacker_cannot_extend_the_chain_to_reach_further_left() {
    let long = "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6, 7.7.7.7, 192.0.2.44";
    let resolved = one_hop().resolve(ip("10.0.0.7"), [long]);
    assert_eq!(resolved.ip(), ip("192.0.2.44"));
    assert_eq!(resolved.hops_honoured(), 1);
}

/// A client cannot escape the chain by claiming to be a trusted proxy inside the header.
///
/// The peer's hop budget is the budget, and the addresses *inside* the header only ever decide
/// whether the walk may continue — never how far it may go.
#[test]
fn a_forwarded_entry_naming_a_trusted_network_does_not_grant_extra_hops() {
    let resolved = one_hop().resolve(ip("10.0.0.7"), ["8.8.8.8, 10.0.0.99"]);
    assert_eq!(resolved.ip(), ip("10.0.0.99"));
    assert_eq!(resolved.hops_honoured(), 1, "one configured hop must remain one honoured hop");
}
