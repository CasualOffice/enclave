//! Named trusted network zones (`docs/06-SECURITY-DLP-ACCESS.md §7.2`).
//!
//! An administrator names networks — "Corporate India", "VPN", "HQ", "Datacenter" — and writes
//! rules against the names rather than against CIDRs. The indirection is what makes a rule
//! survivable: renumbering a datacenter changes one zone definition instead of every rule that
//! mentioned its prefix, and a rule that reads `NOT IN [Corporate India]` is reviewable by somebody
//! who does not know which prefixes that is.
//!
//! # Zones are resolved once, against the resolved client address only
//!
//! `docs/06 §7.3` requires geo and ASN lookups to run on the resolved address and no other. The
//! same applies here for the same reason: a zone computed from the socket peer would put every
//! request behind a load balancer inside the load balancer's zone, which is both wrong and
//! *permissive* — it is the datacenter, and the datacenter is usually trusted.

use core::net::IpAddr;

use enclave_config::NetworkZoneConfig;
use ipnetwork::IpNetwork;

/// One administrator-defined zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkZone {
    name: String,
    networks: Vec<IpNetwork>,
}

impl NetworkZone {
    /// Defines a zone.
    #[must_use]
    pub fn new(name: impl Into<String>, networks: impl IntoIterator<Item = IpNetwork>) -> Self {
        Self { name: name.into(), networks: networks.into_iter().collect() }
    }

    /// The zone's name, as rules refer to it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the address falls inside this zone.
    ///
    /// A zone with no networks contains nothing. That is deliberate and is the opposite of the
    /// usual "empty means any" convention: a half-written zone must not silently become a zone
    /// every address is inside, because the rules referring to it are the ones that grant access.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(addr))
    }
}

/// Every zone this deployment knows about.
#[derive(Debug, Clone, Default)]
pub struct ZoneMap {
    zones: Vec<NetworkZone>,
}

impl ZoneMap {
    /// No zones defined: every address is outside every zone, and `is_trusted_zone` is false for
    /// all traffic.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a map from zone definitions.
    #[must_use]
    pub fn new(zones: impl IntoIterator<Item = NetworkZone>) -> Self {
        Self { zones: zones.into_iter().collect() }
    }

    /// Builds a map from what an operator wrote in `enclave.yaml`.
    #[must_use]
    pub fn from_config(zones: &[NetworkZoneConfig]) -> Self {
        Self::new(
            zones.iter().map(|zone| NetworkZone::new(&zone.name, zone.networks.iter().copied())),
        )
    }

    /// Whether any zone is defined at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// The names of every zone containing `addr`, in definition order.
    ///
    /// An address can be in several — a VPN egress inside the datacenter range is both — so this
    /// returns all of them rather than the first. A rule asking about one zone must not be
    /// answered by whichever zone happened to be listed first in the file.
    #[must_use]
    pub fn zones_for(&self, addr: IpAddr) -> Vec<String> {
        self.zones.iter().filter(|zone| zone.contains(addr)).map(|zone| zone.name.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn map() -> ZoneMap {
        ZoneMap::new([
            NetworkZone::new("Corporate India", ["203.0.113.0/24".parse().unwrap()]),
            NetworkZone::new(
                "VPN",
                ["203.0.113.128/25".parse().unwrap(), "198.51.100.0/24".parse().unwrap()],
            ),
            NetworkZone::new("Empty", []),
        ])
    }

    #[test]
    fn an_address_reports_every_zone_it_is_inside() {
        let map = map();
        assert_eq!(map.zones_for("203.0.113.200".parse().unwrap()), ["Corporate India", "VPN"]);
        assert_eq!(map.zones_for("203.0.113.5".parse().unwrap()), ["Corporate India"]);
        assert_eq!(map.zones_for("198.51.100.9".parse().unwrap()), ["VPN"]);
        assert!(map.zones_for("192.0.2.1".parse().unwrap()).is_empty());
    }

    #[test]
    fn a_zone_with_no_networks_contains_nothing_rather_than_everything() {
        let zone = NetworkZone::new("Empty", []);
        assert!(!zone.contains("203.0.113.5".parse().unwrap()));
        assert!(!map().zones_for("203.0.113.5".parse().unwrap()).contains(&"Empty".to_owned()));
    }
}
