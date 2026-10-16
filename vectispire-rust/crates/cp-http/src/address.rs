//! Whose word to take for the client's address (`TrustedProxies`) and the budget an address spends
//! (`ClientBuckets`) — the two rules every limiter and every audit entry reads.
//!
//! Empty configuration means "nothing in front of us": `X-Forwarded-For` and `X-Forwarded-Proto` are ignored and the
//! peer address is what is counted. Behind a balancer, name it (`VECTISPIRE_TRUSTED_PROXIES`: addresses or CIDRs,
//! comma-separated) or the whole estate shares one bucket and every audit entry names the balancer (decision 0038).

use ipnet::IpNet;
use std::net::IpAddr;

/// The addresses whose `X-Forwarded-*` headers are believed.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

/// A trusted-proxies entry that is neither an address nor a CIDR. Refused at start-up rather than ignored: a
/// typo here silently turns a deployment's limiter into one bucket for everybody.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("'{0}' is neither an address nor a CIDR range")]
pub struct BadProxyEntry(pub String);

impl TrustedProxies {
    pub fn none() -> TrustedProxies {
        TrustedProxies::default()
    }

    /// `10.0.0.0/8, 192.0.2.7, 2001:db8::/32` — blank entries are skipped, as the Java parse does.
    pub fn parse(configured: &str) -> Result<TrustedProxies, BadProxyEntry> {
        let mut nets = Vec::new();
        for entry in configured.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
            let net = if entry.contains('/') {
                entry.parse::<IpNet>().map_err(|_| BadProxyEntry(entry.to_owned()))?
            } else {
                IpNet::from(entry.parse::<IpAddr>().map_err(|_| BadProxyEntry(entry.to_owned()))?)
            };
            nets.push(net);
        }
        Ok(TrustedProxies { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `address` is one of the proxies. A value that is not an address matches nothing.
    pub fn is_trusted(&self, address: &str) -> bool {
        match address.trim().parse::<IpAddr>() {
            Ok(address) => self.nets.iter().any(|net| net.contains(&address)),
            Err(_) => false,
        }
    }

    /// The client's address: the peer unless the peer is a trusted proxy, in which case the right-most
    /// `X-Forwarded-For` hop that is not itself a trusted proxy. When every hop claims to be one, the peer — a
    /// real address rather than a claimed one.
    pub fn client_address(&self, peer: Option<&str>, forwarded_for: Option<&str>) -> String {
        let peer = peer.unwrap_or("unknown");
        if !self.is_trusted(peer) {
            return peer.to_owned();
        }
        let Some(forwarded) = forwarded_for.filter(|value| !value.trim().is_empty()) else {
            return peer.to_owned();
        };
        for hop in forwarded.split(',').rev().map(str::trim) {
            if !hop.is_empty() && !self.is_trusted(hop) {
                return hop.to_owned();
            }
        }
        peer.to_owned()
    }

    /// Whether the request reached us over TLS: the peer said so, or a trusted proxy said it terminated it.
    pub fn is_secure_transport(&self, peer: Option<&str>, secure_peer: bool, forwarded_proto: Option<&str>) -> bool {
        if secure_peer {
            return true;
        }
        if !peer.is_some_and(|peer| self.is_trusted(peer)) {
            return false;
        }
        forwarded_proto
            .and_then(|value| value.split(',').next())
            .is_some_and(|first| first.trim().eq_ignore_ascii_case("https"))
    }
}

/// The key an address is counted under: its own text for IPv4 (an IPv4-mapped IPv6 address counts as the IPv4
/// one), the `/64` for IPv6 — a client rotates through a whole `/64` for free, so counting addresses would count
/// nothing. What is not an address is kept as it came.
pub fn client_bucket(address: &str) -> String {
    let trimmed = address.trim();
    let literal = trimmed.strip_prefix('[').unwrap_or(trimmed);
    let literal = literal.strip_suffix(']').unwrap_or(literal);
    match literal.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let octets = v6.octets();
                let prefix: String = octets.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
                format!("{prefix}::/64")
            }
        },
        Err(_) => address.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies(configured: &str) -> TrustedProxies {
        TrustedProxies::parse(configured).expect("a valid list")
    }

    #[test]
    fn nothing_configured_means_the_peer_is_the_client() {
        let none = TrustedProxies::none();
        assert_eq!(none.client_address(Some("192.0.2.9"), Some("203.0.113.5")), "192.0.2.9");
        assert!(!none.is_secure_transport(Some("192.0.2.9"), false, Some("https")));
    }

    #[test]
    fn a_trusted_peer_hands_over_the_rightmost_hop_that_is_not_a_proxy() {
        let list = proxies("10.0.0.0/8, 192.0.2.7");
        assert_eq!(list.client_address(Some("10.1.2.3"), Some("203.0.113.5, 198.51.100.9, 10.9.9.9")), "198.51.100.9");
        assert_eq!(list.client_address(Some("192.0.2.7"), Some("203.0.113.5")), "203.0.113.5");
    }

    #[test]
    fn a_client_cannot_forge_the_header_when_the_peer_is_not_trusted() {
        let list = proxies("10.0.0.0/8");
        assert_eq!(list.client_address(Some("203.0.113.5"), Some("198.51.100.9")), "203.0.113.5");
    }

    #[test]
    fn every_hop_claiming_to_be_a_proxy_leaves_the_peer() {
        let list = proxies("10.0.0.0/8");
        assert_eq!(list.client_address(Some("10.0.0.1"), Some("10.0.0.2, 10.0.0.3")), "10.0.0.1");
        assert_eq!(list.client_address(Some("10.0.0.1"), Some("  ")), "10.0.0.1");
        assert_eq!(list.client_address(None, None), "unknown");
    }

    #[test]
    fn a_header_value_that_is_not_an_address_matches_nothing() {
        let list = proxies("10.0.0.0/8");
        assert!(!list.is_trusted("not-an-address"));
        assert_eq!(list.client_address(Some("10.0.0.1"), Some("not-an-address")), "not-an-address");
    }

    #[test]
    fn a_bad_entry_is_refused_at_start_up_and_a_blank_list_is_empty() {
        assert!(matches!(TrustedProxies::parse("10.0.0.0/8, nope"), Err(BadProxyEntry(entry)) if entry == "nope"));
        assert!(TrustedProxies::parse("10.0.0.0/99").is_err());
        assert!(TrustedProxies::parse(" , ").is_ok_and(|list| list.is_empty()));
    }

    #[test]
    fn tls_ends_at_a_trusted_proxy_only_when_it_says_so() {
        let list = proxies("10.0.0.0/8");
        assert!(list.is_secure_transport(Some("10.0.0.1"), false, Some("https, http")));
        assert!(!list.is_secure_transport(Some("10.0.0.1"), false, Some("http")));
        assert!(!list.is_secure_transport(Some("203.0.113.5"), false, Some("https")));
        assert!(list.is_secure_transport(Some("203.0.113.5"), true, None));
    }

    #[test]
    fn an_ipv6_client_is_counted_by_its_slash_64() {
        assert_eq!(client_bucket("2001:db8:1:2::1"), client_bucket("2001:db8:1:2:abcd:ef01:2345:6789"));
        assert_eq!(client_bucket("2001:db8:1:2::1"), client_bucket("[2001:db8:1:2::ffff]"));
        assert_ne!(client_bucket("2001:db8:1:2::1"), client_bucket("2001:db8:1:3::1"));
        assert_eq!(client_bucket("2001:db8:1:2::1"), "20010db800010002::/64");
    }

    #[test]
    fn an_ipv4_client_wrapped_or_not_is_its_address_and_the_rest_stays_as_it_came() {
        assert_eq!(client_bucket("192.0.2.10"), "192.0.2.10");
        assert_eq!(client_bucket("::ffff:192.0.2.10"), "192.0.2.10");
        assert_ne!(client_bucket("192.0.2.10"), client_bucket("192.0.2.11"));
        assert_eq!(client_bucket("unknown"), "unknown");
    }
}
