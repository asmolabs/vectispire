//! Whose word to take for the client's address (`TrustedProxies`) and the budget an address spends
//! (`ClientBuckets`) — the two rules every limiter and every audit entry reads.
//!
//! Empty configuration means "nothing in front of us": `X-Forwarded-For` and `X-Forwarded-Proto` are ignored and the
//! peer address is what is counted. Behind a balancer, name it (`VECTISPIRE_TRUSTED_PROXIES`: addresses or CIDRs,
//! comma-separated) or the whole estate shares one bucket and every audit entry names the balancer (decision 0038).

use ipnet::IpNet;
use std::net::IpAddr;
use vectispire_domain::java;

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

    /// Whether `address` is one of the proxies, read as [`address_literal`] reads a hop — a port dropped, brackets
    /// holding IPv6 only. A value that is not an address matches nothing.
    pub fn is_trusted(&self, address: &str) -> bool {
        address_literal(address).is_some_and(|literal| self.matches(&literal))
    }

    fn matches(&self, literal: &str) -> bool {
        of_literal(literal).is_some_and(|address| self.nets.iter().any(|net| net.contains(&address)))
    }

    /// The client's address: the peer unless the peer is a trusted proxy, in which case the right-most
    /// `X-Forwarded-For` hop that is not itself a trusted proxy. When every hop claims to be one, the peer — a
    /// real address rather than a claimed one.
    ///
    /// As Java 1.0's `TrustedProxies` reads it: **every** `X-Forwarded-For` line, each hop through
    /// [`address_literal`] (a balancer's port dropped), and a hop that is no address at all (`unknown`, an obfuscated
    /// identifier) ends the walk at the nearest trusted proxy — a claim the chain cannot read is not a client.
    pub fn client_address<'a>(&self, peer: Option<&str>, forwarded_for: impl IntoIterator<Item = &'a str>) -> String {
        let remote = peer.unwrap_or("unknown");
        let peer = address_literal(remote).unwrap_or_else(|| remote.to_owned());
        if !self.is_trusted(&peer) {
            return peer;
        }
        let hops: Vec<&str> = forwarded_for
            .into_iter()
            .flat_map(|line| line.split(','))
            .map(str::trim)
            .filter(|hop| !hop.is_empty())
            .collect();
        let mut nearest_trusted = peer.clone();
        for hop in hops.iter().rev() {
            let Some(literal) = address_literal(hop) else {
                return nearest_trusted;
            };
            if !self.matches(&literal) {
                return literal;
            }
            nearest_trusted = literal;
        }
        // Every hop claims to be a trusted proxy: nothing identifies a client, and the peer is a real address.
        peer
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

/// `ClientBuckets.of`: the key an address is counted under — its own text for IPv4 (an IPv4-mapped IPv6 address
/// counts as the IPv4 one), the `/64` for IPv6, since a client rotates through a whole `/64` for free and counting
/// addresses would count nothing. What is not an address literal is kept as it came, blank included.
///
/// **Java's grammar, not the standard library's.** `InetAddress.ofLiteral` reads `1.2.3` as `1.2.0.3`, `01.2.3.4` as
/// `1.2.3.4` and `fe80::1%1` as an address; `str::parse` refuses all three, and each was then a bucket of its own on
/// one side and the address's on the other — a budget that changes with the control plane's language. Held to
/// `reference/sign-in/` (`SignInReferenceSetTest`).
pub fn client_bucket(address: &str) -> String {
    if java::is_blank(address) {
        return address.to_owned();
    }
    // Java 1.0 reads the hop through `AddressLiterals` first: a port a balancer appended is dropped, and brackets hold
    // IPv6 only. Before, `203.0.113.7:51234` was kept whole, so each new source port of one client was a new client
    // to the throttles.
    let Some(literal) = address_literal(address) else {
        return address.to_owned();
    };
    match of_literal(&literal) {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => {
            let prefix: String = v6.octets().iter().take(8).map(|byte| format!("{byte:02x}")).collect();
            format!("{prefix}::/64")
        }
        None => address.to_owned(),
    }
}

/// `AddressLiterals.of`: the literal a forwarded hop names — without brackets or a port, otherwise as written — or
/// `None` when the hop is no IP address literal (`unknown`, an obfuscated identifier, a host name, junk). A bare IPv6
/// literal has colons and no port, so a port is read only off a bracketed literal or a value with exactly one colon
/// (an IPv4 address and its port).
#[must_use]
pub fn address_literal(hop: &str) -> Option<String> {
    let value = java::trim(hop);
    if let Some(after) = value.strip_prefix('[') {
        let (inner, rest) = after.split_once(']')?;
        if !rest.is_empty() && !is_port(rest) {
            return None;
        }
        // Brackets hold an IPv6 literal and nothing else (RFC 3986, RFC 7239).
        return (inner.contains(':') && of_literal(inner).is_some()).then(|| inner.to_owned());
    }
    if let Some(colon) = value.find(':')
        && value.rfind(':') == Some(colon)
    {
        let (host, port) = value.split_at(colon);
        return (is_port(port) && ipv4_literal(host).is_some()).then(|| host.to_owned());
    }
    of_literal(value).map(|_| value.to_owned())
}

/// `:` and one to five ASCII digits.
fn is_port(suffix: &str) -> bool {
    let digits = suffix.strip_prefix(':').unwrap_or("");
    (1..=5).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// `InetAddress.ofLiteral`: IPv4 first, then IPv6 — the IPv4-mapped form answered as the IPv4 address it maps.
fn of_literal(text: &str) -> Option<IpAddr> {
    if let Some(v4) = ipv4_literal(text) {
        return Some(IpAddr::V4(v4.into()));
    }
    ipv6_literal(text)
}

/// `IPAddressUtil.textToNumericFormatV4`: one to four dot-separated decimal parts of ASCII digits, leading zeros
/// allowed, at most fifteen characters in all; the last part fills the bytes the others left (`1.2.3` is `1.2.0.3`).
fn ipv4_literal(text: &str) -> Option<[u8; 4]> {
    if text.is_empty() || java::utf16_len(text) > 15 {
        return None;
    }
    let mut bytes = Vec::with_capacity(4);
    let (mut value, mut new_part) = (0u64, true);
    for c in text.chars() {
        if c == '.' {
            if new_part || bytes.len() == 3 {
                return None;
            }
            bytes.push(u8::try_from(value).ok()?);
            (value, new_part) = (0, true);
        } else {
            // Fifteen characters at most, so a part fits a `u64` long before it could overflow.
            value = value.checked_mul(10)?.checked_add(u64::from(c.to_digit(10)?))?;
            new_part = false;
        }
    }
    let left = 4usize.checked_sub(bytes.len())?;
    if new_part || value >= 1u64.checked_shl(u32::try_from(left.checked_mul(8)?).ok()?)? {
        return None;
    }
    bytes.extend(value.to_be_bytes().iter().skip(8usize.checked_sub(left)?));
    bytes.try_into().ok()
}

/// `Inet6Address.ofLiteral`: brackets around the whole taken off, then a scope that is a number up to
/// `Integer.MAX_VALUE` accepted and forgotten. A scope naming an interface is refused: Java resolves it against the
/// host's own interfaces, which a client's address has nothing to do with, and fails when there is none.
fn ipv6_literal(text: &str) -> Option<IpAddr> {
    let literal = match text.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
        Some(inner) if java::utf16_len(text) > 2 => inner,
        _ => text,
    };
    let (body, zone) = match literal.split_once('%') {
        Some((body, zone)) => (body, Some(zone)),
        None => (literal, None),
    };
    if zone.is_some_and(|zone| !numeric_zone(zone)) {
        return None;
    }
    let bytes = ipv6_bytes(literal, body)?;
    let address = std::net::Ipv6Addr::from(bytes);
    match address.to_ipv4_mapped() {
        // `IPv4-mapped address must not contain zone-id`.
        Some(v4) if zone.is_none() => Some(IpAddr::V4(v4)),
        Some(_) => None,
        None => Some(IpAddr::V6(address)),
    }
}

/// `Inet6Address.checkNumericZone`: ASCII digits, refused once past `Integer.MAX_VALUE`.
fn numeric_zone(zone: &str) -> bool {
    zone.chars()
        .try_fold(0i32, |value, c| value.checked_mul(10)?.checked_add(i32::try_from(c.to_digit(10)?).ok()?))
        .is_some()
}

/// `IPAddressUtil.textToNumericFormatV6` over `body` — `literal` before its first `%`: groups of hex digits whose
/// value fits sixteen bits (so `00001` is a group), one `::`, and an IPv4 tail of exactly three dots read as
/// [`ipv4_literal`] reads it.
fn ipv6_bytes(literal: &str, body: &str) -> Option<[u8; 16]> {
    // The shortest literal is `::`; a `%` ending the literal names no zone.
    if java::utf16_len(literal) < 2 || (literal.ends_with('%') && literal.find('%') == literal.len().checked_sub(1)) {
        return None;
    }
    let chars: Vec<char> = body.chars().collect();
    let mut position = 0usize;
    if literal.starts_with(':') {
        if literal.chars().nth(1) != Some(':') {
            return None;
        }
        position = 1;
    }
    let mut out: Vec<u8> = Vec::with_capacity(16);
    let (mut gap, mut token, mut value, mut saw_digit) = (None, position, 0u32, false);
    while let Some(&c) = chars.get(position) {
        position = position.checked_add(1)?;
        if let Some(digit) = c.to_digit(16) {
            value = value.checked_shl(4)? | digit;
            if value > 0xffff {
                return None;
            }
            saw_digit = true;
        } else if c == ':' {
            token = position;
            if !saw_digit {
                if gap.is_some() {
                    return None;
                }
                gap = Some(out.len());
            } else if position == chars.len() || out.len() > 14 {
                return None;
            } else {
                out.extend(u16::try_from(value).ok()?.to_be_bytes());
                (value, saw_digit) = (0, false);
            }
        } else if c == '.' && out.len() <= 12 {
            let tail: String = chars.get(token..)?.iter().collect();
            if tail.matches('.').count() != 3 {
                return None;
            }
            out.extend(ipv4_literal(&tail)?);
            saw_digit = false;
            break;
        } else {
            return None;
        }
    }
    if saw_digit {
        if out.len() > 14 {
            return None;
        }
        out.extend(u16::try_from(value).ok()?.to_be_bytes());
    }
    if let Some(gap) = gap {
        if out.len() == 16 {
            return None;
        }
        let tail = out.split_off(gap);
        out.resize(16usize.checked_sub(tail.len())?, 0);
        out.extend(tail);
    }
    out.try_into().ok()
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
        assert_eq!(none.client_address(Some("192.0.2.9"), ["203.0.113.5"]), "192.0.2.9");
        assert!(!none.is_secure_transport(Some("192.0.2.9"), false, Some("https")));
    }

    #[test]
    fn a_trusted_peer_hands_over_the_rightmost_hop_that_is_not_a_proxy() {
        let list = proxies("10.0.0.0/8, 192.0.2.7");
        assert_eq!(list.client_address(Some("10.1.2.3"), ["203.0.113.5, 198.51.100.9, 10.9.9.9"]), "198.51.100.9");
        assert_eq!(list.client_address(Some("192.0.2.7"), ["203.0.113.5"]), "203.0.113.5");
    }

    #[test]
    fn a_client_cannot_forge_the_header_when_the_peer_is_not_trusted() {
        let list = proxies("10.0.0.0/8");
        assert_eq!(list.client_address(Some("203.0.113.5"), ["198.51.100.9"]), "203.0.113.5");
    }

    #[test]
    fn every_hop_claiming_to_be_a_proxy_leaves_the_peer() {
        let list = proxies("10.0.0.0/8");
        assert_eq!(list.client_address(Some("10.0.0.1"), ["10.0.0.2, 10.0.0.3"]), "10.0.0.1");
        assert_eq!(list.client_address(Some("10.0.0.1"), ["  "]), "10.0.0.1");
        assert_eq!(list.client_address(None, []), "unknown");
    }

    #[test]
    fn a_header_value_that_is_not_an_address_matches_nothing() {
        let list = proxies("10.0.0.0/8");
        assert!(!list.is_trusted("not-an-address"));
        assert_eq!(
            list.client_address(Some("10.0.0.1"), ["not-an-address"]),
            "10.0.0.1",
            "a hop no address answers the nearest trusted proxy"
        );
        assert_eq!(
            list.client_address(Some("10.0.0.1"), ["203.0.113.5:51234"]),
            "203.0.113.5",
            "a balancer's port is dropped"
        );
        assert_eq!(
            list.client_address(Some("10.0.0.1"), ["203.0.113.5", "10.0.0.2"]),
            "203.0.113.5",
            "every line is read"
        );
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
