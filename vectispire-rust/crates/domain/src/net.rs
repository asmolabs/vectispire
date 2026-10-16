//! Whether a host is, or resolves to, an instance metadata address — `LinkLocalHosts` and the
//! part of `IpAddresses` it rests on.
//!
//! **For the one outbound path that does not go through the control plane's guard: the clone.**
//! Private ranges stay allowed — a self-hosted forge on the internal network is the ordinary case
//! — and the metadata endpoints are refused under every policy, decided on the address bytes so
//! that no spelling of an address reaches what another spelling was refused for.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// True when `host` is an address literal in the link-local range or a metadata address.
///
/// A literal is read as `InetAddress.ofLiteral` reads one: IPv6, or IPv4 in any of the four
/// decimal forms `d.d.d.d`, `d.d.d`, `d.d` and `d` — `169.254.43518` is `169.254.169.254` to a
/// socket, and refusing only the dotted quad would refuse one spelling of it.
pub fn is_link_local_literal(host: &str) -> bool {
    parse_literal(unbracketed(host)).is_some_and(is_metadata)
}

/// True when any address `host` resolves to is link-local or a metadata address.
///
/// A name that does not resolve is not refused here: the clone fails on it with its own, clearer
/// message. This narrows the window rather than closing it — the transport resolves again when it
/// connects — but it stops the plain case, a name pointed at the metadata endpoint.
pub fn resolves_to_link_local(host: &str) -> bool {
    if is_link_local_literal(host) {
        return true;
    }
    match (unbracketed(host), 0u16).to_socket_addrs() {
        Ok(addresses) => addresses.map(|address| address.ip()).any(is_metadata),
        Err(_) => false,
    }
}

/// An address literal, or `None` for a host name.
pub fn parse_literal(text: &str) -> Option<IpAddr> {
    if let Ok(v6) = text.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    parse_ipv4_literal(text).map(IpAddr::V4)
}

/// IPv4 in the decimal forms the JDK accepts: one to four parts, the last filling what is left.
fn parse_ipv4_literal(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut values = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.is_empty() || part.len() > 10 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        values.push(part.parse::<u64>().ok()?);
    }
    let (leading, last) = values.split_at(values.len() - 1);
    if leading.iter().any(|value| *value > 0xff) {
        return None;
    }
    let last_bits = 8 * (4 - leading.len() as u32);
    if last[0] >= (1u64 << last_bits) {
        return None;
    }
    let mut address: u64 = 0;
    for (index, value) in leading.iter().enumerate() {
        address |= value << (24 - 8 * index as u32);
    }
    address |= last[0];
    Some(Ipv4Addr::from(u32::try_from(address).ok()?))
}

fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host)
}

/// Link-local, or one of the metadata services that live elsewhere.
pub fn is_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_link_local_v4(v4) || is_metadata_v4(v4),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => is_link_local_v4(v4) || is_metadata_v4(v4),
            None => is_link_local_v6(v6) || v6 == AWS_METADATA_V6,
        },
    }
}

/// `fd00:ec2::254`, AWS's metadata endpoint for IPv6-only instances.
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

fn is_link_local_v4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    a == 169 && b == 254
}

/// Alibaba Cloud's `100.100.100.200`, Oracle's legacy `192.0.0.192`, Azure's WireServer
/// `168.63.129.16`: each in a range the internal policies accept, so refused by address.
fn is_metadata_v4(address: Ipv4Addr) -> bool {
    [Ipv4Addr::new(100, 100, 100, 200), Ipv4Addr::new(192, 0, 0, 192), Ipv4Addr::new(168, 63, 129, 16)]
        .contains(&address)
}

fn is_link_local_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    first & 0xffc0 == 0xfe80
}

/// The IPv4 an IPv6 carries, in each of the spellings that reach it: mapped, NAT64 (public and
/// local-use), 6to4, Teredo, and the obsolete compatible form.
fn embedded_v4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let bytes = address.octets();
    let last_four = |b: &[u8; 16]| Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let prefix = &bytes[..12];
    if prefix == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        || prefix == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
        || bytes[..6] == [0, 0x64, 0xff, 0x9b, 0, 0x01]
    {
        return Some(last_four(&bytes));
    }
    if bytes[..2] == [0x20, 0x02] {
        return Some(Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]));
    }
    if bytes[..4] == [0x20, 0x01, 0, 0] {
        return Some(Ipv4Addr::new(!bytes[12], !bytes[13], !bytes[14], !bytes[15]));
    }
    // `::` and `::1` are the unspecified address and loopback, not wrapped IPv4s.
    let tail = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if prefix.iter().all(|b| *b == 0) && tail > 1 {
        return Some(last_four(&bytes));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_the_metadata_endpoint_is_refused() {
        for host in [
            "169.254.169.254",
            "169.254.43518",
            "169.16689662",
            "2852039166",
            "[::ffff:169.254.169.254]",
            "::ffff:a9fe:a9fe",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::",
            "fe80::1",
            "fd00:ec2::254",
            "100.100.100.200",
            "168.63.129.16",
        ] {
            assert!(is_link_local_literal(host), "{host} should be refused");
        }
    }

    #[test]
    fn private_ranges_and_names_are_not_refused_as_literals() {
        for host in ["10.0.0.1", "192.168.1.1", "gitlab.example.org", "::1", "::", "256.1.1.1", "1.2.3.4.5"] {
            assert!(!is_link_local_literal(host), "{host} should not be refused as a literal");
        }
    }
}
