//! Address classification, decided on the bytes and never on the text — `IpAddresses`.
//!
//! An earlier Java implementation compared string prefixes, and a URL parser normalizes an IPv6
//! address before anyone reads it: `::ffff:127.0.0.1` comes back as `::ffff:7f00:1`, which the
//! pattern matching never saw. Loopback, the private ranges and the metadata endpoint all walked
//! through a guard written that way. So an address is a `Raw` — four or sixteen bytes — and every
//! predicate reads those, whichever way the address was spelled to get here.
//!
//! The agent's `domain::net` holds the one question the clone needs (`is_metadata`); the guard needs
//! the others separately — it words "link-local" and "metadata" as two refusals — and needs the
//! embedded-IPv4 reading they share, which `domain::net` keeps private. It is written out here
//! rather than reached for, so that this crate changes nothing the agent builds on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address as a resolver hands it over: four bytes, or sixteen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Raw {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Raw {
    /// The bytes of `address`, with an IPv4-mapped IPv6 folded down to its IPv4 — as the JDK's
    /// `InetAddress` folds it, in a literal and in a resolver's answer alike.
    pub fn of(address: IpAddr) -> Raw {
        match address {
            IpAddr::V4(v4) => Raw::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Raw::V4(v4.octets()),
                None => Raw::V6(v6.octets()),
            },
        }
    }

    /// The address as a socket takes it: what `InetAddress.getByAddress` builds from these bytes.
    pub fn to_ip(self) -> IpAddr {
        match self {
            Raw::V4(bytes) => IpAddr::V4(Ipv4Addr::from(bytes)),
            Raw::V6(bytes) => match Ipv6Addr::from(bytes).to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(Ipv6Addr::from(bytes)),
            },
        }
    }

    /// `InetAddress.getHostAddress`: IPv4 as a dotted quad, IPv6 as eight groups of lower-case hex
    /// with no leading zeros and **no `::` compression** — the form the refusal messages quote.
    pub fn text(self) -> String {
        match self.to_ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6.segments().iter().map(|group| format!("{group:x}")).collect::<Vec<_>>().join(":"),
        }
    }
}

fn octet(bytes: &[u8], index: usize) -> u8 {
    bytes[index]
}

fn unsigned_int(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

const V4_MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
const NAT64: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
const NAT64_LOCAL: [u8; 6] = [0, 0x64, 0xff, 0x9b, 0, 0x01];
const SIX_TO_FOUR: [u8; 2] = [0x20, 0x02];
const TEREDO: [u8; 4] = [0x20, 0x01, 0, 0];
const AWS_METADATA_V6: [u8; 16] = [0xfd, 0, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54];

/// The IPv4 an IPv6 carries, in each spelling that reaches it: mapped, NAT64 (public and local-use),
/// 6to4, Teredo, and the obsolete `::a.b.c.d`. Each is one more spelling of the same destination,
/// and missing one is enough to reopen the bypass. `::` and `::1` are not wrapped IPv4s.
fn embedded_v4(bytes: &[u8; 16]) -> Option<[u8; 4]> {
    let last_four = || [bytes[12], bytes[13], bytes[14], bytes[15]];
    if bytes[..12] == V4_MAPPED || bytes[..12] == NAT64 || bytes[..6] == NAT64_LOCAL {
        return Some(last_four());
    }
    if bytes[..2] == SIX_TO_FOUR {
        return Some([bytes[2], bytes[3], bytes[4], bytes[5]]);
    }
    if bytes[..4] == TEREDO {
        return Some([!bytes[12], !bytes[13], !bytes[14], !bytes[15]]);
    }
    if all_zero(&bytes[..12]) && unsigned_int(bytes, 12) > 1 {
        return Some(last_four());
    }
    None
}

/// The instance metadata range `169.254.0.0/16` and `fe80::/10`, in IPv4 as in IPv6.
pub fn is_link_local(address: Raw) -> bool {
    match address {
        Raw::V6(bytes) => match embedded_v4(&bytes) {
            Some(v4) => is_link_local_v4(v4),
            None => octet(&bytes, 0) == 0xfe && (octet(&bytes, 1) & 0xc0) == 0x80,
        },
        Raw::V4(bytes) => is_link_local_v4(bytes),
    }
}

fn is_link_local_v4(bytes: [u8; 4]) -> bool {
    bytes[0] == 169 && bytes[1] == 254
}

/// The metadata services outside the link-local range: Alibaba `100.100.100.200`, Oracle's legacy
/// `192.0.0.192`, Azure's WireServer `168.63.129.16`, AWS's `fd00:ec2::254`.
pub fn is_metadata(address: Raw) -> bool {
    match address {
        Raw::V6(bytes) => match embedded_v4(&bytes) {
            Some(v4) => is_metadata_v4(v4),
            None => bytes == AWS_METADATA_V6,
        },
        Raw::V4(bytes) => is_metadata_v4(bytes),
    }
}

fn is_metadata_v4(bytes: [u8; 4]) -> bool {
    [[100, 100, 100, 200], [192, 0, 0, 192], [168, 63, 129, 16]].contains(&bytes)
}

/// `0.0.0.0/8` and `::`: no host, but a connection to them reaches this machine, as loopback would.
pub fn is_unspecified(address: Raw) -> bool {
    match address {
        Raw::V6(bytes) => embedded_v4(&bytes).map_or_else(|| all_zero(&bytes), |v4| v4[0] == 0),
        Raw::V4(bytes) => bytes[0] == 0,
    }
}

/// `127.0.0.0/8` and `::1`, however wrapped: one machine, whichever of its addresses is written.
pub fn is_loopback(address: Raw) -> bool {
    match address {
        Raw::V6(bytes) => match embedded_v4(&bytes) {
            Some(v4) => v4[0] == 127,
            None => all_zero(&bytes[..15]) && bytes[15] == 1,
        },
        Raw::V4(bytes) => bytes[0] == 127,
    }
}

/// Is the address routable on the public Internet? Written out rather than delegated to a standard
/// library predicate, which between them miss carrier-grade NAT, the benchmarking range and the
/// documentation ranges: every range omitted from a list like this is an internal destination a
/// public webhook can reach.
pub fn is_global(address: Raw) -> bool {
    match address {
        Raw::V4(bytes) => is_global_v4(bytes),
        Raw::V6(bytes) => match embedded_v4(&bytes) {
            Some(v4) => is_global_v4(v4),
            None => is_global_v6(&bytes),
        },
    }
}

fn is_global_v4(bytes: [u8; 4]) -> bool {
    let (a, b) = (bytes[0], bytes[1]);
    if a == 0 || a == 10 || a == 127 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false; // CGNAT, 100.64.0.0/10
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 {
        return false; // 192.0.0.0/24 and 192.0.2.0/24
    }
    if a == 198 && (b == 18 || b == 19) {
        return false; // benchmarking
    }
    if a == 198 && b == 51 {
        return false;
    }
    if a == 203 && b == 0 {
        return false;
    }
    a < 224 // multicast and reserved above
}

fn is_global_v6(bytes: &[u8; 16]) -> bool {
    if all_zero(bytes) {
        return false; // `::`
    }
    if all_zero(&bytes[..15]) && bytes[15] == 1 {
        return false; // `::1`
    }
    if (bytes[0] & 0xfe) == 0xfc {
        return false; // fc00::/7, unique local
    }
    if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
        return false; // fe80::/10
    }
    if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0 {
        return false; // fec0::/10, site-local
    }
    if bytes[..4] == [0x20, 0x01, 0x0d, 0xb8] {
        return false; // 2001:db8::/32, documentation
    }
    bytes[0] != 0xff // multicast
}
