//! `SiemEndpoint`: where the SIEM configuration says events go, read according to its protocol.
//!
//! **One format per protocol, and the protocol decides the transport.** A webhook is a URL; a syslog destination
//! is `host:port` — `[2001:db8::1]:6514` for an IPv6 literal — and nothing else. A scheme such as `syslog+tls://`
//! would be a second place to state the transport, and the day it disagreed with the protocol field one of them
//! would silently win. The port is required: the defaults differ by transport, and a guessed port is a collector
//! that receives nothing.
//!
//! Parsing is syntax only. Whether the host may be reached is the outbound guard's question, asked at send time
//! against what the name resolves to then. The refusals are an operator's to read, in Java's words, held to
//! `reference/siem/`.

use std::net::Ipv6Addr;

use crate::bounded_text::Refused;
use crate::java;
use crate::repository_url::java_uri;
use crate::siem::protocol::SiemProtocol;

/// A destination, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiemEndpoint {
    /// An HTTP(S) collector, reached through the pinned HTTP sender. The URL as typed, trimmed.
    Webhook { url: String },
    /// A syslog collector. `host` is as written, brackets removed from an IPv6 literal.
    Syslog { protocol: SiemProtocol, host: String, port: u16 },
}

const PORT_REFUSED: &str = "The port must be a number between 1 and 65535.";
const IPV6_FORM: &str = "An IPv6 syslog endpoint is written [address]:port.";

/// Reads an endpoint for a protocol, or refuses it in words meant for the person who typed it.
pub fn parse(protocol: SiemProtocol, endpoint: Option<&str>) -> Result<SiemEndpoint, Refused> {
    let value = java::trim(endpoint.unwrap_or(""));
    if value.is_empty() {
        return Err(refused("The endpoint is required."));
    }
    match protocol {
        SiemProtocol::Webhook => webhook(value),
        SiemProtocol::SyslogUdp | SiemProtocol::SyslogTcp | SiemProtocol::SyslogTls => syslog(protocol, value),
    }
}

fn refused(message: &str) -> Refused {
    Refused(message.to_owned())
}

/// `new URI(value)`, as the JDK parses it ([`java_uri`]), with an http(s) scheme and a host.
fn webhook(value: &str) -> Result<SiemEndpoint, Refused> {
    let Ok(uri) = java_uri::parse(value) else {
        return Err(refused("The webhook endpoint is not a readable URL."));
    };
    let scheme = java::to_lower_root(uri.scheme.as_deref().unwrap_or(""));
    if scheme != "https" && scheme != "http" {
        return Err(refused("A webhook endpoint is an http(s) URL, for example https://collector.example.com/cef."));
    }
    if uri.host.as_deref().is_none_or(java::is_blank) {
        return Err(refused("The webhook endpoint names no host."));
    }
    Ok(SiemEndpoint::Webhook { url: value.to_owned() })
}

fn syslog(protocol: SiemProtocol, value: &str) -> Result<SiemEndpoint, Refused> {
    let example =
        if protocol == SiemProtocol::SyslogTls { "collector.example.com:6514" } else { "collector.example.com:514" };
    if value.contains('/') {
        // `://` contains a slash: Java's two tests are one.
        return Err(Refused(format!(
            "A syslog endpoint is host:port, for example {example} — no scheme and no path: the protocol field \
             already says how events travel."
        )));
    }
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        // The first `]`, and a colon right after it — anything else is not the bracketed form.
        let Some((host, port)) =
            bracketed.split_once(']').and_then(|(host, rest)| Some((host, rest.strip_prefix(':')?)))
        else {
            return Err(refused(IPV6_FORM));
        };
        if !is_ipv6_literal(host) {
            return Err(Refused(format!("\"{host}\" is not an IPv6 address.")));
        }
        (host, port)
    } else {
        let Some((host, port)) = value.rsplit_once(':') else {
            return Err(Refused(format!("A syslog endpoint needs its port, for example {example}.")));
        };
        if host.contains(':') {
            return Err(refused(IPV6_FORM));
        }
        if !is_host_name(host) {
            return Err(Refused(format!("\"{host}\" is not a host name or an IPv4 address.")));
        }
        (host, port)
    };
    Ok(SiemEndpoint::Syslog { protocol, host: host.to_owned(), port: port_of(port)? })
}

/// `(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?`, spelled out: Java's
/// `(?i)` folds ASCII only, where a Unicode-aware `(?i)` would take the Kelvin sign for a `k`.
fn is_host_name(host: &str) -> bool {
    let labels = host.strip_suffix('.').unwrap_or(host);
    !labels.is_empty()
        && labels.split('.').all(|label| {
            let alphanumeric_ends = label.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                && label.bytes().next_back().is_some_and(|b| b.is_ascii_alphanumeric());
            alphanumeric_ends && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `InetAddress.ofLiteral(text) instanceof Inet6Address`.
///
/// Two of the JDK's answers are reproduced: an IPv4-mapped address (`::ffff:10.0.0.1`) is read as the IPv4
/// address it maps, so it is **not** IPv6; a numeric scope (`fe80::1%2`) is accepted. One is not: the JDK accepts
/// an interface-name scope (`%eth0`) only when the machine has that interface — an answer that depends on where
/// it runs, refused here everywhere, as the outbound guard refuses it. The JDK also reads a group of more than
/// four digits whose value fits (`01234::1`); the standard library does not, and the endpoint is refused — the
/// safe side, for a spelling no collector's address needs.
fn is_ipv6_literal(text: &str) -> bool {
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (text, None),
    };
    if let Some(scope) = scope
        && (scope.is_empty() || !scope.bytes().all(|b| b.is_ascii_digit()) || scope.parse::<i32>().is_err())
    {
        return false;
    }
    address.parse::<Ipv6Addr>().is_ok_and(|parsed| parsed.to_ipv4_mapped().is_none())
}

/// One to five ASCII digits, 1 to 65535 — a full-width `５１４` is not a port.
fn port_of(text: &str) -> Result<u16, Refused> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refused(PORT_REFUSED));
    }
    text.parse::<u16>().ok().filter(|port| *port >= 1).ok_or_else(|| refused(PORT_REFUSED))
}
