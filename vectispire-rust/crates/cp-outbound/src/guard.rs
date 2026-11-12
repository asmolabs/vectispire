//! Validation of the URLs Vectispire will send a request to — `OutboundUrlGuard`.
//!
//! Three settings become server-side requests: the notification webhook, the Ollama server and the
//! local scan API. Each is a string set by an administrator and then called by the server — a
//! server-side request forgery primitive, whose classic target is the metadata endpoint
//! `169.254.169.254`, which hands out the instance's credentials to whoever asks. "Only an
//! administrator can set it" is a mitigation, not an answer.
//!
//! **Two limits, recorded rather than hidden.** *DNS rebinding — closed, but only for callers that
//! take the addresses*: [`OutboundUrlGuard::validate_and_resolve`] returns what was checked, so the
//! caller connects to exactly that and resolves nothing again ([`crate::sender`]); `validate`, which
//! returns the URL alone, leaves the window open and serves the settings screen that saves a value
//! and does not send to it. *Redirects*: this validates the first destination only, so every caller
//! must refuse them — which is why there is one caller, the sender, and a test that keeps it so.
//!
//! The messages are the Java guard's, word for word: they reach the administrator who typed the URL,
//! and the reference set compares them.

use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;

use vectispire_domain::net::parse_literal;
use vectispire_domain::repository_url::java_uri;

use crate::address::{self, Raw};
use crate::policy::OutboundPolicy;

/// A refusal: the label of the setting, and why. `UnsafeUrlException`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UnsafeUrl(pub String);

/// Every address a name resolves to — **every one, not the first**: a name can return a public
/// address and a private one, and checking a single answer lets the other through.
pub trait HostResolver: Send + Sync + 'static {
    fn resolve(&self, hostname: &str) -> Vec<Raw>;
}

impl<F: Fn(&str) -> Vec<Raw> + Send + Sync + 'static> HostResolver for F {
    fn resolve(&self, hostname: &str) -> Vec<Raw> {
        self(hostname)
    }
}

/// The system's resolver: a literal is read as `InetAddress.ofLiteral` reads one, a name goes to
/// `getaddrinfo`. A name that does not resolve answers nothing rather than failing: refusing on a
/// resolution failure would make the settings screen unusable at the slightest DNS hiccup, and the
/// request itself would fail anyway. The one policy for which that is not good enough is handled by
/// the guard.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, hostname: &str) -> Vec<Raw> {
        if let Some(literal) = parse_literal(hostname) {
            return vec![Raw::of(literal)];
        }
        match (hostname, 0u16).to_socket_addrs() {
            Ok(addresses) => addresses.map(|socket| Raw::of(socket.ip())).collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// An endpoint of Vectispire's own infrastructure, refused as a destination under every policy: the
/// Docker daemon's proxy and the database sit on the internal network, which the internal policies
/// exist to reach, so a policy is not enough. The port is part of the match so that the same loopback
/// address can still serve an Ollama on another port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservedEndpoint {
    /// A name or an address, or [`ReservedEndpoint::EVERY_HOST`] for a port refused whatever the host.
    pub host: String,
    pub port: i32,
    /// How the refusal names it to whoever set the URL.
    pub what: String,
}

impl ReservedEndpoint {
    /// The host of a port reserved on every address — never resolved.
    pub const EVERY_HOST: &'static str = "*";

    pub fn new(host: impl Into<String>, port: i32, what: impl Into<String>) -> ReservedEndpoint {
        ReservedEndpoint { host: host.into(), port, what: what.into() }
    }

    /// A port refused on every host: for a service whose addresses cannot be known from here.
    pub fn on_every_host(port: i32, what: impl Into<String>) -> ReservedEndpoint {
        ReservedEndpoint::new(Self::EVERY_HOST, port, what)
    }

    fn every_host(&self) -> bool {
        self.host == Self::EVERY_HOST
    }
}

/// A destination that has been checked, and the addresses it was checked at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// The cleaned URL, unchanged — the host name still travels to the server, so virtual hosting,
    /// SNI and certificate verification all keep working.
    pub url: String,
    /// The host as written, which is what a TLS certificate is verified against.
    pub host: String,
    /// Every address the name resolved to at validation time, all of them accepted by the policy.
    /// **Connect to these and resolve nothing again.** Empty only when the name did not resolve at
    /// all and the policy tolerated it.
    pub addresses: Vec<IpAddr>,
}

/// The guard.
#[derive(Clone)]
pub struct OutboundUrlGuard {
    resolver: Arc<dyn HostResolver>,
    reserved: Vec<ReservedEndpoint>,
}

impl std::fmt::Debug for OutboundUrlGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OutboundUrlGuard").field("reserved", &self.reserved).finish_non_exhaustive()
    }
}

/// What one validation established, before it is turned into either shape.
struct Checked {
    url: String,
    host: String,
    addresses: Vec<Raw>,
}

impl OutboundUrlGuard {
    pub fn new(reserved: Vec<ReservedEndpoint>) -> OutboundUrlGuard {
        OutboundUrlGuard::with_resolver(SystemResolver, reserved)
    }

    pub fn with_resolver(resolver: impl HostResolver, reserved: Vec<ReservedEndpoint>) -> OutboundUrlGuard {
        OutboundUrlGuard { resolver: Arc::new(resolver), reserved }
    }

    /// Validates, and hands back the addresses so the connection can be pinned to them. They come
    /// from the same lookup the policy was applied to — not a second one: a caller that re-resolved
    /// would be checking one answer and using another, which is the whole of DNS rebinding.
    pub fn validate_and_resolve(
        &self,
        url: &str,
        policy: OutboundPolicy,
        label: &str,
    ) -> Result<Destination, UnsafeUrl> {
        self.check(url, policy, label).map(pinned)
    }

    /// The same verdict for a destination that is not a URL: a syslog collector's host and port. Not
    /// a second classifier, and that is the point: a syslog socket reaches exactly the places an HTTP
    /// request does, so the host goes through the same resolution, address rules and reserved
    /// endpoints, and comes back with the addresses to connect to.
    pub fn validate_and_resolve_endpoint(
        &self,
        host: Option<&str>,
        port: i64,
        policy: OutboundPolicy,
        label: &str,
    ) -> Result<Destination, UnsafeUrl> {
        let hostname = strip_brackets(host.map_or("", java_trim));
        if hostname.is_empty() {
            return Err(refuse(label, "missing host."));
        }
        if !(1..=65_535).contains(&port) {
            return Err(refuse(label, "the port must be between 1 and 65535."));
        }
        let written =
            if hostname.contains(':') { format!("[{hostname}]:{port}") } else { format!("{hostname}:{port}") };
        self.check_host(written, hostname, port as i32, policy, label).map(pinned)
    }

    /// Returns the cleaned URL, or the refusal.
    pub fn validate(&self, url: &str, policy: OutboundPolicy, label: &str) -> Result<String, UnsafeUrl> {
        self.check(url, policy, label).map(|checked| checked.url)
    }

    /// The reason, or `None` when the URL is acceptable. Non-throwing variant.
    pub fn unsafe_reason(&self, url: &str, policy: OutboundPolicy, label: &str) -> Option<String> {
        self.validate(url, policy, label).err().map(|refused| refused.0)
    }

    fn check(&self, url: &str, policy: OutboundPolicy, label: &str) -> Result<Checked, UnsafeUrl> {
        let candidate = java_trim(url);
        if candidate.is_empty() {
            return Err(refuse(label, "empty value."));
        }
        let parsed = java_uri::parse(candidate).map_err(|_| refuse(label, "unreadable URL."))?;
        let parts = UriParts::of(candidate, parsed.host.as_deref());

        let scheme = parsed.scheme.as_deref().map(str::to_lowercase).unwrap_or_default();
        if scheme != "http" && scheme != "https" {
            let shown = if scheme.is_empty() { "(none)" } else { scheme.as_str() };
            return Err(refuse(label, &format!("scheme \"{shown}\" is not allowed (expected: https, http).")));
        }

        // `URI.getHost` is null for a host the parser considers malformed, which includes registry-based
        // authorities: the authority is the fallback, so those stay parseable rather than passing as
        // "no host". Brackets around a literal IPv6 are syntax, not part of the address.
        let host = match &parsed.host {
            Some(host) => host.clone(),
            None => parts.authority.clone().unwrap_or_default(),
        };
        let hostname = strip_brackets(&host);
        if hostname.is_empty() {
            return Err(refuse(label, "missing host."));
        }
        let port = if parts.port > 0 {
            parts.port
        } else if scheme == "https" {
            443
        } else {
            80
        };
        self.check_host(candidate.to_owned(), hostname, port, policy, label)
    }

    /// Resolution, the policy on every address, and the reserved endpoints: what a URL and a bare
    /// endpoint share.
    fn check_host(
        &self,
        candidate: String,
        hostname: String,
        port: i32,
        policy: OutboundPolicy,
        label: &str,
    ) -> Result<Checked, UnsafeUrl> {
        let addresses = self.resolver.resolve(&hostname);

        if policy == OutboundPolicy::InternalRequired && addresses.is_empty() {
            // Failing open is defensible for "is this private?" — the request would fail anyway. It is
            // not for "this *must* be private": an unresolvable name proves nothing, and this check is
            // what separates the scanned source code from an external host.
            return Err(refuse(
                label,
                "the host could not be resolved, so it cannot be verified as internal — and this endpoint \
                 receives source code.",
            ));
        }
        for address in &addresses {
            check_address(*address, policy, label)?;
        }
        self.refuse_reserved(&hostname, port, &addresses, label)?;
        Ok(Checked { url: candidate, host: hostname, addresses })
    }

    /// By name and by address: the name alone lets `172.18.0.3:2375` through, and the address alone
    /// misses a name that no longer resolves from here. The reserved host is resolved at each check
    /// rather than once, because a container's address changes when it is recreated. Loopback is one
    /// machine whatever address of it is written.
    fn refuse_reserved(&self, hostname: &str, port: i32, addresses: &[Raw], label: &str) -> Result<(), UnsafeUrl> {
        for endpoint in &self.reserved {
            if endpoint.port != port {
                continue;
            }
            let mut same_host = endpoint.every_host() || equals_ignore_case(&endpoint.host, hostname);
            if !same_host {
                let own = self.resolver.resolve(&endpoint.host);
                same_host = addresses.iter().any(|address| {
                    own.iter().any(|o| o == address || address::is_loopback(*o) && address::is_loopback(*address))
                });
            }
            if same_host && endpoint.every_host() {
                return Err(refuse(
                    label,
                    &format!(
                        "{hostname}:{port} is refused — in a Kubernetes cluster, port {port} is {}'s, which no \
                         setting may send requests to.",
                        endpoint.what
                    ),
                ));
            }
            if same_host {
                return Err(refuse(
                    label,
                    &format!("{hostname}:{port} is {}, which no setting may send requests to.", endpoint.what),
                ));
            }
        }
        Ok(())
    }
}

fn check_address(address: Raw, policy: OutboundPolicy, label: &str) -> Result<(), UnsafeUrl> {
    let text = address.text();
    if address::is_link_local(address) {
        return Err(refuse(
            label,
            &format!("the host resolves to a link-local address ({text}), used by instance metadata services."),
        ));
    }
    if address::is_metadata(address) {
        return Err(refuse(
            label,
            &format!("the host resolves to {text}, a cloud provider's instance metadata address."),
        ));
    }
    if address::is_unspecified(address) {
        return Err(refuse(
            label,
            &format!(
                "the host resolves to the unspecified address ({text}), which reaches this machine. Name the \
                 destination itself."
            ),
        ));
    }
    let global = address::is_global(address);
    if policy == OutboundPolicy::PublicOnly && !global {
        return Err(refuse(
            label,
            &format!(
                "the host resolves to a private or local address ({text}). A public destination is expected here."
            ),
        ));
    }
    if policy == OutboundPolicy::InternalRequired && global {
        return Err(refuse(
            label,
            &format!(
                "the host resolves to a public address ({text}). A local or internal destination is expected \
                 here — this endpoint receives source code."
            ),
        ));
    }
    Ok(())
}

fn pinned(checked: Checked) -> Destination {
    Destination {
        url: checked.url,
        host: checked.host,
        addresses: checked.addresses.into_iter().map(Raw::to_ip).collect(),
    }
}

fn refuse(label: &str, why: &str) -> UnsafeUrl {
    UnsafeUrl(format!("{label}: {why}"))
}

/// `String.trim`: every char up to U+0020, and nothing else.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `replaceAll("^\\[|]$", "")`: a leading `[` and a trailing `]`, independently.
fn strip_brackets(text: &str) -> String {
    let text = text.strip_prefix('[').unwrap_or(text);
    text.strip_suffix(']').unwrap_or(text).to_owned()
}

/// `String.equalsIgnoreCase`: per char, upper- then lower-case.
fn equals_ignore_case(left: &str, right: &str) -> bool {
    let fold = |text: &str| -> Vec<char> {
        text.chars()
            .map(|c| c.to_uppercase().next().unwrap_or(c))
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect()
    };
    fold(left) == fold(right)
}

/// What the parser's `Parsed` does not carry and the guard reads: the authority and the port.
struct UriParts {
    authority: Option<String>,
    port: i32,
}

impl UriParts {
    /// Read from the text of a URI that has already parsed, and whose host the parser gave (`None`
    /// for a registry-based authority or an opaque URI, which have no port).
    fn of(text: &str, host: Option<&str>) -> UriParts {
        let none = UriParts { authority: None, port: -1 };
        let Some(colon) = text.find(':') else { return none };
        let rest = &text[colon + 1..];
        let Some(after) = rest.strip_prefix("//") else { return none };
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let raw = &after[..end];
        let authority = Some(percent_decode(raw));
        if host.is_none() {
            return UriParts { authority, port: -1 };
        }
        let hostport = raw.rfind('@').map_or(raw, |at| &raw[at + 1..]);
        let digits = if let Some(stripped) = hostport.strip_prefix('[') {
            stripped.find(']').and_then(|close| stripped[close + 1..].strip_prefix(':'))
        } else {
            hostport.rfind(':').map(|index| &hostport[index + 1..])
        };
        match digits {
            None | Some("") => UriParts { authority, port: -1 },
            Some(digits) => match digits.parse::<i32>() {
                // A port past `int` never gets here: the JDK throws for it out of `new URI` — not as a
                // `URISyntaxException` but all the same — and `java_uri` refuses the URL before this is read.
                Ok(port) => UriParts { authority, port },
                Err(_) => UriParts { authority, port: -1 },
            },
        }
    }
}

/// `URI.getAuthority`: the raw authority with its escaped octets decoded, as UTF-8.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(value) = pair.and_then(|pair| u8::from_str_radix(pair, 16).ok()) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
