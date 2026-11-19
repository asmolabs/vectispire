//! The address of the cluster's API server, as the agent's pod is told it — and checked against the cluster's own
//! name for it before the service account's token is sent there (`ClusterApiAddress`); and the address the isolation
//! probe tries (`ExecutorChoice.probeTarget`, `KubernetesExecutor.address`).
//!
//! **Why the environment alone is not enough.** The kubelet puts `KUBERNETES_SERVICE_HOST` and
//! `KUBERNETES_SERVICE_PORT` in every container, but a variable of the same name in the pod's spec wins over its
//! value — and the chart renders `agents.extraEnv` into that spec as written. A value pointing elsewhere would carry
//! the token, on every call, to any host presenting a certificate the cluster's authority signed, which a kubelet's
//! serving certificate often is (review of 2026-10-10). So the host must resolve only to addresses of
//! `kubernetes.default.svc`, the service the cluster's DNS answers for and a pod's spec cannot redefine; anything else
//! stops the start, saying which variable to look at.
//!
//! Held to Java by `reference/kubernetes/addresses.json` and `choice.json`.

use std::net::IpAddr;
use vectispire_domain::java;

/// The API server's service, as the cluster's DNS names it inside the pod's search path.
pub const SERVICE_NAME: &str = "kubernetes.default.svc";

/// The API server, as the agent will reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterAddress {
    /// The host as a URI carries it: an IPv6 literal in brackets.
    pub host: String,
    pub port: u16,
}

impl ClusterAddress {
    /// `https://host:port`, as `URI.toString` writes it.
    pub fn uri(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }
}

/// From this process's environment and the system's resolver.
pub fn from_environment() -> Result<ClusterAddress, String> {
    of(|name| std::env::var(name).ok(), system_resolver)
}

/// The system's resolver, as `InetAddress.getAllByName` answers: a literal — an IPv6 one in brackets too — without a
/// lookup, a name through the system's.
pub fn system_resolver(host: &str) -> Option<Vec<IpAddr>> {
    let bare = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')).unwrap_or(host);
    if let Ok(literal) = bare.parse::<IpAddr>() {
        return Some(vec![literal]);
    }
    use std::net::ToSocketAddrs;
    let found: Vec<IpAddr> = (host, 0).to_socket_addrs().ok()?.map(|address| address.ip()).collect();
    Some(found)
}

/// `ClusterApiAddress.of`: `resolver` answers `None` where the name does not resolve, which Java reads from an
/// `UnknownHostException`.
pub fn of(
    environment: impl Fn(&str) -> Option<String>,
    resolver: impl Fn(&str) -> Option<Vec<IpAddr>>,
) -> Result<ClusterAddress, String> {
    let host = environment("KUBERNETES_SERVICE_HOST");
    let port = environment("KUBERNETES_SERVICE_PORT");
    let (Some(host), Some(port)) = (host, port) else { return Err(NOT_IN_A_POD.to_owned()) };
    if java::is_blank(&host) || java::is_blank(&port) {
        return Err(NOT_IN_A_POD.to_owned());
    }
    let host = java::strip(&host);
    let number = port_number(java::strip(&port))?;

    let service = addresses(
        SERVICE_NAME,
        &resolver,
        &format!(
            "the cluster's DNS does not answer for {SERVICE_NAME}, which the agent checks the API server's address \
             against"
        ),
    )?;
    let named = addresses(host, &resolver, &format!("KUBERNETES_SERVICE_HOST ({host}) does not resolve"))?;
    // Every address, not one of them: a name answering both the service and another host would send the token
    // wherever the connection happens to land.
    if !named.iter().all(|address| service.contains(address)) {
        return Err(format!(
            "KUBERNETES_SERVICE_HOST ({host}, resolving to {}) is not the address of the cluster's API server, \
             {SERVICE_NAME} ({}). The agent does not send its service account's token there and does not start: a \
             variable of that name in the pod's spec replaces the kubelet's — remove it from agents.extraEnv.",
            text(&named),
            text(&service)
        ));
    }
    // An IPv6 service address (a single-stack IPv6 cluster) is bracketed in a URI; the kubelet gives it bare.
    let authority = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_owned() };
    Ok(ClusterAddress { host: authority, port: number })
}

const NOT_IN_A_POD: &str =
    "The Kubernetes executor runs in a pod: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set.";

fn port_number(port: &str) -> Result<u16, String> {
    java::parse_int(port).ok().and_then(|number| u16::try_from(number).ok()).filter(|number| *number >= 1).ok_or_else(
        || {
            format!(
                "KUBERNETES_SERVICE_PORT ({port}) is not a port number. The agent does not start: a variable of that \
                 name in the pod's spec replaces the kubelet's — remove it from agents.extraEnv."
            )
        },
    )
}

/// What `host` resolves to, in order and once each — Java's `LinkedHashSet` of them.
fn addresses(
    host: &str,
    resolver: &impl Fn(&str) -> Option<Vec<IpAddr>>,
    refusal: &str,
) -> Result<Vec<IpAddr>, String> {
    let found = resolver(host).filter(|found| !found.is_empty());
    let Some(found) = found else { return Err(format!("{refusal}. The agent does not start.")) };
    let mut unique: Vec<IpAddr> = Vec::with_capacity(found.len());
    for address in found {
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    Ok(unique)
}

fn text(addresses: &[IpAddr]) -> String {
    addresses.iter().map(|address| host_address(*address)).collect::<Vec<_>>().join(", ")
}

/// `InetAddress.getHostAddress`: IPv4 dotted, IPv6 as eight groups of lower-case hex with no leading zeros and **no
/// `::` compression** — the form the refusal quotes.
pub fn host_address(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.segments().iter().map(|group| format!("{group:x}")).collect::<Vec<_>>().join(":"),
    }
}

/// `ExecutorChoice.probeTarget`: the `address:port` the isolation probe tries — the one configured, or the API
/// server's as this pod is told it.
///
/// **Checked before it is used, both of them.** The variables go through the same check the API client applies
/// before it sends its token ([`of`]): the cluster's own service, a port number. A configured target is the
/// operator's, and is held to its shape — an address, not a name, and a port — so a typo stops the start naming the
/// property rather than surfacing as a probe of a name that does not resolve and reads as "blocked".
pub fn probe_target(
    configured: &str,
    cluster: impl FnOnce() -> Result<ClusterAddress, String>,
) -> Result<String, String> {
    if configured.is_empty() {
        let api = cluster()?;
        return Ok(format!("{}:{}", api.host, api.port));
    }
    let (host, port) = match configured.rsplit_once(':') {
        Some((host, port)) => (host, port),
        None => ("", configured),
    };
    let bare = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')).unwrap_or(host);
    let literal = if bare.contains(':') {
        host.starts_with('[') && !bare.is_empty() && bare.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    } else {
        dotted_quad(bare)
    };
    if !literal || !configured_port(port) {
        return Err(format!(
            "vectispire.agent.executor.kubernetes.probe-target is \"{configured}\": an IP address and a port, as \
             10.43.0.1:443 or [fd00::1]:443. The agent does not start."
        ));
    }
    Ok(configured.to_owned())
}

/// `[0-9]{1,3}(\.[0-9]{1,3}){3}`: the shape, not the range — `999.1.1.1` passes it, as on the Java side.
fn dotted_quad(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()))
}

/// `[0-9]{1,5}`, then 1 to 65535.
fn configured_port(text: &str) -> bool {
    (1..=5).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_digit())
        && text.parse::<u32>().is_ok_and(|number| (1..=65_535).contains(&number))
}

/// `KubernetesExecutor.address`: `address:port`, as the probe's target is written — the host with a leading `[` and a
/// trailing `]` taken off, the port as `Integer.parseInt` reads it.
pub fn address(target: &str) -> Result<(String, u16), String> {
    let refused = || format!("The probe's target is an address and a port, not \"{target}\".");
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => {
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            (host, java::parse_int(port).unwrap_or(-1))
        }
        None => (target, -1),
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':') {
        return Err(refused());
    }
    let port = u16::try_from(port).ok().filter(|port| *port >= 1).ok_or_else(refused)?;
    Ok((host.to_owned(), port))
}
