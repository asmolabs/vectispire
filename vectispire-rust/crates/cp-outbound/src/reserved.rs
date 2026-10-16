//! The endpoints of Vectispire's own infrastructure that no setting may send requests to —
//! `ReservedEndpoints`, read from the Docker host, the datasource URL and the Kubernetes service
//! variables.
//!
//! **What it cannot read, it refuses**, rather than reserving nothing: a control plane that cannot
//! tell where its database is cannot keep a settings screen from pointing at it, and "start anyway"
//! is how that kind of check stops existing. The caller turns a [`ReservedError`] into a refusal to
//! start.

use crate::guard::ReservedEndpoint;

const DOCKER: &str = "the Docker daemon";
const DATABASE: &str = "the database";
const KUBERNETES: &str = "the Kubernetes API";

/// The port of the Kubernetes API server on a node.
pub const KUBERNETES_API_SERVER_PORT: i32 = 6443;
/// The kubelet's port.
pub const KUBELET_PORT: i32 = 10250;

/// A value that cannot be read for the hosts it names — `IllegalArgumentException`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ReservedError(pub String);

struct HostPort {
    host: String,
    port: i32,
}

/// The cluster's own API server — `KUBERNETES_SERVICE_HOST` and `_PORT` — and, on every host, the API
/// server's and the kubelet's ports, whose real addresses sit on nodes no variable names.
pub fn of_kubernetes_service(host: Option<&str>, port: Option<&str>) -> Result<Vec<ReservedEndpoint>, ReservedError> {
    let Some(host) = host.filter(|host| !is_blank(host)) else { return Ok(Vec::new()) };
    let host = java_trim(host);
    let source = format!("KUBERNETES_SERVICE_HOST {host}");
    let written = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_owned() };
    let endpoint = host_port(&written, 443, &source)?;
    let service_port = match port.filter(|port| !is_blank(port)) {
        Some(port) => parse_port(&source, port)?,
        None => endpoint.port,
    };
    Ok(vec![
        ReservedEndpoint::new(endpoint.host, service_port, KUBERNETES),
        ReservedEndpoint::on_every_host(KUBERNETES_API_SERVER_PORT, "the Kubernetes API server"),
        ReservedEndpoint::on_every_host(KUBELET_PORT, "the kubelet"),
    ])
}

/// The Docker daemon, from `DOCKER_HOST`: a socket reserves nothing; a TCP endpoint reserves its port,
/// or both conventional ones when it names none.
pub fn of_docker_host(docker_host: Option<&str>) -> Result<Vec<ReservedEndpoint>, ReservedError> {
    let Some(docker_host) = docker_host.filter(|host| !is_blank(host)) else { return Ok(Vec::new()) };
    let value = java_trim(docker_host);
    let separator = value.find("://");
    let scheme = separator.map_or_else(String::new, |at| value[..at].to_lowercase());
    match scheme.as_str() {
        "unix" | "npipe" => Ok(Vec::new()),
        "tcp" | "http" | "https" => {
            let after = &value[separator.unwrap_or(0) + 3..];
            let authority = after.split('/').next().unwrap_or(after);
            let endpoint = host_port(&without_user_info(authority), -1, &format!("DOCKER_HOST {value}"))?;
            if endpoint.port > 0 {
                return Ok(vec![ReservedEndpoint::new(endpoint.host, endpoint.port, DOCKER)]);
            }
            Ok(vec![
                ReservedEndpoint::new(endpoint.host.clone(), 2375, DOCKER),
                ReservedEndpoint::new(endpoint.host, 2376, DOCKER),
            ])
        }
        _ => Err(ReservedError(format!(
            "DOCKER_HOST \"{value}\" is not a form Vectispire can read the daemon's address from (unix://, npipe://, \
             tcp://, http:// or https://), so it cannot keep settings from sending requests to the daemon. Correct \
             it, or unset it to use the socket."
        ))),
    }
}

/// The database, from the datasource URL: every host of it, on its port, and the X protocol's port
/// beside MySQL's.
pub fn of_datasource(jdbc_url: Option<&str>) -> Result<Vec<ReservedEndpoint>, ReservedError> {
    let Some(jdbc_url) = jdbc_url.filter(|url| !is_blank(url)) else { return Ok(Vec::new()) };
    let value = java_trim(jdbc_url);
    let lower = value.to_lowercase();
    if !lower.starts_with("jdbc:") {
        return Err(unreadable(value, "it does not start with jdbc:"));
    }
    let rest = &value["jdbc:".len()..];
    let vendor = rest.find(':').map_or_else(String::new, |at| rest[..at].to_lowercase());
    match vendor.as_str() {
        "sqlite" => Ok(Vec::new()),
        "h2" => {
            // Embedded, in memory or in a file, unless it names a server.
            let h2 = rest[3..].to_lowercase();
            if h2.starts_with("tcp:") || h2.starts_with("ssl:") {
                let authority = after_slashes(value, &rest[3 + 4..])?;
                return host_list(value, &authority, 9092, &[]);
            }
            Ok(Vec::new())
        }
        "postgresql" => {
            let after = &rest["postgresql:".len()..];
            // `jdbc:postgresql:database` is the driver's short form for localhost.
            if after.starts_with("//") {
                host_list(value, &after_slashes(value, after)?, 5432, &[])
            } else {
                Ok(vec![ReservedEndpoint::new("localhost", 5432, DATABASE)])
            }
        }
        "mysql" | "mariadb" | "mysqlx" => {
            let Some(slashes) = rest.find("//") else { return Err(unreadable(value, "it names no host")) };
            // `mysql:replication:`, `mysql:loadbalance:`, `mariadb:sequential:`… change how the hosts are
            // used, not where they are.
            let x = vendor == "mysqlx";
            let port = if x { 33_060 } else { 3_306 };
            let also: &[i32] = if vendor == "mysql" && !x { &[33_060] } else { &[] };
            host_list(value, &after_slashes(value, &rest[slashes..])?, port, also)
        }
        "mysql+srv" | "mysqlx+srv" => Err(unreadable(
            value,
            "its hosts are looked up in DNS SRV records and are not in the URL; name the hosts instead",
        )),
        _ => Err(unreadable(value, "it is not a PostgreSQL, MySQL or MariaDB URL")),
    }
}

fn after_slashes(url: &str, from_slashes: &str) -> Result<String, ReservedError> {
    let Some(authority) = from_slashes.strip_prefix("//") else { return Err(unreadable(url, "it names no host")) };
    let mut depth = 0i32;
    for (index, c) in authority.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '/' | '?' if depth == 0 => return Ok(authority[..index].to_owned()),
            _ => {}
        }
    }
    Ok(authority.to_owned())
}

fn host_list(
    url: &str,
    authority: &str,
    default_port: i32,
    also: &[i32],
) -> Result<Vec<ReservedEndpoint>, ReservedError> {
    let mut endpoints = Vec::new();
    for spec in top_level(&without_user_info(authority)) {
        let endpoint = host_spec(url, java_trim(&spec), default_port)?;
        endpoints.push(ReservedEndpoint::new(endpoint.host.clone(), endpoint.port, DATABASE));
        for port in also {
            endpoints.push(ReservedEndpoint::new(endpoint.host.clone(), *port, DATABASE));
        }
    }
    Ok(endpoints)
}

fn host_spec(url: &str, spec: &str, default_port: i32) -> Result<HostPort, ReservedError> {
    if spec.is_empty() {
        return Ok(HostPort { host: "localhost".to_owned(), port: default_port });
    }
    let lower = spec.to_lowercase();
    if lower.starts_with("address=") || spec.starts_with('(') {
        let body = &spec[if lower.starts_with("address=") { "address=".len() } else { 0 }..];
        let flattened = body.replace(")(", ",").replace(['(', ')'], "");
        let (mut host, mut port): (Option<String>, Option<String>) = (None, None);
        for pair in java_split_comma(&flattened) {
            let Some(equals) = pair.find('=') else {
                return Err(unreadable(url, &format!("\"{spec}\" is not a host")));
            };
            let key = java_trim(&pair[..equals]).to_lowercase();
            if key == "host" {
                host = Some(java_trim(&pair[equals + 1..]).to_owned());
            } else if key == "port" {
                port = Some(java_trim(&pair[equals + 1..]).to_owned());
            }
        }
        let name = match host.filter(|host| !host.is_empty()) {
            None => "localhost".to_owned(),
            Some(host) => strip_brackets(&host),
        };
        let port = match port {
            None => default_port,
            Some(port) => parse_port(url, &port)?,
        };
        return Ok(HostPort { host: name, port });
    }
    host_port(spec, default_port, url)
}

fn host_port(spec: &str, default_port: i32, source: &str) -> Result<HostPort, ReservedError> {
    let not_a_host = || unreadable(source, &format!("\"{spec}\" is not a host"));
    let (host, port): (String, Option<String>) = if let Some(bracketed) = spec.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else { return Err(not_a_host()) };
        let tail = &bracketed[close + 1..];
        let port = if let Some(port) = tail.strip_prefix(':') {
            Some(port.to_owned())
        } else if tail.is_empty() {
            None
        } else {
            return Err(not_a_host());
        };
        (bracketed[..close].to_owned(), port)
    } else {
        match spec.find(':') {
            None => (spec.to_owned(), None),
            Some(colon) => (spec[..colon].to_owned(), Some(spec[colon + 1..].to_owned())),
        }
    };
    if host.is_empty() || host.chars().any(|c| c <= ' ' || matches!(c, '/' | '@' | '(' | ')')) {
        return Err(not_a_host());
    }
    let port = match port.filter(|port| !port.is_empty()) {
        None => default_port,
        Some(port) => parse_port(source, &port)?,
    };
    Ok(HostPort { host, port })
}

fn parse_port(source: &str, port: &str) -> Result<i32, ReservedError> {
    if let Ok(value) = java_trim(port).parse::<i32>()
        && (1..=65_535).contains(&value)
    {
        return Ok(value);
    }
    Err(unreadable(source, &format!("\"{port}\" is not a port")))
}

fn top_level(authority: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    for (index, c) in authority.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(authority[start..index].to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(authority[start..].to_owned());
    parts
}

fn without_user_info(authority: &str) -> String {
    let mut depth = 0i32;
    let mut at: Option<usize> = None;
    for (index, c) in authority.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '@' if depth == 0 => at = Some(index),
            _ => {}
        }
    }
    at.map_or_else(|| authority.to_owned(), |at| authority[at + 1..].to_owned())
}

fn unreadable(source: &str, why: &str) -> ReservedError {
    // The value itself is not repeated for a datasource URL: it may carry a password.
    let named = if source.len() >= 5 && source.is_char_boundary(5) && source[..5].eq_ignore_ascii_case("jdbc:") {
        "The datasource URL"
    } else {
        source
    };
    ReservedError(format!(
        "{named} cannot be read for the hosts it connects to — {why}. Vectispire refuses to start rather than let \
         settings send requests to its own infrastructure."
    ))
}

/// `String.split(",")`: trailing empty strings dropped, and the input itself when it holds no comma.
fn java_split_comma(text: &str) -> Vec<&str> {
    if !text.contains(',') {
        return vec![text];
    }
    let mut parts: Vec<&str> = text.split(',').collect();
    while parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    parts
}

/// `replaceAll("^\\[|]$", "")`.
fn strip_brackets(text: &str) -> String {
    let text = text.strip_prefix('[').unwrap_or(text);
    text.strip_suffix(']').unwrap_or(text).to_owned()
}

/// `String.trim`: every char up to U+0020.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `String.isBlank`: only `Character.isWhitespace` characters.
fn is_blank(text: &str) -> bool {
    text.chars().all(|c| {
        matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{1f}' | ' ' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
    })
}
