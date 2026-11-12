//! Sends a request to the address that was validated, and to no other — `PinnedHttpSender`.
//!
//! **The window this closes.** [`crate::OutboundUrlGuard`] resolves a name to decide whether the
//! policy allows it. A client then given the same *name* resolves it a second time, and between the
//! two lookups the answer can change: a name whose TTL is one second answers with a public address
//! while the settings page is being saved, and with `169.254.169.254` when the request is made.
//! Everything about the guard reads correctly and it protects nothing. That is DNS rebinding, and
//! the only place it can be closed is where the socket is opened — here, through a resolver that
//! knows one name and refuses every other.
//!
//! **The name still travels.** Only the lookup is replaced: the request carries the original host in
//! its URL, so `Host`, SNI and certificate verification are unchanged. Connecting to an IP literal
//! instead would have broken TLS verification, a poor trade for closing an SSRF window.
//!
//! **One client per request, deliberately.** A pooled client keyed by host would hand a later request
//! a socket opened for an earlier validation, and "we checked this destination" would quietly become
//! "we checked it once". These calls are a webhook, a ticket and a model review — rare, and none of
//! them in a hot path.
//!
//! **Redirects refused, not followed**, and **no retry of the client's own**: a guard that validates a
//! URL and then follows a 302 has validated nothing, and a hidden retry sleeps on a thread that has a
//! deadline. **No proxy**, whatever the environment says: a proxy would be the one place the checked
//! address is not the address reached.
//!
//! **Where it differs from the Java sender, on purpose.** The `User-Agent` is `Vectispire`, not Apache's.
//! Responses are not asked for in `gzip` and are not decoded if a server sends them anyway: every
//! answer read here is a small JSON document, and the ceiling then counts the bytes on the wire,
//! which are the bytes read. The verbs are the Java ones.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use vectispire_tls::TlsTrust;

use crate::failure::OutboundFailure;
use crate::guard::Destination;
use crate::pinned_ca::PinnedCa;

/// What an answer may weigh when the caller names no ceiling of its own: 4 MiB. Every answer read
/// here is a small JSON document — a ticket, a model's review, an end-of-life index — well under one
/// megabyte; four leaves room for the largest without leaving room for harm.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// How much longer than its read timeout a whole exchange may last. The timeout bounds each read, not
/// the exchange: a server sending one byte just inside it, again and again, held the calling thread for
/// as long as it liked. Twice the timeout covers a slow connect followed by a slow answer.
pub const DEADLINE_IN_TIMEOUTS: u32 = 2;

/// What a file download reads of an answer that is not the file — a redirect, an error page.
pub const ERROR_BODY_BYTES: u64 = 1024 * 1024;

/// The verbs a caller here has a use for. ServiceNow updates a record by PATCH and GitLab's issue API
/// by PUT; neither routes a POST on a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
}

impl Method {
    fn to_reqwest(self) -> reqwest::Method {
        match self {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
        }
    }
}

/// A response, reduced to what the callers read. Header names are lower-case, each with its values in
/// the order received — a forge states a token's scopes, its expiry and its own version in headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, Vec<String>)>,
}

impl Response {
    /// The first value of a header, by name in any case; `None` when the answer did not carry it.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_lowercase();
        self.headers.iter().find(|(key, _)| *key == wanted).and_then(|(_, values)| values.first()).map(String::as_str)
    }
}

/// A file's answer: its status, its bytes on a 2xx (none otherwise), and where a redirect points —
/// which is **not followed here**; a caller that means to follow it validates the target first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Download {
    pub status: u16,
    pub body: Vec<u8>,
    pub location: Option<String>,
}

/// The door.
#[derive(Clone, Debug)]
pub struct PinnedHttpSender {
    trust: TlsTrust,
}

/// What came back, before the caller shapes it.
struct Raw {
    status: u16,
    headers: Vec<(String, Vec<String>)>,
    body: Vec<u8>,
}

impl PinnedHttpSender {
    /// A sender trusting `trust` — the runtime's authorities, which a pinned CA replaces per request.
    pub fn new(trust: TlsTrust) -> PinnedHttpSender {
        PinnedHttpSender { trust }
    }

    /// Sends, and returns the status with the body: at most [`DEFAULT_MAX_BODY_BYTES`] of the answer.
    ///
    /// `body` is ignored for a GET, which carries none.
    pub async fn send(
        &self,
        method: Method,
        destination: &Destination,
        headers: &[(&str, &str)],
        body: Option<&str>,
        timeout: Duration,
        label: &str,
    ) -> Result<Response, OutboundFailure> {
        self.send_bounded(method, destination, headers, body, timeout, label, DEFAULT_MAX_BODY_BYTES, None).await
    }

    /// Sends with a ceiling on the answer, and optionally a CA the server's certificate must chain to
    /// — for that request alone, and in place of the public CAs, never beside them. Hostname
    /// verification is applied either way.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_bounded(
        &self,
        method: Method,
        destination: &Destination,
        headers: &[(&str, &str)],
        body: Option<&str>,
        timeout: Duration,
        label: &str,
        max_body_bytes: u64,
        trust: Option<&PinnedCa>,
    ) -> Result<Response, OutboundFailure> {
        let raw = self.exchange(method, destination, headers, body, timeout, label, trust, |_| max_body_bytes).await?;
        Ok(Response { status: raw.status, body: decode(&raw.body, content_type(&raw.headers)), headers: raw.headers })
    }

    /// Fetches a file: a GET whose answer is bytes, read up to `max_body_bytes`.
    pub async fn download(
        &self,
        destination: &Destination,
        headers: &[(&str, &str)],
        timeout: Duration,
        label: &str,
        max_body_bytes: u64,
    ) -> Result<Download, OutboundFailure> {
        // An answer that is not the file is read too, within a small ceiling, and dropped.
        let ceiling =
            move |status: u16| if status / 100 == 2 { max_body_bytes } else { max_body_bytes.min(ERROR_BODY_BYTES) };
        let raw = self.exchange(Method::Get, destination, headers, None, timeout, label, None, ceiling).await?;
        let location = raw
            .headers
            .iter()
            .find(|(name, _)| name == "location")
            .and_then(|(_, values)| values.first())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let file = raw.status / 100 == 2;
        Ok(Download { status: raw.status, body: if file { raw.body } else { Vec::new() }, location })
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange(
        &self,
        method: Method,
        destination: &Destination,
        headers: &[(&str, &str)],
        body: Option<&str>,
        timeout: Duration,
        label: &str,
        pinned_ca: Option<&PinnedCa>,
        ceiling: impl Fn(u16) -> u64,
    ) -> Result<Raw, OutboundFailure> {
        if destination.addresses.is_empty() {
            // **Refused rather than sent unpinned.** The guard tolerates a name it could not resolve —
            // for an "is this public?" check the request would fail anyway. Here it cannot be
            // tolerated: with no address to pin to, the client would resolve the name itself and the
            // check above would have decided nothing. The request fails either way; this way it says why.
            return Err(OutboundFailure::new(format!(
                "{label}: the host {} does not resolve, so no checked address exists to send to.",
                destination.host
            )));
        }

        let client = self.client_pinned_to(destination, timeout, pinned_ca, label)?;
        let mut request = client.request(method.to_reqwest(), destination.url.as_str());
        let mut has_content_type = false;
        for (name, value) in headers {
            has_content_type |= name.eq_ignore_ascii_case("content-type");
            request = request.header(*name, *value);
        }
        if let Some(body) = body.filter(|_| method != Method::Get) {
            if !has_content_type {
                request = request.header("Content-Type", "application/json; charset=UTF-8");
            }
            request = request.body(body.to_owned());
        }

        let deadline = timeout * DEADLINE_IN_TIMEOUTS;
        let started = Instant::now();
        let outcome = tokio::time::timeout(deadline, async {
            let mut response = request.send().await?;
            let status = response.status().as_u16();
            let limit = ceiling(status);
            let headers = headers_of(&response);
            let mut bytes: Vec<u8> = Vec::new();
            // Nothing is sized from what the server declares: a `Content-Length` is a claim, and the buffer
            // grows with what actually arrives.
            while let Some(chunk) = response.chunk().await? {
                if (bytes.len() + chunk.len()) as u64 > limit {
                    // The response is dropped here, before anything more is read: dropping closes the
                    // connection rather than draining it so that it could be reused.
                    return Ok(Err(limit));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, reqwest::Error>(Ok(Raw { status, headers, body: bytes }))
        })
        .await;

        match outcome {
            Err(_elapsed) => Err(OutboundFailure::new(format!(
                "{label}: no complete answer within {} s; the request was abandoned.",
                deadline.as_secs()
            ))),
            Ok(Ok(Ok(raw))) => Ok(raw),
            Ok(Ok(Err(limit))) => Err(OutboundFailure::new(format!(
                "{label}: the answer is larger than {limit} bytes and was not read further."
            ))),
            Ok(Err(error)) => Err(failure_of(error, label, started.elapsed() >= deadline)),
        }
    }

    fn client_pinned_to(
        &self,
        destination: &Destination,
        timeout: Duration,
        pinned_ca: Option<&PinnedCa>,
        label: &str,
    ) -> Result<reqwest::Client, OutboundFailure> {
        let resolver =
            Arc::new(PinnedResolver { host: destination.host.clone(), addresses: destination.addresses.clone() });
        let base = match pinned_ca {
            // The pinned CA replaces the authorities and nothing else: the name is still checked.
            Some(ca) => ca.certificates().iter().fold(
                reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).tls_built_in_root_certs(false),
                |builder, certificate| builder.add_root_certificate(certificate.clone()),
            ),
            None => self.trust.client(),
        };
        base.dns_resolver(resolver)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .pool_max_idle_per_host(0)
            .user_agent("Vectispire")
            .build()
            .map_err(|error| {
                OutboundFailure::caused_by(format!("{label}: the HTTP client could not be built ({error})."), error)
            })
    }
}

/// A resolver that knows one name and refuses every other. Refusing is the point: it is not a
/// fallback to the system resolver. If anything in the request path asks for a host that was not
/// checked — a redirect somebody re-enabled, a rewritten URL — the lookup fails instead of quietly
/// succeeding.
struct PinnedResolver {
    host: String,
    addresses: Vec<std::net::IpAddr>,
}

/// The lookup was for a host that is not the checked one.
#[derive(Debug)]
struct NotTheCheckedHost(String);

impl std::fmt::Display for NotTheCheckedHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for NotTheCheckedHost {}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let requested = name.as_str().to_owned();
        if !requested.eq_ignore_ascii_case(&self.host) {
            let refusal = NotTheCheckedHost(format!("{requested} was not the checked host ({})", self.host));
            return Box::pin(async move { Err(Box::new(refusal) as Box<dyn std::error::Error + Send + Sync>) });
        }
        let addresses: Vec<std::net::SocketAddr> =
            self.addresses.iter().map(|ip| std::net::SocketAddr::new(*ip, 0)).collect();
        Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
    }
}

fn failure_of(error: reqwest::Error, label: &str, past_deadline: bool) -> OutboundFailure {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(current) = cause {
        if let Some(refused) = current.downcast_ref::<NotTheCheckedHost>() {
            // What a redirect chased despite the setting, or a rewritten URL, would look like from here.
            let message = format!("{label}: the request tried to reach a host that was never checked ({}).", refused.0);
            return OutboundFailure::caused_by(message, error);
        }
        cause = current.source();
    }
    if past_deadline {
        return OutboundFailure::caused_by(format!("{label}: no complete answer; the request was abandoned."), error);
    }
    let message = format!("{label}: {}", describe(&error));
    OutboundFailure::caused_by(message, error)
}

/// The error and what is under it: reqwest's own text stops at "error sending request".
fn describe(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        let part = current.to_string();
        if !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        cause = current.source();
    }
    text
}

fn headers_of(response: &reqwest::Response) -> Vec<(String, Vec<String>)> {
    let mut headers: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in response.headers() {
        let name = name.as_str().to_lowercase();
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        match headers.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, values)) => values.push(value),
            None => headers.push((name, vec![value])),
        }
    }
    headers
}

fn content_type(headers: &[(String, Vec<String>)]) -> Option<&str> {
    headers.iter().find(|(name, _)| name == "content-type").and_then(|(_, values)| values.first()).map(String::as_str)
}

/// The body as text, in the charset the answer names — UTF-8 when it names none or one unknown.
fn decode(bytes: &[u8], content_type: Option<&str>) -> String {
    let charset = content_type
        .and_then(|value| value.split(';').skip(1).find_map(|parameter| parameter.trim().strip_prefix("charset=")))
        .map(|value| value.trim_matches('"').to_lowercase());
    match charset.as_deref() {
        Some("iso-8859-1" | "latin1" | "latin-1") => bytes.iter().map(|byte| char::from(*byte)).collect(),
        Some("us-ascii" | "ascii") => {
            bytes.iter().map(|byte| if byte.is_ascii() { char::from(*byte) } else { '\u{fffd}' }).collect()
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}
