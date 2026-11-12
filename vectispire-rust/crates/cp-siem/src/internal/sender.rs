//! Sends one CEF event over the transport the configuration names — `SiemSender`.
//!
//! The one place the protocol is honoured:
//!
//! - **Webhook**: a JSON POST `{"cef": "…"}` through the outbound guard and `PinnedHttpSender` — the address checked
//!   is the address reached, no redirect followed — the body Java has always sent, so existing receivers keep
//!   working. The authorization header goes with it.
//! - **Syslog**: the host and port through `OutboundUrlGuard::validate_and_resolve_endpoint` — the same classifier as a
//!   URL, reserved endpoints included — then RFC 5424 over the pinned address ([`super::syslog::SyslogSender`]).
//!   **No header**: a syslog frame has nowhere to carry one. Over TLS, the pinned collector CA when one is configured.
//!
//! Both refuse a private destination unless `siem_allow_private_destination` is on — set by an administrator only —
//! and the metadata endpoint, the Docker proxy and the database under every policy.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::future::BoxFuture;
use vectispire_cp_outbound::{
    Destination, Method, OutboundPolicy, OutboundUrlGuard, PinnedHttpSender, Response, UnsafeUrl,
};
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, CollectorCa, SiemEndpoint, syslog};
use vectispire_domain::{java, wire};

use super::syslog::SyslogSender;
use crate::transport::{PrivateDestinations, SendError, Transport};

/// Like `OutboundPost`'s: long enough for a slow collector, short enough not to hold the relay.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// How every refusal and failure names what was being sent.
pub const LABEL: &str = "SIEM export";

const FAILURE: &str = "OutboundFailureException";

/// The sender.
pub struct SiemSender {
    guard: OutboundUrlGuard,
    http: PinnedHttpSender,
    syslog: SyslogSender,
    private: Arc<dyn PrivateDestinations>,
    version: Option<String>,
    /// Resolved on first use: a lookup at start can block on a host whose name service is unwell.
    hostname: OnceLock<String>,
}

impl std::fmt::Debug for SiemSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SiemSender").field("version", &self.version).finish_non_exhaustive()
    }
}

impl SiemSender {
    /// `version` is `ProductVersion`'s — the CEF header's device version, empty when nothing states one.
    pub fn new(
        guard: OutboundUrlGuard,
        http: PinnedHttpSender,
        syslog: SyslogSender,
        private: Arc<dyn PrivateDestinations>,
        version: Option<String>,
    ) -> SiemSender {
        SiemSender { guard, http, syslog, private, version, hostname: OnceLock::new() }
    }

    /// The HOSTNAME a syslog header states, given rather than read — for a deployment that names itself, and for the
    /// tests, which compare the message with Java's.
    pub fn with_hostname(self, hostname: &str) -> SiemSender {
        let named = OnceLock::new();
        let _ = named.set(hostname.to_owned());
        SiemSender { hostname: named, ..self }
    }

    /// Sends, or says why not: [`SendError::Refused`] for a destination the guard refuses, a failure for an
    /// unreachable or refusing collector. The outbox retries either; the connection test reports it.
    pub async fn send(
        &self,
        endpoint: &SiemEndpoint,
        header: Option<&Secret>,
        ca: Option<&CollectorCa>,
        event: &CefEvent,
    ) -> Result<(), SendError> {
        let cef = event.to_cef_string(self.version.as_deref());
        let policy = self.policy().await?;
        match endpoint {
            SiemEndpoint::Webhook { url } => {
                let destination = self.checked(url.clone(), None, policy).await?;
                let mut headers: Vec<(&str, &str)> = Vec::new();
                if let Some(header) = header.filter(|header| !java::is_blank(header.expose())) {
                    headers.push(("Authorization", header.expose()));
                }
                let answer = self
                    .http
                    .send(Method::Post, &destination, &headers, Some(&body(&cef)), TIMEOUT, LABEL)
                    .await
                    .map_err(|failed| SendError::failed(FAILURE, failed.message()))?;
                if answer.status / 100 != 2 {
                    return Err(status_failure(&answer));
                }
                Ok(())
            }
            SiemEndpoint::Syslog { protocol, host, port } => {
                let destination = self.checked(host.clone(), Some(*port), policy).await?;
                let message = syslog::format(event, Some(self.hostname()), &cef);
                self.syslog
                    .send(*protocol, &destination, *port, &message, TIMEOUT, LABEL, ca)
                    .await
                    .map_err(|failed| SendError::failed(FAILURE, failed.message()))
            }
        }
    }

    /// Private addresses only when an administrator has allowed them for this channel.
    async fn policy(&self) -> Result<OutboundPolicy, SendError> {
        match self.private.allowed().await {
            Ok(true) => Ok(OutboundPolicy::InternalAllowed),
            Ok(false) => Ok(OutboundPolicy::PublicOnly),
            // Java's settings read throws a data-access exception, which the outbox retries; so does this.
            Err(unreadable) => Err(SendError::failed("DataAccessException", unreadable)),
        }
    }

    /// The guard's verdict, off the runtime's threads: it resolves the name, which can block.
    async fn checked(
        &self,
        target: String,
        port: Option<u16>,
        policy: OutboundPolicy,
    ) -> Result<Destination, SendError> {
        let guard = self.guard.clone();
        let verdict = tokio::task::spawn_blocking(move || -> Result<Destination, UnsafeUrl> {
            match port {
                None => guard.validate_and_resolve(&target, policy, LABEL),
                Some(port) => guard.validate_and_resolve_endpoint(Some(&target), i64::from(port), policy, LABEL),
            }
        })
        .await
        .map_err(|stopped| {
            SendError::failed(FAILURE, format!("{LABEL}: the destination check stopped ({stopped})."))
        })?;
        verdict.map_err(SendError::Refused)
    }

    /// The container's or the machine's name, or the NILVALUE. The syslog formatter strips anything a header token may
    /// not hold.
    fn hostname(&self) -> &str {
        self.hostname.get_or_init(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|name| !java::is_blank(name))
                .or_else(|| {
                    let node = rustix::system::uname();
                    let name = node.nodename().to_string_lossy().into_owned();
                    (!name.is_empty()).then_some(name)
                })
                .unwrap_or_else(|| "-".to_owned())
        })
    }
}

impl Transport for SiemSender {
    fn send<'a>(
        &'a self,
        endpoint: &'a SiemEndpoint,
        header: Option<&'a Secret>,
        ca: Option<&'a CollectorCa>,
        event: &'a CefEvent,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(SiemSender::send(self, endpoint, header, ca, event))
    }
}

/// `{"cef": "…"}` as Jackson writes `Map.of("cef", cef)`.
pub fn body(cef: &str) -> String {
    let mut out = String::with_capacity(cef.len().saturating_add(10));
    out.push_str("{\"cef\":");
    wire::write_string(&mut out, cef);
    out.push('}');
    out
}

/// `OutboundStatusException.of`: the status, and whether the collector said "slow down" rather than "no".
fn status_failure(answer: &Response) -> SendError {
    let rate_limited = answer.status == 429
        || (answer.status == 403
            && (answer.header("x-ratelimit-remaining").is_some_and(|remaining| remaining.trim() == "0")
                || answer.header("retry-after").is_some()));
    SendError::failed(
        "OutboundStatusException",
        format!("{LABEL}: HTTP {}{}", answer.status, if rate_limited { ", rate-limited." } else { "." }),
    )
}
