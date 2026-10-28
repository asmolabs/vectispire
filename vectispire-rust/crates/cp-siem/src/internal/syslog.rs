//! Sends one syslog message to the address that was validated, and to no other — `SyslogSender`.
//!
//! The syslog counterpart of `PinnedHttpSender`, bound by the same rule: it takes a [`Destination`] — what the guard
//! resolved and accepted — and connects to those addresses, never to the name. A name resolved a second time here
//! could answer with the metadata endpoint, and the check before it would have decided nothing.
//!
//! **TLS.** The TCP connection is opened to the pinned address and TLS is layered on it with the host *as written*,
//! so SNI and certificate verification are about the name the operator typed. Hostname verification is rustls's and
//! cannot be turned off here — the line JSSE needed (`setEndpointIdentificationAlgorithm("HTTPS")`) is the default;
//! the protocols are TLS 1.3 and 1.2. The trust is the runtime's (the authorities compiled in, or the bundle
//! `VECTISPIRE_TLS_CA_BUNDLE` names, which replaces them as the Java truststore does) — unless the configuration pins
//! the collector's own CA, which then replaces it for this connection alone.
//!
//! **Timeouts.** The connect has one per address; the handshake and the write share one deadline, past which the
//! socket is dropped. A collector that accepts a connection and then stops reading would otherwise hold the relay,
//! and with it every message behind this one — Java's watchdog thread, as a `tokio::time::timeout`.
//!
//! **One connection per message**, as Java: a pooled connection would turn "we checked this destination" into "we
//! checked it once".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use vectispire_cp_outbound::{Destination, OutboundFailure};
use vectispire_domain::siem::{CollectorCa, SiemProtocol, syslog};
use vectispire_tls::TlsTrust;

/// The largest UDP payload IPv4 can carry. Past it the datagram is not truncated, it is not sent.
pub const MAX_DATAGRAM: usize = 65_507;

/// The runtime's trust could not be read — a bundle that is no longer what it was at start. Refused at start.
#[derive(Debug, thiserror::Error)]
#[error("the TLS trust for syslog collectors could not be read: {0}")]
pub struct TrustUnreadable(String);

/// The sender.
#[derive(Clone)]
pub struct SyslogSender {
    runtime: Arc<RootCertStore>,
}

impl std::fmt::Debug for SyslogSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SyslogSender").field("runtime_authorities", &self.runtime.len()).finish()
    }
}

impl SyslogSender {
    /// Over the runtime's trust: the authorities compiled in, or the operator's bundle alone.
    ///
    /// **The bundle is read again here, from the path the runtime read it from**, because `TlsTrust` holds reqwest's
    /// certificates, which do not give their DER back. Read once, at start, as the runtime reads it; a file that no
    /// longer parses is refused, never replaced by the defaults.
    pub fn new(trust: &TlsTrust) -> Result<SyslogSender, TrustUnreadable> {
        let runtime = match trust {
            TlsTrust::BuiltIn => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
            TlsTrust::Bundle { path, .. } => {
                let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
                    .map_err(|error| TrustUnreadable(format!("{}: {error}", path.display())))?
                    .collect::<Result<_, _>>()
                    .map_err(|error| TrustUnreadable(format!("{}: {error}", path.display())))?;
                let mut roots = RootCertStore::empty();
                let (added, _) = roots.add_parsable_certificates(certificates);
                if added == 0 {
                    return Err(TrustUnreadable(format!("{} holds no usable certificate", path.display())));
                }
                roots
            }
        };
        Ok(SyslogSender { runtime: Arc::new(runtime) })
    }

    /// Sends, or fails with an `OutboundFailureException`'s sentence — which the outbox turns into a retry.
    ///
    /// `message` is an RFC 5424 message, unframed: this frames it for the transport. `pinned` is the CA the
    /// collector's certificate must chain to, in place of the runtime's trust; read for TLS only, and already checked
    /// current by the caller.
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        protocol: SiemProtocol,
        destination: &Destination,
        port: u16,
        message: &str,
        timeout: Duration,
        label: &str,
        pinned: Option<&CollectorCa>,
    ) -> Result<(), OutboundFailure> {
        if destination.addresses.is_empty() {
            // Refused rather than sent unpinned, for PinnedHttpSender's reason: with no checked address, the only way
            // to send would be to resolve the name again here.
            return Err(OutboundFailure::new(format!(
                "{label}: the host {} does not resolve, so no checked address exists to send to.",
                destination.host
            )));
        }
        match protocol {
            SiemProtocol::SyslogUdp => send_datagram(destination, port, message, label).await,
            SiemProtocol::SyslogTcp => {
                let stream = connect(destination, port, timeout, label).await?;
                write_frame(stream, &syslog::octet_counted(message), timeout, label).await
            }
            SiemProtocol::SyslogTls => {
                let roots = match pinned {
                    Some(ca) => Arc::new(pinned_roots(ca, label)?),
                    None => self.runtime.clone(),
                };
                let config = client_config(roots, label)?;
                let name = ServerName::try_from(destination.host.clone()).map_err(|error| {
                    OutboundFailure::new(format!(
                        "{label}: {} is not a name TLS can verify ({error}).",
                        destination.host
                    ))
                })?;
                let stream = connect(destination, port, timeout, label).await?;
                let frame = syslog::octet_counted(message);
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let exchange = async {
                    let tls = connector.connect(name, stream).await?;
                    write_all_and_close(tls, &frame).await
                };
                within(timeout, exchange, label).await
            }
            SiemProtocol::Webhook => {
                Err(OutboundFailure::new(format!("{label}: a webhook is sent over HTTP, not syslog.")))
            }
        }
    }
}

/// One datagram, RFC 5426: no framing, the datagram is the message.
///
/// **Fire and forget, and that is UDP's contract, not ours.** A datagram that is sent is a datagram the network may
/// drop; nothing comes back to say so, and the outbox marks it delivered.
async fn send_datagram(
    destination: &Destination,
    port: u16,
    message: &str,
    label: &str,
) -> Result<(), OutboundFailure> {
    let payload = message.as_bytes();
    if payload.len() > MAX_DATAGRAM {
        return Err(OutboundFailure::new(format!(
            "{label}: a {}-byte event does not fit in one UDP datagram.",
            payload.len()
        )));
    }
    // The first checked address, as Java sends to `addresses().getFirst()`.
    let Some(address) = destination.addresses.first().copied() else {
        return Err(OutboundFailure::new(format!("{label}: no checked address to send to.")));
    };
    let local: IpAddr = match address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let failed = |error: std::io::Error| OutboundFailure::caused_by(format!("{label}: {error}"), error);
    let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await.map_err(failed)?;
    socket.send_to(payload, SocketAddr::new(address, port)).await.map_err(failed)?;
    Ok(())
}

/// The first checked address that accepts, in the order the guard resolved them. Every one of them passed the policy,
/// so trying the next is not a way around the check — it is what a name with an IPv6 and an IPv4 answer needs when one
/// of the two families is down.
async fn connect(
    destination: &Destination,
    port: u16,
    timeout: Duration,
    label: &str,
) -> Result<TcpStream, OutboundFailure> {
    let mut last: Option<String> = None;
    for address in &destination.addresses {
        match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(*address, port))).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(refused)) => last = Some(refused.to_string()),
            Err(_elapsed) => last = Some("connect timed out".to_owned()),
        }
    }
    Err(OutboundFailure::new(format!(
        "{label}: {} is unreachable ({}).",
        destination.url,
        last.as_deref().unwrap_or("no address")
    )))
}

/// The frame on a plain stream, under the deadline.
async fn write_frame(stream: TcpStream, frame: &[u8], timeout: Duration, label: &str) -> Result<(), OutboundFailure> {
    within(timeout, write_all_and_close(stream, frame), label).await
}

/// Writes everything, flushes, and closes the sending side: a half-close tells the collector the stream is complete,
/// and over TLS the close sends `close_notify` first.
async fn write_all_and_close<S: AsyncWrite + Unpin>(mut stream: S, frame: &[u8]) -> std::io::Result<()> {
    stream.write_all(frame).await?;
    stream.flush().await?;
    stream.shutdown().await
}

/// The exchange under one deadline; its failure in Java's words.
async fn within(
    timeout: Duration,
    exchange: impl std::future::Future<Output = std::io::Result<()>>,
    label: &str,
) -> Result<(), OutboundFailure> {
    match tokio::time::timeout(timeout, exchange).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failed)) => Err(OutboundFailure::caused_by(format!("{label}: {failed}"), failed)),
        Err(_elapsed) => Err(OutboundFailure::new(format!(
            "{label}: the collector did not accept the event within {}s",
            timeout.as_secs()
        ))),
    }
}

/// The pinned CA and nothing else. Built per message: a cached store would outlive the CA an administrator has just
/// replaced.
fn pinned_roots(ca: &CollectorCa, label: &str) -> Result<RootCertStore, OutboundFailure> {
    let mut roots = RootCertStore::empty();
    for anchor in ca.anchors() {
        roots.add(CertificateDer::from(anchor.der.clone())).map_err(|error| {
            OutboundFailure::new(format!("{label}: the pinned collector CA could not be loaded ({error})."))
        })?;
    }
    Ok(roots)
}

fn client_config(roots: Arc<RootCertStore>, label: &str) -> Result<rustls::ClientConfig, OutboundFailure> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| OutboundFailure::new(format!("{label}: TLS could not be set up ({error}).")))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
