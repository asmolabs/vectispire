//! The transports against real sockets on loopback — `SyslogSenderTest`, `SiemCollectorCaRoutesTest`'s TLS cases and
//! what `SiemSender` hands the wire, held to `reference/siem/module.json` where bytes leave.
//!
//! Loopback is reached the way an operator reaches an internal collector: the private-destination switch on, not a
//! test seam. The TLS collector's certificate comes from a CA made for the run (`openssl`), which no store holds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use vectispire_cp_outbound::address::Raw;
use vectispire_cp_outbound::{Destination, OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_siem::{
    LABEL, MAX_DATAGRAM, PrivateDestinations, SendError, SiemSender, SyslogSender, TIMEOUT, body,
};
use vectispire_domain::instant::Instant;
use vectispire_domain::secret::Secret;
use vectispire_domain::siem::{CefEvent, CollectorCa, SecurityEventType, SiemEndpoint, SiemProtocol, syslog};
use vectispire_tls::TlsTrust;

use support::Pki;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MESSAGE: &str = "<85>1 2026-09-26T10:00:00.000Z h vectispire - VECTI-SEC-999 - CEF:0|Vectispire|é";
const SHORT: Duration = Duration::from_secs(5);

fn destination(host: &str, port: u16) -> Destination {
    Destination { url: format!("{host}:{port}"), host: host.to_owned(), addresses: vec![LOOPBACK] }
}

fn syslog_sender() -> SyslogSender {
    SyslogSender::new(&TlsTrust::BuiltIn).unwrap()
}

fn now() -> Instant {
    let at = time::OffsetDateTime::now_utc();
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

#[tokio::test]
async fn udp_is_one_datagram_the_message_unframed() {
    let collector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    syslog_sender()
        .send(SiemProtocol::SyslogUdp, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", None)
        .await
        .unwrap();
    assert_eq!(support::datagrams(&collector, SHORT).await, vec![MESSAGE.to_owned()]);
}

#[tokio::test]
async fn tcp_is_the_message_octet_counted_then_the_stream_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    syslog_sender()
        .send(SiemProtocol::SyslogTcp, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", None)
        .await
        .unwrap();
    assert_eq!(received.await.unwrap(), syslog::octet_counted(MESSAGE));
}

#[tokio::test]
async fn tls_reaches_the_collector_its_pinned_ca_vouches_for_and_only_then() {
    let pki = Pki::create("Corp SOC Root");
    let (port, mut received) = pki.listen().await;
    let pinned = CollectorCa::parse(Some(&pki.ca_pem), now()).unwrap();
    let sender = syslog_sender();

    // The runtime's authorities do not hold the private CA: refused, whatever else holds.
    let refused = sender
        .send(SiemProtocol::SyslogTls, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", None)
        .await
        .unwrap_err();
    assert!(refused.message().starts_with("SIEM: "), "{}", refused.message());
    assert!(received.recv().await.unwrap().is_empty());

    // Another CA pinned: refused too — pinning replaces the store, it does not add to it.
    let other = CollectorCa::parse(Some(&Pki::create("Someone Else").ca_pem), now()).unwrap();
    sender
        .send(SiemProtocol::SyslogTls, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", Some(&other))
        .await
        .unwrap_err();
    assert!(received.recv().await.unwrap().is_empty());

    sender
        .send(SiemProtocol::SyslogTls, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", Some(&pinned))
        .await
        .unwrap();
    assert_eq!(received.recv().await.unwrap(), syslog::octet_counted(MESSAGE));

    // The name as written is what is verified: the certificate names `collector.test`, reached at the same address.
    sender
        .send(
            SiemProtocol::SyslogTls,
            &destination("collector.test", port),
            port,
            MESSAGE,
            SHORT,
            "SIEM",
            Some(&pinned),
        )
        .await
        .unwrap();
    assert_eq!(received.recv().await.unwrap(), syslog::octet_counted(MESSAGE));
}

#[tokio::test]
async fn tls_refuses_a_certificate_issued_to_another_name_even_from_the_pinned_ca() {
    // Trusted, and issued to 127.0.0.1 and collector.test; configured as other.test, which resolves to the same
    // address. Without hostname verification the handshake would succeed: any certificate the CA issued would do.
    let pki = Pki::create("Corp SOC Root");
    let (port, mut received) = pki.listen().await;
    let pinned = CollectorCa::parse(Some(&pki.ca_pem), now()).unwrap();
    let refused = syslog_sender()
        .send(SiemProtocol::SyslogTls, &destination("other.test", port), port, MESSAGE, SHORT, "SIEM", Some(&pinned))
        .await
        .unwrap_err();
    assert!(refused.message().starts_with("SIEM: "), "{}", refused.message());
    assert!(received.recv().await.unwrap().is_empty());
}

#[tokio::test]
async fn tls_without_a_pin_trusts_the_runtime_s_bundle_which_replaces_the_authorities() {
    let pki = Pki::create("Corp SOC Root");
    let (port, mut received) = pki.listen().await;
    let runtime = SyslogSender::new(&TlsTrust::from_bundle(&pki.ca_path()).unwrap()).unwrap();
    runtime
        .send(SiemProtocol::SyslogTls, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", None)
        .await
        .unwrap();
    assert_eq!(received.recv().await.unwrap(), syslog::octet_counted(MESSAGE));
}

#[tokio::test]
async fn a_pinned_ca_replaces_the_runtime_s_bundle_and_does_not_join_it() {
    let pki = Pki::create("Corp SOC Root");
    let (port, mut received) = pki.listen().await;
    // The runtime trusts the collector's CA; pinning another one must refuse it all the same.
    let runtime = SyslogSender::new(&TlsTrust::from_bundle(&pki.ca_path()).unwrap()).unwrap();
    let other = CollectorCa::parse(Some(&Pki::create("Someone Else").ca_pem), now()).unwrap();
    runtime
        .send(SiemProtocol::SyslogTls, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", Some(&other))
        .await
        .unwrap_err();
    assert!(received.recv().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_collector_that_never_answers_the_handshake_is_given_up_on_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let keep = held.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            keep.lock().unwrap().push(stream);
        }
    });
    let pinned = CollectorCa::parse(Some(&Pki::create("Corp").ca_pem), now()).unwrap();
    let started = std::time::Instant::now();
    let failed = syslog_sender()
        .send(
            SiemProtocol::SyslogTls,
            &destination("127.0.0.1", port),
            port,
            MESSAGE,
            Duration::from_secs(1),
            "SIEM",
            Some(&pinned),
        )
        .await
        .unwrap_err();
    assert_eq!(failed.message(), "SIEM: the collector did not accept the event within 1s");
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
}

#[tokio::test]
async fn a_closed_port_is_a_failure_that_says_where() {
    let port = support::closed_port();
    let failed = syslog_sender()
        .send(SiemProtocol::SyslogTcp, &destination("127.0.0.1", port), port, MESSAGE, SHORT, "SIEM", None)
        .await
        .unwrap_err();
    assert!(failed.message().starts_with(&format!("SIEM: 127.0.0.1:{port} is unreachable (")), "{}", failed.message());
}

#[tokio::test]
async fn a_destination_with_no_checked_address_is_refused_rather_than_resolved_again() {
    let unresolved = Destination { url: "nowhere:514".into(), host: "nowhere".into(), addresses: Vec::new() };
    for protocol in [SiemProtocol::SyslogUdp, SiemProtocol::SyslogTcp, SiemProtocol::SyslogTls] {
        let failed = syslog_sender().send(protocol, &unresolved, 514, MESSAGE, SHORT, "SIEM", None).await.unwrap_err();
        assert_eq!(
            failed.message(),
            "SIEM: the host nowhere does not resolve, so no checked address exists to send to."
        );
    }
}

#[tokio::test]
async fn an_event_too_large_for_one_datagram_is_refused_not_truncated() {
    let huge = "x".repeat(MAX_DATAGRAM + 1);
    let failed = syslog_sender()
        .send(SiemProtocol::SyslogUdp, &destination("127.0.0.1", 9), 9, &huge, SHORT, "SIEM", None)
        .await
        .unwrap_err();
    assert_eq!(failed.message(), format!("SIEM: a {}-byte event does not fit in one UDP datagram.", MAX_DATAGRAM + 1));
    // At the limit this refusal does not apply. Whether the datagram then leaves is the host's: macOS caps one at
    // 9,216 bytes by default and answers "Message too long" — a failure the outbox retries, said in the OS's words.
    let at_limit = syslog_sender()
        .send(SiemProtocol::SyslogUdp, &destination("127.0.0.1", 9), 9, &"x".repeat(MAX_DATAGRAM), SHORT, "SIEM", None)
        .await;
    if let Err(failed) = at_limit {
        assert!(!failed.message().contains("does not fit"), "{}", failed.message());
    }
}

// ---- SiemSender: the policy, the webhook's bytes, the syslog message ----

struct Switch(bool);

impl PrivateDestinations for Switch {
    fn allowed(&self) -> BoxFuture<'_, Result<bool, String>> {
        let allowed = self.0;
        Box::pin(async move { Ok(allowed) })
    }
}

/// Every name resolves to loopback: no test depends on the machine's DNS.
fn sender(private: bool) -> SiemSender {
    let guard = OutboundUrlGuard::with_resolver(|_: &str| vec![Raw::of(LOOPBACK)], Vec::new());
    SiemSender::new(
        guard,
        PinnedHttpSender::new(TlsTrust::BuiltIn),
        syslog_sender(),
        Arc::new(Switch(private)),
        Some("2.3.0".to_owned()),
    )
    .with_hostname("collector-host")
}

/// One HTTP exchange's request head and body, answered with `status` and `headers`.
async fn webhook(status: &'static str, headers: &'static str) -> (u16, tokio::task::JoinHandle<(String, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head, length) = loop {
            let n = stream.read(&mut chunk).await.unwrap();
            buffer.extend_from_slice(&chunk[..n]);
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buffer[..at + 4]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap_or(0usize);
                buffer.drain(..at + 4);
                break (head, length);
            }
        };
        while buffer.len() < length {
            let n = stream.read(&mut chunk).await.unwrap();
            buffer.extend_from_slice(&chunk[..n]);
        }
        let answer = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n{headers}\r\n");
        stream.write_all(answer.as_bytes()).await.unwrap();
        let _ = stream.shutdown().await;
        (head, String::from_utf8(buffer).unwrap())
    });
    (port, seen)
}

fn event() -> CefEvent {
    CefEvent::builder(SecurityEventType::ApiKeyIssued, Instant { epoch_second: 1_790_856_000, nano: 123_000_000 })
        .message("q\"uote \\ é \u{2028} 😀 / ")
        .user("alice")
        .action("API_KEY_CREATED")
        .build()
        .unwrap()
}

#[tokio::test]
async fn a_webhook_is_one_json_post_whose_body_is_jackson_s_and_carries_the_header() {
    let (port, seen) = webhook("202 Accepted", "").await;
    let url = format!("http://collector.test:{port}/cef");
    let header = Secret::new("Bearer siem-token");
    sender(true).send(&SiemEndpoint::Webhook { url }, Some(&header), None, &event()).await.unwrap();
    let (head, sent) = seen.await.unwrap();
    assert!(head.starts_with("POST /cef HTTP/1.1\r\n"), "{head}");
    let lower = head.to_lowercase();
    assert!(lower.contains("authorization: bearer siem-token\r\n"), "{head}");
    assert!(lower.contains("content-type: application/json; charset=utf-8\r\n"), "{head}");
    assert!(lower.contains(&format!("host: collector.test:{port}\r\n")), "{head}");
    assert_eq!(sent, body(&event().to_cef_string(Some("2.3.0"))));
    assert_eq!(
        sent,
        "{\"cef\":\"CEF:0|Vectispire|ASPM|2.3.0|VECTI-SEC-012|API key issued|5|rt=1790856000123 outcome=success \
         suser=alice act=API_KEY_CREATED msg=q\\\"uote \\\\\\\\ é   😀 / \"}"
    );
}

#[tokio::test]
async fn a_blank_header_is_not_sent() {
    let (port, seen) = webhook("200 OK", "").await;
    let url = format!("http://127.0.0.1:{port}/cef");
    sender(true).send(&SiemEndpoint::Webhook { url }, Some(&Secret::new("  ")), None, &event()).await.unwrap();
    let (head, _) = seen.await.unwrap();
    assert!(!head.to_lowercase().contains("authorization"), "{head}");
}

#[tokio::test]
async fn an_answer_that_is_not_2xx_is_a_failure_with_its_status() {
    for (status, headers, expected) in [
        ("404 Not Found", "", "SIEM export: HTTP 404."),
        ("429 Too Many Requests", "", "SIEM export: HTTP 429, rate-limited."),
        ("403 Forbidden", "Retry-After: 30\r\n", "SIEM export: HTTP 403, rate-limited."),
        ("403 Forbidden", "X-RateLimit-Remaining: 0\r\n", "SIEM export: HTTP 403, rate-limited."),
        ("403 Forbidden", "", "SIEM export: HTTP 403."),
        ("302 Found", "Location: http://169.254.169.254/\r\n", "SIEM export: HTTP 302."),
    ] {
        let (port, seen) = webhook(status, headers).await;
        let url = format!("http://127.0.0.1:{port}/cef");
        let failed = sender(true).send(&SiemEndpoint::Webhook { url }, None, None, &event()).await.unwrap_err();
        assert_eq!(failed, SendError::failed("OutboundStatusException", expected), "{status}");
        seen.await.unwrap();
    }
}

#[tokio::test]
async fn a_private_destination_is_refused_unless_an_administrator_allowed_it() {
    let port = support::closed_port();
    let webhook = SiemEndpoint::Webhook { url: format!("http://127.0.0.1:{port}/cef") };
    let syslog = SiemEndpoint::Syslog { protocol: SiemProtocol::SyslogTcp, host: "127.0.0.1".into(), port };
    for endpoint in [&webhook, &syslog] {
        let refused = sender(false).send(endpoint, None, None, &event()).await.unwrap_err();
        assert!(matches!(refused, SendError::Refused(_)), "{refused:?}");
        assert_eq!(refused.kind(), "UnsafeUrlException");
        assert!(refused.message().starts_with(&format!("{LABEL}: ")), "{}", refused.message());
        // Allowed, the attempt is made, and fails on the closed port rather than on the policy.
        let failed = sender(true).send(endpoint, None, None, &event()).await.unwrap_err();
        assert_eq!(failed.kind(), "OutboundFailureException", "{failed:?}");
    }
}

#[tokio::test]
async fn a_syslog_event_leaves_as_java_s_message_and_never_carries_the_header() {
    let reference = vectispire_testkit::read_json("siem/module.json");
    let java = reference["delivered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "syslog over UDP")
        .unwrap()["answer"]["syslog"]["message"]
        .as_str()
        .unwrap()
        .replace("{hostname}", "collector-host");
    let collector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = collector.local_addr().unwrap().port();
    let queued = vectispire_cp_siem::QueuedEvent::read(reference["delivered"][0]["payload"].as_str().unwrap())
        .unwrap()
        .to_event(reference["messageId"].as_str().unwrap())
        .unwrap();
    let endpoint = SiemEndpoint::Syslog { protocol: SiemProtocol::SyslogUdp, host: "collector.test".into(), port };
    sender(true).send(&endpoint, Some(&Secret::new("Bearer never-sent")), None, &queued).await.unwrap();
    assert_eq!(support::datagrams(&collector, SHORT).await, vec![java]);
    assert_eq!(
        TIMEOUT,
        Duration::from_secs(reference["delivered"][3]["answer"]["syslog"]["timeoutSeconds"].as_u64().unwrap())
    );
    assert_eq!(LABEL, reference["delivered"][3]["answer"]["syslog"]["label"].as_str().unwrap());
}
