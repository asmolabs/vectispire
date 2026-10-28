//! The sender against local servers: it connects to the checked address and to no other, refuses what
//! it must refuse, and does not read what it was not told to read.
//!
//! Plain HTTP over loopback for the pin, the redirect, the ceiling and the deadline; TLS from a CA made
//! per run (the `openssl` command — absent, the TLS tests fail rather than skip) for the pinned CA.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vectispire_cp_outbound::pinned_ca::Subject;
use vectispire_cp_outbound::{Destination, Method, PinnedCa, PinnedHttpSender};
use vectispire_tls::TlsTrust;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn sender() -> PinnedHttpSender {
    PinnedHttpSender::new(TlsTrust::BuiltIn)
}

fn destination(host: &str, port: u16, path: &str) -> Destination {
    Destination { url: format!("http://{host}:{port}{path}"), host: host.to_owned(), addresses: vec![LOOPBACK] }
}

/// What a server read: the head as text and the body.
#[derive(Clone, Debug, Default)]
struct Seen {
    head: String,
    body: String,
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Seen {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break buffer.len();
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..end.min(buffer.len())]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            line.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = buffer[end.min(buffer.len())..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Seen { head, body: String::from_utf8_lossy(&body).into_owned() }
}

/// A server answering every connection with `reply(seen)`, and counting them.
async fn serve(
    reply: impl Fn(&Seen) -> Vec<u8> + Send + Sync + 'static,
) -> (u16, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (count, log, reply) = (connections.clone(), requests.clone(), Arc::new(reply));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let (log, reply) = (log.clone(), reply.clone());
            tokio::spawn(async move {
                let seen = read_request(&mut stream).await;
                let answer = reply(&seen);
                log.lock().unwrap().push(seen);
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, connections, requests)
}

fn http(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for header in headers {
        out.push_str(header);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn it_connects_to_the_checked_address_and_the_name_travels() {
    let (port, _, requests) = serve(|_| {
        http("200 OK", &["Content-Type: application/json", "X-Scopes: read", "X-Scopes: write"], b"{\"ok\":true}")
    })
    .await;
    // `rebind.test` resolves nowhere: only the pin can have connected this.
    let answer = sender()
        .send(
            Method::Post,
            &destination("rebind.test", port, "/hook?x=1"),
            &[("X-Token", "t")],
            Some("{\"a\":1}"),
            TIMEOUT,
            "Webhook",
        )
        .await
        .unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, "{\"ok\":true}");
    assert_eq!(answer.header("X-SCOPES"), Some("read"));
    assert_eq!(answer.headers.iter().find(|(name, _)| name == "x-scopes").unwrap().1, vec!["read", "write"]);
    let seen = requests.lock().unwrap()[0].clone();
    assert!(seen.head.starts_with("POST /hook?x=1 HTTP/1.1\r\n"), "{}", seen.head);
    let head = seen.head.to_lowercase();
    assert!(head.contains(&format!("host: rebind.test:{port}\r\n")), "{head}");
    assert!(head.contains("content-type: application/json; charset=utf-8\r\n"), "{head}");
    assert!(head.contains("x-token: t\r\n"), "{head}");
    assert_eq!(seen.body, "{\"a\":1}");
}

#[tokio::test]
async fn each_verb_is_sent_and_a_get_carries_no_body() {
    let (port, _, requests) = serve(|_| http("204 No Content", &[], b"")).await;
    for (method, verb) in [(Method::Get, "GET"), (Method::Put, "PUT"), (Method::Patch, "PATCH"), (Method::Post, "POST")]
    {
        let answer =
            sender().send(method, &destination("h.test", port, "/r"), &[], Some("{}"), TIMEOUT, "L").await.unwrap();
        assert_eq!(answer.status, 204);
        let seen = requests.lock().unwrap().last().unwrap().clone();
        assert!(seen.head.starts_with(&format!("{verb} /r HTTP/1.1")), "{}", seen.head);
        assert_eq!(seen.body, if method == Method::Get { "" } else { "{}" }, "{verb}");
    }
}

#[tokio::test]
async fn a_redirect_is_returned_and_never_followed() {
    let (second, second_connections, _) = serve(|_| http("200 OK", &[], b"you should not be here")).await;
    let location = format!("Location: http://127.0.0.1:{second}/second");
    let (first, _, _) = serve(move |_| http("302 Found", &[location.as_str()], b"moved")).await;

    let answer = sender().send(Method::Get, &destination("h.test", first, "/"), &[], None, TIMEOUT, "L").await.unwrap();
    assert_eq!(answer.status, 302);
    assert_eq!(answer.header("location"), Some(format!("http://127.0.0.1:{second}/second").as_str()));

    // A file download reports where the redirect points, and reads the page it answered with no further.
    let download = sender().download(&destination("h.test", first, "/f"), &[], TIMEOUT, "L", 1024).await.unwrap();
    assert_eq!(download.status, 302);
    assert_eq!(download.location.as_deref(), Some(format!("http://127.0.0.1:{second}/second").as_str()));
    assert!(download.body.is_empty(), "an answer that is not the file is dropped");
    assert_eq!(second_connections.load(Ordering::SeqCst), 0, "the redirect's target was never contacted");
}

#[tokio::test]
async fn a_host_that_was_not_checked_is_never_resolved() {
    let (port, connections, _) = serve(|_| http("200 OK", &[], b"x")).await;
    // The URL names a host the guard never saw: what a rewritten URI, or a redirect somebody
    // re-enabled, would look like from here.
    let mut tampered = destination("checked.test", port, "/");
    tampered.url = format!("http://other.test:{port}/");
    let failure = sender().send(Method::Get, &tampered, &[], None, TIMEOUT, "Webhook").await.unwrap_err();
    assert!(
        failure.message().starts_with("Webhook: the request tried to reach a host that was never checked (other.test was not the checked host (checked.test))"),
        "{}",
        failure.message()
    );
    assert_eq!(connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_checked_address_means_no_request() {
    let mut unresolved = destination("unresolved.test", 9, "/");
    unresolved.addresses.clear();
    let failure = sender().send(Method::Get, &unresolved, &[], None, TIMEOUT, "Webhook").await.unwrap_err();
    assert_eq!(
        failure.message(),
        "Webhook: the host unresolved.test does not resolve, so no checked address exists to send to."
    );
}

/// A server that declares a quarter of a gigabyte and writes it until the client goes away.
async fn flood() -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let written = Arc::new(AtomicU64::new(0));
    let total = written.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let total = total.clone();
            tokio::spawn(async move {
                let _ = read_request(&mut stream).await;
                let declared: u64 = 256 * 1024 * 1024;
                let _ =
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").as_bytes()).await;
                let block = vec![b'x'; 64 * 1024];
                while total.load(Ordering::SeqCst) < declared {
                    if stream.write_all(&block).await.is_err() {
                        break;
                    }
                    total.fetch_add(block.len() as u64, Ordering::SeqCst);
                }
            });
        }
    });
    (port, written)
}

#[tokio::test]
async fn an_answer_past_the_ceiling_is_refused_and_not_read_further() {
    let (port, written) = flood().await;
    let failure = sender()
        .send_bounded(Method::Get, &destination("h.test", port, "/"), &[], None, TIMEOUT, "Webhook", 1000, None)
        .await
        .unwrap_err();
    assert_eq!(failure.message(), "Webhook: the answer is larger than 1000 bytes and was not read further.");
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Drained to the end — the quarter gigabyte the server offered — it would be 268435456; abandoned,
    // the socket buffers are all the server could fill.
    assert!(
        written.load(Ordering::SeqCst) < 64 * 1024 * 1024,
        "the answer was read on: {} bytes written",
        written.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn a_download_over_its_ceiling_fails_and_exactly_at_it_does_not() {
    let (port, _, _) = serve(|_| http("200 OK", &[], &[b'a'; 100])).await;
    let at = sender().download(&destination("h.test", port, "/"), &[], TIMEOUT, "L", 100).await.unwrap();
    assert_eq!(at.body.len(), 100);
    let over = sender().download(&destination("h.test", port, "/"), &[], TIMEOUT, "L", 99).await.unwrap_err();
    assert_eq!(over.message(), "L: the answer is larger than 99 bytes and was not read further.");
}

#[tokio::test]
async fn an_error_page_is_read_within_a_small_ceiling_and_dropped() {
    let (port, _, _) = serve(|_| http("404 Not Found", &[], &[b'e'; 2 * 1024 * 1024])).await;
    // The caller allows 10 MiB for the file; an error page past one MiB is refused, not drained.
    let failure =
        sender().download(&destination("h.test", port, "/"), &[], TIMEOUT, "L", 10 * 1024 * 1024).await.unwrap_err();
    assert!(failure.message().contains("larger than 1048576 bytes"), "{}", failure.message());
}

#[tokio::test]
async fn an_exchange_that_outlasts_two_timeouts_is_abandoned() {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = read_request(&mut stream).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n").await;
                // One byte just inside every read timeout, for far longer than the exchange may last.
                for _ in 0..50 {
                    if stream.write_all(b"x").await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
        }
    });
    let started = Instant::now();
    let failure = sender()
        .send(Method::Get, &destination("h.test", port, "/"), &[], None, Duration::from_millis(1500), "Webhook")
        .await
        .unwrap_err();
    assert_eq!(failure.message(), "Webhook: no complete answer within 3 s; the request was abandoned.");
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

#[tokio::test]
async fn the_answer_is_read_in_the_charset_it_names() {
    let (port, _, _) =
        serve(|_| http("200 OK", &["Content-Type: text/plain; charset=ISO-8859-1"], &[0x63, 0x61, 0x66, 0xe9])).await;
    let latin1 = sender().send(Method::Get, &destination("h.test", port, "/"), &[], None, TIMEOUT, "L").await.unwrap();
    assert_eq!(latin1.body, "café");
    let (port, _, _) = serve(|_| http("200 OK", &[], "café".as_bytes())).await;
    let utf8 = sender().send(Method::Get, &destination("h.test", port, "/"), &[], None, TIMEOUT, "L").await.unwrap();
    assert_eq!(utf8.body, "café");
}

#[tokio::test]
async fn a_refused_connection_says_what_was_being_sent() {
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let failure = sender()
        .send(Method::Get, &destination("h.test", port, "/"), &[], None, TIMEOUT, "Ticket sync")
        .await
        .unwrap_err();
    assert!(failure.message().starts_with("Ticket sync: "), "{}", failure.message());
}

// ---- TLS, from a CA made for the run ----

struct Pki {
    _directory: tempfile::TempDir,
    ca_path: std::path::PathBuf,
    ca_pem: String,
    other_ca_pem: String,
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    server_key: rustls_pki_types::PrivateKeyDer<'static>,
}

fn openssl(directory: &std::path::Path, arguments: &[&str]) {
    let output = std::process::Command::new("openssl")
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("the openssl command");
    assert!(output.status.success(), "openssl {arguments:?}: {}", String::from_utf8_lossy(&output.stderr));
}

fn pki() -> Pki {
    use rustls_pki_types::pem::PemObject;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path();
    for name in ["ca", "other"] {
        openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", &format!("{name}.key")]);
        openssl(
            path,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &format!("{name}.key"),
                "-sha256",
                "-days",
                "2",
                "-subj",
                &format!("/CN=Vectispire test {name} CA"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                &format!("{name}.pem"),
            ],
        );
    }
    openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key"]);
    openssl(path, &["req", "-new", "-key", "server.key", "-subj", "/CN=pinned.test", "-out", "server.csr"]);
    std::fs::write(path.join("server.ext"), "subjectAltName=DNS:pinned.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n").unwrap();
    openssl(
        path,
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            "server.ext",
            "-out",
            "server.pem",
        ],
    );
    let server_chain =
        rustls_pki_types::CertificateDer::pem_file_iter(path.join("server.pem")).unwrap().map(|c| c.unwrap()).collect();
    let server_key = rustls_pki_types::PrivateKeyDer::from_pem_file(path.join("server.key")).unwrap();
    Pki {
        ca_path: path.join("ca.pem"),
        ca_pem: std::fs::read_to_string(path.join("ca.pem")).unwrap(),
        other_ca_pem: std::fs::read_to_string(path.join("other.pem")).unwrap(),
        _directory: directory,
        server_chain,
        server_key,
    }
}

async fn serve_tls(pki: &Pki) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key.clone_key())
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else { return };
                let _ = read_request(&mut tls).await;
                let _ = tls.write_all(&http("200 OK", &[], b"secure")).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

fn tls_destination(host: &str, port: u16) -> Destination {
    Destination { url: format!("https://{host}:{port}/"), host: host.to_owned(), addresses: vec![LOOPBACK] }
}

fn subject() -> Subject {
    Subject { field: "The CA".to_owned(), server: "git.example.org".to_owned() }
}

#[tokio::test]
async fn a_pinned_ca_is_trusted_for_that_request_in_place_of_the_public_ones() {
    let pki = pki();
    let port = serve_tls(&pki).await;
    let ca = PinnedCa::read(Some(&pki.ca_pem), &subject()).unwrap();
    let answer = sender()
        .send_bounded(Method::Get, &tls_destination("pinned.test", port), &[], None, TIMEOUT, "Forge", 1024, Some(&ca))
        .await
        .unwrap();
    assert_eq!((answer.status, answer.body.as_str()), (200, "secure"));

    // Without it the server's certificate chains to nobody the sender trusts.
    let untrusted = sender()
        .send(Method::Get, &tls_destination("pinned.test", port), &[], None, TIMEOUT, "Forge")
        .await
        .unwrap_err();
    assert!(untrusted.message().starts_with("Forge: "), "{}", untrusted.message());

    // Another CA, pinned, is no better: the pin names whom to trust, and it is not this one.
    let wrong = PinnedCa::read(Some(&pki.other_ca_pem), &subject()).unwrap();
    let refused = sender()
        .send_bounded(
            Method::Get,
            &tls_destination("pinned.test", port),
            &[],
            None,
            TIMEOUT,
            "Forge",
            1024,
            Some(&wrong),
        )
        .await
        .unwrap_err();
    assert!(refused.message().starts_with("Forge: "), "{}", refused.message());
}

#[tokio::test]
async fn a_pinned_ca_replaces_the_runtime_s_bundle_for_that_request_and_does_not_join_it() {
    let pki = pki();
    let port = serve_tls(&pki).await;
    // The runtime trusts the CA that signed the server: the plain request goes through.
    let runtime = PinnedHttpSender::new(TlsTrust::from_bundle(&pki.ca_path).unwrap());
    let plain =
        runtime.send(Method::Get, &tls_destination("pinned.test", port), &[], None, TIMEOUT, "Forge").await.unwrap();
    assert_eq!(plain.status, 200);
    // Pin another CA for one request: the runtime's trust is *replaced*, so the same server is refused.
    let other = PinnedCa::read(Some(&pki.other_ca_pem), &subject()).unwrap();
    let refused = runtime
        .send_bounded(
            Method::Get,
            &tls_destination("pinned.test", port),
            &[],
            None,
            TIMEOUT,
            "Forge",
            1024,
            Some(&other),
        )
        .await
        .unwrap_err();
    assert!(refused.message().starts_with("Forge: "), "{}", refused.message());
    // And the next request, with no pin, is back to the runtime's own.
    let after =
        runtime.send(Method::Get, &tls_destination("pinned.test", port), &[], None, TIMEOUT, "Forge").await.unwrap();
    assert_eq!(after.status, 200);
}

#[tokio::test]
async fn a_pinned_ca_changes_whom_to_trust_never_whether_the_name_is_checked() {
    let pki = pki();
    let port = serve_tls(&pki).await;
    let ca = PinnedCa::read(Some(&pki.ca_pem), &subject()).unwrap();
    // The certificate is for pinned.test: the same server, reached under another name, is refused.
    let failure = sender()
        .send_bounded(Method::Get, &tls_destination("wrong.test", port), &[], None, TIMEOUT, "Forge", 1024, Some(&ca))
        .await
        .unwrap_err();
    assert!(failure.message().starts_with("Forge: "), "{}", failure.message());
}

#[test]
fn a_pinned_ca_is_read_as_the_java_class_reads_it() {
    let pki = pki();
    let read = |pem: Option<&str>| PinnedCa::read(pem, &subject()).map(|_| ()).map_err(|e| e.0);
    assert_eq!(read(None), Err("The CA is empty.".to_owned()));
    assert_eq!(read(Some("  \n ")), Err("The CA is empty.".to_owned()));
    assert_eq!(
        read(Some(&"a".repeat(16_385))),
        Err("The CA is 16385 characters long; at most 16384 are accepted.".to_owned())
    );
    assert_eq!(
        read(Some("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")),
        Err("The CA holds something other than certificates. Paste the CA's certificate in PEM form (-----BEGIN CERTIFICATE-----); a private key never belongs here.".to_owned())
    );
    assert_eq!(
        read(Some("not a certificate")),
        Err("The CA holds no certificate. Paste it in PEM form, -----BEGIN CERTIFICATE----- included.".to_owned())
    );
    assert_eq!(
        read(Some("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")),
        Err("The CA is not a readable PEM certificate.".to_owned())
    );
    assert_eq!(read(Some(&pki.ca_pem)), Ok(()));
    let nine = vec![pki.ca_pem.trim().to_owned(); 9].join("\n");
    assert_eq!(read(Some(&nine)), Err("The CA holds more than 8 certificates.".to_owned()));
    let eight = vec![pki.ca_pem.trim().to_owned(); 8].join("\n");
    assert_eq!(read(Some(&eight)), Ok(()));
}

#[tokio::test]
async fn a_name_that_changes_its_answer_after_the_check_is_connected_to_at_the_checked_address() {
    use vectispire_cp_outbound::address::Raw;
    use vectispire_cp_outbound::{OutboundPolicy, OutboundUrlGuard};

    let (port, connections, _) = serve(|_| http("200 OK", &[], b"checked")).await;
    // DNS rebinding: the first lookup answers the loopback the policy allows, every later one the
    // metadata endpoint. Resolved a second time by the client, the request would go there.
    let lookups = Arc::new(AtomicUsize::new(0));
    let counter = lookups.clone();
    let guard = OutboundUrlGuard::with_resolver(
        move |_: &str| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![Raw::V4([127, 0, 0, 1])]
            } else {
                vec![Raw::V4([169, 254, 169, 254])]
            }
        },
        Vec::new(),
    );
    let destination = guard
        .validate_and_resolve(
            &format!("http://rebind.example.test:{port}/"),
            OutboundPolicy::InternalAllowed,
            "Scan API",
        )
        .unwrap();
    let answer = sender().send(Method::Get, &destination, &[], None, TIMEOUT, "Scan API").await.unwrap();
    assert_eq!(answer.body, "checked");
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    assert_eq!(lookups.load(Ordering::SeqCst), 1, "the name was resolved once: by the guard, and by nobody after it");
}

// ---- no proxy, whatever the environment says ----
//
// A proxy would be the one place the checked address is not the address reached. The environment is
// process-wide and cannot be set from a test without `unsafe`, so the test runs *itself* as a child with
// `HTTP_PROXY` pointing at a spy, and asserts the request reached its server and the spy saw nothing.

#[test]
fn the_environment_s_proxy_is_never_used() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (spy, connections) = runtime.block_on(async {
        let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        (port, connections)
    });
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inner_the_request_goes_to_its_server_with_a_proxy_in_the_environment",
            "--include-ignored",
            "--nocapture",
        ])
        .env("HTTP_PROXY", format!("http://127.0.0.1:{spy}"))
        .env("http_proxy", format!("http://127.0.0.1:{spy}"))
        .env("ALL_PROXY", format!("http://127.0.0.1:{spy}"))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(connections.load(Ordering::SeqCst), 0, "the request went through the proxy of the environment");
}

#[tokio::test]
#[ignore = "run by the_environment_s_proxy_is_never_used, as a child with a proxy in its environment"]
async fn inner_the_request_goes_to_its_server_with_a_proxy_in_the_environment() {
    let (port, connections, _) = serve(|_| http("200 OK", &[], b"direct")).await;
    let answer = sender().send(Method::Get, &destination("h.test", port, "/"), &[], None, TIMEOUT, "L").await.unwrap();
    assert_eq!(answer.body, "direct");
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}
