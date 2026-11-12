//! A database of its own on each engine, migrated by `vectispire-migrate` — the runner held to the real Flyway by
//! its own oracle.
//!
//! The database is `vectispire_cp_db::testing`'s: one of its own for each test, in a throwaway container or on
//! the shared server `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names (see that module).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::time::Duration;

use vectispire_domain::secret::Secret;

// ---- what the services are composed with in the tests ----

use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_siem::{SendError, Transport};
use vectispire_domain::siem::{CefEvent, CollectorCa, SiemEndpoint};

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;

pub const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — test fixture

/// Encryption at rest with a local key, as the deployment configures one.
pub fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(Encryption::new(&config, door).expect("a local key"))
}

/// A clock that says what it is told; the system's until then.
#[derive(Debug, Default)]
pub struct TestClock(Mutex<Option<OffsetDateTime>>);

impl TestClock {
    pub fn at(instant: OffsetDateTime) -> Arc<TestClock> {
        Arc::new(TestClock(Mutex::new(Some(instant))))
    }

    pub fn system() -> Arc<TestClock> {
        Arc::new(TestClock(Mutex::new(None)))
    }

    fn read(&self) -> OffsetDateTime {
        self.0.lock().unwrap().unwrap_or_else(OffsetDateTime::now_utc)
    }
}

impl vectispire_cp_audit::Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.read()
    }
}

impl vectispire_cp_maintenance::Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        self.read()
    }
}

/// What a recording transport was handed, in the reference set's words: the destination, the header, the CA's
/// subject and the CEF line at the reference's version.
pub fn describe(
    endpoint: &SiemEndpoint,
    header: Option<&Secret>,
    ca: Option<&CollectorCa>,
    event: &CefEvent,
) -> String {
    let destination = match endpoint {
        SiemEndpoint::Webhook { url } => format!("WEBHOOK {url}"),
        SiemEndpoint::Syslog { protocol, host, port } => format!("{} {host} {port}", protocol.name()),
    };
    format!(
        "{destination} | header={} | ca={} | {}",
        header.map_or("null", Secret::expose),
        ca.map_or("null", CollectorCa::subject),
        event.to_cef_string(Some("2.3.0"))
    )
}

/// What a transport was handed: the destination, the header and the CA's subject as text, the event.
pub type Handed = (SiemEndpoint, Option<String>, Option<String>, CefEvent);

/// A transport that records what it was handed and answers what it is told to.
#[derive(Default)]
pub struct Recording {
    pub sent: Mutex<Vec<String>>,
    pub events: Mutex<Vec<Handed>>,
    pub answer: Mutex<Option<SendError>>,
}

impl Recording {
    pub fn answering(&self, answer: Option<SendError>) {
        *self.answer.lock().unwrap() = answer;
    }

    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl Transport for Recording {
    fn send<'a>(
        &'a self,
        endpoint: &'a SiemEndpoint,
        header: Option<&'a Secret>,
        ca: Option<&'a CollectorCa>,
        event: &'a CefEvent,
    ) -> BoxFuture<'a, Result<(), SendError>> {
        self.sent.lock().unwrap().push(describe(endpoint, header, ca, event));
        self.events.lock().unwrap().push((
            endpoint.clone(),
            header.map(|header| header.expose().to_owned()),
            ca.map(|ca| ca.subject().to_owned()),
            event.clone(),
        ));
        let answer = self.answer.lock().unwrap().clone();
        Box::pin(async move { answer.map_or(Ok(()), Err) })
    }
}

// ---- a private CA and a collector certificate it issued, made per run ----

/// A CA, the certificate it issued to `127.0.0.1` and `collector.test`, and its key — what no system store holds,
/// so only a pinned CA reaches it. The `openssl` command makes them; absent, the TLS tests fail rather than skip.
pub struct Pki {
    pub directory: tempfile::TempDir,
    pub ca_pem: String,
    pub server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    pub server_key: rustls_pki_types::PrivateKeyDer<'static>,
}

fn openssl(directory: &std::path::Path, arguments: &[&str]) {
    let output = Command::new("openssl").args(arguments).current_dir(directory).output().expect("the openssl command");
    assert!(output.status.success(), "openssl {arguments:?}: {}", String::from_utf8_lossy(&output.stderr));
}

impl Pki {
    pub fn create(name: &str) -> Pki {
        use rustls_pki_types::pem::PemObject;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"]);
        openssl(
            path,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                "ca.key",
                "-sha256",
                "-days",
                "2",
                "-subj",
                &format!("/CN={name}"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                "ca.pem",
            ],
        );
        openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key"]);
        openssl(path, &["req", "-new", "-key", "server.key", "-subj", "/CN=collector", "-out", "server.csr"]);
        std::fs::write(
            path.join("server.ext"),
            "subjectAltName=IP:127.0.0.1,DNS:collector.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n\
             extendedKeyUsage=serverAuth\n",
        )
        .unwrap();
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
        let server_chain = rustls_pki_types::CertificateDer::pem_file_iter(path.join("server.pem"))
            .unwrap()
            .map(|certificate| certificate.unwrap())
            .collect();
        let server_key = rustls_pki_types::PrivateKeyDer::from_pem_file(path.join("server.key")).unwrap();
        Pki { ca_pem: std::fs::read_to_string(path.join("ca.pem")).unwrap(), directory, server_chain, server_key }
    }

    /// The CA as a file, for a runtime trust that replaces the authorities with it.
    pub fn ca_path(&self) -> std::path::PathBuf {
        self.directory.path().join("ca.pem")
    }

    /// A TLS collector on loopback: each connection's bytes, once it is closed — empty for a handshake that failed.
    pub async fn listen(&self) -> (u16, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        use tokio::io::AsyncReadExt;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(self.server_chain.clone(), self.server_key.clone_key())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, sender) = (acceptor.clone(), sender.clone());
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut bytes)).await;
                    }
                    let _ = sender.send(bytes);
                });
            }
        });
        (port, receiver)
    }
}

/// A port nothing listens on, on loopback.
pub fn closed_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

/// The datagrams a UDP collector received within `wait`, as text.
pub async fn datagrams(socket: &tokio::net::UdpSocket, wait: Duration) -> Vec<String> {
    let mut received = Vec::new();
    let mut buffer = vec![0u8; 70_000];
    let mut window = wait;
    while let Ok(Ok(length)) = tokio::time::timeout(window, socket.recv(&mut buffer)).await {
        received.push(String::from_utf8_lossy(&buffer[..length]).into_owned());
        window = Duration::from_millis(300);
    }
    received
}
