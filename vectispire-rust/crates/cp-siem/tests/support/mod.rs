//! A throwaway database on each engine, migrated by `vectispire-migrate` — the runner held to the real Flyway by
//! its own oracle.
//!
//! The engines are the campaign's, by digest (`Engine.java`, `scripts/upgrade-drill.sh`). Every container is
//! `vs-rs-siem-*`, removed on drop; a missing Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::time::{Duration, Instant};

use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-siem-test"; // gitleaks:allow — invented, for a container removed after the test

/// A migrated database.
pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    pub port: u16,
    server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "siem-mysql",
                &[
                    "-p",
                    "127.0.0.1::3306",
                    "-e",
                    &format!("MYSQL_ROOT_PASSWORD={PASSWORD}"),
                    "-e",
                    "MYSQL_DATABASE=vectispire",
                    "-e",
                    "MYSQL_USER=vectispire",
                    "-e",
                    &format!("MYSQL_PASSWORD={PASSWORD}"),
                    MYSQL_IMAGE,
                    // The shipped composition's server flags (docker-compose.yml).
                    "--default-time-zone=+00:00",
                    "--max-allowed-packet=160M",
                ],
            ),
            Engine::PostgreSql => Container::run(
                "siem-postgres",
                &[
                    "-p",
                    "127.0.0.1::5432",
                    "-e",
                    &format!("POSTGRES_PASSWORD={PASSWORD}"),
                    "-e",
                    "POSTGRES_USER=vectispire",
                    "-e",
                    "POSTGRES_DB=vectispire",
                    POSTGRES_IMAGE,
                ],
            ),
        };
        wait_until_ready(engine, &server);
        let (port, jdbc) = match engine {
            Engine::MySql => (server.host_port("3306/tcp"), "jdbc:mysql"),
            Engine::PostgreSql => (server.host_port("5432/tcp"), "jdbc:postgresql"),
        };
        let settings = DbSettings {
            url: DatabaseUrl::parse(&format!("{jdbc}://127.0.0.1:{port}/vectispire")).unwrap(),
            username: "vectispire".into(),
            password: Secret::new(PASSWORD),
            pool: PoolSettings { max_connections: 8, min_connections: 1, ..PoolSettings::default() },
            ca_pem: None,
        };
        let migrated = Migrated { engine, settings, port, server };
        let db = migrated.connect().await;
        let database = match &db {
            Db::MySql(pool) => vectispire_migrate::Database::MySql(pool.clone()),
            Db::PostgreSql(pool) => vectispire_migrate::Database::PostgreSql(pool.clone()),
        };
        vectispire_migrate::run(&database, &vectispire_migrate::Options::default()).await.expect("the schema migrates");
        db.close().await;
        migrated
    }

    pub async fn connect(&self) -> Db {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match Db::connect(&self.settings).await {
                Ok(db) => return db,
                Err(failure) => {
                    assert!(Instant::now() < deadline, "{} never answered: {failure}", self.engine);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// A statement as the superuser, inside the container — for what a test does behind the pool's back.
    pub fn sql_as_admin(&self, statement: &str) -> String {
        match self.engine {
            Engine::MySql => self.server.exec(&[
                "mysql",
                "-uroot",
                &format!("-p{PASSWORD}"),
                "-N",
                "--default-character-set=utf8mb4",
                "vectispire",
                "-e",
                statement,
            ]),
            Engine::PostgreSql => self.server.exec(&["psql", "-U", "vectispire", "-tAc", statement]),
        }
    }
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        // A real query, not `mysqladmin ping`: the MySQL image answers pings from its temporary initialisation
        // server, which then stops and restarts.
        let probe = match engine {
            Engine::MySql => Command::new("docker")
                .args([
                    "exec",
                    &server.name,
                    "mysql",
                    "-uvectispire",
                    &format!("-p{PASSWORD}"),
                    "-h127.0.0.1",
                    "-e",
                    "select 1",
                    "vectispire",
                ])
                .output(),
            Engine::PostgreSql => Command::new("docker")
                .args(["exec", &server.name, "psql", "-h", "127.0.0.1", "-U", "vectispire", "-tAc", "select 1"])
                .output(),
        };
        if probe.is_ok_and(|output| output.status.success()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{engine} did not start: {}",
            docker(&["logs", "--tail", "40", &server.name])
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ---- what the services are composed with in the tests ----

use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use time::OffsetDateTime;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_siem::{SendError, Transport};
use vectispire_domain::siem::{CefEvent, CollectorCa, SiemEndpoint};

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
