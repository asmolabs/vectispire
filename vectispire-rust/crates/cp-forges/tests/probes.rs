//! A connection's probe against a forge on loopback, over HTTPS, under a CA no trust store holds — the owner's case:
//! a self-managed GitLab on the internal network behind its own CA (`ForgeConnectionsRoutesTest`, `ForgeProbesTest`).
//! Only a connection pinning that CA reaches it; the runtime's trust alone is refused, `unreachable`, in a 400 whose
//! words are the TLS stack's — which is why the route's recording of that refusal is not compared (`_recording.txt`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_db::Engine;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_forges::ForgeError;
use vectispire_cp_forges::connections::Creation;

fn openssl(directory: &std::path::Path, arguments: &[&str]) {
    let output =
        std::process::Command::new("openssl").args(arguments).current_dir(directory).output().expect("openssl");
    assert!(output.status.success(), "openssl {arguments:?}: {}", String::from_utf8_lossy(&output.stderr));
}

/// A forge stub: its CA's PEM, and its port; it answers each path from `routes`, 404 otherwise.
async fn forge(routes: BTreeMap<&'static str, (u16, &'static str)>) -> (String, u16, Arc<Mutex<Vec<String>>>) {
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
            "/CN=Forge Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            "ca.pem",
        ],
    );
    openssl(path, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "server.key"]);
    openssl(path, &["req", "-new", "-key", "server.key", "-subj", "/CN=forge", "-out", "server.csr"]);
    std::fs::write(path.join("server.ext"), "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n").unwrap();
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
    let chain: Vec<_> = rustls_pki_types::CertificateDer::pem_file_iter(path.join("server.pem"))
        .unwrap()
        .map(|certificate| certificate.unwrap())
        .collect();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(path.join("server.key")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, routes, log) = (acceptor.clone(), routes.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if !matches!(tls.read(&mut byte).await, Ok(1)) {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let path = text.split(' ').nth(1).unwrap_or("").to_owned();
                log.lock().unwrap().push(text.to_ascii_lowercase());
                let (status, body) = routes.get(path.as_str()).copied().unwrap_or((404, r#"{"message":"404"}"#));
                let answer = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    let pem = std::fs::read_to_string(path.join("ca.pem")).unwrap();
    (pem, port, seen)
}

fn gitlab(scopes: &'static str) -> BTreeMap<&'static str, (u16, &'static str)> {
    let token: &'static str = Box::leak(
        format!(
            r#"{{"id":1,"name":"discovery","active":true,"revoked":false,"expires_at":"2027-01-31","scopes":{scopes}}}"#
        )
        .into_boxed_str(),
    );
    BTreeMap::from([
        ("/api/v4/personal_access_tokens/self", (200, token)),
        ("/api/v4/version", (200, r#"{"version":"17.4.1-ee","revision":"abc"}"#)),
        ("/api/v4/user", (200, r#"{"id":7,"username":"group_1_bot","bot":true}"#)),
    ])
}

fn admin() -> RequestActor {
    RequestActor { username: Some("admin".into()), ip_address: Some("127.0.0.1".into()), user_agent: None }
}

fn creation(port: u16, ca: Option<String>, internal: bool) -> Creation {
    Creation {
        name: Some("Internal GitLab".into()),
        kind: Some("gitlab".into()),
        base_url: Some(format!("https://127.0.0.1:{port}")),
        owner: None,
        internal_network: Some(internal),
        ca_pem: ca,
        token: Some("glpat-ProbeSecret0000000001".into()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_ca_reaches_the_forge_and_the_runtime_trust_alone_does_not() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let server = TestDatabase::start(Engine::MySql).await;
    let db = server.connect().await;
    let services = support::services_on(db);
    let (ca, port, seen) = forge(gitlab(r#"["read_api"]"#)).await;

    let refused = services.connections.create(Some(creation(port, None, true)), &admin()).await.unwrap_err();
    let ForgeError::InvalidInput(message) = refused else { panic!("a 400, not {refused:?}") };
    assert!(message.starts_with(&format!("GitLab at https://127.0.0.1:{port}: ")), "{message}");
    assert!(seen.lock().unwrap().is_empty(), "nothing answered over an unverified connection");

    let created = services.connections.create(Some(creation(port, Some(ca), true)), &admin()).await.unwrap();
    assert_eq!(
        (created.edition.as_str(), created.credential_kind.as_str(), created.forge_version.as_deref()),
        ("gitlab_self_managed", "gitlab_bot", Some("17.4.1-ee"))
    );
    assert_eq!(created.scopes, Some(vec!["read_api".to_owned()]));
    assert_eq!(created.token_expires_at.as_deref(), Some("2027-01-31T00:00:00Z"));
    assert_eq!(created.ca_subject.as_deref(), Some("CN=Forge Test CA"));
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 3, "the token's description, the version, the user");
    assert!(requests.iter().all(|request| request.contains("private-token: glpat-probesecret0000000001")));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_scope_and_a_public_only_statement_are_refused_before_anything_is_kept() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let server = TestDatabase::start(Engine::MySql).await;
    let db = server.connect().await;
    let services = support::services_on(db);
    let (ca, port, seen) = forge(gitlab(r#"["read_api","write_repository"]"#)).await;

    let refused =
        services.connections.create(Some(creation(port, Some(ca.clone()), true)), &admin()).await.unwrap_err();
    assert!(refused.to_string().contains("write_repository"), "{refused}");
    assert_eq!(seen.lock().unwrap().len(), 1, "refused at the first answer, the token presented once");

    let blocked = services.connections.create(Some(creation(port, Some(ca), false)), &admin()).await.unwrap_err();
    assert!(
        blocked.to_string().ends_with("If this server is on your internal network, say so on the connection."),
        "{blocked}"
    );
    assert_eq!(seen.lock().unwrap().len(), 1, "a blocked address is sent nothing");
    assert!(services.connections.list(None, None).await.unwrap().is_empty(), "nothing kept");
}
