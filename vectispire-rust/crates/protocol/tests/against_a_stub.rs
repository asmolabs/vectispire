//! The client against a stub control plane on a loopback port: what it sends, and how it reads the
//! answers the Java agent reads — the shape of the conformance suite the protocol stream extends.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vectispire_crypto::{ResultSigner, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::secret::Secret;
use vectispire_protocol::{AgentClient, Description, ProtocolError, SealingKeyOutcome};
use vectispire_tls::TlsTrust;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// One answer of the stub: status, extra headers, body.
type Answer = (u16, Vec<(&'static str, String)>, String);

/// Answers each request with the next of `answers`.
fn stub(answers: Vec<Answer>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    std::thread::spawn(move || {
        for (status, headers, body) in answers {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut parts = line.split_whitespace();
            let (method, path) = (parts.next().unwrap().to_owned(), parts.next().unwrap().to_owned());
            let mut request_headers = Vec::new();
            let mut length = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                let (name, value) = header.trim().split_once(':').unwrap();
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
                request_headers.push((name.to_lowercase(), value.trim().to_owned()));
            }
            let mut content = vec![0; length];
            reader.read_exact(&mut content).unwrap();
            recorded.lock().unwrap().push(Seen {
                method,
                path,
                headers: request_headers,
                body: String::from_utf8(content).unwrap(),
            });
            let mut stream = stream;
            let extra: String = headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
            write!(stream, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).unwrap();
        }
    });
    (address, seen)
}

fn seed() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([9u8; 32])
}

fn description(client: &AgentClient) -> Description {
    Description {
        contract_version: "1",
        hostname: "scanner-01".into(),
        platform: "linux aarch64".into(),
        scanner_engine: "docker".into(),
        sealing_public_key: client.sealing_public_key(),
        version: Some("0.12.0-dev".into()),
    }
}

#[tokio::test]
async fn hello_then_a_signed_sealing_key_then_an_empty_poll() {
    let agent = "3f2b6c1e-8d4a-4b7e-9c2f-5a1d0e7b9c34";
    let (address, seen) = stub(vec![
        (
            200,
            vec![],
            format!(
                r#"{{"id":"{agent}","name":"scanner-01","contractVersion":"1","maxConcurrent":2,"credentialsMode":"delegated"}}"#
            ),
        ),
        (204, vec![], String::new()),
        (204, vec![("X-Vectispire-Max-Concurrent", "3".into())], String::new()),
    ]);
    let signer = ResultSigner::from_base64_seed(&seed()).unwrap();
    let public = signer.public_key();
    let client = AgentClient::new(
        &address,
        Secret::new("invented-api-key"),
        &TlsTrust::BuiltIn,
        Some(signer),
        SealingKeyPair::generate(),
        1_760_000_000_000,
    )
    .unwrap();

    let identity = client.hello(&description(&client)).await.unwrap();
    assert_eq!((identity.max_concurrent, identity.credentials_mode.as_deref()), (2, Some("delegated")));
    assert_eq!(client.announce_sealing_key().await.unwrap(), SealingKeyOutcome::Accepted);
    let claim = client.claim(Duration::from_secs(1)).await.unwrap();
    assert_eq!((claim.task, claim.max_concurrent), (None, Some(3)));

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen.iter().map(|s| format!("{} {}", s.method, s.path)).collect::<Vec<_>>(),
        ["POST /api/v1/agent/hello", "POST /api/v1/agent/sealing-key", "GET /api/v1/agent/jobs?wait=1"]
    );
    assert!(seen.iter().all(|s| { s.headers.contains(&("authorization".into(), "Bearer invented-api-key".into())) }));
    let hello: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(hello["contract_version"], "1", "snake case, as HelloRequest");
    let announced: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
    assert!(vectispire_crypto::verify_sealing_key(
        &public,
        agent.parse().unwrap(),
        announced["generation"].as_i64().unwrap(),
        announced["public_key"].as_str().unwrap(),
        announced["signature"].as_str().unwrap()
    ));
}

#[tokio::test]
async fn a_refusal_is_told_apart_and_a_failure_report_is_signed_over_its_bytes() {
    let (address, seen) = stub(vec![
        (409, vec![], r#"{"detail":"Contract 2 required."}"#.into()),
        (401, vec![], r#"{"detail":"API key refused."}"#.into()),
        (200, vec![], r#"{"retried":true}"#.into()),
    ]);
    let signer = ResultSigner::from_base64_seed(&seed()).unwrap();
    let public = signer.public_key();
    let client =
        AgentClient::new(&address, Secret::new("k"), &TlsTrust::BuiltIn, Some(signer), SealingKeyPair::generate(), 1)
            .unwrap();
    assert!(
        matches!(client.hello(&description(&client)).await, Err(ProtocolError::ContractMismatch(message)) if message == "Contract 2 required.")
    );
    assert!(matches!(client.claim(Duration::from_secs(1)).await, Err(ProtocolError::Unauthorized(_))));
    let task: vectispire_protocol::AssignedTask =
        serde_json::from_str(r#"{"scanId":12,"attempt":1,"task":{}}"#).unwrap();
    assert!(client.report_failure(&task, "why", FailureKind::Transient).await.unwrap());
    let report = seen.lock().unwrap()[2].clone();
    let signature = report
        .headers
        .iter()
        .find(|(name, _)| name == "x-vectispire-agent-signature")
        .map(|(_, value)| value.clone())
        .unwrap();
    assert!(vectispire_crypto::verify_failure(&public, 12, report.body.as_bytes(), &signature));
}
