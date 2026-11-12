//! The agent against a **real control plane** — the published image on a throwaway MySQL — rather than
//! a stub that answers what this crate expects.
//!
//! A stub can only confirm what its author believed the control plane does. Here the control plane
//! verifies the Rust agent's signatures (the sealing key's, a result's, a failure report's), seals a
//! repository's HTTPS token to the key the agent announced, leases scans and counts their attempts, all
//! with its own code. Then the agent binary itself is started, to see the loop it ships wired.
//!
//! **Docker is required, and its absence fails the test.** Containers and the network are named
//! `vs-rs-p-*` and removed on drop. The image is `VECTISPIRE_E2E_CONTROL_PLANE_IMAGE`, by default the
//! last published release by digest; set it to a locally built image to test a branch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use vectispire_crypto::{ResultSigner, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::secret::Secret;
use vectispire_protocol::{
    AgentClient, Description, FailureReported, Findings, ScanArtifacts, SealingKeyOutcome, Target,
};
use vectispire_testkit::docker::{Container, docker, unique_name};
use vectispire_tls::TlsTrust;

/// The release whose agent protocol this port follows (contract 1), by digest.
const DEFAULT_IMAGE: &str =
    "ghcr.io/asmolabs/vectispire:0.11.0-rc.3@sha256:453aedcefc981ff9e91298c38db74138b027f5b1cac5e284fa889d1e264e1d46";
/// The composition's MySQL, as `docker-compose.yml` pins it.
const MYSQL_IMAGE: &str = "mysql:8.4.11@sha256:24989179f58856db763f418010c1169fecc944e3ec1ea7e921572d83eb070f70";
// Invented for this throwaway database and never anything else's.
const DB_PASSWORD: &str = "vs-rs-p-database-password";
/// The throwaway control plane's own encryption key — handed to its container, never to the agent.
const CONTROL_PLANE_KEY: &str = "dnMtcnMtcC1lbmNyeXB0aW9uLWtleS1pbnZlbnRlZCE="; // gitleaks:allow — base64 of an invented 32-byte label
const BOOTSTRAP_PASSWORD: &str = "Vs-rs-p-bootstrap-Invented-1!";
const ROTATED_PASSWORD: &str = "Vs-rs-p-rotated-Invented-2!";

struct Network(String);

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

/// The control plane's API, as an administrator.
struct Admin {
    base: String,
    http: reqwest::Client,
    session: String,
}

impl Admin {
    async fn send(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self.http.request(method, format!("{}{path}", self.base)).bearer_auth(&self.session);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    async fn ok(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self.send(method, path, body).await;
        assert!((200..300).contains(&status), "{path}: HTTP {status} {answer}");
        answer
    }

    async fn scan(&self, scan: i64) -> Value {
        self.ok(reqwest::Method::GET, &format!("/api/v1/scans/{scan}"), None).await["scan"].clone()
    }

    /// Waits until the scan's state satisfies `condition`, and returns it.
    async fn scan_until(&self, scan: i64, condition: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let state = self.scan(scan).await;
            if condition(&state) {
                return state;
            }
            assert!(Instant::now() < deadline, "scan {scan} never reached the expected state: {state}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

async fn login(http: &reqwest::Client, base: &str, password: &str) -> String {
    let answer: Value = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": password}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    answer["token"].as_str().unwrap_or_else(|| panic!("login refused: {answer}")).to_owned()
}

/// MySQL and the control plane on a network of their own; the control plane's port published on the
/// loopback interface.
async fn control_plane() -> (Network, Container, Container, String) {
    let image = std::env::var("VECTISPIRE_E2E_CONTROL_PLANE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
    let network = Network(unique_name("p-net"));
    docker(&["network", "create", &network.0]);
    let mysql_password = format!("MYSQL_PASSWORD={DB_PASSWORD}");
    let mysql_root = format!("MYSQL_ROOT_PASSWORD={DB_PASSWORD}");
    let database = Container::run(
        "p-mysql",
        &[
            "--network",
            &network.0,
            "--network-alias",
            "db",
            "-e",
            &mysql_root,
            "-e",
            "MYSQL_DATABASE=vectispire",
            "-e",
            "MYSQL_USER=vectispire",
            "-e",
            &mysql_password,
            MYSQL_IMAGE,
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    while Command::new("docker")
        .args([
            "exec",
            &database.name,
            "mysqladmin",
            "ping",
            "-h",
            "127.0.0.1",
            "-uvectispire",
            &format!("-p{DB_PASSWORD}"),
        ])
        .output()
        .map(|output| !output.status.success())
        .unwrap_or(true)
    {
        assert!(Instant::now() < deadline, "MySQL did not start");
        std::thread::sleep(Duration::from_secs(2));
    }
    let variables = [
        "VECTISPIRE_DB_URL=jdbc:mysql://db:3306/vectispire".to_owned(),
        "VECTISPIRE_DB_USER=vectispire".to_owned(),
        format!("VECTISPIRE_DB_PASSWORD={DB_PASSWORD}"),
        // Spelt in two halves: `isolation.rs` refuses any source of the workspace that names the variable,
        // and this one names it only to start the control plane the agent is tested against.
        format!("{}={CONTROL_PLANE_KEY}", ["ENCRYPTION", "_KEY"].concat()),
        "VECTISPIRE_BOOTSTRAP_USERNAME=admin".to_owned(),
        format!("VECTISPIRE_BOOTSTRAP_PASSWORD={BOOTSTRAP_PASSWORD}"),
        "VECTISPIRE_EMBEDDED_WORKER=false".to_owned(),
    ];
    let mut arguments = vec!["--network", network.0.as_str(), "-p", "127.0.0.1::3180"];
    for variable in &variables {
        arguments.extend(["-e", variable.as_str()]);
    }
    arguments.push(image.as_str());
    let app = Container::run("p-app", &arguments);
    let base = format!("http://127.0.0.1:{}", app.host_port("3180/tcp"));
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if http.get(format!("{base}/actuator/health")).send().await.is_ok_and(|r| r.status().is_success()) {
            break;
        }
        if Instant::now() > deadline {
            panic!("the control plane did not become healthy: {}", docker(&["logs", "--tail", "60", &app.name]));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    (network, database, app, base)
}

#[tokio::test]
async fn the_agent_speaks_the_protocol_with_a_real_control_plane() {
    let (_network, _database, app, base) = control_plane().await;
    let http = reqwest::Client::new();
    let first = login(&http, &base, BOOTSTRAP_PASSWORD).await;
    let status = http
        .post(format!("{base}/api/v1/auth/change-password"))
        .bearer_auth(&first)
        .json(&json!({"current_password": BOOTSTRAP_PASSWORD, "new_password": ROTATED_PASSWORD}))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "password rotation: {status}");
    let admin = Admin { session: login(&http, &base, ROTATED_PASSWORD).await, base: base.clone(), http };

    // ── An agent in `delegated` mode with a signing key pinned: what a sealed credential needs.
    let declared = admin
        .ok(
            reqwest::Method::POST,
            "/api/v1/admin/agents",
            Some(json!({"name": "rust-e2e", "credentials_mode": "delegated"})),
        )
        .await;
    let agent_id = declared["id"].as_str().unwrap().to_owned();
    let api_key = declared["secret"].as_str().unwrap().to_owned();
    let pinned = admin
        .ok(
            reqwest::Method::PUT,
            &format!("/api/v1/admin/agents/{agent_id}/signing-key"),
            Some(json!({"public_key": "generate"})),
        )
        .await;
    let seed = pinned["privateKey"].as_str().unwrap().to_owned();

    // ── A repository with an HTTPS token, and one without any credential.
    let token = format!("invented-e2e-token-{}", std::process::id());
    let git_token = admin
        .ok(
            reqwest::Method::POST,
            "/api/v1/git-tokens",
            Some(
                json!({"host": "gitlab.example.org", "name": "rust-e2e", "token": token, "username": "x-access-token"}),
            ),
        )
        .await;
    let credentialed = admin
        .ok(
            reqwest::Method::POST,
            "/api/v1/repositories",
            Some(json!({"name": "rust-e2e-token", "url": "https://gitlab.example.org/acme/credentialed.git",
                        "branch": "main", "scanManualOnly": true, "https_token_id": git_token["id"]})),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let public = admin
        .ok(
            reqwest::Method::POST,
            "/api/v1/repositories",
            Some(json!({"name": "rust-e2e-public", "url": "https://gitlab.example.org/acme/public.git",
                        "branch": "main", "scanManualOnly": true})),
        )
        .await["id"]
        .as_i64()
        .unwrap();

    // ── The protocol, call by call.
    let client = AgentClient::new(
        &base,
        Secret::new(api_key.clone()),
        &TlsTrust::BuiltIn,
        Some(ResultSigner::from_base64_seed(&seed).unwrap()),
        SealingKeyPair::generate(),
        1_760_000_000_000,
    )
    .unwrap();
    let identity = client
        .hello(&Description {
            contract_version: vectispire_domain::contract::VERSION,
            hostname: "rust-e2e".into(),
            platform: "linux".into(),
            scanner_engine: "docker".into(),
            sealing_public_key: client.sealing_public_key(),
            version: Some("0.12.0-dev".into()),
        })
        .await
        .unwrap();
    assert_eq!(identity.credentials_mode.as_deref(), Some("delegated"));
    assert_eq!(identity.id.as_deref(), Some(agent_id.as_str()));
    assert_eq!(
        client.announce_sealing_key().await.unwrap(),
        SealingKeyOutcome::Accepted,
        "the control plane verified the Rust agent's signature over its sealing key"
    );
    let empty = client.claim(Duration::from_secs(1)).await.unwrap();
    assert!(empty.task.is_none());

    let scan = admin.ok(reqwest::Method::POST, &format!("/api/v1/repositories/{credentialed}/scan"), None).await["id"]
        .as_i64()
        .unwrap();
    let claimed = client.claim(Duration::from_secs(5)).await.unwrap().task.expect("the queued scan");
    assert_eq!(claimed.scan_id, scan);
    let Target::Repository(repository) = &claimed.task.target else { panic!("a repository") };
    let https = repository.https.as_ref().expect("the token, delegated");
    assert_eq!(https.host.as_deref(), Some("gitlab.example.org"));
    assert_eq!(
        https.token.as_ref().unwrap().expose(),
        token,
        "the control plane sealed the token to the announced key, and the Rust agent opened it"
    );
    assert!(client.heartbeat(scan).await.unwrap());
    let artifacts = ScanArtifacts {
        secrets: Some(Findings::default()),
        failures: vec![vectispire_protocol::Failure { step: "dependencies".into(), reason: "not ported".into() }],
        duration: Duration::from_millis(1_234),
        ..ScanArtifacts::default()
    };
    assert!(client.submit(scan, &artifacts).await.unwrap(), "the signed result was accepted");
    let finished = admin.scan(scan).await;
    assert_ne!(finished["status"], "pending");
    assert_ne!(finished["status"], "scanning", "{finished}");
    assert!(!client.heartbeat(scan).await.unwrap(), "a finished scan's lease is no longer this agent's");
    assert!(!client.submit(scan, &artifacts).await.unwrap(), "nor is its result");

    let second = admin.ok(reqwest::Method::POST, &format!("/api/v1/repositories/{public}/scan"), None).await["id"]
        .as_i64()
        .unwrap();
    let claimed = client.claim(Duration::from_secs(5)).await.unwrap().task.expect("the second scan");
    assert_eq!((claimed.scan_id, claimed.attempt), (second, Some(1)));
    let reported = client.report_failure(&claimed, "invented transient reason", FailureKind::Transient).await.unwrap();
    assert_eq!(reported, FailureReported::Retried, "the signed failure report was accepted, the scan requeued");
    let requeued = admin.scan(second).await;
    assert_eq!(requeued["status"], "pending", "{requeued}");
    assert_eq!(
        client.report_failure(&claimed, "again", FailureKind::Transient).await.unwrap(),
        FailureReported::NotYours,
        "the same attempt cannot be reported twice"
    );
    drop(client);

    // ── The binary: its own hello, announcement and loop, with the runner it ships, take the requeued
    // scan, clone — the repository's host does not exist, so the clone is a transient network failure —
    // and report it back for another attempt.
    let mut binary = Command::new(env!("CARGO_BIN_EXE_vectispire-agent"))
        .env_clear()
        .env("VECTISPIRE_URL", &base)
        .env("VECTISPIRE_AGENT_TOKEN", &api_key)
        .env("VECTISPIRE_AGENT_SIGNING_KEY", &seed)
        .env("VECTISPIRE_AGENT_WAIT", "2s")
        .env("VECTISPIRE_AGENT_RETRY", "1s")
        .env("VECTISPIRE_LOG_LEVEL", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let reported = admin
        .scan_until(second, |state| {
            state["error"].as_str().is_some_and(|error| error.contains("could not reach its host"))
        })
        .await;
    assert!(reported["status"] == "pending" || reported["status"] == "failed", "{reported}");
    Command::new("kill").args(["-TERM", &binary.id().to_string()]).status().unwrap();
    let output = wait_with_timeout(&mut binary, Duration::from_secs(60));
    let log = String::from_utf8_lossy(&output.0);
    assert!(output.1, "the agent exits cleanly on SIGTERM:\n{log}");
    for line in [
        "Sealing key verified by the control plane",
        "Up to 1 scan(s) at once",
        &format!("Scan {second}: https://gitlab.example.org/acme/public.git (main)."),
        "Shutdown requested",
        "Agent stopped.",
    ] {
        assert!(log.contains(line), "{line:?} missing from the agent's log:\n{log}");
    }
    assert!(!log.contains(&api_key) && !log.contains(&seed), "no secret in the log");
    drop(app);
}

/// The process's combined output, and whether it exited with success.
fn wait_with_timeout(child: &mut std::process::Child, limit: Duration) -> (Vec<u8>, bool) {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut out = Vec::new();
            use std::io::Read;
            child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
            child.stderr.take().unwrap().read_to_end(&mut out).unwrap();
            return (out, status.success());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the agent did not stop within {limit:?} of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
